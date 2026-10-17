using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using DnsClient;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

// Email check mode: the domain's mail setup, asked through the lookup resolver list (the first that answers).
public partial class DnsViewModel
{
    public ObservableCollection<MailRow> MailItems { get; } = new();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowMailEmpty))]
    private bool _hasMailItems;
    /// <summary>"gmail.com" — the domain the shown report is for.</summary>
    [ObservableProperty] private string _mailDomain = "";
    /// <summary>"4 ok · 1 warning" while / after the run, or "checking… 3 of 7".</summary>
    [ObservableProperty] private string _mailSummary = "";
    [ObservableProperty] private int _mailOk;
    [ObservableProperty] private int _mailWarn;
    [ObservableProperty] private int _mailFail;
    /// <summary>The resolver the answers came from ("1.1.1.1 · plain").</summary>
    [ObservableProperty] private string _mailVia = "";
    /// <summary>One clear error when the check couldn't run at all.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowMailEmpty))]
    private string _mailError = "";

    /// <summary>The empty-state text: nothing checked yet (no findings, no error).</summary>
    public bool ShowMailEmpty => !HasMailItems && MailError.Length == 0;

    private readonly List<MailCheckItem>?[] _mailAreas = new List<MailCheckItem>?[MailCheck.Areas.Length];

    private async Task RunEmail()
    {
        DomainName = HostExtractor.Extract(DomainName);
        if (string.IsNullOrWhiteSpace(DomainName) || IsWorking) return;
        string domain = DomainName.Trim().TrimEnd('.');
        ClearMail();
        if (System.Net.IPAddress.TryParse(domain, out _) || !domain.Contains('.'))
        {
            MailError = "Enter the mail domain (the part after @), e.g. example.com.";
            return;
        }

        var skipped = new List<(string line, string reason)>();
        var specs = ResolverSpec.ParseList(DnsServersText, skipped);
        if (specs.Count == 0)
        {
            MailError = "No valid resolver in the list — add one (1.1.1.1, https://…/dns-query, tls://…, or system) from Presets.";
            return;
        }
        // a query nobody answers goes down the whole list (each one waits for its timeout): the lookup's cap applies here too
        if (specs.Count > MaxLookupResolvers) specs = specs.Take(MaxLookupResolvers).ToList();

        var token = NewRun();
        HistoryService.Instance.Add("dns.domain", DomainName);
        SaveServers();
        string ascii = SecureDns.ToAscii(domain);
        MailDomain = domain;
        IsWorking = true;
        MailSummary = $"checking… 0 of {MailCheck.Areas.Length}";

        // Automatic fallback: every query goes to the resolver that last answered; one that doesn't answer (timeout,
        // TLS failure) passes the query down the list, and the one that answers becomes the current one.
        var sessions = new DnsSession?[specs.Count];
        int current = 0;
        var failures = new Dictionary<string, string>();
        async Task<DnsResult> Query(string name, QueryType type, CancellationToken ct)
        {
            DnsResult? last = null;
            int start = Volatile.Read(ref current);
            for (int k = 0; k < specs.Count; k++)
            {
                int i = (start + k) % specs.Count;
                DnsSession session;
                lock (sessions) session = sessions[i] ??= new DnsSession(specs[i]);
                var r = await session.QueryAsync(name, type, ct).ConfigureAwait(false);
                if (r.Answered)
                {
                    if (i != start) Interlocked.CompareExchange(ref current, i, start);
                    return r;
                }
                lock (failures) failures[specs[i].Short] = r.ShortError ?? r.Error ?? "no answer";
                last = r;
            }
            return last!;
        }

        int areasDone = 0;
        try
        {
            await Task.Run(() => MailCheck.RunAsync(ascii, Query, (index, items) =>
            {
                int n = Interlocked.Increment(ref areasDone);
                Dispatcher.UIThread.Post(() =>
                {
                    if (token.IsCancellationRequested) return;
                    _mailAreas[index] = items.ToList();
                    RebuildMail();
                    MailSummary = n < MailCheck.Areas.Length ? $"checking… {n} of {MailCheck.Areas.Length}" : MailCheck.Counts(AllMailItems().ToList());
                });
            }, token), token);
            // the posted updates run before this continuation (same dispatcher, FIFO)
            await Dispatcher.UIThread.InvokeAsync(() => { }, DispatcherPriority.Background);
            MailSummary = MailCheck.Counts(AllMailItems().ToList());
            var s = specs[Volatile.Read(ref current)];
            MailVia = $"{s.Short} · {s.TransportLabel}";
            // nothing answered at all: ONE error with every resolver's reason instead of a list of "couldn't look up"
            if (_mailAreas[0] is { Count: 1 } mx && mx[0].Summary.StartsWith("Couldn't look up", StringComparison.Ordinal) && failures.Count >= specs.Count)
            {
                MailError = "No resolver answered: " + string.Join("; ", failures.Select(f => $"{f.Key} — {f.Value}")) + ".";
                Array.Clear(_mailAreas);
                MailItems.Clear();
                HasMailItems = false;
                MailSummary = "";
                MailVia = "";
                MailOk = MailWarn = MailFail = 0;
            }
        }
        catch (OperationCanceledException)
        {
            MailSummary = "stopped";
        }
        finally
        {
            foreach (var s in sessions) s?.Dispose();
            IsWorking = false;
        }
    }

    private void ClearMail()
    {
        Array.Clear(_mailAreas);
        MailItems.Clear();
        HasMailItems = false;
        MailError = "";
        MailSummary = "";
        MailVia = "";
        MailOk = MailWarn = MailFail = 0;
    }

    private IEnumerable<MailCheckItem> AllMailItems() => _mailAreas.Where(a => a != null).SelectMany(a => a!);

    // the areas in their fixed order, whichever finished first
    private void RebuildMail()
    {
        MailItems.Clear();
        foreach (var area in _mailAreas)
        {
            if (area == null) continue;
            for (int i = 0; i < area.Count; i++) MailItems.Add(new MailRow(area[i]) { IsAreaStart = i == 0 && MailItems.Count > 0 });
        }
        HasMailItems = MailItems.Count > 0;
        var all = AllMailItems().ToList();
        MailOk = all.Count(x => x.Status == MailStatus.Ok);
        MailWarn = all.Count(x => x.Status == MailStatus.Warning);
        MailFail = all.Count(x => x.Status == MailStatus.Fail);
    }

    private string MailReport()
    {
        if (MailError.Length > 0) return MailError;
        var all = AllMailItems().ToList();
        return all.Count == 0 ? "" : MailCheck.Report(MailDomain, MailVia, all);
    }
}
