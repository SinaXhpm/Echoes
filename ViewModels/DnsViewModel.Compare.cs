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

// Compare mode: one name against every resolver in the compare list, DnsCompare.Rounds times each.
public partial class DnsViewModel
{
    /// <summary>The compare list (separate from the lookup list; starts as every preset).</summary>
    [ObservableProperty] private string _compareServersText = string.Empty;

    partial void OnCompareServersTextChanged(string value)
    {
        if (IsCompareMode) { OnPropertyChanged(nameof(ResolverText)); RefreshPresetMarks(); }
        if (_loaded) ProfileService.Instance.SetSetting("dns.compare", value);
    }

    public IReadOnlyList<string> CompareTypes { get; } = new[] { "A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA" };

    [ObservableProperty] private string _compareType = "A";

    partial void OnCompareTypeChanged(string value)
    {
        if (_loaded && value != null) ProfileService.Instance.SetSetting("dns.compareType", value);
    }

    public ObservableCollection<CompareRow> CompareRows { get; } = new();

    /// <summary>The recommendation line (or why there is none).</summary>
    [ObservableProperty] private string _compareSummary = "";
    [ObservableProperty] private bool _compareSummaryGood;
    [ObservableProperty] private bool _compareSummaryBad;
    /// <summary>"12 of 51 queries" while running; "17 resolvers · 3 rounds" after.</summary>
    [ObservableProperty] private string _compareProgress = "";
    [ObservableProperty] private bool _hasCompareRows;

    private List<CompareStats>? _compareStats;
    private string _compareName = "";

    private async Task RunCompare()
    {
        DomainName = HostExtractor.Extract(DomainName);
        if (string.IsNullOrWhiteSpace(DomainName) || IsWorking) return;
        string host = DomainName.Trim();
        if (System.Net.IPAddress.TryParse(host, out _))
        {
            ShowCompareMessage("Compare asks resolvers about a name — enter a domain, e.g. example.com.", bad: true);
            return;
        }

        var token = NewRun();
        HistoryService.Instance.Add("dns.domain", DomainName);
        var skipped = new List<(string line, string reason)>();
        var specs = ResolverSpec.ParseList(CompareServersText, skipped);
        if (specs.Count == 0)
        {
            ShowCompareMessage("No valid resolver in the list — add some from Presets, or one per line (1.1.1.1, https://…/dns-query, tls://…).", bad: true);
            return;
        }
        bool cut = specs.Count > DnsCompare.MaxResolvers;
        specs = specs.Take(DnsCompare.MaxResolvers).ToList();

        IsWorking = true;
        _compareStats = null;
        string type = CompareTypes.Contains(CompareType) ? CompareType : "A";
        var qtype = type switch
        {
            "AAAA" => QueryType.AAAA, "MX" => QueryType.MX, "TXT" => QueryType.TXT, "NS" => QueryType.NS,
            "CNAME" => QueryType.CNAME, "SOA" => QueryType.SOA, "CAA" => QueryType.CAA, _ => QueryType.A,
        };
        string ascii = SecureDns.ToAscii(host);
        _compareName = ascii;

        CompareRows.Clear();
        var rows = specs.Select(s => new CompareRow(s)).ToList();
        foreach (var r in rows) CompareRows.Add(r);
        HasCompareRows = true;
        CompareSummary = "";
        CompareSummaryGood = CompareSummaryBad = false;
        int total = specs.Count * DnsCompare.Rounds, done = 0;
        bool finished = false;   // progress posts still queued when the run ends must not overwrite the final state
        CompareProgress = $"0 of {total} queries";

        try
        {
            var stats = await Task.Run(() => DnsCompare.RunAsync(specs, ascii, qtype, (st, round) =>
            {
                int n = Interlocked.Increment(ref done);
                Dispatcher.UIThread.Post(() =>
                {
                    if (token.IsCancellationRequested || finished) return;
                    int i = specs.IndexOf(st.Spec);
                    if (i >= 0 && i < rows.Count) rows[i].Update(st, final: false);
                    CompareProgress = $"{Math.Min(n, total)} of {total} queries";
                });
            }, token), token);

            finished = true;
            _compareStats = stats;
            // fastest first: rebuild the list in that order with the verdicts
            CompareRows.Clear();
            foreach (var st in DnsCompare.Sorted(stats))
            {
                var row = rows[specs.IndexOf(st.Spec)];
                row.Update(st, final: true);
                CompareRows.Add(row);
            }
            CompareSummary = DnsCompare.Recommendation(stats) + (skipped.Count > 0 ? $" ({skipped.Count} line(s) skipped: {skipped[0].reason})" : "")
                             + (cut ? $" Only the first {DnsCompare.MaxResolvers} resolvers were compared." : "");
            CompareSummaryGood = stats.Any(s => s.IsBest);
            CompareSummaryBad = !CompareSummaryGood;
            CompareProgress = $"{stats.Count} resolvers · {DnsCompare.Rounds} rounds · {type}";
        }
        catch (OperationCanceledException)
        {
            // stopped halfway: the rows still waiting said "…" as if the run went on, and Copy had nothing to copy
            finished = true;   // progress posts still queued add nothing now
            foreach (var row in rows) row.MarkStopped();
            CompareSummary = "Stopped before every resolver was asked: the times above are from the queries that finished.";
            CompareSummaryGood = CompareSummaryBad = false;
            CompareProgress = "stopped";
        }
        finally { IsWorking = false; }
    }

    private void ShowCompareMessage(string text, bool bad)
    {
        CompareRows.Clear();
        HasCompareRows = false;
        _compareStats = null;
        CompareSummary = text;
        CompareSummaryBad = bad;
        CompareSummaryGood = !bad;
        CompareProgress = "";
    }

    private string CompareReport()
        => _compareStats is { Count: > 0 } s ? DnsCompare.Report(_compareName, CompareType, s) : CompareSummary;
}
