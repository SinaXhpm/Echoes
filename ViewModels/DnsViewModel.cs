using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DnsClient;
using DnsClient.Protocol;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>One DNS answer (or a status line) shown as a card in the results list.</summary>
public sealed class DnsRecordRow
{
    public string Type { get; init; } = "";
    public string Value { get; init; } = "";
    public string Server { get; init; } = "";
    public bool IsStatus { get; init; }            // "no records" / "timeout" — not a real, copyable record
    public bool IsRecord => !IsStatus;
}

public partial class DnsViewModel : ObservableObject
{
    [ObservableProperty] private string _domainName = string.Empty;
    [ObservableProperty] private string _logText = string.Empty;
    [ObservableProperty] private bool _isWorking;
    [ObservableProperty] private string _dnsServersText = string.Empty;

    // DNS lookups render as record cards (Records); WHOIS renders as freeform text (LogText).
    public ObservableCollection<DnsRecordRow> Records { get; } = new();
    [ObservableProperty] private bool _showRecords;

    // Wrap the WHOIS text pane by default so long lines stay visible.
    [ObservableProperty] private bool _wrapResult = true;
    public Avalonia.Media.TextWrapping ResultWrapping
        => WrapResult ? Avalonia.Media.TextWrapping.Wrap : Avalonia.Media.TextWrapping.NoWrap;

    private bool _loaded;
    partial void OnWrapResultChanged(bool value)
    {
        OnPropertyChanged(nameof(ResultWrapping));
        if (_loaded) ProfileService.Instance.SetBool("dns.wrap", value);
    }

    [ObservableProperty] private bool _typeA = true;
    [ObservableProperty] private bool _typeAAAA;
    [ObservableProperty] private bool _typeMX;
    [ObservableProperty] private bool _typeNS;
    [ObservableProperty] private bool _typeTXT;
    [ObservableProperty] private bool _typeCNAME;
    [ObservableProperty] private bool _typeSOA;
    [ObservableProperty] private bool _typeSRV;
    [ObservableProperty] private bool _typeCAA;
    [ObservableProperty] private bool _typePTR;

    public ObservableCollection<string> DomainHistory => HistoryService.Instance.Get("dns.domain");

    // Compact summary shown on the RECORD TYPES dropdown button (kept in sync with the checkboxes).
    public string SelectedTypesSummary
    {
        get
        {
            var t = GetSelectedTypes();
            if (t.Count == 0) return "none";
            if (t.Count == 10) return "all types";
            if (t.Count <= 2) return string.Join(" · ", t.Select(x => x.ToString()));
            return $"{t[0]} · {t[1]} +{t.Count - 2}";
        }
    }

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (e.PropertyName is { } n && n.StartsWith("Type", StringComparison.Ordinal))
            OnPropertyChanged(nameof(SelectedTypesSummary));
    }

    public DnsViewModel()
    {
        LoadServers();
        if (HistoryService.Instance.Last("dns.domain") is { } last) DomainName = last;
        WrapResult = ProfileService.Instance.GetBool("dns.wrap", true);
        _loaded = true;
    }

    private void LoadServers()
    {
        DnsServersText = ProfileService.Instance.GetSetting("dns.servers") ?? string.Empty;

        if (string.IsNullOrWhiteSpace(DnsServersText))
        {
            DnsServersText = "1.1.1.1" + Environment.NewLine + "8.8.8.8";
            SaveServers();
        }
    }

    private void SaveServers()
        => ProfileService.Instance.SetSetting("dns.servers", DnsServersText);

    // Cancels an in-flight lookup or WHOIS.
    private CancellationTokenSource? _cts;

    [RelayCommand]
    private void Stop() => _cts?.Cancel();

    [RelayCommand]
    private async Task RunLookup()
    {
        // Accept a pasted URL / "host:port" and reduce it to the bare domain/IP.
        DomainName = HostExtractor.Extract(DomainName);
        if (string.IsNullOrWhiteSpace(DomainName) || IsWorking) return;

        _cts?.Cancel();
        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        HistoryService.Instance.Add("dns.domain", DomainName);
        SaveServers();
        IsWorking = true;
        LogText = string.Empty;
        ShowRecords = true;
        Dispatcher.UIThread.Post(() => Records.Clear());

        var servers = DnsServersText.Split(new[] { '\n', '\r', ',' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(s => s.Trim()).Where(s => IPAddress.TryParse(s, out _)).ToList();

        var selectedTypes = GetSelectedTypes();
        if (!selectedTypes.Any() || !servers.Any())
        {
            IsWorking = false;
            return;
        }

        string host = DomainName.Trim();
        string asciiHost = ToAscii(host);   // punycode for internationalized (non-ASCII) domains

        var tasks = servers.Select(async server =>
        {
            // One client per server, reused for every record type (creating one per query
            // needlessly re-allocates sockets/parser state).
            var options = new LookupClientOptions(IPAddress.Parse(server)) { Timeout = TimeSpan.FromSeconds(3), Retries = 0 };
            var client = new LookupClient(options);

            foreach (var type in selectedTypes)
            {
                if (token.IsCancellationRequested) return;
                try
                {
                    // PTR on an IP → reverse lookup; everything else is a forward query.
                    var result = (type == QueryType.PTR && IPAddress.TryParse(host, out var revIp))
                        ? await client.QueryReverseAsync(revIp, token)
                        : await client.QueryAsync(asciiHost, type, QueryClass.IN, token);

                    if (result.Answers.Any())
                    {
                        foreach (var record in result.Answers)
                            AddRow(new DnsRecordRow { Type = type.ToString(), Value = RecordValue(record), Server = server });
                    }
                    else
                    {
                        AddRow(new DnsRecordRow { Type = type.ToString(), Value = "no records", Server = server, IsStatus = true });
                    }
                }
                catch (OperationCanceledException) { return; }   // user hit Stop — leave what we have
                catch
                {
                    AddRow(new DnsRecordRow { Type = type.ToString(), Value = "timeout", Server = server, IsStatus = true });
                }
            }
        });

        try { await Task.WhenAll(tasks); }
        catch (OperationCanceledException) { }
        IsWorking = false;
    }

    [RelayCommand]
    private async Task RunWhois()
    {
        DomainName = HostExtractor.Extract(DomainName);
        if (string.IsNullOrWhiteSpace(DomainName) || IsWorking) return;

        _cts?.Cancel();
        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        HistoryService.Instance.Add("dns.domain", DomainName);
        IsWorking = true;
        ShowRecords = false;   // WHOIS/RDAP is freeform text
        string query = DomainName.Trim();
        LogText = $"# whois {query}" + Environment.NewLine;

        // rdap.org is the IANA bootstrap — it follows to the authoritative RDAP server for any
        // TLD/registry, and also covers IPs and ASNs. Pick the right object type from the input.
        string kind =
            System.Net.IPAddress.TryParse(query, out _) ? "ip" :
            System.Text.RegularExpressions.Regex.IsMatch(query, @"^(AS)?\d+$", System.Text.RegularExpressions.RegexOptions.IgnoreCase)
                ? "autnum" : "domain";
        string key = kind == "autnum" ? query.TrimStart('A', 'S', 'a', 's') : query;

        var providers = new List<string> { $"https://rdap.org/{kind}/{key}" };
        if (kind == "domain")
            providers.Add($"https://rdap.verisign.com/com/v1/domain/{key}");   // .com/.net fallback

        string? lastError = null;
        foreach (var url in providers)
        {
            try
            {
                var (body, status) = await FetchRdap(url, token);

                // Map the common RDAP HTTP statuses to a clear message instead of dumping the body.
                if (status == 404) { lastError = "no registry record (HTTP 404)"; continue; }
                if (status == 429) { lastError = "rate limited (HTTP 429) — try again shortly"; continue; }

                if (status is >= 200 and < 300 && body.TrimStart().StartsWith('{'))
                {
                    using var doc = JsonDocument.Parse(body);
                    var sb = new StringBuilder();
                    ParseElement(doc.RootElement, sb);
                    LogText = TextLimit.Cap(sb.ToString());
                    IsWorking = false;
                    return;
                }
                lastError = $"HTTP {status}";
            }
            catch (OperationCanceledException) { LogText = "cancelled."; IsWorking = false; return; }
            catch (Exception ex) { lastError = ex.Message; }
        }
        LogText = "No RDAP data — " + (lastError ?? "request failed / timed out") + ".";
        IsWorking = false;
    }

    private static async Task<(string body, int status)> FetchRdap(string url, CancellationToken token)
    {
        using var client = HttpHelper.Create(timeout: TimeSpan.FromSeconds(10));
        client.DefaultRequestHeaders.Accept.ParseAdd("application/rdap+json");
        client.DefaultRequestHeaders.Accept.ParseAdd("application/json");

        using var response = await client.GetAsync(url, token);
        return (await response.Content.ReadAsStringAsync(token), (int)response.StatusCode);
    }

    private void ParseElement(JsonElement element, StringBuilder sb)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in element.EnumerateObject())
            {
                if (property.Value.ValueKind == JsonValueKind.Object || property.Value.ValueKind == JsonValueKind.Array)
                    ParseElement(property.Value, sb);
                else
                    sb.AppendLine($"{property.Name}: {property.Value}");
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray()) ParseElement(item, sb);
        }
    }

    // Convert an internationalized domain (Unicode) to its ASCII/punycode form for the query.
    // Leaves IPs and already-ASCII names unchanged; never throws.
    private static string ToAscii(string host)
    {
        if (string.IsNullOrEmpty(host) || IPAddress.TryParse(host, out _)) return host;
        try { return new System.Globalization.IdnMapping().GetAscii(host.TrimEnd('.')); }
        catch { return host; }
    }

    private List<QueryType> GetSelectedTypes()
    {
        var types = new List<QueryType>();
        if (TypeA) types.Add(QueryType.A);
        if (TypeAAAA) types.Add(QueryType.AAAA);
        if (TypeMX) types.Add(QueryType.MX);
        if (TypeNS) types.Add(QueryType.NS);
        if (TypeTXT) types.Add(QueryType.TXT);
        if (TypeCNAME) types.Add(QueryType.CNAME);
        if (TypeSOA) types.Add(QueryType.SOA);
        if (TypeSRV) types.Add(QueryType.SRV);
        if (TypeCAA) types.Add(QueryType.CAA);
        if (TypePTR) types.Add(QueryType.PTR);
        return types;
    }

    // Copy the whole result set: record cards (lookup) or the freeform text (WHOIS).
    [RelayCommand]
    private async Task CopyResult()
    {
        string text = ShowRecords
            ? string.Join(Environment.NewLine, Records.Where(r => r.IsRecord).Select(r => $"{r.Type}\t{r.Value}\t{r.Server}"))
            : LogText;
        if (string.IsNullOrWhiteSpace(text)) return;
        await ClipboardHelper.SetTextAsync(text);
    }

    // Copy a single record's value (the ⧉ button on each card).
    [RelayCommand]
    private async Task CopyRow(DnsRecordRow? row)
    {
        if (row is null || string.IsNullOrEmpty(row.Value)) return;
        await ClipboardHelper.SetTextAsync(row.Value);
    }

    private void AddRow(DnsRecordRow row) => Dispatcher.UIThread.Post(() => Records.Add(row));

    // Extract the clean value of a DNS answer (strongly-typed where possible, else the raw record).
    private static string RecordValue(DnsResourceRecord r) => r switch
    {
        ARecord a => a.Address.ToString(),
        AaaaRecord a => a.Address.ToString(),
        CNameRecord c => c.CanonicalName.ToString(),
        MxRecord m => $"{m.Preference}  {m.Exchange}",
        NsRecord n => n.NSDName.ToString(),
        PtrRecord p => p.PtrDomainName.ToString(),
        TxtRecord t => string.Join(" ", t.Text),
        SoaRecord s => $"{s.MName} {s.RName} (serial {s.Serial})",
        SrvRecord s => $"{s.Priority} {s.Weight} {s.Port} {s.Target}",
        CaaRecord c => $"{c.Flags} {c.Tag} {c.Value}",
        _ => r.ToString()
    };
}