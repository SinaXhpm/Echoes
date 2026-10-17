using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DnsClient;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>
/// DNS &amp; WHOIS: three modes on one page. Lookup — any record types through the user's resolvers (plain, DoH, DoT,
/// recognised from what is typed) plus RDAP/WHOIS; Compare — one name against many resolvers, speed + tampering checks
/// (DnsViewModel.Compare.cs); Email check — MX / SPF / DMARC / DKIM / MTA-STS / TLS-RPT / blocklists (DnsViewModel.Email.cs).
/// </summary>
public partial class DnsViewModel : ObservableObject
{
    [ObservableProperty] private string _domainName = string.Empty;
    [ObservableProperty] private string _logText = string.Empty;
    [ObservableProperty] private bool _isWorking;
    [ObservableProperty] private string _dnsServersText = string.Empty;

    // ---------------------------------------------------------------- mode: Lookup | Compare | Email check
    public const int ModeLookup = 0, ModeCompare = 1, ModeEmail = 2;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsLookupMode), nameof(IsCompareMode), nameof(IsEmailMode), nameof(ResolverText),
                              nameof(ResolverHint), nameof(PrimaryText), nameof(PrimaryTip))]
    private int _modeIndex;

    public bool IsLookupMode => ModeIndex == ModeLookup;
    public bool IsCompareMode => ModeIndex == ModeCompare;
    public bool IsEmailMode => ModeIndex == ModeEmail;

    partial void OnModeIndexChanged(int value)
    {
        RefreshPresetMarks();
        if (_loaded) ProfileService.Instance.SetSetting("dns.mode", value.ToString(CultureInfo.InvariantCulture));
    }

    public string PrimaryText => ModeIndex switch { ModeCompare => "Compare", ModeEmail => "Check", _ => "Look up" };
    public string PrimaryTip => ModeIndex switch
    {
        ModeCompare => "Ask every resolver in the list a few times: speed, reliability, and answers checked against the encrypted ones",
        ModeEmail => "Check the domain's mail setup: MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT and blocklists",
        _ => "Query the record types through every resolver in the list",
    };

    /// <summary>The resolver box: the lookup list in Lookup / Email check (the email check asks the first that answers),
    /// its own list in Compare.</summary>
    public string ResolverText
    {
        get => IsCompareMode ? CompareServersText : DnsServersText;
        set
        {
            if (IsCompareMode) CompareServersText = value ?? "";
            else DnsServersText = value ?? "";
        }
    }

    public string ResolverHint => ModeIndex switch
    {
        ModeCompare => "Resolvers to compare, one per line: an IP, https://host/dns-query (DoH), tls://host (DoT) or system",
        ModeEmail => "Resolvers, one per line — the check uses the first that answers. Spamhaus refuses big public resolvers: put system first to check it.",
        _ => "Resolvers, one per line: an IP or IP:port (plain DNS), https://host/dns-query (DoH), tls://host or host:853 (DoT), or system",
    };

    // DNS lookups render as record rows (Records); WHOIS renders as freeform text (LogText).
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

    // Compact summary shown on the Record types dropdown button (kept in sync with the checkboxes).
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
        {
            OnPropertyChanged(nameof(SelectedTypesSummary));
            if (_loaded) ProfileService.Instance.SetSetting(TypesKey, string.Join(",", GetSelectedTypes()));
        }
    }

    // The ticked record types, remembered as "A,MX,TXT" (empty: none ticked). Not saved yet: A only.
    private const string TypesKey = "dns.types";

    private void RestoreTypes()
    {
        if (ProfileService.Instance.GetSetting(TypesKey) is not { } saved) return;
        var on = new HashSet<string>(saved.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
                                     StringComparer.OrdinalIgnoreCase);
        TypeA = on.Contains("A");
        TypeAAAA = on.Contains("AAAA");
        TypeMX = on.Contains("MX");
        TypeNS = on.Contains("NS");
        TypeTXT = on.Contains("TXT");
        TypeCNAME = on.Contains("CNAME");
        TypeSOA = on.Contains("SOA");
        TypeSRV = on.Contains("SRV");
        TypeCAA = on.Contains("CAA");
        TypePTR = on.Contains("PTR");
    }

    public DnsViewModel()
    {
        PresetGroups = BuildPresets();
        LoadServers();
        if (HistoryService.Instance.Last("dns.domain") is { } last) DomainName = last;
        WrapResult = ProfileService.Instance.GetBool("dns.wrap", true);
        RestoreTypes();
        string? ct = ProfileService.Instance.GetSetting("dns.compareType");
        if (ct != null && CompareTypes.Contains(ct)) CompareType = ct;
        int mode = ProfileService.Instance.GetInt("dns.mode", ModeLookup);
        ModeIndex = mode is ModeCompare or ModeEmail ? mode : ModeLookup;
        RefreshPresetMarks();
        _loaded = true;
    }

    private void LoadServers()
    {
        DnsServersText = ProfileService.Instance.GetSetting("dns.servers") ?? string.Empty;
        if (string.IsNullOrWhiteSpace(DnsServersText))
        {
            // two plain resolvers and an encrypted one: where plain DNS to foreign servers is filtered, the DoH line still
            // answers (and the email check falls back to it by itself)
            DnsServersText = string.Join(Environment.NewLine, "1.1.1.1", "8.8.8.8", "https://cloudflare-dns.com/dns-query");
            SaveServers();
        }
        string? cmp = ProfileService.Instance.GetSetting("dns.compare");
        CompareServersText = string.IsNullOrWhiteSpace(cmp) ? ResolverPresets.DefaultCompareList() : cmp;
    }

    private void SaveServers()
        => ProfileService.Instance.SetSetting("dns.servers", DnsServersText);

    // Persist resolver edits as they happen: saved only by a lookup, an edit followed by WHOIS (or nothing) and
    // closing the app was lost. Cheap — the profile coalesces writes in the background.
    partial void OnDnsServersTextChanged(string value)
    {
        if (!IsCompareMode) { OnPropertyChanged(nameof(ResolverText)); RefreshPresetMarks(); }
        if (_loaded) SaveServers();
    }

    // Cancels an in-flight lookup / comparison / check / WHOIS.
    private CancellationTokenSource? _cts;

    private CancellationToken NewRun()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        return _cts.Token;
    }

    // The resolver decides how many answers come back: a hostile or broken one (any IP can be listed as a resolver)
    // sent 4,000 A records in one TCP answer, and every answer is a row in the results list, which isn't virtualized.
    // Real answers are a handful; past this many per server and type, the rest are counted in one status line.
    private const int MaxAnswersPerQuery = 100;
    // Lookup asks every listed resolver for every type at once: a pasted list of hundreds is cut here.
    private const int MaxLookupResolvers = 20;

    // RDAP answers are a few KB. rdap.org redirects to whichever registry serves the name, so the body is a third
    // party's: it was buffered whole (100 MB in 1.4 s on loopback took ~350 MB of memory) and then parsed on the UI thread.
    private const int MaxRdapBytes = 2 * 1024 * 1024;
    private static readonly TimeSpan RdapTimeout = TimeSpan.FromSeconds(10);

    [RelayCommand]
    private void Stop() => _cts?.Cancel();

    /// <summary>Enter in the domain box / the primary button: the current mode's action.</summary>
    [RelayCommand]
    private Task RunPrimary() => ModeIndex switch
    {
        ModeCompare => RunCompare(),
        ModeEmail => RunEmail(),
        _ => RunLookup(),
    };

    [RelayCommand]
    private async Task RunLookup()
    {
        // Accept a pasted URL / "host:port" and reduce it to the bare domain/IP.
        DomainName = HostExtractor.Extract(DomainName);
        if (string.IsNullOrWhiteSpace(DomainName) || IsWorking) return;

        var token = NewRun();
        HistoryService.Instance.Add("dns.domain", DomainName);
        SaveServers();
        IsWorking = true;
        LogText = string.Empty;
        ShowRecords = true;
        Records.Clear();
        _rowBudget = MaxLookupRows;
        _charBudget = MaxShownChars;

        // Resolvers: IP / ip:port (plain), https://… (DoH), tls://… or host:853 (DoT), "system"; anything else is listed
        // as skipped instead of silently vanishing, so an all-invalid list doesn't just leave a blank pane.
        var skipped = new List<(string line, string reason)>();
        var specs = ResolverSpec.ParseList(DnsServersText, skipped);
        foreach (var (line, reason) in skipped)
            AddRow(new DnsRecordRow { Type = "SKIP", Value = reason, Server = line, IsStatus = true });
        if (specs.Count > MaxLookupResolvers)
        {
            AddRow(new DnsRecordRow { Type = "SKIP", IsStatus = true, Value = $"only the first {MaxLookupResolvers} resolvers are asked ({specs.Count - MaxLookupResolvers} more in the list)" });
            specs = specs.Take(MaxLookupResolvers).ToList();
        }

        var selectedTypes = GetSelectedTypes();
        if (selectedTypes.Count == 0 || specs.Count == 0)
        {
            AddRow(new DnsRecordRow
            {
                Type = "ERR", IsStatus = true,
                Value = specs.Count == 0 ? "No valid resolver — add one per line, e.g. 1.1.1.1 or https://cloudflare-dns.com/dns-query" : "No record type selected — pick one under Record types",
            });
            IsWorking = false;
            return;
        }

        string host = DomainName.Trim();
        string asciiHost = SecureDns.ToAscii(host);   // punycode for internationalized (non-ASCII) domains
        IPAddress? revIp = IPAddress.TryParse(host, out var parsedIp) ? parsedIp : null;

        var tasks = specs.Select(spec => Task.Run(async () =>
        {
            // One session per resolver for every record type: the DoT connection / DoH pool / DnsClient instance is reused.
            using var session = new DnsSession(spec);
            foreach (var type in selectedTypes)
            {
                if (token.IsCancellationRequested) return;
                // PTR on an IP → the reverse name; everything else is a forward query.
                string qname = type == QueryType.PTR && revIp != null ? DnsWire.ArpaName(revIp) : asciiHost;
                DnsResult r;
                try { r = await session.QueryAsync(qname, type, token).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }   // user hit Stop — leave what we have
                if (token.IsCancellationRequested) return;

                string meta = $"{r.Via} · {DnsCompare.Ms(r.RttMs)}";
                string server = spec.Transport == DnsTransport.System ? "" : spec.Short;   // "system (192.168.1.1)" is in the meta already
                if (r.Answers.Count > 0)
                {
                    // Label each answer with its OWN type: an A/AAAA query behind an alias also returns
                    // the CNAME chain, which must not show (or copy) as an "A" record.
                    int shown = 0;
                    foreach (var a in r.Answers)
                    {
                        if (shown++ == MaxAnswersPerQuery) break;
                        AddRow(new DnsRecordRow { Type = a.Type, Value = a.Value, Server = server, Meta = meta, ServerTip = spec.Text });
                    }
                    if (r.AnswerCount > MaxAnswersPerQuery)
                        AddRow(new DnsRecordRow { Type = type.ToString(), Server = server, Meta = meta, ServerTip = spec.Text, IsStatus = true,
                                                  Value = $"{r.AnswerCount - MaxAnswersPerQuery:N0} more answers not shown" });
                }
                else
                {
                    // An error reply (NXDOMAIN / SERVFAIL / REFUSED) also has no answers, but it isn't "no records":
                    // a SERVFAIL (e.g. broken DNSSEC) or a resolver that refuses recursion must not read as such.
                    AddRow(new DnsRecordRow { Type = type.ToString(), Value = r.StatusText, Server = server, Meta = meta, ServerTip = spec.Text, IsStatus = true });
                }
            }
        }, token));

        try { await Task.WhenAll(tasks); }
        catch (OperationCanceledException) { }
        IsWorking = false;
    }

    [RelayCommand]
    private async Task RunWhois()
    {
        DomainName = HostExtractor.Extract(DomainName);
        if (string.IsNullOrWhiteSpace(DomainName) || IsWorking) return;

        var token = NewRun();
        HistoryService.Instance.Add("dns.domain", DomainName);
        IsWorking = true;
        ShowRecords = false;   // WHOIS/RDAP is freeform text
        string query = DomainName.Trim();
        LogText = $"# whois {query}" + Environment.NewLine;

        // rdap.org is the IANA bootstrap — it follows to the authoritative RDAP server for any
        // TLD/registry, and also covers IPs and ASNs. Pick the right object type from the input.
        // ASN test first: IPAddress.TryParse takes a bare number ("13335") as legacy IPv4 (0.0.52.23).
        string kind =
            System.Text.RegularExpressions.Regex.IsMatch(query, @"^(AS)?\d+$", System.Text.RegularExpressions.RegexOptions.IgnoreCase) ? "autnum" :
            System.Net.IPAddress.TryParse(query, out _) ? "ip" : "domain";
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
                    // Up to 2 MB of JSON flattens into a lot of lines: parse and flatten off the UI thread.
                    string text = await Task.Run(() =>
                    {
                        using var doc = JsonDocument.Parse(body);
                        var sb = new StringBuilder();
                        ParseElement(doc.RootElement, sb);
                        return TextLimit.Cap(sb.ToString());
                    }, token);
                    LogText = text;
                    IsWorking = false;
                    return;
                }
                lastError = $"HTTP {status}";
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { LogText = "cancelled."; IsWorking = false; return; }
            // HttpClient.Timeout also surfaces as a cancellation: a slow / filtered rdap.org is a failed provider
            // (try the next one), not a Stop — it used to end the whole WHOIS with "cancelled.".
            catch (OperationCanceledException) { lastError = "timed out"; }
            catch (Exception ex) { lastError = ex.Message; }
        }
        LogText = "No RDAP data — " + (lastError ?? "request failed / timed out") + ".";
        IsWorking = false;
    }

    private static async Task<(string body, int status)> FetchRdap(string url, CancellationToken token)
    {
        using var client = HttpHelper.Create(timeout: RdapTimeout);
        client.DefaultRequestHeaders.Accept.ParseAdd("application/rdap+json");
        client.DefaultRequestHeaders.Accept.ParseAdd("application/json");

        // Headers first, then the body read with a ceiling (decompressed bytes, so a gzip bomb stops there too). The
        // client's Timeout ends with the headers, so the body gets the same deadline; it surfaces as "timed out".
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(RdapTimeout);
        using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
        await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token);
        using var ms = new MemoryStream();
        byte[] buf = new byte[16 * 1024];
        int n;
        while ((n = await stream.ReadAsync(buf, deadline.Token)) > 0)
        {
            if (ms.Length + n > MaxRdapBytes) throw new InvalidDataException($"the answer is larger than {MaxRdapBytes / (1024 * 1024)} MB");
            ms.Write(buf, 0, n);
        }
        // RDAP is JSON, so UTF-8 (RFC 8259); a BOM is skipped as ReadAsStringAsync did.
        int skip = ms.Length >= 3 && ms.GetBuffer()[0] == 0xEF && ms.GetBuffer()[1] == 0xBB && ms.GetBuffer()[2] == 0xBF ? 3 : 0;
        return (Encoding.UTF8.GetString(ms.GetBuffer(), skip, (int)ms.Length - skip), (int)response.StatusCode);
    }

    private static void ParseElement(JsonElement element, StringBuilder sb)
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

    // Copy the whole result set of the current mode: record rows / WHOIS text, the comparison, the email report.
    [RelayCommand]
    private async Task CopyResult()
    {
        string text = ModeIndex switch
        {
            ModeCompare => CompareReport(),
            ModeEmail => MailReport(),
            _ => ShowRecords
                ? string.Join(Environment.NewLine, Records.Where(r => r.IsRecord).Select(r => $"{r.Type}\t{r.CopyValue}\t{r.Server}\t{r.Meta}"))
                : LogText,
        };
        if (string.IsNullOrWhiteSpace(text)) return;
        await ClipboardHelper.SetTextAsync(text);
    }

    // Copy a single record's value (the copy button on each row).
    [RelayCommand]
    private async Task CopyRow(DnsRecordRow? row)
    {
        if (row is null || string.IsNullOrEmpty(row.CopyValue)) return;
        await ClipboardHelper.SetTextAsync(row.CopyValue);
    }

    // The results list isn't virtualized: 20 resolvers × 10 types × 100 answers would be 20,000 rows. Past this many in one
    // lookup, one status line says so and the rest is dropped.
    private const int MaxLookupRows = 600;
    private int _rowBudget = MaxLookupRows;
    // Characters shown over one lookup's rows (each row shows at most DnsRecordRow.MaxShown): laying out long values
    // costs more than linear time, so past this budget a long value shows only its start (Copy still has it all).
    private const int MaxShownChars = 32 * 1024, ShownPastBudget = 160;
    private int _charBudget = MaxShownChars;

    private void AddRow(DnsRecordRow row)
    {
        int left = Interlocked.Decrement(ref _rowBudget);
        if (left < -1) return;
        if (left == -1)
            row = new DnsRecordRow { Type = "MORE", IsStatus = true, Value = $"more than {MaxLookupRows} rows — the rest isn't shown (ask fewer resolvers or types)" };
        else if (row.Value.Length > ShownPastBudget && Interlocked.Add(ref _charBudget, -row.Value.Length) < 0)
            row.ShowAtMost(ShownPastBudget);
        Dispatcher.UIThread.Post(() => Records.Add(row));
    }

    // ---------------------------------------------------------------- presets

    /// <summary>The presets menu: each provider with its plain / DoH / DoT forms as toggles.</summary>
    public IReadOnlyList<PresetGroup> PresetGroups { get; }

    private List<PresetGroup> BuildPresets()
    {
        var groups = new List<PresetGroup>
        {
            new("System", "this device", new[] { new PresetChip("system", "system", "The resolver this device is set to use (usually the router's or the ISP's)", TogglePreset) }),
        };
        foreach (var p in ResolverPresets.Providers)
        {
            var chips = new List<PresetChip>();
            int plain = p.Note == "Iran" ? 2 : 1;
            foreach (string a in p.Addresses.Take(plain)) chips.Add(new PresetChip(a, a, $"Plain DNS (UDP) to {a}", TogglePreset));
            if (p.Doh != null) chips.Add(new PresetChip("DoH", p.Doh, "DNS-over-HTTPS: " + p.Doh, TogglePreset));
            if (p.Dot != null) chips.Add(new PresetChip("DoT", p.Dot, "DNS-over-TLS: " + p.Dot, TogglePreset));
            groups.Add(new PresetGroup(p.Name, p.Note, chips));
        }
        return groups;
    }

    /// <summary>Adds the preset's line to the resolver list, or takes it out when it is already there.</summary>
    [RelayCommand]
    private void TogglePreset(PresetChip? chip)
    {
        if (chip is null || IsWorking) return;
        var lines = SplitLines(ResolverText);
        int before = lines.Count;
        lines.RemoveAll(l => string.Equals(Canonical(l), chip.Canonical, StringComparison.OrdinalIgnoreCase));
        if (lines.Count == before) lines.Add(chip.Line);
        ResolverText = string.Join(Environment.NewLine, lines);
    }

    /// <summary>Every preset, in each form it offers.</summary>
    [RelayCommand]
    private void UseAllPresets()
    {
        if (IsWorking) return;
        ResolverText = ResolverPresets.DefaultCompareList();
    }

    [RelayCommand]
    private void ClearResolvers()
    {
        if (IsWorking) return;
        ResolverText = "";
    }

    private void RefreshPresetMarks()
    {
        if (PresetGroups is null) return;
        var present = new HashSet<string>(SplitLines(ResolverText).Select(Canonical), StringComparer.OrdinalIgnoreCase);
        foreach (var g in PresetGroups)
            foreach (var c in g.Chips) c.IsOn = present.Contains(c.Canonical);
    }

    private static List<string> SplitLines(string? text)
        => (text ?? "").Split(new[] { '\n', '\r', ',' }, StringSplitOptions.RemoveEmptyEntries)
                       .Select(l => l.Trim()).Where(l => l.Length > 0).ToList();

    private static string Canonical(string line) => ResolverSpec.TryParse(line, out var s, out _) ? s.Text : line;
}
