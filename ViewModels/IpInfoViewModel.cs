using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>A geolocation/network record normalised from any provider. Built once per lookup and bound
/// straight to the card layout — every empty field auto-hides in the view.</summary>
public sealed class IpGeoResult
{
    public string Ip { get; set; } = "";
    public string Version { get; set; } = "";        // "IPv4" / "IPv6"
    public string Flag { get; set; } = "";           // emoji, derived from the country code
    public string Country { get; set; } = "";
    public string CountryCode { get; set; } = "";
    public string Region { get; set; } = "";
    public string City { get; set; } = "";
    public string Postal { get; set; } = "";
    public string Latitude { get; set; } = "";
    public string Longitude { get; set; } = "";
    public string Timezone { get; set; } = "";
    public string UtcOffset { get; set; } = "";
    public string Isp { get; set; } = "";
    public string Org { get; set; } = "";
    public string Asn { get; set; } = "";
    public string Hostname { get; set; } = "";
    public bool IsProxy { get; set; }
    public bool IsHosting { get; set; }
    public bool IsMobile { get; set; }
    public string Sources { get; set; } = "";

    // --- view helpers ---
    public string HeroLocation => string.Join(", ", new[] { City, Region, Country }.Where(s => s.Length > 0));
    public bool HasVersion => Version.Length > 0;
    public bool HasFlag => CountryCode.Trim().Length == 2;
    public string Coordinates => (Latitude.Length > 0 && Longitude.Length > 0) ? $"{Latitude}, {Longitude}" : "";
    // The coordinates are provider text — one source is plain HTTP that anything on the path (the proxy under test
    // included) can rewrite — and they went into the browser URL verbatim ("1\"><x>&layers=…" and all). The map link
    // is now built only from two real coordinates, written back as plain numbers.
    public bool HasCoordinates => TryCoordinate(Latitude, 90, out _) && TryCoordinate(Longitude, 180, out _);
    public string MapUrl => TryCoordinate(Latitude, 90, out string lat) && TryCoordinate(Longitude, 180, out string lon)
        ? $"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=11/{lat}/{lon}"
        : "";

    private static bool TryCoordinate(string text, double limit, out string number)
    {
        number = string.Empty;
        if (!double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out double v) || !double.IsFinite(v) || Math.Abs(v) > limit)
            return false;
        number = v.ToString("0.######", CultureInfo.InvariantCulture);
        return true;
    }
    public string SecurityText => string.Join("   ", new[]
    {
        IsProxy ? "⚠ Proxy / VPN / Tor" : null,
        IsHosting ? "🖥 Hosting / Datacenter" : null,
        IsMobile ? "📶 Mobile network" : null,
    }.Where(s => s != null));
    public bool HasSecurity => IsProxy || IsHosting || IsMobile;
    public bool CleanIp => !HasSecurity;
}

/// <summary>One provider's own answer, shown in the per-provider breakdown so the user can see
/// exactly which source returned what (and where they agree/differ).</summary>
public sealed class IpProviderResult
{
    public required string Name { get; init; }
    public required IpGeoResult Data { get; init; }
}

public partial class IpInfoViewModel : ObservableObject
{
    [ObservableProperty] private string _targetIp = string.Empty;
    [ObservableProperty] private string _rawResult = string.Empty;          // copy text + fallback/error text
    [ObservableProperty] private IpGeoResult? _result;                      // merged answer → hero
    [ObservableProperty] private string _statusLine = string.Empty;         // "Cross-checked via …"
    [ObservableProperty] private bool _isWorking;

    // Each responding provider's own answer (for the per-provider comparison list).
    public ObservableCollection<IpProviderResult> ProviderResults { get; } = new();

    [ObservableProperty] private bool _useProxy;
    [ObservableProperty] private string _proxyAddress = string.Empty;
    [ObservableProperty] private string _proxyUser = string.Empty;
    [ObservableProperty] private string _proxyPass = string.Empty;

    // Which provider to query. Index 0 = Auto (all sources, merged/cross-checked); otherwise a single one. The index is
    // what's saved, so new providers go at the end of the table.
    public ObservableCollection<string> Providers { get; } = new(new[] { "Auto (cross-check)" }.Concat(Table.Select(p => p.Name)));
    [ObservableProperty] private int _selectedProviderIndex;

    public ObservableCollection<string> TargetHistory => HistoryService.Instance.Get("ip.target");
    public ObservableCollection<string> ProxyHistory => HistoryService.Instance.Get("ip.proxy");

    [ObservableProperty] private string _subnetInput = "192.168.1.0/24";
    [ObservableProperty] private string _subnetOutput = string.Empty;

    /// <summary>0 Lookup · 1 Subnet / CIDR (remembered).</summary>
    [ObservableProperty] private int _tabIndex;

    private const string KMyIpLast = "ip.myIpLast", KSubnet = "ip.subnet", KTab = "ip.tab";

    partial void OnTabIndexChanged(int value)
    {
        if (_loaded && value >= 0) ProfileService.Instance.SetSetting(KTab, value.ToString(CultureInfo.InvariantCulture));
    }

    // Whether the box comes back empty (the last lookup was this device's own address) or with the last address.
    private static void SaveMyIpLast(bool mine)
    {
        if (ProfileService.Instance.GetBool(KMyIpLast) != mine) ProfileService.Instance.SetBool(KMyIpLast, mine);
    }

    private bool _loaded;
    private static readonly HashSet<string> PersistProps = new()
    { "UseProxy", "ProxyAddress", "ProxyUser", "ProxyPass", "SelectedProviderIndex" };

    // The saved proxy password when it can't be decrypted here (no key file, a profile from another machine): Unprotect
    // gives "" for it, which looked like "no password", and the next save of ANY proxy setting wrote "" over the stored
    // secret. It's written back exactly as stored until the user types a password of their own.
    private string? _unreadablePass;

    public IpInfoViewModel()
    {
        var ps = ProfileService.Instance;
        UseProxy = ps.GetBool("ip.useProxy");
        ProxyAddress = ps.GetSetting("ip.proxyAddr") ?? (HistoryService.Instance.Last("ip.proxy") ?? string.Empty);
        ProxyUser = ps.GetSetting("ip.proxyUser") ?? string.Empty;
        // Stored encrypted via SecretProtector (per-user key); legacy plaintext and old-format values still
        // load and are re-saved in the current format right away.
        string rawPass = ps.GetSetting("ip.proxyPass") ?? string.Empty;
        ProxyPass = SecretProtector.Unprotect(rawPass);
        if (rawPass.Length > 0 && ProxyPass.Length == 0) _unreadablePass = rawPass;
        if (int.TryParse(ps.GetSetting("ip.provider"), out int pi) && pi >= 0 && pi < Providers.Count) SelectedProviderIndex = pi;
        // The address looked up last (none when "My IP" was the last lookup), the subnet box and the sub-tab.
        if (!ps.GetBool(KMyIpLast) && HistoryService.Instance.Last("ip.target") is { } lastTarget) TargetIp = lastTarget;
        if (ps.GetSetting(KSubnet) is { Length: > 0 } subnet) SubnetInput = subnet;
        TabIndex = Math.Clamp(ps.GetInt(KTab, 0), 0, 1);
        _loaded = true;
        // Re-save under the current key: legacy plaintext, or an old "enc1:" value that still decrypts (one that
        // doesn't is left untouched rather than overwritten with an empty password).
        if (rawPass.Length > 0 && (ProxyPass == rawPass || (SecretProtector.IsLegacy(rawPass) && ProxyPass.Length > 0))) SchedulePersist();
        // An address saved with credentials in it (before they were moved out): into the fields, and the profile is
        // rewritten without them.
        MoveProxyCredentials(whileTyping: false);
    }

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (_loaded && e.PropertyName == nameof(ProxyPass)) _unreadablePass = null;   // the user's own password now
        if (_loaded && e.PropertyName is { } n && PersistProps.Contains(n)) SchedulePersist();
    }

    // ---- credentials typed into the proxy address ----

    // "user:pass@host:port" in any scheme ("socks5://user:p%40ss@host:1080"): the address without the user info, and the
    // user / password from it. Null when the address has no user info. The LAST '@' of the authority ends it, so a
    // password holding an '@' moves whole; with a scheme it's URL syntax, so percent escapes are decoded.
    private readonly record struct ProxyUserInfo(string Clean, string User, string Pass, bool HasHost, bool HasPort);

    private static ProxyUserInfo? ParseProxyUserInfo(string? address)
    {
        string a = (address ?? string.Empty).Trim();
        int scheme = a.IndexOf("://", StringComparison.Ordinal);
        int start = scheme >= 0 ? scheme + 3 : 0;
        int end = a.IndexOfAny(new[] { '/', '?', '#' }, start);
        if (end < 0) end = a.Length;
        int at = end > start ? a.LastIndexOf('@', end - 1, end - start) : -1;
        if (at < 0) return null;
        string info = a[start..at], hostPort = a[(at + 1)..end];
        int colon = info.IndexOf(':');
        string user = colon >= 0 ? info[..colon] : info, pass = colon >= 0 ? info[(colon + 1)..] : string.Empty;
        if (scheme >= 0)
        {
            user = Uri.UnescapeDataString(user);
            pass = Uri.UnescapeDataString(pass);
        }
        int portColon = hostPort.LastIndexOf(':');
        bool hasPort = portColon >= 0 && portColon < hostPort.Length - 1 && hostPort[(portColon + 1)..].All(char.IsAsciiDigit);
        return new ProxyUserInfo(a[..start] + a[(at + 1)..], user, pass, hostPort.Length > 0, hasPort);
    }

    /// <summary>
    /// The proxy address is a plaintext profile setting (and .NET never authenticates with credentials written into a
    /// proxy address — only the User / Password fields do), so pasted "user:pass@host:port" credentials move into those
    /// fields (the password is stored encrypted) and the box keeps only the address.
    /// </summary>
    /// <param name="whileTyping">From the debounced save: only an address that already ends in its port is split, so a
    /// pause mid-typing doesn't cut "user:p@ss…" at the wrong '@'. (The save itself never writes the user info.)</param>
    private void MoveProxyCredentials(bool whileTyping)
    {
        if (ParseProxyUserInfo(ProxyAddress) is not { HasHost: true } info || (whileTyping && !info.HasPort)) return;
        ProxyAddress = info.Clean;
        if (info.User.Length > 0) ProxyUser = info.User;
        if (info.Pass.Length > 0) ProxyPass = info.Pass;
    }

    // Debounced: the proxy boxes update on every keystroke, and each save re-serializes + rewrites the whole
    // profile file on the UI thread. Write once typing pauses; a lookup and app exit/background flush it.
    private System.Threading.CancellationTokenSource? _persistCts;
    private bool _persistPending;   // UI thread only

    private void SchedulePersist()
    {
        _persistPending = true;
        _persistCts?.Cancel();
        _persistCts?.Dispose();
        var cts = _persistCts = new System.Threading.CancellationTokenSource();
        _ = Task.Delay(500, cts.Token).ContinueWith(t =>
        {
            // Values are read back on the UI thread at write time, so the latest edit always wins.
            if (!t.IsCanceled) Avalonia.Threading.Dispatcher.UIThread.Post(FlushPendingSave);
        }, TaskScheduler.Default);
    }

    /// <summary>Persist a pending (debounced) settings change now. No-op when nothing is pending. UI thread only.</summary>
    public void FlushPendingSave()
    {
        _persistCts?.Cancel();
        if (!_persistPending) return;
        MoveProxyCredentials(whileTyping: true);   // its property changes re-arm the debounce: cancelled again here
        _persistCts?.Cancel();
        _persistPending = false;
        // The address goes into the plaintext profile: never with user info in it, even half-typed.
        string address = ParseProxyUserInfo(ProxyAddress)?.Clean ?? ProxyAddress;
        ProfileService.Instance.SetMany(
            ("ip.useProxy", UseProxy ? "true" : "false"), ("ip.proxyAddr", address),
            ("ip.proxyUser", ProxyUser), ("ip.proxyPass", _unreadablePass ?? SecretProtector.Protect(ProxyPass)),
            ("ip.provider", SelectedProviderIndex.ToString()));
    }

    [RelayCommand]
    private void RunSubnet()
    {
        try
        {
            if (string.IsNullOrWhiteSpace(SubnetInput)) return;
            if (SubnetInput.Length <= 256) ProfileService.Instance.SetSetting(KSubnet, SubnetInput.Trim());
            SubnetOutput = SubnetCalc.Describe(SubnetInput);
        }
        catch (Exception ex) { SubnetOutput = "Error: " + ex.Message; }
    }

    // Copies just the IP address: what you paste into another tool. The full details stay on screen, selectable.
    [RelayCommand]
    private async Task CopyResult()
    {
        string? ip = Result?.Ip?.Trim();
        if (!string.IsNullOrEmpty(ip)) await ClipboardHelper.SetTextAsync(ip);
    }

    [RelayCommand]
    private async Task CopySubnet() => await ClipboardHelper.SetTextAsync(SubnetOutput);

    [RelayCommand]
    private void OpenMap() => Helpers.LinkHelper.Open(Result?.MapUrl);

    // Both entry points bail while a fetch runs: the buttons are disabled then, but Enter in the target
    // box goes through LookupIpCommand, which is free while GetMyIpCommand runs — two overlapping fetches
    // would interleave their provider rows and race on Result / IsWorking.
    [RelayCommand]
    private async Task GetMyIp()
    {
        if (IsWorking) return;
        TargetIp = string.Empty;
        SaveMyIpLast(true);
        await FetchIpInfo(string.Empty);
    }

    [RelayCommand]
    private async Task LookupIp()
    {
        if (IsWorking) return;
        HistoryService.Instance.Add("ip.target", TargetIp);
        SaveMyIpLast(string.IsNullOrWhiteSpace(TargetIp));
        await FetchIpInfo(TargetIp);
    }

    // An address handed over while a fetch runs (the entry points bail then): looked up as soon as that one ends.
    private bool _lookUpPending;

    /// <summary>Looks <paramref name="ip"/> up as if it were typed and run: what another tool hands over (an address in
    /// the DNS results). A fetch already running finishes first.</summary>
    public void LookUp(string ip)
    {
        TabIndex = 0;   // the Lookup tab, not Subnet / CIDR
        TargetIp = ip;
        if (IsWorking) { _lookUpPending = true; return; }
        LookupIpCommand.Execute(null);
    }

    partial void OnIsWorkingChanged(bool value)
    {
        if (value || !_lookUpPending) return;
        _lookUpPending = false;
        // posted: the fetch that just ended is still unwinding its command
        Avalonia.Threading.Dispatcher.UIThread.Post(() => LookupIpCommand.Execute(null));
    }

    // ---- multi-source fetch + merge ----

    private sealed record IpSource(int Priority, string Name, string Url, Func<JsonElement, IpGeoResult?> Parse);

    /// <summary>A provider: its own-IP URL (null: it has none) and its lookup URL ("{ip}": the address or name).</summary>
    private sealed record IpProvider(string Name, string? SelfUrl, string LookupUrl, Func<JsonElement, IpGeoResult?> Parse);

    // The picker's order (its index is saved: new providers go at the end) and the merge's: the first that supplies a
    // field wins. Keyless free endpoints only.
    private static readonly IpProvider[] Table =
    {
        new("ip-api.com", "http://ip-api.com/json/?fields=66846719", "http://ip-api.com/json/{ip}?fields=66846719", ParseIpApi),
        new("ipwho.is", "https://ipwho.is/", "https://ipwho.is/{ip}", ParseIpWho),
        new("ipapi.co", "https://ipapi.co/json/", "https://ipapi.co/{ip}/json/", ParseIpApiCo),
        new("ipinfo.io", "https://ipinfo.io/json", "https://ipinfo.io/{ip}/json", ParseIpInfo),
        // freeipapi.com/api/json redirects here now
        new("freeipapi", "https://free.freeipapi.com/api/v1/json", "https://free.freeipapi.com/api/v1/json/{ip}", ParseFreeIpApi),
        new("geojs", "https://get.geojs.io/v1/ip/geo.json", "https://get.geojs.io/v1/ip/geo/{ip}.json", ParseGeoJs),
        new("iplocation.net", null, "https://api.iplocation.net/?ip={ip}", ParseIpLocationNet),
        new("ipwhois.app", "https://ipwhois.app/json/", "https://ipwhois.app/json/{ip}", ParseIpWhoisApp),
        new("iplocate.io", "https://iplocate.io/api/lookup/", "https://iplocate.io/api/lookup/{ip}", ParseIpLocate),
        new("ipquery.io", "https://api.ipquery.io/?format=json", "https://api.ipquery.io/{ip}?format=json", ParseIpQuery),
        new("ip2location.io", "https://api.ip2location.io/", "https://api.ip2location.io/?ip={ip}", ParseIp2Location),
        new("geoiplookup.io", "https://json.geoiplookup.io/", "https://json.geoiplookup.io/{ip}", ParseGeoIpLookup),
        new("ifconfig.co", "https://ifconfig.co/json", "https://ifconfig.co/json?ip={ip}", ParseIfconfigCo),
        new("ipleak.net", "https://ipleak.net/json/", "https://ipleak.net/json/{ip}", ParseIpLeak),
        new("ip.sb", "https://api.ip.sb/geoip", "https://api.ip.sb/geoip/{ip}", ParseIpSb),
        new("ip.guide", "https://ip.guide/", "https://ip.guide/{ip}", ParseIpGuide),
        new("db-ip.com", "https://api.db-ip.com/v2/free/self", "https://api.db-ip.com/v2/free/{ip}", ParseDbIp),
        new("geolocation-db", "https://geolocation-db.com/json/", "https://geolocation-db.com/json/{ip}", ParseGeolocationDb),
        new("country.is", "https://api.country.is/", "https://api.country.is/{ip}", ParseCountryIs),
    };

    // Auto asks the providers in three lanes (every third one), each a Fallback chain: its first provider at once, the
    // next a head start later or as soon as one fails, two at most at a time. A dead or blocked provider costs a head
    // start, not a timeout, and no more than six requests are out at once. The first answer from any lane gives the other
    // two a short grace to answer too, for the cross-check.
    private const int Lanes = 3;
    private static readonly TimeSpan Grace = TimeSpan.FromSeconds(2.5);
    private static readonly TimeSpan PerProvider = TimeSpan.FromSeconds(8);
    private const int MaxFieldChars = 120;

    /// <summary>Test hook (the harness): answers every provider request (URL → body, or an exception) instead of the
    /// network. Internal on purpose.</summary>
    internal static Func<string, CancellationToken, Task<string>>? TestGet { get; set; }

    private async Task FetchIpInfo(string ip)
    {
        MoveProxyCredentials(whileTyping: false);   // typing is done: credentials in the address go to the fields this lookup uses
        FlushPendingSave();   // the proxy settings this lookup uses are saved even if the app closes mid-run
        IsWorking = true;
        Result = null;
        ProviderResults.Clear();
        RawResult = "Querying sources…";
        StatusLine = string.Empty;

        // try/finally so no exception (e.g. a malformed proxy address, which HttpHelper.Create rejects)
        // escapes the command — that would crash the app — or leaves IsWorking stuck on.
        try
        {
            string target = ip.Trim();
            IPAddress? asked = IPAddress.TryParse(target, out var literal) ? Canonical(literal) : null;
            // A private or otherwise special address has no location anywhere: nothing to ask.
            if (asked != null && Rdap.SpecialPurpose(asked) is { } note)
            {
                RawResult = $"{note}. There is no location to look up for {asked}.";
                return;
            }

            string? proxy = UseProxy && !string.IsNullOrWhiteSpace(ProxyAddress) ? ProxyAddress : null;
            // Without a proxy the providers' names resolve around a resolver that blocks them (ServiceDns).
            using var client = HttpHelper.Create(proxy, ProxyUser, ProxyPass, timeout: TimeSpan.FromSeconds(10), serviceDns: true);
            // Every provider answers with a few hundred bytes of JSON; don't let a hostile proxy stream more.
            client.MaxResponseContentBufferSize = 256 * 1024;
            if (proxy != null) HistoryService.Instance.Add("ip.proxy", proxy);   // only once it parsed
            // Every request goes to the proxy: when it can't be reached, no provider can, so that is said at once
            // instead of after every provider failed in turn.
            if (proxy != null && await ProxyUnreachableAsync(proxy) is { } why)
            {
                RawResult = why;
                return;
            }

            bool self = target.Length == 0;
            var sources = BuildSources(self, target, asked);

            // Restrict to one provider when the user picked a specific one (index 0 = Auto = all sources).
            if (SelectedProviderIndex > 0)
            {
                string want = ProviderKey(SelectedProviderIndex);
                var only = sources.FirstOrDefault(s => s.Name == want);
                if (only is null)
                {
                    Result = null;
                    RawResult = $"{want} doesn't support {(self ? "My IP" : "this query")} — pick another provider or Auto.";
                    return;
                }
                sources = new List<IpSource> { only };
            }

            var (hits, errors) = await AskAllAsync(client, sources, asked, self);
            if (hits.Count == 0)
            {
                Result = null;
                // one clear line, then every provider's reason, a line per reason
                RawResult = (sources.Count == 1 ? $"{sources[0].Name} didn't answer." : "No source answered.")
                            + (proxy != null ? " Check the address, your connection or the proxy." : " Check the address or your connection.")
                            + (errors.Count > 0 ? "\n" + Reasons(errors) : string.Empty);
                StatusLine = string.Empty;
                return;
            }

            // HTTPS answers win the merge. A plain-HTTP source (ip-api.com's free tier) can be rewritten
            // by anyone on the path — including the proxy under test — so it only fills the fields no
            // HTTPS source supplied. It stays in the batch: it's the only proxy/hosting/mobile source.
            var plain = sources.Where(s => s.Url.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                               .Select(s => s.Name).ToHashSet();
            var ordered = hits.OrderBy(h => plain.Contains(h.name) ? 1 : 0).ThenBy(h => h.prio).ToList();
            // My IP or a host name: the answers can be for different addresses (an IPv4-only provider beside dual-stack
            // ones, a name with several addresses). The address most of them report is the result; the others are listed
            // with their address, not merged.
            string main = ordered.Where(h => h.res.Ip.Length > 0).GroupBy(h => h.res.Ip)
                                 .OrderByDescending(g => g.Count()).Select(g => g.Key).FirstOrDefault() ?? string.Empty;
            var same = ordered.Where(h => h.res.Ip.Length == 0 || h.res.Ip == main).ToList();
            var merged = Merge(same);
            Result = merged;
            foreach (var (_, name, res) in ordered)
            {
                string label = plain.Contains(name) ? name + "  (plain HTTP)" : name;
                ProviderResults.Add(new IpProviderResult { Name = res.Ip.Length > 0 && res.Ip != main ? label + " · " + res.Ip : label, Data = res });
            }
            RawResult = BuildCopyText(merged);
            StatusLine = (same.Count > 1 ? $"Cross-checked via {merged.Sources}" : $"Source: {merged.Sources}")
                         + (same.Count < ordered.Count
                             ? $"; {string.Join(", ", ordered.Where(h => !same.Contains(h)).Select(h => h.name))} answered for another address"
                             : string.Empty);
        }
        catch (Exception ex)
        {
            Result = null;
            ProviderResults.Clear();
            RawResult = "Error: " + ex.Message;
            StatusLine = string.Empty;
        }
        finally
        {
            IsWorking = false;
        }
    }

    // Auto: the lanes described above; one picked provider: just it. The answers (with their priority) and every failed
    // provider's reason ("name: reason").
    private static async Task<(List<(int prio, string name, IpGeoResult res)> Hits, List<string> Errors)> AskAllAsync(
        HttpClient client, List<IpSource> sources, IPAddress? asked, bool self)
    {
        var lanes = Enumerable.Range(0, Math.Min(Lanes, sources.Count))
                              .Select(l => sources.Where((_, i) => i % Lanes == l).ToList()).ToList();
        using var stop = new CancellationTokenSource();
        var tasks = lanes.Select((lane, l) => Fallback.FirstAsync(
                sources.Count == 1 ? "ipinfo.one" : $"ipinfo.{(self ? "self" : "lookup")}.{l}",
                lane.Select(s => new Fallback.Source<IpGeoResult>(s.Name, t => AskAsync(client, s, asked, t))).ToList(),
                stop.Token, perSource: PerProvider, maxConcurrent: 2))
            .ToList();

        var pending = new List<Task<Fallback.Result<IpGeoResult>>>(tasks);
        while (pending.Count > 0)
        {
            var done = await Task.WhenAny(pending);
            pending.Remove(done);
            if (done.IsCompletedSuccessfully && done.Result.Value != null) break;
        }
        if (pending.Count > 0)
        {
            // the other lanes get a little longer to cross-check, then stop
            stop.CancelAfter(Grace);
            try { await Task.WhenAll(pending); }
            catch (OperationCanceledException) { }
        }

        var hits = new List<(int prio, string name, IpGeoResult res)>();
        var errors = new List<string>();
        foreach (var t in tasks)
        {
            if (!t.IsCompletedSuccessfully) continue;   // stopped after the grace
            errors.AddRange(t.Result.Errors);
            if (t.Result.Value is { } value && sources.FirstOrDefault(s => s.Name == t.Result.Source) is { } src)
                hits.Add((src.Priority, src.Name, value));
        }
        return (hits, errors);
    }

    // One provider's answer, checked: null when it has nothing for the address, an exception with the reason when it fails.
    private static async Task<IpGeoResult?> AskAsync(HttpClient client, IpSource s, IPAddress? asked, CancellationToken ct)
    {
        string resp = TestGet is { } hook ? await hook(s.Url, ct).ConfigureAwait(false)
                                          : await client.GetStringAsync(s.Url, ct).ConfigureAwait(false);
        int a = resp.IndexOf('{'), b = resp.LastIndexOf('}');
        if (a < 0 || b < a) throw new InvalidDataException("unreadable answer");
        using var doc = JsonDocument.Parse(resp.AsMemory(a, b - a + 1));
        if (doc.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException("unreadable answer");
        return s.Parse(doc.RootElement) is { } r ? Checked(r, asked) : null;
    }

    /// <summary>
    /// An answer is someone else's text (every field cleaned and capped as it's read): the address must be one, and the one
    /// asked about (a provider that ignores the address answers with the asker's own); a country code is two letters; "-"
    /// or "Not found" is no value and 0,0 no place; and an answer without a place or a network in it is none.
    /// </summary>
    private static IpGeoResult? Checked(IpGeoResult r, IPAddress? asked)
    {
        static string Real(string s) => s is "-" or "--" or "N/A" or "Not found" ? string.Empty : s;
        r.Country = Real(r.Country); r.Region = Real(r.Region); r.City = Real(r.City); r.Postal = Real(r.Postal);
        r.Latitude = Real(r.Latitude); r.Longitude = Real(r.Longitude); r.Timezone = Real(r.Timezone);
        r.UtcOffset = Real(r.UtcOffset); r.Isp = Real(r.Isp); r.Org = Real(r.Org); r.Asn = Real(r.Asn); r.Hostname = Real(r.Hostname);

        var ip = IPAddress.TryParse(r.Ip, out var parsed) ? Canonical(parsed) : null;
        if (asked != null && ip != null && !ip.Equals(asked)) throw new InvalidDataException("answered for another address");
        ip ??= asked;
        r.Ip = ip?.ToString() ?? string.Empty;
        if (ip != null) r.Version = ip.AddressFamily == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4";

        string cc = r.CountryCode.Trim().ToUpperInvariant();
        r.CountryCode = cc.Length == 2 && char.IsAsciiLetterUpper(cc[0]) && char.IsAsciiLetterUpper(cc[1]) && cc is not ("ZZ" or "XX") ? cc : string.Empty;
        if (double.TryParse(r.Latitude, NumberStyles.Float, CultureInfo.InvariantCulture, out double lat)
            && double.TryParse(r.Longitude, NumberStyles.Float, CultureInfo.InvariantCulture, out double lon)
            && Math.Abs(lat) < 0.1 && Math.Abs(lon) < 0.1)
            r.Latitude = r.Longitude = string.Empty;
        return (r.Country + r.CountryCode + r.Region + r.City + r.Isp + r.Org + r.Asn).Length > 0 ? r : null;
    }

    // As the providers write it back: an IPv4-mapped address as IPv4, no zone (a link-local address has no location).
    private static IPAddress Canonical(IPAddress ip)
        => ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4()
         : ip.AddressFamily == AddressFamily.InterNetworkV6 && ip.ScopeId != 0 ? new IPAddress(ip.GetAddressBytes()) : ip;

    // One TCP connection to the proxy (5 s at most): why it can't be reached, or null when it can.
    private static async Task<string?> ProxyUnreachableAsync(string proxy)
    {
        if (!HttpHelper.TryParseProxy(proxy, out var uri)) return null;   // Create already refused a bad address
        Socket socket;
        try { socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true }; }
        catch (SocketException) { return null; }   // no dual-stack socket here: the requests themselves will tell
        using (socket)
        {
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await socket.ConnectAsync(uri.Host.Trim('[', ']'), uri.Port, cts.Token);
                return null;
            }
            catch (Exception ex)
            {
                return $"Couldn't reach the proxy {uri.Host}:{uri.Port} ({Fallback.Reason(ex)}). Check its address, or turn the proxy off.";
            }
        }
    }

    // "name: reason" → a line per reason: "timed out: ip-api.com, ipinfo.io".
    private static string Reasons(List<string> errors)
        => string.Join("\n", errors.Select(e => e.Split(": ", 2)).GroupBy(p => p.Length == 2 ? p[1] : "failed", p => p[0])
                                   .Select(g => g.Key + ": " + string.Join(", ", g)));

    // Providers index (1-based, matching the ComboBox order) → canonical source name.
    private static string ProviderKey(int idx) => idx >= 1 && idx <= Table.Length ? Table[idx - 1].Name : "";

    private static List<IpSource> BuildSources(bool self, string target, IPAddress? asked)
    {
        // an address goes in as its canonical text (hex digits, dots and colons: nothing to escape), a name escaped
        string q = asked?.ToString() ?? Uri.EscapeDataString(target);
        var list = new List<IpSource>();
        for (int i = 0; i < Table.Length; i++)
        {
            var p = Table[i];
            string? url = self ? p.SelfUrl : p.LookupUrl.Replace("{ip}", q, StringComparison.Ordinal);
            if (url != null) list.Add(new IpSource(i + 1, p.Name, url, p.Parse));
        }
        return list;
    }

    // Merge in priority order: the first source that supplies a field wins; flags OR together.
    private static IpGeoResult Merge(IEnumerable<(int prio, string name, IpGeoResult res)> hits)
    {
        var m = new IpGeoResult();
        var names = new List<string>();
        foreach (var (_, name, r) in hits)
        {
            names.Add(name);
            m.Ip = Or(m.Ip, r.Ip);
            m.Version = Or(m.Version, r.Version);
            m.Country = Or(m.Country, r.Country);
            m.CountryCode = Or(m.CountryCode, r.CountryCode);
            m.Region = Or(m.Region, r.Region);
            m.City = Or(m.City, r.City);
            m.Postal = Or(m.Postal, r.Postal);
            m.Latitude = Or(m.Latitude, r.Latitude);
            m.Longitude = Or(m.Longitude, r.Longitude);
            m.Timezone = Or(m.Timezone, r.Timezone);
            m.UtcOffset = Or(m.UtcOffset, r.UtcOffset);
            m.Isp = Or(m.Isp, r.Isp);
            m.Org = Or(m.Org, r.Org);
            m.Asn = Or(m.Asn, r.Asn);
            m.Hostname = Or(m.Hostname, r.Hostname);
            m.IsProxy |= r.IsProxy;
            m.IsHosting |= r.IsHosting;
            m.IsMobile |= r.IsMobile;
        }
        m.Flag = FlagFromCc(m.CountryCode);
        m.Sources = string.Join(" · ", names);
        return m;
    }

    private static string Or(string cur, string val) => cur.Length > 0 ? cur : (val ?? "").Trim();

    private static string BuildCopyText(IpGeoResult r)
    {
        var sb = new StringBuilder();
        void Add(string k, string v) { if (!string.IsNullOrWhiteSpace(v)) sb.Append(k.PadRight(12)).Append(": ").AppendLine(v); }
        Add("IP", r.Ip);
        Add("Version", r.Version);
        Add("City", r.City);
        Add("Region", r.Region);
        Add("Country", r.Country + (r.CountryCode.Length > 0 ? $" ({r.CountryCode})" : ""));
        Add("Postal", r.Postal);
        Add("Coords", r.Coordinates);
        Add("Timezone", r.Timezone);
        Add("UTC", r.UtcOffset);
        Add("ISP", r.Isp);
        Add("Org", r.Org);
        Add("ASN", r.Asn);
        Add("Hostname", r.Hostname);
        if (r.HasSecurity) Add("Flags", r.SecurityText);
        Add("Sources", r.Sources);
        return sb.ToString().TrimEnd();
    }

    // ---- per-provider parsers (each maps its own schema onto IpGeoResult) ----

    private static IpGeoResult ParseIpApi(JsonElement r)   // ip-api.com — richest free schema
    {
        if (S(r, "status") == "fail") return null!;
        return new IpGeoResult
        {
            Ip = S(r, "query"),
            Country = S(r, "country"), CountryCode = S(r, "countryCode"),
            Region = S(r, "regionName"), City = S(r, "city"), Postal = S(r, "zip"),
            Latitude = S(r, "lat"), Longitude = S(r, "lon"),
            Timezone = S(r, "timezone"), UtcOffset = OffsetFromSeconds(S(r, "offset")),
            Isp = S(r, "isp"), Org = S(r, "org"), Asn = NormAsn(S(r, "as")),
            Hostname = S(r, "reverse"),
            IsProxy = B(r, "proxy"), IsHosting = B(r, "hosting"), IsMobile = B(r, "mobile"),
        };
    }

    private static IpGeoResult ParseIpWho(JsonElement r)   // ipwho.is
    {
        if (r.TryGetProperty("success", out var suc) && suc.ValueKind == JsonValueKind.False) return null!;
        var conn = Obj(r, "connection"); var tz = Obj(r, "timezone");
        string asn = conn is { } c ? S(c, "asn") : "";
        string org = conn is { } c2 ? S(c2, "org") : "";
        return new IpGeoResult
        {
            Ip = S(r, "ip"), Version = S(r, "type"),
            Country = S(r, "country"), CountryCode = S(r, "country_code"),
            Region = S(r, "region"), City = S(r, "city"), Postal = S(r, "postal"),
            Latitude = S(r, "latitude"), Longitude = S(r, "longitude"),
            Timezone = tz is { } t ? S(t, "id") : "", UtcOffset = tz is { } t2 ? Utc(S(t2, "utc")) : "",
            Isp = conn is { } c3 ? S(c3, "isp") : "", Org = org,
            Asn = asn.Length > 0 && asn != "0" ? "AS" + asn : "",
        };
    }

    private static IpGeoResult ParseIpApiCo(JsonElement r) // ipapi.co
    {
        if (B(r, "error")) return null!;
        return new IpGeoResult
        {
            Ip = S(r, "ip"), Version = NormVersion(S(r, "version")),
            Country = S(r, "country_name"), CountryCode = S(r, "country_code"),
            Region = S(r, "region"), City = S(r, "city"), Postal = S(r, "postal"),
            Latitude = S(r, "latitude"), Longitude = S(r, "longitude"),
            Timezone = S(r, "timezone"), UtcOffset = Utc(S(r, "utc_offset")),
            Org = S(r, "org"), Asn = NormAsn(S(r, "asn")),
        };
    }

    private static IpGeoResult ParseIpInfo(JsonElement r)  // ipinfo.io  (loc "lat,lon", org "AS### Name")
    {
        if (B(r, "bogon")) return null!;
        string loc = S(r, "loc");
        string lat = "", lon = "";
        int comma = loc.IndexOf(',');
        if (comma > 0) { lat = loc[..comma].Trim(); lon = loc[(comma + 1)..].Trim(); }
        var (asn, org) = SplitAsnOrg(S(r, "org"));
        return new IpGeoResult
        {
            Ip = S(r, "ip"), CountryCode = S(r, "country"),
            Region = S(r, "region"), City = S(r, "city"), Postal = S(r, "postal"),
            Latitude = lat, Longitude = lon, Timezone = S(r, "timezone"),
            Org = org, Asn = asn, Hostname = S(r, "hostname"),
        };
    }

    private static IpGeoResult ParseFreeIpApi(JsonElement r) // freeipapi.com (v1: "timeZones" is the country's list, not used)
    {
        return new IpGeoResult
        {
            Ip = S(r, "ipAddress"), Version = NormVersion(S(r, "ipVersion")),
            Country = S(r, "countryName"), CountryCode = S(r, "countryCode"),
            Region = S(r, "regionName"), City = S(r, "cityName"), Postal = S(r, "zipCode"),
            Latitude = S(r, "latitude"), Longitude = S(r, "longitude"),
            UtcOffset = Utc(S(r, "timeZone")),
            Org = S(r, "asnOrganization"), Asn = NormAsn(S(r, "asn")),
            IsProxy = B(r, "isProxy"),
        };
    }

    private static IpGeoResult ParseGeoJs(JsonElement r)   // get.geojs.io
    {
        var (asn, org) = SplitAsnOrg(S(r, "organization"));
        return new IpGeoResult
        {
            Ip = S(r, "ip"),
            Country = S(r, "country"), CountryCode = S(r, "country_code"),
            Region = S(r, "region"), City = S(r, "city"),
            Latitude = S(r, "latitude"), Longitude = S(r, "longitude"),
            Timezone = S(r, "timezone"),
            Org = S(r, "organization_name") is { Length: > 0 } on ? on : org, Asn = asn,
        };
    }

    private static IpGeoResult ParseIpLocationNet(JsonElement r) // api.iplocation.net (country + ISP only)
    {
        if (S(r, "response_code") is { Length: > 0 } rc && rc != "200") return null!;
        return new IpGeoResult
        {
            Ip = S(r, "ip"), Version = NormVersion(S(r, "ip_version")),
            Country = S(r, "country_name"), CountryCode = S(r, "country_code2"),
            Isp = S(r, "isp"),
        };
    }

    private static IpGeoResult ParseIpWhoisApp(JsonElement r)   // ipwhois.app (asn "AS15169", timezone_gmt "-07:00")
    {
        if (r.TryGetProperty("success", out var suc) && suc.ValueKind == JsonValueKind.False) return null!;
        return new IpGeoResult
        {
            Ip = S(r, "ip"), Version = S(r, "type"),
            Country = S(r, "country"), CountryCode = S(r, "country_code"),
            Region = S(r, "region"), City = S(r, "city"),
            Latitude = S(r, "latitude"), Longitude = S(r, "longitude"),
            Timezone = S(r, "timezone"), UtcOffset = Utc(S(r, "timezone_gmt")),
            Isp = S(r, "isp"), Org = S(r, "org"), Asn = NormAsn(S(r, "asn")),
        };
    }

    private static IpGeoResult ParseIpLocate(JsonElement r)   // iplocate.io (asn object; privacy: proxy / vpn / tor / hosting)
    {
        var asn = Obj(r, "asn"); var privacy = Obj(r, "privacy");
        if (B(privacy, "is_bogon")) return null!;
        return new IpGeoResult
        {
            Ip = S(r, "ip"),
            Country = S(r, "country"), CountryCode = S(r, "country_code"),
            Region = S(r, "subdivision"), City = S(r, "city"), Postal = S(r, "postal_code"),
            Latitude = S(r, "latitude"), Longitude = S(r, "longitude"), Timezone = S(r, "time_zone"),
            Org = S(asn, "name"), Asn = NormAsn(S(asn, "asn")),
            IsProxy = B(privacy, "is_proxy") || B(privacy, "is_vpn") || B(privacy, "is_tor"),
            IsHosting = B(privacy, "is_hosting"),
        };
    }

    private static IpGeoResult ParseIpQuery(JsonElement r)   // api.ipquery.io (isp, location, risk; "AS0" when unknown)
    {
        var isp = Obj(r, "isp"); var loc = Obj(r, "location"); var risk = Obj(r, "risk");
        string asn = S(isp, "asn");
        return new IpGeoResult
        {
            Ip = S(r, "ip"),
            Country = S(loc, "country"), CountryCode = S(loc, "country_code"),
            Region = S(loc, "state"), City = S(loc, "city"), Postal = S(loc, "zipcode"),
            Latitude = S(loc, "latitude"), Longitude = S(loc, "longitude"), Timezone = S(loc, "timezone"),
            Isp = S(isp, "isp"), Org = S(isp, "org"), Asn = asn is "AS0" or "0" ? "" : NormAsn(asn),
            IsProxy = B(risk, "is_proxy") || B(risk, "is_vpn") || B(risk, "is_tor"),
            IsHosting = B(risk, "is_datacenter"), IsMobile = B(risk, "is_mobile"),
        };
    }

    private static IpGeoResult ParseIp2Location(JsonElement r)   // api.ip2location.io, keyless (asn "24940", time_zone "+02:00")
    {
        if (Obj(r, "error") is { } error) throw new InvalidDataException(S(error, "error_message") is { Length: > 0 } m ? m : "refused");
        return new IpGeoResult
        {
            Ip = S(r, "ip"),
            Country = S(r, "country_name"), CountryCode = S(r, "country_code"),
            Region = S(r, "region_name"), City = S(r, "city_name"), Postal = S(r, "zip_code"),
            Latitude = S(r, "latitude"), Longitude = S(r, "longitude"), UtcOffset = Utc(S(r, "time_zone")),
            Org = S(r, "as"), Asn = NormAsn(S(r, "asn")),
            IsProxy = B(r, "is_proxy"),
        };
    }

    private static IpGeoResult ParseGeoIpLookup(JsonElement r)   // json.geoiplookup.io ("success": false when unknown)
    {
        if (r.TryGetProperty("success", out var suc) && suc.ValueKind == JsonValueKind.False) return null!;
        string asn = S(r, "asn_number");
        return new IpGeoResult
        {
            Ip = S(r, "ip"),
            Country = S(r, "country_name"), CountryCode = S(r, "country_code"),
            Region = S(r, "region"), City = S(r, "city"), Postal = S(r, "postal_code"),
            Latitude = S(r, "latitude"), Longitude = S(r, "longitude"), Timezone = S(r, "timezone_name"),
            Isp = S(r, "isp"), Org = S(r, "org"), Asn = asn is "" or "0" ? "" : NormAsn(asn),
            Hostname = S(r, "hostname"),
        };
    }

    private static IpGeoResult ParseIfconfigCo(JsonElement r)   // ifconfig.co (country_iso, asn "AS15169", asn_org)
    {
        return new IpGeoResult
        {
            Ip = S(r, "ip"),
            Country = S(r, "country"), CountryCode = S(r, "country_iso"),
            Region = S(r, "region_name"), City = S(r, "city"), Postal = S(r, "zip_code"),
            Latitude = S(r, "latitude"), Longitude = S(r, "longitude"), Timezone = S(r, "time_zone"),
            Org = S(r, "asn_org"), Asn = NormAsn(S(r, "asn")), Hostname = S(r, "hostname"),
        };
    }

    private static IpGeoResult ParseIpLeak(JsonElement r)   // ipleak.net (as_number, isp_name; no country for a reserved range)
    {
        string asn = S(r, "as_number");
        return new IpGeoResult
        {
            Ip = S(r, "ip"),
            Country = S(r, "country_name"), CountryCode = S(r, "country_code"),
            Region = S(r, "region_name"), City = S(r, "city_name"), Postal = S(r, "postal_code"),
            Latitude = S(r, "latitude"), Longitude = S(r, "longitude"), Timezone = S(r, "time_zone"),
            Isp = S(r, "isp_name"), Asn = asn is "" or "0" ? "" : NormAsn(asn), Hostname = S(r, "reverse"),
        };
    }

    // api.ip.sb geoip (asn a number). Its "offset" isn't used: it read standard time while daylight saving was on.
    private static IpGeoResult ParseIpSb(JsonElement r)
    {
        string asn = S(r, "asn");
        return new IpGeoResult
        {
            Ip = S(r, "ip"),
            Country = S(r, "country"), CountryCode = S(r, "country_code"),
            Region = S(r, "region"), City = S(r, "city"), Postal = S(r, "postal_code"),
            Latitude = S(r, "latitude"), Longitude = S(r, "longitude"), Timezone = S(r, "timezone"),
            Isp = S(r, "isp"), Org = S(r, "asn_organization") is { Length: > 0 } org ? org : S(r, "organization"),
            Asn = asn is "" or "0" ? "" : NormAsn(asn),
        };
    }

    private static IpGeoResult ParseIpGuide(JsonElement r)   // ip.guide (network.autonomous_system, location: a country name only)
    {
        var system = Obj(Obj(r, "network"), "autonomous_system"); var loc = Obj(r, "location");
        string asn = S(system, "asn");
        return new IpGeoResult
        {
            Ip = S(r, "ip"),
            Country = S(loc, "country"), City = S(loc, "city"),
            Latitude = S(loc, "latitude"), Longitude = S(loc, "longitude"), Timezone = S(loc, "timezone"),
            Org = S(system, "organization"), Asn = asn is "" or "0" ? "" : NormAsn(asn),
        };
    }

    private static IpGeoResult ParseDbIp(JsonElement r)   // api.db-ip.com free (country, region, city; "ZZ" when unknown)
    {
        if (S(r, "errorCode") is { Length: > 0 } code) throw new InvalidDataException("refused (" + RemoteText.Clean(code, 40) + ")");
        return new IpGeoResult
        {
            Ip = S(r, "ipAddress"),
            Country = S(r, "countryName"), CountryCode = S(r, "countryCode"),
            Region = S(r, "stateProv"), City = S(r, "city"),
        };
    }

    private static IpGeoResult ParseGeolocationDb(JsonElement r)   // geolocation-db.com ("Not found" when unknown; "IPv4" holds either family)
    {
        return new IpGeoResult
        {
            Ip = S(r, "IPv4"),
            Country = S(r, "country_name"), CountryCode = S(r, "country_code"),
            Region = S(r, "state"), City = S(r, "city"), Postal = S(r, "postal"),
            Latitude = S(r, "latitude"), Longitude = S(r, "longitude"),
        };
    }

    private static IpGeoResult ParseCountryIs(JsonElement r)   // api.country.is (the country only)
        => new() { Ip = S(r, "ip"), CountryCode = S(r, "country") };

    // ---- json + formatting helpers ----

    // Provider text, made safe to show and capped: a field is a name or a number, never a page.
    private static string S(JsonElement e, string name)
    {
        if (e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v))
            return v.ValueKind switch
            {
                JsonValueKind.String => RemoteText.Clean(v.GetString(), MaxFieldChars).Trim(),
                JsonValueKind.Number => RemoteText.Clean(v.GetRawText(), MaxFieldChars),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                _ => "",
            };
        return "";
    }

    private static string S(JsonElement? e, string name) => e is { } x ? S(x, name) : "";

    private static bool B(JsonElement e, string name)
        => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v)
           && (v.ValueKind == JsonValueKind.True
               || (v.ValueKind == JsonValueKind.String && string.Equals(v.GetString(), "true", StringComparison.OrdinalIgnoreCase)));

    private static bool B(JsonElement? e, string name) => e is { } x && B(x, name);

    private static JsonElement? Obj(JsonElement e, string name)
        => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Object ? v : null;

    private static JsonElement? Obj(JsonElement? e, string name) => e is { } x ? Obj(x, name) : null;

    private static string NormVersion(string v)
        => v.Length == 0 ? "" : v.Equals("6") || v.Contains('6') ? "IPv6" : v.Equals("4") || v.Contains('4') ? "IPv4" : v;

    private static string NormAsn(string s)
    {
        s = s.Trim();
        if (s.Length == 0) return "";
        return s.StartsWith("AS", StringComparison.OrdinalIgnoreCase) ? s : "AS" + s;
    }

    // Split ipinfo/geojs "AS15169 Google LLC" → ("AS15169", "Google LLC").
    private static (string asn, string org) SplitAsnOrg(string s)
    {
        s = s.Trim();
        if (s.Length == 0) return ("", "");
        if (s.StartsWith("AS", StringComparison.OrdinalIgnoreCase))
        {
            int sp = s.IndexOf(' ');
            return sp > 0 ? (s[..sp], s[(sp + 1)..].Trim()) : (s, "");
        }
        return ("", s);
    }

    // ip-api "offset" is seconds east of UTC → "UTC+03:30".
    private static string OffsetFromSeconds(string secStr)
    {
        if (!int.TryParse(secStr, NumberStyles.Integer, CultureInfo.InvariantCulture, out int sec)) return "";
        var ts = TimeSpan.FromSeconds(Math.Abs(sec));
        return $"UTC{(sec < 0 ? "-" : "+")}{ts.Hours:00}:{ts.Minutes:00}";
    }

    // Normalise "+05:30" / "+0530" → "UTC+05:30".
    private static string Utc(string s)
    {
        s = s.Trim();
        if (s.Length == 0) return "";
        if (s.StartsWith("UTC", StringComparison.OrdinalIgnoreCase)) return s;
        if (s.Length == 5 && (s[0] == '+' || s[0] == '-')) s = s[..3] + ":" + s[3..]; // +0530 → +05:30
        return "UTC" + s;
    }

    private static string FlagFromCc(string cc)
    {
        cc = cc.Trim().ToUpperInvariant();
        if (cc.Length != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z') return "";
        return char.ConvertFromUtf32(0x1F1E6 + (cc[0] - 'A')) + char.ConvertFromUtf32(0x1F1E6 + (cc[1] - 'A'));
    }
}
