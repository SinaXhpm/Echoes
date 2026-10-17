using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
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

    // Which provider to query. Index 0 = Auto (all sources, merged/cross-checked); otherwise a single one.
    public ObservableCollection<string> Providers { get; } = new()
    { "Auto (cross-check)", "ip-api.com", "ipwho.is", "ipapi.co", "ipinfo.io", "freeipapi", "geojs", "iplocation.net" };
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

    // ---- multi-source fetch + merge ----

    private sealed record IpSource(int Priority, string Name, string Url, Func<JsonElement, IpGeoResult?> Parse);

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
            string? proxy = UseProxy && !string.IsNullOrWhiteSpace(ProxyAddress) ? ProxyAddress : null;
            using var client = HttpHelper.Create(proxy, ProxyUser, ProxyPass, timeout: TimeSpan.FromSeconds(8));
            // Every provider answers with a few hundred bytes of JSON; don't let a hostile proxy stream more.
            client.MaxResponseContentBufferSize = 256 * 1024;
            if (proxy != null) HistoryService.Instance.Add("ip.proxy", proxy);   // only once it parsed

            bool self = string.IsNullOrWhiteSpace(ip);
            var sources = BuildSources(self, ip.Trim());

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

            // Cross-check: query the top sources concurrently (accuracy ↑, latency = the fastest).
            var hits = new List<(int prio, string name, IpGeoResult res)>();
            const int parallelCount = 3;
            var primary = sources.Take(parallelCount).ToArray();
            var results = await Task.WhenAll(primary.Select(s => FetchOne(client, s)));
            foreach (var r in results) if (r.res is not null) hits.Add((r.prio, r.name, r.res));

            // Nothing from the fast batch → walk the remaining fallbacks one by one.
            if (hits.Count == 0)
            {
                foreach (var s in sources.Skip(parallelCount))
                {
                    var r = await FetchOne(client, s);
                    if (r.res is not null) { hits.Add((r.prio, r.name, r.res)); break; }
                }
            }

            if (hits.Count == 0)
            {
                Result = null;
                RawResult = "No source responded. Check the address / your connection" + (proxy != null ? " / proxy." : ".");
                StatusLine = string.Empty;
                return;
            }

            // HTTPS answers win the merge. A plain-HTTP source (ip-api.com's free tier) can be rewritten
            // by anyone on the path — including the proxy under test — so it only fills the fields no
            // HTTPS source supplied. It stays in the batch: it's the only proxy/hosting/mobile source.
            var plain = sources.Where(s => s.Url.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                               .Select(s => s.Name).ToHashSet();
            var ordered = hits.OrderBy(h => plain.Contains(h.name) ? 1 : 0).ThenBy(h => h.prio).ToList();
            var merged = Merge(ordered);
            Result = merged;
            foreach (var (_, name, res) in ordered)
                ProviderResults.Add(new IpProviderResult { Name = plain.Contains(name) ? name + "  (plain HTTP)" : name, Data = res });
            RawResult = BuildCopyText(merged);
            StatusLine = hits.Count > 1
                ? $"Cross-checked via {merged.Sources}"
                : $"Source: {merged.Sources}";
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

    private static async Task<(int prio, string name, IpGeoResult? res)> FetchOne(HttpClient client, IpSource s)
    {
        try
        {
            string resp = await client.GetStringAsync(s.Url);
            int a = resp.IndexOf('{'), b = resp.LastIndexOf('}');
            if (a < 0 || b < a) return (s.Priority, s.Name, null);
            using var doc = JsonDocument.Parse(resp.Substring(a, b - a + 1));
            return (s.Priority, s.Name, s.Parse(doc.RootElement));
        }
        catch { return (s.Priority, s.Name, null); }
    }

    // Providers index (1-based, matching the ComboBox order) → canonical source name.
    private static string ProviderKey(int idx) => idx switch
    {
        1 => "ip-api.com", 2 => "ipwho.is", 3 => "ipapi.co", 4 => "ipinfo.io",
        5 => "freeipapi", 6 => "geojs", 7 => "iplocation.net", _ => "",
    };

    private static List<IpSource> BuildSources(bool self, string ip)
    {
        string E(string x) => Uri.EscapeDataString(x);
        if (self)
            return new()
            {
                new(1, "ip-api.com", "http://ip-api.com/json/?fields=66846719", ParseIpApi),
                new(2, "ipwho.is",   "https://ipwho.is/",                        ParseIpWho),
                new(3, "ipapi.co",   "https://ipapi.co/json/",                   ParseIpApiCo),
                new(4, "ipinfo.io",  "https://ipinfo.io/json",                   ParseIpInfo),
                new(5, "freeipapi",  "https://freeipapi.com/api/json",           ParseFreeIpApi),
                new(6, "geojs",      "https://get.geojs.io/v1/ip/geo.json",      ParseGeoJs),
            };
        return new()
        {
            new(1, "ip-api.com",     $"http://ip-api.com/json/{E(ip)}?fields=66846719", ParseIpApi),
            new(2, "ipwho.is",       $"https://ipwho.is/{E(ip)}",                        ParseIpWho),
            new(3, "ipapi.co",       $"https://ipapi.co/{E(ip)}/json/",                  ParseIpApiCo),
            new(4, "ipinfo.io",      $"https://ipinfo.io/{E(ip)}/json",                  ParseIpInfo),
            new(5, "freeipapi",      $"https://freeipapi.com/api/json/{E(ip)}",          ParseFreeIpApi),
            new(6, "geojs",          $"https://get.geojs.io/v1/ip/geo/{E(ip)}.json",     ParseGeoJs),
            new(7, "iplocation.net", $"https://api.iplocation.net/?ip={E(ip)}",          ParseIpLocationNet),
        };
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

    private static IpGeoResult ParseFreeIpApi(JsonElement r) // freeipapi.com
    {
        return new IpGeoResult
        {
            Ip = S(r, "ipAddress"), Version = NormVersion(S(r, "ipVersion")),
            Country = S(r, "countryName"), CountryCode = S(r, "countryCode"),
            Region = S(r, "regionName"), City = S(r, "cityName"), Postal = S(r, "zipCode"),
            Latitude = S(r, "latitude"), Longitude = S(r, "longitude"),
            UtcOffset = Utc(S(r, "timeZone")),
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

    // ---- json + formatting helpers ----

    private static string S(JsonElement e, string name)
    {
        if (e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v))
            return v.ValueKind switch
            {
                JsonValueKind.String => v.GetString() ?? "",
                JsonValueKind.Number => v.ToString(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                _ => "",
            };
        return "";
    }

    private static bool B(JsonElement e, string name)
        => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v)
           && (v.ValueKind == JsonValueKind.True
               || (v.ValueKind == JsonValueKind.String && string.Equals(v.GetString(), "true", StringComparison.OrdinalIgnoreCase)));

    private static JsonElement? Obj(JsonElement e, string name)
        => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Object ? v : null;

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
