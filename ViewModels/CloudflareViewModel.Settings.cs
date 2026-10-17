using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

// Zone settings (SSL/TLS incl. ECH, HSTS, security, speed, network, cache), cache purge and pausing Cloudflare on a zone.
//   read:   GET /zones/{id}/settings (bulk), then GET /zones/{id}/settings/{setting} for ids the bulk list lacks
//           (ech is one; the bulk endpoint is deprecated, so every id also works on its own)
//   change: PATCH /zones/{id}/settings/{setting} {"value": …} — applied immediately, reverted on failure
//   tiered cache: GET / PATCH /zones/{id}/argo/tiered_caching {"value"} (+ cache/tiered_cache_smart_topology_enable)
//   purge:  POST /zones/{id}/purge_cache {"purge_everything":true} | {"files":[…≤30]}
//   pause:  PATCH /zones/{id} {"paused": true|false}
// Left out on purpose: Brotli, Auto Minify, Mirage, Privacy Pass, Server-side Excludes (deprecated by Cloudflare),
// Cache Deception Armor (now a Cache Rule), and the Enterprise-only switches (True-Client-IP, response buffering…).
public partial class CloudflareViewModel
{
    /// <summary>The selected zone's settings (lazily loaded, cached per zone for the session).</summary>
    [ObservableProperty] private CfZoneSettings? _currentSettings;

    private readonly Dictionary<string, CfZoneSettings> _settingsCache = new(StringComparer.Ordinal);

    private CfZoneSettings SettingsFor(CfZone zone)
    {
        if (!_settingsCache.TryGetValue(zone.Id, out var set))
        {
            set = CreateSettings(zone);
            _settingsCache[zone.Id] = set;
        }
        return set;
    }

    // ---------- definitions ----------

    private static CfOption O(string value, string label) => new(value, label);

    private CfZoneSettings CreateSettings(CfZone zone)
    {
        int plan = zone.PlanRank;
        CfSetting Toggle(string id, string title, string description, int minPlan = CfPlan.Free, bool hide = false,
                         string on = "on", string off = "off", string? path = null)
            => Wire(zone, new CfSetting(id, title, description, CfSettingKind.Toggle)
            {
                MinPlan = minPlan, PlanLocked = plan < minPlan, HideWhenUnavailable = hide, OnValue = on, OffValue = off, ZoneSubPath = path,
            });
        CfSetting Choice(string id, string title, string description, CfOption[] options, int minPlan = CfPlan.Free,
                         bool numeric = false, bool readOnly = false)
            => Wire(zone, new CfSetting(id, title, description, CfSettingKind.Choice, options, numeric: numeric || id == "browser_cache_ttl")
            {
                MinPlan = minPlan, PlanLocked = plan < minPlan, ReadOnly = readOnly,
            });

        var level = Choice("security_level", "Security level",
            "How readily poor-reputation IPs get challenged.",
            new[] { O("essentially_off", "Essentially off"), O("low", "Low"), O("medium", "Medium"), O("high", "High"),
                    O("under_attack", "I'm under attack") });
        var set = new CfZoneSettings(zone.Id)
        {
            Ech = Toggle("ech", "Encrypted Client Hello (ECH)",
                "Hides the site name in TLS. Turn it off if networks block ECH."),
            Ssl = Wire(zone, new CfSetting("ssl", "Encryption mode", "How Cloudflare connects to your origin.",
                CfSettingKind.Segmented, new[] { O("off", "Off"), O("flexible", "Flexible"), O("full", "Full"), O("strict", "Full (strict)") })),
            AutoSsl = Toggle("ssl_automatic_mode", "Automatic SSL/TLS",
                "Picks the most secure mode your origin supports.",
                hide: true, on: "auto", off: "custom"),
            SecurityLevel = level,
            UnderAttack = new CfUnderAttack(level),
        };
        set.EchRow.Add(set.Ech);
        set.SslModeRow.Add(set.Ssl);
        set.SslModeRow.Add(set.AutoSsl);
        var autoSsl = set.AutoSsl;
        set.Ssl.Explain = s =>
        {
            string meaning = s.Value switch
            {
                "off" => "Off: plain HTTP only, no HTTPS.",
                "flexible" => "Flexible: HTTPS to Cloudflare, plain HTTP to your origin.",
                "full" => "Full: HTTPS to your origin, any certificate (self-signed too).",
                "strict" => "Full (strict): HTTPS to your origin, valid certificate (public or Origin CA).",
                "" => string.Empty,
                _ => $"Mode: {s.Value}.",
            };
            return autoSsl.IsLoaded && autoSsl.IsAvailable && autoSsl.IsOnFor(autoSsl.Value) && meaning.Length > 0
                ? meaning + " Picked by Automatic SSL/TLS; choosing one turns it off."
                : meaning;
        };
        // the mode's note mentions automatic mode: refresh it when that changes
        autoSsl.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(CfSetting.Value)) set.Ssl.Note = set.Ssl.Explain?.Invoke(set.Ssl) ?? string.Empty;
        };

        set.SslRows.Add(Toggle("always_use_https", "Always use HTTPS", "Redirect every HTTP request to HTTPS."));
        set.SslRows.Add(Toggle("automatic_https_rewrites", "Automatic HTTPS rewrites",
            "Rewrite http:// links in your pages to https://."));
        set.SslRows.Add(Choice("min_tls_version", "Minimum TLS version", "Older TLS versions are refused.",
            new[] { O("1.0", "TLS 1.0"), O("1.1", "TLS 1.1"), O("1.2", "TLS 1.2"), O("1.3", "TLS 1.3") }));
        set.SslRows.Add(Toggle("tls_1_3", "TLS 1.3", "Allow the newest, fastest TLS version."));
        set.SslRows.Add(Toggle("opportunistic_encryption", "Opportunistic encryption",
            "Encrypt the HTTP site for browsers that support it."));

        set.SecurityRows.Add(level);
        set.SecurityRows.Add(Choice("challenge_ttl", "Challenge passage",
            "How long a solved challenge lasts.", ChallengeTtlOptions(), numeric: true));
        set.SecurityRows.Add(Toggle("browser_check", "Browser integrity check", "Block requests with suspicious or missing browser headers."));
        set.SecurityRows.Add(Toggle("hotlink_protection", "Hotlink protection", "Stop other sites from embedding your images."));
        set.SecurityRows.Add(Toggle("email_obfuscation", "Email obfuscation", "Hide email addresses on your pages from bots."));
        set.SecurityRows.Add(Toggle("replace_insecure_js", "Replace insecure JS libraries",
            "Swap compromised links (like polyfill.io) for safe copies.", hide: true));

        set.SpeedRows.Add(Toggle("early_hints", "Early Hints", "Send 103 Early Hints so assets load sooner."));
        set.SpeedRows.Add(Toggle("speed_brain", "Speed Brain", "Prefetch the next page a visitor is likely to open.", hide: true));
        set.SpeedRows.Add(Toggle("rocket_loader", "Rocket Loader",
            "Load JavaScript after the page renders. Test your site: some scripts break."));
        set.SpeedRows.Add(Toggle("fonts", "Cloudflare Fonts", "Serve Google Fonts from your domain: faster, more private.", hide: true));
        set.SpeedRows.Add(Choice("polish", "Polish image optimization", "Make images smaller without visible loss.",
            new[] { O("off", "Off"), O("lossless", "Lossless"), O("lossy", "Lossy") }, minPlan: CfPlan.Pro));
        set.SpeedRows.Add(Toggle("webp", "WebP images", "With Polish on, serve WebP to browsers that support it.", minPlan: CfPlan.Pro));

        set.NetworkRows.Add(Toggle("http3", "HTTP/3 (QUIC)", "Serve HTTP/3 to browsers that support it."));
        set.NetworkRows.Add(Toggle("0rtt", "0-RTT connection resumption", "Faster repeat visits over TLS 1.3."));
        set.NetworkRows.Add(Toggle("websockets", "WebSockets", "Allow WebSocket connections to your origin."));
        set.NetworkRows.Add(Toggle("origin_max_http_version", "HTTP/2 to origin",
            "Use HTTP/2 to your origin when it can; off = HTTP/1.1.", on: "2", off: "1"));
        set.NetworkRows.Add(Toggle("ipv6", "IPv6 compatibility", "Reachable over IPv6 even when your origin has IPv4 only."));
        set.NetworkRows.Add(Toggle("ip_geolocation", "IP geolocation header", "Add the visitor's country in the CF-IPCountry header."));
        set.NetworkRows.Add(Toggle("opportunistic_onion", "Onion routing", "Let Tor users reach the site via an onion service."));
        set.NetworkRows.Add(Choice("pseudo_ipv4", "Pseudo IPv4", "A placeholder IPv4 header for IPv6 visitors.",
            new[] { O("off", "Off"), O("add_header", "Add header"), O("overwrite_header", "Overwrite headers") }));
        var upload = Choice("max_upload", "Maximum upload size", "The largest request body visitors can send.",
            UploadOptions(plan), numeric: true, readOnly: plan < CfPlan.Business);
        upload.Explain = _ => plan < CfPlan.Business ? "Free / Pro: 100 MB. Business: up to 200 MB, Enterprise: 500 MB." : string.Empty;
        set.NetworkRows.Add(upload);

        var dev = Toggle("development_mode", "Development mode", "Bypass the cache for 3 hours while you change the site.");
        dev.Explain = s => s.IsOn && s.TimeRemaining is int left and > 0 ? $"On: turns itself off in {Duration(left)}." : string.Empty;
        set.CacheRows.Add(dev);
        set.QuickRows.Add(dev);
        set.CacheRows.Add(Toggle("tiered_caching", "Tiered Cache",
            "Data centers ask an upper tier before your origin: less origin load.", path: "argo/tiered_caching"));
        set.CacheRows.Add(Choice("cache_level", "Caching level", "Which query strings get their own cached copy.",
            new[] { O("aggressive", "Standard"), O("basic", "No query string"), O("simplified", "Ignore query string") }));
        set.CacheRows.Add(Choice("browser_cache_ttl", "Browser cache TTL", "How long browsers keep cached files.",
            BrowserTtlOptions()));
        set.CacheRows.Add(Toggle("always_online", "Always Online", "Serve Internet Archive copies when your origin is down."));

        // Under attack: on = under_attack; off = the level before it (remembered in the profile), else Medium.
        set.UnderAttackRow.Add(set.UnderAttack);
        set.UnderAttack.Request = on => SetUnderAttackAsync(zone, set, on);
        set.UnderAttack.RestoreLabel = () => LevelLabel(set.SecurityLevel, RestoreLevel(zone));
        set.HstsRow.Add(set.Hsts);
        set.Hsts.Save = h => SaveHstsAsync(zone, h);
        return set;
    }

    // The values Cloudflare accepts for challenge_ttl.
    private static CfOption[] ChallengeTtlOptions()
    {
        int[] secs = { 300, 900, 1800, 2700, 3600, 7200, 10800, 14400, 28800, 57600, 86400, 604800, 2592000, 31536000 };
        return secs.Select(s => O(s.ToString(CultureInfo.InvariantCulture), s switch
        {
            604800 => "1 week",
            2592000 => "1 month",
            31536000 => "1 year",
            _ => Duration(s),
        })).ToArray();
    }

    // max_upload in MB: one fixed size below Business; Business up to 200, Enterprise up to 500 (a larger value the zone
    // already has is added when it's read).
    private static CfOption[] UploadOptions(int plan)
    {
        int max = plan >= CfPlan.Enterprise ? 500 : plan >= CfPlan.Business ? 200 : 100;
        var list = new List<CfOption>();
        for (int mb = 100; mb <= max; mb += 25) list.Add(O(mb.ToString(CultureInfo.InvariantCulture), mb + " MB"));
        return list.ToArray();
    }

    // The values Cloudflare accepts for browser_cache_ttl (0 = respect the origin's headers).
    private static CfOption[] BrowserTtlOptions()
    {
        int[] secs = { 0, 30, 60, 120, 300, 1200, 1800, 3600, 7200, 10800, 14400, 18000, 28800, 43200, 57600, 72000,
                       86400, 172800, 259200, 345600, 432000, 691200, 1382400, 2073600, 2678400, 5356800, 16070400, 31536000 };
        return secs.Select(s => O(s.ToString(CultureInfo.InvariantCulture), s switch
        {
            0 => "Respect existing headers",
            2678400 => "1 month",
            5356800 => "2 months",
            16070400 => "6 months",
            31536000 => "1 year",
            _ => Duration(s),
        })).ToArray();
    }

    private static string Duration(int seconds)
    {
        if (seconds < 60) return $"{seconds} seconds";
        if (seconds < 3600) return seconds / 60 == 1 ? "1 minute" : $"{seconds / 60} minutes";
        if (seconds < 86400)
        {
            int h = seconds / 3600, m = seconds % 3600 / 60;
            return m == 0 ? (h == 1 ? "1 hour" : $"{h} hours") : $"{h} h {m} min";
        }
        int d = seconds / 86400;
        return d == 1 ? "1 day" : $"{d} days";
    }

    private CfSetting Wire(CfZone zone, CfSetting s)
    {
        s.Apply = (setting, value) => ApplySettingAsync(zone, setting, value);
        return s;
    }

    // ---------- loading ----------

    [RelayCommand]
    private Task RefreshSettings() => SelectedZone is { } zone ? EnsureSettingsAsync(zone, force: true) : Task.CompletedTask;

    private async Task EnsureSettingsAsync(CfZone zone, bool force)
    {
        var set = SettingsFor(zone);
        if (set.IsLoading || (set.IsLoaded && !force)) return;
        var api = Api(out string error);
        if (api is null) { set.LoadError = error; return; }

        int session = _sessionGen;
        var ct = _sessionCts.Token;
        set.IsLoading = true;
        set.LoadError = string.Empty;
        try
        {
            var found = new Dictionary<string, JsonObject>(StringComparer.Ordinal);
            var bulk = await api.GetAsync(CloudflareApi.ZonePath(zone.Id) + "/settings", CfPermission.ZoneSettingsEdit, ct);
            if (session != _sessionGen) return;
            if (bulk.Success && bulk.Result is JsonArray arr)
            {
                foreach (var n in arr)
                    if (n is JsonObject o && CfJson.StrOrNull(o["id"]) is { } id) found[id] = o;
            }
            else if (bulk.AuthFailed)
            {
                // No permission to read settings: every individual GET would fail the same way.
                set.LoadError = LoadProblem("This zone's settings need", "Couldn't read this zone's settings: ", bulk.Denied, bulk.Error,
                                            CfPermission.ZoneSettingsEdit);
                SetError(set.LoadError);
                return;
            }
            // (Any other bulk failure: the per-setting reads below still get every value.)

            // Settings the bulk list doesn't carry (ech, newer ones, the ones on their own endpoint), or all of them if it
            // failed: one GET each, a few at a time. A setting the zone's plan doesn't include isn't asked for.
            var missing = set.All.Where(s => !s.PlanLocked && !found.ContainsKey(s.Id)).ToList();
            var paths = missing.Select(s => s.ZoneSubPath is { } sub ? CloudflareApi.ZonePath(zone.Id) + "/" + sub
                                                                     : CloudflareApi.SettingPath(zone.Id, s.Id)).ToList();
            bool hstsInBulk = found.ContainsKey("security_header");
            if (!hstsInBulk) paths.Add(CloudflareApi.SettingPath(zone.Id, "security_header"));
            var answers = await GetManyAsync(api, paths, CfPermission.ZoneSettingsEdit, ct);
            if (session != _sessionGen) return;
            for (int i = 0; i < missing.Count; i++)
                if (answers[i].Success && answers[i].Result is JsonObject so) found[missing[i].Id] = so;
            if (!hstsInBulk && answers[^1].Success && answers[^1].Result is JsonObject ho) found["security_header"] = ho;

            // Nothing readable at all (no connection, proxy down, rate limited…): say so. Marking every row "not
            // available" under a "loaded" status hid the failure, and stopped the next visit from trying again.
            if (found.Count == 0)
            {
                string why = !bulk.Success ? bulk.Error : answers.FirstOrDefault(a => !a.Success)?.Error ?? "no settings returned";
                set.LoadError = "Couldn't read this zone's settings: " + why;
                if (SelectedZone?.Id == zone.Id) SetError(set.LoadError);
                return;
            }

            foreach (var s in set.All)
            {
                if (s.IsBusy) continue;   // a change in flight decides that row
                s.Error = string.Empty;
                if (found.TryGetValue(s.Id, out var o)) s.Load(o);
                else s.MarkUnavailable();
            }
            if (!set.Hsts.IsBusy)
            {
                if (found.TryGetValue("security_header", out var hsts)) set.Hsts.Load(hsts);
                else set.Hsts.MarkUnavailable();
            }
            zone.UnderAttack = set.SecurityLevel.Value == "under_attack";
            set.IsLoaded = true;
            if (ReferenceEquals(zone, SelectedZone))
                SetStatus($"{zone.Name} settings loaded. Changes apply at once.");
        }
        catch (OperationCanceledException) { }
        finally
        {
            if (session == _sessionGen) set.IsLoading = false;
        }
    }

    // GETs a few at a time (the bulk settings list is deprecated: without it, a zone's settings are dozens of reads).
    private static async Task<CfResponse[]> GetManyAsync(CloudflareApi api, IReadOnlyList<string> paths, CfPermission perm, CancellationToken ct)
    {
        var answers = new CfResponse[paths.Count];
        using var gate = new SemaphoreSlim(6);
        await Task.WhenAll(paths.Select(async (path, i) =>
        {
            await gate.WaitAsync(ct);
            try { answers[i] = await api.GetAsync(path, perm, ct); }
            finally { gate.Release(); }
        }));
        return answers;
    }

    // ---------- applying ----------

    private async Task ApplySettingAsync(CfZone zone, CfSetting s, string value)
    {
        if (IsLocked || s.IsBusy) { s.Revert(); return; }
        var api = Api(out string error);
        if (api is null)
        {
            s.Revert();
            s.Error = error;
            return;
        }
        int session = _sessionGen;
        string before = s.Value;
        s.IsBusy = true;
        s.Error = string.Empty;
        JsonNode node = s.Numeric && int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int n)
            ? JsonValue.Create(n)
            : JsonValue.Create(value)!;
        string path = s.ZoneSubPath is { } sub ? CloudflareApi.ZonePath(zone.Id) + "/" + sub : CloudflareApi.SettingPath(zone.Id, s.Id);
        var set = _settingsCache.TryGetValue(zone.Id, out var cached) ? cached : null;
        CfResponse r;
        string extra = string.Empty;
        try
        {
            // A mode picked by hand must stick: with Automatic SSL/TLS on, Cloudflare would move it again. Switch that
            // off first (what the dashboard does when you choose a mode).
            if (s.Id == "ssl" && set?.AutoSsl is { IsLoaded: true, IsAvailable: true } auto && auto.IsOnFor(auto.Value))
            {
                var off = await api.PatchAsync(CloudflareApi.SettingPath(zone.Id, auto.Id), new JsonObject { ["value"] = auto.OffValue },
                                               CfPermission.ZoneSettingsEdit, _sessionCts.Token);
                if (!off.Success)
                {
                    s.IsBusy = false;
                    if (session != _sessionGen) return;
                    s.Revert();
                    s.Error = "Automatic SSL/TLS couldn't be turned off first: " + off.Error;
                    if (SelectedZone?.Id == zone.Id) SetError($"{s.Title} wasn't changed: {s.Error}");
                    return;
                }
                if (off.Result is JsonObject ao) auto.Load(ao); else auto.SetValue(auto.OffValue);
                extra = " Automatic SSL/TLS is off now, so it stays that way.";
            }

            r = await api.PatchAsync(path, new JsonObject { ["value"] = node }, CfPermission.ZoneSettingsEdit, _sessionCts.Token);

            // Tiered Cache comes with a topology; on every plan that's Smart Tiered Cache (as the dashboard sets it).
            if (r.Success && s.Id == "tiered_caching")
            {
                var topo = await api.PatchAsync(CloudflareApi.ZonePath(zone.Id) + "/cache/tiered_cache_smart_topology_enable",
                                                new JsonObject { ["value"] = value }, CfPermission.ZoneSettingsEdit, _sessionCts.Token);
                if (!topo.Success && value == "on") extra = " (Smart topology couldn't be turned on: " + topo.Error + ")";
            }
        }
        catch (OperationCanceledException) { s.IsBusy = false; s.Revert(); return; }
        s.IsBusy = false;
        if (session != _sessionGen) return;

        // By id: the cached settings keep the CfZone they were made for, while a zone reload (Refresh) selects a new
        // object for the same zone — compared by reference, no change made after a reload reached the status line.
        bool current = SelectedZone?.Id == zone.Id;
        if (r.Success)
        {
            if (r.Result is JsonObject o && o.ContainsKey("value")) s.Load(o);
            else s.SetValue(value);
            if (s.Id == "security_level") AfterLevelChange(zone, before, s.Value, current);
            else if (current)
                SetStatus($"{s.Title}: {Label(s)} for {zone.Name}.{extra}");
        }
        else
        {
            s.Revert();
            s.Error = PlanText(r, s.MinPlan);
            if (current) SetError($"{s.Title} wasn't changed: {s.Error}");
        }
    }

    /// <summary>A failure's text, with "needs the Pro plan" when Cloudflare refused it for the zone's plan.</summary>
    private static string PlanText(CfResponse r, int minPlan)
        => r.PlanLimited && minPlan > CfPlan.Free ? $"{r.Error} — this needs the {CfPlan.Name(minPlan)} plan or higher."
         : r.PlanLimited ? $"{r.Error} — not included in this zone's plan."
         : r.Error;

    private static string Label(CfSetting s)
        => s.IsToggle ? (s.IsOnFor(s.Value) ? "on" : "off") : s.SelectedOption?.Label ?? s.Value;

    private static string LevelLabel(CfSetting level, string value)
        => level.Options.FirstOrDefault(o => o.Value == value)?.Label ?? value;

    // ---------- under attack ----------

    /// <summary>The level turning "I'm under attack" off goes back to: the one remembered for the zone, else Medium.</summary>
    private string RestoreLevel(CfZone zone) => SelectedProfile?.PreviousLevel(zone.Id) ?? "medium";

    private Task SetUnderAttackAsync(CfZone zone, CfZoneSettings set, bool on)
    {
        if (on == (set.SecurityLevel.Value == "under_attack")) return Task.CompletedTask;
        return ApplySettingAsync(zone, set.SecurityLevel, on ? "under_attack" : RestoreLevel(zone));
    }

    private void AfterLevelChange(CfZone zone, string before, string now, bool current)
    {
        zone.UnderAttack = now == "under_attack";
        if (SelectedZone is { } z && z.Id == zone.Id) z.UnderAttack = zone.UnderAttack;
        var profile = SelectedProfile;
        if (now == "under_attack")
        {
            if (profile != null && CfProfile.IsRestorableLevel(before)) profile.SetPreviousLevel(zone.Id, before);
            if (current) SetStatus($"I'm under attack mode is on for {zone.Name}: every visitor gets a challenge page first.");
        }
        else
        {
            profile?.SetPreviousLevel(zone.Id, null);
            var set = _settingsCache.TryGetValue(zone.Id, out var cached) ? cached : null;
            string label = set is null ? now : LevelLabel(set.SecurityLevel, now);
            if (current)
                SetStatus(before == "under_attack"
                    ? $"I'm under attack mode is off for {zone.Name}: security level is {label} again."
                    : $"Security level: {label} for {zone.Name}.");
        }
        _settingsCache.TryGetValue(zone.Id, out var s2);
        s2?.UnderAttack.Sync();
    }

    // ---------- HSTS ----------

    private async Task SaveHstsAsync(CfZone zone, CfHsts h)
    {
        if (IsLocked || h.IsBusy) return;
        var api = Api(out string error);
        if (api is null) { h.Error = error; return; }
        int session = _sessionGen;
        h.IsBusy = true;
        h.Error = string.Empty;
        CfResponse r;
        try
        {
            r = await api.PatchAsync(CloudflareApi.SettingPath(zone.Id, "security_header"), new JsonObject { ["value"] = h.BuildValue() },
                                     CfPermission.ZoneSettingsEdit, _sessionCts.Token);
        }
        catch (OperationCanceledException) { h.IsBusy = false; return; }
        h.IsBusy = false;
        if (session != _sessionGen) return;
        bool current = SelectedZone?.Id == zone.Id;
        if (!r.Success)
        {
            h.Error = PlanText(r, CfPlan.Free);
            if (current) SetError("HSTS wasn't changed: " + h.Error);
            return;
        }
        if (r.Result is JsonObject o) h.Load(o);
        h.IsEditing = false;
        if (current) SetStatus($"HSTS for {zone.Name}: {h.Summary}.");
    }

    // ================================================================ purge

    [ObservableProperty] private bool _purgeAllConfirm;
    [ObservableProperty] private bool _isPurging;
    [ObservableProperty] private string _purgeUrlsText = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasPurgeUrlsError))]
    private string _purgeUrlsError = string.Empty;

    public bool HasPurgeUrlsError => PurgeUrlsError.Length > 0;

    private const int PurgeChunk = 30;      // URLs per purge request (the API's per-call limit on most plans)
    private const int MaxPurgeUrls = 3000;

    [RelayCommand]
    private void RequestPurgeAll() => PurgeAllConfirm = true;

    [RelayCommand]
    private void CancelPurgeAll() => PurgeAllConfirm = false;

    [RelayCommand]
    private async Task PurgeAll()
    {
        PurgeAllConfirm = false;
        if (IsPurging || SelectedZone is not { } zone) return;
        var api = Api(out string error);
        if (api is null) { SetError(error); return; }
        int session = _sessionGen;
        IsPurging = true;
        BeginBusy();
        SetStatus($"Purging the whole cache of {zone.Name}…");
        CfResponse r;
        try
        {
            r = await api.PostAsync(CloudflareApi.ZonePath(zone.Id) + "/purge_cache", new JsonObject { ["purge_everything"] = true },
                                    CfPermission.CachePurge, _sessionCts.Token);
        }
        catch (OperationCanceledException) { return; }
        finally
        {
            if (session == _sessionGen) IsPurging = false;
            EndBusy(session);
        }
        if (session != _sessionGen) return;
        if (r.Success) SetStatus($"Purged everything cached for {zone.Name}. Fresh copies come from your origin from now on.");
        else SetError("Purge failed: " + r.Error);
    }

    /// <summary>Purge the URLs in the box: one per line, http(s) only, on the selected zone; sent 30 at a time.</summary>
    [RelayCommand]
    private async Task PurgeUrls()
    {
        if (IsPurging || SelectedZone is not { } zone) return;
        var urls = ParsePurgeUrls(PurgeUrlsText, zone.Name, out string? problem);
        if (problem != null) { PurgeUrlsError = problem; return; }
        if (urls.Count == 0) { PurgeUrlsError = "Enter at least one URL, like https://" + zone.Name + "/style.css"; return; }
        PurgeUrlsError = string.Empty;
        var api = Api(out string error);
        if (api is null) { SetError(error); return; }

        int session = _sessionGen;
        IsPurging = true;
        BeginBusy();
        int purged = 0;
        string? failure = null;
        try
        {
            for (int i = 0; i < urls.Count; i += PurgeChunk)
            {
                var files = new JsonArray();
                foreach (var u in urls.Skip(i).Take(PurgeChunk)) files.Add((JsonNode?)JsonValue.Create(u));
                SetStatus($"Purging {Math.Min(i + PurgeChunk, urls.Count)} of {urls.Count} URLs…");
                var r = await api.PostAsync(CloudflareApi.ZonePath(zone.Id) + "/purge_cache", new JsonObject { ["files"] = files },
                                            CfPermission.CachePurge, _sessionCts.Token);
                if (session != _sessionGen) return;
                if (!r.Success) { failure = r.Error; break; }
                purged += files.Count;
            }
        }
        catch (OperationCanceledException) { return; }
        finally
        {
            if (session == _sessionGen) IsPurging = false;
            EndBusy(session);
        }
        if (failure is null)
        {
            SetStatus($"Purged {purged} URL{(purged == 1 ? "" : "s")} from the cache of {zone.Name}.");
            PurgeUrlsText = string.Empty;
        }
        else
        {
            PurgeUrlsError = (purged > 0 ? $"Purged {purged}, then: " : string.Empty) + failure;
            SetError("Purge failed: " + failure);
        }
    }

    /// <summary>The purge box: one absolute http(s) URL per line on <paramref name="zone"/> (blank lines and duplicates
    /// dropped). Anything else is reported by line number and nothing is sent.</summary>
    public static List<string> ParsePurgeUrls(string text, string zone, out string? problem)
    {
        problem = null;
        var list = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        string[] lines = (text ?? string.Empty).Split('\n');
        for (int i = 0; i < lines.Length; i++)
        {
            string line = lines[i].Trim();
            if (line.Length == 0) continue;
            string shown = line.Length > 60 ? line[..60] + "…" : line;
            if (line.Length > 2048 || line.Any(c => char.IsWhiteSpace(c) || char.IsControl(c))
                || !Uri.TryCreate(line, UriKind.Absolute, out var uri)
                || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
                || string.IsNullOrEmpty(uri.Host) || !string.IsNullOrEmpty(uri.UserInfo))
            {
                problem = $"Line {i + 1} isn't an http:// or https:// URL: {shown}";
                return new List<string>();
            }
            if (!CloudflareBackup.InZone(uri.IdnHost, zone))
            {
                problem = $"Line {i + 1} isn't on {zone}: {shown}";
                return new List<string>();
            }
            if (seen.Add(line)) list.Add(line);
            if (list.Count > MaxPurgeUrls)
            {
                problem = $"That's more than {MaxPurgeUrls} URLs. Purge everything instead, or split the list.";
                return new List<string>();
            }
        }
        return list;
    }

    // ================================================================ pause

    [ObservableProperty] private bool _pauseConfirm;
    [ObservableProperty] private bool _isPausing;

    /// <summary>Pause asks first (it exposes the origin); resume needs no confirmation.</summary>
    [RelayCommand]
    private Task RequestPause()
    {
        if (SelectedZone is not { } zone) return Task.CompletedTask;
        if (zone.Paused) return SetPausedAsync(zone, false);
        PauseConfirm = true;
        return Task.CompletedTask;
    }

    [RelayCommand]
    private void CancelPause() => PauseConfirm = false;

    [RelayCommand]
    private Task ConfirmPause()
    {
        PauseConfirm = false;
        return SelectedZone is { } zone ? SetPausedAsync(zone, true) : Task.CompletedTask;
    }

    private async Task SetPausedAsync(CfZone zone, bool paused)
    {
        if (IsPausing) return;
        var api = Api(out string error);
        if (api is null) { SetError(error); return; }
        int session = _sessionGen;
        IsPausing = true;
        BeginBusy();
        CfResponse r;
        try
        {
            r = await api.PatchAsync(CloudflareApi.ZonePath(zone.Id), new JsonObject { ["paused"] = paused },
                                     CfPermission.ZoneEdit, _sessionCts.Token);
        }
        catch (OperationCanceledException) { return; }
        finally
        {
            if (session == _sessionGen) IsPausing = false;
            EndBusy(session);
        }
        if (session != _sessionGen) return;
        if (!r.Success)
        {
            SetError((paused ? "Couldn't pause Cloudflare: " : "Couldn't resume Cloudflare: ") + r.Error);
            return;
        }
        zone.Paused = r.Result is JsonObject o && CfJson.BoolOrNull(o["paused"]) is bool p ? p : paused;
        SetStatus(zone.Paused
            ? $"Cloudflare is paused on {zone.Name}: traffic goes straight to your origin."
            : $"Cloudflare is active on {zone.Name} again.");
    }
}
