using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>A part of a zone loaded on its own when its tab opens (analytics, DNSSEC, rules…): load state + error.</summary>
public partial class CfPart : ObservableObject
{
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowContent), nameof(ShowLoading))]
    private bool _isLoading;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowContent), nameof(ShowLoading))]
    private bool _isLoaded;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasError), nameof(ShowContent))]
    private string _error = string.Empty;

    public bool HasError => Error.Length > 0;
    /// <summary>Loaded without an error: the part's content shows.</summary>
    public bool ShowContent => IsLoaded && !HasError;
    /// <summary>The first load is running (a refresh keeps the old content on screen).</summary>
    public bool ShowLoading => IsLoading && !IsLoaded;
}

/// <summary>A label + value pair the user may copy (DNSSEC's DS record fields, a new zone's name servers).</summary>
public sealed class CfField
{
    public CfField(string label, string value, bool mono = true)
    {
        Label = label;
        Value = value;
        Mono = mono;
    }

    public string Label { get; }
    public string Value { get; }
    public bool Mono { get; }
}

// ===================================================================================== under attack

/// <summary>
/// "I'm under attack" as one switch over the security_level setting: on = under_attack, off = the level the zone had
/// before (remembered per zone in the profile; Medium when unknown). Busy state and errors are the setting's own.
/// </summary>
public partial class CfUnderAttack : ObservableObject
{
    private readonly CfSetting _level;
    private bool _syncing;

    public CfUnderAttack(CfSetting level)
    {
        _level = level;
        level.PropertyChanged += (_, e) =>
        {
            switch (e.PropertyName)
            {
                case nameof(CfSetting.Value):
                case nameof(CfSetting.IsLoaded):
                    Sync();
                    break;
                case nameof(CfSetting.IsBusy):
                    // while the change runs the switch keeps showing what was asked for; afterwards the real value
                    if (!level.IsBusy) Sync();
                    OnPropertyChanged(nameof(IsBusy));
                    OnPropertyChanged(nameof(CanEdit));
                    break;
                case nameof(CfSetting.CanEdit):
                    OnPropertyChanged(nameof(CanEdit));
                    break;
                case nameof(CfSetting.Error):
                    OnPropertyChanged(nameof(Error));
                    OnPropertyChanged(nameof(HasError));
                    break;
            }
        };
    }

    /// <summary>Turns it on / off (set by the view-model).</summary>
    internal Func<bool, Task>? Request { get; set; }
    /// <summary>The label of the level "off" goes back to (for the note).</summary>
    internal Func<string>? RestoreLabel { get; set; }

    [ObservableProperty] private bool _isOn;
    [ObservableProperty] private string _note = string.Empty;

    public bool IsBusy => _level.IsBusy;
    public bool CanEdit => _level.CanEdit;
    public string Error => _level.Error;
    public bool HasError => _level.HasError;

    internal void Sync()
    {
        _syncing = true;
        try { IsOn = _level.Value == "under_attack"; }
        finally { _syncing = false; }
        Note = !_level.IsLoaded ? string.Empty
            : IsOn ? $"On now. Turning it off restores security level {RestoreLabel?.Invoke() ?? "Medium"}."
            : string.Empty;
    }

    partial void OnIsOnChanged(bool value)
    {
        if (_syncing) return;
        if (!CanEdit || Request is null)
        {
            Avalonia.Threading.Dispatcher.UIThread.Post(Sync);
            return;
        }
        _ = Request(value);
    }
}

// ===================================================================================== HSTS

/// <summary>
/// HSTS (zone setting security_header: {"strict_transport_security": {enabled, max_age, include_subdomains, preload,
/// nosniff}}). Shown as a summary; "Change" opens the fields, and widening it (turning it on, preload, subdomains, a
/// longer max-age) needs the "I understand" box, as in the dashboard.
/// </summary>
public partial class CfHsts : ObservableObject
{
    public static readonly (int Seconds, string Label)[] Ages =
    {
        (2592000, "1 month"), (5184000, "2 months"), (7776000, "3 months"), (10368000, "4 months"),
        (12960000, "5 months"), (15552000, "6 months"), (31536000, "12 months"),
    };

    public CfHsts()
    {
        foreach (var (s, l) in Ages) MaxAgeOptions.Add(new CfOption(s.ToString(CultureInfo.InvariantCulture), l));
    }

    // what the API last confirmed
    public bool Enabled { get; private set; }
    public int MaxAge { get; private set; }
    public bool IncludeSubdomains { get; private set; }
    public bool Preload { get; private set; }
    public bool Nosniff { get; private set; }

    public ObservableCollection<CfOption> MaxAgeOptions { get; } = new();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanChange), nameof(ShowNotAvailable))]
    private bool _isLoaded;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanChange), nameof(ShowNotAvailable))]
    private bool _isAvailable = true;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanChange))]
    private bool _isEditable = true;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanChange), nameof(CanSave))]
    private bool _isBusy;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanChange))]
    private bool _isEditing;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasError))]
    private string _error = string.Empty;

    [ObservableProperty] private string _summary = "Loading…";
    [ObservableProperty] private bool _isOn;

    // the editor
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(NeedsAcknowledge), nameof(CanSave))]
    private bool _editEnabled;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(NeedsAcknowledge), nameof(CanSave))]
    private CfOption? _editMaxAge;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(NeedsAcknowledge), nameof(CanSave))]
    private bool _editSubdomains;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(NeedsAcknowledge), nameof(CanSave))]
    private bool _editPreload;

    [ObservableProperty] private bool _editNosniff;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanSave))]
    private bool _acknowledged;

    public bool HasError => Error.Length > 0;
    public bool ShowNotAvailable => IsLoaded && !IsAvailable;
    public bool CanChange => IsLoaded && IsAvailable && IsEditable && !IsBusy && !IsEditing;

    private int EditAgeSeconds => int.TryParse(EditMaxAge?.Value, NumberStyles.None, CultureInfo.InvariantCulture, out int s) ? s : 0;

    /// <summary>The edit makes browsers insist on HTTPS more (on, longer, subdomains, preload): "I understand" first.</summary>
    public bool NeedsAcknowledge => EditEnabled && (!IsOn || EditAgeSeconds > MaxAge || (EditSubdomains && !IncludeSubdomains) || (EditPreload && !Preload));
    public bool CanSave => !IsBusy && (!NeedsAcknowledge || Acknowledged);

    /// <summary>Saves the editor (set by the view-model).</summary>
    internal Func<CfHsts, Task>? Save { get; set; }

    internal void Load(JsonObject setting)
    {
        var sts = setting["value"]?["strict_transport_security"];
        Enabled = CfJson.Bool(sts?["enabled"]);
        MaxAge = CfJson.Int(sts?["max_age"]) ?? 0;
        IncludeSubdomains = CfJson.Bool(sts?["include_subdomains"]);
        Preload = CfJson.Bool(sts?["preload"]);
        Nosniff = CfJson.Bool(sts?["nosniff"]);
        IsEditable = CfJson.BoolOrNull(setting["editable"]) ?? true;
        IsAvailable = true;
        IsLoaded = true;
        Error = string.Empty;
        Refresh();
    }

    internal void MarkUnavailable()
    {
        IsAvailable = false;
        IsLoaded = true;
        Summary = "Not available on this zone.";
    }

    private void Refresh()
    {
        IsOn = Enabled && MaxAge > 0;
        var parts = new List<string>();
        if (IsOn)
        {
            parts.Add("On, max-age " + AgeText(MaxAge));
            if (IncludeSubdomains) parts.Add("includes subdomains");
            if (Preload) parts.Add("preload");
        }
        else parts.Add("Off");
        if (Nosniff) parts.Add("no-sniff header");
        Summary = string.Join(" · ", parts);
    }

    public static string AgeText(int seconds)
    {
        foreach (var (s, l) in Ages) if (s == seconds) return l;
        if (seconds <= 0) return "0";
        if (seconds % 86400 == 0) return seconds / 86400 == 1 ? "1 day" : $"{seconds / 86400} days";
        return $"{seconds} seconds";
    }

    [RelayCommand]
    private void BeginEdit()
    {
        if (!CanChange) return;
        EditEnabled = IsOn || !Enabled;   // "Change" on an off policy proposes turning it on
        string want = (IsOn ? MaxAge : 15552000).ToString(CultureInfo.InvariantCulture);
        var opt = MaxAgeOptions.FirstOrDefault(o => o.Value == want);
        if (opt is null)
        {
            opt = new CfOption(want, AgeText(MaxAge));
            MaxAgeOptions.Add(opt);
        }
        EditMaxAge = opt;
        EditSubdomains = IncludeSubdomains;
        EditPreload = Preload;
        EditNosniff = Nosniff;
        Acknowledged = false;
        Error = string.Empty;
        IsEditing = true;
    }

    [RelayCommand]
    private void CancelEdit()
    {
        IsEditing = false;
        Acknowledged = false;
    }

    [RelayCommand]
    private Task SaveEdit() => CanSave && Save != null ? Save(this) : Task.CompletedTask;

    /// <summary>The value the editor describes. Off = enabled false with max_age 0 (what the dashboard's "Disable" sends).</summary>
    internal JsonObject BuildValue() => new()
    {
        ["strict_transport_security"] = new JsonObject
        {
            ["enabled"] = EditEnabled,
            ["max_age"] = EditEnabled ? EditAgeSeconds : 0,
            ["include_subdomains"] = EditEnabled && EditSubdomains,
            ["preload"] = EditEnabled && EditPreload,
            ["nosniff"] = EditNosniff,
        },
    };
}

// ===================================================================================== analytics

public sealed class CfCountryRow
{
    public string Code { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public string Requests { get; init; } = string.Empty;
    /// <summary>Share of all requests, 0..1 (the row's bar).</summary>
    public double Share { get; init; }
    public string ShareText { get; init; } = string.Empty;
}

/// <summary>One range of the zone's traffic summary (last 24 hours or last 7 days).</summary>
public partial class CfAnalytics : CfPart
{
    public CfAnalytics(bool week) => Week = week;

    public bool Week { get; }

    [ObservableProperty] private string _requests = "–";
    [ObservableProperty] private string _cached = "–";
    [ObservableProperty] private string _cachedSub = string.Empty;
    [ObservableProperty] private string _bandwidth = "–";
    [ObservableProperty] private string _bandwidthSub = string.Empty;
    [ObservableProperty] private string _threats = "–";
    [ObservableProperty] private string _visitors = "–";
    [ObservableProperty] private string _pageViews = "–";
    [ObservableProperty] private IReadOnlyList<long> _bars = Array.Empty<long>();
    [ObservableProperty] private string _barsStart = string.Empty;
    [ObservableProperty] private string _barsEnd = string.Empty;
    [ObservableProperty] private string _barsPeak = string.Empty;
    [ObservableProperty] private bool _hasCountries;
    [ObservableProperty] private bool _noTraffic;
    public ObservableCollection<CfCountryRow> Countries { get; } = new();
    internal DateTime LoadedUtc;

    internal void Apply(CloudflareAnalytics.Summary s)
    {
        Requests = CloudflareAnalytics.Count(s.Requests);
        Cached = CloudflareAnalytics.Percent(s.CachedRequests, s.Requests);
        CachedSub = CloudflareAnalytics.Count(s.CachedRequests) + " served from cache";
        Bandwidth = CloudflareAnalytics.Bytes(s.Bytes);
        BandwidthSub = CloudflareAnalytics.Percent(s.CachedBytes, s.Bytes) + " from cache";
        Threats = CloudflareAnalytics.Count(s.Threats);
        Visitors = CloudflareAnalytics.Count(s.Uniques);
        PageViews = CloudflareAnalytics.Count(s.PageViews);
        NoTraffic = s.Requests == 0;

        // A bucket per hour / day over the whole range, gaps (no traffic) included.
        var bars = new List<long>();
        if (s.Week)
        {
            DateTime today = DateTime.UtcNow.Date;
            for (int d = 6; d >= 0; d--)
            {
                DateTime day = today.AddDays(-d);
                bars.Add(s.Series.Where(b => b.Start.Date == day).Sum(b => b.Requests));
            }
            BarsStart = today.AddDays(-6).ToString("ddd d MMM", CultureInfo.InvariantCulture);
            BarsEnd = "Today";
        }
        else
        {
            DateTime now = DateTime.UtcNow;
            DateTime hour = new(now.Year, now.Month, now.Day, now.Hour, 0, 0, DateTimeKind.Utc);
            for (int h = 23; h >= 0; h--)
            {
                DateTime at = hour.AddHours(-h);
                bars.Add(s.Series.Where(b => b.Start == at).Sum(b => b.Requests));
            }
            BarsStart = hour.AddHours(-23).ToLocalTime().ToString("HH:mm", CultureInfo.InvariantCulture);
            BarsEnd = "Now";
        }
        Bars = bars;
        long peak = bars.Count > 0 ? bars.Max() : 0;
        BarsPeak = peak > 0 ? "Peak " + CloudflareAnalytics.Count(peak) + (s.Week ? " a day" : " an hour") : string.Empty;

        Countries.Clear();
        foreach (var c in s.Countries.Take(6))
        {
            double share = s.Requests > 0 ? (double)c.Requests / s.Requests : 0;
            Countries.Add(new CfCountryRow
            {
                Code = c.Code,
                Name = CloudflareCountries.Name(c.Code),
                Requests = CloudflareAnalytics.Count(c.Requests),
                Share = Math.Clamp(share, 0, 1),
                ShareText = CloudflareAnalytics.Percent(c.Requests, s.Requests),
            });
        }
        HasCountries = Countries.Count > 0;
    }
}

// ===================================================================================== DNSSEC

public partial class CfDnssec : CfPart
{
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusText), nameof(IsActive), nameof(IsPending), nameof(IsOff), nameof(IsError),
                              nameof(CanEnable), nameof(CanDisable), nameof(Explanation), nameof(IsPendingOff))]
    private string _status = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanEnable), nameof(CanDisable))]
    private bool _isBusy;

    [ObservableProperty] private bool _confirmDisable;

    public ObservableCollection<CfField> Fields { get; } = new();
    public bool HasFields => Fields.Count > 0;
    public string Ds { get; private set; } = string.Empty;
    /// <summary>What the numbers stand for ("Algorithm 13 = ECDSAP256SHA256 …"), for registrars that ask by name.</summary>
    [ObservableProperty] private string _hint = string.Empty;

    public bool IsActive => Status == "active";
    public bool IsPending => Status == "pending";
    public bool IsPendingOff => Status == "pending-disabled";
    public bool IsOff => Status is "disabled" or "";
    public bool IsError => Status == "error";
    public bool CanEnable => IsLoaded && !IsBusy && (IsOff || IsError || IsPendingOff);
    public bool CanDisable => IsLoaded && !IsBusy && (IsActive || IsPending);

    public string StatusText => Status switch
    {
        "active" => "Active",
        "pending" => "Pending",
        "pending-disabled" => "Turning off",
        "error" => "Error",
        "disabled" => "Off",
        "" => "Unknown",
        _ => Status,
    };

    public string Explanation => Status switch
    {
        "active" => "On: resolvers can verify this zone's answers really come from Cloudflare.",
        "pending" => "Cloudflare signs the zone. Add the DS record below at your registrar to finish (active within about a day).",
        "pending-disabled" => "Turning off. Make sure the DS record is gone from your registrar.",
        "error" => "The DS record at your registrar doesn't match. Update it with the values below.",
        _ => "Signs every DNS answer so resolvers can spot forged ones. Once it's on, add one DS record at your registrar.",
    };

    internal void Load(JsonNode? result)
    {
        Status = CfJson.Str(result?["status"]);
        Ds = CfJson.Str(result?["ds"]);
        Fields.Clear();
        void Add(string label, JsonNode? n, bool mono = true)
        {
            string v = n is JsonValue ? CfJson.ValueText(n) : string.Empty;
            if (v.Length > 0) Fields.Add(new CfField(label, v, mono));
        }
        Add("DS record", result?["ds"]);
        Add("Key tag", result?["key_tag"]);
        Add("Algorithm", result?["algorithm"]);
        Add("Digest type", result?["digest_type"]);
        Add("Digest", result?["digest"]);
        Add("Public key", result?["public_key"]);
        Add("Flags", result?["flags"]);
        OnPropertyChanged(nameof(HasFields));

        var names = new List<string>();
        string alg = CfJson.ValueText(result?["algorithm"]), keyType = CfJson.Str(result?["key_type"]);
        string dt = CfJson.ValueText(result?["digest_type"]), digestAlg = CfJson.Str(result?["digest_algorithm"]);
        if (alg.Length > 0 && keyType.Length > 0) names.Add($"algorithm {alg} is {keyType}");
        if (dt.Length > 0 && digestAlg.Length > 0) names.Add($"digest type {dt} is {digestAlg}");
        if (CfJson.Int(result?["flags"]) == 257) names.Add("flags 257 mark the key-signing key");
        Hint = names.Count == 0 ? string.Empty : char.ToUpperInvariant(names[0][0]) + string.Join(", ", names)[1..] + ".";
        Error = string.Empty;
        IsLoaded = true;
        // Status changed above while IsLoaded was still false: the on / off buttons must re-read it now
        OnPropertyChanged(nameof(CanEnable));
        OnPropertyChanged(nameof(CanDisable));
    }
}

// ===================================================================================== edge certificates

public sealed class CfCertPack
{
    public string Type { get; init; } = string.Empty;
    public string Hosts { get; init; } = string.Empty;
    public string Status { get; init; } = string.Empty;
    public bool IsActive { get; init; }
    public bool IsWarning { get; init; }
    public bool IsBad { get; init; }
    public string Details { get; init; } = string.Empty;
    public bool ExpiresSoon { get; init; }

    public static CfCertPack? FromApi(JsonNode? n)
    {
        if (n is not JsonObject o) return null;
        string type = CfJson.Str(o["type"]);
        string status = CfJson.Str(o["status"]);
        var hosts = CfJson.StrList(o["hosts"]);

        // the pack's soonest expiry among its certificates
        DateTimeOffset? expires = null;
        string issuer = string.Empty;
        if (o["certificates"] is JsonArray certs)
            foreach (var c in certs)
            {
                if (DateTimeOffset.TryParse(CfJson.Str(c?["expires_on"]), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var e)
                    && (expires is null || e < expires)) expires = e;
                if (issuer.Length == 0) issuer = CfJson.Str(c?["issuer"]);
            }
        string ca = CfJson.Str(o["certificate_authority"]) switch
        {
            "lets_encrypt" => "Let's Encrypt",
            "google" => "Google Trust Services",
            "ssl_com" => "SSL.com",
            "digicert" => "DigiCert",
            "sectigo" => "Sectigo",
            "" => issuer,
            var other => other,
        };

        var parts = new List<string>();
        if (ca.Length > 0) parts.Add(ca);
        bool soon = false;
        if (expires is { } exp)
        {
            int days = (int)Math.Floor((exp - DateTimeOffset.UtcNow).TotalDays);
            soon = days < 14;
            parts.Add(days < 0 ? $"expired {exp.ToLocalTime():yyyy-MM-dd}"
                : $"expires {exp.ToLocalTime():yyyy-MM-dd} ({(days == 0 ? "today" : days == 1 ? "in 1 day" : $"in {days} days")})");
        }
        if (CfJson.Int(o["validity_days"]) is int vd) parts.Add($"{vd}-day certificates");

        bool active = status is "active" or "staging_active";
        bool bad = status.Contains("timed_out", StringComparison.Ordinal) || status is "expired" or "deleted" or "inactive"
                   || status.Contains("fail", StringComparison.Ordinal);
        return new CfCertPack
        {
            Type = type switch
            {
                "universal" => "Universal",
                "advanced" => "Advanced",
                "total_tls" => "Total TLS",
                "sni_custom" or "legacy_custom" => "Custom",
                "keyless" => "Keyless",
                "mh_custom" or "managed_hostname" => "Custom hostname",
                "" => "Certificate",
                _ => type,
            },
            Hosts = hosts.Count == 0 ? "(no hosts)" : string.Join(", ", hosts.Take(6)) + (hosts.Count > 6 ? $" +{hosts.Count - 6}" : string.Empty),
            Status = status.Length == 0 ? "Unknown" : char.ToUpperInvariant(status[0]) + status[1..].Replace('_', ' '),
            IsActive = active,
            IsBad = bad,
            IsWarning = !active && !bad,
            Details = string.Join(" · ", parts),
            ExpiresSoon = soon && active,
        };
    }
}

public partial class CfCertificates : CfPart
{
    public CfCertificates(CfSetting universal) => Universal = universal;

    public ObservableCollection<CfCertPack> Packs { get; } = new();
    /// <summary>Universal SSL (ssl/universal/settings {"enabled"}); turning it off asks first.</summary>
    public CfSetting Universal { get; }
    public ObservableCollection<CfSetting> UniversalRow { get; } = new();
    [ObservableProperty] private bool _hasPacks;
    [ObservableProperty] private string _packsError = string.Empty;
}

// ===================================================================================== bots

/// <summary>Bot settings (GET / PUT /zones/{id}/bot_management). Which switch there is depends on the plan's variant:
/// Bot Fight Mode (fight_mode) or Super Bot Fight Mode (sbfm_definitely_automated); Enterprise Bot Management is
/// managed elsewhere. Blocking AI crawlers (ai_bots_protection) is on every plan.</summary>
public partial class CfBot : CfPart
{
    public ObservableCollection<CfSetting> Rows { get; } = new();
    [ObservableProperty] private string _note = string.Empty;
    public bool HasNote => Note.Length > 0;
    partial void OnNoteChanged(string value) => OnPropertyChanged(nameof(HasNote));
}

// ===================================================================================== IP access rules

public partial class CfAccessRule : ObservableObject
{
    public string Id { get; init; } = string.Empty;
    public string Mode { get; init; } = string.Empty;
    public string Target { get; init; } = string.Empty;
    public string Value { get; init; } = string.Empty;
    public string Notes { get; init; } = string.Empty;
    public string Created { get; init; } = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsIdle))]
    private bool _isBusy;

    [ObservableProperty] private bool _pendingDelete;

    public bool IsIdle => !IsBusy;
    public string ModeText => CloudflareRules.AccessModeLabel(Mode);
    public bool IsBlock => Mode == "block";
    public bool IsAllow => Mode == "whitelist";
    public bool IsChallenge => !IsBlock && !IsAllow;
    public string TargetText => CloudflareRules.AccessTargetLabel(Target);
    public string ValueText => Target == "country" ? $"{Value} · {CloudflareCountries.Name(Value)}" : Value;
    public bool HasNotes => Notes.Length > 0;
    public string Meta => HasNotes ? $"{TargetText} · {Notes}" : TargetText;

    public static CfAccessRule? FromApi(JsonNode? n)
    {
        if (n is not JsonObject o) return null;
        string id = CfJson.Str(o["id"]);
        if (!CloudflareApi.IsId(id)) return null;
        return new CfAccessRule
        {
            Id = id.ToLowerInvariant(),
            Mode = CfJson.Str(o["mode"]),
            Target = CfJson.Str(o["configuration"]?["target"]),
            Value = CfJson.Str(o["configuration"]?["value"]),
            Notes = CfJson.Str(o["notes"]),
            Created = CfJson.Str(o["created_on"]),
        };
    }
}

public partial class CfAccessRules : CfPart
{
    public ObservableCollection<CfAccessRule> Rules { get; } = new();
    [ObservableProperty] private string _countText = string.Empty;
    [ObservableProperty] private bool _isEmpty;

    internal void Changed()
    {
        CountText = Rules.Count == 0 ? string.Empty : Rules.Count == 1 ? "1 rule" : $"{Rules.Count} rules";
        IsEmpty = IsLoaded && !HasError && Rules.Count == 0;
    }
}

// ===================================================================================== WAF custom rules + redirects

public partial class CfRule : ObservableObject
{
    private bool _syncing;

    public CfRule(CloudflareRules.Rule r) => Update(r);

    public string Id { get; private set; } = string.Empty;
    public string Description { get; private set; } = string.Empty;
    public string Expression { get; private set; } = string.Empty;
    public string Action { get; private set; } = string.Empty;
    public JsonObject Raw { get; private set; } = new();
    public string Target { get; private set; } = string.Empty;
    public int StatusCode { get; private set; }
    public bool PreserveQuery { get; private set; }

    /// <summary>The rule's switch (bound two-way): a change goes to <see cref="Toggle"/>.</summary>
    [ObservableProperty] private bool _enabled;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsIdle))]
    private bool _isBusy;

    [ObservableProperty] private bool _pendingDelete;

    internal Func<CfRule, bool, Task>? Toggle { get; set; }

    public bool IsIdle => !IsBusy;
    public string Title => Description.Length > 0 ? Description : "Rule without a name";
    public string ActionText => Action == "redirect" ? StatusCode.ToString(CultureInfo.InvariantCulture) : CloudflareRules.ActionLabel(Action);
    public bool IsBlock => Action == "block";
    public bool IsSkip => Action is "skip" or "log";
    public bool IsChallenge => Action is "managed_challenge" or "js_challenge" or "challenge";
    public bool IsRedirect => Action == "redirect";
    /// <summary>The second line: the expression (custom rules) or "→ target" (redirects).</summary>
    public string Detail => IsRedirect ? "→ " + Target : Expression;

    internal void Update(CloudflareRules.Rule r)
    {
        Id = r.Id;
        Description = r.Description;
        Expression = r.Expression;
        Action = r.Action;
        Raw = r.Raw;
        Target = r.Target;
        StatusCode = r.StatusCode;
        PreserveQuery = r.PreserveQuery;
        SetEnabled(r.Enabled);
        foreach (var p in new[] { nameof(Title), nameof(ActionText), nameof(IsBlock), nameof(IsSkip), nameof(IsChallenge),
                                  nameof(IsRedirect), nameof(Detail), nameof(Description), nameof(Expression) })
            OnPropertyChanged(p);
    }

    internal void SetEnabled(bool on)
    {
        _syncing = true;
        try { Enabled = on; }
        finally { _syncing = false; }
    }

    partial void OnEnabledChanged(bool value)
    {
        if (_syncing) return;
        if (IsBusy || Toggle is null)
        {
            bool back = !value;
            Avalonia.Threading.Dispatcher.UIThread.Post(() => SetEnabled(back));
            return;
        }
        _ = Toggle(this, value);
    }
}

public partial class CfRuleList : CfPart
{
    public CfRuleList(string phase) => Phase = phase;

    public string Phase { get; }
    public bool IsRedirects => Phase == CloudflareApi.PhaseRedirect;
    /// <summary>The phase's entry point ruleset; empty while the zone has none (no rule added yet).</summary>
    public string RulesetId { get; set; } = string.Empty;
    public ObservableCollection<CfRule> Rules { get; } = new();
    public int Quota { get; set; }
    public string PlanName { get; set; } = string.Empty;
    [ObservableProperty] private string _countText = string.Empty;
    [ObservableProperty] private bool _isEmpty;

    public string EmptyText => IsRedirects
        ? "No redirect rules yet. They send visitors from one URL to another (www to the root, an old page to a new one)."
        : "No custom rules yet. They block or challenge matching requests (a country, an IP range, the login page).";

    internal void Changed()
    {
        string what = IsRedirects ? "redirect rules" : "custom rules";
        CountText = !IsLoaded || HasError ? string.Empty
            : Quota > 0 ? $"{Rules.Count} of {Quota} {what} ({PlanName} plan)"
            : $"{Rules.Count} {what}";
        IsEmpty = IsLoaded && !HasError && Rules.Count == 0;
    }
}

/// <summary>Everything about one zone besides records and settings, each part loaded when its tab first opens.</summary>
public sealed class CfZoneExtras
{
    public CfZoneExtras(string zoneId, CfSetting universal)
    {
        ZoneId = zoneId;
        Certificates = new CfCertificates(universal);
        Certificates.UniversalRow.Add(universal);
    }

    public string ZoneId { get; }
    public CfAnalytics Day { get; } = new(week: false);
    public CfAnalytics Week { get; } = new(week: true);
    public CfDnssec Dnssec { get; } = new();
    public CfCertificates Certificates { get; }
    public CfBot Bot { get; } = new();
    public CfAccessRules Access { get; } = new();
    public CfRuleList Waf { get; } = new(CloudflareApi.PhaseFirewallCustom);
    public CfRuleList Redirects { get; } = new(CloudflareApi.PhaseRedirect);
}
