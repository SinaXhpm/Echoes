using CommunityToolkit.Mvvm.ComponentModel;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>A Cloudflare zone (domain) as the zones API describes it.</summary>
public partial class CfZone : ObservableObject
{
    public string Id { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    /// <summary>active · pending · initializing · moved · deleted.</summary>
    public string Status { get; init; } = string.Empty;
    public string PlanName { get; init; } = string.Empty;
    /// <summary>The plan's legacy id: free · pro · business · enterprise.</summary>
    public string PlanId { get; init; } = string.Empty;
    /// <summary>The Cloudflare name servers assigned to the zone.</summary>
    public IReadOnlyList<string> NameServers { get; init; } = Array.Empty<string>();
    /// <summary>The account the zone belongs to (where a new zone can be added).</summary>
    public string AccountId { get; init; } = string.Empty;
    public string AccountName { get; init; } = string.Empty;
    public int PlanRank => CfPlan.Rank(PlanId, PlanName);

    /// <summary>The security level is "I'm under attack" (the badge on the zone line; known once settings loaded).</summary>
    [ObservableProperty] private bool _underAttack;

    /// <summary>DNSSEC status for the zone line's chip: "" (not read yet) · active · pending · disabled · pending-disabled · error.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DnssecText), nameof(DnssecOn), nameof(DnssecPending), nameof(HasDnssecStatus))]
    private string _dnssecStatus = string.Empty;

    public bool HasDnssecStatus => DnssecStatus.Length > 0;
    public bool DnssecOn => DnssecStatus == "active";
    public bool DnssecPending => DnssecStatus is "pending" or "pending-disabled" or "error";
    public string DnssecText => DnssecStatus switch
    {
        "active" => "DNSSEC on",
        "pending" => "DNSSEC pending",
        "pending-disabled" => "DNSSEC turning off",
        "error" => "DNSSEC error",
        "" => "DNSSEC",
        _ => "DNSSEC off",
    };

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusText), nameof(IsActive), nameof(IsPending), nameof(IsInactive), nameof(IsWarning))]
    private bool _paused;

    public string StatusText => Paused ? "Paused" : Status switch
    {
        "active" => "Active",
        "pending" => "Pending",
        "initializing" => "Initializing",
        "moved" => "Moved",
        "deleted" => "Deleted",
        "" => "Unknown",
        _ => char.ToUpperInvariant(Status[0]) + Status[1..],
    };

    public bool IsActive => !Paused && Status == "active";
    public bool IsPending => !Paused && Status is "pending" or "initializing";
    /// <summary>Badge tone: pending or paused (amber) vs. moved / deleted (red).</summary>
    public bool IsWarning => IsPending || Paused;
    public bool IsInactive => !IsActive && !IsWarning;
    public bool IsFreePlan => PlanId == "free" || PlanName.StartsWith("Free", StringComparison.OrdinalIgnoreCase);
    public string PlanText => PlanName.Length > 0 ? PlanName : "Unknown plan";
    public bool HasNameServers => NameServers.Count > 0;
    public string NameServersText => string.Join("   ", NameServers);
    // One item each, so the zone line can wrap between them on a phone (Cloudflare assigns two).
    public string NameServer1 => NameServers.Count > 0 ? NameServers[0] : string.Empty;
    public string NameServer2 => NameServers.Count > 1 ? NameServers[1] : string.Empty;
    public string MoreNameServers => NameServers.Count > 2 ? $"+{NameServers.Count - 2}" : string.Empty;

    public override string ToString() => Name;

    public static CfZone? FromApi(JsonNode? n)
    {
        if (n is not JsonObject o) return null;
        string id = CfJson.Str(o["id"]);
        if (!CloudflareApi.IsId(id)) return null;
        return new CfZone
        {
            Id = id.ToLowerInvariant(),
            Name = CfJson.Str(o["name"]),
            Status = CfJson.Str(o["status"]),
            Paused = CfJson.Bool(o["paused"]),
            PlanName = CfJson.Str(o["plan"]?["name"]),
            PlanId = CfJson.Str(o["plan"]?["legacy_id"]),
            NameServers = CfJson.StrList(o["name_servers"]),
            AccountId = CloudflareApi.IsId(CfJson.Str(o["account"]?["id"])) ? CfJson.Str(o["account"]?["id"]).ToLowerInvariant() : string.Empty,
            AccountName = CfJson.Str(o["account"]?["name"]),
        };
    }
}

/// <summary>One DNS record. The list rows bind to it; edits update it in place.</summary>
public partial class CfRecord : ObservableObject
{
    public string Id { get; init; } = string.Empty;
    public string Type { get; init; } = string.Empty;

    [ObservableProperty] private string _name = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DisplayContent))]
    private string _content = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TtlText))]
    private int _ttl = 1;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ProxiedText), nameof(TtlText))]
    private bool _proxied;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DisplayContent))]
    private int? _priority;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasComment))]
    private string _comment = string.Empty;

    /// <summary>A request for this row is running (the proxied pill and row actions are disabled meanwhile).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsIdle))]
    private bool _isBusy;

    /// <summary>The inline "delete this record?" confirmation is showing.</summary>
    [ObservableProperty] private bool _pendingDelete;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanProxy), nameof(ShowDnsOnly))]
    private bool _proxiable;

    /// <summary>Structured value (CAA, SRV, HTTPS, …), detached from the response it came in.</summary>
    public JsonObject? Data { get; set; }
    public List<string>? Tags { get; set; }

    public bool IsIdle => !IsBusy;
    public bool CanProxy => Proxiable && CloudflareBackup.Proxiable(Type);
    public bool ShowDnsOnly => !CanProxy;
    public string ProxiedText => Proxied ? "Proxied" : "DNS only";
    public string TtlText => Proxied || Ttl <= 1 ? "Auto" : CloudflareBackup.TtlText(Ttl);
    public string DisplayContent => CloudflareBackup.UsesPriority(Type) && Priority is int p
        ? p.ToString(CultureInfo.InvariantCulture) + "  " + Content
        : Content;
    public bool HasComment => Comment.Length > 0;

    public static CfRecord? FromApi(JsonNode? n)
    {
        if (n is not JsonObject o) return null;
        string id = CfJson.Str(o["id"]);
        if (!CloudflareApi.IsId(id)) return null;
        string type = CfJson.Str(o["type"]).ToUpperInvariant();
        var proxiable = CfJson.BoolOrNull(o["proxiable"]);
        return new CfRecord
        {
            Id = id.ToLowerInvariant(),
            Type = type,
            Name = CfJson.Str(o["name"]),
            Content = CfJson.Str(o["content"]),
            Ttl = CfJson.Int(o["ttl"]) ?? 1,
            Proxied = CfJson.Bool(o["proxied"]),
            Proxiable = proxiable ?? CloudflareBackup.Proxiable(type),
            Priority = CfJson.Int(o["priority"]),
            Comment = CfJson.Str(o["comment"]),
            Data = (o["data"] as JsonObject)?.DeepClone() as JsonObject,
            Tags = o["tags"] is JsonArray ? CfJson.StrList(o["tags"]) : null,
        };
    }

    /// <summary>Take the values of <paramref name="r"/> (the API's answer to an edit) without replacing the row.</summary>
    public void CopyFrom(CfRecord r)
    {
        Name = r.Name;
        Content = r.Content;
        Ttl = r.Ttl;
        Proxied = r.Proxied;
        Priority = r.Priority;
        Comment = r.Comment;
        Proxiable = r.Proxiable;
        Data = r.Data;
        Tags = r.Tags;
    }

    /// <summary>The backup form of this record: whitelisted fields only (no id, zone id or timestamps).</summary>
    public CloudflareBackup.Entry ToEntry() => new()
    {
        Type = Type,
        Name = Name,
        Content = Content,
        Ttl = Ttl,
        Proxied = Proxied,
        Priority = CloudflareBackup.UsesPriority(Type) ? Priority : null,
        Data = CloudflareBackup.CleanData(Data),
        Comment = HasComment ? Comment : null,
        Tags = Tags is { Count: > 0 } ? new List<string>(Tags) : null,
    };

    public CloudflareBackup.Existing ToExisting() => new()
    {
        Id = Id, Type = Type, Name = Name, Content = Content, Ttl = Ttl, Proxied = Proxied,
        Priority = Priority, Comment = HasComment ? Comment : null,
    };
}

/// <summary>A named Cloudflare connection profile: one set of credentials + its proxy.</summary>
public partial class CfProfile : ObservableObject
{
    [ObservableProperty] private string _name = "Profile";
    // Auth — true: API Token (Bearer); false: Global API Key + email
    [ObservableProperty] private bool _useApiToken = true;
    [ObservableProperty] private string _apiToken = string.Empty;
    [ObservableProperty] private string _apiEmail = string.Empty;
    [ObservableProperty] private string _apiKey = string.Empty;
    // Proxy (per profile)
    [ObservableProperty] private bool _useProxy;
    [ObservableProperty] private string _proxyAddress = string.Empty;
    [ObservableProperty] private string _proxyUser = string.Empty;
    [ObservableProperty] private string _proxyPass = string.Empty;
    /// <summary>The zone (id) last opened with this profile; reselected after the next unlock. Empty = none.</summary>
    [ObservableProperty] private string _lastZone = string.Empty;
    /// <summary>The security level each zone had before "I'm under attack" was turned on here ("zoneId=level;…"), so
    /// turning it off restores it — also after the app restarted. Saved inside the vault with the profile.</summary>
    [ObservableProperty] private string _underAttackPrevious = string.Empty;

    public bool HasCredentials => UseApiToken
        ? !string.IsNullOrWhiteSpace(ApiToken)
        : !string.IsNullOrWhiteSpace(ApiEmail) && !string.IsNullOrWhiteSpace(ApiKey);

    /// <summary>The sign-in method as the account form's segmented picker sees it: 0 = API token, 1 = Global API key.</summary>
    public int AuthIndex
    {
        get => UseApiToken ? 0 : 1;
        set { if (value is 0 or 1) UseApiToken = value == 0; }
    }

    partial void OnUseApiTokenChanged(bool value) => OnPropertyChanged(nameof(AuthIndex));

    /// <summary>The levels a zone can go back to (anything else in the saved text is ignored).</summary>
    public static bool IsRestorableLevel(string level) => level is "off" or "essentially_off" or "low" or "medium" or "high";

    public string? PreviousLevel(string zoneId)
    {
        foreach (string part in UnderAttackPrevious.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = part.IndexOf('=');
            if (eq > 0 && part[..eq] == zoneId && IsRestorableLevel(part[(eq + 1)..])) return part[(eq + 1)..];
        }
        return null;
    }

    public void SetPreviousLevel(string zoneId, string? level)
    {
        var keep = new List<string>();
        foreach (string part in UnderAttackPrevious.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = part.IndexOf('=');
            if (eq <= 0 || part[..eq] == zoneId || !CloudflareApi.IsId(part[..eq]) || !IsRestorableLevel(part[(eq + 1)..])) continue;
            keep.Add(part);
        }
        // At most 50 zones are remembered, the oldest dropped first. (Keeping the FIRST 50 dropped the newest entry
        // instead, on every change once the list was full: that zone came back from "I'm under attack" at Medium.)
        bool add = level != null && CloudflareApi.IsId(zoneId) && IsRestorableLevel(level);
        int max = add ? 49 : 50;
        if (keep.Count > max) keep.RemoveRange(0, keep.Count - max);
        if (add) keep.Add(zoneId + "=" + level);
        UnderAttackPrevious = string.Join(";", keep);
    }

    public override string ToString() => string.IsNullOrWhiteSpace(Name) ? "(unnamed)" : Name;
}

/// <summary>One choice of a setting (value as the API knows it + its label).</summary>
public sealed class CfOption
{
    public CfOption(string value, string label)
    {
        Value = value;
        Label = label;
    }

    public string Value { get; }
    public string Label { get; }
    public override string ToString() => Label;
}

public enum CfSettingKind { Toggle, Choice, Segmented }

/// <summary>Cloudflare plans in order (a feature's minimum plan is compared with the zone's).</summary>
public static class CfPlan
{
    public const int Free = 0, Pro = 1, Business = 2, Enterprise = 3;

    public static int Rank(string legacyId, string name) => legacyId switch
    {
        "pro" => Pro,
        "business" => Business,
        "enterprise" => Enterprise,
        "free" => Free,
        _ => name.StartsWith("Enterprise", StringComparison.OrdinalIgnoreCase) ? Enterprise
           : name.StartsWith("Business", StringComparison.OrdinalIgnoreCase) ? Business
           : name.StartsWith("Pro", StringComparison.OrdinalIgnoreCase) ? Pro
           : Free,
    };

    public static string Name(int rank) => rank switch { Pro => "Pro", Business => "Business", Enterprise => "Enterprise", _ => "Free" };
}

/// <summary>
/// One zone setting row (SSL mode, ECH, HTTP/3, …). A change made in the UI is applied right away through
/// <see cref="Apply"/> (set by the view-model); on failure the view-model calls <see cref="Revert"/>.
/// Also used for the switches that live on other endpoints (Tiered Cache, Universal SSL, Bot Fight Mode): only their
/// <see cref="Apply"/> differs.
/// </summary>
public partial class CfSetting : ObservableObject
{
    public CfSetting(string id, string title, string description, CfSettingKind kind,
                     IEnumerable<CfOption>? options = null, bool numeric = false)
    {
        Id = id;
        Title = title;
        Description = description;
        Kind = kind;
        Numeric = numeric;
        Options = new ObservableCollection<CfOption>(options ?? Enumerable.Empty<CfOption>());
    }

    public string Id { get; }
    public string Title { get; }
    public string Description { get; }
    public CfSettingKind Kind { get; }
    /// <summary>The API value is a number (browser_cache_ttl).</summary>
    public bool Numeric { get; }
    public ObservableCollection<CfOption> Options { get; }

    /// <summary>The values a switch stands for ("on" / "off"; "auto" / "custom"; "2" / "1"; "true" / "false").</summary>
    public string OnValue { get; init; } = "on";
    public string OffValue { get; init; } = "off";
    /// <summary>The plan the feature needs (<see cref="CfPlan"/>).</summary>
    public int MinPlan { get; init; }
    /// <summary>The zone's plan is below <see cref="MinPlan"/>: a plan badge replaces the control, nothing is requested.</summary>
    public bool PlanLocked { get; init; }
    /// <summary>A newer setting that some zones don't have: hidden (not "Not available") when the API doesn't return it.</summary>
    public bool HideWhenUnavailable { get; init; }
    /// <summary>Shown, never changeable here (e.g. the upload limit on plans with one fixed size).</summary>
    public bool ReadOnly { get; init; }
    /// <summary>Read path under the zone when it isn't settings/{id} ("argo/tiered_caching").</summary>
    public string? ZoneSubPath { get; init; }
    /// <summary>Turning the switch off asks first, with this text (Universal SSL).</summary>
    public string? ConfirmOffText { get; init; }

    public bool IsToggle => Kind == CfSettingKind.Toggle;
    public bool IsChoice => Kind == CfSettingKind.Choice;
    public bool IsSegmented => Kind == CfSettingKind.Segmented;
    public string PlanBadge => CfPlan.Name(MinPlan) + (MinPlan == CfPlan.Enterprise ? string.Empty : " plan");
    public string PlanTip => $"{Title} needs the {CfPlan.Name(MinPlan)} plan or higher.";

    /// <summary>Applies a value the user picked (PATCH). Set by the view-model.</summary>
    internal Func<CfSetting, string, Task>? Apply { get; set; }
    /// <summary>The note under the description for the current value (the SSL mode's meaning, time left…).</summary>
    internal Func<CfSetting, string>? Explain { get; set; }

    /// <summary>The "turn it off?" strip is showing (<see cref="ConfirmOffText"/>).</summary>
    [ObservableProperty] private bool _confirmingOff;

    [CommunityToolkit.Mvvm.Input.RelayCommand]
    private void ConfirmOff()
    {
        ConfirmingOff = false;
        if (CanEdit && Apply != null && IsOnFor(Value)) _ = Apply(this, OffValue);
    }

    [CommunityToolkit.Mvvm.Input.RelayCommand]
    private void CancelOff() => ConfirmingOff = false;

    /// <summary>The value as the API last reported it ("on", "strict", "1.2", "14400", …).</summary>
    [ObservableProperty] private string _value = string.Empty;
    [ObservableProperty] private bool _isOn;
    [ObservableProperty] private CfOption? _selectedOption;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanEdit), nameof(ShowNotAvailable), nameof(ShowToggle), nameof(ShowChoice), nameof(ShowSegmented), nameof(DisabledTip), nameof(IsRowVisible))]
    private bool _isLoaded;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanEdit), nameof(ShowNotAvailable), nameof(ShowToggle), nameof(ShowChoice), nameof(ShowSegmented), nameof(DisabledTip), nameof(IsRowVisible))]
    private bool _isAvailable = true;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanEdit), nameof(DisabledTip))]
    private bool _isEditable = true;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanEdit))]
    private bool _isBusy;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasError))]
    private string _error = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasNote))]
    private string _note = string.Empty;

    /// <summary>Seconds left (development mode), when the API reports it.</summary>
    public int? TimeRemaining { get; private set; }

    public bool CanEdit => IsLoaded && IsAvailable && IsEditable && !IsBusy && !PlanLocked && !ReadOnly;
    public bool ShowNotAvailable => IsLoaded && !IsAvailable && !PlanLocked;
    public bool ShowToggle => IsToggle && !ShowNotAvailable && !PlanLocked;
    public bool ShowChoice => IsChoice && !ShowNotAvailable && !PlanLocked;
    public bool ShowSegmented => IsSegmented && !ShowNotAvailable && !PlanLocked;
    public bool IsRowVisible => !(HideWhenUnavailable && IsLoaded && !IsAvailable);
    public bool HasError => Error.Length > 0;
    public bool HasNote => Note.Length > 0;
    public string? DisabledTip => PlanLocked ? PlanTip
        : !IsLoaded ? null
        : !IsAvailable ? "Cloudflare didn't return this setting for this zone (plan or token)."
        : ReadOnly ? "This zone's plan has one fixed value for this setting."
        : !IsEditable ? "Not editable on this zone's plan."
        : null;

    public static bool IsOnValue(string v) => v is "on" or "zrt";   // tls_1_3 "zrt" = on, with 0-RTT

    /// <summary>The switch reads "on" for <paramref name="v"/> (its <see cref="OnValue"/>; tls_1_3's "zrt" counts too).</summary>
    public bool IsOnFor(string v) => v == OnValue || (OnValue == "on" && v == "zrt");

    private bool _syncing;

    /// <summary>Take the API's view of the setting ({"id","value","editable","time_remaining"}).</summary>
    internal void Load(JsonObject o)
    {
        TimeRemaining = CfJson.Int(o["time_remaining"]);
        IsEditable = CfJson.BoolOrNull(o["editable"]) ?? true;
        IsAvailable = true;
        IsLoaded = true;
        SetValue(CfJson.ValueText(o["value"]));
    }

    /// <summary>A value read from an endpoint of its own (bot management, Universal SSL…).</summary>
    internal void LoadValue(string value, bool editable = true)
    {
        IsEditable = editable;
        IsAvailable = true;
        IsLoaded = true;
        Error = string.Empty;
        SetValue(value);
    }

    internal void MarkUnavailable()
    {
        IsAvailable = false;
        IsLoaded = true;
    }

    /// <summary>Show <paramref name="v"/> in the control without treating it as a user change.</summary>
    internal void SetValue(string v)
    {
        _syncing = true;
        try
        {
            Value = v;
            IsOn = IsOnFor(v);
            if (!IsToggle)
            {
                var opt = Options.FirstOrDefault(o => o.Value == v);
                if (opt is null && v.Length > 0)
                {
                    opt = new CfOption(v, v);      // a value this app doesn't list (e.g. a newer plan option)
                    Options.Add(opt);
                }
                SelectedOption = opt;
            }
            Note = Explain?.Invoke(this) ?? string.Empty;
        }
        finally { _syncing = false; }
    }

    /// <summary>Put the control back to the last value the API confirmed.</summary>
    internal void Revert() => SetValue(Value);

    partial void OnIsOnChanged(bool value)
    {
        if (_syncing || !IsToggle) return;
        if (!value && ConfirmOffText != null && CanEdit && Apply != null)
        {
            // Ask first; the switch shows the confirmed value (on) until the user says yes.
            ConfirmingOff = true;
            Avalonia.Threading.Dispatcher.UIThread.Post(Revert);
            return;
        }
        Request(value ? OnValue : OffValue);
    }

    partial void OnSelectedOptionChanged(CfOption? value)
    {
        if (_syncing || IsToggle) return;
        if (value is null)
        {
            // A picker that lost its selection (its template recycled onto another zone's row, items swapped) writes
            // null back: that is not a user choice. Show the confirmed value again.
            if (Value.Length > 0) Avalonia.Threading.Dispatcher.UIThread.Post(Revert);
            return;
        }
        if (value.Value == Value) return;
        Request(value.Value);
    }

    private void Request(string v)
    {
        if (!CanEdit || Apply is null)
        {
            // Never mid-binding: let the control finish its own update, then show the real value again.
            Avalonia.Threading.Dispatcher.UIThread.Post(Revert);
            return;
        }
        _ = Apply(this, v);
    }
}

/// <summary>The settings of one zone, loaded on first open of a settings tab and kept for the session.</summary>
public partial class CfZoneSettings : ObservableObject
{
    public CfZoneSettings(string zoneId) => ZoneId = zoneId;

    public string ZoneId { get; }
    public CfSetting Ech { get; init; } = null!;
    public CfSetting Ssl { get; init; } = null!;
    /// <summary>Automatic SSL/TLS (ssl_automatic_mode: auto / custom); hidden on zones that don't have it.</summary>
    public CfSetting AutoSsl { get; init; } = null!;
    public CfSetting SecurityLevel { get; init; } = null!;
    public CfUnderAttack UnderAttack { get; init; } = null!;
    /// <summary>HSTS (the security_header setting: an object, so it has a card of its own).</summary>
    public CfHsts Hsts { get; } = new();
    // One-row lists for the two cards of their own: an ItemsControl builds fresh controls for each zone's settings,
    // where a ContentControl would recycle the previous zone's (a recycled list picker can lose its selection).
    public ObservableCollection<CfSetting> EchRow { get; } = new();
    public ObservableCollection<CfSetting> SslModeRow { get; } = new();
    public ObservableCollection<CfSetting> SslRows { get; } = new();
    public ObservableCollection<CfSetting> SecurityRows { get; } = new();
    public ObservableCollection<CfSetting> NetworkRows { get; } = new();
    public ObservableCollection<CfSetting> CacheRows { get; } = new();
    /// <summary>Speed: Early Hints, Rocket Loader, Speed Brain, Fonts, Polish, WebP.</summary>
    public ObservableCollection<CfSetting> SpeedRows { get; } = new();
    /// <summary>The overview's quick actions besides Under attack (development mode: the same object as in Cache).</summary>
    public ObservableCollection<CfSetting> QuickRows { get; } = new();
    /// <summary>One-row list for the under-attack card (an ItemsControl, for the same reason as the rows above).</summary>
    public ObservableCollection<CfUnderAttack> UnderAttackRow { get; } = new();
    public ObservableCollection<CfHsts> HstsRow { get; } = new();

    public IEnumerable<CfSetting> All
    {
        get
        {
            yield return Ech;
            yield return Ssl;
            yield return AutoSsl;
            foreach (var s in SslRows) yield return s;
            foreach (var s in SecurityRows) yield return s;
            foreach (var s in NetworkRows) yield return s;
            foreach (var s in CacheRows) yield return s;
            foreach (var s in SpeedRows) yield return s;
        }
    }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowState))]
    private bool _isLoading;

    [ObservableProperty] private bool _isLoaded;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasLoadError), nameof(ShowState))]
    private string _loadError = string.Empty;

    public bool HasLoadError => LoadError.Length > 0;
    /// <summary>The "loading…" line or the load error shows at the top of a settings tab.</summary>
    public bool ShowState => IsLoading || HasLoadError;
}

/// <summary>A line of the restore preview / summary.</summary>
public sealed class CfRestoreRow
{
    public string Action { get; init; } = string.Empty;
    public bool IsAdd { get; init; }
    public bool IsUpdate { get; init; }
    public bool IsSkip { get; init; }
    public bool IsFailed { get; init; }
    public string Type { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public string Content { get; init; } = string.Empty;
    public string Detail { get; init; } = string.Empty;
    public bool HasDetail => Detail.Length > 0;
}
