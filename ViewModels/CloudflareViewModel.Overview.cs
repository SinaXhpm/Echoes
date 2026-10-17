using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

// The zone's tabs and what each one loads on first open, plus the Overview: the traffic summary (GraphQL Analytics,
// Zone → Analytics : Read) and the quick actions (I'm under attack, development mode).
public partial class CloudflareViewModel
{
    /// <summary>Everything about the selected zone besides records and settings (loaded per tab, kept per zone).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CurrentAnalytics))]
    private CfZoneExtras? _currentExtras;

    private readonly Dictionary<string, CfZoneExtras> _extrasCache = new(StringComparer.Ordinal);
    private int _lastTab = TabDns;

    /// <summary>SSL/TLS: 0 encryption · 1 edge certificates. Security: 0 settings · 1 WAF rules · 2 IP access.
    /// Speed & cache: 0 speed · 1 cache.</summary>
    [ObservableProperty] private int _sslTabIndex;
    [ObservableProperty] private int _securityTabIndex;
    [ObservableProperty] private int _speedTabIndex;

    partial void OnSslTabIndexChanged(int value) { SaveSubTab(KSslTab, value); EnsureTabData(); }
    partial void OnSecurityTabIndexChanged(int value) { SaveSubTab(KSecurityTab, value); EnsureTabData(); }
    partial void OnSpeedTabIndexChanged(int value) { SaveSubTab(KSpeedTab, value); EnsureTabData(); }

    // The sub-tabs and the traffic range used last come back like the main tab (cf.tab). Plain UI choices: no secret.
    private const string KSslTab = "cf.sslTab", KSecurityTab = "cf.securityTab", KSpeedTab = "cf.speedTab", KRange = "cf.range";

    private void RestoreSubTabs()
    {
        var ps = ProfileService.Instance;
        SslTabIndex = Math.Clamp(ps.GetInt(KSslTab, 0), 0, 1);
        SecurityTabIndex = Math.Clamp(ps.GetInt(KSecurityTab, 0), 0, 2);
        SpeedTabIndex = Math.Clamp(ps.GetInt(KSpeedTab, 0), 0, 1);
        AnalyticsRange = Math.Clamp(ps.GetInt(KRange, 0), 0, 1);
    }

    private static void SaveSubTab(string key, int value)
    {
        if (value >= 0 && ProfileService.Instance.GetInt(key, 0) != value)
            ProfileService.Instance.SetSetting(key, value.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    private CfZoneExtras ExtrasFor(CfZone zone)
    {
        if (!_extrasCache.TryGetValue(zone.Id, out var x))
        {
            var universal = new CfSetting("universal_ssl", "Universal SSL",
                "Free certificate for the zone and its first-level subdomains.", CfSettingKind.Toggle)
            {
                OnValue = "true",
                OffValue = "false",
                ConfirmOffText = "Turn off Universal SSL? Its certificates are removed; without another one, visitors can't use HTTPS (HSTS and Always use HTTPS lock them out).",
            };
            universal.Apply = (s, v) => SetUniversalSslAsync(zone, s, v);
            x = new CfZoneExtras(zone.Id, universal);
            x.Waf.Quota = CloudflareRules.FirewallQuota(zone.PlanId);
            x.Redirects.Quota = CloudflareRules.RedirectQuota(zone.PlanId);
            x.Waf.PlanName = x.Redirects.PlanName = CfPlan.Name(zone.PlanRank);
            _extrasCache[zone.Id] = x;
        }
        return x;
    }

    /// <summary>Load what the open tab (and sub-tab) shows, if it isn't loaded for this zone yet.</summary>
    private void EnsureTabData()
    {
        if (IsLocked || SelectedZone is not { } zone) return;
        switch (SelectedTabIndex)
        {
            case TabOverview:
                _ = EnsureSettingsAsync(zone, force: false);
                _ = EnsureAnalyticsAsync(zone, force: false);
                break;
            case TabSsl:
                _ = EnsureSettingsAsync(zone, force: false);
                if (SslTabIndex == 1) _ = EnsureCertificatesAsync(zone, force: false);
                break;
            case TabSecurity:
                if (SecurityTabIndex == 1) _ = EnsureRulesAsync(zone, redirects: false, force: false);
                else if (SecurityTabIndex == 2) _ = EnsureAccessRulesAsync(zone, force: false);
                else
                {
                    _ = EnsureSettingsAsync(zone, force: false);
                    _ = EnsureBotAsync(zone, force: false);
                }
                break;
            case TabSpeed:
            case TabNetwork:
                _ = EnsureSettingsAsync(zone, force: false);
                break;
            case TabRules:
                _ = EnsureRulesAsync(zone, redirects: true, force: false);
                break;
        }
    }

    /// <summary>
    /// One sentence for a part that couldn't load: a missing permission says which one to add (instead of Cloudflare's
    /// "Authentication error (code 10000)"); anything else keeps Cloudflare's message after <paramref name="failed"/>.
    /// </summary>
    private static string LoadProblem(string needs, string failed, bool denied, string error, CfPermission perm)
        => denied ? $"{needs} the {CloudflareApi.PermissionText(perm)} permission: add it to the API token, then reload."
                  : failed + error;

    // Closes every page that takes over the tool (rule editor, DNSSEC, import, add a zone) — lock / profile switch.
    private void CloseOverlays()
    {
        IsRuleEditorOpen = false;
        IsDnssecOpen = false;
        CloseImport();
        IsAddZoneOpen = false;
        AccessError = string.Empty;
    }

    // ================================================================ analytics

    /// <summary>0 = last 24 hours, 1 = last 7 days.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CurrentAnalytics))]
    private int _analyticsRange;

    public CfAnalytics? CurrentAnalytics => CurrentExtras is { } x ? (AnalyticsRange == 1 ? x.Week : x.Day) : null;

    public string[] AnalyticsRanges { get; } = { "24 hours", "7 days" };

    partial void OnAnalyticsRangeChanged(int value)
    {
        SaveSubTab(KRange, value);
        if (SelectedZone is { } zone && !IsLocked && SelectedTabIndex == TabOverview) _ = EnsureAnalyticsAsync(zone, force: false);
    }

    private async Task EnsureAnalyticsAsync(CfZone zone, bool force)
    {
        var x = ExtrasFor(zone);
        bool week = AnalyticsRange == 1;
        var a = week ? x.Week : x.Day;
        // a summary older than 5 minutes is read again when the tab opens
        if (a.IsLoading || (a.IsLoaded && !a.HasError && !force && DateTime.UtcNow - a.LoadedUtc < TimeSpan.FromMinutes(5))) return;
        var api = Api(out string error);
        if (api is null) { a.Error = error; return; }
        int session = _sessionGen;
        a.IsLoading = true;
        CfResponse r;
        try
        {
            r = await api.GraphQLAsync(CloudflareAnalytics.BuildQuery(zone.Id, week, DateTime.UtcNow), CfPermission.AnalyticsRead, _sessionCts.Token);
        }
        catch (OperationCanceledException) { return; }
        finally
        {
            if (session == _sessionGen) a.IsLoading = false;
        }
        if (session != _sessionGen) return;
        if (!r.Success)
        {
            a.Error = r.PlanLimited ? "This zone's plan doesn't include this traffic data: " + r.Error
                : LoadProblem("The traffic summary needs", "Couldn't load the traffic summary: ", r.Denied, r.Error, CfPermission.AnalyticsRead);
            a.IsLoaded = true;
            return;
        }
        a.Apply(CloudflareAnalytics.Parse(r.Result, week));
        a.LoadedUtc = DateTime.UtcNow;
        a.Error = string.Empty;
        a.IsLoaded = true;
    }
}
