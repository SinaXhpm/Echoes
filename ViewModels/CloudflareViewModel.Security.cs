using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

// Security beyond the zone settings:
//   bots:      GET / PUT /zones/{id}/bot_management   {"fight_mode": bool} | {"sbfm_definitely_automated": …}
//              | {"ai_bots_protection": "block" | "disabled" | "only_on_ad_pages"}   (Zone → Bot Management : Edit)
//   IP access: GET / POST /zones/{id}/firewall/access_rules/rules, DELETE …/rules/{id}  (Zone → Firewall Services : Edit)
//              {"mode": block | managed_challenge | js_challenge | challenge | whitelist,
//               "configuration": {"target": ip | ip6 | ip_range | asn | country, "value": …}, "notes": …}
public partial class CloudflareViewModel
{
    // ================================================================ bots

    private async Task EnsureBotAsync(CfZone zone, bool force)
    {
        var bot = ExtrasFor(zone).Bot;
        if (bot.IsLoading || (bot.IsLoaded && !force)) return;
        if (bot.Rows.Any(r => r.IsBusy)) return;
        var api = Api(out string error);
        if (api is null) { bot.Error = error; return; }
        int session = _sessionGen;
        bot.IsLoading = true;
        CfResponse r;
        try { r = await api.GetAsync(CloudflareApi.ZonePath(zone.Id) + "/bot_management", CfPermission.BotManagement, _sessionCts.Token); }
        catch (OperationCanceledException) { return; }
        finally
        {
            if (session == _sessionGen) bot.IsLoading = false;
        }
        if (session != _sessionGen) return;
        if (!r.Success || r.Result is not JsonObject o)
        {
            bot.Error = LoadProblem("Bot settings need", "Couldn't read the bot settings: ", r.Denied, r.Success ? "unexpected answer" : r.Error,
                                    CfPermission.BotManagement);
            bot.IsLoaded = true;
            return;
        }
        bot.Error = string.Empty;
        LoadBot(zone, bot, o);
        bot.IsLoaded = true;
    }

    private void LoadBot(CfZone zone, CfBot bot, JsonObject o)
    {
        bot.Rows.Clear();
        bot.Note = string.Empty;
        if (o["fight_mode"] is JsonValue)
        {
            var fight = BotRow(zone, new CfSetting("fight_mode", "Bot Fight Mode",
                "Challenge bot-like requests. Rules can't skip it, so it may catch your API clients.",
                CfSettingKind.Toggle) { OnValue = "true", OffValue = "false" });
            fight.LoadValue(CfJson.Bool(o["fight_mode"]) ? "true" : "false");
            bot.Rows.Add(fight);
        }
        else if (CfJson.StrOrNull(o["sbfm_definitely_automated"]) is { } sbfm)
        {
            var row = BotRow(zone, new CfSetting("sbfm_definitely_automated", "Super Bot Fight Mode",
                "What happens to traffic that is definitely automated.", CfSettingKind.Choice,
                new[] { O("allow", "Allow"), O("managed_challenge", "Managed challenge"), O("block", "Block") }));
            row.LoadValue(sbfm);
            bot.Rows.Add(row);
        }
        else
            bot.Note = "Bot Management (Enterprise) handles bots on this zone; set it up in the Cloudflare dashboard.";

        if (CfJson.StrOrNull(o["ai_bots_protection"]) is { } ai)
        {
            var row = BotRow(zone, new CfSetting("ai_bots_protection", "Block AI crawlers",
                "Stop bots that collect content for AI training.", CfSettingKind.Choice,
                new[] { O("disabled", "Off"), O("block", "Block everywhere"), O("only_on_ad_pages", "Only on hostnames with ads") }));
            row.LoadValue(ai);
            bot.Rows.Add(row);
        }
    }

    private CfSetting BotRow(CfZone zone, CfSetting s)
    {
        s.Apply = (setting, value) => SetBotAsync(zone, setting, value);
        return s;
    }

    private async Task SetBotAsync(CfZone zone, CfSetting s, string value)
    {
        if (IsLocked || s.IsBusy) { s.Revert(); return; }
        var api = Api(out string error);
        if (api is null) { s.Revert(); s.Error = error; return; }
        int session = _sessionGen;
        s.IsBusy = true;
        s.Error = string.Empty;
        JsonNode node = s.IsToggle ? JsonValue.Create(value == s.OnValue) : JsonValue.Create(value)!;
        CfResponse r;
        try
        {
            // Only the field that changed: the API keeps the others.
            r = await api.PutAsync(CloudflareApi.ZonePath(zone.Id) + "/bot_management", new JsonObject { [s.Id] = node },
                                   CfPermission.BotManagement, _sessionCts.Token);
        }
        catch (OperationCanceledException) { s.IsBusy = false; s.Revert(); return; }
        s.IsBusy = false;
        if (session != _sessionGen) return;
        bool current = SelectedZone?.Id == zone.Id;
        if (!r.Success)
        {
            s.Revert();
            s.Error = PlanText(r, CfPlan.Free);
            if (current) SetError($"{s.Title} wasn't changed: {s.Error}");
            return;
        }
        var confirmed = r.Result?[s.Id];
        string now = confirmed?.GetValueKind() switch
        {
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            JsonValueKind.String => confirmed.GetValue<string>(),
            _ => value,
        };
        s.SetValue(now);
        if (current) SetStatus($"{s.Title}: {Label(s)} for {zone.Name}.");
    }

    // ================================================================ IP access rules

    public IReadOnlyList<CfOption> AccessModeOptions { get; } =
        CloudflareRules.AccessModes.Select(m => new CfOption(m.Value, m.Label)).ToList();

    [ObservableProperty] private string _accessInput = string.Empty;
    [ObservableProperty] private CfOption? _accessMode;
    [ObservableProperty] private string _accessNote = string.Empty;
    /// <summary>What the typed value was recognized as ("IPv4 address", "Country: Germany"); empty when nothing yet.</summary>
    [ObservableProperty] private string _accessDetected = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasAccessError))]
    private string _accessError = string.Empty;

    [ObservableProperty] private bool _isAddingAccess;

    public bool HasAccessError => AccessError.Length > 0;
    private CfAccessRule? _pendingAccessDelete;

    partial void OnAccessInputChanged(string value)
    {
        AccessError = string.Empty;
        AccessDetected = value.Trim().Length == 0 ? string.Empty
            : CloudflareRules.TryAccessTarget(value, out string target, out string v, out _)
                ? target == "country" ? $"Country: {CloudflareCountries.Name(v)}" : $"{CloudflareRules.AccessTargetLabel(target)}: {v}"
                : string.Empty;
    }

    private async Task EnsureAccessRulesAsync(CfZone zone, bool force)
    {
        var part = ExtrasFor(zone).Access;
        if (part.IsLoading || (part.IsLoaded && !force)) return;
        var api = Api(out string error);
        if (api is null) { part.Error = error; return; }
        int session = _sessionGen;
        part.IsLoading = true;
        CfListResponse r;
        try
        {
            r = await api.GetAllAsync(CloudflareApi.ZonePath(zone.Id) + "/firewall/access_rules/rules", 100,
                                      CfPermission.FirewallServices, _sessionCts.Token, maxPages: 20);
        }
        catch (OperationCanceledException) { return; }
        finally
        {
            if (session == _sessionGen) part.IsLoading = false;
        }
        if (session != _sessionGen) return;
        if (!r.Success)
        {
            part.Error = LoadProblem("IP access rules need", "Couldn't load the IP access rules: ", r.Denied, r.Error, CfPermission.FirewallServices);
            part.IsLoaded = true;
            part.Changed();
            return;
        }
        part.Error = string.Empty;
        part.Rules.Clear();
        foreach (var rule in r.Items.Select(CfAccessRule.FromApi).OfType<CfAccessRule>()) part.Rules.Add(rule);
        part.IsLoaded = true;
        part.Changed();
    }

    [RelayCommand]
    private async Task AddAccessRule()
    {
        if (IsAddingAccess || SelectedZone is not { } zone) return;
        var part = ExtrasFor(zone).Access;
        if (!CloudflareRules.TryAccessTarget(AccessInput, out string target, out string value, out string why))
        {
            AccessError = why;
            return;
        }
        string mode = AccessMode?.Value ?? "block";
        if (CloudflareRules.CheckNote(AccessNote.Trim()) is { } badNote) { AccessError = badNote; return; }
        if (target == "country" && mode == "block" && zone.PlanRank < CfPlan.Enterprise)
        {
            AccessError = $"Blocking a whole country needs the Enterprise plan. Choose a challenge here, or block it with a WAF custom rule: (ip.src.country eq \"{value}\").";
            return;
        }
        if (part.Rules.Any(r => r.Target == target && string.Equals(r.Value, value, StringComparison.OrdinalIgnoreCase)))
        {
            AccessError = $"There is already a rule for {value}. Delete it first to change its action.";
            return;
        }
        var api = Api(out string error);
        if (api is null) { AccessError = error; return; }
        int session = _sessionGen;
        IsAddingAccess = true;
        AccessError = string.Empty;
        var body = new JsonObject
        {
            ["mode"] = mode,
            ["configuration"] = new JsonObject { ["target"] = target, ["value"] = value },
        };
        if (AccessNote.Trim().Length > 0) body["notes"] = AccessNote.Trim();
        CfResponse r;
        try
        {
            r = await api.PostAsync(CloudflareApi.ZonePath(zone.Id) + "/firewall/access_rules/rules", body,
                                    CfPermission.FirewallServices, _sessionCts.Token);
        }
        catch (OperationCanceledException) { return; }
        finally
        {
            if (session == _sessionGen) IsAddingAccess = false;
        }
        if (session != _sessionGen || SelectedZone?.Id != zone.Id) return;
        if (!r.Success)
        {
            AccessError = r.PlanLimited ? r.Error + " — not available on this zone's plan." : r.Error;
            SetError("The IP access rule wasn't added: " + AccessError);
            return;
        }
        var rule = CfAccessRule.FromApi(r.Result);
        if (rule != null) part.Rules.Insert(0, rule);
        else _ = EnsureAccessRulesAsync(zone, force: true);
        part.Changed();
        AccessInput = string.Empty;
        AccessNote = string.Empty;
        SetStatus($"{CloudflareRules.AccessModeLabel(mode)}: {(target == "country" ? CloudflareCountries.Name(value) : value)} on {zone.Name}.");
    }

    [RelayCommand]
    private void RequestDeleteAccess(CfAccessRule? rule)
    {
        if (_pendingAccessDelete != null) _pendingAccessDelete.PendingDelete = false;
        _pendingAccessDelete = rule;
        if (rule != null) rule.PendingDelete = true;
    }

    [RelayCommand]
    private void CancelDeleteAccess(CfAccessRule? rule)
    {
        if (rule != null) rule.PendingDelete = false;
        if (ReferenceEquals(rule, _pendingAccessDelete)) _pendingAccessDelete = null;
    }

    [RelayCommand]
    private async Task DeleteAccess(CfAccessRule? rule)
    {
        if (rule is null || rule.IsBusy || SelectedZone is not { } zone) return;
        var part = ExtrasFor(zone).Access;
        var api = Api(out string error);
        if (api is null) { SetError(error); return; }
        int session = _sessionGen;
        rule.IsBusy = true;
        CfResponse r;
        try { r = await api.DeleteAsync(CloudflareApi.AccessRulePath(zone.Id, rule.Id), CfPermission.FirewallServices, _sessionCts.Token); }
        catch (OperationCanceledException) { return; }
        finally { rule.IsBusy = false; }
        if (session != _sessionGen) return;
        rule.PendingDelete = false;
        if (ReferenceEquals(rule, _pendingAccessDelete)) _pendingAccessDelete = null;
        if (!r.Success)
        {
            SetError($"Couldn't delete the rule for {rule.Value}: {r.Error}");
            return;
        }
        part.Rules.Remove(rule);
        part.Changed();
        SetStatus($"Deleted the IP access rule for {rule.ValueText}.");
    }
}
