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

// WAF custom rules (phase http_request_firewall_custom, Zone → Zone WAF : Edit) and single redirects (phase
// http_request_dynamic_redirect, Zone → Single Redirect : Edit), through the Rulesets API:
//   list:    GET    /zones/{id}/rulesets/phases/{phase}/entrypoint            (404 = no rules yet)
//   add:     POST   /zones/{id}/rulesets/{ruleset}/rules {rule}               (or PUT …/entrypoint {"rules":[rule]})
//   edit:    PATCH  /zones/{id}/rulesets/{ruleset}/rules/{rule} {definition}  (the rule as read + the changes)
//   delete:  DELETE /zones/{id}/rulesets/{ruleset}/rules/{rule}
// Each write answers with the whole ruleset, which replaces the list.
public partial class CloudflareViewModel
{
    private CfRuleList Rules(CfZone zone, bool redirects) => redirects ? ExtrasFor(zone).Redirects : ExtrasFor(zone).Waf;
    private static CfPermission RulePermission(bool redirects) => redirects ? CfPermission.SingleRedirect : CfPermission.ZoneWaf;
    private static string Phase(bool redirects) => redirects ? CloudflareApi.PhaseRedirect : CloudflareApi.PhaseFirewallCustom;

    private async Task EnsureRulesAsync(CfZone zone, bool redirects, bool force)
    {
        var list = Rules(zone, redirects);
        if (list.IsLoading || (list.IsLoaded && !force)) return;
        if (list.Rules.Any(r => r.IsBusy)) return;
        var api = Api(out string error);
        if (api is null) { list.Error = error; return; }
        int session = _sessionGen;
        list.IsLoading = true;
        CfResponse r;
        try { r = await api.GetAsync(CloudflareApi.EntrypointPath(zone.Id, list.Phase), RulePermission(redirects), _sessionCts.Token); }
        catch (OperationCanceledException) { return; }
        finally
        {
            if (session == _sessionGen) list.IsLoading = false;
        }
        if (session != _sessionGen) return;
        if (r.Success) ApplyRuleset(zone, list, r.Result);
        else if (r.Status == 404)
        {
            // The phase has no entry point ruleset yet: no rules. The first rule added creates it.
            list.RulesetId = string.Empty;
            list.Rules.Clear();
            list.Error = string.Empty;
        }
        else list.Error = LoadProblem(redirects ? "Redirect rules need" : "Custom rules need",
                                      redirects ? "Couldn't load the redirect rules: " : "Couldn't load the custom rules: ",
                                      r.Denied, r.Error, RulePermission(redirects));
        list.IsLoaded = true;
        list.Changed();
    }

    // The ruleset an API call answered with replaces the list (rows of rules that remain are updated in place).
    private void ApplyRuleset(CfZone zone, CfRuleList list, JsonNode? result)
    {
        var (id, rules) = CloudflareRules.ParseRuleset(result);
        if (id.Length > 0) list.RulesetId = id;
        var old = list.Rules.ToDictionary(r => r.Id, StringComparer.Ordinal);
        list.Rules.Clear();
        foreach (var rule in rules)
        {
            if (old.TryGetValue(rule.Id, out var row)) row.Update(rule);
            else
            {
                row = new CfRule(rule);
                bool redirects = list.IsRedirects;
                row.Toggle = (rr, on) => ToggleRuleAsync(zone, redirects, rr, on);
            }
            row.PendingDelete = false;
            list.Rules.Add(row);
        }
        list.Error = string.Empty;
        list.Changed();
    }

    private async Task ToggleRuleAsync(CfZone zone, bool redirects, CfRule rule, bool on)
    {
        var list = Rules(zone, redirects);
        if (rule.IsBusy || list.RulesetId.Length == 0) { rule.SetEnabled(!on); return; }
        var api = Api(out string error);
        if (api is null) { rule.SetEnabled(!on); SetError(error); return; }
        int session = _sessionGen;
        rule.IsBusy = true;
        CfResponse r;
        try
        {
            r = await api.PatchAsync(CloudflareApi.RulePath(zone.Id, list.RulesetId, rule.Id), CloudflareRules.WithEnabled(rule.Raw, on),
                                     RulePermission(redirects), _sessionCts.Token);
        }
        catch (OperationCanceledException) { rule.IsBusy = false; rule.SetEnabled(!on); return; }
        rule.IsBusy = false;
        if (session != _sessionGen) return;
        if (!r.Success)
        {
            rule.SetEnabled(!on);
            SetError($"{rule.Title} wasn't {(on ? "enabled" : "disabled")}: {r.Error}");
            return;
        }
        ApplyRuleset(zone, list, r.Result);
        if (SelectedZone?.Id == zone.Id) SetStatus($"{rule.Title} is {(on ? "on" : "off")}.");
    }

    // ---------------------------------------------------------------- delete (inline confirm)

    private CfRule? _pendingRuleDelete;

    [RelayCommand]
    private void RequestDeleteRule(CfRule? rule)
    {
        if (_pendingRuleDelete != null) _pendingRuleDelete.PendingDelete = false;
        _pendingRuleDelete = rule;
        if (rule != null) rule.PendingDelete = true;
    }

    [RelayCommand]
    private void CancelDeleteRule(CfRule? rule)
    {
        if (rule != null) rule.PendingDelete = false;
        if (ReferenceEquals(rule, _pendingRuleDelete)) _pendingRuleDelete = null;
    }

    [RelayCommand]
    private Task DeleteRule(CfRule? rule) => rule is null ? Task.CompletedTask : DeleteRuleCoreAsync(rule);

    private async Task<bool> DeleteRuleCoreAsync(CfRule rule)
    {
        if (rule.IsBusy || SelectedZone is not { } zone) return false;
        bool redirects = rule.IsRedirect || ExtrasFor(zone).Redirects.Rules.Contains(rule);
        var list = Rules(zone, redirects);
        if (list.RulesetId.Length == 0) return false;
        var api = Api(out string error);
        if (api is null) { SetError(error); return false; }
        int session = _sessionGen;
        rule.IsBusy = true;
        CfResponse r;
        try { r = await api.DeleteAsync(CloudflareApi.RulePath(zone.Id, list.RulesetId, rule.Id), RulePermission(redirects), _sessionCts.Token); }
        catch (OperationCanceledException) { return false; }
        finally { rule.IsBusy = false; }
        if (session != _sessionGen) return false;
        rule.PendingDelete = false;
        if (ReferenceEquals(rule, _pendingRuleDelete)) _pendingRuleDelete = null;
        if (!r.Success)
        {
            SetError($"Couldn't delete {rule.Title}: {r.Error}");
            return false;
        }
        if (r.Result is JsonObject) ApplyRuleset(zone, list, r.Result);
        else { list.Rules.Remove(rule); list.Changed(); }
        SetStatus($"Deleted {rule.Title}.");
        return true;
    }

    // ================================================================ the rule editor (a page over the tool)

    [ObservableProperty] private bool _isRuleEditorOpen;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(RuleEditorTitle), nameof(ShowRuleAction), nameof(ShowRedirectFields), nameof(RuleExpressionLabel))]
    private bool _editingRedirect;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(RuleEditorTitle), nameof(IsNewRule))]
    private CfRule? _editingRule;

    [ObservableProperty] private string _ruleName = string.Empty;
    [ObservableProperty] private string _ruleExpression = string.Empty;
    [ObservableProperty] private CfOption? _ruleAction;
    [ObservableProperty] private string _ruleTarget = string.Empty;
    [ObservableProperty] private CfOption? _ruleStatus;
    [ObservableProperty] private bool _rulePreserveQuery = true;
    [ObservableProperty] private bool _ruleEnabled = true;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasRuleError))]
    private string _ruleError = string.Empty;

    [ObservableProperty] private bool _isSavingRule;
    [ObservableProperty] private bool _ruleDeleteConfirm;
    [ObservableProperty] private string _ruleTargetKind = string.Empty;

    public bool HasRuleError => RuleError.Length > 0;
    public bool IsNewRule => EditingRule is null;
    public bool ShowRuleAction => !EditingRedirect;
    public bool ShowRedirectFields => EditingRedirect;
    public string RuleEditorTitle => (EditingRule is null ? "Add " : "Edit ") + (EditingRedirect ? "redirect rule" : "custom rule");
    public string RuleExpressionLabel => EditingRedirect ? "When the request matches (expression)" : "When the request matches (expression)";

    public ObservableCollection<CfOption> RuleActionOptions { get; } = new(CloudflareRules.FirewallActions.Select(a => new CfOption(a.Value, a.Label)));
    public ObservableCollection<CfOption> RedirectStatusOptions { get; } = new(new[]
    {
        new CfOption("301", "301 · moved permanently"), new CfOption("302", "302 · found (temporary)"),
        new CfOption("307", "307 · temporary, same method"), new CfOption("308", "308 · permanent, same method"),
    });

    /// <summary>The examples offered in the editor (filled in for the selected zone).</summary>
    public ObservableCollection<CloudflareRules.Example> RuleExamples { get; } = new();

    /// <summary>The example picker: picking one fills the fields, then the picker clears itself.</summary>
    [ObservableProperty] private CloudflareRules.Example? _selectedRuleExample;

    partial void OnSelectedRuleExampleChanged(CloudflareRules.Example? value)
    {
        if (value is null) return;
        UseRuleExample(value);
        Avalonia.Threading.Dispatcher.UIThread.Post(() => SelectedRuleExample = null);
    }

    partial void OnRuleTargetChanged(string value)
    {
        string t = value.Trim();
        RuleTargetKind = t.Length == 0 ? string.Empty
            : CloudflareRules.IsStaticUrl(t) ? "A fixed URL (static redirect)."
            : "An expression: the URL is built per request (dynamic redirect).";
    }

    /// <summary>The "Add rule" button of a rule list (custom rules or redirects).</summary>
    [RelayCommand]
    private void NewRule(CfRuleList? list) => OpenRuleEditor(null, redirects: list?.IsRedirects == true);

    [RelayCommand]
    private void EditRule(CfRule? rule)
    {
        if (rule is null || SelectedZone is not { } zone) return;
        OpenRuleEditor(rule, redirects: ExtrasFor(zone).Redirects.Rules.Contains(rule));
    }

    private void OpenRuleEditor(CfRule? rule, bool redirects)
    {
        if (SelectedZone is not { } zone) return;
        RequestDeleteRule(null);
        EditingRedirect = redirects;
        EditingRule = rule;
        RuleExamples.Clear();
        foreach (var e in redirects ? CloudflareRules.RedirectExamples(zone.Name) : CloudflareRules.FirewallExamples(zone.Name)) RuleExamples.Add(e);
        RuleName = rule?.Description ?? string.Empty;
        RuleExpression = rule?.Expression ?? string.Empty;
        RuleEnabled = rule?.Enabled ?? true;
        string action = rule?.Action ?? "block";
        var opt = RuleActionOptions.FirstOrDefault(o => o.Value == action);
        if (opt is null && !redirects)
        {
            opt = new CfOption(action, CloudflareRules.ActionLabel(action));   // a rule using an action not offered here (log…)
            RuleActionOptions.Add(opt);
        }
        RuleAction = opt;
        RuleTarget = rule?.Target ?? string.Empty;
        string status = (rule is { StatusCode: > 0 } ? rule.StatusCode : 301).ToString(CultureInfo.InvariantCulture);
        RuleStatus = RedirectStatusOptions.FirstOrDefault(o => o.Value == status) ?? RedirectStatusOptions[0];
        RulePreserveQuery = rule?.PreserveQuery ?? true;
        RuleError = string.Empty;
        RuleDeleteConfirm = false;
        IsRuleEditorOpen = true;
    }

    /// <summary>An example picked in the editor fills the fields (the name only when it's still empty).</summary>
    [RelayCommand]
    private void UseRuleExample(CloudflareRules.Example? example)
    {
        if (example is null) return;
        if (RuleName.Trim().Length == 0) RuleName = example.Description;
        RuleExpression = example.Expression;
        if (EditingRedirect)
        {
            RuleTarget = example.Target;
            RuleStatus = RedirectStatusOptions.FirstOrDefault(o => o.Value == example.Status.ToString(CultureInfo.InvariantCulture)) ?? RuleStatus;
            RulePreserveQuery = example.PreserveQuery;
        }
        else if (RuleActionOptions.FirstOrDefault(o => o.Value == example.Action) is { } a) RuleAction = a;
        RuleError = string.Empty;
    }

    [RelayCommand]
    private void CancelRuleEditor()
    {
        IsRuleEditorOpen = false;
        RuleDeleteConfirm = false;
        EditingRule = null;
    }

    [RelayCommand]
    private async Task SaveRule()
    {
        if (IsSavingRule || SelectedZone is not { } zone) return;
        bool redirects = EditingRedirect;
        var list = Rules(zone, redirects);
        string name = RuleName.Trim();
        string expression = RuleExpression.Trim();
        if (CloudflareRules.CheckDescription(name) is { } badName) { RuleError = badName; return; }
        if (CloudflareRules.CheckExpression(expression) is { } badExpr) { RuleError = badExpr; return; }
        JsonObject body;
        var editing = EditingRule;
        if (redirects)
        {
            string target = RuleTarget.Trim();
            if (CloudflareRules.CheckTarget(target) is { } badTarget) { RuleError = badTarget; return; }
            int code = int.TryParse(RuleStatus?.Value, NumberStyles.None, CultureInfo.InvariantCulture, out int c) ? c : 301;
            body = CloudflareRules.RedirectBody(editing?.Raw, name, expression, target, code, RulePreserveQuery, RuleEnabled);
        }
        else
        {
            string action = RuleAction?.Value ?? "block";
            body = CloudflareRules.FirewallBody(editing?.Raw, name, expression, action, RuleEnabled);
        }

        var api = Api(out string error);
        if (api is null) { RuleError = error; return; }
        int session = _sessionGen;
        IsSavingRule = true;
        RuleError = string.Empty;
        CfResponse r;
        try { r = await SendRuleAsync(api, zone, list, editing, body, RulePermission(redirects)); }
        catch (OperationCanceledException) { return; }
        finally
        {
            if (session == _sessionGen) IsSavingRule = false;
        }
        if (session != _sessionGen || SelectedZone?.Id != zone.Id) return;
        if (!r.Success)
        {
            RuleError = RuleFailure(r, zone, redirects, list);
            return;
        }
        ApplyRuleset(zone, list, r.Result);
        list.IsLoaded = true;
        list.Changed();
        IsRuleEditorOpen = false;
        string label = name.Length > 0 ? name : (redirects ? "The redirect rule" : "The custom rule");
        SetStatus(editing is null ? $"{label} added to {zone.Name}." : $"{label} saved.");
        EditingRule = null;
    }

    // Edit = PATCH the rule. Add = POST to the phase's ruleset, or, when the phase has none yet, PUT the entry point
    // with this one rule (that creates it). The ruleset id is asked for again right before a PUT, so a ruleset created
    // meanwhile (in the dashboard, say) gets the rule added instead of being replaced.
    private async Task<CfResponse> SendRuleAsync(CloudflareApi api, CfZone zone, CfRuleList list, CfRule? editing, JsonObject body, CfPermission perm)
    {
        var ct = _sessionCts.Token;
        if (editing != null)
            return await api.PatchAsync(CloudflareApi.RulePath(zone.Id, list.RulesetId, editing.Id), body, perm, ct);
        string rulesetId = list.RulesetId;
        if (rulesetId.Length == 0)
        {
            var check = await api.GetAsync(CloudflareApi.EntrypointPath(zone.Id, list.Phase), perm, ct);
            if (check.Success) rulesetId = CloudflareRules.ParseRuleset(check.Result).RulesetId;
            else if (check.Status != 404) return check;
        }
        return rulesetId.Length > 0
            ? await api.PostAsync(CloudflareApi.RulesetPath(zone.Id, rulesetId) + "/rules", body, perm, ct)
            : await api.PutAsync(CloudflareApi.EntrypointPath(zone.Id, list.Phase), new JsonObject { ["rules"] = new JsonArray(body) }, perm, ct);
    }

    // A refused rule: quota and plan features get a plain explanation; the rest is Cloudflare's own message (an
    // expression error names the position).
    private static string RuleFailure(CfResponse r, CfZone zone, bool redirects, CfRuleList list)
    {
        string plan = CfPlan.Name(zone.PlanRank);
        string lower = r.Error.ToLowerInvariant();
        if (lower.Contains("maximum number of rules") || lower.Contains("quota") || (r.PlanLimited && list.Rules.Count >= list.Quota && list.Quota > 0))
            return $"The {plan} plan allows {list.Quota} {(redirects ? "redirect" : "custom")} rules, and this zone has {list.Rules.Count}. Delete one first, or upgrade the plan for more.";
        if (lower.Contains("matches") && (lower.Contains("not entitled") || lower.Contains("not allowed") || lower.Contains("plan")))
            return "Regular expressions (matches) need the Business plan or higher. Use contains, starts_with or eq instead.";
        if (r.Denied) return $"{(redirects ? "Redirect rules need" : "Custom rules need")} the {CloudflareApi.PermissionText(RulePermission(redirects))} permission: add it to the API token.";
        if (r.PlanLimited) return r.Error + " — not included in this zone's plan.";
        return r.Error;
    }

    [RelayCommand]
    private void RequestRuleEditorDelete() => RuleDeleteConfirm = true;

    [RelayCommand]
    private void CancelRuleEditorDelete() => RuleDeleteConfirm = false;

    [RelayCommand]
    private async Task DeleteEditedRule()
    {
        if (EditingRule is not { } rule) return;
        if (await DeleteRuleCoreAsync(rule)) CancelRuleEditor();
        else
        {
            RuleDeleteConfirm = false;
            RuleError = StatusIsError ? StatusMessage : string.Empty;
        }
    }
}
