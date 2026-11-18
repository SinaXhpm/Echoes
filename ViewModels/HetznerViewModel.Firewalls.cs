using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>
/// Firewalls: the project's firewalls with their rules and what they are applied to. Rules are edited on a draft (add,
/// edit, remove); nothing reaches Hetzner until "Review and save" shows every change and the user saves it. Hetzner's
/// set_rules REPLACES the whole list, so the draft is the list as it will be, and a save that removes rules asks for a
/// tick first. "Add my IP" fills a source with this device's public address (the dynamic DNS detector's cross-checked
/// answer), as /32 or /128.
/// </summary>
public partial class HetznerViewModel
{
    public const int MaxRules = 50;
    public const int MaxIpsPerRule = 100;

    public ObservableCollection<HzFirewall> Firewalls { get; } = new();
    /// <summary>The selected firewall's rules as they will be saved (the draft).</summary>
    public ObservableCollection<HzRuleRow> FirewallRules { get; } = new();
    public ObservableCollection<HzRuleChange> RuleChanges { get; } = new();
    public IReadOnlyList<string> ProtocolOptions { get; } = HzRule.Protocols.Select(p => p.ToUpperInvariant()).ToList();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasFirewall), nameof(FirewallUnreadable))]
    private HzFirewall? _selectedFirewall;
    [ObservableProperty] private bool _isLoadingFirewalls;
    [ObservableProperty] private bool _firewallsLoaded;
    [ObservableProperty] private bool _showFirewallsEmpty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanPickFirewall))]
    private bool _hasRuleChanges;
    [ObservableProperty] private string _ruleChangesText = string.Empty;

    // the rule editor
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsOverlayOpen))]
    private bool _isRuleEditorOpen;
    [ObservableProperty] private bool _isNewRule;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(EditIpsLabel))]
    private int _editDirection;   // 0 in, 1 out
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(EditHasPort))]
    private string _editProtocol = "TCP";
    [ObservableProperty] private string _editPort = string.Empty;
    [ObservableProperty] private string _editIps = string.Empty;
    [ObservableProperty] private string _editDescription = string.Empty;
    [ObservableProperty] private string _ruleEditorError = string.Empty;
    [ObservableProperty] private bool _isDetectingIp;
    private int _editIndex = -1;

    // the save preview
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsOverlayOpen))]
    private bool _isRulePreviewOpen;
    /// <summary>Why the review is shown again (the rules changed elsewhere meanwhile); "" the first time.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasPreviewNote))]
    private string _previewNote = string.Empty;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanSaveRules))]
    private int _previewRemoves;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanSaveRules))]
    private bool _previewConfirmed;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanSaveRules))]
    private bool _isSavingRules;

    private List<HzRule> _draft = new();

    public bool HasFirewall => SelectedFirewall != null;
    public bool ShowNoRules => HasFirewall && FirewallRules.Count == 0;
    public bool HasPreviewNote => PreviewNote.Length > 0;
    /// <summary>The firewall has a rule this build can't read: a save would drop it, so its rules can't be edited here.</summary>
    public bool FirewallUnreadable => SelectedFirewall?.HasUnreadableRules == true;
    /// <summary>Rule changes are open (a draft, the editor, the review, a save): nothing may load Hetzner's rules over them.</summary>
    private bool RulesInProgress => HasRuleChanges || IsRuleEditorOpen || IsRulePreviewOpen || IsSavingRules;
    private const string UnreadableRulesText = "This firewall has a rule this version of Echoes can't show, and a save here would drop it. Edit its rules in the Hetzner Console.";
    public bool CanPickFirewall => !HasRuleChanges;
    public bool EditHasPort => EditProtocol is "TCP" or "UDP";
    public string EditIpsLabel => EditDirection == 0 ? "Sources (one IP or CIDR per line)" : "Destinations (one IP or CIDR per line)";
    public bool PreviewHasRemoves => PreviewRemoves > 0;
    public string PreviewRemoveText => PreviewRemoves == 1 ? "I understand that 1 rule is removed" : $"I understand that {PreviewRemoves} rules are removed";
    public bool CanSaveRules => !IsSavingRules && (PreviewRemoves == 0 || PreviewConfirmed);

    partial void OnPreviewRemovesChanged(int value)
    {
        OnPropertyChanged(nameof(PreviewHasRemoves));
        OnPropertyChanged(nameof(PreviewRemoveText));
    }

    private void ClearFirewalls()
    {
        Firewalls.Clear();
        SelectedFirewall = null;
        FirewallRules.Clear();
        _draft = new List<HzRule>();
        FirewallsLoaded = false;
        ShowFirewallsEmpty = false;
        HasRuleChanges = false;
        IsRuleEditorOpen = false;
        IsRulePreviewOpen = false;
    }

    private async Task LoadFirewallsAsync()
    {
        if (Api() is not { } api) return;
        var (ct, gen) = Session();
        long keep = SelectedFirewall?.Id ?? 0;
        IsLoadingFirewalls = true;
        BeginBusy();
        SetStatus("Loading firewalls…");
        try
        {
            HzListResponse r;
            try { r = await Task.Run(() => api.GetAllAsync("/firewalls", "firewalls", ct), ct); }
            catch (OperationCanceledException) { return; }
            if (Stale(gen)) return;
            if (!r.Success)
            {
                Report(r, "load the firewalls");
                return;
            }
            // Changes were opened while this loaded: replacing the list would replace the firewall they belong to, and
            // with it the draft (a review would then "save" nothing). They stay; a save checks Hetzner's rules itself.
            if (RulesInProgress)
            {
                SetStatus("The firewalls weren't reloaded, so your rule changes stay. Save or discard them, then reload.");
                return;
            }
            var names = ServerNames();
            var list = LastById(r.Items.Select(n => HzFirewall.From(n, names)).Where(f => f != null).Select(f => f!), f => f.Id)
                       .OrderBy(f => f.Name, StringComparer.OrdinalIgnoreCase).ToList();
            Firewalls.Clear();
            foreach (var f in list)
            {
                Firewalls.Add(f);
                _firewallNames[f.Id] = f.Name;
            }
            FirewallsLoaded = true;
            ShowFirewallsEmpty = Firewalls.Count == 0;
            SelectedFirewall = Firewalls.FirstOrDefault(f => f.Id == keep) ?? Firewalls.FirstOrDefault();
            SetStatus(Firewalls.Count == 1 ? "1 firewall." : $"{Firewalls.Count} firewalls.");
            BuildServerFields();
        }
        finally
        {
            if (!Stale(gen)) IsLoadingFirewalls = false;
            EndBusy(gen);
        }
    }

    partial void OnSelectedFirewallChanged(HzFirewall? value) => ResetDraft();

    private void ResetDraft()
    {
        _draft = SelectedFirewall?.Rules.ToList() ?? new List<HzRule>();
        RenderDraft();
    }

    // The rows from the draft, each marked against the saved rules: a rule found as it was is unchanged; one at the same
    // place with other values is "changed"; anything else is "new". (Removed ones show in the preview.)
    private void RenderDraft()
    {
        FirewallRules.Clear();
        var saved = SelectedFirewall?.Rules ?? Array.Empty<HzRule>();
        var unmatched = saved.ToList();
        for (int i = 0; i < _draft.Count; i++)
        {
            var rule = _draft[i];
            int same = unmatched.FindIndex(r => r.SameAs(rule));
            string change;
            if (same >= 0) { unmatched.RemoveAt(same); change = string.Empty; }
            else change = i < saved.Count && !_draft.Any(d => d.SameAs(saved[i])) ? "changed" : "new";
            FirewallRules.Add(new HzRuleRow(rule, change));
        }
        OnPropertyChanged(nameof(ShowNoRules));
        var changes = Diff(saved, _draft);
        HasRuleChanges = changes.Count > 0;
        RuleChangesText = changes.Count == 1 ? "1 change not saved" : $"{changes.Count} changes not saved";
    }

    // Added / removed rules between the saved list and the draft (a rule that moved is neither).
    internal static List<HzRuleChange> Diff(IReadOnlyList<HzRule> saved, IReadOnlyList<HzRule> draft)
    {
        var changes = new List<HzRuleChange>();
        var left = saved.ToList();
        var added = new List<HzRule>();
        foreach (var d in draft)
        {
            int at = left.FindIndex(r => r.SameAs(d));
            if (at >= 0) left.RemoveAt(at);
            else added.Add(d);
        }
        foreach (var r in left) changes.Add(new HzRuleChange("Remove", r));
        foreach (var a in added) changes.Add(new HzRuleChange("Add", a));
        return changes;
    }

    // ---------- the rule editor ----------

    [RelayCommand]
    private void NewRule()
    {
        if (SelectedFirewall is null) return;
        if (FirewallUnreadable) { SetError(UnreadableRulesText); return; }
        if (_draft.Count >= MaxRules)
        {
            SetError($"A firewall holds at most {MaxRules} rules.");
            return;
        }
        _editIndex = -1;
        IsNewRule = true;
        EditDirection = 0;
        EditProtocol = "TCP";
        EditPort = string.Empty;
        EditIps = "0.0.0.0/0\n::/0";
        EditDescription = string.Empty;
        RuleEditorError = string.Empty;
        IsRuleEditorOpen = true;
    }

    [RelayCommand]
    private void EditRule(HzRuleRow? row)
    {
        if (row is null) return;
        if (FirewallUnreadable) { SetError(UnreadableRulesText); return; }
        int i = FirewallRules.IndexOf(row);
        if (i < 0 || i >= _draft.Count) return;
        var r = _draft[i];
        _editIndex = i;
        IsNewRule = false;
        EditDirection = r.IsIn ? 0 : 1;
        EditProtocol = r.Protocol.ToUpperInvariant();
        EditPort = r.Port;
        EditIps = string.Join("\n", r.Ips);
        EditDescription = r.Description;
        RuleEditorError = string.Empty;
        IsRuleEditorOpen = true;
    }

    [RelayCommand]
    private void RemoveRule(HzRuleRow? row)
    {
        if (row is null) return;
        if (FirewallUnreadable) { SetError(UnreadableRulesText); return; }
        int i = FirewallRules.IndexOf(row);
        if (i < 0 || i >= _draft.Count) return;
        _draft.RemoveAt(i);
        RenderDraft();
        SetStatus("Rule removed from the draft. Review and save to apply it, or discard.");
    }

    [RelayCommand]
    private void CancelRule()
    {
        IsRuleEditorOpen = false;
        RuleEditorError = string.Empty;
    }

    [RelayCommand]
    private void ApplyRule()
    {
        if (BuildRule(out string error) is not { } rule)
        {
            RuleEditorError = error;
            return;
        }
        if (_editIndex >= 0 && _editIndex < _draft.Count) _draft[_editIndex] = rule;
        else _draft.Add(rule);
        IsRuleEditorOpen = false;
        RenderDraft();
        SetStatus("Rule kept in the draft. Review and save to apply it.");
    }

    private HzRule? BuildRule(out string error)
    {
        error = string.Empty;
        string proto = EditProtocol.ToLowerInvariant();
        if (Array.IndexOf(HzRule.Protocols, proto) < 0) { error = "Choose a protocol."; return null; }
        string port = string.Empty;
        if (proto is "tcp" or "udp")
        {
            if (NormalizePort(EditPort) is not { } p)
            {
                error = "Enter a port (22), a range (8000-8100) or any.";
                return null;
            }
            port = p;
        }
        var ips = new List<string>();
        foreach (var raw in EditIps.Split(new[] { '\n', '\r', ',', ' ', '\t', ';' }, StringSplitOptions.RemoveEmptyEntries))
        {
            if (NormalizeCidr(raw, out string why) is not { } cidr)
            {
                error = why;
                return null;
            }
            if (!ips.Contains(cidr)) ips.Add(cidr);
        }
        if (ips.Count == 0) { error = EditDirection == 0 ? "Enter at least one source (0.0.0.0/0 and ::/0 mean anywhere)." : "Enter at least one destination."; return null; }
        if (ips.Count > MaxIpsPerRule) { error = $"A rule holds at most {MaxIpsPerRule} addresses."; return null; }
        string desc = EditDescription.Trim();
        if (desc.Length > 255) { error = "The description is at most 255 characters."; return null; }
        return new HzRule(EditDirection == 0 ? "in" : "out", proto, port, ips, desc);
    }

    /// <summary>"22", "8000-8100" (low before high) or "any"; null when it is none of them.</summary>
    internal static string? NormalizePort(string? text)
    {
        string t = (text ?? string.Empty).Trim().ToLowerInvariant();
        if (t == "any") return "any";
        int dash = t.IndexOf('-');
        if (dash < 0) return Port(t) is int p ? p.ToString(CultureInfo.InvariantCulture) : null;
        if (Port(t[..dash].Trim()) is int lo && Port(t[(dash + 1)..].Trim()) is int hi && lo < hi)
            return lo.ToString(CultureInfo.InvariantCulture) + "-" + hi.ToString(CultureInfo.InvariantCulture);
        return null;

        static int? Port(string s) => int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out int v) && v is >= 1 and <= 65535 ? v : null;
    }

    /// <summary>
    /// An address or CIDR block as Hetzner takes it: a bare address becomes a single host (/32, /128); a block must be a
    /// network (no host bits set) or a single host. Null with a reason otherwise.
    /// </summary>
    internal static string? NormalizeCidr(string? text, out string error)
    {
        error = string.Empty;
        string t = (text ?? string.Empty).Trim();
        string shown = t.Length > 45 ? t[..45] + "…" : t;
        int slash = t.IndexOf('/');
        string addr = slash < 0 ? t : t[..slash];
        // IPAddress.TryParse also takes "203.0.113" (203.0.0.113), "22" and octal "010": an IPv4 address must be four
        // dotted decimals without leading zeros
        bool shape = addr.Contains(':') || HostExtractor.IsStrictIPv4(addr);
        if (!shape || !IPAddress.TryParse(addr, out var ip) || addr.Contains('%') || (ip.AddressFamily != AddressFamily.InterNetwork && ip.AddressFamily != AddressFamily.InterNetworkV6))
        {
            error = $"\"{shown}\" isn't an IP address or CIDR block (like 203.0.113.7/32 or 2001:db8::/64).";
            return null;
        }
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        int max = ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        int prefix = max;
        if (slash >= 0 && (!int.TryParse(t[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out prefix) || prefix > max))
        {
            error = $"\"{shown}\" has an invalid prefix length (0 to {max}).";
            return null;
        }
        byte[] b = ip.GetAddressBytes();
        var masked = (byte[])b.Clone();
        for (int bit = prefix; bit < max; bit++) masked[bit / 8] &= (byte)~(0x80 >> (bit % 8));
        if (!masked.AsSpan().SequenceEqual(b))
        {
            error = $"\"{shown}\" has host bits set. Use the network ({new IPAddress(masked)}/{prefix}) or a single host ({ip}/{max}).";
            return null;
        }
        return $"{ip}/{prefix}";
    }

    /// <summary>"Add my IPv4" / "Add my IPv6": this device's public address, cross-checked, as a single host.</summary>
    [RelayCommand]
    private async Task AddMyIp(string? family)
    {
        if (IsDetectingIp) return;
        var fam = family == "6" ? DdnsFamily.V6 : DdnsFamily.V4;
        IsDetectingIp = true;
        RuleEditorError = string.Empty;
        try
        {
            var svc = DdnsService.Instance;
            var known = fam == DdnsFamily.V4 ? svc.LastIpv4 : svc.LastIpv6;
            string? ip = known is { Address: { } a } && known.At > DateTimeOffset.UtcNow.AddMinutes(-10) ? a : null;
            if (ip is null)
            {
                DdnsIpResult r;
                try { r = await Task.Run(() => DdnsIpDetector.DetectAsync(fam, CancellationToken.None)); }
                catch (Exception ex) { r = new DdnsIpResult { Error = ex.Message }; }
                ip = r.Address;
                if (ip is null)
                {
                    RuleEditorError = r.Error;
                    return;
                }
            }
            if (!IsRuleEditorOpen) return;
            string cidr = ip + (fam == DdnsFamily.V4 ? "/32" : "/128");
            var lines = EditIps.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => l.Trim()).Where(l => l.Length > 0).ToList();
            // "anywhere" plus my IP would still be anywhere: my IP replaces it
            lines.RemoveAll(l => l is "0.0.0.0/0" or "::/0");
            if (!lines.Contains(cidr)) lines.Add(cidr);
            EditIps = string.Join("\n", lines);
        }
        finally { IsDetectingIp = false; }
    }

    // ---------- review and save ----------

    [RelayCommand]
    private void DiscardRules()
    {
        ResetDraft();
        SetStatus("Changes discarded.");
    }

    [RelayCommand]
    private void ReviewRules()
    {
        if (FirewallUnreadable) { SetError(UnreadableRulesText); return; }
        OpenReview(string.Empty);
    }

    // The review of the draft against the rules it will replace; asks for the tick again whenever it is (re)built.
    private void OpenReview(string note)
    {
        if (SelectedFirewall is not { } fw) return;
        var changes = Diff(fw.Rules, _draft);
        if (changes.Count == 0) { IsRulePreviewOpen = false; return; }
        RuleChanges.Clear();
        foreach (var c in changes.OrderBy(c => c.IsAdd)) RuleChanges.Add(c);
        PreviewRemoves = changes.Count(c => c.IsRemove);
        PreviewConfirmed = false;
        PreviewNote = note;
        IsRulePreviewOpen = true;
    }

    /// <summary>The draft's rules made on <c>Loaded</c>, put on what Hetzner has now (<c>Draft</c>), and whether those
    /// differ (<c>Changed</c>: then nothing may be written before the user has seen the new review).</summary>
    internal sealed record RuleRebase(bool Changed, List<HzRule> Draft);

    /// <summary>
    /// A draft made on the rules as <paramref name="loaded"/>, checked against the rules Hetzner has now
    /// (<paramref name="current"/>). Unchanged: the draft as it is. Changed elsewhere (a colleague removed a rule in the
    /// Console): the user's edits, taken as rules removed and rules added against what they were made on, are applied
    /// to the current rules instead, so nothing the user didn't see in a review comes back or goes away. A rule the user
    /// removed that is already gone stays gone; a rule both added appears once.
    /// </summary>
    internal static RuleRebase RebaseRules(IReadOnlyList<HzRule> loaded, IReadOnlyList<HzRule> draft, IReadOnlyList<HzRule> current)
    {
        if (SameRules(loaded, current)) return new RuleRebase(false, draft.ToList());
        var removed = loaded.ToList();
        var added = new List<HzRule>();
        foreach (var d in draft)
        {
            int at = removed.FindIndex(r => r.SameAs(d));
            if (at >= 0) removed.RemoveAt(at);   // kept as it was
            else added.Add(d);
        }
        var result = current.ToList();
        foreach (var r in removed)
        {
            int at = result.FindIndex(x => x.SameAs(r));
            if (at >= 0) result.RemoveAt(at);
        }
        foreach (var a in added)
            if (!result.Any(x => x.SameAs(a))) result.Add(a);
        return new RuleRebase(true, result);
    }

    /// <summary>The same rules, in any order (Hetzner's rules have no order).</summary>
    internal static bool SameRules(IReadOnlyList<HzRule> a, IReadOnlyList<HzRule> b)
    {
        if (a.Count != b.Count) return false;
        var left = b.ToList();
        foreach (var r in a)
        {
            int at = left.FindIndex(x => x.SameAs(r));
            if (at < 0) return false;
            left.RemoveAt(at);
        }
        return true;
    }

    [RelayCommand]
    private void CloseRulePreview()
    {
        if (IsSavingRules) return;
        IsRulePreviewOpen = false;
        PreviewNote = string.Empty;
    }

    /// <summary>
    /// set_rules with the draft (it replaces every rule), then wait for the actions and read the firewall again. The
    /// firewall is read first: when its rules changed elsewhere since they were loaded, nothing is written; the draft is
    /// put on the current rules (<see cref="RebaseRules"/>) and the review is shown again, to be confirmed again.
    /// </summary>
    [RelayCommand]
    private async Task SaveRulesAsync()
    {
        if (!CanSaveRules || SelectedFirewall is not { } fw || Api() is not { } api) return;
        var (ct, gen) = Session();
        IsSavingRules = true;
        BeginBusy();
        SetStatus($"Checking the rules of {fw.Name}…");
        try
        {
            HzResponse cur;
            try { cur = await Task.Run(() => api.GetAsync(HetznerApi.FirewallPath(fw.Id), ct), ct); }
            catch (OperationCanceledException) { return; }
            if (Stale(gen)) return;
            if (!cur.Success)
            {
                Report(cur, $"check the rules of {fw.Name} before saving, so nothing was saved");
                return;
            }
            if (HzFirewall.From(cur.Body?["firewall"], ServerNames()) is not { } now)
            {
                SetError($"Hetzner's answer for {fw.Name} couldn't be read, so nothing was saved.");
                return;
            }
            var rebase = RebaseRules(fw.Rules, _draft, now.Rules);
            if (rebase.Changed || now.HasUnreadableRules)
            {
                fw.UpdateFrom(now);   // from now on the draft is compared with what Hetzner has
                OnPropertyChanged(nameof(FirewallUnreadable));
                _draft = rebase.Draft;
                RenderDraft();
                if (now.HasUnreadableRules)
                {
                    IsRulePreviewOpen = false;
                    SetError("Nothing was saved. " + UnreadableRulesText);
                }
                else if (!HasRuleChanges)
                {
                    IsRulePreviewOpen = false;
                    SetStatus($"The rules of {fw.Name} were changed elsewhere meanwhile, and they are already as your changes wanted. Nothing was saved.");
                }
                else
                {
                    OpenReview($"The rules of {fw.Name} were changed elsewhere (in the Console or another tool) since they were loaded. Your changes now apply to Hetzner's current rules, and nothing was saved yet: check the list again, then save.");
                    SetStatus($"The rules of {fw.Name} changed elsewhere: check the review again.");
                }
                return;
            }

            var rules = new JsonArray();
            foreach (var rule in _draft) rules.Add((JsonNode)rule.ToJson());
            SetStatus($"Saving the rules of {fw.Name}…");
            HzResponse r;
            try { r = await Task.Run(() => api.PostAsync(HetznerApi.FirewallPath(fw.Id) + "/actions/set_rules", new JsonObject { ["rules"] = rules }, ct), ct); }
            catch (OperationCanceledException) { return; }
            if (Stale(gen)) return;
            if (!r.Success)
            {
                IsRulePreviewOpen = false;
                Report(r, $"save the rules of {fw.Name}");
                return;
            }
            WriteWorked();
            string? failed = null;
            bool running = false;
            if (r.Body?["actions"] is JsonArray actions)
                foreach (var a in actions.Take(20))
                {
                    if (HzAction.From(a) is not { } action) continue;
                    HzActionResult done;
                    try { done = await Task.Run(() => api.WaitActionAsync("firewalls", action, null, ct, TimeSpan.FromSeconds(90)), ct); }
                    catch (OperationCanceledException) { return; }
                    if (Stale(gen)) return;
                    if (done.StillRunning) running = true;
                    else if (!done.Ok) failed ??= done.Error;
                }
            IsRulePreviewOpen = false;
            PreviewNote = string.Empty;
            // the saved list is now the draft (read again below to show what Hetzner keeps)
            fw.Rules = _draft.ToList();
            fw.RaiseRules();
            ResetDraft();
            if (failed != null) SetError($"The rules of {fw.Name} were saved, but applying them failed: {failed}");
            else SetStatus(running ? $"The rules of {fw.Name} were saved; Hetzner is still applying them." : $"The rules of {fw.Name} were saved and applied.");
            IsSavingRules = false;   // done: the reload below may take Hetzner's spelling of the rules
            await ReloadFirewallAsync(fw.Id);
        }
        finally
        {
            if (!Stale(gen)) IsSavingRules = false;
            EndBusy(gen);
        }
    }

    private async Task ReloadFirewallAsync(long id)
    {
        if (Api() is not { } api) return;
        var (ct, gen) = Session();
        HzResponse r;
        try { r = await Task.Run(() => api.GetAsync(HetznerApi.FirewallPath(id), ct), ct); }
        catch (OperationCanceledException) { return; }
        if (Stale(gen) || !r.Success || HzFirewall.From(r.Body?["firewall"], ServerNames()) is not { } fresh) return;
        // in place (the picker keeps its selection), and never over changes opened meanwhile
        if (Firewalls.FirstOrDefault(f => f.Id == id) is not { } fw || RulesInProgress) return;
        fw.UpdateFrom(fresh);
        if (ReferenceEquals(fw, SelectedFirewall))
        {
            OnPropertyChanged(nameof(FirewallUnreadable));
            ResetDraft();
        }
    }
}
