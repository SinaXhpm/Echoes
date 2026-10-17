using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>
/// The account panel: the header picks the active account; "Add account" and "Edit" open one form that works on a
/// <see cref="Draft"/> copy, so nothing changes until it is submitted. A new account (or changed credentials / proxy) is
/// checked with Cloudflare first — listing the zones — and only saved when Cloudflare accepts it. When Cloudflare can't
/// be reached at all, "Save anyway" keeps it unchecked. Removing an account asks first.
/// </summary>
public partial class CloudflareViewModel
{
    /// <summary>The form's working copy (never in <see cref="Profiles"/>, never saved by itself).</summary>
    [ObservableProperty] private CfProfile _draft = new() { Name = string.Empty };

    /// <summary>The open form adds a new account (true) or edits the active one (false).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AccountPanelTitle), nameof(AccountPanelHint), nameof(SubmitLabel), nameof(CanCancelAccount), nameof(IsEditingAccount))]
    private bool _isAddingAccount;

    /// <summary>Why the form's last check failed (empty: it didn't).</summary>
    [ObservableProperty] private string _accountError = string.Empty;

    /// <summary>The check failed for a network reason (not a refusal): the form offers "Save anyway".</summary>
    [ObservableProperty] private bool _canSaveUnchecked;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SubmitLabel))]
    [NotifyCanExecuteChangedFor(nameof(SubmitAccountCommand), nameof(SaveAccountAnywayCommand))]
    private bool _isCheckingAccount;

    private CancellationTokenSource? _checkCts;
    private bool _openingPanel;   // OpenAccountPanel is setting IsAccountExpanded itself

    public bool HasAccounts => Profiles.Count > 0;
    public bool IsEditingAccount => !IsAddingAccount;
    public string AccountPanelTitle => IsAddingAccount ? "Add account" : "Edit account";
    public string AccountPanelHint => IsAddingAccount
        ? "Checked with Cloudflare, then saved in your vault."
        : "Checked with Cloudflare on save; kept in your vault.";
    public string SubmitLabel => IsCheckingAccount ? "Checking…" : IsAddingAccount ? "Add account" : "Save";
    /// <summary>The very first account can't be skipped: without one there is nothing to show.</summary>
    public bool CanCancelAccount => !IsAddingAccount || HasAccounts;

    /// <summary>"API token · 3 zones": the header line next to the account picker.</summary>
    public string AccountStatus
    {
        get
        {
            var p = SelectedProfile;
            if (p is null) return string.Empty;   // the header says "No account yet"
            string auth = p.UseApiToken ? "API token" : "Global API key";
            if (!p.HasCredentials) return "no credentials yet";
            if (IsLoadingZones) return $"{auth} · connecting…";
            if (Zones.Count == 0) return $"{auth} · not connected";
            return $"{auth} · {Zones.Count} zone{(Zones.Count == 1 ? "" : "s")}";
        }
    }

    /// <summary>The empty page's button: connect the active account (again).</summary>
    public string ConnectLabel => ConnectProblem.Length > 0 ? "Try again" : "Connect";
    public bool CanRetryConnect => CanConnect && !IsLoadingZones;

    /// <summary>The "not connected" page: no zone open, and the account form isn't taking its place.</summary>
    public bool ShowEmptyCard => !HasZone && !IsAccountExpanded;

    // ---------- open / close ----------

    /// <summary>The header's "Add account".</summary>
    [RelayCommand]
    private void AddAccount()
    {
        if (IsLocked) return;
        OpenAccountPanel(adding: true);
    }

    /// <summary>The header's "Edit": opens the form for the active account, or folds it away again.</summary>
    [RelayCommand]
    private void EditAccount()
    {
        if (IsLocked || SelectedProfile is null) return;
        if (IsAccountExpanded && !IsAddingAccount) { IsAccountExpanded = false; return; }
        OpenAccountPanel(adding: false);
    }

    [RelayCommand]
    private void CancelAccount()
    {
        if (!CanCancelAccount) return;
        IsAccountExpanded = false;
    }

    private void OpenAccountPanel(bool adding)
    {
        if (IsLocked) return;
        if (!adding && SelectedProfile is null) adding = true;
        StopCheck();
        AccountError = string.Empty;
        CanSaveUnchecked = false;
        DeleteProfileConfirm = false;
        IsAddingAccount = adding;
        Draft = adding ? new CfProfile { Name = string.Empty } : CopyOf(SelectedProfile!);
        _openingPanel = true;
        try { IsAccountExpanded = true; }
        finally { _openingPanel = false; }
    }

    partial void OnIsAccountExpandedChanged(bool value)
    {
        OnPropertyChanged(nameof(ShowEmptyCard));
        if (!value)
        {
            // folded away: forget the form (and the secrets typed into it)
            StopCheck();
            DeleteProfileConfirm = false;
            AccountError = string.Empty;
            CanSaveUnchecked = false;
            IsAddingAccount = false;
            Draft = new CfProfile { Name = string.Empty };
            return;
        }
        // Opened by the code (missing credentials, a refused token…): edit the active account, or add the first one.
        if (!_openingPanel && !IsLocked) OpenAccountPanel(adding: SelectedProfile is null);
    }

    private void StopCheck()
    {
        _checkCts?.Cancel();
        _checkCts?.Dispose();
        _checkCts = null;
        IsCheckingAccount = false;
    }

    // ---------- submit ----------

    private bool CanSubmitAccount() => !IsCheckingAccount;

    /// <summary>"Add account" / "Save": check with Cloudflare, then save.</summary>
    [RelayCommand(CanExecute = nameof(CanSubmitAccount))]
    private Task SubmitAccount() => SubmitAccountAsync(check: true);

    /// <summary>After a network failure only: save without the check.</summary>
    [RelayCommand(CanExecute = nameof(CanSubmitAccount))]
    private Task SaveAccountAnyway() => SubmitAccountAsync(check: false);

    private async Task SubmitAccountAsync(bool check)
    {
        if (IsLocked || IsCheckingAccount || !IsAccountExpanded) return;
        var target = IsAddingAccount ? null : SelectedProfile;
        if (!IsAddingAccount && target is null) { IsAccountExpanded = false; return; }

        var d = Draft;
        d.ApiToken = d.ApiToken.Trim();
        d.ApiEmail = d.ApiEmail.Trim();
        d.ApiKey = d.ApiKey.Trim();
        d.ProxyAddress = d.ProxyAddress.Trim();
        AccountError = string.Empty;
        CanSaveUnchecked = false;

        if (!d.HasCredentials)
        {
            AccountError = d.UseApiToken ? "Paste an API token." : "Enter your account email and Global API key.";
            return;
        }
        if (d.UseProxy && d.ProxyAddress.Length == 0)
        {
            AccountError = "Enter the proxy address, or turn the proxy off.";
            return;
        }
        if (Profiles.FirstOrDefault(p => !ReferenceEquals(p, target) && SameCredentials(p, d)) is { } dup)
        {
            AccountError = $"This account is already saved as \"{dup}\".";
            return;
        }

        bool connectionChanged = target is null || !SameConnection(target, d);
        List<JsonNode>? zones = null;
        if (connectionChanged && check)
        {
            CloudflareApi api;
            try
            {
                api = CloudflareApi.Create(d.UseApiToken, d.ApiToken, d.ApiEmail, d.ApiKey,
                                           d.UseProxy ? d.ProxyAddress : null, d.UseProxy ? d.ProxyUser : null, d.UseProxy ? d.ProxyPass : null);
            }
            catch (ArgumentException ex)
            {
                AccountError = ex.Message;
                return;
            }

            StopCheck();
            var cts = _checkCts = new CancellationTokenSource();
            IsCheckingAccount = true;
            CfListResponse r;
            try { r = await api.GetAllAsync("/zones", 50, CfPermission.ZoneRead, cts.Token); }
            catch (OperationCanceledException) { return; }
            finally { api.Dispose(); }
            // Folded away, locked or reopened meanwhile: that form is gone.
            if (!ReferenceEquals(cts, _checkCts) || IsLocked || !ReferenceEquals(d, Draft)) return;
            IsCheckingAccount = false;

            if (!r.Success)
            {
                AccountError = CheckFailure(r.Error, r.AuthFailed);
                CanSaveUnchecked = !r.AuthFailed;
                return;
            }
            zones = r.Items;
        }

        string name = d.Name.Trim();
        if (name.Length == 0) name = target?.Name is { Length: > 0 } kept ? kept : DefaultAccountName(d, zones);

        if (target is null)
        {
            var account = CopyOf(d);
            account.Name = name;
            IsAccountExpanded = false;      // closes the form (and drops the draft)
            Profiles.Add(account);          // saved
            SelectedProfile = account;      // saved; connects and opens its first zone
            return;
        }

        target.Name = name;
        target.UseApiToken = d.UseApiToken;
        target.ApiToken = d.ApiToken;
        target.ApiEmail = d.ApiEmail;
        target.ApiKey = d.ApiKey;
        target.UseProxy = d.UseProxy;
        target.ProxyAddress = d.ProxyAddress;
        target.ProxyUser = d.ProxyUser;
        target.ProxyPass = d.ProxyPass;
        IsAccountExpanded = false;
        SaveProfiles();
        if (connectionChanged)
        {
            ClearSession();
            _ = LoadZonesAsync(keepZoneId: null);
        }
        else SetStatus($"Account \"{name}\" saved.");
    }

    // ---------- helpers ----------

    /// <summary>The form's text for a failed check. The API client's errors already read "Couldn't reach Cloudflare: …"
    /// or name the refusal ("… Cloudflare rejected these credentials …"); only a bare message gets that context added.</summary>
    internal static string CheckFailure(string error, bool refused)
    {
        error = error.Trim();
        if (refused)
            return error.Contains("Cloudflare", StringComparison.OrdinalIgnoreCase) ? error : "Cloudflare refused these credentials: " + error;
        string text = error.StartsWith("Couldn't reach Cloudflare", StringComparison.OrdinalIgnoreCase) ? error : "Couldn't reach Cloudflare: " + error;
        return text.TrimEnd('.') + ". Check your connection or the proxy and try again, or save it anyway.";
    }

    // Typing in the form makes the last check's verdict (and its "Save anyway") stale.
    partial void OnDraftChanged(CfProfile? oldValue, CfProfile newValue)
    {
        if (oldValue != null) oldValue.PropertyChanged -= OnDraftEdited;
        newValue.PropertyChanged += OnDraftEdited;
    }

    private void OnDraftEdited(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (IsCheckingAccount) return;
        AccountError = string.Empty;
        CanSaveUnchecked = false;
    }

    private static CfProfile CopyOf(CfProfile p) => new()
    {
        Name = p.Name,
        UseApiToken = p.UseApiToken,
        ApiToken = p.ApiToken,
        ApiEmail = p.ApiEmail,
        ApiKey = p.ApiKey,
        UseProxy = p.UseProxy,
        ProxyAddress = p.ProxyAddress,
        ProxyUser = p.ProxyUser,
        ProxyPass = p.ProxyPass,
    };

    private static bool SameCredentials(CfProfile a, CfProfile b)
        => a.UseApiToken == b.UseApiToken && (a.UseApiToken
            ? a.ApiToken.Trim() == b.ApiToken.Trim()
            : string.Equals(a.ApiEmail.Trim(), b.ApiEmail.Trim(), StringComparison.OrdinalIgnoreCase) && a.ApiKey.Trim() == b.ApiKey.Trim());

    private static bool SameConnection(CfProfile a, CfProfile b)
        => SameCredentials(a, b) && a.UseProxy == b.UseProxy
           && (!a.UseProxy || (a.ProxyAddress.Trim() == b.ProxyAddress.Trim() && a.ProxyUser == b.ProxyUser && a.ProxyPass == b.ProxyPass));

    /// <summary>A name left empty: the email (Global API key), else the first zone ("example.com +2"), else "Account N".</summary>
    private string DefaultAccountName(CfProfile d, List<JsonNode>? zones)
    {
        string name;
        if (!d.UseApiToken && d.ApiEmail.Length > 0) name = d.ApiEmail;
        else if (zones?.Select(z => CfJson.Str(z["name"])).Where(n => n.Length > 0).OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToList()
                 is { Count: > 0 } names)
            name = names.Count == 1 ? names[0] : $"{names[0]} +{names.Count - 1}";
        else name = $"Account {Profiles.Count + 1}";

        string unique = name;
        for (int i = 2; Profiles.Any(p => string.Equals(p.Name.Trim(), unique, StringComparison.OrdinalIgnoreCase)); i++)
            unique = $"{name} ({i})";
        return unique;
    }
}
