using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>
/// Projects: the add / edit form (name, token, proxy), the token check before anything is saved, removal (asks first),
/// the restored-project confirmation and the store (<see cref="HetznerStore"/>).
///
/// The token is never shown again once saved: editing a project leaves the token box empty, and only a token typed
/// there replaces the saved one. A new or replaced token is checked with Hetzner first (one GET of the server list);
/// whether it may write shows only when Hetzner refuses a change, which then marks the project read-only.
/// </summary>
public partial class HetznerViewModel
{
    public ObservableCollection<string> ProxyHistory => HistoryService.Instance.Get("hetzner.proxy");

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowEmptyCard), nameof(FormTitle), nameof(FormHint), nameof(TokenPlaceholder), nameof(CanCancelForm),
                              nameof(ShowAddFromEmpty))]
    private bool _isProjectFormOpen;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(FormTitle), nameof(FormHint), nameof(TokenPlaceholder), nameof(IsEditingProject))]
    private bool _isAddingProject;
    [ObservableProperty] private string _formName = string.Empty;
    /// <summary>The token box (never filled from a saved project; emptied once saved).</summary>
    [ObservableProperty] private string _formToken = string.Empty;
    [ObservableProperty] private bool _formUseProxy;
    [ObservableProperty] private string _formProxy = string.Empty;
    [ObservableProperty] private string _formProxyUser = string.Empty;
    [ObservableProperty] private string _formProxyPass = string.Empty;
    [ObservableProperty] private string _formError = string.Empty;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SubmitLabel))]
    private bool _isCheckingToken;
    /// <summary>The check couldn't reach Hetzner (not a refusal): the project may be saved without it.</summary>
    [ObservableProperty] private bool _canSaveUnchecked;
    [ObservableProperty] private bool _confirmRemove;
    /// <summary>The saved list didn't open this run (no device key): it is kept, and nothing may be saved over it.</summary>
    [ObservableProperty] private bool _storeUnreadable;
    /// <summary>The saved list was sealed by another install and is gone; or the projects are kept for this session.</summary>
    [ObservableProperty] private string _storeNote = string.Empty;

    public bool IsEditingProject => !IsAddingProject;
    public bool CanCancelForm => HasProjects;
    /// <summary>The empty page's own Add project button (not while the form is open above it).</summary>
    public bool ShowAddFromEmpty => !HasProjects && !IsProjectFormOpen;
    public string FormTitle => IsAddingProject ? "Add a project" : "Edit project";
    public string FormHint => IsAddingProject
        ? "Paste an API token of one Hetzner Cloud project. It is checked with Hetzner, then kept encrypted on this device."
        : "Leave the token empty to keep the saved one. A new token is checked with Hetzner before it replaces it.";
    public string TokenPlaceholder => IsAddingProject ? "Paste the API token" : "Saved (paste a new one to replace)";
    public string SubmitLabel => IsCheckingToken ? "Checking…" : "Check and save";
    public bool HasStoreNote => StoreNote.Length > 0;

    partial void OnStoreNoteChanged(string value) => OnPropertyChanged(nameof(HasStoreNote));

    private CancellationTokenSource? _checkCts;

    // ---------- the store ----------

    private void LoadProjects()
    {
        var list = HetznerStore.Load(ProfileService.Instance, out var result);
        StoreUnreadable = result == HetznerStore.LoadResult.Unreadable;
        StoreNote = result switch
        {
            HetznerStore.LoadResult.Unreadable => "Your saved projects can't be opened right now (the device key is unavailable). They are kept; restart Echoes.",
            HetznerStore.LoadResult.Lost => "Saved projects from another device (or a restored profile) can't be opened here. Add them again.",
            _ => string.Empty,
        };
        Projects.Clear();
        foreach (var d in list) Projects.Add(new HzProject(d));
        string active = ProfileService.Instance.GetSetting(HetznerStore.ActiveKey) ?? string.Empty;
        SelectedProject = Projects.FirstOrDefault(p => p.Data.Id == active) ?? Projects.FirstOrDefault();
        if (Projects.Count == 0 && !StoreUnreadable) OpenForm(adding: true);
        SyncDdnsAccounts();
    }

    /// <summary>Write the list (sealed). Where this device can't seal, the projects last for this session only.</summary>
    private void SaveProjects()
    {
        if (StoreUnreadable) return;   // never over a list a later run may still open
        bool stored = HetznerStore.Save(ProfileService.Instance, Projects.Select(p => p.Data).ToList());
        StoreNote = stored ? string.Empty : "This device can't store secrets safely: your projects are kept for this session only.";
    }

    // A backup restore replaced the profile: read the projects again (nothing in memory is written back).
    private void OnRestoreApplied()
    {
        if (Avalonia.Threading.Dispatcher.UIThread.CheckAccess()) ReloadAfterRestore();
        else Avalonia.Threading.Dispatcher.UIThread.Post(ReloadAfterRestore);
    }

    private void ReloadAfterRestore()
    {
        CloseForm();
        SelectedProject = null;
        LoadProjects();
    }

    // ---------- the form ----------

    [RelayCommand]
    private void AddProject() => OpenForm(adding: true);

    [RelayCommand]
    private void EditProject()
    {
        if (SelectedProject is null) return;
        OpenForm(adding: false);
    }

    private void OpenForm(bool adding)
    {
        _checkCts?.Cancel();
        IsCheckingToken = false;
        IsAddingProject = adding || SelectedProject is null;
        var d = IsAddingProject ? null : SelectedProject!.Data;
        FormName = d?.Name ?? string.Empty;
        FormToken = string.Empty;
        FormUseProxy = d?.UseProxy ?? false;
        FormProxy = d?.Proxy ?? string.Empty;
        FormProxyUser = d?.ProxyUser ?? string.Empty;
        FormProxyPass = d?.ProxyPass ?? string.Empty;
        FormError = string.Empty;
        ForgetUnchecked();
        ConfirmRemove = false;
        IsProjectFormOpen = true;
    }

    [RelayCommand]
    private void CancelProject() => CloseForm();

    private void CloseForm()
    {
        _checkCts?.Cancel();
        IsCheckingToken = false;
        IsProjectFormOpen = false;
        FormToken = string.Empty;
        FormProxyPass = string.Empty;
        FormError = string.Empty;
        ForgetUnchecked();
        ConfirmRemove = false;
    }

    /// <summary>The form's data as a project (null with <see cref="FormError"/> set when something is missing).</summary>
    private HzProjectData? DraftFromForm()
    {
        if (StoreUnreadable)
        {
            FormError = "Your saved projects can't be opened right now. Restart Echoes before changing them.";
            return null;
        }
        string token = FormToken.Trim();
        var current = IsAddingProject ? null : SelectedProject?.Data;
        if (token.Length == 0 && current is null)
        {
            FormError = "Paste the project's API token (Hetzner Console → your project → Security → API tokens).";
            return null;
        }
        // never echo what was typed: a near-miss is still most of a secret
        if (token.Length > 0 && !HetznerApi.IsTokenShape(token))
        {
            FormError = "That doesn't look like an API token: it has spaces, line breaks or other characters a token doesn't have.";
            return null;
        }
        if (IsAddingProject && Projects.Count >= HetznerStore.MaxProjects)
        {
            FormError = $"At most {HetznerStore.MaxProjects} projects can be saved.";
            return null;
        }
        string proxy = FormProxy.Trim();
        if (FormUseProxy && proxy.Length > 0 && !HttpHelper.TryParseProxy(proxy, out _))
        {
            FormError = "Invalid proxy address. Use host:port (e.g. 127.0.0.1:1080).";
            return null;
        }
        string name = FormName.Trim();
        if (name.Length > 60) name = name[..60];
        var draft = current?.Clone() ?? new HzProjectData { Id = HetznerStore.NewId() };
        if (name.Length == 0) name = current?.Name is { Length: > 0 } old ? old : NextName();
        draft.Name = name;
        if (token.Length > 0 && token != draft.Token)
        {
            draft.Token = token;
            draft.ReadOnly = false;   // a new token: whether it may write is learned again
            draft.Restored = false;   // ...and it is the user's own, typed here, not a backup's
        }
        draft.UseProxy = FormUseProxy && proxy.Length > 0;
        draft.Proxy = proxy;
        draft.ProxyUser = FormProxyUser.Trim();
        draft.ProxyPass = FormProxyPass;
        // another project with this very token: one is enough
        if (Projects.Any(p => p.Data.Id != draft.Id && p.Data.Token == draft.Token))
        {
            FormError = "This token is already saved as another project.";
            return null;
        }
        return draft;
    }

    private string NextName()
    {
        for (int i = 1; ; i++)
        {
            string n = i == 1 ? "My project" : $"My project {i}";
            if (Projects.All(p => !string.Equals(p.Name, n, StringComparison.OrdinalIgnoreCase))) return n;
        }
    }

    /// <summary>Check the token with Hetzner (one GET), then save. A refused token isn't saved.</summary>
    [RelayCommand]
    private async Task SubmitProjectAsync()
    {
        if (IsCheckingToken) return;
        FormError = string.Empty;
        ForgetUnchecked();
        if (DraftFromForm() is not { } draft) return;
        var current = IsAddingProject ? null : SelectedProject?.Data;
        // only the name changed: nothing to check
        bool sameAccess = current != null && current.Token == draft.Token && current.UseProxy == draft.UseProxy && current.Proxy == draft.Proxy
                          && current.ProxyUser == draft.ProxyUser && current.ProxyPass == draft.ProxyPass;
        if (sameAccess)
        {
            Commit(draft, checkedText: null);
            return;
        }

        _checkCts?.Cancel();
        var cts = _checkCts = new CancellationTokenSource();
        IsCheckingToken = true;
        try
        {
            HetznerApi api;
            try
            {
                api = HetznerApi.Create(draft.Token, draft.UseProxy ? draft.Proxy : null, draft.UseProxy ? draft.ProxyUser : null,
                                        draft.UseProxy ? draft.ProxyPass : null);
            }
            catch (ArgumentException ex)
            {
                FormError = ex.Message;
                return;
            }
            HzResponse r;
            using (api)
            {
                try { r = await Task.Run(() => api.GetAsync("/servers?per_page=1", cts.Token), cts.Token); }
                catch (OperationCanceledException) { return; }
            }
            if (cts.IsCancellationRequested) return;
            if (!r.Success)
            {
                FormError = r.AuthFailed
                    ? "Hetzner doesn't accept this token. Copy it again from the Hetzner Console (your project → Security → API tokens); it is shown only once, so you may need a new one."
                    : "The token couldn't be checked: " + r.Error;
                // unreachable (no answer, or the server's fault): the user may save it and connect later
                CanSaveUnchecked = !r.AuthFailed && (r.Status == 0 || r.Status >= 500);
                if (CanSaveUnchecked) _unchecked = draft;
                return;
            }
            long total = CfJson.Long(r.Body?["meta"]?["pagination"]?["total_entries"]) ?? -1;
            string servers = total switch { < 0 => string.Empty, 1 => " (1 server)", _ => $" ({total} servers)" };
            if (draft.UseProxy && !draft.Proxy.Contains('@')) HistoryService.Instance.Add("hetzner.proxy", draft.Proxy);
            Commit(draft, $"Token works{servers}.");
        }
        finally
        {
            if (ReferenceEquals(_checkCts, cts)) IsCheckingToken = false;
        }
    }

    private HzProjectData? _unchecked;   // the draft a failed check offered to save anyway

    /// <summary>Save without the check (Hetzner couldn't be reached); it connects once it can. Only what was checked can
    /// be saved this way: any change to the form since takes the offer back (<see cref="ForgetUnchecked"/>).</summary>
    [RelayCommand]
    private void SaveProjectAnyway()
    {
        if (_unchecked is not { } draft) return;
        ForgetUnchecked();
        Commit(draft, "Saved without a check.");
    }

    private void ForgetUnchecked()
    {
        _unchecked = null;
        CanSaveUnchecked = false;
    }

    // a field changed after a failed check: "Save anyway" would no longer save what is in the form
    partial void OnFormNameChanged(string value) => ForgetUnchecked();
    partial void OnFormTokenChanged(string value) => ForgetUnchecked();
    partial void OnFormUseProxyChanged(bool value) => ForgetUnchecked();
    partial void OnFormProxyChanged(string value) => ForgetUnchecked();
    partial void OnFormProxyUserChanged(string value) => ForgetUnchecked();
    partial void OnFormProxyPassChanged(string value) => ForgetUnchecked();

    private void Commit(HzProjectData draft, string? checkedText)
    {
        var existing = Projects.FirstOrDefault(p => p.Data.Id == draft.Id);
        string? oldKey = existing is null ? null : DdnsService.HetznerKeyOf(existing.Data.Token);
        bool tokenChanged = existing != null && existing.Data.Token != draft.Token;
        if (existing is null)
        {
            var p = new HzProject(draft);
            Projects.Add(p);
            SaveProjects();
            CloseForm();
            SelectedProject = p;   // connects
        }
        else
        {
            bool accessChanged = tokenChanged || existing.Data.UseProxy != draft.UseProxy || existing.Data.Proxy != draft.Proxy
                                 || existing.Data.ProxyUser != draft.ProxyUser || existing.Data.ProxyPass != draft.ProxyPass;
            existing.Replace(draft);
            SaveProjects();
            CloseForm();
            if (oldKey != null) SyncDdnsAccount(existing, oldKey);
            if (accessChanged)
            {
                ClearSession();
                Fire(ConnectAsync, "connect");
            }
        }
        SetStatus((checkedText is null ? string.Empty : checkedText + " ") + $"{draft.Name} is saved, encrypted on this device.");
    }

    // ---------- remove ----------

    [RelayCommand]
    private void RequestRemoveProject() => ConfirmRemove = SelectedProject != null;

    [RelayCommand]
    private void CancelRemoveProject() => ConfirmRemove = false;

    /// <summary>Remove the selected project: its token goes, and so do the dynamic DNS jobs that use it.</summary>
    [RelayCommand]
    private void RemoveProject()
    {
        ConfirmRemove = false;
        if (SelectedProject is not { } p || StoreUnreadable) return;
        string key = DdnsService.HetznerKeyOf(p.Data.Token);
        int index = Projects.IndexOf(p);
        Projects.Remove(p);
        SaveProjects();
        if (Projects.All(o => o.Data.Token != p.Data.Token)) DdnsService.Instance.RemoveAccount(key);
        CloseForm();
        SelectedProject = Projects.Count == 0 ? null : Projects[Math.Clamp(index, 0, Projects.Count - 1)];
        if (Projects.Count == 0) OpenForm(adding: true);
        SetStatus($"{p.Name} was removed from Echoes, with its token and its dynamic DNS records.");
    }

    // ---------- a restored project ----------

    /// <summary>The user confirms a project that came with a backup: dynamic DNS may now use its token.</summary>
    [RelayCommand]
    private void ConfirmRestoredProject()
    {
        if (SelectedProject is not { Restored: true } p) return;
        p.Restored = false;
        SaveProjects();
        SyncDdnsAccount(p, DdnsService.HetznerKeyOf(p.Data.Token));
        SetStatus($"{p.Name} is confirmed. Its dynamic DNS records use it again.");
    }

    /// <summary>The project's credentials as a dynamic DNS job keeps them.</summary>
    private static DdnsService.Credentials DdnsCred(HzProjectData d)
    {
        bool proxy = d.UseProxy && d.Proxy.Trim().Length > 0;
        return DdnsService.Credentials.ForHetzner(d.Token, proxy ? d.Proxy : null, proxy ? d.ProxyUser : null, proxy ? d.ProxyPass : null);
    }

    // The jobs of every project this user has confirmed take its current token, proxy and name. A restored project's
    // jobs wait: they keep their own sealed copy, which a backup from elsewhere can't open.
    private void SyncDdnsAccounts()
    {
        foreach (var p in Projects)
            if (!p.Restored) SyncDdnsAccount(p, DdnsService.HetznerKeyOf(p.Data.Token));
    }

    private static void SyncDdnsAccount(HzProject p, string oldKey)
    {
        if (p.Restored) return;
        var cred = DdnsCred(p.Data);
        if (cred.IsUsable) DdnsService.Instance.UpdateAccount(oldKey, cred, p.Name);
    }
}
