using Avalonia.Threading;
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
/// Hetzner Cloud: projects (a name, an API token and an optional proxy each, stored sealed with the per-install key so
/// dynamic DNS runs in the background with nothing to unlock), the project's servers (status, addresses, power), its
/// firewalls (rules, edited and saved as a whole) and its DNS (zones and record sets, zone files, dynamic DNS).
///
/// Split by area: this file = the selected project, the API client, tabs and the status line; .Projects = the project
/// form and the store; .Servers = the server list, details and power actions; .Firewalls = rules, the rule editor and
/// the save preview; .Dns = zones, record sets and zone files; .Ddns = dynamic DNS jobs of this tool; .Models = the bound
/// item classes.
/// </summary>
public partial class HetznerViewModel : ObservableObject
{
    public ObservableCollection<HzProject> Projects { get; } = new();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasProject), nameof(ShowTabs), nameof(ShowEmptyCard), nameof(EmptyTitle), nameof(EmptyText))]
    private HzProject? _selectedProject;

    /// <summary>A request that blocks the main actions is running.</summary>
    [ObservableProperty] private bool _isBusy;
    private int _busyCount;

    [ObservableProperty] private string _statusMessage = "Add a Hetzner Cloud project with its API token to start.";
    [ObservableProperty] private bool _statusIsError;

    /// <summary>The selected project answered (its servers loaded once): the tabs show.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowTabs), nameof(ShowEmptyCard), nameof(EmptyTitle), nameof(EmptyText))]
    private bool _isConnected;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowEmptyCard), nameof(EmptyTitle), nameof(EmptyText))]
    private bool _isConnecting;

    /// <summary>Why the first load failed: "" · "auth" (token refused) · "other".</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(EmptyTitle), nameof(EmptyText))]
    private string _connectProblem = string.Empty;

    /// <summary>0 Servers · 1 Firewalls · 2 DNS. Each loads on its first open per project.</summary>
    [ObservableProperty] private int _selectedTabIndex;

    public const int TabServers = 0, TabFirewalls = 1, TabDns = 2;

    public bool HasProjects => Projects.Count > 0;
    public bool HasProject => SelectedProject != null;
    public bool ShowTabs => HasProject && IsConnected;
    public bool ShowEmptyCard => !ShowTabs && (!IsProjectFormOpen || !HasProjects);

    public string EmptyTitle => !HasProjects ? "Add your Hetzner Cloud project"
        : IsConnecting ? "Connecting to Hetzner…"
        : ConnectProblem == "auth" ? "Hetzner refused this token"
        : ConnectProblem == "other" ? "Couldn't reach Hetzner"
        : "Not connected";

    public string EmptyText => !HasProjects
        ? "In the Hetzner Console open your project, then Security → API tokens → Generate API token. Choose Read & Write to manage servers, firewalls and DNS here (Read only lets you look). Copy the token: Hetzner shows it once."
        : IsConnecting ? "Loading this project's servers."
        : ConnectProblem == "auth" ? "The token may be mistyped or deleted. Edit the project and paste a new one."
        : ConnectProblem == "other" ? "Check your connection or set a proxy (Edit), then try again. Details below."
        : "Connect to load this project.";

    private readonly IToolLinks? _links;

    // The API client of the selected project (made on first use), and the session everything it started runs under: a
    // project switch or an edit cancels it, so a late answer can't land in the next project's lists.
    private HetznerApi? _api;
    private CancellationTokenSource _sessionCts = new();
    private int _sessionGen;

    public HetznerViewModel(IToolLinks? links = null)
    {
        _links = links;
        _selectedTabIndex = Math.Clamp(ProfileService.Instance.GetInt("hetzner.tab", TabServers), TabServers, TabDns);
        Projects.CollectionChanged += (_, _) =>
        {
            OnPropertyChanged(nameof(HasProjects));
            OnPropertyChanged(nameof(CanCancelForm));
            OnPropertyChanged(nameof(ShowAddFromEmpty));
            OnPropertyChanged(nameof(ShowEmptyCard));
            OnPropertyChanged(nameof(EmptyTitle));
            OnPropertyChanged(nameof(EmptyText));
        };
        InitDdns();
        LoadProjects();
        MasterSession.RestoreApplied += OnRestoreApplied;
    }

    // ---------- the API client and the session ----------

    /// <summary>The selected project's client; null (with the reason in the status line) when there is none.</summary>
    private HetznerApi? Api()
    {
        if (_api != null) return _api;
        if (SelectedProject is not { } p) return null;
        try
        {
            var d = p.Data;
            bool proxy = d.UseProxy && d.Proxy.Trim().Length > 0;
            _api = HetznerApi.Create(d.Token, proxy ? d.Proxy : null, proxy ? d.ProxyUser : null, proxy ? d.ProxyPass : null);
        }
        catch (ArgumentException ex) { SetError(ex.Message); }
        return _api;
    }

    /// <summary>Forget everything the previous project loaded (a switch, an edit, a removal).</summary>
    private void ClearSession()
    {
        _sessionCts.Cancel();
        _sessionCts.Dispose();
        _sessionCts = new CancellationTokenSource();
        _sessionGen++;
        _api?.Dispose();
        _api = null;
        _busyCount = 0;
        IsBusy = false;
        IsConnected = false;
        IsConnecting = false;
        ConnectProblem = string.Empty;
        ClearServers();
        ClearFirewalls();
        ClearDns();
    }

    // (token, generation) for one piece of work; Stale() after an await says the project changed meanwhile
    private (CancellationToken Ct, int Gen) Session() => (_sessionCts.Token, _sessionGen);
    private bool Stale(int gen) => gen != _sessionGen;

    partial void OnSelectedProjectChanged(HzProject? value)
    {
        ConfirmRemove = false;
        ClearSession();
        if (value is null)
        {
            ProfileService.Instance.Remove(HetznerStore.ActiveKey);
            SetStatus(HasProjects ? "Choose a project." : "Add a Hetzner Cloud project with its API token to start.");
            return;
        }
        ProfileService.Instance.SetSetting(HetznerStore.ActiveKey, value.Data.Id);
        if (IsProjectFormOpen && !IsAddingProject) OpenForm(adding: false);
        Fire(ConnectAsync, "connect");
    }

    partial void OnSelectedTabIndexChanged(int value)
    {
        ProfileService.Instance.SetSetting("hetzner.tab", value.ToString(System.Globalization.CultureInfo.InvariantCulture));
        if (IsConnected) Fire(EnsureTabLoadedAsync, "load this tab");
    }

    /// <summary>Load the project: its servers first (that is also the token's check), then the open tab.</summary>
    [RelayCommand]
    private async Task ConnectAsync()
    {
        if (SelectedProject is null || IsConnecting) return;
        int gen = _sessionGen;
        IsConnecting = true;
        ConnectProblem = string.Empty;
        bool ok;
        try { ok = await LoadServersAsync(); }
        // a connect of the project switched away from must not clear the flag of the one that replaced it
        finally { if (!Stale(gen)) IsConnecting = false; }
        if (!ok || Stale(gen)) return;
        IsConnected = true;
        await EnsureTabLoadedAsync();
    }

    private async Task EnsureTabLoadedAsync()
    {
        switch (SelectedTabIndex)
        {
            case TabFirewalls when !FirewallsLoaded: await LoadFirewallsAsync(); break;
            case TabDns when !ZonesLoaded: await LoadZonesAsync(keepZoneId: null); break;
        }
    }

    /// <summary>The refresh button: the open tab again.</summary>
    [RelayCommand]
    private async Task RefreshAsync()
    {
        if (!IsConnected) { await ConnectAsync(); return; }
        switch (SelectedTabIndex)
        {
            case TabServers: await LoadServersAsync(); break;
            case TabFirewalls when RulesInProgress:
                // a reload would put Hetzner's rules over the user's draft
                SetStatus("Save or discard your rule changes first: reloading would replace them.");
                break;
            case TabFirewalls: await LoadFirewallsAsync(); break;
            default: await LoadZonesAsync(keepZoneId: SelectedZone?.Id); break;
        }
    }

    /// <summary>A page over the tool is open (an editor, a preview, an import, dynamic DNS): the tool under it takes no
    /// input, so the keyboard can't reach, say, the zone list while the record set editor is open.</summary>
    public bool IsOverlayOpen => IsRuleEditorOpen || IsRulePreviewOpen || IsRrsetEditorOpen || IsAddZoneOpen || IsImportOpen || IsDdnsOpen;

    /// <summary>
    /// Start work without waiting for it (a load a selection starts). A failure it doesn't report itself still reaches
    /// the status line, and the crash log, instead of vanishing with the task.
    /// </summary>
    private void Fire(Func<Task> work, string doing)
    {
        _ = Run();

        async Task Run()
        {
            try { await work(); }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                CrashLog.Write("Hetzner." + doing, ex);
                SetError($"Couldn't {doing}: {ex.Message}");
            }
        }
    }

    /// <summary>The items with their ids made unique, the last one read winning (a list that changed while it was paged
    /// can repeat an item), in the order first seen.</summary>
    internal static List<T> LastById<T>(IEnumerable<T> items, Func<T, long> id)
    {
        var byId = new Dictionary<long, T>();
        var order = new List<long>();
        foreach (var item in items)
        {
            long key = id(item);
            if (!byId.ContainsKey(key)) order.Add(key);
            byId[key] = item;
        }
        return order.Select(k => byId[k]).ToList();
    }

    /// <summary>Server names by id, for what a firewall is applied to (a repeated id doesn't throw: the last wins).</summary>
    private Dictionary<long, string> ServerNames()
    {
        var names = new Dictionary<long, string>();
        foreach (var s in Servers) names[s.Id] = s.Name;
        return names;
    }

    // ---------- busy + status ----------

    private void BeginBusy()
    {
        _busyCount++;
        IsBusy = true;
    }

    private void EndBusy(int gen)
    {
        if (Stale(gen)) return;   // ClearSession reset the count
        _busyCount = Math.Max(0, _busyCount - 1);
        IsBusy = _busyCount > 0;
    }

    public void SetStatus(string text)
    {
        StatusIsError = false;
        StatusMessage = text;
    }

    public void SetError(string text)
    {
        StatusIsError = true;
        StatusMessage = text;
    }

    /// <summary>A refused call: a 401 marks the connection as refused, a 403 "forbidden" marks the project read-only (the
    /// note says how to get a Read &amp; Write token). The error goes to the status line.</summary>
    private void Report(HzResponse r, string doing)
    {
        if (r.ReadOnly) MarkReadOnly(true);
        if (r.AuthFailed) ConnectProblem = "auth";
        SetError($"Couldn't {doing}: {r.Error}");
    }

    private void Report(HzListResponse r, string doing) => Report(new HzResponse { Status = r.Status, Error = r.Error, Code = r.Code, AuthFailed = r.AuthFailed, ReadOnly = r.ReadOnly }, doing);

    /// <summary>A change went through: the token can write after all (a new token), so the read-only note goes.</summary>
    private void WriteWorked() => MarkReadOnly(false);

    private void MarkReadOnly(bool value)
    {
        if (SelectedProject is not { } p || p.ReadOnly == value) return;
        p.ReadOnly = value;
        SaveProjects();
    }

    // posts a progress report from a background poll to the UI thread
    private static void OnUi(Action a)
    {
        if (Dispatcher.UIThread.CheckAccess()) a();
        else Dispatcher.UIThread.Post(a);
    }
}
