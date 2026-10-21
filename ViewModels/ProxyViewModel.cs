using System;
using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading.Tasks;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

/// <summary>
/// A cross-platform SOCKS5 + HTTP proxy server. Pick a port, optionally require a username/password,
/// press START, and point any client (browser, curl, phone) at it. Runs on the managed
/// <see cref="ProxyServer"/> (TcpListener), so it works on desktop and the Android sandbox with no
/// external binary, driver, or root. Every connection is logged live with its target and status.
/// The second view (.Checker) tests pasted proxy lists.
/// </summary>
public partial class ProxyViewModel : ObservableObject
{
    [ObservableProperty] private int _port = 1080;
    [ObservableProperty] private int _maxConnections = 64;
    [ObservableProperty] private bool _requireAuth;
    [ObservableProperty] private string _authUser = "echoes";
    [ObservableProperty] private string _authPass = string.Empty;
    [ObservableProperty] private bool _isRunning;
    [ObservableProperty] private string _statusMessage = "SOCKS5 and HTTP share one port.";

    // How the server binds: all interfaces (LAN), loopback, or one specific IP. Reuses BindOption.
    public ObservableCollection<BindOption> BindOptions { get; } = new();
    [ObservableProperty] private BindOption? _selectedBind;
    private bool _rebuildingBinds;

    public ObservableCollection<string> Addresses { get; } = new();
    [ObservableProperty] private string? _selectedShareUrl;

    // Live stats.
    [ObservableProperty] private int _activeConnections;
    [ObservableProperty] private long _totalConnections;
    [ObservableProperty] private string _trafficText = "↑ 0 B   ↓ 0 B";

    // Newest connection first; capped so a busy proxy can't grow the list unbounded.
    public ObservableCollection<ProxyLogEntry> Connections { get; } = new();
    public bool HasConnections => Connections.Count > 0;
    private const int MaxLogRows = 200;

    // Server callbacks fire on connection threads. Rather than one UI post per event (a busy or hostile
    // client could queue thousands), log entries wait here and a UI timer drains them in one batch and
    // polls the traffic counters — which also keeps ↑/↓ moving during a long transfer.
    private readonly ConcurrentQueue<ProxyLogEntry> _pendingLog = new();
    private PacedTimer? _statsTimer;

    private ProxyServer? _server;
    // What the running server is actually bound to: the address card shows these, not the (locked)
    // settings, which RebuildBindOptions may still re-pick if an interface goes away.
    private BindOption? _runningBind;
    private int _runningPort;

    public ProxyViewModel()
    {
        RebuildBindOptions();
        RestoreSettings();
    }

    // --- remembered settings: each saved when it changes. The password only sealed (SecretProtector "enc2:"); one that
    // doesn't open on this run stays on disk as stored until a new one is typed. The checker's list is kept sealed too
    // (it can hold user:pass@), saved when a check starts and only up to MaxSavedList characters.
    private const string KPort = "proxy.port", KMaxConn = "proxy.maxConn", KAuth = "proxy.auth", KUser = "proxy.user",
        KPass = "proxy.pass", KBind = "proxy.bind", KView = "proxy.view", KSort = "proxy.sort", KList = "proxy.list";
    private const int MaxSavedList = 16 * 1024;
    private bool _restoring;

    private void RestoreSettings()
    {
        var p = ProfileService.Instance;
        _restoring = true;
        try
        {
            int port = p.GetInt(KPort, 1080);
            Port = port is >= 1 and <= 65535 ? port : 1080;
            MaxConnections = Math.Clamp(p.GetInt(KMaxConn, 64), 1, 512);
            RequireAuth = p.GetBool(KAuth);
            AuthUser = p.GetSetting(KUser) ?? "echoes";
            AuthPass = SecretProtector.Unprotect(p.GetSetting(KPass));
            ViewIndex = Math.Clamp(p.GetInt(KView, 0), 0, 1);
            SortIndex = Math.Clamp(p.GetInt(KSort, 0), 0, SortOptions.Length - 1);
            CheckInput = SecretProtector.Unprotect(p.GetSetting(KList));
            // a saved interface that isn't up now: this device only (the saved pick stays for the next run)
            if (p.GetSetting(KBind) is { Length: > 0 } want
                && (BindOptions.FirstOrDefault(o => o.Kind != "iface" ? o.Kind == want : o.Address.ToString() == want)
                    ?? (IPAddress.TryParse(want, out _) ? BindOptions.FirstOrDefault(o => o.Kind == "loopback") : null)) is { } saved)
            {
                _rebuildingBinds = true;   // as in RebuildBindOptions: the addresses are listed when the page shows
                SelectedBind = saved;
                _rebuildingBinds = false;
            }
        }
        finally { _restoring = false; }
    }

    private static void SaveInt(string key, int value)
        => ProfileService.Instance.SetSetting(key, value.ToString(System.Globalization.CultureInfo.InvariantCulture));

    partial void OnPortChanged(int value) { if (!_restoring && value is >= 1 and <= 65535) SaveInt(KPort, value); }
    partial void OnMaxConnectionsChanged(int value) { if (!_restoring && value is >= 1 and <= 512) SaveInt(KMaxConn, value); }
    partial void OnRequireAuthChanged(bool value) { if (!_restoring) ProfileService.Instance.SetBool(KAuth, value); }
    partial void OnAuthUserChanged(string value) { if (!_restoring) ProfileService.Instance.SetSetting(KUser, value ?? string.Empty); }

    partial void OnAuthPassChanged(string value)
    {
        if (!_restoring) ProfileService.Instance.SetSetting(KPass, string.IsNullOrEmpty(value) ? null : SecretProtector.Protect(value));
    }

    partial void OnViewIndexChanged(int value) { if (!_restoring && value >= 0) SaveInt(KView, value); }

    /// <summary>The checker's list, sealed, when a check starts (a list over <see cref="MaxSavedList"/> isn't kept).</summary>
    private void SaveCheckList(string list)
    {
        if (list.Length <= MaxSavedList)
            ProfileService.Instance.SetSetting(KList, string.IsNullOrWhiteSpace(list) ? null : SecretProtector.Protect(list));
    }

    private void RebuildBindOptions()
    {
        string? prevKind = SelectedBind?.Kind;
        string? prevAddr = SelectedBind?.Address.ToString();

        var list = new System.Collections.Generic.List<BindOption>
        {
            new("All interfaces (0.0.0.0)", IPAddress.Any, "all"),
            new("This device only (127.0.0.1)", IPAddress.Loopback, "loopback"),
        };
        foreach (var (name, address) in NicSnapshot.UpIPv4())
            list.Add(new BindOption($"{address}  ({name})", address, "iface"));

        _rebuildingBinds = true;
        BindOptions.Clear();
        foreach (var o in list) BindOptions.Add(o);
        SelectedBind = BindOptions.FirstOrDefault(o => o.Kind == prevKind && o.Address.ToString() == prevAddr)
                       // a picked interface that went away (DHCP, Wi-Fi off): the narrowest choice, never all interfaces
                       ?? (prevKind == "iface" ? BindOptions.FirstOrDefault(o => o.Kind == "loopback") : null)
                       ?? BindOptions.FirstOrDefault(o => o.Kind == "all")
                       ?? BindOptions.FirstOrDefault();
        _rebuildingBinds = false;
    }

    partial void OnSelectedBindChanged(BindOption? value)
    {
        if (_rebuildingBinds) return;
        if (!_restoring && value is not null)
            ProfileService.Instance.SetSetting(KBind, value.Kind == "iface" ? value.Address.ToString() : value.Kind);
        RefreshAddresses();
    }

    [RelayCommand]
    private void ToggleServer()
    {
        if (IsRunning) StopInternal();
        else Start();
    }

    private void Start()
    {
        if (Port is < 1 or > 65535) { StatusMessage = "Port must be between 1 and 65535."; return; }
        if (RequireAuth && string.IsNullOrEmpty(AuthUser)) { StatusMessage = "Enter a username for auth (or turn auth off)."; return; }
        // The username has a well-known default, so an empty password would be 'auth on' in name only.
        if (RequireAuth && string.IsNullOrEmpty(AuthPass)) { StatusMessage = "Enter a password for auth (or turn auth off)."; return; }

        IPAddress bind = SelectedBind?.Address ?? IPAddress.Any;
        try
        {
            ResetStats();
            _server = new ProxyServer(RequireAuth ? AuthUser : null, RequireAuth ? AuthPass : null, OnConnection, MaxConnections);
            _server.Start(bind, Port);
            _runningBind = SelectedBind ?? new BindOption("All interfaces", IPAddress.Any, "all");
            _runningPort = Port;
            IsRunning = true;
            BackgroundGuard.Acquire("Proxy server");
            _statsTimer = new PacedTimer(500, 2000, PollStats);   // twice a second while traffic moves, every 2 s when idle
            _statsTimer.Start();
            RefreshAddresses();
            // No auth on a LAN-reachable bind = anyone on the network can use it. That's the feature,
            // so it isn't blocked — but say so plainly instead of a bare "live".
            bool openToLan = !RequireAuth && !IPAddress.IsLoopback(bind);
            StatusMessage = $"Proxy live on :{Port} — SOCKS5 + HTTP{(RequireAuth ? ", auth on" : "")}."
                            + (openToLan ? "  ⚠ No auth: anyone on your network can use it." : "");
        }
        catch (SocketException ex)
        {
            try { _server?.Dispose(); } catch { }   // a failed bind still left a listener socket + CTS behind
            _server = null;
            StatusMessage = ex.SocketErrorCode is SocketError.AddressAlreadyInUse
                ? $"Port {Port} is already in use — pick another port."
                : "Cannot start proxy: " + ex.Message;
        }
        catch (Exception ex)
        {
            try { _server?.Dispose(); } catch { }
            _server = null;
            StatusMessage = "Cannot start proxy: " + ex.Message;
        }
    }

    private void StopInternal()
    {
        bool wasRunning = IsRunning;
        _statsTimer?.Stop();
        _statsTimer = null;
        DrainLog();   // entries logged just before STOP still show
        try { _server?.Dispose(); } catch { }
        _server = null;
        IsRunning = false;
        if (wasRunning)
        {
            BackgroundGuard.Release();
            StatusMessage = "Stopped.";
        }
    }

    /// <summary>Release the listening socket + background guard on app shutdown (and stop a running proxy check).</summary>
    public void StopServer()
    {
        StopChecks();
        StopInternal();
    }

    // Connection log callback — fires on a server thread; queued for the next UI tick. Only the newest
    // MaxLogRows can ever show, so older queued ones are dropped if the UI falls behind a flood.
    private void OnConnection(ProxyLogEntry e)
    {
        _pendingLog.Enqueue(e);
        while (_pendingLog.Count > MaxLogRows && _pendingLog.TryDequeue(out _)) { }
    }

    // UI timer tick (while running): refresh the live counters and flush queued log entries.
    // True while anything moves (the paced timer then keeps its fast interval).
    private bool PollStats()
    {
        var s = _server;
        if (s is null) return false;
        long activity = s.BytesUp + s.BytesDown + s.TotalConnections + s.ActiveConnections;
        bool moved = activity != _lastActivity;
        _lastActivity = activity;
        ActiveConnections = s.ActiveConnections;
        TotalConnections = s.TotalConnections;
        if (moved) TrafficText = $"↑ {FileHttpServer.HumanSize(s.BytesUp)}   ↓ {FileHttpServer.HumanSize(s.BytesDown)}";
        return DrainLog() || moved;
    }

    private long _lastActivity = -1;

    private bool DrainLog()
    {
        bool any = false;
        while (_pendingLog.TryDequeue(out var e)) { Connections.Insert(0, e); any = true; }
        if (!any) return false;
        while (Connections.Count > MaxLogRows) Connections.RemoveAt(Connections.Count - 1);
        OnPropertyChanged(nameof(HasConnections));
        return true;
    }

    private void ResetStats()
    {
        ActiveConnections = 0;
        TotalConnections = 0;
        TrafficText = "↑ 0 B   ↓ 0 B";
        _lastActivity = -1;
        _pendingLog.Clear();
        Connections.Clear();
        OnPropertyChanged(nameof(HasConnections));
    }

    [RelayCommand]
    private void ClearLog()
    {
        Connections.Clear();
        OnPropertyChanged(nameof(HasConnections));
    }

    [RelayCommand]
    private void RefreshAddresses()
    {
        RebuildBindOptions();
        Addresses.Clear();

        var bindOpt = IsRunning ? _runningBind : SelectedBind;
        int port = IsRunning ? _runningPort : Port;
        string kind = bindOpt?.Kind ?? "all";
        if (kind == "loopback")
        {
            Addresses.Add($"127.0.0.1:{port}");
        }
        else if (kind == "iface" && bindOpt is not null)
        {
            Addresses.Add($"{bindOpt.Address}:{port}");
        }
        else
        {
            foreach (var (_, address) in NicSnapshot.UpIPv4())
                Addresses.Add($"{address}:{port}");
            if (Addresses.Count == 0) Addresses.Add($"127.0.0.1:{port}");
        }

        if (SelectedShareUrl is null || !Addresses.Contains(SelectedShareUrl))
            SelectedShareUrl = Addresses.FirstOrDefault();
    }

    [RelayCommand]
    private async Task CopyAddress(string? addr)
    {
        if (!string.IsNullOrEmpty(addr)) await ClipboardHelper.SetTextAsync(addr);
    }
}
