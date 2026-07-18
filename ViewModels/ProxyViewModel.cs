using System;
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
/// </summary>
public partial class ProxyViewModel : ObservableObject
{
    [ObservableProperty] private int _port = 1080;
    [ObservableProperty] private int _maxConnections = 64;
    [ObservableProperty] private bool _requireAuth;
    [ObservableProperty] private string _authUser = "echoes";
    [ObservableProperty] private string _authPass = string.Empty;
    [ObservableProperty] private bool _isRunning;
    [ObservableProperty] private string _statusMessage = "Set a port and START — serves SOCKS5 and HTTP on the same port.";

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

    private ProxyServer? _server;

    public ProxyViewModel() => RebuildBindOptions();

    private void RebuildBindOptions()
    {
        string? prevKind = SelectedBind?.Kind;
        string? prevAddr = SelectedBind?.Address.ToString();

        var list = new System.Collections.Generic.List<BindOption>
        {
            new("All interfaces (0.0.0.0) — reachable on your LAN", IPAddress.Any, "all"),
            new("Localhost only (127.0.0.1) — this device", IPAddress.Loopback, "loopback"),
        };
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                    if (ua.Address.AddressFamily == AddressFamily.InterNetwork)
                        list.Add(new BindOption($"{ua.Address}  ({ni.Name})", ua.Address, "iface"));
            }
        }
        catch { /* restricted platform — keep All + Localhost */ }

        _rebuildingBinds = true;
        BindOptions.Clear();
        foreach (var o in list) BindOptions.Add(o);
        SelectedBind = BindOptions.FirstOrDefault(o => o.Kind == prevKind && o.Address.ToString() == prevAddr)
                       ?? BindOptions.FirstOrDefault(o => o.Kind == "all")
                       ?? BindOptions.FirstOrDefault();
        _rebuildingBinds = false;
    }

    partial void OnSelectedBindChanged(BindOption? value)
    {
        if (!_rebuildingBinds) RefreshAddresses();
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

        IPAddress bind = SelectedBind?.Address ?? IPAddress.Any;
        try
        {
            ResetStats();
            _server = new ProxyServer(RequireAuth ? AuthUser : null, RequireAuth ? AuthPass : null, OnConnection, OnStats, MaxConnections);
            _server.Start(bind, Port);
            IsRunning = true;
            BackgroundGuard.Acquire("Proxy server");
            RefreshAddresses();
            StatusMessage = $"Proxy live on :{Port} — SOCKS5 + HTTP{(RequireAuth ? ", auth on" : "")}.";
        }
        catch (SocketException ex)
        {
            _server = null;
            StatusMessage = ex.SocketErrorCode is SocketError.AddressAlreadyInUse
                ? $"Port {Port} is already in use — pick another port."
                : "Cannot start proxy: " + ex.Message;
        }
        catch (Exception ex)
        {
            _server = null;
            StatusMessage = "Cannot start proxy: " + ex.Message;
        }
    }

    private void StopInternal()
    {
        bool wasRunning = IsRunning;
        try { _server?.Dispose(); } catch { }
        _server = null;
        IsRunning = false;
        if (wasRunning)
        {
            BackgroundGuard.Release();
            StatusMessage = "Stopped.";
        }
    }

    /// <summary>Release the listening socket + background guard on app shutdown.</summary>
    public void StopServer() => StopInternal();

    // Connection log callback — fires on a server thread, so marshal to the UI thread.
    private void OnConnection(ProxyLogEntry e)
    {
        Dispatcher.UIThread.Post(() =>
        {
            Connections.Insert(0, e);
            while (Connections.Count > 200) Connections.RemoveAt(Connections.Count - 1);
            OnPropertyChanged(nameof(HasConnections));
        });
    }

    private void OnStats()
    {
        Dispatcher.UIThread.Post(() =>
        {
            var s = _server;
            if (s is null) return;
            ActiveConnections = s.ActiveConnections;
            TotalConnections = s.TotalConnections;
            TrafficText = $"↑ {FileHttpServer.HumanSize(s.BytesUp)}   ↓ {FileHttpServer.HumanSize(s.BytesDown)}";
        });
    }

    private void ResetStats()
    {
        ActiveConnections = 0;
        TotalConnections = 0;
        TrafficText = "↑ 0 B   ↓ 0 B";
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

        string kind = SelectedBind?.Kind ?? "all";
        if (kind == "loopback")
        {
            Addresses.Add($"127.0.0.1:{Port}");
        }
        else if (kind == "iface" && SelectedBind is not null)
        {
            Addresses.Add($"{SelectedBind.Address}:{Port}");
        }
        else
        {
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                        if (ua.Address.AddressFamily == AddressFamily.InterNetwork)
                            Addresses.Add($"{ua.Address}:{Port}");
                }
            }
            catch { }
            if (Addresses.Count == 0) Addresses.Add($"127.0.0.1:{Port}");
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
