using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading.Tasks;
using Avalonia.Collections;
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
/// Connections can leave from a chosen network interface, and the Advanced part holds the usual server options:
/// which protocols answer (SOCKS5 UDP too), an upstream proxy to go on through, time-outs, limits, and rules for who may
/// connect and where to.
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
    [ObservableProperty] private string _statusMessage = "SOCKS5, SOCKS4 and HTTP share one port.";

    /// <summary>The interface every connection to a target leaves from: "Default route" lets the system choose, as it
    /// always did. Taken when the proxy starts; locked while it runs.</summary>
    public IfacePicker OutIface { get; } = new(ProfileService.Instance, KIface, "Default route",
                                               "The system chooses the interface (its routing table)");

    /// <summary>Which kind of address the proxy connects to (<see cref="ProxyIpVersion"/>, by index).</summary>
    public string[] IpVersionOptions { get; } = { "Auto", "IPv4 only", "IPv6 only" };
    [ObservableProperty] private int _ipVersionIndex;

    // ---- Advanced (all read at START, like the settings above) ----
    [ObservableProperty] private bool _showAdvanced;
    [ObservableProperty] private bool _socks5 = true;
    [ObservableProperty] private bool _socks4 = true;
    [ObservableProperty] private bool _http = true;
    /// <summary>SOCKS5 clients may relay UDP (UDP ASSOCIATE). Off until switched on.</summary>
    [ObservableProperty] private bool _udp;
    /// <summary>Seconds a connection to a target may take.</summary>
    [ObservableProperty] private int _connectTimeout = DefaultConnectTimeout;
    /// <summary>Seconds without traffic after which a tunnel is closed.</summary>
    [ObservableProperty] private int _idleTimeout = DefaultIdleTimeout;
    /// <summary>Connections at once from one other device; empty = automatic.</summary>
    [ObservableProperty] private int? _maxPerClient;
    /// <summary>KB/s for all connections together, each way; empty = no limit.</summary>
    [ObservableProperty] private int? _speedLimit;
    // The three rule boxes, as typed (ProxyRules reads them at START).
    [ObservableProperty] private string _allowedClients = string.Empty;
    [ObservableProperty] private string _allowedPorts = string.Empty;
    [ObservableProperty] private string _blockedHosts = string.Empty;

    // The upstream proxy every connection goes on through (ProxyUpstream reads it at START). The address is kept without
    // a login (one typed into it moves to the two fields), the password only sealed.
    [ObservableProperty] private bool _useUpstream;
    [ObservableProperty] private string _upstreamAddress = string.Empty;
    [ObservableProperty] private string _upstreamUser = string.Empty;
    [ObservableProperty] private string _upstreamPass = string.Empty;
    /// <summary>Site names go to the upstream as names (it looks them up), where that is safe.</summary>
    [ObservableProperty] private bool _upstreamResolve = true;

    public const int DefaultConnectTimeout = 15, DefaultIdleTimeout = 300;
    public const int MaxSpeedLimitKb = 1_000_000;
    /// <summary>The longest text a rule box keeps (the boxes' MaxLength).</summary>
    public const int MaxRuleChars = 60_000;

    /// <summary>How many Advanced options are set away from their defaults: the number on the Advanced heading, so a
    /// closed part still shows that something in it is at work.</summary>
    public int AdvancedCount => AdvancedParts().Count;
    public bool HasAdvancedChanges => AdvancedCount > 0;

    /// <summary>The Advanced heading's tooltip: what the part holds, and what is set in it now
    /// ("SOCKS4 off · 500 KB/s · hosts blocked").</summary>
    public string AdvancedTip
    {
        get
        {
            const string what = "Protocols and UDP, an upstream proxy, time-outs, limits, and rules for who may connect and where to";
            var parts = AdvancedParts();
            return parts.Count == 0 ? what : what + "\nSet now: " + string.Join(" · ", parts);
        }
    }

    private List<string> AdvancedParts()
    {
        var parts = new List<string>();
        if (!Socks5) parts.Add("SOCKS5 off");
        if (!Socks4) parts.Add("SOCKS4 off");
        if (!Http) parts.Add("HTTP off");
        if (Udp) parts.Add("UDP on");
        if (UseUpstream) parts.Add("upstream proxy");
        if (ConnectTimeout != DefaultConnectTimeout) parts.Add($"connect {ConnectTimeout} s");
        if (IdleTimeout != DefaultIdleTimeout) parts.Add($"idle {IdleTimeout} s");
        if (MaxPerClient is > 0) parts.Add($"{MaxPerClient} per client");
        if (SpeedLimit is > 0) parts.Add($"{SpeedLimit} KB/s");
        if (!string.IsNullOrWhiteSpace(AllowedClients)) parts.Add("clients limited");
        if (!string.IsNullOrWhiteSpace(AllowedPorts)) parts.Add("ports limited");
        if (!string.IsNullOrWhiteSpace(BlockedHosts)) parts.Add("hosts blocked");
        return parts;
    }

    // How the server binds: all interfaces (LAN), loopback, or one specific IP. Reuses BindOption.
    public ObservableCollection<BindOption> BindOptions { get; } = new();
    [ObservableProperty] private BindOption? _selectedBind;
    private bool _rebuildingBinds;

    public ObservableCollection<string> Addresses { get; } = new();
    [ObservableProperty] private string? _selectedShareUrl;

    // Live stats.
    [ObservableProperty] private int _activeConnections;
    [ObservableProperty] private long _totalConnections;
    // each way: the total since START, and the rate right now
    [ObservableProperty] private string _uploadText = "0 B";
    [ObservableProperty] private string _downloadText = "0 B";
    [ObservableProperty] private string _uploadRate = "0 B/s";
    [ObservableProperty] private string _downloadRate = "0 B/s";

    // Newest connection first; capped so a busy proxy can't grow the list unbounded. Filled a batch at a time (one insert
    // per entry shifted and restyled every striped row once per entry: ~50 a page load).
    public AvaloniaList<ProxyLogEntry> Connections { get; } = new() { ResetBehavior = ResetBehavior.Reset };
    public bool HasConnections => Connections.Count > 0;
    private const int MaxLogRows = 200;

    // Server callbacks fire on connection threads. Rather than one UI post per event (a busy or hostile
    // client could queue thousands), log entries wait here and a UI timer drains them in one batch and
    // polls the traffic counters — which also keeps ↑/↓ moving during a long transfer.
    private readonly ConcurrentQueue<ProxyLogEntry> _pendingLog = new();
    private PacedTimer? _statsTimer;

    private ProxyServer? _server;
    private ListenerWatch? _watch;
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
        KPass = "proxy.pass", KBind = "proxy.bind", KView = "proxy.view", KSort = "proxy.sort", KList = "proxy.list",
        KIface = "proxy.iface", KIpVersion = "proxy.ipVersion", KAdvanced = "proxy.advanced",
        KSocks5 = "proxy.socks5", KSocks4 = "proxy.socks4", KHttp = "proxy.http",
        KConnectTimeout = "proxy.connectTimeout", KIdleTimeout = "proxy.idleTimeout",
        KPerClient = "proxy.perClient", KSpeedLimit = "proxy.speedLimit",
        KAllowClients = "proxy.allowClients", KAllowPorts = "proxy.allowPorts", KBlockHosts = "proxy.blockHosts", KUdp = "proxy.udp",
        // ("proxy.useProxy", as every tool's switch for a proxy is called: a restored backup turns it off, as it does theirs)
        KUseUpstream = "proxy.useProxy", KUpstream = "proxy.upstream", KUpUser = "proxy.upstreamUser", KUpPass = "proxy.upstreamPass",
        KUpResolve = "proxy.upstreamDns";
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
            IpVersionIndex = Math.Clamp(p.GetInt(KIpVersion, 0), 0, IpVersionOptions.Length - 1);
            ShowAdvanced = p.GetBool(KAdvanced);
            Socks5 = p.GetBool(KSocks5, true);
            Socks4 = p.GetBool(KSocks4, true);
            Http = p.GetBool(KHttp, true);
            Udp = p.GetBool(KUdp);
            UseUpstream = p.GetBool(KUseUpstream);
            UpstreamAddress = p.GetSetting(KUpstream) ?? string.Empty;
            UpstreamUser = p.GetSetting(KUpUser) ?? string.Empty;
            UpstreamPass = SecretProtector.Unprotect(p.GetSetting(KUpPass));
            UpstreamResolve = p.GetBool(KUpResolve, true);
            ConnectTimeout = Math.Clamp(p.GetInt(KConnectTimeout, DefaultConnectTimeout), 1, 120);
            IdleTimeout = Math.Clamp(p.GetInt(KIdleTimeout, DefaultIdleTimeout), 10, 86_400);
            MaxPerClient = p.GetInt(KPerClient, 0) is > 0 and <= 512 and var perClient ? perClient : null;
            SpeedLimit = p.GetInt(KSpeedLimit, 0) is > 0 and var kb ? Math.Min(kb, MaxSpeedLimitKb) : null;
            AllowedClients = CapRule(p.GetSetting(KAllowClients));
            AllowedPorts = CapRule(p.GetSetting(KAllowPorts));
            BlockedHosts = CapRule(p.GetSetting(KBlockHosts));
            RestoreCheckOptions(p);
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

    partial void OnIpVersionIndexChanged(int value) { if (!_restoring && value >= 0) SaveInt(KIpVersion, value); }
    partial void OnShowAdvancedChanged(bool value) { if (!_restoring) ProfileService.Instance.SetBool(KAdvanced, value); }

    // An Advanced option changed: kept (not while the saved ones are read in), and the count on the heading follows.
    private void AdvancedChanged(Action save)
    {
        if (!_restoring) save();
        OnPropertyChanged(nameof(AdvancedCount));
        OnPropertyChanged(nameof(HasAdvancedChanges));
        OnPropertyChanged(nameof(AdvancedTip));
    }

    private static void SaveText(string key, string? value)
        => ProfileService.Instance.SetSetting(key, string.IsNullOrWhiteSpace(value) ? null : value);

    // A saved rule list as the box takes it (a plain cut: TextLimit.Cap would add its "truncated" note to the rules).
    private static string CapRule(string? saved)
        => saved is null ? string.Empty : saved.Length <= MaxRuleChars ? saved : saved[..MaxRuleChars];

    partial void OnSocks5Changed(bool value) => AdvancedChanged(() => ProfileService.Instance.SetBool(KSocks5, value));
    partial void OnSocks4Changed(bool value) => AdvancedChanged(() => ProfileService.Instance.SetBool(KSocks4, value));
    partial void OnHttpChanged(bool value) => AdvancedChanged(() => ProfileService.Instance.SetBool(KHttp, value));
    partial void OnConnectTimeoutChanged(int value) => AdvancedChanged(() => { if (value is >= 1 and <= 120) SaveInt(KConnectTimeout, value); });
    partial void OnIdleTimeoutChanged(int value) => AdvancedChanged(() => { if (value is >= 10 and <= 86_400) SaveInt(KIdleTimeout, value); });
    partial void OnMaxPerClientChanged(int? value) => AdvancedChanged(() => SaveInt(KPerClient, value is > 0 and <= 512 ? value.Value : 0));
    partial void OnSpeedLimitChanged(int? value) => AdvancedChanged(() => SaveInt(KSpeedLimit, value is > 0 ? Math.Min(value.Value, MaxSpeedLimitKb) : 0));
    partial void OnAllowedClientsChanged(string value) => AdvancedChanged(() => SaveText(KAllowClients, value));
    partial void OnAllowedPortsChanged(string value) => AdvancedChanged(() => SaveText(KAllowPorts, value));
    partial void OnBlockedHostsChanged(string value) => AdvancedChanged(() => SaveText(KBlockHosts, value));
    partial void OnUdpChanged(bool value) => AdvancedChanged(() => ProfileService.Instance.SetBool(KUdp, value));
    partial void OnUseUpstreamChanged(bool value) => AdvancedChanged(() => ProfileService.Instance.SetBool(KUseUpstream, value));
    partial void OnUpstreamUserChanged(string value) { if (!_restoring) SaveText(KUpUser, value); }
    partial void OnUpstreamResolveChanged(bool value) { if (!_restoring) ProfileService.Instance.SetBool(KUpResolve, value); }

    partial void OnUpstreamPassChanged(string value)
    {
        if (!_restoring) ProfileService.Instance.SetSetting(KUpPass, string.IsNullOrEmpty(value) ? null : SecretProtector.Protect(value));
    }

    // Kept without a login: "user:pass@host:port" is saved as "host:port", and the login moves into the two fields
    // (the password sealed) once typing pauses, so the text doesn't change under the caret.
    partial void OnUpstreamAddressChanged(string value)
    {
        if (_restoring) return;
        SaveText(KUpstream, HttpHelper.WithoutUserInfo(value));
        if (value.Contains('@')) _ = MoveLoginSoonAsync();
    }

    private int _loginEdit;

    // 0.8 s after the last edit (a newer one starts the wait again), back on the UI thread.
    private async Task MoveLoginSoonAsync()
    {
        int edit = ++_loginEdit;
        await Task.Delay(800);
        if (edit == _loginEdit) MoveUpstreamLogin();
    }

    private void MoveUpstreamLogin()
    {
        if (ProxyUpstream.SplitLogin(UpstreamAddress) is not { } split) return;
        UpstreamAddress = split.Address;
        if (split.User.Length > 0) UpstreamUser = split.User;
        if (split.Pass.Length > 0) UpstreamPass = split.Pass;
    }

    // The upstream is this proxy itself (its port, on an address it listens on): every connection would come back here,
    // again and again. Another program's proxy on the same port of another address is fine: v2rayN on 127.0.0.1:1080,
    // shared to the network on the LAN address's port 1080.
    private bool IsThisProxy(ProxyUpstream up, IPAddress bind)
    {
        if (up.Port != Port) return false;
        bool all = bind.Equals(IPAddress.Any);
        if (up.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase)) return all || IPAddress.IsLoopback(bind);
        if (!IPAddress.TryParse(up.Host, out var a)) return false;
        if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
        if (a.AddressFamily != AddressFamily.InterNetwork) return false;   // the listener is IPv4
        if (!all) return a.Equals(bind);
        return IPAddress.IsLoopback(a) || a.Equals(IPAddress.Any) || NetIfaces.Up(withLoopback: true).Any(i => a.Equals(i.V4));
    }

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
    private void ToggleAdvanced() => ShowAdvanced = !ShowAdvanced;

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

        // The Advanced part. What is wrong there is said (and the part opened), never guessed around: a proxy started
        // with half a rule list would let through what the list was written to keep out.
        if (!Socks5 && !Socks4 && !Http) { Refuse("Turn on at least one protocol (Advanced)."); return; }
        if (RequireAuth && !Socks5 && !Http) { Refuse("SOCKS4 has no password login: turn on SOCKS5 or HTTP, or turn the password off."); return; }
        if (ConnectTimeout is < 1 or > 120) { Refuse("The connect time-out must be between 1 and 120 seconds."); return; }
        if (IdleTimeout is < 10 or > 86_400) { Refuse("The idle time-out must be between 10 and 86400 seconds."); return; }
        var rules = ProxyRules.Parse(AllowedClients, BlockedHosts, AllowedPorts, out string? problem);
        if (problem is not null) { Refuse(problem); return; }
        ProxyUpstream? upstream = null;
        if (UseUpstream)
        {
            MoveUpstreamLogin();   // a login still in the address (typed a moment ago)
            upstream = ProxyUpstream.Parse(UpstreamAddress, UpstreamUser, UpstreamPass, UpstreamResolve, out string? upProblem);
            if (upstream is null) { Refuse(upProblem ?? "Enter the upstream proxy's address (host:port)."); return; }
            if (IsThisProxy(upstream, SelectedBind?.Address ?? IPAddress.Any)) { Refuse($"The upstream proxy can't be this proxy itself (port {Port} of this device)."); return; }
        }

        // The chosen outgoing interface as it is now. Not up: said at once, instead of a proxy that connects nowhere.
        var ipVersion = (ProxyIpVersion)Math.Clamp(IpVersionIndex, 0, IpVersionOptions.Length - 1);
        string? outName = OutIface.Name;
        if (outName is not null)
        {
            if (OutIface.Resolve() is not { } via)
            {
                StatusMessage = $"{outName} isn't connected: choose another outgoing interface, or Default route.";
                return;
            }
            if (ipVersion == ProxyIpVersion.IPv6 && !via.HasV6) { StatusMessage = $"{outName} has no IPv6 address: set the IP version to Auto or IPv4 only."; return; }
            if (ipVersion == ProxyIpVersion.IPv4 && !via.HasV4) { StatusMessage = $"{outName} has no IPv4 address: set the IP version to Auto or IPv6 only."; return; }
        }

        IPAddress bind = SelectedBind?.Address ?? IPAddress.Any;
        try
        {
            ResetStats();
            _server = new ProxyServer(new ProxyServerOptions
            {
                User = RequireAuth ? AuthUser : null,
                Pass = RequireAuth ? AuthPass : null,
                MaxConnections = MaxConnections,
                MaxPerClient = MaxPerClient is > 0 ? MaxPerClient.Value : 0,
                Socks5 = Socks5,
                Socks4 = Socks4,
                Http = Http,
                Udp = Udp,
                Upstream = upstream,
                OutInterface = outName,
                IpVersion = ipVersion,
                ConnectTimeoutMs = ConnectTimeout * 1000,
                IdleTimeoutMs = IdleTimeout * 1000,
                SpeedLimit = SpeedLimit is > 0 ? Math.Min(SpeedLimit.Value, MaxSpeedLimitKb) * 1024L : 0,
                Rules = rules,
            }, OnConnection);
            _server.Start(bind, Port);
            var server = _server;
            _watch = new ListenerWatch(bind, Port, reason => RestartLost(server, reason));
            server.ListenerLost += _watch.Lost;
            _runningBind = SelectedBind ?? new BindOption("All interfaces", IPAddress.Any, "all");
            _runningPort = Port;
            IsRunning = true;
            BackgroundGuard.Acquire("Proxy server");
            _statsTimer = new PacedTimer(500, 2000, PollStats);   // twice a second while traffic moves, every 2 s when idle
            _statsTimer.Start();
            RefreshAddresses();
            // No auth on a LAN-reachable bind = anyone on the network can use it. That's the feature,
            // so it isn't blocked — but say so plainly instead of a bare "live".
            bool openToLan = !RequireAuth && !IPAddress.IsLoopback(bind) && !rules.LimitsClients;
            // (SOCKS4 has no password login: with one required it is refused, so it isn't listed)
            // (UDP goes through a SOCKS5 upstream only: through another kind it is said apart)
            bool udpBlocked = Udp && Socks5 && upstream is { Kind: not ProxyUpstreamKind.Socks5 };
            bool udp = Udp && Socks5 && !udpBlocked;
            string protocols = string.Join(" + ", new[] { Socks5 ? udp ? "SOCKS5 with UDP" : "SOCKS5" : null, Socks4 && !RequireAuth ? "SOCKS4" : null, Http ? "HTTP" : null }
                                                  .Where(p => p is not null));
            StatusMessage = $"Proxy live on :{Port} — {protocols}{(RequireAuth ? ", auth on" : "")}{(outName is not null ? $", out through {outName}" : "")}"
                            + (upstream is not null ? $", via {upstream.Display}" : "") + "."
                            + (udpBlocked ? $" UDP is off: {(upstream!.Kind == ProxyUpstreamKind.Socks4a ? "a" : "an")} {upstream.KindName} upstream proxy can't carry it." : "")
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

    // START refused over something in the Advanced part: say what, and show the part.
    private void Refuse(string why)
    {
        StatusMessage = why;
        ShowAdvanced = true;
    }

    private void StopInternal()
    {
        bool wasRunning = IsRunning;
        _statsTimer?.Stop();
        _statsTimer = null;
        DrainLog();   // entries logged just before STOP still show
        try { _server?.Dispose(); } catch { }
        _server = null;
        _watch?.Dispose();
        _watch = null;
        IsRunning = false;
        if (wasRunning)
        {
            BackgroundGuard.Release("Proxy server");
            StatusMessage = "Stopped.";
        }
    }

    // The listening socket is gone (iOS reclaims a suspended app's): the proxy starts again with the same settings.
    private void RestartLost(ProxyServer server, string reason)
    {
        if (!ReferenceEquals(_server, server)) return;
        StopInternal();
        Start();
        if (IsRunning) StatusMessage = $"Started again: the listening socket had closed ({reason}). " + StatusMessage;
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
        _statsTimer?.Poke();   // the first connection after a quiet spell is listed at once
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
        long up = s.BytesUp, down = s.BytesDown;
        if (moved)
        {
            UploadText = FileHttpServer.HumanSize(up);
            DownloadText = FileHttpServer.HumanSize(down);
        }
        // the rate over the time since the last reading (a tick that comes early is added to the next one)
        long now = Stopwatch.GetTimestamp();
        double seconds = Stopwatch.GetElapsedTime(_rateAt, now).TotalSeconds;
        if (seconds >= 0.4)
        {
            UploadRate = Rate((up - _rateUp) / seconds);
            DownloadRate = Rate((down - _rateDown) / seconds);
            (_rateUp, _rateDown, _rateAt) = (up, down, now);
        }
        return DrainLog() || moved;
    }

    private static string Rate(double bytesPerSecond) => FileHttpServer.HumanSize((long)Math.Max(0, bytesPerSecond)) + "/s";

    private long _lastActivity = -1;
    private long _rateUp, _rateDown, _rateAt;

    private bool DrainLog()
    {
        List<ProxyLogEntry>? batch = null;
        while (_pendingLog.TryDequeue(out var e)) (batch ??= new()).Add(e);
        if (batch is null) return false;
        batch.Reverse();   // newest first
        if (batch.Count > MaxLogRows) batch.RemoveRange(MaxLogRows, batch.Count - MaxLogRows);
        Connections.InsertRange(0, batch);
        if (Connections.Count > MaxLogRows) Connections.RemoveRange(MaxLogRows, Connections.Count - MaxLogRows);
        OnPropertyChanged(nameof(HasConnections));
        return true;
    }

    private void ResetStats()
    {
        ActiveConnections = 0;
        TotalConnections = 0;
        UploadText = DownloadText = "0 B";
        UploadRate = DownloadRate = "0 B/s";
        (_rateUp, _rateDown, _rateAt) = (0, 0, Stopwatch.GetTimestamp());
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
