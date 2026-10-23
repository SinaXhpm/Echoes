using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using Renci.SshNet;
using Renci.SshNet.Common;
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>
/// The Forwarding sub-tab: the dynamic SOCKS5 tunnel (-D) and local (-L) / remote (-R) port forwards. They are part of
/// the connection's settings: each starts when the session comes up (and at once when added while connected), reports
/// its own status / error, and stops with the session.
/// </summary>
public partial class SshViewModel
{
    // ===================================================================== dynamic SOCKS tunnel (-D)
    [ObservableProperty] private bool _enableSocksTunnel;
    [ObservableProperty] private int _tunnelPort = 8080;
    [ObservableProperty] private string _tunnelHost = "127.0.0.1";
    [ObservableProperty] private string _tunnelStatus = "Tunnel: Offline";
    [ObservableProperty] private bool _tunnelExposed;   // the live SOCKS listener is reachable beyond loopback
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(CanEditTunnel))] private bool _tunnelActive;
    [ObservableProperty] private bool _tunnelFailed;

    public bool CanEditTunnel => !TunnelActive;

    // ===================================================================== -L / -R
    public ObservableCollection<SshForwardRule> Forwards { get; } = new();

    /// <summary>0 = local (-L), 1 = remote (-R).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(NewForwardHint), nameof(NewForwardBindLabel), nameof(NewForwardTargetLabel))]
    private int _newForwardKind;

    [ObservableProperty] private string _newForwardBindHost = "127.0.0.1";
    [ObservableProperty] private string _newForwardBindPort = string.Empty;
    [ObservableProperty] private string _newForwardTargetHost = "127.0.0.1";
    [ObservableProperty] private string _newForwardTargetPort = string.Empty;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasForwardError))] private string _forwardError = string.Empty;

    public bool HasForwardError => ForwardError.Length > 0;
    public bool HasForwards => Forwards.Count > 0;

    public string NewForwardHint => NewForwardKind == 0
        ? "ssh -L: a local port to host:port, via the server."
        : "ssh -R: a server port to host:port, via this device.";
    public string NewForwardBindLabel => NewForwardKind == 0 ? "Listen here" : "Listen on server";
    public string NewForwardTargetLabel => NewForwardKind == 0 ? "Forward to (from server)" : "Forward to (from here)";

    partial void OnEnableSocksTunnelChanged(bool value)
    {
        if (_filling || _session is not { } s) return;
        _ = Task.Run(() => { if (value) StartDynamic(s); else StopDynamic(s); });
    }

    [RelayCommand]
    private void AddForward()
    {
        ForwardError = string.Empty;
        bool remote = NewForwardKind == 1;
        string bindHost = NewForwardBindHost.Trim(), targetHost = NewForwardTargetHost.Trim();
        if (!SshText.TryPort(NewForwardBindPort, allowZero: !remote, out int bindPort))
        { ForwardError = remote ? "Enter the server port to listen on (1-65535)." : "Enter the local port to listen on (1-65535, 0 = any free port)."; return; }
        if (targetHost.Length == 0 || targetHost.Any(char.IsWhiteSpace)) { ForwardError = "Enter the host to forward to."; return; }
        if (!SshText.TryPort(NewForwardTargetPort, allowZero: false, out int targetPort)) { ForwardError = "Enter the port to forward to (1-65535)."; return; }
        if (bindHost.Any(char.IsWhiteSpace)) { ForwardError = "The listen address can't contain spaces."; return; }
        if (bindHost.Length == 0) bindHost = "127.0.0.1";
        if (Forwards.Count >= SshServerStore.MaxForwards) { ForwardError = $"At most {SshServerStore.MaxForwards} forwards."; return; }
        var spec = new SshForwardSpec(remote, bindHost, bindPort, targetHost, targetPort);
        if (bindPort != 0 && Forwards.Any(r => r.Spec.Remote == remote && r.Spec.BindPort == bindPort && string.Equals(r.Spec.BindHost, bindHost, StringComparison.OrdinalIgnoreCase)))
        { ForwardError = $"{(remote ? "The server port" : "Port")} {bindPort} is already forwarded."; return; }

        var rule = new SshForwardRule(spec);
        Forwards.Add(rule);
        OnPropertyChanged(nameof(HasForwards));
        NewForwardBindPort = string.Empty;
        NewForwardTargetPort = string.Empty;
        if (_session is { } s) StartRule(s, rule);
    }

    [RelayCommand]
    private void RemoveForward(SshForwardRule? rule)
    {
        if (rule is null || !Forwards.Contains(rule)) return;
        Forwards.Remove(rule);
        OnPropertyChanged(nameof(HasForwards));
        var port = rule.Port;
        var owner = rule.Owner as SshSession;
        rule.SetOff();
        if (port is not null) _ = Task.Run(() => ClosePort(owner, port));
    }

    // Thread pool. A remote forward's stop is a global request too: one at a time per session (see RemoteForwardGate).
    private static void ClosePort(SshSession? s, ForwardedPort port)
    {
        if (port is ForwardedPortRemote && s is not null)
        {
            lock (s.RemoteForwardGate) { try { port.Stop(); } catch { } }
        }
        else { try { port.Stop(); } catch { } }
        try { s?.Client.RemoveForwardedPort(port); } catch { }
        try { port.Dispose(); } catch { }
    }

    // UI thread, when a session comes up.
    private void StartForwardsFor(SshSession s)
    {
        foreach (var rule in Forwards) StartRule(s, rule);
        if (EnableSocksTunnel) _ = Task.Run(() => StartDynamic(s));
    }

    // UI thread: marks the rule and starts it on the thread pool (a remote forward waits for the server's answer).
    private void StartRule(SshSession s, SshForwardRule rule)
    {
        rule.SetStarting();
        var spec = rule.Spec;
        _ = Task.Run(() =>
        {
            ForwardedPort? port = null;
            try
            {
                // (-R resolves both hosts here: SSH.NET's constructor looks them up on this device)
                port = spec.Remote
                    ? new ForwardedPortRemote(spec.BindHost, (uint)spec.BindPort, spec.TargetHost, (uint)spec.TargetPort)
                    : new ForwardedPortLocal(spec.BindHost, (uint)spec.BindPort, spec.TargetHost, (uint)spec.TargetPort);
                var live = port;
                port.Exception += (_, e) =>
                {
                    string msg = e.Exception is SocketException se ? SocketText(se) : e.Exception.Message;
                    Dispatcher.UIThread.Post(() => { if (ReferenceEquals(rule.Port, live)) rule.LastError = "Last connection: " + msg; });
                };
                if (s.Closed) throw new SshLoginException("Not connected.");
                s.Client.AddForwardedPort(port);
                if (spec.Remote) { lock (s.RemoteForwardGate) port.Start(); }
                else { EnsurePoolForForwards(); port.Start(); }
                uint bound = port is ForwardedPortLocal l ? l.BoundPort : (uint)spec.BindPort;
                bool exposed = !spec.Remote && !SshText.IsLoopbackOnly(spec.BindHost);
                string status = spec.Remote
                    ? (SshText.IsLoopbackOnly(spec.BindHost) ? "Listening on the server" : "Listening on the server (its network may reach it)")
                    : exposed ? "Listening — ⚠ open to the network, no auth" : "Listening";
                var started = port;
                Dispatcher.UIThread.Post(() =>
                {
                    // removed meanwhile, or the session ended: undo
                    if (!Forwards.Contains(rule) || !ReferenceEquals(_session, s))
                    {
                        _ = Task.Run(() => ClosePort(s, started));
                        return;
                    }
                    rule.Port = started;
                    rule.Owner = s;
                    rule.SetActive(bound, exposed, status);
                });
            }
            catch (Exception ex)
            {
                if (port is not null)
                {
                    try { s.Client.RemoveForwardedPort(port); } catch { }
                    try { port.Dispose(); } catch { }
                }
                string error = ForwardStartError(ex, spec);
                Dispatcher.UIThread.Post(() =>
                {
                    if (Forwards.Contains(rule) && ReferenceEquals(_session, s)) rule.SetFailed(error);
                });
            }
        });
    }

    private static int s_poolRaised;

    // SSH.NET serves each forwarded connection on a pool thread for its whole life; past the pool's minimum, new ones got
    // in at ~1/s (the pool's thread injection rate) and the rest were refused. A browser on a -D tunnel keeps more than 64
    // idle keep-alive connections open. Raised once, never lowered; threads are still only made when needed.
    private static void EnsurePoolForForwards()
    {
        if (Interlocked.Exchange(ref s_poolRaised, 1) != 0) return;
        ThreadPool.GetMinThreads(out int workers, out int io);
        if (workers < 128) ThreadPool.SetMinThreads(128, io);
    }

    private static string ForwardStartError(Exception ex, SshForwardSpec spec)
    {
        if (ex is SocketException se)
            return se.SocketErrorCode switch
            {
                SocketError.AddressAlreadyInUse => $"Port {spec.BindPort} is already in use on this device.",
                SocketError.AccessDenied => $"Not allowed to listen on port {spec.BindPort} here (low ports need admin rights).",
                SocketError.AddressNotAvailable => $"{spec.BindHost} isn't an address of this device.",
                _ => SocketText(se),
            };
        if (spec.Remote && ex is SshException)
            return $"The server refused to listen on {SshText.Endpoint(spec.BindHost, spec.BindPort)} (port in use, or forwarding is off on the server).";
        return ex.Message;
    }

    private static string SocketText(SocketException se) => se.SocketErrorCode switch
    {
        SocketError.ConnectionRefused => "connection refused",
        SocketError.HostNotFound => "host not found",
        SocketError.TimedOut => "timed out",
        _ => se.Message,
    };

    // ---------------------------------------------------------------- dynamic tunnel (thread pool)
    private void StartDynamic(SshSession s)
    {
        if (s.Dynamic is not null || s.Closed) return;
        string listenHost = TunnelHost.Trim();   // read once: the warning must name what was actually bound
        int listenPort = TunnelPort;
        if (listenPort is < 0 or > 65535)
        {
            Dispatcher.UIThread.Post(() => { if (ReferenceEquals(_session, s)) SetTunnelFailed("The tunnel port must be 0-65535."); });
            return;
        }
        var fw = new ForwardedPortDynamic(listenHost, (uint)listenPort);
        try
        {
            s.Client.AddForwardedPort(fw);
            EnsurePoolForForwards();
            fw.Start();
        }
        catch (Exception ex)
        {
            try { s.Client.RemoveForwardedPort(fw); } catch { }
            try { fw.Dispose(); } catch { }
            string error = ex is SocketException { SocketErrorCode: SocketError.AddressAlreadyInUse }
                ? $"SOCKS5 tunnel: port {listenPort} is already in use."
                : "SOCKS5 tunnel: " + ex.Message;
            AppendToTerminal($"# {error}\n");
            Dispatcher.UIThread.Post(() => { if (ReferenceEquals(_session, s)) SetTunnelFailed(error); });
            return;
        }
        s.Dynamic = fw;

        // The SOCKS listener has no authentication: bound anywhere but loopback it is an open proxy that relays anyone
        // who can reach the port through the SSH server. Never let that happen silently.
        string where = SshText.Endpoint(listenHost, fw.BoundPort);
        bool exposed = !SshText.IsLoopbackOnly(listenHost);
        if (exposed)
            AppendToTerminal(
                $"# ⚠ SOCKS tunnel listens on {where} — not loopback, and it has no password:\n" +
                "#   anyone who can reach this port can relay traffic through the SSH server.\n" +
                "#   Set the tunnel's listen address to 127.0.0.1 to keep it local.\n");
        Dispatcher.UIThread.Post(() =>
        {
            if (!ReferenceEquals(_session, s)) return;   // that session already ended
            TunnelActive = true;
            TunnelFailed = false;
            TunnelExposed = exposed;
            TunnelStatus = exposed ? $"SOCKS5 Proxy: {where} — ⚠ open to the network, no auth" : $"SOCKS5 Proxy: {where}";
        });
    }

    private void StopDynamic(SshSession s)
    {
        var fw = s.Dynamic;
        s.Dynamic = null;
        if (fw is not null)
        {
            try { fw.Stop(); } catch { }
            try { s.Client.RemoveForwardedPort(fw); } catch { }
            try { fw.Dispose(); } catch { }
        }
        Dispatcher.UIThread.Post(() => { if (ReferenceEquals(_session, s)) ResetTunnelState(); });
    }

    private void SetTunnelFailed(string error)
    {
        TunnelActive = false;
        TunnelFailed = true;
        TunnelExposed = false;
        TunnelStatus = error;
    }

    private void ResetTunnelState()
    {
        TunnelActive = false;
        TunnelFailed = false;
        TunnelExposed = false;
        TunnelStatus = "Tunnel: Offline";
    }
}
