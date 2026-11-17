namespace Echoes.ViewModels;

/// <summary>
/// What the desktop shell asks of a tool when its tab is closed: whether something runs that closing would stop (then it
/// asks first), and to stop it. Closing a tab ends what runs in it, as a browser tab does; the tool's inputs stay saved.
/// </summary>
public interface IToolSession
{
    /// <summary>A ping, scan, request, connection, server or monitor is running.</summary>
    bool IsBusy { get; }

    /// <summary>Stops whatever runs (no-op when idle). The view-model may be shown again later (a tool's first tab).</summary>
    void EndSession();

    /// <summary>
    /// What the tool's tab shows of it, as a dot on its glyph (MainView): running while <see cref="IsBusy"/>, unless the
    /// tool says more (SSH while it connects, the Monitor while a host is down). Read again on any property change.
    /// </summary>
    ToolState State => IsBusy ? ToolState.Running : ToolState.Idle;
}

/// <summary>A tool's state as its tab shows it: no dot when idle; green running; amber waiting (connecting, a host being
/// checked again before it is called down); red when something it watches is down.</summary>
public enum ToolState
{
    Idle,
    Running,
    Waiting,
    Down,
}

/// <summary>A tool that writes its settings with a delay: the exit flush reaches every instance through this.</summary>
public interface IPendingSave
{
    void FlushPendingSave();
}

// ---- tools that may run in several tabs ----

public partial class PingViewModel : IToolSession
{
    bool IToolSession.IsBusy => IsPinging;
    void IToolSession.EndSession() { if (IsPinging) Stop(); }
}

public partial class DnsViewModel : IToolSession
{
    bool IToolSession.IsBusy => IsWorking;
    void IToolSession.EndSession() => Stop();
}

public partial class CurlViewModel : IToolSession, IPendingSave
{
    bool IToolSession.IsBusy => IsWorking;
    void IToolSession.EndSession() { if (IsWorking) StopCurl(); }
}

public partial class SshViewModel : IToolSession, IPendingSave
{
    bool IToolSession.IsBusy => IsConnected || IsConnecting;
    void IToolSession.EndSession() { if (IsConnected || IsConnecting) Disconnect(); }
    ToolState IToolSession.State => IsConnecting ? ToolState.Waiting : IsConnected ? ToolState.Running : ToolState.Idle;
}

public partial class SocketViewModel : IToolSession
{
    bool IToolSession.IsBusy => IsRunning;
    void IToolSession.EndSession() { if (IsRunning) Stop(); }
}

public partial class PortScannerViewModel : IToolSession
{
    bool IToolSession.IsBusy => IsScanning;
    void IToolSession.EndSession() { if (IsScanning) StopScan(); }
}

public partial class TlsViewModel : IToolSession
{
    bool IToolSession.IsBusy => IsBusy || IsBulkBusy;
    void IToolSession.EndSession()
    {
        _cts?.Cancel();
        _bulkCts?.Cancel();
    }
}

public partial class IpInfoViewModel : IToolSession, IPendingSave
{
    bool IToolSession.IsBusy => IsWorking;
    void IToolSession.EndSession() { }   // a lookup is short and has nothing to stop: its answer just isn't shown
}

public partial class CheckHostViewModel : IToolSession, IPendingSave
{
    bool IToolSession.IsBusy => IsWorking;
    void IToolSession.EndSession() => _cts?.Cancel();
}

public partial class DoctorViewModel : IToolSession, IPendingSave
{
    bool IToolSession.IsBusy => IsRunning;
    void IToolSession.EndSession() { if (IsRunning) Stop(); }
}

public partial class StringLabViewModel : IToolSession, IPendingSave
{
    bool IToolSession.IsBusy => IsBusy;
    void IToolSession.EndSession() => CancelHashFile();
}

public partial class TgViewModel : IToolSession, IPendingSave
{
    bool IToolSession.IsBusy => IsSending || IsConnecting;
    void IToolSession.EndSession()
    {
        _connectCts?.Cancel();
        _sendCts?.Cancel();
    }
    ToolState IToolSession.State => IsConnecting ? ToolState.Waiting : IsSending ? ToolState.Running : ToolState.Idle;
}

// ---- tools with one tab ----

public partial class SpeedTestViewModel : IToolSession
{
    bool IToolSession.IsBusy => IsRunning;
    void IToolSession.EndSession() => _cts?.Cancel();
}

public partial class WebServerViewModel : IToolSession
{
    bool IToolSession.IsBusy => IsRunning || IsCatching;
    void IToolSession.EndSession()
    {
        if (IsRunning) StopServer();
        if (IsCatching) StopCatcher();
    }
}

public partial class ProxyViewModel : IToolSession
{
    bool IToolSession.IsBusy => IsRunning || IsChecking;
    void IToolSession.EndSession()
    {
        if (IsRunning) StopServer();
        if (IsChecking) StopChecks();
    }
}

public sealed partial class MonitorViewModel : IToolSession
{
    bool IToolSession.IsBusy => IsMonitoring;
    void IToolSession.EndSession() { if (IsMonitoring) StopMonitoring(); }
    // a host down is red, one failing but not yet called down (checked again first) amber
    ToolState IToolSession.State => !IsMonitoring ? ToolState.Idle
        : HasDown ? ToolState.Down
        : HasRetrying ? ToolState.Waiting
        : ToolState.Running;
}

public partial class CloudflareViewModel : IToolSession
{
    bool IToolSession.IsBusy => IsBusy;
    void IToolSession.EndSession() => _restoreCts?.Cancel();
}
