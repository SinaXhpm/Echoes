using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;

namespace Echoes.Helpers;

/// <summary>
/// iOS closes the listening sockets of an app it has suspended for a while: a server kept its "running" status and took
/// no one in. A server's view-model keeps one of these while the server runs. When the accept loop reports its socket
/// gone (<see cref="Lost"/>), or Echoes is back on screen after long enough away and its own port no longer answers, the
/// restart action runs once, on the UI thread: the server starts again with the same settings.
/// </summary>
public sealed class ListenerWatch : IDisposable
{
    // iOS suspends an app seconds after it leaves the screen; shorter absences aren't worth a probe
    private const long AwayLongEnoughMs = 20_000;

    private readonly IPAddress _bind;
    private readonly int _port;
    private readonly Action<string> _restart;
    private int _done;

    public ListenerWatch(IPAddress bind, int port, Action<string> restart)
    {
        _bind = bind;
        _port = port;
        _restart = restart;
        if (OperatingSystem.IsIOS()) AppPlatform.ForegroundChanged += OnForegroundChanged;
    }

    /// <summary>The accept loop gave up on its socket (any thread).</summary>
    public void Lost(string reason) => Fire(reason);

    private async void OnForegroundChanged()
    {
        if (!AppPlatform.IsInForeground || AppPlatform.HiddenSince == 0
            || Environment.TickCount64 - AppPlatform.HiddenSince < AwayLongEnoughMs) return;
        try
        {
            if (!await AnswersAsync(_bind, _port)) Fire("the system closed it while Echoes was in the background");
        }
        catch (Exception ex) { CrashLog.Write("ListenerWatch.Probe", ex); }
    }

    private void Fire(string reason)
    {
        if (Interlocked.Exchange(ref _done, 1) != 0) return;
        Dispatcher.UIThread.Post(() => _restart(reason));
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref _done, 1);
        if (OperatingSystem.IsIOS()) AppPlatform.ForegroundChanged -= OnForegroundChanged;
    }

    // A connection to the server's own port: refused means nothing listens there any more. No answer in time is taken for
    // a busy server, not a dead one.
    private static async Task<bool> AnswersAsync(IPAddress bind, int port)
    {
        var to = bind.Equals(IPAddress.Any) ? IPAddress.Loopback : bind.Equals(IPAddress.IPv6Any) ? IPAddress.IPv6Loopback : bind;
        using var probe = new Socket(to.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        using var cts = new CancellationTokenSource(2000);
        try
        {
            await probe.ConnectAsync(to, port, cts.Token).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException) { return true; }
        catch (SocketException) { return false; }
    }
}
