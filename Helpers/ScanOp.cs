using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>
/// One probe's connect or receive, awaited without exceptions and timestamped the moment the OS completes it.
/// The exception-based socket API timed a refusal only after the SocketException had been thrown and unwound — the
/// first throws in a process cost tens of milliseconds, so a 1 ms LAN host's RSTs read as 40 ms, which skewed its
/// RTT estimate and made its SYN-ACKs look suspiciously fast. A scan of 65k closed ports also threw 65k exceptions.
/// </summary>
internal sealed class ScanOp : SocketAsyncEventArgs
{
    private TaskCompletionSource? _done;

    /// <summary>When the operation completed (Stopwatch ticks).</summary>
    public long CompletedTicks { get; private set; }

    protected override void OnCompleted(SocketAsyncEventArgs e)
    {
        CompletedTicks = Stopwatch.GetTimestamp();
        _done?.TrySetResult();
    }

    /// <summary>Connect: Success, a refusal / unreachable error, TimedOut at the deadline, OperationAborted when stopped.</summary>
    public ValueTask<SocketError> ConnectAsync(Socket socket, EndPoint remote, int timeoutMs, CancellationToken ct)
    {
        RemoteEndPoint = remote;
        return RunAsync(socket, connect: true, timeoutMs, ct);
    }

    /// <summary>Receive into <paramref name="buffer"/>: Success (see BytesTransferred), an ICMP-reported error, TimedOut, OperationAborted.</summary>
    public ValueTask<SocketError> ReceiveAsync(Socket socket, Memory<byte> buffer, int timeoutMs, CancellationToken ct)
    {
        SetBuffer(buffer);
        return RunAsync(socket, connect: false, timeoutMs, ct);
    }

    private async ValueTask<SocketError> RunAsync(Socket socket, bool connect, int timeoutMs, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return SocketError.OperationAborted;
        _done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        bool pending;
        try { pending = connect ? socket.ConnectAsync(this) : socket.ReceiveAsync(this); }
        catch (ObjectDisposedException) { return SocketError.OperationAborted; }   // stopped: the socket was closed
        if (!pending)
        {
            CompletedTicks = Stopwatch.GetTimestamp();
            return SocketError;
        }

        // Deadline or stop: abort the operation, which then completes with OperationAborted.
        int expired = 0;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeoutMs);
        await using (deadline.Token.Register(() =>
                     {
                         Volatile.Write(ref expired, 1);
                         try
                         {
                             if (connect) Socket.CancelConnectAsync(this);
                             else socket.Dispose();   // a receive has no cancel: closing the socket ends it
                         }
                         catch { }
                     }).ConfigureAwait(false))
        {
            await _done.Task.ConfigureAwait(false);
        }
        if (SocketError == SocketError.Success) return SocketError.Success;   // completed just as the deadline fired
        if (Volatile.Read(ref expired) == 1)
            return ct.IsCancellationRequested ? SocketError.OperationAborted : SocketError.TimedOut;
        return SocketError;
    }
}
