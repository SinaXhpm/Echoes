using System;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Echoes.Helpers;

namespace Echoes.Desktop;

/// <summary>
/// Lets a second launch bring the running instance's window to the front before it exits (see Program.Main). With
/// close-to-tray that instance may have no window on screen at all, and a launch that silently did nothing would look
/// broken.
///
/// <para>The instance holding the lock listens on a per-user named pipe (a Unix domain socket on Linux / macOS). It is a
/// local IPC surface, so it does as little as possible: both ends are current-user-only (Windows: the pipe's ACL admits
/// only this user, and the client checks the server's owner; Unix: each end checks the peer's uid), the server reads at
/// most a few bytes within a deadline and accepts exactly the ASCII bytes "SHOW" followed by the client closing its end
/// — no parsing, no paths, no arguments — and the one thing a request can do is show the window.</para>
/// </summary>
internal static class SingleInstance
{
    // The whole protocol: these 4 bytes, then the client closes its end.
    private static readonly byte[] ShowCommand = "SHOW"u8.ToArray();

    private const int ConnectTimeoutMs = 1000;   // a listener that exists but is busy with another client
    private const int WriteTimeoutMs = 500;
    private const int SignalTimeoutMs = 2000;    // backstop for the whole exchange
    private const int ReadTimeoutMs = 1000;      // a client that connects and stalls is dropped after this
    private const int MaxFailures = 5;           // listener failures in a row before it gives up

    private static CancellationTokenSource? s_stop;
    private static Task? s_listener;
    private static NamedPipeServerStream? s_server;   // the listener's pipe, so StopListening can close it itself
    private static Action? s_showRequested;

    /// <summary>
    /// Per-user and short: "echoes-" + 16 hex chars of SHA-256(the user's data dir). On Unix .NET makes the name a socket
    /// path in the temp dir, and those are capped at ~104 chars (macOS' $TMPDIR alone is ~50).
    /// </summary>
    internal static string PipeName { get; } = CreatePipeName();

    /// <summary>
    /// What a valid request does, called on the listener's thread (so it must post to the UI thread itself). Set once
    /// the main window exists; until then a request is dropped, as startup is about to show the window anyway.
    /// </summary>
    public static Action? ShowRequested
    {
        get => Volatile.Read(ref s_showRequested);
        set => Volatile.Write(ref s_showRequested, value);
    }

    private static string CreatePipeName()
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(AppStorage.UserDir()));
        return "echoes-" + Convert.ToHexString(hash, 0, 8).ToLowerInvariant();
    }

    // ---------- Second launch ----------

    /// <summary>
    /// Asks the running instance to show its window. True once the request is delivered; false when nothing listens (an
    /// older Echoes, or one still starting up) or anything goes wrong — the caller then exits as before. Never hangs:
    /// no listener fails at once, a busy one gets ~1.5 s, and nothing takes longer than 2 s.
    /// </summary>
    public static bool TrySignalExisting()
    {
        // Every step has its own timeout; this is the backstop on top of them. Whatever might still block (a wedged
        // peer, a pipe call that doesn't honour its cancellation), a second launch gives up and exits rather than hang;
        // a pipe left open is closed with the process (Main returns right after; pool threads don't keep it alive).
        Task<bool> attempt = Task.Run(SendShow);
        try { return attempt.Wait(SignalTimeoutMs) && attempt.Result; }
        catch (Exception) { return false; }
    }

    private static bool SendShow()
    {
        try
        {
            using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.Out,
                                                       PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            if (!TryConnect(pipe)) return false;

            // The running instance raises its window with SetForegroundWindow, which Windows grants only to the process
            // the user is dealing with: this one, just launched — not an instance idling in the background. Hand the
            // right over now that something is listening (it lapses with the user's next input anyway) — to that
            // instance only, the server end of this pipe (CurrentUserOnly: verified to be this user's), not to every
            // process (ASFW_ANY, kept only as the fallback when Windows can't tell the server's id).
            if (OperatingSystem.IsWindows())
                AllowSetForegroundWindow(ServerProcessId(pipe) is int pid ? pid : AsfwAny);

            using var deadline = new CancellationTokenSource(WriteTimeoutMs);
            pipe.WriteAsync(ShowCommand, deadline.Token).AsTask().GetAwaiter().GetResult();
            return true;
        }
        catch (Exception)
        {
            // Timed out, a pipe owned by another user (UnauthorizedAccessException), the listener gone mid-way, ...
            return false;
        }
    }

    // NamedPipeClientStream.Connect keeps retrying "no such pipe" for its whole timeout; a missing listener has to fail
    // at once instead.
    private static bool TryConnect(NamedPipeClientStream pipe)
    {
        if (OperatingSystem.IsWindows())
        {
            // WaitNamedPipe reports a missing pipe immediately, without connecting to it. A pipe that exists but is
            // serving another client gets the full timeout.
            if (!WaitNamedPipe(@"\\.\pipe\" + PipeName, 1) && Marshal.GetLastPInvokeError() == ErrorFileNotFound)
                return false;
            pipe.Connect(ConnectTimeoutMs);
        }
        else
        {
            // A Unix listener's socket takes connections into the kernel's backlog for as long as it exists, busy or
            // not, so a single attempt is conclusive (it throws when nothing listens).
            pipe.Connect(0);
        }
        return true;
    }

    // ---------- Listener (the instance holding the lock) ----------

    /// <summary>Starts listening in the background; returns at once. Program.Main calls it while holding the lock.</summary>
    public static void StartListening()
    {
        if (s_stop is not null) return;
        s_stop = new CancellationTokenSource();
        CancellationToken stop = s_stop.Token;
        s_listener = Task.Run(() => ListenAsync(stop));
    }

    /// <summary>Stops listening and closes the pipe (on Unix that removes the socket file too). Idempotent.</summary>
    public static void StopListening()
    {
        CancellationTokenSource? stop = Interlocked.Exchange(ref s_stop, null);
        if (stop is null) return;
        stop.Cancel();
        // Close the pipe right here instead of waiting for the loop to unwind on a pool thread, which may not get one in
        // time while the app tears down (a leftover Unix socket file did show up once in testing). Disposing twice — here
        // and in the loop — is harmless.
        try { Volatile.Read(ref s_server)?.Dispose(); } catch { }
        try { s_listener?.Wait(TimeSpan.FromSeconds(1)); } catch { }   // bounded: exit must not wait on it
    }

    private static async Task ListenAsync(CancellationToken stop)
    {
        int failures = 0;
        while (!stop.IsCancellationRequested)
        {
            try
            {
                // A single instance, reused for every client: on Windows that means FILE_FLAG_FIRST_PIPE_INSTANCE, so a
                // pipe of this name already created by some other process fails here rather than being shared with it.
                using var server = new NamedPipeServerStream(PipeName, PipeDirection.In, 1, PipeTransmissionMode.Byte,
                                                             PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                Volatile.Write(ref s_server, server);
                while (true)
                {
                    // Blocks (asynchronously) until a client connects: no polling.
                    await server.WaitForConnectionAsync(stop).ConfigureAwait(false);
                    if (await ReadShowAsync(server, stop).ConfigureAwait(false)) RaiseShowRequested();
                    server.Disconnect();
                    failures = 0;
                }
            }
            catch (Exception) when (stop.IsCancellationRequested)
            {
                return;   // stopping: a cancelled wait, or the pipe closed under it by StopListening
            }
            catch (Exception ex)
            {
                // A client that broke the pipe's state, another user's process knocking (Unix peer check), ...: start over
                // with a fresh pipe. Something that keeps failing (the name already taken by another process, the OS
                // refusing pipes) is given up on — the listener is a convenience, Echoes runs fine without it.
                CrashLog.Write("SingleInstance.Listen", ex);
                if (++failures >= MaxFailures) return;
                try { await Task.Delay(500 * failures, stop).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
            }
        }
    }

    // One client: reads until it closes its end (at most one byte past the command) within the deadline. True only for
    // exactly "SHOW"; anything else — longer, shorter, different, too slow — is dropped without an answer.
    private static async Task<bool> ReadShowAsync(PipeStream pipe, CancellationToken stop)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(stop);
        deadline.CancelAfter(ReadTimeoutMs);
        byte[] buffer = new byte[ShowCommand.Length + 1];
        int length = 0;
        try
        {
            while (length < buffer.Length)
            {
                int read = await pipe.ReadAsync(buffer.AsMemory(length), deadline.Token).ConfigureAwait(false);
                if (read == 0) break;   // the client closed its end: that was the whole message
                length += read;
            }
        }
        catch (OperationCanceledException) when (!stop.IsCancellationRequested)
        {
            return false;               // stalled
        }
        catch (IOException)
        {
            return false;               // gone mid-message
        }
        return length == ShowCommand.Length && buffer.AsSpan(0, length).SequenceEqual(ShowCommand);
    }

    private static void RaiseShowRequested()
    {
        try { ShowRequested?.Invoke(); }
        catch (Exception ex) { CrashLog.Write("SingleInstance.Show", ex); }   // the pipe itself is fine: keep listening
    }

    // ---------- Win32 ----------

    /// <summary>Windows: the process id of the instance at the other end of a connected pipe; null when unknown.</summary>
    internal static int? ServerProcessId(NamedPipeClientStream pipe)
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            return GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out uint pid) && pid is > 0 and <= int.MaxValue
                ? (int)pid : null;
        }
        catch (Exception) { return null; }   // a disposed / broken pipe, an old Windows: the fallback applies
    }

    private const int ErrorFileNotFound = 2;
    private const int AsfwAny = -1;   // ASFW_ANY

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint serverProcessId);

    [DllImport("kernel32.dll", EntryPoint = "WaitNamedPipeW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WaitNamedPipe(string name, uint timeoutMs);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AllowSetForegroundWindow(int processId);
}
