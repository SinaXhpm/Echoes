using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

public enum ShareMessageKind { Text, File, Received }

/// <summary>One chat message. <see cref="ShareMessageKind.File"/>: a file this device shared (a download link on the
/// page); <see cref="ShareMessageKind.Received"/>: a file a browser sent to this device (a note, never a link).</summary>
public sealed class ShareMessage
{
    public required long Seq { get; init; }
    /// <summary><see cref="ShareHub.HostCid"/> for this device, else the sending browser's public id.</summary>
    public required string Cid { get; init; }
    public required string From { get; init; }
    public required DateTime Time { get; init; }
    public string Text { get; init; } = string.Empty;
    public ShareMessageKind Kind { get; init; }
    public string? FileId { get; init; }
    public string? FileName { get; init; }
    public long FileSize { get; init; }
    public bool IsHost => Cid == ShareHub.HostCid;
}

/// <summary>A file a browser is sending (or sent). <see cref="Received"/> moves while it arrives.</summary>
public sealed class ShareUpload
{
    internal long ReceivedBytes;
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required long Size { get; init; }
    public required string From { get; init; }
    public required string Cid { get; init; }
    public DateTime Started { get; init; } = DateTime.Now;
    public long Received => Interlocked.Read(ref ReceivedBytes);
}

/// <summary>What one run of the hub serves and how.</summary>
public sealed class ShareHubOptions
{
    public required IPAddress Bind { get; init; }
    public required int Port { get; init; }
    /// <summary>Null = plain HTTP.</summary>
    public ShareCert? Cert { get; init; }
    public bool RequirePin { get; init; } = true;
    public string Pin { get; init; } = string.Empty;
    public int MaxConnections { get; init; } = 64;
    /// <summary>Finished uploads go here (never served).</summary>
    public required string InboxFolder { get; init; }
    /// <summary>Uploads are written here while they arrive (the inbox itself on desktop: the final move is a rename).</summary>
    public required string PartFolder { get; init; }
    public long MaxUploadBytes { get; init; } = 4L * 1024 * 1024 * 1024;
    /// <summary>This device's name in the chat.</summary>
    public string HostName { get; init; } = "Echoes";
    public required Func<IReadOnlyList<SharedItem>> Items { get; init; }
    /// <summary>The chat to continue (an earlier run's messages, renumbered).</summary>
    public IReadOnlyList<ShareMessage> History { get; init; } = Array.Empty<ShareMessage>();
}

/// <summary>Where the hub reports. Called on connection threads — the app only queues.</summary>
public interface IShareHubSink
{
    void OnLog(string line);
    void OnMessage(ShareMessage message);
    void OnChatCleared();
    void OnUploadStarted(ShareUpload upload);
    /// <summary><paramref name="path"/> = where the file is now; null = canceled / failed (<paramref name="error"/>).</summary>
    void OnUploadFinished(ShareUpload upload, string? path, string? error);
    void OnDownload(string itemId, long bytes, bool complete);
}

/// <summary>
/// "Share &amp; chat": a two-way LAN hub for devices that can't reach each other any other way. One port serves a
/// self-contained web page (any browser, phones included) for chat, sending files to this device and downloading what
/// it shares; the first byte of each connection decides between TLS (0x16, the hub's own certificate) and plain HTTP
/// (sent to https:// on the same port while HTTPS is on). Raw sockets, no HttpListener: works on Android and without
/// admin rights.
/// <para>Access: an 8-digit PIN (per-address lockout: 1 s, 2 s, 4 s … 5 min after 5 misses, and a pause for everyone
/// after 300 misses in 10 minutes) buys a random session cookie (HttpOnly, SameSite=Strict, Secure on HTTPS; at most 16
/// per address). Every API call needs the X-Echoes header and a same-origin Origin / Sec-Fetch-Site; the WebSocket needs
/// the same Origin. Scripts download with the PIN as the Basic-auth password (<c>curl -k -u :PIN -OJ https://…/d/ID</c>).
/// A shared file's direct link (<c>/f/{token}/{name}</c>, shown with a QR code in the app) downloads that one file without
/// the PIN: the token is the file's own 128-bit secret, and it dies when the file stops being shared.</para>
/// <para>Limits: connections (all / a quarter per address), request bodies (an idle timeout and a total deadline of at
/// least ~4 KB/s), messages (16 KB, 20 at once then 2 a second per browser, 500 kept in memory), uploads (chunks of at
/// most 8 MB, 2 at once per browser and 8 in all, a size cap, free space), WebSockets (4 per browser, 8 per address, 64
/// in all), long polls (2 per browser). Stop closes everything and deletes partial uploads.</para>
/// </summary>
public sealed partial class ShareHub : IDisposable
{
    public const string HostCid = "host";
    public const int MaxMessageBytes = 16 * 1024;
    public const int MaxChatHistory = 500;
    /// <summary>What the page sends per upload request.</summary>
    public const int ChunkSize = 4 * 1024 * 1024;
    public const int MaxChunkBytes = 8 * 1024 * 1024;
    private const int MaxJsonBody = 64 * 1024;
    private const int HeadTimeoutMs = 10_000, KeepAliveIdleMs = 15_000, BodyIdleMs = 30_000;
    private const int MaxRequestsPerConnection = 1000;
    private const int MaxSessions = 256, MaxSessionsPerAddress = 16;
    private const int AuthFreeTries = 5, MaxLockoutSec = 300, MaxAuthEntries = 4096;
    // 8-digit PIN: even 300 guesses per pause cycle leave months to the whole space, and a stranger needs 300 misses
    // (60 fresh addresses) to pause everyone's PIN entry
    private const int GlobalFailWindowMs = 600_000, GlobalFailLimit = 300, GlobalPauseMs = 60_000;

    /// <summary>Test hook: sees the exception that ended a connection (never set in the app).</summary>
    internal static Action<Exception>? TestErrorHook { get; set; }
    /// <summary>Test hook: the address a connection counts as (per-address limits from one loopback; never set in the app).</summary>
    internal static Func<IPEndPoint, string?>? TestPeerHook { get; set; }

    private readonly ShareHubOptions _o;
    private readonly IShareHubSink _sink;
    private readonly SemaphoreSlim _slots;
    private readonly int _perPeerCap;
    private readonly ConcurrentDictionary<string, int> _perPeer = new();
    private readonly ConcurrentDictionary<long, Socket> _open = new();
    private readonly ConcurrentDictionary<string, HubSession> _sessions = new(StringComparer.Ordinal);
    private readonly string _cookieName;
    private readonly IReadOnlyList<string> _machineNames;
    private byte[] _pin;                              // UTF-8 digits; swapped whole by SetPin
    private Socket? _listener;
    private CancellationTokenSource? _cts;
    private long _nextConn, _totalConn, _bytesSent, _bytesReceived, _downloads;
    private int _active;

    // PIN brute-force throttle (see the class remarks). Under _authGate.
    private readonly object _authGate = new();
    private readonly Dictionary<string, (int Fails, long UntilMs, long LastMs)> _authFail = new();
    private readonly Queue<long> _globalFails = new();
    private long _globalPauseUntil;
    // "the browser refused the certificate" is said once per address per 5 minutes
    private readonly ConcurrentDictionary<string, long> _tlsNoted = new();

    public ShareHub(ShareHubOptions options, IShareHubSink sink)
    {
        _o = options;
        _sink = sink;
        int max = Math.Clamp(options.MaxConnections, 4, 512);
        _slots = new SemaphoreSlim(max);
        // one address may hold at most a quarter of the slots (never fewer than a browser's 6 + its WebSocket + a poll):
        // a device with an IPv4 and a couple of IPv6 addresses still can't take them all
        _perPeerCap = Math.Max(8, max / 4);
        _cookieName = "echoes_" + options.Port.ToString(CultureInfo.InvariantCulture);
        _pin = Encoding.UTF8.GetBytes(options.Pin);
        _machineNames = ShareTls.MachineNames();
        foreach (var m in options.History.Skip(Math.Max(0, options.History.Count - MaxChatHistory)))
            _messages.Add(new ShareMessage
            {
                Seq = ++_seq, Cid = m.Cid, From = m.From, Time = m.Time, Text = m.Text, Kind = m.Kind,
                FileId = m.FileId, FileName = m.FileName, FileSize = m.FileSize,
            });
    }

    public bool IsRunning => _listener != null;
    public bool IsHttps => _o.Cert != null;
    public bool RequiresPin => _o.RequirePin;
    public IPEndPoint? LocalEndPoint { get; private set; }
    public int ActiveConnections => Volatile.Read(ref _active);
    public long TotalConnections => Interlocked.Read(ref _totalConn);
    public long BytesSent => Interlocked.Read(ref _bytesSent);
    public long BytesReceived => Interlocked.Read(ref _bytesReceived);
    public long Downloads => Interlocked.Read(ref _downloads);

    /// <summary>Browsers logged in and seen within the last 90 s (or holding a WebSocket).</summary>
    public int ClientCount
    {
        get
        {
            long now = Environment.TickCount64;
            return _sessions.Values.Count(s => Volatile.Read(ref s.Ws) > 0 || now - Volatile.Read(ref s.LastSeen) < 90_000);
        }
    }

    /// <summary>Binds and starts accepting. <see cref="IPAddress.IPv6Any"/> = every interface (dual-stack). Throws
    /// <see cref="SocketException"/> (port in use, access denied …).</summary>
    public void Start()
    {
        Stop();
        var s = SocketNet.Bind(_o.Bind, _o.Port, SocketType.Stream, ProtocolType.Tcp);
        try { s.Listen(128); }
        catch { s.Dispose(); throw; }
        _listener = s;
        LocalEndPoint = (IPEndPoint)s.LocalEndPoint!;
        var cts = new CancellationTokenSource();
        _cts = cts;
        var token = cts.Token;
        // On the pool: started from the UI thread, the awaits would otherwise capture the Avalonia context.
        _ = Task.Run(() => AcceptLoopAsync(s, token));
        _ = Task.Run(() => MaintainAsync(token));
    }

    /// <summary>Closes the listener and every connection (WebSockets get a "going away" close), wakes long polls,
    /// deletes partial uploads and forgets every session.</summary>
    public void Stop()
    {
        var cts = Interlocked.Exchange(ref _cts, null);
        if (cts is null) return;
        try { cts.Cancel(); } catch { }
        try { _listener?.Dispose(); } catch { }
        _listener = null;
        WsPeer[] peers;
        lock (_evGate)
        {
            peers = _peers.Values.ToArray();
            _peers.Clear();
            WakePollsLocked();
        }
        var closing = peers.Select(p => p.CloseAsync(1001, "Sharing stopped")).ToArray();
        var sockets = _open.Values.ToArray();
        DropAllUploads("Sharing stopped.");
        _sessions.Clear();
        _finished.Clear();
        // Every other request ends on the canceled token at once; the sockets go as soon as the WebSockets had their
        // "going away" (pages then say "stopped" rather than "connection lost") — at most 0.4 s.
        _ = Task.Run(async () =>
        {
            try { await Task.WhenAny(Task.WhenAll(closing), Task.Delay(400)).ConfigureAwait(false); } catch { }
            foreach (var sock in sockets) { try { sock.Dispose(); } catch { } }
            cts.Dispose();
        });
    }

    public void Dispose() => Stop();

    /// <summary>A new PIN (or the same one): every browser is logged out and has to enter it again.</summary>
    public void SetPin(string pin)
    {
        Volatile.Write(ref _pin, Encoding.UTF8.GetBytes(pin));
        RevokeAllSessions("PIN changed");
    }

    private void RevokeAllSessions(string why)
    {
        foreach (var s in _sessions.Values) s.Revoked = true;
        _sessions.Clear();
        WsPeer[] peers;
        lock (_evGate)
        {
            peers = _peers.Values.ToArray();
            _peers.Clear();
            WakePollsLocked();
        }
        foreach (var p in peers) _ = p.CloseAsync(4001, why);
        DropAllUploads("The PIN changed.");
    }

    // ================================================================ accept / connection

    /// <summary>The listening socket stopped working while the hub runs (raised once, on a pool thread): iOS closes the
    /// listeners of an app it suspended, and a bound address can vanish. The owner starts the hub again.</summary>
    public event Action<string>? ListenerLost;
    private int _lost;

    private async Task AcceptLoopAsync(Socket listener, CancellationToken ct)
    {
        int failures = 0;
        while (!ct.IsCancellationRequested)
        {
            // a slot BEFORE accepting: never more sockets in memory than the cap
            try { await _slots.WaitAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
            Socket client;
            try { client = await listener.AcceptAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { _slots.Release(); return; }
            catch (ObjectDisposedException) { _slots.Release(); return; }
            catch (Exception ex)
            {
                _slots.Release();
                // accept failing again and again: the listening socket itself is gone, not one client (retried every
                // 100 ms forever, the page said "sharing" and nothing could connect)
                if (++failures >= SocketErrors.DeadListenerAfter)
                {
                    if (Interlocked.Exchange(ref _lost, 1) == 0)
                    {
                        Log("the listening socket stopped working: " + SocketErrors.Unwrap(ex).Message);
                        try { ListenerLost?.Invoke(SocketErrors.Unwrap(ex).Message); } catch { }
                    }
                    return;
                }
                // a persistent accept failure (e.g. out of file descriptors) must not pin a CPU core
                try { await Task.Delay(100, ct).ConfigureAwait(false); } catch { return; }
                continue;
            }
            failures = 0;
            _ = Task.Run(() => HandleAsync(client, ct));
        }
    }

    /// <summary>One TCP connection: TLS or plain by its first byte, then requests until it closes.</summary>
    private sealed class HubConn
    {
        public required string Ip { get; init; }
        public required Socket Socket { get; init; }
        public required Stream Stream { get; init; }
        public required HubReader Reader { get; init; }
        public required bool Https { get; init; }
    }

    private async Task HandleAsync(Socket socket, CancellationToken ct)
    {
        long id = Interlocked.Increment(ref _nextConn);
        string ip = "?";
        try
        {
            var ep = SocketNet.Normalize((IPEndPoint)socket.RemoteEndPoint!);
            ip = TestPeerHook?.Invoke(ep) ?? ep.Address.ToString();
        }
        catch { }
        int held = Bump(_perPeer, ip, 1);
        Interlocked.Increment(ref _active);
        _open[id] = socket;
        try
        {
            if (held > _perPeerCap || ct.IsCancellationRequested) return;
            Interlocked.Increment(ref _totalConn);
            socket.NoDelay = true;

            // TLS or plain HTTP on the same port: a TLS connection starts with a handshake record (0x16). Peeked, so
            // either side reads the stream from its first byte.
            var peek = new byte[1];
            int n;
            using (var pcts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                pcts.CancelAfter(HeadTimeoutMs);
                try { n = await socket.ReceiveAsync(peek, SocketFlags.Peek, pcts.Token).ConfigureAwait(false); }
                catch { return; }
            }
            if (n <= 0) return;

            var ns = new NetworkStream(socket, ownsSocket: true);
            Stream stream = ns;
            bool https = false;
            if (peek[0] == 0x16)
            {
                if (_o.Cert is null) return;   // HTTPS is off: nothing to answer in TLS (the browser shows a TLS error)
                var ssl = new SslStream(ns, leaveInnerStreamOpen: false);
                stream = ssl;
                using var tcts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                tcts.CancelAfter(HeadTimeoutMs);
                try { await ssl.AuthenticateAsServerAsync(_o.Cert.ServerOptions(), tcts.Token).ConfigureAwait(false); }
                catch (Exception ex)
                {
                    if (!ct.IsCancellationRequested) NoteTlsFailure(ip, ex);
                    await ssl.DisposeAsync().ConfigureAwait(false);
                    return;
                }
                https = true;
            }

            await using (stream.ConfigureAwait(false))
            {
                var conn = new HubConn { Ip = ip, Socket = socket, Stream = stream, Reader = new HubReader(stream, BodyIdleMs), Https = https };
                for (int served = 0; served < MaxRequestsPerConnection && !ct.IsCancellationRequested; served++)
                {
                    bool keep = await ServeOneAsync(conn, served == 0, ct).ConfigureAwait(false);
                    if (!keep) break;
                }
            }
        }
        catch (Exception ex) { TestErrorHook?.Invoke(ex); /* one bad client never takes the loop down */ }
        finally
        {
            _open.TryRemove(id, out _);
            Bump(_perPeer, ip, -1);
            Interlocked.Decrement(ref _active);
            try { socket.Dispose(); } catch { }
            _slots.Release();
        }
    }

    private void NoteTlsFailure(string ip, Exception ex)
    {
        long now = Environment.TickCount64;
        if (_tlsNoted.TryGetValue(ip, out long at) && now - at < 300_000) return;
        if (_tlsNoted.Count > 1024) _tlsNoted.Clear();
        _tlsNoted[ip] = now;
        var e = SocketErrors.Unwrap(ex);
        bool timeout = e is OperationCanceledException or TimeoutException;
        Log(timeout
            ? $"{ip}  TLS handshake timed out"
            : $"{ip}  the browser refused the certificate (first visit: accept its warning once)");
    }

    private static int Bump(ConcurrentDictionary<string, int> map, string peer, int delta)
    {
        int v = map.AddOrUpdate(peer, static (_, d) => d, static (_, old, d) => old + d, delta);
        if (v <= 0) map.TryRemove(new KeyValuePair<string, int>(peer, v));
        return v;
    }

    private void Log(string line) { try { _sink.OnLog(line); } catch { } }

    // ================================================================ one request

    /// <summary>Reads, routes and answers one request. True = keep the connection for the next one.</summary>
    private async Task<bool> ServeOneAsync(HubConn c, bool first, CancellationToken ct)
    {
        HubRequest? req;
        int error;
        using (var hcts = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            hcts.CancelAfter(first ? HeadTimeoutMs : KeepAliveIdleMs);
            try { (req, error) = await c.Reader.ReadHeadAsync(hcts.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) { return false; }   // idle / too slow: just close
            catch (IOException) { return false; }
        }
        if (req is null)
        {
            if (error > 0)
            {
                try
                {
                    await HubHttp.SendAsync(c.Stream, error, "text/plain; charset=utf-8", Encoding.UTF8.GetBytes(HubHttp.Reason(error)), null, false, false, ct).ConfigureAwait(false);
                    await LingerAsync(c, ct).ConfigureAwait(false);
                }
                catch { }
            }
            return false;
        }

        // DNS-rebinding guard: a hostile page can point its own name at this address and then read the hub
        // same-origin. Echoes only hands out IP / localhost / this machine's name, so any other name is refused.
        string? host = req.Header("Host");
        if (host is not null && !IsAllowedHost(host))
        {
            Log($"{c.Ip}  Host {Clean(host)}  → 421");
            await AnswerAsync(c, req, MaxJsonBody, _ => HubHttp.SendAsync(c.Stream, 421, "text/plain; charset=utf-8", "Unknown host - open the address shown in Echoes"u8.ToArray(), null, false, req.IsHead, ct), ct).ConfigureAwait(false);
            return false;
        }

        // plain HTTP while HTTPS is on: the same address, https://
        if (_o.Cert is not null && !c.Https)
        {
            string authority = host ?? (LocalEndPoint is { } ep ? SocketNet.Label(ep) : "127.0.0.1:" + _o.Port.ToString(CultureInfo.InvariantCulture));
            string location = "https://" + authority + req.Target;
            await AnswerAsync(c, req, MaxJsonBody, _ => HubHttp.SendAsync(c.Stream, 307, "text/plain; charset=utf-8", Encoding.UTF8.GetBytes("Use " + location),
                "Location: " + location + "\r\n", false, req.IsHead, ct), ct).ConfigureAwait(false);
            return false;
        }

        try
        {
            return await RouteAsync(c, req, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { return false; }
        catch (IOException) { return false; }
    }

    private async Task<bool> RouteAsync(HubConn c, HubRequest req, CancellationToken ct)
    {
        string path = req.Path;
        if (path is "/" or "/index.html")
        {
            if (req.Method is not ("GET" or "HEAD")) return await RefuseAsync(c, req, 405, "Method Not Allowed", ct).ConfigureAwait(false);
            if (!await c.Reader.DrainAsync(req.ContentLength, MaxJsonBody, BodyIdleMs, ct).ConfigureAwait(false)) return false;
            string authority = (req.Header("Host") ?? "").Trim();
            string csp = SharePage.Csp(c.Https, authority);
            await HubHttp.SendAsync(c.Stream, 200, "text/html; charset=utf-8", SharePage.Bytes, null, req.WantsKeepAlive, req.IsHead, ct, csp).ConfigureAwait(false);
            if (!req.IsHead) Log($"{c.Ip}  {req.Method} /  → 200");
            return req.WantsKeepAlive;
        }
        if (path == "/favicon.ico" || path == "/robots.txt")
            return await RefuseAsync(c, req, 404, "Not Found", ct, quiet: true).ConfigureAwait(false);
        if (path.StartsWith("/api/", StringComparison.Ordinal)) return await ApiAsync(c, req, ct).ConfigureAwait(false);
        if (path == "/ws") return await WebSocketAsync(c, req, ct).ConfigureAwait(false);
        if (path.StartsWith("/d/", StringComparison.Ordinal)) return await DownloadAsync(c, req, ct).ConfigureAwait(false);
        if (path.StartsWith("/f/", StringComparison.Ordinal)) return await DirectAsync(c, req, ct).ConfigureAwait(false);
        return await RefuseAsync(c, req, 404, "Not Found", ct).ConfigureAwait(false);
    }

    /// <summary>A short plain-text refusal; the body of the request (if small) is read first so the connection lives on.</summary>
    private async Task<bool> RefuseAsync(HubConn c, HubRequest req, int status, string text, CancellationToken ct, bool quiet = false, string? extraHeaders = null)
    {
        if (!quiet) Log($"{c.Ip}  {Clean(req.Method)} {Clean(req.Path)}  → {status}");
        return await AnswerAsync(c, req, MaxJsonBody,
            keep => HubHttp.SendAsync(c.Stream, status, "text/plain; charset=utf-8", Encoding.UTF8.GetBytes(text), extraHeaders, keep, req.IsHead, ct), ct).ConfigureAwait(false);
    }

    private async Task<bool> JsonAsync(HubConn c, HubRequest req, int status, byte[] json, CancellationToken ct, string? extraHeaders = null, bool keepAlive = true)
    {
        bool keep = keepAlive && req.WantsKeepAlive;
        await HubHttp.SendJsonAsync(c.Stream, status, json, keep, ct, extraHeaders).ConfigureAwait(false);
        return keep;
    }

    /// <summary>
    /// An answer to a request whose body the route doesn't use. The body (up to <paramref name="max"/>) is read first:
    /// closing with unread bytes makes the OS reset the connection, and the client can lose the answer. When it can't
    /// be read, the answer goes out and the connection is closed gently (<see cref="LingerAsync"/>).
    /// </summary>
    private async Task<bool> AnswerAsync(HubConn c, HubRequest req, long max, Func<bool, Task> send, CancellationToken ct)
    {
        bool drained = await c.Reader.DrainAsync(req.ContentLength, max, BodyIdleMs, ct).ConfigureAwait(false);
        bool keep = drained && req.WantsKeepAlive;
        await send(keep).ConfigureAwait(false);
        if (!drained) await LingerAsync(c, ct).ConfigureAwait(false);
        return keep;
    }

    /// <summary>Ends our side, then reads and drops what the client still sends for a moment (at most 2 MB / 1 s), so the
    /// answer already sent isn't destroyed by a reset.</summary>
    private static async Task LingerAsync(HubConn c, CancellationToken ct)
    {
        try
        {
            if (c.Stream is SslStream ssl) await ssl.ShutdownAsync().ConfigureAwait(false);
            c.Socket.Shutdown(SocketShutdown.Send);
        }
        catch { return; }
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(1000);
        var buf = System.Buffers.ArrayPool<byte>.Shared.Rent(16 * 1024);
        try
        {
            long total = 0;
            while (total < 2L * 1024 * 1024)
            {
                int n = await c.Reader.ReadAsync(buf, cts.Token).ConfigureAwait(false);
                if (n <= 0) break;
                total += n;
            }
        }
        catch { }
        finally { System.Buffers.ArrayPool<byte>.Shared.Return(buf); }
    }

    // ================================================================ the API

    private async Task<bool> ApiAsync(HubConn c, HubRequest req, CancellationToken ct)
    {
        if (!SameOrigin(c, req, requireHeader: true))
        {
            Log($"{c.Ip}  {Clean(req.Method)} {Clean(req.Path)}  → 403 (not from this page)");
            return await AnswerAsync(c, req, MaxChunkBytes,
                keep => HubHttp.SendJsonAsync(c.Stream, 403, HubHttp.Error("Refused: the request didn't come from the Echoes page."), keep, ct), ct).ConfigureAwait(false);
        }

        string path = req.Path;
        bool post = req.Method == "POST", get = req.Method == "GET";
        // bodies: JSON up to 64 KB, upload chunks up to 8 MB (read by the upload route itself)
        bool chunk = path == "/api/up/chunk";
        if (!chunk && req.ContentLength > MaxJsonBody)
        {
            await HubHttp.SendJsonAsync(c.Stream, 413, HubHttp.Error("Too large."), false, ct).ConfigureAwait(false);
            await LingerAsync(c, ct).ConfigureAwait(false);
            return false;
        }

        switch (path)
        {
            case "/api/hello" when get:
            {
                if (!await c.Reader.DrainAsync(req.ContentLength, MaxJsonBody, BodyIdleMs, ct).ConfigureAwait(false)) return false;
                var s = SessionOf(req);
                return await JsonAsync(c, req, 200, HubHttp.Json(w =>
                {
                    w.WriteBoolean("ok", true);
                    w.WriteBoolean("authed", s is not null);
                    w.WriteBoolean("pin", _o.RequirePin);
                    w.WriteString("host", _o.HostName);
                    w.WriteBoolean("https", c.Https);
                    if (s is not null) WriteMe(w, s);
                }), ct).ConfigureAwait(false);
            }
            case "/api/login" when post:
                return await LoginAsync(c, req, ct).ConfigureAwait(false);
            case "/api/logout" when post:
            {
                if (!await c.Reader.DrainAsync(req.ContentLength, MaxJsonBody, BodyIdleMs, ct).ConfigureAwait(false)) return false;
                if (SessionOf(req) is { } s) EndSession(s);
                return await JsonAsync(c, req, 200, HubHttp.Json(w => w.WriteBoolean("ok", true)), ct,
                    $"Set-Cookie: {_cookieName}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict{(c.Https ? "; Secure" : "")}\r\n").ConfigureAwait(false);
            }
        }

        var session = SessionOf(req);
        if (session is null)
        {
            return await AnswerAsync(c, req, MaxChunkBytes,
                keep => HubHttp.SendJsonAsync(c.Stream, 401, HubHttp.Error("Enter the PIN.", w => w.WriteBoolean("login", true)), keep, ct), ct).ConfigureAwait(false);
        }
        Volatile.Write(ref session.LastSeen, Environment.TickCount64);

        switch (path)
        {
            case "/api/state" when get:
                if (!await c.Reader.DrainAsync(req.ContentLength, MaxJsonBody, BodyIdleMs, ct).ConfigureAwait(false)) return false;
                return await JsonAsync(c, req, 200, StateJson(session, c.Https), ct).ConfigureAwait(false);
            case "/api/files" when get:
                if (!await c.Reader.DrainAsync(req.ContentLength, MaxJsonBody, BodyIdleMs, ct).ConfigureAwait(false)) return false;
                return await JsonAsync(c, req, 200, HubHttp.Json(w => { w.WriteBoolean("ok", true); WriteFiles(w); }), ct).ConfigureAwait(false);
            case "/api/name" when post:
                return await RenameAsync(c, req, session, ct).ConfigureAwait(false);
            case "/api/send" when post:
                return await SendMessageAsync(c, req, session, ct).ConfigureAwait(false);
            case "/api/poll" when get:
                if (!await c.Reader.DrainAsync(req.ContentLength, MaxJsonBody, BodyIdleMs, ct).ConfigureAwait(false)) return false;
                return await PollAsync(c, req, session, ct).ConfigureAwait(false);
            case "/api/up/start" when post:
                return await UploadStartAsync(c, req, session, ct).ConfigureAwait(false);
            case "/api/up/chunk" when post:
                return await UploadChunkAsync(c, req, session, ct).ConfigureAwait(false);
            case "/api/up/status" when get:
                if (!await c.Reader.DrainAsync(req.ContentLength, MaxJsonBody, BodyIdleMs, ct).ConfigureAwait(false)) return false;
                return await UploadStatusAsync(c, req, session, ct).ConfigureAwait(false);
            case "/api/up/cancel" when post:
                if (!await c.Reader.DrainAsync(req.ContentLength, MaxJsonBody, BodyIdleMs, ct).ConfigureAwait(false)) return false;
                return await UploadCancelAsync(c, req, session, ct).ConfigureAwait(false);
        }
        return await AnswerAsync(c, req, MaxChunkBytes,
            keep => HubHttp.SendJsonAsync(c.Stream, 404, HubHttp.Error("Unknown request."), keep, ct), ct).ConfigureAwait(false);
    }

    /// <summary>
    /// CSRF: the page's own requests only. A custom header can't be sent cross-origin without a CORS preflight (never
    /// answered), and a browser's Origin / Sec-Fetch-Site, when sent, must name this very origin (the Host as asked for).
    /// </summary>
    private bool SameOrigin(HubConn c, HubRequest req, bool requireHeader)
    {
        if (requireHeader && req.Header("X-Echoes") != "1") return false;
        string? host = req.Header("Host");
        string? origin = req.Header("Origin");
        if (origin is not null)
        {
            if (host is null) return false;
            string expected = (c.Https ? "https://" : "http://") + host.Trim();
            if (!string.Equals(origin.Trim(), expected, StringComparison.OrdinalIgnoreCase)) return false;
        }
        else if (!requireHeader) return false;   // the WebSocket handshake always carries an Origin from a browser
        if (req.Header("Sec-Fetch-Site") is { } site && site != "same-origin") return false;
        return true;
    }

    // ================================================================ sessions + PIN

    internal sealed class HubSession
    {
        public required string Token { get; init; }
        public required string Cid { get; init; }
        public required string Ip { get; init; }
        /// <summary>This device's own chat name: a browser can't take it (see <see cref="Name"/>).</summary>
        public required string HostName { get; init; }
        private string _name = "Guest";
        /// <summary>The browser's chat name; one equal to this device's own gets " (guest)", so nobody posts as the host.</summary>
        public string Name
        {
            get => Volatile.Read(ref _name);
            set => Volatile.Write(ref _name, value.Equals(HostName, StringComparison.OrdinalIgnoreCase) ? value + " (guest)" : value);
        }
        public long LastSeen = Environment.TickCount64;
        public int Ws, Polls, Chunks;
        public volatile bool Revoked;
        // message rate: a bucket of MsgBurst, refilled at MsgPerSec (under the session's lock)
        public double Tokens = MsgBurst;
        public long TokensAt = Environment.TickCount64;
    }

    private HubSession? SessionOf(HubRequest req)
    {
        string? cookie = req.Header("Cookie");
        if (cookie is null) return null;
        foreach (var part in cookie.Split(';'))
        {
            int eq = part.IndexOf('=');
            if (eq <= 0 || !part[..eq].Trim().Equals(_cookieName, StringComparison.Ordinal)) continue;
            string token = part[(eq + 1)..].Trim();
            if (token.Length == 43 && _sessions.TryGetValue(token, out var s) && !s.Revoked) return s;
        }
        return null;
    }

    private HubSession NewSession(string ip, string? name)
    {
        // bounded per address: logging in again and again only replaces this address's own least recently seen session
        // (a peer can't push the other devices out); then the whole table: the least recently seen goes
        var own = _sessions.Values.Where(x => x.Ip == ip).ToList();
        if (own.Count >= MaxSessionsPerAddress)
            EndSession(own.OrderBy(x => Volatile.Read(ref x.LastSeen)).First());
        else if (_sessions.Count >= MaxSessions && _sessions.Values.OrderBy(x => Volatile.Read(ref x.LastSeen)).FirstOrDefault() is { } oldest)
            EndSession(oldest);
        var s = new HubSession
        {
            Token = Base64Url(RandomNumberGenerator.GetBytes(32)),
            Cid = Convert.ToHexString(RandomNumberGenerator.GetBytes(6)).ToLowerInvariant(),
            Ip = ip,
            HostName = _o.HostName,
        };
        s.Name = CleanName(name);
        _sessions[s.Token] = s;
        return s;
    }

    private void EndSession(HubSession s)
    {
        s.Revoked = true;
        _sessions.TryRemove(s.Token, out _);
        WsPeer[] mine;
        lock (_evGate)
        {
            mine = _peers.Values.Where(p => p.Session == s).ToArray();
            foreach (var p in mine) _peers.Remove(p.Key);
        }
        foreach (var p in mine) _ = p.CloseAsync(4001, "Logged out");
    }

    private static string Base64Url(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private void WriteMe(System.Text.Json.Utf8JsonWriter w, HubSession s)
    {
        w.WriteStartObject("me");
        w.WriteString("cid", s.Cid);
        w.WriteString("name", s.Name);
        w.WriteEndObject();
    }

    private async Task<bool> LoginAsync(HubConn c, HubRequest req, CancellationToken ct)
    {
        byte[]? body = req.ContentLength > 0 ? await c.Reader.ReadBodyAsync(req.ContentLength, BodyIdleMs, ct).ConfigureAwait(false) : Array.Empty<byte>();
        if (body is null) return false;
        string? pin = null, name = null;
        if (body.Length > 0)
        {
            using var doc = HubHttp.ParseObject(body);
            if (doc is null) return await JsonAsync(c, req, 400, HubHttp.Error("Bad request."), ct).ConfigureAwait(false);
            pin = HubHttp.Str(doc, "pin");
            name = HubHttp.Str(doc, "name");
        }

        if (_o.RequirePin)
        {
            string key = LockKey(c.Ip);
            if (IsLockedOut(key, out long wait))
                return await LockedAsync(c, req, wait, ct).ConfigureAwait(false);
            bool ok = PinMatches(pin);
            if (!AuthVerdict(key, c.Ip, ok, out wait))
            {
                if (wait > 0) return await LockedAsync(c, req, wait, ct).ConfigureAwait(false);
                Log($"{c.Ip}  wrong PIN");
                return await JsonAsync(c, req, 401, HubHttp.Error("Wrong PIN.", w => w.WriteBoolean("login", true)), ct).ConfigureAwait(false);
            }
        }

        var s = NewSession(c.Ip, name);
        Log($"{c.Ip}  {(_o.RequirePin ? "PIN ok" : "joined")}  → {s.Name}");
        string cookie = $"Set-Cookie: {_cookieName}={s.Token}; Path=/; HttpOnly; SameSite=Strict{(c.Https ? "; Secure" : "")}\r\n";
        return await JsonAsync(c, req, 200, HubHttp.Json(w => { w.WriteBoolean("ok", true); WriteMe(w, s); }), ct, cookie).ConfigureAwait(false);
    }

    private Task<bool> LockedAsync(HubConn c, HubRequest req, long wait, CancellationToken ct)
        => JsonAsync(c, req, 429, HubHttp.Error($"Too many wrong PINs - try again in {wait} s.", w => w.WriteNumber("retry", wait)), ct,
            $"Retry-After: {wait.ToString(CultureInfo.InvariantCulture)}\r\n");

    /// <summary>Digits only (a "482 913" typed with a space still counts), compared in constant time.</summary>
    private bool PinMatches(string? typed)
    {
        if (typed is null) return false;
        var sb = new StringBuilder(8);
        foreach (char ch in typed)
        {
            if (ch is >= '0' and <= '9') sb.Append(ch);
            else if (ch is not (' ' or '-')) return false;
            if (sb.Length > 12) return false;
        }
        return CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(sb.ToString()), Volatile.Read(ref _pin));
    }

    /// <summary>The lockout key: the address itself (an IPv4-mapped one already as IPv4). Never an IPv6 /64: on a LAN every
    /// device shares it, so a stranger's misses locked the others out; addresses that rotate meet the global limit.</summary>
    internal static string LockKey(string ip) => ip;

    private bool IsLockedOut(string key, out long retrySec)
    {
        lock (_authGate) return LockedOut(key, out retrySec);
    }

    // Under _authGate: the address's own lockout, or the pause for everyone.
    private bool LockedOut(string key, out long retrySec)
    {
        retrySec = 0;
        long now = Environment.TickCount64;
        if (_globalPauseUntil > now) { retrySec = (_globalPauseUntil - now + 999) / 1000; return true; }
        if (!_authFail.TryGetValue(key, out var f)) return false;
        long left = f.UntilMs - now;
        if (left <= 0) return false;
        retrySec = (left + 999) / 1000;
        return true;
    }

    // Judges a credential and checks / records the lockout in ONE step (a burst of parallel guesses can't all pass the
    // check before the first failure is counted). True = let in; false + retrySec > 0 = locked out, else a counted miss.
    private bool AuthVerdict(string key, string ip, bool ok, out long retrySec)
    {
        int fails;
        long secs = 0;
        bool paused = false;
        lock (_authGate)
        {
            if (LockedOut(key, out retrySec)) return false;
            if (ok) { _authFail.Remove(key); return true; }
            _authFail.TryGetValue(key, out var f);
            fails = f.Fails + 1;
            if (fails >= AuthFreeTries) secs = Math.Min(1L << Math.Min(fails - AuthFreeTries, 9), MaxLockoutSec);
            if (_authFail.Count >= MaxAuthEntries && !_authFail.ContainsKey(key)) _authFail.Clear();
            long now = Environment.TickCount64;
            _authFail[key] = (fails, secs > 0 ? now + secs * 1000 : 0L, now);
            // everyone together: past GlobalFailLimit misses in the window, a pause for all (addresses can be many)
            _globalFails.Enqueue(now);
            while (_globalFails.Count > 0 && now - _globalFails.Peek() > GlobalFailWindowMs) _globalFails.Dequeue();
            if (_globalFails.Count >= GlobalFailLimit)
            {
                _globalPauseUntil = now + GlobalPauseMs;
                _globalFails.Clear();
                paused = true;
            }
            if (secs > 0) retrySec = secs;
        }
        if (paused) Log($"{GlobalFailLimit} wrong PINs in 10 minutes  → PIN entry paused for {GlobalPauseMs / 1000} s");
        else if (secs > 0) Log($"{ip}  {fails} wrong PINs  → locked out {secs} s");
        return false;
    }

    /// <summary>Scripts: Basic auth with the PIN as the password (any user name).</summary>
    private bool BasicAuthOk(HubConn c, HubRequest req, out long retrySec)
    {
        retrySec = 0;
        string? h = req.Header("Authorization");
        if (h is null || !h.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase)) return false;
        string key = LockKey(c.Ip);
        if (IsLockedOut(key, out retrySec)) return false;
        bool ok;
        try
        {
            string cred = Encoding.UTF8.GetString(Convert.FromBase64String(h[6..].Trim()));
            int colon = cred.IndexOf(':');
            ok = colon >= 0 && PinMatches(cred[(colon + 1)..]);
        }
        catch { ok = false; }
        return AuthVerdict(key, c.Ip, ok, out retrySec);
    }

    // ================================================================ downloads

    private async Task<bool> DownloadAsync(HubConn c, HubRequest req, CancellationToken ct)
    {
        if (req.Method is not ("GET" or "HEAD")) return await RefuseAsync(c, req, 405, "Method Not Allowed", ct).ConfigureAwait(false);
        if (!await c.Reader.DrainAsync(req.ContentLength, MaxJsonBody, BodyIdleMs, ct).ConfigureAwait(false)) return false;

        if (_o.RequirePin && SessionOf(req) is null)
        {
            if (!BasicAuthOk(c, req, out long wait))
            {
                if (wait > 0)
                    return await RefuseAsync(c, req, 429, $"Too many wrong PINs - try again in {wait} s.", ct,
                        extraHeaders: $"Retry-After: {wait.ToString(CultureInfo.InvariantCulture)}\r\n").ConfigureAwait(false);
                // a browser opening the link without logging in first: to the page (it asks for the PIN there)
                if ((req.Header("Accept") ?? "").Contains("text/html", StringComparison.OrdinalIgnoreCase))
                    return await RefuseAsync(c, req, 303, "Log in first", ct, quiet: true, extraHeaders: "Location: /\r\n").ConfigureAwait(false);
                return await RefuseAsync(c, req, 401, "Unauthorized - the PIN is the password", ct,
                    extraHeaders: "WWW-Authenticate: Basic realm=\"Echoes (the PIN is the password)\", charset=\"UTF-8\"\r\n").ConfigureAwait(false);
            }
        }

        string id;
        try { id = Uri.UnescapeDataString(req.Path[3..]); } catch { id = string.Empty; }
        SharedItem? item = null;
        foreach (var it in _o.Items())
            if (string.Equals(it.Id, id, StringComparison.Ordinal)) { item = it; break; }
        if (item is null) return await RefuseAsync(c, req, 404, "Not Found - this file isn't shared any more", ct).ConfigureAwait(false);
        return await ServeItemAsync(c, req, item, string.Empty, ct).ConfigureAwait(false);
    }

    // /f/{token}/{name}: a file's direct link (the app shows it, with its QR code, beside each shared file). The token is
    // the file's own 128-bit secret (SharedItem.LinkToken): the link downloads that one file without the PIN, and nothing
    // else; the name after it is only for the browser and curl -O. Compared in constant time.
    private async Task<bool> DirectAsync(HubConn c, HubRequest req, CancellationToken ct)
    {
        if (req.Method is not ("GET" or "HEAD")) return await RefuseAsync(c, req, 405, "Method Not Allowed", ct).ConfigureAwait(false);
        if (!await c.Reader.DrainAsync(req.ContentLength, MaxJsonBody, BodyIdleMs, ct).ConfigureAwait(false)) return false;

        string rest = req.Path[3..];
        int slash = rest.IndexOf('/');
        byte[] token = Encoding.ASCII.GetBytes(slash < 0 ? rest : rest[..slash]);
        SharedItem? item = null;
        foreach (var it in _o.Items())
            if (CryptographicOperations.FixedTimeEquals(token, Encoding.ASCII.GetBytes(it.LinkToken))) item = it;
        if (item is null) return await RefuseAsync(c, req, 404, "Not Found - this link doesn't work any more (the file isn't shared now)", ct).ConfigureAwait(false);
        return await ServeItemAsync(c, req, item, " (direct link)", ct).ConfigureAwait(false);
    }

    private async Task<bool> ServeItemAsync(HubConn c, HubRequest req, SharedItem item, string via, CancellationToken ct)
    {
        var r = await FileHttpServer.ServeAsync(c.Stream, item, req.IsHead, req.Header("Range"), req.Header("If-Range"),
            HubHttp.CommonHeaders.Replace("Cache-Control: no-store\r\n", "Cache-Control: private, no-store\r\n", StringComparison.Ordinal),
            req.WantsKeepAlive, n => Interlocked.Add(ref _bytesSent, n), ct).ConfigureAwait(false);
        if (!req.IsHead && r.Status is 200 or 206)
        {
            if (r.Status == 200) Interlocked.Increment(ref _downloads);
            try { _sink.OnDownload(item.Id, r.Sent, r.Status == 200); } catch { }
        }
        Log($"{c.Ip}  {req.Method} {Clean(item.Name)}{via}  → {r.Status}");
        return r.KeepAlive;
    }

    // ================================================================ helpers

    // Accepts IP literals ([v6]:port too), localhost and this machine's own name (+ ".local" for mDNS). Never a name
    // merely STARTING with ours — "mypc.evil.example" is the attacker's domain.
    private bool IsAllowedHost(string host)
    {
        host = host.Trim();
        if (host.StartsWith('['))
        {
            int rb = host.IndexOf(']');
            if (rb < 0) return false;
            string rest = host[(rb + 1)..];
            if (rest.Length > 0 && !IsPortSuffix(rest)) return false;
            host = host[1..rb];
        }
        else
        {
            int pc = host.LastIndexOf(':');
            if (pc >= 0)
            {
                if (!IsPortSuffix(host[pc..])) return false;
                host = host[..pc];
            }
        }
        if (host.Length == 0) return false;
        if (IPAddress.TryParse(host, out _)) return true;
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase)) return true;
        foreach (var n in _machineNames) if (host.Equals(n, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static bool IsPortSuffix(string s)
    {
        if (s.Length is < 2 or > 6 || s[0] != ':') return false;
        for (int i = 1; i < s.Length; i++) if (s[i] is < '0' or > '9') return false;
        return true;
    }

    /// <summary>Request text for the log: control / line / bidi characters replaced, capped.</summary>
    internal static string Clean(string s)
    {
        var sb = new StringBuilder(Math.Min(s.Length, 121));
        foreach (char ch in s)
        {
            if (sb.Length >= 120) { sb.Append('…'); break; }
            sb.Append(RequestCatcher.IsUnsafeDisplay(ch) ? '?' : ch);
        }
        return sb.ToString();
    }

    /// <summary>A device name: 1–40 visible characters (no controls, bidi overrides or invisible marks), else "Guest".</summary>
    internal static string CleanName(string? raw)
    {
        if (raw is null) return "Guest";
        var sb = new StringBuilder(Math.Min(raw.Length, 41));
        foreach (var r in raw.EnumerateRunes())
        {
            int v = r.Value;
            if (v < 0x20 || v is >= 0x7F and <= 0x9F || v is >= 0x200B and <= 0x200F || v is >= 0x202A and <= 0x202E
                || v is >= 0x2066 and <= 0x2069 || v is 0x2028 or 0x2029 or 0x061C or 0xFEFF or 0x2060) continue;
            sb.Append(r.ToString());
            if (sb.Length >= 40) break;
        }
        string s = sb.ToString().Trim();
        return s.Length == 0 ? "Guest" : s;
    }

    private async Task MaintainAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { await Task.Delay(20_000, ct).ConfigureAwait(false); }
            catch { return; }
            try
            {
                // WebSocket keep-alive: a ping every 20 s keeps NATs / proxies from dropping a quiet connection, and a
                // client that stopped reading is found (its send times out and the connection is aborted)
                WsPeer[] peers;
                lock (_evGate) peers = _peers.Values.ToArray();
                foreach (var p in peers) p.Ping();
                ExpireUploads();
                long now = Environment.TickCount64;
                foreach (var s in _sessions.Values)
                    if (Volatile.Read(ref s.Ws) == 0 && now - Volatile.Read(ref s.LastSeen) > 24L * 3600 * 1000) EndSession(s);
                lock (_authGate)
                {
                    // misses are forgotten an hour after the last one (and once any lockout is over)
                    foreach (var k in _authFail.Where(kv => now - kv.Value.LastMs > 3_600_000 && kv.Value.UntilMs < now).Select(kv => kv.Key).ToList())
                        _authFail.Remove(k);
                }
            }
            catch (Exception ex) { TestErrorHook?.Invoke(ex); }
        }
    }
}
