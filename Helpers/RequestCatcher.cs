using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>What the catcher answers every request with (immutable: the UI swaps the whole object).</summary>
public sealed class CatcherReply
{
    public int Status { get; init; } = 200;
    public string ContentType { get; init; } = "application/json";
    public byte[] Body { get; init; } = Encoding.UTF8.GetBytes("{\"ok\":true}");
    public int DelayMs { get; init; }
}

public enum CaptureKind { Http, WsUpgrade, WsMessage, WsClose }

/// <summary>
/// One request the catcher received (or one WebSocket message / close on an upgraded connection). Filled on the
/// connection thread; <see cref="Status"/> and <see cref="ResponseBytes"/> are set once the reply went out.
/// </summary>
public sealed class CapturedRequest
{
    private static long s_nextId;

    public long Id { get; } = Interlocked.Increment(ref s_nextId);
    public DateTime Time { get; init; } = DateTime.Now;
    public CaptureKind Kind { get; set; }
    public string Method { get; init; } = string.Empty;
    /// <summary>The request target exactly as sent ("/hook?a=1"); for WebSocket messages the upgrade's path.</summary>
    public string Target { get; init; } = string.Empty;
    public string Version { get; init; } = "HTTP/1.1";
    public IReadOnlyList<KeyValuePair<string, string>> Headers { get; init; } = Array.Empty<KeyValuePair<string, string>>();
    /// <summary>At most <see cref="RequestCatcher.MaxStoredBody"/> bytes of the body.</summary>
    public byte[] Body { get; set; } = Array.Empty<byte>();
    /// <summary>The whole body size (received, or declared when it wasn't read).</summary>
    public long BodyLength { get; set; }
    public string ClientIp { get; init; } = string.Empty;
    public int ClientPort { get; init; }
    public bool IsPreflight { get; set; }
    /// <summary>For WebSocket messages: text (true) or binary.</summary>
    public bool IsText { get; init; }
    /// <summary>For WebSocket messages: how many connected clients got it back.</summary>
    public int Delivered { get; set; }

    // set when the reply has been written (connection thread), read on the UI thread after OnReplied
    public volatile int Status;
    public long ResponseBytes;
    public string? Note { get; set; }

    public bool BodyTruncated => Body.Length < BodyLength;

    public string Path
    {
        get
        {
            int q = Target.IndexOf('?');
            return q >= 0 ? Target[..q] : Target;
        }
    }

    public string Query
    {
        get
        {
            int q = Target.IndexOf('?');
            return q >= 0 ? Target[(q + 1)..] : string.Empty;
        }
    }

    public string? Header(string name)
    {
        foreach (var h in Headers) if (h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)) return h.Value;
        return null;
    }
}

/// <summary>Where the catcher reports. Called on connection threads — the UI only queues.</summary>
public interface ICatcherSink
{
    /// <summary>A request arrived (its body read); the reply may still be pending (a configured delay).</summary>
    void OnRequest(CapturedRequest request);
    /// <summary>The reply for <paramref name="request"/> went out (or the client left first: Status 0).</summary>
    void OnReplied(CapturedRequest request);
}

/// <summary>
/// A request catcher / webhook inspector: a managed HTTP/1.1 server (raw sockets, no HttpListener — works on Android and
/// without admin rights) that accepts ANY method and path, records each request (line, headers, body up to 1 MB) and
/// answers with a configurable reply. CORS is answered automatically — preflights included — so browser code can post to
/// it. Keep-alive, chunked bodies and "Expect: 100-continue" are handled; a WebSocket upgrade is accepted too, and the
/// connection then echoes every message to all connected WebSocket clients. Limits: header / body / connection caps,
/// header and body deadlines, an idle keep-alive timeout; Stop closes everything.
/// </summary>
public sealed class RequestCatcher : IDisposable
{
    public const int MaxStoredBody = 1024 * 1024;
    public const long MaxAcceptedBody = 16L * 1024 * 1024;
    public const int MaxHeadBytes = 32 * 1024;
    public const int MaxHeaderCount = 200;
    public const int HeadTimeoutMs = 10_000;
    public const int KeepAliveIdleMs = 15_000;
    public const int BodyTimeoutMs = 60_000;
    public const int WriteTimeoutMs = 30_000;
    public const int MaxRequestsPerConnection = 1000;
    public const int MaxWsClients = 32;
    public const int MaxWsPerClient = 8;
    public const int MaxWsMessage = 1024 * 1024;
    /// <summary>Echoes waiting for one WebSocket client that doesn't read: past this it is dropped, not buffered on.</summary>
    public const long MaxWsBacklog = 4L * MaxWsMessage;
    public const int MaxDelayMs = 60_000;

    private readonly ICatcherSink _sink;
    private readonly SemaphoreSlim _slots;
    private readonly int _perPeerCap;
    private readonly ConcurrentDictionary<string, int> _perPeer = new();
    private readonly ConcurrentDictionary<long, Socket> _open = new();
    private readonly ConcurrentDictionary<long, WsConnection> _ws = new();
    private readonly WsSink _wsSink;
    private Socket? _listener;
    private CancellationTokenSource? _cts;
    private volatile CatcherReply _reply = new();
    private long _nextConn;
    private int _active;
    private long _requests;

    /// <summary>Test hook: sees the exception that ended a connection (never set in the app).</summary>
    internal static Action<Exception>? TestErrorHook { get; set; }

    public RequestCatcher(ICatcherSink sink, int maxConnections = 32)
    {
        _sink = sink;
        int max = Math.Clamp(maxConnections, 1, 512);
        _slots = new SemaphoreSlim(max);
        // one client may hold at most half the slots (never fewer than a browser's 6), so others always get in
        _perPeerCap = Math.Max(Math.Min(6, max), max / 2);
        _wsSink = new WsSink(this);
    }

    public CatcherReply Reply
    {
        get => _reply;
        set => _reply = value ?? new CatcherReply();
    }

    public bool IsRunning => _listener != null;
    public IPEndPoint? LocalEndPoint { get; private set; }
    public int ActiveConnections => Volatile.Read(ref _active);
    public long TotalRequests => Interlocked.Read(ref _requests);
    public int WebSocketClients => _ws.Count;

    /// <summary>Binds and starts accepting. <see cref="IPAddress.IPv6Any"/> = every interface (dual-stack). Throws
    /// <see cref="SocketException"/> (port in use, access denied …).</summary>
    public void Start(IPAddress bind, int port)
    {
        Stop();
        var s = SocketNet.Bind(bind, port, SocketType.Stream, ProtocolType.Tcp);
        try { s.Listen(128); }
        catch { s.Dispose(); throw; }
        _listener = s;
        LocalEndPoint = (IPEndPoint)s.LocalEndPoint!;
        _cts = new CancellationTokenSource();
        var token = _cts.Token;
        _ = Task.Run(() => AcceptLoopAsync(s, token));
    }

    public void Stop()
    {
        var cts = _cts;
        _cts = null;
        try { cts?.Cancel(); } catch { }
        try { _listener?.Dispose(); } catch { }
        _listener = null;
        foreach (var w in _ws.Values) _ = w.CloseAsync(1001, "Server stopping", 400);
        _ws.Clear();
        foreach (var s in _open.Values) { try { s.Dispose(); } catch { } }
        _open.Clear();
        cts?.Dispose();
    }

    public void Dispose() => Stop();

    // ================================================================ accept

    private async Task AcceptLoopAsync(Socket listener, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            // a slot BEFORE accepting: never more sockets in memory than the cap
            try { await _slots.WaitAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
            Socket client;
            try { client = await listener.AcceptAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { _slots.Release(); return; }
            catch (ObjectDisposedException) { _slots.Release(); return; }
            catch
            {
                _slots.Release();
                try { await Task.Delay(100, ct).ConfigureAwait(false); } catch { return; }
                continue;
            }
            _ = Task.Run(() => HandleAsync(client, ct));
        }
    }

    private async Task HandleAsync(Socket socket, CancellationToken ct)
    {
        long id = Interlocked.Increment(ref _nextConn);
        string ip = "?";
        int port = 0;
        try
        {
            var ep = SocketNet.Normalize((IPEndPoint)socket.RemoteEndPoint!);
            ip = ep.Address.ToString();
            port = ep.Port;
        }
        catch { }
        int held = Bump(ip, 1);
        Interlocked.Increment(ref _active);
        _open[id] = socket;
        try
        {
            if (held > _perPeerCap || ct.IsCancellationRequested) return;
            socket.NoDelay = true;
            using var stream = new NetworkStream(socket, ownsSocket: true);
            var reader = new ConnReader(stream);
            for (int served = 0; served < MaxRequestsPerConnection && !ct.IsCancellationRequested; served++)
            {
                bool keepAlive = await ServeOneAsync(stream, reader, ip, port, served == 0, ct).ConfigureAwait(false);
                if (!keepAlive) break;
            }
        }
        catch (Exception ex) { TestErrorHook?.Invoke(ex); /* one bad client never takes the loop down */ }
        finally
        {
            _open.TryRemove(id, out _);
            Bump(ip, -1);
            Interlocked.Decrement(ref _active);
            try { socket.Dispose(); } catch { }
            _slots.Release();
        }
    }

    private int Bump(string peer, int delta)
    {
        int v = _perPeer.AddOrUpdate(peer, static (_, d) => d, static (_, old, d) => old + d, delta);
        if (v <= 0) _perPeer.TryRemove(new KeyValuePair<string, int>(peer, v));
        return v;
    }

    // ================================================================ one request

    /// <summary>Reads, records and answers one request. True = keep the connection for the next one.</summary>
    private async Task<bool> ServeOneAsync(NetworkStream stream, ConnReader reader, string ip, int port, bool first, CancellationToken ct)
    {
        ConnReader.Head? head;
        using (var hcts = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            hcts.CancelAfter(first ? HeadTimeoutMs : KeepAliveIdleMs);
            try { head = await reader.ReadHeadAsync(MaxHeadBytes, hcts.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) { return false; }   // idle / too slow: just close
            catch (IOException) { return false; }
        }
        if (head is null) return false;   // closed between requests

        if (head.Error is { } err)
        {
            var bad = new CapturedRequest
            {
                Kind = CaptureKind.Http, Method = "?", Target = head.RawLine, Version = "?",
                ClientIp = ip, ClientPort = port, Note = err.Note,
            };
            Interlocked.Increment(ref _requests);
            _sink.OnRequest(bad);
            if (err.Status > 0) await TryWriteAsync(stream, bad, err.Status, "text/plain; charset=utf-8", Encoding.UTF8.GetBytes(err.Note + "\n"), null, close: true, head: false, ct).ConfigureAwait(false);
            _sink.OnReplied(bad);
            return false;
        }

        var req = new CapturedRequest
        {
            Kind = CaptureKind.Http,
            Method = head.Method,
            Target = head.Target,
            Version = head.Version,
            Headers = head.Headers,
            ClientIp = ip,
            ClientPort = port,
        };
        Interlocked.Increment(ref _requests);

        // ---- WebSocket upgrade
        if (head.Method == "GET" && WsProtocol.HasToken(req.Header("Upgrade"), "websocket"))
        {
            await UpgradeAsync(stream, reader, req, ct).ConfigureAwait(false);
            return false;
        }

        // ---- body
        string? te = req.Header("Transfer-Encoding");
        bool chunked = te != null && WsProtocol.HasToken(te, "chunked");
        long declared = 0;
        if (!chunked && req.Header("Content-Length") is { } cl)
        {
            if (!long.TryParse(cl.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out declared))
            {
                req.Note = "The Content-Length header isn't a number.";
                _sink.OnRequest(req);
                await TryWriteAsync(stream, req, 400, "text/plain; charset=utf-8", "Bad Content-Length\n"u8.ToArray(), null, close: true, head: false, ct).ConfigureAwait(false);
                _sink.OnReplied(req);
                return false;
            }
        }
        if (te != null && !chunked)
        {
            req.Note = $"Transfer-Encoding \"{Printable(WsProtocol.Short(te, 40))}\" isn't supported.";
            _sink.OnRequest(req);
            await TryWriteAsync(stream, req, 501, "text/plain; charset=utf-8", "Unsupported Transfer-Encoding\n"u8.ToArray(), null, close: true, head: false, ct).ConfigureAwait(false);
            _sink.OnReplied(req);
            return false;
        }
        if (declared > MaxAcceptedBody)
        {
            req.BodyLength = declared;
            req.Note = $"The body ({SocketPayload.FormatBytes(declared)}) is over the {SocketPayload.FormatBytes(MaxAcceptedBody)} limit — answered 413 without reading it.";
            _sink.OnRequest(req);
            await TryWriteAsync(stream, req, 413, "text/plain; charset=utf-8", "Payload Too Large\n"u8.ToArray(), null, close: true, head: false, ct).ConfigureAwait(false);
            _sink.OnReplied(req);
            return false;
        }

        bool expectContinue = WsProtocol.HasToken(req.Header("Expect"), "100-continue") && head.Version == "HTTP/1.1";
        if (chunked || declared > 0)
        {
            if (expectContinue)
            {
                try { await WriteAllAsync(stream, "HTTP/1.1 100 Continue\r\n\r\n"u8.ToArray(), ct).ConfigureAwait(false); }
                catch { return false; }
            }
            var (ok, tooLarge) = await ReadBodyAsync(reader, req, chunked, declared, ct).ConfigureAwait(false);
            if (tooLarge)
            {
                req.Note = $"The chunked body went over the {SocketPayload.FormatBytes(MaxAcceptedBody)} limit — answered 413.";
                _sink.OnRequest(req);
                await TryWriteAsync(stream, req, 413, "text/plain; charset=utf-8", "Payload Too Large\n"u8.ToArray(), null, close: true, head: false, ct).ConfigureAwait(false);
                _sink.OnReplied(req);
                return false;
            }
            if (!ok)
            {
                req.Note ??= chunked
                    ? $"The client stopped sending after {SocketPayload.FormatBytes(req.BodyLength)} (chunked body never finished)."
                    : $"The client stopped sending after {SocketPayload.FormatBytes(req.BodyLength)} of {SocketPayload.FormatBytes(declared)}.";
                _sink.OnRequest(req);
                _sink.OnReplied(req);   // nobody left to answer
                return false;
            }
        }

        // ---- reply
        bool keepAlive = head.Version == "HTTP/1.1"
            ? !WsProtocol.HasToken(req.Header("Connection"), "close")
            : WsProtocol.HasToken(req.Header("Connection"), "keep-alive");
        string? origin = req.Header("Origin");
        bool preflight = head.Method == "OPTIONS" && origin != null && req.Header("Access-Control-Request-Method") != null;
        req.IsPreflight = preflight;
        _sink.OnRequest(req);

        bool headOnly = head.Method == "HEAD";
        if (preflight)
        {
            var extra = new StringBuilder();
            extra.Append("Access-Control-Allow-Methods: ").Append(SafeHeaderValue(req.Header("Access-Control-Request-Method")!))
                 .Append(", GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD\r\n");
            if (req.Header("Access-Control-Request-Headers") is { Length: > 0 } rh)
                extra.Append("Access-Control-Allow-Headers: ").Append(SafeHeaderValue(rh)).Append("\r\n");
            if (req.Header("Access-Control-Request-Private-Network") != null)
                extra.Append("Access-Control-Allow-Private-Network: true\r\n");
            extra.Append("Access-Control-Max-Age: 600\r\n");
            bool sent = await TryWriteAsync(stream, req, 204, null, Array.Empty<byte>(), extra.ToString(), !keepAlive, headOnly, ct).ConfigureAwait(false);
            _sink.OnReplied(req);
            return sent && keepAlive;
        }

        var reply = _reply;
        if (reply.DelayMs > 0)
        {
            try { await Task.Delay(Math.Min(reply.DelayMs, MaxDelayMs), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { _sink.OnReplied(req); return false; }
        }
        int status = reply.Status is >= 200 and <= 599 ? reply.Status : 200;
        byte[] body = status is 204 or 304 ? Array.Empty<byte>() : reply.Body;
        bool ok2 = await TryWriteAsync(stream, req, status, body.Length > 0 ? reply.ContentType : null, body, null, !keepAlive, headOnly, ct).ConfigureAwait(false);
        _sink.OnReplied(req);
        return ok2 && keepAlive;
    }

    // Body into req.Body (at most MaxStoredBody kept, the rest counted). (ok: false = the client hung up / stalled;
    // tooLarge: a chunked body passed MaxAcceptedBody).
    private static async Task<(bool Ok, bool TooLarge)> ReadBodyAsync(ConnReader reader, CapturedRequest req, bool chunked, long declared, CancellationToken ct)
    {
        using var bcts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        bcts.CancelAfter(BodyTimeoutMs);
        var store = new MemoryStream();
        long total = 0;
        var buf = new byte[32 * 1024];
        try
        {
            if (!chunked)
            {
                while (total < declared)
                {
                    int n = await reader.ReadAsync(buf.AsMemory(0, (int)Math.Min(buf.Length, declared - total)), bcts.Token).ConfigureAwait(false);
                    if (n <= 0) return Done(false, false);
                    Keep(n);
                }
                return Done(true, false);
            }
            while (true)
            {
                string? line = await reader.ReadLineAsync(1024, bcts.Token).ConfigureAwait(false);
                if (line == null) return Done(false, false);
                int semi = line.IndexOf(';');
                string hex = (semi >= 0 ? line[..semi] : line).Trim();
                if (!long.TryParse(hex, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out long size) || size < 0)
                {
                    req.Note = "A chunk size line wasn't valid hex.";
                    return Done(false, false);
                }
                if (size == 0)
                {
                    // trailers, up to the blank line
                    for (int i = 0; i < 64; i++)
                    {
                        string? t = await reader.ReadLineAsync(8192, bcts.Token).ConfigureAwait(false);
                        if (t == null || t.Length == 0) break;
                    }
                    return Done(true, false);
                }
                if (size > MaxAcceptedBody - total) return Done(false, true);   // (total + size could overflow)
                long left = size;
                while (left > 0)
                {
                    int n = await reader.ReadAsync(buf.AsMemory(0, (int)Math.Min(buf.Length, left)), bcts.Token).ConfigureAwait(false);
                    if (n <= 0) return Done(false, false);
                    Keep(n);
                    left -= n;
                }
                string? crlf = await reader.ReadLineAsync(16, bcts.Token).ConfigureAwait(false);
                if (crlf == null) return Done(false, false);
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            req.Note = $"The body didn't arrive within {BodyTimeoutMs / 1000} s (got {SocketPayload.FormatBytes(total)}).";
            return Done(false, false);
        }
        catch (Exception) when (!ct.IsCancellationRequested)
        {
            return Done(false, false);
        }

        void Keep(int n)
        {
            int room = (int)Math.Max(0, MaxStoredBody - store.Length);
            if (room > 0) store.Write(buf, 0, Math.Min(room, n));
            total += n;
        }

        (bool, bool) Done(bool ok, bool tooLarge)
        {
            req.Body = store.ToArray();
            req.BodyLength = total;
            return (ok, tooLarge);
        }
    }

    // ================================================================ replies

    private static string Reason(int status) => status switch
    {
        100 => "Continue", 101 => "Switching Protocols",
        200 => "OK", 201 => "Created", 202 => "Accepted", 204 => "No Content", 206 => "Partial Content",
        301 => "Moved Permanently", 302 => "Found", 303 => "See Other", 304 => "Not Modified", 307 => "Temporary Redirect", 308 => "Permanent Redirect",
        400 => "Bad Request", 401 => "Unauthorized", 403 => "Forbidden", 404 => "Not Found", 405 => "Method Not Allowed",
        408 => "Request Timeout", 409 => "Conflict", 410 => "Gone", 413 => "Payload Too Large", 415 => "Unsupported Media Type",
        422 => "Unprocessable Content", 426 => "Upgrade Required", 429 => "Too Many Requests", 431 => "Request Header Fields Too Large",
        500 => "Internal Server Error", 501 => "Not Implemented", 502 => "Bad Gateway", 503 => "Service Unavailable",
        504 => "Gateway Timeout", 505 => "HTTP Version Not Supported",
        _ => status < 300 ? "OK" : status < 400 ? "Redirect" : status < 500 ? "Client Error" : "Server Error",
    };

    // A request value echoed into a reply header: never a line break (header injection) and not unbounded.
    private static string SafeHeaderValue(string v)
    {
        var sb = new StringBuilder(Math.Min(v.Length, 1024));
        foreach (char c in v)
        {
            if (sb.Length >= 1024) break;
            if (c >= 0x20 && c < 0x7F) sb.Append(c);
        }
        return sb.ToString();
    }

    private static string CorsHeaders(CapturedRequest req)
    {
        string? origin = req.Header("Origin");
        if (origin is null) return "Access-Control-Allow-Origin: *\r\nAccess-Control-Expose-Headers: *\r\n";
        // echo the origin (with credentials allowed), so fetch(..., { credentials: "include" }) works too
        return "Access-Control-Allow-Origin: " + SafeHeaderValue(origin) + "\r\nAccess-Control-Allow-Credentials: true\r\n"
               + "Access-Control-Expose-Headers: *\r\nVary: Origin\r\n";
    }

    private static async Task<bool> TryWriteAsync(NetworkStream stream, CapturedRequest req, int status, string? contentType,
        byte[] body, string? extraHeaders, bool close, bool head, CancellationToken ct)
    {
        var sb = new StringBuilder(256);
        sb.Append("HTTP/1.1 ").Append(status.ToString(CultureInfo.InvariantCulture)).Append(' ').Append(Reason(status)).Append("\r\n");
        sb.Append("Server: Echoes request catcher\r\n");
        sb.Append("Date: ").Append(DateTime.UtcNow.ToString("R", CultureInfo.InvariantCulture)).Append("\r\n");
        if (contentType != null) sb.Append("Content-Type: ").Append(SafeHeaderValue(contentType)).Append("\r\n");
        if (status != 204 && status != 304) sb.Append("Content-Length: ").Append(body.Length.ToString(CultureInfo.InvariantCulture)).Append("\r\n");
        sb.Append(CorsHeaders(req));
        if (extraHeaders != null) sb.Append(extraHeaders);
        sb.Append(close ? "Connection: close\r\n" : "Connection: keep-alive\r\n");
        sb.Append("\r\n");
        byte[] h = Encoding.ASCII.GetBytes(sb.ToString());
        try
        {
            await WriteAllAsync(stream, h, ct).ConfigureAwait(false);
            if (!head && body.Length > 0) await WriteAllAsync(stream, body, ct).ConfigureAwait(false);
            req.Status = status;
            req.ResponseBytes = h.Length + (head ? 0 : body.Length);
            if (close && status >= 400) await LingerAsync(stream, ct).ConfigureAwait(false);
            return true;
        }
        catch
        {
            req.Note ??= "The client left before the reply was sent.";
            return false;
        }
    }

    // An error answer to a request that wasn't read whole (huge headers, a body over the limit): closing at once with
    // unread bytes makes the OS send a reset, and the client may lose the answer. So: end our side, then read and drop
    // what's still coming for a moment (at most 1 MB / 1 s) before closing.
    private static async Task LingerAsync(NetworkStream s, CancellationToken ct)
    {
        try { s.Socket.Shutdown(SocketShutdown.Send); } catch { return; }
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(1000);
        var buf = new byte[16 * 1024];
        long total = 0;
        try
        {
            while (total < 1024 * 1024)
            {
                int n = await s.ReadAsync(buf, cts.Token).ConfigureAwait(false);
                if (n <= 0) break;
                total += n;
            }
        }
        catch { /* gone or timed out: close either way */ }
    }

    private static async Task WriteAllAsync(Stream s, byte[] data, CancellationToken ct)
    {
        using var w = CancellationTokenSource.CreateLinkedTokenSource(ct);
        w.CancelAfter(WriteTimeoutMs);
        await s.WriteAsync(data, w.Token).ConfigureAwait(false);
        await s.FlushAsync(w.Token).ConfigureAwait(false);
    }

    // ================================================================ WebSocket echo / broadcast

    private sealed class WsClient
    {
        public required CapturedRequest Upgrade { get; init; }
        public required long Key { get; init; }
        public readonly TaskCompletionSource Done = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    private async Task UpgradeAsync(NetworkStream stream, ConnReader reader, CapturedRequest req, CancellationToken ct)
    {
        string? key = req.Header("Sec-WebSocket-Key");
        string? version = req.Header("Sec-WebSocket-Version");
        bool keyOk = false;
        try { keyOk = key != null && Convert.FromBase64String(key.Trim()).Length == 16; } catch { }
        if (!keyOk || !WsProtocol.HasToken(req.Header("Connection"), "upgrade"))
        {
            req.Note = "A WebSocket upgrade without a valid Sec-WebSocket-Key / Connection: Upgrade.";
            _sink.OnRequest(req);
            await TryWriteAsync(stream, req, 400, "text/plain; charset=utf-8", "Bad WebSocket handshake\n"u8.ToArray(), null, true, false, ct).ConfigureAwait(false);
            _sink.OnReplied(req);
            return;
        }
        if (version?.Trim() != "13")
        {
            req.Note = $"WebSocket version {Printable(WsProtocol.Short(version ?? "(none)", 10))} — only 13 is spoken.";
            _sink.OnRequest(req);
            await TryWriteAsync(stream, req, 426, "text/plain; charset=utf-8", "Use WebSocket version 13\n"u8.ToArray(), "Sec-WebSocket-Version: 13\r\n", true, false, ct).ConfigureAwait(false);
            _sink.OnReplied(req);
            return;
        }
        // At most MaxWsPerClient from one address: a WebSocket is never closed for being idle, so one client opening
        // the whole MaxWsClients would otherwise lock every other one out until Stop.
        int fromClient = _ws.Values.Count(c => c.Tag is WsClient w && w.Upgrade.ClientIp == req.ClientIp);
        if (_ws.Count >= MaxWsClients || fromClient >= MaxWsPerClient)
        {
            req.Note = fromClient >= MaxWsPerClient
                ? $"This client has {MaxWsPerClient} WebSocket connections open already."
                : $"{MaxWsClients} WebSocket clients are already connected.";
            _sink.OnRequest(req);
            await TryWriteAsync(stream, req, 503, "text/plain; charset=utf-8", "Too many WebSocket clients\n"u8.ToArray(), null, true, false, ct).ConfigureAwait(false);
            _sink.OnReplied(req);
            return;
        }

        req.Kind = CaptureKind.WsUpgrade;
        // a client that asks for subprotocols gets the first one (so clients that insist on one still connect)
        string? proto = req.Header("Sec-WebSocket-Protocol")?.Split(',').Select(p => p.Trim()).FirstOrDefault(WsProtocol.IsToken);
        var sb = new StringBuilder();
        sb.Append("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n");
        sb.Append("Sec-WebSocket-Accept: ").Append(WsProtocol.AcceptFor(key!)).Append("\r\n");
        if (proto != null) sb.Append("Sec-WebSocket-Protocol: ").Append(proto).Append("\r\n");
        sb.Append("Server: Echoes request catcher\r\n\r\n");
        req.Note = "WebSocket — every message is echoed to all connected clients" + (proto != null ? $" (subprotocol {proto})." : ".");
        _sink.OnRequest(req);
        byte[] h = Encoding.ASCII.GetBytes(sb.ToString());
        try { await WriteAllAsync(stream, h, ct).ConfigureAwait(false); }
        catch { req.Note = "The client left during the WebSocket handshake."; _sink.OnReplied(req); return; }
        req.Status = 101;
        req.ResponseBytes = h.Length;
        _sink.OnReplied(req);

        byte[] left = reader.TakeBuffered();
        Stream ws = left.Length > 0 ? new PrefixedStream(stream, left) : stream;
        var conn = new WsConnection(ws, isServer: true, _wsSink, MaxWsMessage, closeOnOversize: true);
        var client = new WsClient { Upgrade = req, Key = Interlocked.Increment(ref _nextConn) };
        conn.Tag = client;
        _ws[client.Key] = conn;
        conn.Start();
        using (ct.Register(() => client.Done.TrySetResult()))
            await client.Done.Task.ConfigureAwait(false);
        _ws.TryRemove(client.Key, out _);
    }

    private sealed class WsSink : IWsSink
    {
        private readonly RequestCatcher _c;
        public WsSink(RequestCatcher c) => _c = c;

        public void OnMessage(WsConnection connection, WsMessage message)
        {
            if (connection.Tag is not WsClient client) return;
            var up = client.Upgrade;
            var rec = new CapturedRequest
            {
                Kind = CaptureKind.WsMessage,
                Method = "WS",
                Target = up.Target,
                Version = message.IsText ? "text" : "binary",
                ClientIp = up.ClientIp,
                ClientPort = up.ClientPort,
                Body = message.Data,
                BodyLength = message.Length,
                IsText = message.IsText,
            };
            Interlocked.Increment(ref _c._requests);
            int n = 0;
            foreach (var other in _c._ws.Values)
            {
                if (!other.IsOpen) continue;
                // Sends aren't awaited (one slow client mustn't stall the others), so a client that never reads would
                // queue every echo in memory — the sender's own included. Past the backlog cap it is dropped instead.
                if (other.PendingSendBytes + message.Data.Length > MaxWsBacklog)
                {
                    other.Abort($"Dropped: it wasn't reading its messages ({SocketPayload.FormatBytes(other.PendingSendBytes)} waiting).");
                    continue;
                }
                n++;
                _ = SendQuietAsync(other, message);
            }
            rec.Delivered = n;
            rec.Status = 101;
            rec.Note = n == 1 ? "Echoed back to the sender." : $"Echoed to all {n} connected clients.";
            _c._sink.OnRequest(rec);
            _c._sink.OnReplied(rec);
        }

        private static async Task SendQuietAsync(WsConnection c, WsMessage m)
        {
            try { await c.SendAsync(m.Opcode, m.Data).ConfigureAwait(false); } catch { /* that client is gone */ }
        }

        public void OnControl(WsConnection connection, WsOpcode opcode, byte[] payload, double? rttMs) { }

        public void OnClosed(WsConnection connection, WsCloseInfo info)
        {
            if (connection.Tag is not WsClient client) return;
            client.Done.TrySetResult();
            if (_c._cts is null) return;   // the catcher is stopping: no per-client lines
            var up = client.Upgrade;
            string how = info.Error ?? (info.ByPeer
                ? $"Closed by the client: {info.CodeText}{(info.Reason.Length > 0 ? " — " + WsProtocol.Short(WebSocketClient.Clean(info.Reason), 80) : "")}."
                : $"Closed: {info.CodeText}.");
            var rec = new CapturedRequest
            {
                Kind = CaptureKind.WsClose,
                Method = "WS",
                Target = up.Target,
                Version = "close",
                ClientIp = up.ClientIp,
                ClientPort = up.ClientPort,
                Note = how,
            };
            rec.Status = info.Code;
            _c._sink.OnRequest(rec);
            _c._sink.OnReplied(rec);
        }
    }

    // ================================================================ reading

    /// <summary>Buffered reads over one connection: request heads, lines (chunk sizes) and body bytes.</summary>
    internal sealed class ConnReader
    {
        public sealed record HeadError(int Status, string Note);

        public sealed class Head
        {
            public string Method = string.Empty, Target = string.Empty, Version = string.Empty, RawLine = string.Empty;
            public List<KeyValuePair<string, string>> Headers = new();
            public HeadError? Error;
        }

        private readonly Stream _s;
        private readonly byte[] _buf = new byte[MaxHeadBytes + 4];
        private int _start, _end;

        public ConnReader(Stream s) => _s = s;

        public byte[] TakeBuffered()
        {
            var b = _buf.AsSpan(_start, _end - _start).ToArray();
            _start = _end = 0;
            return b;
        }

        private void Compact()
        {
            if (_start == 0) return;
            Buffer.BlockCopy(_buf, _start, _buf, 0, _end - _start);
            _end -= _start;
            _start = 0;
        }

        private async Task<int> FillAsync(CancellationToken ct)
        {
            Compact();
            if (_end >= _buf.Length) return -1;
            int n = await _s.ReadAsync(_buf.AsMemory(_end, _buf.Length - _end), ct).ConfigureAwait(false);
            if (n > 0) _end += n;
            return n;
        }

        /// <summary>Null when the connection closed before a byte of a new request.</summary>
        public async Task<Head?> ReadHeadAsync(int max, CancellationToken ct)
        {
            // skip blank lines between requests (RFC 9112 2.2)
            int scanned = 0;
            while (true)
            {
                while (_end - _start >= 2 && _buf[_start] == '\r' && _buf[_start + 1] == '\n') _start += 2;
                int avail = _end - _start;
                if (avail > 0)
                {
                    if (_buf[_start] == 0x16)   // a TLS ClientHello
                        return new Head { RawLine = "(TLS handshake)", Error = new HeadError(0, "Someone spoke TLS (https://) to this plain HTTP port — send to http://, not https://.") };
                    int from = _start + Math.Max(0, scanned - 3);
                    int i = _buf.AsSpan(from, _end - from).IndexOf("\r\n\r\n"u8);
                    if (i >= 0) return Parse(from + i);
                    scanned = avail;
                    if (avail >= max)
                    {
                        string line = FirstLine();
                        return new Head { RawLine = line, Error = new HeadError(431, $"The request headers are larger than {max / 1024} KB.") };
                    }
                }
                int n = await FillAsync(ct).ConfigureAwait(false);
                if (n <= 0)
                {
                    if (_end - _start == 0) return null;
                    return new Head { RawLine = FirstLine(), Error = new HeadError(0, "The client closed the connection in the middle of the request headers.") };
                }
            }
        }

        private string FirstLine()
        {
            var span = _buf.AsSpan(_start, Math.Min(_end - _start, 300));
            int nl = span.IndexOf((byte)'\n');
            if (nl >= 0) span = span[..nl];
            return Printable(Encoding.Latin1.GetString(span).TrimEnd('\r'));
        }

        private Head Parse(int endOfHead)
        {
            string text = Encoding.Latin1.GetString(_buf, _start, endOfHead - _start);
            _start = endOfHead + 4;
            var lines = text.Split("\r\n");
            var head = new Head { RawLine = Printable(WsProtocol.Short(lines[0], 300)) };
            var parts = lines[0].Split(' ');
            bool ctl = lines[0].Any(c => c < 0x20 || c == 0x7F);
            if (parts.Length != 3 || ctl || parts[0].Length == 0 || !WsProtocol.IsToken(parts[0]) || parts[1].Length == 0)
            {
                head.Error = new HeadError(400, "That isn't an HTTP request line (\"METHOD /path HTTP/1.1\").");
                return head;
            }
            if (parts[2] is not ("HTTP/1.1" or "HTTP/1.0"))
            {
                head.Error = parts[2].StartsWith("HTTP/", StringComparison.Ordinal)
                    ? new HeadError(505, $"{Printable(WsProtocol.Short(parts[2], 20))} isn't supported — HTTP/1.1 and 1.0 are.")
                    : new HeadError(400, "That isn't an HTTP request line (\"METHOD /path HTTP/1.1\").");
                return head;
            }
            head.Method = parts[0].ToUpperInvariant();
            head.Target = parts[1];
            head.Version = parts[2];
            int lineCount = 0;
            for (int i = 1; i < lines.Length; i++)
            {
                string l = lines[i];
                if (l.Length == 0) continue;
                // every line counts, folded ones too: thousands of folds each re-joining a growing value cost O(n²)
                if (++lineCount > MaxHeaderCount)
                {
                    head.Error = new HeadError(431, $"More than {MaxHeaderCount} header lines.");
                    return head;
                }
                if (l[0] is ' ' or '\t' && head.Headers.Count > 0)
                {
                    // obsolete line folding: joined to the previous value
                    var last = head.Headers[^1];
                    head.Headers[^1] = new KeyValuePair<string, string>(last.Key, last.Value + " " + l.Trim());
                    continue;
                }
                int c = l.IndexOf(':');
                if (c <= 0)
                {
                    head.Error = new HeadError(400, "A header line has no \"Name: value\".");
                    return head;
                }
                head.Headers.Add(new KeyValuePair<string, string>(l[..c].Trim(), l[(c + 1)..].Trim()));
                if (head.Headers.Count > MaxHeaderCount)
                {
                    head.Error = new HeadError(431, $"More than {MaxHeaderCount} headers.");
                    return head;
                }
            }
            return head;
        }

        public async ValueTask<int> ReadAsync(Memory<byte> dest, CancellationToken ct)
        {
            if (_end > _start)
            {
                int n = Math.Min(dest.Length, _end - _start);
                _buf.AsSpan(_start, n).CopyTo(dest.Span);
                _start += n;
                return n;
            }
            return await _s.ReadAsync(dest, ct).ConfigureAwait(false);
        }

        /// <summary>One CRLF-terminated line (without it); null at EOF or past <paramref name="max"/>.</summary>
        public async Task<string?> ReadLineAsync(int max, CancellationToken ct)
        {
            while (true)
            {
                int i = _buf.AsSpan(_start, _end - _start).IndexOf((byte)'\n');
                if (i >= 0)
                {
                    string line = Encoding.Latin1.GetString(_buf, _start, i).TrimEnd('\r');
                    _start += i + 1;
                    return line;
                }
                if (_end - _start > max) return null;
                int n = await FillAsync(ct).ConfigureAwait(false);
                if (n <= 0) return null;
            }
        }
    }

    // Request text shown in the list: control characters and bidi controls replaced.
    internal static string Printable(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s) sb.Append(IsUnsafeDisplay(c) ? '?' : c);
        return sb.ToString();
    }

    /// <summary>C0 / DEL / C1 controls, line / paragraph separators and bidi marks, embeddings, overrides and isolates:
    /// characters that break a line or change how the rest of it reads.</summary>
    internal static bool IsUnsafeDisplay(char c)
        => char.IsControl(c) || c is >= (char)0x2028 and <= (char)0x202E || c is >= (char)0x2066 and <= (char)0x2069
           || c is (char)0x200E or (char)0x200F or (char)0x061C;
}
