using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>One line in the proxy's live connection log.</summary>
public sealed class ProxyLogEntry
{
    public string Time { get; init; } = "";
    public string Client { get; init; } = "";
    public string Proto { get; init; } = "";     // SOCKS5 / HTTP / HTTPS
    public string Target { get; init; } = "";
    public string User { get; init; } = "—";
    public string Status { get; init; } = "";
    public bool Ok { get; init; }
}

/// <summary>
/// A dependency-free SOCKS5 + HTTP forward proxy on a single <see cref="TcpListener"/>. The protocol
/// is auto-detected from the first byte (0x05 → SOCKS5, anything else → HTTP), so one port serves both.
/// Pure managed BCL — works on desktop and in the Android sandbox (listening socket, INTERNET permission,
/// port &gt; 1024, no driver/root). Optional username/password auth (SOCKS5 RFC 1929 + HTTP Basic 407).
/// Only TCP CONNECT/tunneling is proxied (SOCKS BIND / UDP ASSOCIATE are declined).
/// </summary>
public sealed class ProxyServer : IDisposable
{
    private readonly string? _user;
    private readonly string _pass;
    private readonly bool _authRequired;
    private readonly Action<ProxyLogEntry>? _onConn;
    private readonly Action? _onStats;
    private readonly SemaphoreSlim _slots;

    private TcpListener? _listener;
    private CancellationTokenSource? _cts;

    private int _active;
    private long _totalConn, _bytesUp, _bytesDown;

    public bool IsRunning { get; private set; }
    public int ActiveConnections => Volatile.Read(ref _active);
    public long TotalConnections => Interlocked.Read(ref _totalConn);
    public long BytesUp => Interlocked.Read(ref _bytesUp);
    public long BytesDown => Interlocked.Read(ref _bytesDown);

    public ProxyServer(string? user, string? pass, Action<ProxyLogEntry>? onConn, Action? onStats, int maxConnections)
    {
        _user = string.IsNullOrEmpty(user) ? null : user;
        _pass = pass ?? "";
        _authRequired = _user != null;
        _onConn = onConn;
        _onStats = onStats;
        _slots = new SemaphoreSlim(Math.Clamp(maxConnections, 1, 512));
    }

    public void Start(IPAddress bind, int port)
    {
        Stop();
        _cts = new CancellationTokenSource();
        _listener = new TcpListener(bind, port);
        _listener.Start();
        IsRunning = true;
        _ = AcceptLoop(_listener, _cts.Token);
    }

    public void Stop()
    {
        IsRunning = false;
        try { _cts?.Cancel(); } catch { }
        try { _listener?.Stop(); } catch { }
        _listener = null;
        try { _cts?.Dispose(); } catch { }
        _cts = null;
    }

    public void Dispose() => Stop();

    private async Task AcceptLoop(TcpListener listener, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            // Take a slot before accepting so idle-but-accepted sockets can't grow past the cap.
            try { await _slots.WaitAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }

            TcpClient client;
            try { client = await listener.AcceptTcpClientAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { _slots.Release(); break; }
            catch (ObjectDisposedException) { _slots.Release(); break; }
            catch
            {
                _slots.Release();
                try { await Task.Delay(100, ct).ConfigureAwait(false); } catch { break; }
                continue;
            }

            _ = HandleAsync(client, ct);   // releases the slot in its finally
        }
    }

    private async Task HandleAsync(TcpClient client, CancellationToken ct)
    {
        string peer = "?";
        try { peer = (client.Client.RemoteEndPoint as IPEndPoint)?.Address.ToString() ?? "?"; } catch { }

        Interlocked.Increment(ref _active);
        Interlocked.Increment(ref _totalConn);
        _onStats?.Invoke();
        try
        {
            using (client)
            {
                client.NoDelay = true;
                var stream = client.GetStream();
                var one = new byte[1];
                if (await stream.ReadAsync(one.AsMemory(0, 1), ct).ConfigureAwait(false) == 0) return;

                if (one[0] == 0x05) await HandleSocks5(stream, peer, ct).ConfigureAwait(false);
                else await HandleHttp(stream, peer, one[0], ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { }
        catch { /* per-connection errors are non-fatal to the server */ }
        finally
        {
            Interlocked.Decrement(ref _active);
            _onStats?.Invoke();
            _slots.Release();
        }
    }

    // ------------------------------------------------------------------ SOCKS5

    private async Task HandleSocks5(NetworkStream s, string peer, CancellationToken ct)
    {
        var buf = new byte[512];
        // greeting: VER already consumed. NMETHODS + methods.
        await ReadExact(s, buf, 1, ct);
        int nm = buf[0];
        await ReadExact(s, buf, nm, ct);
        bool noAuth = false, userPass = false;
        for (int i = 0; i < nm; i++) { if (buf[i] == 0x00) noAuth = true; if (buf[i] == 0x02) userPass = true; }

        string user = "—";
        if (_authRequired)
        {
            if (!userPass) { await s.WriteAsync(new byte[] { 0x05, 0xFF }, ct); Log(peer, "SOCKS5", "—", "—", false, "no user/pass method offered"); return; }
            await s.WriteAsync(new byte[] { 0x05, 0x02 }, ct);
            var (ok, u) = await Socks5Auth(s, buf, ct);
            user = u;
            await s.WriteAsync(new byte[] { 0x01, (byte)(ok ? 0x00 : 0x01) }, ct);
            if (!ok) { Log(peer, "SOCKS5", "—", user, false, "bad credentials"); return; }
        }
        else if (noAuth)
        {
            await s.WriteAsync(new byte[] { 0x05, 0x00 }, ct);
        }
        else if (userPass)
        {
            // Auth is off but the client insists on user/pass — accept any credentials.
            await s.WriteAsync(new byte[] { 0x05, 0x02 }, ct);
            (_, user) = await Socks5Auth(s, buf, ct);
            await s.WriteAsync(new byte[] { 0x01, 0x00 }, ct);
        }
        else { await s.WriteAsync(new byte[] { 0x05, 0xFF }, ct); return; }

        // request: VER CMD RSV ATYP DST.ADDR DST.PORT
        await ReadExact(s, buf, 4, ct);
        byte cmd = buf[1], atyp = buf[3];
        string host;
        if (atyp == 0x01) { await ReadExact(s, buf, 4, ct); host = new IPAddress(new[] { buf[0], buf[1], buf[2], buf[3] }).ToString(); }
        else if (atyp == 0x03) { await ReadExact(s, buf, 1, ct); int l = buf[0]; await ReadExact(s, buf, l, ct); host = Encoding.ASCII.GetString(buf, 0, l); }
        else if (atyp == 0x04) { var a = new byte[16]; await ReadExact(s, a, 16, ct); host = new IPAddress(a).ToString(); }
        else { await Socks5Reply(s, 0x08, ct); return; }   // address type not supported
        await ReadExact(s, buf, 2, ct);
        int port = (buf[0] << 8) | buf[1];
        string target = FormatTarget(host, port);

        if (cmd != 0x01) { await Socks5Reply(s, 0x07, ct); Log(peer, "SOCKS5", target, user, false, "command not supported"); return; }

        TcpClient remote;
        try { remote = await Dial(host, port, ct); }
        catch (Exception ex) { await Socks5Reply(s, Socks5ErrFor(ex), ct); Log(peer, "SOCKS5", target, user, false, "connect failed"); return; }

        await Socks5Reply(s, 0x00, ct);
        Log(peer, "SOCKS5", target, user, true, "connected");
        using (remote) await Relay(s, remote.GetStream(), ct);
    }

    private async Task<(bool ok, string user)> Socks5Auth(NetworkStream s, byte[] buf, CancellationToken ct)
    {
        // RFC 1929: VER(0x01) ULEN UNAME PLEN PASSWD
        await ReadExact(s, buf, 2, ct);
        int ulen = buf[1];
        await ReadExact(s, buf, ulen, ct);
        string uname = Encoding.UTF8.GetString(buf, 0, ulen);
        await ReadExact(s, buf, 1, ct);
        int plen = buf[0];
        await ReadExact(s, buf, plen, ct);
        string pass = Encoding.UTF8.GetString(buf, 0, plen);
        return (uname == _user && pass == _pass, uname);
    }

    private static Task Socks5Reply(NetworkStream s, byte rep, CancellationToken ct)
        => s.WriteAsync(new byte[] { 0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, ct).AsTask();

    private static byte Socks5ErrFor(Exception ex) => (byte)(ex is SocketException se ? se.SocketErrorCode switch
    {
        SocketError.ConnectionRefused => 0x05,
        SocketError.NetworkUnreachable => 0x03,
        SocketError.HostUnreachable => 0x04,
        SocketError.HostNotFound => 0x04,
        _ => 0x01,
    } : 0x01);

    // ------------------------------------------------------------------ HTTP

    private async Task HandleHttp(NetworkStream s, string peer, byte first, CancellationToken ct)
    {
        // Read the request head (starting with the already-consumed first byte) up to the blank line.
        var sb = new StringBuilder(256);
        sb.Append((char)first);
        var one = new byte[1];
        while (!EndsWithHeaderBreak(sb))
        {
            if (await s.ReadAsync(one.AsMemory(0, 1), ct).ConfigureAwait(false) == 0) break;
            sb.Append((char)one[0]);
            if (sb.Length > 32 * 1024) { await WriteAscii(s, "HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n", ct); return; }
        }
        string head = sb.ToString();
        int eol = head.IndexOf("\r\n", StringComparison.Ordinal);
        string requestLine = eol >= 0 ? head[..eol] : head;
        var parts = requestLine.Split(' ');
        if (parts.Length < 3) { await WriteAscii(s, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n", ct); return; }
        string method = parts[0], uri = parts[1], ver = parts[2];

        string user = "—";
        if (_authRequired)
        {
            var (ok, u) = CheckHttpAuth(head);
            user = u ?? "—";
            if (!ok)
            {
                await WriteAscii(s, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Echoes\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", ct);
                Log(peer, "HTTP", uri, user, false, "auth required");
                return;
            }
        }

        if (method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
        {
            var (h, p) = SplitHostPort(uri, 443);
            TcpClient remote;
            try { remote = await Dial(h, p, ct); }
            catch { await WriteAscii(s, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n", ct); Log(peer, "HTTPS", FormatTarget(h, p), user, false, "connect failed"); return; }
            await WriteAscii(s, "HTTP/1.1 200 Connection Established\r\n\r\n", ct);
            Log(peer, "HTTPS", FormatTarget(h, p), user, true, "tunnel");
            using (remote) await Relay(s, remote.GetStream(), ct);
        }
        else
        {
            if (!Uri.TryCreate(uri, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttp)
            {
                await WriteAscii(s, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n", ct);
                return;
            }
            string host = u.Host;
            int port = u.IsDefaultPort ? 80 : u.Port;
            TcpClient remote;
            try { remote = await Dial(host, port, ct); }
            catch { await WriteAscii(s, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n", ct); Log(peer, "HTTP", FormatTarget(host, port), user, false, "connect failed"); return; }

            var rstream = remote.GetStream();
            byte[] rebuilt = Encoding.ASCII.GetBytes(RebuildForOrigin(head, method, u, ver));
            await rstream.WriteAsync(rebuilt, ct);
            Interlocked.Add(ref _bytesUp, rebuilt.Length);
            Log(peer, "HTTP", $"{host}:{port}{u.PathAndQuery}", user, true, "forward");
            using (remote) await Relay(s, rstream, ct);
        }
    }

    private static bool EndsWithHeaderBreak(StringBuilder sb)
    {
        int n = sb.Length;
        return n >= 4 && sb[n - 1] == '\n' && sb[n - 2] == '\r' && sb[n - 3] == '\n' && sb[n - 4] == '\r';
    }

    // Convert an absolute-form proxy request into an origin-form request the target server accepts:
    // rewrite the request line to the path, drop Proxy-* hop headers, keep/synthesize Host.
    private static string RebuildForOrigin(string head, string method, Uri u, string ver)
    {
        var lines = head.Split("\r\n");
        var sb = new StringBuilder();
        sb.Append(method).Append(' ').Append(u.PathAndQuery).Append(' ').Append(ver).Append("\r\n");
        bool hasHost = false;
        for (int i = 1; i < lines.Length; i++)
        {
            string line = lines[i];
            if (line.Length == 0) break;
            if (line.StartsWith("Proxy-", StringComparison.OrdinalIgnoreCase)) continue;
            if (line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase)) hasHost = true;
            sb.Append(line).Append("\r\n");
        }
        if (!hasHost) sb.Append("Host: ").Append(u.Authority).Append("\r\n");
        sb.Append("\r\n");
        return sb.ToString();
    }

    private (bool ok, string? user) CheckHttpAuth(string head)
    {
        foreach (var line in head.Split("\r\n"))
        {
            if (!line.StartsWith("Proxy-Authorization:", StringComparison.OrdinalIgnoreCase)) continue;
            string v = line["Proxy-Authorization:".Length..].Trim();
            if (!v.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase)) continue;
            try
            {
                string raw = Encoding.UTF8.GetString(Convert.FromBase64String(v[6..].Trim()));
                int c = raw.IndexOf(':');
                string un = c >= 0 ? raw[..c] : raw;
                string pw = c >= 0 ? raw[(c + 1)..] : "";
                return (un == _user && pw == _pass, un);
            }
            catch { return (false, null); }
        }
        return (false, null);
    }

    private static (string host, int port) SplitHostPort(string s, int def)
    {
        if (s.StartsWith('['))   // [IPv6]:port
        {
            int e = s.IndexOf(']');
            if (e > 0)
            {
                string h = s[1..e];
                int c = s.IndexOf(':', e);
                return (h, c >= 0 && int.TryParse(s.AsSpan(c + 1), out int pp) ? pp : def);
            }
        }
        int i = s.LastIndexOf(':');
        return i > 0 && int.TryParse(s.AsSpan(i + 1), out int p) ? (s[..i], p) : (s, def);
    }

    // ------------------------------------------------------------------ shared

    private static async Task<TcpClient> Dial(string host, int port, CancellationToken ct)
    {
        var remote = new TcpClient { NoDelay = true };
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(15000);
        try { await remote.ConnectAsync(host, port, timeout.Token).ConfigureAwait(false); }
        catch { remote.Dispose(); throw; }
        return remote;
    }

    private async Task Relay(NetworkStream a, NetworkStream b, CancellationToken ct)
    {
        var up = Pump(a, b, true, ct);
        var down = Pump(b, a, false, ct);
        await Task.WhenAny(up, down).ConfigureAwait(false);
        // The disposing 'using' on both endpoints unblocks whichever pump is still reading.
    }

    private async Task Pump(NetworkStream src, NetworkStream dst, bool up, CancellationToken ct)
    {
        var buf = new byte[16 * 1024];
        try
        {
            int n;
            while ((n = await src.ReadAsync(buf.AsMemory(0, buf.Length), ct).ConfigureAwait(false)) > 0)
            {
                await dst.WriteAsync(buf.AsMemory(0, n), ct).ConfigureAwait(false);
                if (up) Interlocked.Add(ref _bytesUp, n); else Interlocked.Add(ref _bytesDown, n);
            }
        }
        catch { /* peer closed / reset — normal end of a tunnel */ }
        try { dst.Socket.Shutdown(SocketShutdown.Send); } catch { }
    }

    private static async Task ReadExact(NetworkStream s, byte[] buf, int n, CancellationToken ct)
    {
        int off = 0;
        while (off < n)
        {
            int r = await s.ReadAsync(buf.AsMemory(off, n - off), ct).ConfigureAwait(false);
            if (r == 0) throw new IOException("unexpected end of stream");
            off += r;
        }
    }

    private static Task WriteAscii(NetworkStream s, string text, CancellationToken ct)
        => s.WriteAsync(Encoding.ASCII.GetBytes(text), ct).AsTask();

    private static string FormatTarget(string host, int port)
        => host.Contains(':') ? $"[{host}]:{port}" : $"{host}:{port}";

    private void Log(string client, string proto, string target, string user, bool ok, string status)
        => _onConn?.Invoke(new ProxyLogEntry
        {
            Time = DateTime.Now.ToString("HH:mm:ss"),
            Client = client,
            Proto = proto,
            Target = target,
            User = string.IsNullOrEmpty(user) ? "—" : user,
            Ok = ok,
            Status = status,
        });
}
