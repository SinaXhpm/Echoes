using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>What a proxy check found.</summary>
public enum ProxyCheckStatus
{
    Waiting,
    Checking,
    /// <summary>It relayed a request: the exit IP is known.</summary>
    Working,
    /// <summary>It is a proxy that wants a username and password (none given).</summary>
    AuthRequired,
    /// <summary>It refused the username and password given.</summary>
    AuthFailed,
    /// <summary>Something answers on that port, but not as a proxy.</summary>
    NotProxy,
    /// <summary>Nothing listens there (connection refused).</summary>
    Refused,
    /// <summary>No answer in time.</summary>
    Timeout,
    /// <summary>The host can't be found or reached.</summary>
    Unreachable,
    /// <summary>A proxy, but the request through it failed.</summary>
    Failed,
    Cancelled,
}

/// <summary>The outcome of one proxy check (never holds the password).</summary>
public sealed class ProxyCheckResult
{
    public ProxyCheckStatus Status { get; init; }
    /// <summary>"SOCKS5", "SOCKS4", "SOCKS4a", "HTTP", "HTTP (no CONNECT)"; empty when unknown.</summary>
    public string Protocol { get; init; } = string.Empty;
    /// <summary>TCP connect time to the proxy.</summary>
    public int? ConnectMs { get; init; }
    /// <summary>From the start of the request through the proxy (TLS included) to the first byte of the answer.</summary>
    public int? FirstByteMs { get; init; }
    public string ExitIp { get; init; } = string.Empty;
    /// <summary>Two-letter country code of the exit IP (as the IP service sees it), upper case.</summary>
    public string Country { get; init; } = string.Empty;
    public string Detail { get; init; } = string.Empty;
}

/// <summary>
/// Checks one proxy: TCP reachability and connect time, the protocol (SOCKS5, SOCKS4/4a or HTTP CONNECT / plain HTTP —
/// detected when the line doesn't say), login failures, and one light request through it to an IP echo service
/// (Cloudflare's https://www.cloudflare.com/cdn-cgi/trace) for the exit IP, its country and the time to first byte.
/// A proxy that only forwards plain http:// requests (no CONNECT) is tried with the same page over http://.
/// </summary>
public static class ProxyCheckEngine
{
    public static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(6);
    /// <summary>The handshake plus the echo request, per attempt.</summary>
    public static readonly TimeSpan StepTimeout = TimeSpan.FromSeconds(12);
    private const int MaxHeadBytes = 16 * 1024;
    private const int MaxBodyBytes = 16 * 1024;

    // Cloudflare's trace by NAME: the TLS hello then carries a server name (some networks' filters reset one without, as to
    // https://1.1.1.1), and http:// is served too (1.1.1.1 redirects it to https). The proxy resolves the name (SOCKS5,
    // HTTP); SOCKS4 can't, so it gets an IPv4 address looked up here.
    private sealed record Echo(string Host, int Port, bool Tls, string Path);

    private static readonly Echo RealEcho = new("www.cloudflare.com", 443, true, "/cdn-cgi/trace");
    private static readonly Echo RealPlainEcho = new("www.cloudflare.com", 80, false, "/cdn-cgi/trace");
    private static Echo? _testEcho;

    private static readonly SemaphoreSlim V4Gate = new(1, 1);
    private static (string Host, IPAddress Address, long Until)? _v4Cache;

    // The echo host's IPv4 address for SOCKS4 (cached for 10 minutes: one lookup for a whole list).
    private static async Task<IPAddress?> EchoIpv4Async(Echo echo, CancellationToken ct)
    {
        if (IPAddress.TryParse(echo.Host, out var literal)) return literal.AddressFamily == AddressFamily.InterNetwork ? literal : null;
        await V4Gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_v4Cache is { } c && c.Host == echo.Host && c.Until > Environment.TickCount64) return c.Address;
            using var dns = CancellationTokenSource.CreateLinkedTokenSource(ct);
            dns.CancelAfter(ConnectTimeout);
            IPAddress[] all;
            try { all = await Dns.GetHostAddressesAsync(echo.Host, AddressFamily.InterNetwork, dns.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return null; }
            catch (SocketException) { return null; }
            var a = Array.Find(all, x => x.AddressFamily == AddressFamily.InterNetwork);
            if (a != null) _v4Cache = (echo.Host, a, Environment.TickCount64 + 10 * 60_000);
            return a;
        }
        finally { V4Gate.Release(); }
    }

    /// <summary>
    /// Test hook: the IP echo service as a loopback plain-HTTP URL (http://127.0.0.1:port/path) answering in the trace
    /// format ("ip=…\nloc=…"). Only loopback is accepted. Null restores Cloudflare's. Not bound to any UI or setting.
    /// </summary>
    internal static void SetTestEcho(string? url)
    {
        if (url is null) { _testEcho = null; return; }
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttp || !IPAddress.TryParse(u.Host, out var ip)
            || !IPAddress.IsLoopback(ip) || ip.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("The test echo must be an http://127.x.x.x URL.");
        _testEcho = new Echo(u.Host, u.Port, false, u.PathAndQuery);
    }

    private static Echo TunnelEcho => _testEcho ?? RealEcho;
    private static Echo PlainEcho => _testEcho ?? RealPlainEcho;

    private enum Verdict { NotThis, Done }

    private sealed class Step
    {
        public Verdict Verdict;
        public ProxyCheckResult? Result;
        public bool SawHttp;
        public string Why = string.Empty;
        /// <summary>The HTTP status of the echo answer (0: none / not HTTP).</summary>
        public int HttpCode;
        /// <summary>The answer came from Cloudflare (a CF-RAY header): the proxy did relay it.</summary>
        public bool Relayed;
    }

    /// <summary>How long a probe waits for the FIRST answer: a server of another protocol often just waits for more.</summary>
    private static readonly TimeSpan FirstAnswerTimeout = TimeSpan.FromSeconds(5);

    // The first reply of a probe, with its own short deadline. Returns 0 (nothing) when that deadline passes.
    private static async Task<int> ReadFirstAsync(Stream s, byte[] buf, int min, CancellationToken ct)
    {
        using var first = CancellationTokenSource.CreateLinkedTokenSource(ct);
        first.CancelAfter(FirstAnswerTimeout);
        try { return await ReadAtLeastAsync(s, buf, min, first.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return 0; }
    }

    private static Step NotThis(string why, bool sawHttp = false) => new() { Verdict = Verdict.NotThis, Why = why, SawHttp = sawHttp };

    /// <summary>Check one proxy. Never throws except an <see cref="OperationCanceledException"/> for <paramref name="ct"/>.</summary>
    public static async Task<ProxyCheckResult> CheckAsync(ProxyCheckEntry entry, CancellationToken ct)
    {
        IPAddress[] addrs;
        if (IPAddress.TryParse(entry.Host, out var literal)) addrs = new[] { literal };
        else
        {
            try
            {
                using var dns = CancellationTokenSource.CreateLinkedTokenSource(ct);
                dns.CancelAfter(ConnectTimeout);
                addrs = await Dns.GetHostAddressesAsync(entry.Host, dns.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return new ProxyCheckResult { Status = ProxyCheckStatus.Unreachable, Detail = "Its name didn't resolve in time." };
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception)
            {
                return new ProxyCheckResult { Status = ProxyCheckStatus.Unreachable, Detail = "Its host name doesn't resolve." };
            }
            if (addrs.Length == 0) return new ProxyCheckResult { Status = ProxyCheckStatus.Unreachable, Detail = "Its host name has no address." };
        }

        ProxyKind[] order = entry.Kind switch
        {
            ProxyKind.Http => new[] { ProxyKind.Http },
            ProxyKind.Socks4 => new[] { ProxyKind.Socks4 },
            ProxyKind.Socks4a => new[] { ProxyKind.Socks4a },
            ProxyKind.Socks5 => new[] { ProxyKind.Socks5 },
            // The usual SOCKS ports try SOCKS5 first; everything else HTTP first. An HTTP probe fails fast on a SOCKS
            // server (it closes on the first byte), while a SOCKS greeting can leave an HTTP proxy waiting for a line.
            _ => entry.Port is 1080 or 1081 or 1085 or 1086 or 9050 or 9150 or 10808 or 7891
                ? new[] { ProxyKind.Socks5, ProxyKind.Http, ProxyKind.Socks4 }
                : new[] { ProxyKind.Http, ProxyKind.Socks5, ProxyKind.Socks4 },
        };

        int? connectMs = null;
        var why = new StringBuilder();
        bool sawHttp = false;
        for (int i = 0; i < order.Length; i++)
        {
            var kind = order[i];
            if (sawHttp && kind != ProxyKind.Http) continue;   // it speaks HTTP: SOCKS won't answer either
            var (socket, ms, fail) = await ConnectAsync(addrs, entry.Port, ct).ConfigureAwait(false);
            if (socket is null) return fail!;   // not reachable at all: the protocol doesn't matter
            connectMs ??= ms;
            Step step;
            using (var stream = new NetworkStream(socket, ownsSocket: true))
            {
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                deadline.CancelAfter(StepTimeout);
                try
                {
                    step = kind switch
                    {
                        ProxyKind.Socks5 => await Socks5Async(stream, entry, deadline.Token).ConfigureAwait(false),
                        ProxyKind.Socks4 or ProxyKind.Socks4a => await Socks4Async(stream, entry, kind, deadline.Token).ConfigureAwait(false),
                        _ => await HttpAsync(stream, entry, addrs, deadline.Token).ConfigureAwait(false),
                    };
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    step = NotThis("no answer");
                }
                catch (OperationCanceledException) { throw; }
                catch (StepTimeoutException ex)
                {
                    ct.ThrowIfCancellationRequested();   // a Stop, not a slow proxy
                    step = new Step { Verdict = Verdict.Done, Result = new ProxyCheckResult { Status = ProxyCheckStatus.Timeout, Protocol = ex.Protocol, Detail = ex.Message } };
                }
                catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
                {
                    step = NotThis("closed the connection");
                }
            }
            if (step.Verdict == Verdict.Done)
            {
                var r = step.Result!;
                return new ProxyCheckResult
                {
                    Status = r.Status, Protocol = r.Protocol, ConnectMs = connectMs, FirstByteMs = r.FirstByteMs,
                    ExitIp = r.ExitIp, Country = r.Country, Detail = r.Detail,
                };
            }
            sawHttp |= step.SawHttp;
            if (sawHttp && kind != ProxyKind.Http && Array.IndexOf(order, ProxyKind.Http) > i)
            {
                // try HTTP next, whatever the order said
                order = new[] { ProxyKind.Http };
                i = -1;
            }
            if (why.Length > 0) why.Append("; ");
            why.Append(Label(kind, entry)).Append(": ").Append(step.Why);
        }

        bool explicitKind = entry.Kind != ProxyKind.Auto;
        return new ProxyCheckResult
        {
            Status = ProxyCheckStatus.NotProxy,
            ConnectMs = connectMs,
            Detail = explicitKind
                ? $"Doesn't answer as a {Label(entry.Kind, entry)} proxy ({why})."
                : $"The port is open, but it doesn't answer as a SOCKS5, SOCKS4 or HTTP proxy ({why}).",
        };
    }

    private static string Label(ProxyKind kind, ProxyCheckEntry entry) => kind switch
    {
        ProxyKind.Socks5 => "SOCKS5",
        ProxyKind.Socks4 => "SOCKS4",
        ProxyKind.Socks4a => "SOCKS4a",
        _ => "HTTP",
    };

    private sealed class StepTimeoutException : Exception
    {
        public StepTimeoutException(string protocol, string message) : base(message) => Protocol = protocol;
        public string Protocol { get; }
    }

    // ---------------------------------------------------------------- TCP

    private static async Task<(Socket? Socket, int Ms, ProxyCheckResult? Fail)> ConnectAsync(IPAddress[] addrs, int port, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(ConnectTimeout);
        SocketException? last = null;
        foreach (var a in addrs)
        {
            var s = new Socket(a.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            var sw = Stopwatch.StartNew();
            try
            {
                await s.ConnectAsync(new IPEndPoint(a, port), cts.Token).ConfigureAwait(false);
                return (s, (int)sw.ElapsedMilliseconds, null);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                s.Dispose();
                return (null, 0, new ProxyCheckResult { Status = ProxyCheckStatus.Timeout, Detail = $"No answer to the connection within {ConnectTimeout.TotalSeconds:0} s." });
            }
            catch (SocketException ex)
            {
                s.Dispose();
                last = ex;
            }
            catch
            {
                s.Dispose();
                throw;
            }
        }
        return (null, 0, last?.SocketErrorCode switch
        {
            SocketError.ConnectionRefused => new ProxyCheckResult { Status = ProxyCheckStatus.Refused, Detail = "Connection refused: nothing listens on that port." },
            SocketError.TimedOut => new ProxyCheckResult { Status = ProxyCheckStatus.Timeout, Detail = "The connection timed out." },
            SocketError.HostUnreachable or SocketError.NetworkUnreachable or SocketError.AddressNotAvailable
                => new ProxyCheckResult { Status = ProxyCheckStatus.Unreachable, Detail = "The host can't be reached from here." },
            _ => new ProxyCheckResult { Status = ProxyCheckStatus.Unreachable, Detail = "Couldn't connect: " + (last?.Message ?? "no address") },
        });
    }

    // Reads at least min bytes (more may come); returns what arrived before the peer closed.
    private static async Task<int> ReadAtLeastAsync(Stream s, byte[] buf, int min, CancellationToken ct)
    {
        int got = 0;
        while (got < min)
        {
            int n = await s.ReadAsync(buf.AsMemory(got, buf.Length - got), ct).ConfigureAwait(false);
            if (n == 0) break;
            got += n;
        }
        return got;
    }

    private static bool LooksHttp(byte[] b, int n) => n >= 2 && b[0] == (byte)'H' && b[1] == (byte)'T';

    // ---------------------------------------------------------------- SOCKS5 (RFC 1928 / 1929)

    private static async Task<Step> Socks5Async(NetworkStream s, ProxyCheckEntry e, CancellationToken ct)
    {
        byte[] greet = e.HasLogin ? new byte[] { 5, 2, 0, 2 } : new byte[] { 5, 1, 0 };
        await s.WriteAsync(greet, ct).ConfigureAwait(false);
        var buf = new byte[512];
        int n = await ReadFirstAsync(s, buf, 2, ct).ConfigureAwait(false);
        if (LooksHttp(buf, n)) return NotThis("answered HTTP", sawHttp: true);
        if (n < 2 || buf[0] != 5) return NotThis(n == 0 ? "no answer" : "unexpected answer");
        const string proto = "SOCKS5";
        switch (buf[1])
        {
            case 0xFF:
                return Done(e.HasLogin ? ProxyCheckStatus.AuthFailed : ProxyCheckStatus.AuthRequired, proto,
                            e.HasLogin ? "It accepts none of the offered login methods." : "It needs a username and password.");
            case 0x02:
                if (!e.HasLogin) return Done(ProxyCheckStatus.AuthRequired, proto, "It needs a username and password.");
                byte[] u = Encoding.UTF8.GetBytes(e.User), p = Encoding.UTF8.GetBytes(e.Pass);
                if (u.Length > 255 || p.Length > 255) return Done(ProxyCheckStatus.AuthFailed, proto, "The username or password is too long for SOCKS5.");
                var auth = new byte[3 + u.Length + p.Length];
                auth[0] = 1;
                auth[1] = (byte)u.Length;
                u.CopyTo(auth, 2);
                auth[2 + u.Length] = (byte)p.Length;
                p.CopyTo(auth, 3 + u.Length);
                await s.WriteAsync(auth, ct).ConfigureAwait(false);
                Array.Clear(auth);
                n = await ReadAtLeastAsync(s, buf, 2, ct).ConfigureAwait(false);
                if (n < 2 || buf[1] != 0) return Done(ProxyCheckStatus.AuthFailed, proto, "Wrong username or password.");
                break;
            case 0x00:
                break;
            default:
                return Done(ProxyCheckStatus.Failed, proto, $"It asks for a login method Echoes doesn't speak (0x{buf[1]:X2}).");
        }

        var echo = TunnelEcho;
        // an address as such; a name for the proxy to resolve (ATYP 3: length + name)
        byte atyp;
        byte[] addr;
        if (IPAddress.TryParse(echo.Host, out var lit))
        {
            addr = lit.GetAddressBytes();
            atyp = (byte)(addr.Length == 4 ? 1 : 4);
        }
        else
        {
            byte[] host = Encoding.ASCII.GetBytes(echo.Host);
            addr = new byte[1 + host.Length];
            addr[0] = (byte)host.Length;
            host.CopyTo(addr, 1);
            atyp = 3;
        }
        var req = new byte[6 + addr.Length];
        req[0] = 5; req[1] = 1; req[2] = 0; req[3] = atyp;
        addr.CopyTo(req, 4);
        req[4 + addr.Length] = (byte)(echo.Port >> 8);
        req[5 + addr.Length] = (byte)echo.Port;
        await s.WriteAsync(req, ct).ConfigureAwait(false);
        n = await ReadAtLeastAsync(s, buf, 5, ct).ConfigureAwait(false);
        if (n < 2 || buf[0] != 5) return Done(ProxyCheckStatus.Failed, proto, "It broke off the connect request.");
        if (buf[1] != 0) return Done(ProxyCheckStatus.Failed, proto, "It couldn't open a connection to the IP service: " + Socks5Reply(buf[1]) + ".");
        if (n < 5) return Done(ProxyCheckStatus.Failed, proto, "It broke off the connect request.");
        // the rest of the reply (the bound address) must be read before the tunnel carries the request
        int need = 4 + buf[3] switch { 1 => 4, 4 => 16, 3 => 1 + buf[4], _ => 0 } + 2;
        if (need > buf.Length) return Done(ProxyCheckStatus.Failed, proto, "Its connect reply is malformed.");
        while (n < need)
        {
            int m = await s.ReadAsync(buf.AsMemory(n, need - n), ct).ConfigureAwait(false);
            if (m == 0) return Done(ProxyCheckStatus.Failed, proto, "It broke off the connect request.");
            n += m;
        }
        return await RequestEchoAsync(s, proto, plainViaHttpProxy: false, e, ct).ConfigureAwait(false);
    }

    private static string Socks5Reply(byte rep) => rep switch
    {
        1 => "general failure",
        2 => "not allowed by its rules",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused",
        6 => "TTL expired",
        7 => "command not supported",
        8 => "address type not supported",
        _ => $"error {rep}",
    };

    // ---------------------------------------------------------------- SOCKS4 / 4a

    private static async Task<Step> Socks4Async(NetworkStream s, ProxyCheckEntry e, ProxyKind kind, CancellationToken ct)
    {
        string proto = kind == ProxyKind.Socks4a ? "SOCKS4a" : "SOCKS4";
        var echo = TunnelEcho;
        byte[] user = Encoding.UTF8.GetBytes(e.User);
        if (user.Length > 255) user = Array.Empty<byte>();
        // SOCKS4a: the proxy resolves the name (address 0.0.0.1, the name after the user id); SOCKS4: an IPv4 address
        byte[] ip, name = Array.Empty<byte>();
        if (kind == ProxyKind.Socks4a && !IPAddress.TryParse(echo.Host, out _))
        {
            ip = new byte[] { 0, 0, 0, 1 };
            name = Encoding.ASCII.GetBytes(echo.Host + "\0");
        }
        else if (await EchoIpv4Async(echo, ct).ConfigureAwait(false) is { } v4) ip = v4.GetAddressBytes();
        else return Done(ProxyCheckStatus.Failed, proto, $"Couldn't look up {echo.Host} for the SOCKS4 test.");
        var req = new byte[9 + user.Length + name.Length];
        req[0] = 4; req[1] = 1;
        req[2] = (byte)(echo.Port >> 8); req[3] = (byte)echo.Port;
        ip.CopyTo(req, 4);
        user.CopyTo(req, 8);
        req[8 + user.Length] = 0;
        name.CopyTo(req, 9 + user.Length);
        await s.WriteAsync(req, ct).ConfigureAwait(false);
        var buf = new byte[64];
        int n = await ReadFirstAsync(s, buf, 8, ct).ConfigureAwait(false);
        if (LooksHttp(buf, n)) return NotThis("answered HTTP", sawHttp: true);
        if (n < 8 || buf[0] is not (0 or 4)) return NotThis(n == 0 ? "no answer" : "unexpected answer");
        return buf[1] switch
        {
            0x5A => await RequestEchoAsync(s, proto, plainViaHttpProxy: false, e, ct).ConfigureAwait(false),
            0x5B => Done(ProxyCheckStatus.Failed, proto, "It rejected the request (91)."),
            0x5C or 0x5D => Done(e.HasLogin ? ProxyCheckStatus.AuthFailed : ProxyCheckStatus.AuthRequired, proto,
                                 "It rejected the user id (identd check failed)."),
            _ => NotThis("unexpected answer"),
        };
    }

    // ---------------------------------------------------------------- HTTP CONNECT, then plain HTTP

    private static async Task<Step> HttpAsync(NetworkStream s, ProxyCheckEntry e, IPAddress[] addrs, CancellationToken ct)
    {
        var echo = TunnelEcho;
        string target = echo.Host + ":" + echo.Port;
        string auth = e.HasLogin ? "Proxy-Authorization: Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(e.User + ":" + e.Pass)) + "\r\n" : string.Empty;
        await s.WriteAsync(Encoding.ASCII.GetBytes(
            $"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: Echoes\r\n{auth}Proxy-Connection: keep-alive\r\n\r\n"), ct).ConfigureAwait(false);
        string? head;
        using (var first = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            first.CancelAfter(FirstAnswerTimeout);
            try { (head, _) = await ReadHeadAsync(s, first.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return NotThis("no answer"); }
        }
        if (head is null) return NotThis("closed the connection");
        if (!head.StartsWith("HTTP/", StringComparison.Ordinal)) return NotThis("unexpected answer");
        int code = StatusCode(head);
        if (code is >= 200 and < 300) return await RequestEchoAsync(s, "HTTP", plainViaHttpProxy: false, e, ct).ConfigureAwait(false);
        if (code == 407)
            return Done(e.HasLogin ? ProxyCheckStatus.AuthFailed : ProxyCheckStatus.AuthRequired, "HTTP",
                        e.HasLogin ? "Wrong username or password (407)." : "It needs a username and password (407).");

        // No CONNECT (or not to this port): a plain-HTTP proxy still forwards "GET http://…" — on a new connection.
        var (socket, _, _) = await ConnectAsync(addrs, e.Port, ct).ConfigureAwait(false);
        if (socket is null) return Done(ProxyCheckStatus.Failed, "HTTP", $"It refused CONNECT (HTTP {code}) and then the connection.");
        using var plain = new NetworkStream(socket, ownsSocket: true);
        var step = await RequestEchoAsync(plain, "HTTP (no CONNECT)", plainViaHttpProxy: true, e, ct).ConfigureAwait(false);
        if (step.Result is { Status: ProxyCheckStatus.Failed } && step.HttpCode is > 0 and not 200 && !step.Relayed)
            return code == 403 && step.HttpCode == 403
                ? Done(ProxyCheckStatus.Failed, "HTTP", "It refuses to relay to the IP service (HTTP 403).")
                : Done(ProxyCheckStatus.NotProxy, string.Empty,
                       $"A web server, not a proxy: it answers HTTP {code} to CONNECT and HTTP {step.HttpCode} to a proxy request.");
        return step;
    }

    private static int StatusCode(string head)
    {
        int sp = head.IndexOf(' ');
        return sp > 0 && head.Length >= sp + 4 && int.TryParse(head.AsSpan(sp + 1, 3), out int c) ? c : 0;
    }

    // Reads up to the blank line after the head. Returns the head (Latin-1) and any body bytes that came with it.
    private static async Task<(string? Head, byte[] Extra)> ReadHeadAsync(Stream s, CancellationToken ct)
    {
        var buf = new byte[MaxHeadBytes];
        int got = 0;
        while (got < buf.Length)
        {
            int n = await s.ReadAsync(buf.AsMemory(got), ct).ConfigureAwait(false);
            if (n == 0) break;
            int from = Math.Max(0, got - 3);
            got += n;
            int end = IndexOfBlankLine(buf, from, got);
            if (end >= 0)
                return (Encoding.Latin1.GetString(buf, 0, end), buf.AsSpan(end + 4, got - end - 4).ToArray());
            if (got >= 5 && !(buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P')) break;   // not HTTP: stop at once
        }
        return got == 0 ? (null, Array.Empty<byte>()) : (Encoding.Latin1.GetString(buf, 0, got), Array.Empty<byte>());
    }

    private static int IndexOfBlankLine(byte[] b, int from, int to)
    {
        for (int i = from; i + 3 < to; i++)
            if (b[i] == '\r' && b[i + 1] == '\n' && b[i + 2] == '\r' && b[i + 3] == '\n') return i;
        return -1;
    }

    // ---------------------------------------------------------------- the request through the proxy

    private static async Task<Step> RequestEchoAsync(Stream tunnel, string proto, bool plainViaHttpProxy, ProxyCheckEntry e, CancellationToken ct)
    {
        var echo = plainViaHttpProxy ? PlainEcho : TunnelEcho;
        var sw = Stopwatch.StartNew();
        Stream s = tunnel;
        SslStream? ssl = null;
        try
        {
            if (echo.Tls && !plainViaHttpProxy)
            {
                ssl = new SslStream(tunnel, leaveInnerStreamOpen: true);
                try
                {
                    await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = echo.Host }, ct).ConfigureAwait(false);
                }
                catch (AuthenticationException)
                {
                    return Done(ProxyCheckStatus.Failed, proto, "HTTPS through it failed the certificate check: it may intercept encrypted traffic.");
                }
                catch (Exception ex) when (ex is IOException or SocketException)
                {
                    return Done(ProxyCheckStatus.Failed, proto, "It dropped the HTTPS connection to the IP service.");
                }
                s = ssl;
            }

            string request;
            if (plainViaHttpProxy)
            {
                string hostPort = echo.Port == 80 ? echo.Host : echo.Host + ":" + echo.Port;
                string auth = e.HasLogin ? "Proxy-Authorization: Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(e.User + ":" + e.Pass)) + "\r\n" : string.Empty;
                request = $"GET http://{hostPort}{echo.Path} HTTP/1.1\r\nHost: {hostPort}\r\nUser-Agent: Echoes\r\nAccept: */*\r\n{auth}Connection: close\r\n\r\n";
            }
            else
            {
                string host = echo.Tls ? echo.Host : echo.Host + ":" + echo.Port;
                request = $"GET {echo.Path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Echoes\r\nAccept: */*\r\nConnection: close\r\n\r\n";
            }
            await s.WriteAsync(Encoding.ASCII.GetBytes(request), ct).ConfigureAwait(false);

            var buf = new byte[MaxHeadBytes + MaxBodyBytes];
            int got = await s.ReadAsync(buf.AsMemory(0, buf.Length), ct).ConfigureAwait(false);
            if (got == 0) return Done(ProxyCheckStatus.Failed, proto, "It closed the connection without an answer.");
            int firstByte = (int)sw.ElapsedMilliseconds;
            try
            {
                while (got < buf.Length)
                {
                    int n = await s.ReadAsync(buf.AsMemory(got), ct).ConfigureAwait(false);
                    if (n == 0) break;
                    got += n;
                    if (LooksComplete(buf, got)) break;
                }
            }
            catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException) { /* what arrived is enough */ }

            string text = Encoding.Latin1.GetString(buf, 0, got);
            int code = text.StartsWith("HTTP/", StringComparison.Ordinal) ? StatusCode(text) : 0;
            if (plainViaHttpProxy && code == 407)
                return Done(e.HasLogin ? ProxyCheckStatus.AuthFailed : ProxyCheckStatus.AuthRequired, proto,
                            e.HasLogin ? "Wrong username or password (407)." : "It needs a username and password (407).");
            int bodyAt = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            string body = bodyAt >= 0 ? text[(bodyAt + 4)..] : string.Empty;
            string ip = DdnsIpDetector.TraceValue(body, "ip");
            if (ip.Length == 0 && IPAddress.TryParse(body.Trim(), out _)) ip = body.Trim();
            if (code != 200 || !IPAddress.TryParse(ip, out var exit))
            {
                var failed = Done(ProxyCheckStatus.Failed, proto, code == 0
                    ? "Its answer wasn't HTTP: it may not relay this kind of traffic."
                    : $"The answer through it was HTTP {code}, not the IP service's page.");
                failed.HttpCode = code;
                failed.Relayed = bodyAt > 0 && text.AsSpan(0, bodyAt).Contains("\r\ncf-ray:", StringComparison.OrdinalIgnoreCase);
                return failed;
            }
            string loc = DdnsIpDetector.TraceValue(body, "loc").ToUpperInvariant();
            return new Step
            {
                Verdict = Verdict.Done,
                Result = new ProxyCheckResult
                {
                    Status = ProxyCheckStatus.Working,
                    Protocol = proto,
                    FirstByteMs = firstByte,
                    ExitIp = exit.ToString(),
                    Country = loc.Length == 2 && char.IsAsciiLetter(loc[0]) && char.IsAsciiLetter(loc[1]) && loc != "XX" && loc != "T1" ? loc : string.Empty,
                },
            };
        }
        catch (OperationCanceledException)
        {
            // the step's deadline (or a Stop: CheckAsync tells them apart)
            throw new StepTimeoutException(proto, "It accepted the connection, but no answer came back through it in time.");
        }
        finally
        {
            ssl?.Dispose();
        }
    }

    // The head is in and the body has all of its Content-Length (the trace answer is small): no need to wait for the close.
    private static bool LooksComplete(byte[] buf, int got)
    {
        int end = IndexOfBlankLine(buf, 0, got);
        if (end < 0) return false;
        string head = Encoding.Latin1.GetString(buf, 0, end);
        int at = head.IndexOf("\r\nContent-Length:", StringComparison.OrdinalIgnoreCase);
        if (at < 0) return false;
        int start = at + "\r\nContent-Length:".Length;
        int stop = head.IndexOf("\r\n", start, StringComparison.Ordinal);
        string value = (stop < 0 ? head[start..] : head[start..stop]).Trim();
        return int.TryParse(value, out int len) && got - (end + 4) >= len;
    }

    private static Step Done(ProxyCheckStatus status, string proto, string detail)
        => new() { Verdict = Verdict.Done, Result = new ProxyCheckResult { Status = status, Protocol = proto, Detail = detail } };
}
