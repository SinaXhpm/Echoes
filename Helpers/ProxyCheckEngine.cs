using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;
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
/// A proxy that only forwards plain http:// requests (no CONNECT) is tried with the same page over http://. When the
/// trace doesn't come through a proxy that took the request, other IP services are asked through it the same way.
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
    private sealed record Echo(string Name, string Host, int Port, bool Tls, string Path);

    private static readonly Echo RealEcho = new("Cloudflare", "www.cloudflare.com", 443, true, "/cdn-cgi/trace");
    private static readonly Echo RealPlainEcho = new("Cloudflare", "www.cloudflare.com", 80, false, "/cdn-cgi/trace");

    // When the trace doesn't come through (Cloudflare unreachable or refusing from the proxy's exit, its name filtered on
    // the way), these are asked through the same proxy, the same way, for the exit IP and its country: the ones not on
    // Cloudflare's network first (ipinfo.io, ipleak.net). Through a tunnel over HTTPS, so the proxy can't rewrite the
    // answer; a proxy without CONNECT only relays http:// (ip.sb and country.is send that on to https).
    private static readonly Echo[] RealTunnelEchoes =
    {
        new("ipinfo.io", "ipinfo.io", 443, true, "/json"),
        new("ipleak.net", "ipleak.net", 443, true, "/json/"),
        new("ipwho.is", "ipwho.is", 443, true, "/"),
        new("ifconfig.co", "ifconfig.co", 443, true, "/json"),
        new("ip.sb", "api.ip.sb", 443, true, "/geoip"),
        new("country.is", "api.country.is", 443, true, "/"),
    };

    private static readonly Echo[] RealPlainEchoes =
    {
        new("ipinfo.io", "ipinfo.io", 80, false, "/json"),
        new("ip-api.com", "ip-api.com", 80, false, "/json/?fields=status,countryCode,query"),
        new("ipleak.net", "ipleak.net", 80, false, "/json/"),
        new("ipwho.is", "ipwho.is", 80, false, "/"),
        new("ifconfig.co", "ifconfig.co", 80, false, "/json"),
    };

    private static Echo? _testEcho;
    private static Echo[] _testOthers = Array.Empty<Echo>();

    // The other IP services: two at a time, a head start apart, each with its own deadline, all within a budget (after a
    // timeout only the first two: the proxy most likely doesn't relay anything).
    private static readonly TimeSpan OthersHeadStart = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan OthersPerSource = TimeSpan.FromSeconds(8);
    private static readonly TimeSpan OthersBudget = TimeSpan.FromSeconds(16);

    private static readonly SemaphoreSlim V4Gate = new(1, 1);
    private static readonly ConcurrentDictionary<string, (IPAddress Address, long Until)> s_v4 = new(StringComparer.OrdinalIgnoreCase);

    // An echo host's IPv4 address for SOCKS4 (cached for 10 minutes: one lookup for a whole list). The proxy is handed the
    // address, so it is resolved around a resolver that blocks the name (ServiceDns): a filter's answer would send it nowhere.
    private static async Task<IPAddress?> EchoIpv4Async(Echo echo, CancellationToken ct)
    {
        if (IPAddress.TryParse(echo.Host, out var literal)) return literal.AddressFamily == AddressFamily.InterNetwork ? literal : null;
        if (s_v4.TryGetValue(echo.Host, out var c) && c.Until > Environment.TickCount64) return c.Address;
        await V4Gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (s_v4.TryGetValue(echo.Host, out c) && c.Until > Environment.TickCount64) return c.Address;
            using var dns = CancellationTokenSource.CreateLinkedTokenSource(ct);
            dns.CancelAfter(ConnectTimeout);
            IPAddress[] all;
            try { all = await ServiceDns.ResolveAsync(echo.Host, dns.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return null; }
            catch (Exception ex) when (ex is SocketException or IOException) { return null; }
            var a = Array.Find(all, x => x.AddressFamily == AddressFamily.InterNetwork);
            if (a != null) s_v4[echo.Host] = (a, Environment.TickCount64 + 10 * 60_000);
            return a;
        }
        finally { V4Gate.Release(); }
    }

    /// <summary>
    /// Test hook: the IP echo service as a loopback plain-HTTP URL (http://127.0.0.1:port/path) answering in the trace
    /// format ("ip=…\nloc=…"), a JSON object ("ip", "country_code") or a bare address; <paramref name="others"/> stand in
    /// for the other IP services (none: none is asked). Only loopback is accepted. Null restores the real services. Not
    /// bound to any UI or setting.
    /// </summary>
    internal static void SetTestEcho(string? url, params string[] others)
    {
        if (url is null)
        {
            _testEcho = null;
            _testOthers = Array.Empty<Echo>();
            return;
        }
        _testEcho = TestEcho(url, "test");
        _testOthers = others.Select((o, i) => TestEcho(o, "test" + (i + 2))).ToArray();
    }

    private static Echo TestEcho(string url, string name)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttp || !IPAddress.TryParse(u.Host, out var ip)
            || !IPAddress.IsLoopback(ip) || ip.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("The test echo must be an http://127.x.x.x URL.");
        return new Echo(name, u.Host, u.Port, false, u.PathAndQuery);
    }

    private static Echo TunnelEcho => _testEcho ?? RealEcho;
    private static Echo PlainEcho => _testEcho ?? RealPlainEcho;
    private static Echo[] OtherEchoes(Via via) => _testEcho != null ? _testOthers : via == Via.Plain ? RealPlainEchoes : RealTunnelEchoes;

    private enum Verdict { NotThis, Done }

    // How a proxy was found to carry a request: what a request to another IP service through it repeats.
    private enum Via { Socks5, Socks4, Socks4a, Connect, Plain }

    private static Via ViaOf(string proto) => proto switch
    {
        "SOCKS5" => Via.Socks5,
        "SOCKS4" => Via.Socks4,
        "SOCKS4a" => Via.Socks4a,
        "HTTP" => Via.Connect,
        _ => Via.Plain,
    };

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
        /// <summary>The proxy took the request but the IP service's answer didn't come through: the other IP services are
        /// asked through it this way (<see cref="Result"/> stands when none answers either).</summary>
        public Via? TryOthers;
        /// <summary>Why the IP service's answer didn't come, in a few words ("HTTP 403", "timed out").</summary>
        public string Brief = string.Empty;
        public bool AfterTimeout;
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
                        ProxyKind.Socks5 => await Socks5Async(stream, entry, TunnelEcho, deadline.Token).ConfigureAwait(false),
                        ProxyKind.Socks4 or ProxyKind.Socks4a => await Socks4Async(stream, entry, kind, TunnelEcho, deadline.Token).ConfigureAwait(false),
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
                    step = new Step
                    {
                        Verdict = Verdict.Done, Result = new ProxyCheckResult { Status = ProxyCheckStatus.Timeout, Protocol = ex.Protocol, Detail = ex.Message },
                        TryOthers = ViaOf(ex.Protocol), Brief = "timed out", AfterTimeout = true,
                    };
                }
                catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
                {
                    step = NotThis("closed the connection");
                }
            }
            if (step.Verdict == Verdict.Done)
            {
                var r = step.Result!;
                // outside the attempt's deadline: the other IP services have their own
                if (step.TryOthers is { } via) r = await OtherEchoesAsync(via, entry, addrs, step, ct).ConfigureAwait(false);
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

    // ---------------------------------------------------------------- the other IP services

    // Cloudflare's trace didn't come through a proxy that took the request: the other IP services through it, the same
    // way, each on a connection of its own (Fallback: the first answer wins). Their result, or the failed one with why
    // they didn't answer either.
    private static async Task<ProxyCheckResult> OtherEchoesAsync(Via via, ProxyCheckEntry e, IPAddress[] addrs, Step failed, CancellationToken ct)
    {
        var r = failed.Result!;
        var echoes = OtherEchoes(via);
        if (failed.AfterTimeout) echoes = echoes.Take(2).ToArray();
        if (echoes.Length == 0) return r;
        var sources = echoes.Select(echo => new Fallback.Source<ProxyCheckResult>(echo.Name, async t =>
        {
            Step s;
            try { s = await ThroughAsync(via, e, addrs, echo, t).ConfigureAwait(false); }
            catch (StepTimeoutException) { t.ThrowIfCancellationRequested(); throw new TimeoutException(); }
            catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException) { throw new InvalidDataException("the connection dropped"); }
            if (s.Result is { Status: ProxyCheckStatus.Working } ok) return ok;
            throw new InvalidDataException(s.Brief.Length > 0 ? s.Brief : s.Why.Length > 0 ? s.Why : "no answer");
        })).ToList();

        string why;
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(OthersBudget);
        try
        {
            var got = await Fallback.FirstAsync(via == Via.Plain ? "proxy-echo-http" : "proxy-echo", sources, budget.Token,
                                                OthersHeadStart, OthersPerSource, maxConcurrent: 2).ConfigureAwait(false);
            if (got.Value is { } ok)
                return new ProxyCheckResult
                {
                    Status = ok.Status, Protocol = ok.Protocol, FirstByteMs = ok.FirstByteMs, ExitIp = ok.ExitIp, Country = ok.Country,
                    Detail = (via == Via.Plain ? "Relays http:// only (no CONNECT). " : string.Empty)
                             + $"Exit IP from {got.Source}: Cloudflare's trace didn't come through ({(failed.Brief.Length > 0 ? failed.Brief : "failed")}).",
                };
            why = string.Join("; ", got.Errors);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { why = $"no answer within {OthersBudget.TotalSeconds:0} s"; }
        if (r.Status is not (ProxyCheckStatus.Failed or ProxyCheckStatus.Timeout) || why.Length == 0) return r;
        return new ProxyCheckResult
        {
            Status = r.Status, Protocol = r.Protocol, FirstByteMs = r.FirstByteMs, ExitIp = r.ExitIp, Country = r.Country,
            Detail = r.Detail + " Other IP services through it: " + why + ".",
        };
    }

    // One IP service through the proxy as the check found it works: a new connection, the same handshake.
    private static async Task<Step> ThroughAsync(Via via, ProxyCheckEntry e, IPAddress[] addrs, Echo echo, CancellationToken ct)
    {
        var (socket, _, fail) = await ConnectAsync(addrs, e.Port, ct).ConfigureAwait(false);
        if (socket is null) return Done(fail!.Status, string.Empty, fail.Detail, "the proxy didn't take the connection");
        using var stream = new NetworkStream(socket, ownsSocket: true);
        switch (via)
        {
            case Via.Socks5: return await Socks5Async(stream, e, echo, ct).ConfigureAwait(false);
            case Via.Socks4: return await Socks4Async(stream, e, ProxyKind.Socks4, echo, ct).ConfigureAwait(false);
            case Via.Socks4a: return await Socks4Async(stream, e, ProxyKind.Socks4a, echo, ct).ConfigureAwait(false);
            case Via.Plain: return await RequestEchoAsync(stream, "HTTP (no CONNECT)", plainViaHttpProxy: true, e, echo, ct).ConfigureAwait(false);
        }
        var (code, notHttp) = await SendConnectAsync(stream, e, echo, ct).ConfigureAwait(false);
        if (notHttp != null) return notHttp;
        return code is >= 200 and < 300
            ? await RequestEchoAsync(stream, "HTTP", plainViaHttpProxy: false, e, echo, ct).ConfigureAwait(false)
            : Done(ProxyCheckStatus.Failed, "HTTP", $"It refused CONNECT to {echo.Host} (HTTP {code}).", $"CONNECT answered HTTP {code}");
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

    private static async Task<Step> Socks5Async(NetworkStream s, ProxyCheckEntry e, Echo echo, CancellationToken ct)
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
        if (buf[1] != 0)
        {
            var refused = Done(ProxyCheckStatus.Failed, proto, "It couldn't open a connection to the IP service: " + Socks5Reply(buf[1]) + ".", Socks5Reply(buf[1]));
            // it can't reach this one (or may not): another IP service may be reachable; an unsupported command isn't
            if (buf[1] is >= 1 and <= 6) refused.TryOthers = Via.Socks5;
            return refused;
        }
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
        return await RequestEchoAsync(s, proto, plainViaHttpProxy: false, e, echo, ct).ConfigureAwait(false);
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

    private static async Task<Step> Socks4Async(NetworkStream s, ProxyCheckEntry e, ProxyKind kind, Echo echo, CancellationToken ct)
    {
        string proto = kind == ProxyKind.Socks4a ? "SOCKS4a" : "SOCKS4";
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
        else
        {
            var unknown = Done(ProxyCheckStatus.Failed, proto, $"Couldn't look up {echo.Host} for the SOCKS4 test.", "no IPv4 address for its name");
            unknown.TryOthers = ViaOf(proto);
            return unknown;
        }
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
        switch (buf[1])
        {
            case 0x5A: return await RequestEchoAsync(s, proto, plainViaHttpProxy: false, e, echo, ct).ConfigureAwait(false);
            case 0x5B:
                // "rejected or failed": it may not reach this IP service; another may come through
                var rejected = Done(ProxyCheckStatus.Failed, proto, "It rejected the request (91).", "rejected (91)");
                rejected.TryOthers = ViaOf(proto);
                return rejected;
            case 0x5C or 0x5D:
                return Done(e.HasLogin ? ProxyCheckStatus.AuthFailed : ProxyCheckStatus.AuthRequired, proto,
                            "It rejected the user id (identd check failed).");
            default: return NotThis("unexpected answer");
        }
    }

    // ---------------------------------------------------------------- HTTP CONNECT, then plain HTTP

    private static async Task<Step> HttpAsync(NetworkStream s, ProxyCheckEntry e, IPAddress[] addrs, CancellationToken ct)
    {
        var (code, notHttp) = await SendConnectAsync(s, e, TunnelEcho, ct).ConfigureAwait(false);
        if (notHttp != null) return notHttp;
        if (code is >= 200 and < 300) return await RequestEchoAsync(s, "HTTP", plainViaHttpProxy: false, e, TunnelEcho, ct).ConfigureAwait(false);
        if (code == 407)
            return Done(e.HasLogin ? ProxyCheckStatus.AuthFailed : ProxyCheckStatus.AuthRequired, "HTTP",
                        e.HasLogin ? "Wrong username or password (407)." : "It needs a username and password (407).");

        // No CONNECT (or not to this port): a plain-HTTP proxy still forwards "GET http://…" — on a new connection.
        var (socket, _, _) = await ConnectAsync(addrs, e.Port, ct).ConfigureAwait(false);
        Step step;
        if (socket is null) step = Done(ProxyCheckStatus.Failed, "HTTP", $"It refused CONNECT (HTTP {code}) and then the connection.");
        else
        {
            using var plain = new NetworkStream(socket, ownsSocket: true);
            step = await RequestEchoAsync(plain, "HTTP (no CONNECT)", plainViaHttpProxy: true, e, PlainEcho, ct).ConfigureAwait(false);
            if (step.Result is { Status: ProxyCheckStatus.Failed } && step.HttpCode is > 0 and not 200 && !step.Relayed)
            {
                var verdict = code == 403 && step.HttpCode == 403
                    ? Done(ProxyCheckStatus.Failed, "HTTP", "It refuses to relay to the IP service (HTTP 403).")
                    : Done(ProxyCheckStatus.NotProxy, string.Empty,
                           $"A web server, not a proxy: it answers HTTP {code} to CONNECT and HTTP {step.HttpCode} to a proxy request.");
                // its own gateway error: a proxy that couldn't reach the IP service, perhaps; another may come through
                if (step.TryOthers != null) { verdict.TryOthers = Via.Plain; verdict.Brief = step.Brief; }
                step = verdict;
            }
        }
        // A gateway error to CONNECT: it tunnels, but couldn't reach the IP service; other ones through a tunnel, then.
        if (code is 502 or 503 or 504 && step.Result?.Status is ProxyCheckStatus.Failed or ProxyCheckStatus.NotProxy)
        {
            step.TryOthers = Via.Connect;
            step.Brief = $"HTTP {code} to CONNECT";
        }
        return step;
    }

    // CONNECT to the echo: the answer's status code, or a step when it isn't an HTTP proxy's answer.
    private static async Task<(int Code, Step? NotHttp)> SendConnectAsync(NetworkStream s, ProxyCheckEntry e, Echo echo, CancellationToken ct)
    {
        string target = echo.Host + ":" + echo.Port;
        string auth = e.HasLogin ? "Proxy-Authorization: Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(e.User + ":" + e.Pass)) + "\r\n" : string.Empty;
        await s.WriteAsync(Encoding.ASCII.GetBytes(
            $"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: Echoes\r\n{auth}Proxy-Connection: keep-alive\r\n\r\n"), ct).ConfigureAwait(false);
        string? head;
        using (var first = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            first.CancelAfter(FirstAnswerTimeout);
            try { (head, _) = await ReadHeadAsync(s, first.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return (0, NotThis("no answer")); }
        }
        if (head is null) return (0, NotThis("closed the connection"));
        if (!head.StartsWith("HTTP/", StringComparison.Ordinal)) return (0, NotThis("unexpected answer"));
        return (StatusCode(head), null);
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

    private static async Task<Step> RequestEchoAsync(Stream tunnel, string proto, bool plainViaHttpProxy, ProxyCheckEntry e, Echo echo, CancellationToken ct)
    {
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
                    return Done(ProxyCheckStatus.Failed, proto, "HTTPS through it failed the certificate check: it may intercept encrypted traffic.", "certificate check failed");
                }
                catch (Exception ex) when (ex is IOException or SocketException)
                {
                    return NoEcho(Done(ProxyCheckStatus.Failed, proto, "It dropped the HTTPS connection to the IP service.", "HTTPS dropped"), proto);
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
            if (got == 0)
            {
                var closed = Done(ProxyCheckStatus.Failed, proto, "It closed the connection without an answer.", "no answer");
                return plainViaHttpProxy ? closed : NoEcho(closed, proto);
            }
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
            if (bodyAt >= 0 && IsChunked(text[..bodyAt])) body = Dechunk(body);
            var (ip, country) = ReadEcho(body);
            if (code != 200 || !IPAddress.TryParse(ip, out var exit))
            {
                var failed = Done(ProxyCheckStatus.Failed, proto, code == 0
                    ? "Its answer wasn't HTTP: it may not relay this kind of traffic."
                    : $"The answer through it was HTTP {code}, not the IP service's page.",
                    code == 0 ? "not HTTP" : code == 200 ? "no address in the answer" : $"HTTP {code}");
                failed.HttpCode = code;
                failed.Relayed = bodyAt > 0 && text.AsSpan(0, bodyAt).Contains("\r\ncf-ray:", StringComparison.OrdinalIgnoreCase);
                // Through a tunnel the proxy did its part. A plain-HTTP proxy did when the IP service answered (relayed),
                // or when it answers with a gateway error of its own (it tried); otherwise it may be no proxy at all.
                if (!plainViaHttpProxy || failed.Relayed || code is 502 or 503 or 504) failed.TryOthers = ViaOf(proto);
                return failed;
            }
            return new Step
            {
                Verdict = Verdict.Done,
                Result = new ProxyCheckResult
                {
                    Status = ProxyCheckStatus.Working,
                    Protocol = proto,
                    FirstByteMs = firstByte,
                    ExitIp = exit.ToString(),
                    Country = country,
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

    // The proxy carried the request, but the IP service's answer didn't come: another IP service may come through.
    private static Step NoEcho(Step failed, string proto)
    {
        failed.TryOthers = ViaOf(proto);
        return failed;
    }

    // The exit IP and its country in an IP service's answer: Cloudflare's trace ("ip=", "loc="), a JSON object ("ip" or
    // "query", and a two-letter "country_code" / "country_iso" / "countryCode" / "country"), or a bare address. The answer
    // is someone else's: only an address and two letters are taken from it.
    private static (string Ip, string Country) ReadEcho(string body)
    {
        string ip = DdnsIpDetector.TraceValue(body, "ip");
        if (ip.Length > 0) return (ip, CountryCode(DdnsIpDetector.TraceValue(body, "loc")));
        int a = body.IndexOf('{'), b = body.LastIndexOf('}');
        if (a < 0 || b < a) return (body.Trim(), string.Empty);
        try
        {
            using var doc = JsonDocument.Parse(body.AsMemory(a, b - a + 1));
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return (string.Empty, string.Empty);
            string Str(string name) => root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? string.Empty : string.Empty;
            string cc = string.Empty;
            foreach (string field in new[] { "country_code", "country_iso", "countryCode", "country" })
                if ((cc = CountryCode(Str(field))).Length > 0) break;
            string found = Str("ip");
            return (found.Length > 0 ? found : Str("query"), cc);
        }
        catch (JsonException) { return (string.Empty, string.Empty); }
    }

    private static string CountryCode(string s)
    {
        s = s.Trim().ToUpperInvariant();
        return s.Length == 2 && char.IsAsciiLetter(s[0]) && char.IsAsciiLetter(s[1]) && s != "XX" && s != "T1" ? s : string.Empty;
    }

    private static bool IsChunked(string head)
    {
        int at = head.IndexOf("\r\nTransfer-Encoding:", StringComparison.OrdinalIgnoreCase);
        if (at < 0) return false;
        int stop = head.IndexOf("\r\n", at + 2, StringComparison.Ordinal);
        return (stop < 0 ? head[at..] : head[at..stop]).Contains("chunked", StringComparison.OrdinalIgnoreCase);
    }

    // A chunked body (RFC 9112 7.1) in one piece; what doesn't read as chunks ends it.
    private static string Dechunk(string body)
    {
        var sb = new StringBuilder(body.Length);
        int pos = 0;
        while (pos < body.Length)
        {
            int eol = body.IndexOf("\r\n", pos, StringComparison.Ordinal);
            if (eol < 0) break;
            string size = body[pos..eol];
            int semi = size.IndexOf(';');
            if (semi >= 0) size = size[..semi];
            if (!int.TryParse(size.Trim(), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out int len) || len <= 0) break;
            int start = eol + 2;
            if ((long)start + len > body.Length)
            {
                sb.Append(body, start, body.Length - start);
                break;
            }
            sb.Append(body, start, len);
            pos = start + len + 2;
        }
        return sb.ToString();
    }

    // The head is in and the body is complete: all of its Content-Length, or a chunked body's last chunk (the answers are
    // small) — no need to wait for the close.
    private static bool LooksComplete(byte[] buf, int got)
    {
        int end = IndexOfBlankLine(buf, 0, got);
        if (end < 0) return false;
        string head = Encoding.Latin1.GetString(buf, 0, end);
        if (IsChunked(head))
            return got - (end + 4) >= 5 && buf.AsSpan(got - 5, 5).SequenceEqual("0\r\n\r\n"u8) && (got - (end + 4) == 5 || buf[got - 7] == '\r');
        int at = head.IndexOf("\r\nContent-Length:", StringComparison.OrdinalIgnoreCase);
        if (at < 0) return false;
        int start = at + "\r\nContent-Length:".Length;
        int stop = head.IndexOf("\r\n", start, StringComparison.Ordinal);
        string value = (stop < 0 ? head[start..] : head[start..stop]).Trim();
        return int.TryParse(value, out int len) && got - (end + 4) >= len;
    }

    private static Step Done(ProxyCheckStatus status, string proto, string detail, string brief = "")
        => new() { Verdict = Verdict.Done, Result = new ProxyCheckResult { Status = status, Protocol = proto, Detail = detail }, Brief = brief };
}
