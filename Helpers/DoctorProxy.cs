using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

public enum DoctorProxyKind { Http, Https, Socks4, Socks5 }

/// <summary>Where getting through a proxy stopped.</summary>
public enum DoctorProxyStage
{
    /// <summary>The proxy itself: its name, or a TCP connection to it.</summary>
    Reach,
    /// <summary>The TLS connection to an https:// proxy.</summary>
    Tls,
    /// <summary>It doesn't speak the protocol (an HTTP proxy addressed as SOCKS, or not a proxy at all).</summary>
    Protocol,
    /// <summary>It wants a login, or refused the one given.</summary>
    Login,
    /// <summary>The proxy works, but couldn't (or wouldn't) reach the target.</summary>
    Tunnel,
}

/// <summary>A proxy failure in one sentence (never with the password in it).</summary>
public sealed class DoctorProxyException : Exception
{
    public DoctorProxyException(DoctorProxyStage stage, string message, Exception? inner = null) : base(message, inner) => Stage = stage;
    public DoctorProxyStage Stage { get; }
}

/// <summary>
/// The proxy the Doctor tests through: HTTP (CONNECT), HTTPS (TLS to the proxy, then CONNECT), SOCKS4 / 4a and SOCKS5,
/// with an optional login (HTTP Basic, SOCKS5 RFC 1929, the SOCKS4 user id). Its own small client rather than the
/// HttpClient proxy support, so every stage — reaching it, its TLS, the protocol, the login, the tunnel — can be told
/// apart. Names are sent to the proxy unresolved (CONNECT, SOCKS4a, SOCKS5 domain names): the proxy does the DNS, as
/// browsers' proxies do. An address without a scheme is detected on first contact (SOCKS5 or HTTP).
/// </summary>
public sealed class DoctorProxy
{
    private readonly string? _user;
    private readonly string? _pass;
    private volatile bool _detected;

    private DoctorProxy(DoctorProxyKind kind, bool guessed, string host, int port, string? user, string? pass)
    {
        Kind = kind;
        Guessed = guessed;
        Host = host;
        Port = port;
        _user = string.IsNullOrEmpty(user) ? null : user;
        _pass = pass ?? "";
        _detected = !guessed;
    }

    public DoctorProxyKind Kind { get; private set; }
    /// <summary>No scheme was written: the protocol was (or will be) detected.</summary>
    public bool Guessed { get; }
    public string Host { get; }
    public int Port { get; }
    public bool HasLogin => _user != null;
    /// <summary>The login for .NET's own HTTP proxy client (the forward requests through an http:// proxy).</summary>
    internal NetworkCredential? Credentials => _user == null ? null : new NetworkCredential(_user, _pass ?? "");
    /// <summary>Trust exactly these roots for an https:// proxy's certificate (tests).</summary>
    internal X509Certificate2Collection? TrustRoots { get; set; }

    public string Scheme => Kind switch
    {
        DoctorProxyKind.Https => "https",
        DoctorProxyKind.Socks4 => "socks4",
        DoctorProxyKind.Socks5 => "socks5",
        _ => "http",
    };

    public string KindName => Kind switch
    {
        DoctorProxyKind.Https => "HTTPS proxy",
        DoctorProxyKind.Socks4 => "SOCKS4",
        DoctorProxyKind.Socks5 => "SOCKS5",
        _ => "HTTP proxy",
    };

    /// <summary>"socks5://127.0.0.1:1080" — never with the login.</summary>
    public string Display => (Guessed ? "" : Scheme + "://") + (Host.Contains(':') ? $"[{Host}]" : Host) + ":" + Port;

    /// <summary>The address as typed (credentials there move to the user / password; the fields win when both are set).</summary>
    public static bool TryParse(string? address, string? user, string? pass, out DoctorProxy? proxy, out string error)
    {
        proxy = null;
        error = "";
        string a = (address ?? "").Trim();
        if (a.Length == 0) { error = "Enter the proxy's address, e.g. socks5://127.0.0.1:1080."; return false; }
        if (a.Length > 512) { error = "That proxy address is too long."; return false; }
        if (CheckHostProxy.Parse(a) is { } info)
        {
            a = info.Clean;
            if (string.IsNullOrEmpty(user) && info.User.Length > 0) { user = info.User; pass = info.Pass; }
        }
        bool typedScheme = a.Contains("://", StringComparison.Ordinal);
        if (!HttpHelper.TryParseProxy(a, out var uri) || uri.Host.Length == 0)
        {
            error = $"\"{HttpHelper.WithoutUserInfo(a)}\" isn't a proxy address — use host:port or socks5://host:port.";
            return false;
        }
        DoctorProxyKind? kind = uri.Scheme.ToLowerInvariant() switch
        {
            "http" => DoctorProxyKind.Http,
            "https" => DoctorProxyKind.Https,
            "socks4" or "socks4a" => DoctorProxyKind.Socks4,
            "socks5" or "socks5h" or "socks" => DoctorProxyKind.Socks5,
            _ => null,
        };
        if (kind == null) { error = $"Unknown proxy type \"{uri.Scheme}\" — use http://, https://, socks4:// or socks5://."; return false; }
        if (uri.Port is <= 0 or > 65535) { error = "The proxy address needs a port, e.g. 127.0.0.1:1080."; return false; }
        if ((!string.IsNullOrEmpty(user) && Encoding.UTF8.GetByteCount(user) > 255) || Encoding.UTF8.GetByteCount(pass ?? "") > 255)
        {
            error = "The proxy user name or password is too long.";
            return false;
        }
        string host = uri.HostNameType == UriHostNameType.IPv6 ? uri.Host.Trim('[', ']') : uri.IdnHost;
        proxy = new DoctorProxy(kind.Value, !typedScheme, host, uri.Port, user, pass);
        return true;
    }

    // ------------------------------------------------------------------ the tunnel

    /// <summary>An open tunnel through the proxy, and how long its stages took.</summary>
    public sealed class Tunnel : IDisposable
    {
        internal Tunnel(Stream stream, double reachMs, double totalMs, bool loginUsed)
        {
            Stream = stream;
            ReachMs = reachMs;
            TotalMs = totalMs;
            LoginUsed = loginUsed;
        }

        public Stream Stream { get; }
        /// <summary>The TCP connection to the proxy itself.</summary>
        public double ReachMs { get; }
        /// <summary>Everything up to the open tunnel.</summary>
        public double TotalMs { get; }
        /// <summary>The proxy asked for the login and accepted it.</summary>
        public bool LoginUsed { get; }
        public void Dispose() => Stream.Dispose();
    }

    /// <summary>Opens a tunnel through the proxy. Throws <see cref="DoctorProxyException"/> saying which stage failed.</summary>
    public async Task<Tunnel> OpenAsync(string host, int port, int timeoutMs, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        var sw = Stopwatch.StartNew();
        // Set once the proxy itself has been reached (TCP, plus TLS for an HTTPS proxy): a timeout before that is the
        // proxy not answering, not a tunnel it couldn't open (a firewall that drops packets outlasts any deadline).
        var reached = new System.Runtime.CompilerServices.StrongBox<bool>();
        try
        {
            try { return await OpenOnceAsync(host, port, sw, reached, cts.Token).ConfigureAwait(false); }
            catch (DoctorProxyException e) when (!_detected && e.Stage == DoctorProxyStage.Protocol && Kind is DoctorProxyKind.Http or DoctorProxyKind.Socks5)
            {
                // a scheme-less address guessed wrong: the other common protocol, on a fresh connection
                var first = Kind;
                Kind = first == DoctorProxyKind.Http ? DoctorProxyKind.Socks5 : DoctorProxyKind.Http;
                try { return await OpenOnceAsync(host, port, sw, reached, cts.Token).ConfigureAwait(false); }
                catch (DoctorProxyException e2) when (e2.Stage == DoctorProxyStage.Protocol)
                {
                    Kind = first;
                    throw new DoctorProxyException(DoctorProxyStage.Protocol, $"it speaks neither HTTP nor SOCKS5 ({e.Message})", e);
                }
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw reached.Value
                ? new DoctorProxyException(DoctorProxyStage.Tunnel, $"the proxy didn't open the tunnel to {Target(host, port)} within {timeoutMs / 1000} s")
                : new DoctorProxyException(DoctorProxyStage.Reach, $"the proxy {Display} doesn't answer (nothing within {timeoutMs / 1000} s)");
        }
        catch (DoctorProxyException) { throw; }
        catch (OperationCanceledException) { throw; }
        catch (Exception e)
        {
            throw new DoctorProxyException(DoctorProxyStage.Protocol, "the proxy broke off the handshake (" + DoctorDns.Short(e) + ")", e);
        }
    }

    private async Task<Tunnel> OpenOnceAsync(string host, int port, Stopwatch sw, System.Runtime.CompilerServices.StrongBox<bool> reached,
                                             CancellationToken ct)
    {
        var (stream, reachMs) = await ReachAsync(ct).ConfigureAwait(false);
        reached.Value = true;
        try
        {
            bool login = Kind switch
            {
                DoctorProxyKind.Socks5 => await Socks5Async(stream, host, port, ct).ConfigureAwait(false),
                DoctorProxyKind.Socks4 => await Socks4Async(stream, host, port, ct).ConfigureAwait(false),
                _ => await ConnectVerbAsync(stream, host, port, ct).ConfigureAwait(false),
            };
            _detected = true;
            return new Tunnel(stream, reachMs, sw.Elapsed.TotalMilliseconds, login);
        }
        catch (DoctorProxyException e) when (e.Stage is DoctorProxyStage.Login or DoctorProxyStage.Tunnel)
        {
            _detected = true;   // it spoke the protocol: the guess was right
            stream.Dispose();
            throw;
        }
        catch (Exception e) when (e is not (DoctorProxyException or OperationCanceledException))
        {
            // reset / closed mid-handshake: the protocol didn't fit (a SOCKS-only proxy hangs up on CONNECT)
            stream.Dispose();
            throw new DoctorProxyException(DoctorProxyStage.Protocol, "the proxy broke off the handshake (" + DoctorDns.Short(e) + ")", e);
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    private async Task<(Stream Stream, double Ms)> ReachAsync(CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        IPAddress[] addrs;
        if (IPAddress.TryParse(Host, out var lit)) addrs = new[] { lit };
        else
        {
            try { addrs = await Dns.GetHostAddressesAsync(Host, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { throw; }
            catch (Exception e) { throw new DoctorProxyException(DoctorProxyStage.Reach, $"the proxy's name {Host} doesn't resolve", e); }
            if (addrs.Length == 0) throw new DoctorProxyException(DoctorProxyStage.Reach, $"the proxy's name {Host} doesn't resolve");
        }
        Exception? last = null;
        foreach (var a in DoctorIp.Ordered(addrs))
        {
            var sock = new Socket(a.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await sock.ConnectAsync(new IPEndPoint(a, Port), ct).ConfigureAwait(false);
                double ms = sw.Elapsed.TotalMilliseconds;
                Stream s = new NetworkStream(sock, ownsSocket: true);
                if (Kind == DoctorProxyKind.Https) s = await ProxyTlsAsync(s, ct).ConfigureAwait(false);
                return (s, ms);
            }
            catch (OperationCanceledException) { sock.Dispose(); throw; }
            catch (DoctorProxyException) { sock.Dispose(); throw; }
            catch (Exception e) { sock.Dispose(); last = e; }
        }
        throw new DoctorProxyException(DoctorProxyStage.Reach, $"the proxy {Display} doesn't answer ({DoctorDns.Short(last!)})", last);
    }

    private async Task<Stream> ProxyTlsAsync(Stream s, CancellationToken ct)
    {
        var ssl = new SslStream(s, false);
        try
        {
            var o = new SslClientAuthenticationOptions
            {
                TargetHost = Host,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                ApplicationProtocols = new() { SslApplicationProtocol.Http11 },
            };
            if (TrustRoots is { Count: > 0 } roots)
            {
                var p = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust, RevocationMode = X509RevocationMode.NoCheck };
                p.CustomTrustStore.AddRange(roots);
                o.CertificateChainPolicy = p;
            }
            await ssl.AuthenticateAsClientAsync(o, ct).ConfigureAwait(false);
            return ssl;
        }
        catch (OperationCanceledException) { ssl.Dispose(); throw; }
        catch (Exception e)
        {
            ssl.Dispose();
            throw new DoctorProxyException(DoctorProxyStage.Tls, e is AuthenticationException
                ? "the TLS connection to the proxy failed (its certificate isn't trusted, or it doesn't speak TLS — try http://)"
                : $"the TLS connection to the proxy failed ({DoctorDns.Short(e)})", e);
        }
    }

    // ---- HTTP CONNECT (http:// and https:// proxies)

    private async Task<bool> ConnectVerbAsync(Stream s, string host, int port, CancellationToken ct)
    {
        string target = Target(host, port);
        var sb = new StringBuilder().Append("CONNECT ").Append(target).Append(" HTTP/1.1\r\nHost: ").Append(target).Append("\r\n");
        if (HasLogin)
            sb.Append("Proxy-Authorization: Basic ").Append(Convert.ToBase64String(Encoding.UTF8.GetBytes(_user + ":" + _pass))).Append("\r\n");
        sb.Append("User-Agent: Echoes-Doctor\r\n\r\n");
        await s.WriteAsync(Encoding.ASCII.GetBytes(sb.ToString()), ct).ConfigureAwait(false);
        await s.FlushAsync(ct).ConfigureAwait(false);

        // the reply's head (capped); any bytes after it already belong to the tunnel
        var buf = new byte[16 * 1024];
        int len = 0, end = -1;
        while (end < 0)
        {
            if (len == buf.Length) throw new DoctorProxyException(DoctorProxyStage.Protocol, "the proxy's answer to CONNECT is too large");
            int n = await s.ReadAsync(buf.AsMemory(len), ct).ConfigureAwait(false);
            if (n == 0)
                throw new DoctorProxyException(len == 0 ? DoctorProxyStage.Protocol : DoctorProxyStage.Tunnel,
                    len == 0 ? "the proxy closed the connection instead of answering CONNECT (not an HTTP proxy? try socks5://)"
                             : "the proxy closed the connection mid-answer");
            len += n;
            end = buf.AsSpan(0, len).IndexOf("\r\n\r\n"u8);
        }
        string head = Encoding.Latin1.GetString(buf, 0, end);
        string status = head.Split("\r\n")[0];
        if (!status.StartsWith("HTTP/", StringComparison.Ordinal))
            throw new DoctorProxyException(DoctorProxyStage.Protocol, $"it doesn't speak HTTP (it answered \"{RemoteText.Clean(status, 40)}\") — try socks5://");
        var parts = status.Split(' ', 3);
        int code = parts.Length >= 2 && int.TryParse(parts[1], out int c) ? c : 0;
        string reason = parts.Length >= 3 ? RemoteText.Clean(parts[2], 40) : "";
        if (code == 407)
            throw new DoctorProxyException(DoctorProxyStage.Login, HasLogin
                ? "the proxy refused the login (HTTP 407) — check the user name and password"
                : "the proxy wants a login (HTTP 407) — enter its user name and password");
        if (code is < 200 or > 299)
            throw new DoctorProxyException(DoctorProxyStage.Tunnel, code is 502 or 504
                ? $"the proxy couldn't reach {target} (HTTP {code} {reason})".TrimEnd()
                : $"the proxy refused the tunnel to {target} (HTTP {code} {reason})".Replace(" )", ")"));
        int extra = len - (end + 4);
        if (extra > 0) throw new DoctorProxyException(DoctorProxyStage.Protocol, "the proxy sent data before the tunnel was used");
        return HasLogin;
    }

    // ---- SOCKS5 (RFC 1928 / 1929)

    private async Task<bool> Socks5Async(Stream s, string host, int port, CancellationToken ct)
    {
        await s.WriteAsync(HasLogin ? new byte[] { 5, 2, 0, 2 } : new byte[] { 5, 1, 0 }, ct).ConfigureAwait(false);
        var b = new byte[2];
        await ReadExactAsync(s, b, "the proxy closed the connection instead of answering SOCKS5 (an HTTP proxy? try http://)", ct).ConfigureAwait(false);
        if (b[0] != 5)
            throw new DoctorProxyException(DoctorProxyStage.Protocol, b[0] == (byte)'H'
                ? "it's an HTTP proxy, not SOCKS5 — use http://"
                : "it doesn't speak SOCKS5");
        bool loginUsed = false;
        switch (b[1])
        {
            case 0: break;
            case 2 when HasLogin:
                byte[] u = Encoding.UTF8.GetBytes(_user!), p = Encoding.UTF8.GetBytes(_pass ?? "");
                var auth = new byte[3 + u.Length + p.Length];
                auth[0] = 1;
                auth[1] = (byte)u.Length;
                u.CopyTo(auth, 2);
                auth[2 + u.Length] = (byte)p.Length;
                p.CopyTo(auth, 3 + u.Length);
                await s.WriteAsync(auth, ct).ConfigureAwait(false);
                await ReadExactAsync(s, b, "the proxy closed the connection during the login", ct).ConfigureAwait(false);
                if (b[1] != 0) throw new DoctorProxyException(DoctorProxyStage.Login, "the proxy refused the login — check the user name and password");
                loginUsed = true;
                break;
            case 2:
                throw new DoctorProxyException(DoctorProxyStage.Login, "the proxy wants a login — enter its user name and password");
            case 0xFF:
                throw new DoctorProxyException(DoctorProxyStage.Login, HasLogin
                    ? "the proxy accepts none of the login methods offered"
                    : "the proxy wants a login — enter its user name and password");
            default:
                throw new DoctorProxyException(DoctorProxyStage.Protocol, $"the proxy asks for a login method this client doesn't support ({b[1]})");
        }

        // CONNECT host:port — a name goes as a name (the proxy resolves it)
        byte[] req;
        if (IPAddress.TryParse(host.Trim('[', ']'), out var ip))
        {
            byte[] a = ip.GetAddressBytes();
            req = new byte[6 + a.Length];
            req[3] = ip.AddressFamily == AddressFamily.InterNetworkV6 ? (byte)4 : (byte)1;
            a.CopyTo(req, 4);
        }
        else
        {
            byte[] name = Encoding.ASCII.GetBytes(host);
            if (name.Length > 255) throw new DoctorProxyException(DoctorProxyStage.Tunnel, "the name is too long for SOCKS5");
            req = new byte[7 + name.Length];
            req[3] = 3;
            req[4] = (byte)name.Length;
            name.CopyTo(req, 5);
        }
        req[0] = 5;
        req[1] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(req.AsSpan(req.Length - 2), (ushort)port);
        await s.WriteAsync(req, ct).ConfigureAwait(false);

        var head = new byte[4];
        await ReadExactAsync(s, head, "the proxy closed the connection instead of opening the tunnel", ct).ConfigureAwait(false);
        if (head[1] != 0)
            throw new DoctorProxyException(DoctorProxyStage.Tunnel, head[1] switch
            {
                2 => $"the proxy's rules don't allow {Target(host, port)}",
                3 => $"the proxy has no route to {Target(host, port)} (network unreachable)",
                4 => $"the proxy couldn't reach {Target(host, port)} (host unreachable, or the name doesn't resolve there)",
                5 => $"{Target(host, port)} refused the proxy's connection",
                6 => $"the proxy's connection to {Target(host, port)} timed out",
                7 => "the proxy doesn't support CONNECT",
                8 => "the proxy doesn't support this address type",
                _ => $"the proxy couldn't open the tunnel to {Target(host, port)} (SOCKS5 error {head[1]})",
            });
        int rest = head[3] switch { 1 => 4, 4 => 16, 3 => -1, _ => 0 };
        if (rest == -1)
        {
            var l = new byte[1];
            await ReadExactAsync(s, l, "the proxy's SOCKS5 reply was cut short", ct).ConfigureAwait(false);
            rest = l[0];
        }
        await ReadExactAsync(s, new byte[rest + 2], "the proxy's SOCKS5 reply was cut short", ct).ConfigureAwait(false);
        return loginUsed;
    }

    // ---- SOCKS4 / 4a (a name as 4a; IPv4 only)

    private async Task<bool> Socks4Async(Stream s, string host, int port, CancellationToken ct)
    {
        byte[] user = Encoding.UTF8.GetBytes(_user ?? "");
        bool isIp = IPAddress.TryParse(host.Trim('[', ']'), out var ip);
        if (isIp && ip!.AddressFamily != AddressFamily.InterNetwork)
            throw new DoctorProxyException(DoctorProxyStage.Tunnel, "SOCKS4 can't carry an IPv6 address — use socks5://");
        byte[] name = isIp ? Array.Empty<byte>() : Encoding.ASCII.GetBytes(host);
        var req = new byte[9 + user.Length + (isIp ? 0 : name.Length + 1)];
        req[0] = 4;
        req[1] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(req.AsSpan(2), (ushort)port);
        if (isIp) ip!.GetAddressBytes().CopyTo(req, 4);
        else req[7] = 1;   // 0.0.0.1: the name follows (SOCKS4a)
        user.CopyTo(req, 8);
        if (!isIp) name.CopyTo(req, 9 + user.Length);
        await s.WriteAsync(req, ct).ConfigureAwait(false);
        var r = new byte[8];
        await ReadExactAsync(s, r, "the proxy closed the connection instead of answering SOCKS4", ct).ConfigureAwait(false);
        if (r[0] != 0) throw new DoctorProxyException(DoctorProxyStage.Protocol, "it doesn't speak SOCKS4");
        if (r[1] == 0x5A) return HasLogin;
        throw new DoctorProxyException(r[1] is 0x5C or 0x5D ? DoctorProxyStage.Login : DoctorProxyStage.Tunnel, r[1] switch
        {
            0x5C or 0x5D => "the proxy refused the user id (identd check)",
            _ => $"the proxy refused or couldn't open the tunnel to {Target(host, port)}",
        });
    }

    // ------------------------------------------------------------------ bits

    private static string Target(string host, int port) => host.Contains(':') && !host.StartsWith('[') ? $"[{host}]:{port}" : $"{host}:{port}";

    private static async Task ReadExactAsync(Stream s, byte[] buf, string closed, CancellationToken ct)
    {
        int got = 0;
        while (got < buf.Length)
        {
            int n;
            try { n = await s.ReadAsync(buf.AsMemory(got), ct).ConfigureAwait(false); }
            catch (IOException e) { throw new DoctorProxyException(DoctorProxyStage.Protocol, closed, e); }
            if (n == 0) throw new DoctorProxyException(got == 0 ? DoctorProxyStage.Protocol : DoctorProxyStage.Tunnel, closed);
            got += n;
        }
    }

    /// <summary>The innermost <see cref="DoctorProxyException"/> behind <paramref name="e"/>, if any.</summary>
    public static DoctorProxyException? Find(Exception? e)
    {
        for (var x = e; x != null; x = x.InnerException)
            if (x is DoctorProxyException p) return p;
        return null;
    }
}
