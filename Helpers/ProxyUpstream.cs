using System;
using System.Collections.Generic;
using System.Globalization;
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

/// <summary>How the upstream proxy is spoken to.</summary>
public enum ProxyUpstreamKind
{
    /// <summary>SOCKS5 (RFC 1928), with a username and password when given (RFC 1929).</summary>
    Socks5,
    /// <summary>SOCKS4a: no password, IPv4 addresses and names only.</summary>
    Socks4a,
    /// <summary>An HTTP proxy asked for a tunnel (CONNECT), with Basic credentials when given. Over TLS for an https://
    /// address (<see cref="ProxyUpstream.Tls"/>).</summary>
    Http,
}

/// <summary>
/// The upstream proxy did not open the connection: it can't be reached, refused the login, or said no to the target.
/// <see cref="Status"/> is the connection log's short text, <see cref="Detail"/> the sentence in the row's tooltip, and
/// <see cref="SocksReply"/> the SOCKS5 reply code a SOCKS5 client is given (the upstream's own where it sent one).
/// </summary>
internal sealed class ProxyUpstreamException : Exception
{
    public ProxyUpstreamException(string status, string detail, byte socksReply = 0x01, Exception? inner = null) : base(detail, inner)
    {
        Status = status;
        Detail = detail;
        SocksReply = socksReply;
    }

    public string Status { get; }
    public string Detail { get; }
    public byte SocksReply { get; }

    /// <summary>The upstream itself is the problem (unreachable, wrong login): another address of the target would
    /// fare no better.</summary>
    public bool Fatal { get; init; }
}

/// <summary>
/// The proxy that <see cref="ProxyServer"/> sends its connections on to, instead of connecting to the targets itself
/// (a parent proxy: another program's local proxy shared with the network, a company's proxy, a server elsewhere).
/// After the handshake here the socket is a plain tunnel to the target, so everything after it (relaying, limits, the
/// idle time-out) is the same as for a direct connection.
/// <para>Only what leaves a raw tunnel behind is taken: SOCKS5, SOCKS4a and HTTP CONNECT, the last also over TLS (an
/// https:// proxy: <see cref="SecureAsync"/>, its certificate checked as a browser checks a site's). A SOCKS5 upstream
/// also carries UDP: its own relay, asked for with <see cref="OpenUdpAsync"/>.</para>
/// </summary>
public sealed class ProxyUpstream
{
    private readonly byte[] _user, _pass;   // UTF-8; the password in a pinned buffer (SecureMemory)

    private ProxyUpstream(ProxyUpstreamKind kind, bool tls, string host, int port, string user, string pass, bool resolvesNames)
    {
        Kind = kind;
        Tls = tls;
        Host = host;
        Port = port;
        ResolvesNames = resolvesNames;
        _user = Encoding.UTF8.GetBytes(user);
        _pass = SecureMemory.Utf8(pass);
    }

    public ProxyUpstreamKind Kind { get; }
    /// <summary>An https:// proxy: an HTTP proxy reached over TLS, so the requests to it (and its login) can't be read
    /// or changed on the way.</summary>
    public bool Tls { get; }
    /// <summary>A name or an address (IPv6 without brackets).</summary>
    public string Host { get; }
    public int Port { get; }
    public bool HasLogin => _user.Length > 0 || _pass.Length > 0;

    /// <summary>Names are handed to the upstream as names (it looks them up) rather than looked up on this device.
    /// <see cref="ProxyServer"/> still looks a name up itself where it must know where it leads.</summary>
    public bool ResolvesNames { get; }

    /// <summary>"socks5://127.0.0.1:10808": for the status line and messages. Never the login.</summary>
    public string Display
        => $"{Kind switch { ProxyUpstreamKind.Socks5 => "socks5", ProxyUpstreamKind.Socks4a => "socks4a", _ => Tls ? "https" : "http" }}://{(Host.Contains(':') ? $"[{Host}]" : Host)}:{Port}";

    /// <summary>"SOCKS5", "SOCKS4a", "HTTP", "HTTPS": the kind in words.</summary>
    public string KindName => Kind switch { ProxyUpstreamKind.Socks5 => "SOCKS5", ProxyUpstreamKind.Socks4a => "SOCKS4a", _ => Tls ? "HTTPS" : "HTTP" };

    /// <summary>Tests only: decides on an https:// upstream's certificate in place of the system's check (a test
    /// certificate is self-signed). Given the certificate and what the system found wrong with it.</summary>
    internal Func<X509Certificate?, SslPolicyErrors, bool>? CertificateCheck { get; set; }

    /// <summary>
    /// Reads the address as the other tools' proxy boxes do (<see cref="HttpHelper.NormalizeProxy"/>: "host:port",
    /// SOCKS5 on the usual SOCKS ports, or with its scheme: socks5://, socks4a://, http://, https://). A login written
    /// into the address ("user:pass@host:port") is used when the two fields are empty. Null with
    /// <paramref name="problem"/> saying what is wrong.
    /// </summary>
    public static ProxyUpstream? Parse(string? address, string? user, string? pass, bool resolvesNames, out string? problem)
    {
        problem = null;
        if (string.IsNullOrWhiteSpace(address)) { problem = "Enter the upstream proxy's address (host:port)."; return null; }
        string shown = HttpHelper.WithoutUserInfo(address);
        if (!HttpHelper.TryParseProxy(address, out var uri)) { problem = $"\"{Cut(shown)}\" isn't a proxy address: write host:port, or socks5://host:port."; return null; }

        ProxyUpstreamKind kind;
        bool tls = false;
        switch (uri.Scheme.ToLowerInvariant())
        {
            case "socks5" or "socks5h" or "socks": kind = ProxyUpstreamKind.Socks5; break;
            case "socks4" or "socks4a": kind = ProxyUpstreamKind.Socks4a; break;
            case "http": kind = ProxyUpstreamKind.Http; break;
            case "https": kind = ProxyUpstreamKind.Http; tls = true; break;
            default:
                problem = $"\"{Cut(uri.Scheme)}://\" isn't a kind of proxy Echoes can forward through: use socks5://, socks4a://, http:// or https://.";
                return null;
        }
        // (no default port: "host" alone is far more often a slip than a proxy on port 80)
        if (uri.Port is < 1 or > 65535 || (uri.IsDefaultPort && !shown.TrimEnd('/').EndsWith(":" + uri.Port, StringComparison.Ordinal)))
        {
            problem = "Add the upstream proxy's port: host:port.";
            return null;
        }
        string host = uri.Host.Trim('[', ']');
        if (host.Length == 0) { problem = "Enter the upstream proxy's address (host:port)."; return null; }

        string u = user ?? string.Empty, p = pass ?? string.Empty;
        if (u.Length == 0 && p.Length == 0 && uri.UserInfo.Length > 0)
        {
            int colon = uri.UserInfo.IndexOf(':');
            u = Uri.UnescapeDataString(colon >= 0 ? uri.UserInfo[..colon] : uri.UserInfo);
            p = colon >= 0 ? Uri.UnescapeDataString(uri.UserInfo[(colon + 1)..]) : string.Empty;
        }
        if (Encoding.UTF8.GetByteCount(u) > 255 || Encoding.UTF8.GetByteCount(p) > 255)
        {
            problem = "The upstream proxy's user name or password is too long (255 bytes at most).";
            return null;
        }
        if (kind == ProxyUpstreamKind.Socks4a && p.Length > 0)
        {
            problem = "SOCKS4 has no password login: use the upstream proxy's socks5:// or http:// address, or leave the password empty.";
            return null;
        }
        return new ProxyUpstream(kind, tls, host, uri.Port, u, p, resolvesNames);
    }

    private static string Cut(string s) => s.Length <= 60 ? s : s[..60] + "…";

    /// <summary>
    /// An address typed with its login ("user:pass@host:port", with or without a scheme): the address without it, and
    /// the user name and password (percent escapes decoded where there is a scheme: that is URL syntax). Null when there
    /// is no login, or what follows it doesn't end in a port yet (still being typed). The LAST '@' before a path ends
    /// the login, so a password holding an '@' moves whole.
    /// </summary>
    public static (string Address, string User, string Pass)? SplitLogin(string? address)
    {
        string a = (address ?? string.Empty).Trim();
        int scheme = a.IndexOf("://", StringComparison.Ordinal);
        int start = scheme >= 0 ? scheme + 3 : 0;
        int end = a.IndexOfAny(new[] { '/', '?', '#' }, start);
        if (end < 0) end = a.Length;
        int at = end > start ? a.LastIndexOf('@', end - 1, end - start) : -1;
        if (at < 0) return null;
        string hostPort = a[(at + 1)..end];
        int colon = hostPort.LastIndexOf(':');
        if (colon <= 0 || colon == hostPort.Length - 1 || hostPort.AsSpan(colon + 1).IndexOfAnyExcept("0123456789") >= 0) return null;
        string info = a[start..at];
        int c = info.IndexOf(':');
        string user = c >= 0 ? info[..c] : info, pass = c >= 0 ? info[(c + 1)..] : string.Empty;
        if (scheme >= 0)
        {
            user = Uri.UnescapeDataString(user);
            pass = Uri.UnescapeDataString(pass);
        }
        return (a[..start] + a[(at + 1)..], user, pass);
    }

    /// <summary>The "Proxy-Authorization: Basic …" line, with its CRLF, that a request to an HTTP upstream carries;
    /// empty without a login.</summary>
    internal string AuthorizationLine()
    {
        if (!HasLogin) return string.Empty;
        var raw = new byte[_user.Length + 1 + _pass.Length];
        _user.CopyTo(raw, 0);
        raw[_user.Length] = (byte)':';
        _pass.CopyTo(raw, _user.Length + 1);
        try { return "Proxy-Authorization: Basic " + Convert.ToBase64String(raw) + "\r\n"; }
        finally { Array.Clear(raw); }
    }

    // ------------------------------------------------------------------ the handshake

    private const int MaxHeadBytes = 8 * 1024;

    /// <summary>
    /// For an https:// upstream: TLS on the connection just made to it, before anything else is said. Its certificate
    /// must be valid for <see cref="Host"/> as a browser requires of a site's (a trusted issuer, not expired, the name or
    /// address it was reached by); HTTP/1.1 is asked for. Returns the stream everything goes over from then on. Throws
    /// <see cref="ProxyUpstreamException"/> when the certificate isn't valid or the handshake fails (an
    /// <see cref="OperationCanceledException"/> for <paramref name="ct"/> passes through).
    /// </summary>
    internal async Task<SslStream> SecureAsync(Stream s, CancellationToken ct)
    {
        var found = SslPolicyErrors.None;
        var ssl = new SslStream(s, leaveInnerStreamOpen: false);
        var options = new SslClientAuthenticationOptions
        {
            TargetHost = Host,
            ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http11 },
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
            {
                found = errors;
                return CertificateCheck is { } check ? check(certificate, errors) : errors == SslPolicyErrors.None;
            },
        };
        try
        {
            await ssl.AuthenticateAsClientAsync(options, ct).ConfigureAwait(false);
            return ssl;
        }
        catch (Exception ex)
        {
            ssl.Dispose();
            if (ex is OperationCanceledException) throw;
            if (found != SslPolicyErrors.None && ex is AuthenticationException) throw BadCertificate(found);
            throw new ProxyUpstreamException("upstream: TLS failed",
                $"TLS with the upstream proxy {Display} failed ({ex.Message.TrimEnd('.')}). Is it an https:// proxy? A plain HTTP proxy is http://.", inner: ex) { Fatal = true };
        }
    }

    private ProxyUpstreamException BadCertificate(SslPolicyErrors errors)
    {
        var what = new List<string>(3);
        if (errors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable)) what.Add("it sent none");
        if (errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch)) what.Add($"it is for another name than {Host}");
        if (errors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors))
            what.Add("it isn't from an issuer this device trusts (a self-signed one isn't), or it has expired");
        return new ProxyUpstreamException("upstream: bad certificate",
            $"The upstream proxy {Display}'s certificate isn't valid: {string.Join("; ", what)}. Nothing was sent to it.") { Fatal = true };
    }

    /// <summary>
    /// Asks the upstream, on a connection just made to it, for a tunnel to <paramref name="host"/> (a name or an
    /// address) : <paramref name="port"/>. Returns with the stream at the tunnel's first byte: nothing of the target's
    /// is read here. Throws <see cref="ProxyUpstreamException"/> when the upstream says no or breaks off (an
    /// <see cref="OperationCanceledException"/> for <paramref name="ct"/> passes through).
    /// </summary>
    internal async Task OpenTunnelAsync(Stream s, string host, int port, CancellationToken ct)
    {
        try
        {
            switch (Kind)
            {
                case ProxyUpstreamKind.Socks5: await Socks5Async(s, host, port, ct).ConfigureAwait(false); break;
                case ProxyUpstreamKind.Socks4a: await Socks4aAsync(s, host, port, ct).ConfigureAwait(false); break;
                default: await HttpConnectAsync(s, host, port, ct).ConfigureAwait(false); break;
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
        {
            throw Closed(ex);
        }
    }

    /// <summary>
    /// Asks a SOCKS5 upstream, on a connection just made to it, for a UDP relay (UDP ASSOCIATE, RFC 1928 §7). Returns
    /// where its relay takes the datagrams as it names it (BND.ADDR: an address, 0.0.0.0 or :: for "where you reached
    /// me", or a name; and BND.PORT). The relay lasts while this connection stays open. Throws as
    /// <see cref="OpenTunnelAsync"/> does; an upstream that doesn't relay UDP is "upstream: no UDP".
    /// </summary>
    internal async Task<(string Host, int Port)> OpenUdpAsync(Stream s, CancellationToken ct)
    {
        try
        {
            var buf = new byte[600];
            await Socks5GreetAsync(s, buf, ct).ConfigureAwait(false);
            // DST 0.0.0.0:0: the upstream isn't told where the datagrams will come from (this device's address, as this
            // connection does; it takes the port of the first one)
            await s.WriteAsync(new byte[] { 5, 3, 0, 1, 0, 0, 0, 0, 0, 0 }, ct).ConfigureAwait(false);
            return await Socks5AnswerAsync(s, buf, udp: true, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
        {
            throw Closed(ex);
        }
    }

    private async Task Socks5Async(Stream s, string host, int port, CancellationToken ct)
    {
        var buf = new byte[600];
        await Socks5GreetAsync(s, buf, ct).ConfigureAwait(false);

        // CONNECT to an address as such, or to a name for the upstream to look up (ATYP 3: length + name)
        int n = 0;
        buf[n++] = 5; buf[n++] = 1; buf[n++] = 0;
        if (IPAddress.TryParse(host, out var ip))
        {
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            buf[n++] = (byte)(ip.AddressFamily == AddressFamily.InterNetwork ? 1 : 4);
            ip.TryWriteBytes(buf.AsSpan(n), out int len);
            n += len;
        }
        else
        {
            byte[] name = NameBytes(host, "SOCKS5");
            buf[n++] = 3;
            buf[n++] = (byte)name.Length;
            name.CopyTo(buf, n);
            n += name.Length;
        }
        buf[n++] = (byte)(port >> 8);
        buf[n++] = (byte)port;
        await s.WriteAsync(buf.AsMemory(0, n), ct).ConfigureAwait(false);
        await Socks5AnswerAsync(s, buf, udp: false, ct).ConfigureAwait(false);   // read whole: the tunnel starts at the target's first byte
    }

    // The greeting, and the login when the upstream asks for one.
    private async Task Socks5GreetAsync(Stream s, byte[] buf, CancellationToken ct)
    {
        // no login, and user / password when there is one to offer
        await s.WriteAsync(HasLogin ? new byte[] { 5, 2, 0, 2 } : new byte[] { 5, 1, 0 }, ct).ConfigureAwait(false);
        await ReadExactAsync(s, buf, 2, ct).ConfigureAwait(false);
        if (buf[0] != 5) throw NotSocks();
        switch (buf[1])
        {
            case 0x00: break;
            case 0x02:
                if (!HasLogin) throw Login("needs a user name and password");
                var auth = new byte[3 + _user.Length + _pass.Length];
                auth[0] = 1;
                auth[1] = (byte)_user.Length;
                _user.CopyTo(auth, 2);
                auth[2 + _user.Length] = (byte)_pass.Length;
                _pass.CopyTo(auth, 3 + _user.Length);
                try { await s.WriteAsync(auth, ct).ConfigureAwait(false); }
                finally { Array.Clear(auth); }
                await ReadExactAsync(s, buf, 2, ct).ConfigureAwait(false);
                if (buf[1] != 0) throw Login("refused the user name and password");
                break;
            default:
                throw Login(HasLogin ? "accepts none of the login methods Echoes speaks" : "needs a login");
        }
    }

    // VER REP RSV ATYP BND.ADDR BND.PORT, all of it read: the bound address (or name) and port. A refusal throws; to a
    // UDP ASSOCIATE, "command not supported" means the upstream has no UDP relay.
    private async Task<(string Host, int Port)> Socks5AnswerAsync(Stream s, byte[] buf, bool udp, CancellationToken ct)
    {
        await ReadExactAsync(s, buf, 4, ct).ConfigureAwait(false);
        if (buf[0] != 5) throw NotSocks();
        if (buf[1] != 0) throw udp && buf[1] == 0x07 ? NoUdp() : Refused(buf[1]);
        byte atyp = buf[3];
        int length;
        switch (atyp)
        {
            case 1: length = 4; break;
            case 4: length = 16; break;
            case 3:
                await ReadExactAsync(s, buf, 1, ct).ConfigureAwait(false);
                length = buf[0];
                break;
            default: throw NotSocks();
        }
        await ReadExactAsync(s, buf, length + 2, ct).ConfigureAwait(false);
        string host = atyp == 3 ? Encoding.ASCII.GetString(buf, 0, length) : new IPAddress(buf.AsSpan(0, length)).ToString();
        return (host, (buf[length] << 8) | buf[length + 1]);
    }

    private ProxyUpstreamException Refused(byte rep)
    {
        (string status, string what) = rep switch
        {
            0x02 => ("upstream: not allowed", "its rules don't allow this connection"),
            0x03 => ("upstream: unreachable", "the network is unreachable from it"),
            0x04 => ("upstream: unreachable", "it can't reach the host (or find its name)"),
            0x05 => ("upstream: refused", "the connection was refused"),
            0x06 => ("upstream: timed out", "the connection timed out"),
            0x07 => ("upstream failed", "it doesn't do this kind of request"),
            0x08 => ("upstream failed", "it doesn't take this kind of address"),
            _ => ("upstream failed", $"it reported a failure ({rep})"),
        };
        return new ProxyUpstreamException(status, $"The upstream proxy {Display} didn't open the connection: {what}.", rep is >= 1 and <= 8 ? rep : (byte)0x01);
    }

    // SOCKS4a: VN 4, CD 1, port, 0.0.0.1 (a name follows) or the IPv4 address, the user id, and the name. The answer is
    // VN 0, CD 0x5A granted, then six bytes nobody reads.
    private async Task Socks4aAsync(Stream s, string host, int port, CancellationToken ct)
    {
        byte[] name = Array.Empty<byte>(), address = { 0, 0, 0, 1 };
        if (IPAddress.TryParse(host, out var ip))
        {
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            if (ip.AddressFamily != AddressFamily.InterNetwork)
                throw new ProxyUpstreamException("upstream: no IPv6", $"The upstream proxy {Display} speaks SOCKS4, which has no IPv6 addresses.", 0x08);
            address = ip.GetAddressBytes();
        }
        else name = NameBytes(host, "SOCKS4a");
        var req = new byte[9 + _user.Length + (name.Length > 0 ? name.Length + 1 : 0)];
        req[0] = 4; req[1] = 1;
        req[2] = (byte)(port >> 8); req[3] = (byte)port;
        address.CopyTo(req, 4);
        _user.CopyTo(req, 8);
        name.CopyTo(req, 9 + _user.Length);
        await s.WriteAsync(req, ct).ConfigureAwait(false);

        var reply = new byte[8];
        await ReadExactAsync(s, reply, 8, ct).ConfigureAwait(false);
        if (reply[0] != 0 && reply[0] != 4) throw NotSocks();
        switch (reply[1])
        {
            case 0x5A: return;
            case 0x5C or 0x5D: throw Login("refused the user id");
            default: throw new ProxyUpstreamException("upstream: refused", $"The upstream proxy {Display} rejected the connection (or couldn't make it).", 0x05);
        }
    }

    // CONNECT host:port, with Basic credentials when there are any. The answer's head is read a byte at a time: a target
    // that speaks first (a mail or FTP banner) may send right behind it, and nothing of the tunnel's may be taken here.
    private async Task HttpConnectAsync(Stream s, string host, int port, CancellationToken ct)
    {
        string target = (host.Contains(':') ? $"[{host}]" : AsciiHost(host) ?? throw NotAName()) + ":" + port;
        byte[] head = Encoding.ASCII.GetBytes(new StringBuilder(200)
            .Append("CONNECT ").Append(target).Append(" HTTP/1.1\r\nHost: ").Append(target).Append("\r\n")
            .Append(AuthorizationLine()).Append("Proxy-Connection: keep-alive\r\n\r\n").ToString());
        try { await s.WriteAsync(head, ct).ConfigureAwait(false); }
        finally { Array.Clear(head); }

        var answer = new byte[MaxHeadBytes];
        int n = 0;
        while (true)
        {
            if (n == answer.Length) throw NotHttp();
            if (await s.ReadAsync(answer.AsMemory(n, 1), ct).ConfigureAwait(false) == 0)
                throw new ProxyUpstreamException("upstream closed", $"The upstream proxy {Display} closed the connection without an answer.") { Fatal = true };
            n++;
            if (n >= 4 && answer[n - 4] == '\r' && answer[n - 3] == '\n' && answer[n - 2] == '\r' && answer[n - 1] == '\n') break;
            if (n == 5 && !answer.AsSpan(0, 5).SequenceEqual("HTTP/"u8)) throw NotHttp();
        }
        // "HTTP/1.1 200 Connection established"
        int sp = Array.IndexOf(answer, (byte)' ', 0, n);
        int code = sp > 0 && sp + 3 < n && int.TryParse(Encoding.ASCII.GetString(answer, sp + 1, 3), out int c) ? c : 0;
        if (code is >= 200 and < 300) return;
        throw code switch
        {
            407 => Login(HasLogin ? "refused the user name and password (HTTP 407)" : "needs a user name and password (HTTP 407)"),
            403 or 405 => new ProxyUpstreamException("upstream: not allowed", $"The upstream proxy {Display} doesn't allow a tunnel to {target} (HTTP {code}). Many HTTP proxies tunnel to port 443 only.", 0x02),
            502 or 503 => new ProxyUpstreamException("upstream: unreachable", $"The upstream proxy {Display} couldn't reach {target} (HTTP {code}).", 0x04),
            504 => new ProxyUpstreamException("upstream: timed out", $"The upstream proxy {Display} got no answer from {target} in time (HTTP 504).", 0x06),
            _ => new ProxyUpstreamException("upstream failed", $"The upstream proxy {Display} answered HTTP {code} to the tunnel request."),
        };
    }

    /// <summary>A host name as it goes to a proxy, in ASCII: a name in another script in its IDNA form, as a browser
    /// sends it (bücher.de → xn--bcher-kva.de), where plain ASCII would turn each such letter into '?'. An ASCII name or
    /// an address as it is. Null when it can't be put in that form.</summary>
    internal static string? AsciiHost(string host)
    {
        if (host.AsSpan().IndexOfAnyExceptInRange('\0', '\x7F') < 0) return host;
        try { return new IdnMapping().GetAscii(host); }
        catch (Exception) { return null; }   // not a name in any script (or no IDN support here)
    }

    // A name for SOCKS (ATYP 3, SOCKS4a): its ASCII form, of at most 255 bytes.
    private static byte[] NameBytes(string host, string kind)
    {
        byte[] name = Encoding.ASCII.GetBytes(AsciiHost(host) ?? throw NotAName());
        if (name.Length is 0 or > 255) throw new ProxyUpstreamException("no such host", $"The host name is too long for {kind}.", 0x04);
        return name;
    }

    private static ProxyUpstreamException NotAName()
        => new("no such host", "The host name can't be written in the ASCII form a proxy takes.", 0x04);

    private ProxyUpstreamException Login(string what)
        => new("upstream login", $"The upstream proxy {Display} {what}.") { Fatal = true };

    private ProxyUpstreamException Closed(Exception inner)
        => new("upstream closed", $"The upstream proxy {Display} closed the connection during its handshake.", inner: inner) { Fatal = true };

    private ProxyUpstreamException NoUdp()
        => new("upstream: no UDP", $"The upstream proxy {Display} doesn't relay UDP (it refused UDP ASSOCIATE): switch UDP on in it, or switch it off here.", 0x07) { Fatal = true };

    private ProxyUpstreamException NotSocks()
        => new("upstream: not SOCKS", $"{Display} doesn't answer as a SOCKS proxy: check the address and the kind of proxy.") { Fatal = true };

    private ProxyUpstreamException NotHttp()
        => new("upstream: not HTTP", $"{Display} doesn't answer as an HTTP proxy: check the address and the kind of proxy.") { Fatal = true };

    private static async Task ReadExactAsync(Stream s, byte[] buf, int count, CancellationToken ct)
    {
        int got = 0;
        while (got < count)
        {
            int n = await s.ReadAsync(buf.AsMemory(got, count - got), ct).ConfigureAwait(false);
            if (n == 0) throw new IOException("the upstream proxy closed the connection");
            got += n;
        }
    }
}
