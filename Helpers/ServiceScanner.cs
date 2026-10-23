using System;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>What -sV found about an open port.</summary>
public sealed class ServiceInfo
{
    public string Service = "unknown";   // http, ssh, https, tcpwrapped, ...
    public string Product = "";          // nginx, OpenSSH, ...
    public string Version = "";          // 1.18.0, 8.9p1, ...
    public string Info = "";             // short extra: OS / TLS version
    public bool Tls;                     // spoken over TLS
    public string Banner = "";           // first line of the greeting, sanitized
    public string Detail = "";           // longer extras: page title, redirect, certificate
    /// <summary>Who answered in the server's place — an antivirus's web or TLS shield, a filtering gateway, an ISP's
    /// block page ("" when nobody did). Then Product / Version describe nothing about the server.</summary>
    public string Interceptor = "";

    /// <summary>"ssl/imap"-style label when a non-HTTPS service runs over TLS.</summary>
    public string ServiceLabel =>
        Tls && Service is not ("https" or "unknown" or "tcpwrapped") && !Service.StartsWith("ssl/", StringComparison.Ordinal)
            ? "ssl/" + Service : Service;

    /// <summary>"nginx 1.18.0 (Ubuntu)" — nmap's VERSION column. Product / Version / Info come from remote banners
    /// and certificates, so the composed text is scrubbed to printable ASCII (it lands in the table, report and CSV).</summary>
    public string VersionText
    {
        get
        {
            if (Interceptor.Length > 0 && Product.Length == 0) return "intercepted by " + Interceptor;
            var sb = new StringBuilder();
            if (Product.Length > 0) sb.Append(Product);
            if (Version.Length > 0) sb.Append(sb.Length > 0 ? " " : "").Append(Version);
            if (Info.Length > 0) sb.Append(sb.Length > 0 ? $" ({Info})" : Info);
            if (sb.Length == 0 && Banner.Length > 0) sb.Append(Banner.Length > 60 ? Banner[..60] : Banner);
            return ServiceScanner.Sanitize(sb.ToString());
        }
    }
}

/// <summary>
/// Managed, cross-platform (incl. Android) service/version detection — nmap's -sV in spirit. The scan's own connection
/// is reused for the passive greeting and, when the server stays silent, for an HTTP request; known TLS ports get a
/// handshake first (certificate names, issuer, expiry). Binary hellos for RDP / PostgreSQL, line probes for Redis /
/// memcached. Every probe is a standard read-only hello: nothing writes to or changes the target. No raw sockets, no
/// native dependencies; IPv4 and IPv6.
/// </summary>
public static class ServiceScanner
{
    // Ports that speak TLS from the first byte.
    private static bool IsTlsPort(int p) => p is 443 or 465 or 563 or 636 or 853 or 989 or 990 or 992 or 993 or 994
        or 995 or 2083 or 2087 or 2096 or 2484 or 4443 or 5061 or 5223 or 5986 or 6443 or 6697 or 7443 or 8443
        or 8834 or 9443;

    // Ports where a silent server is almost certainly HTTP: wait only briefly for a greeting before asking.
    private static bool IsHttpPort(int p) => p is 80 or 81 or 591 or 593 or 3000 or 5000 or 5601 or 7001 or 8000
        or 8008 or 8080 or 8081 or 8088 or 8090 or 8180 or 8443 or 8888 or 9000 or 9090 or 9200 or 10000;

    // ---- fingerprint patterns ----
    // They run over remote text (up to 4 KB of greeting, 8 KB of HTTP reply), and some backtrack: the unanchored
    // "token version" search and the lazy "(.+?)\s*$" header values are quadratic in a line's length. A reply built for
    // that cost ~0.6 s of CPU per header pattern (8 KB of spaces after "Server: a") and ~0.9 s for 4 KB of letters without
    // a newline, on every open port that sent one. So the patterns see bounded lines (MaxRxLine, MaxHeaderLine: far
    // beyond any real banner or header, which keep their results) and the title is found by a linear search; the time
    // limit is only a safety net — long enough that a busy machine can't trip it on a real reply.
    private const int MaxRxLine = 512;        // RFC 5321's reply line; an SSH identification is at most 255
    private const int MaxHeaderLine = 1024;   // header values are shown trimmed to 80 characters anyway
    private static readonly TimeSpan RxLimit = TimeSpan.FromSeconds(1);

    private static Regex Rx(string pattern) => new(pattern, RegexOptions.None, RxLimit);

    private static readonly Regex RedisVersionRx = Rx(@"redis_version:([0-9][\w.\-]*)");
    private static readonly Regex RfbRx = Rx(@"RFB (\d{3})\.(\d{3})");
    private static readonly Regex MySqlVersionRx = Rx(@"^\d+\.\d+");
    private static readonly Regex SshRx = Rx(@"^SSH-([\d.]+)-([^\s]+)\s*(.*)$");
    private static readonly Regex GenericVersionRx = Rx(@"([A-Za-z][\w\-]+)[\s/_]v?(\d+\.[\d.]+\w*)");
    private static readonly Regex ServerHeaderRx = Rx(@"(?im)^Server:[ \t]*(.+?)\s*$");
    private static readonly Regex ServerTokenRx = Rx(@"^([^/\s]+)(?:/([^\s]+))?\s*(?:\((.*?)\))?");
    private static readonly Regex PoweredByRx = Rx(@"(?im)^X-Powered-By:[ \t]*(.+?)\s*$");
    private static readonly Regex StatusRx = Rx(@"^HTTP/\d(?:\.\d)?\s+(\d{3})");
    private static readonly Regex LocationRx = Rx(@"(?im)^Location:[ \t]*(.+?)\s*$");
    private static readonly Regex DaemonVersionRx = Rx(@"^[\s/]v?(\d+\.[\d.]+\w*)");
    private static readonly Regex DaemonTokenRx = Rx(@"([A-Za-z][\w\-+]{2,})[\s/]v?(\d+\.[\d.]+\w*)");
    // Linear, and used by Sanitize, which must never throw: no time limit.
    private static readonly Regex SpacesRx = new(@"\s+", RegexOptions.None, Regex.InfiniteMatchTimeout);
    private static readonly Regex DotsRx = new(@"\.{3,}", RegexOptions.None, Regex.InfiniteMatchTimeout);

    // A pattern that ran out of time hasn't matched.
    private static Match Find(Regex rx, string input)
    {
        try { return rx.Match(input); }
        catch (RegexMatchTimeoutException) { return Match.Empty; }
    }

    private static string Cap(string s, int max) => s.Length > max ? s[..max] : s;

    // The reply with every line cut to MaxHeaderLine (the reply itself when no line is that long).
    private static string CapLines(string s)
    {
        int start = 0;
        for (; start < s.Length; )
        {
            int nl = s.IndexOf('\n', start);
            int end = nl < 0 ? s.Length : nl;
            if (end - start > MaxHeaderLine) break;
            start = end + 1;
        }
        if (start >= s.Length) return s;
        var sb = new StringBuilder(s.Length);
        for (start = 0; start < s.Length; )
        {
            int nl = s.IndexOf('\n', start);
            int end = nl < 0 ? s.Length : nl;
            sb.Append(s, start, Math.Min(end - start, MaxHeaderLine));
            if (nl >= 0) sb.Append('\n');
            start = end + 1;
        }
        return sb.ToString();
    }

    // What `(?is)<title[^>]*>(.*?)</title>` captures, found in linear time: the regex can only ever succeed from the first
    // "<title" (its first '>' and then the first "</title>" after it), and retried every later "<title" when that failed —
    // ~0.3 s on 8 KB of unclosed "<title>" tags.
    private static string? TitleOf(string s)
    {
        int open = s.IndexOf("<title", StringComparison.OrdinalIgnoreCase);
        if (open < 0) return null;
        int gt = s.IndexOf('>', open + 6);
        if (gt < 0) return null;
        int close = s.IndexOf("</title>", gt + 1, StringComparison.OrdinalIgnoreCase);
        return close < 0 ? null : s[(gt + 1)..close];
    }

    /// <summary>
    /// Probe an open port. <paramref name="reuse"/> is the scan's connected socket: the greeting is read from it, and
    /// the HTTP request too when nothing else was sent; it is NOT disposed here (the caller abort-closes it).
    /// <paramref name="sniHost"/> is the target's hostname (TLS SNI, HTTP Host) or empty for the IP.
    /// </summary>
    public static async Task<ServiceInfo> ProbeAsync(IPAddress addr, int port, Socket? reuse, string sniHost,
                                                     int timeoutMs, CancellationToken ct)
    {
        var info = new ServiceInfo { Service = NmapData.ServiceName(port) };
        int t = Math.Max(400, timeoutMs);
        string host = string.IsNullOrEmpty(sniHost) ? Literal(addr) : sniHost;

        // A per-port budget so a slow or black-holing service can't stall the scan; every probe honours it.
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(Math.Clamp(timeoutMs * 4, 3000, 10000));
        var bct = budget.Token;

        try
        {
            // 1. Known TLS port: handshake first (on the scan's socket — nothing was sent on it yet).
            if (IsTlsPort(port))
            {
                bool usedReuse = reuse is { Connected: true };
                if (await TlsProbe(addr, port, host, usedReuse ? reuse : null, info, t, bct)) return info;
                if (usedReuse) reuse = null;   // it carried a ClientHello: no longer usable for plaintext probes
            }

            // 2. Protocols that wait for a binary hello.
            if (port == 3389 && await RdpProbe(addr, info, t, bct)) return info;
            if (port == 5432 && await PostgresProbe(addr, info, t, bct)) return info;

            // 3. NULL probe: SSH / FTP / SMTP / POP3 / IMAP / MySQL / VNC / Telnet greet on connect.
            var conn = reuse is { Connected: true } ? reuse : await ConnectAsync(addr, port, t, bct);
            bool owned = !ReferenceEquals(conn, reuse);
            try
            {
                await using var net = new NetworkStream(conn, ownsSocket: false);
                var (raw, closed) = await ReadGreeting(net, IsHttpPort(port) ? Math.Min(t, 600) : t, bct);
                if (raw.Length > 0)
                {
                    string text = Encoding.Latin1.GetString(raw);
                    info.Banner = Sanitize(FirstLine(text));
                    if (text.StartsWith("HTTP/", StringComparison.Ordinal)) { FingerprintHttp(info, text, ssl: false); return info; }
                    if (Fingerprint(info, raw, text, port)) return info;
                }
                else if (closed)
                {
                    // Handshake completed, then the peer hung up before a byte was exchanged: a TCP wrapper /
                    // ACL behind the listener, or a proxy whose upstream connection failed (nmap: tcpwrapped).
                    info.Service = "tcpwrapped";
                    return info;
                }

                // 4. Still silent: ask for HTTP on the same connection.
                string http = closed ? "" : await HttpExchange(net, host, t, bct);
                if (http.StartsWith("HTTP/", StringComparison.Ordinal)) { FingerprintHttp(info, http, ssl: false); return info; }

                // 5. No greeting and no HTTP: a TLS service on an unusual port answers a plaintext request with
                // silence, a hang-up or a TLS alert record (0x15).
                if (raw.Length == 0 && !info.Tls && (http.Length == 0 || http[0] == '\x15')
                    && await TlsProbe(addr, port, host, null, info, t, bct))
                    return info;
            }
            finally
            {
                if (owned) conn.Dispose();
            }

            // 6. Line-based key/value services that wait for a command.
            if (info.Product.Length == 0 && info.Banner.Length == 0) await ExtraProbes(addr, port, info, t, bct);
        }
        catch { /* best-effort: return what we have */ }
        return info;
    }

    // ---- connection + I/O helpers ----

    private static async Task<Socket> ConnectAsync(IPAddress addr, int port, int timeoutMs, CancellationToken ct)
    {
        var socket = new Socket(addr.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        // Abortive (RST) close on dispose, like the scan's own sockets: a graceful FIN leaves each extra probe
        // connection in TIME_WAIT, and on a big Windows scan those exhaust the ephemeral ports.
        try { socket.LingerState = new LingerOption(true, 0); } catch { }
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        try
        {
            await socket.ConnectAsync(new IPEndPoint(addr, port), cts.Token);
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    // The passive greeting: whatever arrives within the wait, and whether the peer hung up without sending anything.
    private static async Task<(byte[] Data, bool Closed)> ReadGreeting(System.IO.Stream s, int waitMs, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(waitMs);
        var buf = new byte[4096];
        int total = 0;
        try
        {
            while (total < buf.Length)
            {
                int n = await s.ReadAsync(buf.AsMemory(total), cts.Token);
                if (n <= 0) return (buf[..total], total == 0);
                total += n;
                if (LooksComplete(buf, total, headerBlock: false)) break;
            }
        }
        catch (Exception) when (!cts.IsCancellationRequested)
        {
            return (buf[..total], total == 0);   // reset by the peer
        }
        catch { /* waited out */ }
        return (buf[..total], false);
    }

    // completeAt: the minimum length before a '\n' counts as done (short one-line replies pass 2).
    // headerBlock: an HTTP response — wait for the blank line that ends the headers, not just the status line.
    private static async Task<byte[]> ReadBytes(System.IO.Stream stream, int timeoutMs, CancellationToken ct,
                                                int max = 8192, int completeAt = 16, bool headerBlock = false)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        var buf = new byte[max];
        int total = 0;
        try
        {
            while (total < max)
            {
                int n = await stream.ReadAsync(buf.AsMemory(total, max - total), cts.Token);
                if (n <= 0) break;
                total += n;
                if (total >= completeAt && LooksComplete(buf, total, headerBlock)) break;
            }
        }
        catch { /* timeout / reset — return what we got */ }
        return total == buf.Length ? buf : buf[..total];
    }

    private static async Task WriteAsync(System.IO.Stream stream, byte[] data, int timeoutMs, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        await stream.WriteAsync(data, cts.Token);
    }

    private static bool LooksComplete(byte[] buf, int len, bool headerBlock)
    {
        if (headerBlock)
        {
            // An HTTP response: the header block plus a little of the body (for the <title>).
            for (int i = 1; i < len; i++)
                if (buf[i] == (byte)'\n' && (buf[i - 1] == (byte)'\n' || (i >= 2 && buf[i - 1] == (byte)'\r' && buf[i - 2] == (byte)'\n')))
                    return len - i > 512 || Encoding.Latin1.GetString(buf, i, len - i).Contains("</title>", StringComparison.OrdinalIgnoreCase);
            return false;
        }
        for (int i = 1; i < len; i++)
            if (buf[i] == (byte)'\n') return true;
        return false;
    }

    // ---- probes ----

    private static async Task<string> HttpExchange(System.IO.Stream s, string host, int timeoutMs, CancellationToken ct)
    {
        try
        {
            byte[] req = Encoding.ASCII.GetBytes(
                $"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (compatible; Echoes)\r\nAccept: */*\r\nConnection: close\r\n\r\n");
            await WriteAsync(s, req, timeoutMs, ct);
            return Encoding.Latin1.GetString(await ReadBytes(s, timeoutMs, ct, headerBlock: true));
        }
        catch { return ""; }
    }

    // TLS handshake (+ HTTP over it). True when the port speaks TLS.
    private static async Task<bool> TlsProbe(IPAddress addr, int port, string host, Socket? reuse, ServiceInfo info,
                                             int timeoutMs, CancellationToken ct)
    {
        Socket? owned = null;
        try
        {
            var socket = reuse ?? (owned = await ConnectAsync(addr, port, timeoutMs, ct));
            await using var net = new NetworkStream(socket, ownsSocket: false);
            using var ssl = new SslStream(net, false, (_, _, _, _) => true);
            using (var cts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                cts.CancelAfter(timeoutMs);
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = SniName(host) }, cts.Token);
            }
            info.Tls = true;
            info.Info = ssl.SslProtocol switch
            {
                System.Security.Authentication.SslProtocols.Tls13 => "TLSv1.3",
                System.Security.Authentication.SslProtocols.Tls12 => "TLSv1.2",
#pragma warning disable SYSLIB0039 // reporting what a server negotiated, not choosing it
                System.Security.Authentication.SslProtocols.Tls11 => "TLSv1.1",
                System.Security.Authentication.SslProtocols.Tls => "TLSv1.0",
#pragma warning restore SYSLIB0039
                _ => "TLS",
            };
            if (ssl.RemoteCertificate is { } rc) DescribeCertificate(rc, info);
            // "imaps" over TLS is reported as ssl/imap, like nmap.
            info.Service = info.Service switch
            {
                "imaps" => "imap", "pop3s" => "pop3", "smtps" => "smtp", "ldaps" or "ldapssl" => "ldap", "ftps" => "ftp",
                "ircs-tls" => "irc", var s => s,
            };

            // Mail services greet inside the tunnel; web servers wait to be asked.
            var (raw, closed) = await ReadGreeting(ssl, Math.Min(timeoutMs, 700), ct);
            if (raw.Length > 0)
            {
                string text = Encoding.Latin1.GetString(raw);
                info.Banner = Sanitize(FirstLine(text));
                Fingerprint(info, raw, text, port);
            }
            else if (!closed)
            {
                string resp = await HttpExchange(ssl, host, timeoutMs, ct);
                if (resp.StartsWith("HTTP/", StringComparison.Ordinal)) FingerprintHttp(info, resp, ssl: true);
            }
            return true;
        }
        catch { return false; }   // handshake failed: not TLS (or not a TLS we speak)
        finally { owned?.Dispose(); }
    }

    // "certificate esc-a.test · also www.esc-a.test · issuer R3 · expires 2026-05-01" (self-signed noted). A certificate
    // re-signed by an antivirus's or gateway's TLS inspection says so: it isn't the server's.
    private static void DescribeCertificate(X509Certificate rc, ServiceInfo info)
    {
        try
        {
            using var cert = rc as X509Certificate2 ?? new X509Certificate2(rc);
            string cn = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            string issuer = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: true);
            string inspector = InterceptorIn(cert.Issuer);
            if (inspector.Length > 0)
            {
                info.Interceptor = inspector + " TLS inspection";
                info.Detail = Sanitize($"certificate re-signed by \"{issuer}\" — {inspector} inspects TLS here, so the server's own certificate is hidden");
                return;
            }
            var sans = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>()
                           .SelectMany(e => e.EnumerateDnsNames())
                           .Where(n => !string.Equals(n, cn, StringComparison.OrdinalIgnoreCase))
                           .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var sb = new StringBuilder();
            if (cn.Length > 0) sb.Append("certificate ").Append(cn);
            if (sans.Count > 0)
                sb.Append(sb.Length > 0 ? " · also " : "also ").Append(string.Join(", ", sans.Take(4)))
                  .Append(sans.Count > 4 ? $" (+{sans.Count - 4})" : "");
            bool selfSigned = cert.SubjectName.RawData.AsSpan().SequenceEqual(cert.IssuerName.RawData);
            if (selfSigned) sb.Append(" · self-signed");
            else if (issuer.Length > 0) sb.Append(" · issuer ").Append(issuer);
            var expiry = cert.NotAfter.ToUniversalTime();
            sb.Append(expiry < DateTime.UtcNow ? " · expired " : " · expires ").Append(expiry.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
            info.Detail = Sanitize(sb.ToString());
        }
        catch { /* an unreadable certificate: no details */ }
    }

    // RDP: X.224 Connection Request; a Terminal Services server replies with a TPKT (0x03 0x00 ...).
    private static async Task<bool> RdpProbe(IPAddress addr, ServiceInfo info, int timeoutMs, CancellationToken ct)
    {
        try
        {
            using var socket = await ConnectAsync(addr, 3389, timeoutMs, ct);
            await using var net = new NetworkStream(socket, ownsSocket: false);
            byte[] cr =
            {
                0x03, 0x00, 0x00, 0x13,                         // TPKT: version 3, length 19
                0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,       // X.224 CR: LI=14, CR, dst/src ref, class
                0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, // RDP negotiation request: protocols SSL|HYBRID
            };
            await WriteAsync(net, cr, timeoutMs, ct);
            // Only the TPKT header matters; exactly 4 bytes returns as soon as it lands (the reply has no '\n').
            byte[] r = await ReadBytes(net, timeoutMs, ct, 4);
            if (r.Length >= 2 && r[0] == 0x03 && r[1] == 0x00)
            {
                info.Service = "ms-wbt-server";
                info.Product = "Microsoft Terminal Services";
                return true;
            }
        }
        catch { }
        return false;
    }

    // PostgreSQL: SSLRequest (8 bytes); the server answers with a single 'S' (TLS ok) or 'N' (no TLS).
    private static async Task<bool> PostgresProbe(IPAddress addr, ServiceInfo info, int timeoutMs, CancellationToken ct)
    {
        try
        {
            using var socket = await ConnectAsync(addr, 5432, timeoutMs, ct);
            await using var net = new NetworkStream(socket, ownsSocket: false);
            byte[] req = { 0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F }; // length 8 + SSLRequest code 80877103
            await WriteAsync(net, req, timeoutMs, ct);
            byte[] r = await ReadBytes(net, timeoutMs, ct, 1);
            if (r.Length >= 1 && (r[0] == (byte)'S' || r[0] == (byte)'N'))
            {
                info.Service = "postgresql";
                info.Product = "PostgreSQL";
                if (r[0] == (byte)'S') info.Info = "TLS available";
                return true;
            }
        }
        catch { }
        return false;
    }

    private static async Task ExtraProbes(IPAddress addr, int port, ServiceInfo info, int timeoutMs, CancellationToken ct)
    {
        // Redis: PING → +PONG / -NOAUTH; without auth, INFO server gives the version.
        try
        {
            using var socket = await ConnectAsync(addr, port, timeoutMs, ct);
            await using var net = new NetworkStream(socket, ownsSocket: false);
            await WriteAsync(net, Encoding.ASCII.GetBytes("PING\r\n"), timeoutMs, ct);
            string r = Encoding.Latin1.GetString(await ReadBytes(net, timeoutMs, ct, 256, completeAt: 2));
            if (r.StartsWith("+PONG", StringComparison.Ordinal) || r.Contains("NOAUTH"))
            {
                info.Service = "redis"; info.Product = "Redis";
                if (r.Contains("NOAUTH")) { info.Info = "auth required"; return; }
                await WriteAsync(net, Encoding.ASCII.GetBytes("INFO server\r\n"), timeoutMs, ct);
                string inf = Encoding.Latin1.GetString(await ReadBytes(net, timeoutMs, ct));
                var v = Find(RedisVersionRx, inf);
                if (v.Success) info.Version = v.Groups[1].Value;
                return;
            }
        }
        catch { }

        // memcached: "version" → "VERSION n.n.n".
        try
        {
            using var socket = await ConnectAsync(addr, port, timeoutMs, ct);
            await using var net = new NetworkStream(socket, ownsSocket: false);
            await WriteAsync(net, Encoding.ASCII.GetBytes("version\r\n"), timeoutMs, ct);
            string r = Encoding.Latin1.GetString(await ReadBytes(net, timeoutMs, ct, 128, completeAt: 2));
            if (r.StartsWith("VERSION", StringComparison.Ordinal))
            {
                info.Service = "memcached"; info.Product = "memcached";
                info.Version = Sanitize(r["VERSION".Length..].Trim());
            }
        }
        catch { }
    }

    // ---- fingerprinting ----

    // Mail / file daemons that announce themselves in their greeting; nmap's product names.
    private static readonly (string Needle, string Product)[] Daemons =
    {
        ("Postfix", "Postfix smtpd"), ("Exim", "Exim smtpd"), ("Sendmail", "Sendmail"), ("Microsoft ESMTP", "Microsoft ESMTP"),
        ("Exchange", "Microsoft Exchange"), ("qmail", "qmail"), ("OpenSMTPD", "OpenSMTPD"), ("hMailServer", "hMailServer"),
        ("MailEnable", "MailEnable"), ("ProFTPD", "ProFTPD"), ("vsFTPd", "vsftpd"), ("Pure-FTPd", "Pure-FTPd"),
        ("FileZilla Server", "FileZilla ftpd"), ("Microsoft FTP Service", "Microsoft ftpd"), ("Dovecot", "Dovecot"),
        ("Courier", "Courier"), ("Cyrus", "Cyrus"), ("Zimbra", "Zimbra"),
    };

    private static bool Fingerprint(ServiceInfo info, byte[] raw, string text, int port)
    {
        string first = FirstLine(text);

        // Telnet: the server opens with IAC (0xFF) option negotiation.
        if (raw.Length >= 2 && raw[0] == 0xFF && raw[1] is >= 0xFB and <= 0xFE)
        {
            info.Service = "telnet";
            info.Banner = "";
            return true;
        }

        // VNC: "RFB 003.008".
        if (first.StartsWith("RFB ", StringComparison.Ordinal))
        {
            info.Service = "vnc";
            var m = Find(RfbRx, Cap(first, MaxRxLine));
            if (m.Success) info.Info = $"protocol {int.Parse(m.Groups[1].Value)}.{int.Parse(m.Groups[2].Value)}";
            return true;
        }

        // MySQL / MariaDB: parse the real handshake [len:3][seq:1][proto:1] — protocol 10 then a NUL-terminated
        // version, or an ERR packet (0xFF: host not allowed). The length must be plausible too, so an arbitrary binary
        // greeting with 00 FF at offsets 3/4 isn't taken for MySQL.
        int myLen = raw.Length >= 3 ? raw[0] | (raw[1] << 8) | (raw[2] << 16) : 0;
        if (raw.Length >= 6 && raw[3] == 0x00 && myLen >= 3 && myLen < 0x10000)
        {
            if (raw[4] == 0x0A)
            {
                int end = Array.IndexOf(raw, (byte)0x00, 5);
                if (end > 5)
                {
                    string ver = Encoding.Latin1.GetString(raw, 5, end - 5);
                    if (Find(MySqlVersionRx, ver).Success)
                    {
                        info.Service = "mysql";
                        info.Product = ver.Contains("MariaDB", StringComparison.OrdinalIgnoreCase) ? "MariaDB" : "MySQL";
                        info.Version = Sanitize(ver);
                        info.Banner = info.Version;
                        return true;
                    }
                }
            }
            else if (raw[4] == 0xFF)
            {
                info.Service = "mysql"; info.Product = "MySQL"; info.Info = "unauthorized";
                return true;
            }
        }

        // SSH: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"
        if (first.StartsWith("SSH-", StringComparison.Ordinal))
        {
            info.Service = "ssh";
            var m = Find(SshRx, first);   // (anchored: linear on the whole line)
            if (m.Success)
            {
                SplitProductVersion(m.Groups[2].Value.Replace('_', '/'), info);
                if (m.Groups[3].Value.Length > 0) info.Info = m.Groups[3].Value.Trim();
                info.Detail = "protocol " + (m.Groups[1].Value == "1.99" ? "2.0" : m.Groups[1].Value);
            }
            return true;
        }

        // "220" greetings: SMTP or FTP, by keyword and port.
        if (first.StartsWith("220", StringComparison.Ordinal))
        {
            bool smtpKw = ContainsAny(first, "SMTP", "ESMTP", "Postfix", "Exim", "Sendmail", "mail");
            bool ftpKw = first.Contains("FTP", StringComparison.OrdinalIgnoreCase);
            bool smtpPort = port is 25 or 465 or 587 or 2525;
            if (smtpKw || (smtpPort && !ftpKw)) info.Service = "smtp";
            else if (ftpKw || port is 21 or 990) info.Service = "ftp";
            else info.Service = port == 21 ? "ftp" : "smtp";
            IdentifyDaemon(info, first);
            return true;
        }

        // POP3: "+OK Dovecot ready"
        if (first.StartsWith("+OK", StringComparison.Ordinal))
        {
            info.Service = "pop3";
            IdentifyDaemon(info, first);
            return true;
        }

        // IMAP: "* OK [CAPABILITY ...] Dovecot ready"
        if (first.StartsWith("* OK", StringComparison.Ordinal) || first.StartsWith("* PREAUTH", StringComparison.Ordinal))
        {
            info.Service = "imap";
            IdentifyDaemon(info, first);
            return true;
        }

        // Generic: a "Server/1.2.3"-looking token in the greeting.
        var g = Find(GenericVersionRx, Cap(first, MaxRxLine));
        if (g.Success)
        {
            info.Product = g.Groups[1].Value;
            info.Version = g.Groups[2].Value;
            return true;
        }
        return false;
    }

    private static void FingerprintHttp(ServiceInfo info, string resp, bool ssl)
    {
        // A plaintext HTTP answer is http whatever the port's usual name (8443 "https-alt" serving plain HTTP).
        info.Service = ssl ? "https" : "http";
        if (ssl) info.Tls = true;

        // The header patterns see every line cut to MaxHeaderLine (see the patterns above).
        string lines = CapLines(resp);
        var server = Find(ServerHeaderRx, lines);
        if (server.Success)
        {
            // "nginx/1.18.0", "Apache/2.4.41 (Ubuntu)", "Microsoft-IIS/10.0"
            string val = server.Groups[1].Value.Trim();
            var m = Find(ServerTokenRx, val);
            if (m.Success)
            {
                info.Product = m.Groups[1].Value;
                if (m.Groups[2].Success) info.Version = m.Groups[2].Value;
                if (m.Groups[3].Success && m.Groups[3].Value.Length > 0)
                    info.Info = info.Tls && info.Info.Length > 0 ? $"{m.Groups[3].Value}; {info.Info}" : m.Groups[3].Value;
            }
            else info.Product = val;
        }
        else if (Find(PoweredByRx, lines) is { Success: true } pb)
        {
            info.Product = pb.Groups[1].Value.Trim();
        }

        // Status, redirect target and page title go to the detail line ("301 → https://… · title: …").
        var parts = new System.Collections.Generic.List<string>();
        var status = Find(StatusRx, resp);   // (anchored at the start)
        var location = Find(LocationRx, lines);
        if (status.Success && status.Groups[1].Value[0] == '3' && location.Success)
            parts.Add($"{status.Groups[1].Value} → {Trim(location.Groups[1].Value, 80)}");
        else if (status.Success && status.Groups[1].Value != "200")
            parts.Add("status " + status.Groups[1].Value);
        string tt = TitleOf(resp) is { } title ? SpacesRx.Replace(WebUtility.HtmlDecode(title), " ").Trim() : "";
        if (tt.Length > 0) parts.Add("title: " + Trim(tt, 80));

        // A block page from a security product or a filter, sent in the server's place (an antivirus's web shield on
        // this machine rewrites the reply on the way in): the port is open, but nothing here describes the server.
        string code = status.Success ? status.Groups[1].Value : "";
        bool blockPage = code is "403" or "451" or "503"
                         || ContainsAny(tt, "block", "denied", "alert", "forbidden", "threat", "restricted", "warning");
        string who = blockPage ? InterceptorIn(tt) : "";
        if (who.Length == 0 && code is "403" or "451" && ContainsAny(resp, "10.10.34.34", "10.10.34.35", "peyvandha"))
            who = "ISP filtering";
        if (who.Length > 0)
        {
            info.Interceptor = who;
            info.Product = info.Version = info.Banner = "";
            info.Info = ssl ? info.Info : "";
            info.Detail = Sanitize($"{who} answered in the server's place (status {code}" + (tt.Length > 0 ? $", \"{Trim(tt, 60)}\"" : "")
                                   + ") — the server's own reply is hidden");
            return;
        }

        // No Server header: the title is the best name the page offers.
        if (info.Product.Length == 0 && tt.Length > 0) info.Banner = Trim(tt, 60);
        string http = Sanitize(string.Join(" · ", parts));
        if (http.Length > 0) info.Detail = info.Detail.Length > 0 ? $"{http} · {info.Detail}" : http;
    }

    // Security products and filtering gateways that answer in a server's place or re-sign its TLS certificate.
    private static readonly string[] Interceptors =
    {
        "ESET", "Kaspersky", "Bitdefender", "Avast", "AVG", "Norton", "McAfee", "Sophos", "Trend Micro", "Webroot",
        "Malwarebytes", "Dr.Web", "Fortinet", "FortiGuard", "FortiGate", "Zscaler", "Netskope", "Cisco Umbrella",
        "Palo Alto Networks", "Barracuda", "WatchGuard", "SonicWall", "Check Point", "Forcepoint", "Blue Coat",
    };

    // The interceptor named in a title or certificate issuer, as a whole word ("AVG" inside "SAVGAME" is nothing).
    private static string InterceptorIn(string text)
    {
        foreach (var name in Interceptors)
        {
            for (int at = text.IndexOf(name, StringComparison.OrdinalIgnoreCase); at >= 0;
                 at = text.IndexOf(name, at + 1, StringComparison.OrdinalIgnoreCase))
            {
                int end = at + name.Length;
                if ((at == 0 || !char.IsLetterOrDigit(text[at - 1])) && (end >= text.Length || !char.IsLetterOrDigit(text[end])))
                    return name;
            }
        }
        return "";
    }

    // "Postfix", "ProFTPD 1.3.5" … → product + version; the full greeting goes to the detail line.
    private static void IdentifyDaemon(ServiceInfo info, string line)
    {
        info.Detail = Sanitize(line);
        foreach (var (needle, product) in Daemons)
        {
            int at = line.IndexOf(needle, StringComparison.OrdinalIgnoreCase);
            if (at < 0) continue;
            info.Product = product;
            var v = Find(DaemonVersionRx, line[(at + needle.Length)..]);   // (anchored)
            if (v.Success) info.Version = v.Groups[1].Value;
            return;
        }
        var m = Find(DaemonTokenRx, Cap(line, MaxRxLine));
        if (m.Success) { info.Product = m.Groups[1].Value; info.Version = m.Groups[2].Value; }
    }

    private static void SplitProductVersion(string token, ServiceInfo info)
    {
        // "OpenSSH/8.9p1" or "OpenSSH/8.9"
        int slash = token.IndexOf('/');
        if (slash > 0)
        {
            info.Product = token[..slash];
            info.Version = token[(slash + 1)..];
        }
        else info.Product = token;
    }

    private static string FirstLine(string s)
    {
        int i = s.IndexOfAny(new[] { '\r', '\n' });
        return (i >= 0 ? s[..i] : s).Trim();
    }

    private static string Trim(string s, int max) => s.Length > max ? s[..max].TrimEnd() + "…" : s;

    /// <summary>Reduce remote text (banners, headers, certificate names) to printable ASCII — plus the few marks our own
    /// detail lines use — so control characters can't corrupt the table, report or CSV; runs of '.' from binary data
    /// are collapsed.</summary>
    public static string Sanitize(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s)
            sb.Append(c is >= (char)0x20 and < (char)0x7F or '…' or '→' or '·' or '—' ? c : (c is '\t' ? ' ' : '.'));
        return DotsRx.Replace(sb.ToString(), "..").Trim();
    }

    private static bool ContainsAny(string s, params string[] needles)
    {
        foreach (var n in needles)
            if (s.Contains(n, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    // Bracket IPv6 literals for the Host header; leave IPv4 alone.
    private static string Literal(IPAddress addr) =>
        addr.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{addr}]" : addr.ToString();

    // TLS TargetHost wants the bare name/literal ("[2001:db8::1]" is neither a valid SNI name nor seen as an IP, for
    // which SslStream correctly sends no SNI at all).
    private static string SniName(string host) => host.Trim('[', ']');
}
