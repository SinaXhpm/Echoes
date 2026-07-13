using System;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>What -sV found about an open port.</summary>
public sealed class ServiceInfo
{
    public string Service = "unknown";   // http, ssh, https, ...
    public string Product = "";          // nginx, OpenSSH, ...
    public string Version = "";          // 1.18.0, 8.9p1, ...
    public string Info = "";             // extra: OS / protocol / cert CN
    public bool Tls;                     // spoken over TLS
    public string Banner = "";           // raw greeting (first line)

    /// <summary>Service label, "ssl/http"-style when tunneled.</summary>
    public string ServiceLabel =>
        Tls && !Service.EndsWith('s') && Service is not ("https" or "unknown")
            ? "ssl/" + Service : Service;

    /// <summary>"nginx 1.18.0 (Ubuntu)" — the nmap VERSION column.</summary>
    public string VersionText
    {
        get
        {
            var sb = new StringBuilder();
            if (Product.Length > 0) sb.Append(Product);
            if (Version.Length > 0) sb.Append(sb.Length > 0 ? " " : "").Append(Version);
            if (Info.Length > 0) sb.Append(sb.Length > 0 ? $" ({Info})" : Info);
            if (sb.Length == 0 && Banner.Length > 0) sb.Append(Banner.Length > 60 ? Banner[..60] : Banner);
            return sb.ToString();
        }
    }
}

/// <summary>
/// Managed, cross-platform (incl. Android) service/version detection — the nmap "-sV" equivalent.
/// Banner-grab + a few protocol probes (TLS handshake, HTTP GET, SSH/FTP/SMTP/POP3/IMAP greetings,
/// MySQL handshake, Redis/Memcached). No raw sockets, no native deps, no admin/root.
/// </summary>
public static class ServiceScanner
{
    // Ports that speak TLS immediately on connect.
    private static bool IsTlsPort(int p) => p is 443 or 993 or 995 or 465 or 990 or 636 or 989
        or 5061 or 6443 or 8443 or 9443 or 4443 or 2083 or 2087 or 2096 or 2484 or 5223 or 7443;

    private static bool IsHttpPort(int p) => p is 80 or 81 or 591 or 3000 or 8000 or 8008 or 8080
        or 8081 or 8443 or 8888 or 9090 or 5000 or 8180 or 8090 or 443 or 6443 or 9443 or 8443;

    public static async Task<ServiceInfo> ProbeAsync(string ip, int port, int timeoutMs, bool aggressive, CancellationToken ct)
    {
        var info = new ServiceInfo { Service = NmapData.ServiceName(port) };
        int t = Math.Max(400, timeoutMs);
        try
        {
            // A) TLS ports: handshake (cert CN + negotiated protocol), then HTTP-over-TLS for web.
            if (IsTlsPort(port))
            {
                await TlsProbe(ip, port, info, t, ct);
                return info;
            }

            // B) Passive banner grab — SSH/FTP/SMTP/POP3/IMAP/MySQL greet on connect.
            string banner = await BannerGrab(ip, port, t, ct);
            if (!string.IsNullOrWhiteSpace(banner))
            {
                info.Banner = FirstLine(banner);
                if (Fingerprint(info, banner)) return info;
            }

            // C) HTTP probe for web servers that don't greet.
            if (info.Product.Length == 0 && (IsHttpPort(port) || info.Banner.Length == 0))
            {
                string http = await HttpProbe(ip, port, ssl: false, t, ct);
                if (http.Length > 0 && FingerprintHttp(info, http, ssl: false)) return info;
            }

            // D) Aggressive: line-based key/value services.
            if (aggressive && info.Product.Length == 0)
                await ExtraProbes(ip, port, info, t, ct);
        }
        catch { /* detection is best-effort; return whatever we have */ }
        return info;
    }

    // ---- connection + I/O helpers ----

    private static async Task<Socket> ConnectAsync(string ip, int port, int timeoutMs, CancellationToken ct)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        try
        {
            await socket.ConnectAsync(System.Net.IPAddress.Parse(ip), port, cts.Token);
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private static async Task<string> ReadAscii(System.IO.Stream stream, int timeoutMs, CancellationToken ct, int max = 4096)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        var buf = new byte[max];
        int total = 0;
        try
        {
            // One read is enough for a greeting/response header block; loop briefly for slow servers.
            while (total < max)
            {
                int n = await stream.ReadAsync(buf.AsMemory(total, max - total), cts.Token);
                if (n <= 0) break;
                total += n;
                if (total >= 16 && (LooksComplete(buf, total))) break;
            }
        }
        catch { /* timeout / reset — return what we got */ }
        return Encoding.ASCII.GetString(buf, 0, total);
    }

    // Stop early once we have a full line / HTTP header terminator.
    private static bool LooksComplete(byte[] buf, int len)
    {
        for (int i = 1; i < len; i++)
            if (buf[i] == (byte)'\n') return true;
        return false;
    }

    // ---- probes ----

    private static async Task<string> BannerGrab(string ip, int port, int timeoutMs, CancellationToken ct)
    {
        using var socket = await ConnectAsync(ip, port, timeoutMs, ct);
        await using var net = new NetworkStream(socket, ownsSocket: false);
        return await ReadAscii(net, timeoutMs, ct);
    }

    private static async Task<string> HttpProbe(string ip, int port, bool ssl, int timeoutMs, CancellationToken ct)
    {
        using var socket = await ConnectAsync(ip, port, timeoutMs, ct);
        await using var net = new NetworkStream(socket, ownsSocket: false);
        System.IO.Stream stream = net;
        SslStream? sslStream = null;
        if (ssl)
        {
            sslStream = new SslStream(net, false, (_, _, _, _) => true);
            using (var cts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                cts.CancelAfter(timeoutMs);
                await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = ip }, cts.Token);
            }
            stream = sslStream;
        }
        try
        {
            byte[] req = Encoding.ASCII.GetBytes(
                $"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: Echoes\r\nAccept: */*\r\nConnection: close\r\n\r\n");
            using (var cts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                cts.CancelAfter(timeoutMs);
                await stream.WriteAsync(req, cts.Token);
            }
            return await ReadAscii(stream, timeoutMs, ct);
        }
        finally { sslStream?.Dispose(); }
    }

    private static async Task TlsProbe(string ip, int port, ServiceInfo info, int timeoutMs, CancellationToken ct)
    {
        using var socket = await ConnectAsync(ip, port, timeoutMs, ct);
        await using var net = new NetworkStream(socket, ownsSocket: false);
        using var ssl = new SslStream(net, false, (_, _, _, _) => true);
        try
        {
            using (var cts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                cts.CancelAfter(timeoutMs);
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = ip }, cts.Token);
            }
            info.Tls = true;
            info.Info = ssl.SslProtocol.ToString().Replace("Tls", "TLSv").Replace("None", "").Trim();

            // Grab the cert CN for the info column.
            if (ssl.RemoteCertificate is System.Security.Cryptography.X509Certificates.X509Certificate cert)
            {
                string cn = ParseCn(cert.Subject);
                if (cn.Length > 0) info.Info = (info.Info.Length > 0 ? info.Info + ", " : "") + "CN=" + cn;
            }

            // If it's (probably) HTTP, send a request over the TLS stream for the Server header.
            byte[] req = Encoding.ASCII.GetBytes(
                $"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: Echoes\r\nConnection: close\r\n\r\n");
            using (var cts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                cts.CancelAfter(timeoutMs);
                await ssl.WriteAsync(req, cts.Token);
            }
            string resp = await ReadAscii(ssl, timeoutMs, ct);
            if (resp.StartsWith("HTTP/", StringComparison.Ordinal))
            {
                if (info.Service is "unknown" or "https") info.Service = "https";
                FingerprintHttp(info, resp, ssl: true);
            }
        }
        catch { /* handshake failed — leave Tls where it is */ }
    }

    private static async Task ExtraProbes(string ip, int port, ServiceInfo info, int timeoutMs, CancellationToken ct)
    {
        // Redis: PING -> +PONG ; INFO gives version.
        try
        {
            using var socket = await ConnectAsync(ip, port, timeoutMs, ct);
            await using var net = new NetworkStream(socket, ownsSocket: false);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeoutMs);
            await net.WriteAsync(Encoding.ASCII.GetBytes("PING\r\n"), cts.Token);
            string r = await ReadAscii(net, timeoutMs, ct, 128);
            if (r.StartsWith("+PONG", StringComparison.Ordinal) || r.Contains("-NOAUTH"))
            {
                info.Service = "redis"; info.Product = "Redis";
            }
            else if (r.StartsWith("VERSION", StringComparison.Ordinal))
            {
                info.Service = "memcached"; info.Product = "Memcached";
                info.Version = r.Replace("VERSION", "").Trim();
            }
        }
        catch { }
    }

    // ---- fingerprinting ----

    private static bool Fingerprint(ServiceInfo info, string banner)
    {
        string first = FirstLine(banner);

        // SSH — "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
        if (first.StartsWith("SSH-", StringComparison.Ordinal))
        {
            info.Service = "ssh";
            var m = Regex.Match(first, @"^SSH-[\d.]+-([^\s]+)\s*(.*)$");
            if (m.Success)
            {
                SplitProductVersion(m.Groups[1].Value.Replace('_', '/'), info);
                if (m.Groups[2].Value.Length > 0) info.Info = m.Groups[2].Value.Trim();
            }
            return true;
        }

        // MySQL / MariaDB handshake — version string sits after a few binary header bytes.
        var my = Regex.Match(banner, @"([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.\-]*)");
        if ((banner.Contains("mysql", StringComparison.OrdinalIgnoreCase)
             || banner.Contains("MariaDB", StringComparison.OrdinalIgnoreCase)) && my.Success)
        {
            info.Service = "mysql";
            info.Product = banner.Contains("MariaDB", StringComparison.OrdinalIgnoreCase) ? "MariaDB" : "MySQL";
            info.Version = my.Groups[1].Value;
            return true;
        }

        // SMTP / ESMTP — "220 mail.example.com ESMTP Postfix"
        if (first.StartsWith("220", StringComparison.Ordinal) &&
            (first.Contains("SMTP", StringComparison.OrdinalIgnoreCase) || first.Contains("mail", StringComparison.OrdinalIgnoreCase)))
        {
            info.Service = "smtp";
            IdentifyDaemon(info, first);
            return true;
        }

        // FTP — "220 ProFTPD 1.3.5 Server"
        if (first.StartsWith("220", StringComparison.Ordinal))
        {
            info.Service = "ftp";
            IdentifyDaemon(info, first);
            return true;
        }

        // POP3 — "+OK Dovecot ready"
        if (first.StartsWith("+OK", StringComparison.Ordinal))
        {
            info.Service = "pop3";
            IdentifyDaemon(info, first);
            return true;
        }

        // IMAP — "* OK [CAPABILITY ...] Dovecot ready"
        if (first.StartsWith("* OK", StringComparison.Ordinal) || first.StartsWith("* PREAUTH", StringComparison.Ordinal))
        {
            info.Service = "imap";
            IdentifyDaemon(info, first);
            return true;
        }

        // Generic: any "Server/1.2.3"-looking token in the greeting.
        var g = Regex.Match(first, @"([A-Za-z][\w\-]+)[\s/_]v?(\d+\.[\d.]+\w*)");
        if (g.Success)
        {
            info.Product = g.Groups[1].Value;
            info.Version = g.Groups[2].Value;
            return true;
        }
        return false;
    }

    private static bool FingerprintHttp(ServiceInfo info, string resp, bool ssl)
    {
        if (!resp.StartsWith("HTTP/", StringComparison.Ordinal)) return false;
        if (info.Service is "unknown") info.Service = ssl ? "https" : "http";
        if (ssl) info.Tls = true;

        var server = Regex.Match(resp, @"(?im)^Server:\s*(.+?)\s*$");
        if (server.Success)
        {
            string val = server.Groups[1].Value.Trim();
            // "nginx/1.18.0" or "Apache/2.4.41 (Ubuntu)" or "Microsoft-IIS/10.0"
            var m = Regex.Match(val, @"^([^/\s]+)(?:/([^\s]+))?\s*(?:\((.*?)\))?");
            if (m.Success)
            {
                info.Product = m.Groups[1].Value;
                if (m.Groups[2].Success) info.Version = m.Groups[2].Value;
                if (m.Groups[3].Success && m.Groups[3].Value.Length > 0) info.Info = m.Groups[3].Value;
            }
            else info.Product = val;
        }
        else
        {
            // No Server header — note the powered-by or just the status line.
            var pb = Regex.Match(resp, @"(?im)^X-Powered-By:\s*(.+?)\s*$");
            if (pb.Success) info.Info = pb.Groups[1].Value.Trim();
        }
        return true;
    }

    // "ProFTPD 1.3.5" style daemon line → product + version.
    private static void IdentifyDaemon(ServiceInfo info, string line)
    {
        var m = Regex.Match(line, @"([A-Za-z][\w\-+]{2,})[\s/]v?(\d+\.[\d.]+\w*)");
        if (m.Success) { info.Product = m.Groups[1].Value; info.Version = m.Groups[2].Value; }
    }

    private static void SplitProductVersion(string token, ServiceInfo info)
    {
        // "OpenSSH/8.9p1"  or  "OpenSSH/8.9"
        int slash = token.IndexOf('/');
        if (slash > 0)
        {
            info.Product = token[..slash];
            info.Version = token[(slash + 1)..];
        }
        else info.Product = token;
    }

    private static string ParseCn(string subject)
    {
        var m = Regex.Match(subject, @"CN=([^,]+)");
        return m.Success ? m.Groups[1].Value.Trim() : "";
    }

    private static string FirstLine(string s)
    {
        int i = s.IndexOfAny(new[] { '\r', '\n' });
        return (i >= 0 ? s[..i] : s).Trim();
    }
}
