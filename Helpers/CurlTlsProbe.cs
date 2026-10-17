using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>
/// The cURL tab's SSL report: a separate TLS handshake to the request's host, made the SAME way the request reaches it —
/// through its proxy (HTTP CONNECT or SOCKS5), pinned to its override IP, and/or bound to its interface — so the
/// certificate shown is the one on the request's path. Moved out of the view-model unchanged in behaviour.
/// </summary>
public static class CurlTlsProbe
{
    public static async Task<string> InspectAsync(CurlRequest r, string? nicIp, CancellationToken outer)
    {
        try
        {
            if (!Uri.TryCreate(CurlRequest.NormalizeUrl(r.Url), UriKind.Absolute, out var uri)) return string.Empty;
            if (uri.Scheme != Uri.UriSchemeHttps) return "  Not an HTTPS URL — no TLS certificate to inspect.";

            int port = uri.Port > 0 ? uri.Port : 443;
            // Bounded: never hang the SSL probe on an unreachable host.
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(outer);
            cts.CancelAfter(TimeSpan.FromSeconds(12));

            var (probeStream, via) = await OpenProbeConnectionAsync(r, uri, port, nicIp, cts.Token).ConfigureAwait(false);

            var policyErrors = SslPolicyErrors.None;
            using var sslStream = new SslStream(probeStream, false, (_, _, _, errors) => { policyErrors = errors; return true; });
            var sslOptions = new SslClientAuthenticationOptions
            {
                TargetHost = uri.Host,
                ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http2, SslApplicationProtocol.Http11 },
            };
            await sslStream.AuthenticateAsClientAsync(sslOptions, cts.Token).ConfigureAwait(false);

            // hashing, extension parsing and the chain build (which may fetch intermediates) stay off the UI thread
            var errors = policyErrors;
            return await Task.Run(() => FormatTlsReport(sslStream, uri, port, via, errors)).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (outer.IsCancellationRequested) { return string.Empty; }
        catch (OperationCanceledException) { return "  TLS Diagnostic: connection timed out."; }
        catch (Exception ex) { return $"  TLS Diagnostic Error: {ex.Message}"; }
    }

    private static string FormatTlsReport(SslStream sslStream, Uri uri, int port, string via, SslPolicyErrors policyErrors)
    {
        var sb = new StringBuilder();
        Section(sb, $"TLS CONNECTION — {uri.Host}:{port}");
        Row(sb, "Route", via);
        Row(sb, "Protocol", ProtocolName(sslStream.SslProtocol));
        try { AppendCipherRows(sb, sslStream.NegotiatedCipherSuite); } catch { }
        string alpn = sslStream.NegotiatedApplicationProtocol.ToString();
        Row(sb, "ALPN", string.IsNullOrEmpty(alpn) ? "(none)" : alpn);

        if (sslStream.RemoteCertificate is X509Certificate2 cert)
        {
            Section(sb, "CERTIFICATE — SUBJECT");
            Row(sb, "Common Name", DnPart(cert.Subject, "CN"));
            AppendIf(sb, "Organization", DnPart(cert.Subject, "O"));
            Row(sb, "Alt Names (SAN)", GetSubjectAltNames(cert));

            Section(sb, "CERTIFICATE — ISSUER");
            Row(sb, "Common Name", DnPart(cert.Issuer, "CN"));
            AppendIf(sb, "Organization", DnPart(cert.Issuer, "O"));

            Section(sb, "VALIDITY");
            Row(sb, "Not Before", cert.NotBefore.ToUniversalTime().ToString("MMM dd HH:mm:ss yyyy 'UTC'", System.Globalization.CultureInfo.InvariantCulture));
            Row(sb, "Not After", cert.NotAfter.ToUniversalTime().ToString("MMM dd HH:mm:ss yyyy 'UTC'", System.Globalization.CultureInfo.InvariantCulture));
            Row(sb, "Status", ValidityStatus(cert));

            Section(sb, "KEY & SIGNATURE");
            Row(sb, "Public Key", PublicKeyInfo(cert));
            Row(sb, "Signature Algo", cert.SignatureAlgorithm.FriendlyName ?? cert.SignatureAlgorithm.Value ?? "—");
            Row(sb, "Serial Number", Colonize(cert.SerialNumber));
            Row(sb, "SHA-1 Thumb", Colonize(cert.Thumbprint));
            Row(sb, "SHA-256", Colonize(Convert.ToHexString(cert.GetCertHash(HashAlgorithmName.SHA256))));

            Section(sb, "EXTENSIONS");
            AppendExtensions(sb, cert);

            Section(sb, "CHAIN");
            AppendChain(sb, cert, policyErrors);
        }
        return TextLimit.Cap(sb.ToString().TrimStart('\r', '\n'));
    }

    // A raw TCP stream to the target the SAME way the request reaches it, plus a short description of the route.
    private static async Task<(System.IO.Stream stream, string via)> OpenProbeConnectionAsync(CurlRequest r, Uri uri, int port, string? nicIp, CancellationToken ct)
    {
        // The host as it goes on the wire: punycode for an IDN, an IPv6 literal without its brackets.
        string host = uri.IdnHost;
        string nicSuffix = string.IsNullOrEmpty(nicIp) ? "" : $" · nic {nicIp}";

        if (!string.IsNullOrWhiteSpace(r.Proxy))
        {
            var (scheme, pHost, pPort) = ParseProxyEndpoint(r.Proxy);
            var sock = await DialSocketAsync(pHost, pPort, nicIp, ct).ConfigureAwait(false);
            var ns = new NetworkStream(sock, ownsSocket: true);
            try
            {
                if (scheme.StartsWith("socks", StringComparison.Ordinal))
                    await Socks5ConnectAsync(ns, host, port, r.ProxyUser, r.ProxyPass, ct).ConfigureAwait(false);
                else
                    await HttpConnectAsync(ns, host, port, r.ProxyUser, r.ProxyPass, ct).ConfigureAwait(false);
            }
            catch { ns.Dispose(); throw; }
            return (ns, $"proxy {r.Proxy}{nicSuffix}");
        }

        (string ip, int port)? ov = CurlFlagParser.TryParseOverride(r.OverrideIp, port, out var oip, out var oport) ? (oip, oport) : null;
        string dialHost = ov?.ip ?? host;
        int dialPort = ov?.port ?? port;
        var s = await DialSocketAsync(dialHost, dialPort, nicIp, ct).ConfigureAwait(false);
        string via = ov != null ? $"override {ov.Value.ip}:{ov.Value.port}{nicSuffix}"
                                : (string.IsNullOrEmpty(nicIp) ? "direct" : $"direct{nicSuffix}");
        return (new NetworkStream(s, ownsSocket: true), via);
    }

    private static async Task<Socket> DialSocketAsync(string host, int port, string? nicIp, CancellationToken ct)
    {
        IPAddress? bindIp = null;
        if (!string.IsNullOrEmpty(nicIp)) IPAddress.TryParse(nicIp, out bindIp);
        // IPv4 only where the OS has no IPv6 at all (ipv6.disable=1): a dual-stack socket can't be created there.
        var family = bindIp?.AddressFamily ?? (Socket.OSSupportsIPv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork);
        var socket = new Socket(family, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        if (bindIp == null && family == AddressFamily.InterNetworkV6) socket.DualMode = true;
        try
        {
            if (bindIp != null) socket.Bind(new IPEndPoint(bindIp, 0));
            await socket.ConnectAsync(host, port, ct).ConfigureAwait(false);
            return socket;
        }
        catch { socket.Dispose(); throw; }
    }

    private static (string scheme, string host, int port) ParseProxyEndpoint(string proxy)
    {
        string norm = HttpHelper.NormalizeProxy(proxy);
        if (Uri.TryCreate(norm, UriKind.Absolute, out var u))
        {
            string scheme = u.Scheme.ToLowerInvariant();
            int port = u.Port > 0 ? u.Port : (scheme.StartsWith("socks", StringComparison.Ordinal) ? 1080 : 8080);
            return (scheme, u.Host, port);
        }
        return ("http", proxy, 8080);
    }

    private static async Task HttpConnectAsync(System.IO.Stream stream, string host, int port, string? user, string? pass, CancellationToken ct)
    {
        var sb = new StringBuilder();
        string authority = host.Contains(':') ? $"[{host}]:{port}" : $"{host}:{port}";
        sb.Append($"CONNECT {authority} HTTP/1.1\r\n");
        sb.Append($"Host: {authority}\r\n");
        if (!string.IsNullOrEmpty(user))
            sb.Append($"Proxy-Authorization: Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user}:{pass}"))}\r\n");
        sb.Append("Proxy-Connection: keep-alive\r\n\r\n");
        await stream.WriteAsync(Encoding.ASCII.GetBytes(sb.ToString()), ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);

        var resp = new StringBuilder();
        var one = new byte[1];
        while (!resp.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal))
        {
            int n = await stream.ReadAsync(one.AsMemory(0, 1), ct).ConfigureAwait(false);
            if (n == 0) break;
            resp.Append((char)one[0]);
            if (resp.Length > 8192) break;
        }
        string statusLine = resp.ToString().Split('\r')[0];
        if (!statusLine.Contains(" 200")) throw new Exception("proxy CONNECT rejected: " + statusLine);
    }

    private static async Task Socks5ConnectAsync(System.IO.Stream stream, string host, int port, string? user, string? pass, CancellationToken ct)
    {
        bool wantAuth = !string.IsNullOrEmpty(user);
        byte[] greet = wantAuth ? new byte[] { 0x05, 0x02, 0x00, 0x02 } : new byte[] { 0x05, 0x01, 0x00 };
        await stream.WriteAsync(greet, ct).ConfigureAwait(false);

        var sel = await ReadExactAsync(stream, 2, ct).ConfigureAwait(false);
        if (sel[0] != 0x05) throw new Exception("SOCKS5: bad version");
        if (sel[1] == 0x02)
        {
            if (!wantAuth) throw new Exception("SOCKS5: proxy requires username/password");
            var u = Encoding.UTF8.GetBytes(user!);
            var p = Encoding.UTF8.GetBytes(pass ?? string.Empty);
            var authReq = new byte[3 + u.Length + p.Length];
            authReq[0] = 0x01; authReq[1] = (byte)u.Length;
            Array.Copy(u, 0, authReq, 2, u.Length);
            authReq[2 + u.Length] = (byte)p.Length;
            Array.Copy(p, 0, authReq, 3 + u.Length, p.Length);
            await stream.WriteAsync(authReq, ct).ConfigureAwait(false);
            var ar = await ReadExactAsync(stream, 2, ct).ConfigureAwait(false);
            if (ar[1] != 0x00) throw new Exception("SOCKS5: authentication failed");
        }
        else if (sel[1] != 0x00) throw new Exception("SOCKS5: no acceptable auth method");

        var hb = Encoding.UTF8.GetBytes(host);
        var req = new byte[7 + hb.Length];
        req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03; req[4] = (byte)hb.Length;
        Array.Copy(hb, 0, req, 5, hb.Length);
        req[5 + hb.Length] = (byte)(port >> 8);
        req[6 + hb.Length] = (byte)(port & 0xFF);
        await stream.WriteAsync(req, ct).ConfigureAwait(false);

        var rep = await ReadExactAsync(stream, 4, ct).ConfigureAwait(false);
        if (rep[1] != 0x00) throw new Exception($"SOCKS5: connect failed (reply 0x{rep[1]:X2})");
        int addrLen = rep[3] switch
        {
            0x01 => 4,
            0x04 => 16,
            0x03 => (await ReadExactAsync(stream, 1, ct).ConfigureAwait(false))[0],
            _ => throw new Exception("SOCKS5: unexpected address type")
        };
        await ReadExactAsync(stream, addrLen + 2, ct).ConfigureAwait(false);
    }

    private static async Task<byte[]> ReadExactAsync(System.IO.Stream s, int n, CancellationToken ct)
    {
        var buf = new byte[n];
        int off = 0;
        while (off < n)
        {
            int r = await s.ReadAsync(buf.AsMemory(off, n - off), ct).ConfigureAwait(false);
            if (r == 0) throw new Exception("connection closed by peer");
            off += r;
        }
        return buf;
    }

    private static void Section(StringBuilder sb, string title)
    {
        sb.AppendLine();
        sb.AppendLine("══════════════════════════════════════════════════");
        sb.AppendLine("  " + title);
        sb.AppendLine("══════════════════════════════════════════════════");
    }

    private static void Row(StringBuilder sb, string label, string value)
        => sb.AppendLine($"  {label,-16}: {(string.IsNullOrEmpty(value) ? "—" : value)}");

    private static void AppendIf(StringBuilder sb, string label, string value)
    {
        if (!string.IsNullOrWhiteSpace(value)) Row(sb, label, value);
    }

    // Cipher / key-exchange / MAC rows derived from the negotiated suite's IANA name (SslStream's own Cipher* properties are
    // obsolete on .NET 10 — the Android head — and say nothing useful for TLS 1.3).
    private static void AppendCipherRows(StringBuilder sb, TlsCipherSuite suite)
    {
        string name = suite.ToString();
        Row(sb, "Cipher Suite", name);
        if (!name.StartsWith("TLS_", StringComparison.Ordinal)) return;
        string rest = name[4..];
        int with = rest.IndexOf("_WITH_", StringComparison.Ordinal);
        string kx = with >= 0 ? rest[..with] : "(EC)DHE — TLS 1.3";
        string cipherMac = with >= 0 ? rest[(with + 6)..] : rest;
        int us = cipherMac.LastIndexOf('_');
        string last = us > 0 ? cipherMac[(us + 1)..] : string.Empty;
        bool hasMac = last.StartsWith("SHA", StringComparison.Ordinal) || last == "MD5";
        Row(sb, "Cipher", hasMac ? cipherMac[..us] : cipherMac);
        Row(sb, "Key Exchange", kx);
        Row(sb, "MAC / Hash", hasMac ? last : "AEAD");
    }

    private static string ProtocolName(SslProtocols p) => p switch
    {
        SslProtocols.Tls13 => "TLS 1.3",
        SslProtocols.Tls12 => "TLS 1.2",
#pragma warning disable SYSLIB0039
        SslProtocols.Tls11 => "TLS 1.1",
        SslProtocols.Tls => "TLS 1.0",
#pragma warning restore SYSLIB0039
        _ => p.ToString()
    };

    private static string ValidityStatus(X509Certificate2 cert)
    {
        var now = DateTime.Now;
        if (now < cert.NotBefore) return "NOT YET VALID";
        if (now > cert.NotAfter) return "EXPIRED";
        return $"VALID — {(cert.NotAfter - now).Days} days remaining";
    }

    private static string PublicKeyInfo(X509Certificate2 cert)
    {
        using var rsa = cert.GetRSAPublicKey();
        if (rsa != null) return $"RSA {rsa.KeySize}-bit";
        using var ecdsa = cert.GetECDsaPublicKey();
        if (ecdsa != null) return $"ECDSA {ecdsa.KeySize}-bit";
        return cert.PublicKey.Oid.FriendlyName ?? "Unknown";
    }

    private static string DnPart(string dn, string key)
    {
        if (string.IsNullOrEmpty(dn)) return "";
        foreach (var raw in dn.Split(','))
        {
            var part = raw.Trim();
            if (part.StartsWith(key + "=", StringComparison.OrdinalIgnoreCase))
                return part.Substring(key.Length + 1).Trim().Trim('"');
        }
        return "";
    }

    private static string Colonize(string hex)
    {
        if (string.IsNullOrEmpty(hex) || hex.Length % 2 != 0) return hex;
        var parts = new List<string>(hex.Length / 2);
        for (int i = 0; i < hex.Length; i += 2) parts.Add(hex.Substring(i, 2));
        return string.Join(":", parts);
    }

    private static string GetSubjectAltNames(X509Certificate2 cert)
    {
        var ext = cert.Extensions["2.5.29.17"];
        if (ext == null) return "";
        try
        {
            var san = new X509SubjectAlternativeNameExtension(ext.RawData);
            var names = san.EnumerateDnsNames().ToList();
            if (names.Count > 0) return string.Join(", ", names);
        }
        catch { }
        return ext.Format(false).Replace("DNS Name=", "").Replace(Environment.NewLine, ", ").Trim();
    }

    private static void AppendExtensions(StringBuilder sb, X509Certificate2 cert)
    {
        bool any = false;
        foreach (var ext in cert.Extensions)
        {
            switch (ext)
            {
                case X509BasicConstraintsExtension bc:
                    Row(sb, "Basic Constr.", $"CA={bc.CertificateAuthority}" + (bc.HasPathLengthConstraint ? $", PathLen={bc.PathLengthConstraint}" : ""));
                    any = true;
                    break;
                case X509KeyUsageExtension ku:
                    Row(sb, "Key Usage", ku.KeyUsages.ToString());
                    any = true;
                    break;
                case X509EnhancedKeyUsageExtension eku:
                    Row(sb, "Ext Key Usage", string.Join(", ", eku.EnhancedKeyUsages.Cast<Oid>().Select(o => o.FriendlyName ?? o.Value ?? "")));
                    any = true;
                    break;
            }
        }
        if (!any) sb.AppendLine("  (no notable extensions)");
    }

    private static void AppendChain(StringBuilder sb, X509Certificate2 cert, SslPolicyErrors policyErrors)
    {
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            chain.Build(cert);
            int i = 0;
            int last = chain.ChainElements.Count - 1;
            foreach (var element in chain.ChainElements)
            {
                string role = i == 0 ? "leaf" : (i == last ? "root" : "intermediate");
                string cn = DnPart(element.Certificate.Subject, "CN");
                if (string.IsNullOrEmpty(cn)) cn = element.Certificate.Subject;
                sb.AppendLine($"  [{i}] {cn}  ({role})");
                i++;
            }
        }
        catch (Exception ex)
        {
            sb.AppendLine($"  Chain build error: {ex.Message}");
        }
        Row(sb, "Validation", policyErrors == SslPolicyErrors.None ? "OK (trusted)" : policyErrors.ToString());
    }
}
