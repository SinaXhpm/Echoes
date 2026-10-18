using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>The share hub's certificate for one run, with what the app shows about it.</summary>
public sealed class ShareCert : IDisposable
{
    public required X509Certificate2 Certificate { get; init; }
    /// <summary>SHA-256 of the certificate, "4F:2A:…" (what a browser's certificate viewer shows).</summary>
    public required string Fingerprint { get; init; }
    /// <summary>The first 6 bytes of <see cref="Fingerprint"/> — enough to compare by eye with the browser's view.</summary>
    public string ShortFingerprint => Fingerprint.Length > 17 ? Fingerprint[..17] : Fingerprint;
    /// <summary>A new certificate was made this time (first run, expired, or this device's addresses changed).</summary>
    public bool Regenerated { get; init; }
    /// <summary>Built once per run: the server sends the same (self-signed, chain-less) certificate on every handshake.</summary>
    public SslStreamCertificateContext? Context { get; init; }

    public SslServerAuthenticationOptions ServerOptions() => new()
    {
        ServerCertificateContext = Context,
        ServerCertificate = Context is null ? Certificate : null,
        ClientCertificateRequired = false,
        CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
        // the OS default (TLS 1.2 / 1.3); no ALPN (HTTP/1.1 only — and .NET for Android's server mode refuses ALPN options)
        EnabledSslProtocols = SslProtocols.None,
    };

    public void Dispose() => Certificate.Dispose();
}

/// <summary>
/// HTTPS for the share hub without any setup: a self-signed ECDSA P-256 certificate made once per install (AOT-safe
/// <see cref="CertificateRequest"/>), kept sealed in the profile (the PFX through <see cref="SecretProtector"/>), so its
/// fingerprint stays the same across restarts and browsers that accepted it once keep doing so (Firefox remembers the
/// exception per certificate). It names localhost, this machine and its current LAN addresses; a new one is made when it
/// expires (365 days, renewed 14 days early) or when this device has a LAN IPv4 address or name the certificate doesn't
/// cover (moved to another network) — the new one keeps the old addresses too, so moving back doesn't renew again.
/// IPv6 addresses are added but never force a renewal: privacy addresses change daily.
/// </summary>
public static class ShareTls
{
    public const string ProfileKey = "webserver.cert";
    internal const int ValidDays = 365;
    internal const int RenewWithinDays = 14;
    private const int MaxIpSans = 24, MaxDnsSans = 8;
    private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";

    /// <summary>Test hooks: the clock and this device's names / LAN addresses (null = the real ones).</summary>
    internal static Func<DateTimeOffset> Now { get; set; } = () => DateTimeOffset.UtcNow;
    internal static Func<(IReadOnlyList<string> Names, IReadOnlyList<IPAddress> V4, IReadOnlyList<IPAddress> V6)>? IdentityHook { get; set; }

    // A certificate that passed the loopback handshake test in this process (by SHA-256): not tested again.
    private static string? s_tested;
    private static readonly object s_gate = new();

    /// <summary>
    /// The stored certificate when it still fits this device, else a new one (stored sealed). Call off the UI thread.
    /// Throws when the platform can't make or load one — the caller then serves plain HTTP.
    /// </summary>
    public static ShareCert LoadOrCreate()
    {
        lock (s_gate)
        {
            var (names, v4, v6) = Identity();
            var now = Now();
            var p = ProfileService.Instance;
            List<string> keepNames = new();
            List<IPAddress> keepIps = new();
            if (p.GetSetting(ProfileKey) is { Length: > 0 } stored)
            {
                X509Certificate2? cert = null;
                try
                {
                    string b64 = SecretProtector.Unprotect(stored);
                    if (b64.Length > 0) cert = Load(Convert.FromBase64String(b64));
                }
                catch { cert?.Dispose(); cert = null; }
                if (cert is not null)
                {
                    if (Fits(cert, names, v4, now)) return Wrap(cert, regenerated: false);
                    var (oldNames, oldIps) = Sans(cert);
                    keepNames.AddRange(oldNames);
                    keepIps.AddRange(oldIps);
                    cert.Dispose();
                }
            }

            // Current names / addresses first, then the old certificate's (moving back to a network it knew: no renewal).
            var dns = Distinct(new[] { "localhost" }.Concat(names).Concat(keepNames), StringComparer.OrdinalIgnoreCase).Take(MaxDnsSans).ToList();
            var ips = Distinct(new[] { IPAddress.Loopback, IPAddress.IPv6Loopback }.Concat(v4).Concat(v6).Concat(keepIps), null).Take(MaxIpSans).ToList();
            byte[] pfx = Generate(dns, ips, now, names.FirstOrDefault());
            // With no usable key file this run, a stored (sealed) certificate may only be unreadable for now: don't write
            // over it — this one serves the session, and the next run can open the stored one again.
            if (SecretProtector.IsKeyAvailable) p.SetSetting(ProfileKey, SecretProtector.Protect(Convert.ToBase64String(pfx)));
            return Wrap(Load(pfx), regenerated: true);
        }
    }

    /// <summary>
    /// A loopback handshake with the certificate: proves this platform can serve it (.NET for Android's server-side
    /// SslStream, Windows SChannel with the imported key) before any browser depends on it. Null = fine, else why not.
    /// Remembered per certificate for the process.
    /// </summary>
    public static async Task<string?> SelfTestAsync(ShareCert cert, CancellationToken ct)
    {
        lock (s_gate) if (s_tested == cert.Fingerprint) return null;
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(8000);
        var listener = new TcpListener(IPAddress.Loopback, 0);
        try
        {
            listener.Start(1);
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var client = new TcpClient();
            var accepting = listener.AcceptTcpClientAsync(cts.Token).AsTask();
            await client.ConnectAsync(IPAddress.Loopback, port, cts.Token).ConfigureAwait(false);
            using var server = await accepting.ConfigureAwait(false);
            await using var serverSsl = new SslStream(server.GetStream(), false);
            await using var clientSsl = new SslStream(client.GetStream(), false);
            var serving = serverSsl.AuthenticateAsServerAsync(cert.ServerOptions(), cts.Token);
            var asking = clientSsl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "localhost",
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                // exactly our certificate, nothing else
                RemoteCertificateValidationCallback = (_, c, _, _) => c is not null && Hex(c.GetCertHash(HashAlgorithmName.SHA256)) == cert.Fingerprint,
            }, cts.Token);
            await Task.WhenAll(serving, asking).ConfigureAwait(false);
            // one byte each way: the record layer works too, not just the handshake
            await clientSsl.WriteAsync(new byte[] { 0x2A }, cts.Token).ConfigureAwait(false);
            var one = new byte[1];
            int n = await serverSsl.ReadAsync(one, cts.Token).ConfigureAwait(false);
            if (n != 1 || one[0] != 0x2A) return "the test connection didn't carry data";
            lock (s_gate) s_tested = cert.Fingerprint;
            return null;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return "the test handshake timed out";
        }
        catch (Exception ex)
        {
            var e = SocketErrors.Unwrap(ex);
            return e is PlatformNotSupportedException or NotImplementedException or NotSupportedException
                ? "this system's TLS can't act as a server"
                : WsProtocol.Short(e.Message.Trim(), 160);
        }
        finally
        {
            try { listener.Stop(); } catch { }
        }
    }

    /// <summary>"4F:2A:9C:…" — SHA-256 of the certificate's DER bytes.</summary>
    public static string Fingerprint(X509Certificate2 cert) => Hex(cert.GetCertHash(HashAlgorithmName.SHA256));

    private static string Hex(byte[] b)
    {
        var sb = new StringBuilder(b.Length * 3);
        for (int i = 0; i < b.Length; i++)
        {
            if (i > 0) sb.Append(':');
            sb.Append(b[i].ToString("X2", System.Globalization.CultureInfo.InvariantCulture));
        }
        return sb.ToString();
    }

    private static ShareCert Wrap(X509Certificate2 cert, bool regenerated)
    {
        SslStreamCertificateContext? ctx = null;
        try { ctx = SslStreamCertificateContext.Create(cert, additionalCertificates: null, offline: true); }
        catch { /* older / restricted platforms: the plain certificate option is used */ }
        return new ShareCert { Certificate = cert, Fingerprint = Fingerprint(cert), Regenerated = regenerated, Context = ctx };
    }

    // Exportable: .NET for Android's server mode hands the key to Java's SSLEngine as PKCS#8. The default key set on
    // Windows: SChannel can't serve a TLS server key that only lives in memory (EphemeralKeySet); the temporary key
    // container is removed when the certificate is disposed (on Stop).
    private static X509Certificate2 Load(byte[] pfx)
    {
        const X509KeyStorageFlags flags = X509KeyStorageFlags.Exportable;
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12(pfx, null, flags);
#else
        return new X509Certificate2(pfx, (string?)null, flags);
#endif
    }

    /// <summary>Still valid for <see cref="RenewWithinDays"/> days, ECDSA with its key, and names every current name and
    /// LAN IPv4 address of this device.</summary>
    internal static bool Fits(X509Certificate2 cert, IReadOnlyList<string> names, IReadOnlyList<IPAddress> v4, DateTimeOffset now)
    {
        try
        {
            if (!cert.HasPrivateKey) return false;
            if (cert.NotBefore.ToUniversalTime() > now.UtcDateTime.AddMinutes(5)) return false;   // the clock went back a lot
            if (cert.NotAfter.ToUniversalTime() < now.UtcDateTime.AddDays(RenewWithinDays)) return false;
            using (var key = cert.GetECDsaPublicKey()) if (key is null) return false;
            var (dns, ips) = Sans(cert);
            if (!dns.Contains("localhost", StringComparer.OrdinalIgnoreCase)) return false;
            foreach (var n in names) if (!dns.Contains(n, StringComparer.OrdinalIgnoreCase)) return false;
            foreach (var a in v4) if (!ips.Contains(a)) return false;
            return true;
        }
        catch { return false; }
    }

    internal static (List<string> Dns, List<IPAddress> Ips) Sans(X509Certificate2 cert)
    {
        var dns = new List<string>();
        var ips = new List<IPAddress>();
        foreach (var ext in cert.Extensions)
        {
            if (ext.Oid?.Value != "2.5.29.17") continue;
            var san = ext as X509SubjectAlternativeNameExtension ?? new X509SubjectAlternativeNameExtension(ext.RawData, ext.Critical);
            foreach (var d in san.EnumerateDnsNames()) dns.Add(d);
            foreach (var ip in san.EnumerateIPAddresses()) ips.Add(ip);
        }
        return (dns, ips);
    }

    private static byte[] Generate(IReadOnlyList<string> dns, IReadOnlyList<IPAddress> ips, DateTimeOffset now, string? machine)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var dn = new X500DistinguishedNameBuilder();
        dn.AddCommonName(machine is { Length: > 0 } ? "Echoes on " + machine : "Echoes share");
        dn.AddOrganizationName("Echoes (self-signed)");
        var req = new CertificateRequest(dn.Build(), key, HashAlgorithmName.SHA256);
        // a server certificate (CA: false — Firefox refuses to make an exception for a CA used as a server), signature
        // use only, serverAuth (Apple platforms require the EKU), every name in the SAN (browsers ignore the CN)
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(ServerAuthOid, "Server Authentication") }, false));
        var san = new SubjectAlternativeNameBuilder();
        foreach (var d in dns) san.AddDnsName(d);
        foreach (var ip in ips) san.AddIpAddress(ip);
        req.CertificateExtensions.Add(san.Build());
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        // 365 days: under every browser's limit for server certificates (Apple: 398)
        using var cert = req.CreateSelfSigned(now.AddDays(-1), now.AddDays(ValidDays));
        return cert.Export(X509ContentType.Pfx);
    }

    private static IEnumerable<T> Distinct<T>(IEnumerable<T> items, IEqualityComparer<T>? cmp)
    {
        var seen = new HashSet<T>(cmp);
        foreach (var i in items) if (i is not null && seen.Add(i)) yield return i;
    }

    // ------------------------------------------------------------------ this device

    private static (IReadOnlyList<string> Names, IReadOnlyList<IPAddress> V4, IReadOnlyList<IPAddress> V6) Identity()
    {
        if (IdentityHook is { } hook) return hook();
        return (MachineNames(), LanAddresses(AddressFamily.InterNetwork), LanAddresses(AddressFamily.InterNetworkV6));
    }

    /// <summary>This machine's DNS-safe host name and its mDNS form ("mypc", "mypc.local"); none on Android ("localhost").</summary>
    internal static IReadOnlyList<string> MachineNames()
    {
        var list = new List<string>();
        string host = string.Empty;
        try { host = Dns.GetHostName().Trim().TrimEnd('.'); } catch { }
        if (IsDnsName(host) && !host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
        {
            list.Add(host.ToLowerInvariant());
            if (!host.EndsWith(".local", StringComparison.OrdinalIgnoreCase) && !host.Contains('.')) list.Add(host.ToLowerInvariant() + ".local");
        }
        return list;
    }

    private static bool IsDnsName(string s)
    {
        if (s.Length is 0 or > 200) return false;
        foreach (var label in s.Split('.'))
        {
            if (label.Length is 0 or > 63 || label[0] == '-' || label[^1] == '-') return false;
            foreach (char c in label)
                if (!(c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-')) return false;
        }
        return true;
    }

    /// <summary>Unicast addresses of the adapters that are up: IPv4 (no loopback), or IPv6 without loopback / link-local
    /// (a URL can't carry their zone) / multicast.</summary>
    internal static IReadOnlyList<IPAddress> LanAddresses(AddressFamily family)
    {
        var list = new List<IPAddress>();
        if (family == AddressFamily.InterNetwork)
        {
            foreach (var (_, a) in NicSnapshot.UpIPv4()) if (!IPAddress.IsLoopback(a) && !list.Contains(a)) list.Add(a);
            return list;
        }
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    var a = ua.Address;
                    if (a.AddressFamily != AddressFamily.InterNetworkV6 || IPAddress.IsLoopback(a) || a.IsIPv6LinkLocal
                        || a.IsIPv6Multicast || a.IsIPv6SiteLocal || a.IsIPv4MappedToIPv6) continue;
                    var clean = new IPAddress(a.GetAddressBytes());   // without a scope id
                    if (!list.Contains(clean)) list.Add(clean);
                    if (list.Count >= 8) return list;
                }
            }
        }
        catch { /* restricted platforms: IPv4 + loopback are enough */ }
        return list;
    }
}
