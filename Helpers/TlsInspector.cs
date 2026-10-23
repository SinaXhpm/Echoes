using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
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

public sealed class TlsInspectOptions
{
    /// <summary>Server name to send (SNI) and to check the certificate against; null = the host (none for an IP).</summary>
    public string? Sni { get; init; }
    /// <summary>STARTTLS dialect; null = chosen from the port.</summary>
    public StartTlsKind? StartTls { get; init; }
    /// <summary>Test TLS 1.0 – 1.3 one by one (four extra connections) and read the OCSP staple.</summary>
    public bool ProbeVersions { get; init; } = true;
    public bool CheckHsts { get; init; } = true;
    public bool CheckRevocation { get; init; } = true;
    public int TimeoutMs { get; init; } = 10_000;
    /// <summary>Trust exactly these roots instead of this system's store (the test harness).</summary>
    public X509Certificate2Collection? TrustRoots { get; init; }
    public IProgress<string>? Progress { get; init; }
}

/// <summary>One TLS version's test: Supported true / false, or null when the test itself failed.</summary>
public sealed record TlsVersionResult(ushort Version, bool? Supported, string Detail)
{
    public string Name => TlsHello.VersionName(Version);
}

/// <summary>Everything one inspection found. Errors are worded for the user.</summary>
public sealed class TlsReport
{
    public string Host { get; init; } = string.Empty;
    public int Port { get; init; }
    /// <summary>The server name sent (null: connected to an IP without an override, so no SNI).</summary>
    public string? Sni { get; set; }
    public StartTlsKind StartTls { get; set; }
    public string? Address { get; set; }
    public double ConnectMs { get; set; }
    public double HandshakeMs { get; set; }
    public string? Protocol { get; set; }
    public string? CipherSuite { get; set; }
    public string? Alpn { get; set; }
    public List<TlsChainCert> Chain { get; set; } = new();
    /// <summary>The handshake failed here, and the chain was read from the server's unencrypted hello instead.</summary>
    public bool ChainFromProbe { get; set; }
    public SslPolicyErrors PolicyErrors { get; set; }
    public X509ChainStatusFlags ChainFlags { get; set; }
    public List<TlsProblem> Problems { get; } = new();
    /// <summary>Why no TLS session could be set up (connection, STARTTLS or handshake failure).</summary>
    public string? Error { get; set; }
    /// <summary>The system's own message behind <see cref="Error"/> (for a tooltip), when it adds anything.</summary>
    public string? ErrorDetail { get; set; }
    public List<TlsVersionResult> Versions { get; } = new();
    public string? Hsts { get; set; }
    public TlsSeverity HstsSeverity { get; set; }
    public string? Stapling { get; set; }
    public TlsSeverity StaplingSeverity { get; set; }
    public string? Revocation { get; set; }
    public TlsSeverity RevocationSeverity { get; set; }
    public DateTime CheckedAt { get; } = DateTime.Now;

    public bool Handshaken => Protocol != null;
    public X509Certificate2? Leaf => Chain.Count > 0 ? Chain[0].Cert : null;

    public TlsSeverity Verdict
    {
        get
        {
            if (Error != null || Problems.Any(p => p.Severity == TlsSeverity.Error)) return TlsSeverity.Error;
            return Problems.Any(p => p.Severity == TlsSeverity.Warning) ? TlsSeverity.Warning : TlsSeverity.Ok;
        }
    }
}

/// <summary>
/// The TLS inspector's engine: connects (with STARTTLS when the port calls for it), handshakes with SslStream
/// (offering h2 + http/1.1), keeps the chain and every validation problem, then — in parallel — tests each TLS
/// version with a raw hello (<see cref="TlsHello"/>), reads the OCSP staple, checks revocation online and fetches the
/// HSTS header. UI-free; everything is reported in <see cref="TlsReport"/>.
/// </summary>
public static class TlsInspector
{
    public const int DefaultPort = 443;

    // ------------------------------------------------------------------ target parsing

    /// <summary>
    /// "host", "host:port", "[v6]:port" or a pasted URL ("https://example.com/x" → example.com:443;
    /// "smtp://mail.example.com" → :25). The default port is 443.
    /// </summary>
    public static bool TryParseTarget(string? raw, out string host, out int port, out string? error)
    {
        host = string.Empty;
        port = DefaultPort;
        error = null;
        string s = (raw ?? string.Empty).Trim();
        if (s.Length == 0) { error = "Enter a host name, host:port or URL."; return false; }

        if (s.Contains("://", StringComparison.Ordinal) && Uri.TryCreate(s, UriKind.Absolute, out var uri) && uri.Host.Length > 0)
        {
            host = uri.HostNameType == UriHostNameType.IPv6 ? uri.Host.Trim('[', ']') : uri.IdnHost;
            port = uri.IsDefaultPort || uri.Port <= 0 ? SchemePort(uri.Scheme) : uri.Port;
            return true;
        }
        if (HostExtractor.Best(s) is { } f)
        {
            host = f.Host;
            port = f.Port ?? DefaultPort;
            return true;
        }
        if (s.Contains(' ') || s.Contains('/'))
        {
            error = $"\"{s}\" isn't a host name, host:port or URL.";
            return false;
        }
        host = s;
        return true;
    }

    private static int SchemePort(string scheme) => scheme.ToLowerInvariant() switch
    {
        "smtps" => 465,
        "smtp" => 25,
        "submission" => 587,
        "imaps" => 993,
        "imap" => 143,
        "pop3s" => 995,
        "pop3" => 110,
        "ftps" => 990,
        "ftp" => 21,
        "ldaps" => 636,
        _ => DefaultPort,   // https, wss — and http: a TLS inspector means the HTTPS side
    };

    // ------------------------------------------------------------------ inspection

    public static async Task<TlsReport> InspectAsync(string host, int port, TlsInspectOptions o, CancellationToken ct)
    {
        host = host.Trim().Trim('[', ']');
        var rep = new TlsReport { Host = host, Port = port };
        string target = SocketNet.Target(host, port);
        var kind = o.StartTls ?? TlsStartTls.ForPort(port);
        rep.StartTls = kind;
        bool hostIsIp = IPAddress.TryParse(host, out _);
        string? sniOverride = string.IsNullOrWhiteSpace(o.Sni) ? null : SocketNet.AsciiHost(o.Sni.Trim());
        rep.Sni = sniOverride ?? (hostIsIp ? null : SocketNet.AsciiHost(host));
        string checkName = rep.Sni ?? host;

        // ---- connect
        o.Progress?.Report($"Connecting to {target}…");
        Socket socket;
        try { (socket, rep.ConnectMs) = await SocketNet.ConnectTcpTimedAsync(host, port, o.TimeoutMs, ct).ConfigureAwait(false); }
        catch (SocketFailure f) { rep.Error = f.Message; return rep; }
        var remote = SocketNet.Normalize((IPEndPoint)socket.RemoteEndPoint!);
        rep.Address = remote.Address.ToString();
        var ip = ((IPEndPoint)socket.RemoteEndPoint!).Address;

        // ---- STARTTLS + handshake
        Exception? handshakeError = null;
        List<TlsChainCert>? snap = null;
        var flags = X509ChainStatusFlags.NoError;
        var policy = SslPolicyErrors.None;
        await using (var ns = new NetworkStream(socket, ownsSocket: true))
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(o.TimeoutMs);
            try
            {
                if (kind != StartTlsKind.None)
                {
                    o.Progress?.Report($"STARTTLS ({TlsStartTls.Name(kind)})…");
                    await TlsStartTls.NegotiateAsync(ns, kind, cts.Token).ConfigureAwait(false);
                }
                o.Progress?.Report("TLS handshake…");
                await using var ssl = new SslStream(ns, leaveInnerStreamOpen: true, (_, cert, chain, errors) =>
                {
                    try
                    {
                        snap = TlsCertificates.Snapshot(cert, chain);
                        flags = TlsCertificates.Flags(chain);
                        policy = errors;
                    }
                    catch { policy = errors; }
                    return true;   // an inspector looks at bad certificates too; nothing but a HEAD request is ever sent
                });
                var options = new SslClientAuthenticationOptions
                {
                    TargetHost = checkName,
                    EnabledSslProtocols = SslProtocols.None,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                    ApplicationProtocols = kind == StartTlsKind.None
                        ? new List<SslApplicationProtocol> { SslApplicationProtocol.Http2, SslApplicationProtocol.Http11 }
                        : null,
                };
                if (o.TrustRoots is { Count: > 0 } roots)
                {
                    var p = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust, RevocationMode = X509RevocationMode.NoCheck };
                    p.CustomTrustStore.AddRange(roots);
                    options.CertificateChainPolicy = p;
                }
                var hsw = Stopwatch.StartNew();
                await ssl.AuthenticateAsClientAsync(options, cts.Token).ConfigureAwait(false);
                rep.HandshakeMs = hsw.Elapsed.TotalMilliseconds;
                rep.Protocol = TlsCertificates.ProtocolName(ssl.SslProtocol);
                try { rep.CipherSuite = ssl.NegotiatedCipherSuite.ToString(); } catch { /* not reported here */ }
                try
                {
                    var alpn = ssl.NegotiatedApplicationProtocol;
                    rep.Alpn = alpn.Protocol.Length > 0 ? alpn.ToString() : null;
                }
                catch { }
            }
            catch (SocketFailure f) { rep.Error = f.Message; }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { handshakeError = new TimeoutException(); }
            catch (Exception ex) when (ex is not OperationCanceledException) { handshakeError = ex; }
        }
        ct.ThrowIfCancellationRequested();
        if (handshakeError != null)
        {
            rep.Error = SocketErrors.Describe(handshakeError, SocketAction.Tls, target, port);
            rep.ErrorDetail = Innermost(handshakeError);
        }
        if (snap is { Count: > 0 })
        {
            rep.Chain = snap;
            rep.ChainFlags = flags;
            rep.PolicyErrors = policy;
        }

        // ---- in parallel: version tests (+ the staple), revocation, HSTS
        o.Progress?.Report(o.ProbeVersions ? "Testing TLS versions, revocation and HSTS…" : "Checking…");
        bool startTlsFailed = rep.Error != null && handshakeError == null;   // each test would fail the same way
        var versions = startTlsFailed ? Array.Empty<ushort>()
                     : o.ProbeVersions ? new[] { TlsHello.Tls13, TlsHello.Tls12, TlsHello.Tls11, TlsHello.Tls10 }
                     : handshakeError != null ? new[] { TlsHello.Tls12 } : Array.Empty<ushort>();
        var probeTasks = versions.Select(v => ProbeAsync(ip, port, kind, rep.Sni, v, Math.Min(o.TimeoutMs, 8000), ct)).ToArray();
        bool https = kind == StartTlsKind.None && rep.Handshaken
                     && (rep.Alpn is "h2" or "http/1.1" || port is 443 or 8443 or 4443 or 9443);
        string hostHeader = (rep.Sni ?? (hostIsIp && host.Contains(':') ? $"[{host}]" : host)) + (port == 443 ? "" : ":" + port.ToString(CultureInfo.InvariantCulture));
        var hstsTask = o.CheckHsts && https ? HstsAsync(ip, port, rep.Sni ?? host, hostHeader, Math.Min(o.TimeoutMs, 8000), ct) : null;

        var probes = await Task.WhenAll(probeTasks).ConfigureAwait(false);
        for (int i = 0; i < versions.Length; i++)
            if (o.ProbeVersions) rep.Versions.Add(Interpret(versions[i], probes[i].Result, probes[i].Error));

        // our own TLS stack failed: explain with what the raw hellos saw, and read the chain from them
        if (handshakeError != null)
        {
            var notTls = probes.Select(p => p.Result?.NotTls).FirstOrDefault(t => t != null);
            var supported = rep.Versions.Where(v => v.Supported == true).Select(v => v.Version).ToList();
            if (!o.ProbeVersions)
                supported = probes.Where(p => p.Result is { GotServerHello: true }).Select(p => p.Result!.Version).Distinct().ToList();
            if (notTls != null)
                rep.Error = $"{target} isn't speaking TLS — it answered \"{notTls}\".";
            else if (supported.Count > 0 && supported.All(v => v <= TlsHello.Tls11))
                rep.Error = $"{target} only offers {string.Join(" / ", supported.OrderByDescending(v => v).Select(TlsHello.VersionName))}, which this system's TLS stack has turned off — the handshake can't complete here. The certificate below was read from the unencrypted part of the handshake.";
            else if (supported.Count > 0 && rep.Error != null && rep.Error.Contains("isn't speaking TLS", StringComparison.Ordinal))
                // the raw hellos got a ServerHello, so it does speak TLS: this system's own stack gave up
                rep.Error = $"This system's TLS stack couldn't complete the handshake with {target}, although the server answers {string.Join(" / ", supported.OrderByDescending(v => v).Select(TlsHello.VersionName))} hellos: {rep.ErrorDetail ?? "no reason given"}";
            else if (supported.Count > 0 && rep.Error != null && rep.Error.Contains("closed the connection during the TLS handshake", StringComparison.Ordinal))
                // it answered a plain hello, yet this system's handshake was cut off: typically a filter on the path
                rep.Error = $"The TLS handshake with {target} was cut off (the connection was reset), although the server answers {string.Join(" / ", supported.OrderByDescending(v => v).Select(TlsHello.VersionName))} hellos — a firewall or filter on the network may be interfering, or the server rejected this system's TLS settings.";
            if (rep.Chain.Count == 0 && probes.Select(p => p.Result).FirstOrDefault(r => r is { Certificates.Count: > 0 }) is { } withCerts)
            {
                try { ValidateOffline(rep, withCerts.Certificates, checkName, o.TrustRoots); rep.ChainFromProbe = true; }
                catch { /* unreadable certificate */ }
            }
        }

        Task<(string, TlsSeverity)>? revTask = o.CheckRevocation && rep.Chain.Count > 0
            ? Task.Run(() => CheckRevocation(rep.Chain, o.TrustRoots), ct)
            : null;

        // the staple (asked for in the TLS 1.2 hello)
        if (o.ProbeVersions)
        {
            int i12 = Array.IndexOf(versions, TlsHello.Tls12);
            var r12 = i12 >= 0 ? probes[i12].Result : null;
            if (r12 is { GotServerHello: true } && r12.Version == TlsHello.Tls12)
            {
                if (r12.OcspResponse is { } der)
                {
                    var st = TlsHello.ParseOcsp(der, SerialBytes(rep.Leaf));
                    (rep.Stapling, rep.StaplingSeverity) = st switch
                    {
                        null => ("Stapled, but the response couldn't be read", TlsSeverity.Warning),
                        { Status: "good" } => ($"Stapled · good · produced {Ago(st.ProducedAt ?? st.ThisUpdate)}" + (st.NextUpdate is { } nu ? " · valid until " + nu.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : ""), TlsSeverity.Ok),
                        { Status: "revoked" } => ($"Stapled · REVOKED" + (st.RevokedAt is { } ra ? " on " + ra.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : ""), TlsSeverity.Error),
                        _ => ($"Stapled · {st.Status}", TlsSeverity.Warning),
                    };
                    if (st is { Status: "revoked" })
                        rep.Problems.Add(new TlsProblem(TlsSeverity.Error, "The stapled OCSP response says the certificate is revoked."));
                }
                else if (r12.StaplingAcknowledged)
                    (rep.Stapling, rep.StaplingSeverity) = ("Promised, but no response was sent", TlsSeverity.Warning);
                else
                    (rep.Stapling, rep.StaplingSeverity) = ("Not stapled — clients have to ask the CA themselves", TlsSeverity.Info);
            }
            else if (rep.Versions.Any(v => v.Version == TlsHello.Tls13 && v.Supported == true) && !rep.Versions.Any(v => v.Version < TlsHello.Tls13 && v.Supported == true))
                (rep.Stapling, rep.StaplingSeverity) = ("Can't be seen — TLS 1.3 only, where the staple travels encrypted", TlsSeverity.Info);
        }

        if (revTask != null)
        {
            try { (rep.Revocation, rep.RevocationSeverity) = await revTask.ConfigureAwait(false); }
            catch (OperationCanceledException) { throw; }
            catch { (rep.Revocation, rep.RevocationSeverity) = ("Couldn't be checked on this system", TlsSeverity.Info); }
        }
        if (hstsTask != null) (rep.Hsts, rep.HstsSeverity) = await hstsTask.ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();

        // ---- verdict
        if (rep.Chain.Count > 0)
            rep.Problems.AddRange(TlsCertificates.Assess(rep.Chain, rep.ChainFlags, rep.PolicyErrors, checkName, DateTime.UtcNow));
        if (rep.RevocationSeverity == TlsSeverity.Error && !rep.Problems.Any(p => p.Text.Contains("revoked", StringComparison.OrdinalIgnoreCase)))
            rep.Problems.Add(new TlsProblem(TlsSeverity.Error, "The certificate has been revoked by its issuer."));
        var old = rep.Versions.Where(v => v.Supported == true && v.Version <= TlsHello.Tls11).Select(v => v.Name).ToList();
        if (old.Count > 0)
            rep.Problems.Add(new TlsProblem(TlsSeverity.Warning, $"Still accepts {string.Join(" and ", old)} — deprecated (RFC 8996), and refused by current browsers."));
        rep.Problems.Sort((a, b) => b.Severity.CompareTo(a.Severity));
        return rep;
    }

    /// <summary>The bulk check: one handshake per host (no version tests, revocation or HSTS).</summary>
    public static Task<TlsReport> QuickAsync(string host, int port, int timeoutMs, CancellationToken ct, X509Certificate2Collection? trustRoots = null)
        => InspectAsync(host, port, new TlsInspectOptions
        {
            ProbeVersions = false,
            CheckHsts = false,
            CheckRevocation = false,
            TimeoutMs = timeoutMs,
            TrustRoots = trustRoots,
        }, ct);

    // ------------------------------------------------------------------ pieces

    private static async Task<(TlsHelloResult? Result, string? Error)> ProbeAsync(IPAddress ip, int port, StartTlsKind kind, string? sni,
                                                                                   ushort version, int timeoutMs, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        using var s = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await s.ConnectAsync(new IPEndPoint(ip, port), cts.Token).ConfigureAwait(false);
            await using var ns = new NetworkStream(s, ownsSocket: false);
            if (kind != StartTlsKind.None) await TlsStartTls.NegotiateAsync(ns, kind, cts.Token).ConfigureAwait(false);
            var r = await TlsHello.ExchangeAsync(ns, version, sni, statusRequest: version == TlsHello.Tls12, cts.Token).ConfigureAwait(false);
            return (r, null);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return (null, "no answer (timed out)"); }
        catch (OperationCanceledException) { throw; }
        catch (SocketFailure f) { return (null, f.Message); }
        catch (Exception ex)
        {
            var e = SocketErrors.Unwrap(ex);
            if (e is SocketException { SocketErrorCode: SocketError.ConnectionReset or SocketError.ConnectionAborted })
                return (new TlsHelloResult { Closed = true }, null);
            return (null, SocketErrors.Describe(ex, SocketAction.Connect, SocketNet.Target(ip.ToString(), port), port));
        }
    }

    private static TlsVersionResult Interpret(ushort v, TlsHelloResult? r, string? error)
    {
        if (r == null) return new TlsVersionResult(v, null, error ?? "no answer");
        if (r.GotServerHello)
        {
            if (r.Version == v) return new TlsVersionResult(v, true, r.HelloRetry ? "supported (the server asked for another key share)" : "supported");
            return new TlsVersionResult(v, false, $"not supported — offered only {TlsHello.VersionName(v)}, the server answered with {TlsHello.VersionName(r.Version)}");
        }
        if (r.Alert is byte a)
            return new TlsVersionResult(v, false, $"not supported — the server answered \"{TlsHello.AlertName(a)}\"");
        if (r.NotTls != null) return new TlsVersionResult(v, null, $"not TLS — the server answered \"{r.NotTls}\"");
        if (r.Closed) return new TlsVersionResult(v, false, "not supported — the server closed the connection");
        return new TlsVersionResult(v, null, "no usable answer");
    }

    // The chain from a raw hello (our own stack couldn't complete the handshake): validate it like SslStream would.
    private static void ValidateOffline(TlsReport rep, List<byte[]> certs, string checkName, X509Certificate2Collection? roots)
    {
        var leaf = TlsCertificates.Load(certs[0]);
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));   // TLS server authentication
        foreach (var raw in certs.Skip(1)) chain.ChainPolicy.ExtraStore.Add(TlsCertificates.Load(raw));
        if (roots is { Count: > 0 })
        {
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.AddRange(roots);
        }
        bool ok = chain.Build(leaf);
        var errors = ok ? SslPolicyErrors.None : SslPolicyErrors.RemoteCertificateChainErrors;
        if (!TlsCertificates.Covers(leaf, checkName)) errors |= SslPolicyErrors.RemoteCertificateNameMismatch;
        rep.Chain = TlsCertificates.Snapshot(leaf, chain);
        rep.ChainFlags = TlsCertificates.Flags(chain);
        rep.PolicyErrors = errors;
    }

    // Online CRL / OCSP check of the chain (the handshake itself doesn't check revocation).
    private static (string, TlsSeverity) CheckRevocation(List<TlsChainCert> chainCerts, X509Certificate2Collection? roots)
    {
        var leaf = chainCerts[0].Cert;
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(8);
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority
                                              | X509VerificationFlags.IgnoreNotTimeValid;
        foreach (var c in chainCerts.Skip(1)) chain.ChainPolicy.ExtraStore.Add(c.Cert);
        if (roots is { Count: > 0 })
        {
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.AddRange(roots);
        }
        chain.Build(leaf);
        var flags = TlsCertificates.Flags(chain);
        if ((flags & X509ChainStatusFlags.Revoked) != 0) return ("REVOKED by its issuer", TlsSeverity.Error);
        if ((flags & (X509ChainStatusFlags.RevocationStatusUnknown | X509ChainStatusFlags.OfflineRevocation)) != 0)
        {
            bool hasUrls = TlsCertificates.OcspUrls(leaf).Count > 0
                           || leaf.Extensions.Cast<X509Extension>().Any(e => e.Oid?.Value == "2.5.29.31");
            return hasUrls
                ? ("Unknown — the CA's CRL / OCSP server couldn't be reached", TlsSeverity.Warning)
                : ("Can't be checked — the certificate names no CRL or OCSP server", TlsSeverity.Info);
        }
        return ("Not revoked (checked online)", TlsSeverity.Ok);
    }

    // HEAD / over a fresh TLS connection (HTTP/1.1 only), for the Strict-Transport-Security header.
    private static async Task<(string, TlsSeverity)> HstsAsync(IPAddress ip, int port, string sni, string hostHeader, int timeoutMs, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        try
        {
            using var s = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            await s.ConnectAsync(new IPEndPoint(ip, port), cts.Token).ConfigureAwait(false);
            await using var ns = new NetworkStream(s, ownsSocket: false);
            await using var ssl = new SslStream(ns, false, (_, _, _, _) => true);
            try
            {
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = sni,
                    ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http11 },
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                }, cts.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // the inspection's own handshake already worked, so a failure here is about this second connection
                return ("Couldn't be checked — the handshake for the HTTP request (a second connection, HTTP/1.1) failed; the server may only speak HTTP/2, or the network interfered", TlsSeverity.Info);
            }
            string req = $"HEAD / HTTP/1.1\r\nHost: {hostHeader}\r\nUser-Agent: Echoes-TLS-Inspector\r\nAccept: */*\r\nConnection: close\r\n\r\n";
            await ssl.WriteAsync(Encoding.ASCII.GetBytes(req), cts.Token).ConfigureAwait(false);
            await ssl.FlushAsync(cts.Token).ConfigureAwait(false);

            var buf = new byte[16 * 1024];
            int n = 0;
            while (n < buf.Length)
            {
                int r = await ssl.ReadAsync(buf.AsMemory(n), cts.Token).ConfigureAwait(false);
                if (r == 0) break;
                n += r;
                if (buf.AsSpan(0, n).IndexOf("\r\n\r\n"u8) >= 0) break;
            }
            string head = Encoding.Latin1.GetString(buf, 0, n);
            int end = head.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (end >= 0) head = head[..end];
            var lines = head.Split("\r\n");
            if (lines.Length == 0 || !lines[0].StartsWith("HTTP/", StringComparison.Ordinal))
                return ("Couldn't be checked — the server didn't answer an HTTP request", TlsSeverity.Info);
            string status = lines[0].Split(' ', 3) is { Length: >= 2 } parts ? "HTTP " + parts[1] : lines[0];
            string? value = lines.Skip(1)
                .Select(l => l.Split(':', 2))
                .Where(p => p.Length == 2 && p[0].Trim().Equals("Strict-Transport-Security", StringComparison.OrdinalIgnoreCase))
                .Select(p => p[1].Trim())
                .FirstOrDefault();
            if (value == null) return ($"Not set ({status}) — browsers may still try plain HTTP first", TlsSeverity.Warning);
            return DescribeHsts(value);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return ("Couldn't be checked — the HTTP request timed out", TlsSeverity.Info);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            return ("Couldn't be checked — " + SocketErrors.Describe(ex, SocketAction.Tls, hostHeader).TrimEnd('.'), TlsSeverity.Info);
        }
    }

    /// <summary>"max-age=31536000; includeSubDomains; preload" → "1 year · includes subdomains · preload".</summary>
    public static (string, TlsSeverity) DescribeHsts(string value)
    {
        long maxAge = -1;
        bool sub = false, preload = false;
        foreach (var raw in value.Split(';'))
        {
            string d = raw.Trim();
            if (d.StartsWith("max-age", StringComparison.OrdinalIgnoreCase))
            {
                int eq = d.IndexOf('=');
                if (eq > 0) long.TryParse(d[(eq + 1)..].Trim().Trim('"'), NumberStyles.None, CultureInfo.InvariantCulture, out maxAge);
            }
            else if (d.Equals("includeSubDomains", StringComparison.OrdinalIgnoreCase)) sub = true;
            else if (d.Equals("preload", StringComparison.OrdinalIgnoreCase)) preload = true;
        }
        if (maxAge == 0) return ("Switched off (max-age=0)", TlsSeverity.Warning);
        if (maxAge < 0) return ($"Malformed: {value}", TlsSeverity.Warning);
        var parts = new List<string> { "max-age " + Duration(maxAge) };
        if (sub) parts.Add("includes subdomains");
        if (preload) parts.Add("preload");
        return (string.Join(" · ", parts), maxAge < 180L * 86400 ? TlsSeverity.Warning : TlsSeverity.Ok);
    }

    private static string Duration(long seconds)
    {
        double days = seconds / 86400.0;
        if (days >= 365) return TlsCertificates.Plural((int)Math.Round(days / 365.25), "year");
        if (days >= 1) return TlsCertificates.Plural((int)Math.Round(days), "day");
        return TlsCertificates.Plural((int)Math.Max(1, seconds / 60), "minute");
    }

    private static string Ago(DateTime? utc)
    {
        if (utc is not { } t) return "at an unknown time";
        var d = DateTime.UtcNow - t;
        if (d.TotalMinutes < 2) return "just now";
        if (d.TotalHours < 2) return $"{(int)d.TotalMinutes} min ago";
        if (d.TotalDays < 2) return $"{(int)d.TotalHours} h ago";
        return $"{(int)d.TotalDays} days ago";
    }

    private static string Innermost(Exception ex)
    {
        var e = ex;
        while (e.InnerException != null) e = e.InnerException;
        string m = e.Message.Trim();
        return m.Length == 0 ? e.GetType().Name : m;
    }

    private static byte[]? SerialBytes(X509Certificate2? c)
    {
        if (c == null) return null;
        try { return Convert.FromHexString(c.SerialNumber.Length % 2 == 0 ? c.SerialNumber : "0" + c.SerialNumber); }
        catch { return null; }
    }
}
