using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

public enum DoctorTlsOutcome
{
    /// <summary>Handshake done, certificate fine.</summary>
    Ok,
    /// <summary>Handshake done, but browsers would refuse the certificate (expired, wrong name, untrusted).</summary>
    CertProblem,
    /// <summary>Cut when the site's name is in the hello, answered without it / with another name.</summary>
    SniFiltered,
    /// <summary>Every hello to this address is cut, whatever the name: the address (or TLS to it) is blocked.</summary>
    AllCut,
    /// <summary>This system's handshake is cut, though a simple hello with the same name gets an answer.</summary>
    HandshakeCut,
    /// <summary>The server answered with a TLS alert (no common version / cipher, unknown name, …).</summary>
    ServerRefused,
    /// <summary>Something else answers on the port.</summary>
    NotTls,
}

public sealed class DoctorTlsResult
{
    public DoctorTlsOutcome Outcome { get; set; }
    public string? Protocol { get; set; }
    public double HandshakeMs { get; set; }
    public List<TlsProblem> Problems { get; } = new();
    /// <summary>"valid · 89 days left · Let's Encrypt" (the handshake worked).</summary>
    public string? CertText { get; set; }
    /// <summary>Why it failed, one sentence.</summary>
    public string? Error { get; set; }
    /// <summary>What a non-TLS service said ("SSH-2.0-OpenSSH_9.6").</summary>
    public string? NotTlsText { get; set; }
    public bool Expired { get; set; }

    // ---- stage detail for the granular trace (filled when the handshake got that far) ----
    /// <summary>The leaf certificate's subject ("CN example.com").</summary>
    public string? CertSubject { get; set; }
    /// <summary>The leaf certificate's issuer ("Let's Encrypt").</summary>
    public string? CertIssuer { get; set; }
    /// <summary>The certificate names the site (a SAN or CN covers it): true / false, null when there was no certificate.</summary>
    public bool? CoversName { get; set; }
    /// <summary>How a cut handshake was cut: "reset" (RST right after the ClientHello) or "silent" (no answer).</summary>
    public string? CutHow { get; set; }
    /// <summary>A hello without the site's name (or with a harmless one) got a TLS answer: the address speaks TLS.</summary>
    public bool? BaselineAnswered { get; set; }
}

/// <summary>Which way a raw ClientHello went.</summary>
public enum DoctorHello { Answered, Cut, NotTls, NoConnect }

/// <summary>
/// The Doctor's TLS check. Before the real handshake, two raw hellos (no SNI, a harmless SNI) record whether the server's
/// TLS answers at all — before a filter that blocks an address for a while after a forbidden name could spoil them. Then
/// the real handshake with SNI = the site's name; when that is cut (reset, EOF, silence), a raw hello with the same name
/// tells SNI filtering (only the name is cut) from a blocked address (everything is cut) and from a handshake this
/// system's TLS stack can't do. Certificate problems are reported apart from blocking.
/// </summary>
public static class DoctorTls
{
    public static async Task<DoctorTlsResult> CheckAsync(IPAddress addr, int port, string? sni, string harmlessSni,
                                                         X509Certificate2Collection? roots, CancellationToken ct)
    {
        var res = new DoctorTlsResult();
        string target = DoctorIp.EndPoint(addr, port);

        // ---- the baseline: does this address answer a hello without the site's name
        (DoctorHello State, string? Text)[] baseline = Array.Empty<(DoctorHello, string?)>();
        if (sni != null)
        {
            baseline = await Task.WhenAll(
                HelloAsync(addr, port, null, 4000, ct),
                HelloAsync(addr, port, harmlessSni, 4000, ct)).ConfigureAwait(false);
        }
        bool baselineAnswered = baseline.Any(b => b.State == DoctorHello.Answered);
        if (sni != null) res.BaselineAnswered = baselineAnswered;
        if (baseline.Length > 0 && baseline.All(b => b.State == DoctorHello.NotTls))
        {
            res.Outcome = DoctorTlsOutcome.NotTls;
            res.NotTlsText = baseline[0].Text;
            res.Error = $"{target} isn't speaking TLS" + (baseline[0].Text is { } t ? $" — it answered \"{t}\"" : "") + ".";
            return res;
        }

        // ---- the real handshake, with the name
        Exception? failure = null;
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(6000);
            using var s = new Socket(addr.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            await s.ConnectAsync(new IPEndPoint(addr, port), cts.Token).ConfigureAwait(false);
            await using var ns = new NetworkStream(s, ownsSocket: false);
            failure = await HandshakeAsync(ns, sni, sni ?? addr.ToString(), roots, res, cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { failure = new TimeoutException(); }
        catch (OperationCanceledException) { throw; }
        catch (Exception e) { failure = e; }

        if (failure == null) return res;

        // ---- it failed: refused by the server, not TLS, or cut
        var kind = Classify(failure);
        if (kind == DoctorHello.NotTls)
        {
            res.Outcome = DoctorTlsOutcome.NotTls;
            res.Error = $"{target} isn't speaking TLS.";
            return res;
        }
        if (kind == DoctorHello.Answered)
        {
            res.Outcome = DoctorTlsOutcome.ServerRefused;
            res.Error = SocketErrors.TlsFailure(failure, sni ?? target);
            return res;
        }

        string how = failure is TimeoutException ? "went silent" : "was cut (reset)";
        res.CutHow = failure is TimeoutException ? "silent" : "reset";
        if (sni == null)
        {
            res.Outcome = DoctorTlsOutcome.AllCut;
            res.Error = $"The TLS handshake with {target} {how}.";
            return res;
        }
        // the same name in a plain hello: cut again → it's the name; answered → this system's handshake in particular
        var confirm = await HelloAsync(addr, port, sni, 4000, ct).ConfigureAwait(false);
        if (!baselineAnswered)
        {
            res.Outcome = DoctorTlsOutcome.AllCut;
            res.Error = "Cut with or without the name: the address is blocked for TLS (or the server is broken).";
        }
        else if (confirm.State == DoctorHello.Answered)
        {
            res.Outcome = DoctorTlsOutcome.HandshakeCut;
            res.Error = $"This system's handshake {how}, though a simple hello gets through: a filter may match its fingerprint.";
        }
        else
        {
            res.Outcome = DoctorTlsOutcome.SniFiltered;
            res.Error = "Cut when the name is sent, answered without it.";
        }
        return res;
    }

    /// <summary>
    /// One TLS handshake over <paramref name="stream"/> (a socket, or a proxy's tunnel) with SNI <paramref name="sni"/>.
    /// On success it fills <paramref name="res"/> (protocol, time, certificate problems, outcome Ok / CertProblem) and
    /// returns null; otherwise the exception. Only the handshake happens: the stream is not used afterwards.
    /// </summary>
    internal static async Task<Exception?> HandshakeAsync(Stream stream, string? sni, string checkName, X509Certificate2Collection? roots,
                                                          DoctorTlsResult res, CancellationToken ct)
    {
        List<TlsChainCert>? snap = null;
        var flags = X509ChainStatusFlags.NoError;
        var policy = SslPolicyErrors.None;
        try
        {
            await using var ssl = new SslStream(stream, leaveInnerStreamOpen: true, (_, cert, chain, errors) =>
            {
                try
                {
                    snap = TlsCertificates.Snapshot(cert, chain);
                    flags = TlsCertificates.Flags(chain);
                }
                catch { }
                policy = errors;
                return true;   // judged below, apart from blocking
            });
            var options = new SslClientAuthenticationOptions
            {
                TargetHost = sni ?? checkName,
                EnabledSslProtocols = SslProtocols.None,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http2, SslApplicationProtocol.Http11 },
            };
            if (roots is { Count: > 0 })
            {
                var p = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust, RevocationMode = X509RevocationMode.NoCheck };
                p.CustomTrustStore.AddRange(roots);
                options.CertificateChainPolicy = p;
            }
            var sw = Stopwatch.StartNew();
            await ssl.AuthenticateAsClientAsync(options, ct).ConfigureAwait(false);
            res.HandshakeMs = sw.Elapsed.TotalMilliseconds;
            res.Protocol = TlsCertificates.ProtocolName(ssl.SslProtocol);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception e) { return e; }

        if (snap is { Count: > 0 })
        {
            res.Problems.AddRange(TlsCertificates.Assess(snap, flags, policy, checkName, DateTime.UtcNow));
            var leaf = snap[0].Cert;
            res.Expired = DateTime.UtcNow > leaf.NotAfter.ToUniversalTime();
            string org = TlsCertificates.DnPart(leaf.IssuerName, "O");
            string issuer = org.Length > 0 ? org : TlsCertificates.DnPart(leaf.IssuerName, "CN");
            res.CertText = TlsCertificates.ExpiryPhrase(leaf, DateTime.UtcNow) + (issuer.Length > 0 ? $" · {issuer}" : "");
            res.CertSubject = TlsCertificates.ShortName(leaf);
            res.CertIssuer = issuer;
            if (!IPAddress.TryParse(checkName.Trim('[', ']'), out _)) res.CoversName = TlsCertificates.Covers(leaf, checkName);
        }
        res.Outcome = res.Problems.Any(p => p.Severity == TlsSeverity.Error) ? DoctorTlsOutcome.CertProblem : DoctorTlsOutcome.Ok;
        return null;
    }

    /// <summary>The TLS check over an already open tunnel (a proxy): the handshake with the site's name, and how it
    /// failed — cut, refused by the server, or not TLS. (No SNI comparison: the proxy's own network carries it.)</summary>
    public static async Task<DoctorTlsResult> OverStreamAsync(Stream stream, string? sni, string checkName, X509Certificate2Collection? roots,
                                                              int timeoutMs, CancellationToken ct)
    {
        var res = new DoctorTlsResult();
        Exception? failure;
        using (var cts = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            cts.CancelAfter(timeoutMs);
            try { failure = await HandshakeAsync(stream, sni, checkName, roots, res, cts.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { failure = new TimeoutException(); }
        }
        if (failure == null) return res;
        switch (Classify(failure))
        {
            case DoctorHello.NotTls:
                res.Outcome = DoctorTlsOutcome.NotTls;
                res.Error = "the other end isn't speaking TLS";
                break;
            case DoctorHello.Answered:
                res.Outcome = DoctorTlsOutcome.ServerRefused;
                res.Error = SocketErrors.TlsFailure(failure, checkName);
                break;
            default:
                res.Outcome = DoctorTlsOutcome.AllCut;
                res.Error = failure is TimeoutException ? "the handshake went silent" : "the handshake was cut (reset)";
                break;
        }
        return res;
    }

    /// <summary>Does the server at <paramref name="addr"/> serve <paramref name="host"/> (a certificate for that name)?
    /// true / false, or null when no TLS connection could be made.</summary>
    public static async Task<bool?> ServesAsync(IPAddress addr, int port, string host, int timeoutMs, CancellationToken ct)
    {
        X509Certificate2? leaf = null;
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeoutMs);
            using var s = new Socket(addr.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            await s.ConnectAsync(new IPEndPoint(addr, port), cts.Token).ConfigureAwait(false);
            await using var ns = new NetworkStream(s, ownsSocket: false);
            await using var ssl = new SslStream(ns, false, (_, cert, _, _) =>
            {
                try { if (cert != null) leaf = TlsCertificates.Load(cert.GetRawCertData()); } catch { }
                return true;
            });
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = host,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            }, cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return leaf == null ? null : TlsCertificates.Covers(leaf, host); }
        return leaf == null ? null : TlsCertificates.Covers(leaf, host);
    }

    /// <summary>A raw TLS 1.2 ClientHello (the widest accepted) with <paramref name="sni"/>: did the server's TLS answer
    /// (a ServerHello or an alert both count), or was the connection cut?</summary>
    public static async Task<(DoctorHello State, string? Text)> HelloAsync(IPAddress addr, int port, string? sni, int timeoutMs, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        using var s = new Socket(addr.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await s.ConnectAsync(new IPEndPoint(addr, port), cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return (DoctorHello.NoConnect, null); }
        try
        {
            await using var ns = new NetworkStream(s, ownsSocket: false);
            var r = await TlsHello.ExchangeAsync(ns, TlsHello.Tls12, sni, statusRequest: false, cts.Token).ConfigureAwait(false);
            if (r.GotServerHello || r.Alert != null) return (DoctorHello.Answered, null);
            if (r.NotTls != null) return (DoctorHello.NotTls, r.NotTls);
            return (DoctorHello.Cut, null);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return (DoctorHello.Cut, null); }   // reset, or silence until the deadline
    }

    // A failed handshake: cut (reset / EOF / silence), refused by the server's TLS (an alert), or not TLS at all.
    private static DoctorHello Classify(Exception ex)
    {
        if (ex is TimeoutException) return DoctorHello.Cut;
        for (var e = ex; e != null; e = e.InnerException)
        {
            if (e is SocketException) return DoctorHello.Cut;
            if (e is IOException io && (io.Message.Contains("EOF", StringComparison.OrdinalIgnoreCase)
                                        || io.Message.Contains("0 bytes", StringComparison.Ordinal)
                                        || io.Message.Contains("forcibly closed", StringComparison.OrdinalIgnoreCase)
                                        || io.Message.Contains("transport", StringComparison.OrdinalIgnoreCase)))
                return DoctorHello.Cut;
        }
        string sentence = SocketErrors.TlsFailure(ex, "x");
        if (sentence.Contains("isn't speaking TLS", StringComparison.Ordinal)) return DoctorHello.NotTls;
        if (sentence.Contains("closed the connection", StringComparison.Ordinal)) return DoctorHello.Cut;
        return DoctorHello.Answered;
    }
}
