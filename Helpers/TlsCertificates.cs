using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Echoes.Helpers;

public enum TlsSeverity { Ok = 0, Info = 1, Warning = 2, Error = 3 }

/// <summary>One finding about a certificate / chain / connection, worded for the user.</summary>
public sealed record TlsProblem(TlsSeverity Severity, string Text)
{
    public bool IsError => Severity == TlsSeverity.Error;
    public bool IsWarning => Severity == TlsSeverity.Warning;
}

/// <summary>A certificate of the chain as built at handshake time (leaf first) with its own chain status.</summary>
public sealed record TlsChainCert(X509Certificate2 Cert, X509ChainStatusFlags Status, bool FromServer);

/// <summary>
/// Certificate facts and verdicts in plain words: names, SANs, key, signature algorithm, fingerprints, PEM, and the
/// list of problems (name mismatch, untrusted / self-signed, expired, not yet valid, incomplete chain, revoked …).
/// Shared by the TLS inspector and the Socket tool's TLS option. UI-free.
/// </summary>
public static class TlsCertificates
{
    public const int ExpiryWarningDays = 30;

    /// <summary>A certificate from its DER bytes (the .NET 9+ loader where available).</summary>
    public static X509Certificate2 Load(byte[] raw)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadCertificate(raw);
#else
        return new X509Certificate2(raw);
#endif
    }

    /// <summary>
    /// Copies the chain .NET built for the handshake (its elements are disposed after the validation callback),
    /// marking which certificates the server itself sent (they are in the chain's extra store; the root normally
    /// comes from this system's trust store).
    /// </summary>
    public static List<TlsChainCert> Snapshot(X509Certificate? leaf, X509Chain? chain)
    {
        var list = new List<TlsChainCert>();
        var sent = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            if (chain?.ChainPolicy.ExtraStore is { } extra)
                foreach (var c in extra) sent.Add(c.Thumbprint);
        }
        catch { /* platform without an extra store */ }

        if (chain is { ChainElements.Count: > 0 })
        {
            foreach (var el in chain.ChainElements)
            {
                var flags = X509ChainStatusFlags.NoError;
                foreach (var st in el.ChainElementStatus) flags |= st.Status;
                var copy = Load(el.Certificate.RawData);
                bool fromServer = list.Count == 0 || sent.Contains(copy.Thumbprint);
                list.Add(new TlsChainCert(copy, flags, fromServer));
            }
        }
        else if (leaf != null)
        {
            list.Add(new TlsChainCert(Load(leaf.GetRawCertData()), X509ChainStatusFlags.NoError, true));
        }
        return list;
    }

    /// <summary>The overall status of a chain (every element's and the chain's own flags).</summary>
    public static X509ChainStatusFlags Flags(X509Chain? chain)
    {
        var flags = X509ChainStatusFlags.NoError;
        if (chain == null) return flags;
        try { foreach (var st in chain.ChainStatus) flags |= st.Status; } catch { }
        return flags;
    }

    /// <summary>
    /// Every problem with the certificate for <paramref name="host"/>, worst first, plus an expiry warning when the
    /// leaf runs out within <see cref="ExpiryWarningDays"/> days. Empty = trusted and valid.
    /// </summary>
    public static List<TlsProblem> Assess(IReadOnlyList<TlsChainCert> chain, X509ChainStatusFlags chainFlags,
                                          SslPolicyErrors errors, string? host, DateTime utcNow)
    {
        var problems = new List<TlsProblem>();
        if ((errors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0 || chain.Count == 0)
        {
            problems.Add(new TlsProblem(TlsSeverity.Error, "The server sent no certificate."));
            return problems;
        }

        var leaf = chain[0].Cert;
        var all = chainFlags;
        foreach (var c in chain) all |= c.Status;

        // validity, attributed to the certificate it concerns
        for (int i = 0; i < chain.Count; i++)
        {
            var c = chain[i].Cert;
            string who = i == 0 ? "The certificate" : $"The {(i == chain.Count - 1 && IsSelfIssued(c) ? "root" : "intermediate")} certificate ({ShortName(c)})";
            if (utcNow > c.NotAfter.ToUniversalTime())
            {
                int ago = (int)Math.Floor((utcNow - c.NotAfter.ToUniversalTime()).TotalDays);
                problems.Add(new TlsProblem(TlsSeverity.Error,
                    $"{who} expired on {Date(c.NotAfter)}" + (ago >= 1 ? $" ({Plural(ago, "day")} ago)." : " (today).")));
            }
            else if (utcNow < c.NotBefore.ToUniversalTime())
            {
                problems.Add(new TlsProblem(TlsSeverity.Error,
                    $"{who} isn't valid yet — it starts on {Date(c.NotBefore)} (or this device's clock is wrong)."));
            }
        }

        if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0 && !string.IsNullOrEmpty(host))
            problems.Add(new TlsProblem(TlsSeverity.Error, $"Name mismatch — the certificate is for {NamesText(leaf, 4)}, not {host}."));

        if ((errors & SslPolicyErrors.RemoteCertificateChainErrors) != 0 || all != X509ChainStatusFlags.NoError)
        {
            if ((all & X509ChainStatusFlags.Revoked) != 0)
                problems.Add(new TlsProblem(TlsSeverity.Error, "The certificate has been revoked by its issuer."));
            if ((all & X509ChainStatusFlags.ExplicitDistrust) != 0)
                problems.Add(new TlsProblem(TlsSeverity.Error, "A certificate in the chain is explicitly distrusted on this system."));
            if ((all & X509ChainStatusFlags.UntrustedRoot) != 0)
            {
                var top = chain[^1].Cert;
                problems.Add(new TlsProblem(TlsSeverity.Error, chain.Count == 1 && IsSelfIssued(top)
                    ? $"Self-signed — {ShortName(top)} issued itself, so no trusted authority vouches for it."
                    : $"Untrusted root — {ShortName(top)} isn't in this system's trust store (a private / company CA, or an intercepting proxy)."));
            }
            if ((all & X509ChainStatusFlags.PartialChain) != 0)
                problems.Add(new TlsProblem(TlsSeverity.Error,
                    "Incomplete chain — the server didn't send the intermediate certificate(s) and this system couldn't find them, so the chain can't reach a trusted root."));
            if ((all & X509ChainStatusFlags.NotSignatureValid) != 0)
                problems.Add(new TlsProblem(TlsSeverity.Error, "A signature in the chain doesn't verify (a mis-issued or altered certificate)."));
            if ((all & (X509ChainStatusFlags.NotValidForUsage | X509ChainStatusFlags.InvalidExtension)) != 0)
                problems.Add(new TlsProblem(TlsSeverity.Error, "The certificate isn't valid for a TLS server (key usage / extended key usage)."));
            if ((all & X509ChainStatusFlags.InvalidBasicConstraints) != 0)
                problems.Add(new TlsProblem(TlsSeverity.Error, "A certificate in the chain acts as a CA without being allowed to (basic constraints)."));
            if ((all & (X509ChainStatusFlags.InvalidNameConstraints | X509ChainStatusFlags.HasNotPermittedNameConstraint
                        | X509ChainStatusFlags.HasExcludedNameConstraint | X509ChainStatusFlags.HasNotSupportedNameConstraint
                        | X509ChainStatusFlags.HasNotDefinedNameConstraint)) != 0)
                problems.Add(new TlsProblem(TlsSeverity.Error, "The certificate's names fall outside what its CA may issue (name constraints)."));
            if ((all & (X509ChainStatusFlags.InvalidPolicyConstraints | X509ChainStatusFlags.NoIssuanceChainPolicy)) != 0)
                problems.Add(new TlsProblem(TlsSeverity.Error, "The chain violates a certificate policy constraint."));
            if ((all & X509ChainStatusFlags.Cyclic) != 0)
                problems.Add(new TlsProblem(TlsSeverity.Error, "The chain is cyclic."));
            if ((all & X509ChainStatusFlags.HasWeakSignature) != 0)
                problems.Add(new TlsProblem(TlsSeverity.Warning, "A certificate in the chain uses a weak signature (SHA-1 / MD5)."));
            if ((all & (X509ChainStatusFlags.RevocationStatusUnknown | X509ChainStatusFlags.OfflineRevocation)) != 0
                && (all & X509ChainStatusFlags.Revoked) == 0)
                problems.Add(new TlsProblem(TlsSeverity.Warning, "Revocation status unknown — the issuer's CRL / OCSP couldn't be reached."));

            // chain errors that none of the above explained (and not just time validity, reported per certificate)
            bool explained = problems.Any(p => p.Severity == TlsSeverity.Error);
            if (!explained && (errors & SslPolicyErrors.RemoteCertificateChainErrors) != 0)
                problems.Add(new TlsProblem(TlsSeverity.Error, "The certificate chain isn't trusted on this system."));
        }

        // still valid but running out
        if (!problems.Any(p => p.Text.Contains("expired", StringComparison.Ordinal)))
        {
            double days = (leaf.NotAfter.ToUniversalTime() - utcNow).TotalDays;
            if (days >= 0 && days < ExpiryWarningDays)
                problems.Add(new TlsProblem(TlsSeverity.Warning,
                    $"Expires soon — on {Date(leaf.NotAfter)} ({Plural((int)Math.Floor(days), "day")} left)."));
        }

        problems.Sort((a, b) => b.Severity.CompareTo(a.Severity));
        return problems;
    }

    /// <summary>A short "certificate not trusted" sentence for the Socket tool's TLS option.</summary>
    public static string Summary(IReadOnlyList<TlsProblem> problems)
    {
        var errs = problems.Where(p => p.Severity == TlsSeverity.Error).Select(p => p.Text.TrimEnd('.')).ToList();
        if (errs.Count == 0) errs = problems.Select(p => p.Text.TrimEnd('.')).ToList();
        return errs.Count == 0 ? "The certificate isn't trusted." : string.Join(" · ", errs) + ".";
    }

    // ------------------------------------------------------------------ facts

    /// <summary>"TLS 1.3" … (by value: the old members are obsolete on newer frameworks).</summary>
    public static string ProtocolName(System.Security.Authentication.SslProtocols p) => (int)p switch
    {
        12288 => "TLS 1.3",
        3072 => "TLS 1.2",
        768 => "TLS 1.1",
        192 => "TLS 1.0",
        48 => "SSL 3.0",
        12 => "SSL 2.0",
        _ => p.ToString(),
    };

    public static bool IsSelfIssued(X509Certificate2 c)
        => c.SubjectName.RawData.AsSpan().SequenceEqual(c.IssuerName.RawData);

    /// <summary>A DN attribute (CN, O, OU, C …) or "".</summary>
    public static string DnPart(X500DistinguishedName dn, string key)
    {
        string oid = key switch
        {
            "CN" => "2.5.4.3", "O" => "2.5.4.10", "OU" => "2.5.4.11", "C" => "2.5.4.6",
            "L" => "2.5.4.7", "ST" => "2.5.4.8", _ => key,
        };
        try
        {
            foreach (var rdn in dn.EnumerateRelativeDistinguishedNames())
            {
                if (rdn.HasMultipleElements) continue;
                if (rdn.GetSingleElementType().Value == oid) return rdn.GetSingleElementValue() ?? "";
            }
        }
        catch { /* malformed DN */ }
        return "";
    }

    /// <summary>CN, else O, else the whole subject.</summary>
    public static string ShortName(X509Certificate2 c)
    {
        string cn = DnPart(c.SubjectName, "CN");
        if (cn.Length > 0) return cn;
        string o = DnPart(c.SubjectName, "O");
        return o.Length > 0 ? o : c.Subject;
    }

    /// <summary>"CN · O" of the issuer.</summary>
    public static string IssuerText(X509Certificate2 c)
    {
        string cn = DnPart(c.IssuerName, "CN"), o = DnPart(c.IssuerName, "O");
        if (cn.Length > 0 && o.Length > 0 && !cn.Contains(o, StringComparison.OrdinalIgnoreCase)) return $"{cn} · {o}";
        return cn.Length > 0 ? cn : o.Length > 0 ? o : c.Issuer;
    }

    /// <summary>Subject alternative names: DNS names, then IP addresses.</summary>
    public static List<string> Sans(X509Certificate2 c)
    {
        var list = new List<string>();
        foreach (var ext in c.Extensions)
        {
            if (ext.Oid?.Value != "2.5.29.17") continue;
            try
            {
                var san = new X509SubjectAlternativeNameExtension(ext.RawData, ext.Critical);
                list.AddRange(san.EnumerateDnsNames());
                foreach (var ip in san.EnumerateIPAddresses()) list.Add(ip.ToString());
            }
            catch { /* unreadable extension */ }
        }
        return list;
    }

    /// <summary>"a.com, b.com, +12 more" (SANs, else the CN).</summary>
    public static string NamesText(X509Certificate2 c, int max)
    {
        var names = Sans(c);
        if (names.Count == 0)
        {
            string cn = DnPart(c.SubjectName, "CN");
            return cn.Length > 0 ? cn : "(no name)";
        }
        return names.Count <= max ? string.Join(", ", names) : string.Join(", ", names.Take(max)) + $" +{names.Count - max} more";
    }

    /// <summary>"RSA 2048", "ECDSA P-256", "Ed25519".</summary>
    public static string KeyText(X509Certificate2 c)
    {
        string oid = c.PublicKey.Oid.Value ?? "";
        try
        {
            switch (oid)
            {
                case "1.2.840.113549.1.1.1":
                case "1.2.840.113549.1.1.10":
                {
                    using var rsa = c.GetRSAPublicKey();
                    return rsa != null ? $"RSA {rsa.KeySize}" : "RSA";
                }
                case "1.2.840.10045.2.1":
                {
                    using var ec = c.GetECDsaPublicKey();
                    if (ec == null) return "ECDSA";
                    string curve = "";
                    try { curve = CurveName(ec.ExportParameters(false).Curve.Oid); } catch { }
                    return curve.Length > 0 ? $"ECDSA {curve}" : $"ECDSA {ec.KeySize}";
                }
                case "1.3.101.112": return "Ed25519";
                case "1.3.101.113": return "Ed448";
                case "1.2.840.10040.4.1": return "DSA";
            }
        }
        catch { /* key type this platform can't load */ }
        return c.PublicKey.Oid.FriendlyName ?? oid;
    }

    private static string CurveName(Oid? oid) => oid?.Value switch
    {
        "1.2.840.10045.3.1.7" => "P-256",
        "1.3.132.0.34" => "P-384",
        "1.3.132.0.35" => "P-521",
        "1.3.132.0.10" => "secp256k1",
        _ => oid?.FriendlyName switch
        {
            "nistP256" or "ECDSA_P256" or "secp256r1" or "prime256v1" => "P-256",
            "nistP384" or "ECDSA_P384" or "secp384r1" => "P-384",
            "nistP521" or "ECDSA_P521" or "secp521r1" => "P-521",
            { Length: > 0 } f => f,
            _ => "",
        },
    };

    /// <summary>"ECDSA with SHA-384", "RSA-PSS", … (named here so every platform says the same).</summary>
    public static string SignatureText(X509Certificate2 c)
    {
        var oid = c.SignatureAlgorithm;
        return oid.Value switch
        {
            "1.2.840.113549.1.1.4" => "RSA with MD5",
            "1.2.840.113549.1.1.5" => "RSA with SHA-1",
            "1.2.840.113549.1.1.11" => "RSA with SHA-256",
            "1.2.840.113549.1.1.12" => "RSA with SHA-384",
            "1.2.840.113549.1.1.13" => "RSA with SHA-512",
            "1.2.840.113549.1.1.14" => "RSA with SHA-224",
            "1.2.840.113549.1.1.10" => "RSA-PSS",
            "1.2.840.10045.4.1" => "ECDSA with SHA-1",
            "1.2.840.10045.4.3.1" => "ECDSA with SHA-224",
            "1.2.840.10045.4.3.2" => "ECDSA with SHA-256",
            "1.2.840.10045.4.3.3" => "ECDSA with SHA-384",
            "1.2.840.10045.4.3.4" => "ECDSA with SHA-512",
            "1.3.101.112" => "Ed25519",
            "1.3.101.113" => "Ed448",
            "1.2.840.10040.4.3" => "DSA with SHA-1",
            "2.16.840.1.101.3.4.3.2" => "DSA with SHA-256",
            _ => oid.FriendlyName ?? oid.Value ?? "unknown",
        };
    }

    public static string Sha256(X509Certificate2 c) => Colon(c.GetCertHash(HashAlgorithmName.SHA256));
    public static string Sha1(X509Certificate2 c) => Colon(c.GetCertHash(HashAlgorithmName.SHA1));
    public static string Serial(X509Certificate2 c) => Colon(Convert.FromHexString(EvenHex(c.SerialNumber)));

    /// <summary>Bare SHA-256 hex (the identity the Socket tool's "connect anyway" is bound to).</summary>
    public static string Sha256Hex(X509Certificate c) => Convert.ToHexString(c.GetCertHash(HashAlgorithmName.SHA256));

    public static string Pem(X509Certificate2 c) => new string(PemEncoding.Write("CERTIFICATE", c.RawData)) + "\n";

    public static bool IsCa(X509Certificate2 c)
    {
        foreach (var ext in c.Extensions)
            if (ext is X509BasicConstraintsExtension bc) return bc.CertificateAuthority;
        return false;
    }

    /// <summary>OCSP responder URLs from the Authority Information Access extension.</summary>
    public static List<string> OcspUrls(X509Certificate2 c)
    {
        var list = new List<string>();
        foreach (var ext in c.Extensions)
        {
            if (ext.Oid?.Value != "1.3.6.1.5.5.7.1.1") continue;
            try { list.AddRange(new X509AuthorityInformationAccessExtension(ext.RawData, ext.Critical).EnumerateOcspUris()); }
            catch { }
        }
        return list;
    }

    /// <summary>True when one of the certificate's names covers <paramref name="host"/> (wildcards: one label).</summary>
    public static bool Covers(X509Certificate2 c, string host)
    {
        if (string.IsNullOrEmpty(host)) return false;
        host = host.TrimEnd('.').ToLowerInvariant();
        var names = Sans(c);
        if (names.Count == 0) { string cn = DnPart(c.SubjectName, "CN"); if (cn.Length > 0) names.Add(cn); }
        foreach (var raw in names)
        {
            string n = raw.TrimEnd('.').ToLowerInvariant();
            if (n == host) return true;
            if (n.StartsWith("*.", StringComparison.Ordinal))
            {
                int dot = host.IndexOf('.');
                if (dot > 0 && host[(dot + 1)..] == n[2..]) return true;
            }
        }
        return false;
    }

    public static string Date(DateTime local) => local.ToUniversalTime().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
    public static string DateTimeUtc(DateTime local) => local.ToUniversalTime().ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture);

    /// <summary>Whole days left (negative: whole days since it expired) — the same count the wording uses.</summary>
    public static int DaysLeft(X509Certificate2 c, DateTime utcNow)
    {
        var end = c.NotAfter.ToUniversalTime();
        return utcNow > end ? -(int)Math.Floor((utcNow - end).TotalDays) : (int)Math.Floor((end - utcNow).TotalDays);
    }

    /// <summary>"89 days left" · "expires today" · "expired 5 days ago" · "not valid until 2027-01-01".</summary>
    public static string ExpiryPhrase(X509Certificate2 c, DateTime utcNow)
    {
        if (utcNow < c.NotBefore.ToUniversalTime()) return $"not valid until {Date(c.NotBefore)}";
        var end = c.NotAfter.ToUniversalTime();
        if (utcNow > end)
        {
            int ago = (int)Math.Floor((utcNow - end).TotalDays);
            return ago == 0 ? "expired today" : $"expired {Plural(ago, "day")} ago";
        }
        int left = (int)Math.Floor((end - utcNow).TotalDays);
        return left == 0 ? "expires today" : $"{Plural(left, "day")} left";
    }

    /// <summary>How the expiry reads: an error once expired or not yet valid, a warning inside <see cref="ExpiryWarningDays"/>.</summary>
    public static TlsSeverity ExpirySeverity(X509Certificate2 c, DateTime utcNow)
    {
        if (utcNow < c.NotBefore.ToUniversalTime() || utcNow > c.NotAfter.ToUniversalTime()) return TlsSeverity.Error;
        return (c.NotAfter.ToUniversalTime() - utcNow).TotalDays < ExpiryWarningDays ? TlsSeverity.Warning : TlsSeverity.Ok;
    }

    public static string Plural(int n, string unit) => n == 1 ? $"1 {unit}" : $"{n.ToString("N0", CultureInfo.InvariantCulture)} {unit}s";

    public static string Colon(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty) return "";
        const string hex = "0123456789ABCDEF";
        var sb = new StringBuilder(bytes.Length * 3);
        for (int i = 0; i < bytes.Length; i++)
        {
            if (i > 0) sb.Append(':');
            sb.Append(hex[bytes[i] >> 4]).Append(hex[bytes[i] & 0xF]);
        }
        return sb.ToString();
    }

    private static string EvenHex(string s) => s.Length % 2 == 0 ? s : "0" + s;
}
