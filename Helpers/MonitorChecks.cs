using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using DnsClient;
using DnsClient.Protocol;

namespace Echoes.Helpers;

/// <summary>Which DNS answers a monitor watches for changes (opt-in per monitor).</summary>
public enum MonitorDnsKind
{
    Off = 0,
    /// <summary>A and AAAA: the addresses the name resolves to.</summary>
    Address = 1,
    Cname = 2,
    /// <summary>NS of the registrable domain (the zone's name servers).</summary>
    Ns = 3,
}

/// <summary>What a TLS certificate check found. Immutable.</summary>
public sealed class MonitorCertResult
{
    /// <summary>When the check ran (UTC).</summary>
    public DateTime CheckedUtc { get; init; }
    /// <summary>False: no verdict — the connection or the handshake itself failed (the TCP / HTTP checks report that).</summary>
    public bool Reached { get; init; }
    public DateTime? NotAfterUtc { get; init; }
    public DateTime? NotBeforeUtc { get; init; }
    /// <summary>The issuer's common name ("R10", "GTS CA 1C3"), for the detail panel.</summary>
    public string? Issuer { get; init; }
    /// <summary>Non-null: the certificate itself fails — expired, not valid yet, for another name, not trusted.</summary>
    public string? Problem { get; init; }
    /// <summary>Why there is no verdict (when <see cref="Reached"/> is false).</summary>
    public string? NetError { get; init; }
}

public enum MonitorRdapOutcome
{
    /// <summary>The registry answered; <see cref="MonitorRdapResult.ExpiresUtc"/> may still be null (no expiry listed).</summary>
    Found,
    /// <summary>No RDAP record for the name (404).</summary>
    NoData,
    /// <summary>Couldn't ask (offline, timeout, rate limit, a bad answer). Silent: never an alarm.</summary>
    Failed,
}

public readonly record struct MonitorRdapResult(MonitorRdapOutcome Outcome, DateTime? ExpiresUtc);

/// <summary>
/// The monitor's slower, automatic checks — run far less often than ping / TCP / HTTP and never inside a check round:
/// the TLS certificate of https targets (expiry, name, trust), the domain's registration expiry over RDAP, and the DNS
/// answers of a monitor that watches them. Every function catches its own failures (never throws, except
/// <see cref="OperationCanceledException"/> through the caller's token) and touches no UI.
/// </summary>
public static class MonitorChecks
{
    public const int CertWarnDays = 14;
    public const int DomainWarnDays = 30;
    public static readonly TimeSpan CertEvery = TimeSpan.FromHours(6);
    /// <summary>A failing certificate is looked at again sooner, so a renewed one clears the outage without a 6 h wait.</summary>
    public static readonly TimeSpan CertFailingEvery = TimeSpan.FromMinutes(15);
    /// <summary>No verdict (couldn't connect): try again after this.</summary>
    public static readonly TimeSpan CertRetryEvery = TimeSpan.FromMinutes(10);
    public static readonly TimeSpan DomainEvery = TimeSpan.FromDays(1);
    public static readonly TimeSpan DnsEvery = TimeSpan.FromSeconds(60);
    public const int MaxDnsAnswers = 64;

    // RDAP answers are a few KB; the body is a third party's (rdap.org redirects to the registry), so it is capped.
    private const int MaxRdapBytes = 1024 * 1024;
    private static readonly TimeSpan RdapTimeout = TimeSpan.FromSeconds(10);
    public const string DefaultRdapBase = "https://rdap.org";
    private static string _rdapBase = DefaultRdapBase;

    /// <summary>
    /// The RDAP bootstrap root. Test hook only: the real rdap.org or a LOOPBACK address, nothing else (a mock server stands
    /// in for it in tests). Not bound to any UI or setting.
    /// </summary>
    internal static string RdapBaseUrl
    {
        get => _rdapBase;
        set
        {
            string v = (value ?? string.Empty).TrimEnd('/');
            if (v == DefaultRdapBase || (Uri.TryCreate(v, UriKind.Absolute, out var u) && u.IsLoopback
                                         && (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps) && u.AbsolutePath == "/"))
                _rdapBase = v;
            else throw new ArgumentException("The RDAP root can only be rdap.org or a loopback test server.");
        }
    }

    /// <summary>Test hook: answers DNS-watch lookups instead of the resolver (host, kind → answers, or null for "no answer").</summary>
    internal static Func<string, MonitorDnsKind, CancellationToken, Task<string[]?>>? ResolveHook { get; set; }

    /// <summary>Test hook: one extra trusted root for the certificate check and the HTTP check (a loopback test server's
    /// self-signed certificate). Never set by the app.</summary>
    internal static X509Certificate2? TestTrustRoot { get; set; }

    // ================================================================ TLS certificate

    /// <summary>
    /// Connects to <paramref name="host"/>:<paramref name="port"/>, does a TLS handshake (SNI = the host) and judges the
    /// certificate it is shown: expired / not valid yet / for another name / not trusted is a <see cref="MonitorCertResult.Problem"/>;
    /// otherwise the expiry is reported. A failed connection or handshake is no verdict (<see cref="MonitorCertResult.Reached"/>
    /// false) — the TCP / HTTP checks already report those.
    /// </summary>
    public static async Task<MonitorCertResult> CheckCertAsync(string host, int port, int timeoutMs, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(Math.Clamp(timeoutMs, 3000, 30_000));

        Socket socket;
        try { socket = await MonitorProbe.ConnectAsync(host, port, budget.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return NoVerdict(now, "timed out"); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { return NoVerdict(now, MonitorProbe.Describe(ex)); }

        DateTime? notAfter = null, notBefore = null;
        string? issuer = null;
        SslPolicyErrors errors = SslPolicyErrors.None;
        X509ChainStatusFlags chainFlags = X509ChainStatusFlags.NoError;
        bool sawCert = false;
        try
        {
            await using var stream = new NetworkStream(socket, ownsSocket: true);
            await using var ssl = new SslStream(stream, leaveInnerStreamOpen: false);
            var options = new SslClientAuthenticationOptions
            {
                TargetHost = host,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                // Read everything inside the callback (the certificate object belongs to the stream) and always accept:
                // the verdict is ours, and the handshake must finish to tell "expired" from "unreachable".
                RemoteCertificateValidationCallback = (_, cert, chain, policy) =>
                {
                    if (cert is X509Certificate2 c2)
                    {
                        sawCert = true;
                        notAfter = c2.NotAfter.ToUniversalTime();
                        notBefore = c2.NotBefore.ToUniversalTime();
                        issuer = ShortName(c2.GetNameInfo(X509NameType.SimpleName, forIssuer: true));
                        if (chain is not null) foreach (var s in chain.ChainStatus) chainFlags |= s.Status;
                        if ((policy & SslPolicyErrors.RemoteCertificateChainErrors) != 0 && TrustedByTestRoot(c2))
                            policy &= ~SslPolicyErrors.RemoteCertificateChainErrors;
                    }
                    errors = policy;
                    return true;
                },
            };
            await ssl.AuthenticateAsClientAsync(options, budget.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        // A handshake that ends after the certificate was seen still gives a verdict (we accepted it; the server may
        // close for other reasons). One that never got that far is no verdict — the TCP / HTTP checks say why.
        catch (Exception)
        {
            if (!sawCert) return NoVerdict(now, budget.IsCancellationRequested ? "TLS handshake timed out" : "TLS handshake failed");
        }

        if (!sawCert || notAfter is null)
            return new MonitorCertResult { CheckedUtc = now, Reached = true, Problem = "the server sent no certificate" };

        string? problem = null;
        if (notAfter < now)
            problem = $"TLS certificate expired {AgoText(now - notAfter.Value)} ({ShortDate(notAfter.Value)})";
        else if (notBefore is { } nb && nb > now)
            problem = $"TLS certificate isn't valid until {ShortDate(nb)}";
        else if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
            problem = $"TLS certificate isn't for {host}";
        else if ((errors & SslPolicyErrors.RemoteCertificateChainErrors) != 0)
            problem = "TLS certificate isn't trusted (" + ChainReason(chainFlags) + ")";
        else if ((errors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0)
            problem = "the server sent no certificate";

        return new MonitorCertResult
        {
            CheckedUtc = now, Reached = true, NotAfterUtc = notAfter, NotBeforeUtc = notBefore, Issuer = issuer, Problem = problem,
        };
    }

    private static MonitorCertResult NoVerdict(DateTime now, string why)
        => new() { CheckedUtc = now, Reached = false, NetError = why };

    private static string ChainReason(X509ChainStatusFlags f)
    {
        if ((f & X509ChainStatusFlags.Revoked) != 0) return "revoked";
        // No path to a trusted root: a private / unknown CA, or an intermediate the server didn't send.
        if ((f & X509ChainStatusFlags.PartialChain) != 0) return "unknown issuer or incomplete chain";
        if ((f & (X509ChainStatusFlags.UntrustedRoot | X509ChainStatusFlags.NotSignatureValid)) != 0) return "self-signed or unknown issuer";
        return "chain error";
    }

    internal static bool TrustedByTestRoot(X509Certificate2 cert)
    {
        if (TestTrustRoot is not { } root) return false;
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(root);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            return chain.Build(cert);
        }
        catch { return false; }
    }

    private static string? ShortName(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        s = s.Trim();
        return s.Length > 48 ? s[..48] + "…" : s;
    }

    // ================================================================ domain expiry (RDAP)

    /// <summary>
    /// The registration expiry of <paramref name="domain"/> (a registrable name, see <see cref="RegistrableDomain"/>)
    /// over RDAP: the rdap.org bootstrap (it redirects to the registry's server), a capped body, a short deadline, no
    /// credentials. Never throws (except the caller's cancellation): anything that goes wrong is
    /// <see cref="MonitorRdapOutcome.Failed"/>, which callers keep silent.
    /// </summary>
    public static async Task<MonitorRdapResult> FetchDomainExpiryAsync(string domain, CancellationToken ct)
    {
        if (!IsAsciiName(domain)) return new(MonitorRdapOutcome.Failed, null);
        var urls = new List<string> { $"{RdapBaseUrl}/domain/{domain}" };
        // .com / .net: Verisign's own server, should the bootstrap be unreachable (same fallback as the DNS tool's WHOIS).
        if (RdapBaseUrl == DefaultRdapBase && (domain.EndsWith(".com", StringComparison.Ordinal) || domain.EndsWith(".net", StringComparison.Ordinal)))
            urls.Add($"https://rdap.verisign.com/{domain[(domain.LastIndexOf('.') + 1)..]}/v1/domain/{domain}");

        foreach (var url in urls)
        {
            try
            {
                var (status, body) = await FetchRdapAsync(url, ct).ConfigureAwait(false);
                if (status == 404) return new(MonitorRdapOutcome.NoData, null);
                if (status is >= 200 and < 300 && body.TrimStart().StartsWith('{'))
                    return ParseRdap(body) is { } parsed ? parsed : new(MonitorRdapOutcome.Failed, null);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception) { /* next provider; silent */ }
        }
        return new(MonitorRdapOutcome.Failed, null);
    }

    private static async Task<(int Status, string Body)> FetchRdapAsync(string url, CancellationToken ct)
    {
        using var client = HttpHelper.Create(timeout: RdapTimeout);
        client.DefaultRequestHeaders.Accept.ParseAdd("application/rdap+json");
        client.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(RdapTimeout);
        using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
        int status = (int)response.StatusCode;
        if (status is < 200 or >= 300) return (status, string.Empty);
        await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
        using var ms = new MemoryStream();
        byte[] buf = new byte[16 * 1024];
        int n;
        while ((n = await stream.ReadAsync(buf, deadline.Token).ConfigureAwait(false)) > 0)
        {
            if (ms.Length + n > MaxRdapBytes) throw new InvalidDataException("RDAP answer too large");
            ms.Write(buf, 0, n);
        }
        int skip = ms.Length >= 3 && ms.GetBuffer()[0] == 0xEF && ms.GetBuffer()[1] == 0xBB && ms.GetBuffer()[2] == 0xBF ? 3 : 0;
        return (status, Encoding.UTF8.GetString(ms.GetBuffer(), skip, (int)ms.Length - skip));
    }

    /// <summary>The "expiration" event of an RDAP domain object; null when the body isn't one.</summary>
    internal static MonitorRdapResult? ParseRdap(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 64 });
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return null;
            DateTime? exact = null, loose = null;
            if (root.TryGetProperty("events", out var events) && events.ValueKind == JsonValueKind.Array)
            {
                foreach (var e in events.EnumerateArray())
                {
                    if (e.ValueKind != JsonValueKind.Object) continue;
                    if (!e.TryGetProperty("eventAction", out var a) || a.ValueKind != JsonValueKind.String) continue;
                    if (!e.TryGetProperty("eventDate", out var d) || d.ValueKind != JsonValueKind.String) continue;
                    string action = a.GetString() ?? string.Empty;
                    if (!DateTimeOffset.TryParse(d.GetString(), CultureInfo.InvariantCulture,
                                                 DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var when)) continue;
                    if (action.Equals("expiration", StringComparison.OrdinalIgnoreCase)) exact ??= when.UtcDateTime;
                    else if (action.Contains("expiration", StringComparison.OrdinalIgnoreCase)
                             && !action.Contains("registrar", StringComparison.OrdinalIgnoreCase)) loose ??= when.UtcDateTime;
                }
            }
            return new MonitorRdapResult(MonitorRdapOutcome.Found, exact ?? loose);
        }
        catch (JsonException) { return null; }
    }

    // Second-level labels under which a two-letter country code sells names (example.co.uk, example.com.au, x.ac.ir).
    private static readonly HashSet<string> SecondLevel = new(StringComparer.Ordinal)
    {
        "co", "com", "net", "org", "ac", "gov", "edu", "gob", "mil", "or", "ne", "go", "sch", "nic", "ltd", "plc",
        "me", "id", "info", "biz", "nom", "web", "gen", "firm", "res", "ind", "int", "nhs", "police",
    };

    // Names that are never registered with a registry.
    private static readonly HashSet<string> PrivateTlds = new(StringComparer.Ordinal)
    {
        "local", "lan", "home", "internal", "localhost", "test", "example", "invalid", "arpa", "corp", "intranet", "localdomain", "router",
    };

    /// <summary>
    /// The name a registry sells for <paramref name="host"/> ("api.example.co.uk" → "example.co.uk"), or null for an IP
    /// address, a single label, or a private name (.lan, .local, .internal…). A small built-in rule set, not the Public
    /// Suffix List: a miss only means no RDAP lookup (silent), never a false alarm.
    /// </summary>
    public static string? RegistrableDomain(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) return null;
        string h = host.Trim().TrimEnd('.').ToLowerInvariant();
        if (h.Length == 0 || h.Length > 253 || IPAddress.TryParse(h, out _) || !IsAsciiName(h)) return null;
        var labels = h.Split('.');
        if (labels.Length < 2 || labels.Any(l => l.Length == 0)) return null;
        string tld = labels[^1];
        if (PrivateTlds.Contains(tld) || tld.All(char.IsAsciiDigit)) return null;
        if (labels.Length >= 3 && tld.Length == 2 && SecondLevel.Contains(labels[^2]))
            return string.Join('.', labels[^3..]);
        if (labels.Length == 2 && tld.Length == 2 && SecondLevel.Contains(labels[0])) return null;   // "co.uk" itself
        return string.Join('.', labels[^2..]);
    }

    private static bool IsAsciiName(string s)
    {
        foreach (char c in s)
            if (!(char.IsAsciiLetterOrDigit(c) || c is '-' or '.')) return false;
        return s.Length > 0;
    }

    // ================================================================ DNS watch

    private static readonly Lazy<LookupClient> Lookup = new(CreateLookup, LazyThreadSafetyMode.ExecutionAndPublication);

    private static LookupClient CreateLookup()
    {
        try
        {
            // The system's resolvers (falls back to public ones where none can be read, e.g. on Android).
            var options = new LookupClientOptions { UseCache = false, Timeout = TimeSpan.FromSeconds(3), Retries = 1, ContinueOnDnsError = false };
            return new LookupClient(options);
        }
        catch
        {
            var options = new LookupClientOptions(IPAddress.Parse("1.1.1.1"), IPAddress.Parse("8.8.8.8"))
            {
                UseCache = false, Timeout = TimeSpan.FromSeconds(3), Retries = 1,
            };
            return new LookupClient(options);
        }
    }

    /// <summary>
    /// The answer set a DNS watch compares, normalized ("A 93.184.215.14", "CNAME edge.example.net", sorted, no
    /// duplicates, at most <see cref="MaxDnsAnswers"/>); null when the lookup failed (silent: the regular checks report
    /// a name that doesn't resolve).
    /// </summary>
    public static async Task<string[]?> ResolveAsync(string host, MonitorDnsKind kind, CancellationToken ct)
    {
        if (kind == MonitorDnsKind.Off || string.IsNullOrWhiteSpace(host) || IPAddress.TryParse(host, out _)) return null;
        if (ResolveHook is { } hook)
        {
            try { return Normalize(await hook(host, kind, ct).ConfigureAwait(false)); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch { return null; }
        }

        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(TimeSpan.FromSeconds(8));
        try
        {
            switch (kind)
            {
                case MonitorDnsKind.Address:
                {
                    var found = await Dns.GetHostAddressesAsync(host, budget.Token).ConfigureAwait(false);
                    return Normalize(found.Select(a => (a.AddressFamily == AddressFamily.InterNetworkV6 ? "AAAA " : "A ") + a));
                }
                case MonitorDnsKind.Cname:
                {
                    var r = await Lookup.Value.QueryAsync(host, QueryType.CNAME, QueryClass.IN, budget.Token).ConfigureAwait(false);
                    if (r.HasError) return null;
                    return Normalize(r.Answers.OfType<CNameRecord>().Select(c => "CNAME " + Name(c.CanonicalName.Value)));
                }
                case MonitorDnsKind.Ns:
                {
                    string zone = RegistrableDomain(host) ?? host;
                    var r = await Lookup.Value.QueryAsync(zone, QueryType.NS, QueryClass.IN, budget.Token).ConfigureAwait(false);
                    if (r.HasError) return null;
                    var ns = r.Answers.OfType<NsRecord>().Select(n => "NS " + Name(n.NSDName.Value)).ToList();
                    return ns.Count == 0 ? null : Normalize(ns);   // a zone always has NS: none is a failed lookup
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { }
        return null;
    }

    private static string Name(string? s) => (s ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();

    internal static string[]? Normalize(IEnumerable<string>? answers)
    {
        if (answers is null) return null;
        var set = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var a in answers)
        {
            string s = (a ?? string.Empty).Trim();
            if (s.Length == 0 || s.Length > 300) continue;
            set.Add(s);
            if (set.Count >= MaxDnsAnswers) break;
        }
        return set.ToArray();
    }

    /// <summary>"+A 5.6.7.8 · −A 1.2.3.4" (what was added, then what went), shortened past a few entries.</summary>
    public static string DescribeChange(IReadOnlyCollection<string> baseline, IReadOnlyCollection<string> current)
    {
        var added = current.Where(c => !baseline.Contains(c)).ToList();
        var gone = baseline.Where(b => !current.Contains(b)).ToList();
        var parts = new List<string>();
        foreach (var a in added.Take(3)) parts.Add("+" + a);
        if (added.Count > 3) parts.Add($"+{added.Count - 3} more");
        foreach (var g in gone.Take(3)) parts.Add("−" + g);
        if (gone.Count > 3) parts.Add($"−{gone.Count - 3} more");
        if (parts.Count == 0) parts.Add(current.Count == 0 ? "no answers" : "answers changed");
        return string.Join(" · ", parts);
    }

    public static bool SameAnswers(IReadOnlyCollection<string>? a, IReadOnlyCollection<string>? b)
        => a is not null && b is not null && a.Count == b.Count && a.All(b.Contains);

    // ================================================================ text

    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    /// <summary>Whole days left until <paramref name="untilUtc"/> (negative once it is past).</summary>
    public static int DaysLeft(DateTime untilUtc, DateTime nowUtc) => (int)Math.Floor((untilUtc - nowUtc).TotalDays);

    /// <summary>"Oct 24" this year, "Mar 3, 2027" otherwise (local time).</summary>
    public static string ShortDate(DateTime utc)
    {
        var local = utc.ToLocalTime();
        return local.Year == DateTime.Now.Year ? local.ToString("MMM d", Inv) : local.ToString("MMM d, yyyy", Inv);
    }

    /// <summary>"today", "tomorrow", "in 9 days".</summary>
    public static string InDays(int days) => days switch
    {
        <= 0 => "today",
        1 => "tomorrow",
        _ => $"in {days} days",
    };

    private static string AgoText(TimeSpan d)
    {
        int days = (int)Math.Floor(d.TotalDays);
        return days switch { 0 => "today", 1 => "yesterday", _ => $"{days} days ago" };
    }
}
