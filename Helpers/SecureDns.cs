using DnsClient;
using DnsClient.Protocol;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>How a resolver is reached.</summary>
public enum DnsTransport { System, Plain, DoH, DoT }

/// <summary>
/// One resolver line as the user typed it, recognised automatically: "system", a plain IP / ip:port (DnsClient, UDP with
/// TCP fallback), https://host/path (DNS-over-HTTPS, RFC 8484), tls://host[:port] or host:853 (DNS-over-TLS, RFC 7858).
/// </summary>
public sealed class ResolverSpec
{
    public DnsTransport Transport { get; private init; }
    /// <summary>The canonical line (what is stored / compared).</summary>
    public string Text { get; private init; } = "";
    /// <summary>The provider's name when it is a well-known resolver ("Cloudflare"), else <see cref="Short"/>.</summary>
    public string Label { get; private init; } = "";
    /// <summary>A short form for narrow cells: the host (with a non-default port / path), or "system".</summary>
    public string Short { get; private init; } = "";
    /// <summary>Plain: the server. DoT: the address when the host is an IP literal.</summary>
    public IPEndPoint? Endpoint { get; private init; }
    /// <summary>DoH: the endpoint URL.</summary>
    public Uri? Url { get; private init; }
    /// <summary>DoT / DoH: the host (a name or an IP literal) and port.</summary>
    public string Host { get; private init; } = "";
    public int Port { get; private init; }
    /// <summary>DoT: the name the certificate must match (and SNI). Null = match the IP address (an IP SAN).</summary>
    public string? TlsName { get; private init; }

    public bool IsEncrypted => Transport is DnsTransport.DoH or DnsTransport.DoT;
    public string TransportLabel => Transport switch
    {
        DnsTransport.DoH => "DoH",
        DnsTransport.DoT => "DoT",
        DnsTransport.System => "system",
        _ => "plain",
    };

    public override string ToString() => Text;

    public const string HelpText = "use an IP (1.1.1.1), https://host/dns-query (DoH), tls://host (DoT) or system";

    /// <summary>Recognises one line. False with a short reason for anything that isn't a resolver.</summary>
    public static bool TryParse(string? text, [NotNullWhen(true)] out ResolverSpec? spec, out string error)
    {
        spec = null;
        error = "";
        string s = (text ?? "").Trim();
        if (!LocalDigits.HasNonAsciiLetter(s)) s = LocalDigits.Fold(s);   // a resolver IP typed in Persian / Arabic digits
        if (s.Length == 0) { error = "empty"; return false; }
        if (s.Length > 512) { error = "too long"; return false; }

        if (s.Equals("system", StringComparison.OrdinalIgnoreCase))
        {
            spec = new ResolverSpec { Transport = DnsTransport.System, Text = "system", Label = "System", Short = "system" };
            return true;
        }

        int scheme = s.IndexOf("://", StringComparison.Ordinal);
        if (scheme > 0)
        {
            string sch = s[..scheme].ToLowerInvariant();
            if (sch == "https") return TryDoh(s, out spec, out error);
            if (sch == "tls") return TryDot(s[(scheme + 3)..].TrimEnd('/'), out spec, out error);
            error = sch == "http"
                ? "DoH needs https:// (plain http would send the queries in the clear)"
                : $"{sch}:// isn't supported — {HelpText}";
            return false;
        }

        // ip:port / [v6]:port first (IPAddress.TryParse takes "[v6]:port" but drops the port); a bare IPv6 parses as an
        // endpoint with port 0 and falls through to the bare-IP case.
        if (IPEndPoint.TryParse(s, out var ep) && ep.Port > 0)
        {
            if (ep.Port == 853) return TryDot(s, out spec, out error);
            spec = Plain(ep);
            return true;
        }
        if (IPAddress.TryParse(s, out var ip))
        {
            spec = Plain(new IPEndPoint(ip, 53));
            return true;
        }
        // a name with :853 is DoT; any other "name" or "name:port" can't be a plain resolver (it would need a lookup first)
        int colon = s.LastIndexOf(':');
        if (colon > 0 && s.AsSpan(colon + 1).SequenceEqual("853") && HostExtractor.IsHostName(s[..colon], requireDot: true))
            return TryDot(s, out spec, out error);
        error = $"not a resolver — {HelpText}";
        return false;
    }

    private static ResolverSpec Plain(IPEndPoint ep)
    {
        string text = ep.Port == 53 ? ep.Address.ToString() : ep.ToString();
        var known = ResolverPresets.ByAddress(ep.Address);
        return new ResolverSpec
        {
            Transport = DnsTransport.Plain, Text = text, Endpoint = ep, Host = ep.Address.ToString(), Port = ep.Port,
            Short = text, Label = known?.Name ?? text,
        };
    }

    private static bool TryDoh(string s, [NotNullWhen(true)] out ResolverSpec? spec, out string error)
    {
        spec = null;
        error = "";
        if (!Uri.TryCreate(s, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttps || u.Host.Length == 0)
        {
            error = "not a valid https:// URL";
            return false;
        }
        // credentials in the URL would be sent to the resolver with every query
        if (u.UserInfo.Length > 0) { error = "remove the user:password@ part — DoH doesn't use it"; return false; }
        string path = u.AbsolutePath is "" or "/" ? "/dns-query" : u.AbsolutePath;
        var b = new UriBuilder(Uri.UriSchemeHttps, u.Host, u.Port, path) { Query = u.Query.TrimStart('?') };
        var url = b.Uri;
        string host = url.IdnHost;
        string shortText = url.IsDefaultPort ? url.Host : $"{url.Host}:{url.Port}";
        if (path != "/dns-query") shortText += path;
        string canon = url.GetComponents(UriComponents.SchemeAndServer | UriComponents.PathAndQuery, UriFormat.UriEscaped);
        var known = ResolverPresets.ByHost(host);
        spec = new ResolverSpec
        {
            Transport = DnsTransport.DoH, Text = canon, Url = url, Host = host, Port = url.Port,
            Short = shortText, Label = known?.Name ?? shortText,
        };
        return true;
    }

    private static bool TryDot(string hostPort, [NotNullWhen(true)] out ResolverSpec? spec, out string error)
    {
        spec = null;
        error = "";
        string host;
        int port = 853;
        string hp = hostPort.Trim();
        if (hp.StartsWith('['))
        {
            int close = hp.IndexOf(']');
            if (close < 0) { error = "unclosed [ in the address"; return false; }
            host = hp[1..close];
            string rest = hp[(close + 1)..];
            if (rest.Length > 0 && (!rest.StartsWith(':') || !TryPort(rest[1..], out port))) { error = "bad port"; return false; }
            if (!IPAddress.TryParse(host, out _)) { error = "not an IPv6 address inside [ ]"; return false; }
        }
        else if (IPAddress.TryParse(hp, out var bare) && bare.AddressFamily == AddressFamily.InterNetworkV6)
        {
            host = hp;   // a bare IPv6 (its colons aren't a port)
        }
        else
        {
            int colon = hp.LastIndexOf(':');
            if (colon >= 0)
            {
                if (!TryPort(hp[(colon + 1)..], out port)) { error = "bad port"; return false; }
                host = hp[..colon];
            }
            else host = hp;
        }

        IPEndPoint? ep = null;
        string? tlsName;
        if (IPAddress.TryParse(host, out var ip))
        {
            ep = new IPEndPoint(ip, port);
            host = ip.ToString();
            // a known provider's address: check its certificate against the provider's name (and send it as SNI);
            // any other address: the certificate must list that IP
            tlsName = ResolverPresets.ByAddress(ip)?.TlsName;
        }
        else
        {
            string ascii;
            // lowercased first: in invariant mode (the desktop release) GetAscii doesn't fold "Ä", and gave another xn-- name
            try { ascii = new IdnMapping().GetAscii(host.TrimEnd('.').ToLowerInvariant()); } catch { ascii = host; }
            if (!HostExtractor.IsHostName(ascii, requireDot: true)) { error = "not a host name or IP"; return false; }
            host = ascii.ToLowerInvariant();
            tlsName = host;
        }

        string hostText = host.Contains(':') ? $"[{host}]" : host;
        string text = "tls://" + hostText + (port == 853 ? "" : ":" + port.ToString(CultureInfo.InvariantCulture));
        string shortText = hostText + (port == 853 ? "" : ":" + port.ToString(CultureInfo.InvariantCulture));
        var known = ep != null ? ResolverPresets.ByAddress(ep.Address) : ResolverPresets.ByHost(host);
        spec = new ResolverSpec
        {
            Transport = DnsTransport.DoT, Text = text, Endpoint = ep, Host = host, Port = port, TlsName = tlsName,
            Short = shortText, Label = known?.Name ?? shortText,
        };
        return true;
    }

    private static bool TryPort(string s, out int port)
        => int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out port) && port is > 0 and <= 65535;

    /// <summary>Every resolver line in <paramref name="text"/> (newline / comma separated); unrecognised lines go to
    /// <paramref name="skipped"/> with the reason. Duplicates (same canonical form) are dropped.</summary>
    public static List<ResolverSpec> ParseList(string? text, List<(string line, string reason)>? skipped = null)
    {
        var list = new List<ResolverSpec>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string raw in (text ?? "").Split(new[] { '\n', '\r', ',' }, StringSplitOptions.RemoveEmptyEntries))
        {
            string line = raw.Trim();
            if (line.Length == 0) continue;
            if (TryParse(line, out var spec, out string why)) { if (seen.Add(spec.Text)) list.Add(spec); }
            else skipped?.Add((line, why));
        }
        return list;
    }
}

/// <summary>A well-known public resolver: its plain addresses, DoH URL, DoT host and certificate name.</summary>
public sealed record ResolverProvider(string Name, string Note, string[] Addresses, string? Doh, string? Dot, string? TlsName);

/// <summary>The presets offered in the DNS tool (and the bootstrap addresses used to reach their DoH / DoT hosts
/// without asking the system resolver first — a poisoned system resolver can't redirect them).</summary>
public static class ResolverPresets
{
    public static readonly IReadOnlyList<ResolverProvider> Providers = new ResolverProvider[]
    {
        new("Cloudflare", "", new[] { "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001" },
            "https://cloudflare-dns.com/dns-query", "tls://1.1.1.1", "cloudflare-dns.com"),
        new("Google", "", new[] { "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844" },
            "https://dns.google/dns-query", "tls://dns.google", "dns.google"),
        new("Quad9", "", new[] { "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9" },
            "https://dns.quad9.net/dns-query", "tls://dns.quad9.net", "dns.quad9.net"),
        new("OpenDNS", "", new[] { "208.67.222.222", "208.67.220.220", "2620:119:35::35", "2620:119:53::53" },
            "https://doh.opendns.com/dns-query", null, "doh.opendns.com"),
        new("AdGuard", "blocks ads", new[] { "94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff" },
            "https://dns.adguard-dns.com/dns-query", "tls://dns.adguard-dns.com", "dns.adguard-dns.com"),
        new("Shecan", "Iran", new[] { "178.22.122.100", "185.51.200.2" }, null, null, null),
        new("Electro", "Iran", new[] { "78.157.42.100", "78.157.42.101" }, null, null, null),
    };

    // host names a provider's DoH / DoT is reached at → the provider
    private static readonly Dictionary<string, ResolverProvider> Hosts = new(StringComparer.OrdinalIgnoreCase)
    {
        ["cloudflare-dns.com"] = Providers[0], ["one.one.one.one"] = Providers[0], ["1dot1dot1dot1.cloudflare-dns.com"] = Providers[0],
        ["dns.google"] = Providers[1], ["dns.google.com"] = Providers[1], ["dns64.dns.google"] = Providers[1],
        ["dns.quad9.net"] = Providers[2], ["dns9.quad9.net"] = Providers[2], ["dns10.quad9.net"] = Providers[2], ["dns11.quad9.net"] = Providers[2],
        ["doh.opendns.com"] = Providers[3], ["dns.opendns.com"] = Providers[3], ["dns.umbrella.com"] = Providers[3],
        ["dns.adguard-dns.com"] = Providers[4], ["dns.adguard.com"] = Providers[4],
    };

    public static ResolverProvider? ByAddress(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        foreach (var p in Providers)
            foreach (string a in p.Addresses)
                if (IPAddress.TryParse(a, out var x) && x.Equals(ip)) return p;
        return null;
    }

    public static ResolverProvider? ByHost(string host)
    {
        if (IPAddress.TryParse(host.Trim('[', ']'), out var ip)) return ByAddress(ip);
        return Hosts.TryGetValue(host.TrimEnd('.'), out var p) ? p : null;
    }

    /// <summary>Addresses to reach a provider's DoH / DoT host directly (IPv4 first), or empty for any other host.</summary>
    public static IReadOnlyList<IPAddress> Bootstrap(string host)
    {
        if (!Hosts.TryGetValue(host.TrimEnd('.'), out var p)) return Array.Empty<IPAddress>();
        return p.Addresses.Select(IPAddress.Parse)
            .OrderBy(a => a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1).ToArray();
    }

    /// <summary>The comparison list the Compare mode starts with: every preset in each form it offers.</summary>
    public static string DefaultCompareList()
    {
        var lines = new List<string> { "system" };
        foreach (var p in Providers)
        {
            lines.Add(p.Addresses[0]);
            if (p.Doh != null) lines.Add(p.Doh);
            if (p.Dot != null) lines.Add(p.Dot);
            if (p.Note == "Iran") lines.Add(p.Addresses[1]);
        }
        return string.Join(Environment.NewLine, lines);
    }
}

/// <summary>One answer in the shape the DNS view shows: its own type ("CNAME" inside an A answer), the value text and
/// the TTL. <see cref="Texts"/>: a TXT record's character-strings, unjoined (SPF / DKIM join them without spaces).</summary>
public sealed record DnsAnswer(string Type, string Value, int Ttl, IReadOnlyList<string>? Texts = null)
{
    /// <summary>A TXT record's strings concatenated as RFC 7208 / 6376 read them (no separator); else the value.</summary>
    public string Joined => Texts is { Count: > 0 } t ? string.Concat(t) : Value;
}

/// <summary>The outcome of one query: either a DNS response (<see cref="Answered"/>, with its RCODE and answers) or
/// a failure to get one (<see cref="Error"/>: timeout, TLS, refused …). Never both.</summary>
public sealed class DnsResult
{
    public required ResolverSpec Resolver { get; init; }
    public string Name { get; init; } = "";
    public QueryType Type { get; init; }
    public bool Answered { get; init; }
    public int Rcode { get; init; }
    public IReadOnlyList<DnsAnswer> Answers { get; init; } = Array.Empty<DnsAnswer>();
    /// <summary>The answer count the server sent (more than <see cref="Answers"/> when the parser stopped early).</summary>
    public int AnswerCount { get; init; }
    public double RttMs { get; init; }
    /// <summary>What carried the answer: "DoH", "DoH (GET)", "DoT", "plain", "system (192.168.1.1)".</summary>
    public string Via { get; init; } = "";
    /// <summary>Why no response arrived — one sentence.</summary>
    public string? Error { get; init; }
    /// <summary>The same in a word or two for table cells: "timeout", "TLS failed", "refused" …</summary>
    public string? ShortError { get; init; }

    public bool Ok => Answered && Rcode == 0;
    public bool IsNxDomain => Answered && Rcode == 3;

    /// <summary>Answers of the queried type only (an A answer behind an alias also carries the CNAME chain).</summary>
    public IEnumerable<DnsAnswer> OfType(string type) => Answers.Where(a => a.Type == type);

    public string RcodeText => RcodeName(Rcode);

    public static string RcodeName(int rcode) => rcode switch
    {
        0 => "NOERROR",
        1 => "Format error (FORMERR)",
        2 => "Server failure (SERVFAIL)",
        3 => "Non-existent domain (NXDOMAIN)",
        4 => "Not implemented (NOTIMP)",
        5 => "Query refused (REFUSED)",
        _ => "RCODE " + rcode.ToString(CultureInfo.InvariantCulture),
    };

    /// <summary>"no records" / the RCODE / the error — the status line for a query that brought no answer.</summary>
    public string StatusText => !Answered ? (Error ?? "no answer") : Rcode == 0 ? "no records" : RcodeText;
}

/// <summary>
/// Queries one resolver over its transport, keeping what can be reused between queries: the DnsClient instance (plain /
/// system), the DoT connection (one TLS handshake for a whole lookup), the shared pooled DoH client. Thread-safe; DoT
/// queries are serialised on the one connection. Dispose closes the DoT connection.
/// </summary>
public sealed class DnsSession : IDisposable
{
    public ResolverSpec Spec { get; }
    private readonly TimeSpan _timeout;
    private LookupClient? _plain;
    private readonly object _plainGate = new();
    private string _systemVia = "system";
    private bool _systemOsOnly;
    // DoT: up to MaxDotConnections queries at once, each on its own connection; idle connections are reused
    private const int MaxDotConnections = 3;
    private readonly Stack<DotConnection> _dotIdle = new();
    private readonly SemaphoreSlim _dotSlots = new(MaxDotConnections, MaxDotConnections);
    private volatile bool _disposed;

    /// <summary>Test hook (the harness): answers every query instead of the network. Internal on purpose.</summary>
    internal static Func<ResolverSpec, string, QueryType, CancellationToken, Task<DnsResult>>? TestHook { get; set; }

    public DnsSession(ResolverSpec spec, TimeSpan? timeout = null)
    {
        Spec = spec;
        _timeout = timeout ?? (spec.IsEncrypted ? TimeSpan.FromSeconds(5) : TimeSpan.FromSeconds(3));
    }

    /// <summary>One query. Never throws for a network / protocol failure (that is a result with
    /// <see cref="DnsResult.Error"/>); throws <see cref="OperationCanceledException"/> only when <paramref name="ct"/> is cancelled.</summary>
    public async Task<DnsResult> QueryAsync(string name, QueryType type, CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (TestHook is { } hook) return await hook(Spec, name, type, ct).ConfigureAwait(false);

        // DoT: waiting for a free connection slot isn't part of this query's time (or its timeout)
        bool dot = Spec.Transport == DnsTransport.DoT;
        if (dot) await _dotSlots.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var sw = Stopwatch.StartNew();
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(_timeout);
            try
            {
                return Spec.Transport switch
                {
                    DnsTransport.DoH => await DohAsync(name, type, sw, deadline.Token).ConfigureAwait(false),
                    DnsTransport.DoT => await DotAsync(name, type, sw, deadline.Token).ConfigureAwait(false),
                    _ => await PlainAsync(name, type, sw, deadline.Token).ConfigureAwait(false),
                };
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                if (ct.IsCancellationRequested) throw new OperationCanceledException(ct);
                var (full, brief) = Describe(ex, deadline.IsCancellationRequested);
                return new DnsResult
                {
                    Resolver = Spec, Name = name, Type = type, Via = ViaFallback, RttMs = sw.Elapsed.TotalMilliseconds,
                    Error = full, ShortError = brief,
                };
            }
        }
        finally { if (dot) _dotSlots.Release(); }
    }

    private string ViaFallback => Spec.Transport == DnsTransport.System ? _systemVia : Spec.TransportLabel;

    // ------------------------------------------------------------ plain / system (DnsClient)

    private async Task<DnsResult> PlainAsync(string name, QueryType type, Stopwatch sw, CancellationToken ct)
    {
        LookupClient? client;
        lock (_plainGate)   // the email check asks one session from many tasks at once
        {
            if (_plain == null && !_systemOsOnly)
            {
                if (Spec.Transport == DnsTransport.Plain)
                    _plain = new LookupClient(Options(new NameServer(Spec.Endpoint!)));
                else
                {
                    // the servers the OS is configured with; none readable (Android, a locked-down box) → the OS resolver itself
                    IReadOnlyCollection<NameServer> servers;
                    try { servers = NameServer.ResolveNameServers(skipIPv6SiteLocal: true, fallbackToGooglePublicDns: false); }
                    catch { servers = Array.Empty<NameServer>(); }
                    if (servers.Count > 0)
                    {
                        _plain = new LookupClient(Options(servers.ToArray()));
                        _systemVia = "system (" + servers.First().Address + (servers.Count > 1 ? $" +{servers.Count - 1}" : "") + ")";
                    }
                    else { _systemOsOnly = true; _systemVia = "system (OS resolver)"; }
                }
            }
            client = _plain;
        }
        if (client == null) return await OsResolverAsync(name, type, sw, ct).ConfigureAwait(false);

        sw.Restart();
        var resp = await client.QueryAsync(name, type, QueryClass.IN, ct).ConfigureAwait(false);
        double ms = sw.Elapsed.TotalMilliseconds;
        var answers = new List<DnsAnswer>();
        foreach (var r in resp.Answers)
        {
            if (answers.Count == DnsWire.MaxAnswersParsed) break;
            answers.Add(FromDnsClient(r));
        }
        return new DnsResult
        {
            Resolver = Spec, Name = name, Type = type, Answered = true, Rcode = (int)resp.Header.ResponseCode,
            Answers = answers, AnswerCount = resp.Answers.Count, RttMs = ms,
            Via = Spec.Transport == DnsTransport.System ? _systemVia : "plain",
        };
    }

    private LookupClientOptions Options(params NameServer[] servers) => new(servers)
    {
        Timeout = _timeout, Retries = 0, UseCache = false, ThrowDnsErrors = false, ContinueOnDnsError = false,
        ContinueOnEmptyResponse = false, UseRandomNameServer = false,
    };

    // getaddrinfo: only addresses, no TTLs; "host not found" is the NXDOMAIN of this API
    private async Task<DnsResult> OsResolverAsync(string name, QueryType type, Stopwatch sw, CancellationToken ct)
    {
        if (type is not (QueryType.A or QueryType.AAAA))
            return new DnsResult
            {
                Resolver = Spec, Name = name, Type = type, Via = _systemVia,
                Error = $"the system's DNS servers can't be read on this device, and its resolver only answers A / AAAA — use an IP resolver for {type}",
                ShortError = "A/AAAA only",
            };
        sw.Restart();
        try
        {
            var family = type == QueryType.A ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;
            var addrs = await Dns.GetHostAddressesAsync(name, family, ct).ConfigureAwait(false);
            var answers = addrs.Select(a => new DnsAnswer(type.ToString(), a.ToString(), 0)).ToList();
            return new DnsResult
            {
                Resolver = Spec, Name = name, Type = type, Answered = true, Answers = answers, AnswerCount = answers.Count,
                RttMs = sw.Elapsed.TotalMilliseconds, Via = _systemVia,
            };
        }
        catch (SocketException se) when (se.SocketErrorCode is SocketError.HostNotFound or SocketError.NoData)
        {
            return new DnsResult
            {
                Resolver = Spec, Name = name, Type = type, Answered = true, Rcode = se.SocketErrorCode == SocketError.HostNotFound ? 3 : 0,
                RttMs = sw.Elapsed.TotalMilliseconds, Via = _systemVia,
            };
        }
    }

    /// <summary>A DnsClient record → the view's shape (strongly typed where possible, else DnsClient's own text).</summary>
    public static DnsAnswer FromDnsClient(DnsResourceRecord r)
    {
        string type = r.RecordType.ToString();
        return r switch
        {
            ARecord a => new(type, a.Address.ToString(), r.InitialTimeToLive),
            AaaaRecord a => new(type, a.Address.ToString(), r.InitialTimeToLive),
            CNameRecord c => new(type, c.CanonicalName.ToString(), r.InitialTimeToLive),
            MxRecord m => new(type, $"{m.Preference}  {m.Exchange}", r.InitialTimeToLive),
            NsRecord n => new(type, n.NSDName.ToString(), r.InitialTimeToLive),
            PtrRecord p => new(type, p.PtrDomainName.ToString(), r.InitialTimeToLive),
            TxtRecord t => new(type, string.Join(" ", t.Text), r.InitialTimeToLive, t.Text.ToArray()),
            SoaRecord s => new(type, $"{s.MName} {s.RName} (serial {s.Serial})", r.InitialTimeToLive),
            SrvRecord s => new(type, $"{s.Priority} {s.Weight} {s.Port} {s.Target}", r.InitialTimeToLive),
            CaaRecord c => new(type, $"{c.Flags} {c.Tag} {c.Value}", r.InitialTimeToLive),
            _ => new(type, r.ToString(), r.InitialTimeToLive),
        };
    }

    // ------------------------------------------------------------ DNS-over-HTTPS (RFC 8484)

    private static readonly Lazy<HttpClient> DohClient = new(() =>
    {
        var handler = new SocketsHttpHandler
        {
            // a DoH endpoint answers itself: no redirects (nothing to carry along), no cookies, and direct — every
            // transport is measured on the same path (plain DNS / DoT don't go through an HTTP proxy either)
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            PooledConnectionIdleTimeout = TimeSpan.FromSeconds(60),
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            MaxResponseHeadersLength = 32,   // KB
            ConnectCallback = ConnectAsync,
        };
        var client = new HttpClient(handler)
        {
            Timeout = Timeout.InfiniteTimeSpan,                // each query has its own deadline
            MaxResponseContentBufferSize = DnsWire.MaxMessageBytes,
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("Echoes");
        return client;
    });

    private static readonly MediaTypeHeaderValue DnsMessageType = new("application/dns-message");

    /// <summary>Test hook (the harness): send DoH queries as GET from the start. Internal on purpose.</summary>
    internal static bool PreferGetForTest { get; set; }

    private async Task<DnsResult> DohAsync(string name, QueryType type, Stopwatch sw, CancellationToken ct)
    {
        // ID 0 (RFC 8484 §4.1: cache-friendly); the question is still checked on the way back
        byte[] query = DnsWire.BuildQuery(name, (ushort)type, 0);
        bool get = PreferGetForTest;
        var resp = await SendDohAsync(query, get, sw, ct).ConfigureAwait(false);
        try
        {
            // an endpoint that only takes GET (or rejects this POST): once more as GET ?dns=<base64url>
            if (!get && resp.StatusCode is HttpStatusCode.MethodNotAllowed or HttpStatusCode.UnsupportedMediaType
                or HttpStatusCode.NotImplemented or HttpStatusCode.BadRequest)
            {
                resp.Dispose();
                get = true;
                resp = await SendDohAsync(query, get, sw, ct).ConfigureAwait(false);
            }
            string via = "DoH" + (resp.Version.Major >= 3 ? " h3" : resp.Version.Major == 2 ? " h2" : "") + (get ? " GET" : "");
            if (!resp.IsSuccessStatusCode)
            {
                int code = (int)resp.StatusCode;
                string why = code == 404 ? " — not a DoH endpoint (check the path, usually /dns-query)" : "";
                return Failed(name, type, sw, via, $"HTTP {code} {RemoteText.Clean(resp.ReasonPhrase, 60)}{why}".Trim(), $"HTTP {code}");
            }
            string? media = resp.Content.Headers.ContentType?.MediaType;
            if (media != null && !media.Equals("application/dns-message", StringComparison.OrdinalIgnoreCase))
                return Failed(name, type, sw, via, $"not a DoH answer (the server sent {RemoteText.Clean(media, 60)})", "not DoH");
            if (resp.Content.Headers.ContentLength > DnsWire.MaxMessageBytes)
                return Failed(name, type, sw, via, "the answer is larger than 64 KB", "too large");

            await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            byte[] body = await ReadCappedAsync(stream, DnsWire.MaxMessageBytes, ct).ConfigureAwait(false);
            return FromWire(name, type, body, 0, sw.Elapsed.TotalMilliseconds, via);
        }
        finally { resp.Dispose(); }
    }

    // One request (POST, or GET ?dns=). The clock starts here. A connection broken during the connect / handshake (a
    // flaky or filtered path, or a pooled connection the server dropped) is tried once more on a fresh one, within the
    // same deadline. No proxy lookup (UseProxy = false), so SendAsync doesn't block the calling thread.
    private async Task<HttpResponseMessage> SendDohAsync(byte[] query, bool get, Stopwatch sw, CancellationToken ct)
    {
        var client = DohClient.Value;
        sw.Restart();
        try { return await client.SendAsync(get ? Get(query) : Post(query), HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false); }
        catch (HttpRequestException e) when (!ct.IsCancellationRequested && IsConnectionFailure(e))
        {
            sw.Restart();
            return await client.SendAsync(get ? Get(query) : Post(query), HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        }
    }

    // the connection broke (reset, closed mid-handshake) — worth one more try; a certificate problem is not
    private static bool IsConnectionFailure(HttpRequestException e)
    {
        for (Exception? x = e.InnerException; x != null; x = x.InnerException)
            if (x is IOException or SocketException) return true;
        return false;
    }

    private static bool IsCertificateProblem(Exception ex)
        => ex is AuthenticationException a && a.Message.StartsWith("TLS: ", StringComparison.Ordinal);

    private HttpRequestMessage Post(byte[] query) => Request(HttpMethod.Post, null, query);

    private HttpRequestMessage Get(byte[] query)
    {
        string b64 = Convert.ToBase64String(query).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        string url = Spec.Url!.AbsoluteUri + (Spec.Url.Query.Length > 0 ? "&" : "?") + "dns=" + b64;
        return Request(HttpMethod.Get, url, null);
    }

    private HttpRequestMessage Request(HttpMethod method, string? url, byte[]? body)
    {
        var req = new HttpRequestMessage(method, url ?? Spec.Url!.AbsoluteUri)
        {
            Version = HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
        };
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));
        if (body != null)
        {
            req.Content = new ByteArrayContent(body);
            req.Content.Headers.ContentType = DnsMessageType;
        }
        return req;
    }

    private static async Task<byte[]> ReadCappedAsync(Stream s, int cap, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = await s.ReadAsync(buf, ct).ConfigureAwait(false)) > 0)
        {
            if (ms.Length + n > cap) throw new DnsWireException("the answer is larger than 64 KB");
            ms.Write(buf, 0, n);
        }
        return ms.ToArray();
    }

    /// <summary>Connects HTTP (DoH) sockets: a well-known provider's host goes straight to its published addresses,
    /// so a poisoned system resolver can't redirect it (the certificate is still checked against the name).</summary>
    private static async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext ctx, CancellationToken ct)
    {
        var ep = ctx.DnsEndPoint;
        Socket socket = await ConnectSocketAsync(ep.Host, ep.Port, ct).ConfigureAwait(false);
        return new NetworkStream(socket, ownsSocket: true);
    }

    private static async Task<Socket> ConnectSocketAsync(string host, int port, CancellationToken ct)
    {
        var candidates = new List<IPAddress>();
        if (IPAddress.TryParse(host.Trim('[', ']'), out var literal)) candidates.Add(literal);
        else candidates.AddRange(ResolverPresets.Bootstrap(host));

        Exception? last = null;
        foreach (var ip in candidates.Take(4))
        {
            var s = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try { await s.ConnectAsync(new IPEndPoint(ip, port), ct).ConfigureAwait(false); return s; }
            catch (Exception ex) when (!ct.IsCancellationRequested) { s.Dispose(); last = ex; }
            catch { s.Dispose(); throw; }
        }
        if (literal != null) throw last ?? new SocketException((int)SocketError.HostUnreachable);

        // any other name: the system resolver (dual stack, every address in turn)
        var sock = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try { await sock.ConnectAsync(new DnsEndPoint(host, port), ct).ConfigureAwait(false); return sock; }
        catch { sock.Dispose(); throw; }
    }

    // ------------------------------------------------------------ DNS-over-TLS (RFC 7858)

    // Runs inside one of the session's DoT slots (QueryAsync waits for it before the timeout starts): takes an idle
    // connection (or opens one), one query/answer on it, then puts it back for the next query.
    private async Task<DnsResult> DotAsync(string name, QueryType type, Stopwatch sw, CancellationToken ct)
    {
        ushort id = (ushort)RandomNumberGenerator.GetInt32(1, 65536);
        byte[] query = DnsWire.BuildQuery(name, (ushort)type, id);
        DotConnection? conn;
        lock (_dotIdle) conn = _dotIdle.Count > 0 ? _dotIdle.Pop() : null;
        sw.Restart();
        byte[] answer;
        try
        {
            conn ??= await DotConnection.OpenAsync(Spec, ct).ConfigureAwait(false);
            answer = await conn.ExchangeAsync(query, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested && ex is IOException or SocketException or ObjectDisposedException or AuthenticationException
                                   && !IsCertificateProblem(ex))
        {
            // the server closed the idle connection, or the connect / handshake was reset (a flaky or filtered path):
            // once more on a fresh connection, within the same deadline. A certificate that doesn't match isn't retried.
            conn?.Dispose();
            conn = null;
            sw.Restart();
            try
            {
                conn = await DotConnection.OpenAsync(Spec, ct).ConfigureAwait(false);
                answer = await conn.ExchangeAsync(query, ct).ConfigureAwait(false);
            }
            catch { conn?.Dispose(); throw; }
        }
        catch { conn?.Dispose(); throw; }
        double ms = sw.Elapsed.TotalMilliseconds;
        string via = "DoT" + (conn.Protocol is { Length: > 0 } p ? " " + p : "");
        // a connection whose answer didn't fit its query (another ID, a broken message) may still hold a stray answer:
        // back in the pool it would hand that to the next query, and so on — it is closed instead
        DnsResult result;
        try { result = FromWire(name, type, answer, id, ms, via); }
        catch { conn.Dispose(); throw; }
        lock (_dotIdle)
        {
            if (_disposed) conn.Dispose();
            else _dotIdle.Push(conn);
        }
        return result;
    }

    private sealed class DotConnection : IDisposable
    {
        private readonly Socket _socket;
        private readonly SslStream _ssl;
        public string Protocol { get; }

        private DotConnection(Socket socket, SslStream ssl)
        {
            _socket = socket;
            _ssl = ssl;
            Protocol = ssl.SslProtocol switch { SslProtocols.Tls13 => "TLS 1.3", SslProtocols.Tls12 => "TLS 1.2", _ => "" };
        }

        public static async Task<DotConnection> OpenAsync(ResolverSpec spec, CancellationToken ct)
        {
            Socket socket;
            if (spec.Endpoint is { } ep)
            {
                socket = new Socket(ep.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try { await socket.ConnectAsync(ep, ct).ConfigureAwait(false); }
                catch { socket.Dispose(); throw; }
            }
            else socket = await ConnectSocketAsync(spec.Host, spec.Port, ct).ConfigureAwait(false);

            string? nameError = null;
            bool Validate(object sender, X509Certificate? cert, X509Chain? chain, SslPolicyErrors errors)
            {
                if (errors == SslPolicyErrors.None) return true;
                // an IP-only DoT server (no known name): the certificate must list that address as an IP SAN
                if (spec.TlsName == null && errors == SslPolicyErrors.RemoteCertificateNameMismatch
                    && cert is X509Certificate2 c2 && spec.Endpoint is { } ip && HasIpSan(c2, ip.Address))
                    return true;
                nameError = (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0
                    ? $"the certificate isn't for {spec.TlsName ?? spec.Host}"
                    : (errors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0
                        ? "the server sent no certificate"
                        : "the certificate isn't trusted (its chain doesn't verify)";
                return false;
            }

            var ssl = new SslStream(new NetworkStream(socket, ownsSocket: true), leaveInnerStreamOpen: false, Validate);
            try
            {
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = spec.TlsName ?? spec.Host,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                }, ct).ConfigureAwait(false);
            }
            catch (AuthenticationException) when (nameError != null)
            {
                ssl.Dispose();
                throw new AuthenticationException("TLS: " + nameError);
            }
            catch
            {
                ssl.Dispose();
                throw;
            }
            return new DotConnection(socket, ssl);
        }

        public async Task<byte[]> ExchangeAsync(byte[] query, CancellationToken ct)
        {
            byte[] framed = new byte[query.Length + 2];
            framed[0] = (byte)(query.Length >> 8);
            framed[1] = (byte)query.Length;
            query.CopyTo(framed, 2);
            await _ssl.WriteAsync(framed, ct).ConfigureAwait(false);
            await _ssl.FlushAsync(ct).ConfigureAwait(false);

            byte[] lenBuf = new byte[2];
            await _ssl.ReadExactlyAsync(lenBuf, ct).ConfigureAwait(false);
            int len = lenBuf[0] << 8 | lenBuf[1];
            if (len < 12) throw new DnsWireException("the answer is shorter than a DNS header");
            byte[] msg = new byte[len];   // ≤ 65535 by the 2-byte frame
            await _ssl.ReadExactlyAsync(msg, ct).ConfigureAwait(false);
            return msg;
        }

        public void Dispose()
        {
            try { _ssl.Dispose(); } catch { }
            try { _socket.Dispose(); } catch { }
        }
    }

    internal static bool HasIpSan(X509Certificate2 cert, IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        foreach (var ext in cert.Extensions)
        {
            if (ext.Oid?.Value != "2.5.29.17") continue;
            try
            {
                var san = new X509SubjectAlternativeNameExtension(ext.RawData, ext.Critical);
                foreach (var a in san.EnumerateIPAddresses())
                    if (a.Equals(ip)) return true;
            }
            catch { }
        }
        return false;
    }

    // ------------------------------------------------------------ shared

    private DnsResult FromWire(string name, QueryType type, byte[] body, ushort id, double ms, string via)
    {
        var m = DnsWire.Parse(body);
        if (!m.IsResponse || m.Opcode != 0) throw new DnsWireException("the server didn't send a DNS response");
        if (m.Id != id) throw new DnsWireException("the answer is for another query (ID mismatch)");
        if (m.QuestionCount > 0 && (m.QuestionType != (ushort)type
                                    || !string.Equals(m.QuestionName?.TrimEnd('.'), name.TrimEnd('.'), StringComparison.OrdinalIgnoreCase)))
            throw new DnsWireException("the answer is for another question");
        if (m.QuestionCount == 0 && m.Rcode == 0) throw new DnsWireException("the answer has no question");
        if (m.Truncated) throw new DnsWireException("the answer is truncated");
        var answers = m.Answers.Select(a => new DnsAnswer(DnsWire.TypeName(a.Type), a.Value, (int)a.Ttl, a.Texts)).ToList();
        return new DnsResult
        {
            Resolver = Spec, Name = name, Type = type, Answered = true, Rcode = m.Rcode,
            Answers = answers, AnswerCount = m.AnswerCount, RttMs = ms, Via = via,
        };
    }

    private DnsResult Failed(string name, QueryType type, Stopwatch sw, string via, string error, string brief) => new()
    {
        Resolver = Spec, Name = name, Type = type, RttMs = sw.Elapsed.TotalMilliseconds, Via = via,
        Error = error, ShortError = brief,
    };

    /// <summary>One sentence + a word or two for an exception from any transport.</summary>
    private (string full, string brief) Describe(Exception ex, bool timedOut)
    {
        string target = Spec.Short;
        var e = SocketErrors.Unwrap(ex);
        if (e is HttpRequestException { InnerException: { } inner }) e = SocketErrors.Unwrap(inner);
        if (e is DnsResponseException { InnerException: { } dnsInner } && !timedOut) e = SocketErrors.Unwrap(dnsInner);
        if (e is IOException { InnerException: AuthenticationException ae }) e = ae;
        switch (e)
        {
            case OperationCanceledException or TimeoutException:
            case DnsResponseException when timedOut:
                return ("timeout", "timeout");
            case DnsResponseException dre when dre.Code == DnsResponseCode.ConnectionTimeout:
                return ("timeout", "timeout");
            case DnsWireException w:
                return ("bad answer: " + w.Message, "bad answer");
            case AuthenticationException a:
            {
                string m = a.Message.StartsWith("TLS: ", StringComparison.Ordinal) ? a.Message : SocketErrors.TlsFailure(a, target);
                return (m, "TLS failed");
            }
            case SocketException se:
            {
                string brief = se.SocketErrorCode switch
                {
                    SocketError.ConnectionRefused => "refused",
                    SocketError.ConnectionReset => "reset",
                    SocketError.TimedOut => "timeout",
                    SocketError.HostNotFound or SocketError.NoData or SocketError.TryAgain => "host unknown",
                    SocketError.NetworkUnreachable or SocketError.HostUnreachable or SocketError.NetworkDown => "unreachable",
                    _ => "network error",
                };
                return (SocketErrors.Describe(se, SocketAction.Connect, $"{target}"), brief);
            }
            case IOException:
                return ("the connection was closed (the server or a filter reset it)", "reset");
            case ArgumentException:
                return (OneLine(e.Message), "bad name");
        }
        return (OneLine(e.Message), "error");
    }

    private static string OneLine(string message)
    {
        string m = message.ReplaceLineEndings(" ").Trim();
        return m.Length > 200 ? m[..200] + "…" : m;
    }

    public void Dispose()
    {
        lock (_dotIdle)
        {
            if (_disposed) return;
            _disposed = true;
            while (_dotIdle.Count > 0) _dotIdle.Pop().Dispose();   // one still in use is closed when it comes back
        }
    }
}

/// <summary>One-shot queries (a session per call). For several queries to the same resolver keep a
/// <see cref="DnsSession"/>: DoT then pays one handshake for all of them.</summary>
public static class SecureDns
{
    public static async Task<DnsResult> QueryAsync(ResolverSpec spec, string name, QueryType type, CancellationToken ct, TimeSpan? timeout = null)
    {
        using var session = new DnsSession(spec, timeout);
        return await session.QueryAsync(name, type, ct).ConfigureAwait(false);
    }

    /// <summary>Punycode for an internationalized name; IPs and ASCII names unchanged; never throws.</summary>
    public static string ToAscii(string host)
    {
        if (string.IsNullOrEmpty(host) || IPAddress.TryParse(host, out _)) return host;
        try { return new IdnMapping().GetAscii(host.TrimEnd('.').ToLowerInvariant()); }   // lowercased: see TryParse
        catch { return host; }
    }
}
