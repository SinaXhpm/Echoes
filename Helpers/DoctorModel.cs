using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>The Doctor's checks, in the order they are listed: the direct path, then (with a proxy) the same through it.</summary>
public enum DoctorCheck
{
    Network, Internet, DnsSystem, DnsPlain, DnsEncrypted, Connect, Ping, Tls, Https, Http, Mtu, Outside,
    ProxyServer, ProxyDns, ProxyConnect, ProxyTls, ProxyHttps, ProxyHttp,
}

/// <summary>
/// Which ports the web checks use: HTTPS (TLS + an HTTPS request), plain HTTP, or a port that isn't a web port at all
/// (a TCP connect and a TLS probe only). The ones the input asked for are "primary"; the other scheme on its default
/// port is tested as an extra, so "HTTPS is cut, plain HTTP answers" shows up either way.
/// </summary>
public sealed record DoctorPorts(int? Https, int? Http, int? Raw, bool HttpsPrimary, bool HttpPrimary)
{
    /// <summary>Every port to connect to, the primary ones first.</summary>
    public IReadOnlyList<int> All
    {
        get
        {
            var list = new List<int>();
            void Add(int? p) { if (p is int v && !list.Contains(v)) list.Add(v); }
            if (Raw != null) Add(Raw);
            if (HttpsPrimary) Add(Https);
            if (HttpPrimary) Add(Http);
            Add(Https);
            Add(Http);
            return list;
        }
    }

    public bool IsWeb => Https != null || Http != null;
    /// <summary>Both schemes were asked for (no scheme or port given).</summary>
    public bool Both => HttpsPrimary && HttpPrimary;
}

/// <summary>Where one check stands.</summary>
public enum DoctorState { Pending, Running, Ok, Warning, Fail, Skipped }

/// <summary>The verdict card's four outcomes.</summary>
public enum DoctorVerdictKind { Works, Problem, Down, Unknown }

/// <summary>Receives the checks' progress. Called from worker threads; implementations only hand off.</summary>
public interface IDoctorSink
{
    void Report(DoctorCheck check, DoctorState state, string detail, double? ms = null);

    /// <summary>A fine-grained sub-step under one check (DNS record, TCP attempt, a TLS stage, an HTTP stage …): a short
    /// <paramref name="step"/> label, a one-line <paramref name="detail"/>, its state and time. Shown indented under the
    /// check so the user sees exactly where a connection gets stuck. Default: ignored.</summary>
    void Trace(DoctorCheck check, DoctorState state, string step, string detail, double? ms = null) { }
}

/// <summary>The one-sentence answer: what is wrong (or that nothing is), and what to do about it.</summary>
public sealed record DoctorVerdict(DoctorVerdictKind Kind, string Sentence, string Advice)
{
    public string Title => Kind switch
    {
        DoctorVerdictKind.Works => "Works",
        DoctorVerdictKind.Problem => "Problem found",
        DoctorVerdictKind.Down => "Down for everyone",
        _ => "Can't tell",
    };
}

/// <summary>What to diagnose, read from a host, URL or host:port.</summary>
public sealed class DoctorTarget
{
    /// <summary>Ports that speak TLS (HTTPS and Cloudflare's HTTPS ports).</summary>
    private static readonly HashSet<int> TlsPorts = new() { 443, 8443, 2053, 2083, 2087, 2096, 4443, 9443 };
    /// <summary>Ports that speak plain HTTP.</summary>
    private static readonly HashSet<int> HttpPorts = new() { 80, 8080, 8000, 8008, 8880, 8888, 2052, 2082, 2086, 2095, 3000, 5000 };

    /// <summary>The host as shown (an IDN in its own letters).</summary>
    public string Host { get; private init; } = "";
    /// <summary>The host as sent on the wire (punycode) — or the IP literal.</summary>
    public string AsciiHost { get; private init; } = "";
    public IPAddress? Ip { get; private init; }
    public bool IsIp => Ip != null;
    /// <summary>A port written in the input (host:port, or a URL's non-default port).</summary>
    public int? ExplicitPort { get; private init; }
    /// <summary>"http" / "https" (also ws / wss mapped), another scheme, or null when none was given.</summary>
    public string? Scheme { get; private init; }
    /// <summary>The path + query to request ("/" by default).</summary>
    public string Path { get; private init; } = "/";
    /// <summary>A name only the local network knows ("nas", "printer.local", "router.lan") or a private IP: public
    /// resolvers and check-host.net can't help with it.</summary>
    public bool IsLocal { get; private init; }

    /// <summary>The ports to try, in order: the given one, the scheme's, or HTTPS then HTTP.</summary>
    public IReadOnlyList<int> Ports => ExplicitPort is int p ? new[] { p }
        : Scheme == "http" ? new[] { 80 }
        : Scheme == "https" ? new[] { 443 }
        : SchemePort(Scheme) is int sp ? new[] { sp }
        : new[] { 443, 80 };

    public bool PortChosenByUser => ExplicitPort != null || Scheme != null;

    /// <summary>Does <paramref name="port"/> speak TLS? true / false, or null when only a probe can tell.</summary>
    public bool? SpeaksTls(int port)
    {
        if (Scheme == "https") return true;
        if (Scheme == "http") return false;
        if (Scheme is "smtps" or "imaps" or "pop3s" or "ftps" or "ldaps") return true;
        if (Scheme != null) return null;
        if (TlsPorts.Contains(port)) return true;
        if (HttpPorts.Contains(port)) return false;
        return null;
    }

    /// <summary>Is <paramref name="port"/> a web port (an HTTP request makes sense)?</summary>
    public bool IsWeb(int port)
        => Scheme is "http" or "https" || (Scheme == null && (TlsPorts.Contains(port) || HttpPorts.Contains(port)));

    /// <summary>"example.com", "example.com:8443", "[2001:db8::1]:443".</summary>
    public string Display(int? port = null)
    {
        int? p = port ?? ExplicitPort;
        string h = Ip?.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{Host}]" : Host;
        return p is int pp ? $"{h}:{pp}" : h;
    }

    /// <summary>
    /// The ports to test: HTTPS and HTTP together when nothing pins one (the default ports), the asked-for one plus the
    /// other scheme on its default port when a scheme or a web port is given, and just that port when it isn't a web
    /// port (ssh, smtps, a database).
    /// </summary>
    public DoctorPorts Plan(int defaultHttps = 443, int defaultHttp = 80)
    {
        if (Scheme == "https") return new(ExplicitPort ?? defaultHttps, ExplicitPort == defaultHttp ? null : defaultHttp, null, true, false);
        if (Scheme == "http") return new(ExplicitPort == defaultHttps ? null : defaultHttps, ExplicitPort ?? defaultHttp, null, false, true);
        if (Scheme != null) return new(null, null, ExplicitPort ?? SchemePort(Scheme) ?? defaultHttps, false, false);
        if (ExplicitPort is int p)
        {
            if (TlsPorts.Contains(p) || p == defaultHttps) return new(p, p == defaultHttp ? null : defaultHttp, null, true, false);
            if (HttpPorts.Contains(p) || p == defaultHttp) return new(p == defaultHttps ? null : defaultHttps, p, null, false, true);
            return new(null, null, p, false, false);
        }
        return new(defaultHttps, defaultHttp, null, true, true);
    }

    /// <summary>The URL for one scheme on <paramref name="port"/>: the input's path for the asked-for scheme, "/" for the
    /// extra one (a path written for https:// says nothing about the http:// side).</summary>
    public string Url(int port, bool tls, bool withPath)
    {
        string h = Ip?.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{AsciiHost}]" : AsciiHost;
        bool dflt = (tls && port == 443) || (!tls && port == 80);
        return (tls ? "https://" : "http://") + h + (dflt ? "" : ":" + port) + (withPath ? Path : "/");
    }

    /// <summary>The URL to request on <paramref name="port"/> (https when it speaks TLS).</summary>
    public string Url(int port, bool tls)
    {
        string h = Ip?.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{AsciiHost}]" : AsciiHost;
        bool dflt = (tls && port == 443) || (!tls && port == 80);
        return (tls ? "https://" : "http://") + h + (dflt ? "" : ":" + port) + Path;
    }

    private static int? SchemePort(string? scheme) => scheme switch
    {
        "smtps" => 465, "smtp" => 25, "submission" => 587, "imaps" => 993, "imap" => 143, "pop3s" => 995, "pop3" => 110,
        "ftps" => 990, "ftp" => 21, "ssh" => 22, "ldaps" => 636, "rdp" => 3389,
        _ => null,
    };

    /// <summary>Reads a host, IP, host:port or URL (a pasted log line or command too: the host it names).</summary>
    public static bool TryParse(string? raw, out DoctorTarget target, out string error)
    {
        target = new DoctorTarget();
        error = "";
        string s = (raw ?? "").Trim();
        if (s.Length == 0) { error = "Enter a site, URL or host:port to diagnose."; return false; }
        if (s.Length > 2048) { error = "That's too long for a host or URL."; return false; }

        var found = HostExtractor.Best(s);
        if (found is null)
        {
            error = $"\"{(s.Length > 60 ? s[..60] + "…" : s)}\" isn't a host name, URL or host:port.";
            return false;
        }

        string host = found.Host;
        int? port = found.Port;
        string? scheme = null;
        string path = "/";
        if (found.Url is { } url && Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.Host.Length > 0)
        {
            scheme = uri.Scheme.ToLowerInvariant() switch { "wss" => "https", "ws" => "http", var x => x };
            host = uri.HostNameType == UriHostNameType.IPv6 ? uri.Host.Trim('[', ']') : uri.Host.TrimEnd('.');
            port = uri.IsDefaultPort || uri.Port <= 0 ? null : uri.Port;
            if (scheme is "http" or "https")
            {
                path = uri.GetComponents(UriComponents.PathAndQuery, UriFormat.UriEscaped);
                if (path.Length == 0 || path[0] != '/') path = "/" + path;
                if (path.Length > 1024) path = path[..1024];
            }
        }

        IPAddress? ip = IPAddress.TryParse(host.Trim('[', ']'), out var parsed) ? DoctorIp.Normal(parsed) : null;
        string ascii = ip?.ToString() ?? SocketNet.AsciiHost(host.ToLowerInvariant());
        bool local = ip != null ? !DoctorIp.IsPublic(ip) : IsLocalName(ascii);
        if (port is 0 or > 65535) { error = "Port must be a number from 1 to 65535."; return false; }

        target = new DoctorTarget
        {
            Host = ip?.ToString() ?? host.ToLowerInvariant(),
            AsciiHost = ascii,
            Ip = ip,
            ExplicitPort = port,
            Scheme = scheme,
            Path = path,
            IsLocal = local,
        };
        return true;
    }

    /// <summary>A name only the local network can resolve: one label, or a local-only suffix.</summary>
    public static bool IsLocalName(string host)
    {
        string h = host.TrimEnd('.').ToLowerInvariant();
        if (!h.Contains('.')) return true;
        foreach (var suffix in new[] { ".local", ".lan", ".home", ".internal", ".home.arpa", ".localhost", ".localdomain", ".intranet", ".corp" })
            if (h.EndsWith(suffix, StringComparison.Ordinal)) return true;
        return false;
    }
}

/// <summary>A DNS-over-HTTPS resolver reached by its IP address, so asking it needs no DNS itself.</summary>
public sealed record DoctorDohEndpoint(string Name, Uri Uri, string Provider = "");

/// <summary>
/// Where the Doctor's checks go. <see cref="Default"/> is the real world; the test harness builds its own (loopback
/// servers, a fake resolver). Nothing here is a user setting: the Doctor has none.
/// </summary>
internal sealed class DoctorEnvironment
{
    public static DoctorEnvironment Default { get; } = new();

    /// <summary>This system's resolver (the one browsers use).</summary>
    public Func<string, CancellationToken, Task<IPAddress[]>> SystemResolve { get; init; }
        = (host, ct) => Dns.GetHostAddressesAsync(host, ct);

    /// <summary>Public resolvers asked over plain UDP (port 53).</summary>
    public IReadOnlyList<IPEndPoint> PlainDns { get; init; } = new[]
    {
        new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53),
        new IPEndPoint(IPAddress.Parse("8.8.8.8"), 53),
    };

    /// <summary>Encrypted resolvers (RFC 8484) of Cloudflare, Google, Quad9, AdGuard and OpenDNS, by IP literal: their
    /// certificates name the IPs. All are asked at once; the first answers win (a filter rarely blocks every one).</summary>
    public IReadOnlyList<DoctorDohEndpoint> Doh { get; init; } = new[]
    {
        new DoctorDohEndpoint("1.1.1.1", new Uri("https://1.1.1.1/dns-query"), "Cloudflare"),
        new DoctorDohEndpoint("8.8.8.8", new Uri("https://8.8.8.8/dns-query"), "Google"),
        new DoctorDohEndpoint("1.0.0.1", new Uri("https://1.0.0.1/dns-query"), "Cloudflare"),
        new DoctorDohEndpoint("8.8.4.4", new Uri("https://8.8.4.4/dns-query"), "Google"),
        new DoctorDohEndpoint("9.9.9.9", new Uri("https://9.9.9.9/dns-query"), "Quad9"),
        new DoctorDohEndpoint("94.140.14.14", new Uri("https://94.140.14.14/dns-query"), "AdGuard"),
        new DoctorDohEndpoint("208.67.222.222", new Uri("https://208.67.222.222/dns-query"), "OpenDNS"),
    };

    /// <summary>"Is the internet there": quick TCP connects to these.</summary>
    public IReadOnlyList<IPEndPoint> InternetProbes { get; init; } = new[]
    {
        new IPEndPoint(IPAddress.Parse("1.1.1.1"), 443),
        new IPEndPoint(IPAddress.Parse("8.8.8.8"), 443),
    };

    /// <summary>Names every resolver knows (does the system resolver answer at all).</summary>
    public IReadOnlyList<string> WellKnownNames { get; init; } = new[] { "www.google.com", "www.microsoft.com" };

    /// <summary>Captive-portal checks: plain HTTP URLs that answer 204 with no body when nothing intercepts.</summary>
    public IReadOnlyList<Uri> CaptiveChecks { get; init; } = new[]
    {
        new Uri("http://cp.cloudflare.com/generate_204"),
        new Uri("http://connectivitycheck.gstatic.com/generate_204"),
    };

    /// <summary>A name no filter blocks, sent as SNI to tell SNI filtering from a blocked address.</summary>
    public string HarmlessSni { get; init; } = "www.microsoft.com";

    /// <summary>check-host.net's API (a loopback mock in tests).</summary>
    public Uri? CheckHostBase { get; init; }

    /// <summary>Trust exactly these roots for the TLS check (tests: the harness's own CA).</summary>
    public X509Certificate2Collection? TrustRoots { get; init; }

    /// <summary>The "default" HTTPS / HTTP ports (tests: loopback servers on free ports play 443 and 80).</summary>
    public int DefaultHttpsPort { get; init; } = 443;
    public int DefaultHttpPort { get; init; } = 80;
}
