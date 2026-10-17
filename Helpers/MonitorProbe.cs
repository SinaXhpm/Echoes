using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>
/// One monitored target, parsed once from what the user typed: a bare host / IP, <c>host:port</c>,
/// <c>[v6]:port</c>, or an http(s) URL. Immutable, so a check round can read it off the UI thread.
/// </summary>
public sealed class MonitorEndpoint
{
    public const int MaxLength = 2048;

    private MonitorEndpoint(string address, string key, string displayName, string host, int port, string httpUrl)
    {
        Address = address;
        Key = key;
        DisplayName = displayName;
        Host = host;
        Port = port;
        HttpUrl = httpUrl;
    }

    /// <summary>What the user entered (trimmed; credentials stripped from a URL). Persisted as-is.</summary>
    public string Address { get; }

    /// <summary>Canonical identity, so <c>google.com</c>, <c>google.com:80</c> and <c>http://google.com/</c> — the
    /// very same three probes — count as one monitor.</summary>
    public string Key { get; }

    /// <summary>Compact label for the list: the address without its scheme / trailing slash.</summary>
    public string DisplayName { get; }

    /// <summary>ASCII (punycode) host without IPv6 brackets — what ping and the TCP connect resolve.</summary>
    public string Host { get; }

    /// <summary>Port the TCP check connects to.</summary>
    public int Port { get; }

    /// <summary>URL the HTTP check requests; empty where no web server is plausible.</summary>
    public string HttpUrl { get; }

    public bool HasHttp => HttpUrl.Length > 0;
    public bool IsHttps => HttpUrl.StartsWith("https:", StringComparison.OrdinalIgnoreCase);
    public string HttpLabel => IsHttps ? "HTTPS" : "HTTP";

    /// <summary>Parses one entry. <paramref name="error"/> is a plain-words reason when it isn't monitorable.</summary>
    public static bool TryParse(string? text, [NotNullWhen(true)] out MonitorEndpoint? endpoint, out string error)
    {
        endpoint = null;
        error = string.Empty;
        string line = (text ?? string.Empty).Trim();
        if (line.Length == 0) { error = "Enter a host, host:port or URL."; return false; }
        if (line.Length > MaxLength) { error = $"“{Clip(line)}” is too long."; return false; }
        foreach (char c in line)
        {
            if (char.IsWhiteSpace(c) || char.IsControl(c))
            {
                error = $"“{Clip(line)}” has a space in it — enter one target per line.";
                return false;
            }
        }

        // Only a real scheme is a URL: a bare host like "httpbin.org" starts with "http" but is not one.
        if (line.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || line.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            return TryParseUrl(line, out endpoint, out error);
        if (line.Contains("://", StringComparison.Ordinal))
        {
            error = $"“{Clip(line)}”: only http:// and https:// URLs can be monitored. For other services enter host:port.";
            return false;
        }
        return TryParseHost(line, out endpoint, out error);
    }

    private static bool TryParseUrl(string line, out MonitorEndpoint? endpoint, out string error)
    {
        endpoint = null;
        error = string.Empty;
        if (!Uri.TryCreate(line, UriKind.Absolute, out var uri) || uri.IdnHost.Length == 0)
        {
            error = $"“{Clip(line)}” isn't a valid URL.";
            return false;
        }

        string address = line;
        if (uri.UserInfo.Length > 0)
        {
            // HttpClient never sends URL credentials, and they must not end up in the profile file.
            uri = new UriBuilder(uri) { UserName = string.Empty, Password = string.Empty }.Uri;
            address = uri.AbsoluteUri;
        }

        // IdnHost drops the [] of an IPv6 literal and punycodes an IDN (the TCP connect's resolver can't take Unicode
        // off Windows); TCP-probe the URL's own port (8080, 443, …), not 80.
        string host = uri.IdnHost;
        string key = uri.GetComponents(UriComponents.SchemeAndServer | UriComponents.PathAndQuery, UriFormat.UriEscaped);

        string display = address;
        int sep = display.IndexOf("://", StringComparison.Ordinal);
        if (sep >= 0) display = display[(sep + 3)..];
        if (display.EndsWith('/') && display.IndexOf('/') == display.Length - 1) display = display[..^1];

        endpoint = new MonitorEndpoint(address, key, display, host, uri.Port, address);
        return true;
    }

    private static bool TryParseHost(string line, out MonitorEndpoint? endpoint, out string error)
    {
        endpoint = null;
        error = string.Empty;
        string host = line;
        string? portText = null;
        bool v6 = false;

        if (line.StartsWith('['))
        {
            // "[v6]" or "[v6]:port"
            int rb = line.IndexOf(']');
            if (rb <= 1) { error = $"“{Clip(line)}” isn't a valid IPv6 address."; return false; }
            host = line[1..rb];
            string rest = line[(rb + 1)..];
            if (rest.Length > 0)
            {
                if (rest[0] != ':') { error = $"“{Clip(line)}” isn't a valid address — use [IPv6]:port."; return false; }
                portText = rest[1..];
            }
            if (!IPAddress.TryParse(host, out var a6) || a6.AddressFamily != AddressFamily.InterNetworkV6)
            {
                error = $"“{Clip(host)}” isn't a valid IPv6 address.";
                return false;
            }
            v6 = true;
        }
        else
        {
            // An IPv6 address has ':' of its own, so only a single ':' means host:port — "2606:4700::1111" split
            // there would probe 0.0.10.46.
            int colons = 0;
            foreach (char c in line) if (c == ':') colons++;
            if (colons == 1)
            {
                int colon = line.IndexOf(':');
                host = line[..colon];
                portText = line[(colon + 1)..];
            }
            else if (colons > 1)
            {
                if (!IPAddress.TryParse(line, out var a6) || a6.AddressFamily != AddressFamily.InterNetworkV6)
                {
                    error = $"“{Clip(line)}” isn't a valid IPv6 address.";
                    return false;
                }
                v6 = true;
            }
        }

        int port = 80;
        if (portText is not null && !TryParsePort(portText, out port))
        {
            error = portText.Length == 0
                ? $"“{Clip(line)}” is missing the port number after the colon."
                : $"“{Clip(portText)}” isn't a valid port — use 1 to 65535.";
            return false;
        }
        if (host.Length == 0) { error = $"“{Clip(line)}” has no host name."; return false; }

        if (!v6)
        {
            string bare = host.EndsWith('.') ? host[..^1] : host;
            bool ipv4 = HostExtractor.IsStrictIPv4(bare);
            if (!ipv4 && !HostExtractor.IsHostName(bare, requireDot: false))
            {
                error = $"“{Clip(host)}” isn't a valid host name or IP address.";
                return false;
            }
        }

        string ascii = IcmpPinger.AsciiHost(host);   // IDN → punycode for the TCP connect (see TryParseUrl)
        // HTTP only where a web server is plausible: DNS/SSH/DB ports never answer a GET, so the check would time out
        // and pin the monitor down forever. Other ports get ping + TCP only.
        string? scheme = port is 80 or 8000 or 8080 ? "http" : port is 443 or 8443 ? "https" : null;
        string httpUrl = scheme is null ? string.Empty : BuildUrl(scheme, host, port);
        string key = httpUrl.Length > 0 && Uri.TryCreate(httpUrl, UriKind.Absolute, out var u)
            ? u.GetComponents(UriComponents.SchemeAndServer | UriComponents.PathAndQuery, UriFormat.UriEscaped)
            : $"tcp://{(v6 ? "[" + ascii.ToLowerInvariant() + "]" : ascii.ToLowerInvariant())}:{port}";

        endpoint = new MonitorEndpoint(line, key, line, ascii, port, httpUrl);
        return true;
    }

    private static bool TryParsePort(string s, out int port)
        => int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out port) && port is > 0 and <= 65535;

    // UriBuilder adds the [] an IPv6 host needs and omits a default port.
    private static string BuildUrl(string scheme, string host, int port)
    {
        try { return new UriBuilder(scheme, host, port).Uri.AbsoluteUri; }
        catch (UriFormatException) { return $"{scheme}://{host}:{port}"; }   // malformed host: the HTTP check reports it
    }

    private static string Clip(string s) => s.Length <= 60 ? s : s[..57] + "…";
}

/// <summary>Result of one probe (ping, TCP connect or HTTP request). <see cref="Ran"/> is false when the check is off
/// or doesn't apply to the target.</summary>
public readonly record struct ProbeResult(bool Ran, bool Ok, int Ms, int Code, string? Error)
{
    public static ProbeResult Success(int ms, int code = 0) => new(true, true, ms, code, null);
    public static ProbeResult Failure(string error, int ms = 0, int code = 0) => new(true, false, ms, code, error);

    /// <summary>The HTTP check answered, but its keyword rule failed (the text is missing / present).</summary>
    public bool Keyword { get; init; }
}

/// <summary>
/// One monitor as a check round sees it: its endpoint plus its own rules — a keyword the page must (not) contain, and the
/// certificate verdict known when the round started. Built on the UI thread, read on the thread pool (immutable).
/// </summary>
public sealed class MonitorProbeSpec
{
    public MonitorProbeSpec(MonitorEndpoint endpoint) => Endpoint = endpoint;

    public MonitorEndpoint Endpoint { get; }
    /// <summary>The HTTP check runs for this monitor even when it is off for all (a keyword is set on it).</summary>
    public bool ForceHttp { get; init; }
    /// <summary>Text the page is checked for (not case-sensitive); null = no keyword rule.</summary>
    public string? Keyword { get; init; }
    /// <summary>True: the page must contain <see cref="Keyword"/>; false: it must not.</summary>
    public bool KeywordMustContain { get; init; } = true;
    /// <summary>The last certificate check found this wrong with it (expired, untrusted…): the round fails with it.</summary>
    public string? CertProblem { get; init; }
}

/// <summary>Which checks a round runs and their per-check timeout.</summary>
public readonly record struct MonitorCheckOptions(bool Ping, bool Tcp, bool Http, int TimeoutMs)
{
    public bool AppliesTo(MonitorEndpoint ep) => Ping || Tcp || (Http && ep.HasHttp);
}

/// <summary>Everything one check of one target found out.</summary>
public sealed class CheckResult
{
    public ProbeResult Ping { get; init; }
    public ProbeResult Tcp { get; init; }
    public ProbeResult Http { get; init; }
    /// <summary>The certificate verdict applied to this round: ran (and failed) only while the last certificate check
    /// found a problem that this round's HTTPS request didn't disprove.</summary>
    public ProbeResult Cert { get; init; }
    /// <summary>The HTTPS request validated the certificate although the last certificate check had failed it: look again
    /// now (it was renewed / fixed).</summary>
    public bool CertRecheck { get; init; }
    /// <summary>The address ping resolved the host to (null when the lookup failed or ping is off).</summary>
    public string? Address { get; init; }

    public bool AnyRan => Ping.Ran || Tcp.Ran || Http.Ran;

    /// <summary>Up only when every check that ran passed.</summary>
    public bool Ok => AnyRan && (!Ping.Ran || Ping.Ok) && (!Tcp.Ran || Tcp.Ok) && (!Http.Ran || Http.Ok) && (!Cert.Ran || Cert.Ok);

    /// <summary>The monitor's response time: its HTTP check where it has one, else the TCP connect, else ping. NaN for
    /// a failed check (drawn as a gap).</summary>
    public double ResponseMs
    {
        get
        {
            if (!Ok) return double.NaN;
            if (Http.Ran) return Http.Ms;
            if (Tcp.Ran) return Tcp.Ms;
            return Ping.Ran ? Ping.Ms : double.NaN;
        }
    }

    /// <summary>Plain-words reason for a failed check, the most specific probe first ("HTTPS 503 Service
    /// Unavailable", "TCP 443 refused", "Ping timed out"); null when the check passed.</summary>
    public string? Reason(MonitorEndpoint ep)
    {
        if (Ok) return null;
        // A name that doesn't resolve fails every probe the same way: say that once, without a probe in front.
        if ((Http.Ran && Http.Error == MonitorProbe.DnsFailed) || (Tcp.Ran && Tcp.Error == MonitorProbe.DnsFailed)
            || (Ping.Ran && Ping.Error == MonitorProbe.DnsFailed))
            return MonitorProbe.DnsFailed;
        // The certificate's own verdict says more than the HTTPS request's "TLS error" it causes.
        if (Cert.Ran && !Cert.Ok) return Cert.Error ?? "TLS certificate problem";
        if (Http.Ran && !Http.Ok)
            return Http.Code > 0 ? Join($"{ep.HttpLabel} {Http.Code}", Http.Error) : $"{ep.HttpLabel} {Http.Error}";
        if (Tcp.Ran && !Tcp.Ok) return $"TCP {ep.Port} {Tcp.Error}";
        if (Ping.Ran && !Ping.Ok) return $"Ping {Ping.Error}";
        return "No check applies";
    }

    private static string Join(string a, string? b) => string.IsNullOrEmpty(b) ? a : a + " " + b;
}

/// <summary>
/// The monitor's network checks: ICMP ping, a TCP connect and an HTTP GET. Every probe catches its own failures and
/// reports them as a <see cref="ProbeResult"/> (never throws, except <see cref="OperationCanceledException"/> while a
/// batch waits for a free slot), and none of it touches the UI — a round runs entirely on the thread pool.
/// </summary>
public static class MonitorProbe
{
    public const int MinTimeoutMs = 200;
    public const int MaxTimeoutMs = 60_000;
    public const string DnsFailed = "DNS lookup failed";

    /// <summary>A keyword check reads at most this much of the page (decompressed).</summary>
    public const int MaxKeywordBodyBytes = 512 * 1024;
    public const int MaxKeywordLength = 200;

    // Happy-Eyeballs-style stagger: the next address gets its own attempt if the previous one hasn't connected by then.
    private const int ConnectStaggerMs = 250;

    /// <summary>A pooled client for the HTTP check. No client-wide timeout: each request gets the user's timeout
    /// through a linked token (see <see cref="HttpAsync"/>).</summary>
    public static HttpClient CreateHttpClient()
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 10,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None,   // only the status line is read
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),   // re-resolve DNS now and then: a moved site gets noticed
            PooledConnectionIdleTimeout = TimeSpan.FromSeconds(30),
            // An unread body is drained (to reuse the connection) only up to this; a bigger one closes its connection, and
            // the next check connects again. With the compressed answers asked for below, nearly every page fits — but no
            // check downloads more than this (the default was 1 MB per check). See the Accept-Encoding note below.
            MaxResponseDrainSize = 128 * 1024,
            // Same connect strategy as the TCP check (IPv4 first, staggered fallback), so both agree on a host.
            ConnectCallback = static async (context, ct) =>
            {
                var socket = await ConnectAsync(context.DnsEndPoint.Host, context.DnsEndPoint.Port, ct).ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
            },
        };
        // Test hook only (MonitorChecks.TestTrustRoot, never set by the app): a loopback test server's own root is trusted.
        if (MonitorChecks.TestTrustRoot is not null)
            handler.SslOptions.RemoteCertificateValidationCallback = static (_, cert, _, errors) =>
                errors == SslPolicyErrors.None
                || (errors == SslPolicyErrors.RemoteCertificateChainErrors && cert is X509Certificate2 c && MonitorChecks.TrustedByTestRoot(c));
        var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (compatible; Echoes-Monitor/1.0)");
        client.DefaultRequestHeaders.CacheControl = new CacheControlHeaderValue { NoCache = true };
        // Only the status line is read — but to reuse the connection, .NET drains an unread body when the response is
        // disposed, so every check downloaded the whole page: a 300 KB home page every 5 s is ~5 GB a day. Ask for it
        // compressed, as every browser does (never decoded here: AutomaticDecompression stays off), which cuts that to
        // what the server sends compressed, typically a quarter of it or less, and cap the drain (MaxResponseDrainSize).
        // Connection reuse — and so what the response time measures — is unchanged for any page that compresses to
        // 128 KB or less.
        foreach (var encoding in new[] { "gzip", "deflate", "br" })
            client.DefaultRequestHeaders.AcceptEncoding.Add(new StringWithQualityHeaderValue(encoding));
        return client;
    }

    /// <summary>Checks every endpoint, at most <paramref name="maxConcurrency"/> targets at a time (each still runs its
    /// ping / TCP / HTTP probes in parallel), so a long list can't open thousands of sockets at once.</summary>
    public static Task<CheckResult[]> CheckAllAsync(IReadOnlyList<MonitorEndpoint> endpoints, MonitorCheckOptions options,
                                                    HttpClient http, int maxConcurrency, CancellationToken ct)
    {
        var specs = new MonitorProbeSpec[endpoints.Count];
        for (int i = 0; i < specs.Length; i++) specs[i] = new MonitorProbeSpec(endpoints[i]);
        return CheckAllAsync(specs, options, http, maxConcurrency, ct);
    }

    /// <summary>As above, each monitor with its own rules (keyword, certificate verdict).</summary>
    public static async Task<CheckResult[]> CheckAllAsync(IReadOnlyList<MonitorProbeSpec> specs, MonitorCheckOptions options,
                                                          HttpClient http, int maxConcurrency, CancellationToken ct)
    {
        var results = new CheckResult[specs.Count];
        using var gate = new SemaphoreSlim(Math.Max(1, maxConcurrency));
        var tasks = new Task[specs.Count];
        for (int i = 0; i < specs.Count; i++)
        {
            int index = i;
            tasks[i] = Run();

            async Task Run()
            {
                await gate.WaitAsync(ct).ConfigureAwait(false);
                try { results[index] = await CheckAsync(specs[index], options, http, ct).ConfigureAwait(false); }
                finally { gate.Release(); }
            }
        }
        await Task.WhenAll(tasks).ConfigureAwait(false);
        return results;
    }

    /// <summary>Runs the enabled checks that apply to <paramref name="ep"/> in parallel.</summary>
    public static Task<CheckResult> CheckAsync(MonitorEndpoint ep, MonitorCheckOptions o, HttpClient http, CancellationToken ct)
        => CheckAsync(new MonitorProbeSpec(ep), o, http, ct);

    /// <summary>Runs the enabled checks that apply to the monitor in parallel, with its keyword and certificate rules.</summary>
    public static async Task<CheckResult> CheckAsync(MonitorProbeSpec spec, MonitorCheckOptions o, HttpClient http, CancellationToken ct)
    {
        var ep = spec.Endpoint;
        int timeout = Math.Clamp(o.TimeoutMs, MinTimeoutMs, MaxTimeoutMs);
        string? keyword = string.IsNullOrEmpty(spec.Keyword) ? null : spec.Keyword;
        var ping = o.Ping ? PingAsync(ep.Host, timeout, ct) : Task.FromResult((default(ProbeResult), (string?)null));
        var tcp = o.Tcp ? TcpAsync(ep.Host, ep.Port, timeout, ct) : Task.FromResult(default(ProbeResult));
        var web = (o.Http || spec.ForceHttp) && ep.HasHttp
            ? HttpAsync(ep.HttpUrl, timeout, http, keyword, spec.KeywordMustContain, ct)
            : Task.FromResult(default(ProbeResult));
        await Task.WhenAll(ping, tcp, web).ConfigureAwait(false);
        var (p, address) = ping.Result;
        var h = web.Result;

        // A certificate problem found earlier fails the round — unless this round's HTTPS request got an answer, i.e. the
        // client just validated the certificate (system trust store): it was fixed, so look again rather than fail.
        bool httpsVouched = ep.IsHttps && h.Ran && h.Code > 0;
        var cert = spec.CertProblem is { } problem && !httpsVouched ? ProbeResult.Failure(problem) : default;
        return new CheckResult
        {
            Ping = p, Address = address, Tcp = tcp.Result, Http = h, Cert = cert,
            CertRecheck = spec.CertProblem is not null && httpsVouched,
        };
    }

    private static async Task<(ProbeResult, string?)> PingAsync(string host, int timeout, CancellationToken ct)
    {
        IPAddress addr;
        try
        {
            // The lookup gets the same budget: a resolver that hangs (seen on Android) must not stall the round.
            using var dns = CancellationTokenSource.CreateLinkedTokenSource(ct);
            dns.CancelAfter(timeout);
            addr = await IcmpPinger.ResolveAsync(host, dns.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return (ProbeResult.Failure("DNS lookup timed out"), null); }
        catch (Exception) { return (ProbeResult.Failure(ct.IsCancellationRequested ? "canceled" : DnsFailed), null); }

        try
        {
            var r = await IcmpPinger.SendAsync(addr, timeout, ct).ConfigureAwait(false);
            // Where ICMP isn't permitted the probe went out as a UDP datagram (IcmpPinger's Auto): say so in the line.
            // PermissionDenied: neither works here, and the error says why (both reasons).
            string via = r.Method == PingMethod.Udp ? " · UDP" : "";
            if (r.Success) return (ProbeResult.Success((int)Math.Clamp(r.RoundtripMs, 0, int.MaxValue)), addr + via);
            return (ProbeResult.Failure(r.PermissionDenied ? r.Error ?? "not permitted here" : PingError(r.Error) + via), addr.ToString());
        }
        catch (Exception) { return (ProbeResult.Failure(ct.IsCancellationRequested ? "canceled" : "failed"), addr.ToString()); }
    }

    private static string PingError(string? e)
    {
        if (string.IsNullOrEmpty(e)) return "no reply";
        if (e.Contains("TimedOut", StringComparison.OrdinalIgnoreCase) || e.Contains("timed out", StringComparison.OrdinalIgnoreCase)) return "timed out";
        if (e.Contains("Unreachable", StringComparison.OrdinalIgnoreCase)) return "unreachable";
        if (e.Contains("Ttl", StringComparison.OrdinalIgnoreCase)) return "TTL expired";
        return "no reply";
    }

    private static async Task<ProbeResult> TcpAsync(string host, int port, int timeout, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        // Linked CTS: the timeout cancels the lookup and every pending connect attempt (no orphaned timer / socket).
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(timeout);
        try
        {
            // Only a completed connect is "up"; a refused/unreachable one fails fast — not a timeout.
            using var socket = await ConnectAsync(host, port, budget.Token).ConfigureAwait(false);
            int ms = (int)sw.ElapsedMilliseconds;
            // Make the `using` dispose an abortive close (RST): a graceful one leaves this end in TIME_WAIT for 1-2 min,
            // and 256 targets every 2 s pile up ~15K of them, near the ephemeral-port limit. Best effort: if the option
            // can't be set (peer already reset it), the probe still succeeded.
            try { socket.LingerState = new LingerOption(true, 0); } catch { }
            return ProbeResult.Success(ms);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return ProbeResult.Failure("timed out"); }
        catch (Exception ex) { return ProbeResult.Failure(ct.IsCancellationRequested ? "canceled" : Describe(ex)); }
    }

    /// <summary>
    /// Resolves <paramref name="host"/> and connects to the first address that answers: IPv4 addresses first (as ping
    /// does), each next address started <see cref="ConnectStaggerMs"/> after the previous one if that hasn't connected
    /// yet — or at once when it failed. Without this, "localhost:3000" for a server listening on 127.0.0.1 only timed
    /// out: Windows tries ::1 first and retries a refused connect for ~2 s before moving on. Throws on failure;
    /// <paramref name="ct"/> carries the timeout.
    /// </summary>
    internal static async Task<Socket> ConnectAsync(string host, int port, CancellationToken ct)
    {
        IPAddress[] found = IPAddress.TryParse(host, out var literal)
            ? new[] { literal }
            : await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
        var ordered = new List<IPAddress>(Math.Min(found.Length, 4));
        foreach (var a in found) if (a.AddressFamily == AddressFamily.InterNetwork && ordered.Count < 4) ordered.Add(a);
        foreach (var a in found) if (a.AddressFamily == AddressFamily.InterNetworkV6 && ordered.Count < 4) ordered.Add(a);
        if (ordered.Count == 0) throw new SocketException((int)SocketError.HostNotFound);

        using var race = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var pending = new List<Task<Socket>>(ordered.Count);
        Exception? lastError = null;
        int next = 0;
        try
        {
            while (true)
            {
                if (next < ordered.Count) pending.Add(AttemptAsync(ordered[next++], port, race.Token));
                if (pending.Count == 0) throw lastError ?? new SocketException((int)SocketError.HostUnreachable);

                // Wait for an attempt to end — or, while addresses are left, the stagger delay.
                var waitFor = new List<Task>(pending);
                Task? stagger = next < ordered.Count ? Task.Delay(ConnectStaggerMs, race.Token) : null;
                if (stagger is not null) waitFor.Add(stagger);
                var done = await Task.WhenAny(waitFor).ConfigureAwait(false);
                if (done == stagger) continue;   // start the next address alongside

                var attempt = (Task<Socket>)done;
                pending.Remove(attempt);
                if (attempt.IsCompletedSuccessfully) return attempt.Result;
                ct.ThrowIfCancellationRequested();   // the timeout: report it as such, not as the attempt's own error
                lastError = attempt.Exception?.InnerException ?? lastError;
            }
        }
        finally
        {
            // Losers: cancelled now; one that connected meanwhile is closed, a failed one observed.
            race.Cancel();
            foreach (var t in pending)
                _ = t.ContinueWith(static x => { if (x.IsCompletedSuccessfully) x.Result.Dispose(); else _ = x.Exception; },
                    CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }
    }

    private static async Task<Socket> AttemptAsync(IPAddress address, int port, CancellationToken ct)
    {
        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, port), ct).ConfigureAwait(false);
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private static async Task<ProbeResult> HttpAsync(string url, int timeout, HttpClient http, string? keyword, bool mustContain,
                                                     CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(timeout);
        int ms = 0, code = 0;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            // ResponseHeadersRead + dispose returns the connection to the pool right after the status line; the body is
            // never downloaded — unless a keyword rule needs the page (then at most MaxKeywordBodyBytes of it).
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, linked.Token).ConfigureAwait(false);
            ms = (int)sw.ElapsedMilliseconds;
            code = (int)response.StatusCode;
            // 2xx and 3xx (a redirect that wasn't followed, e.g. https → http) mean the site answered; 4xx / 5xx are
            // outages, as in every uptime monitor.
            if (code is >= 200 and <= 399)
            {
                if (keyword is null) return ProbeResult.Success(ms, code);
                var (found, capped, readError) = await FindKeywordAsync(response, keyword, linked.Token).ConfigureAwait(false);
                if (readError is not null)
                    return ProbeResult.Failure("but the page couldn't be read (" + readError + ")", ms, code) with { Keyword = true };
                if (found == mustContain) return ProbeResult.Success(ms, code);
                string quoted = "“" + Clip(keyword, 40) + "”";
                string why = !mustContain ? $"but the page contains {quoted}"
                    : capped ? $"but {quoted} isn't in the first {MaxKeywordBodyBytes / 1024} KB"
                    : $"but {quoted} is missing";
                return ProbeResult.Failure(why, ms, code) with { Keyword = true };
            }
            string? phrase = response.ReasonPhrase;
            if (phrase is { Length: > 40 }) phrase = phrase[..40];
            return ProbeResult.Failure(phrase ?? string.Empty, ms, code);
        }
        // The page itself timing out after its status line came: a failed keyword check with the status kept.
        catch (OperationCanceledException) when (!ct.IsCancellationRequested && code > 0)
        {
            return ProbeResult.Failure("but the page timed out", ms, code) with { Keyword = true };
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return ProbeResult.Failure("timed out"); }
        catch (Exception ex) { return ProbeResult.Failure(ct.IsCancellationRequested ? "canceled" : Describe(ex)); }
    }

    private static string Clip(string s, int max) => s.Length <= max ? s : s[..(max - 1)] + "…";

    /// <summary>
    /// Reads the body — decompressing gzip / deflate / br itself, since the client asks for compressed pages and never
    /// decodes them — up to <see cref="MaxKeywordBodyBytes"/>, and looks for <paramref name="keyword"/> (not
    /// case-sensitive). The timeout cancelling the read throws (the caller reports it); other read problems come back as text.
    /// </summary>
    private static async Task<(bool Found, bool Capped, string? Error)> FindKeywordAsync(HttpResponseMessage response, string keyword, CancellationToken ct)
    {
        Stream? body = null;
        try
        {
            body = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            var encodings = new List<string>(response.Content.Headers.ContentEncoding);
            for (int i = encodings.Count - 1; i >= 0; i--)
            {
                Stream? decoded = encodings[i].Trim().ToLowerInvariant() switch
                {
                    "gzip" or "x-gzip" => new GZipStream(body, CompressionMode.Decompress),
                    "deflate" => new ZLibStream(body, CompressionMode.Decompress),
                    "br" => new BrotliStream(body, CompressionMode.Decompress),
                    "identity" or "" => body,
                    _ => null,
                };
                if (decoded is null) return (false, false, "unsupported encoding " + Clip(encodings[i], 20));
                body = decoded;
            }

            byte[] buf = new byte[16 * 1024];
            using var ms = new MemoryStream();
            bool capped = false;
            int n;
            while ((n = await body.ReadAsync(buf, ct).ConfigureAwait(false)) > 0)
            {
                int room = MaxKeywordBodyBytes - (int)ms.Length;
                if (n >= room) { ms.Write(buf, 0, room); capped = true; break; }
                ms.Write(buf, 0, n);
            }
            // UTF-8 (a Latin-1 page still matches an ASCII keyword byte for byte).
            string text = Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);
            return (text.Contains(keyword, StringComparison.OrdinalIgnoreCase), capped, null);
        }
        catch (OperationCanceledException) { throw; }
        catch (InvalidDataException) { return (false, false, "bad compressed data"); }
        catch (Exception ex) { return (false, false, Describe(ex)); }
        finally
        {
            if (body is not null) await body.DisposeAsync().ConfigureAwait(false);
        }
    }

    /// <summary>A failed connect / request in plain words.</summary>
    internal static string Describe(Exception? ex)
    {
        HttpRequestError? httpError = null;
        // InnerException walks into an AggregateException's first inner one as well.
        for (var e = ex; e is not null; e = e.InnerException)
        {
            switch (e)
            {
                case SocketException s:
                    return s.SocketErrorCode switch
                    {
                        SocketError.ConnectionRefused => "refused",
                        SocketError.HostNotFound or SocketError.NoData or SocketError.TryAgain => DnsFailed,
                        SocketError.HostUnreachable or SocketError.NetworkUnreachable or SocketError.HostDown or SocketError.NetworkDown => "unreachable",
                        SocketError.TimedOut => "timed out",
                        SocketError.ConnectionReset or SocketError.ConnectionAborted => "connection reset",
                        SocketError.AccessDenied => "blocked",
                        _ => "connection failed",
                    };
                case AuthenticationException:
                    return "TLS error";
                case HttpRequestException h when h.HttpRequestError != HttpRequestError.Unknown:
                    httpError ??= h.HttpRequestError;
                    break;
                case TimeoutException or OperationCanceledException:
                    return "timed out";
            }
        }
        return httpError switch
        {
            HttpRequestError.NameResolutionError => DnsFailed,
            HttpRequestError.ConnectionError => "connection failed",
            HttpRequestError.SecureConnectionError => "TLS error",
            HttpRequestError.ResponseEnded => "connection closed",
            HttpRequestError.InvalidResponse or HttpRequestError.HttpProtocolError => "bad response",
            HttpRequestError.ProxyTunnelError => "proxy error",
            _ => "failed",
        };
    }
}

/// <summary>Short, culture-independent text for the monitor's numbers and times.</summary>
public static class MonitorFormat
{
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    public static string Ms(double ms)
    {
        if (double.IsNaN(ms)) return "–";
        if (ms < 0.5) return "<1 ms";
        if (ms < 1000) return Math.Round(ms).ToString("0", Inv) + " ms";
        return (ms / 1000).ToString(ms < 10_000 ? "0.0" : "0", Inv) + " s";
    }

    /// <summary>"45s", "4m 12s", "2h 05m", "3d 4h".</summary>
    public static string Duration(TimeSpan d)
    {
        if (d < TimeSpan.Zero) d = TimeSpan.Zero;
        if (d.TotalSeconds < 60) return ((int)d.TotalSeconds).ToString(Inv) + "s";
        if (d.TotalMinutes < 60) return $"{(int)d.TotalMinutes}m {d.Seconds:00}s";
        if (d.TotalHours < 24) return $"{(int)d.TotalHours}h {d.Minutes:00}m";
        return $"{(int)d.TotalDays}d {d.Hours}h";
    }

    /// <summary>"just now", "8s ago", "4m ago", "2h ago".</summary>
    public static string Age(TimeSpan d)
    {
        if (d.TotalSeconds < 1) return "just now";
        if (d.TotalSeconds < 60) return ((int)d.TotalSeconds).ToString(Inv) + "s ago";
        if (d.TotalMinutes < 60) return ((int)d.TotalMinutes).ToString(Inv) + "m ago";
        if (d.TotalHours < 24) return ((int)d.TotalHours).ToString(Inv) + "h ago";
        return ((int)d.TotalDays).ToString(Inv) + "d ago";
    }

    /// <summary>Row column "Checked": "now", "8s", "4m", "2h", "3d".</summary>
    public static string ShortAge(TimeSpan d)
    {
        if (d.TotalSeconds < 1) return "now";
        if (d.TotalSeconds < 60) return ((int)d.TotalSeconds).ToString(Inv) + "s";
        if (d.TotalMinutes < 60) return ((int)d.TotalMinutes).ToString(Inv) + "m";
        if (d.TotalHours < 24) return ((int)d.TotalHours).ToString(Inv) + "h";
        return ((int)d.TotalDays).ToString(Inv) + "d";
    }

    /// <summary>"5 s", "90 s", "5 min", "1 h 30 min".</summary>
    public static string Interval(int seconds)
    {
        if (seconds < 120 || seconds % 60 != 0) return seconds.ToString(Inv) + " s";
        int min = seconds / 60;
        if (min < 60) return min.ToString(Inv) + " min";
        return min % 60 == 0 ? (min / 60).ToString(Inv) + " h" : $"{min / 60} h {min % 60} min";
    }

    /// <summary>Clock time; a date is added for anything not from today.</summary>
    public static string Clock(DateTime t, DateTime now)
        => t.Date == now.Date ? t.ToString("HH:mm:ss", Inv) : t.ToString("MMM d, HH:mm", Inv);

    /// <summary>Share of successful checks: "100%" only when nothing failed (never rounded up to it).</summary>
    public static string Percent(long ok, long total)
    {
        if (total <= 0) return "–";
        if (ok >= total) return "100%";
        if (ok <= 0) return "0%";
        double p = Math.Floor(1000.0 * ok / total) / 10;
        return p.ToString("0.0", Inv) + "%";
    }

    public static string Count(long n) => n.ToString("#,0", Inv);
}
