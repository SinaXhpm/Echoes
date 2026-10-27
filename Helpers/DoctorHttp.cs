using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

public sealed class DoctorHttpResult
{
    /// <summary>An HTTP status came back for the first request.</summary>
    public bool Answered { get; set; }
    /// <summary>The last status in the chain.</summary>
    public int Status { get; set; }
    public string Reason { get; set; } = "";
    public string? Server { get; set; }
    /// <summary>Time to the first response's headers (connect + TLS + server time).</summary>
    public double FirstByteMs { get; set; }
    /// <summary>"301 → https://www.example.com/" per redirect followed (or seen).</summary>
    public List<string> Chain { get; } = new();
    /// <summary>The answer is a filter's block page (why: "redirects to 10.10.34.34", "a block page (peyvandha)").</summary>
    public string? FilterPage { get; set; }
    /// <summary>The answer is a captive portal's sign-in page.</summary>
    public string? CaptivePage { get; set; }
    public string? Error { get; set; }
    public bool TimedOut { get; set; }
    /// <summary>The URL the chain ended on (an http:// one that went to https://, …).</summary>
    public Uri? FinalUrl { get; set; }
    /// <summary>A proxy refused the login or wants one (the site was never reached).</summary>
    public bool ProxyLogin { get; set; }
    /// <summary>A redirect in the chain went to https://.</summary>
    public bool RedirectsToHttps => Chain.Exists(c => c.Contains("→ https://", StringComparison.Ordinal));
    /// <summary>The redirect target's host when a later hop (not the site itself) failed.</summary>
    public string? FailedHost { get; set; }

    // ---- what was sent and what came back, for the trace and the log
    /// <summary>The imported request went out (rather than the Doctor's own GET).</summary>
    public bool Imported { get; set; }
    /// <summary>The first request as sent: method, target (path and query) and headers, and its body's size.</summary>
    public string Method { get; set; } = "GET";
    public string Target { get; set; } = "/";
    public List<(string Name, string Value)> Sent { get; } = new();
    public int SentBody { get; set; }
    /// <summary>Where the first request went ("93.184.215.14:443", "the proxy's tunnel"), when known.</summary>
    public string? Remote { get; set; }
    /// <summary>The answer's HTTP version ("HTTP/2", "HTTP/1.1").</summary>
    public string? Version { get; set; }
    /// <summary>The last answer's headers as they came (content headers too).</summary>
    public List<(string Name, string Value)> Headers { get; } = new();
    /// <summary>The first connection's TCP connect and TLS handshake (null when not seen, as through an HTTP proxy).</summary>
    public double? ConnectMs { get; set; }
    public double? TlsMs { get; set; }
    /// <summary>From the first request out to the end of the body (as far as it was read).</summary>
    public double TotalMs { get; set; }
    /// <summary>The body as read (decoded; at most 64 KB) and whether there was more.</summary>
    public int BodyBytes { get; set; }
    public bool BodyCut { get; set; }
    public string? ContentType { get; set; }
    /// <summary>The body's encoding when it couldn't be decoded here (zstd …): its size is then the encoded one.</summary>
    public string? Undecoded { get; set; }
    /// <summary>The start of a text body on one line, cleaned and capped; null for none or a body that isn't text.</summary>
    public string? Preview { get; set; }
    /// <summary>What the exchange did that is worth saying ("it redirects off example.com: your headers weren't sent on").</summary>
    public List<string> Notes { get; } = new();
}

/// <summary>
/// One request to the site, connected to the address the Doctor trusts (never the system resolver's, which may be the
/// filter's): the Doctor's own GET, or a request imported from the browser exactly as it was copied. Redirects are
/// followed by hand (at most five, recorded), the body read only up to a small cap — and checked for a filter's block
/// page or a captive portal. No cookie store; the certificate was judged by the TLS check. What was sent and what came
/// back (version, headers, timing, size, the start of the body) is kept for the trace.
/// </summary>
public static class DoctorHttp
{
    private const int MaxHops = 5;
    private const int BodyCap = 64 * 1024;
    private const int WireCap = 256 * 1024;

    // a block page names the filter: Iran's (peyvandha.ir, the 10.10.34.34 iframe), Russia's, Turkey's
    private static readonly string[] FilterMarkers =
    {
        "peyvandha", "10.10.34.34", "10.10.34.35", "10.10.34.36", "warning.rt.ru", "blocklist.rkn.gov.ru", "eais.rkn.gov.ru",
        "195.175.254.2",
    };

    private static readonly string[] PortalWords = { "login", "portal", "hotspot", "captive", "splash", "wifi", "guest", "auth" };

    private const string UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36";

    /// <summary>The request to <paramref name="url"/> at <paramref name="pinned"/>: <paramref name="request"/> (imported
    /// from the browser) when given, else a plain GET. A redirect's other host is looked up by <paramref name="resolveOther"/>.</summary>
    public static async Task<DoctorHttpResult> GetAsync(Uri url, IPAddress pinned, Func<string, CancellationToken, Task<IPAddress?>> resolveOther,
                                                        DoctorRequest? request, CancellationToken ct)
    {
        var known = new ConcurrentDictionary<string, IPAddress>(StringComparer.OrdinalIgnoreCase) { [url.IdnHost] = pinned };
        var st = new Stages();
        using var handler = NewHandler(st);
        handler.ConnectCallback = async (ctx, token) =>
        {
            string host = ctx.DnsEndPoint.Host.Trim('[', ']');
            IPAddress? ip = IPAddress.TryParse(host, out var lit) ? lit
                : known.TryGetValue(host, out var k) ? k
                : await resolveOther(host, token).ConfigureAwait(false);
            if (ip == null) throw new SocketException((int)SocketError.HostNotFound);
            known[host] = ip;
            var s = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                st.Connecting();
                await s.ConnectAsync(new IPEndPoint(ip, ctx.DnsEndPoint.Port), token).ConfigureAwait(false);
                st.Connected(DoctorIp.EndPoint(ip, ctx.DnsEndPoint.Port));
                return new NetworkStream(s, ownsSocket: true);
            }
            catch
            {
                s.Dispose();
                throw;
            }
        };

        // a redirect to another host: its address first, on its own budget (the request's 8 s are for the server)
        async Task<(string? Error, string? Filter)> PrepareHop(string hopHost, CancellationToken token)
        {
            if (IPAddress.TryParse(hopHost, out _) || known.ContainsKey(hopHost)) return (null, null);
            IPAddress? ip;
            using (var rcts = CancellationTokenSource.CreateLinkedTokenSource(token))
            {
                rcts.CancelAfter(5000);
                try { ip = await resolveOther(hopHost, rcts.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) when (!token.IsCancellationRequested) { ip = null; }
            }
            if (ip == null) return ($"{hopHost} (where it redirects) can't be resolved", null);
            if (!DoctorIp.IsPublic(ip) && DoctorIp.IsPublic(pinned))
                return (null, $"it redirects to {hopHost}, which resolves to {ip} here ({DoctorIp.Kind(ip)})");
            known[hopHost] = ip;
            return (null, null);
        }

        return await RunAsync(url, handler, st, request, PrepareHop, ct).ConfigureAwait(false);
    }

    /// <summary>The same request through <paramref name="proxy"/>: an HTTP proxy the standard way (absolute URLs, CONNECT
    /// for https), other kinds through the Doctor's own tunnel. Names are resolved by the proxy — except the site's own name
    /// when <paramref name="dial"/> (the override IP) is set: its tunnels go to that address. An http:// request through
    /// an HTTP proxy names the site and the proxy connects to it, so the override can't apply there.</summary>
    public static async Task<DoctorHttpResult> GetViaProxyAsync(Uri url, DoctorProxy proxy, IPAddress? dial, DoctorRequest? request,
                                                                CancellationToken ct)
    {
        var st = new Stages();
        using var handler = NewHandler(st);
        string site = url.IdnHost.Trim('[', ']');
        if (proxy.Kind == DoctorProxyKind.Http && (dial == null || url.Scheme == Uri.UriSchemeHttp))
        {
            handler.Proxy = new WebProxy(new Uri($"http://{(proxy.Host.Contains(':') ? $"[{proxy.Host}]" : proxy.Host)}:{proxy.Port}"))
            {
                Credentials = proxy.Credentials,
                BypassProxyOnLocal = false,
            };
            handler.UseProxy = true;
        }
        else
            handler.ConnectCallback = async (ctx, token) =>
            {
                string h = ctx.DnsEndPoint.Host.Trim('[', ']');
                if (dial != null && h.Equals(site, StringComparison.OrdinalIgnoreCase)) h = dial.ToString();
                st.Connecting();
                var tunnel = await proxy.OpenAsync(h, ctx.DnsEndPoint.Port, 8000, token).ConfigureAwait(false);
                st.Connected("the proxy's tunnel to " + (h.Contains(':') ? $"[{h}]" : h) + ":" + ctx.DnsEndPoint.Port);
                return tunnel.Stream;
            };
        var res = await RunAsync(url, handler, st, request, null, ct).ConfigureAwait(false);
        if (res.Answered && res.Status == 407)
        {
            // the proxy answered for the site: its login, not the site's page
            res.Answered = false;
            res.ProxyLogin = true;
            res.Error = proxy.HasLogin ? "the proxy refused the login (HTTP 407)" : "the proxy wants a login (HTTP 407)";
        }
        return res;
    }

    // Decoding is done here, not by the handler: its automatic decoding drops Content-Encoding and Content-Length from
    // the headers shown, and those are part of what the server said.
    private static SocketsHttpHandler NewHandler(Stages st)
    {
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            MaxResponseHeadersLength = 64,
            UseCookies = false,
        };
        handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;
        // called once a new connection is ready to carry requests: after the TLS handshake on an https:// one
        handler.PlaintextStreamFilter = (ctx, _) =>
        {
            if (ctx.InitialRequestMessage.RequestUri?.Scheme == Uri.UriSchemeHttps) st.Secured();
            return ValueTask.FromResult(ctx.PlaintextStream);
        };
        return handler;
    }

    // When the first connection's stages ended, for the timing line (a later hop's connection doesn't change them). The
    // hops go one after another, so the callbacks never race.
    private sealed class Stages
    {
        private readonly Stopwatch _clock = Stopwatch.StartNew();
        private double _start = -1, _connected = -1, _secured = -1;
        public string? Remote { get; private set; }
        public double? ConnectMs => _start >= 0 && _connected >= 0 ? _connected - _start : null;
        public double? TlsMs => _connected >= 0 && _secured >= 0 ? _secured - _connected : null;
        public void Connecting() { if (_start < 0) _start = Now; }
        public void Connected(string remote)
        {
            if (_connected >= 0) return;
            _connected = Now;
            Remote = remote;
        }
        public void Secured() { if (_secured < 0 && _connected >= 0) _secured = Now; }
        private double Now => _clock.Elapsed.TotalMilliseconds;
    }

    private static async Task<DoctorHttpResult> RunAsync(Uri url, SocketsHttpHandler handler, Stages st, DoctorRequest? request,
                                                         Func<string, CancellationToken, Task<(string? Error, string? Filter)>>? prepareHop,
                                                         CancellationToken ct)
    {
        var res = new DoctorHttpResult { Imported = request != null };
        using var http = new HttpClient(handler, disposeHandler: false) { Timeout = Timeout.InfiniteTimeSpan };

        var current = url;
        var visited = new HashSet<string>(StringComparer.Ordinal) { url.AbsoluteUri };
        // the imported request goes as it was copied; on a redirect a browser's rules apply: 303 (and 301 / 302 after a
        // POST) go on as a GET without the body, 307 / 308 keep both — and it never leaves its own origin with its headers
        var method = request != null ? new HttpMethod(request.Method) : HttpMethod.Get;
        bool withBody = request?.Body != null;
        var own = request;
        var total = Stopwatch.StartNew();
        for (int hop = 0; hop <= MaxHops; hop++)
        {
            string hopHost = current.IdnHost.Trim('[', ']');
            if (hop > 0 && prepareHop != null)
            {
                var (err, filter) = await prepareHop(hopHost, ct).ConfigureAwait(false);
                if (err != null || filter != null)
                {
                    res.FailedHost = hopHost;
                    res.Error = err;
                    res.FilterPage = filter;
                    return res;
                }
            }

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(8000);
            HttpResponseMessage resp;
            var sw = Stopwatch.StartNew();
            try
            {
                using var req = NewRequest(current, method, own, withBody);
                if (hop == 0) Record(res, req, own);
                resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                res.TimedOut = true;
                if (hop > 0) res.FailedHost = hopHost;
                res.Error = hop == 0 ? "no answer within 8 s" : $"no answer from {hopHost} within 8 s";
                return res;
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception e)
            {
                if (hop > 0) res.FailedHost = hopHost;
                res.Error = (hop == 0 ? "" : hopHost + ": ") + Why(e, out bool proxyLogin);
                res.ProxyLogin = proxyLogin;
                if (hop == 0) Timings(res, st);
                return res;
            }

            using (resp)
            {
                int code = (int)resp.StatusCode;
                if (hop == 0)
                {
                    res.Answered = true;
                    res.FirstByteMs = sw.Elapsed.TotalMilliseconds;
                    Timings(res, st);
                }
                res.Status = code;
                res.Reason = resp.ReasonPhrase ?? "";
                res.Server = resp.Headers.Server.Count > 0 ? resp.Headers.Server.ToString() : res.Server;
                res.FinalUrl = current;
                res.Version = resp.Version.Major >= 2 ? $"HTTP/{resp.Version.Major}" : $"HTTP/{resp.Version.Major}.{resp.Version.Minor}";
                res.Headers.Clear();
                foreach (var h in resp.Headers.NonValidated) foreach (var v in h.Value) res.Headers.Add((h.Key, v));
                foreach (var h in resp.Content.Headers.NonValidated) foreach (var v in h.Value) res.Headers.Add((h.Key, v));
                res.TotalMs = total.Elapsed.TotalMilliseconds;

                if (code == 511) { res.CaptivePage = "the network asks for a sign-in (HTTP 511)"; return res; }

                if (code is >= 300 and < 400 && resp.Headers.Location is { } loc)
                {
                    Uri next = loc.IsAbsoluteUri ? loc : new Uri(current, loc);
                    res.Chain.Add($"{code} → {DoctorNet.Trim(next.GetLeftPart(UriPartial.Path), 70)}");
                    if (Judge(next, url) is { } verdict)
                    {
                        if (verdict.Filter) res.FilterPage = verdict.Why; else res.CaptivePage = verdict.Why;
                        return res;
                    }
                    if (next.Scheme is not ("http" or "https") || !visited.Add(next.AbsoluteUri) || hop == MaxHops) return res;
                    if (own != null)
                    {
                        if (code == 303 ? method != HttpMethod.Get && method != HttpMethod.Head : code is 301 or 302 && method == HttpMethod.Post)
                        {
                            method = HttpMethod.Get;
                            withBody = false;
                        }
                        if (!SameOrigin(url, next))
                        {
                            // its cookies and tokens are for its own site: the redirect's host gets a plain GET
                            own = null;
                            method = HttpMethod.Get;
                            withBody = false;
                            res.Notes.Add($"it redirects off {url.Authority}: your request's headers and body weren't sent on");
                        }
                    }
                    current = next;
                    continue;
                }

                // the body: a little of it — to show its start, and to look for a block page
                var (buf, n, cut, undecoded) = await ReadBodyAsync(resp.Content, cts.Token).ConfigureAwait(false);
                res.TotalMs = total.Elapsed.TotalMilliseconds;
                res.BodyBytes = n;
                res.BodyCut = cut;
                res.Undecoded = undecoded;
                res.ContentType = resp.Content.Headers.ContentType?.ToString();
                if (undecoded == null) res.Preview = Preview(buf, n, res.ContentType);
                string body = Encoding.Latin1.GetString(buf, 0, n);
                foreach (var m in FilterMarkers)
                    if (body.Contains(m, StringComparison.OrdinalIgnoreCase))
                    {
                        res.FilterPage = $"the answer is a filter's block page ({m})";
                        return res;
                    }
                return res;
            }
        }
        return res;
    }

    // One hop's request: the imported one (its method, every header in order, its body) while it is on its own origin,
    // else the Doctor's own GET with a browser's headers. Content headers (Content-Type …) go with the body they describe.
    private static HttpRequestMessage NewRequest(Uri at, HttpMethod method, DoctorRequest? imported, bool withBody)
    {
        var req = new HttpRequestMessage(method, at)
        {
            // as browsers do: HTTP/2 where the server offers it, else HTTP/1.1
            Version = HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
        };
        if (imported == null)
        {
            req.Headers.TryAddWithoutValidation("User-Agent", UserAgent);
            req.Headers.TryAddWithoutValidation("Accept", "text/html,application/xhtml+xml,*/*;q=0.8");
            req.Headers.TryAddWithoutValidation("Accept-Language", "en");
            req.Headers.TryAddWithoutValidation("Accept-Encoding", "gzip, deflate, br");
            return req;
        }
        if (withBody && imported.Body != null) req.Content = new ByteArrayContent(imported.Body);
        foreach (var (name, value) in imported.Headers)
            if (!req.Headers.TryAddWithoutValidation(name, value))
                req.Content?.Headers.TryAddWithoutValidation(name, value);
        return req;
    }

    private static void Record(DoctorHttpResult res, HttpRequestMessage req, DoctorRequest? imported)
    {
        res.Method = req.Method.Method;
        res.Target = req.RequestUri?.PathAndQuery ?? "/";
        // as written (the typed view splits "a, b" into two values)
        foreach (var h in req.Headers.NonValidated) foreach (var v in h.Value) res.Sent.Add((h.Key, v));
        if (req.Content == null) return;
        foreach (var h in req.Content.Headers.NonValidated) foreach (var v in h.Value) res.Sent.Add((h.Key, v));
        res.SentBody = imported?.Body?.Length ?? 0;
    }

    private static void Timings(DoctorHttpResult res, Stages st)
    {
        res.Remote = st.Remote;
        res.ConnectMs = st.ConnectMs;
        res.TlsMs = st.TlsMs;
    }

    private static bool SameOrigin(Uri a, Uri b)
        => string.Equals(a.Scheme, b.Scheme, StringComparison.OrdinalIgnoreCase)
           && string.Equals(a.IdnHost, b.IdnHost, StringComparison.OrdinalIgnoreCase) && a.Port == b.Port;

    // Why a request failed, in a few words: the proxy's own sentence when it was the proxy (its tunnel, its login),
    // .NET's proxy tunnel status, else the socket / TLS reason.
    private static string Why(Exception e, out bool proxyLogin)
    {
        proxyLogin = false;
        if (DoctorProxy.Find(e) is { } p)
        {
            proxyLogin = p.Stage == DoctorProxyStage.Login;
            return p.Message;
        }
        for (var x = e; x != null; x = x.InnerException)
            if (x is HttpRequestException { HttpRequestError: HttpRequestError.ProxyTunnelError } h)
            {
                int code = h.StatusCode is { } sc ? (int)sc : 0;
                proxyLogin = code == 407;
                return code == 407 ? "the proxy refused the login (HTTP 407)"
                     : code is 502 or 504 ? $"the proxy couldn't reach it (HTTP {code})"
                     : code > 0 ? $"the proxy refused the tunnel (HTTP {code})" : "the proxy refused the tunnel";
            }
        return DoctorDns.Short(e);
    }

    // A redirect that gives a filter or a captive portal away: to a private / filter IP, or to a sign-in page elsewhere.
    private static (bool Filter, string Why)? Judge(Uri next, Uri original)
    {
        if (IPAddress.TryParse(next.Host.Trim('[', ']'), out var ip) && !DoctorIp.IsPublic(ip))
        {
            if (DoctorIp.IsKnownFilter(ip) || next.Query.Contains("policy=", StringComparison.OrdinalIgnoreCase))
                return (true, $"redirects to {ip}, the filter's block page");
            if (!(IPAddress.TryParse(original.Host.Trim('[', ']'), out var orig) && !DoctorIp.IsPublic(orig)))
                return (false, $"redirects to a private address ({ip}): a sign-in page or a filter");
        }
        string host = next.Host.ToLowerInvariant();
        if (!SameSite(host, original.Host.ToLowerInvariant()))
        {
            string where = (host + next.AbsolutePath).ToLowerInvariant();
            if (PortalWords.Any(w => where.Contains(w)) && !host.Contains("accounts.") && !host.Contains("login.microsoftonline"))
                return (false, $"redirects to {host}, which looks like a sign-in page");
        }
        return null;
    }

    // same site: one is the other, or both end in the same last two labels (www.example.com ~ example.com)
    private static bool SameSite(string a, string b)
    {
        if (a == b) return true;
        static string Tail(string h)
        {
            var parts = h.Split('.');
            return parts.Length >= 2 ? parts[^2] + "." + parts[^1] : h;
        }
        return Tail(a) == Tail(b);
    }

    // The body's start: at most 256 KB off the wire, decoded (gzip, deflate, br) to at most 64 KB. Undecoded: an encoding
    // that can't be decoded here (zstd …), whose bytes are then the encoded ones.
    private static async Task<(byte[] Buf, int Length, bool Cut, string? Undecoded)> ReadBodyAsync(HttpContent content, CancellationToken ct)
    {
        var buf = new byte[BodyCap];
        try
        {
            string? coding = content.Headers.ContentEncoding.LastOrDefault()?.Trim().ToLowerInvariant();
            if (coding is "identity" or "") coding = null;
            await using var stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            if (coding is null or not ("gzip" or "x-gzip" or "deflate" or "br"))
            {
                var (n, cut) = await FillAsync(stream, buf, ct).ConfigureAwait(false);
                return (buf, n, cut, coding);
            }
            var wire = new byte[WireCap];
            var (got, _) = await FillAsync(stream, wire, ct).ConfigureAwait(false);
            using var raw = new MemoryStream(wire, 0, got);
            // HTTP's "deflate" is meant to be zlib-wrapped; some servers send it bare
            await using Stream decoder = coding switch
            {
                "br" => new BrotliStream(raw, CompressionMode.Decompress),
                "deflate" when got >= 2 && (wire[0] & 0x0F) == 8 && ((wire[0] << 8) | wire[1]) % 31 == 0 => new ZLibStream(raw, CompressionMode.Decompress),
                "deflate" => new DeflateStream(raw, CompressionMode.Decompress),
                _ => new GZipStream(raw, CompressionMode.Decompress),
            };
            var (len, more) = await FillAsync(decoder, buf, ct).ConfigureAwait(false);
            return (buf, len, more || got == WireCap, null);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { return (buf, 0, false, null); }
        catch { return (buf, 0, false, null); }
    }

    // Reads into buf until it is full or the stream ends; Cut: there was more.
    private static async Task<(int Length, bool Cut)> FillAsync(Stream s, byte[] buf, CancellationToken ct)
    {
        int n = 0;
        while (n < buf.Length)
        {
            int got = await s.ReadAsync(buf.AsMemory(n), ct).ConfigureAwait(false);
            if (got == 0) return (n, false);
            n += got;
        }
        return (n, await s.ReadAsync(new byte[1], ct).ConfigureAwait(false) > 0);
    }

    // The start of a text body on one line: its charset (UTF-8 unless it names a Latin one), runs of white space folded,
    // at most 300 characters. Null for an empty body or one that isn't text.
    private static string? Preview(byte[] buf, int n, string? contentType)
    {
        if (n == 0) return null;
        string ct = (contentType ?? "").ToLowerInvariant();
        bool text = ct.Length == 0 || ct.StartsWith("text/", StringComparison.Ordinal) || ct.Contains("json") || ct.Contains("xml")
                    || ct.Contains("javascript") || ct.Contains("html") || ct.Contains("form-urlencoded");
        if (!text) return null;
        int look = Math.Min(n, 4096);
        for (int i = 0; i < Math.Min(look, 512); i++) if (buf[i] == 0) return null;   // binary after all
        var enc = ct.Contains("iso-8859-1") || ct.Contains("windows-1252") || ct.Contains("latin1") ? Encoding.Latin1 : Encoding.UTF8;
        var sb = new StringBuilder(320);
        bool space = false;
        foreach (char c in enc.GetString(buf, 0, look))
        {
            if (char.IsWhiteSpace(c)) { space = sb.Length > 0; continue; }
            if (space) { sb.Append(' '); space = false; }
            sb.Append(c);
            if (sb.Length >= 320) break;
        }
        return sb.Length == 0 ? null : RemoteText.Clean(sb.ToString(), 300);
    }
}
