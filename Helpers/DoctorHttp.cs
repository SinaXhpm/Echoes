using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
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
}

/// <summary>
/// One GET of the site, connected to the address the Doctor trusts (never the system resolver's, which may be the
/// filter's), redirects followed by hand (at most five, recorded), the body read only up to a small cap — and checked
/// for a filter's block page or a captive portal. No credentials, no cookies; the certificate was judged by the TLS check.
/// </summary>
public static class DoctorHttp
{
    private const int MaxHops = 5;
    private const int BodyCap = 64 * 1024;

    // a block page names the filter: Iran's (peyvandha.ir, the 10.10.34.34 iframe), Russia's, Turkey's
    private static readonly string[] FilterMarkers =
    {
        "peyvandha", "10.10.34.34", "10.10.34.35", "10.10.34.36", "warning.rt.ru", "blocklist.rkn.gov.ru", "eais.rkn.gov.ru",
        "195.175.254.2",
    };

    private static readonly string[] PortalWords = { "login", "portal", "hotspot", "captive", "splash", "wifi", "guest", "auth" };

    private const string UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36";

    public static async Task<DoctorHttpResult> GetAsync(Uri url, IPAddress pinned, Func<string, CancellationToken, Task<IPAddress?>> resolveOther,
                                                        CancellationToken ct)
    {
        var known = new ConcurrentDictionary<string, IPAddress>(StringComparer.OrdinalIgnoreCase) { [url.IdnHost] = pinned };
        using var handler = NewHandler();
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
                await s.ConnectAsync(new IPEndPoint(ip, ctx.DnsEndPoint.Port), token).ConfigureAwait(false);
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

        return await RunAsync(url, handler, PrepareHop, ct).ConfigureAwait(false);
    }

    /// <summary>The same GET through <paramref name="proxy"/>: an HTTP proxy the standard way (absolute URLs, CONNECT for
    /// https), other kinds through the Doctor's own tunnel. Names are resolved by the proxy.</summary>
    public static async Task<DoctorHttpResult> GetViaProxyAsync(Uri url, DoctorProxy proxy, CancellationToken ct)
    {
        using var handler = NewHandler();
        if (proxy.Kind == DoctorProxyKind.Http)
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
                (await proxy.OpenAsync(ctx.DnsEndPoint.Host.Trim('[', ']'), ctx.DnsEndPoint.Port, 8000, token).ConfigureAwait(false)).Stream;
        var res = await RunAsync(url, handler, null, ct).ConfigureAwait(false);
        if (res.Answered && res.Status == 407)
        {
            // the proxy answered for the site: its login, not the site's page
            res.Answered = false;
            res.ProxyLogin = true;
            res.Error = proxy.HasLogin ? "the proxy refused the login (HTTP 407)" : "the proxy wants a login (HTTP 407)";
        }
        return res;
    }

    private static SocketsHttpHandler NewHandler()
    {
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            MaxResponseHeadersLength = 64,
            UseCookies = false,
        };
        handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;
        return handler;
    }

    private static async Task<DoctorHttpResult> RunAsync(Uri url, SocketsHttpHandler handler,
                                                         Func<string, CancellationToken, Task<(string? Error, string? Filter)>>? prepareHop,
                                                         CancellationToken ct)
    {
        var res = new DoctorHttpResult();
        using var http = new HttpClient(handler, disposeHandler: false) { Timeout = Timeout.InfiniteTimeSpan };

        var current = url;
        var visited = new HashSet<string>(StringComparer.Ordinal) { url.AbsoluteUri };
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
                using var req = new HttpRequestMessage(HttpMethod.Get, current);
                req.Headers.TryAddWithoutValidation("User-Agent", UserAgent);
                req.Headers.TryAddWithoutValidation("Accept", "text/html,application/xhtml+xml,*/*;q=0.8");
                req.Headers.TryAddWithoutValidation("Accept-Language", "en");
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
                return res;
            }

            using (resp)
            {
                int code = (int)resp.StatusCode;
                if (hop == 0)
                {
                    res.Answered = true;
                    res.FirstByteMs = sw.Elapsed.TotalMilliseconds;
                }
                res.Status = code;
                res.Reason = resp.ReasonPhrase ?? "";
                res.Server = resp.Headers.Server.Count > 0 ? resp.Headers.Server.ToString() : res.Server;
                res.FinalUrl = current;

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
                    current = next;
                    continue;
                }

                // the body: a little, and only to look for a block page
                string body = await ReadTextAsync(resp.Content, cts.Token).ConfigureAwait(false);
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

    private static async Task<string> ReadTextAsync(HttpContent content, CancellationToken ct)
    {
        try
        {
            await using var stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            var buf = new byte[BodyCap];
            int n = 0;
            while (n < buf.Length)
            {
                int got = await stream.ReadAsync(buf.AsMemory(n), ct).ConfigureAwait(false);
                if (got == 0) break;
                n += got;
            }
            return Encoding.Latin1.GetString(buf, 0, n);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { return ""; }
        catch { return ""; }
    }
}
