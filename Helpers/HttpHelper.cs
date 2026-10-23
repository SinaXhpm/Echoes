using System;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

public static class HttpHelper
{
    /// <summary>
    /// The most a buffered read (GetStringAsync / GetByteArrayAsync / a ResponseContentRead send) of a client from
    /// <see cref="Create"/> takes, counted after decompression: responses are decompressed automatically, so without a cap
    /// a small gzip / brotli bomb (or a proxy answering in the server's place) could expand into gigabytes in memory. Far
    /// above any answer the callers read (update check, IP Info, RDAP, check-host.net: KBs). A caller may set a smaller
    /// <see cref="HttpClient.MaxResponseContentBufferSize"/> before its first request; one that streams the body with
    /// ResponseHeadersRead caps its own read (RDAP, Check Host do).
    /// </summary>
    public const int MaxBufferedResponseBytes = 8 * 1024 * 1024;

    // "Echoes/<version>" from the assembly (it read a stale hard-coded "0.2.5")
    private static readonly string UserAgent =
        typeof(HttpHelper).Assembly.GetName().Version is { } v ? $"Echoes/{v.Major}.{v.Minor}.{v.Build}" : "Echoes";

    /// <summary>Builds a client, optionally through a proxy. Throws <see cref="ArgumentException"/> (with a
    /// user-readable message) when the proxy address is malformed — callers create the client inside
    /// their try and show ex.Message.
    /// <para>Redirects are followed (rdap.org answers with cross-host 302s to the registries, GitHub's API with 301s for a
    /// moved repository). SocketsHttpHandler drops the Authorization header on every redirect and never follows https →
    /// http, but it replays every OTHER request header to wherever a redirect points — so a caller must not add a secret
    /// header (an API key, a cookie) or put one in the URL. None does: the tools that send credentials (Cloudflare,
    /// Telegram) build their own handler with redirects off. Proxy credentials only ever go to the proxy.</para></summary>
    public static HttpClient Create(
        string? proxyAddress = null,
        string? proxyUser = null,
        string? proxyPass = null,
        bool skipSslVerify = false,
        TimeSpan? timeout = null)
    {
        // Validate the proxy before allocating the handler: WebProxy(string) runs new Uri() and throws a
        // bare UriFormatException on a typo ("1.2.3.4 8080", port 99999), which reads as a crash.
        // Reject rather than silently skip it: going direct would leak the real IP in a proxy test.
        WebProxy? proxy = null;
        if (!string.IsNullOrWhiteSpace(proxyAddress))
        {
            // The address is quoted to show the typo — never with a user:password@ in it (the message is UI text, and
            // can end up in a screenshot or a pasted error).
            if (!TryParseProxy(proxyAddress, out var proxyUri))
                throw new ArgumentException(WithoutUserInfo(proxyAddress) is { Length: > 0 } shown
                    ? $"Invalid proxy address '{shown}' — use host:port (e.g. 127.0.0.1:8080)."
                    : "Invalid proxy address — use host:port (e.g. 127.0.0.1:8080).");
            proxy = new WebProxy(proxyUri);
            if (!string.IsNullOrWhiteSpace(proxyUser))
                proxy.Credentials = new NetworkCredential(proxyUser, proxyPass ?? string.Empty);
        }

        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = true,
            AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromSeconds(15)
        };

        if (proxy != null)
        {
            handler.Proxy = proxy;
            handler.UseProxy = true;
        }

        if (skipSslVerify)
            handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;

        // No proxy given: the system proxy applies, and SocketsHttpHandler looks it up inside SendAsync on the thread that
        // starts the request — every request (measured on .NET 8). The callers start theirs on the UI thread (IP Info three
        // at once, Check Host, RDAP), and with Windows' default "Automatically detect settings" that lookup can be a WPAD
        // discovery taking seconds: the window froze meanwhile. So such a client starts each request on the thread pool.
        HttpMessageHandler pipeline = proxy is null ? new StartOnThreadPool(handler) : handler;
        var client = new HttpClient(pipeline)
        {
            Timeout = timeout ?? TimeSpan.FromSeconds(15),
            MaxResponseContentBufferSize = MaxBufferedResponseBytes,
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        return client;
    }

    /// <summary>Runs the inner handler's SendAsync — its synchronous start included — on the thread pool. Nothing else
    /// changes: cancellation, timeouts and exceptions reach the caller exactly as before.</summary>
    private sealed class StartOnThreadPool(HttpMessageHandler inner) : DelegatingHandler(inner)
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.Run(() => base.SendAsync(request, cancellationToken), CancellationToken.None);
    }

    /// <summary>
    /// <paramref name="address"/> (trimmed) without any user info: everything between the scheme (if any) and the LAST
    /// '@' goes, so "user:p@ss@1.2.3.4 8080" shows as "1.2.3.4 8080" and "socks5://u:p@host:99999" as "socks5://host:99999".
    /// For messages only — it doesn't validate anything.
    /// </summary>
    internal static string WithoutUserInfo(string? address)
    {
        string a = (address ?? string.Empty).Trim();
        int at = a.LastIndexOf('@');
        if (at < 0) return a;
        int scheme = a.IndexOf("://", StringComparison.Ordinal);
        int start = scheme >= 0 && scheme < at ? scheme + 3 : 0;
        return (a[..start] + a[(at + 1)..]).Trim();
    }

    /// <summary>Normalises (see <see cref="NormalizeProxy"/>) and parses a proxy address without throwing.</summary>
    public static bool TryParseProxy(string? proxy, [NotNullWhen(true)] out Uri? uri)
    {
        uri = null;
        return !string.IsNullOrWhiteSpace(proxy)
               && Uri.TryCreate(NormalizeProxy(proxy), UriKind.Absolute, out uri)
               && uri.Host.Length > 0;
    }

    /// <summary>
    /// The proxy as curl's -x should get it, by the same rules as <see cref="NormalizeProxy"/>: a bare host:port on
    /// 1080 / 1081 / 9050 is SOCKS5 (curl alone would read any bare host:port as an HTTP proxy, so the same input
    /// worked in the .NET engine and failed in curl). An inferred SOCKS5 proxy becomes socks5h — names resolved by the
    /// proxy, as .NET does for socks5 — so no local DNS lookup leaks past it. An explicit scheme is kept as typed.
    /// </summary>
    public static string CurlProxyArg(string proxy)
    {
        proxy = FoldDigits(proxy.Trim());
        if (proxy.Contains("://")) return proxy;
        string norm = NormalizeProxy(proxy);
        return norm.StartsWith("socks5://", StringComparison.Ordinal) ? "socks5h://" + norm["socks5://".Length..] : norm;
    }

    public static string NormalizeProxy(string proxy)
    {
        proxy = FoldDigits(proxy.Trim());
        if (proxy.Contains("://")) return proxy;

        // Infer SOCKS5 from the ACTUAL numeric port, not a substring: a Contains(":1080") test wrongly
        // tags ports like 10800 / 10809 (v2rayN's default HTTP port) as SOCKS and breaks every request.
        int lastColon = proxy.LastIndexOf(':');
        if (lastColon >= 0 && int.TryParse(proxy.AsSpan(lastColon + 1), out int port)
            && port is 1080 or 1081 or 9050)
            return "socks5://" + proxy;

        return "http://" + proxy;
    }

    // Digits typed in the phone's language read in ASCII in the address; user info before "@" is a credential and stays
    // as typed, and so does a name in another script (an internationalised host).
    private static string FoldDigits(string proxy)
    {
        int at = proxy.LastIndexOf('@');
        string address = proxy[(at + 1)..];
        return !LocalDigits.Any(address) || LocalDigits.HasNonAsciiLetter(address) ? proxy : proxy[..(at + 1)] + LocalDigits.Fold(address);
    }
}
