using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>
/// How one kind of speed test server is measured: a latency probe (a tiny request on a warm connection), the download
/// requests, and the upload requests when it takes them. <see cref="SpeedTestEngine"/> does the timing, the parallel
/// streams and the steady-state math the same way for every provider.
/// </summary>
public interface ISpeedTestProvider
{
    SpeedTestDestination Destination { get; }
    /// <summary>What it turned out to be (an Auto destination resolves to one of the others).</summary>
    SpeedTestKind Kind { get; }
    /// <summary>The address the requests are built on, after same-host redirects and the HTTP fallback.</summary>
    Uri Base { get; }
    bool SupportsLatency { get; }
    bool SupportsUpload { get; }
    /// <summary>A plain web server that may limit requests per address (Hetzner's answer HTTP 429 after ~18 quick ones):
    /// the engine asks it as little as possible — a whole-file stream per connection, fewer and slower latency probes.</summary>
    bool FewRequests { get; }
    /// <summary>True: <see cref="CreateDownloadRequest"/> asks for exactly that many bytes. False: each request is an
    /// open-ended stream (a whole file) that is read until the phase or its byte budget ends.</summary>
    bool SizedDownloads { get; }
    long MaxDownloadChunk { get; }
    long MaxUploadChunk { get; }
    HttpRequestMessage CreateLatencyRequest(string? during);
    /// <summary>The server's own processing time in a latency answer (ms), 0 when it doesn't say.</summary>
    double ServerTimeMs(HttpResponseMessage response);
    HttpRequestMessage CreateDownloadRequest(long bytes);
    HttpRequestMessage CreateUploadRequest(HttpContent body);
    /// <summary>Who / where, from a latency answer's headers (Cloudflare), else null.</summary>
    SpeedTestServer? ServerFromHeaders(HttpResponseMessage response);
    /// <summary>Who / where, from the service (Cloudflare's /meta), else null. Never throws.</summary>
    Task<SpeedTestServer?> FetchServerInfoAsync(HttpClient client, CancellationToken ct);
    /// <summary>The sentence for an HTTP 429, when the service has a better one than the generic.</summary>
    string? RateLimitMessage { get; }
}

/// <summary>An HTTP status where a success was expected.</summary>
public sealed class SpeedTestHttpException(HttpStatusCode status, string? reason, string? location = null, TimeSpan? retryAfter = null)
    : Exception($"HTTP {(int)status} {reason}".Trim())
{
    public HttpStatusCode Status { get; } = status;
    public string? Location { get; } = location;
    /// <summary>The server's Retry-After, when it gave one.</summary>
    public TimeSpan? RetryAfter { get; } = retryAfter;
    /// <summary>Busy or limiting (429, 503): worth another try after a pause.</summary>
    public bool Transient => Status is HttpStatusCode.TooManyRequests or HttpStatusCode.ServiceUnavailable;
}

/// <summary>Shared plumbing of the providers.</summary>
public abstract class SpeedTestProvider : ISpeedTestProvider
{
    protected const long Mb = 1024 * 1024;

    protected SpeedTestProvider(SpeedTestDestination destination, Uri baseUrl)
    {
        Destination = destination;
        Base = baseUrl;
    }

    public SpeedTestDestination Destination { get; }
    public abstract SpeedTestKind Kind { get; }
    public Uri Base { get; protected set; }
    public virtual bool SupportsLatency => true;
    public abstract bool SupportsUpload { get; }
    public virtual bool SizedDownloads => true;
    public virtual bool FewRequests => false;
    public virtual long MaxDownloadChunk => 64 * Mb;
    public virtual long MaxUploadChunk => 32 * Mb;
    public virtual string? RateLimitMessage => null;

    public abstract HttpRequestMessage CreateLatencyRequest(string? during);
    public virtual double ServerTimeMs(HttpResponseMessage response) => 0;
    public abstract HttpRequestMessage CreateDownloadRequest(long bytes);
    public virtual HttpRequestMessage CreateUploadRequest(HttpContent body) => throw new NotSupportedException("This server doesn't take uploads.");
    public virtual SpeedTestServer? ServerFromHeaders(HttpResponseMessage response) => null;
    public virtual Task<SpeedTestServer?> FetchServerInfoAsync(HttpClient client, CancellationToken ct) => Task.FromResult<SpeedTestServer?>(null);

    /// <summary>Checks the server answers as its kind should, and learns what it needs (file size, API flavor).
    /// Throws <see cref="SpeedTestException"/> for a wrong answer; network errors pass through as they are.</summary>
    internal abstract Task PrepareAsync(HttpClient client, CancellationToken ct);

    private static long _nonce = Random.Shared.Next(1, int.MaxValue);
    /// <summary>A fresh value for cache-busting query parameters.</summary>
    protected static string Nonce() => Interlocked.Increment(ref _nonce).ToString(CultureInfo.InvariantCulture);

    protected Uri At(string relative) => new(Base, relative);

    protected static HttpRequestMessage Get(Uri url) => new(HttpMethod.Get, url);

    protected static HttpRequestMessage Post(Uri url, HttpContent body) => new(HttpMethod.Post, url) { Content = body };
}

/// <summary>speed.cloudflare.com (or a server with its API): __down?bytes=N, POST __up, /meta; Server-Timing gives the
/// server's own time, the headers name the data center.</summary>
public sealed class CloudflareProvider(SpeedTestDestination destination, Uri baseUrl) : SpeedTestProvider(destination, baseUrl)
{
    private readonly string _measId = Random.Shared.NextInt64(1_000_000_000_000, 9_999_999_999_999).ToString(CultureInfo.InvariantCulture);

    public override SpeedTestKind Kind => SpeedTestKind.Cloudflare;
    public override bool SupportsUpload => true;

    public override string? RateLimitMessage => Base.Host.Equals("speed.cloudflare.com", StringComparison.OrdinalIgnoreCase)
        ? "Cloudflare is rate-limiting speed tests from this address (HTTP 429). Try again in a minute, or pick another server."
        : null;

    internal override async Task PrepareAsync(HttpClient client, CancellationToken ct)
    {
        var (resp, final) = await SpeedTestProviders.GetFollowingAsync(client, At("__down?bytes=0"), null, ct).ConfigureAwait(false);
        using (resp)
        {
            SpeedTestProviders.EnsureOk(resp);
            await SpeedTestProviders.ExpectDataAsync(resp, Base.Host, ct).ConfigureAwait(false);
        }
        Base = new Uri(final, "./");
    }

    public override HttpRequestMessage CreateLatencyRequest(string? during)
        => Get(At(during is null ? "__down?bytes=0" : "__down?bytes=0&during=" + during));

    public override double ServerTimeMs(HttpResponseMessage response)
        => SpeedTestMath.ServerTimeMs(response.Headers.TryGetValues("Server-Timing", out var st) ? st : null);

    public override HttpRequestMessage CreateDownloadRequest(long bytes)
        => Get(At("__down?bytes=" + bytes.ToString(CultureInfo.InvariantCulture) + "&measId=" + _measId));

    public override HttpRequestMessage CreateUploadRequest(HttpContent body) => Post(At("__up?measId=" + _measId), body);

    // The __down answer names the data center and how Cloudflare sees the client (a fallback for /meta).
    public override SpeedTestServer? ServerFromHeaders(HttpResponseMessage resp)
    {
        string? H(string name) => SpeedTestMath.CleanLabel(resp.Headers.TryGetValues(name, out var v) ? v.FirstOrDefault() : null);
        var s = new SpeedTestServer
        {
            Colo = H("colo") ?? H("cf-meta-colo"),
            ClientIp = H("cf-meta-ip"),
            Asn = int.TryParse(H("asn"), NumberStyles.Integer, CultureInfo.InvariantCulture, out int asn) ? asn : 0,
            ClientCity = H("city"),
            ClientCountry = H("country"),
        };
        return s.Colo is null && s.ClientIp is null ? null : s;
    }

    // The real /meta reply is ~300 bytes of JSON. Read no more than this of it: buffered whole, a broken or hostile
    // endpoint (an intercepting proxy, a captive portal) could make the test hold any amount in memory.
    private const int MaxMetaBytes = 64 * 1024;

    // /meta answers only the site's own page (anything else gets 403 "{}"), hence the Referer.
    public override async Task<SpeedTestServer?> FetchServerInfoAsync(HttpClient client, CancellationToken ct)
    {
        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(TimeSpan.FromSeconds(8));
            using var req = Get(At("meta"));
            req.Headers.Referrer = Base;
            using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode || resp.Content.Headers.ContentLength > MaxMetaBytes) return null;
            byte[]? body = await SpeedTestProviders.ReadSmallAsync(resp, MaxMetaBytes, deadline.Token).ConfigureAwait(false);
            return body is null ? null : SpeedTestMath.ParseMeta(body);
        }
        catch (Exception)
        {
            return null;   // optional: the headers of the latency probes say most of it
        }
    }
}

/// <summary>
/// An Ookla Speedtest server. The OoklaServer daemon (every current one, "hello 2.x"): GET /latency.txt, GET
/// /download?size=N, POST /upload. An old PHP / ASP install: /speedtest/latency.txt, the 4000×4000 random JPEG (read as a
/// stream) and POST /speedtest/upload.php.
/// </summary>
public sealed class SpeedtestProvider(SpeedTestDestination destination, Uri baseUrl) : SpeedTestProvider(destination, baseUrl)
{
    private bool _legacy;

    public override SpeedTestKind Kind => SpeedTestKind.Speedtest;
    public override bool SupportsUpload => true;
    public override bool SizedDownloads => !_legacy;
    // Unknown per-server body limits: start well inside what other Speedtest clients send; the engine halves it on a 413.
    public override long MaxUploadChunk => 16 * Mb;

    internal override async Task PrepareAsync(HttpClient client, CancellationToken ct)
    {
        var (resp, final) = await SpeedTestProviders.GetFollowingAsync(client, At("hello"), null, ct).ConfigureAwait(false);
        using (resp)
        {
            if (resp.IsSuccessStatusCode && await SpeedTestProviders.ReadSmallAsync(resp, 1024, ct).ConfigureAwait(false) is { } hello
                && Encoding.ASCII.GetString(hello).StartsWith("hello", StringComparison.OrdinalIgnoreCase))
            {
                Base = new Uri(final, "./");
                return;
            }
        }
        var (old, oldFinal) = await SpeedTestProviders.GetFollowingAsync(client, At("speedtest/latency.txt"), null, ct).ConfigureAwait(false);
        using (old)
        {
            SpeedTestProviders.EnsureOk(old);
            if (await SpeedTestProviders.ReadSmallAsync(old, 1024, ct).ConfigureAwait(false) is not { } body
                || !Encoding.ASCII.GetString(body).StartsWith("test=test", StringComparison.Ordinal))
                throw new SpeedTestException($"{Base.Host} doesn't answer like a Speedtest server.");
        }
        _legacy = true;
        Base = new Uri(oldFinal, "../");
    }

    public override HttpRequestMessage CreateLatencyRequest(string? during)
        => Get(At((_legacy ? "speedtest/latency.txt?x=" : "latency.txt?x=") + Nonce()));

    public override HttpRequestMessage CreateDownloadRequest(long bytes)
        => Get(At(_legacy
            ? "speedtest/random4000x4000.jpg?x=" + Nonce()
            : "download?nocache=" + Nonce() + "&size=" + bytes.ToString(CultureInfo.InvariantCulture)));

    public override HttpRequestMessage CreateUploadRequest(HttpContent body)
        => Post(At((_legacy ? "speedtest/upload.php?x=" : "upload?nocache=") + Nonce()), body);
}

/// <summary>A LibreSpeed backend: GET empty.php (latency), GET garbage.php?ckSize=100 (100 MB of random data per request,
/// read as a stream), POST empty.php (upload).</summary>
public sealed class LibreSpeedProvider(SpeedTestDestination destination, Uri baseUrl) : SpeedTestProvider(destination, baseUrl)
{
    public override SpeedTestKind Kind => SpeedTestKind.LibreSpeed;
    public override bool SupportsUpload => true;
    public override bool SizedDownloads => false;
    public override long MaxUploadChunk => 16 * Mb;

    internal override async Task PrepareAsync(HttpClient client, CancellationToken ct)
    {
        var (resp, final) = await SpeedTestProviders.GetFollowingAsync(client, At("empty.php?r=" + Nonce()), null, ct).ConfigureAwait(false);
        using (resp)
        {
            SpeedTestProviders.EnsureOk(resp);
            await SpeedTestProviders.ExpectDataAsync(resp, Base.Host, ct).ConfigureAwait(false);
        }
        Base = new Uri(final, "./");
    }

    public override HttpRequestMessage CreateLatencyRequest(string? during) => Get(At("empty.php?r=" + Nonce()));

    public override HttpRequestMessage CreateDownloadRequest(long bytes) => Get(At("garbage.php?r=" + Nonce() + "&ckSize=100"));

    public override HttpRequestMessage CreateUploadRequest(HttpContent body) => Post(At("empty.php?r=" + Nonce()), body);
}

/// <summary>
/// A big file on a web server. Plain web servers may limit requests per address (Hetzner's answer HTTP 429 after ~18 quick
/// ones), so it is asked as little as possible: each connection reads the file as one stream (from a random place in it
/// when the server takes ranges, so the streams don't all read the same bytes) until the phase or its budget ends, and
/// latency is a 1-byte range on a warm connection, probed less often. Without Range support latency isn't measured (a
/// small request isn't possible). Uploads go to the destination's upload URL when it has one.
/// </summary>
public sealed class FileProvider(SpeedTestDestination destination, Uri fileUrl) : SpeedTestProvider(destination, fileUrl)
{
    /// <summary>A smaller file is refused: requests would be mostly overhead.</summary>
    public const long MinFileBytes = 1024 * 1024;

    private bool _ranges;
    private long _size = -1;

    public override SpeedTestKind Kind => SpeedTestKind.File;
    public override bool SupportsLatency => _ranges;
    public override bool SupportsUpload => Destination.UploadUrl is not null;
    public override bool SizedDownloads => false;
    public override bool FewRequests => true;
    public override long MaxUploadChunk => 16 * Mb;
    public long FileSize => _size;

    internal override async Task PrepareAsync(HttpClient client, CancellationToken ct)
    {
        var (resp, final) = await SpeedTestProviders.GetFollowingAsync(client, Base, r => r.Headers.Range = new RangeHeaderValue(0, 0), ct).ConfigureAwait(false);
        using (resp)
        {
            if (resp.StatusCode == HttpStatusCode.NotFound)
                throw new SpeedTestException($"{final.Host} doesn't have that file (HTTP 404).");
            SpeedTestProviders.EnsureOk(resp);
            if (SpeedTestProviders.IsHtml(resp))
                throw new SpeedTestException($"{final.Host} answered with a web page instead of the test file: the address is wrong, or the site is blocked on this network.");
            if (resp.StatusCode == HttpStatusCode.PartialContent)
            {
                _ranges = true;
                _size = resp.Content.Headers.ContentRange is { HasLength: true, Length: { } total } ? total : -1;
                await SpeedTestProviders.ReadSmallAsync(resp, 64 * 1024, ct).ConfigureAwait(false);
            }
            else
            {
                // the whole file is on its way: don't read it (disposing the answer drops the connection)
                _ranges = false;
                _size = resp.Content.Headers.ContentLength ?? -1;
            }
        }
        if (_size >= 0 && _size < MinFileBytes)
            throw new SpeedTestException($"The file at {final.Host} is only {Kb(_size)}: a speed test needs a big file (100 MB or more).");
        Base = final;
    }

    private static string Kb(long bytes) => bytes < 1024 ? bytes.ToString(CultureInfo.InvariantCulture) + " bytes"
        : (bytes / 1024).ToString(CultureInfo.InvariantCulture) + " KB";

    public override HttpRequestMessage CreateLatencyRequest(string? during)
    {
        var req = Get(Base);
        req.Headers.Range = new RangeHeaderValue(0, 0);
        return req;
    }

    /// <summary>The file as a stream: from a random place in its first part when the server takes ranges (to the end), else
    /// whole. The bytes asked for don't matter: the engine reads until the phase or its budget ends.</summary>
    public override HttpRequestMessage CreateDownloadRequest(long bytes)
    {
        var req = Get(Base);
        if (_ranges && _size > 2 * 64 * Mb)
            req.Headers.Range = new RangeHeaderValue(Random.Shared.NextInt64(0, _size / 2), null);
        return req;
    }

    public override HttpRequestMessage CreateUploadRequest(HttpContent body)
        => Post(Destination.UploadUrl ?? throw new NotSupportedException("This server doesn't take uploads."), body);
}

/// <summary>Connecting to a destination: the provider for its kind (or the kind an Auto address turns out to run), the
/// HTTPS → HTTP fallback, and the rules every probe follows (same-host redirects only, capped reads).</summary>
public static class SpeedTestProviders
{
    public const int MaxRedirects = 3;
    private const int MaxSmallBody = 64 * 1024;

    /// <summary>
    /// Connects to <paramref name="destination"/> and checks it answers as it should; the result is ready for the engine.
    /// HTTPS first; when it can't connect at all (refused, reset, timed out, TLS failed) and the destination has a plain
    /// HTTP address on the same host, that one. Throws <see cref="SpeedTestException"/> (one sentence) when nothing works,
    /// <see cref="OperationCanceledException"/> when stopped.
    /// </summary>
    public static async Task<ISpeedTestProvider> ConnectAsync(SpeedTestDestination destination, HttpClient client, TimeSpan timeout,
                                                              CancellationToken ct)
    {
        try
        {
            return await ConnectToAsync(destination, destination.Url, client, timeout, ct).ConfigureAwait(false);
        }
        catch (Exception first) when (destination.HttpFallback is { } http && !ct.IsCancellationRequested && IsConnectFailure(first))
        {
            try
            {
                return await ConnectToAsync(destination, http, client, timeout, ct).ConfigureAwait(false);
            }
            catch (Exception second) when (!ct.IsCancellationRequested && IsConnectFailure(second))
            {
                throw new SpeedTestException($"Can't reach {destination.Url.Host} over HTTPS ({ShortReason(first)}) or HTTP ({ShortReason(second)}): " +
                                             "the network is down or the site is blocked.", first);
            }
        }
    }

    private static async Task<ISpeedTestProvider> ConnectToAsync(SpeedTestDestination d, Uri url, HttpClient client, TimeSpan timeout,
                                                                 CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeout);
        try
        {
            switch (d.Kind)
            {
                case SpeedTestKind.Auto:
                    return await DetectAsync(d, url, client, deadline.Token).ConfigureAwait(false);
                default:
                    var p = Create(d, d.Kind, url);
                    await p.PrepareAsync(client, deadline.Token).ConfigureAwait(false);
                    return p;
            }
        }
        catch (OperationCanceledException ex) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException($"{url.Host} didn't answer within {timeout.TotalSeconds:0} seconds.", ex);
        }
    }

    internal static SpeedTestProvider Create(SpeedTestDestination d, SpeedTestKind kind, Uri url) => kind switch
    {
        SpeedTestKind.Cloudflare => new CloudflareProvider(d, url),
        SpeedTestKind.Speedtest => new SpeedtestProvider(d, url),
        SpeedTestKind.LibreSpeed => new LibreSpeedProvider(d, url),
        _ => new FileProvider(d, url),
    };

    // A bare server address: whichever API answers — Speedtest (/hello), LibreSpeed (empty.php), Cloudflare-style
    // (__down?bytes=0). A wrong guess answers 404 or a web page, which only moves on to the next.
    private static async Task<ISpeedTestProvider> DetectAsync(SpeedTestDestination d, Uri url, HttpClient client, CancellationToken ct)
    {
        foreach (var kind in new[] { SpeedTestKind.Speedtest, SpeedTestKind.LibreSpeed, SpeedTestKind.Cloudflare })
        {
            var p = Create(d, kind, url);
            try
            {
                await p.PrepareAsync(client, ct).ConfigureAwait(false);
                return p;
            }
            catch (Exception ex) when (ex is SpeedTestException or SpeedTestHttpException)
            {
                // not this kind: try the next
            }
        }
        throw new SpeedTestException($"No speed test server answers at {url.Host}: give the address of a big file, or of a LibreSpeed, " +
                                     "Speedtest or Cloudflare-style server.");
    }

    /// <summary>GET that follows redirects on the same host only (http → https allowed, https → http not), at most
    /// <see cref="MaxRedirects"/>. Returns the answer (headers read; the caller disposes it) and where it came from.</summary>
    internal static async Task<(HttpResponseMessage Response, Uri Url)> GetFollowingAsync(HttpClient client, Uri url,
        Action<HttpRequestMessage>? configure, CancellationToken ct)
    {
        for (int hop = 0; ; hop++)
        {
            var req = new HttpRequestMessage(HttpMethod.Get, url);
            configure?.Invoke(req);
            HttpResponseMessage resp;
            try { resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false); }
            finally { req.Dispose(); }
            int code = (int)resp.StatusCode;
            if (code is not (301 or 302 or 303 or 307 or 308) || resp.Headers.Location is not { } loc) return (resp, url);
            resp.Dispose();
            var next = loc.IsAbsoluteUri ? loc : new Uri(url, loc);
            if (next.Scheme != Uri.UriSchemeHttp && next.Scheme != Uri.UriSchemeHttps)
                throw new SpeedTestException($"{url.Host} redirects to an address that isn't a web address.");
            if (!next.Host.Equals(url.Host, StringComparison.OrdinalIgnoreCase))
                throw new SpeedTestException($"{url.Host} redirects to another host ({next.Host}), which a speed test doesn't follow: " +
                                             "use that address directly.");
            if (url.Scheme == Uri.UriSchemeHttps && next.Scheme == Uri.UriSchemeHttp)
                throw new SpeedTestException($"{url.Host} redirects from HTTPS to plain HTTP, which a speed test doesn't follow.");
            if (next.UserInfo.Length > 0)
                throw new SpeedTestException($"{url.Host} redirects to an address with a user name in it, which a speed test doesn't follow.");
            if (hop >= MaxRedirects)
                throw new SpeedTestException($"{url.Host} redirects too many times.");
            url = next;
        }
    }

    internal static void EnsureOk(HttpResponseMessage resp)
    {
        if (!resp.IsSuccessStatusCode)
            throw new SpeedTestHttpException(resp.StatusCode, resp.ReasonPhrase, resp.Headers.Location?.ToString(),
                resp.Headers.RetryAfter is { } ra ? ra.Delta ?? (ra.Date is { } at ? at - DateTimeOffset.UtcNow : null) : null);
    }

    internal static bool IsHtml(HttpResponseMessage resp)
        => resp.Content.Headers.ContentType?.MediaType is { } m
           && (m.Equals("text/html", StringComparison.OrdinalIgnoreCase) || m.Equals("application/xhtml+xml", StringComparison.OrdinalIgnoreCase));

    /// <summary>A probe of an API endpoint must not come back as a web page (a block page, a catch-all site): it's
    /// empty or a few bytes. Reads (at most <see cref="MaxSmallBody"/> of) the body.</summary>
    internal static async Task ExpectDataAsync(HttpResponseMessage resp, string host, CancellationToken ct)
    {
        byte[]? body = await ReadSmallAsync(resp, MaxSmallBody, ct).ConfigureAwait(false);
        if (body is null || (IsHtml(resp) && body.Length > 0))
            throw new SpeedTestException($"{host} answered with a web page instead of the test data: the address is wrong, or the site is blocked on this network.");
    }

    /// <summary>The body when it is at most <paramref name="max"/> bytes; null when longer (reading stops there and the
    /// connection is dropped with the answer).</summary>
    internal static async Task<byte[]?> ReadSmallAsync(HttpResponseMessage resp, int max, CancellationToken ct)
    {
        if (resp.Content.Headers.ContentLength > max) return null;
        await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var buf = new byte[Math.Min(max + 1, (int)(resp.Content.Headers.ContentLength ?? max) + 1)];
        int total = 0, n;
        while (total < buf.Length && (n = await stream.ReadAsync(buf.AsMemory(total), ct).ConfigureAwait(false)) > 0) total += n;
        if (total > max) return null;
        return buf.AsSpan(0, total).ToArray();
    }

    /// <summary>Couldn't connect at all (as opposed to: connected, and got a wrong answer).</summary>
    internal static bool IsConnectFailure(Exception ex)
    {
        if (ex is SpeedTestException or SpeedTestHttpException) return false;
        for (Exception? e = ex; e is not null; e = e.InnerException)
            if (e is SocketException or AuthenticationException or IOException or TimeoutException) return true;
        return ex is HttpRequestException { StatusCode: null };
    }

    /// <summary>A few words on why a connection failed, for a sentence that lists several.</summary>
    internal static string ShortReason(Exception ex)
    {
        for (Exception? e = ex; e is not null; e = e.InnerException)
        {
            switch (e)
            {
                case SocketException se when se.SocketErrorCode is SocketError.HostNotFound or SocketError.NoData or SocketError.TryAgain:
                    return "the name doesn't resolve";
                case SocketException se when se.SocketErrorCode is SocketError.ConnectionRefused:
                    return "refused";
                case SocketException se when se.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionAborted:
                    return "the connection was reset";
                case SocketException se when se.SocketErrorCode is SocketError.TimedOut:
                    return "no answer";
                case SocketException se when se.SocketErrorCode is SocketError.NetworkUnreachable or SocketError.HostUnreachable or SocketError.NetworkDown:
                    return "no route";
                case AuthenticationException:
                    return "the secure connection failed";
                case TimeoutException:
                    return "no answer in time";
            }
        }
        return ex is IOException or HttpRequestException ? "the connection was cut off" : ex.Message.TrimEnd('.');
    }
}
