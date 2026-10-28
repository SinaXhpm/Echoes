using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>What Globalping answered to a new measurement.</summary>
public sealed record GlobalpingCreated(string Id, int ProbesCount);

/// <summary>One look at a running measurement: its document (disposed with this), or nothing new since the last look.</summary>
public sealed class GlobalpingPoll : IDisposable
{
    public JsonDocument? Document { get; init; }
    /// <summary>The answer's ETag, sent back with the next look so an unchanged measurement costs an empty 304.</summary>
    public EntityTagHeaderValue? ETag { get; init; }
    public void Dispose() => Document?.Dispose();
}

/// <summary>
/// Globalping's public API (https://globalping.io/docs/api.globalping.io), Check Host's fallback when check-host.net can't
/// be reached: measurements from its probes around the world, without an account. An address may run 250 tests an hour
/// (each probe of a measurement is one test), on up to 50 probes per measurement, and read a running measurement at most
/// twice a second. Every failure comes out as a <see cref="CheckHostException"/> whose message says why, in one sentence.
/// </summary>
public sealed class GlobalpingClient
{
    public static readonly Uri DefaultBase = new("https://api.globalping.io/");

    /// <summary>The largest measurement read (after decompression): 50 probes' HTTP results, headers and all, are ~150 KB.</summary>
    public const int MaxBodyBytes = 2 * 1024 * 1024;
    /// <summary>The probe list: ~2.2 MB for 5,300 probes in October 2026 (140 KB on the wire).</summary>
    public const int MaxProbeListBytes = 12 * 1024 * 1024;

    private const string Service = "Globalping";
    private static readonly TimeSpan FallbackTimeout = TimeSpan.FromSeconds(15);

    private readonly HttpClient _http;
    private readonly Uri _base;
    private readonly bool _viaProxy;

    /// <param name="http">Configured by the caller (proxy, timeout); not disposed here.</param>
    public GlobalpingClient(HttpClient http, Uri? baseUri = null, bool viaProxy = false)
    {
        _http = http;
        _base = baseUri ?? DefaultBase;
        _viaProxy = viaProxy;
    }

    /// <summary>The measurement's page on globalping.io.</summary>
    public static string ReportUrl(string id) => "https://globalping.io/?measurement=" + Uri.EscapeDataString(id);

    /// <summary>A measurement id as Globalping writes them ("2XdEHjyU9wiqXvNTK00021Oln"): it goes into a URL, so an answer
    /// is never used unchecked.</summary>
    public static bool IsMeasurementId(string? id) =>
        id is { Length: > 0 and <= 64 } && id.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    /// <summary>Starts a measurement (<paramref name="json"/>: the request body).</summary>
    public async Task<GlobalpingCreated> CreateAsync(string json, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, new Uri(_base, "v1/measurements"))
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };
        var a = await SendAsync(req, MaxBodyBytes, ct).ConfigureAwait(false);
        if (a.Code is not (200 or 201 or 202)) throw Failure(a, creating: true);
        using var doc = ParseJson(a);
        var root = doc.RootElement;
        string id = root.ValueKind == JsonValueKind.Object && root.TryGetProperty("id", out var idEl) && idEl.ValueKind == JsonValueKind.String
            ? idEl.GetString() ?? "" : "";
        if (!IsMeasurementId(id)) throw new CheckHostException("Globalping started the check but sent no usable id to read its results.");
        int count = root.TryGetProperty("probesCount", out var pc) && pc.ValueKind == JsonValueKind.Number && pc.TryGetInt32(out int n) ? n : 0;
        return new GlobalpingCreated(id, count);
    }

    /// <summary>The measurement so far; with <paramref name="etag"/> from the last look, no document when nothing changed.</summary>
    public async Task<GlobalpingPoll> GetAsync(string id, EntityTagHeaderValue? etag, CancellationToken ct)
    {
        if (!IsMeasurementId(id)) throw new CheckHostException("Globalping's measurement id isn't usable.");
        using var req = new HttpRequestMessage(HttpMethod.Get, new Uri(_base, "v1/measurements/" + id));
        if (etag is not null) req.Headers.IfNoneMatch.Add(etag);
        var a = await SendAsync(req, MaxBodyBytes, ct).ConfigureAwait(false);
        if (a.Code == 304) return new GlobalpingPoll { ETag = etag };
        if (a.Code != 200) throw Failure(a, creating: false);
        return new GlobalpingPoll { Document = ParseJson(a), ETag = a.ETag };
    }

    /// <summary>Where Globalping has probes right now (/v1/probes, no limit on it): read once per session, and only to map
    /// check-host.net nodes picked one by one to Globalping's places.</summary>
    public async Task<GlobalpingProbeIndex> ProbesAsync(CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, new Uri(_base, "v1/probes"));
        var a = await SendAsync(req, MaxProbeListBytes, ct).ConfigureAwait(false);
        if (a.Code != 200) throw Failure(a, creating: false);
        using var doc = ParseJson(a);
        var index = GlobalpingProbeIndex.Parse(doc.RootElement);
        if (index.Count == 0) throw new CheckHostException("Globalping sent an empty probe list.");
        return index;
    }

    // ---------------- transport ----------------

    private readonly record struct Answer(int Code, string Reason, byte[] Body, int Length, EntityTagHeaderValue? ETag,
                                          TimeSpan? RetryAfter, int? Remaining, TimeSpan? Reset);

    private async Task<Answer> SendAsync(HttpRequestMessage req, int max, CancellationToken ct)
    {
        req.Headers.Accept.ParseAdd("application/json");
        // One deadline for the headers AND the body (streamed to cap it): HttpClient.Timeout stops counting at the headers.
        var timeout = _http.Timeout > TimeSpan.Zero && _http.Timeout != Timeout.InfiniteTimeSpan ? _http.Timeout : FallbackTimeout;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeout);
        HttpResponseMessage resp;
        try
        {
            resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { throw new CheckHostException(CheckHostErrors.Network(ex, _viaProxy, timeout, Service), ex); }

        using (resp)
        {
            byte[] body;
            int length;
            try { (body, length) = await ReadCappedAsync(resp.Content, max, deadline.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (CheckHostException) { throw; }
            catch (OperationCanceledException ex)
            {
                throw new CheckHostException($"Globalping didn't finish sending its answer within {CheckHostErrors.Seconds(timeout)}"
                                             + (_viaProxy ? " through the proxy" : "") + " — the connection is too slow or something is holding it up. Run again, or try a proxy.", ex);
            }
            catch (Exception ex) { throw new CheckHostException(CheckHostErrors.Network(ex, _viaProxy, timeout, Service), ex); }

            var h = resp.Headers;
            TimeSpan? retry = h.RetryAfter?.Delta ?? (h.RetryAfter?.Date is { } at ? at - DateTimeOffset.UtcNow : null);
            return new Answer((int)resp.StatusCode, resp.ReasonPhrase ?? "", body, length,
                              h.ETag is { } tag && tag.Tag.Length <= 200 ? tag : null,
                              retry is { } r && r > TimeSpan.Zero ? r : null,
                              Int(h, "X-RateLimit-Remaining"), Int(h, "X-RateLimit-Reset") is int s ? TimeSpan.FromSeconds(s) : null);
        }
    }

    private static int? Int(HttpResponseHeaders h, string name) =>
        h.TryGetValues(name, out var values) && int.TryParse(values.FirstOrDefault(), NumberStyles.None, CultureInfo.InvariantCulture, out int v)
            ? v : null;

    /// <summary>The body, read as a stream: at most <paramref name="max"/> bytes (decompressed), else one clear error.</summary>
    private static async Task<(byte[], int)> ReadCappedAsync(HttpContent content, int max, CancellationToken ct)
    {
        if (content.Headers.ContentLength is long declared && declared > max) throw TooLarge(max);
        await using var stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        byte[] chunk = new byte[16 * 1024];
        while (true)
        {
            int n = await stream.ReadAsync(chunk, ct).ConfigureAwait(false);
            if (n == 0) break;
            if (buffer.Length + n > max) throw TooLarge(max);
            buffer.Write(chunk, 0, n);
        }
        return (buffer.GetBuffer(), (int)buffer.Length);

        static CheckHostException TooLarge(int max) => new(
            $"Globalping sent an answer over {max / (1024 * 1024)} MB — far more than any result, so it was not read. "
            + "Something on the path (a proxy or filter) may be answering in its place.");
    }

    private static bool LooksLikeHtml(Answer a)
    {
        for (int i = 0; i < a.Length; i++)
        {
            byte b = a.Body[i];
            if (b is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n' or 0xEF or 0xBB or 0xBF) continue;
            return b == '<';
        }
        return false;
    }

    private static JsonDocument ParseJson(Answer a)
    {
        if (LooksLikeHtml(a)) throw WebPage();
        try { return JsonDocument.Parse(a.Body.AsMemory(0, a.Length)); }
        catch (JsonException)
        {
            throw new CheckHostException(a.Length == 0 ? "Globalping sent an empty answer." : "Globalping sent an answer this version can't read.");
        }
    }

    private static CheckHostException WebPage() => new(
        "Globalping sent a web page instead of data — something on this network (a filter, a login page or a proxy) may be answering in its place.");

    /// <summary>A refusal in one sentence: the API's own words for a check it didn't take, the wait for a rate limit.</summary>
    private CheckHostException Failure(Answer a, bool creating)
    {
        if (a.Code == 407) return new CheckHostException("The proxy asked for a login (HTTP 407) — check the proxy's user name and password.");
        if (LooksLikeHtml(a) && a.Code != 429) return WebPage();
        string said = ApiMessage(a);
        switch (a.Code)
        {
            case 429 when creating:
                return new CheckHostException("Globalping's hourly limit for your address is used up"
                                              + (a.Reset is { } reset ? $" — it resets in {Minutes(reset)}." : " — try again later."), rateLimited: true)
                {
                    RetryAfter = a.Reset,
                    Remaining = a.Remaining,
                };
            case 429:
                return new CheckHostException("Globalping asked to slow down.", rateLimited: true) { RetryAfter = a.RetryAfter ?? TimeSpan.FromSeconds(2) };
            case 400:
                return new CheckHostException(said.Length > 0 ? $"Globalping didn't accept the check: {said.TrimEnd('.')}." : "Globalping didn't accept the check (HTTP 400).");
            case 422:
                return new CheckHostException("Globalping has no probes for this check in the chosen places right now"
                                              + (said.Length > 0 ? $" ({said.TrimEnd('.')})." : "."));
            case 404 when !creating:
                return new CheckHostException("Globalping no longer has this check's results (HTTP 404). Run it again.");
            case >= 500:
                return new CheckHostException($"Globalping has a problem right now (HTTP {a.Code}). Try again in a moment.");
            default:
                return new CheckHostException($"Globalping refused the request (HTTP {a.Code} {a.Reason}).".Replace(" )", ")"));
        }
    }

    /// <summary>The API's error, {"error": {"message": …, "params": {"target": "…"}}}, as one cleaned line.</summary>
    private static string ApiMessage(Answer a)
    {
        try
        {
            using var doc = JsonDocument.Parse(a.Body.AsMemory(0, a.Length));
            if (doc.RootElement.ValueKind != JsonValueKind.Object || !doc.RootElement.TryGetProperty("error", out var err)
                || err.ValueKind != JsonValueKind.Object) return "";
            string message = err.TryGetProperty("message", out var m) && m.ValueKind == JsonValueKind.String ? m.GetString() ?? "" : "";
            var details = new List<string>();
            if (err.TryGetProperty("params", out var p) && p.ValueKind == JsonValueKind.Object)
                foreach (var param in p.EnumerateObject().Take(3))
                    if (param.Value.ValueKind == JsonValueKind.String) details.Add(param.Value.GetString() ?? "");
            string text = details.Count > 0 ? message.TrimEnd('.') + ": " + string.Join("; ", details) : message;
            return RemoteText.Clean(text.ReplaceLineEndings(" ").Trim(), 200);
        }
        catch (JsonException) { return ""; }
    }

    /// <summary>"1 minute", "23 minutes".</summary>
    private static string Minutes(TimeSpan t)
    {
        int m = Math.Max(1, (int)Math.Ceiling(t.TotalMinutes));
        return m == 1 ? "1 minute" : m.ToString(CultureInfo.InvariantCulture) + " minutes";
    }
}

/// <summary>Where Globalping has probes: the countries, and the cities by country (as it spells them).</summary>
public sealed class GlobalpingProbeIndex
{
    private readonly HashSet<string> _countries = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _cities = new(StringComparer.Ordinal);

    /// <summary>Probes listed.</summary>
    public int Count { get; private set; }

    public bool HasCountry(string countryCode) => _countries.Contains(countryCode.ToUpperInvariant());

    /// <summary>Globalping's own spelling of <paramref name="city"/> when it has a probe there, else null.</summary>
    public string? City(string countryCode, string city) =>
        city.Length > 0 && _cities.TryGetValue(Key(countryCode, city), out var name) ? name : null;

    /// <summary>From /v1/probes: [{"location": {"country": "DE", "city": "Frankfurt", …}, …}, …].</summary>
    public static GlobalpingProbeIndex Parse(JsonElement root)
    {
        var index = new GlobalpingProbeIndex();
        if (root.ValueKind != JsonValueKind.Array) return index;
        foreach (var probe in root.EnumerateArray())
        {
            if (probe.ValueKind != JsonValueKind.Object || !probe.TryGetProperty("location", out var loc) || loc.ValueKind != JsonValueKind.Object)
                continue;
            string cc = Str(loc, "country"), city = Str(loc, "city");
            if (cc.Length != 2 || !cc.All(char.IsAsciiLetter)) continue;
            cc = cc.ToUpperInvariant();
            index.Count++;
            index._countries.Add(cc);
            if (city.Length is > 0 and <= 128) index._cities.TryAdd(Key(cc, city), city);
        }
        return index;
    }

    private static string Str(JsonElement o, string name) =>
        o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? (v.GetString() ?? "").Trim() : "";

    // "Sao Paulo", "sao-paulo" and "SAO PAULO" are one city
    private static string Key(string countryCode, string city)
    {
        var sb = new StringBuilder(countryCode.Length + 1 + city.Length).Append(countryCode.ToUpperInvariant()).Append('|');
        foreach (char c in city)
            if (char.IsLetterOrDigit(c)) sb.Append(char.ToLowerInvariant(c));
        return sb.ToString();
    }
}
