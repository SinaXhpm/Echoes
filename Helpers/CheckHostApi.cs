using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>The checks check-host.net runs from its nodes.</summary>
public enum CheckHostKind { Ping, Http, Tcp, Udp, Dns }

public static class CheckHostKinds
{
    /// <summary>In check-host.net's own order (its site lists Ping, HTTP, TCP port, UDP port, DNS).</summary>
    public static readonly CheckHostKind[] All = { CheckHostKind.Ping, CheckHostKind.Http, CheckHostKind.Tcp, CheckHostKind.Udp, CheckHostKind.Dns };

    /// <summary>The API's name: check-<c>ping</c>, check-<c>http</c>, …</summary>
    public static string Api(this CheckHostKind kind) => kind switch
    {
        CheckHostKind.Http => "http",
        CheckHostKind.Tcp => "tcp",
        CheckHostKind.Udp => "udp",
        CheckHostKind.Dns => "dns",
        _ => "ping",
    };

    public static string Label(this CheckHostKind kind) => kind switch
    {
        CheckHostKind.Http => "HTTP",
        CheckHostKind.Tcp => "TCP",
        CheckHostKind.Udp => "UDP",
        CheckHostKind.Dns => "DNS",
        _ => "Ping",
    };

    public static bool TryParse(string? api, out CheckHostKind kind)
    {
        foreach (var k in All)
            if (string.Equals(k.Api(), api?.Trim(), StringComparison.OrdinalIgnoreCase)) { kind = k; return true; }
        kind = CheckHostKind.Ping;
        return false;
    }
}

/// <summary>
/// A check-host.net probe node: its id ("de4.node.check-host.net"), where it is and who hosts it. Built from a check's
/// node map (<c>["de", "Germany", "Frankfurt", "185.37.147.117", "AS34549"]</c>) or the node list
/// (<c>{"asn": …, "ip": …, "location": ["de", "Germany", "Frankfurt"]}</c>).
/// </summary>
public sealed class CheckHostNode
{
    public CheckHostNode(string id, string countryCode, string country, string city, string ip, string asn)
    {
        Id = id.Trim();
        ShortId = Short(Id);
        CountryCode = countryCode.Trim().ToLowerInvariant();
        Country = country.Trim();
        City = city.Trim();
        Ip = ip.Trim();
        Asn = asn.Trim();
        Region = CheckHostRegions.Of(CountryCode);
        Location = City.Length == 0 || string.Equals(City, Country, StringComparison.OrdinalIgnoreCase)
            ? (Country.Length > 0 ? Country : ShortId)
            : Country.Length > 0 ? $"{City}, {Country}" : City;
    }

    /// <summary>"de4.node.check-host.net"</summary>
    public string Id { get; }
    /// <summary>"de4"</summary>
    public string ShortId { get; }
    /// <summary>ISO code, lower case ("de"; check-host.net uses "gb" for the UK).</summary>
    public string CountryCode { get; }
    public string Country { get; }
    public string City { get; }
    /// <summary>The node's own address.</summary>
    public string Ip { get; }
    /// <summary>"AS34549", or "" when unknown.</summary>
    public string Asn { get; }
    public string Region { get; }
    /// <summary>"Frankfurt, Germany"; just the country when the city is the same ("Hong Kong", "Singapore").</summary>
    public string Location { get; }
    public bool HasFlag => CountryCode.Length == 2;

    /// <summary>"de4" from "de4.node.check-host.net" (the first label of any other name).</summary>
    public static string Short(string id)
    {
        const string suffix = ".node.check-host.net";
        if (id.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)) return id[..^suffix.Length];
        int dot = id.IndexOf('.');
        return dot > 0 ? id[..dot] : id;
    }

    /// <summary>A node from a check's node map: ["cc", "Country", "City", "ip", "ASN"], or the older ["cc", "Country, City", "ip"].</summary>
    public static CheckHostNode FromAssigned(string id, JsonElement value)
    {
        string At(int i) => value.ValueKind == JsonValueKind.Array && value.GetArrayLength() > i && value[i].ValueKind == JsonValueKind.String
            ? value[i].GetString() ?? "" : "";
        string cc = At(0), country = At(1), city = At(2), ip = At(3), asn = At(4);
        if (value.ValueKind == JsonValueKind.Array && value.GetArrayLength() == 3 && country.Contains(','))
        {
            // the older shape: the address is the third item and "Country, City" the second
            ip = city;
            int c = country.IndexOf(',');
            city = country[(c + 1)..];
            country = country[..c];
        }
        return new CheckHostNode(id, cc, country, city, ip, asn);
    }

    /// <summary>A node from /nodes/hosts: {"asn": "AS…", "ip": "…", "location": ["cc", "Country", "City"]}.</summary>
    public static CheckHostNode FromCatalog(string id, JsonElement value)
    {
        string Str(string name) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String
            ? p.GetString() ?? "" : "";
        string cc = "", country = "", city = "";
        if (value.ValueKind == JsonValueKind.Object && value.TryGetProperty("location", out var loc) && loc.ValueKind == JsonValueKind.Array)
        {
            string At(int i) => loc.GetArrayLength() > i && loc[i].ValueKind == JsonValueKind.String ? loc[i].GetString() ?? "" : "";
            cc = At(0); country = At(1); city = At(2);
        }
        return new CheckHostNode(id, cc, country, city, Str("ip"), Str("asn"));
    }

    /// <summary>Natural order of node ids: "de2" before "de10", then the rest of the name.</summary>
    public static int CompareIds(string a, string b)
    {
        string sa = Short(a), sb = Short(b);
        int i = 0, j = 0;
        while (i < sa.Length && j < sb.Length)
        {
            if (char.IsDigit(sa[i]) && char.IsDigit(sb[j]))
            {
                int si = i, sj = j;
                while (i < sa.Length && char.IsDigit(sa[i])) i++;
                while (j < sb.Length && char.IsDigit(sb[j])) j++;
                long na = long.TryParse(sa.AsSpan(si, i - si), NumberStyles.None, CultureInfo.InvariantCulture, out var x) ? x : 0;
                long nb = long.TryParse(sb.AsSpan(sj, j - sj), NumberStyles.None, CultureInfo.InvariantCulture, out var y) ? y : 0;
                if (na != nb) return na.CompareTo(nb);
                continue;
            }
            int c = char.ToLowerInvariant(sa[i]).CompareTo(char.ToLowerInvariant(sb[j]));
            if (c != 0) return c;
            i++; j++;
        }
        int len = (sa.Length - i).CompareTo(sb.Length - j);
        return len != 0 ? len : string.Compare(a, b, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>Which part of the world a node is in, from its country code (check-host.net's list carries no region).</summary>
public static class CheckHostRegions
{
    public const string Europe = "Europe";
    public const string MiddleEast = "Middle East";
    public const string Asia = "Asia";
    public const string Americas = "Americas";
    public const string Africa = "Africa";
    public const string Oceania = "Oceania";
    public const string Other = "Other";

    /// <summary>Display order (a region list and the grouped results follow it).</summary>
    public static readonly string[] Order = { Europe, MiddleEast, Asia, Americas, Africa, Oceania, Other };

    private static readonly Dictionary<string, string> Map = Build();

    private static Dictionary<string, string> Build()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        void Add(string region, string codes)
        {
            foreach (var cc in codes.Split(' ', StringSplitOptions.RemoveEmptyEntries)) map[cc] = region;
        }
        Add(Europe, "ad al at ax ba be bg by ch cy cz de dk ee es fi fo fr gb gg gi gr hr hu ie im is it je li lt lu lv mc md me mk mt nl no pl pt ro rs ru se si sj sk sm ua uk va xk");
        Add(MiddleEast, "ae bh il iq ir jo kw lb om ps qa sa sy tr ye");
        Add(Asia, "af am az bd bn bt cn ge hk id in jp kg kh kp kr kz la lk mm mn mo mv my np ph pk sg th tj tl tm tw uz vn");
        Add(Americas, "ag ai ar aw bb bl bm bo bq br bs bz ca cl co cr cu cw dm do ec fk gd gf gl gp gt gy hn ht jm kn ky lc mf mq ms mx ni pa pe pm pr py sr sv sx tc tt us uy vc ve vg vi");
        Add(Africa, "ao bf bi bj bw cd cf cg ci cm cv dj dz eg eh er et ga gh gm gn gq gw ke km lr ls ly ma mg ml mr mu mw mz na ne ng re rw sc sd sh sl sn so ss st sz td tg tn tz ug yt za zm zw");
        Add(Oceania, "as au ck fj fm gu ki mh mp nc nf nr nu nz pf pg pn pw sb tk to tv vu wf ws");
        return map;
    }

    public static string Of(string? countryCode) =>
        countryCode is { Length: 2 } && Map.TryGetValue(countryCode, out var region) ? region : Other;

    public static int Rank(string region)
    {
        int i = Array.IndexOf(Order, region);
        return i < 0 ? Order.Length : i;
    }
}

/// <summary>
/// Credentials typed into a proxy address ("user:pass@host:port", "socks5://user:p%40ss@host:1080"). The address is a
/// plaintext setting and .NET never authenticates with user info written into a proxy address — only the user / password
/// fields do (the password stored encrypted) — so the view-model moves them there. Same rules as IP Info's.
/// </summary>
public static class CheckHostProxy
{
    /// <param name="Clean">The address without the user info.</param>
    /// <param name="HasHost">Something follows the '@' (not "user:pass@" half-typed).</param>
    /// <param name="HasPort">The address already ends in its port: typing is likely done.</param>
    public readonly record struct UserInfo(string Clean, string User, string Pass, bool HasHost, bool HasPort);

    /// <summary>The address split from its user info, or null when it has none. The LAST '@' of the authority ends the
    /// user info, so a password holding an '@' moves whole; with a scheme it's URL syntax, so percent escapes are decoded.</summary>
    public static UserInfo? Parse(string? address)
    {
        string a = (address ?? string.Empty).Trim();
        int scheme = a.IndexOf("://", StringComparison.Ordinal);
        int start = scheme >= 0 ? scheme + 3 : 0;
        int end = a.IndexOfAny(new[] { '/', '?', '#' }, start);
        if (end < 0) end = a.Length;
        int at = end > start ? a.LastIndexOf('@', end - 1, end - start) : -1;
        if (at < 0) return null;
        string info = a[start..at], hostPort = a[(at + 1)..end];
        int colon = info.IndexOf(':');
        string user = colon >= 0 ? info[..colon] : info, pass = colon >= 0 ? info[(colon + 1)..] : string.Empty;
        if (scheme >= 0)
        {
            user = Uri.UnescapeDataString(user);
            pass = Uri.UnescapeDataString(pass);
        }
        int portColon = hostPort.LastIndexOf(':');
        bool hasPort = portColon >= 0 && portColon < hostPort.Length - 1 && hostPort[(portColon + 1)..].All(char.IsAsciiDigit);
        return new UserInfo(a[..start] + a[(at + 1)..], user, pass, hostPort.Length > 0, hasPort);
    }

    /// <summary>The address as it may be stored or used: never with user info in it, even half-typed.</summary>
    public static string Clean(string? address) => Parse(address)?.Clean ?? (address ?? string.Empty).Trim();
}

/// <summary>A failure that reads as one clear sentence (shown as is).</summary>
public sealed class CheckHostException : Exception
{
    public CheckHostException(string message, Exception? inner = null, bool rateLimited = false) : base(message, inner)
        => RateLimited = rateLimited;

    /// <summary>check-host.net is throttling this address: a poll should back off rather than give up.</summary>
    public bool RateLimited { get; }
}

/// <summary>What check-host.net answered to a check request.</summary>
public sealed class CheckHostStart
{
    public CheckHostStart(string requestId, string permalink, IReadOnlyList<CheckHostNode> nodes)
    {
        RequestId = requestId;
        Permalink = permalink;
        Nodes = nodes;
    }

    public string RequestId { get; }
    /// <summary>https://check-host.net/check-report/&lt;request id&gt; — the check's page on the site.</summary>
    public string Permalink { get; }
    public IReadOnlyList<CheckHostNode> Nodes { get; }
}

/// <summary>
/// The target as check-host.net wants it for each check: a bare host for ping / DNS, the input as typed for HTTP (a URL
/// or a host), host:port for TCP / UDP (a URL's scheme also names the port for TCP: smtp://, https://).
/// </summary>
public static class CheckHostTarget
{
    /// <summary>The target to send; <paramref name="note"/> says what was assumed ("" when nothing). Throws
    /// <see cref="CheckHostException"/> when the input can't be used for this check.</summary>
    public static string Normalize(CheckHostKind kind, string? raw, out string note)
    {
        note = "";
        string t = (raw ?? "").Trim();
        if (t.Length == 0) throw new CheckHostException("Enter a host, IP or URL to check.");
        if (t.Length > 2000) throw new CheckHostException("That target is too long — enter a host, IP, host:port or URL.");
        if (t.IndexOfAny(new[] { ' ', '\t', '\r', '\n' }) >= 0 && !t.Contains("://", StringComparison.Ordinal))
        {
            // pasted text with more than a host in it: take the host it names
            if (HostExtractor.Best(t) is { } inText) t = inText.Url ?? inText.HostPort;
        }
        var found = HostExtractor.Best(t);
        switch (kind)
        {
            case CheckHostKind.Ping:
            case CheckHostKind.Dns:
                return found?.Host ?? t;
            case CheckHostKind.Http:
                return t;
            case CheckHostKind.Tcp:
                if (found is null) return t;
                if (found.Url is not null || found.Port is not null) return found.Url is not null ? t : found.HostPort;
                note = "port 80";
                return (found.Kind == HostExtractor.Kind.IPv6 ? $"[{found.Host}]" : found.Host) + ":80";
            default:   // UDP
                if (found?.Port is not null) return found.HostPort;
                throw new CheckHostException("A UDP check needs a port — e.g. 8.8.8.8:53 (DNS) or pool.ntp.org:123 (NTP).");
        }
    }
}

/// <summary>
/// check-host.net's public API (https://check-host.net/about/api): start a check, read its results, list the nodes.
/// Every failure comes out as a <see cref="CheckHostException"/> whose message says why, in one sentence.
/// </summary>
public sealed class CheckHostClient
{
    public static readonly Uri DefaultBase = new("https://check-host.net/");

    private readonly HttpClient _http;
    private readonly Uri _base;
    private readonly bool _viaProxy;

    /// <param name="http">Configured by the caller (proxy, timeout); not disposed here.</param>
    public CheckHostClient(HttpClient http, Uri? baseUri = null, bool viaProxy = false)
    {
        _http = http;
        _base = baseUri ?? DefaultBase;
        _viaProxy = viaProxy;
    }

    /// <summary>The site's page for a check.</summary>
    public static string ReportUrl(string requestId) => "https://check-host.net/check-report/" + Uri.EscapeDataString(requestId);

    /// <summary>"check-ping?host=…&amp;max_nodes=20", or with node=… for each chosen node (then no max_nodes).</summary>
    public static string StartPath(CheckHostKind kind, string target, int maxNodes, IReadOnlyList<string>? nodes)
    {
        var sb = new StringBuilder("check-").Append(kind.Api()).Append("?host=").Append(Uri.EscapeDataString(target));
        if (nodes is { Count: > 0 })
            foreach (var n in nodes) sb.Append("&node=").Append(Uri.EscapeDataString(n));
        else
            sb.Append("&max_nodes=").Append(Math.Clamp(maxNodes, 1, 100).ToString(CultureInfo.InvariantCulture));
        return sb.ToString();
    }

    public async Task<CheckHostStart> StartAsync(CheckHostKind kind, string target, int maxNodes, IReadOnlyList<string>? nodes, CancellationToken ct)
    {
        string body = await GetAsync(StartPath(kind, target, maxNodes, nodes), Call.Start, ct).ConfigureAwait(false);
        using var doc = ParseJson(body, Call.Start, target);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new CheckHostException("check-host.net sent an answer this version can't read.");
        if (root.TryGetProperty("error", out var err) && err.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined))
            throw ApiError(err.ValueKind == JsonValueKind.String ? err.GetString() ?? "" : err.GetRawText(), target);
        bool ok = root.TryGetProperty("ok", out var okEl)
                  && (okEl.ValueKind == JsonValueKind.True || (okEl.ValueKind == JsonValueKind.Number && okEl.TryGetInt32(out int o) && o == 1));
        if (!ok) throw new CheckHostException($"check-host.net didn't accept the check for \"{target}\".");

        string id = root.TryGetProperty("request_id", out var rid) ? rid.ValueKind == JsonValueKind.String ? rid.GetString() ?? "" : rid.GetRawText() : "";
        if (id.Length == 0) throw new CheckHostException("check-host.net started the check but sent no request id to read its results.");
        // the report's page on the site (it becomes a link the user can open): only ever check-host.net itself
        string link = root.TryGetProperty("permanent_link", out var pl) && pl.ValueKind == JsonValueKind.String ? pl.GetString() ?? "" : "";
        if (!Uri.TryCreate(link, UriKind.Absolute, out var linkUri) || linkUri.Scheme != Uri.UriSchemeHttps
            || !(linkUri.Host.Equals("check-host.net", StringComparison.OrdinalIgnoreCase) || linkUri.Host.EndsWith(".check-host.net", StringComparison.OrdinalIgnoreCase)))
            link = ReportUrl(id);

        var list = new List<CheckHostNode>();
        if (root.TryGetProperty("nodes", out var nodesEl) && nodesEl.ValueKind == JsonValueKind.Object)
            foreach (var np in nodesEl.EnumerateObject())
                list.Add(CheckHostNode.FromAssigned(np.Name, np.Value));
        if (list.Count == 0)
            throw new CheckHostException("check-host.net assigned no nodes to the check — none of the chosen nodes may be online. Try again, or let it pick (Automatic).");
        return new CheckHostStart(id, link, list);
    }

    /// <summary>The raw results so far (a node is null while it is still working). The caller disposes it.</summary>
    public async Task<JsonDocument> ResultsAsync(string requestId, CancellationToken ct)
    {
        string body = await GetAsync("check-result/" + Uri.EscapeDataString(requestId), Call.Poll, ct).ConfigureAwait(false);
        return ParseJson(body, Call.Poll, "");
    }

    /// <summary>Every node check-host.net runs (/nodes/hosts), in its order.</summary>
    public async Task<IReadOnlyList<CheckHostNode>> NodesAsync(CancellationToken ct)
    {
        string body = await GetAsync("nodes/hosts", Call.Nodes, ct).ConfigureAwait(false);
        using var doc = ParseJson(body, Call.Nodes, "");
        var list = new List<CheckHostNode>();
        if (doc.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.TryGetProperty("nodes", out var nodes)
            && nodes.ValueKind == JsonValueKind.Object)
            foreach (var np in nodes.EnumerateObject())
                list.Add(CheckHostNode.FromCatalog(np.Name, np.Value));
        if (list.Count == 0) throw new CheckHostException("check-host.net sent an empty node list.");
        return list;
    }

    private enum Call { Start, Poll, Nodes }

    /// <summary>The largest answer read (after decompression). The biggest real one — the node list, or a check's results
    /// from 100 nodes — is a few tens of KB; anything this size isn't a check-host.net answer.</summary>
    public const int MaxBodyBytes = 2 * 1024 * 1024;

    private static readonly TimeSpan FallbackTimeout = TimeSpan.FromSeconds(15);

    private async Task<string> GetAsync(string path, Call call, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, new Uri(_base, path));
        req.Headers.Accept.ParseAdd("application/json");
        // One deadline for the headers AND the body: with the body streamed (to cap its size), HttpClient.Timeout stops
        // counting once the headers are in, and a server trickling bytes could hold the run forever.
        var timeout = _http.Timeout > TimeSpan.Zero && _http.Timeout != Timeout.InfiniteTimeSpan ? _http.Timeout : FallbackTimeout;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeout);
        HttpResponseMessage resp;
        try
        {
            resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { throw new CheckHostException(CheckHostErrors.Network(ex, _viaProxy, timeout), ex); }

        using (resp)
        {
            string body;
            try { body = await ReadCappedAsync(resp.Content, deadline.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (CheckHostException) { throw; }
            catch (OperationCanceledException ex)
            {
                throw new CheckHostException($"check-host.net didn't finish sending its answer within {CheckHostErrors.Seconds(timeout)}"
                                             + (_viaProxy ? " through the proxy" : "") + " — the connection is too slow or something is holding it up. Run again, or try a proxy.", ex);
            }
            catch (Exception ex) { throw new CheckHostException(CheckHostErrors.Network(ex, _viaProxy, timeout), ex); }

            if (resp.IsSuccessStatusCode) return body;
            int code = (int)resp.StatusCode;
            bool html = LooksLikeHtml(body);
            if (code == 429 || (!html && body.Contains("limit", StringComparison.OrdinalIgnoreCase) && code is 403 or 503))
                throw new CheckHostException(CheckHostErrors.RateLimited, rateLimited: true);
            if (code == 407)
                throw new CheckHostException("The proxy asked for a login (HTTP 407) — check the proxy's user name and password.");
            if (code is 403 or 503 && html && LooksLikeBotWall(body))
                throw new CheckHostException("check-host.net's bot protection blocked the request (HTTP " + code
                                             + "). Wait a few minutes and run again, or route it through a proxy.");
            if (code >= 500)
                throw new CheckHostException($"check-host.net has a problem right now (HTTP {code}). Try again in a moment.");
            if (code == 404 && call == Call.Poll)
                throw new CheckHostException("check-host.net no longer has this check's results (HTTP 404). Run it again.");
            throw new CheckHostException($"check-host.net refused the request (HTTP {code} {resp.ReasonPhrase}).".Replace(" )", ")"));
        }
    }

    /// <summary>The body as text, read as a stream: at most <see cref="MaxBodyBytes"/> (decompressed), else one clear error.
    /// JSON is UTF-8 (RFC 8259); a byte-order mark is dropped.</summary>
    private static async Task<string> ReadCappedAsync(HttpContent content, CancellationToken ct)
    {
        if (content.Headers.ContentLength is long declared && declared > MaxBodyBytes) throw TooLarge();
        await using var stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        byte[] chunk = new byte[16 * 1024];
        while (true)
        {
            int n = await stream.ReadAsync(chunk, ct).ConfigureAwait(false);
            if (n == 0) break;
            if (buffer.Length + n > MaxBodyBytes) throw TooLarge();
            buffer.Write(chunk, 0, n);
        }
        byte[] data = buffer.GetBuffer();
        int length = (int)buffer.Length, start = length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF ? 3 : 0;
        return Encoding.UTF8.GetString(data, start, length - start);

        static CheckHostException TooLarge() => new(
            $"check-host.net sent an answer over {MaxBodyBytes / (1024 * 1024)} MB — far more than any check result, so it was not read. "
            + "Something on the path (a proxy or filter) may be answering in its place.");
    }

    private static JsonDocument ParseJson(string body, Call call, string target)
    {
        if (LooksLikeHtml(body))
            throw new CheckHostException(call == Call.Start
                ? $"check-host.net didn't run the check — it sent back a web page instead of a result, which means it didn't accept \"{target}\" as a host, IP, host:port or URL."
                : LooksLikeBotWall(body)
                    ? "check-host.net's bot protection answered instead of the API. Wait a few minutes and run again, or route it through a proxy."
                    : "check-host.net sent a web page instead of data.");
        try { return JsonDocument.Parse(body); }
        catch (JsonException)
        {
            throw new CheckHostException(body.Trim().Length == 0
                ? "check-host.net sent an empty answer."
                : "check-host.net sent an answer this version can't read.");
        }
    }

    private static CheckHostException ApiError(string error, string target)
    {
        string e = error.Trim().Trim('"');
        if (e.Contains("limit", StringComparison.OrdinalIgnoreCase))
            return new CheckHostException(CheckHostErrors.RateLimited, rateLimited: true);
        if (e.Length == 0) return new CheckHostException($"check-host.net didn't accept the check for \"{target}\".");
        if (e.Length > 160) e = e[..160] + "…";
        return new CheckHostException($"check-host.net didn't run the check: {e.TrimEnd('.')}.");
    }

    private static bool LooksLikeHtml(string body)
    {
        foreach (char c in body)
        {
            if (char.IsWhiteSpace(c) || c == '﻿') continue;
            return c == '<';
        }
        return false;
    }

    private static bool LooksLikeBotWall(string body) =>
        body.Contains("cloudflare", StringComparison.OrdinalIgnoreCase) || body.Contains("cf-chl", StringComparison.OrdinalIgnoreCase)
        || body.Contains("Just a moment", StringComparison.OrdinalIgnoreCase) || body.Contains("Attention Required", StringComparison.OrdinalIgnoreCase)
        || body.Contains("captcha", StringComparison.OrdinalIgnoreCase);
}

/// <summary>Why check-host.net couldn't be reached, in one sentence that says what to do.</summary>
public static class CheckHostErrors
{
    public const string RateLimited =
        "check-host.net is limiting requests from your address — wait a minute, then run again.";

    /// <summary>"1 second", "15 seconds".</summary>
    public static string Seconds(TimeSpan timeout)
    {
        double secs = Math.Max(1, Math.Round(timeout.TotalSeconds));
        return secs == 1 ? "1 second" : secs.ToString(CultureInfo.InvariantCulture) + " seconds";
    }

    public static string Network(Exception ex, bool viaProxy, TimeSpan timeout)
    {
        string via = viaProxy ? " through the proxy" : "";
        if (ex is TaskCanceledException or OperationCanceledException or TimeoutException)
            return $"check-host.net didn't answer within {Seconds(timeout)}{via} — it may be slow or blocked on this network. Run again, or try a proxy.";

        SocketException? socket = null;
        HttpRequestError httpError = HttpRequestError.Unknown;
        bool tls = false;
        for (var e = ex; e is not null; e = e.InnerException)
        {
            if (e is HttpRequestException h && h.HttpRequestError != HttpRequestError.Unknown && httpError == HttpRequestError.Unknown)
                httpError = h.HttpRequestError;
            if (e is SocketException s) socket ??= s;
            if (e is AuthenticationException) tls = true;
        }
        if (httpError == HttpRequestError.ProxyTunnelError)
            return "The proxy refused to connect to check-host.net — check the proxy address and that it allows HTTPS (CONNECT).";
        if (httpError == HttpRequestError.SecureConnectionError || tls)
            return "The secure connection to check-host.net failed — a firewall, antivirus or proxy may be intercepting HTTPS.";
        if (httpError == HttpRequestError.NameResolutionError || socket?.SocketErrorCode is SocketError.HostNotFound or SocketError.NoData or SocketError.TryAgain)
            return viaProxy
                ? "The proxy's address doesn't resolve — check the proxy host name."
                : "Can't reach check-host.net — its name doesn't resolve on this network (DNS). Check the connection, or use a proxy.";
        switch (socket?.SocketErrorCode)
        {
            case SocketError.ConnectionRefused:
                return viaProxy
                    ? "The proxy refused the connection — is it running at that address and port?"
                    : "check-host.net refused the connection — something on this network may be blocking it. Try a proxy.";
            case SocketError.TimedOut:
                return $"Can't reach check-host.net{via}: the connection timed out — it may be blocked on this network. Try a proxy.";
            case SocketError.NetworkUnreachable or SocketError.HostUnreachable or SocketError.NetworkDown:
                return "No network route to check-host.net — check the connection.";
            case SocketError.ConnectionReset or SocketError.ConnectionAborted:
                return $"The connection to check-host.net was cut off{via} — it may be filtered on this network. Try a proxy.";
        }
        if (ex is IOException or HttpRequestException)
        {
            string inner = Innermost(ex);
            return $"Can't reach check-host.net{via} ({inner.TrimEnd('.')}).";
        }
        return "Can't reach check-host.net: " + Innermost(ex).TrimEnd('.') + ".";
    }

    private static string Innermost(Exception ex)
    {
        string msg = ex.Message;
        for (var e = ex.InnerException; e is not null; e = e.InnerException)
            if (!string.IsNullOrWhiteSpace(e.Message)) msg = e.Message;
        msg = CloudflareApi.RedactUserInfo(msg.Trim());
        return msg.Length > 140 ? msg[..140] + "…" : msg;
    }
}
