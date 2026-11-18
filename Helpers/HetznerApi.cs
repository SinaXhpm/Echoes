using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>The outcome of one Hetzner Cloud API call. Never carries the token.</summary>
public sealed class HzResponse
{
    public bool Success { get; init; }
    /// <summary>HTTP status; 0 when no response arrived (network error, timeout).</summary>
    public int Status { get; init; }
    /// <summary>The answer's JSON (on success; an error answer is read into <see cref="Error"/> instead).</summary>
    public JsonNode? Body { get; init; }
    /// <summary>A readable error ("message (code)" plus a hint), already redacted. Empty on success.</summary>
    public string Error { get; init; } = string.Empty;
    /// <summary>Hetzner's machine-readable error code ("forbidden", "not_found", "locked" …); "" when there is none.</summary>
    public string Code { get; init; } = string.Empty;
    /// <summary>401: Hetzner doesn't know this token (mistyped, or deleted in the Console).</summary>
    public bool AuthFailed { get; init; }
    /// <summary>403 "forbidden": the token is valid but may only read (a Read token asked to change something).</summary>
    public bool ReadOnly { get; init; }
    public bool NotFound => Status == 404;

    internal static HzResponse Fail(string error, int status = 0) => new() { Error = error, Status = status };
}

/// <summary>A paginated list call: every page's items, or the first failure.</summary>
public sealed class HzListResponse
{
    public bool Success { get; init; }
    public int Status { get; init; }
    public string Error { get; init; } = string.Empty;
    public string Code { get; init; } = string.Empty;
    public bool AuthFailed { get; init; }
    public bool ReadOnly { get; init; }
    public List<JsonNode> Items { get; init; } = new();
    /// <summary>The list was cut at the page cap (it has more items than were read).</summary>
    public bool Truncated { get; init; }
}

/// <summary>One asynchronous Hetzner action (a power change, new DNS records, firewall rules …) as last seen.</summary>
public sealed class HzAction
{
    public long Id { get; init; }
    public string Command { get; init; } = string.Empty;
    /// <summary>running, success or error.</summary>
    public string Status { get; init; } = string.Empty;
    public int Progress { get; init; }
    public string ErrorCode { get; init; } = string.Empty;
    public string ErrorMessage { get; init; } = string.Empty;

    public bool IsRunning => Status == "running";
    public bool IsSuccess => Status == "success";
    public bool IsError => Status == "error";

    /// <summary>An action object ({"id", "command", "status", "progress", "error"}); null when it isn't one.</summary>
    public static HzAction? From(JsonNode? n)
    {
        if (n is not JsonObject o || CfJson.Long(o["id"]) is not long id || !HetznerApi.IsId(id)) return null;
        return new HzAction
        {
            Id = id,
            Command = HetznerApi.Clip(CfJson.Str(o["command"]), 60),
            Status = CfJson.Str(o["status"]) switch { "running" => "running", "success" => "success", "error" => "error", _ => "running" },
            Progress = Math.Clamp(CfJson.Int(o["progress"]) ?? 0, 0, 100),
            ErrorCode = HetznerApi.Clip(CfJson.Str(o["error"]?["code"]), 60),
            ErrorMessage = HetznerApi.Clip(CfJson.Str(o["error"]?["message"]), 300),
        };
    }
}

/// <summary>How a waited-for action ended.</summary>
public sealed class HzActionResult
{
    public bool Ok { get; init; }
    /// <summary>It was still running when the wait gave up (it may well finish on Hetzner's side).</summary>
    public bool StillRunning { get; init; }
    public string Error { get; init; } = string.Empty;
    public HzAction? Action { get; init; }
}

/// <summary>
/// A small Hetzner Cloud API client (https://api.hetzner.cloud/v1) for one project's API token and its optional proxy.
/// Servers, firewalls and DNS (zones and record sets: the Cloud API took DNS over from the old DNS Console API, which
/// was shut down in May 2026) all go through it.
///
/// <para>Security: the token goes out as the Authorization header only, and nothing here logs or echoes it: every error
/// text that reaches the UI is passed through <see cref="Redact"/>. Redirects are NOT followed (the header would go to
/// whatever host a redirect names). Ids are numbers and record-set names and types are checked before they go into a
/// URL path, and the host is fixed (<see cref="BaseUrl"/>). Answers are untrusted: the body is capped in size and
/// time, and strings taken from it are clipped by the callers.</para>
///
/// <para>JSON is read with <see cref="JsonNode"/> and written with <see cref="JsonObject"/> (no reflection; AOT and
/// trim safe).</para>
/// </summary>
public sealed class HetznerApi : IDisposable
{
    public const string DefaultBaseUrl = "https://api.hetzner.cloud/v1";
    private const int MaxResponseBytes = 16 * 1024 * 1024;
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(25);
    // 3600 requests an hour per project, refilled gradually (about one a second): a 429 is retried after a short wait.
    private const int MaxAttempts = 3;
    private static readonly TimeSpan MaxRetryWait = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan RefillWait = TimeSpan.FromSeconds(2);

    /// <summary>Where a read-only token is upgraded, in the Console's words.</summary>
    public const string ReadWriteHint =
        "This token can only read. In the Hetzner Console open the project, then Security → API tokens, and generate a token with Read & Write.";

    private static string _baseUrl = DefaultBaseUrl;

    /// <summary>
    /// The API root. Test hook only (a local mock server stands in for the API): it accepts the real API or a LOOPBACK
    /// address, nothing else, so user data can never point the client, and the token it sends, at another host. Not
    /// bound to any UI or setting.
    /// </summary>
    internal static string BaseUrl
    {
        get => _baseUrl;
        set
        {
            string v = (value ?? string.Empty).TrimEnd('/');
            if (v == DefaultBaseUrl || IsLoopbackRoot(v)) _baseUrl = v;
            else throw new ArgumentException("The Hetzner API root can only be the real API or a loopback test server.");
        }
    }

    /// <summary>Test hook: the pause between two polls of a running action (tests shorten it).</summary>
    internal static TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(1.5);

    private static bool IsLoopbackRoot(string url)
        => Uri.TryCreate(url, UriKind.Absolute, out var u)
           && (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps)
           && u.IsLoopback && string.IsNullOrEmpty(u.UserInfo) && string.IsNullOrEmpty(u.Query) && string.IsNullOrEmpty(u.Fragment);

    private readonly HttpClient _http;
    private readonly string[] _secrets;

    private HetznerApi(HttpClient http, string[] secrets)
    {
        _http = http;
        _secrets = secrets;
    }

    /// <summary>
    /// Build a client for one project's token. Throws <see cref="ArgumentException"/> with a readable message (never
    /// containing the token) when the token or the proxy address is unusable.
    /// </summary>
    public static HetznerApi Create(string? token, string? proxy, string? proxyUser, string? proxyPass)
    {
        token = token?.Trim() ?? string.Empty;
        if (token.Length == 0) throw new ArgumentException("Enter an API token.");
        if (!IsTokenShape(token)) throw new ArgumentException("The token contains spaces, line breaks or other characters a token doesn't have. Paste it again.");

        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,      // the token must never follow a redirect to another host
            AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromSeconds(15),
            UseCookies = false,
        };
        if (!string.IsNullOrWhiteSpace(proxy))
        {
            // Same parsing and scheme inference as every other tool (HttpHelper); the message never echoes the address,
            // which may carry user:password@.
            if (!HttpHelper.TryParseProxy(proxy, out var proxyUri))
            {
                handler.Dispose();
                throw new ArgumentException("Invalid proxy address. Use host:port (e.g. 127.0.0.1:1080).");
            }
            var wp = new WebProxy(proxyUri);
            if (!string.IsNullOrWhiteSpace(proxyUser)) wp.Credentials = new NetworkCredential(proxyUser, proxyPass ?? string.Empty);
            handler.Proxy = wp;
            handler.UseProxy = true;
        }
        // No proxy given: the system proxy applies (SocketsHttpHandler's default), as with HttpHelper, and the API's name
        // goes around a resolver that blocks it (ServiceDns).
        else handler.ConnectCallback = ServiceDns.ConnectAsync;

        var http = new HttpClient(handler) { Timeout = Timeout };
        var ver = typeof(HetznerApi).Assembly.GetName().Version;
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"Echoes/{ver?.Major ?? 0}.{ver?.Minor ?? 0}.{ver?.Build ?? 0}");
        http.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", "Bearer " + token);

        var secrets = new List<string>();
        foreach (var s in new[] { token, proxyPass ?? string.Empty })
            if (s.Length >= 4) secrets.Add(s);
        return new HetznerApi(http, secrets.ToArray());
    }

    /// <summary>A token is one run of visible ASCII (Hetzner's are 64 letters and digits); anything else would break or
    /// split the header.</summary>
    public static bool IsTokenShape(string? token)
    {
        if (string.IsNullOrEmpty(token) || token.Length > 512) return false;
        foreach (char c in token)
            if (c <= ' ' || c >= 0x7F) return false;
        return true;
    }

    public void Dispose() => _http.Dispose();

    // ---------------------------------------------------------------- ids, names and paths

    /// <summary>Hetzner ids are positive integers up to 2^53 - 1.</summary>
    public static bool IsId(long id) => id is >= 1 and <= 9007199254740991;

    public static bool TryParseId(string? text, out long id)
        => long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out id) && IsId(id);

    public static string ServerPath(long id) => IsId(id) ? "/servers/" + Num(id) : throw new ArgumentException("Invalid server id.");
    public static string FirewallPath(long id) => IsId(id) ? "/firewalls/" + Num(id) : throw new ArgumentException("Invalid firewall id.");
    public static string ZonePath(long id) => IsId(id) ? "/zones/" + Num(id) : throw new ArgumentException("Invalid zone id.");

    /// <summary>/zones/{id}/rrsets/{name}/{TYPE}: the name and type are checked first (<see cref="IsRrName"/>,
    /// <see cref="IsRrType"/>).</summary>
    public static string RrsetPath(long zoneId, string name, string type)
    {
        if (!IsRrName(name)) throw new ArgumentException("Invalid record set name.");
        if (!IsRrType(type)) throw new ArgumentException("Invalid record type.");
        return ZonePath(zoneId) + "/rrsets/" + NameSegment(name) + "/" + type;
    }

    /// <summary>Where a running action of this kind is polled ("servers", "firewalls" or "zones").</summary>
    public static string ActionPath(string resource, long actionId)
        => resource is "servers" or "firewalls" or "zones" && IsId(actionId)
            ? "/" + resource + "/actions/" + Num(actionId)
            : throw new ArgumentException("Invalid action.");

    private static string Num(long id) => id.ToString(CultureInfo.InvariantCulture);

    /// <summary>The record types the Cloud API's DNS knows, in the order the UI lists them.</summary>
    public static readonly string[] RrTypes =
        { "A", "AAAA", "CNAME", "MX", "TXT", "NS", "CAA", "SRV", "HTTPS", "SVCB", "TLSA", "DS", "PTR", "HINFO", "RP", "SOA" };

    public static bool IsRrType(string? type) => type is not null && Array.IndexOf(RrTypes, type) >= 0;

    /// <summary>
    /// A record-set name as the API spells it: "@" for the zone apex, otherwise lower-case labels relative to the zone
    /// (no trailing dot, not ending in the zone's name). Letters, digits, '-' and '_'; a leftmost "*" label for a
    /// wildcard. Non-ASCII names must be given as punycode (xn--…).
    /// </summary>
    public static bool IsRrName(string? name)
    {
        if (string.IsNullOrEmpty(name) || name.Length > 253) return false;
        if (name == "@") return true;
        var labels = name.Split('.');
        for (int i = 0; i < labels.Length; i++)
        {
            string l = labels[i];
            if (l.Length is 0 or > 63) return false;
            if (l == "*") { if (i != 0) return false; continue; }
            foreach (char c in l)
                if (!(char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c is '-' or '_')) return false;
        }
        return true;
    }

    /// <summary>
    /// What a user typed for a record name, made into the API's relative name: trimmed, lower-case, without a trailing
    /// dot; empty or the zone's own name is "@"; "www.example.com" in example.com is "www". Null with a reason when it
    /// can't be one.
    /// </summary>
    public static string? NormalizeRrName(string? input, string zoneName, out string error)
    {
        error = string.Empty;
        string n = (input ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
        string zone = (zoneName ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
        if (n.Length == 0 || n == "@" || (zone.Length > 0 && n == zone)) return "@";
        if (zone.Length > 0 && n.EndsWith("." + zone, StringComparison.Ordinal)) n = n[..^(zone.Length + 1)];
        foreach (char c in n)
            if (c > 0x7F)
            {
                error = "Write a name with non-ASCII letters in its punycode form (xn--…).";
                return null;
            }
        if (!IsRrName(n))
        {
            error = "A name is made of letters, digits, '-' and '_' between dots (a leading * for a wildcard), or @ for the zone itself.";
            return null;
        }
        return n;
    }

    /// <summary>The name with the zone: "@" → "example.com", "www" → "www.example.com".</summary>
    public static string FullName(string rrName, string zoneName)
        => rrName == "@" || rrName.Length == 0 ? zoneName : rrName + "." + zoneName;

    // Validated names hold only [a-z0-9-_.*@]: '*' is the one that isn't plain in a path segment.
    private static string NameSegment(string name) => name.Replace("*", "%2A", StringComparison.Ordinal);

    /// <summary>A zone name: a domain of two or more labels, ASCII (punycode for IDNs), at most 255 characters.</summary>
    public static string? NormalizeZoneName(string? input, out string error)
    {
        error = string.Empty;
        string n = (input ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
        if (n.StartsWith("http://", StringComparison.Ordinal) || n.StartsWith("https://", StringComparison.Ordinal))
        {
            error = "Enter the domain only, like example.com.";
            return null;
        }
        var labels = n.Split('.');
        bool ok = n.Length is > 0 and <= 255 && labels.Length >= 2;
        foreach (var l in labels)
        {
            ok &= l.Length is > 0 and <= 63 && l[0] != '-' && l[^1] != '-';
            foreach (char c in l) ok &= char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c == '-';
        }
        if (!ok)
        {
            error = "Enter a domain like example.com (punycode xn--… for non-ASCII names).";
            return null;
        }
        return n;
    }

    internal static string Clip(string? s, int max)
    {
        s ??= string.Empty;
        // a control character in an answer would draw as garbage or break a line: shown as a space
        var sb = new StringBuilder(Math.Min(s.Length, max));
        foreach (char c in s)
        {
            if (sb.Length >= max) { sb.Append('…'); break; }
            sb.Append(char.IsControl(c) ? ' ' : c);
        }
        return sb.ToString();
    }

    // ---------------------------------------------------------------- requests

    public Task<HzResponse> GetAsync(string path, CancellationToken ct = default) => SendAsync(HttpMethod.Get, path, null, ct);
    public Task<HzResponse> PostAsync(string path, JsonNode? body, CancellationToken ct = default) => SendAsync(HttpMethod.Post, path, body ?? new JsonObject(), ct);
    public Task<HzResponse> PutAsync(string path, JsonNode body, CancellationToken ct = default) => SendAsync(HttpMethod.Put, path, body, ct);
    public Task<HzResponse> DeleteAsync(string path, CancellationToken ct = default) => SendAsync(HttpMethod.Delete, path, null, ct);

    /// <summary>
    /// One request. Never throws for network / HTTP / API failures (they come back as a failed <see cref="HzResponse"/>
    /// with a readable error); only an <see cref="OperationCanceledException"/> for <paramref name="ct"/> escapes.
    /// </summary>
    public async Task<HzResponse> SendAsync(HttpMethod method, string path, JsonNode? body, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(path) || path[0] != '/' || path.Contains("..", StringComparison.Ordinal) || path.Contains("//", StringComparison.Ordinal)
            || path.Contains('#') || path.Contains('\\'))
            return HzResponse.Fail("Invalid request.");
        string? json = body?.ToJsonString();
        for (int attempt = 1; ; attempt++)
        {
            var (result, retryAfter) = await SendOnceAsync(method, path, json, ct).ConfigureAwait(false);
            if (result.Status != 429 || attempt >= MaxAttempts || retryAfter is not { } wait) return result;
            await Task.Delay(wait, ct).ConfigureAwait(false);
        }
    }

    private async Task<(HzResponse Result, TimeSpan? RetryAfter)> SendOnceAsync(HttpMethod method, string path, string? json, CancellationToken ct)
    {
        // HttpClient.Timeout ends with the response headers (ResponseHeadersRead): this deadline covers the body too, and
        // each chunk that arrives re-arms it (ReadCappedAsync), so a large zone file on a slow link still completes.
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(Timeout);
        try
        {
            using var req = new HttpRequestMessage(method, BaseUrl + path);
            req.Headers.Accept.ParseAdd("application/json");
            if (json != null) req.Content = new StringContent(json, Encoding.UTF8, "application/json");

            using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
            string text = await ReadCappedAsync(resp.Content, deadline).ConfigureAwait(false);
            int status = (int)resp.StatusCode;
            var result = Interpret(status, text);
            return (result, status == 429 ? RetryWait(resp) : null);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { return (HzResponse.Fail($"Hetzner didn't answer within {Timeout.TotalSeconds:0} seconds."), null); }
        catch (HttpRequestException ex) { return (HzResponse.Fail("Couldn't reach Hetzner: " + Redact(Innermost(ex))), null); }
        catch (IOException ex) { return (HzResponse.Fail("Connection error: " + Redact(ex.Message)), null); }
        catch (ObjectDisposedException) { return (HzResponse.Fail("The request was cancelled."), null); }
        // a proxy scheme the handler can't use (socks5h://, ftp://) throws this from the send
        catch (NotSupportedException ex) { return (HzResponse.Fail("Couldn't reach Hetzner: " + Redact(ex.Message)), null); }
    }

    /// <summary>
    /// How long to wait before retrying a 429: Retry-After when given and short, else the time to RateLimit-Reset (a
    /// UNIX time) when that is short; otherwise a couple of seconds, since the project's allowance refills by about
    /// one request a second. Never negative (Task.Delay(-1 ms) would wait forever).
    /// </summary>
    internal static TimeSpan RetryWait(HttpResponseMessage resp)
    {
        var ra = resp.Headers.RetryAfter;
        TimeSpan? wait = ra?.Delta ?? (ra?.Date is { } at ? at - DateTimeOffset.UtcNow : null);
        if (wait is null && resp.Headers.TryGetValues("RateLimit-Reset", out var values))
            foreach (var v in values)
                if (long.TryParse(v.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out long unix))
                {
                    wait = DateTimeOffset.FromUnixTimeSeconds(Math.Min(unix, 253402300799)) - DateTimeOffset.UtcNow;
                    break;
                }
        if (wait is not { } w || w > MaxRetryWait) return RefillWait;
        return w < TimeSpan.Zero ? TimeSpan.Zero : w;
    }

    /// <summary>
    /// GET every page of a list endpoint (<c>per_page</c> / <c>page</c>, following <c>meta.pagination.next_page</c>) and
    /// collect the array named <paramref name="listKey"/> ("servers", "zones", "rrsets" …), up to <paramref name="maxPages"/>.
    /// </summary>
    public async Task<HzListResponse> GetAllAsync(string path, string listKey, CancellationToken ct = default, int perPage = 50, int maxPages = 100)
    {
        var items = new List<JsonNode>();
        char join = path.Contains('?') ? '&' : '?';
        int page = 1;
        bool more = false;
        perPage = Math.Clamp(perPage, 1, 50);
        while (true)
        {
            var r = await GetAsync($"{path}{join}per_page={perPage}&page={page}", ct).ConfigureAwait(false);
            if (!r.Success)
                return new HzListResponse { Status = r.Status, Error = r.Error, Code = r.Code, AuthFailed = r.AuthFailed, ReadOnly = r.ReadOnly };
            int got = 0;
            if (r.Body?[listKey] is JsonArray arr)
                foreach (var n in arr)
                    if (n != null) { items.Add(n); got++; }
            // the next page as the answer names it; an empty page is the end whatever it claims
            long? next = CfJson.Long(r.Body?["meta"]?["pagination"]?["next_page"]);
            more = got > 0 && next is { } np && np > page;
            if (!more) break;
            if (page >= maxPages) break;
            page = (int)Math.Min(next!.Value, int.MaxValue);
        }
        return new HzListResponse { Success = true, Status = 200, Items = items, Truncated = more };
    }

    /// <summary>
    /// Wait for an action to end, polling it under <paramref name="resource"/> ("servers", "firewalls", "zones") and
    /// reporting each state seen. Gives up after <paramref name="limit"/> (default 3 minutes) with
    /// <see cref="HzActionResult.StillRunning"/>. Only a cancellation of <paramref name="ct"/> throws.
    /// </summary>
    public async Task<HzActionResult> WaitActionAsync(string resource, HzAction action, Action<HzAction>? progress, CancellationToken ct,
                                                      TimeSpan? limit = null)
    {
        var until = DateTimeOffset.UtcNow + (limit ?? TimeSpan.FromMinutes(3));
        var current = action;
        progress?.Invoke(current);
        int failures = 0;
        while (current.IsRunning)
        {
            if (DateTimeOffset.UtcNow >= until)
                return new HzActionResult { StillRunning = true, Action = current, Error = "It is still running at Hetzner; check again in a moment." };
            await Task.Delay(PollInterval, ct).ConfigureAwait(false);
            var r = await GetAsync(ActionPath(resource, current.Id), ct).ConfigureAwait(false);
            if (!r.Success)
            {
                // a lost poll isn't a failed action: try a few more times before saying so
                if (++failures >= 3) return new HzActionResult { StillRunning = true, Action = current, Error = r.Error };
                continue;
            }
            failures = 0;
            if (HzAction.From(r.Body?["action"]) is { } next && next.Id == current.Id) current = next;
            progress?.Invoke(current);
        }
        if (current.IsSuccess) return new HzActionResult { Ok = true, Action = current };
        string why = current.ErrorMessage.Length > 0 ? current.ErrorMessage : "the action failed";
        if (current.ErrorCode.Length > 0) why += $" ({current.ErrorCode})";
        return new HzActionResult { Action = current, Error = Redact(why) };
    }

    // ---------------------------------------------------------------- responses + errors

    private HzResponse Interpret(int status, string text)
    {
        JsonNode? root = ParseAnswer(text, out bool unreadable);
        if (status is >= 200 and < 300)
        {
            if (unreadable) return HzResponse.Fail($"Hetzner's answer couldn't be read (HTTP {status}).", status);
            return new HzResponse { Success = true, Status = status, Body = root };
        }

        string code = Clip(CfJson.Str(root?["error"]?["code"]), 60);
        string msg = Clip(CfJson.Str(root?["error"]?["message"]), 300);
        string first = msg.Length > 0
            ? (code.Length > 0 ? $"{msg} ({code})" : msg)
            : unreadable ? $"Hetzner's answer couldn't be read (HTTP {status})"
            : status == 0 ? "no response" : $"request failed (HTTP {status})";
        string field = FieldErrors(root?["error"]?["details"]);
        if (field.Length > 0) first += ": " + field;

        bool auth = status == 401 || code == "unauthorized";
        // the spec lists "forbidden"; "token_readonly" is what read-only tokens were refused with before, kept in case
        bool readOnly = !auth && status == 403 && (code is "forbidden" or "token_readonly" || code.Length == 0);
        string? hint = auth ? "Hetzner doesn't accept this token. It may be mistyped, or deleted in the Console. Paste a new one (Edit)."
            : readOnly ? ReadWriteHint
            : status == 429 ? "The project's rate limit (3600 requests an hour) is used up for now. Try again in a minute."
            : code == "locked" ? "Another action is still running on it. Try again in a moment."
            : code == "protected" ? "It is protected. Turn the protection off in the Hetzner Console first."
            : code == "maintenance" ? "Hetzner is doing maintenance on it. Try again later."
            : null;
        string error = Redact(first);
        return new HzResponse
        {
            Status = status,
            Code = code,
            AuthFailed = auth,
            ReadOnly = readOnly,
            Error = hint is null ? error : error + " — " + hint,
        };
    }

    // invalid_input details: {"fields": [{"name": "records", "messages": ["…"]}]} → "records: …" (a few of them)
    private static string FieldErrors(JsonNode? details)
    {
        if (details?["fields"] is not JsonArray fields) return string.Empty;
        var parts = new List<string>();
        foreach (var f in fields)
        {
            string name = Clip(CfJson.Str(f?["name"]), 60);
            var msgs = CfJson.StrList(f?["messages"]);
            string m = msgs.Count > 0 ? Clip(string.Join(", ", msgs), 200) : string.Empty;
            if (name.Length > 0 || m.Length > 0) parts.Add(m.Length > 0 ? $"{name} {m}".Trim() : name);
            if (parts.Count == 3) break;
        }
        return string.Join("; ", parts);
    }

    /// <summary>Strip anything secret from a message bound for the UI: this client's token and proxy password, and any
    /// user:password@ in a URL.</summary>
    public string Redact(string? message)
    {
        string m = message ?? string.Empty;
        foreach (var s in _secrets) m = m.Replace(s, "•••", StringComparison.Ordinal);
        return CloudflareApi.RedactUserInfo(m);
    }

    private static string Innermost(Exception ex)
    {
        string msg = ex.Message;
        for (var e = ex.InnerException; e != null; e = e.InnerException)
            if (!string.IsNullOrWhiteSpace(e.Message)) msg = e.Message;
        return msg;
    }

    /// <summary>
    /// The answer as JSON with every part of it already readable (a repeated property name or a lone surrogate escape
    /// throws only when touched, which would escape this client's never-throws contract): the tree is walked once here,
    /// and such an answer is <paramref name="unreadable"/>. Null when the body is empty or not JSON.
    /// </summary>
    private static JsonNode? ParseAnswer(string text, out bool unreadable)
    {
        unreadable = false;
        if (!LooksLikeJson(text)) return null;
        try
        {
            var root = JsonNode.Parse(text, documentOptions: new JsonDocumentOptions { MaxDepth = 64 });
            Materialize(root);
            return root;
        }
        catch (JsonException) { unreadable = true; return null; }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            unreadable = true;
            return null;
        }
    }

    private static void Materialize(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject o:
                foreach (var p in o) Materialize(p.Value);
                break;
            case JsonArray a:
                foreach (var item in a) Materialize(item);
                break;
            case JsonValue v when v.GetValueKind() == JsonValueKind.String:
                v.GetValue<string>();
                break;
        }
    }

    private static bool LooksLikeJson(string text)
    {
        foreach (char c in text)
        {
            if (char.IsWhiteSpace(c) || c == '\uFEFF') continue;
            return c is '{' or '[';
        }
        return false;
    }

    // idle: cancelled when no data arrives for Timeout (re-armed per chunk), or with the caller's token.
    private static async Task<string> ReadCappedAsync(HttpContent content, CancellationTokenSource idle)
    {
        await using var s = await content.ReadAsStreamAsync(idle.Token).ConfigureAwait(false);
        using var ms = new MemoryStream();
        byte[] buf = new byte[16 * 1024];
        int n;
        while ((n = await s.ReadAsync(buf, idle.Token).ConfigureAwait(false)) > 0)
        {
            idle.CancelAfter(Timeout);
            if (ms.Length + n > MaxResponseBytes) throw new IOException("The response is too large.");
            ms.Write(buf, 0, n);
        }
        return Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);
    }
}
