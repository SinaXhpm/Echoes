using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>The token permission an API call needs. A permission failure is turned into a hint that names it.</summary>
public enum CfPermission
{
    None,
    /// <summary>Zone → Zone : Read (list zones, read one).</summary>
    ZoneRead,
    /// <summary>Zone → DNS : Edit (list, create, edit, delete and export records).</summary>
    DnsEdit,
    /// <summary>Zone → Zone Settings : Edit (read and change SSL/TLS, ECH, security, network and cache settings).</summary>
    ZoneSettingsEdit,
    /// <summary>Zone → Cache Purge : Purge.</summary>
    CachePurge,
    /// <summary>Zone → Zone : Edit (pause / resume Cloudflare on a zone).</summary>
    ZoneEdit,
    /// <summary>Zone → Analytics : Read (the GraphQL traffic summary).</summary>
    AnalyticsRead,
    /// <summary>Zone → Firewall Services : Edit (IP access rules of a zone).</summary>
    FirewallServices,
    /// <summary>Zone → Zone WAF : Edit (WAF custom rules, phase http_request_firewall_custom).</summary>
    ZoneWaf,
    /// <summary>Zone → Single Redirect : Edit (redirect rules, phase http_request_dynamic_redirect).</summary>
    SingleRedirect,
    /// <summary>Zone → Bot Management : Edit (Bot Fight Mode, AI bots).</summary>
    BotManagement,
    /// <summary>Zone → SSL and Certificates : Edit (edge certificates, Universal SSL).</summary>
    SslCertificates,
    /// <summary>Account → Account Settings : Read (list the accounts a new zone can go into).</summary>
    AccountRead,
    /// <summary>Zone → Zone : Edit on "All zones from an account" (add a zone).</summary>
    ZoneCreate,
}

/// <summary>The outcome of one Cloudflare API call. Never carries credentials.</summary>
public sealed class CfResponse
{
    public bool Success { get; init; }
    /// <summary>HTTP status; 0 when no response arrived (network error, timeout).</summary>
    public int Status { get; init; }
    public JsonNode? Result { get; init; }
    public JsonNode? ResultInfo { get; init; }
    /// <summary>Readable error ("message (code N); …" plus a permission hint). Empty on success.</summary>
    public string Error { get; init; } = string.Empty;
    /// <summary>Cloudflare refused the credentials or the permission (401 / 403 / an auth error code).</summary>
    public bool AuthFailed { get; init; }
    /// <summary>The refusal reads like a plan restriction ("not available on your plan", "upgrade", a quota…): the
    /// caller can say which plan the feature needs.</summary>
    public bool PlanLimited { get; init; }
    /// <summary>The credentials are fine but the token lacks the permission for this call (403 / 10000 / 9109…).</summary>
    public bool Denied { get; init; }
    /// <summary>The body as text (plain-text endpoints such as the BIND export).</summary>
    public string Text { get; init; } = string.Empty;
    public IReadOnlyList<int> Codes { get; init; } = Array.Empty<int>();

    internal static CfResponse Fail(string error, int status = 0) => new() { Error = error, Status = status };
}

/// <summary>A paginated list call: every page's <c>result</c> items, or the first failure.</summary>
public sealed class CfListResponse
{
    public bool Success { get; init; }
    public int Status { get; init; }
    public string Error { get; init; } = string.Empty;
    public bool AuthFailed { get; init; }
    public bool PlanLimited { get; init; }
    public bool Denied { get; init; }
    public List<JsonNode> Items { get; init; } = new();
    /// <summary>The list was cut at the page cap (it has more items than were read).</summary>
    public bool Truncated { get; init; }
}

/// <summary>
/// A small Cloudflare API v4 client: one profile's credentials (API token, or Global API key + email) and its proxy.
///
/// <para>Security: the credentials go out as request headers only; nothing here logs or echoes them, and every error
/// text that reaches the UI is passed through <see cref="Redact"/>. Redirects are NOT followed: a redirect would carry
/// the X-Auth-* headers (and on some stacks the bearer token) to whatever host it names. Zone and record ids are
/// checked (32 hex chars) before they go into a URL path, and the host is fixed (<see cref="BaseUrl"/>).</para>
///
/// <para>JSON is read with <see cref="JsonNode"/> / written with <see cref="JsonObject"/> (no reflection; AOT/trim-safe).</para>
/// </summary>
public sealed class CloudflareApi : IDisposable
{
    public const string DefaultBaseUrl = "https://api.cloudflare.com/client/v4";
    private const int MaxResponseBytes = 16 * 1024 * 1024;
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(25);
    // A 429 is retried after its Retry-After when that is short; a longer wait comes back as the error.
    private const int MaxAttempts = 3;
    private static readonly TimeSpan MaxRetryWait = TimeSpan.FromSeconds(60);

    private static string _baseUrl = DefaultBaseUrl;

    /// <summary>
    /// The API root. Test hook only (a local mock server stands in for the API): it accepts the real API or a LOOPBACK
    /// address, nothing else, so user data can never point the client — and the credentials it sends — at another host.
    /// Not bound to any UI or setting.
    /// </summary>
    internal static string BaseUrl
    {
        get => _baseUrl;
        set
        {
            string v = (value ?? string.Empty).TrimEnd('/');
            if (v == DefaultBaseUrl || IsLoopbackRoot(v)) _baseUrl = v;
            else throw new ArgumentException("The Cloudflare API root can only be the real API or a loopback test server.");
        }
    }

    private static bool IsLoopbackRoot(string url)
        => Uri.TryCreate(url, UriKind.Absolute, out var u)
           && (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps)
           && u.IsLoopback && string.IsNullOrEmpty(u.UserInfo) && string.IsNullOrEmpty(u.Query) && string.IsNullOrEmpty(u.Fragment);

    private readonly HttpClient _http;
    private readonly string[] _secrets;

    private CloudflareApi(HttpClient http, string[] secrets)
    {
        _http = http;
        _secrets = secrets;
    }

    /// <summary>
    /// Build a client for one set of credentials. Throws <see cref="ArgumentException"/> with a readable message (never
    /// containing a secret) when a credential or the proxy address is unusable.
    /// </summary>
    public static CloudflareApi Create(bool useToken, string? token, string? email, string? key,
                                       string? proxy, string? proxyUser, string? proxyPass)
    {
        token = token?.Trim() ?? string.Empty;
        email = email?.Trim() ?? string.Empty;
        key = key?.Trim() ?? string.Empty;
        if (useToken)
        {
            if (token.Length == 0) throw new ArgumentException("Enter an API token.");
            if (!IsHeaderSafe(token)) throw new ArgumentException("The API token contains spaces or line breaks. Paste it again.");
        }
        else
        {
            if (email.Length == 0 || key.Length == 0) throw new ArgumentException("Enter your account email and Global API key.");
            if (!IsHeaderSafe(email) || !IsHeaderSafe(key)) throw new ArgumentException("The email or Global API key contains spaces or line breaks.");
        }

        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,      // credentials must never follow a redirect to another host
            AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromSeconds(15),
            UseCookies = false,
        };
        if (!string.IsNullOrWhiteSpace(proxy))
        {
            // Same parsing / scheme inference as every other tool (HttpHelper); the message never echoes the address,
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
        // No proxy given: the system proxy applies (SocketsHttpHandler's default), as with HttpHelper.

        var http = new HttpClient(handler) { Timeout = Timeout };
        var ver = typeof(CloudflareApi).Assembly.GetName().Version;
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"Echoes/{ver?.Major ?? 0}.{ver?.Minor ?? 0}.{ver?.Build ?? 0}");
        if (useToken)
            http.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", "Bearer " + token);
        else
        {
            http.DefaultRequestHeaders.TryAddWithoutValidation("X-Auth-Email", email);
            http.DefaultRequestHeaders.TryAddWithoutValidation("X-Auth-Key", key);
        }

        var secrets = new List<string>();
        foreach (var s in new[] { token, key, proxyPass ?? string.Empty })
            if (s.Length >= 4) secrets.Add(s);
        return new CloudflareApi(http, secrets.ToArray());
    }

    private static bool IsHeaderSafe(string s)
    {
        foreach (char c in s)
            if (c <= ' ' || c == 0x7F) return false;   // whitespace / control chars would break (or split) the header
        return true;
    }

    public void Dispose() => _http.Dispose();

    // ---------------------------------------------------------------- ids and paths

    /// <summary>A Cloudflare object id: exactly 32 hex characters.</summary>
    public static bool IsId(string? s)
    {
        if (s is not { Length: 32 }) return false;
        foreach (char c in s)
            if (!char.IsAsciiHexDigit(c)) return false;
        return true;
    }

    public static string ZonePath(string zoneId)
        => IsId(zoneId) ? "/zones/" + zoneId.ToLowerInvariant() : throw new ArgumentException("Invalid zone id.");

    public static string RecordPath(string zoneId, string recordId)
        => IsId(recordId) ? ZonePath(zoneId) + "/dns_records/" + recordId.ToLowerInvariant() : throw new ArgumentException("Invalid record id.");

    /// <summary>Setting ids are lower-case words ("ssl", "0rtt", "always_use_https"); anything else is URL-encoded.</summary>
    public static string SettingPath(string zoneId, string settingId)
    {
        bool plain = settingId.Length is > 0 and <= 64;
        foreach (char c in settingId) plain &= char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c == '_';
        return ZonePath(zoneId) + "/settings/" + (plain ? settingId : Uri.EscapeDataString(settingId));
    }

    /// <summary>The rule phases this app reads and writes (a zone's custom WAF rules and its single redirects).</summary>
    public const string PhaseFirewallCustom = "http_request_firewall_custom";
    public const string PhaseRedirect = "http_request_dynamic_redirect";

    public static string EntrypointPath(string zoneId, string phase)
        => phase is PhaseFirewallCustom or PhaseRedirect
            ? ZonePath(zoneId) + "/rulesets/phases/" + phase + "/entrypoint"
            : throw new ArgumentException("Unsupported ruleset phase.");

    public static string RulesetPath(string zoneId, string rulesetId)
        => IsId(rulesetId) ? ZonePath(zoneId) + "/rulesets/" + rulesetId.ToLowerInvariant() : throw new ArgumentException("Invalid ruleset id.");

    public static string RulePath(string zoneId, string rulesetId, string ruleId)
        => IsId(ruleId) ? RulesetPath(zoneId, rulesetId) + "/rules/" + ruleId.ToLowerInvariant() : throw new ArgumentException("Invalid rule id.");

    public static string AccessRulePath(string zoneId, string ruleId)
        => IsId(ruleId) ? ZonePath(zoneId) + "/firewall/access_rules/rules/" + ruleId.ToLowerInvariant() : throw new ArgumentException("Invalid rule id.");

    // ---------------------------------------------------------------- requests

    public Task<CfResponse> GetAsync(string path, CfPermission perm, CancellationToken ct = default)
        => SendAsync(HttpMethod.Get, path, null, perm, ct);

    public Task<CfResponse> PostAsync(string path, JsonNode body, CfPermission perm, CancellationToken ct = default)
        => SendAsync(HttpMethod.Post, path, body, perm, ct);

    public Task<CfResponse> PatchAsync(string path, JsonNode body, CfPermission perm, CancellationToken ct = default)
        => SendAsync(HttpMethod.Patch, path, body, perm, ct);

    public Task<CfResponse> PutAsync(string path, JsonNode body, CfPermission perm, CancellationToken ct = default)
        => SendAsync(HttpMethod.Put, path, body, perm, ct);

    public Task<CfResponse> DeleteAsync(string path, CfPermission perm, CancellationToken ct = default)
        => SendAsync(HttpMethod.Delete, path, null, perm, ct);

    /// <summary>A plain-text endpoint (the BIND zone export). On success <see cref="CfResponse.Text"/> holds the body.</summary>
    public Task<CfResponse> GetTextAsync(string path, CfPermission perm, CancellationToken ct = default)
        => SendAsync(HttpMethod.Get, path, null, perm, ct, plainText: true);

    /// <summary>
    /// A multipart/form-data POST (the BIND zone import): one file part plus plain text fields. The parts are rebuilt for
    /// every attempt (a 429 retry), since a sent request disposes its content.
    /// </summary>
    public Task<CfResponse> PostFileAsync(string path, string fileField, string fileName, byte[] file,
                                          IReadOnlyList<(string Name, string Value)> fields, CfPermission perm, CancellationToken ct = default)
        => SendCoreAsync(HttpMethod.Post, path, () =>
        {
            var form = new MultipartFormDataContent();
            var part = new ByteArrayContent(file);
            part.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("text/plain");
            form.Add(part, fileField, fileName);
            foreach (var (name, value) in fields) form.Add(new StringContent(value, Encoding.UTF8), name);
            return form;
        }, perm, plainText: false, graphQL: false, ct);

    /// <summary>
    /// A GraphQL Analytics query (POST /graphql, {"query": …}). Its answer is {"data", "errors"} rather than the v4
    /// envelope: on success <see cref="CfResponse.Result"/> holds "data"; a failure carries the first messages, with the
    /// permission hint when the token may not read analytics, or <see cref="CfResponse.PlanLimited"/> when the zone's
    /// plan doesn't include the data asked for.
    /// </summary>
    public Task<CfResponse> GraphQLAsync(string query, CfPermission perm, CancellationToken ct = default)
    {
        var body = new JsonObject { ["query"] = query };
        return SendCoreAsync(HttpMethod.Post, "/graphql",
            () => new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"), perm, plainText: false, graphQL: true, ct);
    }

    /// <summary>
    /// One request. Never throws for network / HTTP / API failures (they come back as a failed <see cref="CfResponse"/>
    /// with a readable error); only an <see cref="OperationCanceledException"/> for <paramref name="ct"/> escapes.
    /// </summary>
    public Task<CfResponse> SendAsync(HttpMethod method, string path, JsonNode? body, CfPermission perm,
                                      CancellationToken ct = default, bool plainText = false)
    {
        string? json = body?.ToJsonString();
        return SendCoreAsync(method, path, json is null ? null : () => new StringContent(json, Encoding.UTF8, "application/json"),
                             perm, plainText, graphQL: false, ct);
    }

    private async Task<CfResponse> SendCoreAsync(HttpMethod method, string path, Func<HttpContent>? content, CfPermission perm,
                                                 bool plainText, bool graphQL, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(path) || path[0] != '/' || path.Contains("..", StringComparison.Ordinal) || path.Contains("//", StringComparison.Ordinal))
            return CfResponse.Fail("Invalid request.");

        // Rate limited (429; 1200 requests per 5 minutes per user): the request wasn't processed, and Retry-After says
        // when capacity is back. Without waiting for it, a restore or a long list failed every request left in the window.
        for (int attempt = 1; ; attempt++)
        {
            var (result, retryAfter) = await SendOnceAsync(method, path, content, perm, plainText, graphQL, ct).ConfigureAwait(false);
            if (result.Status != 429 || attempt >= MaxAttempts || retryAfter is not { } wait || wait > MaxRetryWait) return result;
            await Task.Delay(wait, ct).ConfigureAwait(false);
        }
    }

    private async Task<(CfResponse Result, TimeSpan? RetryAfter)> SendOnceAsync(HttpMethod method, string path, Func<HttpContent>? content,
                                                                               CfPermission perm, bool plainText, bool graphQL, CancellationToken ct)
    {
        // HttpClient.Timeout ends with the response headers (ResponseHeadersRead): a body that stalled after them hung the
        // call — and the zone / record load waiting on it — until a lock. This deadline covers the body too; each chunk
        // that arrives re-arms it (ReadCappedAsync), so a large export on a slow link still completes.
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(Timeout);
        try
        {
            using var req = new HttpRequestMessage(method, BaseUrl + path);
            req.Headers.Accept.ParseAdd(plainText ? "text/plain, application/json" : "application/json");
            if (content != null) req.Content = content();

            using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
            string text = await ReadCappedAsync(resp.Content, deadline).ConfigureAwait(false);
            int status = (int)resp.StatusCode;

            if (plainText && resp.IsSuccessStatusCode && !LooksLikeJson(text))
                return (new CfResponse { Success = true, Status = status, Text = text }, null);
            var result = graphQL ? InterpretGraphQL(status, text, perm) : Interpret(status, text, perm);
            return (result, status == 429 ? RetryAfter(resp) : null);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { return (CfResponse.Fail($"Cloudflare didn't answer within {Timeout.TotalSeconds:0} seconds."), null); }
        catch (HttpRequestException ex) { return (CfResponse.Fail("Couldn't reach Cloudflare: " + Redact(Innermost(ex))), null); }
        catch (IOException ex) { return (CfResponse.Fail("Connection error: " + Redact(ex.Message)), null); }
        catch (ObjectDisposedException) { return (CfResponse.Fail("The request was cancelled."), null); }
        // A proxy scheme the handler can't use (socks5h://, the curl spelling of SOCKS5; ftp://…) throws this from the
        // send: it escaped every caller (a settings row stayed "Saving…" for good, a zone load ended with no error shown).
        catch (NotSupportedException ex) { return (CfResponse.Fail("Couldn't reach Cloudflare: " + Redact(ex.Message)), null); }
    }

    // Retry-After as a wait (delta-seconds or an HTTP date); never negative: Task.Delay(-1 ms) would wait forever.
    private static TimeSpan? RetryAfter(HttpResponseMessage resp)
    {
        var ra = resp.Headers.RetryAfter;
        TimeSpan? wait = ra?.Delta ?? (ra?.Date is { } at ? at - DateTimeOffset.UtcNow : null);
        return wait < TimeSpan.Zero ? TimeSpan.Zero : wait;
    }

    /// <summary>
    /// GET every page of a list endpoint (<c>per_page</c> / <c>page</c>, following <c>result_info.total_pages</c>), up to
    /// <paramref name="maxPages"/>.
    /// </summary>
    public async Task<CfListResponse> GetAllAsync(string path, int perPage, CfPermission perm,
                                                  CancellationToken ct = default, int maxPages = 200)
    {
        var items = new List<JsonNode>();
        int page = 1, totalPages = 1;
        char join = path.Contains('?') ? '&' : '?';
        do
        {
            var r = await GetAsync($"{path}{join}per_page={perPage}&page={page}", perm, ct).ConfigureAwait(false);
            if (!r.Success)
                return new CfListResponse { Status = r.Status, Error = r.Error, AuthFailed = r.AuthFailed, PlanLimited = r.PlanLimited, Denied = r.Denied };
            int got = 0;
            if (r.Result is JsonArray arr)
                foreach (var n in arr)
                    if (n != null) { items.Add(n); got++; }
            // An empty page is the end, whatever result_info claims: a total_pages that overstates (or a broken answer)
            // used to walk all maxPages requests for nothing, a sixth of the 5-minute rate limit per list.
            if (got == 0) { totalPages = page - 1; break; }
            totalPages = TotalPages(r.ResultInfo, got, page);
            page++;
        } while (page <= totalPages && page <= maxPages);

        return new CfListResponse { Success = true, Status = 200, Items = items, Truncated = totalPages > maxPages };
    }

    // result_info.total_pages when given; some lists (IP access rules, accounts) only report total_count, so the page
    // count comes from it and per_page; with neither, a full page means there may be another one.
    private static int TotalPages(JsonNode? info, int got, int page)
    {
        if (CfJson.Int(info?["total_pages"]) is int tp) return tp;
        int perPage = CfJson.Int(info?["per_page"]) ?? 0;
        if (CfJson.Int(info?["total_count"]) is int total && perPage > 0) return (total + perPage - 1) / perPage;
        return perPage > 0 && got >= perPage ? page + 1 : page;
    }

    // ---------------------------------------------------------------- responses + errors

    private CfResponse Interpret(int status, string text, CfPermission perm)
        => Interpret(status, ParseAnswer(text, out bool unreadable), unreadable, perm);

    private CfResponse Interpret(int status, JsonNode? root, bool unreadable, CfPermission perm)
    {
        bool ok = root is JsonObject o && o["success"]?.GetValueKind() == JsonValueKind.True && status is >= 200 and < 300;
        if (ok)
            return new CfResponse { Success = true, Status = status, Result = root!["result"], ResultInfo = root["result_info"] };

        var codes = ErrorCodes(root);
        string first = root is null
            ? (unreadable ? $"Cloudflare's answer couldn't be read (HTTP {status})"
               : status == 0 ? "no response" : $"request failed (HTTP {status})")
            : FirstError(root);
        string message = Redact(first);
        bool badCredentials = status == 401
                              || codes.Exists(c => c is 1000 or 6003 or 6103 or 6111 or 9103 or 9106)
                              || message.Contains("Invalid access token", StringComparison.OrdinalIgnoreCase)
                              || message.Contains("Invalid API Token", StringComparison.OrdinalIgnoreCase);
        bool plan = !badCredentials && LooksPlanLimited(message);
        // A plan refusal can come as a 403 too: it isn't a missing permission, so it gets no permission hint.
        bool denied = !plan && (status == 403 || codes.Exists(c => c is 9109 or 10000 or (>= 10001 and <= 10019)));

        string? hint = badCredentials
            ? "Cloudflare rejected these credentials: check the API token (or the email and Global API key)."
            : denied && perm != CfPermission.None
                ? PermissionHint(perm)
                : null;
        return new CfResponse
        {
            Status = status,
            Codes = codes,
            AuthFailed = badCredentials || denied,
            Denied = denied && !badCredentials,
            PlanLimited = plan,
            Error = hint is null ? message : message + " — " + hint,
        };
    }

    /// <summary>"the token needs the Zone → X : Edit permission for this zone." (account-level ones say so).</summary>
    public static string PermissionHint(CfPermission perm) => perm switch
    {
        CfPermission.AccountRead => $"the token needs the {PermissionText(perm)} permission.",
        CfPermission.ZoneCreate => "the token needs the Zone → Zone : Edit permission with Zone Resources set to All zones from an account.",
        _ => $"the token needs the {PermissionText(perm)} permission for this zone.",
    };

    /// <summary>Cloudflare's wording for "your plan doesn't include this" (settings, rule quotas, operators, datasets).</summary>
    public static bool LooksPlanLimited(string message)
    {
        string m = message.ToLowerInvariant();
        if (m.Contains("not entitled") || m.Contains("entitlement") || m.Contains("upgrade your plan") || m.Contains("upgrade to")
            || m.Contains("does not have access to the path") || m.Contains("exceeded maximum number of rules")
            || m.Contains("exceeds the maximum number of rules") || m.Contains("quota"))
            return true;
        return m.Contains("plan") && (m.Contains("not available") || m.Contains("not allowed") || m.Contains("not supported")
                                      || m.Contains("requires") || m.Contains("only available") || m.Contains("upgrade")
                                      || m.Contains("not enabled") || m.Contains("limit"));
    }

    // GraphQL answers {"data": …, "errors": [{"message", "path", "extensions"}]} (with an HTTP status that may still be
    // 200). A gateway refusal (bad token) can come in the v4 envelope instead: that one goes through Interpret.
    private CfResponse InterpretGraphQL(int status, string text, CfPermission perm)
    {
        JsonNode? root = ParseAnswer(text, out bool unreadable);
        if (root is JsonObject env && env.ContainsKey("success")) return Interpret(status, root, unreadable, perm);

        var errors = root?["errors"] as JsonArray;
        bool ok = status is >= 200 and < 300 && root?["data"] is JsonObject && (errors is null || errors.Count == 0);
        if (ok) return new CfResponse { Success = true, Status = status, Result = root!["data"] };

        string message = Redact(errors is { Count: > 0 } ? FirstError(root)
                                : unreadable ? $"Cloudflare's answer couldn't be read (HTTP {status})"
                                : status == 0 ? "no response" : $"request failed (HTTP {status})");
        string lower = message.ToLowerInvariant();
        bool badCredentials = status == 401 || (lower.Contains("unauthorized") && !lower.Contains("not authorized"));
        bool plan = !badCredentials && LooksPlanLimited(message);
        bool denied = !badCredentials && !plan && (status == 403 || lower.Contains("not authorized") || lower.Contains("are not authorized"));
        string? hint = badCredentials
            ? "Cloudflare rejected these credentials: check the API token (or the email and Global API key)."
            : denied ? PermissionHint(perm) : null;
        return new CfResponse
        {
            Status = status,
            AuthFailed = badCredentials || denied,
            Denied = denied,
            PlanLimited = plan,
            Error = hint is null ? message : message + " — " + hint,
        };
    }

    /// <summary>Cloudflare's "errors": "message (code N)" joined with "; ", or "request failed".</summary>
    public static string FirstError(JsonNode? root)
    {
        if (root is JsonObject o && o["errors"] is JsonArray errs && errs.Count > 0)
        {
            var msgs = new List<string>();
            foreach (var e in errs)
            {
                if (e is not JsonObject eo) continue;
                string msg = CfJson.Str(eo["message"]);
                int code = CfJson.Int(eo["code"]) ?? 0;
                if (msg.Length > 300) msg = msg[..300] + "…";
                if (!string.IsNullOrWhiteSpace(msg)) msgs.Add(code != 0 ? $"{msg} (code {code})" : msg);
                if (msgs.Count == 4) break;
            }
            if (msgs.Count > 0) return string.Join("; ", msgs);
        }
        return "request failed";
    }

    private static List<int> ErrorCodes(JsonNode? root)
    {
        var list = new List<int>();
        if (root is JsonObject o && o["errors"] is JsonArray errs)
            foreach (var e in errs)
                if (e is JsonObject eo && CfJson.Int(eo["code"]) is int c) list.Add(c);
        return list;
    }

    public static string PermissionText(CfPermission p) => p switch
    {
        CfPermission.ZoneRead => "Zone → Zone : Read",
        CfPermission.DnsEdit => "Zone → DNS : Edit",
        CfPermission.ZoneSettingsEdit => "Zone → Zone Settings : Edit",
        CfPermission.CachePurge => "Zone → Cache Purge : Purge",
        CfPermission.ZoneEdit => "Zone → Zone : Edit",
        CfPermission.AnalyticsRead => "Zone → Analytics : Read",
        CfPermission.FirewallServices => "Zone → Firewall Services : Edit",
        CfPermission.ZoneWaf => "Zone → Zone WAF : Edit",
        CfPermission.SingleRedirect => "Zone → Single Redirect : Edit",
        CfPermission.BotManagement => "Zone → Bot Management : Edit",
        CfPermission.SslCertificates => "Zone → SSL and Certificates : Edit",
        CfPermission.AccountRead => "Account → Account Settings : Read",
        CfPermission.ZoneCreate => "Zone → Zone : Edit (All zones from an account)",
        _ => "required",
    };

    /// <summary>Strip anything secret from a message bound for the UI: this client's token / key / proxy password, and
    /// any user:password@ in a URL.</summary>
    public string Redact(string? message)
    {
        string m = message ?? string.Empty;
        foreach (var s in _secrets) m = m.Replace(s, "•••", StringComparison.Ordinal);
        return RedactUserInfo(m);
    }

    internal static string RedactUserInfo(string m)
    {
        int at = m.IndexOf("://", StringComparison.Ordinal);
        while (at >= 0)
        {
            int start = at + 3, end = start;
            while (end < m.Length && m[end] is not ('/' or ' ' or '\'' or '"' or ')' or '\n')) end++;
            int userInfo = m.IndexOf('@', start, end - start);
            if (userInfo > start) m = m[..start] + "•••" + m[userInfo..];
            at = m.IndexOf("://", start, StringComparison.Ordinal);
        }
        return m;
    }

    private static string Innermost(Exception ex)
    {
        string msg = ex.Message;
        for (var e = ex.InnerException; e != null; e = e.InnerException)
            if (!string.IsNullOrWhiteSpace(e.Message)) msg = e.Message;
        return msg;
    }

    /// <summary>
    /// The answer as JSON with every part of it already readable; null when it isn't JSON. JsonNode builds objects and
    /// decodes strings lazily: an answer with a repeated property name or a lone surrogate escape ("\ud800") parsed fine,
    /// then threw ArgumentException / InvalidOperationException out of whichever reader touched that node first — past
    /// this client's never-throws contract, into the crash log, with the caller's busy flag left on (a setting row stuck
    /// disabled, "Loading zones…" for good). The tree is walked once here instead (the body is capped at 16 MB and the
    /// depth at 64), and such an answer is <paramref name="unreadable"/>: a failed response.
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
        catch (JsonException) { return null; }
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
                // enumerating builds the property table: a repeated or undecodable property name throws here
                foreach (var p in o) Materialize(p.Value);
                break;
            case JsonArray a:
                foreach (var item in a) Materialize(item);
                break;
            case JsonValue v when v.GetValueKind() == JsonValueKind.String:
                v.GetValue<string>();   // a lone surrogate escape throws here
                break;
        }
    }

    private static bool LooksLikeJson(string text)
    {
        foreach (char c in text)
        {
            if (char.IsWhiteSpace(c) || c == '﻿') continue;
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

/// <summary>Null-safe, type-checked readers for <see cref="JsonNode"/> values (a wrong type reads as missing, never throws).</summary>
public static class CfJson
{
    public static string Str(JsonNode? n)
        => n is JsonValue v && v.GetValueKind() == JsonValueKind.String ? v.GetValue<string>() : string.Empty;

    public static string? StrOrNull(JsonNode? n)
        => n is JsonValue v && v.GetValueKind() == JsonValueKind.String ? v.GetValue<string>() : null;

    public static int? Int(JsonNode? n)
    {
        if (n is not JsonValue v || v.GetValueKind() != JsonValueKind.Number) return null;
        if (v.TryGetValue(out int i)) return i;
        if (v.TryGetValue(out long l)) return l is >= int.MinValue and <= int.MaxValue ? (int)l : null;
        if (v.TryGetValue(out double d) && d is >= int.MinValue and <= int.MaxValue && Math.Abs(d % 1) < double.Epsilon) return (int)d;
        return null;
    }

    /// <summary>A number that may exceed int (byte counts), truncated to a whole one; a non-number or an out-of-range
    /// value reads as missing.</summary>
    public static long? Long(JsonNode? n)
    {
        if (n is not JsonValue v || v.GetValueKind() != JsonValueKind.Number) return null;
        if (v.TryGetValue(out long l)) return l;
        if (v.TryGetValue(out int i)) return i;
        if (v.TryGetValue(out double d) && double.IsFinite(d) && d is >= long.MinValue and <= long.MaxValue) return (long)d;
        return null;
    }

    public static bool Bool(JsonNode? n) => n?.GetValueKind() == JsonValueKind.True;

    public static bool? BoolOrNull(JsonNode? n) => n?.GetValueKind() switch
    {
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        _ => null,
    };

    /// <summary>A setting value as text: strings as-is, numbers in invariant form, booleans as on/off.</summary>
    public static string ValueText(JsonNode? n) => n?.GetValueKind() switch
    {
        JsonValueKind.String => n.GetValue<string>(),
        JsonValueKind.Number => Int(n)?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? n.ToJsonString(),
        JsonValueKind.True => "on",
        JsonValueKind.False => "off",
        _ => string.Empty,
    };

    public static List<string> StrList(JsonNode? n)
    {
        var list = new List<string>();
        if (n is JsonArray a)
            foreach (var e in a)
                if (StrOrNull(e) is { } s) list.Add(s);
        return list;
    }
}
