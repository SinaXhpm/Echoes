using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>How a Bot API call ended.</summary>
public enum TgOutcome
{
    /// <summary>"ok": true.</summary>
    Ok,
    /// <summary>Telegram answered "ok": false with an error_code and description.</summary>
    ApiError,
    /// <summary>An HTTP status without Telegram's JSON (a proxy / gateway page, a redirect).</summary>
    HttpError,
    /// <summary>No response: DNS, TLS, proxy or connection failure.</summary>
    NetworkError,
    /// <summary>No response within the deadline.</summary>
    Timeout,
    /// <summary>Stopped by the user.</summary>
    Cancelled,
    /// <summary>Refused locally: a file over the upload limit, a response over the size cap, a bad method name.</summary>
    Refused,
}

/// <summary>A local file to send as multipart/form-data. Opened only when the request is sent.</summary>
public sealed class TgUpload
{
    public TgUpload(string fileName, long? length, Func<CancellationToken, Task<Stream>> open)
    {
        FileName = string.IsNullOrWhiteSpace(fileName) ? "file" : fileName;
        Length = length;
        Open = open;
    }

    public string FileName { get; }
    /// <summary>Size in bytes when the platform reports it.</summary>
    public long? Length { get; }
    public Func<CancellationToken, Task<Stream>> Open { get; }

    public string SizeText => Length is long l ? TelegramApi.FormatBytes(l) : "size unknown";
}

/// <summary>One Bot API request: a JSON body, or multipart fields + files. Never carries the token.</summary>
public sealed class TgRequest
{
    public TgRequest(string method) => Method = method;

    public string Method { get; }
    /// <summary>application/json body; null = none (or multipart when <see cref="Files"/> has entries).</summary>
    public string? JsonBody { get; set; }
    /// <summary>multipart/form-data text parts (used when <see cref="Files"/> is not empty).</summary>
    public List<KeyValuePair<string, string>> Fields { get; } = new();
    /// <summary>multipart/form-data file parts: parameter name → file.</summary>
    public List<KeyValuePair<string, TgUpload>> Files { get; } = new();

    public bool IsMultipart => Files.Count > 0;
}

/// <summary>The outcome of one call. Every text in it has been redacted (no token, no proxy password).</summary>
public sealed class TgCallResult
{
    public TgOutcome Outcome { get; init; }
    public bool Ok => Outcome == TgOutcome.Ok;
    /// <summary>HTTP status; 0 when no response arrived.</summary>
    public int HttpStatus { get; init; }
    /// <summary>Telegram's error_code (0 when there is none).</summary>
    public int ErrorCode { get; init; }
    /// <summary>Telegram's description, or a plain-words reason for a local / network failure.</summary>
    public string Description { get; init; } = string.Empty;
    /// <summary>parameters.retry_after (seconds) on a 429.</summary>
    public int? RetryAfter { get; init; }
    /// <summary>parameters.migrate_to_chat_id when a group became a supergroup.</summary>
    public long? MigrateToChatId { get; init; }
    /// <summary>The response body (redacted, at most <see cref="TelegramApi.MaxResponseBytes"/>).</summary>
    public string Body { get; init; } = string.Empty;
    public long Bytes { get; init; }
    public TimeSpan Elapsed { get; init; }
    /// <summary>The body parsed (Telegram's envelope), when it was JSON. Callers dispose it.</summary>
    public JsonDocument? Json { get; init; }

    internal static TgCallResult Fail(TgOutcome outcome, string description, TimeSpan elapsed = default)
        => new() { Outcome = outcome, Description = description, Elapsed = elapsed };
}

/// <summary>
/// A small Telegram Bot API client for one bot token (and an optional proxy).
///
/// <para>Security: the token only ever goes into the request path to the fixed API host (<see cref="BaseUrl"/>), it is
/// checked against the token format first (digits, a colon, then [A-Za-z0-9_-]) so it can't change the path, and the
/// method name is checked the same way. Redirects are NOT followed (the token is in the URL). Every text bound for the
/// UI — errors and bodies — goes through <see cref="Redact"/>. Responses are capped at <see cref="MaxResponseBytes"/>,
/// uploads at <see cref="MaxUploadBytes"/>, and every call has an idle deadline that covers the body too.</para>
///
/// <para>JSON is read with <see cref="JsonDocument"/> and written with <see cref="Utf8JsonWriter"/> (no reflection;
/// AOT / trim safe).</para>
/// </summary>
public sealed class TelegramApi : IDisposable
{
    public const string DefaultBaseUrl = "https://api.telegram.org";
    /// <summary>What the UI shows for the host (the token is shown as •••).</summary>
    public const string DisplayHost = "api.telegram.org";
    public const int MaxResponseBytes = 8 * 1024 * 1024;
    /// <summary>The Bot API's upload limit for multipart files (photos: 10 MB).</summary>
    public const long MaxUploadBytes = 50L * 1024 * 1024;
    /// <summary>The Bot API's download limit for getFile.</summary>
    public const long MaxDownloadBytes = 20L * 1024 * 1024;
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan MaxTimeout = TimeSpan.FromSeconds(120);

    private static string _baseUrl = DefaultBaseUrl;

    /// <summary>
    /// The API root. Test hook only (a local mock server stands in for Telegram): it accepts the real API or a LOOPBACK
    /// address, nothing else, so no input can ever point the client, and the token in its URLs, at another host. Not
    /// bound to any UI or setting.
    /// </summary>
    internal static string BaseUrl
    {
        get => _baseUrl;
        set
        {
            string v = (value ?? string.Empty).TrimEnd('/');
            if (v == DefaultBaseUrl || IsLoopbackRoot(v)) _baseUrl = v;
            else throw new ArgumentException("The Telegram API root can only be the real API or a loopback test server.");
        }
    }

    private static bool IsLoopbackRoot(string url)
        => Uri.TryCreate(url, UriKind.Absolute, out var u)
           && (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps)
           && u.IsLoopback && string.IsNullOrEmpty(u.UserInfo) && u.AbsolutePath == "/"
           && string.IsNullOrEmpty(u.Query) && string.IsNullOrEmpty(u.Fragment);

    private static readonly Regex TokenRx = new(@"^[0-9]{3,20}:[A-Za-z0-9_-]{20,128}$", RegexOptions.CultureInvariant);
    private static readonly Regex MethodRx = new(@"^[A-Za-z][A-Za-z0-9_]{0,63}$", RegexOptions.CultureInvariant);
    // Anything token-shaped in a text (the URL form "bot<token>" included).
    private static readonly Regex TokenLikeRx = new(@"[0-9]{3,20}:[A-Za-z0-9_-]{20,128}", RegexOptions.CultureInvariant);

    private readonly HttpClient _http;
    private readonly string _token;
    private readonly string[] _secrets;

    private TelegramApi(HttpClient http, string token, string[] secrets)
    {
        _http = http;
        _token = token;
        _secrets = secrets;
    }

    /// <summary>A bot token: the bot's id, a colon and the secret part ([A-Za-z0-9_-]).</summary>
    public static bool IsTokenFormat(string? token) => token is { Length: <= 160 } && TokenRx.IsMatch(token);

    /// <summary>A Bot API method name: a letter, then letters, digits or underscores (no '/', '?', '%'…).</summary>
    public static bool IsMethodName(string? name) => name is not null && MethodRx.IsMatch(name);

    /// <summary>The bot's id (the part before the colon) — not secret; null when the text isn't token-shaped.</summary>
    public static string? BotIdOf(string? token)
    {
        if (string.IsNullOrEmpty(token)) return null;
        int colon = token.IndexOf(':');
        if (colon <= 0) return null;
        for (int i = 0; i < colon; i++) if (!char.IsAsciiDigit(token[i])) return null;
        return token[..colon];
    }

    /// <summary>The endpoint as the UI shows it: the token is never displayed.</summary>
    public static string DisplayEndpoint(string method) => $"{DisplayHost}/bot•••/{method}";

    /// <summary>
    /// A client for one token. Throws <see cref="ArgumentException"/> with a readable message (never containing the token
    /// or the proxy address, which may carry a password) when the token or the proxy is unusable.
    /// </summary>
    public static TelegramApi Create(string? token, string? proxy, string? proxyUser, string? proxyPass)
    {
        token = token?.Trim() ?? string.Empty;
        if (token.Length == 0) throw new ArgumentException("Paste your bot token first.");
        if (!IsTokenFormat(token)) throw new ArgumentException("That doesn't look like a bot token. It looks like 123456789:AAH… (from @BotFather).");

        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,      // the token is in the URL: never replay it to whatever host a redirect names
            AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromSeconds(15),
            UseCookies = false,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        };
        if (!string.IsNullOrWhiteSpace(proxy))
        {
            if (!HttpHelper.TryParseProxy(proxy, out var proxyUri))
            {
                handler.Dispose();
                throw new ArgumentException("Invalid proxy address. Use host:port, e.g. 127.0.0.1:1080 or socks5://127.0.0.1:1080.");
            }
            // user:password@ typed in the address: WebProxy ignores it, so it becomes the credentials (the fields win).
            if (proxyUri.UserInfo.Length > 0)
            {
                string[] ui = proxyUri.UserInfo.Split(':', 2);
                if (string.IsNullOrWhiteSpace(proxyUser))
                {
                    proxyUser = Uri.UnescapeDataString(ui[0]);
                    proxyPass = ui.Length > 1 ? Uri.UnescapeDataString(ui[1]) : string.Empty;
                }
                proxyUri = new UriBuilder(proxyUri) { UserName = string.Empty, Password = string.Empty }.Uri;
            }
            var wp = new WebProxy(proxyUri);
            if (!string.IsNullOrWhiteSpace(proxyUser)) wp.Credentials = new NetworkCredential(proxyUser, proxyPass ?? string.Empty);
            handler.Proxy = wp;
            handler.UseProxy = true;
        }
        // No proxy given: the system proxy applies (SocketsHttpHandler's default), as with HttpHelper.

        // The per-call deadline (re-armed while bytes move) replaces HttpClient.Timeout, which would cut a slow upload.
        var http = new HttpClient(handler) { Timeout = System.Threading.Timeout.InfiniteTimeSpan };
        var ver = typeof(TelegramApi).Assembly.GetName().Version;
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"Echoes/{ver?.Major ?? 0}.{ver?.Minor ?? 0}.{ver?.Build ?? 0}");

        var secrets = new List<string> { token };
        if (!string.IsNullOrEmpty(proxyPass) && proxyPass.Length >= 3) secrets.Add(proxyPass);
        return new TelegramApi(http, token, secrets.ToArray());
    }

    public void Dispose() => _http.Dispose();

    // ---------------------------------------------------------------- calls

    /// <summary>
    /// One Bot API call. Never throws: network, HTTP, API and local failures come back as a <see cref="TgCallResult"/>
    /// with a readable, redacted description (a cancellation through <paramref name="ct"/> is <see cref="TgOutcome.Cancelled"/>).
    /// <paramref name="idleTimeout"/> is how long the call may go without progress (long polling needs more than the
    /// default). <paramref name="uploaded"/> receives the bytes of file parts sent so far.
    /// </summary>
    public async Task<TgCallResult> CallAsync(TgRequest request, TimeSpan idleTimeout, IProgress<long>? uploaded = null,
                                              CancellationToken ct = default)
    {
        if (!IsMethodName(request.Method))
            return TgCallResult.Fail(TgOutcome.Refused, "The method name can only have letters, digits and underscores.");
        if (idleTimeout <= TimeSpan.Zero) idleTimeout = DefaultTimeout;
        if (idleTimeout > MaxTimeout) idleTimeout = MaxTimeout;

        var sw = Stopwatch.StartNew();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(idleTimeout);
        try
        {
            using var msg = new HttpRequestMessage(HttpMethod.Post, $"{BaseUrl}/bot{_token}/{request.Method}");
            msg.Headers.Accept.ParseAdd("application/json");
            msg.Content = BuildContent(request, deadline, idleTimeout, uploaded);

            using var resp = await _http.SendAsync(msg, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
            var (text, bytes) = await ReadCappedAsync(resp.Content, deadline, idleTimeout, MaxResponseBytes).ConfigureAwait(false);
            return Interpret((int)resp.StatusCode, resp.ReasonPhrase, text, bytes, sw.Elapsed);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return TgCallResult.Fail(TgOutcome.Cancelled, "Stopped before Telegram answered.", sw.Elapsed);
        }
        // A local problem (file too large / unreadable / changed, response over the cap) — the send wraps it in an
        // HttpRequestException, which must not read as "couldn't reach Telegram".
        catch (Exception ex) when (FindLocal(ex) is { } local)
        {
            return TgCallResult.Fail(TgOutcome.Refused, Redact(local.Message), sw.Elapsed);
        }
        catch (OperationCanceledException)
        {
            return TgCallResult.Fail(TgOutcome.Timeout, $"Telegram didn't answer within {idleTimeout.TotalSeconds:0} seconds.", sw.Elapsed);
        }
        catch (HttpRequestException ex)
        {
            return TgCallResult.Fail(TgOutcome.NetworkError, NetworkText(ex), sw.Elapsed);
        }
        catch (IOException ex)
        {
            return TgCallResult.Fail(TgOutcome.NetworkError, "Connection error: " + Redact(ex.Message), sw.Elapsed);
        }
        catch (ObjectDisposedException)
        {
            return TgCallResult.Fail(TgOutcome.Cancelled, "The request was cancelled.", sw.Elapsed);
        }
        // A proxy scheme the handler can't use (socks5h://, ftp://…) throws this from the send.
        catch (NotSupportedException ex)
        {
            return TgCallResult.Fail(TgOutcome.NetworkError, "Couldn't use the proxy: " + Redact(ex.Message), sw.Elapsed);
        }
        // Anything else still comes back as a result: an exception escaping here could carry the URL (and the token in it)
        // into a crash log.
        catch (Exception ex)
        {
            return TgCallResult.Fail(TgOutcome.NetworkError, "Unexpected error: " + Redact(ex.Message), sw.Elapsed);
        }
    }

    /// <summary>
    /// Download a file by the file_path getFile returned, into <paramref name="destination"/>. Returns null on success,
    /// else a readable (redacted) reason. Capped at <see cref="MaxDownloadBytes"/>.
    /// </summary>
    public async Task<string?> DownloadAsync(string filePath, Stream destination, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(filePath) || filePath.Length > 512 || filePath.Contains("..", StringComparison.Ordinal)
            || filePath.StartsWith('/') || filePath.Contains('\\') || filePath.Contains('?') || filePath.Contains('#'))
            return "That file path can't be downloaded.";

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(DefaultTimeout);
        try
        {
            using var msg = new HttpRequestMessage(HttpMethod.Get, $"{BaseUrl}/file/bot{_token}/{EscapePath(filePath)}");
            using var resp = await _http.SendAsync(msg, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                return $"Telegram answered HTTP {(int)resp.StatusCode} for the file. A file_path is valid for about an hour: run getFile again.";
            await using var s = await resp.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
            byte[] buf = ArrayPool<byte>.Shared.Rent(64 * 1024);
            try
            {
                long total = 0;
                int n;
                while ((n = await s.ReadAsync(buf.AsMemory(0, 64 * 1024), deadline.Token).ConfigureAwait(false)) > 0)
                {
                    deadline.CancelAfter(DefaultTimeout);
                    total += n;
                    if (total > MaxDownloadBytes) return "The file is larger than 20 MB, the Bot API's download limit.";
                    await destination.WriteAsync(buf.AsMemory(0, n), deadline.Token).ConfigureAwait(false);
                }
            }
            finally { ArrayPool<byte>.Shared.Return(buf); }
            return null;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { return "Download stopped."; }
        catch (OperationCanceledException) { return "The download timed out."; }
        catch (HttpRequestException ex) { return NetworkText(ex); }
        catch (IOException ex) { return "Couldn't save the file: " + Redact(ex.Message); }
        catch (UnauthorizedAccessException ex) { return "Couldn't save the file: " + Redact(ex.Message); }
        catch (NotSupportedException ex) { return "Couldn't use the proxy: " + Redact(ex.Message); }
    }

    private static string EscapePath(string path)
    {
        var parts = path.Split('/');
        for (int i = 0; i < parts.Length; i++) parts[i] = Uri.EscapeDataString(parts[i]);
        return string.Join('/', parts);
    }

    // ---------------------------------------------------------------- request bodies

    private HttpContent? BuildContent(TgRequest request, CancellationTokenSource deadline, TimeSpan idle, IProgress<long>? uploaded)
    {
        if (request.IsMultipart)
        {
            var form = new MultipartFormDataContent();
            foreach (var (name, value) in request.Fields)
                form.Add(new StringContent(value, Encoding.UTF8), name);
            long done = 0;
            foreach (var (name, file) in request.Files)
            {
                var part = new UploadContent(file, n =>
                {
                    deadline.CancelAfter(idle);   // bytes are moving: the call isn't stuck
                    done += n;
                    uploaded?.Report(done);
                });
                part.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
                form.Add(part, name, file.FileName);
            }
            return form;
        }
        if (!string.IsNullOrEmpty(request.JsonBody))
            return new StringContent(request.JsonBody, Encoding.UTF8, "application/json");
        return null;   // no parameters (getMe, getWebhookInfo…)
    }

    /// <summary>A file part streamed from its source in chunks, reporting progress and enforcing the upload cap.</summary>
    private sealed class UploadContent : HttpContent
    {
        private readonly TgUpload _file;
        private readonly Action<long> _progress;

        public UploadContent(TgUpload file, Action<long> progress)
        {
            _file = file;
            _progress = progress;
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
            => SerializeToStreamAsync(stream, context, CancellationToken.None);

        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context, CancellationToken ct)
        {
            Stream src;
            try { src = await _file.Open(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { throw new LocalFailure($"Couldn't read {_file.FileName}: {ex.Message}"); }

            await using var _ = src;
            byte[] buf = ArrayPool<byte>.Shared.Rent(64 * 1024);
            try
            {
                long total = 0;
                int n;
                while (true)
                {
                    try { n = await src.ReadAsync(buf.AsMemory(0, 64 * 1024), ct).ConfigureAwait(false); }
                    catch (OperationCanceledException) { throw; }
                    catch (Exception ex) { throw new LocalFailure($"Couldn't read {_file.FileName}: {ex.Message}"); }
                    if (n <= 0) break;
                    total += n;
                    if (total > MaxUploadBytes) throw new LocalFailure("The file is larger than 50 MB, the Bot API's upload limit.");
                    // A declared length that turns out wrong would corrupt the request framing: refuse instead.
                    if (_file.Length is long declared && total > declared) throw new LocalFailure($"{_file.FileName} changed while it was being sent. Choose it again.");
                    await stream.WriteAsync(buf.AsMemory(0, n), ct).ConfigureAwait(false);
                    _progress(n);
                }
                if (_file.Length is long expected && total != expected)
                    throw new LocalFailure($"{_file.FileName} changed while it was being sent. Choose it again.");
            }
            finally { ArrayPool<byte>.Shared.Return(buf); }
        }

        protected override bool TryComputeLength(out long length)
        {
            length = _file.Length ?? 0;
            return _file.Length is not null;
        }
    }

    /// <summary>A failure on this side of the connection (file / size cap), reported as <see cref="TgOutcome.Refused"/>.</summary>
    private sealed class LocalFailure : Exception
    {
        public LocalFailure(string message) : base(message) { }
    }

    private static LocalFailure? FindLocal(Exception? ex)
    {
        for (int depth = 0; ex != null && depth < 8; ex = ex.InnerException, depth++)
            if (ex is LocalFailure lf) return lf;
        return null;
    }

    // ---------------------------------------------------------------- responses

    private TgCallResult Interpret(int status, string? reason, string text, long bytes, TimeSpan elapsed)
    {
        string body = Redact(text);
        JsonDocument? doc = null;
        try
        {
            if (LooksLikeJson(body))
                doc = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 256, AllowTrailingCommas = false });
        }
        catch (JsonException) { doc = null; }

        if (doc is not null && doc.RootElement.ValueKind == JsonValueKind.Object
            && doc.RootElement.TryGetProperty("ok", out var ok) && ok.ValueKind is JsonValueKind.True or JsonValueKind.False)
        {
            var root = doc.RootElement;
            if (ok.ValueKind == JsonValueKind.True && status is >= 200 and < 300)
                return new TgCallResult { Outcome = TgOutcome.Ok, HttpStatus = status, Body = body, Bytes = bytes, Elapsed = elapsed, Json = doc };

            int code = root.TryGetProperty("error_code", out var ec) && ec.ValueKind == JsonValueKind.Number && ec.TryGetInt32(out int c) ? c : status;
            string desc = root.TryGetProperty("description", out var d) && d.ValueKind == JsonValueKind.String ? d.GetString() ?? "" : "";
            int? retry = null;
            long? migrate = null;
            if (root.TryGetProperty("parameters", out var p) && p.ValueKind == JsonValueKind.Object)
            {
                if (p.TryGetProperty("retry_after", out var ra) && ra.ValueKind == JsonValueKind.Number && ra.TryGetInt32(out int r)) retry = Math.Max(0, r);
                if (p.TryGetProperty("migrate_to_chat_id", out var mg) && mg.ValueKind == JsonValueKind.Number && mg.TryGetInt64(out long m)) migrate = m;
            }
            if (desc.Length > 500) desc = desc[..500] + "…";
            return new TgCallResult
            {
                Outcome = TgOutcome.ApiError, HttpStatus = status, ErrorCode = code,
                Description = desc.Length > 0 ? desc : $"Request failed (error {code}).",
                RetryAfter = retry, MigrateToChatId = migrate, Body = body, Bytes = bytes, Elapsed = elapsed, Json = doc,
            };
        }

        doc?.Dispose();
        string what = status switch
        {
            >= 300 and < 400 => $"Telegram answered with a redirect (HTTP {status}). It isn't followed, because the request carries the bot token.",
            407 => "The proxy needs a user name and password (HTTP 407).",
            >= 500 => $"Telegram's server had a problem (HTTP {status}{(string.IsNullOrEmpty(reason) ? "" : " " + reason)}). Try again in a moment.",
            _ => $"The server answered HTTP {status}{(string.IsNullOrEmpty(reason) ? "" : " " + reason)} without Telegram's JSON. A proxy or firewall may be in the way.",
        };
        return new TgCallResult { Outcome = TgOutcome.HttpError, HttpStatus = status, Description = Redact(what), Body = body, Bytes = bytes, Elapsed = elapsed };
    }

    // "Couldn't reach api.telegram.org (connection refused)." — what failed, in a few words; the hint (what to do) is
    // added by the caller.
    private string NetworkText(HttpRequestException ex)
    {
        string inner = Innermost(ex);
        string what = ex.HttpRequestError switch
        {
            HttpRequestError.NameResolutionError => "its name didn't resolve",
            HttpRequestError.SecureConnectionError => "the secure (TLS) connection failed",
            HttpRequestError.ProxyTunnelError => "the proxy refused the connection",
            _ => ShortReason(inner),
        };
        return $"Couldn't reach {DisplayHost} ({what}).";
    }

    private string ShortReason(string inner)
    {
        bool Has(string s) => inner.Contains(s, StringComparison.OrdinalIgnoreCase);
        if (Has("actively refused") || Has("Connection refused")) return "connection refused";
        if (Has("No such host") || Has("Name or service not known") || Has("nodename nor servname")) return "host not found";
        if (Has("timed out")) return "connection timed out";
        if (Has("reset")) return "connection reset";
        if (Has("unreachable")) return "network unreachable";
        if (Has("certificate") || Has("SSL") || Has("TLS")) return "the secure (TLS) connection failed";
        if (Has("proxy")) return "proxy error";
        string m = Redact(inner).Trim().TrimEnd('.');
        return m.Length > 90 ? m[..90] + "…" : m.Length > 0 ? m : "connection failed";
    }

    /// <summary>Strip anything secret from a text bound for the UI: this client's token (also any token-shaped string),
    /// its proxy password, and any user:password@ in a URL.</summary>
    public string Redact(string? text)
    {
        string m = text ?? string.Empty;
        if (m.Length == 0) return m;
        foreach (var s in _secrets) m = m.Replace(s, "•••", StringComparison.Ordinal);
        return RedactStatic(m);
    }

    /// <summary>Token-shaped strings and URL user-info removed (no client needed).</summary>
    public static string RedactStatic(string? text)
    {
        string m = text ?? string.Empty;
        if (m.Length == 0) return m;
        try { m = TokenLikeRx.Replace(m, "•••"); }
        catch (RegexMatchTimeoutException) { }
        return CloudflareApi.RedactUserInfo(m);
    }

    private static string Innermost(Exception ex)
    {
        string msg = ex.Message;
        for (var e = ex.InnerException; e != null; e = e.InnerException)
            if (!string.IsNullOrWhiteSpace(e.Message)) msg = e.Message;
        return msg;
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

    // idle: cancelled when no data arrives for the idle timeout (re-armed per chunk), or with the caller's token.
    private static async Task<(string Text, long Bytes)> ReadCappedAsync(HttpContent content, CancellationTokenSource idle, TimeSpan idleTimeout, int cap)
    {
        await using var s = await content.ReadAsStreamAsync(idle.Token).ConfigureAwait(false);
        using var ms = new MemoryStream();
        byte[] buf = ArrayPool<byte>.Shared.Rent(16 * 1024);
        try
        {
            int n;
            while ((n = await s.ReadAsync(buf.AsMemory(0, 16 * 1024), idle.Token).ConfigureAwait(false)) > 0)
            {
                idle.CancelAfter(idleTimeout);
                if (ms.Length + n > cap) throw new LocalFailure($"The response is larger than {cap / (1024 * 1024)} MB, so it wasn't read.");
                ms.Write(buf, 0, n);
            }
        }
        finally { ArrayPool<byte>.Shared.Return(buf); }
        return (Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length), ms.Length);
    }

    // ---------------------------------------------------------------- formatting helpers

    private static readonly JsonWriterOptions Indented = new()
    {
        Indented = true,
        // Non-Latin text (Persian, emoji) stays readable instead of \uXXXX escapes.
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>The JSON indented with two spaces and readable non-ASCII text; the text itself when it isn't JSON.</summary>
    public static string Pretty(JsonDocument? doc, string fallback)
    {
        if (doc is null) return fallback;
        try
        {
            var buffer = new ArrayBufferWriter<byte>(Math.Max(256, fallback.Length + fallback.Length / 2));
            using (var w = new Utf8JsonWriter(buffer, Indented)) doc.RootElement.WriteTo(w);
            return Readable(Encoding.UTF8.GetString(buffer.WrittenSpan));
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException) { return fallback; }
    }

    /// <summary>
    /// Utf8JsonWriter escapes every character outside the BMP (emoji…) as a 👋 pair, even with the relaxed
    /// encoder. Put those characters back so the text reads as it does in Telegram; the result is still valid JSON.
    /// Other escapes are copied whole, so an escaped backslash can't start a false match.
    /// </summary>
    public static string Readable(string json)
    {
        if (json.IndexOf("\\uD", StringComparison.OrdinalIgnoreCase) < 0) return json;
        var sb = new StringBuilder(json.Length);
        int n = json.Length;
        for (int k = 0; k < n; k++)
        {
            char c = json[k];
            if (c != '\\' || k + 1 >= n) { sb.Append(c); continue; }
            char next = json[k + 1];
            if (next == 'u' && k + 12 <= n
                && Hex4(json, k + 2) is int hi and >= 0xD800 and <= 0xDBFF
                && json[k + 6] == '\\' && json[k + 7] == 'u'
                && Hex4(json, k + 8) is int lo and >= 0xDC00 and <= 0xDFFF)
            {
                sb.Append((char)hi).Append((char)lo);
                k += 11;
                continue;
            }
            sb.Append(c).Append(next);
            k++;
        }
        return sb.ToString();
    }

    private static int? Hex4(string s, int at)
    {
        int v = 0;
        for (int i = at; i < at + 4; i++)
        {
            int d = s[i] switch
            {
                >= '0' and <= '9' => s[i] - '0',
                >= 'a' and <= 'f' => s[i] - 'a' + 10,
                >= 'A' and <= 'F' => s[i] - 'A' + 10,
                _ => -1,
            };
            if (d < 0) return null;
            v = v * 16 + d;
        }
        return v;
    }

    public static string FormatBytes(long bytes) => bytes switch
    {
        < 1024 => bytes.ToString(CultureInfo.InvariantCulture) + " B",
        < 1024 * 1024 => (bytes / 1024.0).ToString("0.#", CultureInfo.InvariantCulture) + " KB",
        _ => (bytes / (1024.0 * 1024)).ToString("0.#", CultureInfo.InvariantCulture) + " MB",
    };
}
