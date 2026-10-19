using System;
using System.Buffers;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Unicode;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>One parsed request head of the share hub.</summary>
internal sealed class HubRequest
{
    public string Method = string.Empty, Target = string.Empty, Path = string.Empty, Query = string.Empty, Version = string.Empty;
    public readonly List<KeyValuePair<string, string>> Headers = new();
    /// <summary>-1 = no body.</summary>
    public long ContentLength = -1;
    public bool IsHead => Method == "HEAD";

    public string? Header(string name)
    {
        foreach (var h in Headers) if (h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)) return h.Value;
        return null;
    }

    /// <summary>The first value of a query parameter (percent-decoded, '+' as space), or null.</summary>
    public string? QueryValue(string key)
    {
        if (Query.Length == 0) return null;
        foreach (var part in Query.Split('&'))
        {
            int eq = part.IndexOf('=');
            string k = eq >= 0 ? part[..eq] : part;
            if (!Decode(k).Equals(key, StringComparison.Ordinal)) continue;
            return eq >= 0 ? Decode(part[(eq + 1)..]) : string.Empty;
        }
        return null;
    }

    private static string Decode(string s)
    {
        try { return Uri.UnescapeDataString(s.Replace('+', ' ')); }
        catch { return s; }
    }

    /// <summary>HTTP/1.1 keeps the connection unless asked to close; 1.0 only when asked to keep it.</summary>
    public bool WantsKeepAlive => Version == "HTTP/1.1"
        ? !WsProtocol.HasToken(Header("Connection"), "close")
        : WsProtocol.HasToken(Header("Connection"), "keep-alive");
}

/// <summary>
/// Buffered reads over one hub connection: request heads (strict, capped) and body bytes. Like the request catcher's
/// reader, but it refuses what the hub never needs (absolute-form targets, folded or duplicate-length headers, chunked
/// request bodies) instead of interpreting it.
/// </summary>
internal sealed class HubReader
{
    public const int MaxHead = 16 * 1024;
    private const int MaxHeaders = 100;

    private readonly Stream _s;
    private readonly byte[] _buf = new byte[MaxHead + 4];
    private int _start, _end;
    private readonly int _bodyIdleMs;
    // The current request's body must be in by then (Environment.TickCount64; 0 = no body): idle + 1 ms per 4 bytes, at
    // least ~4 KB/s overall. The per-read idle timeout alone let a client trickle a byte every 29 s and hold a connection
    // slot for days — on every route, before any PIN.
    private long _bodyDeadline;

    public HubReader(Stream s, int bodyIdleMs)
    {
        _s = s;
        _bodyIdleMs = bodyIdleMs;
    }

    /// <summary>Bytes read past the head (handed to a WebSocket).</summary>
    public byte[] TakeBuffered()
    {
        var b = _buf.AsSpan(_start, _end - _start).ToArray();
        _start = _end = 0;
        return b;
    }

    private async Task<int> FillAsync(CancellationToken ct)
    {
        if (_start > 0)
        {
            Buffer.BlockCopy(_buf, _start, _buf, 0, _end - _start);
            _end -= _start;
            _start = 0;
        }
        if (_end >= _buf.Length) return -1;
        int n = await _s.ReadAsync(_buf.AsMemory(_end, _buf.Length - _end), ct).ConfigureAwait(false);
        if (n > 0) _end += n;
        return n;
    }

    /// <summary>(null, 0) = closed before a new request; (null, status) = a bad request to answer with status.</summary>
    public async Task<(HubRequest? Request, int Error)> ReadHeadAsync(CancellationToken ct)
    {
        _bodyDeadline = 0;   // the last request's: set again by Parse for this one's body
        int scanned = 0;
        while (true)
        {
            while (_end - _start >= 2 && _buf[_start] == '\r' && _buf[_start + 1] == '\n') _start += 2;   // blank lines between requests
            int avail = _end - _start;
            if (avail > 0)
            {
                int from = _start + Math.Max(0, scanned - 3);
                int i = _buf.AsSpan(from, _end - from).IndexOf("\r\n\r\n"u8);
                if (i >= 0) return Parse(from + i);
                scanned = avail;
                if (avail >= MaxHead) return (null, 431);
            }
            int n = await FillAsync(ct).ConfigureAwait(false);
            if (n <= 0) return (null, _end - _start == 0 ? 0 : 400);
        }
    }

    private (HubRequest?, int) Parse(int endOfHead)
    {
        string text = Encoding.Latin1.GetString(_buf, _start, endOfHead - _start);
        _start = endOfHead + 4;
        var lines = text.Split("\r\n");
        string first = lines[0];
        foreach (char c in first) if (c < 0x20 || c == 0x7F) return (null, 400);
        var parts = first.Split(' ');
        if (parts.Length != 3 || !WsProtocol.IsToken(parts[0]) || parts[1].Length == 0 || parts[1][0] != '/' || parts[1].Length > 4096)
            return (null, 400);
        if (parts[2] is not ("HTTP/1.1" or "HTTP/1.0")) return (null, parts[2].StartsWith("HTTP/", StringComparison.Ordinal) ? 505 : 400);

        var req = new HubRequest { Method = parts[0].ToUpperInvariant(), Target = parts[1], Version = parts[2] };
        int q = req.Target.IndexOf('?');
        req.Path = q >= 0 ? req.Target[..q] : req.Target;
        req.Query = q >= 0 ? req.Target[(q + 1)..] : string.Empty;
        for (int i = 1; i < lines.Length; i++)
        {
            string l = lines[i];
            if (l.Length == 0) continue;
            if (l[0] is ' ' or '\t') return (null, 400);                 // obsolete folding: refused
            int c = l.IndexOf(':');
            if (c <= 0) return (null, 400);
            string name = l[..c];
            if (!WsProtocol.IsToken(name)) return (null, 400);   // also "Content-Length : 5" (RFC 9112: whitespace before the colon)
            string value = l[(c + 1)..].Trim();
            foreach (char ch in value) if (ch < 0x20 && ch != '\t' || ch == 0x7F) return (null, 400);
            req.Headers.Add(new KeyValuePair<string, string>(name, value));
            if (req.Headers.Count > MaxHeaders) return (null, 431);
        }
        if (req.Header("Transfer-Encoding") is not null) return (null, 501);   // XHR never sends chunked bodies
        long length = -1;
        foreach (var h in req.Headers)
        {
            if (!h.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)) continue;
            if (!long.TryParse(h.Value, NumberStyles.None, CultureInfo.InvariantCulture, out long v) || length >= 0 && v != length) return (null, 400);
            length = v;
        }
        req.ContentLength = length;
        _bodyDeadline = length > 0 ? Environment.TickCount64 + _bodyIdleMs + length / 4 : 0;
        return (req, 0);
    }

    /// <summary>Buffered bytes first, then the stream. Past the request body's deadline it throws
    /// <see cref="OperationCanceledException"/> (as an idle timeout does): the caller drops the connection.</summary>
    public async ValueTask<int> ReadAsync(Memory<byte> dest, CancellationToken ct)
    {
        if (_end > _start)
        {
            int n = Math.Min(dest.Length, _end - _start);
            _buf.AsSpan(_start, n).CopyTo(dest.Span);
            _start += n;
            return n;
        }
        long deadline = _bodyDeadline;
        if (deadline == 0) return await _s.ReadAsync(dest, ct).ConfigureAwait(false);
        long left = deadline - Environment.TickCount64;
        if (left <= 0) throw new OperationCanceledException("The request body didn't arrive in time.");
        using var total = CancellationTokenSource.CreateLinkedTokenSource(ct);
        total.CancelAfter((int)Math.Min(left, int.MaxValue));
        return await _s.ReadAsync(dest, total.Token).ConfigureAwait(false);
    }

    /// <summary>Exactly <paramref name="length"/> body bytes (small JSON bodies), each read within <paramref name="idleMs"/>;
    /// null when the client stopped sending.</summary>
    public async Task<byte[]?> ReadBodyAsync(long length, int idleMs, CancellationToken ct)
    {
        var body = new byte[length];
        int got = 0;
        using var idle = CancellationTokenSource.CreateLinkedTokenSource(ct);
        while (got < length)
        {
            idle.CancelAfter(idleMs);
            int n;
            try { n = await ReadAsync(body.AsMemory(got), idle.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return null; }
            if (n <= 0) return null;
            got += n;
        }
        return body;
    }

    /// <summary>Reads and drops a body the route doesn't use (at most <paramref name="max"/> bytes). False = the
    /// connection can't be reused.</summary>
    public async Task<bool> DrainAsync(long length, long max, int idleMs, CancellationToken ct)
    {
        if (length <= 0) return true;
        if (length > max) return false;
        var buf = ArrayPool<byte>.Shared.Rent(16 * 1024);
        try
        {
            using var idle = CancellationTokenSource.CreateLinkedTokenSource(ct);
            long left = length;
            while (left > 0)
            {
                idle.CancelAfter(idleMs);
                int n = await ReadAsync(buf.AsMemory(0, (int)Math.Min(buf.Length, left)), idle.Token).ConfigureAwait(false);
                if (n <= 0) return false;
                left -= n;
            }
            return true;
        }
        catch { return false; }
        finally { ArrayPool<byte>.Shared.Return(buf); }
    }
}

/// <summary>Response writing and JSON for the share hub.</summary>
internal static class HubHttp
{
    /// <summary>On every answer: no sniffing, no referrer, no framing, no caching (the page and the API are live).</summary>
    public const string CommonHeaders = "X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\nCache-Control: no-store\r\n";

    /// <summary>Everything but the page: nothing in an answer can run or load anything, should a browser render it.</summary>
    public const string InertCsp = "Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; sandbox\r\n";

    // JSON for the page: every Unicode letter as itself (Persian text stays 2 bytes a character), the HTML-sensitive
    // characters still escaped.
    private static readonly JsonWriterOptions WriterOptions = new() { Encoder = JavaScriptEncoder.Create(UnicodeRanges.All) };

    public static string Reason(int status) => status switch
    {
        101 => "Switching Protocols",
        200 => "OK", 201 => "Created", 204 => "No Content", 206 => "Partial Content",
        303 => "See Other", 307 => "Temporary Redirect",
        400 => "Bad Request", 401 => "Unauthorized", 403 => "Forbidden", 404 => "Not Found", 405 => "Method Not Allowed",
        409 => "Conflict", 410 => "Gone", 411 => "Length Required", 413 => "Payload Too Large", 416 => "Range Not Satisfiable",
        421 => "Misdirected Request", 426 => "Upgrade Required", 429 => "Too Many Requests", 431 => "Request Header Fields Too Large",
        500 => "Internal Server Error", 501 => "Not Implemented", 503 => "Service Unavailable", 505 => "HTTP Version Not Supported",
        507 => "Insufficient Storage",
        _ => status < 300 ? "OK" : status < 400 ? "Redirect" : status < 500 ? "Client Error" : "Server Error",
    };

    /// <summary>One complete answer. <paramref name="csp"/> null = <see cref="InertCsp"/>.</summary>
    public static async Task SendAsync(Stream s, int status, string? contentType, ReadOnlyMemory<byte> body, string? extraHeaders,
        bool keepAlive, bool head, CancellationToken ct, string? csp = null)
    {
        var sb = new StringBuilder(384);
        sb.Append("HTTP/1.1 ").Append(status.ToString(CultureInfo.InvariantCulture)).Append(' ').Append(Reason(status)).Append("\r\n");
        sb.Append("Server: Echoes\r\n");
        if (contentType is not null) sb.Append("Content-Type: ").Append(contentType).Append("\r\n");
        sb.Append("Content-Length: ").Append(body.Length.ToString(CultureInfo.InvariantCulture)).Append("\r\n");
        sb.Append(CommonHeaders);
        sb.Append(csp ?? InertCsp);
        if (extraHeaders is not null) sb.Append(extraHeaders);
        sb.Append(keepAlive ? "Connection: keep-alive\r\n\r\n" : "Connection: close\r\n\r\n");
        byte[] h = Encoding.ASCII.GetBytes(sb.ToString());
        if (!head && body.Length > 0 && body.Length <= 64 * 1024)
        {
            // one write (one TLS record) for the usual small answer
            var all = new byte[h.Length + body.Length];
            h.CopyTo(all, 0);
            body.CopyTo(all.AsMemory(h.Length));
            await FileHttpServer.WriteWithTimeout(s, all, ct).ConfigureAwait(false);
        }
        else
        {
            await FileHttpServer.WriteWithTimeout(s, h, ct).ConfigureAwait(false);
            if (!head && body.Length > 0) await FileHttpServer.WriteWithTimeout(s, body, ct).ConfigureAwait(false);
        }
        await s.FlushAsync(ct).ConfigureAwait(false);
    }

    public static Task SendJsonAsync(Stream s, int status, byte[] json, bool keepAlive, CancellationToken ct, string? extraHeaders = null)
        => SendAsync(s, status, "application/json; charset=utf-8", json, extraHeaders, keepAlive, false, ct);

    /// <summary>{"error": message} (+ more fields).</summary>
    public static byte[] Error(string message, Action<Utf8JsonWriter>? more = null)
        => Json(w =>
        {
            w.WriteBoolean("ok", false);
            w.WriteString("error", message);
            more?.Invoke(w);
        });

    /// <summary>A JSON object written by <paramref name="body"/> (inside the braces).</summary>
    public static byte[] Json(Action<Utf8JsonWriter> body)
    {
        var buf = new ArrayBufferWriter<byte>(256);
        using (var w = new Utf8JsonWriter(buf, WriterOptions))
        {
            w.WriteStartObject();
            body(w);
            w.WriteEndObject();
        }
        return buf.WrittenSpan.ToArray();
    }

    /// <summary>The request body as a JSON object, or null when it isn't one.</summary>
    public static JsonDocument? ParseObject(byte[] body)
    {
        try
        {
            var doc = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 8 });
            if (doc.RootElement.ValueKind == JsonValueKind.Object) return doc;
            doc.Dispose();
        }
        catch (JsonException) { }
        return null;
    }

    public static string? Str(JsonDocument doc, string name)
        => doc.RootElement.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    public static long? Num(JsonDocument doc, string name)
        => doc.RootElement.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out long n) ? n : null;

    public static void WriteUnixMs(Utf8JsonWriter w, string name, DateTime local)
        => w.WriteNumber(name, new DateTimeOffset(local).ToUnixTimeMilliseconds());
}
