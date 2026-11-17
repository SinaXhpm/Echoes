using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>
/// One HTTP response as a tool caught it, for the response viewer (Doctor, Monitor, Check Host, the proxy checker, a
/// refused WebSocket handshake): its status line, its headers as they came and the start of its body, decoded. Pure data,
/// built off the UI thread; the body is at most what the tool chose to keep (<see cref="Cap"/>).
/// </summary>
public sealed class HttpResponseSnapshot
{
    public HttpResponseSnapshot(string statusLine, IReadOnlyList<(string Name, string Value)> headers, byte[] body, int length,
                                bool cut, int cap)
    {
        StatusLine = statusLine.Trim();
        Headers = headers;
        Body = body;
        Length = Math.Clamp(length, 0, body.Length);
        Cut = cut;
        Cap = cap;
    }

    /// <summary>"HTTP/1.1 503 Service Unavailable" (as it came, or put together from the version, code and reason).</summary>
    public string StatusLine { get; }
    public IReadOnlyList<(string Name, string Value)> Headers { get; }
    /// <summary>The body as kept: decoded (gzip, deflate, br) unless <see cref="Undecoded"/> says otherwise.</summary>
    public byte[] Body { get; }
    public int Length { get; }
    /// <summary>There was more than was kept (or it broke off).</summary>
    public bool Cut { get; }
    /// <summary>The most that was kept, for "the first 64 KB".</summary>
    public int Cap { get; }
    /// <summary>The encoding the body still has when it couldn't be decoded here (zstd …): its bytes are the encoded ones.</summary>
    public string? Undecoded { get; init; }
    /// <summary>The URL it answered, when known (a file name to save it under).</summary>
    public string? Url { get; init; }
    /// <summary>What the tool wants said about it ("from Frankfurt, DE", "the proxy's own answer, not the site's").</summary>
    public string? About { get; init; }

    public string? ContentType => Header("Content-Type");

    /// <summary>The first value of a header (names aren't case-sensitive), or null.</summary>
    public string? Header(string name)
    {
        foreach (var (n, v) in Headers) if (string.Equals(n, name, StringComparison.OrdinalIgnoreCase)) return v;
        return null;
    }

    /// <summary>The status line and every header, one per line, as a response's head reads.</summary>
    public string HeadText()
    {
        var sb = new StringBuilder(StatusLine);
        foreach (var (n, v) in Headers) sb.Append('\n').Append(n).Append(": ").Append(v);
        return sb.ToString();
    }

    /// <summary>"1.2 KB" / "the first 64 KB" — the size kept, and whether there was more.</summary>
    public string SizeText => Length == 0 ? "empty"
        : Cut ? $"the first {FileHttpServer.HumanSize(Length)}" : FileHttpServer.HumanSize(Length);

    /// <summary>A head and body split out of raw bytes off a socket (a proxy's answer, a refused WebSocket handshake):
    /// the head up to the blank line read as Latin-1, a chunked body put together; null when no status line is there.</summary>
    public static HttpResponseSnapshot? Parse(byte[] raw, int length, int cap, bool more, string? url = null, string? about = null)
    {
        length = Math.Clamp(length, 0, raw.Length);
        int end = IndexOf(raw, length, "\r\n\r\n"u8);
        int bodyAt = end >= 0 ? end + 4 : length;
        string head = Encoding.Latin1.GetString(raw, 0, end >= 0 ? end : length);
        var lines = head.Split('\n');
        string status = lines[0].TrimEnd('\r');
        if (!status.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase)) return null;
        var headers = new List<(string, string)>();
        foreach (var line in lines.Skip(1))
        {
            string l = line.TrimEnd('\r');
            int colon = l.IndexOf(':');
            if (colon > 0) headers.Add((l[..colon].Trim(), l[(colon + 1)..].Trim()));
        }
        byte[] body = raw.AsSpan(bodyAt, length - bodyAt).ToArray();
        int n = body.Length;
        bool cut = more;
        if (headers.Exists(h => h.Item1.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase)
                                && h.Item2.Contains("chunked", StringComparison.OrdinalIgnoreCase)))
            (body, n, cut) = Dechunk(body, n, cut);
        if (n > cap) { n = cap; cut = true; }
        return new HttpResponseSnapshot(status, headers, body, n, cut, cap) { Url = url, About = about };
    }

    // a chunked body put together; what was read of a chunk cut short is kept (and the body is then cut)
    private static (byte[] Body, int Length, bool Cut) Dechunk(byte[] b, int n, bool cut)
    {
        var o = new MemoryStream(n);
        int i = 0;
        while (i < n)
        {
            int eol = IndexOf(b.AsSpan(i, n - i), "\r\n"u8);
            if (eol < 0) return (o.ToArray(), (int)o.Length, true);
            string size = Encoding.Latin1.GetString(b, i, eol).Split(';')[0].Trim();
            if (!int.TryParse(size, System.Globalization.NumberStyles.HexNumber, null, out int len) || len < 0)
                return (o.ToArray(), (int)o.Length, true);
            i += eol + 2;
            if (len == 0) return (o.ToArray(), (int)o.Length, cut);
            int take = Math.Min(len, n - i);
            o.Write(b, i, take);
            if (take < len) return (o.ToArray(), (int)o.Length, true);
            i += len + 2;
        }
        return (o.ToArray(), (int)o.Length, true);
    }

    private static int IndexOf(byte[] b, int n, ReadOnlySpan<byte> what) => IndexOf(b.AsSpan(0, n), what);
    private static int IndexOf(ReadOnlySpan<byte> b, ReadOnlySpan<byte> what) => b.IndexOf(what);
}

/// <summary>A body read off a response: at most a cap of it, decoded (gzip, deflate, br) when it was compressed.</summary>
public readonly record struct HttpBodyRead(byte[] Buf, int Length, bool Cut, string? Undecoded);

/// <summary>
/// Reads the start of a response's body for showing it: at most <c>cap</c> bytes once decoded, at most <c>wireCap</c> off
/// the wire. What was read is kept when the body breaks off, is damaged or runs out of time (it is then marked cut);
/// an encoding this can't decode (zstd …) is kept as it came and named.
/// </summary>
public static class HttpBodyReader
{
    public static async Task<HttpBodyRead> ReadAsync(HttpContent content, int cap, int wireCap, CancellationToken ct)
    {
        string? coding = content.Headers.ContentEncoding.LastOrDefault()?.Trim().ToLowerInvariant();
        if (coding is "identity" or "") coding = null;
        Stream stream;
        try { stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false); }
        catch (Exception) { return new HttpBodyRead(Array.Empty<byte>(), 0, false, null); }   // (the time ran out too)
        await using (stream.ConfigureAwait(false))
        {
            if (coding is null or not ("gzip" or "x-gzip" or "deflate" or "br"))
            {
                var (b, n, cut) = await ReadCappedAsync(stream, cap, ct).ConfigureAwait(false);
                return new HttpBodyRead(b, n, cut, coding);
            }
            var (wire, got, wireCut) = await ReadCappedAsync(stream, wireCap, ct).ConfigureAwait(false);
            var (buf, len, more) = await DecodeAsync(wire, got, coding, cap, ct).ConfigureAwait(false);
            return new HttpBodyRead(buf, len, more || wireCut, null);
        }
    }

    /// <summary>Compressed bytes (gzip, deflate — zlib-wrapped or bare —, br) decoded to at most <paramref name="cap"/>
    /// bytes; a stream cut short keeps what decoded before the cut.</summary>
    public static async Task<(byte[] Buf, int Length, bool Cut)> DecodeAsync(byte[] wire, int got, string coding, int cap, CancellationToken ct)
    {
        using var raw = new MemoryStream(wire, 0, got, writable: false);
        // HTTP's "deflate" is meant to be zlib-wrapped; some servers send it bare
        await using Stream decoder = coding switch
        {
            "br" => new BrotliStream(raw, CompressionMode.Decompress),
            "deflate" when got >= 2 && (wire[0] & 0x0F) == 8 && ((wire[0] << 8) | wire[1]) % 31 == 0 => new ZLibStream(raw, CompressionMode.Decompress),
            "deflate" => new DeflateStream(raw, CompressionMode.Decompress),
            _ => new GZipStream(raw, CompressionMode.Decompress),
        };
        return await ReadCappedAsync(decoder, cap, ct).ConfigureAwait(false);
    }

    /// <summary>Reads until <paramref name="cap"/> bytes or the end; Cut: there was more, or it broke off (a reset, damaged
    /// compressed data, the time ran out). The buffer grows as it fills: a small body doesn't take the whole cap.</summary>
    public static async Task<(byte[] Buf, int Length, bool Cut)> ReadCappedAsync(Stream s, int cap, CancellationToken ct)
    {
        var buf = new byte[Math.Min(cap, 16 * 1024)];
        int n = 0;
        try
        {
            while (true)
            {
                if (n == buf.Length)
                {
                    if (n >= cap) return (buf, n, await s.ReadAsync(new byte[1], ct).ConfigureAwait(false) > 0);
                    Array.Resize(ref buf, (int)Math.Min(cap, buf.Length * 2L));
                }
                int got = await s.ReadAsync(buf.AsMemory(n), ct).ConfigureAwait(false);
                if (got == 0) return (buf, n, false);
                n += got;
            }
        }
        catch (Exception e) when (e is IOException or InvalidDataException or HttpRequestException or OperationCanceledException
                                      or ObjectDisposedException)
        {
            return (buf, n, true);
        }
    }
}
