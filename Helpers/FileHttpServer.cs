using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>One file offered for download. The server opens it lazily via <see cref="Open"/>, so
/// the source can be a desktop <c>FileStream</c> (seekable → Range works) or an Android content
/// stream — the server never touches the filesystem path, which is why path traversal is impossible.</summary>
public sealed class SharedItem
{
    public required string Id { get; init; }          // opaque, URL-safe; the ONLY way to address a file
    public required string Name { get; init; }
    public required long Size { get; init; }
    public required string ContentType { get; init; }
    public required Func<Task<Stream>> Open { get; init; }
    // Mtime of the version that was picked (desktop only; Android content streams have none). When set,
    // a seekable source gets Last-Modified + a strong ETag, so browsers can resume and If-Range works.
    public DateTime? LastModifiedUtc { get; init; }

    /// <summary>The secret of the file's direct link (<c>/f/{LinkToken}/{name}</c>, the share hub): 128 random bits, so the
    /// link downloads this one file without the PIN (whoever was given it may) and can't be guessed. It ends with the item
    /// (removed, cleared).</summary>
    public string LinkToken { get; } = NewLinkToken();

    private static string NewLinkToken()
    {
        Span<byte> bytes = stackalloc byte[16];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');   // URL-safe, 22 chars
    }
}

/// <summary>Thrown by a <see cref="SharedItem.Open"/> whose file no longer matches what was picked
/// (size/mtime changed on disk). The server answers 410 instead of serving other bytes under the same
/// id — a blind resume (<c>curl -C -</c>, <c>wget -c</c>) would otherwise splice two versions.</summary>
public sealed class SharedItemChangedException : IOException
{
    public SharedItemChangedException() : base("The shared file changed since it was added.") { }
}

/// <summary>What one download answer did: the status sent, the body bytes written, and whether the connection can
/// carry another request (a source without a known length is streamed to its end and the connection closed).</summary>
internal readonly record struct DownloadResult(int Status, long Sent, bool Partial, bool KeepAlive);

/// <summary>
/// The download half of the share hub (<see cref="ShareHub"/> serves <c>/d/{id}</c> through it): one shared file per
/// request, by opaque id — there is no URL→path mapping, so a client can never ask for an arbitrary file. HEAD, single
/// Range requests (resume), If-Range with a strong ETag of the picked version, 410 when the file changed on disk, 416
/// past the end. Slow readers can't pin a connection: every write has an idle timeout and a minimum average rate.
/// Also the app's shared byte-size / MIME helpers.
/// </summary>
public static class FileHttpServer
{
    // A single write that stalls past WriteIdleMs (a slow-reading client) is aborted, freeing the
    // slot + source stream. Reads use ct (a slow SOURCE is not a client DoS); writes use the idle CTS.
    internal const int WriteIdleMs = 30000;

    /// <summary>Serves <paramref name="item"/> on <paramref name="stream"/>. <paramref name="extraHeaders"/> (CRLF-ended
    /// lines) go on every answer; <paramref name="onBytes"/> sees each chunk as it is written.</summary>
    internal static async Task<DownloadResult> ServeAsync(Stream stream, SharedItem item, bool head, string? range, string? ifRange,
        string extraHeaders, bool keepAlive, Action<int>? onBytes, CancellationToken ct)
    {
        Stream src;
        try { src = await item.Open().ConfigureAwait(false); }
        catch (SharedItemChangedException)
        {
            await WriteTextAsync(stream, 410, "Gone", "The file changed since it was shared - add it again in Echoes.", extraHeaders, keepAlive, head, ct).ConfigureAwait(false);
            return new DownloadResult(410, 0, false, keepAlive);
        }
        catch
        {
            await WriteTextAsync(stream, 500, "Internal Server Error", "The file can't be opened.", extraHeaders, keepAlive, head, ct).ConfigureAwait(false);
            return new DownloadResult(500, 0, false, keepAlive);
        }

        await using (src)
        {
            // Only a SEEKABLE source has an authoritative length we can promise (Content-Length) and
            // seek within (Range). A non-seekable Android content stream is streamed to EOF with
            // Connection: close and NO Content-Length / NO Range — so a null/stale picked size can
            // never truncate the download or produce a 0-byte file.
            bool seekable = src.CanSeek;
            long total = seekable ? src.Length : -1;

            // Validators for the picked version (see SharedItem.LastModifiedUtc). If-Range that doesn't
            // match them (or arrives when we have none) means "send it whole" — never splice versions.
            string? etag = null, lastMod = null;
            if (seekable && item.LastModifiedUtc is DateTime lm)
            {
                etag = $"\"{lm.Ticks:x}-{item.Size:x}\"";
                lastMod = lm.ToString("R", CultureInfo.InvariantCulture);
            }

            long start = 0, end = total - 1;
            bool partial = false;
            if (ifRange is not null && ifRange != etag && ifRange != lastMod) range = null;
            if (range is not null && seekable && total > 0)
            {
                if (TryParseRange(range, total, out start, out end, out bool unsatisfiable)) partial = true;
                else if (unsatisfiable)
                {
                    // A range starting at or past the end — typically resuming a download that is already complete
                    // (curl -C -, wget -c). 416 tells them there is nothing left; sending the whole file again (200)
                    // made curl fail and wget refuse to overwrite the finished file.
                    await WriteTextAsync(stream, 416, "Range Not Satisfiable", "Range Not Satisfiable",
                        extraHeaders + $"Content-Range: bytes */{total.ToString(CultureInfo.InvariantCulture)}\r\n", keepAlive, head, ct).ConfigureAwait(false);
                    return new DownloadResult(416, 0, false, keepAlive);
                }
            }

            bool keep = keepAlive && seekable;
            long count = partial ? end - start + 1 : total;
            var hb = new StringBuilder(512);
            hb.Append(partial ? "HTTP/1.1 206 Partial Content\r\n" : "HTTP/1.1 200 OK\r\n");
            hb.Append("Content-Type: ").Append(item.ContentType).Append("\r\n");
            if (seekable) hb.Append("Content-Length: ").Append(count.ToString(CultureInfo.InvariantCulture)).Append("\r\n");
            hb.Append("Accept-Ranges: ").Append(seekable ? "bytes" : "none").Append("\r\n");
            if (etag is not null) hb.Append("ETag: ").Append(etag).Append("\r\nLast-Modified: ").Append(lastMod).Append("\r\n");
            if (partial)
                hb.Append("Content-Range: bytes ").Append(start.ToString(CultureInfo.InvariantCulture)).Append('-')
                  .Append(end.ToString(CultureInfo.InvariantCulture)).Append('/').Append(total.ToString(CultureInfo.InvariantCulture)).Append("\r\n");
            hb.Append(ContentDisposition(item.Name));
            // Browsers download it (attachment); should a client render it anyway, a shared .html / .svg still can't
            // run script on this origin (where it could read the page's API) or be sniffed into HTML.
            hb.Append("X-Content-Type-Options: nosniff\r\nContent-Security-Policy: sandbox\r\n");
            hb.Append(extraHeaders);
            hb.Append(keep ? "Connection: keep-alive\r\n\r\n" : "Connection: close\r\n\r\n");
            await WriteWithTimeout(stream, Encoding.ASCII.GetBytes(hb.ToString()), ct).ConfigureAwait(false);

            if (head) return new DownloadResult(partial ? 206 : 200, 0, partial, keep);

            if (partial) src.Seek(start, SeekOrigin.Begin);
            long sent = seekable
                ? await CopyExactAsync(src, stream, count, onBytes, ct).ConfigureAwait(false)
                : await CopyToEndAsync(src, stream, onBytes, ct).ConfigureAwait(false);
            await stream.FlushAsync(ct).ConfigureAwait(false);
            // a source shorter than promised leaves the client waiting for bytes that never come: close
            return new DownloadResult(partial ? 206 : 200, sent, partial, keep && sent == count);
        }
    }

    /// <summary>The attachment header: an ASCII fallback name plus the exact UTF-8 one (RFC 6266).</summary>
    internal static string ContentDisposition(string name)
        => "Content-Disposition: attachment; filename=\"" + AsciiName(name) + "\"; filename*=UTF-8''" + Uri.EscapeDataString(name) + "\r\n";

    internal static async Task WriteTextAsync(Stream stream, int code, string reason, string msg, string extraHeaders, bool keepAlive, bool head, CancellationToken ct)
    {
        byte[] body = Encoding.UTF8.GetBytes(msg);
        var hb = new StringBuilder(256)
            .Append("HTTP/1.1 ").Append(code.ToString(CultureInfo.InvariantCulture)).Append(' ').Append(reason).Append("\r\n")
            .Append("Content-Type: text/plain; charset=utf-8\r\n")
            .Append("X-Content-Type-Options: nosniff\r\n")
            .Append("Content-Length: ").Append(body.Length.ToString(CultureInfo.InvariantCulture)).Append("\r\n")
            .Append(extraHeaders)
            .Append(keepAlive ? "Connection: keep-alive\r\n\r\n" : "Connection: close\r\n\r\n");
        await WriteWithTimeout(stream, Encoding.ASCII.GetBytes(hb.ToString()), ct).ConfigureAwait(false);
        if (!head) await WriteWithTimeout(stream, body, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    internal static async Task WriteWithTimeout(Stream dst, ReadOnlyMemory<byte> data, CancellationToken ct)
    {
        using var idle = CancellationTokenSource.CreateLinkedTokenSource(ct);
        idle.CancelAfter(WriteIdleMs);
        await dst.WriteAsync(data, idle.Token).ConfigureAwait(false);
    }

    // Slow-read floor: the per-chunk idle timer alone let a client draining ~2 KB/s (one 64 KB chunk
    // per ~30 s) hold a slot for a whole big file. Over every SlowReadWindowSec spent BLOCKED IN WRITES
    // the client must average MinBytesPerSec (4 KB/s) — far below any real LAN client, fatal only to
    // deliberate tricklers. Source reads don't count: a slow share / content provider is not the
    // client's fault. It must be a RATE: a fixed byte count per window is met by any two 64 KB writes,
    // however long each blocked (up to WriteIdleMs), so it never fired.
    private const int SlowReadWindowSec = 30;
    private const int MinBytesPerSec = 4 * 1024;

    private sealed class SlowReadGuard
    {
        private long _blockedTicks, _bytes;

        public void Wrote(long startTimestamp, int n)
        {
            _blockedTicks += Stopwatch.GetTimestamp() - startTimestamp;
            _bytes += n;
            double blockedSec = (double)_blockedTicks / Stopwatch.Frequency;   // double: no overflow on huge files
            if (blockedSec < SlowReadWindowSec) return;
            if (_bytes < MinBytesPerSec * blockedSec) throw new TimeoutException("client reads too slowly");
            _blockedTicks = 0;
            _bytes = 0;
        }
    }

    private static async Task<long> CopyExactAsync(Stream src, Stream dst, long count, Action<int>? onBytes, CancellationToken ct)
    {
        using var idle = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var guard = new SlowReadGuard();
        var buf = new byte[64 * 1024];
        long remaining = count, sent = 0;
        while (remaining > 0)
        {
            int want = (int)Math.Min(buf.Length, remaining);
            int n = await src.ReadAsync(buf.AsMemory(0, want), ct).ConfigureAwait(false);
            if (n <= 0) break;
            idle.CancelAfter(WriteIdleMs);
            long t0 = Stopwatch.GetTimestamp();
            await dst.WriteAsync(buf.AsMemory(0, n), idle.Token).ConfigureAwait(false);
            idle.CancelAfter(Timeout.Infinite);   // disarm: the next source read must not eat the write's budget
            onBytes?.Invoke(n);
            guard.Wrote(t0, n);
            sent += n;
            remaining -= n;
        }
        return sent;
    }

    private static async Task<long> CopyToEndAsync(Stream src, Stream dst, Action<int>? onBytes, CancellationToken ct)
    {
        using var idle = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var guard = new SlowReadGuard();
        var buf = new byte[64 * 1024];
        long sent = 0;
        int n;
        while ((n = await src.ReadAsync(buf, ct).ConfigureAwait(false)) > 0)
        {
            idle.CancelAfter(WriteIdleMs);
            long t0 = Stopwatch.GetTimestamp();
            await dst.WriteAsync(buf.AsMemory(0, n), idle.Token).ConfigureAwait(false);
            idle.CancelAfter(Timeout.Infinite);
            onBytes?.Invoke(n);
            guard.Wrote(t0, n);
            sent += n;
        }
        return sent;
    }

    // False = serve the whole file (no / invalid / multi range) — or, with unsatisfiable set, answer 416: a well-formed
    // range that selects nothing ("bytes=N-" with N >= size, or "bytes=-0").
    internal static bool TryParseRange(string header, long total, out long start, out long end, out bool unsatisfiable)
    {
        start = 0; end = total - 1; unsatisfiable = false;
        // Only the simple single-range "bytes=start-end" / "bytes=start-" / "bytes=-suffix".
        const string p = "bytes=";
        if (!header.StartsWith(p, StringComparison.OrdinalIgnoreCase)) return false;
        string spec = header[p.Length..].Trim();
        if (spec.Contains(',')) return false;                 // multi-range not supported
        int dash = spec.IndexOf('-');
        if (dash < 0) return false;
        string a = spec[..dash], b = spec[(dash + 1)..];
        if (a.Length == 0)
        {
            if (!long.TryParse(b, NumberStyles.None, CultureInfo.InvariantCulture, out long suffix) || suffix < 0) return false;
            if (suffix == 0) { unsatisfiable = true; return false; }
            start = Math.Max(0, total - suffix); end = total - 1;
        }
        else
        {
            if (!long.TryParse(a, NumberStyles.None, CultureInfo.InvariantCulture, out start) || start < 0) return false;
            if (b.Length == 0) end = total - 1;
            else if (!long.TryParse(b, NumberStyles.None, CultureInfo.InvariantCulture, out end) || end < start) return false;
            if (start >= total) { unsatisfiable = true; return false; }
            if (end >= total) end = total - 1;
        }
        return true;
    }

    internal static string AsciiName(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (char c in name)
            sb.Append(c is '"' or '\\' or < ' ' or > (char)126 ? '_' : c);
        return sb.ToString();
    }

    public static string HumanSize(long bytes)
    {
        string[] u = { "B", "KB", "MB", "GB", "TB" };
        double v = bytes; int i = 0;
        while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
        return i == 0 ? $"{bytes} B" : $"{v:0.#} {u[i]}";
    }

    // Minimal MIME map — default is octet-stream (forces a download, which is what we want anyway).
    public static string GuessContentType(string name)
    {
        string ext = Path.GetExtension(name).ToLowerInvariant();
        return ext switch
        {
            ".txt" or ".log" or ".md" or ".csv" => "text/plain; charset=utf-8",
            ".html" or ".htm" => "text/html; charset=utf-8",
            ".json" => "application/json",
            ".xml" => "application/xml",
            ".pdf" => "application/pdf",
            ".zip" => "application/zip",
            ".png" => "image/png",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".gif" => "image/gif",
            ".webp" => "image/webp",
            ".svg" => "image/svg+xml",
            ".mp4" => "video/mp4",
            ".webm" => "video/webm",
            ".mp3" => "audio/mpeg",
            ".wav" => "audio/wav",
            ".apk" => "application/vnd.android.package-archive",
            _ => "application/octet-stream",
        };
    }
}
