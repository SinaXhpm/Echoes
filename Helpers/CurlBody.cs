using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace Echoes.Helpers;

/// <summary>What a response body is, for picking its view.</summary>
public enum CurlBodyKind { Empty, Json, Xml, Html, Text, Image, Binary }

/// <summary>One Set-Cookie of a response.</summary>
public sealed record CurlCookie(string Name, string Value, string Attributes);

/// <summary>Response body helpers: decoding, sniffing, pretty-printing, cookies, a file name to save under. Pure (no UI).</summary>
public static class CurlBody
{
    /// <summary>Bodies above this are shown raw only (pretty-printing them would double the memory for little gain).</summary>
    public const int PrettyLimit = 8 * 1024 * 1024;

    public static string? CharsetOf(string? contentType)
    {
        if (string.IsNullOrEmpty(contentType)) return null;
        return System.Net.Http.Headers.MediaTypeHeaderValue.TryParse(contentType, out var mt) ? mt.CharSet : null;
    }

    public static string MediaTypeOf(string? contentType)
    {
        if (string.IsNullOrEmpty(contentType)) return string.Empty;
        int semi = contentType.IndexOf(';');
        return (semi >= 0 ? contentType[..semi] : contentType).Trim().ToLowerInvariant();
    }

    /// <summary>Bytes → text. A BOM wins (as in browsers), then the response's charset (legacy code pages resolve through
    /// the CodePagesEncodingProvider registered at startup), then UTF-8. A body cut at the cap says so.</summary>
    public static string Decode(byte[] buf, int len, string? charset, bool truncated)
    {
        len = Math.Clamp(len, 0, buf.Length);
        Encoding enc;
        int skip = 0;
        if (len >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF) { enc = Encoding.UTF8; skip = 3; }
        else if (len >= 2 && buf[0] == 0xFF && buf[1] == 0xFE) { enc = Encoding.Unicode; skip = 2; }
        else if (len >= 2 && buf[0] == 0xFE && buf[1] == 0xFF) { enc = Encoding.BigEndianUnicode; skip = 2; }
        else enc = ResolveCharset(charset);
        string text = enc.GetString(buf, skip, Math.Max(0, len - skip));
        if (truncated) text += $"\n\n… [response truncated at {CurlEngine.MaxResponseBytes / (1024 * 1024)} MB]";
        return text;
    }

    private static Encoding ResolveCharset(string? charset)
    {
        if (!string.IsNullOrWhiteSpace(charset))
        {
            try { return Encoding.GetEncoding(charset.Trim().Trim('"')); } catch { }
        }
        return Encoding.UTF8;
    }

    public static CurlBodyKind Sniff(byte[] buf, int len, string? contentType)
    {
        len = Math.Clamp(len, 0, buf.Length);
        if (len == 0) return CurlBodyKind.Empty;
        string mt = MediaTypeOf(contentType);
        if (mt is "image/png" or "image/jpeg" or "image/jpg" or "image/gif" or "image/webp" or "image/bmp" or "image/x-icon" or "image/vnd.microsoft.icon")
            return CurlBodyKind.Image;
        if (mt.EndsWith("/json", StringComparison.Ordinal) || mt.EndsWith("+json", StringComparison.Ordinal)) return CurlBodyKind.Json;
        if (mt == "text/html" || mt == "application/xhtml+xml") return CurlBodyKind.Html;
        if (mt.EndsWith("/xml", StringComparison.Ordinal) || mt.EndsWith("+xml", StringComparison.Ordinal)) return CurlBodyKind.Xml;
        if (mt.StartsWith("image/", StringComparison.Ordinal) || mt.StartsWith("audio/", StringComparison.Ordinal)
            || mt.StartsWith("video/", StringComparison.Ordinal) || mt.StartsWith("font/", StringComparison.Ordinal)
            || mt is "application/octet-stream" or "application/pdf" or "application/zip" or "application/gzip" or "application/x-gzip"
                or "application/wasm" or "application/x-protobuf" or "application/protobuf" or "application/msgpack")
            return LooksBinary(buf, len) ? CurlBodyKind.Binary : CurlBodyKind.Text;
        if (LooksBinary(buf, len)) return ImageMagic(buf, len) ? CurlBodyKind.Image : CurlBodyKind.Binary;
        if (mt.StartsWith("text/", StringComparison.Ordinal) && mt != "text/plain") return CurlBodyKind.Text;

        // no (useful) Content-Type: look at the first non-blank byte
        int i = 0;
        if (len >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF) i = 3;
        while (i < len && buf[i] is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n') i++;
        if (i < len && (buf[i] == '{' || buf[i] == '['))
        {
            try { using var _ = JsonDocument.Parse(buf.AsMemory(0, len)); return CurlBodyKind.Json; } catch { }
        }
        if (i < len && buf[i] == '<')
        {
            string head = Encoding.ASCII.GetString(buf, i, Math.Min(256, len - i)).ToLowerInvariant();
            return head.StartsWith("<!doctype html", StringComparison.Ordinal) || head.StartsWith("<html", StringComparison.Ordinal)
                ? CurlBodyKind.Html : CurlBodyKind.Xml;
        }
        return CurlBodyKind.Text;
    }

    // NUL bytes or many control characters in the first 8 KB = not text.
    private static bool LooksBinary(byte[] buf, int len)
    {
        int n = Math.Min(len, 8192), ctl = 0;
        for (int i = 0; i < n; i++)
        {
            byte b = buf[i];
            if (b == 0) return true;
            if (b < 0x09 || (b > 0x0D && b < 0x20)) ctl++;
        }
        return n > 0 && ctl * 10 > n;
    }

    private static bool ImageMagic(byte[] b, int len) =>
        (len > 8 && b[0] == 0x89 && b[1] == 'P' && b[2] == 'N' && b[3] == 'G') ||
        (len > 3 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF) ||
        (len > 6 && b[0] == 'G' && b[1] == 'I' && b[2] == 'F') ||
        (len > 12 && b[0] == 'R' && b[1] == 'I' && b[2] == 'F' && b[3] == 'F' && b[8] == 'W' && b[9] == 'E' && b[10] == 'B' && b[11] == 'P');

    /// <summary>Indented JSON (2 spaces, non-ASCII kept readable), or null when it isn't valid JSON.</summary>
    public static string? PrettyJson(byte[] buf, int len)
    {
        len = Math.Clamp(len, 0, buf.Length);
        if (len == 0 || len > PrettyLimit) return null;
        try
        {
            int skip = len >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF ? 3 : 0;
            using var doc = JsonDocument.Parse(buf.AsMemory(skip, len - skip), new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip, MaxDepth = 256 });
            return Indent(doc);
        }
        catch { return null; }
    }

    /// <summary>The same for text (the request body's Format button). Null when invalid.</summary>
    public static string? PrettyJson(string text)
    {
        try
        {
            using var doc = JsonDocument.Parse(text, new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip, MaxDepth = 256 });
            return Indent(doc);
        }
        catch { return null; }
    }

    private static string Indent(JsonDocument doc)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping, SkipValidation = true }))
            doc.WriteTo(w);
        return Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);
    }

    /// <summary>Where a JSON text is broken ("Line 3, column 7: …"), or null when it's valid.</summary>
    public static string? JsonError(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        try
        {
            using var _ = JsonDocument.Parse(text, new JsonDocumentOptions { AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow, MaxDepth = 256 });
            return null;
        }
        catch (JsonException ex)
        {
            string where = ex.LineNumber is long line ? $"Line {line + 1}, column {(ex.BytePositionInLine ?? 0) + 1}" : "Invalid JSON";
            string msg = ex.Message;
            int cut = msg.IndexOf(" LineNumber:", StringComparison.Ordinal);
            if (cut > 0) msg = msg[..cut];
            msg = msg.TrimEnd('.', ' ');
            return $"{where}: {msg}";
        }
    }

    /// <summary>Indented XML, or null when it isn't well-formed. DTDs are ignored (no external entities, no entity bombs).</summary>
    public static string? PrettyXml(string text)
    {
        if (text.Length == 0 || text.Length > PrettyLimit) return null;
        try
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore, XmlResolver = null, MaxCharactersFromEntities = 1024 };
            using var sr = new StringReader(text);
            using var reader = XmlReader.Create(sr, settings);
            var doc = XDocument.Load(reader);
            string body = doc.ToString(SaveOptions.None);
            return doc.Declaration != null ? doc.Declaration + "\n" + body : body;
        }
        catch { return null; }
    }

    public static string? XmlError(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        try
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore, XmlResolver = null, MaxCharactersFromEntities = 1024 };
            using var sr = new StringReader(text);
            using var reader = XmlReader.Create(sr, settings);
            while (reader.Read()) { }
            return null;
        }
        catch (XmlException ex) { return $"Line {ex.LineNumber}, column {ex.LinePosition}: {ex.Message.Split(" Line ")[0].TrimEnd('.', ' ')}"; }
        catch (Exception ex) { return ex.Message; }
    }

    /// <summary>A classic hex dump (offset · 16 bytes · ASCII) of the first <paramref name="max"/> bytes.</summary>
    public static string HexDump(byte[] buf, int len, int max = 64 * 1024)
    {
        len = Math.Clamp(len, 0, buf.Length);
        int n = Math.Min(len, max);
        var sb = new StringBuilder(n * 4 + 64);
        for (int off = 0; off < n; off += 16)
        {
            sb.Append(off.ToString("x8")).Append("  ");
            for (int k = 0; k < 16; k++)
            {
                if (off + k < n) sb.Append(buf[off + k].ToString("x2")).Append(' ');
                else sb.Append("   ");
                if (k == 7) sb.Append(' ');
            }
            sb.Append(' ');
            for (int k = 0; k < 16 && off + k < n; k++)
            {
                byte b = buf[off + k];
                sb.Append(b is >= 0x20 and < 0x7F ? (char)b : '.');
            }
            sb.Append('\n');
        }
        if (len > n) sb.Append($"… {len - n:N0} more bytes — Save to keep the whole body");
        return sb.ToString();
    }

    public static List<CurlCookie> SetCookies(IEnumerable<(string Name, string Value)> headers)
    {
        var list = new List<CurlCookie>();
        foreach (var (n, v) in headers)
        {
            if (!n.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase)) continue;
            int semi = v.IndexOf(';');
            string pair = semi >= 0 ? v[..semi] : v;
            string attrs = semi >= 0 ? v[(semi + 1)..].Trim() : string.Empty;
            int eq = pair.IndexOf('=');
            string name = eq >= 0 ? pair[..eq].Trim() : pair.Trim();
            string value = eq >= 0 ? pair[(eq + 1)..].Trim() : string.Empty;
            list.Add(new CurlCookie(name, value, string.Join(" · ", attrs.Split(';').Select(a => a.Trim()).Where(a => a.Length > 0))));
        }
        return list;
    }

    /// <summary>A file name to save the body under: Content-Disposition's, else the URL's last path segment, with an
    /// extension that matches the Content-Type.</summary>
    public static string SuggestFileName(string url, string? contentType, string? contentDisposition)
    {
        string? name = null;
        if (!string.IsNullOrEmpty(contentDisposition)
            && System.Net.Http.Headers.ContentDispositionHeaderValue.TryParse(contentDisposition, out var cd))
            name = (cd.FileNameStar ?? cd.FileName)?.Trim('"');
        if (string.IsNullOrWhiteSpace(name) && Uri.TryCreate(url, UriKind.Absolute, out var u))
        {
            string seg = u.Segments.Length > 0 ? Uri.UnescapeDataString(u.Segments[^1]).Trim('/') : string.Empty;
            if (seg.Length > 0) name = seg;
        }
        if (string.IsNullOrWhiteSpace(name)) name = "response";
        foreach (char c in Path.GetInvalidFileNameChars()) name = name.Replace(c, '_');
        if (name.Length > 120) name = name[..120];
        if (Path.GetExtension(name).Length == 0) name += ExtensionFor(contentType);
        return name;
    }

    public static string ExtensionFor(string? contentType) => MediaTypeOf(contentType) switch
    {
        var m when m.EndsWith("/json", StringComparison.Ordinal) || m.EndsWith("+json", StringComparison.Ordinal) => ".json",
        "text/html" or "application/xhtml+xml" => ".html",
        var m when m.EndsWith("/xml", StringComparison.Ordinal) || m.EndsWith("+xml", StringComparison.Ordinal) => m == "image/svg+xml" ? ".svg" : ".xml",
        "text/css" => ".css",
        "text/csv" => ".csv",
        "application/javascript" or "text/javascript" => ".js",
        "image/png" => ".png",
        "image/jpeg" => ".jpg",
        "image/gif" => ".gif",
        "image/webp" => ".webp",
        "application/pdf" => ".pdf",
        "application/zip" => ".zip",
        "application/gzip" or "application/x-gzip" => ".gz",
        "text/plain" => ".txt",
        "" => ".txt",
        _ => ".bin",
    };
}
