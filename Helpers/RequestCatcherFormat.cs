using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace Echoes.Helpers;

public enum CatcherBodyKind { None, Json, Form, Multipart, Text, Binary }

/// <summary>A name / value line of the details pane (header, query parameter, form field, multipart part).</summary>
public sealed class CatcherField
{
    public CatcherField(string name, string value, string? detail = null)
    {
        Name = name;
        Value = value;
        Detail = detail;
    }

    public string Name { get; }
    public string Value { get; }
    /// <summary>"photo.png · image/png · 12 KB" for a multipart file part.</summary>
    public string? Detail { get; }
    public bool HasDetail => !string.IsNullOrEmpty(Detail);
}

/// <summary>How a captured body reads: pretty JSON, form fields, multipart parts, text, or bytes for a hex dump.</summary>
public sealed class CatcherBodyView
{
    public CatcherBodyKind Kind { get; init; }
    /// <summary>"JSON · 1.2 KB", "Form · 3 fields", "Binary · 512 B".</summary>
    public string Label { get; init; } = string.Empty;
    public string? Text { get; init; }
    public IReadOnlyList<CatcherField>? Fields { get; init; }
    public byte[]? Bytes { get; init; }
    public string? Note { get; init; }
}

/// <summary>Turns captured requests into what the catcher's details pane shows, and into a curl command.</summary>
public static class CatcherFormat
{
    /// <summary>Longest text the details pane renders (copy still gets the whole body).</summary>
    public const int MaxTextChars = 100_000;
    /// <summary>Longest name / value of one field (header, query parameter, form field, part) the details pane renders.</summary>
    public const int MaxNameChars = 300, MaxValueChars = 4000;

    private static readonly JsonWriterOptions Pretty = new()
    {
        Indented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,   // keep non-ASCII readable (display only)
    };

    // ================================================================ body

    public static CatcherBodyView Body(CapturedRequest r)
    {
        byte[] b = r.Body;
        string size = SocketPayload.FormatBytes(r.BodyLength);
        string? cut = r.BodyTruncated ? $"Showing the first {SocketPayload.FormatBytes(b.Length)} of {size}." : null;
        if (r.BodyLength == 0 && b.Length == 0)
            return new CatcherBodyView { Kind = CatcherBodyKind.None, Label = "No body" };

        string ct = (r.Kind == CaptureKind.WsMessage ? (r.IsText ? "text/plain" : "application/octet-stream") : r.Header("Content-Type") ?? string.Empty).ToLowerInvariant();
        bool textish = SocketPayload.LooksLikeText(b);

        // JSON: declared, or a text body that starts like JSON
        bool jsonType = ct.Contains("json", StringComparison.Ordinal);
        string trimmed = textish ? TrimStart(b) : string.Empty;
        if (!r.BodyTruncated && (jsonType || (textish && trimmed.Length > 0 && trimmed[0] is '{' or '[')))
        {
            string? pretty = PrettyJson(b, out string? err);
            if (pretty != null)
                return new CatcherBodyView { Kind = CatcherBodyKind.Json, Label = "JSON · " + size, Text = EscapeUnsafe(Cap(pretty, out string? capNote)), Note = capNote };
            if (jsonType && textish)
                return TextView(b, size, "Not valid JSON: " + err + " — shown as text.");
        }

        if (ct.StartsWith("application/x-www-form-urlencoded", StringComparison.Ordinal) && textish)
        {
            // capped like headers / query: one 1 MB value in a wrapping text block would stall the UI thread
            var fields = Pairs(Encoding.UTF8.GetString(b), plusIsSpace: true)
                .Select(kv => new CatcherField(WsProtocol.Short(kv.Key, MaxNameChars), WsProtocol.Short(kv.Value, MaxValueChars))).ToList();
            return new CatcherBodyView { Kind = CatcherBodyKind.Form, Label = $"Form · {Plural(fields.Count, "field")} · {size}", Fields = fields, Note = cut };
        }

        if (ct.StartsWith("multipart/", StringComparison.Ordinal) && Boundary(r.Header("Content-Type")) is { } boundary)
        {
            var parts = Multipart(b, boundary);
            if (parts.Count > 0)
                return new CatcherBodyView { Kind = CatcherBodyKind.Multipart, Label = $"Multipart · {Plural(parts.Count, "part")} · {size}", Fields = parts, Note = cut };
        }

        if (textish) return TextView(b, size, cut);
        return new CatcherBodyView { Kind = CatcherBodyKind.Binary, Label = "Binary · " + size, Bytes = b, Note = cut };
    }

    private static CatcherBodyView TextView(byte[] b, string size, string? note)
    {
        string t = SocketPayload.ToDisplayText(b, MaxTextChars, out int shown);
        if (shown < b.Length) note = (note == null ? "" : note + " ") + $"Showing the first {MaxTextChars:N0} characters.";
        return new CatcherBodyView { Kind = CatcherBodyKind.Text, Label = "Text · " + size, Text = t, Note = note };
    }

    private static string Cap(string s, out string? note)
    {
        note = null;
        if (s.Length <= MaxTextChars) return s;
        note = $"Showing the first {MaxTextChars:N0} characters — copy the body for all of it.";
        int cut = MaxTextChars;
        if (char.IsHighSurrogate(s[cut - 1])) cut--;
        return s[..cut];
    }

    // Pretty JSON keeps non-ASCII readable, so bidi controls / C1 controls / separators inside strings would reach the
    // text block raw (and reorder or break what follows): shown as their JSON escape instead.
    private static string EscapeUnsafe(string s)
    {
        int i = 0;
        while (i < s.Length && (s[i] is '\r' or '\n' or '\t' || !RequestCatcher.IsUnsafeDisplay(s[i]))) i++;
        if (i == s.Length) return s;
        var sb = new StringBuilder(s.Length + 16).Append(s, 0, i);
        for (; i < s.Length; i++)
        {
            char c = s[i];
            if (c is '\r' or '\n' or '\t' || !RequestCatcher.IsUnsafeDisplay(c)) sb.Append(c);
            else sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
        }
        return sb.ToString();
    }

    private static string TrimStart(byte[] b)
    {
        int i = 0;
        if (b.Length >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF) i = 3;   // BOM
        while (i < b.Length && b[i] is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n') i++;
        return i < b.Length ? ((char)b[i]).ToString() : string.Empty;
    }

    /// <summary>Indented JSON, or null + the reason ("line 3, position 12: …").</summary>
    public static string? PrettyJson(ReadOnlySpan<byte> utf8, out string? error)
    {
        error = null;
        if (utf8.Length >= 3 && utf8[0] == 0xEF && utf8[1] == 0xBB && utf8[2] == 0xBF) utf8 = utf8[3..];
        try
        {
            var reader = new Utf8JsonReader(utf8, new JsonReaderOptions { CommentHandling = JsonCommentHandling.Skip, MaxDepth = 256 });
            using var ms = new MemoryStream(utf8.Length * 2 + 16);
            using (var w = new Utf8JsonWriter(ms, Pretty))
            {
                while (reader.Read())
                {
                    switch (reader.TokenType)
                    {
                        case JsonTokenType.StartObject: w.WriteStartObject(); break;
                        case JsonTokenType.EndObject: w.WriteEndObject(); break;
                        case JsonTokenType.StartArray: w.WriteStartArray(); break;
                        case JsonTokenType.EndArray: w.WriteEndArray(); break;
                        case JsonTokenType.PropertyName: w.WritePropertyName(reader.GetString()!); break;
                        case JsonTokenType.String: w.WriteStringValue(reader.GetString()); break;
                        case JsonTokenType.Number:
                            // the number exactly as written (no double round trip: big ids stay intact)
                            w.WriteRawValue(reader.ValueSpan, skipInputValidation: true);
                            break;
                        case JsonTokenType.True: w.WriteBooleanValue(true); break;
                        case JsonTokenType.False: w.WriteBooleanValue(false); break;
                        case JsonTokenType.Null: w.WriteNullValue(); break;
                    }
                }
            }
            if (reader.BytesConsumed == 0) { error = "it's empty"; return null; }
            return Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);
        }
        catch (JsonException ex)
        {
            error = ex.LineNumber is long ln && ex.BytePositionInLine is long pos
                ? $"line {ln + 1}, position {pos + 1}"
                : "the text isn't JSON";
            return null;
        }
        catch (InvalidOperationException)
        {
            error = "the text isn't JSON";
            return null;
        }
    }

    /// <summary>"a=1&amp;b=x%20y" → pairs (decoded; '+' as a space for forms).</summary>
    public static List<KeyValuePair<string, string>> Pairs(string s, bool plusIsSpace)
    {
        var list = new List<KeyValuePair<string, string>>();
        foreach (var part in s.Split('&'))
        {
            if (part.Length == 0) continue;
            int eq = part.IndexOf('=');
            string k = eq >= 0 ? part[..eq] : part;
            string v = eq >= 0 ? part[(eq + 1)..] : string.Empty;
            list.Add(new KeyValuePair<string, string>(Decode(k, plusIsSpace), Decode(v, plusIsSpace)));
            if (list.Count >= 1000) break;
        }
        return list;
    }

    private static string Decode(string s, bool plus)
    {
        if (plus) s = s.Replace('+', ' ');
        try { return RequestCatcher.Printable(Uri.UnescapeDataString(s)); }
        catch { return RequestCatcher.Printable(s); }
    }

    public static string? Boundary(string? contentType)
    {
        if (contentType == null) return null;
        foreach (var p in contentType.Split(';'))
        {
            string t = p.Trim();
            if (!t.StartsWith("boundary=", StringComparison.OrdinalIgnoreCase)) continue;
            string b = t[9..].Trim().Trim('"');
            return b.Length is > 0 and <= 200 ? b : null;
        }
        return null;
    }

    /// <summary>multipart/form-data parts: name → value (text) or a size line; file name and type in the detail.</summary>
    public static List<CatcherField> Multipart(byte[] body, string boundary)
    {
        var list = new List<CatcherField>();
        byte[] delim = Encoding.ASCII.GetBytes("--" + boundary);
        var span = body.AsSpan();
        int pos = span.IndexOf(delim);
        while (pos >= 0 && list.Count < 200)
        {
            int start = pos + delim.Length;
            if (start + 2 <= span.Length && span[start] == '-' && span[start + 1] == '-') break;   // closing delimiter
            if (start + 2 <= span.Length && span[start] == '\r' && span[start + 1] == '\n') start += 2;
            int next = span[start..].IndexOf(delim);
            int end = next >= 0 ? start + next : span.Length;
            var part = span[start..end];
            if (part.Length >= 2 && part[^2] == '\r' && part[^1] == '\n') part = part[..^2];
            int hdrEnd = part.IndexOf("\r\n\r\n"u8);
            string headers = hdrEnd >= 0 ? Encoding.UTF8.GetString(part[..hdrEnd]) : string.Empty;
            var content = hdrEnd >= 0 ? part[(hdrEnd + 4)..] : part;
            string name = "(unnamed)", file = string.Empty, type = string.Empty;
            foreach (var line in headers.Split("\r\n"))
            {
                if (line.StartsWith("Content-Disposition:", StringComparison.OrdinalIgnoreCase))
                {
                    name = Param(line, "name") ?? name;
                    file = Param(line, "filename") ?? file;
                }
                else if (line.StartsWith("Content-Type:", StringComparison.OrdinalIgnoreCase)) type = line[13..].Trim();
            }
            bool text = file.Length == 0 && SocketPayload.LooksLikeText(content);
            string value = text
                ? SocketPayload.ToDisplayText(content, 4000, out _)
                : $"({SocketPayload.FormatBytes(content.Length)}{(SocketPayload.LooksLikeText(content) ? " of text" : " binary")})";
            string? detail = file.Length > 0 || type.Length > 0
                ? string.Join(" · ", new[] { WsProtocol.Short(file, 200), WsProtocol.Short(type, 100), SocketPayload.FormatBytes(content.Length) }.Where(x => x.Length > 0))
                : null;
            list.Add(new CatcherField(RequestCatcher.Printable(WsProtocol.Short(name, MaxNameChars)), value, detail is null ? null : RequestCatcher.Printable(detail)));
            if (next < 0) break;
            pos = start + next;
        }
        return list;
    }

    private static string? Param(string header, string key)
    {
        foreach (var p in header.Split(';'))
        {
            string t = p.Trim();
            if (t.StartsWith(key + "=", StringComparison.OrdinalIgnoreCase))
                return t[(key.Length + 1)..].Trim().Trim('"');
        }
        return null;
    }

    private static string Plural(int n, string unit) => n == 1 ? $"1 {unit}" : $"{n} {unit}s";

    // ================================================================ curl

    private static readonly string[] SkipHeaders =
    {
        "Host", "Content-Length", "Connection", "Transfer-Encoding", "Expect", "Keep-Alive", "Proxy-Connection", "TE",
    };

    /// <summary>
    /// A curl command that sends the same request again: method, URL (from the Host header, else
    /// <paramref name="fallbackAuthority"/>), headers, and the body (text with --data-raw, bytes through printf).
    /// </summary>
    public static string Curl(CapturedRequest r, string fallbackAuthority)
    {
        string host = r.Header("Host") is { Length: > 0 } h && h.All(c => c > 0x20 && c < 0x7F) ? h : fallbackAuthority;
        string url = r.Target.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || r.Target.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            ? r.Target
            : "http://" + host + (r.Target.StartsWith('/') ? r.Target : "/" + r.Target);
        var lines = new List<string>();
        byte[] body = r.Body;
        bool hasBody = body.Length > 0;
        bool binary = hasBody && (!SocketPayload.LooksLikeText(body) || Array.IndexOf(body, (byte)0) >= 0);

        string first = "curl";
        if (r.Method == "HEAD") first += " -I";
        // The method came from the network too: an HTTP token may hold ` $ | & ' ! ^, so anything but plain letters is quoted.
        else if (r.Method != "GET" || hasBody) first += " -X " + (r.Method.All(char.IsAsciiLetterUpper) ? r.Method : Quote(r.Method));
        first += " " + Quote(url);
        lines.Add(first);
        foreach (var kv in r.Headers)
        {
            if (SkipHeaders.Any(s => s.Equals(kv.Key, StringComparison.OrdinalIgnoreCase))) continue;
            lines.Add("-H " + Quote(kv.Key + ": " + kv.Value));
        }
        string prefix = string.Empty;
        if (hasBody)
        {
            if (binary)
            {
                prefix = "printf '%b' " + Quote(PrintfEscape(body)) + " | ";
                lines.Add("--data-binary @-");
            }
            else lines.Add("--data-raw " + Quote(Encoding.UTF8.GetString(body)));
        }
        string cmd = prefix + string.Join(" \\\n  ", lines);
        if (r.BodyTruncated)
            cmd = $"# note: only the first {SocketPayload.FormatBytes(body.Length)} of the {SocketPayload.FormatBytes(r.BodyLength)} body was kept\n" + cmd;
        return cmd;
    }

    /// <summary>
    /// One shell word for the copied command (all of it comes from the network). Plain text: POSIX single quotes, a
    /// quote inside written '"'"' — the usual '\'' would leave what follows it unquoted if the command were pasted into
    /// PowerShell. Text holding control, C1 or bidi characters (a terminal acts on those when they are pasted): ANSI-C
    /// quoting $'…' with each of them escaped, so the clipboard never carries them raw.
    /// </summary>
    public static string Quote(string s)
    {
        bool special = false;
        foreach (char c in s)
            // a backslash too: fish reads \' inside '…' as an escaped quote, so a value ending in \ would leave the
            // string open there; $'…' escapes it (bash / zsh), and fish refuses $'…' outright instead of running it
            if (c == '\\' || (c is not ('\n' or '\t') && RequestCatcher.IsUnsafeDisplay(c))) { special = true; break; }
        if (!special) return "'" + s.Replace("'", "'\"'\"'") + "'";
        var sb = new StringBuilder(s.Length + 16).Append("$'");
        foreach (char c in s)
        {
            switch (c)
            {
                case '\\': sb.Append("\\\\"); break;
                case '\'': sb.Append("\\x27"); break;
                case '\n': sb.Append("\\n"); break;
                case '\t': sb.Append("\\t"); break;
                case '\r': sb.Append("\\r"); break;
                default:
                    if (c < 0x20 || c == 0x7F) sb.Append("\\x").Append(((int)c).ToString("x2", CultureInfo.InvariantCulture));
                    else if (RequestCatcher.IsUnsafeDisplay(c)) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else sb.Append(c);
                    break;
            }
        }
        return sb.Append('\'').ToString();
    }

    private static string PrintfEscape(byte[] data)
    {
        var sb = new StringBuilder(data.Length * 2);
        foreach (byte b in data)
        {
            if (b == (byte)'\\') sb.Append("\\\\");
            else if (b is >= 0x20 and < 0x7F && b != (byte)'\'') sb.Append((char)b);
            else sb.Append("\\x").Append(b.ToString("x2", CultureInfo.InvariantCulture));
        }
        return sb.ToString();
    }
}
