using System;
using System.Buffers;
using System.Globalization;
using System.IO;
using System.Text;

namespace Echoes.Helpers;

/// <summary>Line ending the Socket tool appends to text it sends.</summary>
public enum LineEnding { None = 0, Lf = 1, CrLf = 2 }

/// <summary>
/// Byte handling for the Socket tool, UI-free: what the send box turns into on the wire (text + line ending, or
/// lenient hex) and how bytes are shown (text with control bytes escaped, hex string, hex dump).
/// </summary>
public static class SocketPayload
{
    private static readonly UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false);
    private const string HexDigits = "0123456789abcdef";

    /// <summary>
    /// Text as typed → bytes (UTF-8). Line breaks typed inside the message (Shift+Enter) become the chosen line
    /// ending too, and one more is appended — so "GET / HTTP/1.1", "Host: x", "" with CRLF goes out exactly as an
    /// HTTP request. With no line ending the text goes out as typed (inner breaks as LF).
    /// </summary>
    public static byte[] FromText(string? text, LineEnding eol)
    {
        string norm = (text ?? string.Empty).Replace("\r\n", "\n").Replace('\r', '\n');
        if (eol != LineEnding.None)
        {
            string nl = eol == LineEnding.CrLf ? "\r\n" : "\n";
            norm = (eol == LineEnding.CrLf ? norm.Replace("\n", "\r\n") : norm) + nl;
        }
        return Utf8.GetBytes(norm);
    }

    /// <summary>Hex as typed ("48 65 6c", "0x48,0x65", "48656c", "\x48") → bytes. Throws <see cref="FormatException"/>
    /// with a message that says what is wrong.</summary>
    public static byte[] FromHex(string? hex) => TextBytes.ParseHexLenient(hex ?? string.Empty);

    /// <summary>
    /// True when the bytes read as text: valid UTF-8 (a multi-byte character cut at the end of a TCP chunk still
    /// counts) with at most 1 in 20 control bytes (tab, CR and LF don't count).
    /// </summary>
    public static bool LooksLikeText(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return true;
        int controls = 0, i = 0;
        while (i < data.Length)
        {
            var status = Rune.DecodeFromUtf8(data[i..], out var rune, out int used);
            if (status == OperationStatus.NeedMoreData) break;   // truncated at the very end: fine
            if (status != OperationStatus.Done) return false;
            int v = rune.Value;
            if ((v < 0x20 && v is not (9 or 10 or 13)) || v == 0x7F) controls++;
            i += used;
        }
        return controls * 20 <= data.Length;
    }

    /// <summary>
    /// Bytes as readable text: UTF-8 with line breaks kept (CRLF shown as one break) and tabs kept; every other
    /// control byte, and every byte that isn't valid UTF-8, escaped (\0, \r, \x1b …). Trailing line breaks are left
    /// off — each transcript entry is its own block, and the byte count and the hex view keep the exact bytes.
    /// At most <paramref name="maxChars"/> characters and <paramref name="maxLines"/> lines; <paramref name="shownBytes"/>
    /// says how much was rendered.
    /// </summary>
    public static string ToDisplayText(ReadOnlySpan<byte> data, int maxChars, out int shownBytes, int maxLines = int.MaxValue)
    {
        int end = data.Length;
        while (end > 0 && (data[end - 1] == (byte)'\n' || data[end - 1] == (byte)'\r')) end--;
        var sb = new StringBuilder(Math.Min(end, maxChars) + 16);
        int i = 0, lines = 1;
        while (i < end && sb.Length < maxChars)
        {
            byte b = data[i];
            if (b < 0x80)
            {
                if ((b == (byte)'\n' || b == (byte)'\r' && i + 1 < end && data[i + 1] == (byte)'\n') && ++lines > maxLines) break;
                switch (b)
                {
                    case (byte)'\n': sb.Append('\n'); break;
                    case (byte)'\t': sb.Append('\t'); break;
                    case (byte)'\r':
                        if (i + 1 < end && data[i + 1] == (byte)'\n') { sb.Append('\n'); i++; }
                        else sb.Append("\\r");
                        break;
                    case 0: sb.Append("\\0"); break;
                    case 0x1B: sb.Append("\\e"); break;
                    default:
                        if (b < 0x20 || b == 0x7F) AppendHexEscape(sb, b);
                        else sb.Append((char)b);
                        break;
                }
                i++;
                continue;
            }
            var status = Rune.DecodeFromUtf8(data[i..end], out var rune, out int used);
            if (status == OperationStatus.Done && !Rune.IsControl(rune) && !IsHiddenControl(rune.Value))
            {
                sb.Append(rune.ToString());
                i += used;
            }
            else
            {
                AppendHexEscape(sb, b);   // invalid / truncated sequence, a C1 or bidi control: one byte at a time
                i++;
            }
        }
        shownBytes = i >= end ? data.Length : i;
        return sb.ToString();
    }

    /// <summary>One line, C-style: printable ASCII as is, \r \n \t \0 \\ escaped, everything else \xNN.
    /// For pasting into code or a shell (printf / echo -e).</summary>
    public static string ToEscaped(ReadOnlySpan<byte> data)
    {
        var sb = new StringBuilder(data.Length + 16);
        foreach (byte b in data)
        {
            switch (b)
            {
                case (byte)'\r': sb.Append("\\r"); break;
                case (byte)'\n': sb.Append("\\n"); break;
                case (byte)'\t': sb.Append("\\t"); break;
                case 0: sb.Append("\\0"); break;
                case (byte)'\\': sb.Append("\\\\"); break;
                case (byte)'"': sb.Append("\\\""); break;
                default:
                    if (b is >= 0x20 and < 0x7F) sb.Append((char)b);
                    else AppendHexEscape(sb, b);
                    break;
            }
        }
        return sb.ToString();
    }

    /// <summary>"48 65 6c 6c 6f" — what the hex send box accepts back.</summary>
    public static string ToHexString(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return string.Empty;
        var chars = new char[data.Length * 3 - 1];
        for (int i = 0, c = 0; i < data.Length; i++)
        {
            if (i > 0) chars[c++] = ' ';
            chars[c++] = HexDigits[data[i] >> 4];
            chars[c++] = HexDigits[data[i] & 0xF];
        }
        return new string(chars);
    }

    /// <summary>The <c>hexdump -C</c> layout used for copy / save (16 bytes a line, ASCII column).</summary>
    public static string HexDump(ReadOnlySpan<byte> data) => TextBytes.HexDump(data);

    /// <summary>12 B · 1.4 KB · 3.2 MB</summary>
    public static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return bytes.ToString(CultureInfo.InvariantCulture) + " B";
        double v = bytes / 1024.0;
        if (v < 1024) return v.ToString(v < 10 ? "0.0" : "0", CultureInfo.InvariantCulture) + " KB";
        v /= 1024;
        if (v < 1024) return v.ToString(v < 10 ? "0.0" : "0", CultureInfo.InvariantCulture) + " MB";
        return (v / 1024).ToString("0.0", CultureInfo.InvariantCulture) + " GB";
    }

    private static void AppendHexEscape(StringBuilder sb, byte b)
        => sb.Append("\\x").Append(HexDigits[b >> 4]).Append(HexDigits[b & 0xF]);

    // Bidi embeddings, overrides and isolates (U+202A–U+202E, U+2066–U+2069) change the order the text around them is
    // drawn in, so a peer could make a transcript line read differently from the bytes it sent: they are escaped like
    // other invisible controls. LRM / RLM / ZWNJ are kept — ordinary Persian and Arabic text uses them. The line and
    // paragraph separators (U+2028 / U+2029) break a line like LF without being one, and U+FEFF is invisible: escaped too.
    private static bool IsHiddenControl(int cp)
        => cp is (>= 0x202A and <= 0x202E) or (>= 0x2066 and <= 0x2069) or 0x2028 or 0x2029 or 0xFEFF;

    /// <summary>Writes a name a file system accepts (the transcript's suggested file name).</summary>
    public static string SafeFileName(string s)
    {
        var bad = Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(s.Length);
        foreach (char ch in s) sb.Append(Array.IndexOf(bad, ch) >= 0 || ch is ':' or '[' or ']' or ' ' ? '_' : ch);
        return sb.ToString();
    }
}
