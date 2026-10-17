using System;
using System.Globalization;
using System.Security;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace Echoes.Helpers;

/// <summary>
/// Escape / unescape helpers for String Lab's ESCAPE tab (and the Text Lab separator field).
/// Everything here is plain string walking — no reflection, so it is trim/AOT-safe.
/// </summary>
public static class TextEscape
{
    // ---------- XML ----------

    public static string XmlEscape(string s) => SecurityElement.Escape(s) ?? string.Empty;

    /// <summary>The five predefined XML entities plus numeric &amp;#65; / &amp;#x41; references.</summary>
    public static string XmlUnescape(string s)
    {
        if (s.IndexOf('&') < 0) return s;
        var sb = new StringBuilder(s.Length);
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (c == '&')
            {
                // Entity names/refs are short, so a ';' further than 12 chars away means this '&' is just
                // text. Look only that far: an unbounded search rescanned the rest of the input for
                // every '&' — quadratic on a paste full of them.
                int semi = s.IndexOf(';', i + 1, Math.Min(12, s.Length - i - 1));
                if (semi > i + 1)
                {
                    string? rep = XmlEntity(s.AsSpan(i + 1, semi - i - 1));
                    if (rep != null) { sb.Append(rep); i = semi; continue; }
                }
            }
            sb.Append(c);
        }
        return sb.ToString();
    }

    private static string? XmlEntity(ReadOnlySpan<char> e)
    {
        switch (e)
        {
            case "lt": return "<";
            case "gt": return ">";
            case "amp": return "&";
            case "quot": return "\"";
            case "apos": return "'";
        }
        if (e.Length < 2 || e[0] != '#') return null;
        bool hex = e[1] is 'x' or 'X';
        var digits = hex ? e[2..] : e[1..];
        if (!int.TryParse(digits, hex ? NumberStyles.AllowHexSpecifier : NumberStyles.None, CultureInfo.InvariantCulture, out int cp))
            return null;
        return IsScalar(cp) ? char.ConvertFromUtf32(cp) : null;
    }

    // ---------- JSON string ----------

    /// <summary>
    /// Escape text for use inside a JSON string (no surrounding quotes). Relaxed encoder: only what
    /// JSON requires is escaped, so é / 中 / emoji stay readable instead of becoming \uXXXX.
    /// </summary>
    public static string JsonEscape(string s) =>
        JsonEncodedText.Encode(s, JavaScriptEncoder.UnsafeRelaxedJsonEscaping).ToString();

    /// <summary>
    /// Decode a JSON string body (with or without its surrounding quotes), including \uXXXX and
    /// surrogate pairs. Raw line breaks/tabs are tolerated (they are escaped before parsing).
    /// </summary>
    public static string JsonUnescape(string s)
    {
        string t = s.Trim('\r', '\n');
        string trimmed = t.Trim();
        string body = trimmed.Length >= 2 && trimmed[0] == '"' && trimmed[^1] == '"' ? trimmed[1..^1] : t;
        body = body.Replace("\r", "\\r").Replace("\n", "\\n").Replace("\t", "\\t");

        byte[] utf8 = Encoding.UTF8.GetBytes("\"" + body + "\"");
        try
        {
            var reader = new Utf8JsonReader(utf8);
            if (!reader.Read() || reader.TokenType != JsonTokenType.String)
                throw new FormatException("Not a JSON string.");
            string value = reader.GetString() ?? string.Empty;
            if (reader.Read())   // anything after the closing quote (an unescaped " in the middle)
                throw new FormatException("Unescaped '\"' inside the string — escape it as \\\".");
            return value;
        }
        catch (JsonException ex)
        {
            // BytePositionInLine counts the quote we added, so it is already 1-based for the user.
            throw new FormatException($"Invalid JSON string near position {ex.BytePositionInLine}: unescaped quote or bad \\ escape.");
        }
    }

    // ---------- Unicode \uXXXX ----------

    /// <summary>Every non-ASCII char → \uXXXX (astral chars become a surrogate pair, as in Java/JS/JSON).</summary>
    public static string UnicodeEscape(string s)
    {
        var sb = new StringBuilder(s.Length + 16);
        foreach (char c in s)
        {
            if (c > 0x7E) sb.Append("\\u").Append(((int)c).ToString("X4"));
            else sb.Append(c);
        }
        return sb.ToString();
    }

    /// <summary>Decodes \uXXXX (pairs included), \u{1F600} and \U0001F600; everything else is left alone.</summary>
    public static string UnicodeUnescape(string s)
    {
        if (s.IndexOf('\\') < 0) return s;
        var sb = new StringBuilder(s.Length);
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (c == '\\' && i + 1 < s.Length)
            {
                char n = s[i + 1];
                if (n == '\\') { sb.Append("\\\\"); i++; continue; }   // an escaped backslash is not an escape
                if ((n == 'u' || n == 'U') && TryReadUnicode(s, i, out string rep, out int consumed))
                {
                    sb.Append(rep);
                    i += consumed - 1;
                    continue;
                }
            }
            sb.Append(c);
        }
        return sb.ToString();
    }

    // ---------- C# / JS string literal ----------

    /// <summary>
    /// Quote text as a double-quoted literal that is valid in both C# and JavaScript. Non-ASCII
    /// letters are kept as-is; control chars and the JS line terminators U+2028/2029 are escaped.
    /// </summary>
    public static string ToStringLiteral(string s)
    {
        var sb = new StringBuilder(s.Length + 16);
        sb.Append('"');
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            switch (c)
            {
                case '\\': sb.Append("\\\\"); break;
                case '"': sb.Append("\\\""); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\v': sb.Append("\\v"); break;
                case '\0':
                    // JS reads "\01" as a (forbidden in strict mode) octal escape, so spell it out then
                    sb.Append(i + 1 < s.Length && char.IsAsciiDigit(s[i + 1]) ? "\\u0000" : "\\0");
                    break;
                default:
                    if (c < 0x20 || c == 0x7F || c == '\u2028' || c == '\u2029')
                        sb.Append("\\u").Append(((int)c).ToString("X4"));
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
        return sb.ToString();
    }

    // ---------- backslash escapes ----------

    /// <summary>
    /// Interpret C-style escapes: \n \t \r \0 \a \b \f \v \e \\ \" \' \/ \xHH \NNN (octal)
    /// \uXXXX \u{…} \UXXXXXXXX. Unknown escapes are kept verbatim (backslash included).
    /// </summary>
    public static string BackslashUnescape(string s)
    {
        if (s.IndexOf('\\') < 0) return s;
        var sb = new StringBuilder(s.Length);
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (c != '\\' || i + 1 >= s.Length) { sb.Append(c); continue; }

            char n = s[i + 1];
            switch (n)
            {
                case 'n': sb.Append('\n'); i++; continue;
                case 't': sb.Append('\t'); i++; continue;
                case 'r': sb.Append('\r'); i++; continue;
                case 'a': sb.Append('\a'); i++; continue;
                case 'b': sb.Append('\b'); i++; continue;
                case 'f': sb.Append('\f'); i++; continue;
                case 'v': sb.Append('\v'); i++; continue;
                case 'e': sb.Append('\u001B'); i++; continue;
                case '\\': sb.Append('\\'); i++; continue;
                case '"': sb.Append('"'); i++; continue;
                case '\'': sb.Append('\''); i++; continue;
                case '/': sb.Append('/'); i++; continue;
                case 'x':
                {
                    // \xHH — one or two hex digits (C# allows up to 4, but 2 is the common denominator)
                    int j = i + 2, v = 0, count = 0;
                    while (j < s.Length && count < 2 && Uri.IsHexDigit(s[j])) { v = v * 16 + Uri.FromHex(s[j]); j++; count++; }
                    if (count == 0) break;
                    sb.Append((char)v);
                    i = j - 1;
                    continue;
                }
                case 'u':
                case 'U':
                    if (TryReadUnicode(s, i, out string rep, out int consumed)) { sb.Append(rep); i += consumed - 1; continue; }
                    break;
                default:
                    if (n is >= '0' and <= '7')
                    {
                        // \0 or octal \101 (max 3 digits, max \377)
                        int j = i + 1, v = 0, count = 0;
                        while (j < s.Length && count < 3 && s[j] is >= '0' and <= '7' && v * 8 + (s[j] - '0') <= 0xFF) { v = v * 8 + (s[j] - '0'); j++; count++; }
                        sb.Append((char)v);
                        i = j - 1;
                        continue;
                    }
                    break;
            }
            // unknown / malformed escape: keep it literally
            sb.Append(c);
        }
        return sb.ToString();
    }

    // Reads \uXXXX, \u{X…} or \UXXXXXXXX starting at s[start] == '\\'. consumed = chars used.
    private static bool TryReadUnicode(string s, int start, out string rep, out int consumed)
    {
        rep = string.Empty; consumed = 0;
        char kind = s[start + 1];
        if (kind == 'u' && start + 2 < s.Length && s[start + 2] == '{')
        {
            // At most 6 hex digits, so the '}' is within 7 chars — searching further made a run of
            // unclosed "\u{" quadratic.
            int close = s.IndexOf('}', start + 3, Math.Min(7, s.Length - start - 3));
            if (close < 0 || close - (start + 3) is < 1 or > 6) return false;
            if (!int.TryParse(s.AsSpan(start + 3, close - start - 3), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out int cp) || !IsScalar(cp))
                return false;
            rep = char.ConvertFromUtf32(cp);
            consumed = close - start + 1;
            return true;
        }

        int len = kind == 'U' ? 8 : 4;
        if (start + 2 + len > s.Length) return false;
        var hex = s.AsSpan(start + 2, len);
        foreach (char h in hex) if (!Uri.IsHexDigit(h)) return false;
        int value = int.Parse(hex, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
        if (kind == 'U')
        {
            if (!IsScalar(value)) return false;
            rep = char.ConvertFromUtf32(value);
        }
        else rep = ((char)value).ToString();   // a lone surrogate half pairs up with the next \uXXXX naturally
        consumed = 2 + len;
        return true;
    }

    private static bool IsScalar(int cp) => cp is >= 0 and <= 0x10FFFF and not (>= 0xD800 and <= 0xDFFF);
}
