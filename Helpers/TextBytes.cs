using System;
using System.Collections.Generic;
using System.Text;

namespace Echoes.Helpers;

/// <summary>
/// Byte ⇄ text helpers shared by String Lab's BASE64 / HEX / HASH tools: lenient hex / binary
/// parsing (whatever people paste from debuggers, Wireshark, C sources…), hex / binary / dump
/// rendering, and "is this actually text?" detection so binary data never shows up as mojibake.
/// </summary>
public static class TextBytes
{
    private const string HexLower = "0123456789abcdef";
    private const string HexUpper = "0123456789ABCDEF";

    // throwOnInvalidBytes: the default UTF8 decoder silently swaps bad bytes for U+FFFD, which is
    // exactly the mojibake we want to detect and avoid.
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    public static bool TryDecodeUtf8(byte[] bytes, out string text)
    {
        try { text = StrictUtf8.GetString(bytes); return true; }
        catch (DecoderFallbackException) { text = string.Empty; return false; }
    }

    /// <summary>
    /// PowerShell <c>-EncodedCommand</c> payloads and most Windows blobs are UTF-16LE: ASCII with a
    /// 0x00 after every byte. That is technically valid UTF-8 as well (a string full of NULs), so it
    /// has to be recognised before the UTF-8 attempt.
    /// </summary>
    public static bool LooksUtf16Le(byte[] b)
    {
        if (b.Length >= 2 && b[0] == 0xFF && b[1] == 0xFE) return b.Length % 2 == 0;   // explicit BOM
        if (b.Length < 4 || b.Length % 2 != 0) return false;
        int pairs = b.Length / 2, oddZeros = 0, evenZeros = 0;
        for (int i = 0; i < b.Length; i += 2)
        {
            if (b[i] == 0) evenZeros++;
            if (b[i + 1] == 0) oddZeros++;
        }
        return oddZeros * 10 >= pairs * 7 && evenZeros * 10 <= pairs;
    }

    /// <summary>
    /// Render decoded bytes for a text box: UTF-8 text when it is valid UTF-8, UTF-16LE text when it
    /// clearly is that, otherwise a labelled hex dump (never U+FFFD soup).
    /// </summary>
    public static string DecodeForDisplay(byte[] bytes, int maxDumpBytes = 256 * 1024)
    {
        if (bytes.Length == 0) return string.Empty;
        if (LooksUtf16Le(bytes))
        {
            int skip = bytes[0] == 0xFF && bytes[1] == 0xFE ? 2 : 0;
            return "# UTF-16LE text (e.g. PowerShell -EncodedCommand):" + Environment.NewLine
                   + Encoding.Unicode.GetString(bytes, skip, bytes.Length - skip);
        }
        if (TryDecodeUtf8(bytes, out var text)) return text;
        return $"# Not valid UTF-8 — {bytes.Length:N0} bytes shown as hex:" + Environment.NewLine
               + HexDump(bytes, maxDumpBytes);
    }

    /// <summary>Classic <c>hexdump -C</c> layout: offset, 16 bytes in two groups of 8, ASCII column.</summary>
    public static string HexDump(ReadOnlySpan<byte> data, int maxBytes = int.MaxValue)
    {
        int n = Math.Min(data.Length, Math.Max(0, maxBytes));
        var sb = new StringBuilder((n / 16 + 2) * 80);
        for (int off = 0; off < n; off += 16)
        {
            int len = Math.Min(16, n - off);
            sb.Append(off.ToString("x8")).Append("  ");
            for (int i = 0; i < 16; i++)
            {
                if (i < len)
                {
                    byte b = data[off + i];
                    sb.Append(HexLower[b >> 4]).Append(HexLower[b & 0xF]).Append(' ');
                }
                else sb.Append("   ");
                if (i == 7) sb.Append(' ');
            }
            sb.Append(" |");
            for (int i = 0; i < len; i++)
            {
                byte b = data[off + i];
                sb.Append(b is >= 0x20 and < 0x7F ? (char)b : '.');
            }
            sb.Append('|').Append(Environment.NewLine);
        }
        if (n < data.Length)
            sb.Append($"… [{data.Length - n:N0} more bytes not shown]");
        return sb.ToString().TrimEnd();
    }

    /// <summary>Output chars per input byte for each <see cref="ToHex"/> style (for size guards).</summary>
    public static int HexCharsPerByte(string style) => style switch
    {
        "space" or "colon" => 3,
        "c" => 6,
        _ => 2,
    };

    /// <summary>
    /// Hex with a separator style: "none" → 48656c, "space" → 48 65 6c, "colon" → 48:65:6c,
    /// "c" → 0x48, 0x65, 0x6c (C/C#/JS array initialiser, 16 per line).
    /// </summary>
    public static string ToHex(ReadOnlySpan<byte> data, string style, bool upper)
    {
        string digits = upper ? HexUpper : HexLower;
        var sb = new StringBuilder(data.Length * HexCharsPerByte(style) + 16);
        for (int i = 0; i < data.Length; i++)
        {
            byte b = data[i];
            if (i > 0)
            {
                switch (style)
                {
                    case "space": sb.Append(' '); break;
                    case "colon": sb.Append(':'); break;
                    case "c": sb.Append(i % 16 == 0 ? "," + Environment.NewLine : ", "); break;
                }
            }
            if (style == "c") sb.Append("0x");
            sb.Append(digits[b >> 4]).Append(digits[b & 0xF]);
        }
        return sb.ToString();
    }

    private static bool IsHexDigit(char c) => c is (>= '0' and <= '9') or (>= 'a' and <= 'f') or (>= 'A' and <= 'F');

    private static int HexVal(char c) => c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10;

    /// <summary>
    /// Accepts "48 65 6c", "48:65:6C", "0x48, 0x65", "\x48\x65", "{ 0x48 }", "%48%65", "48656c" and
    /// any mix of them across lines. When the input is split into tokens, a lone digit ("0x5")
    /// counts as one byte (05) instead of shifting every following nibble.
    /// </summary>
    public static byte[] ParseHexLenient(string s)
    {
        var bytes = new List<byte>(s.Length / 2);
        var token = new StringBuilder();

        void Flush()
        {
            if (token.Length == 0) return;
            if (token.Length == 1) token.Insert(0, '0');
            if (token.Length % 2 != 0)
                throw new FormatException($"Odd number of hex digits in \"{Shorten(token.ToString())}\" — each byte needs two digits.");
            for (int i = 0; i < token.Length; i += 2)
                bytes.Add((byte)(HexVal(token[i]) << 4 | HexVal(token[i + 1])));
            token.Clear();
        }

        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            // "0x" / "0X" prefix (only at the start of a token, so "10x" is still an error)
            if (c == '0' && token.Length == 0 && i + 1 < s.Length && (s[i + 1] == 'x' || s[i + 1] == 'X')) { i++; continue; }
            // "\x48" escape style
            if (c == '\\' && i + 1 < s.Length && (s[i + 1] == 'x' || s[i + 1] == 'X')) { Flush(); i++; continue; }
            if (IsHexDigit(c)) { token.Append(c); continue; }
            if (char.IsWhiteSpace(c) || c is ',' or ':' or ';' or '-' or '%' or '{' or '}' or '[' or ']' or '(' or ')' or '"' or '\'' or '\\' or '|')
            {
                Flush();
                continue;
            }
            throw new FormatException($"Unexpected character '{c}' at position {i + 1} — not a hex digit.");
        }
        Flush();
        return bytes.ToArray();
    }

    public static string ToBinary(ReadOnlySpan<byte> data)
    {
        var sb = new StringBuilder(data.Length * 9);
        for (int i = 0; i < data.Length; i++)
        {
            if (i > 0) sb.Append(' ');
            byte b = data[i];
            for (int bit = 7; bit >= 0; bit--)
                sb.Append((b >> bit & 1) == 1 ? '1' : '0');
        }
        return sb.ToString();
    }

    /// <summary>
    /// "01001000 01101001" or one continuous run of bits (multiple of 8). Space-separated groups
    /// shorter than 8 bits (e.g. 7-bit ASCII "1001000 1101001") are each taken as one byte.
    /// </summary>
    public static byte[] ParseBinaryLenient(string s)
    {
        var tokens = s.Split(new[] { ' ', '\t', '\r', '\n', ',', ';', ':', '_', '|', '-' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var t in tokens)
            foreach (char c in t)
                if (c is not ('0' or '1'))
                    throw new FormatException($"Unexpected character '{c}' — binary input may only contain 0 and 1.");

        var bytes = new List<byte>();
        bool grouped = tokens.Length > 1 && Array.TrueForAll(tokens, t => t.Length <= 8);
        if (grouped)
        {
            foreach (var t in tokens) bytes.Add(Convert.ToByte(t, 2));
            return bytes.ToArray();
        }

        string all = string.Concat(tokens);
        if (all.Length % 8 != 0)
            throw new FormatException($"{all.Length} bits is not a whole number of bytes (needs a multiple of 8).");
        for (int i = 0; i < all.Length; i += 8)
            bytes.Add(Convert.ToByte(all.Substring(i, 8), 2));
        return bytes.ToArray();
    }

    private static string Shorten(string s) => s.Length <= 24 ? s : s[..24] + "…";
}
