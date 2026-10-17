using System;
using System.Globalization;
using System.Text;
using Avalonia.Data;
using Avalonia.Data.Converters;

namespace Echoes.Helpers;

/// <summary>
/// What a read-only output box shows of its (full) bound value: at most <see cref="MaxChars"/>
/// characters plus a note. A TextBox shapes every glyph of its text on the UI thread, so a multi-MB
/// result (TEXT → HEX of a 1 MB paste is 3 M chars) froze the window for seconds and cost ~100 MB.
/// The view-model keeps the exact value — COPY binds to that, never to the box.
/// <see cref="ByteRows"/> also lays a one-line hex / binary / Base64 result out in rows of 64 bytes
/// (Base64: 64 chars, the PEM width) — display only, too.
/// </summary>
public sealed class DisplayCapConverter : IValueConverter
{
    public const int MaxChars = TextLimit.Default;

    private const int RowBytes = 64;

    public static readonly DisplayCapConverter Instance = new(byteRows: false);
    public static readonly DisplayCapConverter ByteRows = new(byteRows: true);

    private readonly bool _byteRows;

    private DisplayCapConverter(bool byteRows) => _byteRows = byteRows;

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        string text = value as string ?? string.Empty;
        return (_byteRows ? Rows(text) : null) ?? Cap(text);
    }

    // One-way by design: the shortened text must never flow back into the full value.
    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => BindingOperations.DoNothing;

    /// <summary>The first <see cref="MaxChars"/> characters (ending on a line break when one is near) plus a note.</summary>
    public static string Cap(string text)
    {
        if (text.Length <= MaxChars) return text;
        // Stop at a line break near the limit so the last line shown is whole (dumps, tables, diffs).
        int cut = text.LastIndexOf('\n', MaxChars - 1, 1024);
        if (cut > 0 && text[cut - 1] == '\r') cut--;
        if (cut <= 0)
        {
            cut = MaxChars;
            if (char.IsHighSurrogate(text[cut - 1])) cut--;   // never split an emoji in half
        }
        return string.Concat(text.AsSpan(0, cut), Note(cut, text.Length));
    }

    // A one-line hex ("48656c…", "48 65 6c", "48:65:6c"), binary ("01001000 01101001") or Base64 /
    // Base64URL result as rows of 64 bytes, capped like Cap. Null for anything else — decoded text, a
    // hex dump, the C-array form — which is only capped. Only the part that can be shown is scanned.
    private static string? Rows(string text)
    {
        int scan = Math.Min(text.Length, MaxChars);
        int tok = 0;   // chars per token when separated: 2 = a hex byte, 8 = bits; 0 = one continuous run
        char sep = '\0';
        if (text.Length > 2 && text[2] is (' ' or ':') && IsHex(text[0]) && IsHex(text[1])) { tok = 2; sep = text[2]; }
        else if (text.Length > 8 && text[8] == ' ' && IsBits(text.AsSpan(0, 8))) { tok = 8; sep = ' '; }

        int rowChars, stride;
        if (tok > 0)
        {
            for (int i = 0; i < scan; i++)
            {
                char c = text[i];
                if (i % (tok + 1) == tok ? c != sep : tok == 2 ? !IsHex(c) : c is not ('0' or '1')) return null;
            }
            rowChars = RowBytes * (tok + 1) - 1;   // 64 tokens and the separators between them
            stride = rowChars + 1;                 // the separator after a row becomes its line break
        }
        else
        {
            bool hex = true, upper = false, lower = false;
            for (int i = 0; i < scan; i++)
            {
                char c = text[i];
                if (c is >= 'A' and <= 'Z') upper = true;
                else if (c is >= 'a' and <= 'z') lower = true;
                if (IsHex(c)) continue;
                hex = false;
                if (!(char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '-' or '_' || (c == '=' && i >= text.Length - 2))) return null;
            }
            // Real Base64 of more than a row mixes both letter cases; one case only is a word / slug.
            if (!hex && !(upper && lower)) return null;
            rowChars = hex ? RowBytes * 2 : RowBytes;
            stride = rowChars;
        }
        if (text.Length <= rowChars) return null;   // one row: nothing to lay out

        var sb = new StringBuilder(scan + 256);
        int pos = 0;
        while (pos < text.Length && sb.Length + rowChars <= MaxChars)
        {
            if (pos > 0) sb.Append('\n');
            sb.Append(text, pos, Math.Min(rowChars, text.Length - pos));
            pos += stride;
        }
        if (pos < text.Length) sb.Append(Note(pos, text.Length));
        return sb.ToString();
    }

    private static string Note(int shown, int total) => string.Create(CultureInfo.InvariantCulture,
        $"{Environment.NewLine}{Environment.NewLine}… [showing the first {shown:N0} of {total:N0} characters — use Copy for the full result]");

    private static bool IsHex(char c) => char.IsAsciiHexDigit(c);

    private static bool IsBits(ReadOnlySpan<char> s)
    {
        foreach (char c in s) if (c is not ('0' or '1')) return false;
        return true;
    }
}
