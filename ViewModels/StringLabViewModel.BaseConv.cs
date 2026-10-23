using System;
using System.Globalization;
using System.Numerics;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _baseInput = string.Empty;
    [ObservableProperty] private string _baseOutput = string.Empty;
    [ObservableProperty] private string _baseFrom = string.Empty;   // blank = auto (0x / 0b / 0o / decimal)
    [ObservableProperty] private string _baseTo = string.Empty;     // blank = only the standard rows

    private const string Digits36 = "0123456789abcdefghijklmnopqrstuvwxyz";

    // BigInteger keeps huge values exact, but parsing is O(n²) — cap the digit count so a pasted
    // megabyte of digits can't pin the UI thread.
    private const int MaxBaseDigits = 4096;

    [RelayCommand]
    private void RunBaseConv()
    {
        try
        {
            ResetError();
            var s = LocalDigits.Fold(BaseInput.Trim());
            if (string.IsNullOrEmpty(s)) return;

            if (!TryReadBase(BaseFrom, out int fromBase, allowBlank: true) || !TryReadBase(BaseTo, out int toBase, allowBlank: true))
            {
                ErrorMessage = "Base must be a whole number from 2 to 36 (leave From base blank to auto-detect).";
                return;
            }

            bool negative = s.StartsWith('-');
            string body = negative || s.StartsWith('+') ? s[1..].TrimStart() : s;
            string detected;
            if (fromBase == 0)
            {
                if (body.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) { fromBase = 16; body = body[2..]; detected = "Hex"; }
                else if (body.StartsWith("0b", StringComparison.OrdinalIgnoreCase)) { fromBase = 2; body = body[2..]; detected = "Binary"; }
                else if (body.StartsWith("0o", StringComparison.OrdinalIgnoreCase)) { fromBase = 8; body = body[2..]; detected = "Octal"; }
                else { fromBase = 10; detected = "Decimal"; }
            }
            else
            {
                detected = $"Base {fromBase}";
                // an explicit FROM 16/2/8 still tolerates the matching 0x / 0b / 0o prefix
                string? prefix = fromBase switch { 16 => "0x", 2 => "0b", 8 => "0o", _ => null };
                if (prefix != null && body.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) body = body[2..];
            }

            if (!TryParseBig(body, fromBase, out BigInteger value, out string? why))
            {
                ErrorMessage = why ?? "Invalid number.";
                return;
            }
            if (negative) value = -value;

            var sb = new StringBuilder();
            Row2(sb, "Input as", detected);
            sb.AppendLine();
            Row2(sb, "Decimal", value.ToString(CultureInfo.InvariantCulture));
            Row2(sb, "Hex", Signed(value, 16, "0x", upper: true));
            Row2(sb, "Octal", Signed(value, 8, "0o", upper: false));
            Row2(sb, "Binary", Signed(value, 2, "0b", upper: false));
            if (toBase != 0)
                Row2(sb, $"Base {toBase}", Signed(value, toBase, "", upper: toBase == 16));

            BigInteger abs = BigInteger.Abs(value);
            Row2(sb, "Bit length", abs.IsZero ? "0" : ((long)abs.GetBitLength()).ToString(CultureInfo.InvariantCulture));

            if (value.Sign < 0)
            {
                // Two's complement at the common widths — what a debugger / memory dump shows.
                sb.AppendLine();
                foreach (int bits in new[] { 8, 16, 32, 64 })
                {
                    BigInteger min = -(BigInteger.One << (bits - 1));
                    string label = $"int{bits} (2's)";
                    if (value < min) { Row2(sb, label, "out of range"); continue; }
                    BigInteger twos = (BigInteger.One << bits) + value;
                    Row2(sb, label, "0x" + ToBase(twos, 16, upper: true).PadLeft(bits / 4, '0'));
                }
            }

            if (value > 0 && value <= 0x10FFFF && !(value >= 0xD800 && value <= 0xDFFF))
                Row2(sb, "Char", $"{char.ConvertFromUtf32((int)value)}   (U+{(int)value:X4})");

            BaseOutput = sb.ToString().TrimEnd();
        }
        catch (Exception ex) { ErrorMessage = ex.Message; }
    }

    private static bool TryReadBase(string text, out int b, bool allowBlank)
    {
        b = 0;
        if (string.IsNullOrWhiteSpace(text) || text.Trim().Equals("auto", StringComparison.OrdinalIgnoreCase)) return allowBlank;
        return int.TryParse(LocalDigits.Fold(text.Trim()), NumberStyles.None, CultureInfo.InvariantCulture, out b) && b is >= 2 and <= 36;
    }

    // Digits for any base 2-36 (case-insensitive); '_', ' ' and ',' are accepted as digit-group
    // separators ("1_000_000", "0xFFFF_FFFF", "1010 1010").
    private static bool TryParseBig(string text, int radix, out BigInteger value, out string? why)
    {
        value = BigInteger.Zero;
        why = null;
        int digits = 0;
        foreach (char ch in text)
        {
            if (ch is '_' or ' ' or ',') continue;
            int d = Digits36.IndexOf(char.ToLowerInvariant(ch));
            if (d < 0 || d >= radix)
            {
                why = $"'{ch}' is not a valid base-{radix} digit.";
                return false;
            }
            if (++digits > MaxBaseDigits)
            {
                why = $"Too many digits (max {MaxBaseDigits:N0}).";
                return false;
            }
            value = value * radix + d;
        }
        if (digits == 0) { why = "No digits to convert."; return false; }
        return true;
    }

    private static string Signed(BigInteger v, int radix, string prefix, bool upper) =>
        (v.Sign < 0 ? "-" : "") + prefix + ToBase(BigInteger.Abs(v), radix, upper);

    // Non-negative BigInteger → digits in any base 2-36. Peels off chunks of base^k that fit in a
    // long, so a 4096-digit number needs a few hundred BigInteger divisions instead of thousands.
    private static string ToBase(BigInteger v, int radix, bool upper)
    {
        if (v.IsZero) return "0";
        string digits = upper ? Digits36.ToUpperInvariant() : Digits36;

        int per = 1;
        long chunk = radix;
        while (chunk <= long.MaxValue / radix) { chunk *= radix; per++; }

        var parts = new StringBuilder();
        var buf = new char[per];
        while (!v.IsZero)
        {
            v = BigInteger.DivRem(v, chunk, out BigInteger rem);
            long r = (long)rem;
            for (int i = per - 1; i >= 0; i--) { buf[i] = digits[(int)(r % radix)]; r /= radix; }
            parts.Insert(0, buf);
        }
        string result = parts.ToString().TrimStart('0');
        return result.Length == 0 ? "0" : result;
    }
}
