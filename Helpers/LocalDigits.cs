using System.Globalization;

namespace Echoes.Helpers;

/// <summary>
/// Phone keyboards type the digits of the phone's language: a Persian or Arabic keyboard gives Eastern Arabic digits
/// for "8.8.8.8" and port "22", Hindi and Bengali keyboards their own, CJK keyboards in full-width mode full-width
/// ones. .NET parses none of them and a resolver takes such an "8.8.8.8" for a host name, so what holds addresses,
/// ports and numbers is folded to ASCII: as it is typed (InputAssist) and where it is read.
/// </summary>
public static class LocalDigits
{
    /// <summary>True when <paramref name="s"/> holds anything <see cref="Fold"/> changes.</summary>
    public static bool Any(string? s)
    {
        if (s is null) return false;
        foreach (char c in s)
            if (c > '\u007F' && Map(c) != c) return true;
        return false;
    }

    /// <summary><paramref name="s"/> with every decimal digit made ASCII and the Arabic and full-width dot, comma and
    /// colon made plain (a Persian "192.168.1.1" reads in ASCII); <paramref name="s"/> itself when there is nothing to fold.</summary>
    public static string Fold(string s)
    {
        if (!Any(s)) return s;
        return string.Create(s.Length, s, static (span, src) =>
        {
            for (int i = 0; i < src.Length; i++) span[i] = Map(src[i]);
        });
    }

    /// <summary><see cref="Fold"/>, null and empty kept as they are.</summary>
    public static string? FoldOrNull(string? s) => string.IsNullOrEmpty(s) ? s : Fold(s);

    /// <summary>True when <paramref name="s"/> has a letter beyond ASCII: an internationalised name or a word, whose
    /// digits are part of it and stay.</summary>
    public static bool HasNonAsciiLetter(string? s)
    {
        if (s is null) return false;
        foreach (char c in s)
            if (c > '\u007F' && char.IsLetter(c)) return true;
        return false;
    }

    private static char Map(char c)
    {
        if (c <= '\u007F') return c;
        // every Unicode decimal digit block (Arabic-Indic, Persian, Devanagari, Thai, full-width ...) reads 0-9 here;
        // the tables ship inside the runtime, so this works with InvariantGlobalization too
        if (CharUnicodeInfo.GetUnicodeCategory(c) == UnicodeCategory.DecimalDigitNumber)
            return (char)('0' + CharUnicodeInfo.GetDecimalDigitValue(c));
        return c switch
        {
            '\u066B' or '\uFF0E' or '\u3002' or '\uFF61' => '.',   // Arabic decimal separator, full-width and ideographic full stops
            '\u060C' or '\u066C' or '\uFF0C' => ',',               // Arabic comma, Arabic thousands separator, full-width comma
            '\uFF1A' => ':',
            '\uFF0F' => '/',
            '\uFF0D' => '-',
            _ => c,
        };
    }
}
