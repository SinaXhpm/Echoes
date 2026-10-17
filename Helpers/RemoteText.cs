using System;
using System.Text;

namespace Echoes.Helpers;

/// <summary>
/// Text that came from someone else's server (a DNS record, a policy file, a status line) made safe to show: control
/// characters, line / paragraph separators and bidi embeddings / overrides / isolates (U+202A–U+202E, U+2066–U+2069)
/// become '?', so a record can't redraw the text around it in another order; and its length is capped, because a
/// single line of tens of thousands of characters takes the text layout seconds to minutes. LRM / RLM / ZWNJ stay —
/// ordinary Persian and Arabic text uses them.
/// </summary>
public static class RemoteText
{
    /// <summary><paramref name="s"/> with unsafe characters replaced and cut at <paramref name="max"/> characters
    /// ("…" added). <paramref name="keepNewlines"/>: '\n' stays (multi-line details); a tab is always a space.</summary>
    public static string Clean(string? s, int max = int.MaxValue, bool keepNewlines = false)
    {
        if (string.IsNullOrEmpty(s)) return string.Empty;
        int len = s.Length <= max ? s.Length : Math.Max(0, max);
        if (len < s.Length && len > 0 && char.IsHighSurrogate(s[len - 1])) len--;   // never half a surrogate pair
        StringBuilder? sb = null;
        for (int i = 0; i < len; i++)
        {
            char c = s[i];
            char r = c == '\t' ? ' '
                   : c == '\n' && keepNewlines ? c
                   : char.IsControl(c) || c is >= (char)0x2028 and <= (char)0x202E || c is >= (char)0x2066 and <= (char)0x2069 ? '?'
                   : c;
            if (r != c && sb == null) sb = new StringBuilder(len + 1).Append(s, 0, i);
            sb?.Append(r);
        }
        string clean = sb?.ToString() ?? (len == s.Length ? s : s[..len]);
        return len < s.Length ? clean + "…" : clean;
    }

    /// <summary>The first <paramref name="max"/> characters of an already clean <paramref name="s"/>, with a note of how
    /// much was left out (the whole text is kept elsewhere, e.g. for Copy).</summary>
    public static string Shorten(string s, int max)
    {
        if (s.Length <= max) return s;
        int cut = max;
        if (cut > 0 && char.IsHighSurrogate(s[cut - 1])) cut--;
        return s[..cut] + $"… ({s.Length - cut:N0} more characters; Copy gives all of it)";
    }
}
