using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _caseInput = string.Empty;
    [ObservableProperty] private string _caseOutput = string.Empty;

    [RelayCommand]
    private Task CaseAction(string mode)
    {
        string input = CaseInput;
        if (string.IsNullOrEmpty(input)) { ResetError(); return Task.CompletedTask; }

        return RunOffUi("case", () => mode switch
        {
            "upper" => input.ToUpperInvariant(),
            "lower" => input.ToLowerInvariant(),
            // Invariant culture on purpose: the current culture would turn "title" into "Tıtle" on a
            // Turkish phone.
            "title" => CultureInfo.InvariantCulture.TextInfo.ToTitleCase(input.ToLowerInvariant()),
            "sentence" => Sentence(input),
            "camel" => JoinCamel(Words(input), camel: true),
            "pascal" => JoinCamel(Words(input), camel: false),
            "snake" => string.Join("_", Words(input).Select(w => w.ToLowerInvariant())),
            "kebab" => string.Join("-", Words(input).Select(w => w.ToLowerInvariant())),
            "constant" => string.Join("_", Words(input).Select(w => w.ToUpperInvariant())),
            "dot" => string.Join(".", Words(input).Select(w => w.ToLowerInvariant())),
            "path" => string.Join("/", Words(input).Select(w => w.ToLowerInvariant())),
            "train" => string.Join("-", Words(input).Select(Capitalize)),
            "slug" => Slug(input),
            "invert" => InvertCase(input),
            "alternating" => AlternatingCase(input),
            "reverse" => ReverseGraphemes(input),
            _ => input
        }, r => CaseOutput = r, "Case: ");
    }

    /// <summary>
    /// Identifier words: any non letter/digit separates, plus camelCase humps and acronym ends
    /// ("parseHTTPResponse2Fast" → parse, HTTP, Response2, Fast). Plain char walking, no regex.
    /// </summary>
    private static List<string> Words(string input)
    {
        var words = new List<string>();
        var cur = new StringBuilder();
        for (int i = 0; i < input.Length; i++)
        {
            char c = input[i];
            if (!char.IsLetterOrDigit(c))
            {
                Flush();
                continue;
            }
            if (cur.Length > 0 && char.IsUpper(c))
            {
                char prev = input[i - 1];
                bool nextLower = i + 1 < input.Length && char.IsLower(input[i + 1]);
                // lower/digit → Upper starts a word ("myVar"); inside an acronym the last capital
                // starts the next word when a lowercase follows ("HTTPServer" → HTTP, Server).
                if (char.IsLower(prev) || char.IsDigit(prev) || (char.IsUpper(prev) && nextLower))
                    Flush();
            }
            cur.Append(c);
        }
        Flush();
        return words;

        void Flush()
        {
            if (cur.Length > 0) { words.Add(cur.ToString()); cur.Clear(); }
        }
    }

    private static string Capitalize(string w)
    {
        if (w.Length == 0) return w;
        string lower = w.ToLowerInvariant();
        return char.ToUpperInvariant(lower[0]) + lower[1..];
    }

    private static string JoinCamel(List<string> words, bool camel)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < words.Count; i++)
            sb.Append(camel && i == 0 ? words[i].ToLowerInvariant() : Capitalize(words[i]));
        return sb.ToString();
    }

    // Release desktop builds run with InvariantGlobalization, where Normalize(FormD) silently returns
    // the text unchanged — "Café" slugged to "caf". Probed once (a throw counts as "no", too).
    private static readonly bool FormDDecomposes = ProbeFormD();

    private static bool ProbeFormD()
    {
        try { return "\u00e9".Normalize(NormalizationForm.FormD).Length == 2; }   // precomposed é
        catch (Exception) { return false; }
    }

    // Latin letters → ASCII for slugs: the accented ones for when FormD can't split them, plus the
    // ones FormD never splits on any platform (ß, æ, ø, ł, đ, þ…).
    private static readonly Dictionary<char, string> LatinFold = BuildLatinFold();

    private static Dictionary<char, string> BuildLatinFold()
    {
        var map = new Dictionary<char, string>();
        foreach (var (letters, ascii) in new[]
        {
            ("àáâãäåāăąǎÀÁÂÃÄÅĀĂĄǍ", "a"), ("çćĉċčÇĆĈĊČ", "c"), ("ďđĎĐ", "d"), ("èéêëēĕėęěÈÉÊËĒĔĖĘĚ", "e"),
            ("ĝğġģĜĞĠĢ", "g"), ("ĥħĤĦ", "h"), ("ìíîïĩīĭįıǐÌÍÎÏĨĪĬĮİǏ", "i"), ("ĵĴ", "j"), ("ķĶ", "k"),
            ("ĺļľŀłĹĻĽĿŁ", "l"), ("ñńņňǹÑŃŅŇǸ", "n"), ("òóôõöøōŏőơǒÒÓÔÕÖØŌŎŐƠǑ", "o"), ("ŕŗřŔŖŘ", "r"),
            ("śŝşšșŚŜŞŠȘ", "s"), ("ţťŧțŢŤŦȚ", "t"), ("ùúûüũūŭůűųưǔǖǘǚǜÙÚÛÜŨŪŬŮŰŲƯǓǕǗǙǛ", "u"), ("ŵŴ", "w"),
            ("ýÿŷÝŸŶ", "y"), ("źżžŹŻŽ", "z"),
            ("ßẞ", "ss"), ("æÆ", "ae"), ("œŒ", "oe"), ("þÞ", "th"), ("ðÐ", "d"), ("ĳĲ", "ij"),
        })
        {
            foreach (char c in letters) map[c] = ascii;
        }
        // Vietnamese vowels with tone marks (Latin Extended Additional) come in one block per base letter.
        foreach (var (first, last, ascii) in new[] { (0x1EA0, 0x1EB7, "a"), (0x1EB8, 0x1EC7, "e"), (0x1EC8, 0x1ECB, "i"),
                                                      (0x1ECC, 0x1EE3, "o"), (0x1EE4, 0x1EF1, "u"), (0x1EF2, 0x1EF9, "y") })
        {
            for (int c = first; c <= last; c++) map[(char)c] = ascii;
        }
        return map;
    }

    private static string Slug(string input)
    {
        // Strip accents (é → e) so "Café au lait" slugs to "cafe-au-lait", not "caf-au-lait": by
        // decomposition where the runtime can, by the fold table everywhere — so desktop Release and
        // Android give the same slug.
        string text = input;
        if (FormDDecomposes)
        {
            try { text = input.Normalize(NormalizationForm.FormD); }
            catch (ArgumentException) { }   // a lone surrogate half: fold what we can instead
        }
        var sb = new StringBuilder(text.Length);
        bool dash = false;
        foreach (char ch in text)
        {
            if (CharUnicodeInfo.GetUnicodeCategory(ch) == UnicodeCategory.NonSpacingMark) continue;
            char c = char.ToLowerInvariant(ch);
            if (c is (>= 'a' and <= 'z') or (>= '0' and <= '9')) { sb.Append(c); dash = false; }
            else if (LatinFold.TryGetValue(ch, out string? ascii)) { sb.Append(ascii); dash = false; }
            else if ((char.IsWhiteSpace(c) || c is '-' or '_' or '.' or '/') && !dash && sb.Length > 0) { sb.Append('-'); dash = true; }
        }
        return sb.ToString().TrimEnd('-');
    }

    private static string Sentence(string input)
    {
        var sb = new StringBuilder(input.Length);
        bool capNext = true;
        foreach (char ch in input)
        {
            char c = char.ToLowerInvariant(ch);
            if (capNext && char.IsLetterOrDigit(c)) { c = char.ToUpperInvariant(c); capNext = false; }
            else if (c is '.' or '!' or '?') capNext = true;
            sb.Append(c);
        }
        return sb.ToString();
    }

    private static string InvertCase(string input)
    {
        var chars = input.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            char c = chars[i];
            chars[i] = char.IsUpper(c) ? char.ToLowerInvariant(c) : char.IsLower(c) ? char.ToUpperInvariant(c) : c;
        }
        return new string(chars);
    }

    // "aLtErNaTiNg": flips on letters only, so spaces/punctuation don't break the rhythm.
    private static string AlternatingCase(string input)
    {
        var chars = input.ToCharArray();
        bool upper = false;
        for (int i = 0; i < chars.Length; i++)
        {
            if (!char.IsLetter(chars[i])) continue;
            chars[i] = upper ? char.ToUpperInvariant(chars[i]) : char.ToLowerInvariant(chars[i]);
            upper = !upper;
        }
        return new string(chars);
    }
}
