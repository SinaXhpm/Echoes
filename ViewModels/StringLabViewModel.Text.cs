using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

// TEXT LAB: in-place line/text operations on one editor, with a live stats line and one-step undo.
public partial class StringLabViewModel
{
    [ObservableProperty] private string _editInput = string.Empty;
    [ObservableProperty] private int _charCount;
    [ObservableProperty] private int _charNoSpaceCount;
    [ObservableProperty] private int _wordCount;
    [ObservableProperty] private int _lineCount;
    [ObservableProperty] private long _byteCount;          // UTF-8
    [ObservableProperty] private int _uniqueLineCount;

    [ObservableProperty] private string _editFind = string.Empty;
    [ObservableProperty] private string _editReplace = string.Empty;
    [ObservableProperty] private bool _editIgnoreCase;
    [ObservableProperty] private string _editPrefix = string.Empty;
    [ObservableProperty] private string _editSuffix = string.Empty;
    [ObservableProperty] private string _editSeparator = ", ";      // JOIN / SPLIT; \t and \n are understood
    [ObservableProperty] private string _editStatus = string.Empty; // "Removed 3 duplicate lines" etc.

    // Every operation rewrites the editor in place, so keep the text from before the last one (or
    // before CLEAR). UNDO swaps it back — pressing it again is a redo.
    private string? _editUndo;

    // Reused per keystroke: unique-line counting hashes each line's chars (64-bit FNV-1a) straight
    // off the string, so no line substrings or split arrays are allocated while typing.
    private readonly HashSet<ulong> _lineHashes = new();
    private const ulong FnvOffset = 14695981039346656037UL;
    private const ulong FnvPrime = 1099511628211UL;

    private sealed record EditOptions(string Find, string Replace, bool IgnoreCase, string Prefix, string Suffix, string Separator);

    partial void OnEditInputChanged(string value)
    {
        string s = value ?? string.Empty;
        int nonSpace = 0, words = 0, lines = s.Length == 0 ? 0 : 1;
        long bytes = 0;
        bool inWord = false;
        ulong h = FnvOffset;
        _lineHashes.Clear();

        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];

            // UTF-8 size: a surrogate pair is 4 bytes (counted on the high half); a lone surrogate
            // would be written as U+FFFD, i.e. 3 bytes.
            if (c < 0x80) bytes += 1;
            else if (c < 0x800) bytes += 2;
            else if (char.IsHighSurrogate(c) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) bytes += 4;
            else if (!(char.IsLowSurrogate(c) && i > 0 && char.IsHighSurrogate(s[i - 1]))) bytes += 3;

            if (!char.IsWhiteSpace(c))
            {
                nonSpace++;
                if (!inWord) { words++; inWord = true; }
            }
            else inWord = false;

            if (c is '\n' or '\r')
            {
                if (c == '\r' && i + 1 < s.Length && s[i + 1] == '\n') continue;   // CRLF: the \n ends the line
                lines++;
                _lineHashes.Add(h);
                h = FnvOffset;
            }
            else h = (h ^ c) * FnvPrime;
        }
        // The empty "line" after a trailing newline counts as a line (like an editor) but not as a
        // distinct value — "a\na\n" has one unique line.
        if (s.Length > 0 && s[^1] is not ('\n' or '\r')) _lineHashes.Add(h);

        CharCount = s.Length;
        CharNoSpaceCount = nonSpace;
        WordCount = words;
        LineCount = lines;
        ByteCount = bytes;
        UniqueLineCount = _lineHashes.Count;
    }

    [RelayCommand]
    private Task EditAction(string mode)
    {
        string input = EditInput;
        if (string.IsNullOrEmpty(input)) { ResetError(); return Task.CompletedTask; }
        var opts = new EditOptions(EditFind, EditReplace, EditIgnoreCase, EditPrefix, EditSuffix,
                                   TextEscape.BackslashUnescape(EditSeparator ?? string.Empty));

        return RunOffUi("edit", () => ApplyEdit(mode, input, opts), r =>
        {
            // The user kept typing while a big operation ran — don't silently throw their edits away.
            if (EditInput != input)
            {
                ErrorMessage = "The text changed while the operation was running — result discarded, run it again.";
                return;
            }
            if (r.Text != input)
            {
                _editUndo = input;
                EditInput = r.Text;
            }
            EditStatus = r.Status;
        }, "Text Lab: ");
    }

    [RelayCommand]
    private void EditUndo()
    {
        ResetError();
        if (_editUndo is null) { EditStatus = "Nothing to undo."; return; }
        (EditInput, _editUndo) = (_editUndo, EditInput);
        EditStatus = "Undone — press UNDO again to redo.";
    }

    private static (string Text, string Status) ApplyEdit(string mode, string input, EditOptions o)
    {
        string nl = Environment.NewLine;

        // Whole-text operations first (no line split needed).
        switch (mode)
        {
            case "trim": return (input.Trim(), "Trimmed leading/trailing whitespace.");
            case "upper": return (input.ToUpperInvariant(), "UPPERCASED.");
            case "lower": return (input.ToLowerInvariant(), "lowercased.");
            case "reversetext": return (ReverseGraphemes(input), "Reversed the text.");
            case "replace": return FindReplace(input, o);
            case "split":
            {
                if (o.Separator.Length == 0) throw new InvalidOperationException("Enter a delimiter to split by (\\t and \\n work too).");
                var parts = input.Split(o.Separator);
                return (string.Join(nl, parts), $"Split into {parts.Length:N0} line(s).");
            }
        }

        // Line operations. A trailing newline is set aside and restored, so sorting/shuffling
        // doesn't drag an empty line to the top.
        var lines = input.Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.None).ToList();
        bool trailingNewline = lines.Count > 1 && lines[^1].Length == 0;
        if (trailingNewline) lines.RemoveAt(lines.Count - 1);
        int before = lines.Count;

        string Join(IEnumerable<string> l) => string.Join(nl, l) + (trailingNewline ? nl : string.Empty);

        switch (mode)
        {
            case "sort":
                return (Join(lines.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ThenBy(x => x, StringComparer.Ordinal)), $"Sorted {before:N0} line(s) A→Z.");
            case "sortdesc":
                return (Join(lines.OrderByDescending(x => x, StringComparer.OrdinalIgnoreCase).ThenByDescending(x => x, StringComparer.Ordinal)), $"Sorted {before:N0} line(s) Z→A.");
            case "natural":
                return (Join(lines.OrderBy(x => x, NaturalComparer.Instance)), $"Natural-sorted {before:N0} line(s) (file2 before file10).");
            case "shuffle":
            {
                var arr = lines.ToArray();
                RandomNumberGenerator.Shuffle(arr.AsSpan());   // crypto RNG, unbiased Fisher–Yates
                return (Join(arr), $"Shuffled {before:N0} line(s).");
            }
            case "reverse":
                lines.Reverse();
                return (Join(lines), $"Reversed the order of {before:N0} line(s).");
            case "unique":
            {
                var kept = lines.Distinct(StringComparer.Ordinal).ToList();
                return (Join(kept), $"Removed {before - kept.Count:N0} duplicate line(s).");
            }
            case "uniqueci":
            {
                var kept = lines.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                return (Join(kept), $"Removed {before - kept.Count:N0} duplicate line(s), ignoring case.");
            }
            case "noempty":
            {
                var kept = lines.Where(l => !string.IsNullOrWhiteSpace(l)).ToList();
                return (Join(kept), $"Removed {before - kept.Count:N0} empty line(s).");
            }
            case "trimlines":
                return (Join(lines.Select(l => l.Trim())), $"Trimmed {before:N0} line(s).");
            case "clean":
            {
                var kept = lines.Where(l => !string.IsNullOrWhiteSpace(l)).Select(l => l.Trim()).ToList();
                return (string.Join(nl, kept), $"Cleaned up: {kept.Count:N0} non-empty trimmed line(s).");
            }
            case "collapse":
                return (Join(lines.Select(CollapseWhitespace)), "Collapsed runs of spaces/tabs to one space.");
            case "oneline":
                return (string.Join(" ", lines.Select(l => l.Trim()).Where(l => l.Length > 0)), $"Joined {before:N0} line(s) into one.");
            case "join":
                // the separator is paid once per line: a long one over many lines multiplied the text (22 KB → 20 M chars)
                EnsureOutputSize(input.Length + (long)Math.Max(0, before - 1) * o.Separator.Length, "Result");
                return (string.Join(o.Separator, lines), $"Joined {before:N0} line(s).");
            case "affix":
            {
                if (o.Prefix.Length == 0 && o.Suffix.Length == 0) throw new InvalidOperationException("Enter a prefix and/or a suffix first.");
                EnsureOutputSize(input.Length + (long)before * (o.Prefix.Length + o.Suffix.Length), "Result");
                return (Join(lines.Select(l => o.Prefix + l + o.Suffix)), $"Added prefix/suffix to {before:N0} line(s).");
            }
            case "number":
            {
                int width = before.ToString(CultureInfo.InvariantCulture).Length;
                return (Join(lines.Select((l, i) => (i + 1).ToString(CultureInfo.InvariantCulture).PadLeft(width) + ". " + l)), $"Numbered {before:N0} line(s).");
            }
            default:
                return (input, string.Empty);
        }
    }

    private static (string Text, string Status) FindReplace(string input, EditOptions o)
    {
        if (o.Find.Length == 0) throw new InvalidOperationException("Enter the text to find.");
        var cmp = o.IgnoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

        int count = 0;
        for (int at = input.IndexOf(o.Find, cmp); at >= 0; at = input.IndexOf(o.Find, at + o.Find.Length, cmp))
            count++;
        if (count == 0) return (input, "No occurrences found.");

        EnsureOutputSize(input.Length + (long)count * Math.Max(0, o.Replace.Length - o.Find.Length), "Result");
        return (input.Replace(o.Find, o.Replace, cmp), $"Replaced {count:N0} occurrence(s).");
    }

    private static string CollapseWhitespace(string line)
    {
        var sb = new StringBuilder(line.Length);
        bool prevSpace = false;
        foreach (char c in line)
        {
            if (c is ' ' or '\t' || (char.IsWhiteSpace(c) && c is not ('\r' or '\n')))
            {
                if (!prevSpace) sb.Append(' ');
                prevSpace = true;
            }
            else { sb.Append(c); prevSpace = false; }
        }
        return sb.ToString();
    }

    // Reverse by grapheme cluster so emoji, flags and accented letters (e + ◌́) survive intact.
    private static string ReverseGraphemes(string s)
    {
        var elements = new List<string>();
        var e = StringInfo.GetTextElementEnumerator(s);
        while (e.MoveNext()) elements.Add(e.GetTextElement());
        var sb = new StringBuilder(s.Length);
        for (int i = elements.Count - 1; i >= 0; i--) sb.Append(elements[i]);
        return sb.ToString();
    }

    /// <summary>
    /// "file2" &lt; "file10": runs of digits compare by numeric value (any length — no overflow),
    /// everything else case-insensitively; full ties fall back to ordinal so the order is total.
    /// </summary>
    private sealed class NaturalComparer : IComparer<string>
    {
        public static readonly NaturalComparer Instance = new();

        public int Compare(string? x, string? y)
        {
            if (ReferenceEquals(x, y)) return 0;
            if (x is null) return -1;
            if (y is null) return 1;

            int i = 0, j = 0;
            while (i < x.Length && j < y.Length)
            {
                if (char.IsAsciiDigit(x[i]) && char.IsAsciiDigit(y[j]))
                {
                    int si = i, sj = j;
                    while (si < x.Length && x[si] == '0') si++;   // leading zeros don't change the value
                    while (sj < y.Length && y[sj] == '0') sj++;
                    int ei = si, ej = sj;
                    while (ei < x.Length && char.IsAsciiDigit(x[ei])) ei++;
                    while (ej < y.Length && char.IsAsciiDigit(y[ej])) ej++;

                    int byLength = (ei - si).CompareTo(ej - sj);   // more significant digits = bigger
                    if (byLength != 0) return byLength;
                    int byDigits = string.CompareOrdinal(x, si, y, sj, ei - si);
                    if (byDigits != 0) return byDigits;
                    int byZeros = (si - i).CompareTo(sj - j);      // "7" before "007"
                    if (byZeros != 0) return byZeros;
                    i = ei; j = ej;
                }
                else
                {
                    int c = char.ToUpperInvariant(x[i]).CompareTo(char.ToUpperInvariant(y[j]));
                    if (c != 0) return c;
                    i++; j++;
                }
            }
            int rest = (x.Length - i).CompareTo(y.Length - j);
            return rest != 0 ? rest : string.CompareOrdinal(x, y);
        }
    }
}
