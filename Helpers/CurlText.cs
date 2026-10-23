using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Echoes.Helpers;

public enum CurlSyntax { None, Json, Xml }

public enum CurlTokenKind : byte { Plain, Key, String, Number, Literal, Punct, Tag, Attr, Comment }

public readonly record struct CurlToken(int Start, int Length, CurlTokenKind Kind);

/// <summary>
/// Read-only text for the response viewer: line breaks normalized, tabs expanded, control characters made visible, an
/// index of line starts (so a 16 MB body is shown line by line, never laid out whole) and a per-line lexer for JSON /
/// XML colouring, run lazily for the lines on screen and cached. Built off the UI thread; pure (no UI types).
/// </summary>
public sealed class CurlTextDocument
{
    // What Create rewrites: \r, tabs and the other C0 controls (not \n), DEL. Most bodies hold none, and their text is
    // kept as it came (no second multi-MB copy). Declared before Empty: static fields initialize in order.
    private static readonly SearchValues<char> Rewritten =
        SearchValues.Create(Enumerable.Range(0, 0x20).Where(c => c != '\n').Select(c => (char)c).Append('\x7F').ToArray());

    public static readonly CurlTextDocument Empty = Create(string.Empty, CurlSyntax.None);

    /// <summary>Lines longer than this aren't coloured (a minified multi-MB line would be lexed whole for one frame).</summary>
    public const int MaxLexLength = 20_000;

    private readonly int[] _starts;   // start offset of each line (+ a sentinel = Text.Length + 1)
    private readonly Dictionary<int, CurlToken[]> _tokens = new();
    private readonly Queue<int> _tokenOrder = new();

    public string Text { get; }
    public CurlSyntax Syntax { get; }
    public int LineCount => _starts.Length - 1;
    public int MaxLineLength { get; }
    public bool IsEmpty => Text.Length == 0;

    private CurlTextDocument(string text, int[] starts, int maxLen, CurlSyntax syntax)
    {
        Text = text;
        _starts = starts;
        MaxLineLength = maxLen;
        Syntax = syntax;
    }

    public static CurlTextDocument Create(string? source, CurlSyntax syntax)
    {
        source ??= string.Empty;
        if (source.AsSpan().IndexOfAny(Rewritten) < 0) return Indexed(source, syntax);
        var sb = new StringBuilder(source.Length);
        var starts = new List<int>(Math.Max(16, source.Length / 40)) { 0 };
        int col = 0, maxLen = 0;
        for (int i = 0; i < source.Length; i++)
        {
            char c = source[i];
            if (c == '\r')
            {
                if (i + 1 < source.Length && source[i + 1] == '\n') i++;
                c = '\n';
            }
            if (c == '\n')
            {
                maxLen = Math.Max(maxLen, col);
                sb.Append('\n');
                starts.Add(sb.Length);
                col = 0;
                continue;
            }
            if (c == '\t')
            {
                int pad = 4 - (col % 4);
                sb.Append(' ', pad);
                col += pad;
                continue;
            }
            // other C0 controls / DEL would draw as boxes (or nothing): a visible middle dot in their place
            sb.Append(c < 0x20 || c == 0x7F ? '·' : c);
            col++;
        }
        maxLen = Math.Max(maxLen, col);
        starts.Add(sb.Length + 1);   // sentinel: the last line ends at Text.Length
        return new CurlTextDocument(sb.ToString(), starts.ToArray(), maxLen, syntax);
    }

    /// <summary>Create for a text with nothing to rewrite: only the line index is built.</summary>
    private static CurlTextDocument Indexed(string text, CurlSyntax syntax)
    {
        var starts = new List<int>(Math.Max(16, text.Length / 40)) { 0 };
        int at = 0, maxLen = 0;
        for (int nl; (nl = text.IndexOf('\n', at)) >= 0; at = nl + 1)
        {
            maxLen = Math.Max(maxLen, nl - at);
            starts.Add(nl + 1);
        }
        maxLen = Math.Max(maxLen, text.Length - at);
        starts.Add(text.Length + 1);   // sentinel: the last line ends at Text.Length
        return new CurlTextDocument(text, starts.ToArray(), maxLen, syntax);
    }

    public int LineStart(int line) => _starts[Math.Clamp(line, 0, LineCount)];
    public int LineLength(int line) => line < 0 || line >= LineCount ? 0 : _starts[line + 1] - 1 - _starts[line];
    public ReadOnlySpan<char> Line(int line) => Text.AsSpan(LineStart(line), LineLength(line));

    /// <summary>The line holding <paramref name="offset"/> and the column in it.</summary>
    public (int Line, int Col) PositionOf(int offset)
    {
        offset = Math.Clamp(offset, 0, Text.Length);
        int lo = 0, hi = LineCount - 1;
        while (lo < hi)
        {
            int mid = (lo + hi + 1) >> 1;
            if (_starts[mid] <= offset) lo = mid; else hi = mid - 1;
        }
        return (lo, offset - _starts[lo]);
    }

    public int OffsetOf(int line, int col)
    {
        line = Math.Clamp(line, 0, Math.Max(0, LineCount - 1));
        return LineStart(line) + Math.Clamp(col, 0, LineLength(line));
    }

    public string GetText(int start, int end)
    {
        start = Math.Clamp(start, 0, Text.Length);
        end = Math.Clamp(end, start, Text.Length);
        return Text[start..end];
    }

    /// <summary>The colour runs of one line (cached; the cache keeps the most recently drawn few thousand lines).</summary>
    public CurlToken[] Tokens(int line)
    {
        if (Syntax == CurlSyntax.None) return Array.Empty<CurlToken>();
        if (_tokens.TryGetValue(line, out var cached)) return cached;
        var span = Line(line);
        var result = span.Length > MaxLexLength ? Array.Empty<CurlToken>()
                   : Syntax == CurlSyntax.Json ? LexJson(span) : LexXml(span);
        _tokens[line] = result;
        _tokenOrder.Enqueue(line);
        while (_tokenOrder.Count > 4096) _tokens.Remove(_tokenOrder.Dequeue());
        return result;
    }

    // ---------------------------------------------------------------- lexers (one line at a time)

    public static CurlToken[] LexJson(ReadOnlySpan<char> s)
    {
        var list = new List<CurlToken>();
        int i = 0;
        while (i < s.Length)
        {
            char c = s[i];
            if (c == ' ') { i++; continue; }
            if (c == '"')
            {
                int start = i++;
                while (i < s.Length)
                {
                    if (s[i] == '\\') { i += 2; continue; }
                    if (s[i] == '"') { i++; break; }
                    i++;
                }
                i = Math.Min(i, s.Length);
                int j = i;
                while (j < s.Length && s[j] == ' ') j++;
                list.Add(new CurlToken(start, i - start, j < s.Length && s[j] == ':' ? CurlTokenKind.Key : CurlTokenKind.String));
                continue;
            }
            if (c == '-' || char.IsAsciiDigit(c))
            {
                int start = i++;
                while (i < s.Length && (char.IsAsciiDigit(s[i]) || s[i] is '.' or 'e' or 'E' or '+' or '-')) i++;
                list.Add(new CurlToken(start, i - start, CurlTokenKind.Number));
                continue;
            }
            if (char.IsAsciiLetter(c))
            {
                int start = i;
                while (i < s.Length && char.IsAsciiLetter(s[i])) i++;
                var word = s[start..i];
                bool literal = word.SequenceEqual("true") || word.SequenceEqual("false") || word.SequenceEqual("null");
                list.Add(new CurlToken(start, i - start, literal ? CurlTokenKind.Literal : CurlTokenKind.Plain));
                continue;
            }
            if (c is '{' or '}' or '[' or ']' or ',' or ':')
            {
                list.Add(new CurlToken(i, 1, CurlTokenKind.Punct));
                i++;
                continue;
            }
            i++;
        }
        return list.ToArray();
    }

    public static CurlToken[] LexXml(ReadOnlySpan<char> s)
    {
        var list = new List<CurlToken>();
        int i = 0;
        while (i < s.Length)
        {
            if (s[i] != '<') { i++; continue; }
            if (s[i..].StartsWith("<!--"))
            {
                int end = s[(i + 4)..].IndexOf("-->");
                int stop = end < 0 ? s.Length : i + 4 + end + 3;
                list.Add(new CurlToken(i, stop - i, CurlTokenKind.Comment));
                i = stop;
                continue;
            }
            // "<name" / "</name" / "<?xml" / "<!DOCTYPE"
            int tagStart = i;
            i++;
            if (i < s.Length && s[i] is '/' or '?' or '!') i++;
            while (i < s.Length && !char.IsWhiteSpace(s[i]) && s[i] is not ('>' or '/')) i++;
            list.Add(new CurlToken(tagStart, i - tagStart, CurlTokenKind.Tag));
            // attributes up to '>'
            while (i < s.Length && s[i] != '>')
            {
                char c = s[i];
                if (c == '"' || c == '\'')
                {
                    int q = s[(i + 1)..].IndexOf(c);
                    int stop = q < 0 ? s.Length : i + 1 + q + 1;
                    list.Add(new CurlToken(i, stop - i, CurlTokenKind.String));
                    i = stop;
                    continue;
                }
                if (char.IsLetter(c) || c is '_' or ':' or '-')
                {
                    int a = i;
                    while (i < s.Length && (char.IsLetterOrDigit(s[i]) || s[i] is '_' or ':' or '-' or '.')) i++;
                    list.Add(new CurlToken(a, i - a, CurlTokenKind.Attr));
                    continue;
                }
                if (c is '/' or '?' or '=') list.Add(new CurlToken(i, 1, CurlTokenKind.Punct));
                i++;
            }
            if (i < s.Length) { list.Add(new CurlToken(i, 1, CurlTokenKind.Tag)); i++; }
        }
        return list.ToArray();
    }

    // ---------------------------------------------------------------- search

    /// <summary>Start offsets of every match (case-insensitive), at most <paramref name="max"/>.</summary>
    public List<int> FindAll(string query, int max = 10_000)
    {
        var hits = new List<int>();
        if (string.IsNullOrEmpty(query)) return hits;
        int at = 0;
        while (hits.Count < max)
        {
            int i = Text.IndexOf(query, at, StringComparison.OrdinalIgnoreCase);
            if (i < 0) break;
            hits.Add(i);
            at = i + Math.Max(1, query.Length);
        }
        return hits;
    }
}
