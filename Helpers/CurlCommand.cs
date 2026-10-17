using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Echoes.Helpers;

/// <summary>The shell a pasted command was written for (decides quoting / escaping / line continuations).</summary>
public enum CurlShell { Bash, Cmd, PowerShell }

/// <summary>What <see cref="CurlCommand.Parse"/> made of a pasted curl command.</summary>
public sealed class CurlImportResult
{
    public CurlRequest Request { get; } = new();
    public string? Error { get; internal set; }
    public bool Ok => Error is null;
    public CurlShell Shell { get; internal set; }
    /// <summary>Options that change the request but aren't supported, as written ("--retry 3", "--cacert ca.pem").</summary>
    public List<string> Ignored { get; } = new();
    /// <summary>Other things worth saying (only the first URL used, variables kept as typed, …).</summary>
    public List<string> Notes { get; } = new();

    // Connection settings are the user's environment: the import changes them only when the command names them.
    public bool SetsProxy { get; internal set; }
    public bool SetsProxyUser { get; internal set; }
    public bool SetsOverride { get; internal set; }
    public bool SetsTimeout { get; internal set; }
    public bool SetsConnectTimeout { get; internal set; }
    public bool SetsMaxRedirects { get; internal set; }
    /// <summary>--interface as written (an IP, a NIC name, "if!eth0" / "host!1.2.3.4"), or null.</summary>
    public string? Interface { get; internal set; }

    /// <summary>"POST · 6 headers · JSON body · 2 cookies · Basic auth".</summary>
    public string Summary()
    {
        var r = Request;
        var bits = new List<string> { r.Method };
        int headers = r.Headers.Count(h => h.Enabled && h.Name.Length > 0);
        if (headers > 0) bits.Add(headers == 1 ? "1 header" : $"{headers} headers");
        int query = CurlRequest.SplitUrl(r.Url).Query.Count;
        if (query > 0) bits.Add(query == 1 ? "1 param" : $"{query} params");
        switch (r.BodyMode)
        {
            case CurlBodyMode.Raw: bits.Add((r.RawType == "text" ? "text" : r.RawType.ToUpperInvariant()) + " body"); break;
            case CurlBodyMode.Form: bits.Add("form body"); break;
            case CurlBodyMode.Multipart: bits.Add(r.Parts.Count == 1 ? "1 multipart field" : $"{r.Parts.Count} multipart fields"); break;
            case CurlBodyMode.File: bits.Add("file body"); break;
        }
        if (r.Cookies.Count > 0) bits.Add(r.Cookies.Count == 1 ? "1 cookie" : $"{r.Cookies.Count} cookies");
        if (r.Auth == CurlAuthMode.Basic) bits.Add("Basic auth");
        if (r.Auth == CurlAuthMode.Bearer) bits.Add("Bearer token");
        return string.Join(" · ", bits);
    }
}

/// <summary>
/// Reads a pasted curl command line — bash / zsh (Chrome, Edge, Firefox "Copy as cURL", Postman, Insomnia, docs), Windows
/// cmd (Chrome / Firefox "Copy as cURL (cmd)") or PowerShell (curl.exe with backtick continuations) — into a
/// <see cref="CurlRequest"/>, with curl's own rules for -d / -G / -F / -I / -X / -u / -b … Nothing is executed and no
/// variable is expanded: $VARS and $(…) stay as typed. Pure string work (AOT / trim safe).
/// </summary>
public static class CurlCommand
{
    // An optional prompt ("$ ", "> ", "PS C:\x> ", "C:\x>"), optional "sudo " / "& ", then curl / curl.exe / a path to it.
    private static readonly Regex StartRx = new(
        @"^[ \t]*(?:(?:\$|%|>|PS[ \t][^>\r\n]*>|[A-Za-z]:\\[^>\r\n]*>)[ \t]*)?(?:sudo[ \t]+|&[ \t]*)?(?<exe>""?(?:[^\s""'`]*[\\/])?curl(?:\.exe)?""?)(?=[ \t\r\n]|$)",
        RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    /// <summary>True when the text is a curl command (its first word is curl / curl.exe, after an optional prompt) with
    /// at least one argument — what the URL box imports instead of pasting.</summary>
    public static bool LooksLikeCurl(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        string t = StripFences(text.Replace("\r\n", "\n").Replace('\r', '\n')).TrimStart();
        try
        {
            var m = StartRx.Match(t);
            if (!m.Success || m.Index != 0) return false;
            return t[(m.Index + m.Length)..].Trim().Length > 0;
        }
        catch (RegexMatchTimeoutException) { return false; }
    }

    // A command pasted from a Markdown code block: drop the ``` fences around it.
    private static string StripFences(string t)
    {
        string s = t.Trim();
        if (s.StartsWith("```", StringComparison.Ordinal))
        {
            int nl = s.IndexOf('\n');
            s = nl < 0 ? string.Empty : s[(nl + 1)..];
            if (s.TrimEnd().EndsWith("```", StringComparison.Ordinal)) s = s.TrimEnd()[..^3];
        }
        return s;
    }

    /// <summary>
    /// The request the tab shows after an import: the command's request, with the connection settings — timeouts, the
    /// redirect limit, proxy, interface — kept from <paramref name="current"/> unless the command sets them. An override IP
    /// belongs to one host, so it's kept only while the imported URL has the same host.
    /// </summary>
    public static CurlRequest Merge(CurlRequest current, CurlImportResult imp)
    {
        var r = imp.Request.Clone();
        if (!imp.SetsTimeout) r.TimeoutSec = current.TimeoutSec;
        if (!imp.SetsConnectTimeout) r.ConnectTimeoutSec = current.ConnectTimeoutSec;
        if (!imp.SetsMaxRedirects) r.MaxRedirects = current.MaxRedirects;
        if (!imp.SetsProxy) r.Proxy = current.Proxy;
        if (!imp.SetsProxyUser)
        {
            // credentials belong to the proxy they were typed for
            r.ProxyUser = imp.SetsProxy ? null : current.ProxyUser;
            r.ProxyPass = imp.SetsProxy ? null : current.ProxyPass;
        }
        if (!imp.SetsOverride) r.OverrideIp = SameHost(current.Url, r.Url) ? current.OverrideIp : null;
        r.InterfaceIp = imp.Interface ?? current.InterfaceIp;
        return r;
    }

    private static bool SameHost(string a, string b)
        => Uri.TryCreate(CurlRequest.NormalizeUrl(a), UriKind.Absolute, out var ua) && Uri.TryCreate(CurlRequest.NormalizeUrl(b), UriKind.Absolute, out var ub)
           && string.Equals(ua.IdnHost, ub.IdnHost, StringComparison.OrdinalIgnoreCase);

    // ================================================================== entry point

    public static CurlImportResult Parse(string? text)
    {
        var r = new CurlImportResult();
        if (string.IsNullOrWhiteSpace(text)) { r.Error = "Nothing to import — paste a curl command."; return r; }

        string t = text.Replace("\r\n", "\n").Replace('\r', '\n');
        if (t.Length > 0 && t[0] == '\uFEFF') t = t[1..];
        t = StripFences(t);
        t = NormalizeSmartQuotes(t);

        Match m;
        try { m = StartRx.Match(t); }
        catch (RegexMatchTimeoutException) { r.Error = "That doesn't look like a curl command."; return r; }
        if (!m.Success) { r.Error = "That isn't a curl command — it should start with curl."; return r; }
        if (t[..m.Index].Trim().Length > 0) r.Notes.Add("Text before the curl command was skipped");

        string cmd = t[m.Groups["exe"].Index..];   // from the executable on
        var shell = DetectShell(cmd, m.Groups["exe"].Value);
        r.Shell = shell;

        var tz = new Tokenized();
        switch (shell)
        {
            case CurlShell.Cmd:
            {
                // Chrome's cmd quoting writes every quote as ^" and every backslash as ^\ (this app's own snippet leaves
                // backslashes bare); Firefox's has bare "…" with its own markers (see TokenizeCmd)
                string args = cmd[m.Groups["exe"].Length..];
                bool caretQuoted = !Regex.IsMatch(args, "(?<!\\^)\"");
                bool firefox = !caretQuoted && (FirefoxWinMarks(args) || BackslashRunsAllEven(args));
                TokenizeCmd(cmd, tz, firefox, halveBackslashes: caretQuoted ? CaretEscapedBackslash(args) : firefox);
                break;
            }
            case CurlShell.PowerShell: TokenizePowerShell(cmd, tz); break;
            default: TokenizeBash(cmd, tz); break;
        }
        if (tz.Tokens.Count == 0) { r.Error = "That isn't a curl command."; return r; }
        tz.Tokens.RemoveAt(0);   // the curl executable itself

        if (tz.Expanded) r.Notes.Add("Shell variables / $(…) were kept as typed — they aren't expanded");
        if (tz.Unterminated) r.Notes.Add("A quote wasn't closed — read to the end of the text");
        if (tz.Rest is { Length: > 0 } rest) r.Notes.Add("Ignored after the command: " + Shorten(rest, 40));

        new OptionReader(r, tz.Tokens, shell).Run();
        return r;
    }

    // Text copied out of a document often arrives with typographic quotes. Only when the command has no ASCII quote at
    // all (then they can't be data that a real quote encloses) are they read as quotes.
    private static string NormalizeSmartQuotes(string t)
    {
        if (t.IndexOf('\'') >= 0 || t.IndexOf('"') >= 0) return t;
        if (t.IndexOfAny(new[] { '\u2018', '\u2019', '\u201C', '\u201D' }) < 0) return t;
        return t.Replace('\u2018', '\'').Replace('\u2019', '\'').Replace('\u201C', '"').Replace('\u201D', '"');
    }

    private static CurlShell DetectShell(string cmd, string exe)
    {
        if (CaretOutsideSingleQuotes(cmd)) return CurlShell.Cmd;
        if (Regex.IsMatch(cmd, @"`[ \t]*\n")) return CurlShell.PowerShell;
        bool exeForm = exe.Trim('"').EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
        bool sqOutside = SingleQuoteOutsideDouble(cmd);
        if (exeForm)
        {
            if (cmd.Contains('`')) return CurlShell.PowerShell;
            if (sqOutside && !cmd.Contains("\\\n")) return CurlShell.PowerShell;   // cmd has no single quotes
            if (!cmd.Contains("\\\n") && !sqOutside) return CurlShell.Cmd;
        }
        // Firefox's "Copy as cURL (Windows)": only "…" quoting, "" for a quote inside, "%" for a percent sign, `$ / ``.
        if (!sqOutside && !cmd.Contains("\\\n") && FirefoxWinMarks(cmd)) return CurlShell.Cmd;
        return CurlShell.Bash;
    }

    // A ^\ escape pair (Chrome escapes every backslash for cmd.exe; nothing else needs to). Read pair by pair, so an
    // escaped caret followed by a bare backslash (^^\) doesn't count.
    private static bool CaretEscapedBackslash(string s)
    {
        bool cmdQuote = false;
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (c == '"') { cmdQuote = !cmdQuote; continue; }
            if (c != '^' || cmdQuote || i + 1 >= s.Length) continue;
            if (s[i + 1] == '\\') return true;
            i++;   // the escaped character
        }
        return false;
    }

    // Firefox's "Copy as cURL (Windows)" markers: "" for a quote inside "…", "%" for a percent sign, `` / `$ for a backtick
    // / dollar, "^ + newline for a line break.
    private static bool FirefoxWinMarks(string s)
        => QuoteQuoteInsideWord(s) || s.Contains("\"%\"", StringComparison.Ordinal) || s.Contains("``", StringComparison.Ordinal)
           || s.Contains("`$", StringComparison.Ordinal) || s.Contains("\"^\n", StringComparison.Ordinal);

    // Every backslash run that isn't a quote escape has an even length — what a generator that doubles each one leaves
    // (a hand-typed Windows path has single ones).
    private static bool BackslashRunsAllEven(string s)
    {
        bool any = false;
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] != '\\') continue;
            int k = i;
            while (k < s.Length && s[k] == '\\') k++;
            if (k < s.Length && s[k] == '"') { i = k; continue; }
            if ((k - i) % 2 == 1) return false;
            any = true;
            i = k - 1;
        }
        return any;
    }

    // "" that isn't a standalone empty argument: a quote inside a Windows "…" string ("a""b", ": ""x").
    private static bool QuoteQuoteInsideWord(string s)
    {
        for (int i = s.IndexOf("\"\"", StringComparison.Ordinal); i >= 0; i = s.IndexOf("\"\"", i + 2, StringComparison.Ordinal))
        {
            bool before = i == 0 || char.IsWhiteSpace(s[i - 1]);
            bool after = i + 2 >= s.Length || char.IsWhiteSpace(s[i + 2]);
            if (!(before && after)) return true;
        }
        return false;
    }

    // cmd.exe's marks — a ^" quote or a ^ line continuation — outside any quoted string ('…', $'…' or "…", where a bash
    // command may well carry them as data).
    private static bool CaretOutsideSingleQuotes(string s)
    {
        bool inSingle = false, ansi = false, inDouble = false;
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (inSingle)
            {
                if (ansi && c == '\\') { i++; continue; }
                if (c == '\'') inSingle = false;
                continue;
            }
            if (inDouble)
            {
                if (c == '\\') { i++; continue; }
                if (c == '"') inDouble = false;
                continue;
            }
            if (c == '^')
            {
                if (i + 1 < s.Length && s[i + 1] == '"') return true;
                int j = i + 1;
                while (j < s.Length && (s[j] == ' ' || s[j] == '\t')) j++;
                if (j < s.Length && s[j] == '\n') return true;
                continue;
            }
            if (c == '\'') { inSingle = true; ansi = i > 0 && s[i - 1] == '$'; continue; }
            if (c == '"') { inDouble = true; continue; }
            if (c == '\\') i++;
        }
        return false;
    }

    // A ' outside every "…" — how a POSIX shell command quotes; a Windows one only ever has them inside "…".
    private static bool SingleQuoteOutsideDouble(string s)
    {
        bool inDq = false;
        foreach (char c in s)
        {
            if (c == '"') inDq = !inDq;
            else if (c == '\'' && !inDq) return true;
        }
        return false;
    }

    private static string Shorten(string s, int max)
    {
        s = s.Replace('\n', ' ').Trim();
        return s.Length <= max ? s : s[..max] + "…";
    }

    private sealed class Tokenized
    {
        public readonly List<string> Tokens = new();
        public bool Expanded;
        public bool Unterminated;
        public string? Rest;
    }

    // ================================================================== bash / zsh / sh

    private static void TokenizeBash(string s, Tokenized tz)
    {
        var sb = new StringBuilder();
        bool inTok = false;
        int i = 0;
        int n = s.Length;

        void End()
        {
            if (inTok) { tz.Tokens.Add(sb.ToString()); sb.Clear(); inTok = false; }
        }

        while (i < n)
        {
            char c = s[i];

            if (c == '\\')
            {
                if (i + 1 < n && s[i + 1] == '\n') { i += 2; continue; }                // line continuation
                if (i + 1 < n) { sb.Append(s[i + 1]); inTok = true; i += 2; continue; }
                i++; continue;
            }
            if (c == '\'')
            {
                int close = s.IndexOf('\'', i + 1);
                if (close < 0) { sb.Append(s, i + 1, n - i - 1); tz.Unterminated = true; inTok = true; i = n; continue; }
                sb.Append(s, i + 1, close - i - 1); inTok = true; i = close + 1; continue;
            }
            if (c == '$' && i + 1 < n && s[i + 1] == '\'')
            {
                i = ReadAnsiC(s, i + 2, sb, tz); inTok = true; continue;
            }
            if (c == '"' || (c == '$' && i + 1 < n && s[i + 1] == '"'))
            {
                i = ReadBashDouble(s, c == '$' ? i + 2 : i + 1, sb, tz); inTok = true; continue;
            }
            if (c == '$' && i + 1 < n && (s[i + 1] == '(' || s[i + 1] == '{' || char.IsLetter(s[i + 1]) || s[i + 1] == '_'))
            {
                i = CopyExpansion(s, i, sb); tz.Expanded = true; inTok = true; continue;
            }
            if (c == '`')
            {
                int close = s.IndexOf('`', i + 1);
                int end = close < 0 ? n : close + 1;
                sb.Append(s, i, end - i); tz.Expanded = true; inTok = true; i = end; continue;
            }
            if (c == '#' && !inTok)
            {
                int nl = s.IndexOf('\n', i);
                i = nl < 0 ? n : nl;
                continue;
            }
            if (c == '\n')
            {
                End();
                // A bare newline ends a shell command. Commands copied out of docs often lost their " \" though: a
                // following line that starts with an option, a quote or a URL still belongs to this one.
                int j = i + 1;
                while (j < n && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n')) j++;
                if (j >= n) break;
                if (s[j] == '-' || s[j] == '\'' || s[j] == '"' || s.AsSpan(j).StartsWith("http", StringComparison.OrdinalIgnoreCase))
                { i = j; continue; }
                tz.Rest = s[j..];
                break;
            }
            if (c == ' ' || c == '\t') { End(); i++; continue; }

            if (c == '|' || c == ';' || (c == '&' && IsCommandAmp(s, i, inTok)))
            {
                End();
                string rest = s[i..].Trim();
                if (rest.Length > 0) tz.Rest = rest;
                return;
            }
            if (c == '>' || c == '<')
            {
                // a redirect: "> out.json", "2>/dev/null", "2>&1", "< body.json" — drop it (and a bare fd number before it)
                if (inTok && sb.Length > 0 && sb.ToString().All(char.IsDigit)) { sb.Clear(); inTok = false; }
                End();
                int j = i + 1;
                if (j < n && (s[j] == '>' || s[j] == '&')) j++;
                while (j < n && (s[j] == ' ' || s[j] == '\t')) j++;
                int start = j;
                while (j < n && !char.IsWhiteSpace(s[j])) j++;
                tz.Rest = (tz.Rest is null ? "" : tz.Rest + " ") + (c + " " + s[start..j]).Trim();
                i = j;
                continue;
            }

            sb.Append(c);
            inTok = true;
            i++;
        }
        End();
    }

    // '&' ends the command ("cmd &", "a && b"); inside a word it's part of an unquoted URL ("?a=1&b=2").
    private static bool IsCommandAmp(string s, int i, bool inTok)
    {
        if (i + 1 < s.Length && s[i + 1] == '&') return true;
        if (!inTok) return true;
        return i + 1 >= s.Length || char.IsWhiteSpace(s[i + 1]);
    }

    // "…" in bash: \ escapes only $ ` " \ and newline; $VAR / $(…) are kept as typed.
    private static int ReadBashDouble(string s, int i, StringBuilder sb, Tokenized tz)
    {
        int n = s.Length;
        while (i < n)
        {
            char c = s[i];
            if (c == '"') return i + 1;
            if (c == '\\' && i + 1 < n)
            {
                char d = s[i + 1];
                if (d == '\n') { i += 2; continue; }
                if (d is '$' or '`' or '"' or '\\') { sb.Append(d); i += 2; continue; }
                sb.Append('\\'); i++; continue;
            }
            if (c == '$' && i + 1 < n && (s[i + 1] == '(' || s[i + 1] == '{' || char.IsLetter(s[i + 1]) || s[i + 1] == '_'))
            {
                i = CopyExpansion(s, i, sb); tz.Expanded = true; continue;
            }
            if (c == '`') tz.Expanded = true;
            sb.Append(c);
            i++;
        }
        tz.Unterminated = true;
        return n;
    }

    // $NAME, ${…} or $(…) copied verbatim (balanced, quotes inside skipped).
    private static int CopyExpansion(string s, int i, StringBuilder sb)
    {
        int n = s.Length;
        int start = i;
        i++;   // '$'
        if (i < n && (s[i] == '(' || s[i] == '{'))
        {
            char open = s[i], close = open == '(' ? ')' : '}';
            int depth = 0;
            while (i < n)
            {
                char c = s[i];
                if (c == '\'' ) { int q = s.IndexOf('\'', i + 1); i = q < 0 ? n : q + 1; continue; }
                if (c == open) depth++;
                else if (c == close && --depth == 0) { i++; break; }
                i++;
            }
        }
        else
        {
            while (i < n && (char.IsLetterOrDigit(s[i]) || s[i] == '_')) i++;
        }
        sb.Append(s, start, i - start);
        return i;
    }

    // $'…' (bash ANSI-C quoting): \n \t \r \\ \' \" \xHH \uHHHH \UHHHHHHHH \NNN (octal) \e \a \b \f \v \cX
    private static int ReadAnsiC(string s, int i, StringBuilder sb, Tokenized tz)
    {
        int n = s.Length;
        while (i < n)
        {
            char c = s[i];
            if (c == '\'') return i + 1;
            if (c != '\\' || i + 1 >= n) { sb.Append(c); i++; continue; }
            char d = s[i + 1];
            i += 2;
            switch (d)
            {
                case 'n': sb.Append('\n'); break;
                case 't': sb.Append('\t'); break;
                case 'r': sb.Append('\r'); break;
                case 'a': sb.Append('\a'); break;
                case 'b': sb.Append('\b'); break;
                case 'f': sb.Append('\f'); break;
                case 'v': sb.Append('\v'); break;
                case 'e': case 'E': sb.Append('\u001B'); break;
                case '\\': sb.Append('\\'); break;
                case '\'': sb.Append('\''); break;
                case '"': sb.Append('"'); break;
                case '?': sb.Append('?'); break;
                case 'c':
                    if (i < n) { sb.Append((char)(s[i] & 0x1F)); i++; }
                    break;
                case 'x':
                    i = AppendHex(s, i, 2, sb, bytes: true);
                    break;
                case 'u':
                    i = AppendHex(s, i, 4, sb, bytes: false);
                    break;
                case 'U':
                    i = AppendHex(s, i, 8, sb, bytes: false);
                    break;
                default:
                    if (d is >= '0' and <= '7')
                    {
                        int v = d - '0', k = 0;
                        while (k < 2 && i < n && s[i] is >= '0' and <= '7') { v = v * 8 + (s[i] - '0'); i++; k++; }
                        AppendByte(sb, (byte)(v & 0xFF));
                    }
                    else { sb.Append('\\').Append(d); }
                    break;
            }
        }
        tz.Unterminated = true;
        return n;
    }

    // \xHH bytes are collected as raw bytes and decoded as UTF-8 together (Chrome writes non-ASCII as \u, but a
    // hand-written $'\xc3\xa9' is UTF-8 bytes).
    private static int AppendHex(string s, int i, int max, StringBuilder sb, bool bytes)
    {
        int start = i, v = 0;
        while (i < s.Length && i - start < max && Uri.IsHexDigit(s[i])) { v = v * 16 + Convert.ToInt32(s[i].ToString(), 16); i++; }
        if (i == start) { sb.Append(bytes ? "\\x" : (max == 4 ? "\\u" : "\\U")); return i; }
        if (bytes) AppendByte(sb, (byte)v);
        else if (max == 4) sb.Append((char)v);   // a UTF-16 unit: Chrome writes an emoji as 😀 — the halves pair up
        else if (v <= 0x10FFFF && (v < 0xD800 || v > 0xDFFF)) sb.Append(char.ConvertFromUtf32(v));
        return i;
    }

    // Raw bytes from \x / octal escapes: kept in a private-use marker range and folded into UTF-8 text afterwards.
    private static void AppendByte(StringBuilder sb, byte b)
    {
        if (b < 0x80) { sb.Append((char)b); return; }
        sb.Append((char)(0xF700 + b));   // marker, see FoldBytes
    }

    // Turns runs of marker chars (raw bytes > 0x7F) back into text: UTF-8 when the run is valid UTF-8 (a hand-written
    // $'\xc3\xa9'), else one Latin-1 character per byte \u2014 Firefox writes "\u00E9" as \xe9 (its char code), not as UTF-8.
    private static readonly Encoding StrictUtf8 = new UTF8Encoding(false, throwOnInvalidBytes: true);

    private static string FoldBytes(string token)
    {
        int first = -1;
        for (int k = 0; k < token.Length; k++) if (token[k] is >= '\uF780' and <= '\uF7FF') { first = k; break; }
        if (first < 0) return token;
        var sb = new StringBuilder(token.Length);
        var buf = new List<byte>();
        void Flush()
        {
            if (buf.Count == 0) return;
            byte[] bytes = buf.ToArray();
            try { sb.Append(StrictUtf8.GetString(bytes)); }
            catch (DecoderFallbackException) { foreach (byte b in bytes) sb.Append((char)b); }
            buf.Clear();
        }
        foreach (char ch in token)
        {
            if (ch is >= '\uF780' and <= '\uF7FF') { buf.Add((byte)(ch - 0xF700)); continue; }
            Flush();
            sb.Append(ch);
        }
        Flush();
        return sb.ToString();
    }

    // ================================================================== Windows cmd.exe (+ the MS C runtime's argv rules)

    // Two layers, as Windows runs it: cmd.exe first (^ escapes and ^-newline continuations, outside its own "quotes"),
    // then the C runtime splits the line into argv ("…" groups, \" is a quote, "" inside quotes is a quote, backslashes
    // are literal unless a quote follows them). The browsers' "Copy as cURL" double EVERY backslash, though — Chrome's
    // writes each as ^\^\ inside ^"…^", Firefox's as \\ inside "…" (plus "" for a quote, "%" for a percent sign, `$ for a
    // dollar) — so real curl.exe receives them doubled. Their commands are read the way the browser meant them
    // (halveBackslashes); everything else, this app's own "curl (cmd)" snippet included, by the C runtime's rule.
    private static void TokenizeCmd(string s, Tokenized tz, bool firefox, bool halveBackslashes)
    {
        // ---- layer 1: cmd.exe
        var line = new StringBuilder(s.Length);
        bool cmdQuote = false;
        int i = 0, n = s.Length;
        while (i < n)
        {
            char c = s[i];
            if (c == '"') { cmdQuote = !cmdQuote; line.Append(c); i++; continue; }
            if (c == '^' && !cmdQuote)
            {
                if (i + 1 >= n) { i++; continue; }
                char d = s[i + 1];
                if (d == '\n')
                {
                    i += 2;                         // continuation; the next char is taken literally
                    if (i < n) { line.Append(s[i] == '"' ? '\u0001' : s[i]); i++; }
                    continue;
                }
                line.Append(d == '"' ? '\u0001' : d);   // ^" is a quote cmd.exe doesn't see; the C runtime does
                i += 2;
                continue;
            }
            if (c == '\n')
            {
                string rest = s[(i + 1)..].Trim();
                if (rest.Length > 0) tz.Rest = rest;
                break;
            }
            if (!cmdQuote && (c == '|' || (c == '&' && (i + 1 < n && s[i + 1] == '&' || i + 1 >= n || s[i + 1] == ' '))))
            {
                string rest = s[i..].Trim();
                if (rest.Length > 0) tz.Rest = rest;
                break;
            }
            if (!cmdQuote && (c == '>' || c == '<'))
            {
                int j = i + 1;
                if (j < n && (s[j] == '>' || s[j] == '&')) j++;
                while (j < n && s[j] == ' ') j++;
                int start = j;
                while (j < n && !char.IsWhiteSpace(s[j])) j++;
                tz.Rest = (tz.Rest is null ? "" : tz.Rest + " ") + (c + " " + s[start..j]).Trim();
                i = j;
                continue;
            }
            line.Append(c);
            i++;
        }

        // ---- layer 2: C runtime argv
        string a = line.ToString().Replace('\u0001', '"');
        var sb = new StringBuilder();
        bool inTok = false, inQuote = false;
        n = a.Length;
        for (i = 0; i < n; i++)
        {
            char c = a[i];
            if (c == '\\')
            {
                int k = i;
                while (k < n && a[k] == '\\') k++;
                int count = k - i;
                if (k < n && a[k] == '"')
                {
                    sb.Append('\\', count / 2);
                    if (count % 2 == 1) { sb.Append('"'); i = k; }        // \" → a literal quote
                    else i = k - 1;                                       // the quote itself is handled next
                }
                else
                {
                    // not before a quote: literal for the C runtime, doubled by a browser (see above)
                    sb.Append('\\', halveBackslashes ? count / 2 + count % 2 : count);
                    i = k - 1;
                }
                inTok = true;
                continue;
            }
            if (c == '"')
            {
                if (inQuote && i + 1 < n && a[i + 1] == '"') { sb.Append('"'); i++; inTok = true; continue; }   // "" in quotes
                inQuote = !inQuote;
                inTok = true;
                continue;
            }
            // Firefox's Windows command (no ^"…^" quoting) escapes for PowerShell too: `$ for $ and `` for a backtick
            if (firefox && c == '`' && i + 1 < n && (a[i + 1] == '$' || a[i + 1] == '`')) { sb.Append(a[i + 1]); i++; inTok = true; continue; }
            if ((c == ' ' || c == '\t') && !inQuote)
            {
                if (inTok) { tz.Tokens.Add(sb.ToString()); sb.Clear(); inTok = false; }
                continue;
            }
            sb.Append(c);
            inTok = true;
        }
        if (inQuote) tz.Unterminated = true;
        if (inTok) tz.Tokens.Add(sb.ToString());
    }

    // ================================================================== PowerShell (curl.exe …)

    private static void TokenizePowerShell(string s, Tokenized tz)
    {
        var sb = new StringBuilder();
        bool inTok = false;
        int i = 0, n = s.Length;

        void End()
        {
            if (inTok) { tz.Tokens.Add(sb.ToString()); sb.Clear(); inTok = false; }
        }

        while (i < n)
        {
            char c = s[i];
            if (c == '`')
            {
                if (i + 1 < n && s[i + 1] == '\n') { i += 2; continue; }   // continuation
                if (i + 1 < n) { sb.Append(PsEscape(s[i + 1])); inTok = true; i += 2; continue; }
                i++; continue;
            }
            if (c == '\'')
            {
                i++;
                while (i < n)
                {
                    if (s[i] == '\'')
                    {
                        if (i + 1 < n && s[i + 1] == '\'') { sb.Append('\''); i += 2; continue; }
                        break;
                    }
                    sb.Append(s[i]); i++;
                }
                if (i >= n) tz.Unterminated = true;
                i++; inTok = true; continue;
            }
            if (c == '"')
            {
                i++;
                while (i < n)
                {
                    char d = s[i];
                    if (d == '`' && i + 1 < n)
                    {
                        if (s[i + 1] == '\n') { i += 2; continue; }
                        sb.Append(PsEscape(s[i + 1])); i += 2; continue;
                    }
                    if (d == '"')
                    {
                        if (i + 1 < n && s[i + 1] == '"') { sb.Append('"'); i += 2; continue; }
                        break;
                    }
                    if (d == '$' && i + 1 < n && (s[i + 1] == '(' || s[i + 1] == '{' || char.IsLetter(s[i + 1]) || s[i + 1] == '_'))
                    {
                        i = CopyExpansion(s, i, sb); tz.Expanded = true; continue;
                    }
                    sb.Append(d); i++;
                }
                if (i >= n) tz.Unterminated = true;
                i++; inTok = true; continue;
            }
            if (c == '$' && i + 1 < n && (s[i + 1] == '(' || s[i + 1] == '{' || char.IsLetter(s[i + 1]) || s[i + 1] == '_'))
            {
                i = CopyExpansion(s, i, sb); tz.Expanded = true; inTok = true; continue;
            }
            if (c == '\n')
            {
                End();
                int j = i + 1;
                while (j < n && char.IsWhiteSpace(s[j])) j++;
                if (j >= n) break;
                if (s[j] == '-' || s[j] == '\'' || s[j] == '"' || s.AsSpan(j).StartsWith("http", StringComparison.OrdinalIgnoreCase))
                { i = j; continue; }
                tz.Rest = s[j..];
                break;
            }
            if (c == ' ' || c == '\t') { End(); i++; continue; }
            if (c == '|' || c == ';')
            {
                End();
                tz.Rest = s[i..].Trim();
                return;
            }
            if (c == '>' && !inTok)
            {
                int j = i + 1;
                while (j < n && s[j] == ' ') j++;
                int start = j;
                while (j < n && !char.IsWhiteSpace(s[j])) j++;
                tz.Rest = (tz.Rest is null ? "" : tz.Rest + " ") + ("> " + s[start..j]).Trim();
                i = j;
                continue;
            }
            sb.Append(c);
            inTok = true;
            i++;
        }
        End();
    }

    private static string PsEscape(char c) => c switch
    {
        'n' => "\n", 't' => "\t", 'r' => "\r", '0' => "\0", 'a' => "\a", 'b' => "\b", 'f' => "\f", 'v' => "\v", 'e' => "\u001B",
        _ => c.ToString(),
    };

    // ================================================================== curl options

    // Long options that take a value (curl 8.x "--help all"); every other option is a switch.
    private static readonly HashSet<string> LongWithValue = new(StringComparer.Ordinal)
    {
        "abstract-unix-socket", "alt-svc", "aws-sigv4", "cacert", "capath", "cert", "cert-type", "ciphers", "config",
        "connect-timeout", "connect-to", "continue-at", "cookie", "cookie-jar", "create-file-mode", "crlfile", "curves",
        "data", "data-ascii", "data-binary", "data-raw", "data-urlencode", "delegation", "dns-interface", "dns-ipv4-addr",
        "dns-ipv6-addr", "dns-servers", "doh-url", "dump-header", "ech", "egd-file", "engine", "etag-compare", "etag-save",
        "expect100-timeout", "form", "form-string", "ftp-account", "ftp-alternative-to-user", "ftp-method", "ftp-port",
        "ftp-ssl-ccc-mode", "happy-eyeballs-timeout-ms", "haproxy-clientip", "header", "hostpubmd5", "hostpubsha256", "hsts",
        "interface", "ip-tos", "ipfs-gateway", "json", "keepalive-cnt", "keepalive-time", "key", "key-type", "krb", "libcurl",
        "limit-rate", "local-port", "login-options", "mail-auth", "mail-from", "mail-rcpt", "max-filesize", "max-redirs",
        "max-time", "netrc-file", "noproxy", "oauth2-bearer", "output", "output-dir", "parallel-max", "pass", "pinnedpubkey",
        "preproxy", "proto", "proto-default", "proto-redir", "proxy", "proxy-cacert", "proxy-capath", "proxy-cert",
        "proxy-cert-type", "proxy-ciphers", "proxy-crlfile", "proxy-header", "proxy-key", "proxy-key-type", "proxy-pass",
        "proxy-pinnedpubkey", "proxy-service-name", "proxy-tls13-ciphers", "proxy-tlsauthtype", "proxy-tlspassword",
        "proxy-tlsuser", "proxy-user", "proxy1.0", "quote", "random-file", "range", "rate", "referer", "request",
        "request-target", "resolve", "retry", "retry-delay", "retry-max-time", "sasl-authzid", "service-name", "socks4",
        "socks4a", "socks5", "socks5-gssapi-service", "socks5-hostname", "speed-limit", "speed-time", "stderr",
        "telnet-option", "tftp-blksize", "time-cond", "tls-max", "tls13-ciphers", "tlsauthtype", "tlspassword", "tlsuser",
        "trace", "trace-ascii", "trace-config", "unix-socket", "upload-file", "url", "url-query", "user", "user-agent",
        "variable", "write-out", "vlan-priority", "ip-tos", "upload-flags", "knownhosts", "ssl-sessions", "out-null",
    };

    private static readonly Dictionary<char, string> ShortNames = new()
    {
        ['A'] = "user-agent", ['b'] = "cookie", ['c'] = "cookie-jar", ['C'] = "continue-at", ['d'] = "data",
        ['D'] = "dump-header", ['e'] = "referer", ['E'] = "cert", ['F'] = "form", ['H'] = "header", ['K'] = "config",
        ['m'] = "max-time", ['o'] = "output", ['P'] = "ftp-port", ['Q'] = "quote", ['r'] = "range", ['T'] = "upload-file",
        ['t'] = "telnet-option", ['u'] = "user", ['U'] = "proxy-user", ['w'] = "write-out", ['x'] = "proxy",
        ['X'] = "request", ['y'] = "speed-time", ['Y'] = "speed-limit", ['z'] = "time-cond",
        ['0'] = "http1.0", ['1'] = "tlsv1", ['2'] = "sslv2", ['3'] = "sslv3", ['4'] = "ipv4", ['6'] = "ipv6",
        ['a'] = "append", ['B'] = "use-ascii", ['f'] = "fail", ['g'] = "globoff", ['G'] = "get", ['h'] = "help",
        ['i'] = "include", ['I'] = "head", ['j'] = "junk-session-cookies", ['J'] = "remote-header-name", ['k'] = "insecure",
        ['l'] = "list-only", ['L'] = "location", ['M'] = "manual", ['n'] = "netrc", ['N'] = "no-buffer",
        ['O'] = "remote-name", ['p'] = "proxytunnel", ['q'] = "disable", ['R'] = "remote-time", ['s'] = "silent",
        ['S'] = "show-error", ['v'] = "verbose", ['V'] = "version", ['Z'] = "parallel", ['#'] = "progress-bar",
        [':'] = "next",
    };

    // Options that only shape curl's own output / progress / retries — not the request. Accepted without a word.
    private static readonly HashSet<string> Quiet = new(StringComparer.Ordinal)
    {
        "silent", "show-error", "verbose", "include", "progress-bar", "no-progress-meter", "fail", "fail-with-body",
        "fail-early", "no-buffer", "globoff", "output", "output-dir", "remote-name", "remote-name-all", "remote-header-name",
        "dump-header", "write-out", "trace", "trace-ascii", "trace-time", "trace-ids", "trace-config", "stderr", "libcurl",
        "create-dirs", "create-file-mode", "remote-time", "styled-output", "xattr", "junk-session-cookies", "path-as-is",
        "tcp-nodelay", "ssl-no-revoke", "ssl-revoke-best-effort", "disable", "keepalive-time", "keepalive-cnt",
        "no-keepalive", "keepalive", "proxytunnel", "proxy-basic", "basic", "raw", "skip-existing", "remove-on-error",
        "clobber", "no-clobber", "parallel", "parallel-immediate", "parallel-max", "suppress-connect-headers", "sessionid",
        "no-sessionid", "alpn", "no-alpn", "npn", "no-npn", "compressed-ssh", "buffer", "out-null", "rate", "help", "manual",
        "version", "tcp-fastopen", "happy-eyeballs-timeout-ms", "proto", "proto-redir", "proto-default", "max-filesize",
        "ssl-allow-beast", "ssl-auto-client-cert", "progress-meter", "doh-insecure", "netrc-optional",
    };

    private enum DataKind { Data, Binary, Raw, UrlEncode, Json }

    private sealed class OptionReader
    {
        private readonly CurlImportResult _r;
        private readonly List<string> _t;
        private readonly CurlShell _shell;
        private readonly CurlRequest _req;

        private readonly List<string> _urls = new();
        private string? _method;
        private bool _head, _get;
        private readonly List<(DataKind Kind, string Value)> _data = new();
        private string? _uploadFile;
        private readonly List<string> _urlQuery = new();
        private bool _authOther;
        private string? _userAgent, _referer;   // -A / -e: curl's own headers, which a custom -H of that name replaces
        private bool _follow, _insecure, _compressed;
        private CurlHttpVersion _http;
        private string? _resolve, _connectTo;
        private readonly List<string> _ignored = new();
        private bool _stopped;

        public OptionReader(CurlImportResult r, List<string> tokens, CurlShell shell)
        {
            _r = r; _t = tokens; _shell = shell; _req = r.Request;
            _req.FollowRedirects = false;   // curl's defaults; the command turns them on
            _req.Compressed = false;
            _req.Insecure = false;
        }

        public void Run()
        {
            for (int i = 0; i < _t.Count && !_stopped; i++)
            {
                string tok = FoldBytes(_t[i]);
                if (tok.StartsWith("--", StringComparison.Ordinal) && tok.Length > 2)
                {
                    string name = tok[2..];
                    string? inline = null;
                    if (!LongWithValue.Contains(name) && !IsSwitch(name, out _))
                    {
                        int eq = name.IndexOf('=');
                        if (eq > 0 && LongWithValue.Contains(name[..eq])) { inline = name[(eq + 1)..]; name = name[..eq]; }
                    }
                    if (LongWithValue.Contains(name))
                    {
                        string? value = inline;
                        if (value is null)
                        {
                            if (i + 1 < _t.Count) value = FoldBytes(_t[++i]);
                            else { _r.Notes.Add($"--{name} has no value — skipped"); continue; }
                        }
                        Apply(name, value, "--" + name);
                    }
                    else
                    {
                        bool on = true;
                        if (!IsSwitch(name, out _) && name.StartsWith("no-", StringComparison.Ordinal)) { on = false; name = name[3..]; }
                        Switch(name, on, tok);
                    }
                }
                else if (tok.Length > 1 && tok[0] == '-' && tok != "-")
                {
                    // a cluster of short options: -sSL, -XPOST, -d@file, -H'X: y' (value glued on)
                    for (int k = 1; k < tok.Length; k++)
                    {
                        char ch = tok[k];
                        if (!ShortNames.TryGetValue(ch, out var name))
                        {
                            _ignored.Add("-" + ch);
                            continue;
                        }
                        if (LongWithValue.Contains(name))
                        {
                            string? value = k + 1 < tok.Length ? tok[(k + 1)..] : (i + 1 < _t.Count ? FoldBytes(_t[++i]) : null);
                            if (value is null) _r.Notes.Add($"-{ch} has no value — skipped");
                            else Apply(name, value, "-" + ch);
                            break;
                        }
                        Switch(name, true, "-" + ch);
                    }
                }
                else
                {
                    _urls.Add(tok);   // curl reads any non-option word as a URL
                }
            }
            Finish();
        }

        private static readonly HashSet<string> Switches = new(StringComparer.Ordinal)
        {
            "insecure", "location", "location-trusted", "compressed", "get", "head", "http1.0", "http1.1", "http2",
            "http2-prior-knowledge", "http3", "http3-only", "digest", "ntlm", "ntlm-wb", "negotiate", "anyauth",
            "ipv4", "ipv6", "next", "post301", "post302", "post303", "proxy-insecure", "proxy-digest", "proxy-ntlm",
            "proxy-negotiate", "proxy-anyauth", "ssl", "ssl-reqd", "tlsv1", "tlsv1.0", "tlsv1.1", "tlsv1.2", "tlsv1.3",
            "sslv2", "sslv3", "netrc", "append", "use-ascii", "list-only", "ignore-content-length", "tr-encoding",
            "retry-connrefused", "retry-all-errors", "cert-status", "false-start", "disallow-username-in-url", "mptcp",
            "proxy-http2", "proxy-ssl-auto-client-cert", "sasl-ir", "crlf", "ftp-create-dirs", "ftp-pasv", "ftp-skip-pasv-ip",
            "ftp-ssl-ccc", "ftp-ssl-control", "ftp-pret", "ftp-ssl", "ftp-ssl-reqd", "socks5-basic", "socks5-gssapi",
            "socks5-gssapi-nec", "metalink", "http0.9", "no-http0.9", "insecure-proxy",
        };

        private static bool IsSwitch(string name, out bool quiet)
        {
            quiet = Quiet.Contains(name);
            return Switches.Contains(name) || quiet;
        }

        private void Switch(string name, bool on, string asTyped)
        {
            switch (name)
            {
                case "insecure": _insecure = on; break;
                case "location": _follow = on; break;
                case "location-trusted":
                    _follow = on;
                    _r.Notes.Add("--location-trusted: headers and credentials are still sent only to the original host");
                    break;
                case "compressed": _compressed = on; break;
                case "get": _get = on; break;
                case "head": _head = on; break;
                case "http1.0":
                    _http = CurlHttpVersion.Http1;
                    _r.Notes.Add("--http1.0 isn't offered — HTTP/1.1 is used");
                    break;
                case "http1.1": _http = CurlHttpVersion.Http1; break;
                case "http2": case "http2-prior-knowledge": _http = CurlHttpVersion.Http2; break;
                case "http3": case "http3-only": _http = CurlHttpVersion.Http3; break;
                case "digest": case "ntlm": case "ntlm-wb": case "negotiate": case "anyauth":
                    _authOther = true;
                    _ignored.Add(asTyped);
                    break;
                case "next":
                    _stopped = true;
                    _r.Notes.Add("Only the first request was imported (the command continues after --next)");
                    break;
                default:
                    if (!Quiet.Contains(name)) _ignored.Add(asTyped);
                    break;
            }
        }

        private void Apply(string name, string value, string asTyped)
        {
            switch (name)
            {
                case "url": _urls.Add(value); break;
                case "request": _method = value; break;
                case "header": AddHeader(value); break;
                case "user-agent":
                    if (value.Length == 0) _r.Notes.Add("-A \"\" (send no User-Agent) isn't supported — the engine's own is sent");
                    else _userAgent = value;
                    break;
                case "referer":
                {
                    string v = value;
                    if (v.EndsWith(";auto", StringComparison.OrdinalIgnoreCase)) v = v[..^5];
                    if (v.Length > 0 && !v.Equals("auto", StringComparison.OrdinalIgnoreCase)) _referer = v;
                    break;
                }
                case "cookie":
                    if (value.Contains('=')) AddCookies(value);
                    else _ignored.Add($"{asTyped} {Shorten(value, 24)} (cookie file)");
                    break;
                case "cookie-jar": _ignored.Add($"{asTyped} {Shorten(value, 24)}"); break;
                case "user": SetUser(value); break;
                case "oauth2-bearer":
                    _req.Auth = CurlAuthMode.Bearer;
                    _req.AuthToken = value;
                    break;
                case "data": case "data-ascii": _data.Add((DataKind.Data, FixPsJson(value))); break;
                case "data-binary": _data.Add((DataKind.Binary, FixPsJson(value))); break;
                case "data-raw": _data.Add((DataKind.Raw, FixPsJson(value))); break;
                case "data-urlencode": _data.Add((DataKind.UrlEncode, value)); break;
                case "json": _data.Add((DataKind.Json, FixPsJson(value))); break;
                case "form": AddPart(value, literal: false); break;
                case "form-string": AddPart(value, literal: true); break;
                case "upload-file": _uploadFile = value; break;
                case "url-query": _urlQuery.Add(value); break;
                case "max-redirs":
                    if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int mr))
                    {
                        _req.MaxRedirects = mr < 0 ? 50 : Math.Min(mr, 50);
                        _r.SetsMaxRedirects = true;
                    }
                    break;
                case "max-time":
                    if (TryCeil(value, out int mt)) { _req.TimeoutSec = mt; _r.SetsTimeout = true; }
                    break;
                case "connect-timeout":
                    if (TryCeil(value, out int ct)) { _req.ConnectTimeoutSec = ct; _r.SetsConnectTimeout = true; }
                    break;
                case "proxy": SetProxy(value, null); break;
                case "socks4": SetProxy(value, "socks4"); break;
                case "socks4a": SetProxy(value, "socks4a"); break;
                case "socks5": SetProxy(value, "socks5"); break;
                case "socks5-hostname": SetProxy(value, "socks5h"); break;
                case "proxy-user":
                {
                    int c = value.IndexOf(':');
                    _req.ProxyUser = c >= 0 ? value[..c] : value;
                    _req.ProxyPass = c >= 0 ? value[(c + 1)..] : string.Empty;
                    _r.SetsProxyUser = true;
                    break;
                }
                case "resolve": _resolve ??= value; if (_resolve != value) _ignored.Add($"{asTyped} {value}"); break;
                case "connect-to": _connectTo ??= value; if (_connectTo != value) _ignored.Add($"{asTyped} {value}"); break;
                case "interface": _r.Interface = value; break;
                default:
                    if (!Quiet.Contains(name)) _ignored.Add($"{asTyped} {Shorten(value, 24)}");
                    break;
            }
        }

        private static bool TryCeil(string v, out int seconds)
        {
            seconds = 0;
            if (!double.TryParse(v, NumberStyles.Float, CultureInfo.InvariantCulture, out double d) || d < 0) return false;
            seconds = d == 0 ? 0 : (int)Math.Min(int.MaxValue, Math.Ceiling(d));
            return true;
        }

        // -H "Name: value" adds; "Name;" sends it empty; "Name:" removes one of curl's own headers (not offered).
        private void AddHeader(string h)
        {
            if (h.StartsWith('@')) { _ignored.Add("-H " + Shorten(h, 24) + " (headers from a file)"); return; }
            int colon = h.IndexOf(':');
            int semi = h.IndexOf(';');
            if (colon <= 0)
            {
                if (semi > 0 && h[(semi + 1)..].Trim().Length == 0) { AddHeaderRow(h[..semi].Trim(), string.Empty); return; }
                _ignored.Add("-H " + Shorten(h, 24));
                return;
            }
            string name = h[..colon].Trim();
            string value = h[(colon + 1)..].Trim();
            if (name.Length == 0) { _ignored.Add("-H " + Shorten(h, 24)); return; }
            if (value.Length == 0)
            {
                _r.Notes.Add($"-H \"{name}:\" (drop curl's own {name} header) isn't supported — skipped");
                return;
            }
            if (name.Equals("Cookie", StringComparison.OrdinalIgnoreCase)) { AddCookies(value); return; }
            AddHeaderRow(name, value);
        }

        // every -H is sent, repeated names included (as curl does)
        private void AddHeaderRow(string name, string value) => _req.Headers.Add(new CurlPair(name, value));

        private bool HasHeader(string name) => _req.Headers.Any(x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

        private void AddCookies(string value)
        {
            foreach (var piece in value.Split(';'))
            {
                string p = piece.Trim();
                if (p.Length == 0) continue;
                int eq = p.IndexOf('=');
                if (eq <= 0) { _req.Cookies.Add(new CurlPair(p, string.Empty)); continue; }
                _req.Cookies.Add(new CurlPair(p[..eq].Trim(), p[(eq + 1)..].Trim()));
            }
        }

        private void SetUser(string value)
        {
            int c = value.IndexOf(':');
            if (value == ":") return;   // "-u :" = let the OS negotiate — nothing to import
            _req.Auth = CurlAuthMode.Basic;
            if (c >= 0) { _req.AuthUser = value[..c]; _req.AuthPass = value[(c + 1)..]; }
            else
            {
                _req.AuthUser = value;
                _req.AuthPass = string.Empty;
                _r.Notes.Add("-u has no password (curl would ask for it) — the Auth password is empty");
            }
        }

        private void SetProxy(string value, string? scheme)
        {
            string v = value.Trim();
            // user:pass@ in the proxy URL goes to the proxy credentials, not into the address
            int at = v.LastIndexOf('@');
            string? user = null, pass = null;
            if (at > 0)
            {
                int schemeEnd = v.IndexOf("://", StringComparison.Ordinal);
                int credStart = schemeEnd >= 0 ? schemeEnd + 3 : 0;
                if (at > credStart)
                {
                    string cred = v[credStart..at];
                    int c = cred.IndexOf(':');
                    user = CurlRequest.FormDecode(c >= 0 ? cred[..c] : cred);
                    pass = c >= 0 ? CurlRequest.FormDecode(cred[(c + 1)..]) : string.Empty;
                    v = v[..credStart] + v[(at + 1)..];
                }
            }
            if (scheme != null && !v.Contains("://", StringComparison.Ordinal)) v = scheme + "://" + v;
            _req.Proxy = v;
            _r.SetsProxy = true;
            if (user != null) { _req.ProxyUser = user; _req.ProxyPass = pass; _r.SetsProxyUser = true; }
        }

        private void AddPart(string spec, bool literal)
        {
            int eq = spec.IndexOf('=');
            if (eq <= 0) { _ignored.Add("-F " + Shorten(spec, 24)); return; }
            var part = new CurlPart { Name = spec[..eq] };
            string content = spec[(eq + 1)..];
            if (literal)
            {
                part.Value = content;
                _req.Parts.Add(part);
                return;
            }
            if (content.StartsWith('@') || content.StartsWith('<'))
            {
                bool asText = content[0] == '<';
                var (path, rest) = ReadFormWord(content[1..]);
                if (path.Contains(',') && !content[1..].TrimStart().StartsWith('"'))
                {
                    _r.Notes.Add($"-F {part.Name}: only the first of several files was imported");
                    path = path[..path.IndexOf(',')];
                }
                part.IsFile = true;
                part.Value = path;
                ParsePartParams(rest, part);
                if (asText) _r.Notes.Add($"-F {part.Name}=<file is sent as a file upload");
                if (path == "-") _r.Notes.Add($"-F {part.Name}: reading stdin isn't possible here — choose a file");
            }
            else
            {
                var (value, rest) = ReadFormWord(content);
                part.Value = value;
                ParsePartParams(rest, part);
            }
            _req.Parts.Add(part);
        }

        // A -F word: up to ';' (or the end); a leading "…" is read with \" and \\ escapes, as curl does.
        private static (string Word, string Tail) ReadFormWord(string s)
        {
            if (s.StartsWith('"'))
            {
                var sb = new StringBuilder();
                int i = 1;
                for (; i < s.Length; i++)
                {
                    char c = s[i];
                    if (c == '\\' && i + 1 < s.Length && (s[i + 1] == '\\' || s[i + 1] == '"')) { sb.Append(s[i + 1]); i++; continue; }
                    if (c == '"') { i++; break; }
                    sb.Append(c);
                }
                return (sb.ToString(), i < s.Length ? s[i..] : string.Empty);
            }
            // a plain value keeps everything up to ";type=" / ";filename=" / ";headers=" / ";encoder="
            int cut = -1;
            foreach (var key in new[] { ";type=", ";filename=", ";headers=", ";encoder=" })
            {
                int k = s.IndexOf(key, StringComparison.OrdinalIgnoreCase);
                if (k >= 0 && (cut < 0 || k < cut)) cut = k;
            }
            return cut < 0 ? (s, string.Empty) : (s[..cut], s[cut..]);
        }

        private static void ParsePartParams(string rest, CurlPart part)
        {
            while (rest.StartsWith(';'))
            {
                rest = rest[1..];
                int eq = rest.IndexOf('=');
                if (eq <= 0) break;
                string key = rest[..eq].Trim().ToLowerInvariant();
                var (value, after) = ReadFormWord(rest[(eq + 1)..]);
                // ReadFormWord on a plain word stops only at known keys: also stop at the next ';'
                if (!rest[(eq + 1)..].StartsWith('"'))
                {
                    int semi = value.IndexOf(';');
                    if (semi >= 0) { after = value[semi..] + after; value = value[..semi]; }
                }
                if (key == "type") part.ContentType = value;
                else if (key == "filename") part.FileName = value;
                rest = after;
            }
        }

        // Windows PowerShell 5.1 needs '{\"a\":1}' to get quotes through to curl.exe; read as JSON, that's what was meant.
        private string FixPsJson(string v)
        {
            if (_shell != CurlShell.PowerShell || !v.Contains("\\\"")) return v;
            string un = v.Replace("\\\"", "\"");
            return IsJson(un) && !IsJson(v) ? un : v;
        }

        private void Finish()
        {
            // ---- URL
            if (_urls.Count == 0) { _r.Error = "The curl command has no URL."; return; }
            // an option this table doesn't know may have left its value behind as a word: prefer one that reads as a URL
            string url = _urls.FirstOrDefault(LooksLikeUrl) ?? _urls[0];
            if (_urls.Count > 1) _r.Notes.Add($"Only one of {_urls.Count} URLs was used: {Shorten(url, 48)}");
            // Chrome escapes [ ] { } in the URL for curl's globber (\[ …); nothing is globbed here, so they're literal
            url = Regex.Replace(url, @"\\([\[\]{}])", "$1");
            if (!url.Contains("://", StringComparison.Ordinal)) url = "http://" + url;
            if (url.IndexOfAny(new[] { '{', '}', '[', ']' }) >= 0 && !url.Contains("://[", StringComparison.Ordinal))
                _r.Notes.Add("URL globbing ({…} / […]) isn't expanded — sent literally");

            foreach (var q in _urlQuery) url = AppendQuery(url, EncodeQueryArg(q, query: true));

            // ---- body
            var body = new List<string>();
            bool anyJson = false;
            string? fileBody = null;
            foreach (var (kind, value) in _data)
            {
                string v = value;
                switch (kind)
                {
                    case DataKind.Raw:
                        body.Add(v);
                        break;
                    case DataKind.UrlEncode:
                        body.Add(EncodeQueryArg(v, query: false));
                        break;
                    case DataKind.Json:
                        anyJson = true;
                        if (v.StartsWith('@')) { fileBody ??= v[1..]; continue; }
                        body.Add(v);
                        break;
                    default:   // -d / --data-binary: "@file" reads a file
                        if (v.StartsWith('@'))
                        {
                            if (v == "@-") { _r.Notes.Add("A body read from stdin (@-) can't be imported"); continue; }
                            if (fileBody is null) fileBody = v[1..];
                            else _r.Notes.Add("Only the first @file body was imported");
                            continue;
                        }
                        body.Add(v);
                        break;
                }
            }

            // ---- method (curl's order: -X wins, then -I, -G, data / -F → POST, -T → PUT)
            bool hasData = body.Count > 0 || fileBody != null;
            string method;
            if (!string.IsNullOrEmpty(_method)) method = NormalizeMethod(_method);
            else if (_head) method = "HEAD";
            else if (_get) method = "GET";
            else if (hasData || _req.Parts.Count > 0) method = "POST";
            else if (_uploadFile != null) method = "PUT";
            else method = "GET";
            _req.Method = method;

            if (_get && body.Count > 0)
            {
                // -G: the data goes into the query string instead
                url = AppendQuery(url, string.Join("&", body));
                body.Clear();
            }

            _req.Url = url;
            var ctHeader = _req.Headers.FirstOrDefault(h => h.Name.Equals("Content-Type", StringComparison.OrdinalIgnoreCase));
            string? ct = ctHeader?.Value;

            if (_req.Parts.Count > 0)
            {
                _req.BodyMode = CurlBodyMode.Multipart;
                if (hasData) _r.Notes.Add("-d data together with -F (curl refuses that) — the form fields were used");
                // the boundary is the engine's: a pasted multipart Content-Type would carry a stale one
                if (ct != null && ct.StartsWith("multipart/form-data", StringComparison.OrdinalIgnoreCase)) _req.Headers.Remove(ctHeader!);
            }
            else if (fileBody != null && body.Count == 0)
            {
                _req.BodyMode = CurlBodyMode.File;
                _req.BodyFile = fileBody;
                if (anyJson && ct is null) AddHeaderRow("Content-Type", "application/json");
            }
            else if (_uploadFile != null && body.Count == 0)
            {
                if (_uploadFile is "-" or ".") _r.Notes.Add("-T - (upload from stdin) can't be imported");
                else { _req.BodyMode = CurlBodyMode.File; _req.BodyFile = _uploadFile; }
            }
            else if (body.Count > 0)
            {
                if (fileBody != null) _r.Notes.Add("An @file body mixed with other data was dropped");
                string text = anyJson && _data.All(d => d.Kind == DataKind.Json) ? string.Concat(body) : string.Join("&", body);
                SetBody(text, ct, anyJson);
            }

            // --json also says Accept: application/json (its Content-Type comes from the Raw JSON body mode)
            if (anyJson && !_req.Headers.Any(h => h.Name.Equals("Accept", StringComparison.OrdinalIgnoreCase)))
                _req.Headers.Add(new CurlPair("Accept", "application/json"));

            if (_userAgent != null && !HasHeader("User-Agent")) _req.Headers.Add(new CurlPair("User-Agent", _userAgent));
            if (_referer != null && !HasHeader("Referer")) _req.Headers.Add(new CurlPair("Referer", _referer));

            // ---- switches
            _req.FollowRedirects = _follow;
            _req.Insecure = _insecure;
            _req.Compressed = _compressed;
            _req.HttpVersion = _http;
            if (_authOther && _req.Auth == CurlAuthMode.Basic)
                _r.Notes.Add("Only Basic auth is offered — the -u credentials are sent as Basic");

            // ---- --resolve / --connect-to → the override address for the URL's host
            if (Uri.TryCreate(_req.Url, UriKind.Absolute, out var uri))
            {
                int urlPort = uri.Port > 0 ? uri.Port : (uri.Scheme == "https" ? 443 : 80);
                if (_resolve != null) ApplyResolve(_resolve, uri, urlPort);
                if (_connectTo != null) ApplyConnectTo(_connectTo, uri, urlPort);
            }

            if (_ignored.Count > 0) _r.Ignored.AddRange(_ignored.Distinct());
        }

        private static readonly Regex HostLikeRx = new(@"^(?:localhost|[\w-]+(?:\.[\w-]+)+|\[[0-9a-fA-F:.]+\])(?::\d+)?(?:[/?#]|$)",
            RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

        private static bool LooksLikeUrl(string u) => u.Contains("://", StringComparison.Ordinal) || HostLikeRx.IsMatch(u);

        private static string NormalizeMethod(string m)
        {
            string up = m.Trim().ToUpperInvariant();
            return up is "GET" or "POST" or "PUT" or "PATCH" or "DELETE" or "HEAD" or "OPTIONS" or "TRACE" or "CONNECT" ? up : m.Trim();
        }

        private void SetBody(string text, string? ct, bool json)
        {
            string ctl = (ct ?? string.Empty).ToLowerInvariant();
            // a form Content-Type over a body that isn't name=value pairs stays raw: its bytes are sent exactly
            if ((ctl.StartsWith("application/x-www-form-urlencoded", StringComparison.Ordinal) || (ct is null && !json)) && IsFormLike(text))
            {
                _req.BodyMode = CurlBodyMode.Form;
                foreach (var piece in text.Split('&'))
                {
                    if (piece.Length == 0) continue;
                    int eq = piece.IndexOf('=');
                    _req.Form.Add(eq < 0 ? new CurlPair(CurlRequest.FormDecode(piece), string.Empty)
                                         : new CurlPair(CurlRequest.FormDecode(piece[..eq]), CurlRequest.FormDecode(piece[(eq + 1)..])));
                }
                // the body mode adds this Content-Type itself
                var h = _req.Headers.FirstOrDefault(x => x.Name.Equals("Content-Type", StringComparison.OrdinalIgnoreCase));
                if (h != null && h.Value.Trim().Equals("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)) _req.Headers.Remove(h);
                return;
            }

            _req.BodyMode = CurlBodyMode.Raw;
            _req.RawBody = text;
            if (ct != null) _req.RawType = CurlRequest.RawTypeFor(ct);
            else if (json || IsJson(text)) _req.RawType = "json";
            else if (text.TrimStart().StartsWith('<')) _req.RawType = "xml";
            else _req.RawType = "text";

            if (ct is null && !json)
                _r.Notes.Add($"No Content-Type in the command — sending it as {CurlRequest.RawContentType(_req.RawType)} (curl would say application/x-www-form-urlencoded)");
        }

        // "a=1&b=two" — pairs of name=value, no line breaks, no JSON / XML look.
        private static bool IsFormLike(string s)
        {
            if (s.Length == 0 || s.IndexOfAny(new[] { '\n', '\r' }) >= 0) return false;
            string t = s.TrimStart();
            if (t.StartsWith('{') || t.StartsWith('[') || t.StartsWith('<')) return false;
            foreach (var piece in s.Split('&'))
            {
                if (piece.Length == 0) continue;
                int eq = piece.IndexOf('=');
                if (eq <= 0) return false;
                if (piece[..eq].IndexOfAny(new[] { ' ', '"', '{', '}' }) >= 0) return false;
            }
            return true;
        }

        // --data-urlencode / --url-query: "content", "=content", "name=content" (content encoded), "@file" / "name@file"
        // (not read here), and for --url-query "+name=value" (used as-is).
        private string EncodeQueryArg(string v, bool query)
        {
            if (query && v.StartsWith('+')) return v[1..];
            int eq = v.IndexOf('=');
            int at = v.IndexOf('@');
            if (at >= 0 && (eq < 0 || at < eq))
            {
                _r.Notes.Add($"{(query ? "--url-query" : "--data-urlencode")} {Shorten(v, 24)}: reading a file isn't supported — sent as text");
            }
            if (eq < 0) return CurlRequest.FormEncode(v);
            if (eq == 0) return CurlRequest.FormEncode(v[1..]);
            return v[..eq] + "=" + CurlRequest.FormEncode(v[(eq + 1)..]);
        }

        private static string AppendQuery(string url, string query)
        {
            if (query.Length == 0) return url;
            string fragment = string.Empty;
            int hash = url.IndexOf('#');
            if (hash >= 0) { fragment = url[hash..]; url = url[..hash]; }
            return url + (url.Contains('?') ? (url.EndsWith('?') || url.EndsWith('&') ? "" : "&") : "?") + query + fragment;
        }

        // --resolve host:port:addr[,addr…]
        private void ApplyResolve(string v, Uri uri, int urlPort)
        {
            string s = v.StartsWith('+') ? v[1..] : v;
            if (s.StartsWith('-')) return;   // "-host:port" clears an entry
            int c1 = s.IndexOf(':');
            int c2 = c1 < 0 ? -1 : s.IndexOf(':', c1 + 1);
            if (c1 <= 0 || c2 < 0) { _r.Ignored.Add("--resolve " + v); return; }
            string host = s[..c1].Trim('[', ']');
            if (host != "*" && !host.Equals(uri.IdnHost, StringComparison.OrdinalIgnoreCase) && !host.Equals(uri.Host.Trim('[', ']'), StringComparison.OrdinalIgnoreCase))
            { _r.Notes.Add($"--resolve for {host} doesn't match the URL's host — not used"); return; }
            if (!int.TryParse(s[(c1 + 1)..c2], out int port) || (port != urlPort))
            { _r.Notes.Add($"--resolve for port {s[(c1 + 1)..c2]} doesn't match the URL's port — not used"); return; }
            string addr = s[(c2 + 1)..];
            int comma = addr.IndexOf(',');
            if (comma >= 0) addr = addr[..comma];
            addr = addr.Trim().Trim('[', ']');
            if (addr.Length == 0) return;
            _req.OverrideIp = addr;
            _r.SetsOverride = true;
        }

        // --connect-to host1:port1:host2:port2 (empty host1 / port1 = any)
        private void ApplyConnectTo(string v, Uri uri, int urlPort)
        {
            int c1 = v.IndexOf(':');
            int c2 = c1 < 0 ? -1 : v.IndexOf(':', c1 + 1);
            if (c1 < 0 || c2 < 0) { _r.Ignored.Add("--connect-to " + v); return; }
            string host1 = v[..c1].Trim('[', ']');
            string port1 = v[(c1 + 1)..c2];
            if (host1.Length > 0 && !host1.Equals(uri.IdnHost, StringComparison.OrdinalIgnoreCase) && !host1.Equals(uri.Host.Trim('[', ']'), StringComparison.OrdinalIgnoreCase))
            { _r.Notes.Add($"--connect-to for {host1} doesn't match the URL's host — not used"); return; }
            if (port1.Length > 0 && (!int.TryParse(port1, out int p1) || p1 != urlPort))
            { _r.Notes.Add($"--connect-to for port {port1} doesn't match the URL's port — not used"); return; }
            string rest = v[(c2 + 1)..];
            string host2, port2 = string.Empty;
            if (rest.StartsWith('['))
            {
                int close = rest.IndexOf(']');
                if (close < 0) { _r.Ignored.Add("--connect-to " + v); return; }
                host2 = rest[1..close];
                if (close + 1 < rest.Length && rest[close + 1] == ':') port2 = rest[(close + 2)..];
            }
            else
            {
                int lc = rest.LastIndexOf(':');
                host2 = lc >= 0 ? rest[..lc] : rest;
                if (lc >= 0) port2 = rest[(lc + 1)..];
            }
            if (host2.Length == 0) host2 = uri.IdnHost;
            int targetPort = int.TryParse(port2, out int p2) && p2 is > 0 and <= 65535 ? p2 : urlPort;
            _req.OverrideIp = targetPort == urlPort ? host2 : (host2.Contains(':') ? $"[{host2}]:{targetPort}" : $"{host2}:{targetPort}");
            _r.SetsOverride = true;
        }
    }

    internal static bool IsJson(string s)
    {
        string t = s.Trim();
        if (t.Length < 2 || !(t[0] == '{' || t[0] == '[')) return false;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(t, new System.Text.Json.JsonDocumentOptions { AllowTrailingCommas = true });
            return true;
        }
        catch { return false; }
    }
}
