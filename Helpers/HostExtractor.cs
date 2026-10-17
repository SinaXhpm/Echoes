using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace Echoes.Helpers;

/// <summary>
/// Finds the host(s) in whatever the user pasted — a URL, "host:port", "user@host", "[v6]:port",
/// an e-mail, a UNC path, an "ip:port:user:pass" proxy line, a log line, an nmap report, a defanged
/// IOC ("hxxps://evil[.]com") — and validates them (strict dotted-quad IPv4, IPv6, RFC-style host
/// names), so junk never ends up in a host field. Idempotent: a clean host or IP comes back unchanged.
/// </summary>
public static class HostExtractor
{
    public enum Prefer { Any, Domain, Ip }

    public enum Kind { IPv4, IPv6, Domain, Label }

    /// <summary>
    /// One host found in the text. <see cref="Via"/> says how it was recognised ("url", "user@host",
    /// "host:port", "proxy", "unc", "text"); <see cref="Url"/> is the cleaned URL when it came from one.
    /// </summary>
    public sealed record Found(string Host, Kind Kind, int? Port, string? User, string? Password,
                               string? Url, string Via, int Index)
    {
        public bool IsIp => Kind is Kind.IPv4 or Kind.IPv6;

        /// <summary>"host:port" (IPv6 bracketed) when a port was given, else just the host.</summary>
        public string HostPort => Port is int p ? (Kind == Kind.IPv6 ? $"[{Host}]:{p}" : $"{Host}:{p}") : Host;
    }

    private static readonly TimeSpan RxTimeout = TimeSpan.FromMilliseconds(250);

    // scheme://… up to whitespace or a quote/angle bracket (those never appear unescaped in a URL).
    private static readonly Regex UrlRx = new(@"\b[a-z][a-z0-9+.\-]{0,15}://[^\s<>""'`]+",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    // \\server\share → server
    private static readonly Regex UncRx = new(@"\\\\([^\\/\s:*?""<>|]+)", RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex Ipv4Rx = new(
        @"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$",
        RegexOptions.CultureInvariant, RxTimeout);

    // Defanged indicators (threat-intel style) → the real characters. Only bracketed forms: a bare
    // " dot " is ordinary prose.
    private static readonly Regex DefangRx = new(
        @"\[://\]|\[:\]|\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}|\[@\]|\[at\]|\(at\)|\bh[x*]{2}p(?=s?://)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    // ---------------------------------------------------------------- public API

    /// <summary>
    /// The single best host in <paramref name="raw"/>; when nothing host-like is found the trimmed input
    /// comes back unchanged (so a typed value is never replaced by an arbitrary token).
    /// </summary>
    public static string Extract(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return raw?.Trim() ?? string.Empty;
        return Best(raw)?.Host ?? raw.Trim();
    }

    /// <summary>The best host candidate, or null when the text holds nothing host-like.</summary>
    public static Found? Best(string? raw, Prefer prefer = Prefer.Any)
    {
        var all = FindAll(raw);
        if (all.Count == 0) return null;
        Found best = all[0];
        double bestScore = Score(best, prefer);
        for (int i = 1; i < all.Count; i++)
        {
            double s = Score(all[i], prefer);
            if (s > bestScore) { best = all[i]; bestScore = s; }   // ties keep the earliest (reading order)
        }
        return best;
    }

    /// <summary>Every host candidate in reading order (duplicates of the same host:port removed).</summary>
    public static List<Found> FindAll(string? raw)
    {
        var found = new List<Found>();
        if (string.IsNullOrWhiteSpace(raw)) return found;
        try
        {
            string s = Normalize(raw);
            char[] rest = s.ToCharArray();

            // 1) URLs first — their host is explicit, and their path/query must not be mined for tokens.
            foreach (System.Text.RegularExpressions.Match m in UrlRx.Matches(s))
            {
                string url = TrimUrlTail(m.Value);
                if (FromUrl(url, m.Index) is { } f) found.Add(f);
                Array.Fill(rest, ' ', m.Index, m.Length);
            }

            // 2) UNC paths.
            foreach (System.Text.RegularExpressions.Match m in UncRx.Matches(new string(rest)))
            {
                if (Classify(m.Groups[1].Value, m.Index, allowLabel: true) is { } f) found.Add(f with { Via = "unc" });
                Array.Fill(rest, ' ', m.Index, m.Length);
            }

            // 3) Everything else, token by token.
            var tokens = Tokenize(new string(rest));
            bool single = tokens.Count == 1 && found.Count == 0;   // a lone word may be a LAN name ("nas")
            foreach (var (tok, idx) in tokens)
                if (Classify(tok, idx, allowLabel: single) is { } f) found.Add(f);

            // "ssh -p 2222 -l root host" — the port / user live in separate arguments, and the host
            // argument may be a bare LAN name that the prose rules above skip.
            if (found.Count == 0 && SshCommandRx.IsMatch(s) && SshHostArg(s) is { } hostArg
                && Classify(hostArg, Math.Max(0, s.IndexOf(hostArg, StringComparison.Ordinal)), allowLabel: true) is { } fromArg)
                found.Add(fromArg);
            if (found.Count > 0 && SshCommandRx.IsMatch(s))
            {
                var (port, user) = SshArgs(s);
                for (int i = 0; i < found.Count; i++)
                    found[i] = found[i] with { Port = found[i].Port ?? port, User = found[i].User ?? user };
            }
        }
        catch (RegexMatchTimeoutException) { /* pathological input — treat as no host */ }

        found.Sort((a, b) => a.Index.CompareTo(b.Index));
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        found.RemoveAll(f => !seen.Add(f.HostPort));
        return found;
    }

    /// <summary>
    /// Scanner targets from a blob: IPs, hosts, and CIDR / range notation kept verbatim, one entry per
    /// target, de-duplicated, reading order. Bare words only count when the whole paste is a clean list.
    /// </summary>
    public static List<string> ExtractTargets(string? raw)
    {
        var result = new List<string>();
        if (string.IsNullOrWhiteSpace(raw)) return result;
        try
        {
            string s = Normalize(raw);
            char[] rest = s.ToCharArray();
            var hits = new List<(int idx, string target)>();

            foreach (System.Text.RegularExpressions.Match m in UrlRx.Matches(s))
            {
                if (FromUrl(TrimUrlTail(m.Value), m.Index) is { } f) hits.Add((m.Index, f.Host));
                Array.Fill(rest, ' ', m.Index, m.Length);
            }

            var tokens = Tokenize(new string(rest));
            // A list-shaped paste (one item per line, or a comma list) may contain LAN names like "nas";
            // in prose those would be ordinary words ("scan", "report"), so bare names only count there.
            bool listShape = s.Split('\n').All(line => line.Trim().Replace(", ", ",").IndexOfAny(new[] { ' ', '\t' }) < 0);
            bool clean = listShape && tokens.Count > 0
                         && tokens.All(t => IsCidrOrRange(TrimToken(t.tok)) || Classify(t.tok, t.idx, allowLabel: true) != null);
            foreach (var (tok, idx) in tokens)
            {
                string t = TrimToken(tok);
                if (IsCidrOrRange(t)) { hits.Add((idx, t)); continue; }
                if (Classify(tok, idx, allowLabel: clean) is { } f) hits.Add((idx, f.Host));
            }

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var (_, target) in hits.OrderBy(h => h.idx))
                if (seen.Add(target)) result.Add(target);
        }
        catch (RegexMatchTimeoutException) { result.Clear(); }
        return result;
    }

    /// <summary>
    /// The URL to request: the first scheme://… in the text (a pasted <c>curl …</c> command yields its URL
    /// argument), or the whole input when it is a single schemeless token like "example.com/api".
    /// Null when nothing usable is found.
    /// </summary>
    public static string? ExtractUrl(string? raw, out bool fromCurlCommand)
    {
        fromCurlCommand = false;
        if (string.IsNullOrWhiteSpace(raw)) return null;
        try
        {
            string s = Normalize(raw).Trim();
            if (CurlCommandRx.IsMatch(s) && CurlUrlArg(s) is { Length: > 0 } fromCurl)
            {
                fromCurlCommand = true;
                return fromCurl;
            }
            if (UrlRx.Match(s) is { Success: true } m) return TrimUrlTail(m.Value);
            if (s.IndexOfAny(new[] { ' ', '\t', '\r', '\n' }) < 0) return s.Trim('"', '\'', '`', '<', '>');
            // A blob without any scheme: the first token that starts with a valid host ("GET example.com/a").
            foreach (var (tok, _) in Tokenize(s))
            {
                string t = TrimToken(tok);
                int cut = t.IndexOfAny(new[] { '/', '?', '#' });
                string hostPart = cut > 0 ? t[..cut] : t;
                if (Classify(hostPart, 0, allowLabel: false) != null) return t;
            }
        }
        catch (RegexMatchTimeoutException) { }
        return null;
    }

    /// <summary>A Telegram bot token ("123456789:AA…", also inside an api.telegram.org/bot… URL), or null.</summary>
    public static string? ExtractBotToken(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        try
        {
            var m = BotTokenRx.Match(raw);
            return m.Success ? m.Groups[1].Value : null;
        }
        catch (RegexMatchTimeoutException) { return null; }
    }

    /// <summary>
    /// A pasted list cleaned line by line: trimmed, bullets / numbering stripped, defanged text restored,
    /// blank lines and duplicates dropped.
    /// </summary>
    public static List<string> CleanLines(string? raw)
    {
        var lines = new List<string>();
        if (string.IsNullOrWhiteSpace(raw)) return lines;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in Normalize(raw).Split('\n', '\r'))
        {
            string l = BulletRx.Replace(line.Trim(), "").Trim();
            if (l.Length > 0 && seen.Add(l)) lines.Add(l);
        }
        return lines;
    }

    /// <summary>Strict validation helpers (shared with the scanner / UI).</summary>
    public static bool IsStrictIPv4(string s) => s.Length is >= 7 and <= 15 && Ipv4Rx.IsMatch(s);

    public static bool IsHostName(string s, bool requireDot)
    {
        if (s.Length is 0 or > 253) return false;
        var labels = s.Split('.');
        if (requireDot && labels.Length < 2) return false;
        foreach (var l in labels)
        {
            if (l.Length is 0 or > 63 || l[0] == '-' || l[^1] == '-') return false;
            foreach (char c in l)
                if (!(char.IsLetterOrDigit(c) || c == '-' || c == '_')) return false;
        }
        // The last label must contain a letter: rules out versions / dates / bare numbers ("1.2.3").
        return labels[^1].Any(char.IsLetter);
    }

    // ---------------------------------------------------------------- internals

    private static double Score(Found f, Prefer prefer)
    {
        double s = (f.Kind, prefer) switch
        {
            (Kind.Label, _) => f.Via == "url" ? 2.5 : 1,
            (Kind.IPv4 or Kind.IPv6, Prefer.Domain) => 2,
            (Kind.Domain, Prefer.Ip) => 2,
            _ => 3,
        };
        return f.Via == "url" ? s + 0.5 : s;   // an explicit URL host beats a bare mention of the same kind
    }

    /// <summary>Refang defanged text, drop invisible characters, normalise odd spaces and newlines.</summary>
    public static string Normalize(string raw)
    {
        var sb = new StringBuilder(raw.Length);
        foreach (char c in raw)
        {
            if (c is '\u200B' or '\u200C' or '\u200D' or '\u2060' or '\uFEFF') continue;
            sb.Append(c is '\u00A0' or '\u2007' or '\u202F' or '\u3000' ? ' ' : c);
        }
        string s = sb.Replace("\r\n", "\n").ToString();
        // Chrome's "Copy as cURL (cmd)" escapes for cmd.exe: every quote is ^" and most punctuation is ^-prefixed (^&, ^%).
        // Undone first, or the URL came out as ^https://…?a=1^&b=2^ (cURL field) and Check-Host kept the carets.
        if (s.Contains("^\"", StringComparison.Ordinal) && CurlCommandRx.IsMatch(s)) s = Uncaret(s);
        // Two passes: "hxxp[://]x" only reads as a scheme once its brackets are restored.
        return Refang(Refang(s));

        static string Refang(string s) => DefangRx.Replace(s, m => m.Value.ToLowerInvariant() switch
        {
            "[://]" => "://",
            "[:]" => ":",
            "[@]" or "[at]" or "(at)" => "@",
            var v when v.StartsWith('h') => "http",
            _ => ".",
        });

        // cmd.exe: ^X is a literal X; ^ before a line break continues the command on the next line.
        static string Uncaret(string s)
        {
            var sb = new StringBuilder(s.Length);
            for (int i = 0; i < s.Length; i++)
            {
                if (s[i] == '^' && i + 1 < s.Length)
                {
                    i++;                          // the escaped character, taken literally
                    if (s[i] == '\n') continue;   // ... except a line break: the command goes on
                }
                sb.Append(s[i]);
            }
            return sb.ToString();
        }
    }

    /// <summary>True when <paramref name="raw"/> contained defanged notation.</summary>
    public static bool WasDefanged(string? raw)
    {
        if (string.IsNullOrEmpty(raw)) return false;
        try { return DefangRx.IsMatch(raw); } catch (RegexMatchTimeoutException) { return false; }
    }

    private static Found? FromUrl(string url, int index)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || string.IsNullOrEmpty(uri.Host)) return null;
        string host = uri.DnsSafeHost.Trim('[', ']');
        Kind kind = uri.HostNameType switch
        {
            UriHostNameType.IPv4 => Kind.IPv4,
            UriHostNameType.IPv6 => Kind.IPv6,
            _ => host.Contains('.') ? Kind.Domain : Kind.Label,
        };
        if (kind is Kind.Domain or Kind.Label)
        {
            host = host.TrimEnd('.').ToLowerInvariant();
            if (!IsHostName(host, requireDot: false)) return null;
        }
        string? user = null, pass = null;
        if (uri.UserInfo.Length > 0)
        {
            string ui = Uri.UnescapeDataString(uri.UserInfo);
            int c = ui.IndexOf(':');
            user = c >= 0 ? ui[..c] : ui;
            pass = c >= 0 ? ui[(c + 1)..] : null;
        }
        return new Found(host, kind, uri.IsDefaultPort ? null : uri.Port, NullIfEmpty(user), NullIfEmpty(pass), url, "url", index);
    }

    /// <summary>Recognise one token as a host (with optional user / port), or null.</summary>
    private static Found? Classify(string token, int index, bool allowLabel)
    {
        string t = TrimToken(token);
        if (t.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase)) t = t[7..];
        if (t.Length == 0) return null;

        string via = "text";
        string? user = null, pass = null;
        int? port = null;

        // user[:pass]@host — e-mail addresses land here too (host = the mail domain).
        int at = t.LastIndexOf('@');
        if (at >= 0)
        {
            if (at == 0 || at == t.Length - 1) return null;
            string cred = t[..at];
            int c = cred.IndexOf(':');
            user = c >= 0 ? cred[..c] : cred;
            pass = c >= 0 ? cred[(c + 1)..] : null;
            t = t[(at + 1)..];
            via = "user@host";
        }

        // host/path → host (also turns "10.0.0.0/24" into its network address for single-host fields).
        int slash = t.IndexOf('/');
        if (slash == 0) return null;
        if (slash > 0) t = t[..slash];

        // [v6] or [v6]:port
        if (t.StartsWith('['))
        {
            int close = t.IndexOf(']');
            if (close < 2) return null;
            string inner = t[1..close];
            if (!IsIPv6(inner)) return null;
            string tail = t[(close + 1)..];
            if (tail.Length > 0)
            {
                if (!tail.StartsWith(':') || !TryPort(tail[1..], out int bp)) return null;
                port = bp;
                if (via == "text") via = "host:port";
            }
            return new Found(inner.ToLowerInvariant(), Kind.IPv6, port, NullIfEmpty(user), NullIfEmpty(pass), null, via, index);
        }

        int colons = 0;
        foreach (char ch in t) if (ch == ':') colons++;

        if (colons >= 2)
        {
            if (IsIPv6(t)) return new Found(t.ToLowerInvariant(), Kind.IPv6, null, NullIfEmpty(user), NullIfEmpty(pass), null, via, index);

            // Proxy-list line "host:port:user:pass".
            var parts = t.Split(':');
            if (parts.Length == 4 && user == null && TryPort(parts[1], out int pp) && HostOnly(parts[0], allowLabel) is { } ph)
                return new Found(ph.host, ph.kind, pp, NullIfEmpty(parts[2]), NullIfEmpty(parts[3]), null, "proxy", index);
            return null;
        }

        if (colons == 1)
        {
            int c = t.IndexOf(':');
            if (!TryPort(t[(c + 1)..], out int hp)) return null;   // "10:00", "note:" … not a host:port
            port = hp;
            t = t[..c];
            if (via == "text") via = "host:port";
        }

        // user@host is a strong signal on its own, so a bare LAN name counts there ("pi@raspberrypi").
        if (HostOnly(t, allowLabel || via == "user@host") is not { } h) return null;
        return new Found(h.host, h.kind, port, NullIfEmpty(user), NullIfEmpty(pass), null, via, index);
    }

    private static (string host, Kind kind)? HostOnly(string t, bool allowLabel)
    {
        t = t.TrimEnd('.');
        if (IsStrictIPv4(t)) return (t, Kind.IPv4);
        string lower = t.ToLowerInvariant();
        if (IsHostName(lower, requireDot: true)) return (lower, Kind.Domain);
        if (allowLabel && IsHostName(lower, requireDot: false)) return (lower, Kind.Label);
        return null;
    }

    private static bool IsIPv6(string s)
        => s.Contains(':') && IPAddress.TryParse(s, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6;

    private static bool TryPort(string s, out int port)
    {
        port = 0;
        return s.Length is >= 1 and <= 5 && s.All(char.IsAsciiDigit)
               && int.TryParse(s, out port) && port is >= 1 and <= 65535;
    }

    // CIDR (v4 /0-32, v6 /0-128) or an IPv4 range ("a.b.c.d-e.f.g.h" / "a.b.c.d-N").
    private static bool IsCidrOrRange(string t)
    {
        int slash = t.IndexOf('/');
        if (slash > 0)
        {
            string ip = t[..slash], pre = t[(slash + 1)..];
            if (!int.TryParse(pre, out int p) || !pre.All(char.IsAsciiDigit)) return false;
            if (IsStrictIPv4(ip)) return p is >= 0 and <= 32;
            return IsIPv6(ip) && p is >= 0 and <= 128;
        }
        int dash = t.IndexOf('-');
        if (dash > 0 && IsStrictIPv4(t[..dash]))
        {
            string end = t[(dash + 1)..];
            return IsStrictIPv4(end) || (end.Length is >= 1 and <= 3 && end.All(char.IsAsciiDigit) && int.Parse(end) <= 255);
        }
        return false;
    }

    // Split on whitespace and punctuation that never occurs inside a host token. '[' ']' (IPv6),
    // ':' (ports / IPv6), '@', '/' and '-' stay inside tokens.
    private static List<(string tok, int idx)> Tokenize(string s)
    {
        var list = new List<(string, int)>();
        int start = -1;
        for (int i = 0; i <= s.Length; i++)
        {
            bool sep = i == s.Length || char.IsWhiteSpace(s[i])
                       || s[i] is ',' or ';' or '|' or '"' or '\'' or '`' or '<' or '>' or '(' or ')' or '{' or '}' or '=';
            if (sep)
            {
                if (start >= 0) { list.Add((s[start..i], start)); start = -1; }
            }
            else if (start < 0) start = i;
        }
        return list;
    }

    // Strip sentence punctuation and stray wrappers around a token, keeping IPv6 forms intact.
    // Walked over [start,end) with a single final substring: a huge paste of one character (a run of ':' or ']')
    // must not become an O(n²) scan — the old version re-ran IPAddress.TryParse / Contains on a fresh substring
    // for every trailing character, which froze the UI for seconds on such a paste.
    private static string TrimToken(string t)
    {
        t = t.Trim();
        int start = 0, end = t.Length;
        while (start < end && t[start] is '*' or '#' or '!' or '?') start++;
        // Trailing trimming never removes a '[', so whether one is present is invariant — compute it once.
        bool hasOpenBracket = t.IndexOf('[', start, end - start) >= 0;
        while (end > start)
        {
            char last = t[end - 1];
            if (last is '.' or ',' or ';' or '!' or '?') { end--; continue; }
            // "1.2.3.4:" (ping output) loses the colon, but "fe80::" stays. No IPv6 literal is longer than 45
            // characters, so the length guard keeps a run of colons O(1) per step instead of a parse each time.
            if (last == ':') { if (end - start <= 45 && IsIPv6(t.Substring(start, end - start))) break; end--; continue; }
            if (last == ']' && !hasOpenBracket) { end--; continue; }
            break;
        }
        t = start == 0 && end == t.Length ? t : t.Substring(start, end - start);
        if (t.StartsWith('[') && !t.Contains(']')) t = t[1..];
        if (t.StartsWith('[') && t.EndsWith(']') && !IsIPv6(t[1..^1])) t = t[1..^1];   // "[example.com]"
        return t;
    }

    // Drop trailing punctuation that is almost certainly prose, and unbalanced closing brackets
    // ("(see https://x.com/a)" → "https://x.com/a").
    private static string TrimUrlTail(string url)
    {
        while (url.Length > 0)
        {
            char c = url[^1];
            if (c is '.' or ',' or ';' or ':' or '!' or '?' or '\'' or '"') { url = url[..^1]; continue; }
            if ((c == ')' && Count(url, '(') < Count(url, ')')) ||
                (c == ']' && Count(url, '[') < Count(url, ']')) ||
                (c == '}' && Count(url, '{') < Count(url, '}')) ||
                c == '>')
            { url = url[..^1]; continue; }
            break;
        }
        return url;

        static int Count(string s, char ch) { int n = 0; foreach (char x in s) if (x == ch) n++; return n; }
    }

    private static string? NullIfEmpty(string? s) => string.IsNullOrEmpty(s) ? null : s;

    // ---- pasted commands ----

    private static readonly Regex SshCommandRx = new(@"^\s*ssh(\.exe)?\s", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);
    private static readonly Regex CurlCommandRx = new(@"^\s*curl(\.exe)?\s", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);
    private static readonly Regex BotTokenRx = new(@"(?<![0-9A-Za-z_-])(?:bot)?(\d{5,12}:[A-Za-z0-9_-]{30,})(?![A-Za-z0-9_-])",
        RegexOptions.CultureInvariant, RxTimeout);
    private static readonly Regex BulletRx = new(@"^(?:[-*•·▪►]+|\d{1,3}[.)])\s+", RegexOptions.CultureInvariant, RxTimeout);

    // ssh options that consume the next argument.
    private static readonly HashSet<string> SshValueOpts = new(StringComparer.Ordinal)
    { "-p", "-l", "-i", "-o", "-F", "-J", "-L", "-R", "-D", "-b", "-c", "-E", "-e", "-m", "-O", "-Q", "-S", "-W", "-w", "-B", "-I" };

    private static string? SshHostArg(string s)
    {
        var args = ShellSplit(s);
        for (int i = 1; i < args.Count; i++)
        {
            if (SshValueOpts.Contains(args[i])) { i++; continue; }
            if (args[i].StartsWith('-')) continue;
            return args[i];
        }
        return null;
    }

    private static (int? port, string? user) SshArgs(string s)
    {
        var args = ShellSplit(s);
        int? port = null; string? user = null;
        for (int i = 1; i < args.Count; i++)
        {
            string a = args[i];
            if (a == "-p" && i + 1 < args.Count && TryPort(args[i + 1], out int p)) { port = p; i++; }
            else if (a.StartsWith("-p", StringComparison.Ordinal) && TryPort(a[2..], out int p2)) port = p2;
            else if (a == "-l" && i + 1 < args.Count) { user = args[i + 1]; i++; }
        }
        return (port, user);
    }

    // curl options that consume the next argument (so it isn't mistaken for the URL).
    private static readonly HashSet<string> CurlValueOpts = new(StringComparer.Ordinal)
    {
        "-H", "--header", "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--data-ascii",
        "-X", "--request", "-u", "--user", "-A", "--user-agent", "-e", "--referer", "-b", "--cookie",
        "-c", "--cookie-jar", "-o", "--output", "-x", "--proxy", "-U", "--proxy-user", "-F", "--form",
        "-T", "--upload-file", "-m", "--max-time", "--connect-timeout", "--resolve", "--connect-to",
        "-w", "--write-out", "--cacert", "--cert", "--key", "-E", "-K", "--config", "--retry", "-r",
        "--range", "-z", "--interface", "--dns-servers", "--json", "-y", "-Y", "--limit-rate",
    };

    private static string? CurlUrlArg(string s)
    {
        var args = ShellSplit(s);
        for (int i = 1; i < args.Count; i++)
        {
            string a = args[i];
            if (a == "--url" && i + 1 < args.Count) return args[i + 1];
            if (a.StartsWith("--url=", StringComparison.Ordinal)) return a[6..];
        }
        for (int i = 1; i < args.Count; i++)
        {
            string a = args[i];
            if (CurlValueOpts.Contains(a)) { i++; continue; }
            if (a.StartsWith('-')) continue;
            return a;   // first positional argument
        }
        return null;
    }

    // Minimal POSIX/cmd-style argument split: '…' literal, "…" with \ escapes, line continuations
    // (\ or ^ at end of line, as in copied "Copy as cURL" commands) ignored.
    private static List<string> ShellSplit(string s)
    {
        var args = new List<string>();
        var cur = new StringBuilder();
        bool any = false;
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if ((c == '\\' || c == '^') && i + 1 < s.Length && s[i + 1] == '\n') { i++; continue; }
            if (char.IsWhiteSpace(c))
            {
                if (any) { args.Add(cur.ToString()); cur.Clear(); any = false; }
                continue;
            }
            any = true;
            if (c == '\'')
            {
                int end = s.IndexOf('\'', i + 1);
                if (end < 0) end = s.Length;
                cur.Append(s, i + 1, end - i - 1);
                i = end;
            }
            else if (c == '"')
            {
                for (i++; i < s.Length && s[i] != '"'; i++)
                {
                    if (s[i] == '\\' && i + 1 < s.Length && s[i + 1] is '"' or '\\' or '$' or '`') i++;
                    cur.Append(s[i]);
                }
            }
            else cur.Append(c);
        }
        if (any) args.Add(cur.ToString());
        return args;
    }
}
