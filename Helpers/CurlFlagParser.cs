using System.Collections.Generic;
using System.Text;

namespace Echoes.Helpers;

public class HttpRequestSpec
{
    public string? Url;
    public string Method = "GET";
    public List<(string Name, string Value)> Headers = new();
    public string? Body;
    public string? Proxy;
    public string? ProxyUser;
    public string? ProxyPass;
    public string? BasicUser;
    public string? BasicPass;
    public bool Insecure;
    public bool FollowRedirects;
    public bool Compressed;
    public string? UserAgent;
    public string? Cookie;
    public string? Referer;
    public int? ConnectTimeoutSec;
    public int? MaxTimeSec;                                // curl -m/--max-time: whole-operation cap
    public Dictionary<string, string> Overrides = new();   // original host -> override IP
}

/// <summary>
/// Parses a common subset of curl flags into an <see cref="HttpRequestSpec"/> so the
/// cURL tab can run on .NET's HttpClient without the curl binary.
/// </summary>
public static class CurlFlagParser
{
    public static HttpRequestSpec Parse(string flags)
    {
        var spec = new HttpRequestSpec();
        var t = Tokenize(flags);

        for (int i = 0; i < t.Count; i++)
        {
            string cur = t[i];
            string Next() => i + 1 < t.Count ? t[++i] : string.Empty;

            switch (cur)
            {
                case "-X": case "--request": spec.Method = Next().ToUpperInvariant(); break;

                case "-H": case "--header":
                    string h = Next();
                    int c = h.IndexOf(':');
                    if (c > 0) spec.Headers.Add((h[..c].Trim(), h[(c + 1)..].Trim()));
                    break;

                case "-d": case "--data": case "--data-raw": case "--data-binary": case "--data-ascii":
                    string d = Next();
                    spec.Body = spec.Body == null ? d : spec.Body + "&" + d;
                    if (spec.Method == "GET") spec.Method = "POST";
                    break;

                case "-x": case "--proxy": spec.Proxy = Next(); break;

                case "-U": case "--proxy-user":
                    Split(Next(), out spec.ProxyUser, out spec.ProxyPass); break;

                case "-u": case "--user":
                    Split(Next(), out spec.BasicUser, out spec.BasicPass); break;

                case "-k": case "--insecure": spec.Insecure = true; break;
                case "-L": case "--location": spec.FollowRedirects = true; break;
                case "--compressed": spec.Compressed = true; break;

                case "-A": case "--user-agent": spec.UserAgent = Next(); break;
                case "-b": case "--cookie": spec.Cookie = Next(); break;
                case "-e": case "--referer": spec.Referer = Next(); break;

                case "--connect-timeout":
                    if (int.TryParse(Next(), out int cto)) spec.ConnectTimeoutSec = cto;
                    break;
                case "-m": case "--max-time":
                    if (int.TryParse(Next(), out int mt)) spec.MaxTimeSec = mt;
                    break;

                case "--resolve":   // host:port:addr   (addr may be IPv6 with colons, or [ipv6])
                    if (TryParseResolve(Next(), out var rHost, out var rAddr))
                        spec.Overrides[rHost] = rAddr;
                    break;

                case "--connect-to":   // host1:port1:host2:port2   (host2 may be [ipv6])
                    if (TryParseConnectTo(Next(), out var ccHost, out var ccAddr))
                        spec.Overrides[ccHost] = ccAddr;
                    break;

                // valueless flags with no .NET equivalent (curl noise) — ignore
                case "-v": case "--verbose": case "-s": case "--silent":
                case "-i": case "--include": case "-S": case "--show-error":
                case "-g": case "--globoff": case "-#": case "--progress-bar":
                    break;

                // flags that consume a value we don't map — skip the value too
                // (--interface is applied via the .NET ConnectCallback, not parsed here)
                case "-o": case "--output": case "-K": case "--config":
                case "--cacert": case "--cert": case "--key": case "--interface":
                    Next(); break;

                default:
                    if (!cur.StartsWith('-') && cur.Length > 0) spec.Url = cur;   // positional = URL
                    break;
            }
        }

        return spec;
    }

    private static void Split(string s, out string? a, out string? b)
    {
        int i = s.IndexOf(':');
        if (i >= 0) { a = s[..i]; b = s[(i + 1)..]; }
        else { a = s; b = null; }
    }

    // --resolve host:port:addr — addr is everything after the 2nd ':' so an IPv6 literal
    // (which itself contains colons) survives intact; strips optional [] and the '+' TTL prefix.
    private static bool TryParseResolve(string s, out string host, out string addr)
    {
        host = addr = string.Empty;
        if (s.StartsWith('+')) s = s[1..];
        int c1 = s.IndexOf(':');
        if (c1 <= 0) return false;
        int c2 = s.IndexOf(':', c1 + 1);
        if (c2 < 0) return false;
        host = s[..c1];
        addr = s[(c2 + 1)..].Trim('[', ']');
        return addr.Length > 0;
    }

    // --connect-to host1:port1:host2:port2 — host2 (the connect target) may be [ipv6].
    private static bool TryParseConnectTo(string s, out string host, out string addr)
    {
        host = addr = string.Empty;
        int c1 = s.IndexOf(':');
        if (c1 <= 0) return false;
        int c2 = s.IndexOf(':', c1 + 1);
        if (c2 < 0) return false;
        host = s[..c1];
        string rest = s[(c2 + 1)..];   // host2[:port2], host2 possibly bracketed
        if (rest.StartsWith('['))
        {
            int close = rest.IndexOf(']');
            if (close < 1) return false;
            addr = rest[1..close];
        }
        else
        {
            int lc = rest.LastIndexOf(':');
            addr = lc > 0 ? rest[..lc] : rest;   // drop trailing :port2
        }
        return addr.Length > 0;
    }

    private static List<string> Tokenize(string s)
    {
        var tokens = new List<string>();
        var sb = new StringBuilder();
        bool inTok = false;
        char quote = '\0';

        foreach (char ch in s)
        {
            if (quote != '\0')
            {
                if (ch == quote) quote = '\0';
                else sb.Append(ch);
                inTok = true;
            }
            else if (ch == '"' || ch == '\'')
            {
                quote = ch;
                inTok = true;
            }
            else if (char.IsWhiteSpace(ch))
            {
                if (inTok) { tokens.Add(sb.ToString()); sb.Clear(); inTok = false; }
            }
            else
            {
                sb.Append(ch);
                inTok = true;
            }
        }
        if (inTok) tokens.Add(sb.ToString());
        return tokens;
    }
}
