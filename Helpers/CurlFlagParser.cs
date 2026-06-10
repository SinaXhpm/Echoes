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

                case "--connect-timeout": case "-m": case "--max-time":
                    if (int.TryParse(Next(), out int ct)) spec.ConnectTimeoutSec = ct;
                    break;

                case "--resolve":   // host:port:addr
                    var r = Next().Split(':');
                    if (r.Length >= 3) spec.Overrides[r[0]] = r[^1];
                    break;

                case "--connect-to":   // host1:port1:host2:port2
                    var cc = Next().Split(':');
                    if (cc.Length >= 3 && cc[2].Length > 0) spec.Overrides[cc[0]] = cc[2];
                    break;

                // valueless flags with no .NET equivalent (curl noise) — ignore
                case "-v": case "--verbose": case "-s": case "--silent":
                case "-i": case "--include": case "-S": case "--show-error":
                case "-g": case "--globoff": case "-#": case "--progress-bar":
                    break;

                // flags that consume a value we don't map — skip the value too
                case "-o": case "--output": case "-K": case "--config":
                case "--cacert": case "--cert": case "--key":
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
