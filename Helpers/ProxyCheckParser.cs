using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Text;

namespace Echoes.Helpers;

/// <summary>The protocol a proxy line asked for: none (auto-detect), HTTP (CONNECT / plain), SOCKS4, SOCKS4a or SOCKS5.</summary>
public enum ProxyKind { Auto, Http, Socks4, Socks4a, Socks5 }

/// <summary>One proxy from a pasted list: the line it came from (kept as typed, for "Copy working") and its parts.</summary>
public sealed class ProxyCheckEntry
{
    /// <summary>The text it was written as ("socks5://u:p@1.2.3.4:1080", "1.2.3.4:8080:u:p", …).</summary>
    public string Original { get; init; } = string.Empty;
    public ProxyKind Kind { get; init; }
    /// <summary>Host name or address (IPv6 without brackets).</summary>
    public string Host { get; init; } = string.Empty;
    public int Port { get; init; }
    public string User { get; init; } = string.Empty;
    public string Pass { get; init; } = string.Empty;
    public bool HasLogin => User.Length > 0;

    /// <summary>"socks5://user@host:port" — what the table shows (never the password).</summary>
    public string Display
    {
        get
        {
            string scheme = Kind switch
            {
                ProxyKind.Http => "http://",
                ProxyKind.Socks4 => "socks4://",
                ProxyKind.Socks4a => "socks4a://",
                ProxyKind.Socks5 => "socks5://",
                _ => string.Empty,
            };
            string host = Host.Contains(':') ? "[" + Host + "]" : Host;
            return scheme + (HasLogin ? User + "@" : string.Empty) + host + ":" + Port.ToString(CultureInfo.InvariantCulture);
        }
    }

    /// <summary>What two lines must share to be the same proxy.</summary>
    internal string Key => $"{Kind}|{Host.ToLowerInvariant()}|{Port}|{User}|{Pass}";

    public override string ToString() => Display;
}

/// <summary>
/// Reads proxies out of pasted text in the usual shapes — one per line or mixed with other text:
/// <c>host:port</c>, <c>scheme://[user:pass@]host:port</c> (http, https, socks4, socks4a, socks5, socks5h, socks),
/// <c>user:pass@host:port</c>, <c>host:port:user:pass</c>, <c>user:pass:host:port</c>, <c>[v6]:port</c>, and table rows
/// whose host and port are separate columns ("1.2.3.4  8080  HTTP  US"). Duplicates are folded; at most
/// <paramref name="cap"/> are kept.
/// </summary>
public static class ProxyCheckParser
{
    public const int DefaultCap = 2000;
    private const int MaxTokenChars = 512;

    public sealed class Result
    {
        public List<ProxyCheckEntry> Entries { get; } = new();
        public int Duplicates { get; set; }
        /// <summary>Proxies beyond the cap (not kept).</summary>
        public int OverCap { get; set; }
    }

    public static Result Parse(string? text, int cap = DefaultCap)
    {
        var result = new Result();
        if (string.IsNullOrWhiteSpace(text)) return result;
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (string rawLine in text.Split('\n'))
        {
            string line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith("//", StringComparison.Ordinal)) continue;
            var tokens = Tokens(line);
            for (int i = 0; i < tokens.Count; i++)
            {
                var entry = ParseToken(tokens[i]);
                // a table row: "1.2.3.4   8080 …" — host and port in separate columns
                if (entry is null && i + 1 < tokens.Count && IsHost(tokens[i], requireDot: true) && IsPort(tokens[i + 1], out int port))
                {
                    entry = new ProxyCheckEntry { Original = tokens[i] + ":" + tokens[i + 1], Host = tokens[i].Trim('[', ']'), Port = port };
                    i++;
                }
                if (entry is null) continue;
                Add(result, seen, entry, cap);
            }
        }
        return result;
    }

    private static void Add(Result result, HashSet<string> seen, ProxyCheckEntry entry, int cap)
    {
        if (!seen.Add(entry.Key)) { result.Duplicates++; return; }
        if (result.Entries.Count >= cap) { result.OverCap++; return; }
        result.Entries.Add(entry);
    }

    // Whitespace, commas, semicolons, pipes and quotes separate tokens (passwords with those characters need the URL form,
    // where they are percent-encoded).
    private static List<string> Tokens(string line)
    {
        var list = new List<string>();
        var sb = new StringBuilder();
        foreach (char c in line)
        {
            if (char.IsWhiteSpace(c) || c is ',' or ';' or '|' or '"' or '\'' or '<' or '>' or '(' or ')')
            {
                if (sb.Length > 0) { list.Add(sb.ToString()); sb.Clear(); }
                continue;
            }
            sb.Append(c);
            if (sb.Length > MaxTokenChars) { sb.Clear(); }   // not a proxy: drop it
        }
        if (sb.Length > 0) list.Add(sb.ToString());
        return list;
    }

    /// <summary>One token as a proxy, or null.</summary>
    public static ProxyCheckEntry? ParseToken(string token)
    {
        string t = token.Trim().TrimEnd('/', '.');
        if (t.Length is 0 or > MaxTokenChars) return null;

        // scheme://[user:pass@]host:port
        int sep = t.IndexOf("://", StringComparison.Ordinal);
        if (sep > 0)
        {
            ProxyKind? kind = t[..sep].ToLowerInvariant() switch
            {
                "http" or "https" => ProxyKind.Http,
                "socks4" => ProxyKind.Socks4,
                "socks4a" => ProxyKind.Socks4a,
                "socks5" or "socks5h" or "socks" => ProxyKind.Socks5,
                _ => null,
            };
            if (kind is null) return null;
            string rest = t[(sep + 3)..];
            int slash = rest.IndexOf('/');
            if (slash >= 0) rest = rest[..slash];
            string user = string.Empty, pass = string.Empty;
            int at = rest.LastIndexOf('@');
            if (at >= 0)
            {
                string login = rest[..at];
                rest = rest[(at + 1)..];
                int colon = login.IndexOf(':');
                user = Unescape(colon >= 0 ? login[..colon] : login);
                pass = colon >= 0 ? Unescape(login[(colon + 1)..]) : string.Empty;
            }
            if (!SplitHostPort(rest, out string host, out int port)) return null;
            return new ProxyCheckEntry { Original = token.Trim(), Kind = kind.Value, Host = host, Port = port, User = user, Pass = pass };
        }

        // user:pass@host:port
        int amp = t.LastIndexOf('@');
        if (amp > 0)
        {
            string login = t[..amp];
            if (!SplitHostPort(t[(amp + 1)..], out string host, out int port)) return null;
            int colon = login.IndexOf(':');
            if (colon <= 0) return null;
            return new ProxyCheckEntry { Original = t, Host = host, Port = port, User = login[..colon], Pass = login[(colon + 1)..] };
        }

        // [v6]:port
        if (t.StartsWith('['))
            return SplitHostPort(t, out string h6, out int p6) ? new ProxyCheckEntry { Original = t, Host = h6, Port = p6 } : null;

        string[] parts = t.Split(':');
        if (parts.Length == 2)
            return IsHost(parts[0], requireDot: false) && IsPort(parts[1], out int p) ? new ProxyCheckEntry { Original = t, Host = parts[0], Port = p } : null;
        if (parts.Length == 4)
        {
            // host:port:user:pass — or user:pass:host:port (the port tells which end the host is at)
            if (IsHost(parts[0], requireDot: true) && IsPort(parts[1], out int p1) && !(IsHost(parts[2], requireDot: true) && IsPort(parts[3], out _)))
                return new ProxyCheckEntry { Original = t, Host = parts[0], Port = p1, User = parts[2], Pass = parts[3] };
            if (IsHost(parts[2], requireDot: true) && IsPort(parts[3], out int p3))
                return new ProxyCheckEntry { Original = t, Host = parts[2], Port = p3, User = parts[0], Pass = parts[1] };
            if (IsHost(parts[0], requireDot: false) && IsPort(parts[1], out p1))
                return new ProxyCheckEntry { Original = t, Host = parts[0], Port = p1, User = parts[2], Pass = parts[3] };
        }
        return null;
    }

    private static string Unescape(string s)
    {
        try { return Uri.UnescapeDataString(s); }
        catch { return s; }
    }

    private static bool SplitHostPort(string s, out string host, out int port)
    {
        host = string.Empty;
        port = 0;
        if (s.StartsWith('['))
        {
            int close = s.IndexOf(']');
            if (close < 2 || close + 1 >= s.Length || s[close + 1] != ':') return false;
            host = s[1..close];
            return IPAddress.TryParse(host, out var a) && a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                   && IsPort(s[(close + 2)..], out port);
        }
        int colon = s.LastIndexOf(':');
        if (colon <= 0 || s.IndexOf(':') != colon) return false;
        host = s[..colon];
        return IsHost(host, requireDot: false) && IsPort(s[(colon + 1)..], out port);
    }

    private static bool IsPort(string s, out int port)
        => int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out port) && port is >= 1 and <= 65535;

    /// <summary>An IPv4 address, or a DNS name (with a dot unless <paramref name="requireDot"/> is off — "localhost").</summary>
    private static bool IsHost(string s, bool requireDot)
    {
        s = s.Trim('[', ']');
        if (s.Length is 0 or > 253) return false;
        if (IPAddress.TryParse(s, out var ip)) return ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? s.Split('.').Length == 4 : true;
        bool dot = false, letter = false;
        foreach (char c in s)
        {
            if (c == '.') { dot = true; continue; }
            if (c == '-' || char.IsAsciiDigit(c)) continue;
            if (char.IsAsciiLetter(c)) { letter = true; continue; }
            return false;
        }
        if (s[0] is '.' or '-' || s[^1] is '.' or '-') return false;
        return letter && (dot || (!requireDot && s.Equals("localhost", StringComparison.OrdinalIgnoreCase)));
    }
}
