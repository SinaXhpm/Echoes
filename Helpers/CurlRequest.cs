using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace Echoes.Helpers;

/// <summary>What the request body is built from.</summary>
public enum CurlBodyMode { None, Raw, Form, Multipart, File }

/// <summary>Auth helper that produces the Authorization header.</summary>
public enum CurlAuthMode { None, Basic, Bearer }

/// <summary>HTTP version to ask for. Auto = the engine's own choice (HTTP/2 over TLS where it can, else 1.1).</summary>
public enum CurlHttpVersion { Auto, Http1, Http2, Http3 }

/// <summary>A name/value row: query parameter, header, cookie or url-encoded form field.</summary>
public sealed class CurlPair
{
    public bool Enabled = true;
    public string Name = string.Empty;
    public string Value = string.Empty;
    /// <summary>Query parameters only: false for a bare "?flag" (no '='), which is rebuilt without one.</summary>
    public bool HasEquals = true;

    public CurlPair() { }
    public CurlPair(string name, string value, bool enabled = true) { Name = name; Value = value; Enabled = enabled; }
    public CurlPair Clone() => new(Name, Value, Enabled) { HasEquals = HasEquals };
}

/// <summary>A multipart/form-data part: a text value, or a file (Value = its path).</summary>
public sealed class CurlPart
{
    public bool Enabled = true;
    public string Name = string.Empty;
    public string Value = string.Empty;
    public bool IsFile;
    /// <summary>curl's ";type=" — the part's Content-Type (files: guessed from the extension when empty).</summary>
    public string? ContentType;
    /// <summary>curl's ";filename=" — the name sent for a file part (default: the file's own name).</summary>
    public string? FileName;

    public CurlPart Clone() => new() { Enabled = Enabled, Name = Name, Value = Value, IsFile = IsFile, ContentType = ContentType, FileName = FileName };
}

/// <summary>
/// One HTTP request as the cURL tab describes it — the single source for both engines, the snippets, the curl import,
/// saved requests and the history. Pure data (no UI types), so the test harness can drive it directly.
/// </summary>
public sealed class CurlRequest
{
    public string Method = "GET";
    public string Url = string.Empty;
    public List<CurlPair> Headers = new();
    public List<CurlPair> Cookies = new();

    public CurlBodyMode BodyMode;
    public string RawBody = string.Empty;
    /// <summary>Raw body kind: json | xml | html | text | javascript — picks the automatic Content-Type.</summary>
    public string RawType = "json";
    public List<CurlPair> Form = new();
    public List<CurlPart> Parts = new();
    public string BodyFile = string.Empty;

    public CurlAuthMode Auth;
    public string AuthUser = string.Empty;
    public string AuthPass = string.Empty;
    public string AuthToken = string.Empty;

    public bool FollowRedirects = true;
    public int MaxRedirects = DefaultMaxRedirects;
    public bool Insecure;
    public bool Compressed = true;
    public int TimeoutSec = 30;            // whole operation (curl --max-time); 0 = no limit
    public int ConnectTimeoutSec;          // 0 = engine default
    public CurlHttpVersion HttpVersion;

    // connection: proxy, pinned address, source interface
    public string? Proxy;
    public string? ProxyUser;
    public string? ProxyPass;
    public string? OverrideIp;
    public string? InterfaceIp;

    public const int DefaultMaxRedirects = 10;

    public CurlRequest Clone() => new()
    {
        Method = Method, Url = Url,
        Headers = Headers.Select(h => h.Clone()).ToList(),
        Cookies = Cookies.Select(c => c.Clone()).ToList(),
        BodyMode = BodyMode, RawBody = RawBody, RawType = RawType,
        Form = Form.Select(f => f.Clone()).ToList(),
        Parts = Parts.Select(p => p.Clone()).ToList(),
        BodyFile = BodyFile,
        Auth = Auth, AuthUser = AuthUser, AuthPass = AuthPass, AuthToken = AuthToken,
        FollowRedirects = FollowRedirects, MaxRedirects = MaxRedirects, Insecure = Insecure, Compressed = Compressed,
        TimeoutSec = TimeoutSec, ConnectTimeoutSec = ConnectTimeoutSec, HttpVersion = HttpVersion,
        Proxy = Proxy, ProxyUser = ProxyUser, ProxyPass = ProxyPass, OverrideIp = OverrideIp, InterfaceIp = InterfaceIp,
    };

    // ------------------------------------------------------------------ what goes on the wire

    /// <summary>HEAD never carries a body (curl refuses -I with data); every other method sends the body it has.</summary>
    public static bool MethodAllowsBody(string? method) => !string.Equals(method, "HEAD", StringComparison.OrdinalIgnoreCase);

    /// <summary>The body actually sent: the mode, unless the method can't carry one or the mode has nothing in it.</summary>
    public CurlBodyMode EffectiveBodyMode
    {
        get
        {
            if (!MethodAllowsBody(Method)) return CurlBodyMode.None;
            return BodyMode switch
            {
                CurlBodyMode.Raw => CurlBodyMode.Raw,   // an empty raw body is still a (zero-length) body
                CurlBodyMode.Form => CurlBodyMode.Form,
                CurlBodyMode.Multipart => Parts.Any(p => p.Enabled && p.Name.Length > 0) ? CurlBodyMode.Multipart : CurlBodyMode.None,
                CurlBodyMode.File => BodyFile.Trim().Length > 0 ? CurlBodyMode.File : CurlBodyMode.None,
                _ => CurlBodyMode.None,
            };
        }
    }

    /// <summary>The URL as sent: trimmed, and "http://" in front of a scheme-less one (what curl does too).</summary>
    public static string NormalizeUrl(string? url)
    {
        string u = (url ?? string.Empty).Trim();
        if (u.Length == 0) return u;
        if (!u.Contains("://", StringComparison.Ordinal)) u = "http://" + u;
        return u;
    }

    /// <summary>Content-Type the body mode implies (Multipart: the engine adds it with the boundary; null = none).</summary>
    public string? AutoContentType()
    {
        return EffectiveBodyMode switch
        {
            CurlBodyMode.Raw => RawContentType(RawType),
            CurlBodyMode.Form => "application/x-www-form-urlencoded",
            CurlBodyMode.File => GuessMime(BodyFile, "application/octet-stream"),
            _ => null,
        };
    }

    public static string RawContentType(string? rawType) => (rawType ?? "").ToLowerInvariant() switch
    {
        "json" => "application/json",
        "xml" => "application/xml",
        "html" => "text/html",
        "javascript" => "application/javascript",
        _ => "text/plain",
    };

    /// <summary>The raw-body kind a Content-Type names (json / xml / html / javascript / text).</summary>
    public static string RawTypeFor(string? contentType)
    {
        string ct = (contentType ?? string.Empty).ToLowerInvariant();
        int semi = ct.IndexOf(';');
        if (semi >= 0) ct = ct[..semi];
        ct = ct.Trim();
        if (ct.EndsWith("/json", StringComparison.Ordinal) || ct.EndsWith("+json", StringComparison.Ordinal)) return "json";
        if (ct.EndsWith("/xml", StringComparison.Ordinal) || ct.EndsWith("+xml", StringComparison.Ordinal)) return "xml";
        if (ct == "text/html") return "html";
        if (ct.Contains("javascript", StringComparison.Ordinal)) return "javascript";
        return "text";
    }

    /// <summary>
    /// The request headers in send order: the enabled user headers, then what the helpers add — Authorization (Auth tab,
    /// unless a header of that name is already there), Cookie (the Cookies tab, merged into a user Cookie header) and the
    /// body's Content-Type (unless the user set one). Auto = which of them were added (for the "added automatically" line).
    /// </summary>
    public List<(string Name, string Value)> EffectiveHeaders(List<string>? auto = null)
    {
        var list = new List<(string Name, string Value)>();
        foreach (var h in Headers)
        {
            // a line break inside a header would start a new header (or the body) on the wire: never sent as such
            string n = OneLine(h.Name).Trim();
            if (!h.Enabled || n.Length == 0) continue;
            list.Add((n, OneLine(h.Value).Trim()));
        }

        bool Has(string name) => list.Any(h => h.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

        if (AuthorizationValue() is { } authValue && !Has("Authorization"))
        {
            list.Add(("Authorization", authValue));
            auto?.Add("Authorization");
        }

        string cookie = CookieHeaderValue();
        if (cookie.Length > 0)
        {
            int i = list.FindIndex(h => h.Name.Equals("Cookie", StringComparison.OrdinalIgnoreCase));
            if (i >= 0) list[i] = (list[i].Name, list[i].Value.TrimEnd().TrimEnd(';') + "; " + cookie);
            else list.Add(("Cookie", cookie));
            auto?.Add("Cookie");
        }

        if (AutoContentType() is { } ct && !Has("Content-Type"))
        {
            list.Add(("Content-Type", ct));
            auto?.Add("Content-Type");
        }
        return list;
    }

    private static string OneLine(string s) => s.IndexOfAny(new[] { '\r', '\n' }) < 0 ? s : s.Replace("\r\n", " ").Replace('\r', ' ').Replace('\n', ' ');

    /// <summary>The Authorization header the Auth tab produces, or null.</summary>
    public string? AuthorizationValue() => Auth switch
    {
        CurlAuthMode.Basic when AuthUser.Length > 0 || AuthPass.Length > 0
            => "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(AuthUser + ":" + AuthPass)),
        CurlAuthMode.Bearer when AuthToken.Trim().Length > 0 => "Bearer " + AuthToken.Trim(),
        _ => null,
    };

    /// <summary>The enabled cookies as one Cookie header value ("a=1; b=2"), or "".</summary>
    public string CookieHeaderValue()
    {
        var sb = new StringBuilder();
        foreach (var c in Cookies)
        {
            string n = c.Name.Trim();
            if (!c.Enabled || n.Length == 0) continue;
            if (sb.Length > 0) sb.Append("; ");
            sb.Append(n).Append('=').Append(c.Value.Trim());
        }
        return sb.ToString();
    }

    /// <summary>The url-encoded form body ("a=1&amp;b=hello%20world") from the enabled Form rows.</summary>
    public string FormBody()
    {
        var sb = new StringBuilder();
        foreach (var f in Form)
        {
            if (!f.Enabled || f.Name.Length == 0) continue;
            if (sb.Length > 0) sb.Append('&');
            sb.Append(FormEncode(f.Name)).Append('=').Append(FormEncode(f.Value));
        }
        return sb.ToString();
    }

    /// <summary>Form encoding exactly as curl's --data-urlencode writes it: RFC 3986 unreserved characters as they are, a
    /// space as '+', everything else %XX of its UTF-8 bytes.</summary>
    public static string FormEncode(string s)
    {
        if (string.IsNullOrEmpty(s)) return string.Empty;
        var sb = new StringBuilder(s.Length + 8);
        foreach (byte b in Encoding.UTF8.GetBytes(s))
        {
            char c = (char)b;
            if (char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~') sb.Append(c);
            else if (c == ' ') sb.Append('+');
            else sb.Append('%').Append(b.ToString("X2"));
        }
        return sb.ToString();
    }

    /// <summary>Decodes a form / query component: %XX (UTF-8) and '+' as a space.</summary>
    public static string FormDecode(string s)
    {
        if (string.IsNullOrEmpty(s)) return string.Empty;
        try { return Uri.UnescapeDataString(s.Replace('+', ' ')); }
        catch { return s; }
    }

    /// <summary>The bytes of a Raw / Form body (null for the other modes).</summary>
    public byte[]? BodyBytes() => EffectiveBodyMode switch
    {
        CurlBodyMode.Raw => Encoding.UTF8.GetBytes(RawBody),
        CurlBodyMode.Form => Encoding.ASCII.GetBytes(FormBody()),
        _ => null,
    };

    // ------------------------------------------------------------------ query string <-> rows

    /// <summary>Splits a URL into the part before "?", the query rows (exactly as written — no decoding), and the
    /// "#fragment" (with its '#', or "").</summary>
    public static (string Base, List<CurlPair> Query, string Fragment) SplitUrl(string? url)
    {
        string u = url ?? string.Empty;
        string fragment = string.Empty;
        int hash = u.IndexOf('#');
        if (hash >= 0) { fragment = u[hash..]; u = u[..hash]; }
        int q = u.IndexOf('?');
        var rows = new List<CurlPair>();
        if (q < 0) return (u, rows, fragment);
        string query = u[(q + 1)..];
        if (query.Length > 0)
        {
            foreach (var piece in query.Split('&'))
            {
                if (piece.Length == 0) continue;
                int eq = piece.IndexOf('=');
                rows.Add(eq < 0 ? new CurlPair(piece, string.Empty) { HasEquals = false }
                                : new CurlPair(piece[..eq], piece[(eq + 1)..]));
            }
        }
        return (u[..q], rows, fragment);
    }

    /// <summary>Rebuilds a URL from its base, the enabled query rows (written as typed) and the fragment.</summary>
    public static string JoinUrl(string baseUrl, IEnumerable<CurlPair> rows, string fragment)
    {
        var sb = new StringBuilder(baseUrl);
        bool first = true;
        foreach (var r in rows)
        {
            if (!r.Enabled || (r.Name.Length == 0 && r.Value.Length == 0)) continue;
            sb.Append(first ? '?' : '&');
            first = false;
            sb.Append(r.Name);
            if (r.HasEquals || r.Value.Length > 0) sb.Append('=').Append(r.Value);
        }
        sb.Append(fragment);
        return sb.ToString();
    }

    /// <summary>
    /// A multipart part's Content-Type reduced to a bare media type ("type/subtype"), safe to splice into curl's
    /// <c>-F "name=…;type=…"</c> spec. curl reads ';' inside that spec as the start of another directive — a crafted
    /// value such as <c>text/plain;headers=@/etc/passwd</c> would otherwise make curl read a local file and send it —
    /// so everything from the first character that can't appear in a media type (';', space, '@', '"', ','…) is dropped.
    /// The .NET engine parses the Content-Type structurally and never needed this.
    /// </summary>
    public static string SafeMimeType(string? contentType)
    {
        string s = (contentType ?? string.Empty).Trim();
        int i = 0;
        while (i < s.Length && (char.IsAsciiLetterOrDigit(s[i]) || s[i] is '/' or '+' or '-' or '.' or '_')) i++;
        return s[..i];
    }

    // ------------------------------------------------------------------ MIME guess (curl's own small table + a few more)

    public static string GuessMime(string? path, string fallback)
    {
        string ext = (Path.GetExtension(path ?? string.Empty) ?? string.Empty).ToLowerInvariant();
        return ext switch
        {
            ".txt" or ".log" or ".csv" => ext == ".csv" ? "text/csv" : "text/plain",
            ".htm" or ".html" => "text/html",
            ".json" => "application/json",
            ".xml" => "application/xml",
            ".js" => "application/javascript",
            ".css" => "text/css",
            ".pdf" => "application/pdf",
            ".zip" => "application/zip",
            ".gz" => "application/gzip",
            ".png" => "image/png",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".gif" => "image/gif",
            ".webp" => "image/webp",
            ".svg" => "image/svg+xml",
            ".ico" => "image/x-icon",
            ".mp4" => "video/mp4",
            ".mp3" => "audio/mpeg",
            ".wav" => "audio/wav",
            _ => fallback,
        };
    }

    // ------------------------------------------------------------------ JSON (saved requests) — Utf8JsonWriter/JsonDocument, AOT-safe

    public void WriteJson(Utf8JsonWriter w, bool includeSecrets = true)
    {
        w.WriteStartObject();
        w.WriteString("method", Method);
        w.WriteString("url", Url);
        WritePairs(w, "headers", Headers, includeSecrets);
        if (includeSecrets) WritePairs(w, "cookies", Cookies, true);
        w.WriteString("bodyMode", BodyMode.ToString());
        if (RawBody.Length > 0) w.WriteString("raw", RawBody);
        w.WriteString("rawType", RawType);
        WritePairs(w, "form", Form, true);
        if (Parts.Count > 0)
        {
            w.WriteStartArray("parts");
            foreach (var p in Parts)
            {
                w.WriteStartObject();
                if (!p.Enabled) w.WriteBoolean("off", true);
                w.WriteString("n", p.Name);
                w.WriteString("v", p.Value);
                if (p.IsFile) w.WriteBoolean("file", true);
                if (p.ContentType is { Length: > 0 }) w.WriteString("type", p.ContentType);
                if (p.FileName is { Length: > 0 }) w.WriteString("fname", p.FileName);
                w.WriteEndObject();
            }
            w.WriteEndArray();
        }
        if (BodyFile.Length > 0) w.WriteString("bodyFile", BodyFile);
        w.WriteString("auth", Auth.ToString());
        if (includeSecrets)
        {
            if (AuthUser.Length > 0) w.WriteString("authUser", AuthUser);
            if (AuthPass.Length > 0) w.WriteString("authPass", AuthPass);
            if (AuthToken.Length > 0) w.WriteString("authToken", AuthToken);
        }
        w.WriteBoolean("follow", FollowRedirects);
        w.WriteNumber("maxRedirs", MaxRedirects);
        w.WriteBoolean("insecure", Insecure);
        w.WriteBoolean("compressed", Compressed);
        w.WriteNumber("timeout", TimeoutSec);
        w.WriteNumber("connectTimeout", ConnectTimeoutSec);
        w.WriteString("http", HttpVersion.ToString());
        if (Proxy is { Length: > 0 }) w.WriteString("proxy", Proxy);
        if (includeSecrets && ProxyUser is { Length: > 0 }) w.WriteString("proxyUser", ProxyUser);
        if (includeSecrets && ProxyPass is { Length: > 0 }) w.WriteString("proxyPass", ProxyPass);
        if (OverrideIp is { Length: > 0 }) w.WriteString("overrideIp", OverrideIp);
        if (InterfaceIp is { Length: > 0 }) w.WriteString("nic", InterfaceIp);
        w.WriteEndObject();
    }

    private static readonly string[] SecretHeaders = { "Authorization", "Proxy-Authorization", "Cookie" };

    private static void WritePairs(Utf8JsonWriter w, string name, List<CurlPair> rows, bool includeSecrets)
    {
        var keep = rows.Where(r => r.Name.Length > 0 || r.Value.Length > 0)
                       .Where(r => includeSecrets || !SecretHeaders.Contains(r.Name.Trim(), StringComparer.OrdinalIgnoreCase))
                       .ToList();
        if (keep.Count == 0) return;
        w.WriteStartArray(name);
        foreach (var r in keep)
        {
            w.WriteStartObject();
            if (!r.Enabled) w.WriteBoolean("off", true);
            w.WriteString("n", r.Name);
            w.WriteString("v", r.Value);
            if (!r.HasEquals) w.WriteBoolean("noEq", true);
            w.WriteEndObject();
        }
        w.WriteEndArray();
    }

    public string ToJson(bool includeSecrets = true)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms)) WriteJson(w, includeSecrets);
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    public static CurlRequest FromJson(JsonElement e)
    {
        var r = new CurlRequest
        {
            Method = Str(e, "method", "GET"),
            Url = Str(e, "url", string.Empty),
            Headers = Pairs(e, "headers"),
            Cookies = Pairs(e, "cookies"),
            BodyMode = Enum.TryParse(Str(e, "bodyMode", "None"), out CurlBodyMode bm) ? bm : CurlBodyMode.None,
            RawBody = Str(e, "raw", string.Empty),
            RawType = Str(e, "rawType", "json"),
            Form = Pairs(e, "form"),
            BodyFile = Str(e, "bodyFile", string.Empty),
            Auth = Enum.TryParse(Str(e, "auth", "None"), out CurlAuthMode am) ? am : CurlAuthMode.None,
            AuthUser = Str(e, "authUser", string.Empty),
            AuthPass = Str(e, "authPass", string.Empty),
            AuthToken = Str(e, "authToken", string.Empty),
            FollowRedirects = Bool(e, "follow", true),
            MaxRedirects = Int(e, "maxRedirs", DefaultMaxRedirects),
            Insecure = Bool(e, "insecure", false),
            Compressed = Bool(e, "compressed", true),
            TimeoutSec = Int(e, "timeout", 30),
            ConnectTimeoutSec = Int(e, "connectTimeout", 0),
            HttpVersion = Enum.TryParse(Str(e, "http", "Auto"), out CurlHttpVersion hv) ? hv : CurlHttpVersion.Auto,
            Proxy = NullIfEmpty(Str(e, "proxy", string.Empty)),
            ProxyUser = NullIfEmpty(Str(e, "proxyUser", string.Empty)),
            ProxyPass = NullIfEmpty(Str(e, "proxyPass", string.Empty)),
            OverrideIp = NullIfEmpty(Str(e, "overrideIp", string.Empty)),
            InterfaceIp = NullIfEmpty(Str(e, "nic", string.Empty)),
        };
        if (e.TryGetProperty("parts", out var parts) && parts.ValueKind == JsonValueKind.Array)
        {
            foreach (var p in parts.EnumerateArray())
            {
                if (p.ValueKind != JsonValueKind.Object) continue;
                r.Parts.Add(new CurlPart
                {
                    Enabled = !Bool(p, "off", false),
                    Name = Str(p, "n", string.Empty),
                    Value = Str(p, "v", string.Empty),
                    IsFile = Bool(p, "file", false),
                    ContentType = NullIfEmpty(Str(p, "type", string.Empty)),
                    FileName = NullIfEmpty(Str(p, "fname", string.Empty)),
                });
            }
        }
        return r;
    }

    private static string? NullIfEmpty(string s) => s.Length == 0 ? null : s;

    private static List<CurlPair> Pairs(JsonElement e, string name)
    {
        var list = new List<CurlPair>();
        if (!e.TryGetProperty(name, out var arr) || arr.ValueKind != JsonValueKind.Array) return list;
        foreach (var p in arr.EnumerateArray())
        {
            if (p.ValueKind != JsonValueKind.Object) continue;
            list.Add(new CurlPair(Str(p, "n", string.Empty), Str(p, "v", string.Empty), !Bool(p, "off", false))
            { HasEquals = !Bool(p, "noEq", false) });
        }
        return list;
    }

    internal static string Str(JsonElement e, string name, string def)
        => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() ?? def : def;

    internal static bool Bool(JsonElement e, string name, bool def)
        => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v)
            ? v.ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, _ => def } : def;

    internal static int Int(JsonElement e, string name, int def)
        => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number
           && v.TryGetInt32(out int i) ? i : def;

    internal static long Long(JsonElement e, string name, long def)
        => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number
           && v.TryGetInt64(out long i) ? i : def;

    /// <summary>A short label for lists: "GET example.com/path".</summary>
    public string ShortLabel()
    {
        string u = Url.Trim();
        int s = u.IndexOf("://", StringComparison.Ordinal);
        if (s >= 0) u = u[(s + 3)..];
        int q = u.IndexOf('?');
        if (q >= 0) u = u[..q];
        if (u.EndsWith('/') && u.Count(c => c == '/') == 1) u = u.TrimEnd('/');
        return u.Length == 0 ? "Untitled request" : u;
    }

    internal static string Inv(double d) => d.ToString("0.###", CultureInfo.InvariantCulture);
}
