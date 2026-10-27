using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Echoes.Helpers;

/// <summary>
/// A request copied from a browser's developer tools, as the Doctor sends it: the method, the URL with its whole path
/// and query, every header in order (cookies, user agent, referer, custom ones) and the body. It reads "Copy as cURL"
/// (bash or cmd, through <see cref="CurlCommand"/>), "Copy as fetch" (browser or Node.js), "Copy as PowerShell", a HAR
/// file or one entry of it, and a raw request ("GET / HTTP/1.1" and its headers). Its headers and body are the user's
/// own and may carry secrets: the view model keeps it only sealed, and everything shown is masked
/// (<see cref="DoctorSecrets"/>). Pure string work: AOT- and trim-safe.
/// </summary>
public sealed class DoctorRequest
{
    /// <summary>The longest text read (a HAR with its responses can be large; a request never is).</summary>
    public const int MaxText = 8 * 1024 * 1024;
    /// <summary>The largest body sent: the Doctor diagnoses a site, it doesn't upload to it.</summary>
    public const int MaxBody = 64 * 1024;
    private const int MaxHeaders = 100;
    private const int MaxHeaderValue = 16 * 1024;

    private DoctorRequest(string method, Uri url, List<(string Name, string Value)> headers, byte[]? body, string source,
                          List<string> notes, string? resolveTo)
    {
        Method = method;
        Url = url;
        Headers = headers;
        Body = body;
        Source = source;
        Notes = notes;
        ResolveTo = resolveTo;
    }

    public string Method { get; }
    /// <summary>An absolute http:// or https:// URL, without user info or fragment.</summary>
    public Uri Url { get; }
    /// <summary>The headers as sent, in order. The connection's own (Host, Content-Length, Connection …) aren't kept: the
    /// URL and the body say them.</summary>
    public IReadOnlyList<(string Name, string Value)> Headers { get; }
    /// <summary>The body, or null for none.</summary>
    public byte[]? Body { get; }
    /// <summary>What it was copied as: "cURL", "fetch", "PowerShell", "HAR", "raw HTTP".</summary>
    public string Source { get; }
    /// <summary>What couldn't be taken over, in a few words each ("its body file (data.json) isn't read").</summary>
    public IReadOnlyList<string> Notes { get; }
    /// <summary>The address a cURL command pinned the host to (--resolve / --connect-to), as written; null when none.</summary>
    public string? ResolveTo { get; }

    public string? Header(string name) => Headers.FirstOrDefault(h => h.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;

    /// <summary>"POST example.com/api/items?… · 7 headers · 120-byte body".</summary>
    public string Summary
    {
        get
        {
            string where = Url.IdnHost + (Url.IsDefaultPort ? "" : ":" + Url.Port) + Url.AbsolutePath + (Url.Query.Length > 1 ? "?…" : "");
            string body = Body is { } b ? $" · {b.Length.ToString("N0", CultureInfo.InvariantCulture)}-byte body" : "";
            return $"{Method} {where} · {Count(Headers.Count, "header")}{body}";
        }
    }

    /// <summary>Everything about it, masked: the request line, each header, the body's size and type, and the notes (the
    /// tooltip of the imported request, and the copied report).</summary>
    public string Describe()
    {
        var sb = new StringBuilder();
        sb.Append(Method).Append(' ').Append(DoctorSecrets.Url(Url.AbsoluteUri)).Append("  (from ").Append(Source).Append(')');
        foreach (var (n, v) in Headers) sb.Append('\n').Append(n).Append(": ").Append(DoctorSecrets.Header(n, v));
        if (Body is { } b) sb.Append('\n').Append($"Body: {b.Length.ToString("N0", CultureInfo.InvariantCulture)} bytes");
        foreach (var note in Notes) sb.Append('\n').Append("Note: ").Append(note);
        return sb.ToString();
    }

    private static string Count(int n, string unit) => n == 1 ? $"1 {unit}" : $"{n} {unit}s";

    // ================================================================== reading

    private static readonly Regex FetchRx = new(@"(?:^|[\s;(=!])(?:await\s+)?fetch\s*\(",
        RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private static readonly Regex PsCallRx = new(@"(?:^|[\s;|(=])(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)(?=\s)",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
    private static readonly Regex PsUserAgentRx = new(@"\$\w+\.UserAgent\s*=\s*",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
    private static readonly Regex PsCookieRx = new(@"New-Object\s+System\.Net\.Cookie\s*\(\s*",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
    private static readonly Regex RawLineRx = new(@"^([A-Za-z]{3,12})\s+(\S+)\s+HTTP/\d(?:\.\d)?\s*$",
        RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    /// <summary>True when the text looks like something <see cref="TryParse"/> reads (what the clipboard pre-fills).</summary>
    public static bool LooksLikeRequest(string? text)
    {
        if (string.IsNullOrWhiteSpace(text) || text.Length > MaxText) return false;
        string t = StripFences(text.Trim());
        try
        {
            if (CurlCommand.LooksLikeCurl(t) || FetchRx.IsMatch(t) || PsCallRx.IsMatch(t)) return true;
            if (t[0] == '{') return t.Contains("\"request\"", StringComparison.Ordinal) || t.Contains("\"method\"", StringComparison.Ordinal);
            return RawLineRx.IsMatch(FirstLine(t));
        }
        catch (RegexMatchTimeoutException) { return false; }
    }

    /// <summary>Reads a request copied from a browser (see the class summary). False with one sentence on why not.</summary>
    public static bool TryParse(string? text, out DoctorRequest? request, out string error)
    {
        request = null;
        error = "";
        string t = (text ?? "").Trim();
        if (t.Length > 0 && t[0] == (char)0xFEFF) t = t[1..];   // a byte order mark pasted along
        if (t.Length == 0)
        {
            error = "Paste a request copied from the browser: Copy as cURL, Copy as fetch, Copy as PowerShell or a HAR entry.";
            return false;
        }
        if (t.Length > MaxText) { error = "That's too long to be one request."; return false; }
        t = StripFences(t);
        try
        {
            Draft? d;
            if (CurlCommand.LooksLikeCurl(t)) d = FromCurl(t, out error);
            else if (t[0] is '{' or '[') d = FromHar(t, out error);
            else if (FetchRx.IsMatch(t)) d = FromFetch(t, out error);
            else if (PsCallRx.IsMatch(t)) d = FromPowerShell(t, out error);
            else if (RawLineRx.IsMatch(FirstLine(t))) d = FromRaw(t, out error);
            else
            {
                error = "That isn't a request copied from a browser: in its developer tools (Network), use Copy as cURL, Copy as fetch, "
                        + "Copy as PowerShell or Save as HAR.";
                return false;
            }
            return d != null && Finish(d, out request, out error);
        }
        catch (JsonException)
        {
            error = "That JSON couldn't be read: it is cut short or broken. Copy the HAR (or one entry of it) again.";
            return false;
        }
        catch (Exception e) when (e is FormatException or RegexMatchTimeoutException or ArgumentException or InvalidOperationException
                                       or OverflowException)
        {
            error = "That request couldn't be read: " + (e is RegexMatchTimeoutException ? "it's too complex" : e is FormatException ? e.Message : DoctorDns.Short(e)) + ".";
            return false;
        }
    }

    // A request as read, before it is checked and cleaned (Finish).
    private sealed class Draft
    {
        public string Method = "GET";
        public string Url = "";
        public readonly List<(string Name, string Value)> Headers = new();
        public byte[]? Body;
        public string Source = "";
        public readonly List<string> Notes = new();
        public string? ResolveTo;
        public bool Has(string name) => Headers.Exists(h => h.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
    }

    // ---------------------------------------------------------------- cURL (bash, cmd, PowerShell's curl.exe)

    private static Draft? FromCurl(string t, out string error)
    {
        error = "";
        var r = CurlCommand.Parse(t);
        if (!r.Ok) { error = r.Error ?? "That curl command couldn't be read."; return null; }
        var q = r.Request;
        var d = new Draft { Source = "cURL", Method = q.Method, Url = q.Url };
        // what the command sends: its -H headers, then the cookies (-b), -u's Authorization and the body's Content-Type;
        // --compressed (the browsers' copies say that instead of their Accept-Encoding) asks for what curl decodes
        foreach (var h in q.EffectiveHeaders()) d.Headers.Add(h);
        if (q.Compressed && !d.Has("Accept-Encoding")) d.Headers.Add(("Accept-Encoding", "gzip, deflate, br"));
        switch (q.EffectiveBodyMode)
        {
            case CurlBodyMode.Raw:
            case CurlBodyMode.Form:
                d.Body = q.BodyBytes();
                break;
            case CurlBodyMode.File:
                d.Notes.Add($"its body file ({Shorten(q.BodyFile, 30)}) isn't read: sent without a body");
                break;
            case CurlBodyMode.Multipart:
                d.Notes.Add("its form fields (-F) aren't sent");
                d.Headers.RemoveAll(h => h.Name.Equals("Content-Type", StringComparison.OrdinalIgnoreCase));
                break;
        }
        if (q.OverrideIp is { Length: > 0 } pin) d.ResolveTo = pin;
        if (q.Proxy is { Length: > 0 }) d.Notes.Add("its proxy isn't used: switch on Proxy for that");
        if (r.Ignored.Count > 0) d.Notes.Add("ignored " + string.Join(", ", r.Ignored.Take(4)) + (r.Ignored.Count > 4 ? " …" : ""));
        return d;
    }

    // ---------------------------------------------------------------- HAR (Save all as HAR, or one entry / request)

    private static Draft? FromHar(string t, out string error)
    {
        error = "";
        using var doc = JsonDocument.Parse(t, new JsonDocumentOptions
        {
            AllowTrailingCommas = true,
            CommentHandling = JsonCommentHandling.Skip,
            MaxDepth = 64,
        });
        var root = doc.RootElement;
        var d = new Draft { Source = "HAR" };

        // the entries of a whole HAR file, a list of entries, one entry, or a request object
        JsonElement? entries = root.ValueKind == JsonValueKind.Object && root.TryGetProperty("log", out var log)
                               && log.TryGetProperty("entries", out var e) && e.ValueKind == JsonValueKind.Array ? e
                             : root.ValueKind == JsonValueKind.Array ? root : null;
        JsonElement req;
        if (entries is { } list)
        {
            var all = list.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.Object && x.TryGetProperty("request", out _)).ToList();
            if (all.Count == 0) { error = "That HAR has no requests in it."; return null; }
            // the page itself (the document request) when there is one: what "this site won't open" is about
            var page = all.FirstOrDefault(x => Str(x, "_resourceType").Equals("document", StringComparison.OrdinalIgnoreCase));
            var pick = page.ValueKind == JsonValueKind.Object ? page : all[0];
            if (all.Count > 1) d.Notes.Add($"the HAR holds {all.Count} requests: the {(page.ValueKind == JsonValueKind.Object ? "page's own" : "first")} one is used");
            req = pick.GetProperty("request");
        }
        else if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty("request", out var r1) && r1.ValueKind == JsonValueKind.Object) req = r1;
        else if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty("url", out _)) req = root;
        else { error = "That JSON isn't a HAR file or entry (it has no request in it)."; return null; }

        d.Method = Str(req, "method", "GET");
        d.Url = Str(req, "url");
        if (req.TryGetProperty("headers", out var hs) && hs.ValueKind == JsonValueKind.Array)
            foreach (var h in hs.EnumerateArray())
                if (Str(h, "name") is { Length: > 0 } n) d.Headers.Add((n, Str(h, "value")));
        if (!d.Has("Cookie") && req.TryGetProperty("cookies", out var cs) && cs.ValueKind == JsonValueKind.Array)
        {
            var pairs = cs.EnumerateArray().Where(c => Str(c, "name").Length > 0).Select(c => Str(c, "name") + "=" + Str(c, "value")).ToList();
            if (pairs.Count > 0) d.Headers.Add(("Cookie", string.Join("; ", pairs)));
        }
        if (req.TryGetProperty("postData", out var pd) && pd.ValueKind == JsonValueKind.Object)
        {
            string mime = Str(pd, "mimeType");
            if (pd.TryGetProperty("text", out var text) && text.ValueKind == JsonValueKind.String)
                d.Body = Encoding.UTF8.GetBytes(text.GetString() ?? "");
            else if (pd.TryGetProperty("params", out var ps) && ps.ValueKind == JsonValueKind.Array)
                d.Body = Encoding.ASCII.GetBytes(string.Join("&", ps.EnumerateArray()
                    .Select(p => CurlRequest.FormEncode(Str(p, "name")) + "=" + CurlRequest.FormEncode(Str(p, "value")))));
            if (mime.Length > 0 && !d.Has("Content-Type")) d.Headers.Add(("Content-Type", mime));
        }
        return d;
    }

    private static string Str(JsonElement e, string name, string def = "")
        => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? def : def;

    // ---------------------------------------------------------------- fetch("url", { … }) (browser and Node.js)

    private static Draft? FromFetch(string t, out string error)
    {
        error = "";
        var m = FetchRx.Match(t);
        var js = new JsReader(t, m.Index + m.Length);
        if (js.ReadValue() is not string url) { error = "The fetch call has no URL string in it."; return null; }
        var d = new Draft { Source = "fetch", Url = url };
        js.Skip();
        if (js.Peek == ',')
        {
            js.Next();
            js.Skip();
            if (js.Peek == '{' && js.ReadValue() is Dictionary<string, object?> o) FetchOptions(o, d);
        }
        if (js.Template) d.Notes.Add("a `template` with ${…} in it is sent as written");
        return d;
    }

    private static void FetchOptions(Dictionary<string, object?> o, Draft d)
    {
        if (o.TryGetValue("method", out var m) && m is string method) d.Method = method;
        switch (o.GetValueOrDefault("headers"))
        {
            case Dictionary<string, object?> map:
                foreach (var kv in map) Add(kv.Key, kv.Value);
                break;
            case List<object?> pairs:   // [["name", "value"], …]
                foreach (var p in pairs) if (p is List<object?> { Count: 2 } pair && pair[0] is string k) Add(k, pair[1]);
                break;
            case JsCode code:
                d.Notes.Add($"its headers are code ({Shorten(code.Text, 30)}): not sent");
                break;
        }
        switch (o.GetValueOrDefault("body"))
        {
            case string body: d.Body = Encoding.UTF8.GetBytes(body); break;
            case JsCode code: d.Notes.Add($"its body is code ({Shorten(code.Text, 30)}): sent without a body"); break;
        }
        // the browser fetch writes the page it ran on apart from the headers; it goes as Referer
        if (o.GetValueOrDefault("referrer") is string referrer && referrer.Length > 0 && !d.Has("Referer")) d.Headers.Add(("Referer", referrer));

        void Add(string name, object? value)
        {
            if (value is string s) d.Headers.Add((name, s));
            else if (value is double n) d.Headers.Add((name, n.ToString(CultureInfo.InvariantCulture)));
            else if (value is bool b) d.Headers.Add((name, b ? "true" : "false"));
        }
    }

    // A value in JavaScript source that is code (a variable, a call): not run, said in a note.
    private sealed record JsCode(string Text);

    // The JavaScript literals "Copy as fetch" writes: strings ('…', "…", `…`) with their escapes, objects, arrays,
    // numbers, true / false / null / undefined; anything else is kept as code.
    private sealed class JsReader
    {
        private readonly string _s;
        private int _i;
        public JsReader(string s, int i) { _s = s; _i = i; }

        public bool Template { get; private set; }
        public char Peek => _i < _s.Length ? _s[_i] : '\0';
        public void Next() => _i++;

        public void Skip()
        {
            while (_i < _s.Length)
            {
                char c = _s[_i];
                if (char.IsWhiteSpace(c)) { _i++; continue; }
                if (c == '/' && _i + 1 < _s.Length && _s[_i + 1] == '/')
                {
                    int nl = _s.IndexOf('\n', _i);
                    _i = nl < 0 ? _s.Length : nl + 1;
                    continue;
                }
                if (c == '/' && _i + 1 < _s.Length && _s[_i + 1] == '*')
                {
                    int end = _s.IndexOf("*/", _i + 2, StringComparison.Ordinal);
                    _i = end < 0 ? _s.Length : end + 2;
                    continue;
                }
                break;
            }
        }

        public object? ReadValue(int depth = 0)
        {
            if (depth > 32) throw new FormatException("it nests too deep");
            Skip();
            char c = Peek;
            if (c is '"' or '\'' or '`') return ReadString();
            if (c == '{') return ReadObject(depth);
            if (c == '[') return ReadArray(depth);
            // a number, true / false / null / undefined, or code: up to the next , } ] or ) outside brackets
            int start = _i, nest = 0;
            while (_i < _s.Length)
            {
                char x = _s[_i];
                if (x is '"' or '\'' or '`') { ReadString(); continue; }
                if (x is '(' or '[' or '{') nest++;
                else if (x is ')' or ']' or '}') { if (nest == 0) break; nest--; }
                else if (x == ',' && nest == 0) break;
                _i++;
            }
            string word = _s[start.._i].Trim();
            if (word is "" or "null" or "undefined") return null;
            if (word == "true") return true;
            if (word == "false") return false;
            if (double.TryParse(word, NumberStyles.Float, CultureInfo.InvariantCulture, out double num)) return num;
            return new JsCode(word);
        }

        private Dictionary<string, object?> ReadObject(int depth)
        {
            var o = new Dictionary<string, object?>(StringComparer.Ordinal);
            _i++;   // {
            while (true)
            {
                Skip();
                if (Peek == '}') { _i++; return o; }
                if (Peek == '\0') throw new FormatException("a { isn't closed");
                string key;
                if (Peek is '"' or '\'' or '`') key = ReadString();
                else
                {
                    int s0 = _i;
                    while (_i < _s.Length && (char.IsLetterOrDigit(_s[_i]) || _s[_i] is '_' or '$' or '-')) _i++;
                    key = _s[s0.._i];
                    if (key.Length == 0) throw new FormatException("a name was expected in an object");
                }
                Skip();
                if (Peek != ':') throw new FormatException($"\"{key}\" has no value");
                _i++;
                o[key] = ReadValue(depth + 1);
                Skip();
                if (Peek == ',') { _i++; continue; }
                if (Peek == '}') { _i++; return o; }
                throw new FormatException("a , or } was expected in an object");
            }
        }

        private List<object?> ReadArray(int depth)
        {
            var list = new List<object?>();
            _i++;   // [
            while (true)
            {
                Skip();
                if (Peek == ']') { _i++; return list; }
                if (Peek == '\0') throw new FormatException("a [ isn't closed");
                list.Add(ReadValue(depth + 1));
                Skip();
                if (Peek == ',') { _i++; continue; }
                if (Peek == ']') { _i++; return list; }
                throw new FormatException("a , or ] was expected in a list");
            }
        }

        public string ReadString()
        {
            char q = _s[_i++];
            var sb = new StringBuilder();
            while (_i < _s.Length)
            {
                char c = _s[_i++];
                if (c == q) return sb.ToString();
                if (c == '\\' && _i < _s.Length)
                {
                    char e = _s[_i++];
                    switch (e)
                    {
                        case 'n': sb.Append('\n'); break;
                        case 'r': sb.Append('\r'); break;
                        case 't': sb.Append('\t'); break;
                        case 'b': sb.Append('\b'); break;
                        case 'f': sb.Append('\f'); break;
                        case 'v': sb.Append('\v'); break;
                        case '0': sb.Append('\0'); break;
                        case 'x': sb.Append((char)Hex(2)); break;
                        case 'u':
                            if (Peek == '{')
                            {
                                int close = _s.IndexOf('}', _i);
                                if (close < 0) throw new FormatException("a \\u{…} isn't closed");
                                int cp = int.Parse(_s[(_i + 1)..close], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                                _i = close + 1;
                                sb.Append(char.ConvertFromUtf32(cp));
                            }
                            else sb.Append((char)Hex(4));
                            break;
                        case '\r': if (Peek == '\n') _i++; break;   // a line continuation
                        case '\n': break;
                        default: sb.Append(e); break;               // \" \' \\ \/ \`
                    }
                    continue;
                }
                if (q == '`' && c == '$' && Peek == '{') Template = true;
                sb.Append(c);
            }
            throw new FormatException("a string isn't closed");
        }

        private int Hex(int digits)
        {
            if (_i + digits > _s.Length) throw new FormatException("an escape is cut short");
            int v = int.Parse(_s.AsSpan(_i, digits), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            _i += digits;
            return v;
        }
    }

    // ---------------------------------------------------------------- PowerShell (Invoke-WebRequest / Invoke-RestMethod)

    private static Draft? FromPowerShell(string t, out string error)
    {
        error = "";
        var d = new Draft { Source = "PowerShell" };
        // $session.UserAgent = "…" and $session.Cookies.Add((New-Object System.Net.Cookie("name", "value", "/", "domain")))
        foreach (Match m in PsUserAgentRx.Matches(t))
            if (new PsReader(t, m.Index + m.Length).ReadString() is { } ua) d.Headers.Add(("User-Agent", ua));
        var cookies = new List<string>();
        foreach (Match m in PsCookieRx.Matches(t))
        {
            var ps = new PsReader(t, m.Index + m.Length);
            string? name = ps.ReadString();
            ps.SkipSpace();
            if (ps.Peek == ',') ps.Next();
            string? value = ps.ReadString();
            if (name is { Length: > 0 } && value != null) cookies.Add(name + "=" + value);
        }

        var call = PsCallRx.Match(t);
        var r = new PsReader(t, call.Index + call.Length);
        string? contentType = null;
        while (r.NextParameter() is { } name)
        {
            switch (name.ToLowerInvariant())
            {
                case "uri":
                    d.Url = r.ReadWord() ?? "";
                    break;
                case "method":
                    d.Method = r.ReadWord() ?? "GET";
                    break;
                case "headers":
                    // Chrome's older exports list HTTP/2's pseudo-headers here without their colon: the URL says them
                    foreach (var h in r.ReadHashtable())
                        if (h.Item1.ToLowerInvariant() is not ("authority" or "method" or "path" or "scheme")) d.Headers.Add(h);
                    break;
                case "contenttype":
                    contentType = r.ReadWord();
                    break;
                case "useragent":
                    if (r.ReadWord() is { } ua && !d.Has("User-Agent")) d.Headers.Add(("User-Agent", ua));
                    break;
                case "body":
                {
                    // a string, or ([System.Text.Encoding]::UTF8.GetBytes("…")) for a body with non-ASCII text
                    string? raw = r.ReadValue(out bool literal);
                    string? body = literal ? raw : raw != null ? new PsReader(raw, 0).FindString() : null;
                    if (body != null) d.Body = Encoding.UTF8.GetBytes(body);
                    else if (raw != null) d.Notes.Add($"its body is code ({Shorten(raw, 30)}): sent without a body");
                    break;
                }
                default:
                    r.SkipValue();   // -WebSession $session, -TimeoutSec 30 … (a switch has no value)
                    break;
            }
        }
        if (d.Url.Length == 0) { error = "The PowerShell command has no -Uri."; return null; }
        if (cookies.Count > 0 && !d.Has("Cookie")) d.Headers.Add(("Cookie", string.Join("; ", cookies)));
        if (contentType != null && !d.Has("Content-Type")) d.Headers.Add(("Content-Type", contentType));
        if (r.Expanded) d.Notes.Add("PowerShell variables ($…) are sent as written");
        return d;
    }

    // PowerShell's quoting: "…" with backtick escapes (`" `$ `n …) and "" for a quote, '…' with '' for a quote, a
    // backtick at a line's end continues the command, @{ "k"="v" … } a hashtable.
    private sealed class PsReader
    {
        private static readonly Regex CharRx = new(@"\$\(\[char\]\s*(0x[0-9A-Fa-f]{1,4}|\d{1,5})\)",
            RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));

        private readonly string _s;
        private int _i;
        public PsReader(string s, int i) { _s = s; _i = i; }

        private static int? ParseNumber(string s)
            => s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                ? int.TryParse(s[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int h) ? h : null
                : int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out int d) ? d : null;

        public bool Expanded { get; private set; }
        public char Peek => _i < _s.Length ? _s[_i] : '\0';
        public void Next() => _i++;

        public void SkipSpace()
        {
            while (_i < _s.Length)
            {
                char c = _s[_i];
                if (c == '`' && _i + 1 < _s.Length && (_s[_i + 1] == '\n' || _s[_i + 1] == '\r')) { _i += 2; continue; }
                if (c is ' ' or '\t' or '\r' or '\n') { _i++; continue; }
                break;
            }
        }

        /// <summary>The next "-Name" of the command, or null at its end.</summary>
        public string? NextParameter()
        {
            SkipSpace();
            if (Peek != '-' || _i + 1 >= _s.Length || !char.IsLetter(_s[_i + 1])) return null;
            int start = ++_i;
            while (_i < _s.Length && (char.IsLetterOrDigit(_s[_i]) || _s[_i] == '_')) _i++;
            string name = _s[start.._i];
            if (Peek == ':') _i++;   // -Name:value
            return name;
        }

        /// <summary>A parameter's value: a string's text, or anything else as written (a word, $var, ( … )).</summary>
        public string? ReadWord() => ReadValue(out _);

        public string? ReadValue(out bool literal)
        {
            literal = false;
            SkipSpace();
            char c = Peek;
            if (c is '"' or '\'') { literal = true; return ReadString(); }
            if (c == '\0' || (c == '-' && _i + 1 < _s.Length && char.IsLetter(_s[_i + 1]))) return null;
            int start = _i;
            if (c == '(' || (c == '@' && _i + 1 < _s.Length && _s[_i + 1] is '{' or '('))
            {
                SkipBalanced();
                return _s[start.._i];
            }
            while (_i < _s.Length && !char.IsWhiteSpace(_s[_i])) _i++;
            return _s[start.._i];
        }

        public void SkipValue()
        {
            SkipSpace();
            if (Peek == '\0' || (Peek == '-' && _i + 1 < _s.Length && char.IsLetter(_s[_i + 1]))) return;   // a switch
            ReadValue(out _);
        }

        public IEnumerable<(string, string)> ReadHashtable()
        {
            var list = new List<(string, string)>();
            SkipSpace();
            if (!(Peek == '@' && _i + 1 < _s.Length && _s[_i + 1] == '{')) { ReadValue(out _); return list; }
            _i += 2;
            while (true)
            {
                while (_i < _s.Length && (char.IsWhiteSpace(_s[_i]) || _s[_i] == ';' || _s[_i] == '`')) _i++;
                if (Peek == '}') { _i++; return list; }
                if (Peek == '\0') throw new FormatException("a @{ isn't closed");
                string key;
                if (Peek is '"' or '\'') key = ReadString() ?? "";
                else
                {
                    int s0 = _i;
                    while (_i < _s.Length && _s[_i] != '=' && !char.IsWhiteSpace(_s[_i])) _i++;
                    key = _s[s0.._i];
                }
                while (_i < _s.Length && _s[_i] is ' ' or '\t') _i++;
                if (Peek != '=') throw new FormatException($"the header \"{key}\" has no value");
                _i++;
                while (_i < _s.Length && _s[_i] is ' ' or '\t') _i++;
                string value;
                if (Peek is '"' or '\'') value = ReadString() ?? "";
                else
                {
                    int s0 = _i;
                    while (_i < _s.Length && _s[_i] is not ('\n' or '\r' or ';' or '}')) _i++;
                    value = _s[s0.._i].Trim();
                }
                list.Add((key, value));
            }
        }

        /// <summary>The first string literal from here on (inside an expression), or null.</summary>
        public string? FindString()
        {
            while (_i < _s.Length)
            {
                if (_s[_i] is '"' or '\'') return ReadString();
                _i++;
            }
            return null;
        }

        public string? ReadString()
        {
            SkipSpace();
            char q = Peek;
            if (q is not ('"' or '\'')) return null;
            _i++;
            var sb = new StringBuilder();
            while (_i < _s.Length)
            {
                char c = _s[_i++];
                if (c == q)
                {
                    if (Peek == q) { sb.Append(q); _i++; continue; }   // "" / '' inside: a quote
                    return sb.ToString();
                }
                if (q == '"' && c == '`' && _i < _s.Length)
                {
                    char e = _s[_i++];
                    sb.Append(e switch
                    {
                        'n' => '\n', 't' => '\t', 'r' => '\r', '0' => '\0', 'a' => '\a', 'b' => '\b', 'f' => '\f', 'v' => '\v',
                        'e' => '\u001B',
                        _ => e,
                    });
                    continue;
                }
                if (q == '"' && c == '$' && _i < _s.Length && (char.IsLetter(_s[_i]) || _s[_i] is '{' or '(' or '_'))
                {
                    // Chrome writes a character outside ASCII as $([char]233): that one character
                    var ch = CharRx.Match(_s, _i - 1);
                    if (ch.Success && ch.Index == _i - 1 && ParseNumber(ch.Groups[1].Value) is int code and <= 0xFFFF)
                    {
                        sb.Append((char)code);
                        _i = ch.Index + ch.Length;
                        continue;
                    }
                    Expanded = true;
                }
                sb.Append(c);
            }
            throw new FormatException("a string isn't closed");
        }

        private void SkipBalanced()
        {
            int depth = 0;
            while (_i < _s.Length)
            {
                char c = _s[_i];
                if (c is '"' or '\'') { ReadString(); continue; }
                if (c is '(' or '{' or '[') depth++;
                else if (c is ')' or '}' or ']')
                {
                    depth--;
                    if (depth <= 0) { _i++; return; }
                }
                _i++;
            }
        }
    }

    // ---------------------------------------------------------------- the raw request ("GET /path HTTP/1.1", headers, body)

    private static Draft? FromRaw(string t, out string error)
    {
        error = "";
        string text = t.Replace("\r\n", "\n");
        int blank = text.IndexOf("\n\n", StringComparison.Ordinal);
        string head = blank < 0 ? text : text[..blank];
        string? body = blank < 0 ? null : text[(blank + 2)..];
        var lines = head.Split('\n');
        var m = RawLineRx.Match(lines[0].Trim());
        var d = new Draft { Source = "raw HTTP", Method = m.Groups[1].Value };
        foreach (var line in lines.Skip(1))
        {
            int colon = line.IndexOf(':', 1);   // from 1: an HTTP/2 pseudo-header (":authority: x") starts with one
            if (colon <= 0) continue;
            d.Headers.Add((line[..colon].Trim(), line[(colon + 1)..].Trim()));
        }
        string target = m.Groups[2].Value;
        if (target.Contains("://", StringComparison.Ordinal)) d.Url = target;
        else
        {
            string? host = d.Headers.FirstOrDefault(h => h.Name.Equals("Host", StringComparison.OrdinalIgnoreCase) || h.Name == ":authority").Value;
            if (string.IsNullOrWhiteSpace(host)) { error = "The request has no Host header, so its site is unknown."; return null; }
            // a raw request doesn't say its scheme: https, as nearly every site is now
            d.Url = "https://" + host.Trim() + (target.StartsWith('/') ? target : "/" + target);
            d.Notes.Add("its scheme isn't in the text: https:// is used");
        }
        if (!string.IsNullOrEmpty(body)) d.Body = Encoding.UTF8.GetBytes(body);
        return d;
    }

    // ================================================================== checking

    // The connection's own headers: the URL, the body and the HTTP version decide them. A proxy's login is for the
    // proxy, never for the site.
    private static readonly HashSet<string> ConnectionHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Host", "Content-Length", "Connection", "Keep-Alive", "Transfer-Encoding", "TE", "Upgrade", "Proxy-Connection",
        "Expect", "Trailer", "Proxy-Authorization", "HTTP2-Settings",
    };

    private static bool Finish(Draft d, out DoctorRequest? request, out string error)
    {
        request = null;
        error = "";
        string url = d.Url.Trim();
        if (url.Length == 0) { error = "The request has no URL."; return false; }
        if (url.StartsWith('/'))
        {
            error = $"Its URL is only a path ({Shorten(url, 40)}): copy the request again from the Network tab, which gives the whole address.";
            return false;
        }
        if (!url.Contains("://", StringComparison.Ordinal)) url = "http://" + url;   // as curl reads a bare host
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") || uri.Host.Length == 0)
        {
            error = $"\"{Shorten(url, 60)}\" isn't an http:// or https:// address.";
            return false;
        }
        var notes = d.Notes;
        // a fragment never leaves the browser; user:password in the URL would go into the report
        if (uri.UserInfo.Length > 0) notes.Add("the user name and password in its URL aren't sent: an Authorization header carries them");
        if (uri.UserInfo.Length > 0 || uri.Fragment.Length > 0)
            uri = new Uri(uri.GetComponents(UriComponents.SchemeAndServer | UriComponents.PathAndQuery, UriFormat.UriEscaped));

        string method = d.Method.Trim();
        if (method.Length == 0) method = "GET";
        string upper = method.ToUpperInvariant();
        if (upper is "GET" or "POST" or "PUT" or "PATCH" or "DELETE" or "HEAD" or "OPTIONS") method = upper;
        if (!IsToken(method) || method.Length > 20) { error = $"\"{Shorten(method, 20)}\" isn't an HTTP method."; return false; }
        if (method is "CONNECT" or "TRACE") { error = $"A {method} request can't be diagnosed: copy the page's own request."; return false; }

        var headers = new List<(string Name, string Value)>();
        var dropped = new List<string>();
        foreach (var (n0, v0) in d.Headers)
        {
            string n = n0.Trim();
            if (n.StartsWith(':')) continue;   // HTTP/2 pseudo-headers (:authority, :path …): the URL says them
            if (ConnectionHeaders.Contains(n))
            {
                // Host and Content-Length go without saying; the others are worth a word
                if (n.ToLowerInvariant() is not ("host" or "content-length") && !dropped.Contains(n, StringComparer.OrdinalIgnoreCase)) dropped.Add(n);
                continue;
            }
            if (!IsToken(n)) { notes.Add($"\"{Shorten(n, 24)}\" isn't a header name: left out"); continue; }
            // a line break inside a value would start another header on the wire
            string v = v0.Replace("\r", " ").Replace("\n", " ").Trim();
            if (v.Length > MaxHeaderValue) { error = $"Its {n} header is too long ({v.Length.ToString("N0", CultureInfo.InvariantCulture)} characters)."; return false; }
            headers.Add((n, v));
        }
        if (headers.Count > MaxHeaders) { error = $"It has {headers.Count} headers; the Doctor sends at most {MaxHeaders}."; return false; }
        if (dropped.Count > 0) notes.Add($"{string.Join(", ", dropped)} {(dropped.Count == 1 ? "is" : "are")} the connection's own: not copied");

        byte[]? body = d.Body;
        if (body is { Length: > MaxBody })
        {
            error = $"Its body is {body.Length.ToString("N0", CultureInfo.InvariantCulture)} bytes; the Doctor sends at most {MaxBody / 1024} KB.";
            return false;
        }
        if (body != null && method == "HEAD") { body = null; notes.Add("a HEAD request carries no body: left out"); }
        if (body is { Length: 0 } && method is "GET" or "OPTIONS") body = null;

        request = new DoctorRequest(method, uri, headers, body, d.Source, notes, d.ResolveTo);
        return true;
    }

    // An HTTP token (a method or a header name): letters, digits and !#$%&'*+-.^_`|~
    private static bool IsToken(string s)
        => s.Length > 0 && s.All(c => c < 128 && (char.IsAsciiLetterOrDigit(c) || "!#$%&'*+-.^_`|~".Contains(c)));

    private static string StripFences(string t)
    {
        if (!t.StartsWith("```", StringComparison.Ordinal)) return t;
        int nl = t.IndexOf('\n');
        string s = nl < 0 ? "" : t[(nl + 1)..].TrimEnd();
        return s.EndsWith("```", StringComparison.Ordinal) ? s[..^3].Trim() : s.Trim();
    }

    private static string FirstLine(string t)
    {
        int nl = t.IndexOf('\n');
        return (nl < 0 ? t : t[..nl]).Trim();
    }

    private static string Shorten(string s, int max) => s.Length <= max ? s : s[..max] + "…";

    // ================================================================== kept sealed (the view model persists it)

    public string ToJson()
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            w.WriteNumber("v", 1);
            w.WriteString("method", Method);
            w.WriteString("url", Url.AbsoluteUri);
            w.WriteString("source", Source);
            w.WriteStartArray("headers");
            foreach (var (n, v) in Headers)
            {
                w.WriteStartArray();
                w.WriteStringValue(n);
                w.WriteStringValue(v);
                w.WriteEndArray();
            }
            w.WriteEndArray();
            if (Body != null) w.WriteBase64String("body", Body);
            if (ResolveTo != null) w.WriteString("resolve", ResolveTo);
            w.WriteStartArray("notes");
            foreach (var n in Notes) w.WriteStringValue(n);
            w.WriteEndArray();
            w.WriteEndObject();
        }
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    /// <summary>A request written by <see cref="ToJson"/>, checked again; null when it isn't one.</summary>
    public static DoctorRequest? FromJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var e = doc.RootElement;
            var d = new Draft { Method = Str(e, "method", "GET"), Url = Str(e, "url"), Source = Str(e, "source") };
            if (e.TryGetProperty("headers", out var hs) && hs.ValueKind == JsonValueKind.Array)
                foreach (var h in hs.EnumerateArray())
                    if (h.ValueKind == JsonValueKind.Array && h.GetArrayLength() == 2)
                        d.Headers.Add((h[0].GetString() ?? "", h[1].GetString() ?? ""));
            if (e.TryGetProperty("body", out var b) && b.ValueKind == JsonValueKind.String) d.Body = b.GetBytesFromBase64();
            if (Str(e, "resolve") is { Length: > 0 } pin) d.ResolveTo = pin;
            if (e.TryGetProperty("notes", out var ns) && ns.ValueKind == JsonValueKind.Array)
                foreach (var n in ns.EnumerateArray()) if (n.GetString() is { Length: > 0 } s) d.Notes.Add(s);
            return Finish(d, out var r, out _) ? r : null;
        }
        catch (Exception ex) when (ex is JsonException or FormatException or InvalidOperationException) { return null; }
    }
}

/// <summary>
/// What the Doctor shows and copies never carries the user's secrets: cookie and token values, Authorization's
/// credentials and the ones in a URL are masked, while names, schemes and cookie attributes stay readable.
/// </summary>
public static class DoctorSecrets
{
    public const string Dots = "•••";

    private static readonly Regex UserInfo = new(@"(://)[^/?#\s]*@", RegexOptions.CultureInvariant);

    /// <summary>A header whose value is (or may be) a secret.</summary>
    public static bool IsSecretHeader(string name)
    {
        string n = name.Trim().ToLowerInvariant();
        return n is "cookie" or "set-cookie" or "set-cookie2" or "authorization" or "proxy-authorization"
               || n.Contains("token") || n.Contains("secret") || n.Contains("passw") || n.Contains("session") || n.Contains("csrf")
               || n.Contains("xsrf") || n.Contains("auth") || n.Contains("signature") || n.Contains("cred")
               || n.EndsWith("key", StringComparison.Ordinal) || n.Contains("api-key") || n.Contains("apikey");
    }

    /// <summary>The value as shown: a cookie's value hidden behind its name ("sid=•••; Path=/; HttpOnly"),
    /// Authorization's credentials behind its scheme ("Bearer •••"), any other secret header wholly.</summary>
    public static string Header(string name, string value)
    {
        if (!IsSecretHeader(name)) return value;
        string n = name.Trim().ToLowerInvariant();
        if (n == "cookie")
            return string.Join("; ", value.Split(';').Select(p => p.Trim()).Where(p => p.Length > 0)
                                          .Select(p => p.IndexOf('=') is int eq and > 0 ? p[..eq].TrimEnd() + "=" + Dots : Dots));
        if (n is "set-cookie" or "set-cookie2")
        {
            int semi = value.IndexOf(';');
            string first = semi < 0 ? value : value[..semi];
            int eq = first.IndexOf('=');
            return (eq > 0 ? first[..eq].TrimEnd() + "=" + Dots : Dots) + (semi < 0 ? "" : value[semi..]);
        }
        if (n is "authorization" or "proxy-authorization")
        {
            int sp = value.Trim().IndexOf(' ');
            return sp > 0 ? value.Trim()[..sp] + " " + Dots : Dots;
        }
        return Dots;
    }

    /// <summary>A URL as shown: no user:password@, secret-looking query values (token, key, sig, session …) emptied.</summary>
    public static string Url(string url) => UrlSecrets.Redact(UserInfo.Replace(url, "$1"));
}
