using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Echoes.Helpers;

/// <summary>
/// Renders the cURL tab's current request as a ready-to-run snippet in several tools/languages. Pure string building
/// (AOT/trim safe) so the CODE section stays in sync with whatever the user would actually send — same method, URL,
/// headers, cookies, auth, body (raw / form / multipart / file), proxy, override IP, TLS / redirect / timeout options.
/// "curl" and "curl (cmd)" read back through <see cref="CurlCommand.Parse"/> into the same request (round trip).
/// </summary>
public static class RequestSnippets
{
    public static readonly string[] Languages =
        { "curl", "curl (cmd)", "PowerShell", "Python", "JavaScript", "HTTPie", "wget" };

    public static string Build(string language, CurlRequest r) => language switch
    {
        "curl" => Curl(r, windows: false),
        "curl (cmd)" => Curl(r, windows: true),
        "PowerShell" => PowerShell(r),
        "Python" => Python(r),
        "JavaScript" => JavaScript(r),
        "HTTPie" => Httpie(r),
        "wget" => Wget(r),
        _ => Curl(r, windows: false),
    };

    // ---- escaping helpers ----

    // POSIX single-quote: wrap in '...', and close/escape/reopen around any embedded quote. A value holding a carriage
    // return or another control character goes in $'...' with escapes instead (as Chrome writes it): pasted back, a raw
    // CR would otherwise be taken for a Windows line ending.
    private static string Sq(string? v)
    {
        v ??= string.Empty;
        bool ctl = false;
        foreach (char c in v) if (c < 0x20 && c is not ('\n' or '\t') || c == 0x7F) { ctl = true; break; }
        if (!ctl) return "'" + v.Replace("'", "'\\''") + "'";
        var sb = new StringBuilder("$'");
        foreach (char c in v)
        {
            switch (c)
            {
                case '\\': sb.Append("\\\\"); break;
                case '\'': sb.Append("\\'"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20 || c == 0x7F) sb.Append("\\u").Append(((int)c).ToString("x4"));
                    else sb.Append(c);
                    break;
            }
        }
        return sb.Append('\'').ToString();
    }

    // Windows cmd.exe, in two layers like Chrome's "Copy as cURL (cmd)" — but with the C runtime's REAL backslash rule:
    // (1) for curl.exe's argv, backslashes are doubled only where they precede a quote (or the closing quote) and a quote
    // is \" — Chrome doubles every backslash, which curl.exe then receives doubled; (2) for cmd.exe, the value sits in
    // ^"…^" with every other unsafe character ^-escaped, %X broken as %^X (no variable expansion) and a line break as
    // ^ + two newlines. A backslash needs nothing from cmd.exe and is left bare — so the import can tell this from Chrome's
    // output (which always writes ^\) and read it back exactly.
    private static string CmdQ(string? v)
    {
        string raw = (v ?? string.Empty).Replace("\r\n", "\n");
        var crt = new StringBuilder(raw.Length + 8);
        for (int i = 0; i < raw.Length; i++)
        {
            int n = 0;
            while (i < raw.Length && raw[i] == '\\') { n++; i++; }
            if (i == raw.Length) { crt.Append('\\', n * 2); break; }          // before the closing quote
            if (raw[i] == '"') { crt.Append('\\', n * 2 + 1).Append('"'); continue; }
            crt.Append('\\', n).Append(raw[i]);
        }
        string s = crt.ToString();
        var sb = new StringBuilder(s.Length + 8).Append("^\"");
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (c is '\n' or '\r') { sb.Append("^\n\n"); continue; }
            if (c == '%')
            {
                sb.Append("^%");
                if (i + 1 < s.Length && (char.IsAsciiLetterOrDigit(s[i + 1]) || s[i + 1] == '_')) sb.Append('^');
                continue;
            }
            bool safe = char.IsAsciiLetterOrDigit(c) || c is ' ' or '\t' or '_' or '-' or ':' or '=' or '+' or '~' or '\''
                        or '/' or '.' or ',' or '?' or ';' or '(' or ')' or '*' or '`' or '\\';
            if (!safe) sb.Append('^');
            sb.Append(c);
        }
        return sb.Append("^\"").ToString();
    }

    // PowerShell single-quote literal. PowerShell's tokenizer treats the Unicode quotes ‘ ’ ‚ ‛ as single
    // quotes too, so a pasted curly apostrophe would close the literal (and could run code after it):
    // double every one of them — a doubled pair of any of these is one literal char in a verbatim string.
    private static string Psq(string? v)
    {
        var sb = new StringBuilder("'");
        foreach (char c in v ?? string.Empty)
        {
            if (c is '\'' or '‘' or '’' or '‚' or '‛') sb.Append(c);
            sb.Append(c);
        }
        sb.Append('\'');
        return sb.ToString();
    }

    // JSON-ish double-quoted string for JS / Python. Plain chars are appended as chars (a 1 MB body stays one pass).
    private static string Dq(string? v)
    {
        v ??= string.Empty;
        var sb = new StringBuilder(v.Length + 2).Append('"');
        foreach (char c in v)
        {
            switch (c)
            {
                case '\\': sb.Append("\\\\"); break;
                case '"': sb.Append("\\\""); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case (char)0x2028: sb.Append("\\u2028"); break;   // a raw U+2028 / U+2029 ends a JS string literal
                case (char)0x2029: sb.Append("\\u2029"); break;
                default:
                    if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                    else sb.Append(c);
                    break;
            }
        }
        return sb.Append('"').ToString();
    }

    // One entry per header name (any case) for the snippets that build a dictionary: PowerShell refuses a hashtable
    // literal with a repeated key, and a Python dict / JS object silently kept only the last value. Values are joined
    // as the .NET engine sends repeated headers: "; " for Cookie, ", " otherwise.
    private static List<(string Name, string Value)> Merged(IEnumerable<(string Name, string Value)> headers)
    {
        var list = new List<(string Name, string Value)>();
        foreach (var (n, v) in headers)
        {
            int i = list.FindIndex(h => string.Equals(h.Name, n, StringComparison.OrdinalIgnoreCase));
            if (i < 0) list.Add((n, v));
            else list[i] = (list[i].Name, list[i].Value + (n.Equals("Cookie", StringComparison.OrdinalIgnoreCase) ? "; " : ", ") + v);
        }
        return list;
    }

    // The headers a snippet sends itself: the effective ones, minus a multipart Content-Type (the tool adds the boundary).
    private static List<(string Name, string Value)> SnippetHeaders(CurlRequest r)
    {
        var all = r.EffectiveHeaders();
        if (r.EffectiveBodyMode == CurlBodyMode.Multipart)
            all.RemoveAll(h => h.Name.Equals("Content-Type", StringComparison.OrdinalIgnoreCase)
                               && h.Value.TrimStart().StartsWith("multipart/", StringComparison.OrdinalIgnoreCase));
        return Merged(all);
    }

    private static (string host, int port) HostPort(string url)
    {
        if (Uri.TryCreate(CurlRequest.NormalizeUrl(url), UriKind.Absolute, out var u))
            return (u.Host, u.Port > 0 ? u.Port : (u.Scheme == "https" ? 443 : 80));
        return (url, 443);
    }

    private static string ProxyUrl(string proxy) => proxy.Contains("://") ? proxy : "http://" + proxy;
    private static bool HasProxy(CurlRequest r) => !string.IsNullOrWhiteSpace(r.Proxy);
    private static bool HasProxyCreds(CurlRequest r) => !string.IsNullOrEmpty(r.ProxyUser) || !string.IsNullOrEmpty(r.ProxyPass);

    // ---- curl (bash / cmd) ----

    private static string Curl(CurlRequest r, bool windows)
    {
        Func<string?, string> q = windows ? CmdQ : Sq;
        string url = CurlRequest.NormalizeUrl(r.Url);
        var mode = r.EffectiveBodyMode;
        bool hasBody = mode != CurlBodyMode.None;

        // HEAD must be -I (with -X HEAD curl waits for a body that never comes). A body makes curl POST by itself, and an
        // explicit -X POST would keep POST across a 301/302/303 that a browser turns into GET — so it's left out.
        string? methodArg = r.Method switch
        {
            "HEAD" => "-I",
            "GET" => hasBody ? "-X " + q("GET") : null,
            "POST" => hasBody ? null : "-X " + q("POST"),
            _ => "-X " + q(r.Method),
        };
        var lines = new List<string> { "curl " + q(url) + (methodArg is null ? "" : " " + methodArg) };

        // headers exactly as typed; Cookie headers and the Cookies tab become one -b; the Auth tab is -u / --oauth2-bearer
        var userHeaders = r.Headers.Where(h => h.Enabled && h.Name.Trim().Length > 0)
                                   .Select(h => (Name: h.Name.Trim(), Value: h.Value.Trim())).ToList();
        string cookie = string.Join("; ", userHeaders.Where(h => h.Name.Equals("Cookie", StringComparison.OrdinalIgnoreCase))
                                                    .Select(h => h.Value.TrimEnd(';', ' ')).Append(r.CookieHeaderValue())
                                                    .Where(v => v.Length > 0));
        foreach (var (n, v) in userHeaders)
        {
            if (n.Equals("Cookie", StringComparison.OrdinalIgnoreCase)) continue;
            lines.Add("-H " + q(v.Length == 0 ? n + ";" : $"{n}: {v}"));   // "Name:" would REMOVE the header in curl
        }

        // curl's own Content-Type for -d is form-urlencoded: a raw / file body says what it is
        bool userCt = userHeaders.Any(h => h.Name.Equals("Content-Type", StringComparison.OrdinalIgnoreCase));
        if (!userCt && mode is CurlBodyMode.Raw or CurlBodyMode.File && r.AutoContentType() is { } ct)
            lines.Add("-H " + q("Content-Type: " + ct));
        if (cookie.Length > 0) lines.Add("-b " + q(cookie));

        bool userAuth = userHeaders.Any(h => h.Name.Equals("Authorization", StringComparison.OrdinalIgnoreCase));
        if (!userAuth && r.AuthorizationValue() != null)
        {
            if (r.Auth == CurlAuthMode.Basic) lines.Add("-u " + q($"{r.AuthUser}:{r.AuthPass}"));
            else if (r.Auth == CurlAuthMode.Bearer) lines.Add("--oauth2-bearer " + q(r.AuthToken.Trim()));
        }

        switch (mode)
        {
            case CurlBodyMode.Raw:
                // --data-raw, not --data: --data reads a body that starts with '@' as a file to upload
                lines.Add("--data-raw " + q(r.RawBody));
                break;
            case CurlBodyMode.Form:
                foreach (var f in r.Form.Where(f => f.Enabled && f.Name.Length > 0))
                {
                    // --data-urlencode "name=value" encodes the value only: a name that needs encoding goes pre-encoded
                    if (f.Name.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or '~' or '[' or ']'))
                        lines.Add("--data-urlencode " + q($"{f.Name}={f.Value}"));
                    else
                        lines.Add("--data-raw " + q($"{CurlRequest.FormEncode(f.Name)}={CurlRequest.FormEncode(f.Value)}"));
                }
                break;
            case CurlBodyMode.Multipart:
                foreach (var p in r.Parts.Where(p => p.Enabled && p.Name.Length > 0))
                    lines.Add(FormArg(p, q));
                break;
            case CurlBodyMode.File:
                lines.Add("--data-binary " + q("@" + r.BodyFile.Trim()));
                break;
        }

        if (r.Compressed) lines.Add("--compressed");
        switch (r.HttpVersion)
        {
            case CurlHttpVersion.Http1: lines.Add("--http1.1"); break;
            case CurlHttpVersion.Http2: lines.Add("--http2"); break;
            case CurlHttpVersion.Http3: lines.Add("--http3"); break;
        }
        if (HasProxy(r))
        {
            lines.Add("-x " + q(HttpHelper.CurlProxyArg(r.Proxy!)));   // same proxy rules as the app's engines
            if (HasProxyCreds(r)) lines.Add("-U " + q($"{r.ProxyUser}:{r.ProxyPass}"));
        }
        var (host, port) = HostPort(url);
        if (CurlFlagParser.TryParseOverride(r.OverrideIp, port, out var ovIp, out var ovPort))
        {
            // Same rule the app uses: --resolve for the URL's own port, --connect-to when the override
            // carries a different port (a "ip:port" inside --resolve is not valid curl syntax).
            string h1 = host.Contains(':') && !host.StartsWith('[') ? $"[{host}]" : host;
            if (ovPort == port) lines.Add("--resolve " + q($"{h1}:{port}:{ovIp}"));
            else lines.Add("--connect-to " + q($"{h1}:{port}:{(ovIp.Contains(':') ? $"[{ovIp}]" : ovIp)}:{ovPort}"));
        }
        if (!string.IsNullOrWhiteSpace(r.InterfaceIp)) lines.Add("--interface " + q(r.InterfaceIp));
        if (r.Insecure) lines.Add("-k");
        if (r.FollowRedirects)
        {
            lines.Add("-L");
            if (r.MaxRedirects != CurlRequest.DefaultMaxRedirects) lines.Add($"--max-redirs {r.MaxRedirects}");
        }
        if (r.TimeoutSec > 0) lines.Add($"--max-time {r.TimeoutSec}");
        if (r.ConnectTimeoutSec > 0) lines.Add($"--connect-timeout {r.ConnectTimeoutSec}");

        return string.Join(windows ? " ^\n  " : " \\\n  ", lines);
    }

    // -F name=value / --form-string (a value starting with @ or <, or holding a ';', would be read by -F) / -F name=@file.
    private static string FormArg(CurlPart p, Func<string?, string> q)
    {
        // A part's Content-Type is spliced into curl's -F ";type=" spec; keep only a bare media type so a crafted value
        // ("text/plain;headers=@/etc/passwd") can't smuggle another -F directive that makes curl read a local file when
        // the copied snippet is run. (Shell quoting doesn't help: curl's own -F parser is what splits on ';'.)
        string type = CurlRequest.SafeMimeType(p.ContentType);
        if (!p.IsFile)
        {
            bool plain = p.Value.Length == 0 || (p.Value[0] is not ('@' or '<') && !p.Value.Contains(';') && !p.Value.Contains('"'));
            if (plain && type.Length == 0) return "-F " + q($"{p.Name}={p.Value}");
            if (type.Length == 0) return "--form-string " + q($"{p.Name}={p.Value}");
            return "-F " + q($"{p.Name}={FormWord(p.Value)};type={type}");
        }
        var sb = new StringBuilder();
        sb.Append(p.Name).Append("=@").Append(FormWord(p.Value.Trim()));
        if (type.Length > 0) sb.Append(";type=").Append(type);
        if (!string.IsNullOrEmpty(p.FileName)) sb.Append(";filename=").Append(FormWord(p.FileName));
        return "-F " + q(sb.ToString());
    }

    // A -F word: quoted (with \" and \\) when it holds ; , " or edge spaces — curl's own rule.
    private static string FormWord(string s)
    {
        if (s.IndexOfAny(new[] { ';', ',', '"' }) < 0 && s.Trim() == s) return s;
        return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
    }

    // ---- PowerShell (Invoke-RestMethod) ----

    private static string PowerShell(CurlRequest r)
    {
        var sb = new StringBuilder();
        var mode = r.EffectiveBodyMode;
        var headers = SnippetHeaders(r);
        // Invoke-RestMethod takes the Content-Type through -ContentType (a header of that name is refused with -Form)
        var ct = headers.FirstOrDefault(h => h.Name.Equals("Content-Type", StringComparison.OrdinalIgnoreCase));
        headers.RemoveAll(h => h.Name.Equals("Content-Type", StringComparison.OrdinalIgnoreCase));
        if (headers.Count > 0)
        {
            sb.AppendLine("$headers = @{");
            foreach (var (n, v) in headers) sb.AppendLine($"    {Psq(n)} = {Psq(v)}");
            sb.AppendLine("}");
        }
        if (mode == CurlBodyMode.Form)
        {
            sb.AppendLine("$body = @{");
            foreach (var (n, v) in Merged(r.Form.Where(f => f.Enabled && f.Name.Length > 0).Select(f => (f.Name, f.Value))))
                sb.AppendLine($"    {Psq(n)} = {Psq(v)}");
            sb.AppendLine("}");
        }
        if (mode == CurlBodyMode.Multipart)
        {
            sb.AppendLine("$form = @{   # PowerShell 7+");
            foreach (var p in r.Parts.Where(p => p.Enabled && p.Name.Length > 0))
                sb.AppendLine(p.IsFile ? $"    {Psq(p.Name)} = Get-Item {Psq(p.Value)}" : $"    {Psq(p.Name)} = {Psq(p.Value)}");
            sb.AppendLine("}");
        }

        var args = new List<string> { $"-Uri {Psq(CurlRequest.NormalizeUrl(r.Url))}", $"-Method {r.Method}" };
        if (headers.Count > 0) args.Add("-Headers $headers");
        switch (mode)
        {
            case CurlBodyMode.Raw: args.Add($"-Body {Psq(r.RawBody)}"); break;
            case CurlBodyMode.Form: args.Add("-Body $body"); break;
            case CurlBodyMode.Multipart: args.Add("-Form $form"); break;
            case CurlBodyMode.File: args.Add($"-InFile {Psq(r.BodyFile.Trim())}"); break;
        }
        if (ct.Name != null && mode != CurlBodyMode.Multipart) args.Add($"-ContentType {Psq(ct.Value)}");
        if (HasProxy(r))
        {
            args.Add($"-Proxy {Psq(ProxyUrl(r.Proxy!))}");
            if (!string.IsNullOrWhiteSpace(r.ProxyUser)) args.Add("-ProxyCredential (Get-Credential)");
        }
        if (r.HttpVersion == CurlHttpVersion.Http1) args.Add("-HttpVersion 1.1");
        if (r.HttpVersion == CurlHttpVersion.Http2) args.Add("-HttpVersion 2.0");
        if (r.HttpVersion == CurlHttpVersion.Http3) args.Add("-HttpVersion 3.0");
        if (r.Insecure) args.Add("-SkipCertificateCheck");     // PowerShell 6+
        if (!r.FollowRedirects) args.Add("-MaximumRedirection 0");
        else if (r.MaxRedirects != CurlRequest.DefaultMaxRedirects) args.Add($"-MaximumRedirection {r.MaxRedirects}");
        if (r.TimeoutSec > 0) args.Add($"-TimeoutSec {r.TimeoutSec}");

        sb.Append("Invoke-RestMethod " + string.Join(" `\n    ", args));
        if (!string.IsNullOrWhiteSpace(r.OverrideIp))
            sb.Append($"\n\n# Override IP {r.OverrideIp}: add a hosts-file entry, e.g.\n#   {r.OverrideIp}  {HostPort(r.Url).host}");
        if (!string.IsNullOrWhiteSpace(r.InterfaceIp))
            sb.Append($"\n# Source interface {r.InterfaceIp}: Invoke-* can't bind a source IP (use curl --interface).");
        return sb.ToString();
    }

    // ---- Python (requests) ----

    private static string Python(CurlRequest r)
    {
        var sb = new StringBuilder();
        var mode = r.EffectiveBodyMode;
        sb.AppendLine("import requests");
        sb.AppendLine();
        var headers = SnippetHeaders(r);
        if (headers.Count > 0)
        {
            sb.AppendLine("headers = {");
            foreach (var (n, v) in headers) sb.AppendLine($"    {Dq(n)}: {Dq(v)},");
            sb.AppendLine("}");
        }
        if (mode == CurlBodyMode.Form)
        {
            sb.AppendLine("data = [");
            foreach (var f in r.Form.Where(f => f.Enabled && f.Name.Length > 0)) sb.AppendLine($"    ({Dq(f.Name)}, {Dq(f.Value)}),");
            sb.AppendLine("]");
        }
        if (mode == CurlBodyMode.Multipart)
        {
            sb.AppendLine("files = [");
            foreach (var p in r.Parts.Where(p => p.Enabled && p.Name.Length > 0))
            {
                if (p.IsFile)
                {
                    string fname = !string.IsNullOrEmpty(p.FileName) ? p.FileName : System.IO.Path.GetFileName(p.Value.Trim());
                    string type = !string.IsNullOrEmpty(p.ContentType) ? p.ContentType : CurlRequest.GuessMime(p.Value, "application/octet-stream");
                    sb.AppendLine($"    ({Dq(p.Name)}, ({Dq(fname)}, open({Dq(p.Value.Trim())}, \"rb\"), {Dq(type)})),");
                }
                else sb.AppendLine($"    ({Dq(p.Name)}, (None, {Dq(p.Value)})),");
            }
            sb.AppendLine("]");
        }
        if (HasProxy(r))
        {
            string p = ProxyUrl(r.Proxy!.Trim());
            if (HasProxyCreds(r))
            {
                // Percent-encode: a raw '#', '/' or '@' in the password would be parsed as URL structure
                int i = p.IndexOf("://", StringComparison.Ordinal) + 3;
                p = p[..i] + Uri.EscapeDataString(r.ProxyUser ?? string.Empty) + ":" + Uri.EscapeDataString(r.ProxyPass ?? string.Empty) + "@" + p[i..];
            }
            sb.AppendLine($"proxies = {{\"http\": {Dq(p)}, \"https\": {Dq(p)}}}");
        }
        sb.AppendLine();
        sb.AppendLine("resp = requests.request(");
        sb.AppendLine($"    {Dq(r.Method)}, {Dq(CurlRequest.NormalizeUrl(r.Url))},");
        if (headers.Count > 0) sb.AppendLine("    headers=headers,");
        switch (mode)
        {
            case CurlBodyMode.Raw: sb.AppendLine($"    data={Dq(r.RawBody)}.encode(\"utf-8\"),"); break;
            case CurlBodyMode.Form: sb.AppendLine("    data=data,"); break;
            case CurlBodyMode.Multipart: sb.AppendLine("    files=files,"); break;
            case CurlBodyMode.File: sb.AppendLine($"    data=open({Dq(r.BodyFile.Trim())}, \"rb\"),"); break;
        }
        if (HasProxy(r)) sb.AppendLine("    proxies=proxies,");
        if (r.Insecure) sb.AppendLine("    verify=False,");
        sb.AppendLine($"    allow_redirects={(r.FollowRedirects ? "True" : "False")},");
        if (r.TimeoutSec > 0) sb.AppendLine($"    timeout={r.TimeoutSec},");
        sb.AppendLine(")");
        sb.AppendLine("print(resp.status_code)");
        sb.Append("print(resp.text)");
        if (r.HttpVersion is CurlHttpVersion.Http2 or CurlHttpVersion.Http3)
            sb.Append("\n# requests speaks HTTP/1.1 only — for HTTP/2 use httpx.Client(http2=True).");
        if (!string.IsNullOrWhiteSpace(r.OverrideIp))
            sb.Append($"\n# Override IP {r.OverrideIp}: pin DNS via a custom adapter or /etc/hosts ({HostPort(r.Url).host}).");
        if (!string.IsNullOrWhiteSpace(r.InterfaceIp))
            sb.Append($"\n# Source IP {r.InterfaceIp}: use an HTTPAdapter with source_address=({Dq(r.InterfaceIp)}, 0).");
        return sb.ToString();
    }

    // ---- JavaScript (fetch) ----

    private static string JavaScript(CurlRequest r)
    {
        var sb = new StringBuilder();
        var mode = r.EffectiveBodyMode;
        var headers = SnippetHeaders(r);
        if (mode is CurlBodyMode.Multipart or CurlBodyMode.File) sb.AppendLine("import fs from \"node:fs\";   // Node 20+ (openAsBlob)\n");
        if (mode == CurlBodyMode.Form)
        {
            sb.AppendLine("const body = new URLSearchParams();");
            foreach (var f in r.Form.Where(f => f.Enabled && f.Name.Length > 0)) sb.AppendLine($"body.append({Dq(f.Name)}, {Dq(f.Value)});");
            sb.AppendLine();
        }
        if (mode == CurlBodyMode.Multipart)
        {
            sb.AppendLine("const body = new FormData();");
            foreach (var p in r.Parts.Where(p => p.Enabled && p.Name.Length > 0))
            {
                if (p.IsFile)
                {
                    string fname = !string.IsNullOrEmpty(p.FileName) ? p.FileName : System.IO.Path.GetFileName(p.Value.Trim());
                    sb.AppendLine($"body.append({Dq(p.Name)}, await fs.openAsBlob({Dq(p.Value.Trim())}), {Dq(fname)});");
                }
                else sb.AppendLine($"body.append({Dq(p.Name)}, {Dq(p.Value)});");
            }
            sb.AppendLine();
        }
        sb.AppendLine("const resp = await fetch(" + Dq(CurlRequest.NormalizeUrl(r.Url)) + ", {");
        sb.AppendLine($"  method: {Dq(r.Method)},");
        if (headers.Count > 0)
        {
            sb.AppendLine("  headers: {");
            foreach (var (n, v) in headers) sb.AppendLine($"    {Dq(n)}: {Dq(v)},");
            sb.AppendLine("  },");
        }
        switch (mode)
        {
            case CurlBodyMode.Raw: sb.AppendLine($"  body: {Dq(r.RawBody)},"); break;
            case CurlBodyMode.Form: case CurlBodyMode.Multipart: sb.AppendLine("  body,"); break;
            case CurlBodyMode.File: sb.AppendLine($"  body: await fs.openAsBlob({Dq(r.BodyFile.Trim())}),"); break;
        }
        sb.AppendLine($"  redirect: {Dq(r.FollowRedirects ? "follow" : "manual")},");
        if (r.TimeoutSec > 0) sb.AppendLine($"  signal: AbortSignal.timeout({r.TimeoutSec * 1000}),");
        sb.AppendLine("});");
        sb.AppendLine("console.log(resp.status);");
        sb.Append("console.log(await resp.text());");
        var notes = new List<string>();
        if (HasProxy(r)) notes.Add($"proxy {r.Proxy} — set an Agent (Node undici ProxyAgent); not settable from browser fetch");
        if (r.Insecure) notes.Add("insecure TLS — Node only: set an Agent with rejectUnauthorized:false");
        if (!string.IsNullOrWhiteSpace(r.OverrideIp)) notes.Add($"override IP {r.OverrideIp} — Node only: custom lookup/Agent");
        if (!string.IsNullOrWhiteSpace(r.InterfaceIp)) notes.Add($"source interface {r.InterfaceIp} — Node only: Agent localAddress");
        if (notes.Count > 0) sb.Append("\n\n// " + string.Join("\n// ", notes));
        return sb.ToString();
    }

    // ---- HTTPie ----

    private static string Httpie(CurlRequest r)
    {
        var mode = r.EffectiveBodyMode;
        var parts = new List<string> { "http" };
        if (mode == CurlBodyMode.Form) parts.Add("--form");
        if (mode == CurlBodyMode.Multipart) parts.Add("--multipart");
        if (r.Insecure) parts.Add("--verify=no");
        if (r.FollowRedirects)
        {
            parts.Add("--follow");
            if (r.MaxRedirects != CurlRequest.DefaultMaxRedirects) parts.Add($"--max-redirects={r.MaxRedirects}");
        }
        if (r.TimeoutSec > 0) parts.Add($"--timeout={r.TimeoutSec}");
        if (HasProxy(r))
        {
            string p = ProxyUrl(r.Proxy!.Trim());
            parts.Add($"--proxy=http:{Sq(p)}");
            parts.Add($"--proxy=https:{Sq(p)}");
        }
        if (mode == CurlBodyMode.Raw) parts.Add("--raw " + Sq(r.RawBody));
        parts.Add(r.Method);
        parts.Add(Sq(CurlRequest.NormalizeUrl(r.Url)));
        foreach (var (n, v) in SnippetHeaders(r))
        {
            // the form modes set their own Content-Type
            if (mode is CurlBodyMode.Form or CurlBodyMode.Multipart && n.Equals("Content-Type", StringComparison.OrdinalIgnoreCase)) continue;
            parts.Add(Sq($"{n}:{v}"));
        }
        if (mode == CurlBodyMode.Form)
            foreach (var f in r.Form.Where(f => f.Enabled && f.Name.Length > 0)) parts.Add(Sq($"{f.Name}={f.Value}"));
        if (mode == CurlBodyMode.Multipart)
            foreach (var p in r.Parts.Where(p => p.Enabled && p.Name.Length > 0))
                parts.Add(Sq(p.IsFile ? $"{p.Name}@{p.Value.Trim()}" + (string.IsNullOrEmpty(p.ContentType) ? "" : ";type=" + p.ContentType) : $"{p.Name}={p.Value}"));
        string cmd = string.Join(" ", parts);
        if (mode == CurlBodyMode.File) cmd += " < " + Sq(r.BodyFile.Trim());
        if (r.HttpVersion is CurlHttpVersion.Http2 or CurlHttpVersion.Http3)
            cmd += "\n# HTTPie speaks HTTP/1.1 (HTTP/2 needs the httpie-http2 plugin).";
        if (!string.IsNullOrWhiteSpace(r.OverrideIp))
            cmd += $"\n# Override IP {r.OverrideIp}: pin via /etc/hosts ({HostPort(r.Url).host}).";
        if (!string.IsNullOrWhiteSpace(r.InterfaceIp))
            cmd += $"\n# Source IP {r.InterfaceIp}: httpie has no bind-address option (use curl --interface).";
        return cmd;
    }

    // ---- wget ----

    private static string Wget(CurlRequest r)
    {
        var mode = r.EffectiveBodyMode;
        var lines = new List<string> { $"wget -qSO- --method={r.Method} {Sq(CurlRequest.NormalizeUrl(r.Url))}" };
        foreach (var (n, v) in SnippetHeaders(r)) lines.Add($"  --header={Sq($"{n}: {v}")}");
        switch (mode)
        {
            case CurlBodyMode.Raw: lines.Add($"  --body-data={Sq(r.RawBody)}"); break;
            case CurlBodyMode.Form: lines.Add($"  --body-data={Sq(r.FormBody())}"); break;
            case CurlBodyMode.File: lines.Add($"  --body-file={Sq(r.BodyFile.Trim())}"); break;
        }
        if (r.Compressed) lines.Add("  --compression=auto");
        if (HasProxy(r))
        {
            string p = ProxyUrl(r.Proxy!.Trim());
            lines.Add($"  -e use_proxy=yes -e http_proxy={Sq(p)} -e https_proxy={Sq(p)}");
            if (!string.IsNullOrWhiteSpace(r.ProxyUser))
                lines.Add($"  --proxy-user={Sq(r.ProxyUser)} --proxy-password={Sq(r.ProxyPass)}");
        }
        if (!string.IsNullOrWhiteSpace(r.InterfaceIp)) lines.Add($"  --bind-address={Sq(r.InterfaceIp)}");
        if (r.Insecure) lines.Add("  --no-check-certificate");
        if (!r.FollowRedirects) lines.Add("  --max-redirect=0");
        else if (r.MaxRedirects != CurlRequest.DefaultMaxRedirects) lines.Add($"  --max-redirect={r.MaxRedirects}");
        if (r.TimeoutSec > 0) lines.Add($"  --timeout={r.TimeoutSec}");
        string cmd = string.Join(" \\\n", lines);
        if (mode == CurlBodyMode.Multipart) cmd += "\n# wget can't send multipart/form-data — use the curl snippet.";
        if (r.HttpVersion is CurlHttpVersion.Http2 or CurlHttpVersion.Http3) cmd += "\n# wget speaks HTTP/1.1 (wget2 adds HTTP/2).";
        return cmd;
    }
}
