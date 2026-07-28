using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Echoes.Helpers;

/// <summary>
/// Renders the cURL tab's current request as a ready-to-run snippet in several tools/languages.
/// Pure string building (AOT/trim safe) so the CODE tab stays in sync with whatever the user would
/// actually send — same method, URL, headers, body, proxy, override IP, insecure/redirect/timeout flags.
/// </summary>
public static class RequestSnippets
{
    public sealed record Spec(
        string Method,
        string Url,
        IReadOnlyList<(string Name, string Value)> Headers,
        string? Body,
        string? Proxy,
        string? ProxyUser,
        string? ProxyPass,
        bool Insecure,
        bool FollowRedirects,
        int TimeoutSec,
        string? OverrideIp,
        string? Interface);

    public static readonly string[] Languages =
        { "curl", "PowerShell", "Python", "JavaScript", "HTTPie", "wget" };

    public static string Build(string language, Spec s) => language switch
    {
        "curl"       => Curl(s),
        "PowerShell" => PowerShell(s),
        "Python"     => Python(s),
        "JavaScript" => JavaScript(s),
        "HTTPie"     => Httpie(s),
        "wget"       => Wget(s),
        _            => Curl(s),
    };

    // ---- escaping helpers ----

    // POSIX single-quote: wrap in '...', and close/escape/reopen around any embedded quote.
    private static string Sq(string? v) => "'" + (v ?? string.Empty).Replace("'", "'\\''") + "'";

    // PowerShell single-quote literal: only the single quote needs doubling.
    private static string Psq(string? v) => "'" + (v ?? string.Empty).Replace("'", "''") + "'";

    // JSON-ish double-quoted string for JS / Python.
    private static string Dq(string? v)
    {
        var sb = new StringBuilder("\"");
        foreach (char c in v ?? string.Empty)
            sb.Append(c switch
            {
                '\\' => "\\\\",
                '"'  => "\\\"",
                '\n' => "\\n",
                '\r' => "\\r",
                '\t' => "\\t",
                _    => c.ToString()
            });
        sb.Append('"');
        return sb.ToString();
    }

    private static bool HasBody(Spec s) => !string.IsNullOrEmpty(s.Body);

    // host:port for the URL (used by curl --resolve and as a note elsewhere)
    private static (string host, int port) HostPort(string url)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var u))
            return (u.Host, u.Port > 0 ? u.Port : (u.Scheme == "https" ? 443 : 80));
        return (url, 443);
    }

    // ---- generators ----

    private static string Curl(Spec s)
    {
        var lines = new List<string> { $"curl -X {s.Method} {Sq(s.Url)}" };
        foreach (var (n, v) in s.Headers) lines.Add($"  -H {Sq($"{n}: {v}")}");
        if (HasBody(s)) lines.Add($"  --data {Sq(s.Body)}");
        if (!string.IsNullOrWhiteSpace(s.Proxy))
        {
            lines.Add($"  -x {Sq(s.Proxy)}");
            if (!string.IsNullOrWhiteSpace(s.ProxyUser) || !string.IsNullOrWhiteSpace(s.ProxyPass))
                lines.Add($"  -U {Sq($"{s.ProxyUser}:{s.ProxyPass}")}");
        }
        if (!string.IsNullOrWhiteSpace(s.OverrideIp))
        {
            var (host, port) = HostPort(s.Url);
            lines.Add($"  --resolve {Sq($"{host}:{port}:{s.OverrideIp.Trim().Trim('[', ']')}")}");
        }
        if (!string.IsNullOrWhiteSpace(s.Interface)) lines.Add($"  --interface {Sq(s.Interface)}");
        if (s.Insecure) lines.Add("  -k");
        if (s.FollowRedirects) lines.Add("  -L");
        if (s.TimeoutSec > 0) lines.Add($"  --max-time {s.TimeoutSec}");
        return string.Join(" \\\n", lines);
    }

    private static string PowerShell(Spec s)
    {
        var sb = new StringBuilder();
        string hdrVar = "$headers";
        if (s.Headers.Count > 0)
        {
            sb.AppendLine($"{hdrVar} = @{{");
            foreach (var (n, v) in s.Headers) sb.AppendLine($"    {Psq(n)} = {Psq(v)}");
            sb.AppendLine("}");
        }

        var args = new List<string> { $"-Uri {Psq(s.Url)}", $"-Method {s.Method}" };
        if (s.Headers.Count > 0) args.Add($"-Headers {hdrVar}");
        if (HasBody(s)) args.Add($"-Body {Psq(s.Body)}");
        if (!string.IsNullOrWhiteSpace(s.Proxy))
        {
            // Invoke-* wants a URI; add a scheme if the user typed a bare host:port.
            string p = s.Proxy!.Contains("://") ? s.Proxy! : "http://" + s.Proxy;
            args.Add($"-Proxy {Psq(p)}");
            if (!string.IsNullOrWhiteSpace(s.ProxyUser))
                args.Add("-ProxyCredential (Get-Credential)");
        }
        if (s.Insecure) args.Add("-SkipCertificateCheck");     // PowerShell 6+
        if (!s.FollowRedirects) args.Add("-MaximumRedirection 0");
        if (s.TimeoutSec > 0) args.Add($"-TimeoutSec {s.TimeoutSec}");

        sb.Append("Invoke-RestMethod " + string.Join(" `\n    ", args));
        if (!string.IsNullOrWhiteSpace(s.OverrideIp))
            sb.Append($"\n\n# Override IP {s.OverrideIp}: add a hosts-file entry, e.g.\n#   {s.OverrideIp}  {HostPort(s.Url).host}");
        if (!string.IsNullOrWhiteSpace(s.Interface))
            sb.Append($"\n# Source interface {s.Interface}: Invoke-* can't bind a source IP (use curl --interface).");
        return sb.ToString();
    }

    private static string Python(Spec s)
    {
        var sb = new StringBuilder();
        sb.AppendLine("import requests");
        sb.AppendLine();
        if (s.Headers.Count > 0)
        {
            sb.AppendLine("headers = {");
            foreach (var (n, v) in s.Headers) sb.AppendLine($"    {Dq(n)}: {Dq(v)},");
            sb.AppendLine("}");
        }
        if (!string.IsNullOrWhiteSpace(s.Proxy))
        {
            string p = s.Proxy!.Contains("://") ? s.Proxy! : "http://" + s.Proxy;
            if (!string.IsNullOrWhiteSpace(s.ProxyUser))
            {
                int i = p.IndexOf("://", StringComparison.Ordinal) + 3;
                p = p[..i] + $"{s.ProxyUser}:{s.ProxyPass}@" + p[i..];
            }
            sb.AppendLine($"proxies = {{\"http\": {Dq(p)}, \"https\": {Dq(p)}}}");
        }
        sb.AppendLine();
        sb.AppendLine("resp = requests.request(");
        sb.AppendLine($"    {Dq(s.Method)}, {Dq(s.Url)},");
        if (s.Headers.Count > 0) sb.AppendLine("    headers=headers,");
        if (HasBody(s)) sb.AppendLine($"    data={Dq(s.Body)},");
        if (!string.IsNullOrWhiteSpace(s.Proxy)) sb.AppendLine("    proxies=proxies,");
        if (s.Insecure) sb.AppendLine("    verify=False,");
        sb.AppendLine($"    allow_redirects={(s.FollowRedirects ? "True" : "False")},");
        if (s.TimeoutSec > 0) sb.AppendLine($"    timeout={s.TimeoutSec},");
        sb.AppendLine(")");
        sb.AppendLine("print(resp.status_code)");
        sb.Append("print(resp.text)");
        if (!string.IsNullOrWhiteSpace(s.OverrideIp))
            sb.Append($"\n# Override IP {s.OverrideIp}: pin DNS via a custom adapter or /etc/hosts ({HostPort(s.Url).host}).");
        if (!string.IsNullOrWhiteSpace(s.Interface))
            sb.Append($"\n# Source IP {s.Interface}: use an HTTPAdapter with source_address=({Dq(s.Interface)}, 0).");
        return sb.ToString();
    }

    private static string JavaScript(Spec s)
    {
        var sb = new StringBuilder();
        sb.AppendLine("const resp = await fetch(" + Dq(s.Url) + ", {");
        sb.AppendLine($"  method: {Dq(s.Method)},");
        if (s.Headers.Count > 0)
        {
            sb.AppendLine("  headers: {");
            foreach (var (n, v) in s.Headers) sb.AppendLine($"    {Dq(n)}: {Dq(v)},");
            sb.AppendLine("  },");
        }
        if (HasBody(s)) sb.AppendLine($"  body: {Dq(s.Body)},");
        sb.AppendLine($"  redirect: {Dq(s.FollowRedirects ? "follow" : "manual")},");
        sb.AppendLine("});");
        sb.AppendLine("console.log(resp.status);");
        sb.Append("console.log(await resp.text());");
        var notes = new List<string>();
        if (!string.IsNullOrWhiteSpace(s.Proxy)) notes.Add($"proxy {s.Proxy} — set an Agent (Node undici ProxyAgent); not settable from browser fetch");
        if (s.Insecure) notes.Add("insecure TLS — Node only: set an Agent with rejectUnauthorized:false");
        if (!string.IsNullOrWhiteSpace(s.OverrideIp)) notes.Add($"override IP {s.OverrideIp} — Node only: custom lookup/Agent");
        if (!string.IsNullOrWhiteSpace(s.Interface)) notes.Add($"source interface {s.Interface} — Node only: Agent localAddress");
        if (notes.Count > 0) sb.Append("\n\n// " + string.Join("\n// ", notes));
        return sb.ToString();
    }

    private static string Httpie(Spec s)
    {
        var parts = new List<string> { "http" };
        if (s.Insecure) parts.Add("--verify=no");
        if (s.FollowRedirects) parts.Add("--follow");
        if (s.TimeoutSec > 0) parts.Add($"--timeout={s.TimeoutSec}");
        if (!string.IsNullOrWhiteSpace(s.Proxy))
        {
            string p = s.Proxy!.Contains("://") ? s.Proxy! : "http://" + s.Proxy;
            parts.Add($"--proxy=http:{Sq(p)}");
            parts.Add($"--proxy=https:{Sq(p)}");
        }
        parts.Add(s.Method);
        parts.Add(Sq(s.Url));
        foreach (var (n, v) in s.Headers) parts.Add(Sq($"{n}:{v}"));
        string cmd = string.Join(" ", parts);
        if (HasBody(s)) cmd = $"echo {Sq(s.Body)} | " + cmd + " --raw=@-";
        if (!string.IsNullOrWhiteSpace(s.OverrideIp))
            cmd += $"\n# Override IP {s.OverrideIp}: pin via /etc/hosts ({HostPort(s.Url).host}).";
        if (!string.IsNullOrWhiteSpace(s.Interface))
            cmd += $"\n# Source IP {s.Interface}: httpie has no bind-address option (use curl --interface).";
        return cmd;
    }

    private static string Wget(Spec s)
    {
        var lines = new List<string> { $"wget -qSO- --method={s.Method} {Sq(s.Url)}" };
        foreach (var (n, v) in s.Headers) lines.Add($"  --header={Sq($"{n}: {v}")}");
        if (HasBody(s)) lines.Add($"  --body-data={Sq(s.Body)}");
        if (!string.IsNullOrWhiteSpace(s.Proxy))
        {
            string p = s.Proxy!.Contains("://") ? s.Proxy! : "http://" + s.Proxy;
            lines.Add($"  -e use_proxy=yes -e http_proxy={Sq(p)} -e https_proxy={Sq(p)}");
            if (!string.IsNullOrWhiteSpace(s.ProxyUser))
                lines.Add($"  --proxy-user={Sq(s.ProxyUser)} --proxy-password={Sq(s.ProxyPass)}");
        }
        if (!string.IsNullOrWhiteSpace(s.Interface)) lines.Add($"  --bind-address={Sq(s.Interface)}");
        if (s.Insecure) lines.Add("  --no-check-certificate");
        if (!s.FollowRedirects) lines.Add("  --max-redirect=0");
        if (s.TimeoutSec > 0) lines.Add($"  --timeout={s.TimeoutSec}");
        return string.Join(" \\\n", lines);
    }
}
