using System;
using System.Linq;
using System.Net;

namespace Echoes.Helpers;

/// <summary>
/// Pull a bare host (domain or IP) out of whatever the user pasted — a full URL, "host:port",
/// "user@host", "ping host", a path, surrounding quotes/brackets, and so on. Idempotent: a value
/// that's already a clean host or IP comes back unchanged.
/// </summary>
public static class HostExtractor
{
    public static string Extract(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return raw?.Trim() ?? string.Empty;

        string s = raw.Trim().Trim('"', '\'', '`', '<', '>');

        // Already a bare IP (v4 or v6)? Keep it.
        if (IPAddress.TryParse(s, out _)) return s;

        // A blob with spaces (e.g. "ping example.com" or a pasted log line) → pick the most
        // host-like token: prefer one with a scheme, else one containing a dot or colon.
        if (s.IndexOfAny(new[] { ' ', '\t', '\r', '\n' }) >= 0)
        {
            var tokens = s.Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            s = tokens.FirstOrDefault(t => t.Contains("://"))
                ?? tokens.FirstOrDefault(t => t.Contains('.') || t.Contains(':'))
                ?? tokens[0];
            s = s.Trim('"', '\'', '`', '<', '>', ',', ';', '(', ')');
        }

        if (IPAddress.TryParse(s, out _)) return s;

        // Bracketed IPv6, e.g. [::1] or [::1]:8080
        if (s.StartsWith('['))
        {
            int end = s.IndexOf(']');
            if (end > 1 && IPAddress.TryParse(s.Substring(1, end - 1), out _))
                return s.Substring(1, end - 1);
        }

        // Let Uri strip scheme / userinfo / port / path / query / fragment.
        string withScheme = s.Contains("://") ? s : "http://" + s;
        if (Uri.TryCreate(withScheme, UriKind.Absolute, out var u) && !string.IsNullOrEmpty(u.DnsSafeHost))
            return u.DnsSafeHost;

        // Manual fallback: strip userinfo@, then path/query, then a single :port (not IPv6).
        string h = s;
        int at = h.LastIndexOf('@'); if (at >= 0) h = h[(at + 1)..];
        int slash = h.IndexOf('/'); if (slash >= 0) h = h[..slash];
        int q = h.IndexOf('?'); if (q >= 0) h = h[..q];
        if (h.Count(c => c == ':') == 1) h = h[..h.IndexOf(':')];
        return h.Trim();
    }
}
