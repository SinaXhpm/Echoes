using System;
using System.Text.RegularExpressions;

namespace Echoes.Helpers;

/// <summary>
/// Credentials that ride inside a URL besides user:pass@ (which <see cref="ProfileService"/> strips itself): query values
/// named like secrets (?token=…, &amp;api_key=…, &amp;sig=…) and a Telegram bot token in the path (/bot123456:AA…).
/// The plain-text stores (the history, cURL's recent list) keep a URL without them; the value is emptied, the name stays,
/// so the entry still shows what was called.
/// </summary>
public static class UrlSecrets
{
    private static readonly Regex SecretParam = new(
        @"(?i)([?&])([^=&?#\s]*(token|key|secret|auth|pass|pwd|sig|session|jwt|code)[^=&#\s]*)=[^&#\s]*",
        RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(200));

    private static readonly Regex BotToken = new(
        @"(?i)(/bot)[0-9]{3,20}:[A-Za-z0-9_-]{20,128}", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(200));

    /// <summary>The text with secret-looking query values emptied and a bot token replaced by •••. Never throws.</summary>
    public static string Redact(string? value)
    {
        string v = value ?? string.Empty;
        if (v.IndexOf('?') < 0 && v.IndexOf('&') < 0 && v.IndexOf("/bot", StringComparison.OrdinalIgnoreCase) < 0) return v;
        try
        {
            v = SecretParam.Replace(v, "$1$2=");
            return BotToken.Replace(v, "$1•••");
        }
        catch (RegexMatchTimeoutException) { return string.Empty; }   // pathological input: keep nothing rather than the secret
    }

    /// <summary>True when <see cref="Redact"/> would change the text.</summary>
    public static bool HasSecrets(string? value) => !string.Equals(Redact(value), value ?? string.Empty, StringComparison.Ordinal);
}
