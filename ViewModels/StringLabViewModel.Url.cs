using System;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _urlInput = string.Empty;
    [ObservableProperty] private string _urlOutput = string.Empty;

    [RelayCommand]
    private Task UrlAction(string mode)
    {
        string input = UrlInput;
        if (string.IsNullOrEmpty(input)) { ResetError(); return Task.CompletedTask; }

        return RunOffUi("url", () =>
        {
            if (mode is "enc" or "form") EnsureOutputSize(PercentEncodedSizeBound(input), "Encoded output");
            return Transform();
        }, r => UrlOutput = r, "URL: ");

        string Transform() => mode switch
        {
            // RFC 3986 component encoding: space → %20, only unreserved chars left bare (path/query values).
            "enc" => Uri.EscapeDataString(input),
            // HTML form encoding (application/x-www-form-urlencoded): space → '+'.
            "form" => WebUtility.UrlEncode(input),
            "parse" => ParseUrl(input),
            // UrlDecode understands both %20 and '+', so it undoes either encoding above.
            _ => WebUtility.UrlDecode(input),
        };
    }

    // Percent-encoding writes %XX per UTF-8 byte: up to 9 chars for one char (CJK ×9), so it gets the output ceiling
    // like the other expanding encoders. Unreserved ASCII stays 1 char; everything else is counted at its worst.
    private static long PercentEncodedSizeBound(string s)
    {
        long n = 0;
        foreach (char c in s)
            n += c < 0x80 ? (char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or '~' ? 1 : 3)
                 : c < 0x800 || char.IsSurrogate(c) ? 6 : 9;
        return n;
    }

    // Schemes that legitimately have no "//authority" part; anything else without "://" is treated
    // as a bare host ("example.com:8080/x" would otherwise parse with scheme "example.com").
    private static readonly string[] OpaqueSchemes = { "mailto:", "urn:", "tel:", "data:", "file:", "news:" };

    private static string ParseUrl(string input)
    {
        string s = input.Trim();
        bool assumed = false;
        bool hasScheme = s.Contains("://", StringComparison.Ordinal)
                         || Array.Exists(OpaqueSchemes, p => s.StartsWith(p, StringComparison.OrdinalIgnoreCase));
        if (!hasScheme) { s = "http://" + s; assumed = true; }

        if (!Uri.TryCreate(s, UriKind.Absolute, out var uri))
            throw new FormatException("Not a parseable URL.");

        var sb = new StringBuilder();
        Row2(sb, "Scheme", uri.Scheme + (assumed ? "   (none given — assumed http)" : ""));

        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            int colon = uri.UserInfo.IndexOf(':');
            Row2(sb, "User", Uri.UnescapeDataString(colon >= 0 ? uri.UserInfo[..colon] : uri.UserInfo));
            if (colon >= 0) Row2(sb, "Password", Uri.UnescapeDataString(uri.UserInfo[(colon + 1)..]));
        }

        if (!string.IsNullOrEmpty(uri.Host))
        {
            Row2(sb, "Host", uri.Host);
            // Punycode form of an internationalised host; IDN mapping can be unavailable under
            // InvariantGlobalization (release desktop builds), so it is best-effort.
            string? idn = null;
            try { idn = uri.IdnHost; } catch (Exception) { /* no IDN support — skip the row */ }
            if (idn != null && !string.Equals(idn, uri.Host, StringComparison.OrdinalIgnoreCase))
                Row2(sb, "Host (IDN)", idn);
            Row2(sb, "Host type", uri.HostNameType.ToString());
            if (uri.Port >= 0) Row2(sb, "Port", uri.Port + (uri.IsDefaultPort ? "   (default)" : ""));
        }

        string path = uri.AbsolutePath;
        string decodedPath = Uri.UnescapeDataString(path);
        Row2(sb, "Path", path);
        if (decodedPath != path) Row2(sb, "Path (decoded)", decodedPath);

        if (!string.IsNullOrEmpty(uri.Query))
        {
            Row2(sb, "Query", uri.Query);
            var pairs = uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries);
            int n = 0;
            foreach (var pair in pairs)
            {
                int eq = pair.IndexOf('=');
                string key = FormDecode(eq >= 0 ? pair[..eq] : pair);
                string val = eq >= 0 ? FormDecode(pair[(eq + 1)..]) : "(no value)";
                sb.AppendLine($"  [{++n}] {key} = {val}");
            }
        }

        if (!string.IsNullOrEmpty(uri.Fragment))
        {
            Row2(sb, "Fragment", uri.Fragment);
            string decodedFragment = Uri.UnescapeDataString(uri.Fragment);
            if (decodedFragment != uri.Fragment) Row2(sb, "Frag (decoded)", decodedFragment);
        }

        // scheme://host[:port] only — GetLeftPart(Authority) would echo the user:password back.
        if (!string.IsNullOrEmpty(uri.Host))
            Row2(sb, "Origin", uri.GetComponents(UriComponents.SchemeAndServer, UriFormat.UriEscaped));
        return sb.ToString().TrimEnd();
    }

    // Query strings in the wild use '+' for spaces (form encoding); Uri.UnescapeDataString alone leaves it.
    private static string FormDecode(string s) => Uri.UnescapeDataString(s.Replace('+', ' '));
}
