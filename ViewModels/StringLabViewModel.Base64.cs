using System;
using System.Text;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _b64Input = string.Empty;
    [ObservableProperty] private string _b64Output = string.Empty;

    [RelayCommand]
    private Task B64Action(string mode)
    {
        string input = B64Input;
        if (string.IsNullOrEmpty(input)) { ResetError(); return Task.CompletedTask; }

        return RunOffUi("b64", () =>
        {
            if (mode is not ("enc" or "encurl")) return TextBytes.DecodeForDisplay(LenientBase64Decode(input));
            byte[] bytes = Encoding.UTF8.GetBytes(input);
            EnsureOutputSize((bytes.Length + 2L) / 3 * 4, "Base64 output");
            return mode == "enc" ? Convert.ToBase64String(bytes) : ToBase64Url(bytes);
        }, r => B64Output = r, "Base64: ");
    }

    // RFC 4648 §5: '-' and '_' instead of '+' and '/', and no '=' padding (JWT, URLs, file names).
    private static string ToBase64Url(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>
    /// Decodes what people actually paste: MIME-wrapped lines and stray whitespace, the URL-safe
    /// alphabet (auto-detected, even mixed), missing '=' padding, and a leading data: URI header.
    /// Throws FormatException with a readable reason.
    /// </summary>
    private static byte[] LenientBase64Decode(string input)
    {
        var span = input.AsSpan().Trim();
        if (span.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
        {
            int comma = span.IndexOf(',');
            if (comma >= 0) span = span[(comma + 1)..];
        }

        var sb = new StringBuilder(span.Length + 3);
        int padding = 0;
        for (int i = 0; i < span.Length; i++)
        {
            char c = span[i];
            if (char.IsWhiteSpace(c)) continue;
            if (c == '=') { padding++; continue; }
            // '=' only belongs at the very end — data after it means two blobs were glued together.
            if (padding > 0)
                throw new FormatException("'=' padding appears in the middle — is this several Base64 strings joined together?");
            char mapped = c switch { '-' => '+', '_' => '/', _ => c };
            if (!(char.IsAsciiLetterOrDigit(mapped) || mapped == '+' || mapped == '/'))
                throw new FormatException($"Invalid character '{c}' at position {i + 1} — not part of the Base64 alphabet.");
            sb.Append(mapped);
        }

        if (sb.Length % 4 == 1)
            throw new FormatException("Invalid length — a Base64 string can't end with a single leftover character (truncated?).");
        sb.Append('=', (4 - sb.Length % 4) % 4);
        return Convert.FromBase64String(sb.ToString());
    }
}
