using System.Net;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _escInput = string.Empty;
    [ObservableProperty] private string _escOutput = string.Empty;

    [RelayCommand]
    private Task EscAction(string mode)
    {
        string input = EscInput;
        if (string.IsNullOrEmpty(input)) { ResetError(); return Task.CompletedTask; }

        return RunOffUi("esc", () =>
        {
            if (mode is "htmlenc" or "xmlenc" or "jsonenc" or "uenc" or "literal")
                EnsureOutputSize(EscapedSizeBound(input), "Escaped output");

            return mode switch
            {
                "htmlenc" => WebUtility.HtmlEncode(input),
                "htmldec" => WebUtility.HtmlDecode(input),
                "xmlenc" => TextEscape.XmlEscape(input),
                "xmldec" => TextEscape.XmlUnescape(input),
                "jsonenc" => TextEscape.JsonEscape(input),
                "jsondec" => TextEscape.JsonUnescape(input),
                "uenc" => TextEscape.UnicodeEscape(input),
                "udec" => TextEscape.UnicodeUnescape(input),
                "literal" => TextEscape.ToStringLiteral(input),
                _ => TextEscape.BackslashUnescape(input),   // "unescape"
            };
        }, r => EscOutput = r, "Escape: ");
    }

    // Upper bound on the output of every escape mode: a char that any of them may escape (outside
    // printable ASCII, quotes, < > & \ + `) grows to at most 6 (\uXXXX, &quot;, &#255;), the rest stay
    // 1 — so plain text isn't refused as if every char became \uXXXX.
    private static long EscapedSizeBound(string s)
    {
        long n = s.Length;
        foreach (char c in s)
            if (c is < ' ' or > '~' or '<' or '>' or '&' or '"' or '\'' or '\\' or '+' or '`') n += 5;
        return n;
    }
}
