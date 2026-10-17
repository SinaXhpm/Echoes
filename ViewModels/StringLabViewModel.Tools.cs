using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Echoes.ViewModels;

// REGEX tool (URL and HASH live in their own partials).
public partial class StringLabViewModel
{
    [ObservableProperty] private string _regexInput = string.Empty;
    [ObservableProperty] private string _regexOutput = string.Empty;
    [ObservableProperty] private string _regexPattern = string.Empty;
    [ObservableProperty] private string _regexReplacement = string.Empty;
    [ObservableProperty] private bool _regexIgnoreCase;
    [ObservableProperty] private bool _regexMultiline;
    [ObservableProperty] private bool _regexSingleline;
    [ObservableProperty] private bool _regexExplicitCapture;
    [ObservableProperty] private KeyValuePair<string, string>? _selectedRegex;

    // Listing more than this many matches only produces an unreadable (and slow to render) wall of text.
    private const int MaxListedMatches = 5_000;

    private const string Octet = @"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)";

    public List<KeyValuePair<string, string>> DefaultRegexList { get; } = new()
    {
        new("Extract IPv4", $@"\b(?:{Octet}\.){{3}}{Octet}\b"),
        new("Extract IPv4 CIDR (a.b.c.d/nn)", $@"\b(?:{Octet}\.){{3}}{Octet}/(?:3[0-2]|[12]?\d)\b"),
        new("Extract IPv4:port", $@"\b(?:{Octet}\.){{3}}{Octet}:(?:6553[0-5]|655[0-2]\d|65[0-4]\d\d|6[0-4]\d{{3}}|[1-5]\d{{4}}|[1-9]\d{{0,3}})\b"),
        new("Extract IPv6", @"(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}"),
        new("Extract Domains", @"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"),
        new("Extract URLs", @"https?://[^\s/$.?#][^\s]*"),
        new("URL query params (key, value)", @"[?&]([^=&#\s]+)=([^&#\s]*)"),
        new("Extract Emails", @"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        new("Extract host:port", @"\b(?:[a-zA-Z0-9.-]+|\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}\b"),
        new("Extract MAC Address", @"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"),
        new("Extract Dates (ISO)", @"\b\d{4}-\d{2}-\d{2}\b"),
        new("Extract Times", @"\b\d{1,2}:\d{2}(?::\d{2})?\b"),
        new("Extract Phone Numbers", @"\+?\d[\d\s().-]{7,}\d"),
        new("Extract GUID / UUID", @"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}"),
        new("Extract UUID v4", @"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"),
        new("Extract JWT", @"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        new("Card-like numbers (13-19 digits)", @"\b(?:\d[ -]?){12,18}\d\b"),
        new("Extract Hex Colors", @"#(?:[0-9a-fA-F]{6}|[0-9a-fA-F]{3})\b"),
        new("Extract HTML Tags", @"</?[a-zA-Z][^>]*>"),
        new("Extract Hashtags", @"#\w+"),
        new("Extract Mentions (@)", @"@\w+"),
        new("Extract Numbers", @"-?\d+(?:\.\d+)?"),
        new("Extract Words", @"\b\w+\b"),
        new("Whitespace runs (2+)", @"\s{2,}"),
    };

    partial void OnSelectedRegexChanged(KeyValuePair<string, string>? value)
    {
        if (value.HasValue) RegexPattern = value.Value.Value;
    }

    // Shared so an option toggle can't diverge between match / replace / split.
    private RegexOptions BuildRegexOptions()
    {
        var options = RegexOptions.None;
        if (RegexIgnoreCase) options |= RegexOptions.IgnoreCase;
        if (RegexMultiline) options |= RegexOptions.Multiline;
        if (RegexSingleline) options |= RegexOptions.Singleline;
        if (RegexExplicitCapture) options |= RegexOptions.ExplicitCapture;
        return options;
    }

    // Captures pattern/input/options on the UI thread, then compiles + runs on the pool with the
    // 5 s match timeout (a runaway pattern throws RegexMatchTimeoutException instead of hanging).
    private Task RunRegexTool(Func<Regex, string, string> run)
    {
        string input = RegexInput, pattern = RegexPattern;
        if (string.IsNullOrEmpty(input) || string.IsNullOrEmpty(pattern)) { ResetError(); return Task.CompletedTask; }
        var options = BuildRegexOptions();
        return RunOffUi("regex", () => run(new Regex(pattern, options, RegexTimeout), input), r => RegexOutput = r, "Regex: ");
    }

    // The 5 s match timeout covers ONE Match / NextMatch: a pattern that needs just under that per match (seen: 0.55 s
    // each, 400 matches still running after 90 s) kept a worker busy, and the Regex tool locked, for up to 5,000 × 5 s.
    // The listing as a whole gets this budget too. (Replace and Split run all their matches under one timeout.)
    private static readonly TimeSpan RegexListBudget = TimeSpan.FromSeconds(10);

    [RelayCommand]
    private Task RunRegex() => RunRegexTool((re, input) =>
    {
        var sb = new StringBuilder();
        int count = 0;
        bool more = false, slow = false;
        var budget = System.Diagnostics.Stopwatch.StartNew();
        var m = re.Match(input);
        while (m.Success)
        {
            if (count == MaxListedMatches) { more = true; break; }
            if (budget.Elapsed > RegexListBudget) { slow = true; break; }
            count++;
            sb.Append('[').Append(count).Append("] @").Append(m.Index).Append(" len ").Append(m.Length).Append(": ").AppendLine(m.Value);
            for (int i = 1; i < m.Groups.Count; i++)
            {
                var g = m.Groups[i];
                if (g.Success)
                    sb.AppendLine($"    └─ group[{(string.IsNullOrEmpty(g.Name) || g.Name == i.ToString() ? i.ToString() : g.Name)}] @{g.Index}: {g.Value}");
            }
            m = m.NextMatch();
        }
        if (count == 0) return "No matches found.";

        string header = more
            ? $"# showing the first {MaxListedMatches:N0} matches — more exist (list truncated)"
            : slow
                ? $"# stopped after {count:N0} match(es): matching took over {RegexListBudget.TotalSeconds:0} s (slow pattern) — list truncated"
                : $"# {count:N0} match(es)";
        return header + Environment.NewLine + Environment.NewLine + sb.ToString().TrimEnd();
    });

    [RelayCommand]
    private Task ReplaceRegex()
    {
        string replacement = RegexReplacement ?? string.Empty;
        return RunRegexTool((re, input) => re.Replace(input, replacement));
    }

    [RelayCommand]
    private Task SplitRegex() => RunRegexTool((re, input) =>
    {
        var parts = re.Split(input);
        return $"# {parts.Length:N0} part(s)" + Environment.NewLine + Environment.NewLine + string.Join(Environment.NewLine, parts);
    });
}
