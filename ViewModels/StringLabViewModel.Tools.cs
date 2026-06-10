using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _urlInput = string.Empty;
    [ObservableProperty] private string _urlOutput = string.Empty;
    [ObservableProperty] private string _hashInput = string.Empty;
    [ObservableProperty] private string _hashOutput = string.Empty;
    [ObservableProperty] private string _regexInput = string.Empty;
    [ObservableProperty] private string _regexOutput = string.Empty;
    [ObservableProperty] private string _regexPattern = string.Empty;
    [ObservableProperty] private string _regexReplacement = string.Empty;
    [ObservableProperty] private bool _regexIgnoreCase;
    [ObservableProperty] private bool _regexMultiline;
    [ObservableProperty] private KeyValuePair<string, string>? _selectedRegex;

    public List<KeyValuePair<string, string>> DefaultRegexList { get; } = new()
    {
        new("Extract IPv4", @"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"),
        new("Extract IPv6", @"(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}"),
        new("Extract Domains", @"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"),
        new("Extract URLs", @"https?://[^\s/$.?#][^\s]*"),
        new("Extract Emails", @"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        new("Extract host:port", @"\b(?:[a-zA-Z0-9.-]+|\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}\b"),
        new("Extract MAC Address", @"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"),
        new("Extract Dates (ISO)", @"\b\d{4}-\d{2}-\d{2}\b"),
        new("Extract Times", @"\b\d{1,2}:\d{2}(?::\d{2})?\b"),
        new("Extract Phone Numbers", @"\+?\d[\d\s().-]{7,}\d"),
        new("Extract GUID / UUID", @"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}"),
        new("Extract JWT", @"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        new("Extract Hex Colors", @"#(?:[0-9a-fA-F]{6}|[0-9a-fA-F]{3})\b"),
        new("Extract HTML Tags", @"</?[a-zA-Z][^>]*>"),
        new("Extract Hashtags", @"#\w+"),
        new("Extract Mentions (@)", @"@\w+"),
        new("Extract Numbers", @"-?\d+(?:\.\d+)?"),
        new("Extract Words", @"\b\w+\b")
    };

    partial void OnSelectedRegexChanged(KeyValuePair<string, string>? value)
    {
        if (value.HasValue) RegexPattern = value.Value.Value;
    }

    [RelayCommand]
    private void UrlAction(string mode)
    {
        try { ResetError(); if (string.IsNullOrEmpty(UrlInput)) return; UrlOutput = mode == "enc" ? WebUtility.UrlEncode(UrlInput) : WebUtility.UrlDecode(UrlInput); }
        catch (Exception ex) { ErrorMessage = ex.Message; }
    }

    [RelayCommand]
    private void HashAction(string type)
    {
        try { ResetError(); if (string.IsNullOrEmpty(HashInput)) return; byte[] h = type == "md5" ? MD5.HashData(Encoding.UTF8.GetBytes(HashInput)) : SHA256.HashData(Encoding.UTF8.GetBytes(HashInput)); var sb = new StringBuilder(); foreach (var b in h) sb.Append(b.ToString("x2")); HashOutput = sb.ToString(); }
        catch (Exception ex) { ErrorMessage = ex.Message; }
    }

    [RelayCommand]
    private void RunRegex()
    {
        try
        {
            ResetError();
            if (string.IsNullOrEmpty(RegexInput) || string.IsNullOrEmpty(RegexPattern)) return;

            var options = RegexOptions.None;
            if (RegexIgnoreCase) options |= RegexOptions.IgnoreCase;
            if (RegexMultiline) options |= RegexOptions.Multiline;

            var matches = Regex.Matches(RegexInput, RegexPattern, options, TimeSpan.FromSeconds(5));
            if (matches.Count == 0) { RegexOutput = "No matches found."; return; }

            var sb = new StringBuilder();
            sb.AppendLine($"# {matches.Count} match(es)");
            sb.AppendLine();

            foreach (Match m in matches)
            {
                sb.AppendLine(m.Value);
                for (int i = 1; i < m.Groups.Count; i++)
                {
                    var g = m.Groups[i];
                    if (g.Success)
                        sb.AppendLine($"    └─ group[{(string.IsNullOrEmpty(g.Name) || g.Name == i.ToString() ? i.ToString() : g.Name)}]: {g.Value}");
                }
            }

            RegexOutput = sb.ToString().TrimEnd();
        }
        catch (RegexMatchTimeoutException) { ErrorMessage = "Regex timed out (possible catastrophic backtracking)."; }
        catch (Exception ex) { ErrorMessage = ex.Message; }
    }

    [RelayCommand]
    private void ReplaceRegex()
    {
        try
        {
            ResetError();
            if (string.IsNullOrEmpty(RegexInput) || string.IsNullOrEmpty(RegexPattern)) return;

            var options = RegexOptions.None;
            if (RegexIgnoreCase) options |= RegexOptions.IgnoreCase;
            if (RegexMultiline) options |= RegexOptions.Multiline;

            RegexOutput = Regex.Replace(RegexInput, RegexPattern, RegexReplacement ?? string.Empty, options, TimeSpan.FromSeconds(5));
        }
        catch (RegexMatchTimeoutException) { ErrorMessage = "Regex timed out (possible catastrophic backtracking)."; }
        catch (Exception ex) { ErrorMessage = ex.Message; }
    }
}