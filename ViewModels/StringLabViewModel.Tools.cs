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
    [ObservableProperty] private KeyValuePair<string, string>? _selectedRegex;

    public List<KeyValuePair<string, string>> DefaultRegexList { get; } = new()
    {
        new("Extract IPs", @"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
        new("Extract Emails", @"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        new("Extract URLs", @"https?://[^\s/$.?#].[^\s]*")
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
        try { ResetError(); if (string.IsNullOrEmpty(RegexInput) || string.IsNullOrEmpty(RegexPattern)) return; var m = Regex.Matches(RegexInput, RegexPattern); RegexOutput = string.Join(Environment.NewLine, m.Cast<Match>().Select(x => x.Value)); }
        catch (Exception ex) { ErrorMessage = ex.Message; }
    }
}