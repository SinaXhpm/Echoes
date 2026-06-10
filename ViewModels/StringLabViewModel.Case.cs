using System;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _caseInput = string.Empty;
    [ObservableProperty] private string _caseOutput = string.Empty;

    [RelayCommand]
    private void CaseAction(string mode)
    {
        try
        {
            ResetError();
            if (string.IsNullOrEmpty(CaseInput)) return;

            CaseOutput = mode switch
            {
                "upper" => CaseInput.ToUpperInvariant(),
                "lower" => CaseInput.ToLowerInvariant(),
                "title" => CultureInfo.InvariantCulture.TextInfo.ToTitleCase(CaseInput.ToLowerInvariant()),
                "sentence" => Sentence(CaseInput),
                "camel" => Join(Words(CaseInput), camel: true),
                "pascal" => Join(Words(CaseInput), camel: false),
                "snake" => string.Join("_", Words(CaseInput).Select(w => w.ToLowerInvariant())),
                "kebab" => string.Join("-", Words(CaseInput).Select(w => w.ToLowerInvariant())),
                "constant" => string.Join("_", Words(CaseInput).Select(w => w.ToUpperInvariant())),
                "slug" => Slug(CaseInput),
                "reverse" => new string(CaseInput.Reverse().ToArray()),
                _ => CaseInput
            };
        }
        catch (Exception ex) { ErrorMessage = ex.Message; }
    }

    private static string[] Words(string input)
    {
        // Split on separators and camelCase boundaries.
        var spaced = Regex.Replace(input, @"([a-z0-9])([A-Z])", "$1 $2");
        return spaced.Split(new[] { ' ', '_', '-', '.', '/', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
    }

    private static string Join(string[] words, bool camel)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < words.Length; i++)
        {
            var w = words[i].ToLowerInvariant();
            if (camel && i == 0) sb.Append(w);
            else sb.Append(char.ToUpperInvariant(w[0])).Append(w.Length > 1 ? w[1..] : "");
        }
        return sb.ToString();
    }

    private static string Slug(string input)
    {
        var lower = input.ToLowerInvariant();
        var cleaned = Regex.Replace(lower, @"[^a-z0-9\s-]", "");
        return Regex.Replace(cleaned, @"[\s-]+", "-").Trim('-');
    }

    private static string Sentence(string input)
    {
        var lower = input.ToLowerInvariant();
        return Regex.Replace(lower, @"(^\s*\w)|([.!?]\s*\w)", m => m.Value.ToUpperInvariant());
    }
}
