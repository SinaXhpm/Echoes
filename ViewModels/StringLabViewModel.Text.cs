using System;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _editInput = string.Empty;
    [ObservableProperty] private int _charCount;
    [ObservableProperty] private int _wordCount;
    [ObservableProperty] private int _lineCount;

    partial void OnEditInputChanged(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            CharCount = WordCount = LineCount = 0;
            return;
        }
        CharCount = value.Length;
        LineCount = value.Split('\n').Length;
        WordCount = value.Split(new[] { ' ', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Length;
    }

    [RelayCommand]
    private void EditAction(string mode)
    {
        try
        {
            ResetError();
            if (string.IsNullOrEmpty(EditInput)) return;
            var lines = EditInput.Split(new[] { Environment.NewLine, "\n", "\r" }, StringSplitOptions.None).ToList();
            switch (mode)
            {
                case "sort": EditInput = string.Join(Environment.NewLine, lines.OrderBy(x => x)); break;
                case "unique": EditInput = string.Join(Environment.NewLine, lines.Distinct()); break;
                case "reverse": EditInput = string.Join(Environment.NewLine, lines.AsEnumerable().Reverse()); break;
                case "trim": EditInput = EditInput.Trim(); break;
                case "clean": EditInput = string.Join(Environment.NewLine, lines.Where(l => !string.IsNullOrWhiteSpace(l)).Select(l => l.Trim())); break;
                case "upper": EditInput = EditInput.ToUpperInvariant(); break;
                case "lower": EditInput = EditInput.ToLowerInvariant(); break;
            }
        }
        catch (Exception ex) { ErrorMessage = ex.Message; }
    }
}