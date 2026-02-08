using System.Collections.Generic;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Echoes.ViewModels;

public partial class StringLabViewModel : ObservableObject
{
    [ObservableProperty] private string _errorMessage = string.Empty;

    private void ResetError() => ErrorMessage = string.Empty;

    [RelayCommand]
    private void Clear(string tab)
    {
        ResetError();
        switch (tab)
        {
            case "b64": B64Input = B64Output = string.Empty; break;
            case "url": UrlInput = UrlOutput = string.Empty; break;
            case "hash": HashInput = HashOutput = string.Empty; break;
            case "regex": RegexInput = RegexOutput = RegexPattern = string.Empty; break;
            case "edit": EditInput = string.Empty; break;
            case "json": JsonInput = JsonOutput = string.Empty; break;
        }
    }
}