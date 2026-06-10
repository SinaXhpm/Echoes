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
            case "regex": RegexInput = RegexOutput = RegexPattern = RegexReplacement = string.Empty; break;
            case "edit": EditInput = string.Empty; break;
            case "json": JsonInput = JsonOutput = string.Empty; break;
            case "subnet": SubnetInput = SubnetOutput = string.Empty; break;
            case "epoch": EpochInput = EpochOutput = string.Empty; break;
            case "gen": GenerateOutput = string.Empty; break;
            case "baseconv": BaseInput = BaseOutput = string.Empty; break;
            case "hashid": HashIdInput = HashIdOutput = string.Empty; break;
            case "diff": DiffLeft = DiffRight = DiffOutput = string.Empty; break;
            case "case": CaseInput = CaseOutput = string.Empty; break;
            case "convert": ConvertInput = ConvertOutput = string.Empty; break;
        }
    }
}