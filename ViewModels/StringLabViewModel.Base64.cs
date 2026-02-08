using System;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _b64Input = string.Empty;
    [ObservableProperty] private string _b64Output = string.Empty;

    [RelayCommand]
    private void B64Action(string mode)
    {
        try
        {
            ResetError();
            if (string.IsNullOrEmpty(B64Input)) return;
            B64Output = mode == "enc"
                ? Convert.ToBase64String(Encoding.UTF8.GetBytes(B64Input))
                : Encoding.UTF8.GetString(Convert.FromBase64String(B64Input));
        }
        catch { ErrorMessage = "Invalid Base64 format."; }
    }
}