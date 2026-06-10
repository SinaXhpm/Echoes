using System;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _subnetInput = "192.168.1.0/24";
    [ObservableProperty] private string _subnetOutput = string.Empty;

    [RelayCommand]
    private void RunSubnet()
    {
        try
        {
            ResetError();
            if (string.IsNullOrWhiteSpace(SubnetInput)) return;
            SubnetOutput = SubnetCalc.Describe(SubnetInput);
        }
        catch (Exception ex) { ErrorMessage = ex.Message; }
    }

    // Shared aligned "label : value" row used by the Subnet/Epoch/BaseConv outputs.
    private static void Row2(StringBuilder sb, string label, string value)
        => sb.AppendLine($"{label,-14}: {value}");
}
