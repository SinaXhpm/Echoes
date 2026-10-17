using System.Text;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _hexInput = string.Empty;
    [ObservableProperty] private string _hexOutput = string.Empty;
    [ObservableProperty] private bool _hexUpper;
    [ObservableProperty] private string _hexSeparator = "space";

    public string[] HexSeparators { get; } = { "none", "space", "colon", "0x C-array" };

    [RelayCommand]
    private Task HexAction(string mode)
    {
        string input = HexInput;
        if (string.IsNullOrEmpty(input)) { ResetError(); return Task.CompletedTask; }
        string style = HexSeparator == "0x C-array" ? "c" : HexSeparator ?? "none";
        bool upper = HexUpper;

        return RunOffUi("hex", () =>
        {
            switch (mode)
            {
                case "tohex":
                {
                    byte[] bytes = Encoding.UTF8.GetBytes(input);
                    EnsureOutputSize((long)bytes.Length * TextBytes.HexCharsPerByte(style), "Hex output");
                    return TextBytes.ToHex(bytes, style, upper);
                }
                case "tobin":
                {
                    byte[] bytes = Encoding.UTF8.GetBytes(input);
                    EnsureOutputSize((long)bytes.Length * 9, "Binary output");
                    return TextBytes.ToBinary(bytes);
                }
                case "dump":
                {
                    byte[] bytes = Encoding.UTF8.GetBytes(input);
                    EnsureOutputSize((long)bytes.Length * 5, "Hex dump");
                    return TextBytes.HexDump(bytes);
                }
                case "frombin":
                    return TextBytes.DecodeForDisplay(TextBytes.ParseBinaryLenient(input));
                default:   // "fromhex"
                    return TextBytes.DecodeForDisplay(TextBytes.ParseHexLenient(input));
            }
        }, r => HexOutput = r, "Hex: ");
    }
}
