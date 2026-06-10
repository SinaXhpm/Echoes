using System;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _baseInput = string.Empty;
    [ObservableProperty] private string _baseOutput = string.Empty;

    [RelayCommand]
    private void RunBaseConv()
    {
        try
        {
            ResetError();
            var s = BaseInput.Trim();
            if (string.IsNullOrEmpty(s)) return;

            long value;
            string detected;
            try
            {
                if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) { value = Convert.ToInt64(s[2..], 16); detected = "Hex"; }
                else if (s.StartsWith("0b", StringComparison.OrdinalIgnoreCase)) { value = Convert.ToInt64(s[2..], 2); detected = "Binary"; }
                else if (s.StartsWith("0o", StringComparison.OrdinalIgnoreCase)) { value = Convert.ToInt64(s[2..], 8); detected = "Octal"; }
                else { value = Convert.ToInt64(s, 10); detected = "Decimal"; }
            }
            catch
            {
                ErrorMessage = "Invalid number. Use a plain decimal or a 0x / 0b / 0o prefix.";
                return;
            }

            var sb = new StringBuilder();
            Row2(sb, "Input as", detected);
            sb.AppendLine();
            Row2(sb, "Decimal", value.ToString());
            Row2(sb, "Hex", "0x" + Convert.ToString(value, 16).ToUpperInvariant());
            Row2(sb, "Octal", "0o" + Convert.ToString(value, 8));
            Row2(sb, "Binary", "0b" + Convert.ToString(value, 2));
            if (value >= 0 && value <= 0x10FFFF && value > 0)
            {
                try { Row2(sb, "Char", char.ConvertFromUtf32((int)value)); } catch { }
            }

            BaseOutput = sb.ToString().TrimEnd();
        }
        catch (Exception ex) { ErrorMessage = ex.Message; }
    }
}
