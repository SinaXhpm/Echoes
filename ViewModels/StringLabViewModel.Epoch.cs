using System;
using System.Globalization;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _epochInput = string.Empty;
    [ObservableProperty] private string _epochOutput = string.Empty;

    [RelayCommand]
    private void EpochNow()
    {
        EpochInput = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        RunEpoch();
    }

    [RelayCommand]
    private void RunEpoch()
    {
        try
        {
            ResetError();
            var s = EpochInput.Trim();
            if (string.IsNullOrEmpty(s)) return;

            DateTimeOffset dto;

            if (long.TryParse(s, out var num))
            {
                int digits = s.TrimStart('-').Length;
                dto = digits switch
                {
                    >= 16 => DateTimeOffset.FromUnixTimeMilliseconds(num / 1000),   // microseconds
                    >= 13 => DateTimeOffset.FromUnixTimeMilliseconds(num),          // milliseconds
                    _ => DateTimeOffset.FromUnixTimeSeconds(num)                    // seconds
                };
            }
            else if (!DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out dto))
            {
                ErrorMessage = "Enter a Unix timestamp (sec/ms) or a date string.";
                return;
            }

            var utc = dto.ToUniversalTime();
            var local = dto.ToLocalTime();
            var now = DateTimeOffset.UtcNow;
            var delta = now - utc;

            var sb = new StringBuilder();
            Row2(sb, "Unix (sec)", utc.ToUnixTimeSeconds().ToString());
            Row2(sb, "Unix (ms)", utc.ToUnixTimeMilliseconds().ToString());
            sb.AppendLine();
            Row2(sb, "UTC", utc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'"));
            Row2(sb, "Local", local.ToString("yyyy-MM-dd HH:mm:ss zzz"));
            Row2(sb, "ISO 8601", utc.ToString("yyyy-MM-ddTHH:mm:ssZ"));
            Row2(sb, "RFC 1123", utc.ToString("r"));
            Row2(sb, "Day", utc.DayOfWeek.ToString());
            Row2(sb, "Relative", Relative(delta));

            EpochOutput = sb.ToString().TrimEnd();
        }
        catch (Exception ex) { ErrorMessage = ex.Message; }
    }

    private static string Relative(TimeSpan delta)
    {
        bool past = delta.TotalSeconds >= 0;
        var d = delta.Duration();
        string unit =
            d.TotalDays >= 365 ? $"{d.TotalDays / 365:F1} years" :
            d.TotalDays >= 1 ? $"{d.TotalDays:F0} days" :
            d.TotalHours >= 1 ? $"{d.TotalHours:F0} hours" :
            d.TotalMinutes >= 1 ? $"{d.TotalMinutes:F0} minutes" :
            $"{d.TotalSeconds:F0} seconds";
        return past ? $"{unit} ago" : $"in {unit}";
    }
}
