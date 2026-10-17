using System;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _epochInput = string.Empty;
    [ObservableProperty] private string _epochOutput = string.Empty;

    // "+1h", "-3d", "now+90m", "now - 2w" (s/m/h/d/w/y; "mo" = 30 days)
    private static readonly Regex RelativeTimeRe = new(@"^(?:now\s*)?([+-])\s*(\d{1,9})\s*(s|sec|m|min|h|hr|d|day|days|w|wk|mo|y|yr)$",
        RegexOptions.IgnoreCase, InternalRegexTimeout);
    // ISO week date: 2026-W39 or 2026-W39-3 (day 1 = Monday)
    private static readonly Regex IsoWeekRe = new(@"^(\d{4})-?W(\d{2})(?:-?([1-7]))?$", RegexOptions.IgnoreCase, InternalRegexTimeout);

    [RelayCommand]
    private void EpochNow()
    {
        EpochInput = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
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

            if (!TryParseEpochInput(s, out DateTimeOffset dto, out string how))
            {
                ErrorMessage = "Enter a Unix timestamp (s/ms/µs/ns), a date, \"now\", a relative time (+1h, -3d) or an ISO week (2026-W39-3).";
                return;
            }

            var utc = dto.ToUniversalTime();
            var local = dto.ToLocalTime();
            var delta = DateTimeOffset.UtcNow - utc;

            var sb = new StringBuilder();
            Row2(sb, "Input as", how);
            sb.AppendLine();
            Row2(sb, "Unix (sec)", utc.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture));
            Row2(sb, "Unix (ms)", utc.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture));
            sb.AppendLine();
            Row2(sb, "UTC", utc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture));
            Row2(sb, "Local", local.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture));
            Row2(sb, "ISO 8601", utc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture));
            Row2(sb, "RFC 1123", utc.ToString("r", CultureInfo.InvariantCulture));
            Row2(sb, "Day", utc.DayOfWeek.ToString());
            Row2(sb, "Day of year", utc.DayOfYear.ToString(CultureInfo.InvariantCulture));
            Row2(sb, "ISO week", $"{ISOWeek.GetYear(utc.UtcDateTime)}-W{ISOWeek.GetWeekOfYear(utc.UtcDateTime):00}-{IsoDay(utc.DayOfWeek)}");
            Row2(sb, "Relative", Relative(delta));

            EpochOutput = sb.ToString().TrimEnd();
        }
        catch (Exception ex) when (ex is ArgumentOutOfRangeException or OverflowException)
        {
            ErrorMessage = "That time is outside the representable date range (years 1–9999).";
        }
        catch (Exception ex) { ErrorMessage = ex.Message; }
    }

    private static int IsoDay(DayOfWeek d) => d == DayOfWeek.Sunday ? 7 : (int)d;

    private static bool TryParseEpochInput(string s, out DateTimeOffset dto, out string how)
    {
        dto = default;
        how = string.Empty;

        if (s.Equals("now", StringComparison.OrdinalIgnoreCase)) { dto = DateTimeOffset.UtcNow; how = "now"; return true; }

        if (long.TryParse(s, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var num))
        {
            // Unit by magnitude (digit count): 10 ≈ seconds, 13 ms, 16 µs, 19 ns.
            int digits = s.TrimStart('-', '+').Length;
            (dto, how) = digits switch
            {
                >= 19 => (DateTimeOffset.FromUnixTimeMilliseconds(num / 1_000_000), "Unix nanoseconds"),
                >= 16 => (DateTimeOffset.FromUnixTimeMilliseconds(num / 1000), "Unix microseconds"),
                >= 13 => (DateTimeOffset.FromUnixTimeMilliseconds(num), "Unix milliseconds"),
                _ => (DateTimeOffset.FromUnixTimeSeconds(num), "Unix seconds"),
            };
            return true;
        }

        var rel = RelativeTimeRe.Match(s);
        if (rel.Success)
        {
            double n = double.Parse(rel.Groups[2].Value, CultureInfo.InvariantCulture) * (rel.Groups[1].Value == "-" ? -1 : 1);
            string unit = rel.Groups[3].Value.ToLowerInvariant();
            TimeSpan span = unit switch
            {
                "s" or "sec" => TimeSpan.FromSeconds(n),
                "m" or "min" => TimeSpan.FromMinutes(n),
                "h" or "hr" => TimeSpan.FromHours(n),
                "d" or "day" or "days" => TimeSpan.FromDays(n),
                "w" or "wk" => TimeSpan.FromDays(n * 7),
                "mo" => TimeSpan.FromDays(n * 30),
                _ => TimeSpan.FromDays(n * 365),   // y / yr
            };
            dto = DateTimeOffset.UtcNow + span;
            how = $"now {rel.Groups[1].Value} {rel.Groups[2].Value}{unit}";
            return true;
        }

        var week = IsoWeekRe.Match(s);
        if (week.Success)
        {
            int year = int.Parse(week.Groups[1].Value, CultureInfo.InvariantCulture);
            int wk = int.Parse(week.Groups[2].Value, CultureInfo.InvariantCulture);
            int day = week.Groups[3].Success ? int.Parse(week.Groups[3].Value, CultureInfo.InvariantCulture) : 1;
            if (wk < 1 || wk > ISOWeek.GetWeeksInYear(year)) return false;
            var date = ISOWeek.ToDateTime(year, wk, day == 7 ? DayOfWeek.Sunday : (DayOfWeek)day);
            dto = new DateTimeOffset(date, TimeSpan.Zero);
            how = "ISO week date (UTC midnight)";
            return true;
        }

        if (DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out dto))
        {
            how = "date string (no offset = UTC)";
            return true;
        }
        return false;
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
