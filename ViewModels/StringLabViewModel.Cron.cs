using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    // A preset is just a friendly name + the 5-field expression it fills in.
    // ToString => Name so the ComboBox renders it without an ItemTemplate.
    public sealed record CronPreset(string Name, string Expr) { public override string ToString() => Name; }

    public List<CronPreset> CronPresets { get; } = new()
    {
        new("Every minute",            "* * * * *"),
        new("Every 5 minutes",         "*/5 * * * *"),
        new("Every 15 minutes",        "*/15 * * * *"),
        new("Every 30 minutes",        "*/30 * * * *"),
        new("Hourly (top of hour)",    "0 * * * *"),
        new("Every 6 hours",           "0 */6 * * *"),
        new("Daily at midnight",       "0 0 * * *"),
        new("Daily at 9 AM",           "0 9 * * *"),
        new("Weekdays at 9 AM",        "0 9 * * 1-5"),
        new("Weekly (Sun midnight)",   "0 0 * * 0"),
        new("Monthly (1st, midnight)", "0 0 1 * *"),
        new("Yearly (Jan 1)",          "0 0 1 1 *"),
    };

    // The five editable fields (source of truth) …
    [ObservableProperty] private string _cronMinute = "*";
    [ObservableProperty] private string _cronHour = "*";
    [ObservableProperty] private string _cronDom = "*";
    [ObservableProperty] private string _cronMonth = "*";
    [ObservableProperty] private string _cronDow = "*";

    // … and the assembled expression (also editable — paste one in and the fields follow).
    [ObservableProperty] private string _cronExpression = "* * * * *";
    [ObservableProperty] private string _cronDescription = string.Empty;
    [ObservableProperty] private string _cronNextRuns = string.Empty;
    [ObservableProperty] private CronPreset? _selectedCronPreset;

    private bool _cronSyncing;   // guards the field <-> expression two-way sync from recursing

    // No other partial defines a constructor; this one restores the remembered choices (StringLabViewModel.Prefs.cs) and
    // seeds the initial description / next runs.
    public StringLabViewModel()
    {
        RestorePrefs();
        EvaluateCron();
    }

    partial void OnCronMinuteChanged(string value) => RebuildCronExpression();
    partial void OnCronHourChanged(string value) => RebuildCronExpression();
    partial void OnCronDomChanged(string value) => RebuildCronExpression();
    partial void OnCronMonthChanged(string value) => RebuildCronExpression();
    partial void OnCronDowChanged(string value) => RebuildCronExpression();

    partial void OnCronExpressionChanged(string value)
    {
        if (_cronSyncing) return;
        // The user edited the whole expression — push its fields back into the boxes.
        var parts = (value ?? string.Empty).Trim().Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 5)
        {
            _cronSyncing = true;
            CronMinute = parts[0]; CronHour = parts[1]; CronDom = parts[2]; CronMonth = parts[3]; CronDow = parts[4];
            _cronSyncing = false;
        }
        EvaluateCron();
    }

    partial void OnSelectedCronPresetChanged(CronPreset? value)
    {
        if (value is null) return;
        CronExpression = value.Expr;   // OnCronExpressionChanged fans it out to the fields + evaluates
    }

    private void RebuildCronExpression()
    {
        if (_cronSyncing) return;
        _cronSyncing = true;
        CronExpression = $"{Blank(CronMinute)} {Blank(CronHour)} {Blank(CronDom)} {Blank(CronMonth)} {Blank(CronDow)}";
        _cronSyncing = false;
        EvaluateCron();
        static string Blank(string s) => string.IsNullOrWhiteSpace(s) ? "*" : s.Trim();
    }

    private void EvaluateCron()
    {
        var cron = Helpers.CronExpression.Parse(CronExpression);
        if (!cron.IsValid)
        {
            CronDescription = "⚠ " + cron.Error;
            CronNextRuns = string.Empty;
            return;
        }
        CronDescription = cron.Describe();

        var now = DateTime.Now;
        var runs = cron.NextRuns(now, 5);
        if (runs.Count == 0)
        {
            CronNextRuns = "No upcoming runs within the next 6 years (impossible date?).";
            return;
        }
        // Invariant, like the desktop Release build (InvariantGlobalization): a phone set to fa-IR or
        // th-TH would otherwise print a Persian / Buddhist calendar year and local day names under an
        // English description.
        var sb = new StringBuilder();
        foreach (var r in runs)
        {
            // Elapsed time via UTC: local wall-clock subtraction is an hour off across a DST change.
            var delta = r.ToUniversalTime() - now.ToUniversalTime();
            sb.AppendLine(string.Create(CultureInfo.InvariantCulture, $"{r:ddd  yyyy-MM-dd  HH:mm}   ({RelativeShort(delta)})"));
        }
        CronNextRuns = sb.ToString().TrimEnd();
    }

    private static string RelativeShort(TimeSpan d)
    {
        var inv = CultureInfo.InvariantCulture;
        if (d.TotalMinutes < 1) return "now";
        if (d.TotalHours < 1) return string.Create(inv, $"in {d.TotalMinutes:F0} min");
        if (d.TotalDays < 1) return string.Create(inv, $"in {(int)d.TotalHours} h {d.Minutes} min");   // whole hours: 1:54 is "1 h 54 min", not "2 h 54 min"
        if (d.TotalDays < 30) return string.Create(inv, $"in {d.TotalDays:F0} d");
        if (d.TotalDays < 365) return string.Create(inv, $"in {d.TotalDays / 30:F0} mo");
        return string.Create(inv, $"in {d.TotalDays / 365:F1} yr");
    }

    // Through CopyText, so a failed clipboard write shows "Copy failed: …" like every other COPY
    // instead of escaping the command into the global crash handler with no feedback.
    [RelayCommand]
    private System.Threading.Tasks.Task CopyCron() => CopyText(CronExpression);
}
