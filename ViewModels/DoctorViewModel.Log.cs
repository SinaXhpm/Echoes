using System.Globalization;
using System.Text;
using System.Threading.Tasks;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

// The run log: every step of the last run (each row's progress, each sub-step, and what only the log carries: every
// header sent, every probe, every resolver's whole answer) with its time from the start. Shown as text beside the
// checks, copied on its own, and the last part of the report. Secrets are masked where the lines are made.
public partial class DoctorViewModel
{
    // a run writes a few hundred lines; the cap keeps a pathological one (a huge header set) from growing without end
    private const int MaxLogChars = 400_000;

    private readonly StringBuilder _log = new();
    private bool _logFull;
    private string _logText = "";
    private bool _logRefreshPending;
    private int _logVersion, _logShownVersion;   // changes since the text was last handed to the view

    /// <summary>What the lower card shows: 0 the checks, 1 the run log, 2 the HTTP answers (DoctorViewModel.Response).
    /// The checks or the log are persisted (the answers are gone at the next start).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowLog), nameof(ShowChecks), nameof(ShowResponse), nameof(CopyText), nameof(CopyTip))]
    private int _viewIndex;

    public bool ShowLog => ViewIndex == 1;
    public bool HasLog => _log.Length > 0;
    /// <summary>The log as the view shows it: refreshed a moment after new lines, and only while it is on screen.</summary>
    public string LogText => _logText;

    public string CopyText => AppPlatform.IsMobile ? "Copy" : ShowLog ? "Copy log" : "Copy report";
    public string CopyTip => ShowLog
        ? "Copy the run log: every step with its time (cookies and tokens masked)"
        : "Copy the verdict, every check with its steps, and the run log (cookies and tokens masked)";

    partial void OnViewIndexChanged(int value)
    {
        if (value == 1) RefreshLog();
    }

    [RelayCommand]
    private async Task Copy()
    {
        if (_reportTarget == null) return;
        await ClipboardHelper.SetTextAsync(ShowLog ? _log.ToString() : BuildReport());
    }

    private void ClearLog()
    {
        _log.Clear();
        _logFull = false;
        _logVersion++;
        OnPropertyChanged(nameof(HasLog));
        RefreshLog();
    }

    // "  1.234s OK   TLS              ServerHello: received (TLS 1.3)  (95 ms)" — a line of the run itself has no state
    // or check ("  0.000s Echoes Doctor, run started …")
    private void AddLog(double atMs, DoctorCheck? check, string tag, string text)
    {
        if (_logFull) return;
        bool first = _log.Length == 0;
        if (_log.Length > MaxLogChars)
        {
            _log.Append("… (the log stops here: it is too long)\n");
            _logFull = true;
        }
        else
        {
            _log.Append((atMs / 1000).ToString("0.000", CultureInfo.InvariantCulture).PadLeft(7)).Append("s ");
            if (check is { } c) _log.Append(tag.PadRight(5)).Append(DoctorEngine.ReportTitle(c).PadRight(15));
            _log.Append(text).Append('\n');
        }
        _logVersion++;
        if (first) OnPropertyChanged(nameof(HasLog));
        ScheduleLogRefresh();
    }

    private void LogReport(double atMs, DoctorCheck check, DoctorState state, string detail, double? ms)
        => AddLog(atMs, check, DoctorVerdicts.Tag(state), detail + Time(ms));

    private void LogTrace(double atMs, DoctorCheck check, DoctorState state, string step, string detail, double? ms)
        => AddLog(atMs, check, DoctorVerdicts.Tag(state), $"  {step}: {detail}" + Time(ms));

    private static string Time(double? ms) => DoctorStepRow.FormatTime(ms) is { Length: > 0 } t ? $"  ({t})" : "";

    // The text is laid out again as a whole: at most every quarter second while lines arrive, and not at all while the
    // checks are on screen (it catches up when the log is shown).
    private void ScheduleLogRefresh()
    {
        if (!ShowLog || _logRefreshPending) return;
        _logRefreshPending = true;
        _ = Task.Delay(250).ContinueWith(_ => Dispatcher.UIThread.Post(() =>
        {
            _logRefreshPending = false;
            RefreshLog();
        }), TaskScheduler.Default);
    }

    private void RefreshLog()
    {
        if (_logShownVersion == _logVersion) return;
        _logShownVersion = _logVersion;
        _logText = _log.ToString();
        OnPropertyChanged(nameof(LogText));
    }
}
