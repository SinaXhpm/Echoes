using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

/// <summary>One check in the Doctor's list: its status glyph, title, one-line finding, time, and the granular sub-steps
/// (DNS records, TCP attempts, the TLS stages, HTTP stages) that show exactly where it got stuck.</summary>
public partial class DoctorStepRow : ObservableObject
{
    public DoctorStepRow(DoctorCheck check)
    {
        Check = check;
        Title = DoctorEngine.Title(check);
        _detail = DoctorEngine.About(check);
    }

    public DoctorCheck Check { get; }
    public string Title { get; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsOk), nameof(IsWarning), nameof(IsFail), nameof(IsSkipped), nameof(IsRunning),
                              nameof(IsPending), nameof(IsDone), nameof(StateText))]
    private DoctorState _state;

    [ObservableProperty] private string _detail;
    [ObservableProperty] private string _time = "";

    /// <summary>The fine-grained sub-steps under this check (empty until the check runs).</summary>
    public ObservableCollection<DoctorTraceRow> Trace { get; } = new();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowTrace))]
    private bool _isExpanded;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasTrace), nameof(ShowTrace), nameof(StepCountText))]
    private int _traceCount;

    public bool HasTrace => TraceCount > 0;
    public bool ShowTrace => IsExpanded && TraceCount > 0;
    /// <summary>"3 steps" badge, shown on the collapsed row so the user knows detail is there.</summary>
    public string StepCountText => TraceCount == 0 ? "" : TraceCount == 1 ? "1 step" : $"{TraceCount} steps";

    public bool IsOk => State == DoctorState.Ok;
    public bool IsWarning => State == DoctorState.Warning;
    public bool IsFail => State == DoctorState.Fail;
    public bool IsSkipped => State == DoctorState.Skipped;
    public bool IsRunning => State == DoctorState.Running;
    public bool IsPending => State == DoctorState.Pending;
    public bool IsDone => State is DoctorState.Ok or DoctorState.Warning or DoctorState.Fail or DoctorState.Skipped;

    /// <summary>Toggle the sub-steps open / closed (the row is clickable only when it has any).</summary>
    [RelayCommand]
    private void Toggle() { if (HasTrace) IsExpanded = !IsExpanded; }

    internal void AddTrace(DoctorTraceRow row)
    {
        Trace.Add(row);
        TraceCount = Trace.Count;
    }

    internal void ClearTrace()
    {
        Trace.Clear();
        TraceCount = 0;
        IsExpanded = false;
    }

    /// <summary>For screen readers and the tooltip.</summary>
    public string StateText => State switch
    {
        DoctorState.Ok => "OK",
        DoctorState.Warning => "Warning",
        DoctorState.Fail => "Problem",
        DoctorState.Skipped => "Skipped",
        DoctorState.Running => "Checking",
        _ => "Waiting",
    };

    public static string FormatTime(double? ms) => ms is not double v || v <= 0 ? ""
        : v >= 1000 ? (v / 1000).ToString("0.0", CultureInfo.InvariantCulture) + " s"
        : v < 10 ? v.ToString("0.#", CultureInfo.InvariantCulture) + " ms"
        : System.Math.Round(v).ToString(CultureInfo.InvariantCulture) + " ms";
}

/// <summary>One granular sub-step shown indented under a check: a short step label, a one-line finding, state and time.</summary>
public partial class DoctorTraceRow : ObservableObject
{
    public DoctorTraceRow(DoctorState state, string step, string detail, string time)
    {
        State = state;
        Step = step;
        Detail = detail;
        Time = time;
    }

    public DoctorState State { get; }
    public string Step { get; }
    public string Detail { get; }
    public string Time { get; }

    public bool IsOk => State == DoctorState.Ok;
    public bool IsWarning => State == DoctorState.Warning;
    public bool IsFail => State == DoctorState.Fail;
    public bool IsSkipped => State == DoctorState.Skipped;
}
