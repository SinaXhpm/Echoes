using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>
/// The two thresholds every monitor follows: failed checks in a row before it is marked down, successful checks in a
/// row before a down monitor is marked up again. One instance per <see cref="MonitorViewModel"/>, shared by its targets
/// (UI thread only), so a settings change reaches every row at once.
/// </summary>
public sealed class MonitorThresholds
{
    public int DownAfter { get; internal set; } = 2;
    public int UpAfter { get; internal set; } = 1;
}

/// <summary>
/// One monitored target: its parsed endpoint, its state machine (<see cref="MonitorStatusTracker"/>, "mark down after N
/// failures" / "mark up again after M successes"), the bounded history behind the sparkline / status bar, and the text
/// its row shows. UI thread only — a check round hands it a finished <see cref="CheckResult"/> (see
/// <see cref="MonitorViewModel"/>).
/// </summary>
public sealed partial class MonitorTarget : ObservableObject
{
    private static int _lastId;
    private readonly MonitorThresholds _rules;

    internal MonitorTarget(MonitorEndpoint endpoint, MonitorThresholds rules)
    {
        Endpoint = endpoint;
        _rules = rules;
        Id = Interlocked.Increment(ref _lastId);
    }

    internal int Id { get; }
    internal MonitorEndpoint Endpoint { get; }
    internal MonitorStatusTracker Tracker { get; } = new();

    // Scheduling (UI thread): checked out of turn on the next loop pass (just added / resumed); gone from the list.
    internal bool NeedsCheck;
    internal bool Removed;

    // Session response-time totals behind the average.
    internal double LatencySum;
    internal long LatencyCount;

    internal CheckResult? Last;
    internal DateTime? LastChecked;
    internal string? LastError;
    internal DateTime? LastErrorAt;

    public MonitorHistory History { get; } = new();
    public string Address => Endpoint.Address;
    public string DisplayName => Endpoint.DisplayName;

    /// <summary>Bumped after every recorded check: redraws the row's sparkline and status bar.</summary>
    [ObservableProperty] private int _historyVersion;

    [ObservableProperty] private string _stateText = "Pending";
    /// <summary>The status pill's tooltip: what the state means, with the threshold count while it isn't settled.</summary>
    [ObservableProperty] private string _stateTip = "Not checked yet";
    [ObservableProperty] private bool _isUp;
    [ObservableProperty] private bool _isDown;
    [ObservableProperty] private bool _isRetrying;
    [ObservableProperty] private bool _isRecovering;
    [ObservableProperty] private bool _isPaused;
    [ObservableProperty] private string _pauseTip = "Pause";

    // One chip per check that applies: "HTTP 200 · 84 ms", "TCP 443 · refused", "Ping · 9 ms".
    [ObservableProperty] private bool _showPing;
    [ObservableProperty] private bool _showTcp;
    [ObservableProperty] private bool _showHttp;
    [ObservableProperty] private string _pingText = "Ping · –";
    [ObservableProperty] private string _tcpText = string.Empty;
    [ObservableProperty] private string _httpText = string.Empty;
    [ObservableProperty] private bool _pingFailed;
    [ObservableProperty] private bool _tcpFailed;
    [ObservableProperty] private bool _httpFailed;

    // Phone rows: one line instead of the chips (the failing check, else the response).
    [ObservableProperty] private string _summaryText = "Not checked yet";
    [ObservableProperty] private bool _summaryFailed;

    [ObservableProperty] private string _uptimeText = "–";
    [ObservableProperty] private string _lastCheckedText = string.Empty;

    /// <summary>Shows / hides the chips for the enabled checks and refreshes their text.</summary>
    internal void ApplyChecks(MonitorCheckOptions o)
    {
        o = Eff(o);
        ShowPing = o.Ping;
        ShowTcp = o.Tcp;
        ShowHttp = o.Http && Endpoint.HasHttp;
        RefreshChips(o);
        RefreshState(o);
    }

    /// <summary>Takes one finished check (UI thread).</summary>
    internal void Apply(CheckResult r, DateTime now, MonitorCheckOptions o)
    {
        o = Eff(o);
        Last = r;
        LastChecked = now;
        double ms = r.ResponseMs;
        if (!double.IsNaN(ms)) { LatencySum += ms; LatencyCount++; }
        if (!r.Ok) { LastError = r.Reason(Endpoint); LastErrorAt = now; }

        // Amber = not settled yet: failing below "mark down after", or answering below "mark up again after".
        var beat = Tracker.State switch
        {
            MonitorState.Up => MonitorBeat.Up,
            MonitorState.Down => r.Ok ? MonitorBeat.Pending : MonitorBeat.Down,
            _ => r.Ok ? MonitorBeat.Up : MonitorBeat.Pending,
        };
        History.Add(beat, ms);
        HistoryVersion++;

        UptimeText = MonitorFormat.Percent(Tracker.SuccessfulChecks, Tracker.TotalChecks);
        RefreshChips(o);
        RefreshState(o);
        RefreshAge(now);
    }

    internal void RefreshState(MonitorCheckOptions o)
    {
        o = Eff(o);
        var tr = Tracker;
        var s = tr.State;
        IsUp = s == MonitorState.Up;
        IsDown = s == MonitorState.Down;
        IsRetrying = tr.IsRetrying;
        IsRecovering = tr.IsRecovering;
        IsPaused = s == MonitorState.Paused;
        // A warning (certificate / domain expiring, DNS changed) shows on an up monitor in amber; it isn't downtime.
        IsWarning = IsUp && Warnings.Count > 0;
        IsGreen = IsUp && !IsWarning;
        IsAmber = IsRetrying || IsWarning;
        PauseTip = IsPaused ? "Resume checks" : "Pause checks";
        StateText = s switch
        {
            MonitorState.Up => IsWarning ? "Warning" : "Up",
            MonitorState.Down => "Down",
            MonitorState.Paused => "Paused",
            _ => "Pending",
        };
        int down = Math.Clamp(_rules.DownAfter, 1, MonitorStatusTracker.MaxDownAfter);
        int up = Math.Clamp(_rules.UpAfter, 1, MonitorStatusTracker.MaxUpAfter);
        StateTip = s switch
        {
            MonitorState.Up when IsWarning => "Up, with a warning: " + WarningSummary(),
            MonitorState.Up => "Up: every enabled check passes",
            MonitorState.Down when tr.IsRecovering =>
                $"Down, answering again: {tr.ConsecutiveSuccesses} of {up} successful checks in a row before it's marked up",
            MonitorState.Down => down == 1 ? "Down: the last check failed" : $"Down: it failed {down} checks in a row",
            MonitorState.Paused => "Paused: not checked",
            _ when tr.IsRetrying => $"Failing: {tr.ConsecutiveFailures} of {down} failed checks in a row before it's marked down",
            _ => "Not checked yet",
        };

        SummaryWarn = false;
        if (IsPaused) { SummaryText = "Paused"; SummaryFailed = false; }
        else if (!o.AppliesTo(Endpoint))
        {
            SummaryText = $"HTTP doesn't apply to port {Endpoint.Port} — turn on TCP or ping";
            SummaryFailed = false;
        }
        else if (Last is not { } r) { SummaryText = "Not checked yet"; SummaryFailed = false; }
        else if (!r.Ok)
        {
            // Phone rows: the count toward "mark down after" while it is still pending.
            string reason = r.Reason(Endpoint) ?? "Failed";
            SummaryText = tr.IsRetrying ? $"Failing {tr.ConsecutiveFailures}/{down} · {reason}" : reason;
            SummaryFailed = true;
        }
        else if (IsWarning)
        {
            SummaryText = WarningSummary();
            SummaryFailed = false;
            SummaryWarn = true;
        }
        else
        {
            string answer = r.Http.Ran ? $"{Endpoint.HttpLabel} {r.Http.Code} · {MonitorFormat.Ms(r.Http.Ms)}"
                : r.Tcp.Ran ? $"TCP {Endpoint.Port} · {MonitorFormat.Ms(r.Tcp.Ms)}"
                : $"Ping · {MonitorFormat.Ms(r.Ping.Ms)}";
            SummaryText = tr.IsRecovering ? $"Recovering {tr.ConsecutiveSuccesses}/{up} · {answer}" : answer;
            SummaryFailed = false;
        }
    }

    /// <summary>The first warning, with how many more there are.</summary>
    internal string WarningSummary()
        => Warnings.Count == 0 ? string.Empty
         : Warnings.Count == 1 ? Warnings[0].Text
         : $"{Warnings[0].Text} (+{Warnings.Count - 1} more)";

    private void RefreshChips(MonitorCheckOptions o)
    {
        var r = Last;
        (PingText, PingFailed) = Chip("Ping", r?.Ping, o.Ping);
        (TcpText, TcpFailed) = Chip($"TCP {Endpoint.Port}", r?.Tcp, o.Tcp);
        if (Endpoint.HasHttp)
        {
            var http = r?.Http;
            if (http is { Ran: true, Keyword: true } k)
                (HttpText, HttpFailed) = ($"{Endpoint.HttpLabel} {k.Code} · keyword", true);
            else if (http is { Ran: true } h && h.Code > 0)
                (HttpText, HttpFailed) = ($"{Endpoint.HttpLabel} {h.Code} · {MonitorFormat.Ms(h.Ms)}", !h.Ok);
            else
                (HttpText, HttpFailed) = Chip(Endpoint.HttpLabel, http, o.Http);
        }
    }

    private static (string, bool) Chip(string label, ProbeResult? p, bool enabled)
    {
        if (!enabled || p is not { Ran: true } r) return ($"{label} · –", false);
        return r.Ok ? ($"{label} · {MonitorFormat.Ms(r.Ms)}", false) : ($"{label} · {r.Error}", true);
    }

    /// <summary>The "8s" age in the Checked column; only raises a change when the text does.</summary>
    internal void RefreshAge(DateTime now)
        => LastCheckedText = LastChecked is { } t ? MonitorFormat.ShortAge(now - t) : string.Empty;
}

public enum MonitorEventKind
{
    Down, Up, Paused, Resumed, Started, Stopped,
    /// <summary>A new warning: certificate / domain expiring soon, DNS answers changed.</summary>
    Warning,
    /// <summary>A warning went away (renewed, answers accepted / back).</summary>
    Resolved,
    /// <summary>About the Telegram alerts themselves (a send that failed, or went through after retrying).</summary>
    Telegram,
}

/// <summary>One line of the events log: a state change of a monitor, or monitoring starting / stopping.</summary>
public sealed class MonitorEvent
{
    public MonitorEvent(DateTime time, MonitorEventKind kind, string target, string message, int targetId, bool failure = false)
    {
        Time = time;
        Kind = kind;
        Target = target;
        Message = message;
        TargetId = targetId;
        IsFailure = failure;
        TimeText = MonitorFormat.Clock(time, DateTime.Now);
        KindText = kind switch
        {
            MonitorEventKind.Down => "Down",
            MonitorEventKind.Up => "Up",
            MonitorEventKind.Paused => "Paused",
            MonitorEventKind.Resumed => "Resumed",
            MonitorEventKind.Started => "Started",
            MonitorEventKind.Warning => "Warning",
            MonitorEventKind.Resolved => "Resolved",
            MonitorEventKind.Telegram => "Telegram",
            _ => "Stopped",
        };
    }

    public DateTime Time { get; }
    internal MonitorEventKind Kind { get; }
    internal int TargetId { get; }
    /// <summary>A Telegram send that failed.</summary>
    internal bool IsFailure { get; }
    public string TimeText { get; }
    public string KindText { get; }
    public string Target { get; }
    public string Message { get; }
    public bool IsDown => Kind == MonitorEventKind.Down;
    public bool IsUp => Kind == MonitorEventKind.Up;
    public bool IsWarning => Kind == MonitorEventKind.Warning;
    /// <summary>Pill colors: red for down and failed alerts, green for up and resolved warnings.</summary>
    public bool IsDanger => Kind == MonitorEventKind.Down || (Kind == MonitorEventKind.Telegram && IsFailure);
    public bool IsGood => Kind is MonitorEventKind.Up or MonitorEventKind.Resolved;
}

/// <summary>The detail panel's text for the selected monitor (refreshed in place after each round and every second).</summary>
public sealed partial class MonitorDetail : ObservableObject
{
    [ObservableProperty] private string _title = string.Empty;
    [ObservableProperty] private string _address = string.Empty;
    [ObservableProperty] private string _stateText = string.Empty;
    [ObservableProperty] private string _stateTip = string.Empty;
    [ObservableProperty] private bool _isUp;
    [ObservableProperty] private bool _isDown;
    [ObservableProperty] private bool _isRetrying;
    [ObservableProperty] private bool _isGreen;
    [ObservableProperty] private bool _isAmber;
    /// <summary>Failing below "mark down after", or answering again below "mark up again after": the state line is amber.</summary>
    [ObservableProperty] private bool _isUnsettled;
    /// <summary>The state line in amber: not settled yet, or up with a warning.</summary>
    [ObservableProperty] private bool _stateLineAmber;
    [ObservableProperty] private bool _isPaused;
    [ObservableProperty] private string _stateLine = string.Empty;
    [ObservableProperty] private string _pauseText = "Pause";

    [ObservableProperty] private string _uptime = "–";
    [ObservableProperty] private string _checks = "0";
    [ObservableProperty] private string _failures = "0";
    [ObservableProperty] private string _min = "–";
    [ObservableProperty] private string _avg = "–";
    [ObservableProperty] private string _max = "–";
    [ObservableProperty] private string _p95 = "–";
    [ObservableProperty] private string _windowText = "Last checks";
    [ObservableProperty] private string _responseNow = "–";
    [ObservableProperty] private string _lastChecked = "–";

    [ObservableProperty] private bool _showPing;
    [ObservableProperty] private bool _showTcp;
    [ObservableProperty] private bool _showHttp;
    [ObservableProperty] private string _tcpLabel = "TCP";
    [ObservableProperty] private string _httpLabel = "HTTP";
    [ObservableProperty] private string _pingResult = "–";
    [ObservableProperty] private string _tcpResult = "–";
    [ObservableProperty] private string _httpResult = "–";
    [ObservableProperty] private bool _pingFailed;
    [ObservableProperty] private bool _tcpFailed;
    [ObservableProperty] private bool _httpFailed;
    [ObservableProperty] private string _lastError = "None this session";
    [ObservableProperty] private bool _hasLastError;

    internal void Update(MonitorTarget t, DateTime now, MonitorCheckOptions o, MonitorThresholds rules)
    {
        var tr = t.Tracker;
        Title = t.DisplayName;
        Address = t.Address;
        StateText = t.StateText;
        StateTip = t.StateTip;
        IsUp = t.IsUp;
        IsDown = t.IsDown;
        IsRetrying = t.IsRetrying;
        IsGreen = t.IsGreen;
        IsAmber = t.IsAmber;
        IsUnsettled = t.IsRetrying || t.IsRecovering;
        StateLineAmber = IsUnsettled || t.IsWarning;
        IsPaused = t.IsPaused;
        PauseText = t.IsPaused ? "Resume" : "Pause";
        RefreshTimes(t, now, rules);

        Uptime = MonitorFormat.Percent(tr.SuccessfulChecks, tr.TotalChecks);
        Checks = MonitorFormat.Count(tr.TotalChecks);
        Failures = MonitorFormat.Count(tr.FailedChecks);
        var stats = t.History.GetLatencyStats();
        Min = MonitorFormat.Ms(stats.Min);
        Avg = MonitorFormat.Ms(stats.Avg);
        Max = MonitorFormat.Ms(stats.Max);
        P95 = MonitorFormat.Ms(stats.P95);
        WindowText = t.History.Count == 0 ? "No checks yet" : $"Last {t.History.Count} check{(t.History.Count == 1 ? "" : "s")}";
        ResponseNow = t.Last is { } last ? MonitorFormat.Ms(last.ResponseMs) : "–";

        var ep = t.Endpoint;
        var r = t.Last;
        o = t.Eff(o);
        ShowPing = o.Ping;
        ShowTcp = o.Tcp;
        ShowHttp = o.Http && ep.HasHttp;
        TcpLabel = $"TCP {ep.Port}";
        HttpLabel = ep.HttpLabel;
        (PingResult, PingFailed) = Line(r?.Ping, r?.Address);
        (TcpResult, TcpFailed) = Line(r?.Tcp, null);
        (HttpResult, HttpFailed) = r?.Http is { Ran: true, Code: > 0 } h
            ? ($"{h.Code}{(string.IsNullOrEmpty(h.Error) ? "" : " " + h.Error)} · {MonitorFormat.Ms(h.Ms)}", !h.Ok)
            : Line(r?.Http, null);
        UpdateExtras(t);

        HasLastError = t.LastError is not null;
        LastError = t.LastError is { } e && t.LastErrorAt is { } at ? $"{e} · {MonitorFormat.Clock(at, now)}" : "None this session";
    }

    /// <summary>Durations and clock times only (the 1-second tick).</summary>
    internal void RefreshTimes(MonitorTarget t, DateTime now, MonitorThresholds rules)
    {
        var tr = t.Tracker;
        int down = Math.Clamp(rules.DownAfter, 1, MonitorStatusTracker.MaxDownAfter);
        int up = Math.Clamp(rules.UpAfter, 1, MonitorStatusTracker.MaxUpAfter);
        StateLine = tr.State switch
        {
            MonitorState.Up when tr.UpSince is { } since =>
                $"Up for {MonitorFormat.Duration(now - since)} · since {MonitorFormat.Clock(since, now)}",
            MonitorState.Down when tr.IsRecovering && tr.DownSince is { } since =>
                $"Answering again — {tr.ConsecutiveSuccesses} of {up} successful checks before it counts as up · down {MonitorFormat.Duration(now - since)}",
            MonitorState.Down when tr.DownSince is { } since =>
                $"Down for {MonitorFormat.Duration(now - since)} · since {MonitorFormat.Clock(since, now)}",
            MonitorState.Paused when tr.PausedAt is { } at => $"Paused at {MonitorFormat.Clock(at, now)}",
            _ when tr.IsRetrying => $"Failing — {tr.ConsecutiveFailures} of {down} failed checks before it counts as down",
            _ => "Not checked yet",
        };
        LastChecked = t.LastChecked is { } c ? $"{MonitorFormat.Clock(c, now)} ({MonitorFormat.Age(now - c)})" : "–";
    }

    private static (string, bool) Line(ProbeResult? p, string? address)
    {
        if (p is not { Ran: true } r) return ("–", false);
        if (!r.Ok) return (r.Error ?? "failed", true);
        return (address is null ? MonitorFormat.Ms(r.Ms) : $"{MonitorFormat.Ms(r.Ms)} · {address}", false);
    }
}

/// <summary>
/// Uptime monitor in the spirit of Uptime Kuma / UptimeRobot: a persistent list of targets, each checked with ping,
/// a TCP connect and (where a web server is plausible) an HTTP GET on a fixed cadence; flapping protection both ways
/// ("mark down after N failed checks in a row", "mark up again after M successful checks"); session uptime,
/// response-time history, an events log, distinct sounds for down, back up and a new warning at one alert volume, and
/// starting by itself — with Echoes, at sign-in, with the phone (MonitorViewModel.Startup.cs). Everything — the list, each
/// monitor's own rules, every setting, the Telegram alerts — is saved in the profile as it changes.
///
/// <para>Threading: every round collects its due targets on the UI thread, runs all their checks on the thread pool
/// (<c>MonitorProbe.CheckAllAsync</c>), then applies the results back on the UI thread in ONE batch — never a
/// UI update per check. History is a fixed ring per target (<see cref="MonitorHistory"/>), the events log is capped.</para>
/// </summary>
public sealed partial class MonitorViewModel : ObservableObject
{
    public const int MaxTargets = 256;            // cap the watch list so a big paste can't fan out unbounded
    private const int MaxConcurrentChecks = 50;   // per-round concurrency (each target still does ping + tcp + http)
    private const int MaxEvents = 500;
    private const int RecentEventsShown = 6;
    public const int MinInterval = 1, MaxInterval = 86_400;   // seconds
    private const int DefaultInterval = 5, DefaultTimeout = 3000, DefaultDownAfter = 2, DefaultUpAfter = 1;
    private const string ExampleTargets = "google.com\n1.1.1.1:53\nhttps://api.ipify.org";

    // Profile keys (plain settings: nothing secret is stored — URL credentials are stripped at parse time).
    // monitor.sound is the old single sound switch: read as the default of both sound switches, removed once they're saved.
    private const string KeyTargets = "monitor.targets", KeyPaused = "monitor.paused", KeyPing = "monitor.ping",
        KeyTcp = "monitor.tcp", KeyHttp = "monitor.http", KeyInterval = "monitor.interval", KeyTimeout = "monitor.timeout",
        KeyDownAfter = "monitor.downAfter", KeyUpAfter = "monitor.upAfter", KeySound = "monitor.sound",
        KeySoundDown = "monitor.soundDown", KeySoundUp = "monitor.soundUp", KeySoundWarning = "monitor.soundWarn",
        KeyVolume = SoundHelper.VolumeKey;

    // Per-request timeouts come from a linked token (see MonitorProbe), so the client itself has none.
    private readonly HttpClient _http = MonitorProbe.CreateHttpClient();
    private readonly Dictionary<string, MonitorTarget> _byKey = new(StringComparer.Ordinal);
    private readonly MonitorThresholds _rules = new();
    private readonly bool _loaded;
    private CancellationTokenSource? _cts;        // the current run; null when stopped
    private CancellationTokenSource? _sleepCts;   // the current run's wait between rounds (cancelled = wake up early)
    private long _nextRoundAt;                    // Environment.TickCount64 of the next full round
    private long _roundStartedAt;
    private bool _hasRun;
    private (MonitorTarget Target, int Index)? _lastRemoved;
    private DateTime? _addMessageExpires;

    public ObservableCollection<MonitorTarget> Targets { get; } = new();
    public ObservableCollection<MonitorEvent> Events { get; } = new();
    /// <summary>The selected monitor's latest events, for the detail panel.</summary>
    public ObservableCollection<MonitorEvent> SelectedEvents { get; } = new();
    public MonitorDetail Detail { get; } = new();

    // ---- settings (persisted) ----
    [ObservableProperty] private bool _checkPing = true;
    [ObservableProperty] private bool _checkTcp = true;
    [ObservableProperty] private bool _checkHttp = true;
    [ObservableProperty] private int _interval = DefaultInterval;     // seconds between rounds
    [ObservableProperty] private int _timeoutMs = DefaultTimeout;     // per check (ping / TCP connect / HTTP)
    [ObservableProperty] private int _downAfter = DefaultDownAfter;   // failed checks in a row before a monitor is down
    [ObservableProperty] private int _upAfter = DefaultUpAfter;       // successful checks in a row before it is up again
    [ObservableProperty] private bool _soundOnDown = true;            // the "down" sound when a monitor goes down
    [ObservableProperty] private bool _soundOnUp = true;              // the "up" sound when it comes back up
    [ObservableProperty] private bool _soundOnWarning = true;         // the soft double tap for a new warning
    /// <summary>The alert volume, 0–100 % (0 = no sound). Shared with every Echoes alert sound (SoundHelper).</summary>
    [ObservableProperty] private int _volume = SoundHelper.DefaultVolume;

    // ---- run state ----
    [ObservableProperty] private bool _isMonitoring;
    [ObservableProperty] private string _runStateText = "Not running";
    [ObservableProperty] private string _lastRoundText = "No round has run yet";
    [ObservableProperty] private string _notice = string.Empty;   // inline problem with Start (no monitors, no checks)

    // ---- summary strip ----
    [ObservableProperty] private int _upCount;
    [ObservableProperty] private int _downCount;
    [ObservableProperty] private int _pendingCount;
    [ObservableProperty] private int _retryingCount;   // the pending ones that are failing (not just unchecked)
    [ObservableProperty] private int _pausedCount;
    [ObservableProperty] private int _warningCount;    // up, with a warning (not counted in UpCount)
    [ObservableProperty] private string _uptimeText = "–";
    [ObservableProperty] private string _avgResponseText = "–";

    // ---- adding / editing ----
    [ObservableProperty] private string _newTarget = string.Empty;
    [ObservableProperty] private string _addMessage = string.Empty;
    [ObservableProperty] private bool _addMessageIsError;
    [ObservableProperty] private bool _canUndoRemove;
    [ObservableProperty] private bool _isEditingList;
    [ObservableProperty] private string _editListText = string.Empty;
    [ObservableProperty] private string _editMessage = string.Empty;
    [ObservableProperty] private bool _isSettingsOpen;

    [ObservableProperty] private MonitorTarget? _selectedTarget;

    public int TargetCount => Targets.Count;
    public bool HasTargets => Targets.Count > 0;
    public bool ShowList => Targets.Count > 0 && !IsEditingList;
    public bool ShowEmpty => Targets.Count == 0 && !IsEditingList;
    public bool HasEvents => Events.Count > 0;
    public bool HasSelectedEvents => SelectedEvents.Count > 0;
    public bool HasSelection => SelectedTarget is not null;
    public bool HasNotice => Notice.Length > 0;
    public bool HasAddMessage => AddMessage.Length > 0;
    public bool HasEditMessage => EditMessage.Length > 0;
    public bool HasUp => UpCount > 0;
    public bool HasDown => DownCount > 0;
    public bool HasPending => PendingCount > 0;
    public bool HasRetrying => RetryingCount > 0;
    public bool HasPaused => PausedCount > 0;
    public bool HasWarnings => WarningCount > 0;
    public bool NoChecksEnabled => !CheckPing && !CheckTcp && !CheckHttp;

    public MonitorViewModel()
    {
        // _loaded is still false: setting these doesn't write them straight back.
        var ps = ProfileService.Instance;
        CheckPing = ps.GetBool(KeyPing, true);
        CheckTcp = ps.GetBool(KeyTcp, true);
        CheckHttp = ps.GetBool(KeyHttp, true);
        Interval = Math.Clamp(ps.GetInt(KeyInterval, DefaultInterval), MinInterval, MaxInterval);
        TimeoutMs = Math.Clamp(ps.GetInt(KeyTimeout, DefaultTimeout), MonitorProbe.MinTimeoutMs, MonitorProbe.MaxTimeoutMs);
        DownAfter = Math.Clamp(ps.GetInt(KeyDownAfter, DefaultDownAfter), 1, MonitorStatusTracker.MaxDownAfter);
        UpAfter = Math.Clamp(ps.GetInt(KeyUpAfter, DefaultUpAfter), 1, MonitorStatusTracker.MaxUpAfter);
        _rules.DownAfter = DownThreshold;
        _rules.UpAfter = UpThreshold;
        // Before the two switches existed, one "Sound alert" covered both: it is their default until they're saved.
        bool oldSound = ps.GetBool(KeySound, true);
        SoundOnDown = ps.GetBool(KeySoundDown, oldSound);
        SoundOnUp = ps.GetBool(KeySoundUp, oldSound);
        SoundOnWarning = ps.GetBool(KeySoundWarning, true);
        Volume = Math.Clamp(ps.GetInt(KeyVolume, SoundHelper.DefaultVolume), 0, 100);
        LoadStartupSettings(ps);

        // The saved list; on the first run of this version, the last list the old Setup tab started.
        string source = ps.GetSetting(KeyTargets) ?? HistoryService.Instance.Last("monitor.addresses") ?? string.Empty;
        var paused = new HashSet<string>((ps.GetSetting(KeyPaused) ?? string.Empty)
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries), StringComparer.Ordinal);
        var now = DateTime.Now;
        var o = Options;
        LoadExtraCache(ps);
        var targetOptions = ReadTargetOptions(ps.GetSetting(KeyTargetOptions));
        foreach (var entry in SplitEntries(source))
        {
            if (Targets.Count >= MaxTargets) break;
            if (!MonitorEndpoint.TryParse(entry, out var ep, out _) || _byKey.ContainsKey(ep.Key)) continue;
            var t = new MonitorTarget(ep, _rules);
            if (paused.Contains(ep.Address)) t.Tracker.Pause(now);
            if (targetOptions.TryGetValue(ep.Address, out var opts)) ApplyTargetOptions(t, opts);
            LinkExtras(t);
            t.ApplyChecks(o);
            _byKey[ep.Key] = t;
            Targets.Add(t);
        }

        Targets.CollectionChanged += (_, _) =>
        {
            OnPropertyChanged(nameof(TargetCount));
            OnPropertyChanged(nameof(HasTargets));
            OnPropertyChanged(nameof(ShowList));
            OnPropertyChanged(nameof(ShowEmpty));
        };
        Events.CollectionChanged += (_, _) => OnPropertyChanged(nameof(HasEvents));
        SelectedEvents.CollectionChanged += (_, _) => OnPropertyChanged(nameof(HasSelectedEvents));
        SyncOpenAtLogin();   // what is really registered for sign-in (still !_loaded: nothing is written back)
        LoadTelegramSettings(ps);
        _loaded = true;
        UpdateSummary();
    }

    private MonitorCheckOptions Options =>
        new(CheckPing, CheckTcp, CheckHttp, Math.Clamp(TimeoutMs, MonitorProbe.MinTimeoutMs, MonitorProbe.MaxTimeoutMs));

    // Clamped so a huge value can't overflow the delay (an interval over ~24.8 days used to wrap int into a negative
    // Task.Delay that ended the run after its first round).
    private int IntervalSeconds => Math.Clamp(Interval, MinInterval, MaxInterval);
    private int DownThreshold => Math.Clamp(DownAfter, 1, MonitorStatusTracker.MaxDownAfter);
    private int UpThreshold => Math.Clamp(UpAfter, 1, MonitorStatusTracker.MaxUpAfter);

    /// <summary>The thresholds part of event texts: "down after 3 failures", plus "up after 2 successes" when set.</summary>
    private string RulesText()
    {
        int down = DownThreshold, up = UpThreshold;
        string text = $"down after {down} failure{(down == 1 ? "" : "s")}";
        return up > 1 ? $"{text} · up after {up} successes" : text;
    }

    // ================================================================ start / stop

    // Synchronous on purpose: it stays enabled while a run is in flight, so Stop is always clickable.
    [RelayCommand]
    private void ToggleMonitor()
    {
        CancelPendingLaunch();   // a click decides, not a start still waiting for the network
        if (IsMonitoring) StopMonitoring();
        else StartMonitoring();
    }

    /// <summary>Starts a run (no-op while running). Problems are reported inline in <see cref="Notice"/>.</summary>
    public void StartMonitoring() => StartMonitoring(atLaunch: false);

    private void StartMonitoring(bool atLaunch, string launchNote = " · started with Echoes")
    {
        if (IsMonitoring) return;
        if (Targets.Count == 0) { Notice = "Add at least one monitor first."; return; }
        if (NoChecksEnabled)
        {
            Notice = "Turn on at least one check — ping, TCP or HTTP — in settings.";
            IsSettingsOpen = true;
            return;
        }
        Notice = string.Empty;

        // The History tab keeps listing what was monitored (bounded there to one profile entry's size).
        HistoryService.Instance.Add("monitor.addresses", string.Join("\n", Targets.Select(t => t.Address)));

        var o = Options;
        foreach (var t in Targets)
        {
            t.Tracker.BeginRun();
            t.NeedsCheck = false;
            t.RefreshState(o);
        }
        BeginExtrasRun();
        // Local CTS/token, never the field, inside the loop: after Stop → quick Start the old run may still be unwinding
        // (e.g. stuck in a DNS lookup on Android). Reading _cts it would pick up — and later dispose/null — the new run's
        // CTS, or keep looping on the new token and probe every target twice.
        var cts = new CancellationTokenSource();
        _cts = cts;
        _hasRun = true;
        _nextRoundAt = Environment.TickCount64;   // first round right away
        IsMonitoring = true;
        int active = Targets.Count(t => !t.IsPaused);
        AddEvent(null, MonitorEventKind.Started,
            $"{active} monitor{(active == 1 ? "" : "s")} · every {MonitorFormat.Interval(IntervalSeconds)} · {RulesText()}"
            + (atLaunch ? launchNote : ""));
        UpdateSummary();
        RefreshDetail();
        _ = RunAsync(cts);
    }

    public void StopMonitoring()
    {
        if (!IsMonitoring) return;
        _cts?.Cancel();
        _cts = null;   // the stopped run unwinds on its own CTS; it must not touch a newer run's state
        IsMonitoring = false;
        AddEvent(null, MonitorEventKind.Stopped, "Monitoring stopped");
        UpdateSummary();
    }

    private async Task RunAsync(CancellationTokenSource cts)
    {
        var token = cts.Token;
        // Keep the process alive while monitoring so an Android background switch doesn't silently freeze the checks
        // (no-op on desktop).
        BackgroundGuard.Acquire(BackgroundReason);
        try
        {
            while (!token.IsCancellationRequested)
            {
                // The slow checks (certificate, domain, DNS watch) run beside the rounds, never inside one — except that a
                // certificate never judged before gets (at most) the time of one check to finish first.
                if (ScheduleExtraChecks(token) is { Count: > 0 } firstCerts)
                    await Task.WhenAny(Task.WhenAll(firstCerts), Task.Delay(Math.Clamp(TimeoutMs, 1000, 10_000), token));
                var due = CollectDue();
                if (due.Count > 0)
                {
                    var specs = new MonitorProbeSpec[due.Count];
                    for (int i = 0; i < due.Count; i++) specs[i] = SpecFor(due[i]);
                    var options = Options;
                    var sw = Stopwatch.StartNew();
                    // All network work on the thread pool; this method resumes on the UI thread afterwards.
                    var results = await Task.Run(() => MonitorProbe.CheckAllAsync(specs, options, _http, MaxConcurrentChecks, token), token);
                    // Stop mid-round: the checks answer the cancellation with failures rather than throwing. Don't record
                    // that as an outage (false failures, an uptime dip and a "down" alert for a target that was up).
                    if (token.IsCancellationRequested) break;
                    ApplyRound(due, results, options, sw.Elapsed);
                }
                await SleepAsync(token);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            CrashLog.Write("Monitor.Run", ex);
            if (ReferenceEquals(_cts, cts)) Notice = "Monitoring stopped after an internal error: " + ex.Message;
        }
        finally
        {
            // Only the run that still owns _cts resets the shared state (a superseded run just cleans up its own).
            if (ReferenceEquals(_cts, cts))
            {
                _cts = null;
                IsMonitoring = false;
                UpdateSummary();
            }
            cts.Dispose();
            BackgroundGuard.Release();
        }
    }

    // UI thread. A full round when the cadence says so; otherwise just the monitors added / resumed meanwhile.
    private List<MonitorTarget> CollectDue()
    {
        long now = Environment.TickCount64;
        bool fullRound = now >= _nextRoundAt;
        if (fullRound)
        {
            _roundStartedAt = now;
            _nextRoundAt = now + IntervalSeconds * 1000L;
        }
        var o = Options;
        var due = new List<MonitorTarget>();
        foreach (var t in Targets)
        {
            bool flagged = t.NeedsCheck;
            t.NeedsCheck = false;   // cleared even when skipped, or the wait below would never sleep
            if (t.IsPaused || !t.Eff(o).AppliesTo(t.Endpoint)) continue;
            if (fullRound || flagged) due.Add(t);
        }
        return due;
    }

    // Waits for the next round; a new / resumed monitor or an interval change wakes it early.
    private async Task SleepAsync(CancellationToken token)
    {
        long wait = _nextRoundAt - Environment.TickCount64;
        if (wait <= 0 || Targets.Any(t => t.NeedsCheck && !t.IsPaused)) return;
        using var sleep = CancellationTokenSource.CreateLinkedTokenSource(token);
        _sleepCts = sleep;
        try { await Task.Delay(TimeSpan.FromMilliseconds(wait), sleep.Token); }
        catch (OperationCanceledException) when (!token.IsCancellationRequested) { }   // woken up early
        finally { if (ReferenceEquals(_sleepCts, sleep)) _sleepCts = null; }
    }

    private void Wake()
    {
        try { _sleepCts?.Cancel(); }
        catch (ObjectDisposedException) { }
    }

    /// <summary>UI-thread time the last round's results took to apply (diagnostics).</summary>
    internal double LastApplyMs { get; private set; }
    internal int RoundsApplied { get; private set; }

    // UI thread, once per round: every result, the summary and the detail panel in one go.
    private void ApplyRound(List<MonitorTarget> due, CheckResult[] results, MonitorCheckOptions o, TimeSpan elapsed)
    {
        long applyStart = Stopwatch.GetTimestamp();
        var now = DateTime.Now;
        int downThreshold = DownThreshold, upThreshold = UpThreshold;
        bool anyDown = false, anyUp = false, anyWarning = false;
        for (int i = 0; i < due.Count; i++)
        {
            var t = due[i];
            var r = results[i];
            // Removed or paused while its check was in flight; or nothing applied.
            if (t.Removed || t.IsPaused || r is null || !r.AnyRan) continue;

            if (r.CertRecheck) RecheckCertSoon(t);
            var change = t.Tracker.Record(r.Ok, now, downThreshold, upThreshold);
            if (RefreshWarnings(t, raiseEvents: true)) anyWarning = true;
            t.Apply(r, now, o);
            switch (change)
            {
                case MonitorTransition.WentDown:
                    anyDown = true;
                    string reason = r.Reason(t.Endpoint) ?? "Check failed";
                    AddEvent(t, MonitorEventKind.Down,
                        downThreshold > 1 ? $"{reason} · down after {downThreshold} failures in a row" : reason);
                    Alert(MonitorAlertKind.Down, t, reason, t.Tracker.DownSince ?? now);
                    break;
                case MonitorTransition.Recovered:
                    anyUp = true;
                    string back = t.Tracker.LastDowntime is { } d ? $"Back up after {MonitorFormat.Duration(d)} down" : "Back up";
                    AddEvent(t, MonitorEventKind.Up,
                        upThreshold > 1 ? $"{back} · up again after {upThreshold} successes in a row" : back);
                    Alert(MonitorAlertKind.Up, t, back, now);
                    break;
            }
        }

        // One alert per round at most (and SoundHelper throttles across rounds): a network drop flips every target at once.
        PlayAlert(anyDown, anyUp, anyWarning);

        LastRoundText = $"Last round: {due.Count} monitor{(due.Count == 1 ? "" : "s")} checked in {MonitorFormat.Ms(elapsed.TotalMilliseconds)} at {MonitorFormat.Clock(now, now)}";
        UpdateSummary();
        RefreshDetail();
        RoundsApplied++;
        LastApplyMs = Stopwatch.GetElapsedTime(applyStart).TotalMilliseconds;
    }

    /// <summary>
    /// The one sound of a round: when monitors went down and others came back in the same round, the down sound wins
    /// (something needs attention). With the down sound switched off, monitors that came back still get the up sound.
    /// </summary>
    internal static AlertTone? PickAlertTone(bool anyWentDown, bool anyCameBack, bool soundOnDown, bool soundOnUp)
        => PickAlertTone(anyWentDown, anyCameBack, false, soundOnDown, soundOnUp, false);

    /// <summary>
    /// The same with warnings (a certificate / domain expiring, DNS answers changed): down first, then a new warning
    /// (it wants a look), then back up. A switched-off sound gives way to the next one that applies.
    /// </summary>
    internal static AlertTone? PickAlertTone(bool anyWentDown, bool anyCameBack, bool anyWarning,
                                             bool soundOnDown, bool soundOnUp, bool soundOnWarning)
        => anyWentDown && soundOnDown ? AlertTone.Down
         : anyWarning && soundOnWarning ? AlertTone.Warning
         : anyCameBack && soundOnUp ? AlertTone.Up
         : null;

    /// <summary>Tests: the last sound a round / slow check asked for, and how many were asked for (played unless muted).</summary>
    internal AlertTone? LastAlertTone { get; private set; }
    internal int AlertsPlayed { get; private set; }

    private void PlayAlert(bool anyDown, bool anyUp, bool anyWarning)
    {
        if (PickAlertTone(anyDown, anyUp, anyWarning, SoundOnDown, SoundOnUp, SoundOnWarning) is not { } tone) return;
        LastAlertTone = tone;
        AlertsPlayed++;
        if (Volume > 0) SoundHelper.Play(tone);
    }

    /// <summary>Called every second by the view while it is on screen: the "8s ago" ages and the detail durations.</summary>
    public void Tick()
    {
        var now = DateTime.Now;
        foreach (var t in Targets) t.RefreshAge(now);
        if (SelectedTarget is { } s) Detail.RefreshTimes(s, now, _rules);
        if (_addMessageExpires is { } expires && now >= expires)
        {
            SetAddMessage(string.Empty, false);
            CanUndoRemove = false;
            _lastRemoved = null;
        }
    }

    // ================================================================ adding, removing, editing

    [RelayCommand]
    private void AddTargets() => AddFromInput();

    /// <summary>Enter in the add box (desktop): add what's typed, and start monitoring if it isn't running —
    /// an empty box just starts. Never stops a run (Stop stays an explicit click).</summary>
    public void SubmitAddBox()
    {
        bool hadText = NewTarget.Trim().Length > 0;
        bool ok = !hadText || AddFromInput();
        if (ok && !IsMonitoring && Targets.Count > 0) StartMonitoring();
    }

    [RelayCommand]
    private void AddExamples()
    {
        NewTarget = ExampleTargets;
        AddFromInput();
    }

    // Adds every entry of the add box. What can't be added stays in the box with the reason underneath.
    private bool AddFromInput()
    {
        var entries = SplitEntries(NewTarget);
        if (entries.Count == 0)
        {
            SetAddMessage("Type a host, host:port or URL first.", true);
            return false;
        }

        int added = 0, dupes = 0, overLimit = 0;
        var rejected = new List<string>();
        string? firstError = null, firstDupe = null;
        var o = Options;
        foreach (var entry in entries)
        {
            if (!MonitorEndpoint.TryParse(entry, out var ep, out var error))
            {
                rejected.Add(entry);
                firstError ??= error;
                continue;
            }
            if (_byKey.ContainsKey(ep.Key)) { dupes++; firstDupe ??= ep.DisplayName; continue; }   // duplicates are ignored
            if (Targets.Count >= MaxTargets) { overLimit++; rejected.Add(entry); continue; }

            var t = new MonitorTarget(ep, _rules);
            LinkExtras(t);
            t.ApplyChecks(o);
            t.NeedsCheck = IsMonitoring;   // checked right away, not at the next round
            _byKey[ep.Key] = t;
            Targets.Add(t);
            added++;
        }

        NewTarget = string.Join("\n", rejected);
        var parts = new List<string>();
        if (added > 0) parts.Add($"Added {added} monitor{(added == 1 ? "" : "s")}");
        if (dupes > 0) parts.Add(dupes == 1 && added == 0 ? $"{firstDupe} is already monitored" : $"{dupes} already monitored");
        if (overLimit > 0) parts.Add($"{overLimit} not added — the limit is {MaxTargets} monitors");
        if (firstError is not null)
            parts.Add(rejected.Count - overLimit == 1 ? firstError : $"{rejected.Count - overLimit} entries need fixing. First: {firstError}");
        SetAddMessage(string.Join(" · ", parts), firstError is not null || overLimit > 0);
        CanUndoRemove = false;

        if (added > 0)
        {
            PersistTargets();
            UpdateSummary();
            if (IsMonitoring) Wake();
        }
        return added > 0 || (dupes > 0 && rejected.Count == 0);
    }

    [RelayCommand]
    private void RemoveTarget(MonitorTarget? t)
    {
        if (t is null || t.Removed) return;
        int index = Targets.IndexOf(t);
        if (index < 0) return;
        if (ReferenceEquals(SelectedTarget, t)) SelectedTarget = null;
        t.Removed = true;
        _byKey.Remove(t.Endpoint.Key);
        Targets.RemoveAt(index);
        _lastRemoved = (t, index);
        SetAddMessage($"Removed {t.DisplayName}.", false, seconds: 10);
        CanUndoRemove = true;
        PersistTargets();
        UpdateSummary();
    }

    [RelayCommand]
    private void UndoRemove()
    {
        if (_lastRemoved is not { } last || _byKey.ContainsKey(last.Target.Endpoint.Key) || Targets.Count >= MaxTargets)
        {
            CanUndoRemove = false;
            return;
        }
        var t = last.Target;
        t.Removed = false;
        t.NeedsCheck = IsMonitoring && !t.IsPaused;
        t.ApplyChecks(Options);
        _byKey[t.Endpoint.Key] = t;
        Targets.Insert(Math.Clamp(last.Index, 0, Targets.Count), t);
        _lastRemoved = null;
        CanUndoRemove = false;
        SetAddMessage($"Restored {t.DisplayName}.", false);
        PersistTargets();
        UpdateSummary();
        if (IsMonitoring) Wake();
    }

    [RelayCommand]
    private void TogglePause(MonitorTarget? t)
    {
        if (t is null || t.Removed) return;
        var now = DateTime.Now;
        if (t.IsPaused)
        {
            t.Tracker.Resume();
            t.NeedsCheck = IsMonitoring;
            AddEvent(t, MonitorEventKind.Resumed, "Checks resumed");
            if (IsMonitoring) Wake();
        }
        else
        {
            t.Tracker.Pause(now);
            t.NeedsCheck = false;
            AddEvent(t, MonitorEventKind.Paused, "Checks paused");
        }
        t.RefreshState(Options);
        PersistTargets();
        UpdateSummary();
        RefreshDetail();
    }

    [RelayCommand]
    private void OpenEditList()
    {
        EditListText = string.Join("\n", Targets.Select(t => t.Address));
        EditMessage = string.Empty;
        IsEditingList = true;
    }

    [RelayCommand]
    private void CancelEditList()
    {
        IsEditingList = false;
        EditMessage = string.Empty;
    }

    [RelayCommand]
    private void SaveEditList() => ApplyEditList();

    /// <summary>Enter in the list editor (desktop): save, and start monitoring if it isn't running.</summary>
    public void SubmitEditList()
    {
        if (ApplyEditList() && !IsMonitoring && Targets.Count > 0) StartMonitoring();
    }

    // Replaces the list with the editor's lines. Monitors that stay keep their history; nothing is applied while a line
    // is invalid, so a typo can't silently drop a monitor.
    private bool ApplyEditList()
    {
        var parsed = new List<MonitorEndpoint>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        int bad = 0;
        string? firstError = null;
        foreach (var entry in SplitEntries(EditListText))
        {
            if (!MonitorEndpoint.TryParse(entry, out var ep, out var error)) { bad++; firstError ??= error; continue; }
            if (seen.Add(ep.Key)) parsed.Add(ep);   // duplicates are ignored
        }
        if (bad > 0)
        {
            EditMessage = bad == 1 ? $"Fix this line to save: {firstError}" : $"{bad} lines need fixing before saving. First: {firstError}";
            return false;
        }
        if (parsed.Count > MaxTargets)
        {
            EditMessage = $"At most {MaxTargets} monitors — remove {parsed.Count - MaxTargets} line{(parsed.Count - MaxTargets == 1 ? "" : "s")}.";
            return false;
        }

        var o = Options;
        var keep = new List<MonitorTarget>(parsed.Count);
        int added = 0;
        foreach (var ep in parsed)
        {
            if (_byKey.TryGetValue(ep.Key, out var existing)) { keep.Add(existing); continue; }
            var t = new MonitorTarget(ep, _rules);
            LinkExtras(t);
            t.ApplyChecks(o);
            t.NeedsCheck = IsMonitoring;
            keep.Add(t);
            added++;
        }
        var kept = new HashSet<MonitorTarget>(keep);
        int removed = 0;
        foreach (var t in Targets)
            if (!kept.Contains(t)) { t.Removed = true; removed++; }

        var selected = SelectedTarget;
        if (selected is not null && !kept.Contains(selected)) selected = null;
        _byKey.Clear();
        foreach (var t in keep) _byKey[t.Endpoint.Key] = t;
        // Same order as the editor. Moves keep the realized rows (no full reset of a long list).
        for (int i = Targets.Count - 1; i >= 0; i--)
            if (Targets[i].Removed) Targets.RemoveAt(i);
        for (int i = 0; i < keep.Count; i++)
        {
            int at = Targets.IndexOf(keep[i]);
            if (at < 0) Targets.Insert(i, keep[i]);
            else if (at != i) Targets.Move(at, i);
        }
        SelectedTarget = selected;

        IsEditingList = false;
        EditMessage = string.Empty;
        _lastRemoved = null;
        CanUndoRemove = false;
        SetAddMessage(added == 0 && removed == 0 ? "List saved — no changes." : $"List saved · {added} added · {removed} removed.", false);
        PersistTargets();
        UpdateSummary();
        if (IsMonitoring && added > 0) Wake();
        return true;
    }

    /// <summary>Splits pasted / typed text into entries: one per line, or comma-separated (not inside a URL, where a
    /// comma can be part of the query).</summary>
    internal static List<string> SplitEntries(string? text)
    {
        var list = new List<string>();
        if (string.IsNullOrWhiteSpace(text)) return list;
        foreach (var raw in text.Split('\n', '\r'))
        {
            string line = raw.Trim();
            if (line.Length == 0) continue;
            if (line.Contains("://", StringComparison.Ordinal)) { list.Add(line); continue; }
            foreach (var part in line.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                list.Add(part);
        }
        return list;
    }

    // Confirmations fade out on their own after a few seconds (no animation: the line just goes); problems stay until
    // the box is edited or the next add.
    private void SetAddMessage(string text, bool isError, int seconds = 6)
    {
        AddMessageIsError = isError;
        AddMessage = text;
        _addMessageExpires = !isError && text.Length > 0 ? DateTime.Now.AddSeconds(seconds) : null;
    }

    partial void OnNewTargetChanged(string value)
    {
        if (AddMessageIsError && AddMessage.Length > 0) SetAddMessage(string.Empty, false);
    }

    // ================================================================ settings

    [RelayCommand]
    private void ToggleSettings() => IsSettingsOpen = !IsSettingsOpen;

    partial void OnCheckPingChanged(bool value) => OnChecksChanged();
    partial void OnCheckTcpChanged(bool value) => OnChecksChanged();
    partial void OnCheckHttpChanged(bool value) => OnChecksChanged();

    private void OnChecksChanged()
    {
        if (!_loaded) return;
        OnPropertyChanged(nameof(NoChecksEnabled));
        var o = Options;
        foreach (var t in Targets) t.ApplyChecks(o);
        if (!NoChecksEnabled && Notice.StartsWith("Turn on", StringComparison.Ordinal)) Notice = string.Empty;
        PersistSettings();
        UpdateSummary();
        RefreshDetail();
    }

    partial void OnIntervalChanged(int value)
    {
        if (!_loaded) return;
        PersistSettings();
        if (IsMonitoring)
        {
            // A shorter interval applies from the round that's already running, not after the old, longer wait.
            _nextRoundAt = Math.Min(_nextRoundAt, _roundStartedAt + IntervalSeconds * 1000L);
            Wake();
        }
        UpdateRunState();
    }

    partial void OnTimeoutMsChanged(int value) { if (_loaded) PersistSettings(); }
    partial void OnSoundOnDownChanged(bool value) { if (_loaded) PersistSettings(); }
    partial void OnSoundOnUpChanged(bool value) { if (_loaded) PersistSettings(); }
    partial void OnSoundOnWarningChanged(bool value) { if (_loaded) PersistSettings(); }

    // The slider: clamped (a restored / hand-edited value can't go outside 0–100) and written to the profile straight
    // away — SoundHelper reads it from there, for Ping's sounds too.
    partial void OnVolumeChanged(int value)
    {
        int v = Math.Clamp(value, 0, 100);
        if (v != value) { Volume = v; return; }
        OnPropertyChanged(nameof(VolumeText));
        OnPropertyChanged(nameof(IsMuted));
        if (_loaded) PersistSettings();
    }

    /// <summary>"70 %", or "Off" at 0 (no sound then, whatever the switches say).</summary>
    public string VolumeText => Volume <= 0 ? "Off" : Volume.ToString(System.Globalization.CultureInfo.InvariantCulture) + " %";
    public bool IsMuted => Volume <= 0;
    partial void OnDownAfterChanged(int value) => OnThresholdsChanged();
    partial void OnUpAfterChanged(int value) => OnThresholdsChanged();

    // The new counts apply from the next check; the rows' "Failing 1/3" texts and the detail panel follow right away.
    private void OnThresholdsChanged()
    {
        if (!_loaded) return;
        _rules.DownAfter = DownThreshold;
        _rules.UpAfter = UpThreshold;
        PersistSettings();
        var o = Options;
        foreach (var t in Targets) t.RefreshState(o);
        RefreshDetail();
    }

    // ▶ beside each sound switch: hear it without waiting for an outage (at the alert volume).
    [RelayCommand]
    private void PreviewDownSound() => SoundHelper.Preview(AlertTone.Down);

    [RelayCommand]
    private void PreviewUpSound() => SoundHelper.Preview(AlertTone.Up);

    [RelayCommand]
    private void PreviewWarningSound() => SoundHelper.Preview(AlertTone.Warning);

    /// <summary>Test: the down sound, then the up sound, at the chosen volume.</summary>
    [RelayCommand]
    private void TestSound() => SoundHelper.PlayTest();

    partial void OnIsEditingListChanged(bool value)
    {
        OnPropertyChanged(nameof(ShowList));
        OnPropertyChanged(nameof(ShowEmpty));
    }

    partial void OnNoticeChanged(string value) => OnPropertyChanged(nameof(HasNotice));
    partial void OnAddMessageChanged(string value) => OnPropertyChanged(nameof(HasAddMessage));
    partial void OnEditMessageChanged(string value) => OnPropertyChanged(nameof(HasEditMessage));
    partial void OnUpCountChanged(int value) => OnPropertyChanged(nameof(HasUp));
    partial void OnDownCountChanged(int value) => OnPropertyChanged(nameof(HasDown));
    partial void OnPendingCountChanged(int value) => OnPropertyChanged(nameof(HasPending));
    partial void OnRetryingCountChanged(int value) => OnPropertyChanged(nameof(HasRetrying));
    partial void OnPausedCountChanged(int value) => OnPropertyChanged(nameof(HasPaused));
    partial void OnWarningCountChanged(int value) => OnPropertyChanged(nameof(HasWarnings));
    partial void OnIsMonitoringChanged(bool value) => UpdateRunState();

    private void PersistSettings()
    {
        var inv = System.Globalization.CultureInfo.InvariantCulture;
        var ps = ProfileService.Instance;
        ps.SetMany(
            (KeyPing, CheckPing ? "true" : "false"), (KeyTcp, CheckTcp ? "true" : "false"), (KeyHttp, CheckHttp ? "true" : "false"),
            (KeyInterval, IntervalSeconds.ToString(inv)),
            (KeyTimeout, Math.Clamp(TimeoutMs, MonitorProbe.MinTimeoutMs, MonitorProbe.MaxTimeoutMs).ToString(inv)),
            (KeyDownAfter, DownThreshold.ToString(inv)),
            (KeyUpAfter, UpThreshold.ToString(inv)),
            (KeySoundDown, SoundOnDown ? "true" : "false"),
            (KeySoundUp, SoundOnUp ? "true" : "false"),
            (KeySoundWarning, SoundOnWarning ? "true" : "false"),
            (KeyVolume, Math.Clamp(Volume, 0, 100).ToString(inv)),
            (KeyAutoStart, StartWithApp ? "true" : "false"),
            (BootStart.ProfileKey, StartOnBoot ? "true" : "false"));
        ps.Remove(KeySound);   // migrated: the two switches above replace it
    }

    // The profile writes behind (coalesced, off the UI thread) and is flushed on exit / backgrounding.
    // The list itself stays in its original format (one address per line), so older builds still read it; each
    // monitor's own rules go in a separate key (see MonitorViewModel.Checks.cs).
    private void PersistTargets()
    {
        if (!_loaded) return;
        ProfileService.Instance.SetMany(
            (KeyTargets, string.Join("\n", Targets.Select(t => t.Address))),
            (KeyPaused, string.Join("\n", Targets.Where(t => t.IsPaused).Select(t => t.Address))),
            (KeyTargetOptions, SerializeTargetOptions()));
    }

    // ================================================================ selection, events, summary

    [RelayCommand]
    private void CloseDetail() => SelectedTarget = null;

    partial void OnSelectedTargetChanged(MonitorTarget? value)
    {
        OnPropertyChanged(nameof(HasSelection));
        IsEditingChecks = false;
        SelectedEvents.Clear();
        if (value is null) return;
        foreach (var e in Events)
        {
            if (e.TargetId != value.Id) continue;
            SelectedEvents.Add(e);
            if (SelectedEvents.Count >= RecentEventsShown) break;
        }
        RefreshDetail();
    }

    private void RefreshDetail()
    {
        if (SelectedTarget is { } t) Detail.Update(t, DateTime.Now, Options, _rules);
    }

    [RelayCommand]
    private void ClearEvents()
    {
        Events.Clear();
        SelectedEvents.Clear();
    }

    private void AddEvent(MonitorTarget? t, MonitorEventKind kind, string message, bool failure = false)
    {
        string who = t?.DisplayName ?? (kind == MonitorEventKind.Telegram ? "Telegram alerts" : "All monitors");
        var e = new MonitorEvent(DateTime.Now, kind, who, message, t?.Id ?? 0, failure);
        Events.Insert(0, e);
        while (Events.Count > MaxEvents) Events.RemoveAt(Events.Count - 1);
        if (t is not null && ReferenceEquals(t, SelectedTarget))
        {
            SelectedEvents.Insert(0, e);
            while (SelectedEvents.Count > RecentEventsShown) SelectedEvents.RemoveAt(SelectedEvents.Count - 1);
        }
    }

    private void UpdateSummary()
    {
        int up = 0, down = 0, pending = 0, retrying = 0, paused = 0, warning = 0;
        long total = 0, ok = 0, latencyCount = 0;
        double latencySum = 0;
        foreach (var t in Targets)
        {
            switch (t.Tracker.State)
            {
                case MonitorState.Up when t.IsWarning: warning++; break;
                case MonitorState.Up: up++; break;
                case MonitorState.Down: down++; break;
                case MonitorState.Paused: paused++; break;
                default:
                    pending++;
                    if (t.Tracker.IsRetrying) retrying++;
                    break;
            }
            total += t.Tracker.TotalChecks;
            ok += t.Tracker.SuccessfulChecks;
            latencySum += t.LatencySum;
            latencyCount += t.LatencyCount;
        }
        UpCount = up;
        DownCount = down;
        PendingCount = pending;
        RetryingCount = retrying;
        PausedCount = paused;
        WarningCount = warning;
        UptimeText = MonitorFormat.Percent(ok, total);
        AvgResponseText = latencyCount == 0 ? "–" : MonitorFormat.Ms(latencySum / latencyCount);
        UpdateRunState();
    }

    private void UpdateRunState()
    {
        RunStateText = IsMonitoring ? $"Checking every {MonitorFormat.Interval(IntervalSeconds)}"
            : _waitingForNetwork && Targets.Count > 0 ? "Starting when the network is up…"
            : Targets.Count == 0 ? "Add a monitor to begin"
            : _hasRun ? "Stopped"
            : "Not running";
    }
}
