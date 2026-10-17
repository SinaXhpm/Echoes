using System;

namespace Echoes.Helpers;

/// <summary>How one check ended, as drawn in a monitor's status bar.</summary>
public enum MonitorBeat : byte
{
    None = 0,
    Up = 1,
    /// <summary>Not settled yet: failed, but fewer times in a row than "mark down after" — or answered while down,
    /// but fewer times in a row than "mark up again after".</summary>
    Pending = 2,
    Down = 3,
}

/// <summary>Spread of the response times kept in a <see cref="MonitorHistory"/>.</summary>
public readonly record struct LatencyStats(int Samples, double Min, double Avg, double Max, double P95);

/// <summary>
/// The most recent checks of one monitor — status and response time — in a fixed-size ring, so memory stays bounded
/// however long monitoring runs (60 × 5 bytes per target). Mutated and read on the UI thread only.
/// </summary>
public sealed class MonitorHistory
{
    public const int Capacity = 60;

    private readonly MonitorBeat[] _beats = new MonitorBeat[Capacity];
    private readonly float[] _ms = new float[Capacity];
    private int _next;    // slot the next check goes into
    private int _count;

    public int Count => _count;

    /// <summary>Appends a check; <paramref name="ms"/> is NaN when it has no response time (a failed check).</summary>
    public void Add(MonitorBeat beat, double ms)
    {
        _beats[_next] = beat;
        _ms[_next] = double.IsNaN(ms) || ms < 0 ? float.NaN : (float)Math.Min(ms, float.MaxValue);
        _next = (_next + 1) % Capacity;
        if (_count < Capacity) _count++;
    }

    /// <summary>Status of check <paramref name="i"/>: 0 is the oldest kept, <see cref="Count"/> − 1 the newest.</summary>
    public MonitorBeat BeatAt(int i) => _beats[Slot(i)];

    /// <summary>Response time of check <paramref name="i"/> in ms, NaN for none.</summary>
    public double MsAt(int i) => _ms[Slot(i)];

    private int Slot(int i)
    {
        if ((uint)i >= (uint)_count) throw new ArgumentOutOfRangeException(nameof(i));
        return (_next - _count + i + Capacity) % Capacity;
    }

    public void Clear()
    {
        _next = 0;
        _count = 0;
    }

    /// <summary>Min / average / max / 95th percentile (nearest rank) of the kept response times.</summary>
    public LatencyStats GetLatencyStats()
    {
        Span<float> v = stackalloc float[Capacity];
        int n = 0;
        double sum = 0;
        for (int i = 0; i < _count; i++)
        {
            float ms = _ms[Slot(i)];
            if (float.IsNaN(ms)) continue;
            v[n++] = ms;
            sum += ms;
        }
        if (n == 0) return new LatencyStats(0, double.NaN, double.NaN, double.NaN, double.NaN);
        var s = v[..n];
        s.Sort();
        int rank = (int)Math.Ceiling(0.95 * n);   // nearest-rank: the smallest value ≥ 95 % of the samples
        return new LatencyStats(n, s[0], sum / n, s[n - 1], s[Math.Clamp(rank, 1, n) - 1]);
    }
}

/// <summary>The four states a monitor is shown in.</summary>
public enum MonitorState
{
    /// <summary>Not checked yet in this run, or failing but not yet confirmed down (see <see cref="MonitorStatusTracker.IsRetrying"/>).</summary>
    Pending,
    Up,
    Down,
    Paused,
}

/// <summary>What a recorded check changed.</summary>
public enum MonitorTransition
{
    None,
    /// <summary>Pending → up (first success of the run, or the end of a short blip). Not an incident.</summary>
    CameUp,
    /// <summary>The failure that reached the "mark down after" threshold: an incident starts.</summary>
    WentDown,
    /// <summary>Down → up, once the "mark up again after" threshold is reached: the incident is over
    /// (<see cref="MonitorStatusTracker.LastDowntime"/>).</summary>
    Recovered,
}

/// <summary>
/// One monitor's state machine with flapping protection both ways: a failed check only makes it
/// <see cref="MonitorState.Down"/> after <c>downAfter</c> failures in a row (until then it is
/// <see cref="MonitorState.Pending"/> and "retrying"), so a single dropped packet never pages anyone; and a monitor that
/// is down only counts as up again after <c>upAfter</c> successes in a row (until then it stays down and "recovering"),
/// so a target that answers every other check doesn't alert on every round. Also keeps the session counters behind the
/// uptime figure. Pure logic, UI-thread only.
/// </summary>
public sealed class MonitorStatusTracker
{
    public const int MaxDownAfter = 20;
    public const int MaxUpAfter = 10;

    public MonitorState State { get; private set; } = MonitorState.Pending;
    /// <summary>Failed checks in a row (0 after any success).</summary>
    public int ConsecutiveFailures { get; private set; }
    /// <summary>Successful checks in a row (0 after any failure).</summary>
    public int ConsecutiveSuccesses { get; private set; }
    public long TotalChecks { get; private set; }
    public long SuccessfulChecks { get; private set; }
    public long FailedChecks => TotalChecks - SuccessfulChecks;

    /// <summary>When the current up period began (kept through a blip that never reached the threshold).</summary>
    public DateTime? UpSince { get; private set; }
    /// <summary>When the current (or last) outage began: the first failed check of the streak that took it down.</summary>
    public DateTime? DownSince { get; private set; }
    /// <summary>First failure of the current streak.</summary>
    public DateTime? FailingSince { get; private set; }
    /// <summary>First success of the current streak (while recovering: when the target started answering again).</summary>
    public DateTime? SucceedingSince { get; private set; }
    public DateTime? PausedAt { get; private set; }
    /// <summary>Length of the outage that the last <see cref="MonitorTransition.Recovered"/> ended.</summary>
    public TimeSpan? LastDowntime { get; private set; }

    /// <summary>Failing, but fewer times in a row than "mark down after": shown as pending, not yet down.</summary>
    public bool IsRetrying => State == MonitorState.Pending && ConsecutiveFailures > 0;

    /// <summary>Down, answering again, but fewer times in a row than "mark up again after": still down.</summary>
    public bool IsRecovering => State == MonitorState.Down && ConsecutiveSuccesses > 0;

    /// <summary>
    /// Records one check. <paramref name="downAfter"/> = failures in a row that mark the monitor down (1–20);
    /// <paramref name="upAfter"/> = successes in a row that mark a down monitor up again (1–10).
    /// </summary>
    public MonitorTransition Record(bool ok, DateTime now, int downAfter, int upAfter = 1)
    {
        if (State == MonitorState.Paused) return MonitorTransition.None;   // a late answer for a paused monitor
        int downThreshold = Math.Clamp(downAfter, 1, MaxDownAfter);
        int upThreshold = Math.Clamp(upAfter, 1, MaxUpAfter);
        TotalChecks++;

        if (ok)
        {
            SuccessfulChecks++;
            ConsecutiveFailures = 0;
            FailingSince = null;
            if (ConsecutiveSuccesses == 0) SucceedingSince = now;
            if (ConsecutiveSuccesses < int.MaxValue) ConsecutiveSuccesses++;
            switch (State)
            {
                case MonitorState.Up:
                    return MonitorTransition.None;
                case MonitorState.Down:
                    if (ConsecutiveSuccesses < upThreshold) return MonitorTransition.None;   // recovering: not up yet
                    State = MonitorState.Up;
                    // The outage ended when the target started answering again — the first success of this streak.
                    UpSince = SucceedingSince ?? now;
                    LastDowntime = DownSince is { } d ? UpSince - d : null;
                    return MonitorTransition.Recovered;
                default:
                    State = MonitorState.Up;
                    UpSince ??= now;   // a blip below the threshold doesn't restart the up period
                    return MonitorTransition.CameUp;
            }
        }

        ConsecutiveSuccesses = 0;
        SucceedingSince = null;
        if (ConsecutiveFailures == 0) FailingSince = now;
        if (ConsecutiveFailures < int.MaxValue) ConsecutiveFailures++;
        if (State == MonitorState.Down) return MonitorTransition.None;   // still down (a recovery streak, if any, is over)
        if (ConsecutiveFailures >= downThreshold)
        {
            State = MonitorState.Down;
            DownSince = FailingSince ?? now;
            UpSince = null;
            return MonitorTransition.WentDown;
        }
        State = MonitorState.Pending;   // retrying: not down until the threshold is reached
        return MonitorTransition.None;
    }

    /// <summary>Stops counting this monitor until <see cref="Resume"/>.</summary>
    public void Pause(DateTime now)
    {
        State = MonitorState.Paused;
        PausedAt = now;
        ConsecutiveFailures = 0;
        ConsecutiveSuccesses = 0;
        FailingSince = null;
        SucceedingSince = null;
        UpSince = null;
    }

    /// <summary>Back to pending; the next check settles the state again.</summary>
    public void Resume()
    {
        if (State != MonitorState.Paused) return;
        PausedAt = null;
        StartOver();
    }

    /// <summary>
    /// A new monitoring run: the last known state is stale (nothing was checked while monitoring was off), so an
    /// unpaused monitor starts over as pending. Session counters and the outage record are kept.
    /// </summary>
    public void BeginRun()
    {
        if (State != MonitorState.Paused) StartOver();
    }

    private void StartOver()
    {
        State = MonitorState.Pending;
        ConsecutiveFailures = 0;
        ConsecutiveSuccesses = 0;
        FailingSince = null;
        SucceedingSince = null;
        UpSince = null;
    }
}
