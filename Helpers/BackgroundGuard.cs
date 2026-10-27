namespace Echoes.Helpers;

/// <summary>What a running job needs from a phone while Echoes is in the background (or its screen is idle).</summary>
public enum GuardKind
{
    /// <summary>Waits for the network: a server or a session. The process must stay, but the CPU may sleep between
    /// packets (an incoming one wakes the phone), and the iPhone's screen may lock once nobody uses it.</summary>
    Waits,
    /// <summary>Runs on its own clock until stopped: the monitor. The CPU is kept awake for its rounds.</summary>
    Ticks,
    /// <summary>Works until it finishes: a scan, a speed test. The CPU is kept awake, and the iPhone's screen on, to the end.</summary>
    Finite,
}

/// <summary>
/// Platform hook for keeping long-running work (Monitor, Port Scanner, …) alive while the
/// app is in the background. The desktop heads never register an implementation, so every
/// call is a no-op there; the Android head registers one that runs a foreground service (with a
/// partial wake lock only while a job needs the CPU, see Echoes.Android/KeepAliveService.cs).
/// </summary>
public interface IBackgroundGuard
{
    /// <summary>Ensure the OS keeps the process running. <paramref name="reason"/> is shown to the user (e.g. in the Android notification).</summary>
    void Acquire(string reason);

    /// <summary>Release the keep-alive; the OS may reclaim the process once nothing else holds it.</summary>
    void Release();

    /// <summary>What keeps Echoes running changed while the guard is held: the new text for the user.</summary>
    void Update(string reason) { }

    /// <summary>What the running jobs need (called before <see cref="Acquire"/> and whenever it changes):
    /// <paramref name="cpu"/> when one runs on its own clock or until it finishes (a monitor, a scan), not only waits for
    /// the network; <paramref name="finite"/> when one ends by itself (a scan, a speed test).</summary>
    void Needs(bool cpu, bool finite) { }
}

/// <summary>
/// Reference-counted front door to the platform <see cref="IBackgroundGuard"/>. Both Monitor
/// and Scanner can hold it at once; the underlying service is started on the first acquire and
/// stopped only after the last matching release. The text the user sees names everything holding it
/// ("Monitoring targets · SSH session"), not just the first. Thread-safe and exception-swallowing so a VM
/// loop can never fail because of a platform hiccup.
/// </summary>
public static class BackgroundGuard
{
    private static IBackgroundGuard? _impl;
    private static readonly List<(string Reason, GuardKind Kind)> _jobs = new();   // one entry per Acquire not yet released
    // The platform refused the start: Android 12+ won't start a foreground service once the app is in the background (the
    // user tapped Start and switched away while a scan was still resolving names, or a web server made its certificate).
    // The job then showed "running" while Android froze the process; Reacquire makes the start once the app is back.
    private static bool _failed;
    private static (bool Cpu, bool Finite)? _needs;   // what the platform was last told
    private static readonly object _lock = new();
    private static long _lastActivity = Environment.TickCount64;

    /// <summary>Called once at startup by a platform head that supports background execution.</summary>
    public static void Register(IBackgroundGuard impl) => _impl = impl;

    /// <summary>When the user last touched Echoes or a server last had a visitor (<see cref="Environment.TickCount64"/>).
    /// The iPhone keeps its screen on for a waiting job only this long after it (Echoes.iOS/IosBackgroundGuard).</summary>
    public static long LastActivity => Volatile.Read(ref _lastActivity);

    /// <summary>Someone is using Echoes: a touch or a key, a request to a server, data in a session. Cheap enough for
    /// every chunk of a transfer.</summary>
    public static void NoteActivity() => Volatile.Write(ref _lastActivity, Environment.TickCount64);

    public static void Acquire(string reason, GuardKind kind = GuardKind.Waits)
    {
        lock (_lock)
        {
            _jobs.Add((reason, kind));
            if (_jobs.Count == 1) StartLocked();
            else UpdateLocked();
        }
    }

    /// <summary>The app is in the foreground again (Android: MainActivity.OnStart): a start the OS refused while it was in
    /// the background is made now, where it is allowed.</summary>
    public static void Reacquire()
    {
        lock (_lock)
        {
            if (_jobs.Count > 0 && _failed) StartLocked();
        }
    }

    private static void StartLocked()
    {
        try
        {
            TellNeedsLocked();
            _impl?.Acquire(Text);
            _failed = false;
        }
        catch (Exception ex)
        {
            _failed = true;
            CrashLog.Write("BackgroundGuard.Acquire", ex);
        }
    }

    /// <summary>Ends one <see cref="Acquire"/> made with the same <paramref name="reason"/>.</summary>
    public static void Release(string reason)
    {
        lock (_lock)
        {
            if (_jobs.Count == 0) return;   // never let an unmatched release drive the count negative
            int at = _jobs.FindLastIndex(j => j.Reason == reason);
            _jobs.RemoveAt(at >= 0 ? at : _jobs.Count - 1);
            if (_jobs.Count == 0)
            {
                _failed = false;
                _needs = null;
                try { _impl?.Release(); }
                catch (Exception ex) { CrashLog.Write("BackgroundGuard.Release", ex); }
            }
            else UpdateLocked();
        }
    }

    // Each running job once, in the order they started.
    private static string Text => string.Join(" · ", _jobs.Select(j => j.Reason).Distinct());

    private static void UpdateLocked()
    {
        if (_failed) return;   // not started: Reacquire starts it with the text of then
        try
        {
            TellNeedsLocked();
            _impl?.Update(Text);
        }
        catch (Exception ex) { CrashLog.Write("BackgroundGuard.Update", ex); }
    }

    private static void TellNeedsLocked()
    {
        var needs = (Cpu: _jobs.Exists(j => j.Kind != GuardKind.Waits), Finite: _jobs.Exists(j => j.Kind == GuardKind.Finite));
        if (_needs == needs) return;
        _needs = needs;
        _impl?.Needs(needs.Cpu, needs.Finite);
    }
}
