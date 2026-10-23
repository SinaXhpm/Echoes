namespace Echoes.Helpers;

/// <summary>
/// Platform hook for keeping long-running work (Monitor, Port Scanner, …) alive while the
/// app is in the background. The desktop heads never register an implementation, so every
/// call is a no-op there; the Android head registers one that runs a foreground service +
/// partial wake lock (see Echoes.Android/KeepAliveService.cs).
/// </summary>
public interface IBackgroundGuard
{
    /// <summary>Ensure the OS keeps the process running. <paramref name="reason"/> is shown to the user (e.g. in the Android notification).</summary>
    void Acquire(string reason);

    /// <summary>Release the keep-alive; the OS may reclaim the process once nothing else holds it.</summary>
    void Release();

    /// <summary>What keeps Echoes running changed while the guard is held: the new text for the user.</summary>
    void Update(string reason) { }
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
    private static readonly List<string> _reasons = new();   // one entry per Acquire not yet released
    // The platform refused the start: Android 12+ won't start a foreground service once the app is in the background (the
    // user tapped Start and switched away while a scan was still resolving names, or a web server made its certificate).
    // The job then showed "running" while Android froze the process; Reacquire makes the start once the app is back.
    private static bool _failed;
    private static readonly object _lock = new();

    /// <summary>Called once at startup by a platform head that supports background execution.</summary>
    public static void Register(IBackgroundGuard impl) => _impl = impl;

    public static void Acquire(string reason)
    {
        lock (_lock)
        {
            _reasons.Add(reason);
            if (_reasons.Count == 1) StartLocked();
            else UpdateLocked();
        }
    }

    /// <summary>The app is in the foreground again (Android: MainActivity.OnStart): a start the OS refused while it was in
    /// the background is made now, where it is allowed.</summary>
    public static void Reacquire()
    {
        lock (_lock)
        {
            if (_reasons.Count > 0 && _failed) StartLocked();
        }
    }

    private static void StartLocked()
    {
        try
        {
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
            if (_reasons.Count == 0) return;   // never let an unmatched release drive the count negative
            int at = _reasons.LastIndexOf(reason);
            _reasons.RemoveAt(at >= 0 ? at : _reasons.Count - 1);
            if (_reasons.Count == 0)
            {
                _failed = false;
                try { _impl?.Release(); }
                catch (Exception ex) { CrashLog.Write("BackgroundGuard.Release", ex); }
            }
            else UpdateLocked();
        }
    }

    // Each running job once, in the order they started.
    private static string Text => string.Join(" · ", _reasons.Distinct());

    private static void UpdateLocked()
    {
        if (_failed) return;   // not started: Reacquire starts it with the text of then
        try { _impl?.Update(Text); }
        catch (Exception ex) { CrashLog.Write("BackgroundGuard.Update", ex); }
    }
}
