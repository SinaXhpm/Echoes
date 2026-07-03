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
}

/// <summary>
/// Reference-counted front door to the platform <see cref="IBackgroundGuard"/>. Both Monitor
/// and Scanner can hold it at once; the underlying service is started on the first acquire and
/// stopped only after the last matching release. Thread-safe and exception-swallowing so a VM
/// loop can never fail because of a platform hiccup.
/// </summary>
public static class BackgroundGuard
{
    private static IBackgroundGuard? _impl;
    private static int _count;
    private static readonly object _lock = new();

    /// <summary>Called once at startup by a platform head that supports background execution.</summary>
    public static void Register(IBackgroundGuard impl) => _impl = impl;

    public static void Acquire(string reason)
    {
        lock (_lock)
        {
            _count++;
            if (_count == 1)
            {
                try { _impl?.Acquire(reason); } catch { }
            }
        }
    }

    public static void Release()
    {
        lock (_lock)
        {
            if (_count == 0) return;   // never let an unmatched release drive the count negative
            _count--;
            if (_count == 0)
            {
                try { _impl?.Release(); } catch { }
            }
        }
    }
}
