using Echoes.Helpers;
using Foundation;
using UIKit;

namespace Echoes.iOS;

/// <summary>
/// iOS has no foreground service: an app is suspended soon after it leaves the screen, and so is the screen's auto-lock.
/// While a server, the monitor, a scan or a socket session is running (<see cref="BackgroundGuard"/> counts them), this
/// keeps the screen on — a locked phone would suspend the app and every connection with it — and asks iOS for the extra
/// seconds it grants a task that is still finishing when the user switches to another app.
///
/// The screen is what costs a phone the most, so it stays on only while that is worth it: to the end of a job that
/// finishes by itself (a scan, a speed test); for one that waits or runs until stopped (a server, a session, the
/// monitor) while the phone charges, and on battery for <see cref="IdleWindow"/> after the last touch or visitor
/// (<see cref="BackgroundGuard.LastActivity"/>). Then the phone locks as usual; the servers start again and the monitor
/// resumes when Echoes is back on screen. Nothing is shown to the user.
/// Registered by <see cref="AppDelegate"/> (BackgroundGuard.Register).
/// </summary>
internal sealed class IosBackgroundGuard : IBackgroundGuard
{
    /// <summary>How long after the last use a waiting job keeps the screen on, on battery (the self-test shortens it).</summary>
    internal static TimeSpan IdleWindow { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>How often that is looked at while a job runs.</summary>
    internal static TimeSpan CheckEvery { get; set; } = TimeSpan.FromSeconds(20);

    private nint _task = UIApplication.BackgroundTaskInvalid;   // main thread only
    private bool _held, _finite;                                 // main thread only
    private NSTimer? _check;                                     // main thread only
    private NSObject? _toBackground, _toForeground;

    public void Acquire(string reason) => OnMain(() =>
    {
        _held = true;
        UIDevice.CurrentDevice.BatteryMonitoringEnabled = true;
        Observe();
        Decide();
        _check ??= NSTimer.CreateRepeatingScheduledTimer(CheckEvery, _ => Decide());
        if (UIApplication.SharedApplication.ApplicationState == UIApplicationState.Background) BeginTask();
    });

    public void Release() => OnMain(() =>
    {
        _held = false;
        _check?.Invalidate();
        _check = null;
        UIApplication.SharedApplication.IdleTimerDisabled = false;
        UIDevice.CurrentDevice.BatteryMonitoringEnabled = false;
        EndTask();
    });

    // Called before Acquire and whenever the running jobs change.
    public void Needs(bool cpu, bool finite) => OnMain(() =>
    {
        _finite = finite;
        Decide();
    });

    // Screen on for a job that finishes by itself, on a charging phone, or a few minutes after someone used Echoes.
    private void Decide()
    {
        if (!_held) return;
        bool charging = UIDevice.CurrentDevice.BatteryState is UIDeviceBatteryState.Charging or UIDeviceBatteryState.Full;
        bool used = Environment.TickCount64 - BackgroundGuard.LastActivity < (long)IdleWindow.TotalMilliseconds;
        bool on = _finite || charging || used;
        if (UIApplication.SharedApplication.IdleTimerDisabled != on) UIApplication.SharedApplication.IdleTimerDisabled = on;
    }

    // The extra time lasts one trip to the background (about 30 s), so a task is begun each time Echoes leaves the screen
    // while a job runs and ended when it comes back. One begun only with the first job ran out on the first trip, and every
    // later one got no time at all: the app was suspended at once and its connections dropped.
    private void Observe()
    {
        if (_toBackground is not null) return;
        _toBackground = UIApplication.Notifications.ObserveDidEnterBackground((_, _) => { if (_held) BeginTask(); });
        _toForeground = UIApplication.Notifications.ObserveWillEnterForeground((_, _) => EndTask());
    }

    private void BeginTask()
    {
        if (_task != UIApplication.BackgroundTaskInvalid) return;
        // The expiration handler runs on the main thread, and UIKit requires the task to be ended before it returns (a
        // posted end could run after the suspension, and iOS kills an app that leaves a task open).
        _task = UIApplication.SharedApplication.BeginBackgroundTask("Echoes", EndTask);
    }

    private void EndTask()
    {
        if (_task == UIApplication.BackgroundTaskInvalid) return;
        UIApplication.SharedApplication.EndBackgroundTask(_task);
        _task = UIApplication.BackgroundTaskInvalid;
    }

    // UIKit wants the main thread; the guard is called from view-models (UI thread) and from thread-pool continuations.
    // Always posted, even from the main thread, so an Acquire and the Release after it can never swap places.
    private static void OnMain(Action action)
    {
        try
        {
            NSRunLoop.Main.BeginInvokeOnMainThread(() =>
            {
                try { action(); }
                catch (Exception ex) { CrashLog.Write("BackgroundGuard.iOS", ex); }
            });
        }
        catch (Exception ex) { CrashLog.Write("BackgroundGuard.iOS", ex); }
    }
}
