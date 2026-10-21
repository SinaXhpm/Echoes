using Echoes.Helpers;
using Foundation;
using UIKit;

namespace Echoes.iOS;

/// <summary>
/// iOS has no foreground service: an app is suspended soon after it leaves the screen, and so is the screen's auto-lock.
/// While a server, the monitor, a scan or a socket session is running (<see cref="BackgroundGuard"/> counts them), this
/// keeps the screen on — a locked phone would suspend the app and every connection with it — and asks iOS for the extra
/// seconds it grants a task that is still finishing when the user switches to another app. Nothing is shown to the user:
/// the screen simply stays on while Echoes is in front, and goes back to its normal timeout when the last job ends.
/// Registered by <see cref="AppDelegate"/> (BackgroundGuard.Register).
/// </summary>
internal sealed class IosBackgroundGuard : IBackgroundGuard
{
    private nint _task = UIApplication.BackgroundTaskInvalid;   // main thread only
    private bool _held;                                          // main thread only
    private NSObject? _toBackground, _toForeground;

    public void Acquire(string reason) => OnMain(() =>
    {
        _held = true;
        UIApplication.SharedApplication.IdleTimerDisabled = true;
        Observe();
        if (UIApplication.SharedApplication.ApplicationState == UIApplicationState.Background) BeginTask();
    });

    public void Release() => OnMain(() =>
    {
        _held = false;
        UIApplication.SharedApplication.IdleTimerDisabled = false;
        EndTask();
    });

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
