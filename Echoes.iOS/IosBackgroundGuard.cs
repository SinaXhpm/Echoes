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

    public void Acquire(string reason) => OnMain(() =>
    {
        UIApplication.SharedApplication.IdleTimerDisabled = true;
        if (_task != UIApplication.BackgroundTaskInvalid) return;
        _task = UIApplication.SharedApplication.BeginBackgroundTask("Echoes", () => OnMain(EndTask));   // the system's time is up
    });

    public void Release() => OnMain(() =>
    {
        UIApplication.SharedApplication.IdleTimerDisabled = false;
        EndTask();
    });

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
