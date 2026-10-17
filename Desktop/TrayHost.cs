using System;
using System.Threading;
using System.Threading.Tasks;
using Tmds.DBus.Protocol;

namespace Echoes.Desktop;

/// <summary>
/// Whether a tray icon can actually be seen. Windows and macOS always have a tray. On Linux, Avalonia's tray icon is a
/// StatusNotifierItem, which only appears if a host (Plasma, the GNOME AppIndicator extension, waybar, the xfce4-panel
/// SNI plugin, ...) owns org.kde.StatusNotifierWatcher on the session bus. Stock GNOME has none: there, hiding the
/// window would leave Echoes running with no way back, so closing it quits as it always did.
/// </summary>
internal static class TrayHost
{
    private const string WatcherName = "org.kde.StatusNotifierWatcher";
    private static readonly TimeSpan CheckTimeout = TimeSpan.FromSeconds(2);

    private static volatile bool s_linuxHost;   // the last answer; false until the first check has returned
    private static int s_checking;              // 1 while a check runs: one at a time

    /// <summary>The cached answer, read when the window is closed; never blocks.</summary>
    public static bool IsAvailable => !OperatingSystem.IsLinux() || s_linuxHost;

    /// <summary>
    /// Linux: asks the session bus again, in the background — a host can come or go while Echoes runs (the extension
    /// toggled, the panel restarted). Called whenever the window is shown. No-op elsewhere.
    /// </summary>
    public static void Refresh()
    {
        if (!OperatingSystem.IsLinux() || Interlocked.Exchange(ref s_checking, 1) == 1) return;
        _ = Task.Run(async () =>
        {
            try { s_linuxHost = await HasWatcherAsync().ConfigureAwait(false); }
            finally { Volatile.Write(ref s_checking, 0); }
        });
    }

    /// <summary>
    /// A launch that starts hidden in the tray (login): whether a host is there, or turns up within
    /// <paramref name="patience"/> (asked about once a second — at sign-in the panel may still be starting). Also
    /// refreshes <see cref="IsAvailable"/>. True at once off Linux.
    /// </summary>
    public static async Task<bool> WaitForHostAsync(TimeSpan patience)
    {
        if (!OperatingSystem.IsLinux()) return true;
        long deadline = Environment.TickCount64 + (long)patience.TotalMilliseconds;
        while (true)
        {
            bool found = await HasWatcherAsync().ConfigureAwait(false);
            s_linuxHost = found;
            if (found || Environment.TickCount64 >= deadline) return found;
            await Task.Delay(1000).ConfigureAwait(false);
        }
    }

    private static async Task<bool> HasWatcherAsync()
    {
        try
        {
            // The shared session connection connects by itself on first use (AutoConnect: an explicit ConnectAsync isn't
            // needed, and its DisconnectedAsync is off limits). It's process-wide, so it is never disposed here.
            Task<string[]> call = DBusConnection.Session.ListServicesAsync();
            // If the timeout below gives up on the call, a late failure mustn't surface as an unobserved task exception.
            _ = call.ContinueWith(static t => _ = t.Exception, CancellationToken.None,
                                  TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                                  TaskScheduler.Default);
            string[] names = await call.WaitAsync(CheckTimeout).ConfigureAwait(false);
            return Array.IndexOf(names, WatcherName) >= 0;
        }
        catch (Exception)
        {
            // No session bus (a bare X or SSH session), a bus that doesn't answer in time, ...: no usable tray.
            return false;
        }
    }
}
