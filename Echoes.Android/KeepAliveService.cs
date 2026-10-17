using Android.App;
using Android.Content;
using Android.OS;

namespace Echoes.Android;

/// <summary>
/// A foreground service that keeps the process running (and the CPU awake via a partial
/// wake lock) while a long-running tool — Monitor or Port Scanner — is active. Started and
/// stopped by <see cref="AndroidBackgroundGuard"/>, which is driven by the shared
/// <c>Echoes.Helpers.BackgroundGuard</c> ref-count.
///
/// Declared as a <c>dataSync</c> foreground service; the <c>[Service]</c> attribute emits the
/// matching &lt;service&gt; entry (with android:foregroundServiceType="dataSync") into the merged
/// manifest, so only the permissions need to live in AndroidManifest.xml.
/// </summary>
[Service(Exported = false, ForegroundServiceType = global::Android.Content.PM.ForegroundService.TypeDataSync)]
public class KeepAliveService : Service
{
    public const string ExtraReason = "reason";

    private const int NotificationId = 0x4563;          // arbitrary, non-zero
    private const string ChannelId = "echoes.keepalive";

    private PowerManager.WakeLock? _wakeLock;

    // Set by AndroidBackgroundGuard (mostly from the UI thread) and this service's callbacks. A service started with
    // StartForegroundService MUST reach StartForeground before it is stopped — otherwise Android kills the whole app
    // ("Context.startForegroundService() did not then call Service.startForeground()"), and no catch can prevent it.
    // So a release that comes before OnStartCommand (a boot start with nothing to monitor, a scan that ends at once)
    // is only recorded in StopWanted, and OnStartCommand stops the service right after going foreground.
    internal static volatile bool IsForeground;
    internal static volatile bool StopWanted;

    public override IBinder? OnBind(Intent? intent) => null;

    public override StartCommandResult OnStartCommand(Intent? intent, StartCommandFlags flags, int startId)
    {
        string reason = intent?.GetStringExtra(ExtraReason) ?? "Working in the background";

        EnsureChannel();
        Notification notification = BuildNotification(reason);

        // API 34+ requires the FGS type to be passed to StartForeground and to match the manifest.
        if (OperatingSystem.IsAndroidVersionAtLeast(34))
            StartForeground(NotificationId, notification, global::Android.Content.PM.ForegroundService.TypeDataSync);
        else
            StartForeground(NotificationId, notification);
        IsForeground = true;

        if (StopWanted)
        {
            // released before it got here: it had to go foreground first (see IsForeground), now it can go
            StopWanted = false;
            StopSelf();
            return StartCommandResult.NotSticky;
        }

        AcquireWakeLock();

        // If the OS kills us under pressure, don't auto-restart with a null intent — the VM
        // re-acquires when the user starts a tool again.
        return StartCommandResult.NotSticky;
    }

    // When the platform calls onTimeout the service MUST stop within a few seconds, or Android raises a
    // RemoteServiceException and kills the process. Monitoring simply ends in the background — a documented
    // platform limit. This API 34 overload is only called for the shortService type; kept as a harmless fallback.
    public override void OnTimeout(int startId)
    {
        ReleaseWakeLock();
        StopSelf();
        base.OnTimeout(startId);
    }

#if ANDROID35_0_OR_GREATER || __ANDROID_35__
    // Android 15 (API 35) time-boxes dataSync foreground services (6 h per rolling 24 h) for apps targeting SDK 35+,
    // and reports the timeout through THIS overload, not the one above — required before targetSdk goes to 35.
    // (Compiled only against API 35+ bindings, where it exists; the type is bound as the ForegroundService enum.)
    [System.Runtime.Versioning.SupportedOSPlatform("android35.0")]
    public override void OnTimeout(int startId, global::Android.Content.PM.ForegroundService fgsType)
    {
        ReleaseWakeLock();
        StopSelf();
        base.OnTimeout(startId, fgsType);
    }
#endif

    public override void OnDestroy()
    {
        IsForeground = false;
        ReleaseWakeLock();
        try
        {
            if (OperatingSystem.IsAndroidVersionAtLeast(24))
                StopForeground(StopForegroundFlags.Remove);
#pragma warning disable CA1422
            else
                StopForeground(true);
#pragma warning restore CA1422
        }
        catch { }
        base.OnDestroy();
    }

    private void EnsureChannel()
    {
        if (!OperatingSystem.IsAndroidVersionAtLeast(26)) return;
        if (GetSystemService(NotificationService) is not NotificationManager manager) return;
        if (manager.GetNotificationChannel(ChannelId) != null) return;

        var channel = new NotificationChannel(ChannelId, "Background tasks", NotificationImportance.Low)
        {
            Description = "Keeps Monitor / Scanner running while Echoes is in the background"
        };
        channel.SetShowBadge(false);
        manager.CreateNotificationChannel(channel);
    }

    private Notification BuildNotification(string reason)
    {
        Notification.Builder builder = OperatingSystem.IsAndroidVersionAtLeast(26)
            ? new Notification.Builder(this, ChannelId)
            : new Notification.Builder(this);

        // Tapping the notification brings the app back to the foreground.
        Intent? launch = PackageManager?.GetLaunchIntentForPackage(PackageName!);
        if (launch != null)
        {
            launch.AddFlags(ActivityFlags.SingleTop);
            PendingIntentFlags pendingFlags = OperatingSystem.IsAndroidVersionAtLeast(31)
                ? PendingIntentFlags.Immutable | PendingIntentFlags.UpdateCurrent
                : PendingIntentFlags.UpdateCurrent;
            builder.SetContentIntent(PendingIntent.GetActivity(this, 0, launch, pendingFlags));
        }

        return builder
            .SetContentTitle("Echoes")
            .SetContentText(reason)
            .SetSmallIcon(global::Android.Resource.Drawable.StatNotifySync)
            .SetOngoing(true)
            .Build();
    }

    private void AcquireWakeLock()
    {
        if (_wakeLock != null) return;
        if (GetSystemService(PowerService) is not PowerManager power) return;

        _wakeLock = power.NewWakeLock(WakeLockFlags.Partial, "echoes:keepalive");
        try { _wakeLock?.Acquire(); } catch { }
    }

    private void ReleaseWakeLock()
    {
        try
        {
            if (_wakeLock is { IsHeld: true } wl) wl.Release();
        }
        catch { }
        _wakeLock = null;
    }
}
