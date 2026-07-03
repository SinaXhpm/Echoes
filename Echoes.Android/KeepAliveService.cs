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

        AcquireWakeLock();

        // If the OS kills us under pressure, don't auto-restart with a null intent — the VM
        // re-acquires when the user starts a tool again.
        return StartCommandResult.NotSticky;
    }

    public override void OnDestroy()
    {
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
