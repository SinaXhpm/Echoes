using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.Util;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Threading;
using Echoes.Helpers;
using Echoes.ViewModels;

namespace Echoes.Android;

/// <summary>
/// "Start monitoring when the phone starts" (Monitor settings). Runs after a reboot (BOOT_COMPLETED, sent once the user
/// has unlocked the phone) and after Echoes was updated (MY_PACKAGE_REPLACED: the update killed the running monitor).
///
/// <para>Off by default and switched off in the manifest (android:enabled="false"): a phone that never asked for it
/// doesn't even start Echoes at boot. The setting switches the component on (<see cref="AndroidBootStart"/>); the
/// receiver still checks the setting itself, cheaply — the profile is already in memory, since the process start ran
/// MainApplication.OnCreate, which initialized Avalonia, the App and its MainViewModel (without any activity or UI).</para>
///
/// <para>It starts <see cref="KeepAliveService"/> right here, inside the broadcast: BOOT_COMPLETED and
/// MY_PACKAGE_REPLACED are among the few moments a background app may start a foreground service. That holds for a
/// dataSync service while targetSdk stays at 34 — apps that target 35+ may no longer start dataSync / mediaPlayback /
/// camera … services from BOOT_COMPLETED, so moving targetSdk up means changing this service's type first. Then the
/// Monitor itself starts on the UI thread (waiting for a network first), and the receiver's hold on the service is
/// released: the running Monitor holds its own.</para>
///
/// <para>Not LOCKED_BOOT_COMPLETED: that comes before the first unlock, while Echoes' data (credential-encrypted
/// storage) can't be read yet — the profile would look unreadable.</para>
/// </summary>
[BroadcastReceiver(Name = "com.sinaxhpm.echoes.BootReceiver", Enabled = false, Exported = true, DirectBootAware = false)]
[IntentFilter(new[] { Intent.ActionBootCompleted, Intent.ActionMyPackageReplaced })]
public sealed class BootReceiver : BroadcastReceiver
{
    internal const string LogTag = "Echoes";

    public override void OnReceive(Context? context, Intent? intent)
    {
        string? action = intent?.Action;
        // Only the two system broadcasts (both protected: no other app can send them).
        if (action != Intent.ActionBootCompleted && action != Intent.ActionMyPackageReplaced) return;
        try
        {
            if (!BootStart.IsWanted)
            {
                Log.Info(LogTag, "Boot start: off in the Monitor settings");
                return;
            }
            Log.Info(LogTag, "Boot start: " + action);
            // Now, inside the broadcast, while a foreground service may still be started from the background.
            BackgroundGuard.Acquire(MonitorViewModel.BackgroundReason);
            _ = Dispatcher.UIThread.InvokeAsync(StartMonitoringAsync);
        }
        catch (Exception ex)
        {
            CrashLog.Write("BootReceiver", ex);
        }
    }

    // UI thread. The App made its MainViewModel in OnFrameworkInitializationCompleted and hung it on the single-view
    // lifetime's main view (as for any launch); the view isn't shown — no activity — but it is the same view-model the UI
    // shows when Echoes is opened later, so monitoring is never started twice.
    private static async Task StartMonitoringAsync()
    {
        try
        {
            var lifetime = global::Avalonia.Application.Current?.ApplicationLifetime as ISingleViewApplicationLifetime;
            if (lifetime?.MainView?.DataContext is not MainViewModel main)
            {
                Log.Warn(LogTag, "Boot start: the app isn't initialized");
                return;
            }
            var monitor = main.MonitorVM;
            await monitor.StartAtBootAsync();
            Log.Info(LogTag, monitor.IsMonitoring ? $"Boot start: monitoring {monitor.TargetCount} target(s)" : "Boot start: nothing to monitor");
        }
        catch (Exception ex)
        {
            CrashLog.Write("BootReceiver.Start", ex);
        }
        finally
        {
            BackgroundGuard.Release();   // the running Monitor holds its own
        }
    }
}

/// <summary>
/// <see cref="IBootStartHost"/> for Android: switches <see cref="BootReceiver"/> on / off in the package manager
/// (it is off in the manifest), and opens Echoes' page in the system settings (auto launch, battery, notifications).
/// </summary>
public sealed class AndroidBootStart : IBootStartHost
{
    private readonly Context _context;

    public AndroidBootStart(Context context) => _context = context;

    private ComponentName Component => new(_context, Java.Lang.Class.FromType(typeof(BootReceiver)));

    // DEFAULT means "as in the manifest", which is off.
    public bool IsEnabled
        => _context.PackageManager?.GetComponentEnabledSetting(Component) == ComponentEnabledState.Enabled;

    public string? SetEnabled(bool on)
    {
        if (_context.PackageManager is not { } pm) return "Couldn't change starting with the phone: no package manager.";
        pm.SetComponentEnabledSetting(Component, on ? ComponentEnabledState.Enabled : ComponentEnabledState.Disabled,
                                      ComponentEnableOption.DontKillApp);
        return IsEnabled == on ? null : "Couldn't change starting with the phone: the system didn't take the change.";
    }

    public void OpenAppSettings()
    {
        var intent = new Intent(global::Android.Provider.Settings.ActionApplicationDetailsSettings,
                                global::Android.Net.Uri.Parse("package:" + _context.PackageName));
        intent.AddFlags(ActivityFlags.NewTask);
        _context.StartActivity(intent);
    }
}
