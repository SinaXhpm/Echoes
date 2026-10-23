using Android.App;
using Android.Runtime;
using Avalonia;
using Avalonia.Android;

namespace Echoes.Android;

// In Avalonia 12 the Android entry point moved from the activity to the Android
// Application: AvaloniaAndroidApplication<TApp> bootstraps Avalonia with the given
// App type, and CustomizeAppBuilder is where builder tweaks (fonts, etc.) go.
//
// OnCreate runs for EVERY start of the process — the launcher, but also a broadcast with no activity at all (the boot
// receiver): base.OnCreate initializes Avalonia and runs App.OnFrameworkInitializationCompleted (the MainViewModel and
// the single-view main view are created there, the view just isn't shown until an activity attaches it).
[Application]
public class MainApplication : AvaloniaAndroidApplication<global::Echoes.App>
{
    public MainApplication(nint javaReference, JniHandleOwnership transfer)
        : base(javaReference, transfer)
    {
    }

    public override void OnCreate()
    {
        // The platform hooks the shared code uses, registered BEFORE the App starts (base.OnCreate), so nothing it
        // sets up can run without them. The context is attached before OnCreate, so `this` is usable here.
        //  • keep the Monitor / Scanner loops alive in the background with a foreground service (no-op on desktop);
        //  • play the alert sounds on the notification stream (desktop plays them itself);
        //  • "Start monitoring when the phone starts": the boot receiver's on / off switch;
        //  • the About box's platform line: the Android release and API level (shared code can't read Build.VERSION).
        Echoes.Helpers.BackgroundGuard.Register(new AndroidBackgroundGuard(this));
        Echoes.Helpers.SoundHelper.RegisterPlayer(new AndroidSoundPlayer());
        Echoes.Helpers.BootStart.Register(new AndroidBootStart(this));
        var os = global::Android.OS.Build.VERSION.Release;
        var api = (int)global::Android.OS.Build.VERSION.SdkInt;
        Echoes.Helpers.AppInfo.PlatformOverride = $"Android {os} (API {api})";
        Echoes.Helpers.AppInfo.DeviceName = PhoneName();
        //  • after a backup restore, "Restart now" opens Echoes again in a fresh process, which loads the restored files.
        Echoes.Helpers.AppPlatform.RestartApp = RestartApp;
        base.OnCreate();
    }

    // The launcher activity in a new task, then this process ends (it holds the pre-restore state and saves nothing).
    private void RestartApp()
    {
        if (PackageName is { } package && PackageManager?.GetLaunchIntentForPackage(package)?.Component is { } component)
            StartActivity(global::Android.Content.Intent.MakeRestartActivityTask(component));
        Java.Lang.JavaSystem.Exit(0);
    }

    // The name the user gave the phone (Settings › About phone › Device name, no permission needed), else maker + model.
    private string PhoneName()
    {
        try
        {
            string? name = global::Android.Provider.Settings.Global.GetString(ContentResolver, "device_name");
            if (!string.IsNullOrWhiteSpace(name)) return name.Trim();
        }
        catch { }
        string maker = global::Android.OS.Build.Manufacturer ?? string.Empty;
        string model = global::Android.OS.Build.Model ?? string.Empty;
        string both = model.StartsWith(maker, StringComparison.OrdinalIgnoreCase) ? model : $"{maker} {model}";
        return both.Trim();
    }

    protected override AppBuilder CustomizeAppBuilder(AppBuilder builder)
        => base.CustomizeAppBuilder(builder).WithInterFont();
}
