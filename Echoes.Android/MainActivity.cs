using Android.App;
using Android.Content.PM;
using Android.OS;
using Avalonia.Android;

namespace Echoes.Android;

// Avalonia 12 Android model: the activity is non-generic and empty; the Avalonia
// App type + AppBuilder customization live in the Android Application subclass below
// (see MainApplication / Application.cs).
[Activity(
    Label = "Echoes",
    Theme = "@style/MyTheme.NoActionBar",
    MainLauncher = true,
    ConfigurationChanges = ConfigChanges.Orientation | ConfigChanges.ScreenSize | ConfigChanges.UiMode)]
public class MainActivity : AvaloniaMainActivity
{
    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);

        // API 33+ needs runtime consent to show the foreground-service notification. The
        // service still runs without it; this just makes the ongoing notification visible.
        if (OperatingSystem.IsAndroidVersionAtLeast(33) &&
            CheckSelfPermission(global::Android.Manifest.Permission.PostNotifications) != Permission.Granted)
        {
            RequestPermissions(new[] { global::Android.Manifest.Permission.PostNotifications }, 1001);
        }
    }
}
