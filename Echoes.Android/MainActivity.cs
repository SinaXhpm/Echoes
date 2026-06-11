using Android.App;
using Android.Content.PM;
using Avalonia.Android;

namespace Echoes.Android;

// Avalonia 12 Android model: the activity is non-generic and empty; the Avalonia
// App type + AppBuilder customization live in the Android Application subclass below
// (see MainApplication / Application.cs).
[Activity(
    Label = "Echoes",
    Theme = "@android:style/Theme.DeviceDefault.NoActionBar",
    MainLauncher = true,
    ConfigurationChanges = ConfigChanges.Orientation | ConfigChanges.ScreenSize | ConfigChanges.UiMode)]
public class MainActivity : AvaloniaMainActivity
{
}
