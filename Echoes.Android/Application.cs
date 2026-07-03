using Android.App;
using Android.Runtime;
using Avalonia;
using Avalonia.Android;

namespace Echoes.Android;

// In Avalonia 12 the Android entry point moved from the activity to the Android
// Application: AvaloniaAndroidApplication<TApp> bootstraps Avalonia with the given
// App type, and CustomizeAppBuilder is where builder tweaks (fonts, etc.) go.
[Application]
public class MainApplication : AvaloniaAndroidApplication<global::Echoes.App>
{
    public MainApplication(nint javaReference, JniHandleOwnership transfer)
        : base(javaReference, transfer)
    {
    }

    public override void OnCreate()
    {
        base.OnCreate();
        // Let the shared Monitor/Scanner loops keep the process alive in the background
        // by starting a foreground service (no-op on desktop, which never registers one).
        Echoes.Helpers.BackgroundGuard.Register(new AndroidBackgroundGuard(this));
    }

    protected override AppBuilder CustomizeAppBuilder(AppBuilder builder)
        => base.CustomizeAppBuilder(builder).WithInterFont();
}
