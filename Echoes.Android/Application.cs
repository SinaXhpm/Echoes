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

    protected override AppBuilder CustomizeAppBuilder(AppBuilder builder)
        => base.CustomizeAppBuilder(builder).WithInterFont();
}
