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

        if (Avalonia.Application.Current is { } app)
        {
            // Removed in OnDestroy: the Application outlives this activity (a recreated one, or the monitor's service
            // keeping the process), and must not keep a dead one alive or recolour its window.
            _themeChanged = (_, _) => PostSystemBars();
            app.ActualThemeVariantChanged += _themeChanged;
            // Now, before the first frame (MainApplication has loaded the profile and set the theme): styles.xml only
            // knows the dark theme, and with the light one saved every cold start showed dark bars that then flipped. The
            // post below stays the final word after Avalonia's own theme handling.
            ApplySystemBars();
            PostSystemBars();
        }
    }

    // Back in the foreground: a keep-alive service that Android refused to start while Echoes was in the background (a job
    // started just before switching away) is started now.
    protected override void OnStart()
    {
        base.OnStart();
        Echoes.Helpers.AppPlatform.SetForeground(true);
        Echoes.Helpers.BackgroundGuard.Reacquire();
    }

    private EventHandler? _themeChanged;

    protected override void OnDestroy()
    {
        if (_themeChanged is not null && Avalonia.Application.Current is { } app) app.ActualThemeVariantChanged -= _themeChanged;
        _themeChanged = null;
        base.OnDestroy();
    }

    // The bars follow the app's theme: the status bar continues the app bar (Bg.Sidebar), the navigation bar and the
    // window behind them match the page (Bg.App), and their icons turn dark on the light theme. styles.xml only knows the
    // dark theme. Posted after Avalonia's own theme handling, so this is what stays.
    private void PostSystemBars()
        => Avalonia.Threading.Dispatcher.UIThread.Post(ApplySystemBars, Avalonia.Threading.DispatcherPriority.Background);

    private void ApplySystemBars()
    {
        if (Window is not { } window || Avalonia.Application.Current is not { } app) return;
        var variant = app.ActualThemeVariant;
        if (!TryColor(app, "Bg.App", variant, out var page) || !TryColor(app, "Bg.Sidebar", variant, out var bar)) return;
        bool light = variant == Avalonia.Styling.ThemeVariant.Light;
        try
        {
            window.DecorView.SetBackgroundColor(page);
#pragma warning disable CA1422   // deprecated on API 35+, still honoured while targetSdk stays 34
            window.SetStatusBarColor(bar);
            window.SetNavigationBarColor(page);
#pragma warning restore CA1422
            if (OperatingSystem.IsAndroidVersionAtLeast(30) && window.InsetsController is { } controller)
            {
                var looks = (int)(global::Android.Views.WindowInsetsControllerAppearance.LightStatusBars
                                  | global::Android.Views.WindowInsetsControllerAppearance.LightNavigationBars);
                controller.SetSystemBarsAppearance(light ? looks : 0, looks);
            }
        }
        catch (Exception ex) { Echoes.Helpers.CrashLog.Write("MainActivity.ApplySystemBars", ex); }
    }

    private static bool TryColor(Avalonia.Application app, string key, Avalonia.Styling.ThemeVariant variant, out global::Android.Graphics.Color color)
    {
        color = default;
        if (!Avalonia.Controls.ResourceNodeExtensions.TryFindResource(app, key, variant, out var res)
            || res is not Avalonia.Media.ISolidColorBrush brush) return false;
        var c = brush.Color;
        color = global::Android.Graphics.Color.Argb(c.A, c.R, c.G, c.B);
        return true;
    }

    // Leaving the screen is the last moment Android promises before it may kill the process. App flushes every pending
    // edit here already (IActivatableLifetime.Deactivated → MainViewModel.FlushPersistence); this makes sure the profile
    // — the Monitor's list, its settings, the Telegram alerts — is on disk even if that hook didn't run. A no-op when
    // nothing is pending; a few KB written synchronously otherwise.
    protected override void OnStop()
    {
        base.OnStop();
        Echoes.Helpers.AppPlatform.SetForeground(false);   // the clocks of views nobody sees stop (Monitor's ages)
        try { Echoes.Helpers.ProfileService.Instance.Flush(); }
        catch (Exception ex) { Echoes.Helpers.CrashLog.Write("MainActivity.OnStop", ex); }
    }
}
