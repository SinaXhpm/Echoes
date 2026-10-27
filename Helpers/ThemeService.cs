using Avalonia;
using Avalonia.Styling;

namespace Echoes.Helpers;

/// <summary>
/// Light / dark theme. Every color token lives in Styles/Tokens.axaml's theme dictionaries and views read them with
/// DynamicResource, so switching <see cref="Application.RequestedThemeVariant"/> re-colors the whole app live. Until
/// the user picks one, Echoes follows the system's light / dark setting (and its changes, live), as a macOS app does;
/// the switch then pins the choice in the profile.
/// </summary>
public static class ThemeService
{
    private const string Key = "app.theme";

    public static bool IsLight => Application.Current?.ActualThemeVariant == ThemeVariant.Light;

    /// <summary>Applies the saved theme. Called before the first window or view exists, so nothing opens in the
    /// wrong theme and then flips.</summary>
    public static void ApplySaved()
    {
        if (Application.Current is not { } app) return;
        app.RequestedThemeVariant = ProfileService.Instance.GetSetting(Key) switch
        {
            "light" => ThemeVariant.Light,
            "dark" => ThemeVariant.Dark,
            _ => ThemeVariant.Default,   // the system's
        };
    }

    public static void Toggle()
    {
        if (Application.Current is not { } app) return;
        bool light = app.ActualThemeVariant != ThemeVariant.Light;
        app.RequestedThemeVariant = light ? ThemeVariant.Light : ThemeVariant.Dark;
        ProfileService.Instance.SetSetting(Key, light ? "light" : "dark");
    }
}
