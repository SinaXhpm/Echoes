using Avalonia;
using Avalonia.Styling;

namespace Echoes.Helpers;

/// <summary>
/// Light / dark theme. Every color token lives in Styles/Tokens.axaml's theme dictionaries and views read them with
/// DynamicResource, so switching <see cref="Application.RequestedThemeVariant"/> re-colors the whole app live. The
/// choice persists in the profile; dark is the default (what Echoes always was).
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
        app.RequestedThemeVariant = ProfileService.Instance.GetSetting(Key) == "light" ? ThemeVariant.Light : ThemeVariant.Dark;
    }

    public static void Toggle()
    {
        if (Application.Current is not { } app) return;
        bool light = app.ActualThemeVariant != ThemeVariant.Light;
        app.RequestedThemeVariant = light ? ThemeVariant.Light : ThemeVariant.Dark;
        ProfileService.Instance.SetSetting(Key, light ? "light" : "dark");
    }
}
