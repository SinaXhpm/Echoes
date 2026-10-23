using System;
using Avalonia;
using Avalonia.Controls;

namespace Echoes.Helpers;

/// <summary>
/// Tiny runtime flag so shared views can hide/show desktop-only bits on the mobile
/// shell. Set once at startup (single-view lifetime => mobile) before any view loads.
/// </summary>
public static class AppPlatform
{
    public static bool IsMobile { get; set; }
    public static bool IsDesktop => !IsMobile;

    /// <summary>False while nobody can see Echoes: the window hidden in the tray or minimized, the phone app in the
    /// background, macOS Hide. Set on the UI thread by the main window, the lifetime's Activated / Deactivated and the
    /// Android activity's OnStart / OnStop. A phone app in the background keeps its views "visible", so what redraws on a
    /// clock (Monitor's ages, the Wi-Fi poll, SSH server health) asks this too.</summary>
    public static bool IsInForeground { get; private set; } = true;
    public static event Action? ForegroundChanged;

    public static void SetForeground(bool value)
    {
        if (IsInForeground == value) return;
        IsInForeground = value;
        ForegroundChanged?.Invoke();
    }

    /// <summary>Whether <paramref name="view"/> can be seen: shown, in a window that isn't minimized, the app in front.</summary>
    public static bool OnScreen(Visual view)
        => IsInForeground && view.IsEffectivelyVisible && TopLevel.GetTopLevel(view) is { } top
           && top is not Window { WindowState: WindowState.Minimized };
}
