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

    /// <summary>Environment.TickCount64 when Echoes last went out of sight (0 = never): coming back after long enough,
    /// the servers check iOS hasn't closed their listening sockets meanwhile.</summary>
    public static long HiddenSince { get; private set; }

    public static void SetForeground(bool value)
    {
        if (IsInForeground == value) return;
        IsInForeground = value;
        if (!value) HiddenSince = Environment.TickCount64;
        ForegroundChanged?.Invoke();
    }

    /// <summary>True while the phone shell's drawer or the About box covers the page. A native view (cURL's web preview)
    /// is drawn above everything Avalonia draws on Android and iOS, so it hides itself meanwhile.</summary>
    public static bool OverlayOpen { get; private set; }
    public static event Action? OverlayChanged;

    public static void SetOverlay(bool open)
    {
        if (OverlayOpen == open) return;
        OverlayOpen = open;
        OverlayChanged?.Invoke();
    }

    /// <summary>Starts Echoes again in a fresh process (a restored backup is loaded that way), set by the Android head.
    /// Null where an app can't do that itself: iOS forbids it, and on a desktop the user quits and starts it.</summary>
    public static Action? RestartApp { get; set; }

    /// <summary>Whether <paramref name="view"/> can be seen: shown, in a window that isn't minimized, the app in front.</summary>
    public static bool OnScreen(Visual view)
        => IsInForeground && view.IsEffectivelyVisible && TopLevel.GetTopLevel(view) is { } top
           && top is not Window { WindowState: WindowState.Minimized };
}
