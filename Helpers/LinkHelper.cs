using System;
using System.Runtime.InteropServices;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;

namespace Echoes.Helpers;

/// <summary>
/// Opens a URL in the OS browser cross-platform. Uses Avalonia's <c>TopLevel.Launcher</c> (works on
/// BOTH desktop and Android), falling back to the platform shell command on desktop only if no
/// TopLevel is available. Replaces raw <c>Process.Start("xdg-open"/…)</c>, which no-ops on Android.
/// </summary>
public static class LinkHelper
{
    public static void Open(string? url)
    {
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri)) return;

        try
        {
            if (GetTopLevel()?.Launcher is { } launcher) { _ = launcher.LaunchUriAsync(uri); return; }
        }
        catch { }

        // Desktop-only fallback (no TopLevel / launcher available). Never reached on Android.
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(uri.ToString()) { UseShellExecute = true });
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                System.Diagnostics.Process.Start("xdg-open", uri.ToString());
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                System.Diagnostics.Process.Start("open", uri.ToString());
        }
        catch { }
    }

    // Fully-qualify: on the Android head bare `Application` clashes with Android.App.Application.
    private static TopLevel? GetTopLevel() => Avalonia.Application.Current?.ApplicationLifetime switch
    {
        IClassicDesktopStyleApplicationLifetime desktop => desktop.MainWindow,
        ISingleViewApplicationLifetime single when single.MainView is { } mv => TopLevel.GetTopLevel(mv),
        _ => null,
    };
}
