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

        // Web links only. Both the launcher and the shell fallback hand the URI to the OS, which
        // happily runs file:///…/x.exe, \\host\share payloads or protocol handlers (ms-msdt:,
        // search-ms:, …). Some URLs opened here come from network responses (the release page URL
        // from the update check), so an unexpected scheme must never reach the shell.
        if (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp) return;

        try
        {
            if (GetTopLevel()?.Launcher is { } launcher) { _ = launcher.LaunchUriAsync(uri); return; }
        }
        catch { }

        // Desktop-only fallback (no TopLevel / launcher available). Never reached on Android.
        // AbsoluteUri is the escaped form (no raw spaces), and ArgumentList passes it as ONE argv
        // entry, so a crafted URL can't split into extra xdg-open / open arguments.
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true });
            else if ((RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                     // Absolute path only: a bare "xdg-open" would also be looked up in the app / current directory.
                     && ExecutablePath.Find(RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "open" : "xdg-open") is { } opener)
            {
                var psi = new System.Diagnostics.ProcessStartInfo(opener)
                {
                    UseShellExecute = false,
                };
                psi.ArgumentList.Add(uri.AbsoluteUri);
                System.Diagnostics.Process.Start(psi)?.Dispose();
            }
        }
        catch { }
    }

    /// <summary>Whether <see cref="OpenFolder"/> can show a folder here: desktop only (Android has no file manager to hand it to).</summary>
    public static bool CanOpenFolder => !OperatingSystem.IsAndroid() && !OperatingSystem.IsIOS();

    /// <summary>Shows a local folder in the OS file manager (the About box's data folder). Desktop only; never throws.</summary>
    public static void OpenFolder(string? path)
    {
        if (!CanOpenFolder || string.IsNullOrWhiteSpace(path) || !System.IO.Directory.Exists(path)) return;
        try
        {
            if (GetTopLevel()?.Launcher is { } launcher)
            {
                _ = Avalonia.Platform.Storage.LauncherExtensions.LaunchDirectoryInfoAsync(launcher, new System.IO.DirectoryInfo(path));
                return;
            }
        }
        catch { }
        try
        {
            // Absolute path, like the xdg-open lookup above; the folder is one argv entry.
            if (OperatingSystem.IsWindows())
            {
                var psi = new System.Diagnostics.ProcessStartInfo(
                    System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"))
                { UseShellExecute = false };
                psi.ArgumentList.Add(path);
                System.Diagnostics.Process.Start(psi)?.Dispose();
            }
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
