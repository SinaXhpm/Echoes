using System;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform;
using Avalonia.Threading;
using Echoes.Helpers;
using Echoes.Views;

namespace Echoes.Desktop;

/// <summary>
/// The desktop shell around the main window: a tray icon whose menu opens the window, toggles close-to-tray and quits;
/// closing the window hides it to the tray while that's on (MainWindow.OnClosing asks <see cref="CanCloseToTray"/>);
/// and the window comes back from the tray icon, the macOS Dock and a second launch (<see cref="SingleInstance"/>).
/// Running tools (web server, proxy, monitor, scans) keep going while the window is hidden — that's the point.
/// Installed by Program.Main through App.DesktopStarted.
/// </summary>
internal sealed class TrayService
{
    private const string CloseToTrayKey = "app.closeToTray";

    private readonly IClassicDesktopStyleApplicationLifetime _desktop;
    private readonly MainWindow _window;
    private TrayIcon? _icon;
    private NativeMenuItem? _closeToTrayItem;
    private bool _closeToTray;

    private TrayService(IClassicDesktopStyleApplicationLifetime desktop, MainWindow window)
    {
        _desktop = desktop;
        _window = window;
    }

    /// <summary>
    /// App.DesktopStarted: on the UI thread, once the main window exists (before it is first shown).
    /// <paramref name="startHidden"/>: a login launch (--background) — only the tray icon, no window.
    /// </summary>
    public static void Attach(IClassicDesktopStyleApplicationLifetime desktop, MainWindow window, bool startHidden = false)
        => new TrayService(desktop, window).Start(startHidden);

    private void Start(bool startHidden)
    {
        _closeToTray = ProfileService.Instance.GetBool(CloseToTrayKey, true);
        try
        {
            _icon = CreateIcon();
        }
        catch (Exception ex)
        {
            // No tray icon: closing quits as it always did, and a relaunch still brings the window forward.
            CrashLog.Write("Tray.Create", ex);
            _icon = null;
        }

        _window.CanCloseToTray = CanCloseToTray;
        // Linux: a tray host can come or go while Echoes runs; look again every time the window is shown (Opened is
        // raised on each Show, the first one included).
        _window.Opened += (_, _) => TrayHost.Refresh();

        // A second launch (called on the listener's thread).
        SingleInstance.ShowRequested = () => Dispatcher.UIThread.Post(_window.BringToFront);

        // macOS: clicking the Dock icon of the running app ("reopen") must bring a hidden window back. Raised on the UI
        // thread. Cmd+Q is untouched: it is an application shutdown, which the window never intercepts.
        if (Application.Current?.TryGetFeature<IActivatableLifetime>() is { } activatable)
        {
            activatable.Activated += (_, e) =>
            {
                if (e.Kind == ActivationKind.Reopen) _window.BringToFront();
            };
        }

        _desktop.Exit += (_, _) => Stop();

        if (startHidden) StartHidden();
    }

    // A login launch: Echoes runs in the tray with no window. The lifetime shows desktop.MainWindow right after startup,
    // before its main loop runs, so the window sits out that one Show and is handed back on the first dispatcher pass
    // (the clipboard and link helpers find the window through it). No tray icon to come back through — creation failed,
    // or on Linux no StatusNotifier host turns up — and the window opens after all: an invisible Echoes would look like
    // it never started.
    private void StartHidden()
    {
        if (_icon is null) return;
        _desktop.MainWindow = null;
        Dispatcher.UIThread.Post(() => _desktop.MainWindow = _window);
        if (OperatingSystem.IsLinux()) _ = ShowUnlessTrayHostAsync();
    }

    private async Task ShowUnlessTrayHostAsync()
    {
        // At sign-in the panel that hosts tray icons may still be starting: give it a few seconds.
        if (!await TrayHost.WaitForHostAsync(TimeSpan.FromSeconds(8)).ConfigureAwait(false))
            Post(_window.BringToFront);
    }

    // Hide instead of quitting only when the user wants it AND the icon is there to bring the window back.
    private bool CanCloseToTray() => _closeToTray && _icon is not null && TrayHost.IsAvailable;

    private TrayIcon CreateIcon()
    {
        var open = new NativeMenuItem("Open Echoes");
        open.Click += (_, _) => Post(_window.BringToFront);

        _closeToTrayItem = new NativeMenuItem("Close to tray")
        {
            ToggleType = MenuItemToggleType.CheckBox,
            IsChecked = _closeToTray,
        };
        _closeToTrayItem.Click += (_, _) => Post(ToggleCloseToTray);

        var quit = new NativeMenuItem("Quit Echoes");
        quit.Click += (_, _) => Post(Quit);

        var menu = new NativeMenu();
        menu.Add(open);
        menu.Add(new NativeMenuItemSeparator());
        menu.Add(_closeToTrayItem);
        menu.Add(new NativeMenuItemSeparator());
        menu.Add(quit);

        WindowIcon image;
        using (var png = AssetLoader.Open(new Uri("avares://Echoes/Assets/logo-256.png")))
            image = new WindowIcon(png);   // decoded right away; the stream isn't kept

        var icon = new TrayIcon { Icon = image, ToolTipText = "Echoes", Menu = menu };
        // Windows: left click (right click opens the menu); Linux: the host's "activate". macOS shows the menu instead.
        icon.Clicked += (_, _) => Post(_window.BringToFront);

        // Avalonia 12 creates the platform icon only once it is in the application's TrayIcon.Icons.
        TrayIcon.SetIcons(Application.Current!, new TrayIcons { icon });
        return icon;
    }

    // Tray events can arrive on a platform thread (Linux: D-Bus) or in the middle of the Windows tray menu's own click
    // handling (that menu is an Avalonia window); act on the UI thread once that has finished.
    private static void Post(Action action) => Dispatcher.UIThread.Post(action);

    private void ToggleCloseToTray()
    {
        // From our own state, not the item's: on Windows the tray menu is an Avalonia MenuItem, two-way bound to the
        // item, which has already flipped IsChecked by the time Click arrives; native menus (macOS, Linux) haven't.
        // Toggling the item itself would undo the click on one or the other.
        _closeToTray = !_closeToTray;
        if (_closeToTrayItem is not null) _closeToTrayItem.IsChecked = _closeToTray;
        ProfileService.Instance.SetBool(CloseToTrayKey, _closeToTray);
    }

    // The regular shutdown, exactly like closing the last window used to be: ShutdownRequested (FlushOnExit: pending
    // edits, the web / proxy servers), then the window closes as an application shutdown — which it never turns into a
    // hide — then Exit. Not Shutdown(): that skips ShutdownRequested.
    private void Quit() => _desktop.TryShutdown();

    private void Stop()
    {
        SingleInstance.ShowRequested = null;   // the window is going away
        if (_icon is null) return;
        try
        {
            // Remove it now: on Windows an icon still registered when the process ends stays in the notification area
            // as a dead "ghost" until the mouse passes over it.
            _icon.Dispose();
        }
        catch (Exception ex)
        {
            CrashLog.Write("Tray.Dispose", ex);
        }
        _icon = null;
    }
}
