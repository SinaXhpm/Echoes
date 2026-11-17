using System;
using Avalonia;
using Avalonia.Controls;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class MainWindow : Window
{
    // What un-minimizing returns to: normal, maximized or full screen, whichever the window had before.
    private WindowState _restoreState = WindowState.Normal;
    private bool _closed;

    public MainWindow()
    {
        InitializeComponent();
        // Windows / Linux: the title bar Avalonia draws its caption buttons in is as tall as MainView's top bar (44), and
        // so are the buttons (CaptionButtonHeight, Styles/Tokens.axaml), in one row with About and the theme switch.
        // macOS keeps its own title bar for the traffic lights.
        if (!OperatingSystem.IsMacOS()) ExtendClientAreaTitleBarHeightHint = 44;
        // The UI lives in MainView (shared with the Android single-view head);
        // it triggers the update check on Loaded.
    }

    // The window opens 828 x 607: every tool's page fits there without scrolling (the tools sit in a top bar, so the
    // page has the full width), and so does a new tab's launcher, with its search box and every card (its cards are
    // compact for that). Its edges resize it. No maximize (MainView hides the greyed-out full-screen button Avalonia
    // draws beside the caption buttons, and keeps their width free at the end of the top bar). On a screen shorter
    // than 607 it opens at the work area's height instead.
    protected override void OnOpened(EventArgs e)
    {
        base.OnOpened(e);
        if (_sized) return;   // Opened comes again after the window is hidden to the tray and shown
        _sized = true;
        if (Screens.ScreenFromWindow(this) is { } screen && screen.Scaling > 0)
        {
            double frame = Math.Max(0, (FrameSize?.Height ?? Height) - ClientSize.Height);
            double room = Math.Floor(screen.WorkingArea.Height / screen.Scaling - frame);
            if (Height > room && room > 200) Height = room;
        }
    }

    private bool _sized;

    /// <summary>
    /// Set by the desktop head (Desktop/TrayService): whether closing should keep Echoes running in the tray instead of
    /// quitting — "Close to tray" is on AND a tray icon is actually there to bring the window back. Null (no tray
    /// service) keeps the plain close-quits behaviour. This file is shared with the Android head, hence a hook.
    /// </summary>
    public Func<bool>? CanCloseToTray { get; set; }

    protected override void OnClosing(WindowClosingEventArgs e)
    {
        base.OnClosing(e);
        if (e.Cancel || !IsUserClose(e) || CanCloseToTray?.Invoke() != true) return;

        e.Cancel = true;
        Hide();
        // Hidden isn't exited, and the user may never come back before the machine goes down: write pending debounced
        // edits now (notes, Cloudflare profiles, settings), as an exit would. After Hide, so the window goes at once.
        (DataContext as MainViewModel)?.FlushPersistence();
    }

    // Only the user's own close — the title-bar button, Alt+F4, Cmd+W, the taskbar's "Close window": the platform raises
    // these as WindowClosing and never programmatic. Quit / Cmd+Q / TryShutdown (ApplicationShutdown), the OS shutting
    // down or logging off (OSShutdown, or ApplicationShutdown for a logoff), a Close() call from code (programmatic) and
    // anything the platform doesn't explain (Undefined) must really close, so ShutdownRequested -> FlushOnExit still runs.
    private static bool IsUserClose(WindowClosingEventArgs e)
        => e.CloseReason == WindowCloseReason.WindowClosing && !e.IsProgrammatic;

    protected override void OnClosed(EventArgs e)
    {
        _closed = true;
        base.OnClosed(e);
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        // hidden in the tray or minimized: nobody sees the pages (their clocks pause, see AppPlatform.IsInForeground)
        if (change.Property == WindowStateProperty || change.Property == IsVisibleProperty)
            Helpers.AppPlatform.SetForeground(IsVisible && WindowState != WindowState.Minimized);
        if (change.Property == WindowStateProperty)
        {
            var state = change.GetNewValue<WindowState>();
            // No maximize (see OnOpened): maximized / full screen (Win+Up, a shell command) go straight back.
            if (state is WindowState.Maximized or WindowState.FullScreen)
            {
                Avalonia.Threading.Dispatcher.UIThread.Post(() => WindowState = WindowState.Normal);
                return;
            }
            if (state != WindowState.Minimized) _restoreState = state;
        }
    }

    /// <summary>
    /// Brings the window back — from the tray icon or menu, the macOS Dock, a second launch: shown if it was hidden,
    /// un-minimized to its previous state, activated. Safe to repeat. UI thread.
    /// </summary>
    public void BringToFront()
    {
        if (_closed) return;   // a closed window can't be shown again (Avalonia throws); only reachable while shutting down
        if (!IsVisible) Show();
        if (WindowState == WindowState.Minimized) WindowState = _restoreState;
        Activate();
    }
}
