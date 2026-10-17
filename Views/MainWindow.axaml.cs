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
        // The UI lives in MainView (shared with the Android single-view head);
        // it triggers the update check on Loaded.
    }

    // The window is 860 wide to start (the sidebar always shows its labels; the width stays the user's) and exactly as
    // tall as the nav list, always: never shorter (the sidebar would scroll) and never taller (empty space under it).
    // It opens fitted (SizeToContent = Height; the page area asks for no height, see HeightNeutral), then the height is
    // locked there (MinHeight = MaxHeight, no maximize) and re-fitted when the sidebar grows (the update pill) or the
    // window moves to a screen with another scale. On a screen shorter than the list it stops at the work area, where
    // the list scrolls: the only case it does.
    protected override void OnOpened(EventArgs e)
    {
        base.OnOpened(e);
        // Opened can come again after the window is hidden to the tray and shown: subscribe once, not on every show.
        if (!_fitHooked)
        {
            _fitHooked = true;
            ScalingChanged += (_, _) => PostFit();
            if (DataContext is MainViewModel vm)
                vm.PropertyChanged += (_, a) => { if (a.PropertyName == nameof(MainViewModel.IsUpdateAvailable)) PostFit(); };
        }
        PostFit();
    }

    private bool _fitPending, _fitHooked;

    private void PostFit()
        => Avalonia.Threading.Dispatcher.UIThread.Post(FitHeightToNav, Avalonia.Threading.DispatcherPriority.Background);

    // Avalonia measures and sizes the frame itself (SizeToContent); the result is then pinned with MinHeight = MaxHeight.
    private void FitHeightToNav()
    {
        if (_closed) return;
        if (!IsVisible || WindowState != WindowState.Normal) { _fitPending = true; return; }   // when it's back
        _fitPending = false;
        MinHeight = 0;   // free first, or the old lock would clamp the new fit
        MaxHeight = double.PositiveInfinity;
        SizeToContent = SizeToContent.Height;
        Avalonia.Threading.Dispatcher.UIThread.Post(LockHeight, Avalonia.Threading.DispatcherPriority.Background);
    }

    private void LockHeight()
    {
        if (_closed || SizeToContent != SizeToContent.Height) return;
        double fit = ClientSize.Height;
        SizeToContent = SizeToContent.Manual;
        if (fit <= 0) return;
        // A screen shorter than the list: stop at its work area (the list scrolls there — the one case it does).
        if (Screens.ScreenFromWindow(this) is { } screen && screen.Scaling > 0)
        {
            double frame = Math.Max(0, (FrameSize?.Height ?? fit) - fit);
            double room = Math.Floor(screen.WorkingArea.Height / screen.Scaling - frame);
            if (fit > room && room > 200) { Height = room; fit = room; }
        }
        // With the client area extended into the title bar, Avalonia on Windows adds the decoration margin to
        // Min/MaxHeight once more when it builds the window's track size (measured: a lock at the fitted height let the
        // window grow by the title bar's 30 DIP). So the lock leaves it out; the window then sits exactly at the fit.
        double margin = OperatingSystem.IsWindows() && IsExtendedIntoWindowDecorations
            ? WindowDecorationMargin.Top + WindowDecorationMargin.Bottom : 0;
        MinHeight = MaxHeight = Math.Max(0, fit - margin);
    }

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
        if (change.Property == WindowStateProperty)
        {
            var state = change.GetNewValue<WindowState>();
            // The height is the nav list's: maximized / full screen (Win+Up, a shell command) go straight back.
            if (state is WindowState.Maximized or WindowState.FullScreen)
            {
                Avalonia.Threading.Dispatcher.UIThread.Post(() => WindowState = WindowState.Normal);
                return;
            }
            if (state != WindowState.Minimized) _restoreState = state;
            if (state == WindowState.Normal && _fitPending) PostFit();
        }
        else if (change.Property == IsVisibleProperty && change.GetNewValue<bool>() && _fitPending) PostFit();
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
