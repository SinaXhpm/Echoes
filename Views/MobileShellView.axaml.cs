using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Echoes.Helpers;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class MobileShellView : UserControl
{
    // App-bar text (bound from the XAML), taken from the selected drawer entry.
    public static readonly Avalonia.StyledProperty<string?> PageTitleProperty =
        Avalonia.AvaloniaProperty.Register<MobileShellView, string?>(nameof(PageTitle));
    public static readonly Avalonia.StyledProperty<string?> PageSubtitleProperty =
        Avalonia.AvaloniaProperty.Register<MobileShellView, string?>(nameof(PageSubtitle));

    public string? PageTitle { get => GetValue(PageTitleProperty); set => SetValue(PageTitleProperty, value); }
    public string? PageSubtitle { get => GetValue(PageSubtitleProperty); set => SetValue(PageSubtitleProperty, value); }

    private void UpdatePageHeader()
    {
        if (Nav?.SelectedItem is Controls.INavInfo nav)
        {
            PageTitle = nav.Title;
            PageSubtitle = nav.Subtitle;
        }
    }

    public MobileShellView()
    {
        InitializeComponent();
        UpdatePageHeader();
        Loaded += async (s, e) =>
        {
            if (DataContext is MainViewModel vm)
                await vm.CheckForUpdatesAsync();
        };
        AttachedToVisualTree += (_, _) => ApplySystemBars();
        ActualThemeVariantChanged += (_, _) => ApplySystemBars();
        AttachedToVisualTree += (_, _) =>
        {
            Unhook();
            _top = TopLevel.GetTopLevel(this);
            if (_top is null) return;
            _top.BackRequested += OnBackRequested;
            _pane = _top.InputPane;
            if (_pane is not null) _pane.StateChanged += OnInputPaneChanged;
        };
        DetachedFromVisualTree += (_, _) => Unhook();
    }

    private TopLevel? _top;
    private Avalonia.Controls.Platform.IInputPane? _pane;
    private Thickness? _pagesMargin;   // the page area's own margin, before any room was made for the keyboard

    private void Unhook()
    {
        if (_top is not null) _top.BackRequested -= OnBackRequested;
        if (_pane is not null) _pane.StateChanged -= OnInputPaneChanged;
        _top = null;
        _pane = null;
    }

    // The on-screen keyboard is drawn OVER the app: a box in the lower half (a chat's message box, a form's last field)
    // ended up behind it, typed into blind. While it is open, the page area gives up the height the keyboard covers, so
    // the page's scroller can bring the focused box into view above it; closed, the margin is the page's own again.
    private void OnInputPaneChanged(object? sender, Avalonia.Controls.Platform.InputPaneStateEventArgs e)
    {
        if (Pages is null || _top is null) return;
        _pagesMargin ??= Pages.Margin;
        var m = _pagesMargin.Value;
        double covered = 0;
        if (e.NewState == Avalonia.Controls.Platform.InputPaneState.Open
            && this.TranslatePoint(new Point(0, Bounds.Height), _top) is { } bottom)
            covered = Math.Clamp(bottom.Y - e.EndRect.Top, 0, Bounds.Height * 0.8);   // the keyboard's part of this shell
        Pages.Margin = new Thickness(m.Left, m.Top, m.Right, m.Bottom + covered);
        if (covered > 0)
            Avalonia.Threading.Dispatcher.UIThread.Post(
                () => (_top?.FocusManager?.GetFocusedElement() as Control)?.BringIntoView(),
                Avalonia.Threading.DispatcherPriority.Background);
    }

    // Android back with the drawer open closes the drawer instead of leaving the app (the About box handles its own).
    private void OnBackRequested(object? sender, RoutedEventArgs e)
    {
        if (e.Handled || Split is not { IsPaneOpen: true }) return;
        Split.IsPaneOpen = false;
        e.Handled = true;
    }

    // Android draws the status / navigation bars itself. This picks their icons' dark or light look for the theme; the
    // bar colours themselves are set by the Android head (MainActivity.ApplySystemBars), which Avalonia's SystemBarColor
    // doesn't do on recent Android (the light theme kept dark bars with dark icons).
    private void ApplySystemBars()
    {
        if (Avalonia.Controls.TopLevel.GetTopLevel(this)?.InsetsManager is { } insets
            && this.TryFindResource("Bg.App", ActualThemeVariant, out var res) && res is Avalonia.Media.ISolidColorBrush brush)
            insets.SystemBarColor = brush.Color;
    }

    // App assigns the MainViewModel after InitializeComponent, when SelectedIndex="0" has already fired
    // Nav_SelectionChanged with no DataContext — build that initially selected tool now.
    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);
        if (DataContext is MainViewModel vm) EnsureSelectedToolView(vm);
    }

    private void TogglePane(object? sender, RoutedEventArgs e)
        => Split.IsPaneOpen = !Split.IsPaneOpen;

    // The About box opens over the page; the drawer it was opened from closes behind it.
    private void About_Click(object? sender, RoutedEventArgs e)
        => Split.IsPaneOpen = false;

    private void Nav_SelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        // SelectionChanged also fires while the XAML tree is still being populated
        // (when SelectedIndex="0" is applied), before sibling named controls like
        // Split are assigned — guard against the null to avoid a startup crash.
        if (Split is not null)
            Split.IsPaneOpen = false; // close the drawer after picking a tool
        UpdatePageHeader();

        // Build the tool on first visit, then mirror the desktop shell's per-tab refresh so live data
        // is current when shown. The tool name lives in Tag: Content is an icon + label panel.
        if (DataContext is MainViewModel vm && (sender as ListBox)?.SelectedItem is ListBoxItem { Tag: string name })
        {
            EnsureSelectedToolView(vm);
            ToolViews.RefreshAfterRender(vm, name, "MobileShell.TabRefresh");
        }
    }

    // Fills the Carousel slot the Nav list is showing (same index) with the tool its Tag names.
    private void EnsureSelectedToolView(MainViewModel vm)
    {
        // Pages is still null while InitializeComponent applies SelectedIndex="0".
        if (Pages is null || Nav?.SelectedItem is not ListBoxItem { Tag: string tool }) return;
        if (tool == "DATA")
        {
            ToolViews.Fill(HistoryHost, "HISTORY", vm);
            ToolViews.Fill(BackupHost, "BACKUP", vm);
        }
        else if (Nav.SelectedIndex < Pages.ItemCount && Pages.Items[Nav.SelectedIndex] is Decorator host)
        {
            ToolViews.Fill(host, tool, vm);
        }
    }
}
