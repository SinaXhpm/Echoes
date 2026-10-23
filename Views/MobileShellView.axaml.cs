using System;
using System.Collections.Specialized;
using System.ComponentModel;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Threading;
using Avalonia.VisualTree;
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
                await vm.CheckForUpdatesIfStale();
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
            _overlays = OverlayLayer.GetOverlayLayer(this);
            if (_overlays is not null) _overlays.Children.CollectionChanged += OnOverlaysChanged;
            UpdateOverlay();
        };
        DetachedFromVisualTree += (_, _) => Unhook();

        Split.PropertyChanged += (_, e) => { if (e.Property == SplitView.IsPaneOpenProperty) UpdateOverlay(); };

        // handledEventsToo: buttons mark their presses handled; tunnel: before the control under the finger acts on them
        AddHandler(HoldingEvent, OnHolding, RoutingStrategies.Bubble, handledEventsToo: true);
        AddHandler(PointerPressedEvent, (_, _) => { _swallowRelease = false; CloseHeldTip(); }, RoutingStrategies.Tunnel, handledEventsToo: true);
        AddHandler(PointerReleasedEvent, OnPointerReleasedAfterHold, RoutingStrategies.Tunnel, handledEventsToo: true);
    }

    private TopLevel? _top;
    private Avalonia.Controls.Platform.IInputPane? _pane;
    private OverlayLayer? _overlays;
    private MainViewModel? _vm;
    private Thickness? _pagesMargin;   // the page area's own margin, before any room was made for the keyboard

    private void Unhook()
    {
        if (_top is not null) _top.BackRequested -= OnBackRequested;
        if (_pane is not null) _pane.StateChanged -= OnInputPaneChanged;
        if (_overlays is not null) _overlays.Children.CollectionChanged -= OnOverlaysChanged;
        _top = null;
        _pane = null;
        _overlays = null;
    }

    // ---------------------------------------------------------------- what covers the page

    // cURL's web preview is a native view, drawn above everything Avalonia draws: it hides while the drawer, the About box
    // or a flyout / menu / drop-down list is open over the page (AppPlatform.OverlayOpen).
    private void UpdateOverlay()
        => AppPlatform.SetOverlay(Split is { IsPaneOpen: true } || _vm is { IsAboutOpen: true } || TopPopup() is not null);

    private void OnOverlaysChanged(object? sender, NotifyCollectionChangedEventArgs e) => UpdateOverlay();

    private void OnVmPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainViewModel.IsAboutOpen)) UpdateOverlay();
    }

    // The popup drawn last, the one on top: a flyout, a menu or a drop-down list (a tooltip has no Popup of its own).
    private Popup? TopPopup()
    {
        if (_overlays is null) return null;
        for (int i = _overlays.Children.Count - 1; i >= 0; i--)
            if (_overlays.Children[i] is OverlayPopupHost { IsVisible: true, Content: Control { Parent: Popup { IsOpen: true } popup } })
                return popup;
        return null;
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

    // Android back closes what is on top first, the way Escape does on a desktop: the drawer, then a flyout, menu or
    // drop-down list (Avalonia closes none of them on back), then whatever the page closes on Escape (cURL's import and
    // save panels, a rename, the Telegram browser). With nothing left to close, Android leaves the app as before. The About
    // box handles its own.
    private void OnBackRequested(object? sender, RoutedEventArgs e)
    {
        if (e.Handled) return;
        if (Split is { IsPaneOpen: true }) { Split.IsPaneOpen = false; e.Handled = true; return; }
        if (_vm is { IsAboutOpen: true }) return;
        if (TopPopup() is { } popup) { popup.IsOpen = false; e.Handled = true; return; }
        e.Handled = EscapeOnPage();
    }

    // An Escape press where the keyboard focus is (on the page itself when nothing there has focus).
    private bool EscapeOnPage()
    {
        Interactive? target = _top?.FocusManager?.GetFocusedElement() is Control { IsEffectivelyVisible: true } focused
                              && focused.IsAttachedToVisualTree() ? focused : SelectedPage();
        if (target is null) return false;
        var esc = new KeyEventArgs { RoutedEvent = KeyDownEvent, Key = Key.Escape, KeyDeviceType = KeyDeviceType.Keyboard };
        target.RaiseEvent(esc);
        return esc.Handled;
    }

    private Control? SelectedPage()
        => Pages is { SelectedIndex: >= 0 } && Pages.SelectedIndex < Pages.ItemCount && Pages.Items[Pages.SelectedIndex] is Decorator host
            ? ToolViews.ViewIn(host) : null;

    // ---------------------------------------------------------------- long-press tooltips

    // A phone has no hover, so the help kept in tooltips (what an option does, an icon button's name) never showed. A
    // finger held on a control shows its tooltip for a few seconds, as Android does for icon buttons, and the release
    // ending that press doesn't click it. Text boxes keep long-press for selecting text, and a control with a context menu
    // keeps it for the menu.
    private Control? _heldTip;
    private bool _swallowRelease;
    private DispatcherTimer? _tipTimer;

    private void OnHolding(object? sender, HoldingRoutedEventArgs e)
    {
        if (e.HoldingState != HoldingState.Started || e.PointerType == PointerType.Mouse) return;
        Control? tipped = null;
        for (var v = e.Source as Visual; v is not null && !ReferenceEquals(v, this); v = v.GetVisualParent())
        {
            if (v is not Control c) continue;
            if (tipped is null)
            {
                if (c is TextBox or AutoCompleteBox) return;   // a hold on the text selects it
                if (c.ContextMenu is not null || c.ContextFlyout is not null) return;
                if (ToolTip.GetTip(c) is not null) tipped = c;
            }
            // a menu further up opens on the same hold; a text box's own menu only from its text (the paste icon's
            // hold doesn't reach it)
            else if (c is not (TextBox or AutoCompleteBox) && (c.ContextMenu is not null || c.ContextFlyout is not null)) return;
        }
        if (tipped is not null) ShowHeldTip(tipped);
    }

    private void ShowHeldTip(Control c)
    {
        CloseHeldTip();
        _heldTip = c;
        _swallowRelease = true;
        ToolTip.SetIsOpen(c, true);
        _tipTimer ??= new DispatcherTimer(TimeSpan.FromSeconds(4), DispatcherPriority.Normal, (_, _) => CloseHeldTip());
        _tipTimer.Stop();
        _tipTimer.Start();
    }

    private void CloseHeldTip()
    {
        _tipTimer?.Stop();
        if (_heldTip is { } c) ToolTip.SetIsOpen(c, false);
        _heldTip = null;
    }

    private void OnPointerReleasedAfterHold(object? sender, PointerReleasedEventArgs e)
    {
        if (!_swallowRelease) return;
        _swallowRelease = false;
        e.Handled = true;   // the press showed a tooltip: the button under it isn't clicked
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
        if (_vm is not null) _vm.PropertyChanged -= OnVmPropertyChanged;
        _vm = DataContext as MainViewModel;
        if (_vm is not null)
        {
            _vm.PropertyChanged += OnVmPropertyChanged;
            EnsureSelectedToolView(_vm);
        }
        UpdateOverlay();
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
