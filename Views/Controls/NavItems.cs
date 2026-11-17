using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Threading;
using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Echoes.Helpers;
using Echoes.ViewModels;

namespace Echoes.Views.Controls;

/// <summary>
/// The metadata the phone drawer shows for a tool: the section it starts (<see cref="Group"/>, e.g. "Diagnose"), its
/// name (<see cref="Title"/>) and one line on what it does (<see cref="Subtitle"/>), the last two as the page header.
/// </summary>
public interface INavInfo
{
    string? Group { get; }
    string? Title { get; }
    string? Subtitle { get; }
}

/// <summary>
/// A desktop tab: one tool instance (<see cref="Tool"/>; which of the tool's tabs it is, <see cref="InstanceId"/>; the
/// settings it keeps, <see cref="Store"/>; its view-model once its page is built), or a new tab (no tool: the launcher).
/// A tool's content is an empty host its page is built in the first time the tab is shown (ToolViews). Closing a tab
/// ends what runs in it (MainView).
/// </summary>
public class NavTabItem : TabItem
{
    public static readonly StyledProperty<Geometry?> GlyphProperty =
        AvaloniaProperty.Register<NavTabItem, Geometry?>(nameof(Glyph));
    public static readonly StyledProperty<string?> TipProperty =
        AvaloniaProperty.Register<NavTabItem, string?>(nameof(Tip));

    /// <summary>Raised (bubbling) by the tab's close button or a middle click; the shell decides what follows.</summary>
    public static readonly RoutedEvent<RoutedEventArgs> CloseRequestedEvent =
        RoutedEvent.Register<NavTabItem, RoutedEventArgs>(nameof(CloseRequested), RoutingStrategies.Bubble);

    public NavTabItem(ToolInfo? tool, int instanceId, ToolStore? store)
    {
        Tool = tool;
        InstanceId = tool is null ? 0 : instanceId;
        Store = tool is null ? null : store ?? ToolStore.Main;
        Tag = tool?.Tag;
        Classes.Add("navtab");
        if (tool is not null) Content = new Decorator();
    }

    /// <summary>The tool; null for a new tab.</summary>
    public ToolInfo? Tool { get; }

    /// <summary>0: the tool's first tab (its settings are the tool's own, as on the phone); else a further tab's id.</summary>
    public int InstanceId { get; }

    public ToolStore? Store { get; }

    /// <summary>The view-model of the tool's page, once built. The tab watches it for <see cref="State"/>.</summary>
    public object? ViewModel
    {
        get => _viewModel;
        set
        {
            if (ReferenceEquals(_viewModel, value)) return;
            if (_viewModel is INotifyPropertyChanged old) old.PropertyChanged -= OnModelChanged;
            _viewModel = value;
            if (value is INotifyPropertyChanged now) now.PropertyChanged += OnModelChanged;
            bool wasUnseen = _unseen;
            _unseen = false;
            if (!UpdateState() && wasUnseen) ShowState();
        }
    }

    private object? _viewModel;

    // ---- what runs in the tab: a dot in place of its glyph ----

    /// <summary>What the tool in this tab is doing (<see cref="IToolSession.State"/>), shown as a dot in place of the tab's
    /// glyph (green running, amber waiting, red down) by the pseudo-classes :running, :waiting, :down.</summary>
    public ToolState State => _state;

    /// <summary>Its run ended while another tab was chosen: a blue dot (:unseen) until this tab is chosen again, so a scan
    /// or a speed test finished in the background is noticed.</summary>
    public bool IsUnseen => _unseen;

    /// <summary>Raised when <see cref="State"/> or <see cref="IsUnseen"/> changes (UI thread).</summary>
    public event EventHandler? StateChanged;

    private ToolState _state;
    private bool _unseen;

    // A view-model may raise its changes from a worker thread; the state is read and shown on the UI thread, by one queued
    // check however many changes come in meanwhile (a capture raises several every 150 ms).
    private void OnModelChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (Dispatcher.UIThread.CheckAccess())
        {
            UpdateState();
            return;
        }
        if (Interlocked.Exchange(ref _checkQueued, 1) == 1) return;
        Dispatcher.UIThread.Post(() =>
        {
            Volatile.Write(ref _checkQueued, 0);
            UpdateState();
        });
    }

    private int _checkQueued;

    // Reads the state again; true when it changed (and is shown).
    private bool UpdateState()
    {
        var state = (_viewModel as IToolSession)?.State ?? ToolState.Idle;
        if (state == _state) return false;
        bool ended = state == ToolState.Idle && _state != ToolState.Idle;
        _state = state;
        // a run that ends while the tab is out of sight leaves the blue dot; a new one takes its place
        _unseen = ended ? !IsSelected : _unseen && state == ToolState.Idle;
        ShowState();
        return true;
    }

    private void ShowState()
    {
        PseudoClasses.Set(":running", _state == ToolState.Running);
        PseudoClasses.Set(":waiting", _state == ToolState.Waiting);
        PseudoClasses.Set(":down", _state == ToolState.Down);
        PseudoClasses.Set(":unseen", _state == ToolState.Idle && _unseen);
        UpdateTip();
        StateChanged?.Invoke(this, EventArgs.Empty);
    }

    // The tooltip says what the dot means: "Ping: 1.1.1.1 · running".
    private void UpdateTip()
    {
        string? note = _state switch
        {
            ToolState.Running => "running",
            ToolState.Waiting => "waiting",
            ToolState.Down => "something is down",
            _ => _unseen ? "finished while you were away" : null,
        };
        TipShown = note is null ? Tip : string.IsNullOrEmpty(Tip) ? note : Tip + " · " + note;
        AutomationProperties.SetHelpText(this, note);
    }

    public static readonly DirectProperty<NavTabItem, string?> TipShownProperty =
        AvaloniaProperty.RegisterDirect<NavTabItem, string?>(nameof(TipShown), o => o.TipShown);

    /// <summary>The tab's tooltip: <see cref="Tip"/>, and what runs in it.</summary>
    public string? TipShown
    {
        get => _tipShown;
        private set => SetAndRaise(TipShownProperty, ref _tipShown, value);
    }

    private string? _tipShown;

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == TipProperty) UpdateTip();
        // chosen again: whatever finished here has been seen
        else if (change.Property == IsSelectedProperty && IsSelected && _unseen)
        {
            _unseen = false;
            ShowState();
        }
    }

    /// <summary>When the tab was last the chosen one (relative to the others).</summary>
    public long LastUsed { get; set; }

    /// <summary>The shell's watch on <see cref="Store"/> for the tab's label, removed when the tab closes.</summary>
    public Action<string>? SubjectWatch { get; set; }

    public bool IsNewTab => Tool is null;

    /// <summary>The tab in the saved list: "PING" (the tool's first tab), "PING#7" (a further one) or "NEW".</summary>
    public string SaveKey => Tool is null ? NewTabKey
        : InstanceId == 0 ? Tool.Tag : Tool.Tag + "#" + InstanceId.ToString(CultureInfo.InvariantCulture);

    public const string NewTabKey = "NEW";

    /// <summary>The tool's 24-unit glyph (Assets/ToolIcons.axaml), drawn at the start of the tab.</summary>
    public Geometry? Glyph { get => GetValue(GlyphProperty); set => SetValue(GlyphProperty, value); }

    public string? Tip { get => GetValue(TipProperty); set => SetValue(TipProperty, value); }

    public event EventHandler<RoutedEventArgs>? CloseRequested
    {
        add => AddHandler(CloseRequestedEvent, value);
        remove => RemoveHandler(CloseRequestedEvent, value);
    }

    private Button? _close;

    protected override void OnApplyTemplate(TemplateAppliedEventArgs e)
    {
        base.OnApplyTemplate(e);
        if (_close is not null) _close.Click -= OnCloseClick;
        _close = e.NameScope.Find<Button>("PART_Close");
        if (_close is not null) _close.Click += OnCloseClick;
    }

    private void OnCloseClick(object? sender, RoutedEventArgs e)
    {
        e.Handled = true;
        RaiseEvent(new RoutedEventArgs(CloseRequestedEvent, this));
    }

    // A middle click closes a tab, as in a browser.
    protected override void OnPointerReleased(PointerReleasedEventArgs e)
    {
        base.OnPointerReleased(e);
        if (e.InitialPressMouseButton == MouseButton.Middle)
        {
            e.Handled = true;
            RaiseEvent(new RoutedEventArgs(CloseRequestedEvent, this));
        }
    }

    // Styled (and themed) as a plain TabItem: selectors like "TabItem.navtab" match it.
    protected override Type StyleKeyOverride => typeof(TabItem);
}

/// <summary>
/// The desktop shell's TabControl. Unlike a plain one it may have nothing selected for a moment (the shell always keeps
/// one tab: a new tab when the last one closes).
/// </summary>
public class ShellTabControl : TabControl
{
    public ShellTabControl() => SelectionMode = SelectionMode.Single;

    protected override Type StyleKeyOverride => typeof(TabControl);
}

/// <summary>
/// The top bar's row of tabs, in their order, each at its natural width so its label shows in full. When they don't fit,
/// the widest give way first (labels trimming to an ellipsis), down to each tab's MinWidth; past that the row scrolls
/// (the mouse wheel over it, or the arrows at its ends, <see cref="ScrollPage"/>; the chosen tab is kept in view,
/// <see cref="Reveal"/>). No tab is ever closed for room.
/// A tab can be dragged along the row to another place (<see cref="Reordered"/>).
/// </summary>
public sealed class TabStripPanel : Panel
{
    public static readonly StyledProperty<double> SpacingProperty =
        AvaloniaProperty.Register<TabStripPanel, double>(nameof(Spacing));

    static TabStripPanel() => AffectsMeasure<TabStripPanel>(SpacingProperty);

    public TabStripPanel()
    {
        // on the row, not on each tab: a pressed tab keeps the pointer, and its moves come up through here (also the ones
        // a tab has marked handled)
        AddHandler(PointerPressedEvent, OnTabPressed, RoutingStrategies.Bubble, handledEventsToo: true);
        AddHandler(PointerMovedEvent, OnTabMoved, RoutingStrategies.Bubble, handledEventsToo: true);
        AddHandler(PointerReleasedEvent, OnTabReleased, RoutingStrategies.Bubble, handledEventsToo: true);
    }

    public double Spacing { get => GetValue(SpacingProperty); set => SetValue(SpacingProperty, value); }

    private readonly List<(Control Child, double Width)> _row = new();
    private readonly List<double> _lefts = new();   // each tab's left edge as last arranged, parallel to _row
    private double _extent, _viewport, _offset;
    private Control? _reveal;
    private Control? _kept;   // the tab last revealed: kept in view when the bar's width changes
    private bool _overflowing, _canBack, _canForward;

    /// <summary>The row is wider than the bar: some tabs are scrolled out of view.</summary>
    public bool IsOverflowing => _overflowing;

    /// <summary>Tabs are out of view before the first one showing (the arrow at the row's start goes to them).</summary>
    public bool CanScrollBack => _canBack;

    /// <summary>Tabs are out of view after the last one showing (the arrow at the row's end goes to them).</summary>
    public bool CanScrollForward => _canForward;

    /// <summary>Raised (after the layout pass that changed them) when <see cref="IsOverflowing"/>,
    /// <see cref="CanScrollBack"/> or <see cref="CanScrollForward"/> change.</summary>
    public event EventHandler? ScrollChanged;

    protected override Size MeasureOverride(Size availableSize)
    {
        _row.Clear();
        double height = 0;
        foreach (var child in Children)
        {
            if (!child.IsVisible) continue;
            child.Measure(new Size(double.PositiveInfinity, availableSize.Height));
            _row.Add((child, child.DesiredSize.Width));
            height = Math.Max(height, child.DesiredSize.Height);
        }
        _extent = 0;
        if (_row.Count == 0) return default;

        double gaps = Spacing * (_row.Count - 1);
        double total = gaps;
        foreach (var (_, w) in _row) total += w;
        if (!double.IsInfinity(availableSize.Width) && total > availableSize.Width)
        {
            // Water-filling: the largest width cap at which the row fits; tabs narrower than it keep their width, none goes
            // below its MinWidth (then the row is wider than the bar, and scrolls).
            double room = Math.Max(0, availableSize.Width - gaps);
            var widths = new List<double>(_row.Count);
            foreach (var (_, w) in _row) widths.Add(w);
            widths.Sort();
            double cap = 0, used = 0;
            for (int i = 0; i < widths.Count; i++)
            {
                double share = (room - used) / (widths.Count - i);
                if (widths[i] <= share) { used += widths[i]; continue; }
                cap = share;
                break;
            }
            total = gaps;
            for (int i = 0; i < _row.Count; i++)
            {
                var (child, w) = _row[i];
                double fitted = Math.Max(child.MinWidth, Math.Min(w, cap));
                if (fitted < w) child.Measure(new Size(fitted, availableSize.Height));
                _row[i] = (child, fitted);
                total += fitted;
            }
        }
        _extent = total;
        return new Size(double.IsInfinity(availableSize.Width) ? total : Math.Min(total, availableSize.Width), height);
    }

    protected override Size ArrangeOverride(Size finalSize)
    {
        // The bar's width changed (the window was resized, the list-of-tabs button came or went beside the row): the tab
        // last revealed, the chosen one, stays in view. A wheel scroll changes no width, so it is left where it was put.
        if (_reveal is null && _kept is not null && Math.Abs(finalSize.Width - _viewport) > 0.5) _reveal = _kept;
        _viewport = finalSize.Width;
        double max = Math.Max(0, _extent - _viewport);
        if (_reveal is { } target)
        {
            double x0 = 0;
            foreach (var (child, w) in _row)
            {
                if (ReferenceEquals(child, target))
                {
                    if (x0 < _offset) _offset = x0;
                    else if (x0 + w > _offset + _viewport) _offset = x0 + w - _viewport;
                    break;
                }
                x0 += w + Spacing;
            }
            _reveal = null;
        }
        _offset = Math.Clamp(_offset, 0, max);

        double x = -_offset;
        _lefts.Clear();
        foreach (var (child, w) in _row)
        {
            _lefts.Add(x);
            child.Arrange(new Rect(x, 0, w, finalSize.Height));
            x += w + Spacing;
        }
        foreach (var child in Children)
            if (!child.IsVisible) child.Arrange(default);
        if (_dragging) ShowDrag();   // the row was laid out again under a drag (the window resized): the same drag on the new places

        // half a pixel of slack: a row that fits exactly doesn't count (layout rounding)
        bool overflowing = max > 0.5, back = _offset > 0.5, forward = _offset < max - 0.5;
        if (overflowing != _overflowing || back != _canBack || forward != _canForward)
        {
            _overflowing = overflowing;
            _canBack = back;
            _canForward = forward;
            // posted: the listener shows or hides buttons beside the row, which must not happen inside this pass
            Dispatcher.UIThread.Post(() => ScrollChanged?.Invoke(this, EventArgs.Empty));
        }
        return finalSize;
    }

    /// <summary>Scrolls the row (when it is wider than the bar) so that this tab shows whole.</summary>
    public void Reveal(Control child)
    {
        StopGlide();
        _reveal = child;
        _kept = child;
        InvalidateArrange();
    }

    // ---- the arrows at the row's ends ----

    /// <summary>Scrolls about a bar's width of tabs back (-1) or forward (1), stopping where a tab starts so the first one
    /// showing is whole (at the very end, the last one ends with the row). The row glides there.</summary>
    public void ScrollPage(int way)
    {
        double max = Math.Max(0, _extent - _viewport);
        if (max <= 0 || _row.Count == 0 || _dragging || way == 0) return;
        // a click while the row still glides goes on from where it is heading
        double from = _glide?.IsEnabled == true ? _glideTo : _offset;
        double target = Math.Clamp(from + Math.Sign(way) * Math.Max(120, _viewport * 0.7), 0, max);
        if (target > 0 && target < max)
        {
            var starts = new List<double>(_row.Count);
            double x = 0;
            foreach (var (_, w) in _row)
            {
                starts.Add(x);
                x += w + Spacing;
            }
            int at = starts.FindLastIndex(start => start <= target);   // the tab under the target (the first starts at 0)
            double snapped = starts[at];
            // a tab wider than the step: on to the next one, so every click moves
            if (way > 0 && snapped <= from + 0.5) snapped = at + 1 < starts.Count ? starts[at + 1] : max;
            else if (way < 0 && snapped >= from - 0.5) snapped = at > 0 ? starts[at - 1] : 0;
            target = Math.Clamp(snapped, 0, max);
        }
        if (Math.Abs(target - _offset) < 0.5) return;
        _glideFrom = _offset;
        _glideTo = target;
        _glideStart = Stopwatch.GetTimestamp();
        if (_glide is null)
        {
            _glide = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(15) };
            _glide.Tick += (_, _) => GlideStep();
        }
        _glide.Start();
    }

    // The glide: quick at first, easing into place; the timer runs only while the row moves.
    private DispatcherTimer? _glide;
    private double _glideFrom, _glideTo;
    private long _glideStart;
    private const double GlideMs = 160;

    private void GlideStep()
    {
        double t = Math.Min(1, Stopwatch.GetElapsedTime(_glideStart).TotalMilliseconds / GlideMs);
        double eased = 1 - (1 - t) * (1 - t) * (1 - t);
        _offset = _glideFrom + (_glideTo - _glideFrom) * eased;
        if (t >= 1) _glide!.Stop();
        InvalidateArrange();
    }

    // the wheel, a drag or a tab being revealed takes over from a glide
    private void StopGlide() => _glide?.Stop();

    // ---- dragging a tab to another place in the row ----

    /// <summary>A tab was dragged to another place: the tab, and the index among the row's children it goes to. The row
    /// only shows the drag; the shell moves the tab.</summary>
    public event Action<Control, int>? Reordered;

    private const double DragStart = 6;   // how far the pointer goes on a pressed tab before it is a drag and not a click
    private Control? _pressed;            // the tab the pointer went down on
    private bool _dragging;
    private double _pressX, _dragBy;
    private int _dropAt = -1;             // where in the row the dragged tab would land

    private void OnTabPressed(object? sender, PointerPressedEventArgs e)
    {
        if (_dragging) return;
        _pressed = null;
        if (!e.GetCurrentPoint(this).Properties.IsLeftButtonPressed) return;
        Control? tab = null;
        for (var v = e.Source as Visual; v is not null && !ReferenceEquals(v, this); v = v.GetVisualParent())
        {
            if (v is Button) return;   // a tab's close button is its own click
            if (v is Control c && ReferenceEquals(c.GetVisualParent(), this)) tab = c;
        }
        _pressed = tab;
        _pressX = e.GetPosition(this).X;
    }

    private void OnTabMoved(object? sender, PointerEventArgs e)
    {
        if (_pressed is null) return;
        if (!e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
        {
            // let go somewhere the row didn't hear of
            if (_dragging) EndDrag(commit: false);
            else _pressed = null;
            return;
        }
        double by = e.GetPosition(this).X - _pressX;
        if (!_dragging)
        {
            if (Math.Abs(by) < DragStart || _row.Count < 2) return;
            // The tab keeps the pointer till it is let go, wherever it goes: its moves and its release still come up
            // through the row, and the tab itself sees the release (its pressed look ends there).
            e.Pointer.Capture(_pressed);
            _pressed.PointerCaptureLost += OnDragCaptureLost;
            StopGlide();
            _dragging = true;
            if (_pressed is TabItem tab) tab.IsSelected = true;   // a finger's press chooses a tab only when it lifts
            _pressed.ZIndex = 1;   // drawn over the tabs it passes
            // no tab's tooltip comes up under the pointer while it carries one (set on each tab: a tab takes inherited
            // values from the tab control, not from this row)
            foreach (var child in Children)
            {
                ToolTip.SetServiceEnabled(child, false);
                ToolTip.SetIsOpen(child, false);
            }
        }
        _dragBy = by;
        ShowDrag();
        e.Handled = true;
    }

    private void OnTabReleased(object? sender, PointerReleasedEventArgs e)
    {
        if (!_dragging)
        {
            _pressed = null;
            return;
        }
        e.Handled = true;
        EndDrag(commit: true);
        e.Pointer.Capture(null);
    }

    // The pointer was taken from the dragged tab (the window lost the input, another gesture took over): the tab goes
    // back where it was.
    private void OnDragCaptureLost(object? sender, PointerCaptureLostEventArgs e) => EndDrag(commit: false);

    // The dragged tab follows the pointer, inside the bar and the row; the tabs it has passed the middle of step aside by
    // its width. What shows is the row as it will be when the tab is let go. Render transforms only: the layout, and the
    // order of the tabs, stay as they are until then.
    private void ShowDrag()
    {
        int from = _pressed is null ? -1 : _row.FindIndex(r => ReferenceEquals(r.Child, _pressed));
        if (from < 0 || _lefts.Count != _row.Count)
        {
            _dropAt = -1;
            return;
        }
        double width = _row[from].Width, home = _lefts[from];
        double lowest = Math.Max(0, _lefts[0]);
        double highest = Math.Min(_viewport, _lefts[^1] + _row[^1].Width) - width;
        double wanted = home + _dragBy;
        double left = highest < lowest ? home : Math.Clamp(wanted, lowest, highest);
        double right = left + width;
        // held against an end of the bar with more of the row beyond it: the row scrolls under the tab
        double max = Math.Max(0, _extent - _viewport);
        ScrollUnderDrag(wanted < lowest - 1 && _offset > 0.5 ? -1 : wanted > highest + 1 && _offset < max - 0.5 ? 1 : 0);

        int to = from;
        for (int i = 0; i < from; i++)
            if (left < _lefts[i] + _row[i].Width / 2) { to = i; break; }
        if (to == from)
            for (int i = _row.Count - 1; i > from; i--)
                if (right > _lefts[i] + _row[i].Width / 2) { to = i; break; }
        _dropAt = to;

        double step = width + Spacing;
        for (int i = 0; i < _row.Count; i++)
        {
            double shift = i == from ? left - home
                : i >= to && i < from ? step
                : i > from && i <= to ? -step
                : 0;
            Shift(_row[i].Child, shift);
        }
    }

    // While a dragged tab is held at an end of a row that goes on beyond it, the row scrolls that way in small steps, so
    // the tab can be taken to a place that was out of view. The timer runs only then.
    private DispatcherTimer? _edgeTimer;
    private int _edgeWay;

    private void ScrollUnderDrag(int way)
    {
        _edgeWay = way;
        if (way == 0)
        {
            _edgeTimer?.Stop();
            return;
        }
        if (_edgeTimer is null)
        {
            _edgeTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(20) };
            _edgeTimer.Tick += (_, _) =>
            {
                double before = _offset;
                _offset = Math.Clamp(_offset + _edgeWay * 8, 0, Math.Max(0, _extent - _viewport));
                double moved = _offset - before;
                if (!_dragging || moved == 0)
                {
                    _edgeTimer!.Stop();
                    return;
                }
                // the row went by under the pointer: the tab's own place moved with it, the tab stays in the hand
                _pressX -= moved;
                _dragBy += moved;
                InvalidateArrange();
            };
        }
        _edgeTimer.Start();
    }

    private static void Shift(Control child, double by)
    {
        if (by == 0) child.RenderTransform = null;
        else if (child.RenderTransform is TranslateTransform move) move.X = by;
        else child.RenderTransform = new TranslateTransform(by, 0);
    }

    private void EndDrag(bool commit)
    {
        var tab = _pressed;
        bool dragged = _dragging;
        int from = tab is null ? -1 : _row.FindIndex(r => ReferenceEquals(r.Child, tab));
        Control? target = dragged && _dropAt >= 0 && _dropAt < _row.Count ? _row[_dropAt].Child : null;
        _pressed = null;
        _dragging = false;
        _dragBy = 0;
        _dropAt = -1;
        _edgeTimer?.Stop();
        if (!dragged || tab is null) return;
        tab.PointerCaptureLost -= OnDragCaptureLost;
        foreach (var child in Children)
        {
            Shift(child, 0);
            child.ClearValue(ToolTip.ServiceEnabledProperty);
        }
        tab.ZIndex = 0;
        if (commit && from >= 0 && target is not null && !ReferenceEquals(target, tab))
            Reordered?.Invoke(tab, Children.IndexOf(target));
    }

    protected override void OnPointerWheelChanged(PointerWheelEventArgs e)
    {
        base.OnPointerWheelChanged(e);
        if (_dragging) return;
        double max = Math.Max(0, _extent - _viewport);
        if (max <= 0) return;
        StopGlide();
        double delta = Math.Abs(e.Delta.X) > Math.Abs(e.Delta.Y) ? e.Delta.X : e.Delta.Y;
        _offset = Math.Clamp(_offset - delta * 48, 0, max);
        InvalidateArrange();
        e.Handled = true;
    }
}

/// <summary>
/// The top bar's tabs and the buttons right after them (+, and the list of all tabs while the row scrolls): the tabs get
/// whatever room the buttons leave (the first child, the tab row, shrinks and scrolls inside it), and the buttons sit
/// after the last tab, not at the far end of the bar.
/// </summary>
public sealed class TabBarPanel : Panel
{
    protected override Size MeasureOverride(Size availableSize)
    {
        if (Children.Count < 2) return base.MeasureOverride(availableSize);
        Control strip = Children[0];
        double buttons = 0, height = 0;
        for (int i = 1; i < Children.Count; i++)
        {
            Children[i].Measure(availableSize);   // a hidden one measures as nothing
            buttons += Children[i].DesiredSize.Width;
            height = Math.Max(height, Children[i].DesiredSize.Height);
        }
        double room = double.IsInfinity(availableSize.Width) ? availableSize.Width
            : Math.Max(0, availableSize.Width - buttons);
        strip.Measure(new Size(room, availableSize.Height));
        return new Size(strip.DesiredSize.Width + buttons, Math.Max(strip.DesiredSize.Height, height));
    }

    protected override Size ArrangeOverride(Size finalSize)
    {
        if (Children.Count < 2) return base.ArrangeOverride(finalSize);
        Control strip = Children[0];
        double buttons = 0;
        for (int i = 1; i < Children.Count; i++) buttons += Children[i].DesiredSize.Width;
        double x = Math.Min(strip.DesiredSize.Width, Math.Max(0, finalSize.Width - buttons));
        strip.Arrange(new Rect(0, 0, x, finalSize.Height));
        for (int i = 1; i < Children.Count; i++)
        {
            double w = Children[i].DesiredSize.Width;
            Children[i].Arrange(new Rect(x, 0, w, finalSize.Height));
            x += w;
        }
        return finalSize;
    }
}

/// <summary>
/// The inside of a tab: [glyph] label [close]. The close button's slot always counts in the tab's natural width, so a
/// tab is as wide whether the button shows or not, and nothing moves when the pointer crosses the bar. In a tab squeezed
/// below that width (a full bar) the label takes the slot as well while the button is hidden (a tab that is neither
/// chosen nor under the pointer), so more of its name stays readable.
/// </summary>
public sealed class TabRowPanel : Panel
{
    public static readonly StyledProperty<double> CloseSlotProperty =
        AvaloniaProperty.Register<TabRowPanel, double>(nameof(CloseSlot), 16);

    static TabRowPanel() => AffectsMeasure<TabRowPanel>(CloseSlotProperty);

    /// <summary>The width kept for the close button (the third child).</summary>
    public double CloseSlot { get => GetValue(CloseSlotProperty); set => SetValue(CloseSlotProperty, value); }

    protected override Size MeasureOverride(Size availableSize)
    {
        if (Children.Count != 3) return base.MeasureOverride(availableSize);
        Control icon = Children[0], label = Children[1], close = Children[2];
        double slot = CloseSlot;
        var unbounded = new Size(double.PositiveInfinity, availableSize.Height);
        icon.Measure(unbounded);
        close.Measure(new Size(slot, availableSize.Height));
        label.Measure(unbounded);
        double natural = icon.DesiredSize.Width + label.DesiredSize.Width + slot;
        if (natural > availableSize.Width)
        {
            // squeezed: the label trims to the room it has, which includes the slot while the button is hidden
            double room = availableSize.Width - icon.DesiredSize.Width - (close.IsVisible ? slot : 0);
            label.Measure(new Size(Math.Max(0, room), availableSize.Height));
        }
        double height = Math.Max(icon.DesiredSize.Height, Math.Max(label.DesiredSize.Height, close.DesiredSize.Height));
        return new Size(Math.Min(natural, availableSize.Width), height);
    }

    protected override Size ArrangeOverride(Size finalSize)
    {
        if (Children.Count != 3) return base.ArrangeOverride(finalSize);
        Control icon = Children[0], label = Children[1], close = Children[2];
        double slot = Math.Min(CloseSlot, finalSize.Width);
        double iconWidth = Math.Min(icon.DesiredSize.Width, finalSize.Width);
        icon.Arrange(new Rect(0, 0, iconWidth, finalSize.Height));
        // up to the slot; over it only as far as the label was measured to need (a squeezed tab, the button hidden)
        double beforeSlot = Math.Max(0, finalSize.Width - iconWidth - slot);
        double labelWidth = close.IsVisible ? beforeSlot
            : Math.Min(Math.Max(beforeSlot, label.DesiredSize.Width), Math.Max(0, finalSize.Width - iconWidth));
        label.Arrange(new Rect(iconWidth, 0, labelWidth, finalSize.Height));
        close.Arrange(new Rect(finalSize.Width - slot, 0, slot, finalSize.Height));
        return finalSize;
    }
}

/// <summary>Mobile drawer entry: a ListBoxItem (index-coupled to the page Carousel) plus page metadata.</summary>
public class NavListItem : ListBoxItem, INavInfo
{
    public static readonly StyledProperty<string?> GroupProperty =
        AvaloniaProperty.Register<NavListItem, string?>(nameof(Group));
    public static readonly StyledProperty<string?> TitleProperty =
        AvaloniaProperty.Register<NavListItem, string?>(nameof(Title));
    public static readonly StyledProperty<string?> SubtitleProperty =
        AvaloniaProperty.Register<NavListItem, string?>(nameof(Subtitle));

    public string? Group { get => GetValue(GroupProperty); set => SetValue(GroupProperty, value); }
    public string? Title { get => GetValue(TitleProperty); set => SetValue(TitleProperty, value); }
    public string? Subtitle { get => GetValue(SubtitleProperty); set => SetValue(SubtitleProperty, value); }

    protected override Type StyleKeyOverride => typeof(ListBoxItem);
}
