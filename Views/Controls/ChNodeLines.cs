using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using Avalonia;
using Avalonia.Automation.Peers;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Controls.Templates;
using Avalonia.Input;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Media.TextFormatting;
using Avalonia.VisualTree;
using Echoes.Helpers;
using Echoes.ViewModels;

namespace Echoes.Views.Controls;

/// <summary>
/// A line of Check Host's node list, drawn directly rather than templated (a re-sort while results stream in re-lays every
/// visible line; one control with a few cached text layouts costs a fraction of a templated row). The colors are styled
/// properties that CheckHostView sets from the design tokens with DynamicResource, so a theme switch re-colors the lines;
/// sizes and fonts are the static tokens.
/// </summary>
public abstract class ChLine : Control
{
    // Column geometry of a wide line, shared with the column heads above the list (they bind these with x:Static).
    /// <summary>The list's width below which lines use the two-line phone layout.</summary>
    public static double NarrowBelow => 600;
    /// <summary>Chevron + flag, before the location text.</summary>
    public static double LeadColumn => 54;
    public static double LocationColumn => 188;
    public static double NodeColumn => 104;
    public static double ResultColumn => 136;
    public static double LatencyColumn => 72;
    /// <summary>Space between the right-aligned latency and the details.</summary>
    public static double DetailsGap => 14;
    public static double RightPad => 12;
    public static Thickness HeadMargin => new(LeadColumn, 0, RightPad, 0);

    public static readonly StyledProperty<IBrush?> PrimaryBrushProperty = AvaloniaProperty.Register<ChLine, IBrush?>(nameof(PrimaryBrush));
    public static readonly StyledProperty<IBrush?> SecondaryBrushProperty = AvaloniaProperty.Register<ChLine, IBrush?>(nameof(SecondaryBrush));
    public static readonly StyledProperty<IBrush?> MutedBrushProperty = AvaloniaProperty.Register<ChLine, IBrush?>(nameof(MutedBrush));
    public static readonly StyledProperty<IBrush?> SuccessBrushProperty = AvaloniaProperty.Register<ChLine, IBrush?>(nameof(SuccessBrush));
    public static readonly StyledProperty<IBrush?> SuccessSoftBrushProperty = AvaloniaProperty.Register<ChLine, IBrush?>(nameof(SuccessSoftBrush));
    public static readonly StyledProperty<IBrush?> SuccessBorderBrushProperty = AvaloniaProperty.Register<ChLine, IBrush?>(nameof(SuccessBorderBrush));
    public static readonly StyledProperty<IBrush?> WarningBrushProperty = AvaloniaProperty.Register<ChLine, IBrush?>(nameof(WarningBrush));
    public static readonly StyledProperty<IBrush?> WarningSoftBrushProperty = AvaloniaProperty.Register<ChLine, IBrush?>(nameof(WarningSoftBrush));
    public static readonly StyledProperty<IBrush?> WarningBorderBrushProperty = AvaloniaProperty.Register<ChLine, IBrush?>(nameof(WarningBorderBrush));
    public static readonly StyledProperty<IBrush?> DangerBrushProperty = AvaloniaProperty.Register<ChLine, IBrush?>(nameof(DangerBrush));
    public static readonly StyledProperty<IBrush?> DangerSoftBrushProperty = AvaloniaProperty.Register<ChLine, IBrush?>(nameof(DangerSoftBrush));
    public static readonly StyledProperty<IBrush?> DangerBorderBrushProperty = AvaloniaProperty.Register<ChLine, IBrush?>(nameof(DangerBorderBrush));
    public static readonly StyledProperty<IBrush?> NeutralSoftBrushProperty = AvaloniaProperty.Register<ChLine, IBrush?>(nameof(NeutralSoftBrush));
    public static readonly StyledProperty<IBrush?> NeutralBorderBrushProperty = AvaloniaProperty.Register<ChLine, IBrush?>(nameof(NeutralBorderBrush));
    public static readonly StyledProperty<IBrush?> RuleBrushProperty = AvaloniaProperty.Register<ChLine, IBrush?>(nameof(RuleBrush));
    public static readonly StyledProperty<IBrush?> HeaderBrushProperty = AvaloniaProperty.Register<ChLine, IBrush?>(nameof(HeaderBrush));
    public static readonly StyledProperty<IBrush?> HoverBrushProperty = AvaloniaProperty.Register<ChLine, IBrush?>(nameof(HoverBrush));
    public static readonly StyledProperty<IBrush?> PressedBrushProperty = AvaloniaProperty.Register<ChLine, IBrush?>(nameof(PressedBrush));
    public static readonly StyledProperty<IBrush?> SelectedBrushProperty = AvaloniaProperty.Register<ChLine, IBrush?>(nameof(SelectedBrush));
    public static readonly StyledProperty<IBrush?> SelectedHoverBrushProperty = AvaloniaProperty.Register<ChLine, IBrush?>(nameof(SelectedHoverBrush));


    public IBrush? PrimaryBrush { get => GetValue(PrimaryBrushProperty); set => SetValue(PrimaryBrushProperty, value); }
    public IBrush? SecondaryBrush { get => GetValue(SecondaryBrushProperty); set => SetValue(SecondaryBrushProperty, value); }
    public IBrush? MutedBrush { get => GetValue(MutedBrushProperty); set => SetValue(MutedBrushProperty, value); }
    public IBrush? SuccessBrush { get => GetValue(SuccessBrushProperty); set => SetValue(SuccessBrushProperty, value); }
    public IBrush? SuccessSoftBrush { get => GetValue(SuccessSoftBrushProperty); set => SetValue(SuccessSoftBrushProperty, value); }
    public IBrush? SuccessBorderBrush { get => GetValue(SuccessBorderBrushProperty); set => SetValue(SuccessBorderBrushProperty, value); }
    public IBrush? WarningBrush { get => GetValue(WarningBrushProperty); set => SetValue(WarningBrushProperty, value); }
    public IBrush? WarningSoftBrush { get => GetValue(WarningSoftBrushProperty); set => SetValue(WarningSoftBrushProperty, value); }
    public IBrush? WarningBorderBrush { get => GetValue(WarningBorderBrushProperty); set => SetValue(WarningBorderBrushProperty, value); }
    public IBrush? DangerBrush { get => GetValue(DangerBrushProperty); set => SetValue(DangerBrushProperty, value); }
    public IBrush? DangerSoftBrush { get => GetValue(DangerSoftBrushProperty); set => SetValue(DangerSoftBrushProperty, value); }
    public IBrush? DangerBorderBrush { get => GetValue(DangerBorderBrushProperty); set => SetValue(DangerBorderBrushProperty, value); }
    public IBrush? NeutralSoftBrush { get => GetValue(NeutralSoftBrushProperty); set => SetValue(NeutralSoftBrushProperty, value); }
    public IBrush? NeutralBorderBrush { get => GetValue(NeutralBorderBrushProperty); set => SetValue(NeutralBorderBrushProperty, value); }
    public IBrush? RuleBrush { get => GetValue(RuleBrushProperty); set => SetValue(RuleBrushProperty, value); }
    public IBrush? HeaderBrush { get => GetValue(HeaderBrushProperty); set => SetValue(HeaderBrushProperty, value); }
    public IBrush? HoverBrush { get => GetValue(HoverBrushProperty); set => SetValue(HoverBrushProperty, value); }
    public IBrush? PressedBrush { get => GetValue(PressedBrushProperty); set => SetValue(PressedBrushProperty, value); }
    public IBrush? SelectedBrush { get => GetValue(SelectedBrushProperty); set => SetValue(SelectedBrushProperty, value); }
    public IBrush? SelectedHoverBrush { get => GetValue(SelectedHoverBrushProperty); set => SetValue(SelectedHoverBrushProperty, value); }

    private readonly Dictionary<IBrush, IPen> _pens = new();
    private readonly Dictionary<IBrush, IPen> _roundPens = new();
    private readonly Dictionary<string, double> _sizes = new(StringComparer.Ordinal);
    private FontFamily? _mono;
    private CheckHostRow? _row, _watched;
    private bool _attached, _hover, _pressed;
    private double _builtWidth = -1;

    static ChLine()
    {
        // The line draws the list's selection itself.
        ListBoxItem.IsSelectedProperty.Changed.AddClassHandler<ListBoxItem>((item, _) =>
            (item.Presenter?.Child as ChLine)?.InvalidateVisual());
    }

    protected ChLine()
    {
        ContextRequested += OnContextRequested;
    }

    protected CheckHostRow? Row => _row;
    protected bool Narrow { get; private set; }
    protected bool Hover => _hover;
    protected bool Pressed => _pressed;
    protected bool Selected => this.FindAncestorOfType<ListBoxItem>() is { IsSelected: true };
    protected double LineHeight { get; set; }

    protected abstract void Build(double width);
    protected abstract void Draw(DrawingContext dc, double width);
    protected virtual List<MenuItem> MenuItems() => new();
    protected virtual bool Clickable => false;
    protected virtual void Clicked() { }
    protected virtual void RowReplaced() { }
    protected virtual void RowChanged(string? property) => Invalidate();
    protected virtual double MeasureBelow(double width) => 0;
    protected virtual void ArrangeBelow(Size size) { }

    // ---- the row ----

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);
        var row = DataContext as CheckHostRow;
        if (ReferenceEquals(row, _row)) return;
        _row = row;
        Watch();
        RowReplaced();
        Invalidate();
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        _attached = true;
        Watch();
        Invalidate();
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnDetachedFromVisualTree(e);
        _attached = false;
        _hover = _pressed = false;
        Watch();
    }

    // Subscribed only while on screen: rows outlive the lines that show them.
    private void Watch()
    {
        var want = _attached ? _row : null;
        if (ReferenceEquals(want, _watched)) return;
        if (_watched is not null) _watched.PropertyChanged -= OnRowPropertyChanged;
        _watched = want;
        if (want is not null) want.PropertyChanged += OnRowPropertyChanged;
    }

    private void OnRowPropertyChanged(object? sender, PropertyChangedEventArgs e) => RowChanged(e.PropertyName);

    protected void Invalidate()
    {
        _builtWidth = -1;
        InvalidateMeasure();
        InvalidateVisual();
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        // a brush is baked into the text layouts: re-lay with the new color (a theme switch)
        if (change.Property.OwnerType == typeof(ChLine) && change.Property.PropertyType == typeof(IBrush))
        {
            _pens.Clear();
            _roundPens.Clear();
            Invalidate();
        }
        else if (change.Property == TextElement.FontFamilyProperty) Invalidate();
    }

    // ---- layout ----

    private void EnsureBuilt(double width)
    {
        if (!double.IsFinite(width)) width = 960;
        if (width == _builtWidth) return;
        _builtWidth = width;
        Narrow = width < NarrowBelow;
        if (_row is null) LineHeight = 0;
        else Build(width);
    }

    protected override Size MeasureOverride(Size availableSize)
    {
        double w = double.IsFinite(availableSize.Width) ? availableSize.Width : 960;
        EnsureBuilt(w);
        return new Size(w, LineHeight + MeasureBelow(w));
    }

    protected override Size ArrangeOverride(Size finalSize)
    {
        EnsureBuilt(finalSize.Width);
        ArrangeBelow(finalSize);
        return finalSize;
    }

    public sealed override void Render(DrawingContext context)
    {
        if (_row is null) return;
        EnsureBuilt(Bounds.Width);
        Draw(context, Bounds.Width);
    }

    // ---- input ----

    private bool OnLine(Point p) => p.X >= 0 && p.X < Bounds.Width && p.Y >= 0 && p.Y < LineHeight;

    private void SetHover(bool on)
    {
        if (on == _hover || !Clickable) return;
        _hover = on;
        InvalidateVisual();
    }

    protected override void OnPointerEntered(PointerEventArgs e)
    {
        base.OnPointerEntered(e);
        SetHover(OnLine(e.GetPosition(this)));
    }

    protected override void OnPointerMoved(PointerEventArgs e)
    {
        base.OnPointerMoved(e);
        SetHover(OnLine(e.GetPosition(this)));
    }

    protected override void OnPointerExited(PointerEventArgs e)
    {
        base.OnPointerExited(e);
        SetHover(false);
    }

    // Not marked handled: the list item still selects the row (keyboard focus, Enter, the copy shortcut).
    protected override void OnPointerPressed(PointerPressedEventArgs e)
    {
        base.OnPointerPressed(e);
        if (Clickable && e.GetCurrentPoint(this).Properties.IsLeftButtonPressed && OnLine(e.GetPosition(this)))
        {
            _pressed = true;
            InvalidateVisual();
        }
    }

    protected override void OnPointerReleased(PointerReleasedEventArgs e)
    {
        base.OnPointerReleased(e);
        if (!_pressed) return;
        _pressed = false;
        InvalidateVisual();
        if (e.InitialPressMouseButton == MouseButton.Left && OnLine(e.GetPosition(this))) Clicked();
    }

    // A touch drag turned into a scroll: no click.
    protected override void OnPointerCaptureLost(PointerCaptureLostEventArgs e)
    {
        base.OnPointerCaptureLost(e);
        if (!_pressed) return;
        _pressed = false;
        InvalidateVisual();
    }

    private void OnContextRequested(object? sender, ContextRequestedEventArgs e)
    {
        if (e.Handled) return;
        if (e.TryGetPosition(this, out var p) && !OnLine(p)) return;   // the details' text has its own menu
        e.Handled = OpenMenu();
    }

    /// <summary>The row's copy menu (right-click, long-press, or the list's menu key), built on demand.</summary>
    public bool OpenMenu()
    {
        if (_row is null) return false;
        var items = MenuItems();
        if (items.Count == 0) return false;
        var menu = new ContextMenu();
        foreach (var item in items) menu.Items.Add(item);
        menu.Open(this);
        return true;
    }

    protected static MenuItem Item(string header, System.Windows.Input.ICommand command) => new() { Header = header, Command = command };

    protected override AutomationPeer OnCreateAutomationPeer() => new LinePeer(this);

    private sealed class LinePeer(ChLine owner) : ControlAutomationPeer(owner)
    {
        protected override string? GetNameCore() => owner._row?.Describe();
        protected override AutomationControlType GetAutomationControlTypeCore() => AutomationControlType.Text;
    }

    // ---- drawing helpers ----

    protected void Fill(DrawingContext dc, IBrush? brush, Rect rect)
    {
        if (brush is not null) dc.DrawRectangle(brush, null, rect);
    }

    protected IPen? Pen(IBrush? brush)
    {
        if (brush is null) return null;
        if (!_pens.TryGetValue(brush, out var pen)) _pens[brush] = pen = new Pen(brush, 1);
        return pen;
    }

    /// <summary>The 1.5 px round-capped pen of the chevron.</summary>
    protected IPen? RoundPen(IBrush? brush)
    {
        if (brush is null) return null;
        if (!_roundPens.TryGetValue(brush, out var pen))
            _roundPens[brush] = pen = new Pen(brush, 1.5, lineCap: PenLineCap.Round, lineJoin: PenLineJoin.Round);
        return pen;
    }

    private double Size(string key, double fallback)
    {
        if (!_sizes.TryGetValue(key, out double v))
            _sizes[key] = v = this.TryFindResource(key, out var found) && found is double d ? d : fallback;
        return v;
    }

    protected double Body => Size("Font.Body", 12.5);
    protected double Small => Size("Font.Small", 11.5);
    protected double Caption => Size("Font.Caption", 10.5);

    private FontFamily Mono => _mono ??= this.TryFindResource("MonoFont", out var m) && m is FontFamily f ? f : GetValue(TextElement.FontFamilyProperty);

    /// <summary>One run of text, trimmed with an ellipsis to <paramref name="maxWidth"/>.</summary>
    protected TextLayout Text(string text, double size, IBrush? brush, double maxWidth, bool mono = false, FontWeight weight = FontWeight.Normal)
    {
        var family = mono ? Mono : GetValue(TextElement.FontFamilyProperty);
        return new TextLayout(text, new Typeface(family, FontStyle.Normal, weight), size, brush,
            textWrapping: TextWrapping.NoWrap, textTrimming: TextTrimming.CharacterEllipsis, maxWidth: Math.Max(1, maxWidth));
    }

    protected static void Drop(ref TextLayout? layout)
    {
        layout?.Dispose();
        layout = null;
    }

    protected static Point At(double x, double y) => new(Math.Round(x), Math.Round(y));

    protected static double BadgeWidth(TextLayout t, double padX) => Math.Ceiling(t.Width) + 2 * padX + 2;
    protected static double BadgeHeight(TextLayout t, double padY) => Math.Ceiling(t.Height) + 2 * padY + 2;

    /// <summary>A result pill: solid soft fill, 1 px border, the text inside.</summary>
    protected void Badge(DrawingContext dc, TextLayout text, double x, double y, double padX, double padY, IBrush? fill, IBrush? border)
    {
        x = Math.Round(x);
        y = Math.Round(y);
        double w = BadgeWidth(text, padX), h = BadgeHeight(text, padY), r = Math.Min(6, h / 2);
        dc.DrawRectangle(fill, Pen(border), new Rect(x + 0.5, y + 0.5, w - 1, h - 1), r, r);
        text.Draw(dc, new Point(x + 1 + padX, y + 1 + padY));
    }

    /// <summary>Text, fill and border of a state's pill.</summary>
    protected (IBrush? Text, IBrush? Fill, IBrush? Border) StateBrushes(CheckHostState state) => state switch
    {
        CheckHostState.Ok => (SuccessBrush, SuccessSoftBrush, SuccessBorderBrush),
        CheckHostState.Warning => (WarningBrush, WarningSoftBrush, WarningBorderBrush),
        CheckHostState.Failed => (DangerBrush, DangerSoftBrush, DangerBorderBrush),
        _ => (MutedBrush, NeutralSoftBrush, NeutralBorderBrush),
    };
}

/// <summary>A region heading: "Europe" and its nodes' counts.</summary>
public sealed class ChGroupLine : ChLine
{
    private TextLayout? _name, _summary;

    private CheckHostGroupRow? GroupRow => Row as CheckHostGroupRow;

    protected override void Build(double width)
    {
        Drop(ref _name); Drop(ref _summary);
        var r = GroupRow!;
        double pad = Narrow ? 12 : 14, inner = Math.Max(0, width - 2 * pad);
        _name = Text(r.Region, Small, PrimaryBrush, inner, weight: FontWeight.SemiBold);
        double room = inner - Math.Ceiling(_name.Width) - 10;
        if (room >= 40) _summary = Text(r.Summary, Caption, MutedBrush, room);
        LineHeight = Math.Ceiling(Math.Max(_name.Height, _summary?.Height ?? 0) + 2 * 6 + 1);
    }

    protected override void Draw(DrawingContext dc, double width)
    {
        double h = LineHeight, pad = Narrow ? 12 : 14, mid = (h - 1) / 2;
        Fill(dc, Selected ? SelectedBrush : HeaderBrush, new Rect(0, 0, width, h - 1));
        Fill(dc, RuleBrush, new Rect(0, h - 1, width, 1));
        _name!.Draw(dc, At(pad, mid - _name.Height / 2));
        _summary?.Draw(dc, At(pad + Math.Ceiling(_name.Width) + 10, mid - _summary.Height / 2 + 0.5));
    }

    protected override List<MenuItem> MenuItems() => new() { Item("Copy", GroupRow!.CopyCommand) };
}

/// <summary>A node: flag, location, node id, result pill (with each ping reply as a cell), latency and the rest of its
/// result. Click (or Enter) opens the details below it.</summary>
public sealed class ChNodeLine : ChLine
{
    public static readonly StyledProperty<IDataTemplate?> DetailsTemplateProperty =
        AvaloniaProperty.Register<ChNodeLine, IDataTemplate?>(nameof(DetailsTemplate));

    /// <summary>Builds the panel under an expanded line — only then: most lines never need one.</summary>
    public IDataTemplate? DetailsTemplate
    {
        get => GetValue(DetailsTemplateProperty);
        set => SetValue(DetailsTemplateProperty, value);
    }

    private TextLayout? _loc, _node, _asn, _status, _lat, _det;
    private Bitmap? _flag;
    private Control? _details;
    private double _first, _second;   // heights of the line's text rows (the second only on a phone)

    private CheckHostNodeRow? NodeRow => Row as CheckHostNodeRow;

    protected override bool Clickable => true;

    protected override void Clicked()
    {
        if (NodeRow is { } r) r.IsExpanded = !r.IsExpanded;
    }

    protected override void RowReplaced() => SyncDetails();

    protected override void RowChanged(string? property)
    {
        if (property == nameof(CheckHostNodeRow.IsExpanded))
        {
            SyncDetails();
            InvalidateVisual();   // the chevron
        }
        else base.RowChanged(property);
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == DetailsTemplateProperty) SyncDetails();
    }

    private void SyncDetails()
    {
        bool want = NodeRow is { IsExpanded: true } && DetailsTemplate is not null;
        if (want == (_details is not null)) return;
        if (_details is { } old)
        {
            _details = null;
            VisualChildren.Remove(old);
            LogicalChildren.Remove(old);
        }
        else if (DetailsTemplate!.Build(NodeRow) is { } panel)
        {
            _details = panel;   // inherits this line's DataContext: the row
            LogicalChildren.Add(panel);
            VisualChildren.Add(panel);
        }
        InvalidateMeasure();
    }

    protected override double MeasureBelow(double width)
    {
        if (_details is null) return 0;
        _details.Measure(new Size(width, double.PositiveInfinity));
        return _details.DesiredSize.Height;
    }

    protected override void ArrangeBelow(Size size) =>
        _details?.Arrange(new Rect(0, LineHeight, size.Width, _details.DesiredSize.Height));

    // ping replies as cells after the pill
    private const double CellW = 6, CellH = 12, CellGap = 2;
    private int Cells => Math.Min(8, NodeRow?.Replies.Count ?? 0);
    private double CellsWidth => Cells == 0 ? 0 : Cells * CellW + (Cells - 1) * CellGap;

    protected override void Build(double width)
    {
        Drop(ref _loc); Drop(ref _node); Drop(ref _asn); Drop(ref _status); Drop(ref _lat); Drop(ref _det);
        var r = NodeRow!;
        var n = r.Node;
        _flag = n.HasFlag ? CountryFlagConverter.Instance.Convert(n.CountryCode, typeof(Bitmap), null, CultureInfo.InvariantCulture) as Bitmap : null;
        bool final = r.State is CheckHostState.Ok or CheckHostState.Warning or CheckHostState.Failed;
        var (statusBrush, _, _) = StateBrushes(r.State);
        bool warnDetail = (r.State == CheckHostState.Warning && r.Kind == CheckHostKind.Udp) || r.AnswerDiffers;
        var detBrush = r.DetailIsError ? DangerBrush : warnDetail ? WarningBrush : SecondaryBrush;
        string det = r.DetailText;
        string lat = r.LatencyText;
        _status = Text(r.StatusText, Caption, statusBrush, Narrow ? 132 : ResultColumn - 10 - (Cells > 0 ? CellsWidth + 8 : 0), weight: FontWeight.SemiBold);

        if (Narrow)
        {
            // line 1: flag, location … pill (+ reply cells); line 2: node · latency · details
            double right = width - RightPad - BadgeWidth(_status, 7) - (Cells > 0 ? CellsWidth + 8 : 0) - 10;
            _loc = Text(n.Location, Body, PrimaryBrush, Math.Max(24, right - LeadColumn + 6), weight: FontWeight.SemiBold);
            string sub = string.Join(" · ", new[] { n.ShortId, lat, det }.Where(s => s.Length > 0));
            _det = Text(sub, Caption, r.DetailIsError ? DangerBrush : warnDetail ? WarningBrush : MutedBrush, Math.Max(24, width - LeadColumn - RightPad));
            _first = Math.Max(_loc.Height, BadgeHeight(_status, 1));
            _second = _det.Height;
            LineHeight = Math.Ceiling(7 + _first + 2 + _second + 7 + 1);
            return;
        }

        _loc = Text(n.Location, Body, PrimaryBrush, LocationColumn - 10, weight: FontWeight.SemiBold);
        _node = Text(n.ShortId, Small, SecondaryBrush, NodeColumn - 8, mono: true);
        double asnRoom = NodeColumn - 8 - Math.Ceiling(_node.Width) - 6;
        if (n.Asn.Length > 0 && asnRoom >= 36) _asn = Text(n.Asn, Caption, MutedBrush, asnRoom, mono: true);
        if (lat.Length > 0) _lat = Text(lat, Small, final && r.State != CheckHostState.Failed ? PrimaryBrush : MutedBrush, LatencyColumn, mono: true);
        double detX = LeadColumn + LocationColumn + NodeColumn + ResultColumn + LatencyColumn + DetailsGap;
        if (det.Length > 0 && width - RightPad - detX >= 24) _det = Text(det, Small, detBrush, width - RightPad - detX);
        _first = Math.Max(Math.Max(_loc.Height, _node.Height), Math.Max(BadgeHeight(_status, 1), Math.Max(_lat?.Height ?? 0, _det?.Height ?? 0)));
        _second = 0;
        LineHeight = Math.Ceiling(2 * 6 + _first + 1);
    }

    protected override void Draw(DrawingContext dc, double width)
    {
        var r = NodeRow!;
        double h = LineHeight;
        var bg = Pressed ? PressedBrush : Hover ? (Selected ? SelectedHoverBrush : HoverBrush) : Selected ? SelectedBrush : null;
        // (Transparent is only the hit-test fill of an idle line)
        if (bg is null) dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, width, h - 1));
        else Fill(dc, bg, new Rect(0, 0, width, h - 1));
        Fill(dc, RuleBrush, new Rect(0, h - 1, width, 1));

        double top = Narrow ? 7 : 6;
        double mid = top + _first / 2;

        // chevron: › closed, ⌄ open
        var pen = RoundPen(Hover ? SecondaryBrush : MutedBrush);
        double cx = 14, cy = Math.Round(mid);
        if (pen is not null)
        {
            if (r.IsExpanded)
            {
                dc.DrawLine(pen, new Point(cx - 3.5, cy - 1.75), new Point(cx, cy + 1.75));
                dc.DrawLine(pen, new Point(cx, cy + 1.75), new Point(cx + 3.5, cy - 1.75));
            }
            else
            {
                dc.DrawLine(pen, new Point(cx - 1.75, cy - 3.5), new Point(cx + 1.75, cy));
                dc.DrawLine(pen, new Point(cx + 1.75, cy), new Point(cx - 1.75, cy + 3.5));
            }
        }

        DrawFlag(dc, 26, mid);

        _loc!.Draw(dc, At(LeadColumn, mid - _loc.Height / 2));
        var (_, fill, border) = StateBrushes(r.State);
        if (Narrow)
        {
            double pillW = BadgeWidth(_status!, 7);
            double x = width - RightPad - pillW;
            Badge(dc, _status!, x, mid - BadgeHeight(_status!, 1) / 2, 7, 1, fill, border);
            if (Cells > 0) DrawCells(dc, r, x - 8 - CellsWidth, mid);
            _det?.Draw(dc, At(LeadColumn, top + _first + 2));
            return;
        }

        double nx = LeadColumn + LocationColumn;
        _node!.Draw(dc, At(nx, mid - _node.Height / 2));
        _asn?.Draw(dc, At(nx + Math.Ceiling(_node.Width) + 6, mid - _asn.Height / 2 + 0.5));
        double rx = nx + NodeColumn;
        Badge(dc, _status!, rx, mid - BadgeHeight(_status!, 1) / 2, 7, 1, fill, border);
        if (Cells > 0) DrawCells(dc, r, rx + BadgeWidth(_status!, 7) + 8, mid);
        double lx = rx + ResultColumn;
        _lat?.Draw(dc, At(lx + LatencyColumn - _lat.Width, mid - _lat.Height / 2));
        _det?.Draw(dc, At(lx + LatencyColumn + DetailsGap, mid - _det.Height / 2));
    }

    /// <summary>One cell per ping reply: OK green, malformed amber, timeout red.</summary>
    private void DrawCells(DrawingContext dc, CheckHostNodeRow r, double x, double mid)
    {
        double y = Math.Round(mid - CellH / 2);
        for (int i = 0; i < Cells; i++)
        {
            var reply = r.Replies[i];
            var brush = reply.IsOk ? SuccessBrush : reply.Status == "MALFORMED" ? WarningBrush : DangerBrush;
            dc.DrawRectangle(brush, null, new Rect(Math.Round(x + i * (CellW + CellGap)), y, CellW, CellH), 1.5, 1.5);
        }
    }

    // the country's flag in a 20 × 15 box (or a ring when the node has no country)
    private void DrawFlag(DrawingContext dc, double x, double mid)
    {
        const double w = 20, boxH = 15;
        if (_flag is { } bmp && bmp.Size.Width > 0)
        {
            double h = Math.Min(boxH, Math.Round(w * bmp.Size.Height / bmp.Size.Width));
            var rect = new Rect(x, Math.Round(mid - h / 2), w, h);
            using (dc.PushClip(new RoundedRect(rect, 2)))
                dc.DrawImage(bmp, new Rect(bmp.Size), rect);
            return;
        }
        if (Pen(MutedBrush) is { } pen) dc.DrawEllipse(null, pen, new Point(x + w / 2, Math.Round(mid) + 0.5), 6, 6);
    }

    protected override List<MenuItem> MenuItems()
    {
        var r = NodeRow!;
        var items = new List<MenuItem>
        {
            Item(r.IsExpanded ? "Hide details" : "Show details", r.ToggleExpandCommand),
            Item("Copy row", r.CopyRowCommand),
        };
        if (r.HasAddress) items.Add(Item("Copy address", r.CopyAddressCommand));
        items.Add(Item("Copy node name", r.CopyNodeCommand));
        return items;
    }
}

/// <summary>
/// A run's nodes as one segmented bar: ok, warning, failed, then the ones still waiting or stopped — the live progress
/// of a run (the neutral part shrinks as nodes report). Brushes come from the design tokens via styles.
/// </summary>
public sealed class ChStatusBar : Control
{
    public static readonly StyledProperty<int> OkProperty = AvaloniaProperty.Register<ChStatusBar, int>(nameof(Ok));
    public static readonly StyledProperty<int> WarningProperty = AvaloniaProperty.Register<ChStatusBar, int>(nameof(Warning));
    public static readonly StyledProperty<int> FailedProperty = AvaloniaProperty.Register<ChStatusBar, int>(nameof(Failed));
    public static readonly StyledProperty<int> RestProperty = AvaloniaProperty.Register<ChStatusBar, int>(nameof(Rest));
    public static readonly StyledProperty<IBrush?> OkBrushProperty = AvaloniaProperty.Register<ChStatusBar, IBrush?>(nameof(OkBrush));
    public static readonly StyledProperty<IBrush?> WarningBrushProperty = AvaloniaProperty.Register<ChStatusBar, IBrush?>(nameof(WarningBrush));
    public static readonly StyledProperty<IBrush?> FailedBrushProperty = AvaloniaProperty.Register<ChStatusBar, IBrush?>(nameof(FailedBrush));
    public static readonly StyledProperty<IBrush?> RestBrushProperty = AvaloniaProperty.Register<ChStatusBar, IBrush?>(nameof(RestBrush));

    static ChStatusBar()
    {
        AffectsRender<ChStatusBar>(OkProperty, WarningProperty, FailedProperty, RestProperty,
            OkBrushProperty, WarningBrushProperty, FailedBrushProperty, RestBrushProperty);
    }

    public int Ok { get => GetValue(OkProperty); set => SetValue(OkProperty, value); }
    public int Warning { get => GetValue(WarningProperty); set => SetValue(WarningProperty, value); }
    public int Failed { get => GetValue(FailedProperty); set => SetValue(FailedProperty, value); }
    /// <summary>Waiting or stopped nodes.</summary>
    public int Rest { get => GetValue(RestProperty); set => SetValue(RestProperty, value); }
    public IBrush? OkBrush { get => GetValue(OkBrushProperty); set => SetValue(OkBrushProperty, value); }
    public IBrush? WarningBrush { get => GetValue(WarningBrushProperty); set => SetValue(WarningBrushProperty, value); }
    public IBrush? FailedBrush { get => GetValue(FailedBrushProperty); set => SetValue(FailedBrushProperty, value); }
    public IBrush? RestBrush { get => GetValue(RestBrushProperty); set => SetValue(RestBrushProperty, value); }

    public override void Render(DrawingContext context)
    {
        double w = Bounds.Width, h = Bounds.Height;
        if (w < 4 || h < 1) return;
        int total = Math.Max(0, Ok) + Math.Max(0, Warning) + Math.Max(0, Failed) + Math.Max(0, Rest);
        var track = new RoundedRect(new Rect(0, 0, w, h), h / 2);
        using (context.PushClip(track))
        {
            if (RestBrush is not null) context.DrawRectangle(RestBrush, null, new Rect(0, 0, w, h));
            if (total == 0) return;
            double x = 0;
            void Part(int count, IBrush? brush)
            {
                if (count <= 0) return;
                // whole pixels, at least 2 so one node still shows; the last part ends exactly at the edge
                double right = Math.Round(x + w * count / total);
                double width = Math.Max(2, right - Math.Round(x));
                if (brush is not null) context.DrawRectangle(brush, null, new Rect(Math.Round(x), 0, width, h));
                x = Math.Round(x) + width;
            }
            Part(Ok, OkBrush);
            Part(Warning, WarningBrush);
            Part(Failed, FailedBrush);
        }
    }
}
