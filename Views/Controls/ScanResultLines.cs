using System;
using System.Collections.Generic;
using System.ComponentModel;
using Avalonia;
using Avalonia.Automation.Peers;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Controls.Templates;
using Avalonia.Input;
using Avalonia.Media;
using Avalonia.Media.TextFormatting;
using Avalonia.VisualTree;
using Echoes.Helpers;
using Echoes.ViewModels;

namespace Echoes.Views.Controls;

/// <summary>
/// One line of the port scanner's results, drawn directly rather than templated. Every reset of the list (filter,
/// view, sort, the end of a pass) realizes a screenful of rows again; as templates of a dozen text blocks and borders
/// that cost ~25 ms a row (each element is matched against every class style in the app) and stalled the UI for
/// half a second. As one control with a few cached text layouts a row costs well under a millisecond.
/// Colors, fonts and radii are the design tokens, looked up in the tree and again after a theme switch.
/// </summary>
public abstract class ScanRowLine : Control
{
    // Column geometry, shared with the column heads above the list (they bind these with x:Static).
    /// <summary>The list's width below which rows use the phone layout: the card inside ResultsRoot's 600 break.</summary>
    public static double NarrowBelow => 598;
    public static double PortColumn => 96;
    public static double PortColumnNarrow => 76;
    public static double StateColumn => 112;
    public static double StateColumnNarrow => 104;
    public static double ServiceColumn => 138;   // 130 of text + 8 before the version
    public static double LatencyColumn => 56;
    /// <summary>Port rows sit indented under their host; the column heads use the same margins.</summary>
    public static Thickness Indent => new(28, 0, 12, 0);
    public static Thickness IndentNarrow => new(20, 0, 10, 0);

    private readonly Dictionary<string, object?> _tokens = new(StringComparer.Ordinal);
    private readonly Dictionary<(string, bool), IPen> _pens = new();
    private ScanRow? _row, _watched;
    private bool _attached, _hover, _pressed;
    private double _builtWidth = -1;

    static ScanRowLine()
    {
        // The line draws the list's selection itself (a host's solid band would hide the item's own background).
        ListBoxItem.IsSelectedProperty.Changed.AddClassHandler<ListBoxItem>((item, _) =>
            (item.Presenter?.Child as ScanRowLine)?.InvalidateVisual());
    }

    protected ScanRowLine()
    {
        ActualThemeVariantChanged += (_, _) => Retheme();
        ContextRequested += OnContextRequested;
    }

    protected ScanRow? Row => _row;
    protected bool Narrow { get; private set; }
    protected bool Hover => _hover;
    protected bool Pressed => _pressed;
    protected bool Selected => this.FindAncestorOfType<ListBoxItem>() is { IsSelected: true };

    /// <summary>Height of the drawn line; a port's details hang below it.</summary>
    protected double LineHeight { get; set; }

    /// <summary>Lays the row out for this width: text layouts, positions and <see cref="LineHeight"/>.</summary>
    protected abstract void Build(double width);
    protected abstract void Draw(DrawingContext dc, double width);
    protected abstract List<MenuItem> MenuItems();
    /// <summary>What a screen reader announces for the row.</summary>
    protected abstract string Describe();

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
        var row = DataContext as ScanRow;
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
        Invalidate();   // the row may have changed while this line was off screen
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnDetachedFromVisualTree(e);
        _attached = false;
        _hover = _pressed = false;
        Watch();
    }

    // Subscribed only while on screen: rows outlive the lines that show them, and must not keep them alive.
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

    private void Retheme()
    {
        _tokens.Clear();
        _pens.Clear();
        Invalidate();
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        // (not the inherited Foreground: the list item changes it on hover and selection, and the rows draw with tokens)
        if (change.Property == TextElement.FontFamilyProperty) Invalidate();
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

    /// <summary>The row's copy menu (right-click, long-press, or the list's menu key). Built on demand: a menu per
    /// realized row would cost more than the row itself.</summary>
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

    private sealed class LinePeer(ScanRowLine owner) : ControlAutomationPeer(owner)
    {
        protected override string? GetNameCore() => owner._row is null ? null : owner.Describe();
        protected override AutomationControlType GetAutomationControlTypeCore() => AutomationControlType.Text;
    }

    // ---- tokens and drawing helpers ----

    private object? Token(string key)
    {
        if (!_tokens.TryGetValue(key, out var value))
            _tokens[key] = value = this.TryFindResource(key, ActualThemeVariant, out var found) ? found : null;
        return value;
    }

    // (falls back to the inherited text color only if a token were missing)
    protected IBrush? Brush(string key) => Token(key) as IBrush ?? GetValue(TextElement.ForegroundProperty);

    protected void Fill(DrawingContext dc, string key, Rect rect) => dc.DrawRectangle(Brush(key), null, rect);

    private double FontSizeOf(string key) => Token(key) is double d ? d : GetValue(TextElement.FontSizeProperty);

    private double Radius => Token("Radius.Sm") is CornerRadius r ? r.TopLeft : 0;

    /// <summary>A 1 px border pen, or the 1.5 px round-capped pen of the chevron.</summary>
    protected IPen Pen(string key, bool round = false)
    {
        if (!_pens.TryGetValue((key, round), out var pen))
            _pens[(key, round)] = pen = round
                ? new Pen(Brush(key), 1.5, lineCap: PenLineCap.Round, lineJoin: PenLineJoin.Round)
                : new Pen(Brush(key), 1);
        return pen;
    }

    /// <summary>One run of text, trimmed with an ellipsis to <paramref name="maxWidth"/> (or wrapped).</summary>
    protected TextLayout Text(string text, string sizeKey, IBrush? brush, double maxWidth,
                              bool mono = false, FontWeight weight = FontWeight.Normal, bool wrap = false)
    {
        var family = mono && Token("MonoFont") is FontFamily m ? m : GetValue(TextElement.FontFamilyProperty);
        return new TextLayout(text, new Typeface(family, FontStyle.Normal, weight), FontSizeOf(sizeKey), brush,
            textWrapping: wrap ? TextWrapping.Wrap : TextWrapping.NoWrap,
            textTrimming: wrap ? TextTrimming.None : TextTrimming.CharacterEllipsis,
            maxWidth: Math.Max(1, maxWidth));
    }

    protected static void Drop(ref TextLayout? layout)
    {
        layout?.Dispose();
        layout = null;
    }

    protected static Point At(double x, double y) => new(Math.Round(x), Math.Round(y));

    protected static string Join(params string[] parts) => string.Join(", ", Array.FindAll(parts, p => p.Length > 0));

    protected static double BadgeWidth(TextLayout t, double padX) => Math.Ceiling(t.Width) + 2 * padX + 2;
    protected static double BadgeHeight(TextLayout t, double padY) => Math.Ceiling(t.Height) + 2 * padY + 2;

    /// <summary>A state pill or change badge: solid soft fill, 1 px border, the text inside.</summary>
    protected void Badge(DrawingContext dc, TextLayout text, double x, double y, double padX, double padY, string fill, string border)
    {
        x = Math.Round(x);
        y = Math.Round(y);
        double w = BadgeWidth(text, padX), h = BadgeHeight(text, padY), r = Math.Min(Radius, h / 2);
        dc.DrawRectangle(Brush(fill), Pen(border), new Rect(x + 0.5, y + 0.5, w - 1, h - 1), r, r);
        text.Draw(dc, new Point(x + 1 + padX, y + 1 + padY));
    }

    /// <summary>Text, fill and border tokens of a change badge ("new" / "came up", or "was open" / "went down").</summary>
    protected static (string Text, string Fill, string Border) ChangeTokens(ScanChange change) => change == ScanChange.Gone
        ? ("Danger", "Danger.Soft", "Danger.Border")
        : ("Info", "Info.Soft", "Info.Border");
}

/// <summary>A host's header: status dot, address, name, change badge and its port counts; then the reverse name, MAC /
/// maker and latency, and a warning when its results can't be taken at face value.</summary>
public sealed class ScanHostLine : ScanRowLine
{
    private TextLayout? _addr, _name, _chg, _counts, _meta, _warn;
    private double _first;   // height of the address line

    private ScanHostRow? HostRow => Row as ScanHostRow;

    private double Pad => Narrow ? 10 : 12;

    protected override void Build(double width)
    {
        Drop(ref _addr); Drop(ref _name); Drop(ref _chg); Drop(ref _counts); Drop(ref _meta); Drop(ref _warn);
        var r = HostRow!;
        string counts = r.Counts, name = r.Name, meta = r.Meta, warning = r.Warning;   // (each getter formats)
        double inner = Math.Max(0, width - 2 * Pad), sub = Math.Max(0, inner - 18);
        var secondary = Brush("Text.Secondary");
        if (counts.Length > 0)
            _counts = Narrow ? Text(counts, "Font.Caption", secondary, sub) : Text(counts, "Font.Small", secondary, inner * 0.6);
        if (r.HasChange) _chg = Text(r.ChangeText, "Font.Caption", Brush(ChangeTokens(r.Change).Text), double.PositiveInfinity, weight: FontWeight.SemiBold);

        // the address line: dot, address, name (trimmed first), change badge — counts at the right on a desktop
        double room = inner - 18 - (!Narrow && _counts is not null ? Math.Ceiling(_counts.Width) + 12 : 0)
                      - (_chg is null ? 0 : BadgeWidth(_chg, 6) + 10);
        _addr = Text(r.Address, "Font.Body", Brush("Text.Primary"), Math.Max(24, room), mono: true, weight: FontWeight.SemiBold);
        double nameRoom = room - Math.Ceiling(_addr.Width) - 10;
        if (name.Length > 0 && nameRoom >= 32) _name = Text(name, "Font.Body", secondary, nameRoom);
        if (meta.Length > 0) _meta = Text(meta, "Font.Caption", Brush("Text.Muted"), sub);
        if (warning.Length > 0) _warn = Text(warning, "Font.Caption", Brush("Warning"), sub, wrap: true);

        _first = Math.Max(_addr.Height, Math.Max(_name?.Height ?? 0, _chg is null ? 0 : BadgeHeight(_chg, 0)));
        if (!Narrow && _counts is not null) _first = Math.Max(_first, _counts.Height);
        double h = 7 + _first;
        if (Narrow && _counts is not null) h += 3 + _counts.Height;
        if (_meta is not null) h += 3 + _meta.Height;
        if (_warn is not null) h += 3 + _warn.Height;
        LineHeight = Math.Ceiling(h + 7 + 1);
    }

    protected override void Draw(DrawingContext dc, double width)
    {
        var r = HostRow!;
        double h = LineHeight, pad = Pad, mid = 7 + _first / 2, sub = pad + 18;
        Fill(dc, Selected ? "Bg.Selected" : "Bg.Card", new Rect(0, 0, width, h - 1));
        Fill(dc, "Border.Subtle", new Rect(0, h - 1, width, 1));

        string dot = r.Host.Status switch { HostStatus.Up => "Success", HostStatus.Down => "Text.Disabled", _ => "Warning" };
        dc.DrawEllipse(Brush(dot), null, new Point(pad + 4, Math.Round(mid)), 4, 4);
        double x = sub;
        _addr!.Draw(dc, At(x, mid - _addr.Height / 2));
        x += Math.Ceiling(_addr.Width) + 10;
        if (_name is not null)
        {
            _name.Draw(dc, At(x, mid - _name.Height / 2));
            x += Math.Ceiling(_name.Width) + 10;
        }
        if (_chg is not null)
        {
            var (_, fill, border) = ChangeTokens(r.Change);
            Badge(dc, _chg, x, mid - BadgeHeight(_chg, 0) / 2, 6, 0, fill, border);
        }

        double y = 7 + _first;
        if (_counts is not null)
        {
            if (Narrow)
            {
                _counts.Draw(dc, At(sub, y + 3));
                y += 3 + _counts.Height;
            }
            else _counts.Draw(dc, At(width - pad - _counts.Width, mid - _counts.Height / 2));
        }
        if (_meta is not null)
        {
            _meta.Draw(dc, At(sub, y + 3));
            y += 3 + _meta.Height;
        }
        _warn?.Draw(dc, At(sub, y + 3));
    }

    protected override List<MenuItem> MenuItems()
    {
        var r = HostRow!;
        var items = new List<MenuItem> { Item("Copy address", r.CopyAddressCommand) };
        if (r.HasName) items.Add(Item("Copy name", r.CopyNameCommand));
        if (r.HasMac) items.Add(Item("Copy MAC address", r.CopyMacCommand));
        return items;
    }

    protected override string Describe()
    {
        var r = HostRow!;
        return Join(r.Address, r.Name, r.Counts, r.Meta, r.ChangeText, r.Warning);
    }
}

/// <summary>A port: number, state pill, service, version, change badge and latency. Click (or Enter) opens the
/// details below it — the full version, details, reason and endpoint, as selectable text.</summary>
public sealed class ScanPortLine : ScanRowLine
{
    public static readonly StyledProperty<IDataTemplate?> DetailsTemplateProperty =
        AvaloniaProperty.Register<ScanPortLine, IDataTemplate?>(nameof(DetailsTemplate));

    /// <summary>Builds the panel under an expanded row — only then: most rows never need one.</summary>
    public IDataTemplate? DetailsTemplate
    {
        get => GetValue(DetailsTemplateProperty);
        set => SetValue(DetailsTemplateProperty, value);
    }

    private TextLayout? _port, _state, _svc, _ver, _lat, _chg;
    private Control? _details;
    private double _top, _content;   // padding above the cells; height of the cells

    private ScanPortRow? PortRow => Row as ScanPortRow;

    protected override bool Clickable => true;

    protected override void Clicked()
    {
        if (PortRow is { } p) p.IsExpanded = !p.IsExpanded;
    }

    protected override void RowReplaced() => SyncDetails();

    protected override void RowChanged(string? property)
    {
        if (property == nameof(ScanPortRow.IsExpanded))
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
        bool want = PortRow is { IsExpanded: true } && DetailsTemplate is not null;
        if (want == (_details is not null)) return;
        if (_details is { } old)
        {
            _details = null;
            VisualChildren.Remove(old);
            LogicalChildren.Remove(old);
        }
        else if (DetailsTemplate!.Build(PortRow) is { } panel)
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

    private static (string Text, string Fill, string Border) StateTokens(PortState state) => state switch
    {
        PortState.Open => ("Success", "Success.Soft", "Success.Border"),
        PortState.Filtered or PortState.OpenFiltered => ("Warning", "Warning.Soft", "Warning.Border"),
        PortState.Unknown => ("Danger", "Danger.Soft", "Danger.Border"),
        _ => ("Text.Muted", "Bg.Raised", "Border.Default"),   // closed: neutral, it recedes
    };

    protected override void Build(double width)
    {
        Drop(ref _port); Drop(ref _state); Drop(ref _svc); Drop(ref _ver); Drop(ref _lat); Drop(ref _chg);
        var r = PortRow!;
        // open rows read brightest; closed / filtered rows recede (their pill still says which)
        bool open = r.Finding.State == PortState.Open;
        var muted = Brush("Text.Muted");
        var strong = open ? Brush("Text.Primary") : muted;
        var normal = open ? Brush("Text.Secondary") : muted;
        var indent = Narrow ? IndentNarrow : Indent;
        double portW = Narrow ? PortColumnNarrow : PortColumn, stateW = Narrow ? StateColumnNarrow : StateColumn;

        _port = Text(r.PortLabel, "Font.Small", strong, portW - 6, mono: true);
        _state = Text(r.StateText, "Font.Caption", Brush(StateTokens(r.Finding.State).Text), stateW - 18, mono: true, weight: FontWeight.SemiBold);
        if (r.HasChange) _chg = Text(r.ChangeText, "Font.Caption", Brush(ChangeTokens(r.Finding.Change).Text), double.PositiveInfinity, weight: FontWeight.SemiBold);
        if (!Narrow && r.LatencyText.Length > 0) _lat = Text(r.LatencyText, "Font.Caption", muted, LatencyColumn);

        double right = width - indent.Right - (Narrow ? 0 : LatencyColumn) - (_chg is null ? 0 : BadgeWidth(_chg, 6) + 6);
        double room = Math.Max(0, right - 8 - (indent.Left + portW + stateW));
        if (Narrow)
        {
            // the version goes under the service
            _svc = Text(r.Service, "Font.Small", strong, room);
            if (r.HasVersion) _ver = Text(r.Version, "Font.Small", normal, room, mono: true);
        }
        else
        {
            _svc = Text(r.Service, "Font.Small", strong, Math.Min(ServiceColumn - 8, room));
            if (r.HasVersion && room - ServiceColumn >= 24) _ver = Text(r.Version, "Font.Small", normal, room - ServiceColumn, mono: true);
        }

        double cells = Narrow && _ver is not null ? _svc.Height + 2 + _ver.Height : Math.Max(_svc.Height, _ver?.Height ?? 0);
        _content = Math.Max(Math.Max(cells, _port.Height), Math.Max(BadgeHeight(_state, 1), _chg is null ? 0 : BadgeHeight(_chg, 0)));
        _top = Narrow ? 6 : 5;
        LineHeight = Math.Ceiling(2 * _top + _content + 1);
    }

    protected override void Draw(DrawingContext dc, double width)
    {
        var r = PortRow!;
        double h = LineHeight, mid = _top + _content / 2;
        var indent = Narrow ? IndentNarrow : Indent;
        string? bg = Pressed ? "Bg.Pressed" : Hover ? (Selected ? "Bg.SelectedHover" : "Bg.Hover") : Selected ? "Bg.Selected" : null;
        // (Transparent is only the hit-test fill of an idle row)
        if (bg is null) dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, width, h - 1));
        else Fill(dc, bg, new Rect(0, 0, width, h - 1));
        Fill(dc, "Border.Subtle", new Rect(0, h - 1, width, 1));

        // chevron in the indent: › closed, ⌄ open
        var pen = Pen(Hover ? "Text.Secondary" : "Text.Muted", round: true);
        double cx = Math.Round(indent.Left / 2), cy = Math.Round(mid);
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

        double x = indent.Left;
        _port!.Draw(dc, At(x, mid - _port.Height / 2));
        x += Narrow ? PortColumnNarrow : PortColumn;
        var (_, fill, border) = StateTokens(r.Finding.State);
        Badge(dc, _state!, x, mid - BadgeHeight(_state!, 1) / 2, 7, 1, fill, border);
        x += Narrow ? StateColumnNarrow : StateColumn;
        if (Narrow && _ver is not null)
        {
            double y = mid - (_svc!.Height + 2 + _ver.Height) / 2;
            _svc.Draw(dc, At(x, y));
            _ver.Draw(dc, At(x, y + _svc.Height + 2));
        }
        else
        {
            _svc!.Draw(dc, At(x, mid - _svc.Height / 2));
            _ver?.Draw(dc, At(x + ServiceColumn, mid - _ver.Height / 2));
        }

        double rx = width - indent.Right;
        if (!Narrow)
        {
            rx -= LatencyColumn;
            _lat?.Draw(dc, At(rx + LatencyColumn - _lat.Width, mid - _lat.Height / 2));
            rx -= 6;
        }
        if (_chg is not null)
        {
            var (_, cfill, cborder) = ChangeTokens(r.Finding.Change);
            Badge(dc, _chg, rx - BadgeWidth(_chg, 6), mid - BadgeHeight(_chg, 0) / 2, 6, 0, cfill, cborder);
        }
    }

    protected override List<MenuItem> MenuItems()
    {
        var r = PortRow!;
        var items = new List<MenuItem>
        {
            Item(r.IsExpanded ? "Hide details" : "Show details", r.ToggleExpandCommand),
            Item("Copy address:port", r.CopyEndpointCommand),
            Item("Copy row", r.CopyRowCommand),
        };
        if (r.IsWeb) items.Add(Item("Open in browser", r.OpenInBrowserCommand));
        return items;
    }

    protected override string Describe()
    {
        var r = PortRow!;
        return Join(r.PortLabel, r.StateText, r.Service, r.Version, r.ChangeText);
    }
}
