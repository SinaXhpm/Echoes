using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Media.TextFormatting;
using Avalonia.Threading;
using Avalonia.Utilities;
using Echoes.Helpers;

namespace Echoes.Views.Controls;

/// <summary>
/// The cURL tab's read-only response viewer. Only the lines on screen are laid out (a logical scroller inside a
/// ScrollViewer), so a multi-megabyte body scrolls as smoothly as a short one; JSON / XML are coloured per line; line
/// numbers, wrapping, mouse selection with copy, and search with highlighted matches. Monospace metrics are used for
/// positions (wide CJK / emoji glyphs may sit a little off the grid — the text itself is always drawn whole). Every colour
/// is a brush property, set from the view's styles with DynamicResource, so a theme switch repaints it.
/// </summary>
public sealed class CurlCodeView : Control, ILogicalScrollable
{
    public static readonly StyledProperty<CurlTextDocument?> DocumentProperty =
        AvaloniaProperty.Register<CurlCodeView, CurlTextDocument?>(nameof(Document));
    public static readonly StyledProperty<bool> WrapProperty =
        AvaloniaProperty.Register<CurlCodeView, bool>(nameof(Wrap));
    public static readonly StyledProperty<string?> SearchTextProperty =
        AvaloniaProperty.Register<CurlCodeView, string?>(nameof(SearchText));
    public static readonly StyledProperty<FontFamily> FontFamilyProperty = TextElement.FontFamilyProperty.AddOwner<CurlCodeView>();
    public static readonly StyledProperty<double> FontSizeProperty = TextElement.FontSizeProperty.AddOwner<CurlCodeView>();
    public static readonly StyledProperty<IBrush?> ForegroundProperty = TextElement.ForegroundProperty.AddOwner<CurlCodeView>();
    public static readonly StyledProperty<IBrush?> BackgroundProperty = AvaloniaProperty.Register<CurlCodeView, IBrush?>(nameof(Background));
    public static readonly StyledProperty<IBrush?> LineNumberBrushProperty = AvaloniaProperty.Register<CurlCodeView, IBrush?>(nameof(LineNumberBrush));
    public static readonly StyledProperty<IBrush?> GutterBorderBrushProperty = AvaloniaProperty.Register<CurlCodeView, IBrush?>(nameof(GutterBorderBrush));
    public static readonly StyledProperty<IBrush?> KeyBrushProperty = AvaloniaProperty.Register<CurlCodeView, IBrush?>(nameof(KeyBrush));
    public static readonly StyledProperty<IBrush?> StringBrushProperty = AvaloniaProperty.Register<CurlCodeView, IBrush?>(nameof(StringBrush));
    public static readonly StyledProperty<IBrush?> NumberBrushProperty = AvaloniaProperty.Register<CurlCodeView, IBrush?>(nameof(NumberBrush));
    public static readonly StyledProperty<IBrush?> LiteralBrushProperty = AvaloniaProperty.Register<CurlCodeView, IBrush?>(nameof(LiteralBrush));
    public static readonly StyledProperty<IBrush?> PunctBrushProperty = AvaloniaProperty.Register<CurlCodeView, IBrush?>(nameof(PunctBrush));
    public static readonly StyledProperty<IBrush?> TagBrushProperty = AvaloniaProperty.Register<CurlCodeView, IBrush?>(nameof(TagBrush));
    public static readonly StyledProperty<IBrush?> AttrBrushProperty = AvaloniaProperty.Register<CurlCodeView, IBrush?>(nameof(AttrBrush));
    public static readonly StyledProperty<IBrush?> CommentBrushProperty = AvaloniaProperty.Register<CurlCodeView, IBrush?>(nameof(CommentBrush));
    public static readonly StyledProperty<IBrush?> SelectionBrushProperty = AvaloniaProperty.Register<CurlCodeView, IBrush?>(nameof(SelectionBrush));
    public static readonly StyledProperty<IBrush?> MatchBrushProperty = AvaloniaProperty.Register<CurlCodeView, IBrush?>(nameof(MatchBrush));
    public static readonly StyledProperty<IBrush?> CurrentMatchBrushProperty = AvaloniaProperty.Register<CurlCodeView, IBrush?>(nameof(CurrentMatchBrush));

    /// <summary>"3 / 17", "No matches" or "" — for a label next to the search box.</summary>
    public static readonly DirectProperty<CurlCodeView, string> MatchSummaryProperty =
        AvaloniaProperty.RegisterDirect<CurlCodeView, string>(nameof(MatchSummary), o => o.MatchSummary);

    public CurlTextDocument? Document { get => GetValue(DocumentProperty); set => SetValue(DocumentProperty, value); }
    public bool Wrap { get => GetValue(WrapProperty); set => SetValue(WrapProperty, value); }
    public string? SearchText { get => GetValue(SearchTextProperty); set => SetValue(SearchTextProperty, value); }
    public FontFamily FontFamily { get => GetValue(FontFamilyProperty); set => SetValue(FontFamilyProperty, value); }
    public double FontSize { get => GetValue(FontSizeProperty); set => SetValue(FontSizeProperty, value); }
    public IBrush? Foreground { get => GetValue(ForegroundProperty); set => SetValue(ForegroundProperty, value); }
    public IBrush? Background { get => GetValue(BackgroundProperty); set => SetValue(BackgroundProperty, value); }
    public IBrush? LineNumberBrush { get => GetValue(LineNumberBrushProperty); set => SetValue(LineNumberBrushProperty, value); }
    public IBrush? GutterBorderBrush { get => GetValue(GutterBorderBrushProperty); set => SetValue(GutterBorderBrushProperty, value); }
    public IBrush? KeyBrush { get => GetValue(KeyBrushProperty); set => SetValue(KeyBrushProperty, value); }
    public IBrush? StringBrush { get => GetValue(StringBrushProperty); set => SetValue(StringBrushProperty, value); }
    public IBrush? NumberBrush { get => GetValue(NumberBrushProperty); set => SetValue(NumberBrushProperty, value); }
    public IBrush? LiteralBrush { get => GetValue(LiteralBrushProperty); set => SetValue(LiteralBrushProperty, value); }
    public IBrush? PunctBrush { get => GetValue(PunctBrushProperty); set => SetValue(PunctBrushProperty, value); }
    public IBrush? TagBrush { get => GetValue(TagBrushProperty); set => SetValue(TagBrushProperty, value); }
    public IBrush? AttrBrush { get => GetValue(AttrBrushProperty); set => SetValue(AttrBrushProperty, value); }
    public IBrush? CommentBrush { get => GetValue(CommentBrushProperty); set => SetValue(CommentBrushProperty, value); }
    public IBrush? SelectionBrush { get => GetValue(SelectionBrushProperty); set => SetValue(SelectionBrushProperty, value); }
    public IBrush? MatchBrush { get => GetValue(MatchBrushProperty); set => SetValue(MatchBrushProperty, value); }
    public IBrush? CurrentMatchBrush { get => GetValue(CurrentMatchBrushProperty); set => SetValue(CurrentMatchBrushProperty, value); }

    private string _matchSummary = string.Empty;
    public string MatchSummary { get => _matchSummary; private set => SetAndRaise(MatchSummaryProperty, ref _matchSummary, value); }

    private const double PadX = 12, PadY = 8;

    // metrics
    private Typeface _typeface;
    private double _cw = 7, _lh = 17, _textH = 15;
    private bool _metricsValid;

    // scrolling
    private Size _extent, _viewport;
    private Vector _offset;
    private EventHandler? _scrollInvalidated;

    // wrap: first visual row of each line (+ total); valid for _wrapCols and _rowStartsDoc
    private int[] _rowStarts = Array.Empty<int>();
    private int _wrapCols;
    private CurlTextDocument? _rowStartsDoc;
    private readonly Dictionary<int, TextLayout> _numberLayouts = new();

    // selection (document offsets)
    private int _anchor, _caret;
    private bool _dragging;

    // search
    private List<int> _matches = new();
    private int _matchLen, _current = -1;
    private CancellationTokenSource? _searchCts;
    private DispatcherTimer? _searchTimer;

    // a few hundred laid-out rows reused across frames while nothing changes
    private readonly Dictionary<(int Line, int Start, int End), TextLayout> _layouts = new();

    static CurlCodeView()
    {
        FocusableProperty.OverrideDefaultValue<CurlCodeView>(true);
        ClipToBoundsProperty.OverrideDefaultValue<CurlCodeView>(true);
        AffectsRender<CurlCodeView>(BackgroundProperty, LineNumberBrushProperty, GutterBorderBrushProperty, SelectionBrushProperty,
                                    MatchBrushProperty, CurrentMatchBrushProperty);
    }

    public CurlCodeView()
    {
        var copy = new MenuItem { Header = "Copy" };
        copy.Click += async (_, _) => await CopySelectionAsync();
        var all = new MenuItem { Header = "Select all" };
        all.Click += (_, _) => SelectAll();
        var flyout = new MenuFlyout();
        flyout.Items.Add(copy);
        flyout.Items.Add(all);
        flyout.Opening += (_, _) => copy.IsEnabled = _anchor != _caret;
        ContextFlyout = flyout;
        Cursor = new Cursor(StandardCursorType.Ibeam);
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        var p = change.Property;
        if (p == DocumentProperty)
        {
            _anchor = _caret = 0;
            _offset = default;
            ClearLayouts();
            _matches = new List<int>();
            _current = -1;
            MatchSummary = string.Empty;
            UpdateExtent();
            ScheduleSearch(immediate: true);
        }
        else if (p == WrapProperty)
        {
            _offset = new Vector(0, _offset.Y);
            ClearLayouts();
            UpdateExtent();
        }
        else if (p == FontFamilyProperty || p == FontSizeProperty)
        {
            _metricsValid = false;
            ClearLayouts();
            ClearNumberLayouts();
            UpdateExtent();
        }
        else if (p == LineNumberBrushProperty)
        {
            ClearNumberLayouts();   // the brush is baked into the cached numbers
            InvalidateVisual();
        }
        else if (p == ForegroundProperty || p == KeyBrushProperty || p == StringBrushProperty || p == NumberBrushProperty
                 || p == LiteralBrushProperty || p == PunctBrushProperty || p == TagBrushProperty || p == AttrBrushProperty
                 || p == CommentBrushProperty)
        {
            ClearLayouts();   // the colours are baked into the cached layouts
            InvalidateVisual();
        }
        else if (p == SearchTextProperty)
        {
            ScheduleSearch(immediate: false);
        }
    }

    // ================================================================== metrics / extent

    private void EnsureMetrics()
    {
        if (_metricsValid) return;
        _typeface = new Typeface(FontFamily ?? FontFamily.Default);
        double size = FontSize > 0 ? FontSize : 12;
        using (var probe = new TextLayout("0000000000", _typeface, size, Foreground ?? Brushes.Gray))
        {
            _cw = Math.Max(1, probe.WidthIncludingTrailingWhitespace / 10.0);
            _textH = Math.Max(1, probe.Height);
        }
        _lh = Math.Ceiling(_textH * 1.25);
        _metricsValid = true;
    }

    private CurlTextDocument Doc => Document ?? CurlTextDocument.Empty;

    private double GutterWidth
    {
        get
        {
            int digits = Math.Max(2, Doc.LineCount.ToString().Length);
            return digits * _cw + 2 * PadX;
        }
    }

    private double TextLeft => GutterWidth + PadX;

    private void UpdateExtent()
    {
        EnsureMetrics();
        var doc = Doc;
        if (Wrap)
        {
            int cols = Math.Max(8, (int)((_viewport.Width - TextLeft - PadX) / _cw));
            if (cols != _wrapCols || !ReferenceEquals(_rowStartsDoc, doc) || _rowStarts.Length != doc.LineCount + 1)
            {
                _wrapCols = cols;
                _rowStartsDoc = doc;
                _rowStarts = new int[doc.LineCount + 1];
                int rows = 0;
                for (int i = 0; i < doc.LineCount; i++)
                {
                    _rowStarts[i] = rows;
                    int len = doc.LineLength(i);
                    rows += len == 0 ? 1 : (len + cols - 1) / cols;
                }
                _rowStarts[doc.LineCount] = rows;
            }
            _extent = new Size(_viewport.Width, PadY * 2 + TotalRows * _lh);
        }
        else
        {
            _extent = new Size(TextLeft + doc.MaxLineLength * _cw + PadX * 2, PadY * 2 + doc.LineCount * _lh);
        }
        _offset = ClampOffset(_offset);
        _scrollInvalidated?.Invoke(this, EventArgs.Empty);
        InvalidateVisual();
    }

    private int TotalRows => Wrap ? (_rowStarts.Length > 0 ? _rowStarts[^1] : 0) : Doc.LineCount;

    private Vector ClampOffset(Vector v) => new(
        Math.Clamp(v.X, 0, Math.Max(0, _extent.Width - _viewport.Width)),
        Math.Clamp(v.Y, 0, Math.Max(0, _extent.Height - _viewport.Height)));

    // visual row → (line, first column of that row, last column (exclusive))
    private (int Line, int Start, int End) RowToLine(int row)
    {
        var doc = Doc;
        if (!Wrap) return (row, 0, doc.LineLength(row));
        int lo = 0, hi = doc.LineCount - 1;
        while (lo < hi)
        {
            int mid = (lo + hi + 1) >> 1;
            if (_rowStarts[mid] <= row) lo = mid; else hi = mid - 1;
        }
        int seg = row - _rowStarts[lo];
        int len = doc.LineLength(lo);
        int start = seg * _wrapCols;
        return (lo, start, Math.Min(len, start + _wrapCols));
    }

    private int LineToRow(int line, int col) => Wrap ? _rowStarts[line] + (_wrapCols > 0 ? Math.Min(col, Math.Max(0, Doc.LineLength(line) - 1)) / _wrapCols : 0) : line;

    protected override Size MeasureOverride(Size availableSize)
    {
        EnsureMetrics();
        double w = double.IsInfinity(availableSize.Width) ? 600 : availableSize.Width;
        double h = double.IsInfinity(availableSize.Height) ? 300 : availableSize.Height;
        return new Size(w, h);
    }

    protected override Size ArrangeOverride(Size finalSize)
    {
        if (finalSize != _viewport)
        {
            bool widthChanged = Math.Abs(finalSize.Width - _viewport.Width) > 0.5;
            _viewport = finalSize;
            if (widthChanged && Wrap) ClearLayouts();
            UpdateExtent();
        }
        return finalSize;
    }

    // ================================================================== ILogicalScrollable

    public bool CanHorizontallyScroll { get; set; }
    public bool CanVerticallyScroll { get; set; }
    public bool IsLogicalScrollEnabled => true;
    public Size ScrollSize => new(Math.Max(1, _cw * 4), Math.Max(1, _lh * 3));
    public Size PageScrollSize => new(Math.Max(1, _viewport.Width * 0.9), Math.Max(1, _viewport.Height - _lh));
    public Size Extent => _extent;
    public Size Viewport => _viewport;

    public Vector Offset
    {
        get => _offset;
        set
        {
            var v = ClampOffset(value);
            if (v != _offset)
            {
                _offset = v;
                InvalidateVisual();
            }
            // asked for more than the content allows: the ScrollViewer learns the clamped offset
            if (v != value) _scrollInvalidated?.Invoke(this, EventArgs.Empty);
        }
    }

    event EventHandler? ILogicalScrollable.ScrollInvalidated
    {
        add => _scrollInvalidated += value;
        remove => _scrollInvalidated -= value;
    }

    public bool BringIntoView(Control target, Rect targetRect) => false;
    public Control? GetControlInDirection(NavigationDirection direction, Control? from) => null;
    public void RaiseScrollInvalidated(EventArgs e) => _scrollInvalidated?.Invoke(this, e);

    // ================================================================== render

    public override void Render(DrawingContext ctx)
    {
        EnsureMetrics();
        var bounds = new Rect(Bounds.Size);
        if (Background is { } bg) ctx.FillRectangle(bg, bounds);
        var doc = Doc;
        if (doc.LineCount == 0) return;

        double gutter = GutterWidth;
        double textLeft = gutter + PadX;
        int firstRow = Math.Max(0, (int)Math.Floor((_offset.Y - PadY) / _lh));
        int lastRow = Math.Min(TotalRows - 1, (int)Math.Ceiling((_offset.Y + _viewport.Height - PadY) / _lh));
        int selStart = Math.Min(_anchor, _caret), selEnd = Math.Max(_anchor, _caret);
        double size = FontSize > 0 ? FontSize : 12;

        // the gutter: a hairline, numbers right-aligned
        if (GutterBorderBrush is { } gb) ctx.FillRectangle(gb, new Rect(gutter - 1, 0, 1, bounds.Height));

        using (ctx.PushClip(new Rect(textLeft - 2, 0, Math.Max(0, bounds.Width - textLeft + 2), bounds.Height)))
        {
            for (int row = firstRow; row <= lastRow; row++)
            {
                var (line, start, end) = RowToLine(row);
                double y = PadY + row * _lh - _offset.Y;
                int lineOff = doc.LineStart(line);
                int c0 = start, c1 = end;
                double x0 = textLeft;
                if (!Wrap)
                {
                    // only the visible columns of a long line are laid out
                    c0 = Math.Min(end, Math.Max(0, (int)Math.Floor(_offset.X / _cw) - 4));
                    c1 = Math.Min(end, (int)Math.Ceiling((_offset.X + _viewport.Width) / _cw) + 4);
                    x0 = textLeft + c0 * _cw - _offset.X;
                }

                // selection behind the text (a selected line break shows as a sliver past the end)
                if (selEnd > selStart && SelectionBrush is { } sel)
                {
                    int a = Math.Max(selStart, lineOff + start), b = Math.Min(selEnd, lineOff + end);
                    bool eol = end == doc.LineLength(line) && selEnd > lineOff + end && selStart <= lineOff + end;
                    if (b > a || eol)
                    {
                        double xa = x0 + (Math.Max(a, lineOff + c0) - lineOff - c0) * _cw;
                        double xb = x0 + (Math.Max(b, lineOff + c0) - lineOff - c0) * _cw + (eol ? _cw * 0.6 : 0);
                        if (xb > xa) ctx.FillRectangle(sel, new Rect(xa, y, xb - xa, _lh));
                    }
                }

                // search matches
                if (_matches.Count > 0 && _matchLen > 0)
                {
                    int rowA = lineOff + start, rowB = lineOff + end;
                    int k = LowerBound(_matches, rowA - _matchLen + 1);
                    for (; k < _matches.Count && _matches[k] < rowB; k++)
                    {
                        int a = Math.Max(_matches[k], rowA), b = Math.Min(_matches[k] + _matchLen, rowB);
                        if (b <= a) continue;
                        var brush = k == _current ? CurrentMatchBrush : MatchBrush;
                        if (brush is null) continue;
                        double xa = x0 + (a - lineOff - c0) * _cw, xb = x0 + (b - lineOff - c0) * _cw;
                        ctx.FillRectangle(brush, new Rect(xa, y, Math.Max(1, xb - xa), _lh));
                    }
                }

                if (c1 > c0)
                {
                    var layout = LayoutFor(doc, line, c0, c1, size);
                    layout.Draw(ctx, new Point(x0, y + (_lh - _textH) / 2));
                }
            }
        }

        // line numbers (on a line's first visual row)
        if (LineNumberBrush is { } nb)
        {
            if (_numberLayouts.Count > 600) ClearNumberLayouts();
            for (int row = firstRow; row <= lastRow; row++)
            {
                var (line, start, _) = RowToLine(row);
                if (start != 0) continue;
                if (!_numberLayouts.TryGetValue(line, out var l))
                    _numberLayouts[line] = l = new TextLayout((line + 1).ToString(), _typeface, size, nb);
                double y = PadY + row * _lh - _offset.Y;
                l.Draw(ctx, new Point(gutter - PadX - l.WidthIncludingTrailingWhitespace, y + (_lh - _textH) / 2));
            }
        }
    }

    private void ClearNumberLayouts()
    {
        foreach (var l in _numberLayouts.Values) l.Dispose();
        _numberLayouts.Clear();
    }

    private TextLayout LayoutFor(CurlTextDocument doc, int line, int c0, int c1, double size)
    {
        if (_layouts.TryGetValue((line, c0, c1), out var cached)) return cached;
        if (_layouts.Count > 600) ClearLayouts();
        string text = doc.Line(line)[c0..c1].ToString();
        List<ValueSpan<TextRunProperties>>? overrides = null;
        var tokens = doc.Tokens(line);
        if (tokens.Length > 0)
        {
            overrides = new List<ValueSpan<TextRunProperties>>();
            foreach (var t in tokens)
            {
                int a = Math.Max(t.Start, c0), b = Math.Min(t.Start + t.Length, c1);
                if (b <= a) continue;
                var brush = BrushFor(t.Kind);
                if (brush is null) continue;
                overrides.Add(new ValueSpan<TextRunProperties>(a - c0, b - a,
                    new GenericTextRunProperties(_typeface, size, null, brush, null, BaselineAlignment.Baseline, null, null)));
            }
        }
        var layout = new TextLayout(text, _typeface, size, Foreground ?? Brushes.Gray, TextAlignment.Left, TextWrapping.NoWrap,
            TextTrimming.None, null, FlowDirection.LeftToRight, double.PositiveInfinity, double.PositiveInfinity, double.NaN, 0, 0,
            null, overrides);
        _layouts[(line, c0, c1)] = layout;
        return layout;
    }

    private IBrush? BrushFor(CurlTokenKind kind) => kind switch
    {
        CurlTokenKind.Key => KeyBrush,
        CurlTokenKind.String => StringBrush,
        CurlTokenKind.Number => NumberBrush,
        CurlTokenKind.Literal => LiteralBrush,
        CurlTokenKind.Punct => PunctBrush,
        CurlTokenKind.Tag => TagBrush,
        CurlTokenKind.Attr => AttrBrush,
        CurlTokenKind.Comment => CommentBrush,
        _ => null,
    };

    private static int LowerBound(List<int> list, int value)
    {
        int lo = 0, hi = list.Count;
        while (lo < hi)
        {
            int mid = (lo + hi) >> 1;
            if (list[mid] < value) lo = mid + 1; else hi = mid;
        }
        return lo;
    }

    // ================================================================== selection (mouse / pen; touch pans the ScrollViewer)

    private int HitTest(Point p)
    {
        var doc = Doc;
        if (doc.LineCount == 0) return 0;
        int row = Math.Clamp((int)Math.Floor((p.Y + _offset.Y - PadY) / _lh), 0, Math.Max(0, TotalRows - 1));
        var (line, start, end) = RowToLine(row);
        double x = p.X - TextLeft + (Wrap ? 0 : _offset.X);
        int col = start + (int)Math.Round(x / _cw);
        col = Math.Clamp(col, start, end);
        return doc.LineStart(line) + col;
    }

    protected override void OnPointerPressed(PointerPressedEventArgs e)
    {
        base.OnPointerPressed(e);
        if (e.Pointer.Type == PointerType.Touch) return;
        var pt = e.GetCurrentPoint(this);
        if (!pt.Properties.IsLeftButtonPressed) return;
        Focus();
        int off = HitTest(pt.Position);
        if (e.ClickCount == 2) SelectWord(off);
        else if (e.ClickCount >= 3) SelectLine(off);
        else
        {
            if ((e.KeyModifiers & KeyModifiers.Shift) == 0) _anchor = off;
            _caret = off;
            _dragging = true;
            e.Pointer.Capture(this);
        }
        e.Handled = true;
        InvalidateVisual();
    }

    protected override void OnPointerMoved(PointerEventArgs e)
    {
        base.OnPointerMoved(e);
        if (!_dragging) return;
        var p = e.GetPosition(this);
        // drag past an edge scrolls
        double dy = p.Y < 0 ? p.Y : p.Y > Bounds.Height ? p.Y - Bounds.Height : 0;
        double dx = Wrap ? 0 : (p.X < TextLeft ? p.X - TextLeft : p.X > Bounds.Width ? p.X - Bounds.Width : 0);
        if (dx != 0 || dy != 0)
        {
            Offset = new Vector(_offset.X + dx, _offset.Y + dy);
            _scrollInvalidated?.Invoke(this, EventArgs.Empty);
        }
        _caret = HitTest(p);
        InvalidateVisual();
    }

    protected override void OnPointerReleased(PointerReleasedEventArgs e)
    {
        base.OnPointerReleased(e);
        if (!_dragging) return;
        _dragging = false;
        e.Pointer.Capture(null);
    }

    private void SelectWord(int off)
    {
        var text = Doc.Text;
        if (text.Length == 0) return;
        int a = Math.Clamp(off, 0, text.Length), b = a;
        static bool W(char c) => char.IsLetterOrDigit(c) || c is '_' or '-' or '.' or '@';
        while (a > 0 && W(text[a - 1])) a--;
        while (b < text.Length && W(text[b])) b++;
        _anchor = a;
        _caret = b;
    }

    private void SelectLine(int off)
    {
        var doc = Doc;
        var (line, _) = doc.PositionOf(off);
        _anchor = doc.LineStart(line);
        _caret = Math.Min(doc.Text.Length, _anchor + doc.LineLength(line) + 1);
    }

    public void SelectAll()
    {
        _anchor = 0;
        _caret = Doc.Text.Length;
        InvalidateVisual();
    }

    public string SelectedText
    {
        get
        {
            int a = Math.Min(_anchor, _caret), b = Math.Max(_anchor, _caret);
            return b > a ? Doc.GetText(a, b) : string.Empty;
        }
    }

    private async Task CopySelectionAsync()
    {
        string s = SelectedText;
        if (s.Length == 0) return;
        var clip = TopLevel.GetTopLevel(this)?.Clipboard;
        if (clip is null) return;
        try { await clip.SetTextAsync(s); } catch { /* clipboard busy */ }
    }

    protected override async void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        bool cmd = (e.KeyModifiers & (KeyModifiers.Control | KeyModifiers.Meta)) != 0;
        if (cmd && e.Key == Key.C) { e.Handled = true; await CopySelectionAsync(); }
        else if (cmd && e.Key == Key.A) { e.Handled = true; SelectAll(); }
        else if (e.Key == Key.F3 || (e.Key == Key.Enter && cmd)) { e.Handled = true; FindNext((e.KeyModifiers & KeyModifiers.Shift) != 0); }
    }

    // ================================================================== search

    private void ScheduleSearch(bool immediate)
    {
        _searchTimer ??= CreateSearchTimer();
        _searchTimer.Stop();
        if (immediate) RunSearch();
        else _searchTimer.Start();
    }

    private DispatcherTimer CreateSearchTimer()
    {
        var t = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(220) };
        t.Tick += (_, _) => { t.Stop(); RunSearch(); };
        return t;
    }

    private async void RunSearch()
    {
        _searchCts?.Cancel();
        string q = SearchText ?? string.Empty;
        var doc = Doc;
        if (q.Length == 0 || doc.IsEmpty)
        {
            _matches = new List<int>();
            _current = -1;
            MatchSummary = string.Empty;
            InvalidateVisual();
            return;
        }
        var cts = _searchCts = new CancellationTokenSource();
        List<int> hits;
        try
        {
            // a big body is scanned off the UI thread
            hits = doc.Text.Length > 200_000 ? await Task.Run(() => doc.FindAll(q), cts.Token) : doc.FindAll(q);
        }
        catch (OperationCanceledException) { return; }
        if (cts.IsCancellationRequested || !ReferenceEquals(doc, Doc)) return;
        _matches = hits;
        _matchLen = q.Length;
        _current = hits.Count > 0 ? 0 : -1;
        UpdateSummary();
        if (_current >= 0) ScrollToMatch();
        InvalidateVisual();
    }

    public void FindNext(bool backwards = false)
    {
        if (_matches.Count == 0) { RunSearch(); return; }
        _current = backwards ? (_current - 1 + _matches.Count) % _matches.Count : (_current + 1) % _matches.Count;
        UpdateSummary();
        ScrollToMatch();
        InvalidateVisual();
    }

    private void UpdateSummary()
    {
        if (_matches.Count == 0) { MatchSummary = "No matches"; return; }
        string total = _matches.Count >= 10_000 ? "10,000+" : _matches.Count.ToString("N0");
        MatchSummary = $"{_current + 1:N0} / {total}";
    }

    private void ScrollToMatch()
    {
        if (_current < 0 || _current >= _matches.Count) return;
        var (line, col) = Doc.PositionOf(_matches[_current]);
        int row = LineToRow(line, col);
        double y = PadY + row * _lh;
        double targetY = y - Math.Max(0, (_viewport.Height - _lh) / 2);
        double x = _offset.X;
        if (!Wrap)
        {
            double cx = TextLeft + col * _cw;
            if (cx - x < TextLeft || cx + _matchLen * _cw - x > _viewport.Width - PadX)
                x = Math.Max(0, cx - TextLeft - _viewport.Width / 3);
        }
        Offset = new Vector(x, targetY);
        _scrollInvalidated?.Invoke(this, EventArgs.Empty);
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnDetachedFromVisualTree(e);
        _searchCts?.Cancel();
        ClearLayouts();
        ClearNumberLayouts();
    }

    private void ClearLayouts()
    {
        foreach (var l in _layouts.Values) l.Dispose();
        _layouts.Clear();
    }
}
