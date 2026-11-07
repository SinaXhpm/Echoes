using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Presenters;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.VisualTree;
using Echoes.ViewModels;

namespace Echoes.Views.Controls;

/// <summary>
/// The chat transcript's items panel: only the rows near the viewport exist, like <see cref="VirtualizingStackPanel"/>,
/// but it knows every row's height instead of guessing.
/// <para>
/// VirtualizingStackPanel sizes the whole list as "the average of the rows on screen" × the row count, so with messages
/// of different lengths the list's height swings several times over while scrolling: the scrollbar jumps, dragging it
/// lands anywhere, and dropping the oldest row moves what is being read. Here each row has its height: measured once it
/// has been shown, until then worked out from its text (<see cref="Estimate"/>). A row's place is the sum of the heights
/// above it, so an offset always means the same place. The ScrollViewer's anchoring keeps what is on screen still when a
/// row above changes height or goes away.
/// </para>
/// <para>
/// Rows that leave are kept, hidden, and get the next message (only their bindings change). The items control's own
/// recycling clears the row's template, so every row that scrolls in would be built again.
/// </para>
/// </summary>
public sealed class ChatPanel : VirtualizingPanel
{
    /// <summary>Rows are kept this many viewports beyond each edge, so most scrolling only moves what is already there.</summary>
    private const double Buffer = 0.5;
    private const int MaxPool = 32;

    private readonly List<double> _heights = new();
    private List<Control> _rows = new();          // the shown rows: items _first, _first + 1, ...
    private List<Control> _nextRows = new();
    private readonly Stack<Control> _pool = new();
    private int _first;
    private double _coveredTop, _coveredBottom;   // what the shown rows span, as of the last measure
    private Rect _viewport;
    private IScrollAnchorProvider? _anchors;

    // Read off a shown row, per width (Calibrate): a row's height = _chrome + lines × _lineHeight.
    private double _width = -1;
    private double _chrome = 60, _lineHeight = 16, _charsPerLine = 80;
    private bool _calibrated;

    public ChatPanel() => EffectiveViewportChanged += OnViewportChanged;

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        _anchors = this.FindAncestorOfType<IScrollAnchorProvider>();
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnDetachedFromVisualTree(e);
        _anchors = null;
    }

    // ------------------------------------------------------------------ layout

    protected override Size MeasureOverride(Size availableSize)
    {
        var items = Items;
        if (items.Count != _heights.Count) ResetHeights(items);
        if (availableSize.Width != _width)
        {
            _width = availableSize.Width;
            _calibrated = false;
        }

        bool wasCalibrated = _calibrated;
        Realize(items, availableSize);
        if (_calibrated && !wasCalibrated)
        {
            // the first row told the real sizes: the estimates change, and with them what the viewport covers
            for (int i = 0; i < items.Count; i++) _heights[i] = Estimate(items[i]);
            Realize(items, availableSize);
        }

        double total = 0;
        foreach (double h in _heights) total += h;
        return new Size(double.IsInfinity(availableSize.Width) ? 0 : availableSize.Width, total);
    }

    /// <summary>Shows the rows the viewport needs, reusing those already right, and measures them.</summary>
    private void Realize(IReadOnlyList<object?> items, Size available)
    {
        double buffer = _viewport.Height * Buffer;
        double top = _viewport.Top - buffer, bottom = _viewport.Bottom + buffer;

        int first = 0;
        double y = 0;
        if (_viewport.Height <= 0) first = items.Count;   // nothing can be seen: nothing to build
        else
            while (first < items.Count && y + _heights[first] <= top)
                y += _heights[first++];

        // free what is out of range first, so those rows can be used right away
        int estimatedLast = first;
        for (double e = y; estimatedLast < items.Count && e < bottom; estimatedLast++) e += _heights[estimatedLast];
        for (int i = 0; i < _rows.Count; i++)
        {
            int index = _first + i;
            if (index < first || index > estimatedLast) Recycle(_rows[i]);
        }

        _nextRows.Clear();
        double rowTop = y;
        int at = first;
        var constraint = new Size(available.Width, double.PositiveInfinity);
        while (at < items.Count && rowTop < bottom)
        {
            int old = at - _first;
            var row = old >= 0 && old < _rows.Count && at >= first && at <= estimatedLast ? _rows[old] : Take(items[at], at);
            row.Measure(constraint);
            double h = row.DesiredSize.Height;
            if (Math.Abs(h - _heights[at]) > 0.01) KeepOnScreen();
            _heights[at] = h;
            if (!_calibrated) Calibrate(row, items[at]);
            _nextRows.Add(row);
            rowTop += h;
            at++;
        }
        // a row the estimate kept but the real heights didn't need
        for (int i = 0; i < _rows.Count; i++)
        {
            int index = _first + i;
            if (index >= at && index <= estimatedLast) Recycle(_rows[i]);
        }

        (_rows, _nextRows) = (_nextRows, _rows);
        _nextRows.Clear();
        _first = first;
        _coveredTop = y;
        _coveredBottom = rowTop;
    }

    protected override Size ArrangeOverride(Size finalSize)
    {
        double y = 0;
        for (int i = 0; i < _first && i < _heights.Count; i++) y += _heights[i];
        foreach (var row in _rows)
        {
            double h = row.DesiredSize.Height;
            var rect = new Rect(0, y, finalSize.Width, h);
            row.Arrange(rect);
            if (_viewport.Intersects(rect)) _anchors?.RegisterAnchorCandidate(row);
            y += h;
        }
        return finalSize;
    }

    private void OnViewportChanged(object? sender, EffectiveViewportChangedEventArgs e)
    {
        var viewport = e.EffectiveViewport.Intersect(new Rect(Bounds.Size));
        double margin = viewport.Height * Buffer / 2;
        bool needMore = viewport.Height > 0 && _viewport.Height <= 0
            || (viewport.Top - margin < _coveredTop && _first > 0)
            || (viewport.Bottom + margin > _coveredBottom && _first + _rows.Count < _heights.Count);
        _viewport = viewport;
        if (needMore) InvalidateMeasure();
    }

    // ------------------------------------------------------------------ rows

    private Control Take(object? item, int index)
    {
        var generator = ItemContainerGenerator!;
        generator.NeedsContainer(item, index, out var recycleKey);
        if (_pool.TryPop(out var row))
        {
            // the row's controls stay: the presenter's template only gets a new item
            if (row is ContentPresenter presenter) presenter.SetCurrentValue(ContentPresenter.ContentProperty, item);
            generator.PrepareItemContainer(row, item, index);
            row.SetCurrentValue(IsVisibleProperty, true);
            generator.ItemContainerPrepared(row, item, index);
            // The new text only invalidated the text block itself: its parents would answer the measure below with the
            // size of the previous message.
            foreach (var part in row.GetVisualDescendants().OfType<Layoutable>()) part.InvalidateMeasure();
            return row;
        }
        row = generator.CreateContainer(item, index, recycleKey);
        generator.PrepareItemContainer(row, item, index);
        AddInternalChild(row);
        generator.ItemContainerPrepared(row, item, index);
        return row;
    }

    private void Recycle(Control row)
    {
        _anchors?.UnregisterAnchorCandidate(row);
        // a selection belongs to the message, not to the row that goes on to show another one
        foreach (var text in row.GetVisualDescendants().OfType<SelectableTextBlock>()) text.ClearSelection();
        if (_pool.Count >= MaxPool)
        {
            ItemContainerGenerator!.ClearItemContainer(row);
            RemoveInternalChild(row);
            return;
        }
        row.SetCurrentValue(IsVisibleProperty, false);
        _pool.Push(row);
    }

    private void RecycleAll()
    {
        foreach (var row in _rows) Recycle(row);
        _rows.Clear();
        _first = 0;
    }

    // ------------------------------------------------------------------ heights

    private void ResetHeights(IReadOnlyList<object?> items)
    {
        RecycleAll();
        _heights.Clear();
        foreach (var item in items) _heights.Add(Estimate(item));
    }

    /// <summary>A row's height from its text, for rows not shown yet. Close is enough: it's replaced when the row is shown.</summary>
    private double Estimate(object? item)
    {
        if (item is not ChatRow row) return _chrome + _lineHeight;
        int lines = row.IsLong ? 1 : 0;   // its "Show all" takes about a line
        var rest = row.ShownText.AsSpan();
        while (true)
        {
            int newline = rest.IndexOf('\n');
            int length = newline < 0 ? rest.Length : newline;
            lines += Math.Max(1, (int)Math.Ceiling(length / _charsPerLine));
            if (newline < 0) break;
            rest = rest[(newline + 1)..];
        }
        return _chrome + lines * _lineHeight;
    }

    /// <summary>Learns the row's chrome, line height and text width from a shown message.</summary>
    private void Calibrate(Control row, object? item)
    {
        if (item is not ChatRow { IsFile: false, IsLong: false }) return;
        var text = row.GetVisualDescendants().OfType<SelectableTextBlock>().FirstOrDefault();
        if (text is null) return;
        var layout = text.TextLayout;
        int lines = layout.TextLines.Count;
        if (lines == 0 || layout.MaxWidth is <= 0 or double.PositiveInfinity) return;
        _lineHeight = layout.Height / lines;
        _chrome = row.DesiredSize.Height - layout.Height;
        _charsPerLine = Math.Max(8, layout.MaxWidth / (text.FontSize * AverageCharWidth));
        _calibrated = true;
    }

    /// <summary>Of the font size, for running text with spaces; wrapping at words loses a little more of each line.</summary>
    private const double AverageCharWidth = 0.54;

    // ------------------------------------------------------------------ the list changed

    protected override void OnItemsChanged(IReadOnlyList<object?> items, NotifyCollectionChangedEventArgs e)
    {
        base.OnItemsChanged(items, e);
        switch (e)
        {
            // new messages go to the end
            case { Action: NotifyCollectionChangedAction.Add, NewItems: { } added } when e.NewStartingIndex == _heights.Count:
                foreach (var item in added) _heights.Add(Estimate(item));
                break;
            // the oldest are dropped past the row limit
            case { Action: NotifyCollectionChangedAction.Remove, OldItems: { } removed } when e.OldStartingIndex + removed.Count <= _first:
                DropAbove(e.OldStartingIndex, removed.Count);
                break;
            default:
                ResetHeights(items);
                break;
        }
        InvalidateMeasure();
    }

    /// <summary>Rows gone from above the shown ones: those move up by that much, and what is read must not move on screen.</summary>
    private void DropAbove(int at, int count)
    {
        double gone = 0;
        for (int i = at; i < at + count; i++) gone += _heights[i];
        _heights.RemoveRange(at, count);
        _first -= count;
        // the same rows stay shown; the anchoring then moves the offset with them
        _viewport = _viewport.WithY(_viewport.Y - gone);
        KeepOnScreen();
    }

    /// <summary>Rows are about to move inside the list. The scroller's anchoring keeps them still on screen, but it only runs
    /// when the scroller arranges its content, and it doesn't do that by itself if the list's total height comes out the same
    /// (one message in and one out, one row taller and one shorter).</summary>
    private void KeepOnScreen()
    {
        for (var parent = this.GetVisualParent(); parent is Layoutable layoutable; parent = parent.GetVisualParent())
        {
            layoutable.InvalidateArrange();
            if (ReferenceEquals(parent, _anchors)) break;
        }
    }

    // ------------------------------------------------------------------ what VirtualizingPanel asks for

    protected override Control? ScrollIntoView(int index) => ContainerFromIndex(index);

    protected override Control? ContainerFromIndex(int index)
        => index >= _first && index < _first + _rows.Count ? _rows[index - _first] : null;

    protected override int IndexFromContainer(Control container)
    {
        int i = _rows.IndexOf(container);
        return i < 0 ? -1 : _first + i;
    }

    protected override IEnumerable<Control>? GetRealizedContainers() => _rows;

    // the rows aren't a navigable list: Tab goes through their buttons as in any other panel
    protected override IInputElement? GetControl(NavigationDirection direction, IInputElement? from, bool wrap) => null;
}
