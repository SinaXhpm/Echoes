using System;
using System.Collections.Generic;
using Avalonia;
using Avalonia.Controls;

namespace Echoes.Views.Controls;

/// <summary>
/// The launcher's cards: a block per group, its heading over its cards in equal columns, row by row. Groups share a band
/// (blocks side by side under one line of headings) where that makes the page shorter: Diagnose's ten cards in two
/// columns beside Web &amp; API's five in one, both five rows deep, rather than every group under the last with half-empty
/// rows between them. The columns follow the width (each at least <see cref="MinColumnWidth"/>, at most
/// <see cref="MaxColumns"/> of them); the bands and how many columns each group takes are chosen for the shortest page,
/// then the fewest empty places. Every card is the same size, so the rows line up across the page. With room to spare
/// below (<see cref="FitHeight"/>), the cards grow taller, by up to <see cref="MaxGrow"/>, to fill it.
/// Children, in order: a <see cref="TextBlock"/> starts a group (its heading), the controls after it are its cards. Hidden
/// ones take no place (the shell hides a heading whose cards are all hidden by a search).
/// </summary>
public sealed class LauncherPanel : Panel
{
    public static readonly StyledProperty<double> MinColumnWidthProperty =
        AvaloniaProperty.Register<LauncherPanel, double>(nameof(MinColumnWidth), 240);
    public static readonly StyledProperty<int> MaxColumnsProperty =
        AvaloniaProperty.Register<LauncherPanel, int>(nameof(MaxColumns), 4);
    public static readonly StyledProperty<double> FitHeightProperty =
        AvaloniaProperty.Register<LauncherPanel, double>(nameof(FitHeight), double.PositiveInfinity);
    public static readonly StyledProperty<double> MaxGrowProperty =
        AvaloniaProperty.Register<LauncherPanel, double>(nameof(MaxGrow), 16);

    static LauncherPanel()
        => AffectsMeasure<LauncherPanel>(MinColumnWidthProperty, MaxColumnsProperty, FitHeightProperty, MaxGrowProperty);

    /// <summary>The narrowest a column may be: a card's name and line still read in full.</summary>
    public double MinColumnWidth { get => GetValue(MinColumnWidthProperty); set => SetValue(MinColumnWidthProperty, value); }

    public int MaxColumns { get => GetValue(MaxColumnsProperty); set => SetValue(MaxColumnsProperty, value); }

    /// <summary>The height there is to fill (the scroller's, inside a scroller); infinite for none.</summary>
    public double FitHeight { get => GetValue(FitHeightProperty); set => SetValue(FitHeightProperty, value); }

    /// <summary>How much taller than they need a card may grow to fill <see cref="FitHeight"/>.</summary>
    public double MaxGrow { get => GetValue(MaxGrowProperty); set => SetValue(MaxGrowProperty, value); }

    /// <summary>How many columns the cards were last laid out in.</summary>
    public int Columns => _columns;

    private sealed class Group
    {
        public Control? Heading;
        public readonly List<Control> Cards = new();
        public int Span = 1;   // the columns it takes in its band
    }

    private readonly List<Group> _groups = new();
    private readonly List<(int First, int Count, int Rows)> _bands = new();   // groups [First, First + Count) side by side
    private int _columns = 1;
    private double _headingHeight, _cardHeight, _grow;

    protected override Size MeasureOverride(Size availableSize)
    {
        double min = Math.Max(1, MinColumnWidth);
        int most = Math.Max(1, MaxColumns);
        double width = double.IsInfinity(availableSize.Width) ? min * most : availableSize.Width;
        _columns = Math.Clamp((int)Math.Floor(width / min), 1, most);
        double column = width / _columns;

        _groups.Clear();
        _bands.Clear();
        _headingHeight = _cardHeight = _grow = 0;
        Group? group = null;
        foreach (var child in Children)
        {
            if (!child.IsVisible) continue;
            if (child is TextBlock)
            {
                group = new Group { Heading = child };
                _groups.Add(group);
                child.Measure(new Size(width, double.PositiveInfinity));
                _headingHeight = Math.Max(_headingHeight, child.DesiredSize.Height);
                continue;
            }
            if (group is null) _groups.Add(group = new Group());
            group.Cards.Add(child);
            child.Measure(new Size(column, double.PositiveInfinity));
            _cardHeight = Math.Max(_cardHeight, child.DesiredSize.Height);
        }
        if (_groups.Count == 0) return default;

        Pack();

        int rows = 0;
        double height = 0;
        foreach (var band in _bands)
        {
            rows += band.Rows;
            height += HeadingOf(band) + band.Rows * _cardHeight;
        }
        if (!double.IsInfinity(FitHeight) && rows > 0 && FitHeight > height)
            _grow = Math.Min(Math.Max(0, MaxGrow), Math.Floor((FitHeight - height) / rows));
        return new Size(width, height + rows * _grow);
    }

    protected override Size ArrangeOverride(Size finalSize)
    {
        double column = finalSize.Width / _columns;
        double card = _cardHeight + _grow;
        double y = 0;
        foreach (var band in _bands)
        {
            double top = y + HeadingOf(band), x = 0;
            for (int i = band.First; i < band.First + band.Count; i++)
            {
                var group = _groups[i];
                group.Heading?.Arrange(new Rect(x, y, group.Span * column, _headingHeight));
                for (int c = 0; c < group.Cards.Count; c++)
                    group.Cards[c].Arrange(new Rect(x + c % group.Span * column, top + c / group.Span * card, column, card));
                x += group.Span * column;
            }
            y = top + band.Rows * card;
        }
        return finalSize;
    }

    // a band has a line for its headings when one of its groups has one
    private double HeadingOf((int First, int Count, int Rows) band)
    {
        for (int i = band.First; i < band.First + band.Count; i++)
            if (_groups[i].Heading is not null) return _headingHeight;
        return 0;
    }

    // Every way of cutting the groups, in order, into bands is tried (a launcher has a handful of groups; past a dozen,
    // each group is a band of its own): the shortest page wins, then the fewest empty places, then the fewest bands.
    private void Pack()
    {
        int count = _groups.Count;
        if (count > 12)
        {
            for (int i = 0; i < count; i++)
            {
                var (rows, _, spans) = FitBand(i, 1)!.Value;
                _groups[i].Span = spans[0];
                _bands.Add((i, 1, rows));
            }
            return;
        }
        double bestHeight = double.MaxValue;
        int bestHoles = int.MaxValue, bestBands = int.MaxValue;
        var tried = new List<(int First, int Count, int Rows, int[] Spans)>();
        List<(int First, int Count, int Rows, int[] Spans)>? best = null;
        for (int cuts = 0; cuts < 1 << (count - 1); cuts++)
        {
            tried.Clear();
            double height = 0;
            int holes = 0, first = 0;
            bool fits = true;
            for (int i = 1; i <= count && fits; i++)
            {
                if (i < count && (cuts & (1 << (i - 1))) == 0) continue;   // group i goes in the same band as the one before
                if (FitBand(first, i - first) is { } fit)
                {
                    tried.Add((first, i - first, fit.Rows, fit.Spans));
                    holes += fit.Holes;
                    bool headed = false;
                    for (int j = first; j < i; j++) headed |= _groups[j].Heading is not null;
                    height += (headed ? _headingHeight : 0) + fit.Rows * _cardHeight;
                }
                else fits = false;
                first = i;
            }
            if (!fits) continue;
            bool shorter = height < bestHeight - 0.5;
            bool asTall = !shorter && height <= bestHeight + 0.5;
            if (shorter || (asTall && (holes < bestHoles || (holes == bestHoles && tried.Count < bestBands))))
            {
                bestHeight = height;
                bestHoles = holes;
                bestBands = tried.Count;
                best = new List<(int, int, int, int[])>(tried);
            }
        }
        foreach (var (first, n, rows, spans) in best!)
        {
            for (int j = 0; j < n; j++) _groups[first + j].Span = spans[j];
            _bands.Add((first, n, rows));
        }
    }

    // The groups [first, first + count) side by side, each in one or more columns (never more than it has cards): the
    // split with the fewest rows, then the fewest empty places (columns left over count too). Null when they don't fit.
    private (int Rows, int Holes, int[] Spans)? FitBand(int first, int count)
    {
        if (count > _columns) return null;
        var spans = new int[count];
        var bestSpans = new int[count];
        int bestRows = int.MaxValue, bestHoles = int.MaxValue;
        Try(0, 0);
        return (bestRows, bestHoles, bestSpans);

        void Try(int j, int used)
        {
            if (j == count)
            {
                int rows = 0;
                for (int i = 0; i < count; i++)
                    rows = Math.Max(rows, (_groups[first + i].Cards.Count + spans[i] - 1) / spans[i]);
                int holes = (_columns - used) * rows;
                for (int i = 0; i < count; i++) holes += spans[i] * rows - _groups[first + i].Cards.Count;
                if (rows < bestRows || (rows == bestRows && holes < bestHoles))
                {
                    bestRows = rows;
                    bestHoles = holes;
                    spans.CopyTo(bestSpans, 0);
                }
                return;
            }
            // what is left, keeping a column for each group still to come
            int room = _columns - used - (count - j - 1);
            int most = Math.Max(1, Math.Min(_groups[first + j].Cards.Count, room));
            for (int k = 1; k <= most; k++)
            {
                spans[j] = k;
                Try(j + 1, used + k);
            }
        }
    }
}
