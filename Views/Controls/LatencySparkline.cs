using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Echoes.Helpers;

namespace Echoes.Views.Controls;

/// <summary>
/// Recent round-trip times (a <see cref="LatencySeries"/>) as a small chart, newest at the right edge: a line over a solid
/// area, or (<see cref="Bars"/>) one bar per probe like mtr's graph. Scaled from 0 to the slowest value shown, but never
/// below <see cref="MinScale"/> ms, so a LAN hop's sub-millisecond wobble doesn't fill the whole height. A probe that got
/// no answer is a gap with a small mark on the baseline. Drawn straight into the context — no child visuals, no
/// animation — and only when <see cref="Version"/> (or a brush) changes. Colors come from the design tokens via styles.
/// </summary>
public sealed class LatencySparkline : Control
{
    public static readonly StyledProperty<LatencySeries?> SeriesProperty =
        AvaloniaProperty.Register<LatencySparkline, LatencySeries?>(nameof(Series));

    /// <summary>Bumped by the owner after each change to the series; a change redraws.</summary>
    public static readonly StyledProperty<int> VersionProperty =
        AvaloniaProperty.Register<LatencySparkline, int>(nameof(Version));

    public static readonly StyledProperty<IBrush?> LineBrushProperty =
        AvaloniaProperty.Register<LatencySparkline, IBrush?>(nameof(LineBrush));
    public static readonly StyledProperty<IBrush?> FillBrushProperty =
        AvaloniaProperty.Register<LatencySparkline, IBrush?>(nameof(FillBrush));
    public static readonly StyledProperty<IBrush?> LossBrushProperty =
        AvaloniaProperty.Register<LatencySparkline, IBrush?>(nameof(LossBrush));
    public static readonly StyledProperty<double> StrokeThicknessProperty =
        AvaloniaProperty.Register<LatencySparkline, double>(nameof(StrokeThickness), 1.5);

    /// <summary>How many samples span the width (the newest ones); 0 = the series' capacity.</summary>
    public static readonly StyledProperty<int> PointsProperty =
        AvaloniaProperty.Register<LatencySparkline, int>(nameof(Points));

    public static readonly StyledProperty<bool> BarsProperty =
        AvaloniaProperty.Register<LatencySparkline, bool>(nameof(Bars));

    public static readonly StyledProperty<double> MinScaleProperty =
        AvaloniaProperty.Register<LatencySparkline, double>(nameof(MinScale), 10);

    /// <summary>The top of the scale as a multiple of the slowest value shown (1.25 = a steady line sits at 80 %,
    /// leaving room to see a spike above it).</summary>
    public static readonly StyledProperty<double> HeadroomProperty =
        AvaloniaProperty.Register<LatencySparkline, double>(nameof(Headroom), 1.0);

    private IPen? _pen;

    static LatencySparkline()
    {
        AffectsRender<LatencySparkline>(SeriesProperty, VersionProperty, LineBrushProperty, FillBrushProperty, LossBrushProperty,
            StrokeThicknessProperty, PointsProperty, BarsProperty, MinScaleProperty, HeadroomProperty);
    }

    public LatencySeries? Series { get => GetValue(SeriesProperty); set => SetValue(SeriesProperty, value); }
    public int Version { get => GetValue(VersionProperty); set => SetValue(VersionProperty, value); }
    public IBrush? LineBrush { get => GetValue(LineBrushProperty); set => SetValue(LineBrushProperty, value); }
    public IBrush? FillBrush { get => GetValue(FillBrushProperty); set => SetValue(FillBrushProperty, value); }
    public IBrush? LossBrush { get => GetValue(LossBrushProperty); set => SetValue(LossBrushProperty, value); }
    public double StrokeThickness { get => GetValue(StrokeThicknessProperty); set => SetValue(StrokeThicknessProperty, value); }
    public int Points { get => GetValue(PointsProperty); set => SetValue(PointsProperty, value); }
    public bool Bars { get => GetValue(BarsProperty); set => SetValue(BarsProperty, value); }
    public double MinScale { get => GetValue(MinScaleProperty); set => SetValue(MinScaleProperty, value); }
    public double Headroom { get => GetValue(HeadroomProperty); set => SetValue(HeadroomProperty, value); }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == LineBrushProperty || change.Property == StrokeThicknessProperty) _pen = null;
    }

    public override void Render(DrawingContext context)
    {
        var series = Series;
        double width = Bounds.Width, height = Bounds.Height;
        if (series is null || series.Count == 0 || width < 4 || height < 4) return;

        int points = Math.Clamp(Points > 0 ? Points : series.Capacity, 2, 2000);
        int count = series.Count;
        int shown = Math.Min(count, points);
        int first = count - shown;

        double slowest = 0;
        for (int i = first; i < count; i++)
        {
            double v = series[i];
            if (!double.IsNaN(v) && v > slowest) slowest = v;
        }
        double max = Math.Max(Math.Max(0.001, MinScale), slowest * Math.Max(1, Headroom));

        if (Bars) DrawBars(context, series, first, count, points, max, width, height);
        else DrawLine(context, series, first, count, points, max, width, height);
    }

    private void DrawBars(DrawingContext context, LatencySeries series, int first, int count, int points, double max,
                          double width, double height)
    {
        double slot = width / points;
        double gap = slot >= 4 ? 1 : 0;
        var bar = LineBrush;
        var loss = LossBrush;
        for (int i = first; i < count; i++)
        {
            // Whole pixels, so the bars stay crisp; the newest one ends at the right edge.
            double right = Math.Round(width - (count - 1 - i) * slot);
            double left = Math.Round(width - (count - i) * slot);
            double w = Math.Max(1, right - left - gap);
            double v = series[i];
            if (double.IsNaN(v))
            {
                if (loss is not null) context.DrawRectangle(loss, null, new Rect(left, height - 3, w, 3));
                continue;
            }
            if (bar is null) continue;
            double h = Math.Max(1, Math.Round(v / max * height));
            context.DrawRectangle(bar, null, new Rect(left, height - h, w, h));
        }
    }

    private void DrawLine(DrawingContext context, LatencySeries series, int first, int count, int points, double max,
                          double width, double height)
    {
        double stroke = Math.Max(0.5, StrokeThickness);
        double top = stroke, bottom = height - stroke / 2 - 1, usable = Math.Max(1, bottom - top);
        double dx = (width - stroke) / (points - 1);
        double right = width - stroke / 2;
        double X(int i) => right - (count - 1 - i) * dx;
        double Y(double v) => bottom - v / max * usable;

        var line = new StreamGeometry();
        var area = FillBrush is null ? null : new StreamGeometry();
        var loss = LossBrush;
        using (var lc = line.Open())
        using (var ac = area?.Open())
        {
            int runStart = -1;
            Point last = default;
            for (int i = first; i <= count; i++)
            {
                double v = i < count ? series[i] : double.NaN;
                if (double.IsNaN(v))
                {
                    if (runStart >= 0)
                    {
                        lc.EndFigure(false);
                        if (ac is not null)
                        {
                            ac.LineTo(new Point(last.X, bottom), false);
                            ac.EndFigure(true);
                        }
                        // A lone answer between losses is a dot, not an invisible zero-length line.
                        if (i - runStart == 1 && LineBrush is { } dot) context.DrawEllipse(dot, null, last, stroke, stroke);
                        runStart = -1;
                    }
                    if (i < count && loss is not null)
                        context.DrawRectangle(loss, null, new Rect(Math.Round(X(i)) - 1, height - 2, 2, 2));
                    continue;
                }

                var p = new Point(X(i), Y(v));
                if (runStart < 0)
                {
                    runStart = i;
                    lc.BeginFigure(p, false);
                    if (ac is not null)
                    {
                        ac.BeginFigure(new Point(p.X, bottom), true);
                        ac.LineTo(p, false);
                    }
                }
                else
                {
                    lc.LineTo(p, true);
                    ac?.LineTo(p, false);
                }
                last = p;
            }
        }

        if (area is not null) context.DrawGeometry(FillBrush, null, area);
        _pen ??= LineBrush is { } brush ? new Pen(brush, stroke, null, PenLineCap.Round, PenLineJoin.Round) : null;
        if (_pen is not null) context.DrawGeometry(null, _pen, line);
    }
}
