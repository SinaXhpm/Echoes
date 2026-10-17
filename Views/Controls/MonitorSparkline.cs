using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Echoes.Helpers;

namespace Echoes.Views.Controls;

/// <summary>
/// Response-time sparkline of a monitor's recent checks: a line over a solid area, scaled from 0 to the window's
/// slowest response (so a steady 80 ms reads as steady, not as noise), newest at the right edge. A failed check is a
/// gap in the line with a small mark on the baseline. One geometry per redraw, no child visuals, no animation; it
/// redraws only when <see cref="Version"/> changes. Colors come from the design tokens through styles.
/// </summary>
public sealed class MonitorSparkline : Control
{
    public static readonly StyledProperty<MonitorHistory?> HistoryProperty =
        AvaloniaProperty.Register<MonitorSparkline, MonitorHistory?>(nameof(History));

    /// <summary>Bumped by the owner after each new check; a change redraws the line.</summary>
    public static readonly StyledProperty<int> VersionProperty =
        AvaloniaProperty.Register<MonitorSparkline, int>(nameof(Version));

    public static readonly StyledProperty<IBrush?> LineBrushProperty =
        AvaloniaProperty.Register<MonitorSparkline, IBrush?>(nameof(LineBrush));
    public static readonly StyledProperty<IBrush?> FillBrushProperty =
        AvaloniaProperty.Register<MonitorSparkline, IBrush?>(nameof(FillBrush));
    public static readonly StyledProperty<IBrush?> FailBrushProperty =
        AvaloniaProperty.Register<MonitorSparkline, IBrush?>(nameof(FailBrush));
    public static readonly StyledProperty<double> StrokeThicknessProperty =
        AvaloniaProperty.Register<MonitorSparkline, double>(nameof(StrokeThickness), 1.5);

    /// <summary>How many of the kept checks span the width (the newest ones).</summary>
    public static readonly StyledProperty<int> PointsProperty =
        AvaloniaProperty.Register<MonitorSparkline, int>(nameof(Points), MonitorHistory.Capacity);

    private IPen? _pen;

    static MonitorSparkline()
    {
        AffectsRender<MonitorSparkline>(HistoryProperty, VersionProperty, LineBrushProperty, FillBrushProperty,
            FailBrushProperty, StrokeThicknessProperty, PointsProperty);
    }

    public MonitorHistory? History { get => GetValue(HistoryProperty); set => SetValue(HistoryProperty, value); }
    public int Version { get => GetValue(VersionProperty); set => SetValue(VersionProperty, value); }
    public IBrush? LineBrush { get => GetValue(LineBrushProperty); set => SetValue(LineBrushProperty, value); }
    public IBrush? FillBrush { get => GetValue(FillBrushProperty); set => SetValue(FillBrushProperty, value); }
    public IBrush? FailBrush { get => GetValue(FailBrushProperty); set => SetValue(FailBrushProperty, value); }
    public double StrokeThickness { get => GetValue(StrokeThicknessProperty); set => SetValue(StrokeThicknessProperty, value); }
    public int Points { get => GetValue(PointsProperty); set => SetValue(PointsProperty, value); }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == LineBrushProperty || change.Property == StrokeThicknessProperty) _pen = null;
    }

    public override void Render(DrawingContext context)
    {
        var history = History;
        double width = Bounds.Width, height = Bounds.Height;
        if (history is null || history.Count == 0 || width < 4 || height < 4) return;

        int points = Math.Clamp(Points, 2, MonitorHistory.Capacity);
        int count = history.Count;
        int shown = Math.Min(count, points);
        int first = count - shown;

        double max = 0;
        for (int i = first; i < count; i++)
        {
            double v = history.MsAt(i);
            if (!double.IsNaN(v) && v > max) max = v;
        }
        if (max <= 0) max = 1;   // all answers under a millisecond: a flat line on the baseline

        double stroke = Math.Max(0.5, StrokeThickness);
        double top = stroke, bottom = height - stroke / 2 - 1, usable = Math.Max(1, bottom - top);
        double dx = (width - stroke) / (points - 1);
        double right = width - stroke / 2;
        double X(int i) => right - (count - 1 - i) * dx;
        double Y(double v) => bottom - v / max * usable;

        var line = new StreamGeometry();
        var area = FillBrush is null ? null : new StreamGeometry();
        var failBrush = FailBrush;
        using (var lc = line.Open())
        using (var ac = area?.Open())
        {
            int runStart = -1;
            Point last = default;
            for (int i = first; i <= count; i++)
            {
                double v = i < count ? history.MsAt(i) : double.NaN;
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
                        // A lone point between gaps is drawn as a dot below, not as an invisible zero-length line.
                        if (i - runStart == 1) DrawDot(context, last, stroke);
                        runStart = -1;
                    }
                    if (i < count && failBrush is not null && history.BeatAt(i) is MonitorBeat.Down or MonitorBeat.Pending)
                        context.DrawRectangle(failBrush, null, new Rect(X(i) - 1, height - 2, 2, 2));
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

    private void DrawDot(DrawingContext context, Point p, double stroke)
    {
        if (LineBrush is { } brush) context.DrawEllipse(brush, null, p, stroke, stroke);
    }
}
