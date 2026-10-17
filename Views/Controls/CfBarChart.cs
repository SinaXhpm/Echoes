using System;
using System.Collections.Generic;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;

namespace Echoes.Views.Controls;

/// <summary>
/// The Cloudflare overview's traffic bars: one solid bar per hour / day, scaled to the busiest one, on a hairline
/// baseline. Drawn straight into the <see cref="DrawingContext"/> (a handful of rectangles, no visuals per bar, no
/// animation); it redraws only when <see cref="Values"/> is replaced. Brushes come from the design tokens in XAML.
/// </summary>
public sealed class CfBarChart : Control
{
    public static readonly StyledProperty<IReadOnlyList<long>?> ValuesProperty =
        AvaloniaProperty.Register<CfBarChart, IReadOnlyList<long>?>(nameof(Values));

    public static readonly StyledProperty<IBrush?> BarBrushProperty =
        AvaloniaProperty.Register<CfBarChart, IBrush?>(nameof(BarBrush));

    public static readonly StyledProperty<IBrush?> BaselineBrushProperty =
        AvaloniaProperty.Register<CfBarChart, IBrush?>(nameof(BaselineBrush));

    static CfBarChart()
    {
        AffectsRender<CfBarChart>(ValuesProperty, BarBrushProperty, BaselineBrushProperty);
    }

    public IReadOnlyList<long>? Values { get => GetValue(ValuesProperty); set => SetValue(ValuesProperty, value); }
    public IBrush? BarBrush { get => GetValue(BarBrushProperty); set => SetValue(BarBrushProperty, value); }
    public IBrush? BaselineBrush { get => GetValue(BaselineBrushProperty); set => SetValue(BaselineBrushProperty, value); }

    public override void Render(DrawingContext context)
    {
        double width = Bounds.Width, height = Bounds.Height;
        if (width <= 0 || height <= 2) return;
        if (BaselineBrush is { } line) context.DrawRectangle(line, null, new Rect(0, height - 1, width, 1));

        var values = Values;
        if (values is null || values.Count == 0 || BarBrush is not { } bar) return;
        long max = 0;
        foreach (long v in values) max = Math.Max(max, v);
        if (max <= 0) return;

        int n = values.Count;
        double gap = n > 12 ? 3 : 8;
        double step = (width + gap) / n;
        double barWidth = step - gap;
        if (barWidth < 1) { gap = 0; step = width / n; barWidth = step; }
        double room = height - 2;   // above the baseline
        for (int i = 0; i < n; i++)
        {
            if (values[i] <= 0) continue;
            double h = Math.Max(2, Math.Round(room * values[i] / max));
            double left = Math.Round(i * step);
            double right = Math.Round(i * step + barWidth);
            if (right - left < 1) right = left + 1;
            context.DrawRectangle(bar, null, new Rect(left, height - 1 - h, right - left, h), 2, 2);
        }
    }
}
