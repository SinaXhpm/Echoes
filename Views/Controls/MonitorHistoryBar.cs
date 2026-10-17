using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Echoes.Helpers;

namespace Echoes.Views.Controls;

/// <summary>
/// A monitor's recent checks as a row of colored ticks — up / pending / down — newest at the right edge, empty slots
/// on the left until enough checks have run (the beat bar of Uptime Kuma / UptimeRobot). Drawn straight into the
/// <see cref="DrawingContext"/>: one control per row instead of a visual per tick, no animation, and it redraws only
/// when <see cref="Version"/> changes. The colors come from the design tokens through styles.
/// </summary>
public sealed class MonitorHistoryBar : Control
{
    public static readonly StyledProperty<MonitorHistory?> HistoryProperty =
        AvaloniaProperty.Register<MonitorHistoryBar, MonitorHistory?>(nameof(History));

    /// <summary>Bumped by the owner after each new check; a change redraws the bar.</summary>
    public static readonly StyledProperty<int> VersionProperty =
        AvaloniaProperty.Register<MonitorHistoryBar, int>(nameof(Version));

    public static readonly StyledProperty<IBrush?> UpBrushProperty =
        AvaloniaProperty.Register<MonitorHistoryBar, IBrush?>(nameof(UpBrush));
    public static readonly StyledProperty<IBrush?> PendingBrushProperty =
        AvaloniaProperty.Register<MonitorHistoryBar, IBrush?>(nameof(PendingBrush));
    public static readonly StyledProperty<IBrush?> DownBrushProperty =
        AvaloniaProperty.Register<MonitorHistoryBar, IBrush?>(nameof(DownBrush));
    public static readonly StyledProperty<IBrush?> EmptyBrushProperty =
        AvaloniaProperty.Register<MonitorHistoryBar, IBrush?>(nameof(EmptyBrush));

    public static readonly StyledProperty<double> TickWidthProperty =
        AvaloniaProperty.Register<MonitorHistoryBar, double>(nameof(TickWidth), 3);
    public static readonly StyledProperty<double> TickGapProperty =
        AvaloniaProperty.Register<MonitorHistoryBar, double>(nameof(TickGap), 1);

    /// <summary>Widen the ticks (on whole pixels) so all <see cref="MonitorHistory.Capacity"/> slots span the width,
    /// instead of fixed-size ticks right-aligned in a wide panel.</summary>
    public static readonly StyledProperty<bool> StretchTicksProperty =
        AvaloniaProperty.Register<MonitorHistoryBar, bool>(nameof(StretchTicks));

    static MonitorHistoryBar()
    {
        AffectsRender<MonitorHistoryBar>(HistoryProperty, VersionProperty, UpBrushProperty, PendingBrushProperty,
            DownBrushProperty, EmptyBrushProperty, TickWidthProperty, TickGapProperty, StretchTicksProperty);
    }

    public MonitorHistory? History { get => GetValue(HistoryProperty); set => SetValue(HistoryProperty, value); }
    public int Version { get => GetValue(VersionProperty); set => SetValue(VersionProperty, value); }
    public IBrush? UpBrush { get => GetValue(UpBrushProperty); set => SetValue(UpBrushProperty, value); }
    public IBrush? PendingBrush { get => GetValue(PendingBrushProperty); set => SetValue(PendingBrushProperty, value); }
    public IBrush? DownBrush { get => GetValue(DownBrushProperty); set => SetValue(DownBrushProperty, value); }
    public IBrush? EmptyBrush { get => GetValue(EmptyBrushProperty); set => SetValue(EmptyBrushProperty, value); }
    public double TickWidth { get => GetValue(TickWidthProperty); set => SetValue(TickWidthProperty, value); }
    public double TickGap { get => GetValue(TickGapProperty); set => SetValue(TickGapProperty, value); }
    public bool StretchTicks { get => GetValue(StretchTicksProperty); set => SetValue(StretchTicksProperty, value); }

    public override void Render(DrawingContext context)
    {
        double width = Bounds.Width, height = Bounds.Height;
        double tick = Math.Max(1, TickWidth), gap = Math.Max(0, TickGap), step = tick + gap;
        if (width < tick || height <= 0) return;

        int slots;
        double x0;
        bool stretch = StretchTicks && (width + gap) / MonitorHistory.Capacity >= step;
        if (stretch)
        {
            // All slots across the full width; each edge snapped to a whole pixel, so ticks stay crisp (they differ by
            // at most a pixel in width) and the bar ends flush with both sides.
            slots = MonitorHistory.Capacity;
            step = (width + gap) / slots;
            if (step >= 8) gap = Math.Round(step / 4);   // wide beats get a proportional gap
            x0 = 0;
        }
        else
        {
            slots = Math.Min(MonitorHistory.Capacity, (int)((width + gap) / step));
            // Right-aligned on whole pixels: the newest check ends exactly at the right edge.
            x0 = Math.Floor(width - (slots * step - gap));
        }
        if (slots <= 0) return;

        var history = History;
        int count = history?.Count ?? 0;
        double radius = Math.Min(1, tick / 2);
        for (int s = 0; s < slots; s++)
        {
            int i = count - slots + s;   // < 0: no check for this slot yet
            IBrush? brush = i < 0 || history is null
                ? EmptyBrush
                : history.BeatAt(i) switch
                {
                    MonitorBeat.Up => UpBrush,
                    MonitorBeat.Pending => PendingBrush,
                    MonitorBeat.Down => DownBrush,
                    _ => EmptyBrush,
                };
            if (brush is null) continue;
            double left = stretch ? Math.Round(x0 + s * step) : x0 + s * step;
            double right = stretch ? Math.Round(x0 + (s + 1) * step - gap) : left + tick;
            if (right - left >= 1)
                context.DrawRectangle(brush, null, new Rect(left, 0, right - left, height), radius, radius);
        }
    }
}
