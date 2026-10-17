using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;

namespace Echoes.Views.Controls;

/// <summary>One bar of the cURL tab's timing waterfall: a solid track with a solid segment from <see cref="Start"/> for
/// <see cref="Length"/> (both fractions of the total). Colours come from the view's styles (DynamicResource).</summary>
public sealed class CurlTimingBar : Control
{
    public static readonly StyledProperty<double> StartProperty = AvaloniaProperty.Register<CurlTimingBar, double>(nameof(Start));
    public static readonly StyledProperty<double> LengthProperty = AvaloniaProperty.Register<CurlTimingBar, double>(nameof(Length));
    public static readonly StyledProperty<IBrush?> FillProperty = AvaloniaProperty.Register<CurlTimingBar, IBrush?>(nameof(Fill));
    public static readonly StyledProperty<IBrush?> TrackProperty = AvaloniaProperty.Register<CurlTimingBar, IBrush?>(nameof(Track));

    public double Start { get => GetValue(StartProperty); set => SetValue(StartProperty, value); }
    public double Length { get => GetValue(LengthProperty); set => SetValue(LengthProperty, value); }
    public IBrush? Fill { get => GetValue(FillProperty); set => SetValue(FillProperty, value); }
    public IBrush? Track { get => GetValue(TrackProperty); set => SetValue(TrackProperty, value); }

    static CurlTimingBar()
    {
        AffectsRender<CurlTimingBar>(StartProperty, LengthProperty, FillProperty, TrackProperty);
    }

    protected override Size MeasureOverride(Size availableSize) => new(double.IsInfinity(availableSize.Width) ? 100 : availableSize.Width, 8);

    public override void Render(DrawingContext ctx)
    {
        double w = Bounds.Width, h = Bounds.Height;
        if (w <= 0 || h <= 0) return;
        double barH = Math.Min(8, h);
        double y = (h - barH) / 2;
        if (Track is { } track) ctx.FillRectangle(track, new Rect(0, y, w, barH), 3);
        if (Fill is not { } fill) return;
        double x = Math.Clamp(Start, 0, 1) * w;
        double len = Math.Max(2, Math.Clamp(Length, 0, 1) * w);
        if (x + len > w) x = Math.Max(0, w - len);
        ctx.FillRectangle(fill, new Rect(x, y, len, barH), 3);
    }
}
