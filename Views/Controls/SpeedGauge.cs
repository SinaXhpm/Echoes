using System;
using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Media;

namespace Echoes.Views.Controls;

/// <summary>
/// A speedometer for the speed test: a 240° track with the value's arc over it and a knob at its end, the scale's marks
/// inside (0, 5, 10, 25, 50, 100, 250, 500, 1000 Mbps — equal steps, so 8 Mbps and 800 Mbps both read clearly; ×10 for
/// a <see cref="Maximum"/> of 10000). The number itself is laid over it in XAML. Drawn straight into the context and
/// redrawn only when a property changes (the view-model sets the value a few times a second) — no animation. Colors
/// come from the design tokens through styles.
/// </summary>
public sealed class SpeedGauge : Control
{
    public static readonly StyledProperty<double> ValueProperty =
        AvaloniaProperty.Register<SpeedGauge, double>(nameof(Value));
    public static readonly StyledProperty<double> MaximumProperty =
        AvaloniaProperty.Register<SpeedGauge, double>(nameof(Maximum), 1000);
    public static readonly StyledProperty<IBrush?> TrackBrushProperty =
        AvaloniaProperty.Register<SpeedGauge, IBrush?>(nameof(TrackBrush));
    public static readonly StyledProperty<IBrush?> ValueBrushProperty =
        AvaloniaProperty.Register<SpeedGauge, IBrush?>(nameof(ValueBrush));
    public static readonly StyledProperty<IBrush?> KnobBrushProperty =
        AvaloniaProperty.Register<SpeedGauge, IBrush?>(nameof(KnobBrush));
    public static readonly StyledProperty<IBrush?> LabelBrushProperty =
        AvaloniaProperty.Register<SpeedGauge, IBrush?>(nameof(LabelBrush));
    public static readonly StyledProperty<double> ThicknessProperty =
        AvaloniaProperty.Register<SpeedGauge, double>(nameof(Thickness), 10);
    public static readonly StyledProperty<double> LabelSizeProperty =
        AvaloniaProperty.Register<SpeedGauge, double>(nameof(LabelSize), 10);

    private const double StartAngle = 150, Sweep = 240;
    private static readonly double[] Marks = { 0, 5, 10, 25, 50, 100, 250, 500, 1000 };

    private FormattedText[]? _labels;
    private IPen? _trackPen, _valuePen;

    static SpeedGauge()
    {
        AffectsRender<SpeedGauge>(ValueProperty, MaximumProperty, TrackBrushProperty, ValueBrushProperty, KnobBrushProperty,
            LabelBrushProperty, ThicknessProperty, LabelSizeProperty);
    }

    public double Value { get => GetValue(ValueProperty); set => SetValue(ValueProperty, value); }
    public double Maximum { get => GetValue(MaximumProperty); set => SetValue(MaximumProperty, value); }
    public IBrush? TrackBrush { get => GetValue(TrackBrushProperty); set => SetValue(TrackBrushProperty, value); }
    public IBrush? ValueBrush { get => GetValue(ValueBrushProperty); set => SetValue(ValueBrushProperty, value); }
    public IBrush? KnobBrush { get => GetValue(KnobBrushProperty); set => SetValue(KnobBrushProperty, value); }
    public IBrush? LabelBrush { get => GetValue(LabelBrushProperty); set => SetValue(LabelBrushProperty, value); }
    public double Thickness { get => GetValue(ThicknessProperty); set => SetValue(ThicknessProperty, value); }
    public double LabelSize { get => GetValue(LabelSizeProperty); set => SetValue(LabelSizeProperty, value); }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == MaximumProperty || change.Property == LabelBrushProperty || change.Property == LabelSizeProperty
            || change.Property == TextElement.FontFamilyProperty)
            _labels = null;
        if (change.Property == TrackBrushProperty || change.Property == ThicknessProperty) _trackPen = null;
        if (change.Property == ValueBrushProperty || change.Property == ThicknessProperty) _valuePen = null;
    }

    /// <summary>Where <paramref name="value"/> sits on the scale, 0..1 (equal steps between the marks).</summary>
    public static double Fraction(double value, double maximum)
    {
        if (double.IsNaN(value) || value <= 0) return 0;
        double scale = maximum > 0 ? maximum / 1000 : 1;
        for (int i = 1; i < Marks.Length; i++)
        {
            double lo = Marks[i - 1] * scale, hi = Marks[i] * scale;
            if (value <= hi) return (i - 1 + (value - lo) / (hi - lo)) / (Marks.Length - 1);
        }
        return 1;
    }

    public override void Render(DrawingContext context)
    {
        double w = Bounds.Width, h = Bounds.Height;
        double t = Math.Max(2, Thickness);
        if (w < 4 * t || h < 4 * t) return;

        // The arc reaches r above the center and r·sin 30° below it: 1.5 r in all (plus the stroke).
        double r = Math.Min((w - t) / 2, (h - t) / 1.5);
        var center = new Point(w / 2, t / 2 + r);

        _trackPen ??= TrackBrush is { } tb ? new Pen(tb, t, null, PenLineCap.Round) : null;
        if (_trackPen is not null) context.DrawGeometry(null, _trackPen, Arc(center, r, StartAngle, Sweep));

        double f = Fraction(Value, Maximum);
        if (f > 0.0005)
        {
            _valuePen ??= ValueBrush is { } vb ? new Pen(vb, t, null, PenLineCap.Round) : null;
            if (_valuePen is not null) context.DrawGeometry(null, _valuePen, Arc(center, r, StartAngle, Sweep * f));
            var knob = At(center, r, StartAngle + Sweep * f);
            if (ValueBrush is { } kb) context.DrawEllipse(kb, null, knob, t * 0.85, t * 0.85);
            if (KnobBrush is { } inner) context.DrawEllipse(inner, null, knob, t * 0.35, t * 0.35);
        }

        // the scale's marks, inside the track
        if (LabelBrush is not { } labelBrush) return;
        _labels ??= BuildLabels(labelBrush);
        double labelRadius = r - t / 2 - 5;
        for (int i = 0; i < _labels.Length; i++)
        {
            var text = _labels[i];
            double angle = StartAngle + Sweep * i / (Marks.Length - 1);
            // push each label in by half its extent along the radius, so it sits just inside the arc
            double rad = angle * Math.PI / 180;
            double inset = Math.Abs(Math.Cos(rad)) * text.Width / 2 + Math.Abs(Math.Sin(rad)) * text.Height / 2;
            var p = At(center, labelRadius - inset, angle);
            context.DrawText(text, new Point(Math.Round(p.X - text.Width / 2), Math.Round(p.Y - text.Height / 2)));
        }
    }

    private FormattedText[] BuildLabels(IBrush brush)
    {
        var typeface = new Typeface(GetValue(TextElement.FontFamilyProperty));
        double scale = Maximum > 0 ? Maximum / 1000 : 1;
        var labels = new FormattedText[Marks.Length];
        for (int i = 0; i < Marks.Length; i++)
            labels[i] = new FormattedText(Label(Marks[i] * scale), CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
                                          typeface, Math.Max(6, LabelSize), brush);
        return labels;

        static string Label(double v) => v >= 1000 ? (v / 1000).ToString("0.#", CultureInfo.InvariantCulture) + "k" : v.ToString("0", CultureInfo.InvariantCulture);
    }

    private static Point At(Point c, double r, double degrees)
    {
        double rad = degrees * Math.PI / 180;
        return new Point(c.X + r * Math.Cos(rad), c.Y + r * Math.Sin(rad));
    }

    private static StreamGeometry Arc(Point c, double r, double start, double sweep)
    {
        var g = new StreamGeometry();
        using var ctx = g.Open();
        ctx.BeginFigure(At(c, r, start), false);
        // ArcTo can't draw a full circle in one segment; the gauge never sweeps more than 240°.
        ctx.ArcTo(At(c, r, start + sweep), new Size(r, r), 0, sweep > 180, SweepDirection.Clockwise);
        ctx.EndFigure(false);
        return g;
    }
}
