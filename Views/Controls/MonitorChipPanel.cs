using System;
using System.Collections.Generic;
using Avalonia;
using Avalonia.Controls;

namespace Echoes.Views.Controls;

/// <summary>
/// Lays its children (the per-check result chips of a monitor row) out in one line and never shows one cut in half:
/// a chip that doesn't fit is left out entirely. Chips carrying <see cref="PriorityClass"/> (failures) are kept
/// first, so a narrow row drops "Ping · 9 ms" before it drops the red "TCP 443 · refused"; the shown chips stay in
/// their original order, so columns read the same on every row.
/// </summary>
public sealed class MonitorChipPanel : Panel
{
    public static readonly StyledProperty<double> SpacingProperty =
        AvaloniaProperty.Register<MonitorChipPanel, double>(nameof(Spacing), 4);

    public static readonly StyledProperty<string?> PriorityClassProperty =
        AvaloniaProperty.Register<MonitorChipPanel, string?>(nameof(PriorityClass), "fail");

    // Children picked by the current arrange (reused list: no allocation per layout pass).
    private readonly List<Control> _shown = new(4);

    static MonitorChipPanel()
    {
        AffectsMeasure<MonitorChipPanel>(SpacingProperty, PriorityClassProperty);
        ClipToBoundsProperty.OverrideDefaultValue<MonitorChipPanel>(true);
    }

    public double Spacing { get => GetValue(SpacingProperty); set => SetValue(SpacingProperty, value); }
    public string? PriorityClass { get => GetValue(PriorityClassProperty); set => SetValue(PriorityClassProperty, value); }

    protected override Size MeasureOverride(Size availableSize)
    {
        double width = 0, height = 0;
        bool first = true;
        foreach (var child in Children)
        {
            if (!child.IsVisible) continue;
            child.Measure(new Size(double.PositiveInfinity, availableSize.Height));
            width += (first ? 0 : Spacing) + child.DesiredSize.Width;
            height = Math.Max(height, child.DesiredSize.Height);
            first = false;
        }
        // Never asks for more than it has: whatever doesn't fit is dropped in ArrangeOverride.
        return new Size(double.IsInfinity(availableSize.Width) ? width : Math.Min(width, availableSize.Width), height);
    }

    protected override Size ArrangeOverride(Size finalSize)
    {
        double spacing = Spacing, budget = finalSize.Width, used = 0;
        string? priority = PriorityClass;
        _shown.Clear();

        // Pick: priority chips first, then the others — each only if it fits whole.
        for (int pass = 0; pass < 2; pass++)
        {
            foreach (var child in Children)
            {
                if (!child.IsVisible) continue;
                bool isPriority = priority is not null && child.Classes.Contains(priority);
                if (isPriority != (pass == 0)) continue;
                double need = child.DesiredSize.Width + (_shown.Count == 0 ? 0 : spacing);
                if (used + need > budget + 0.5) continue;
                used += need;
                _shown.Add(child);
            }
        }

        // Place the picked ones in document order; the rest outside the (clipped) bounds.
        double x = 0;
        foreach (var child in Children)
        {
            if (!child.IsVisible) continue;
            var size = child.DesiredSize;
            if (_shown.Contains(child))
            {
                child.Arrange(new Rect(x, Math.Max(0, (finalSize.Height - size.Height) / 2), size.Width, size.Height));
                x += size.Width + spacing;
            }
            else
            {
                child.Arrange(new Rect(finalSize.Width + 1000, 0, size.Width, size.Height));
            }
        }
        return finalSize;
    }
}
