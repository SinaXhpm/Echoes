using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.LogicalTree;

namespace Echoes.Views.Controls;

/// <summary>
/// The desktop page header: the title block (first child) on the left and the page's tab strip (second child) on the
/// right, its bottom on the subtitle's line, which keeps it below the window's caption buttons on Windows. When the
/// strip doesn't fit beside the page title, it goes on a row of its own under the title. The subtitle gives way first
/// (it trims), the title never.
/// </summary>
public sealed class PageHeaderLayout : Panel
{
    private const double Gap = 16, RowGap = 8;
    private bool _stacked;

    protected override Size MeasureOverride(Size availableSize)
    {
        if (Children.Count < 2) return base.MeasureOverride(availableSize);
        Control title = Children[0], tabs = Children[1];
        double width = double.IsInfinity(availableSize.Width) ? 10000 : availableSize.Width;
        tabs.Measure(new Size(double.PositiveInfinity, availableSize.Height));
        double tabsWidth = tabs.IsVisible ? tabs.DesiredSize.Width : 0;
        _stacked = tabsWidth > 0 && width - tabsWidth - Gap < TitleWidth(title);
        if (_stacked)
        {
            title.Measure(new Size(width, availableSize.Height));
            tabs.Measure(new Size(width, availableSize.Height));
            return new Size(width, title.DesiredSize.Height + RowGap + tabs.DesiredSize.Height + 4);   // + room above the page
        }
        title.Measure(new Size(Math.Max(0, width - (tabsWidth > 0 ? tabsWidth + Gap : 0)), availableSize.Height));
        return new Size(width, Math.Max(title.DesiredSize.Height, tabsWidth > 0 ? tabs.DesiredSize.Height : 0));
    }

    protected override Size ArrangeOverride(Size finalSize)
    {
        if (Children.Count < 2) return base.ArrangeOverride(finalSize);
        Control title = Children[0], tabs = Children[1];
        if (_stacked)
        {
            title.Arrange(new Rect(0, 0, finalSize.Width, title.DesiredSize.Height));
            tabs.Arrange(new Rect(0, title.DesiredSize.Height + RowGap, finalSize.Width, tabs.DesiredSize.Height));
            return finalSize;
        }
        double tabsWidth = tabs.IsVisible ? Math.Min(tabs.DesiredSize.Width, finalSize.Width) : 0;
        title.Arrange(new Rect(0, 0, Math.Max(0, finalSize.Width - (tabsWidth > 0 ? tabsWidth + Gap : 0)), title.DesiredSize.Height));
        tabs.Arrange(new Rect(finalSize.Width - tabsWidth, finalSize.Height - tabs.DesiredSize.Height, tabsWidth, tabs.DesiredSize.Height));
        return finalSize;
    }

    // The page title's own width (the title block's first text): what must stay readable beside the strip.
    private static double TitleWidth(Control title)
    {
        foreach (var node in title.GetSelfAndLogicalDescendants())
            if (node is TextBlock t)
            {
                t.Measure(Size.Infinity);
                return t.DesiredSize.Width + 8;
            }
        return 120;
    }
}
