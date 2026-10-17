using Avalonia;
using Avalonia.Controls;

namespace Echoes.Views.Controls;

/// <summary>
/// Takes whatever height it is arranged with but asks for none. The desktop window opens sized to its content's height
/// (SizeToContent, see MainWindow); wrapped around the page area, the open tool doesn't count, so the window opens
/// exactly as tall as the sidebar's nav list, whichever tool is showing.
/// </summary>
public sealed class HeightNeutral : Decorator
{
    protected override Size MeasureOverride(Size availableSize)
        => base.MeasureOverride(availableSize).WithHeight(0);
}
