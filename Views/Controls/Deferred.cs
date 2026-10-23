using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Templates;
using Avalonia.Metadata;

namespace Echoes.Views.Controls;

/// <summary>
/// Builds its content from its template the first time it is laid out, which is the first time it is shown (an unselected
/// tab's content, a closed panel and a hidden page are never measured), and keeps it from then on, so a tab keeps its scroll
/// position, selection and focus like inline content. A tool used to build every tab and panel it has the moment it was
/// opened (a page of 900 controls with their styles and live bindings, most never looked at: ~120 MB managed with every
/// tool opened once).
/// <code>&lt;ctl:Deferred&gt;&lt;DataTemplate x:DataType="vm:…"&gt; the content &lt;/DataTemplate&gt;&lt;/ctl:Deferred&gt;</code>
/// The content inherits the DataContext. Names inside the template are in its own scope: code-behind finds those controls
/// through events (sender) or after the content exists, not through generated fields.
/// </summary>
public sealed class Deferred : Control
{
    private Control? _child;

    [Content]
    public IDataTemplate? Template { get; set; }

    /// <summary>The content once built (null until first shown).</summary>
    public Control? Child => _child;

    protected override Size MeasureOverride(Size availableSize)
    {
        if (_child is null && Template is { } template && template.Build(DataContext) is { } built)
        {
            _child = built;
            LogicalChildren.Add(built);
            VisualChildren.Add(built);
        }
        if (_child is null) return default;
        _child.Measure(availableSize);
        return _child.DesiredSize;
    }

    protected override Size ArrangeOverride(Size finalSize)
    {
        _child?.Arrange(new Rect(finalSize));
        return finalSize;
    }
}
