using System;
using Avalonia;
using Avalonia.Controls;

namespace Echoes.Views.Controls;

/// <summary>
/// The page metadata both shells show for a tool: the sidebar / drawer section it starts
/// (<see cref="Group"/>, e.g. "Diagnose"), and the page header's <see cref="Title"/> and
/// <see cref="Subtitle"/>. One declaration per tool drives the nav grouping and the header.
/// </summary>
public interface INavInfo
{
    string? Group { get; }
    string? Title { get; }
    string? Subtitle { get; }
}

/// <summary>Desktop sidebar entry: a TabItem (lazy tool host, see ToolViews) plus page metadata.</summary>
public class NavTabItem : TabItem, INavInfo
{
    public static readonly StyledProperty<string?> GroupProperty =
        AvaloniaProperty.Register<NavTabItem, string?>(nameof(Group));
    public static readonly StyledProperty<string?> TitleProperty =
        AvaloniaProperty.Register<NavTabItem, string?>(nameof(Title));
    public static readonly StyledProperty<string?> SubtitleProperty =
        AvaloniaProperty.Register<NavTabItem, string?>(nameof(Subtitle));

    public string? Group { get => GetValue(GroupProperty); set => SetValue(GroupProperty, value); }
    public string? Title { get => GetValue(TitleProperty); set => SetValue(TitleProperty, value); }
    public string? Subtitle { get => GetValue(SubtitleProperty); set => SetValue(SubtitleProperty, value); }

    // Styled (and themed) as a plain TabItem: selectors like "TabItem.navtab" match it.
    protected override Type StyleKeyOverride => typeof(TabItem);
}

/// <summary>Mobile drawer entry: a ListBoxItem (index-coupled to the page Carousel) plus page metadata.</summary>
public class NavListItem : ListBoxItem, INavInfo
{
    public static readonly StyledProperty<string?> GroupProperty =
        AvaloniaProperty.Register<NavListItem, string?>(nameof(Group));
    public static readonly StyledProperty<string?> TitleProperty =
        AvaloniaProperty.Register<NavListItem, string?>(nameof(Title));
    public static readonly StyledProperty<string?> SubtitleProperty =
        AvaloniaProperty.Register<NavListItem, string?>(nameof(Subtitle));

    public string? Group { get => GetValue(GroupProperty); set => SetValue(GroupProperty, value); }
    public string? Title { get => GetValue(TitleProperty); set => SetValue(TitleProperty, value); }
    public string? Subtitle { get => GetValue(SubtitleProperty); set => SetValue(SubtitleProperty, value); }

    protected override Type StyleKeyOverride => typeof(ListBoxItem);
}
