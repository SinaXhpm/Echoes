using System;
using System.Globalization;
using Avalonia.Controls;
using Avalonia.Data.Converters;

namespace Echoes.Views;

/// <summary>
/// Returns the tool name of a selected ContentControl (e.g. the drawer's selected ListBoxItem) —
/// used to show the current tool name in the mobile app bar. Prefers Tag, because the drawer items
/// carry an icon + label panel as their Content rather than a bare string.
/// </summary>
public sealed class ListBoxItemContentConverter : IValueConverter
{
    public static readonly ListBoxItemContentConverter Instance = new();

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is not Control c ? "Echoes"
           : c.Tag as string ?? (c as ContentControl)?.Content as string ?? "Echoes";

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
