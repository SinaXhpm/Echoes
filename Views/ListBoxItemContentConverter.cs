using System;
using System.Globalization;
using Avalonia.Controls;
using Avalonia.Data.Converters;

namespace Echoes.Views;

/// <summary>
/// Returns the string Content of a selected ContentControl (e.g. the drawer's
/// selected ListBoxItem) — used to show the current tool name in the mobile app bar.
/// </summary>
public sealed class ListBoxItemContentConverter : IValueConverter
{
    public static readonly ListBoxItemContentConverter Instance = new();

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => (value as ContentControl)?.Content?.ToString() ?? "Echoes";

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
