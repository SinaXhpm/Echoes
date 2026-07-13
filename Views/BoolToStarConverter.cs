using System;
using System.Globalization;
using Avalonia.Controls;
using Avalonia.Data.Converters;

namespace Echoes.Views;

/// <summary>
/// true → a 1* grid column, false → a 0-width column. Used to collapse the Monitor STATUS
/// columns (PING / TCP / HTTP) when their check is turned off, keeping header + rows aligned.
/// </summary>
public sealed class BoolToStarConverter : IValueConverter
{
    public static readonly BoolToStarConverter Instance = new();
    private static readonly GridLength Star = new(1, GridUnitType.Star);
    private static readonly GridLength Zero = new(0, GridUnitType.Pixel);

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is true ? Star : Zero;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
