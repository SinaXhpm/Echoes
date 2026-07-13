using Avalonia.Data.Converters;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using System;
using System.Collections.Generic;
using System.Globalization;

namespace Echoes.Helpers;

/// <summary>
/// Turns a two-letter ISO country code into its bundled flag bitmap
/// (avares://Echoes/Assets/flags/{cc}.png). Real images are used instead of flag emoji because
/// Windows has no flag-emoji glyphs — it renders the regional-indicator pair as bare letters.
/// Results are cached; an unknown code returns null (the view shows a globe fallback).
/// </summary>
public sealed class CountryFlagConverter : IValueConverter
{
    public static readonly CountryFlagConverter Instance = new();
    private static readonly Dictionary<string, Bitmap?> _cache = new();

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        string cc = (value as string ?? "").Trim().ToLowerInvariant();
        if (cc.Length != 2) return null;

        if (_cache.TryGetValue(cc, out var cached)) return cached;

        Bitmap? bmp = null;
        try
        {
            var uri = new Uri($"avares://Echoes/Assets/flags/{cc}.png");
            if (AssetLoader.Exists(uri))
                using (var s = AssetLoader.Open(uri))
                    bmp = new Bitmap(s);
        }
        catch { bmp = null; }

        _cache[cc] = bmp;
        return bmp;
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
