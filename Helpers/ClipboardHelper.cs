using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Input.Platform;

namespace Echoes.Helpers;

public static class ClipboardHelper
{
    public static async Task SetTextAsync(string? text)
    {
        if (string.IsNullOrEmpty(text)) return;
        var clipboard = Clipboard();
        if (clipboard != null) await clipboard.SetTextAsync(text);
    }

    // Read the clipboard's text (Avalonia 12 exposes this as the TryGetTextAsync extension).
    public static async Task<string?> GetTextAsync()
    {
        var clipboard = Clipboard();
        if (clipboard == null) return null;
        return await clipboard.TryGetTextAsync();
    }

    private static IClipboard? Clipboard()
        => (Avalonia.Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)
            ?.MainWindow?.Clipboard;
}
