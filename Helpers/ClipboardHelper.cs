using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
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

    // Resolve the clipboard for whichever lifetime is active. Desktop exposes it on MainWindow;
    // Android / single-view has no MainWindow, so pull the TopLevel from MainView instead —
    // otherwise every copy/paste silently no-ops on the mobile head.
    private static IClipboard? Clipboard()
        => Avalonia.Application.Current?.ApplicationLifetime switch
        {
            IClassicDesktopStyleApplicationLifetime desktop => desktop.MainWindow?.Clipboard,
            ISingleViewApplicationLifetime single => TopLevel.GetTopLevel(single.MainView)?.Clipboard,
            _ => null,
        };
}
