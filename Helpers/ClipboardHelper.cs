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
        var clipboard = (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)
            ?.MainWindow?.Clipboard;
        if (clipboard != null) await clipboard.SetTextAsync(text);
    }
}
