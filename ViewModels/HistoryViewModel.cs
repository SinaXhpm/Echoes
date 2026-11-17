using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

/// <summary>One history entry: the list shows a shortened <see cref="Display"/>, COPY copies the full <see cref="Value"/>.</summary>
public sealed class HistoryEntry
{
    private const int MaxDisplayChars = 300;   // a pasted target list stays a few lines instead of a wall of text

    public HistoryEntry(string value)
    {
        Value = value;
        if (value.Length <= MaxDisplayChars) Display = value;
        else
        {
            int cut = char.IsHighSurrogate(value[MaxDisplayChars - 1]) ? MaxDisplayChars - 1 : MaxDisplayChars;
            Display = value[..cut] + $"… (+{value.Length - cut} chars)";
        }
    }

    public string Value { get; }
    public string Display { get; }

    /// <summary>The last value of its tool field: its row closes the card (rounded bottom, the gap after it).</summary>
    public bool IsLast { get; init; }

    /// <summary>Copies <see cref="Value"/> (the page's command, handed to each row: no lookup up the tree per row).</summary>
    public System.Windows.Input.ICommand? Copy { get; init; }
}

/// <summary>A tool field's header in the history list: the top of its card.</summary>
public sealed class HistoryHeader(string title, int count)
{
    public string Title { get; } = title;
    public int Count { get; } = count;
}

/// <summary>
/// Read-only view over the input history that <see cref="ProfileService"/> already records for
/// every tool (the same data that powers each tab's suggestion dropdowns), grouped per tool.
/// </summary>
public partial class HistoryViewModel : ObservableObject
{
    /// <summary>One flat list for the view: each tool field's <see cref="HistoryHeader"/>, then its values
    /// (<see cref="HistoryEntry"/>). Flat so that only the lines on screen are built: as cards holding a list of their
    /// values, every card that scrolled into view built all its rows (up to 50 values of selectable text and a button),
    /// and a long history scrolled at ~15 frames a second.</summary>
    [ObservableProperty] private IReadOnlyList<object> _lines = System.Array.Empty<object>();
    [ObservableProperty] private int _totalCount;

    public bool HasItems => TotalCount > 0;
    partial void OnTotalCountChanged(int value) => OnPropertyChanged(nameof(HasItems));

    // HistoryService.Version the shown groups were built from (-1: never built).
    private long _shownVersion = -1;

    // Friendly labels for the internal history keys.
    private static readonly Dictionary<string, string> Labels = new()
    {
        ["ping.host"] = "Ping · Host",
        ["dns.domain"] = "DNS · Domain",
        ["curl.url"] = "cURL · URL",
        ["curl.proxy"] = "cURL · Proxy",
        ["ip.target"] = "IP Info · Target",
        ["ip.proxy"] = "IP Info · Proxy",
        ["checkhost.host"] = "Check-Host · Host",
        ["portscan.target"] = "Scanner · Targets",
        ["portscan.ports"] = "Scanner · Ports",
        ["ssh.host"] = "SSH · Host",
        ["ssh.user"] = "SSH · User",
        ["tg.proxy"] = "Telegram · Proxy",
        ["cf.proxy"] = "Cloudflare · Proxy",
        ["monitor.addresses"] = "Monitor · Addresses",
        ["doctor"] = "Doctor · Site",
        ["tls.target"] = "TLS · Target",
        ["socket.target"] = "Socket · Target",
        ["socket.ws"] = "Socket · WebSocket URL",
    };

    // A key without a label above (a tool added later): "speed.server" → "Speed · Server", never the raw key.
    private static string LabelFor(string key)
    {
        if (Labels.TryGetValue(key, out var label)) return label;
        var parts = key.Split('.', System.StringSplitOptions.RemoveEmptyEntries)
                       .Select(p => p.Length == 0 ? p : char.ToUpperInvariant(p[0]) + p[1..]);
        return string.Join(" · ", parts);
    }

    public HistoryViewModel() => Reload();

    // The DATA tab calls this on every visit (and REFRESH): rebuild only when the history changed since last time.
    [RelayCommand]
    public void Reload()
    {
        // Read BEFORE the snapshot: a change racing it bumps the version past this one, so the next call rebuilds.
        long version = HistoryService.Instance.Version;
        if (version == _shownVersion) return;
        _shownVersion = version;

        var lines = new List<object>();
        int total = 0;

        foreach (var entry in ProfileService.Instance.AllHistory()
                     .OrderBy(kv => LabelFor(kv.Key), System.StringComparer.OrdinalIgnoreCase))
        {
            var values = entry.Values;
            lines.Add(new HistoryHeader(LabelFor(entry.Key), values.Count));
            for (int i = 0; i < values.Count; i++)
                lines.Add(new HistoryEntry(values[i]) { IsLast = i == values.Count - 1, Copy = CopyCommand });
            total += values.Count;
        }

        Lines = lines;
        TotalCount = total;
    }

    [RelayCommand]
    private async Task Copy(string? value)
    {
        if (!string.IsNullOrEmpty(value)) await ClipboardHelper.SetTextAsync(value);
    }

    [RelayCommand]
    private void ClearAll()
    {
        ProfileService.Instance.ClearAllHistory();
        Reload();
    }
}
