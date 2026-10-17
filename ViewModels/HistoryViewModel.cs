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
}

public class HistoryGroup
{
    public string Title { get; set; } = string.Empty;
    public IReadOnlyList<HistoryEntry> Items { get; set; } = new List<HistoryEntry>();
    public int Count => Items.Count;
}

/// <summary>
/// Read-only view over the input history that <see cref="ProfileService"/> already records for
/// every tool (the same data that powers each tab's suggestion dropdowns), grouped per tool.
/// </summary>
public partial class HistoryViewModel : ObservableObject
{
    [ObservableProperty] private ObservableCollection<HistoryGroup> _groups = new();
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

        var groups = new ObservableCollection<HistoryGroup>();
        int total = 0;

        foreach (var entry in ProfileService.Instance.AllHistory()
                     .OrderBy(kv => LabelFor(kv.Key), System.StringComparer.OrdinalIgnoreCase))
        {
            var g = new HistoryGroup
            {
                Title = LabelFor(entry.Key),
                Items = entry.Values.Select(v => new HistoryEntry(v)).ToList()
            };
            total += g.Items.Count;
            groups.Add(g);
        }

        Groups = groups;
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
