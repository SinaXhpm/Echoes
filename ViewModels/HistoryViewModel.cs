using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

public class HistoryGroup
{
    public string Title { get; set; } = string.Empty;
    public ObservableCollection<string> Items { get; set; } = new();
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

    // Friendly labels for the internal history keys.
    private static readonly Dictionary<string, string> Labels = new()
    {
        ["ping.host"] = "Ping · Host",
        ["dns.domain"] = "DNS · Domain",
        ["curl.url"] = "cURL · URL",
        ["curl.proxy"] = "cURL · Proxy",
        ["ip.target"] = "IP Info · Target",
        ["ip.proxy"] = "IP Info · Proxy",
        ["portscan.target"] = "Scanner · Targets",
        ["portscan.ports"] = "Scanner · Ports",
        ["ssh.host"] = "SSH · Host",
        ["ssh.user"] = "SSH · User",
        ["tg.proxy"] = "Telegram · Proxy",
        ["cf.proxy"] = "Cloudflare · Proxy",
        ["monitor.addresses"] = "Monitor · Addresses",
    };

    public HistoryViewModel() => Reload();

    [RelayCommand]
    public void Reload()
    {
        var groups = new ObservableCollection<HistoryGroup>();
        int total = 0;

        foreach (var entry in ProfileService.Instance.AllHistory()
                     .OrderBy(kv => Labels.TryGetValue(kv.Key, out var l) ? l : kv.Key,
                              System.StringComparer.OrdinalIgnoreCase))
        {
            var g = new HistoryGroup
            {
                Title = Labels.TryGetValue(entry.Key, out var lbl) ? lbl : entry.Key,
                Items = new ObservableCollection<string>(entry.Values)
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
