using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Input.Platform;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Echoes.ViewModels;

public class NetworkAdapterInfo
{
    public string Name { get; set; } = string.Empty;
    public string Model { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public bool IsUp { get; set; }
    public string Type { get; set; } = string.Empty;
    public string Speed { get; set; } = "—";
    public string IPv4 { get; set; } = "—";
    public string IPv6 { get; set; } = "—";
    public string Subnet { get; set; } = "—";
    public string MacAddress { get; set; } = "—";
    public string Gateway { get; set; } = "—";
    public string Dns { get; set; } = "—";

    // Formatted block used by the per-card "copy all" button.
    public string Summary =>
        $"{Name} ({Model})\n" +
        $"Type: {Type}   Status: {Status}   Speed: {Speed}\n" +
        $"IPv4: {IPv4}   Subnet: {Subnet}\n" +
        $"IPv6: {IPv6}\n" +
        $"MAC: {MacAddress}   Gateway: {Gateway}\n" +
        $"DNS: {Dns}";
}

public partial class NetworkInfoViewModel : ObservableObject
{
    [ObservableProperty]
    private ObservableCollection<NetworkAdapterInfo> _adapters = new();

    public NetworkInfoViewModel()
    {
        _ = RefreshAsync();
    }

    [RelayCommand]
    private async Task Refresh() => await RefreshAsync();

    private async Task RefreshAsync()
    {
        // Adapter enumeration hits blocking OS/driver calls (speed, DNS list) — do it off the
        // UI thread and swap in the finished collection on the UI thread.
        var list = await Task.Run(BuildAdapters);
        Adapters = new ObservableCollection<NetworkAdapterInfo>(list);
    }

    [RelayCommand]
    private async Task CopyToClipboard(string text)
    {
        if (string.IsNullOrEmpty(text) || text == "—" || text == "---") return;

        var clipboard = Avalonia.Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop
                        ? desktop.MainWindow?.Clipboard
                        : null;

        if (clipboard != null)
        {
            await clipboard.SetTextAsync(text);
        }
    }

    private static List<NetworkAdapterInfo> BuildAdapters()
    {
        var result = new List<NetworkAdapterInfo>();
        var interfaces = NetworkInterface.GetAllNetworkInterfaces();

        foreach (var ni in interfaces)
        {
            var props = ni.GetIPProperties();

            var v4Info = props.UnicastAddresses
                .FirstOrDefault(x => x.Address.AddressFamily == AddressFamily.InterNetwork);
            string v4 = v4Info?.Address.ToString() ?? "—";
            string subnet = v4Info != null ? PrefixToMask(v4Info.PrefixLength) : "—";

            // Prefer a routable IPv6 (not link-local fe80::) but fall back to whatever exists.
            var v6Addrs = props.UnicastAddresses
                .Where(x => x.Address.AddressFamily == AddressFamily.InterNetworkV6)
                .Select(x => x.Address).ToList();
            var v6 = v6Addrs.FirstOrDefault(a => !a.IsIPv6LinkLocal) ?? v6Addrs.FirstOrDefault();
            string ipv6 = v6?.ToString() ?? "—";

            string gw = props.GatewayAddresses.FirstOrDefault()?.Address.ToString() ?? "—";

            var dnsList = props.DnsAddresses.Select(d => d.ToString()).ToList();
            string dns = dnsList.Count > 0 ? string.Join(", ", dnsList) : "—";

            var mac = ni.GetPhysicalAddress().ToString();
            mac = mac.Length == 12
                ? string.Join(":", Enumerable.Range(0, 6).Select(i => mac.Substring(i * 2, 2)))
                : (mac.Length == 0 ? "—" : mac);

            result.Add(new NetworkAdapterInfo
            {
                Name = ni.Name,
                Model = ni.Description,
                Status = ni.OperationalStatus.ToString(),
                IsUp = ni.OperationalStatus == OperationalStatus.Up,
                Type = FriendlyType(ni.NetworkInterfaceType),
                Speed = FormatSpeed(SafeSpeed(ni)),
                IPv4 = v4,
                IPv6 = ipv6,
                Subnet = subnet,
                Gateway = gw,
                Dns = dns,
                MacAddress = mac
            });
        }

        // Active (Up) adapters first, then alphabetically — the ones the user cares about on top.
        return result
            .OrderByDescending(a => a.IsUp)
            .ThenBy(a => a.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static long SafeSpeed(NetworkInterface ni)
    {
        try { return ni.Speed; } catch { return -1; }
    }

    private static string FormatSpeed(long bps)
    {
        if (bps <= 0) return "—";
        if (bps >= 1_000_000_000) return $"{bps / 1_000_000_000.0:0.#} Gbps";
        if (bps >= 1_000_000) return $"{bps / 1_000_000.0:0.#} Mbps";
        if (bps >= 1_000) return $"{bps / 1_000.0:0.#} Kbps";
        return $"{bps} bps";
    }

    private static string FriendlyType(NetworkInterfaceType t) => t switch
    {
        NetworkInterfaceType.Ethernet => "Ethernet",
        NetworkInterfaceType.Wireless80211 => "Wi-Fi",
        NetworkInterfaceType.Loopback => "Loopback",
        NetworkInterfaceType.Tunnel => "Tunnel",
        NetworkInterfaceType.Ppp => "PPP",
        NetworkInterfaceType.GigabitEthernet => "Ethernet (Gb)",
        _ => t.ToString()
    };

    private static string PrefixToMask(int prefix)
    {
        if (prefix < 0 || prefix > 32) return "—";
        uint mask = prefix == 0 ? 0u : 0xffffffffu << (32 - prefix);
        return $"{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff} (/{prefix})";
    }
}
