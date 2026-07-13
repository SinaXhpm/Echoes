using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading.Tasks;
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
        // UI thread and swap in the finished collection on the UI thread. Guarded so a platform
        // that can't enumerate (or throws mid-build) leaves an empty list instead of crashing.
        try
        {
            var list = await Task.Run(BuildAdapters);
            Adapters = new ObservableCollection<NetworkAdapterInfo>(list);
        }
        catch
        {
            Adapters = new ObservableCollection<NetworkAdapterInfo>();
        }
    }

    [RelayCommand]
    private async Task CopyToClipboard(string text)
    {
        if (string.IsNullOrEmpty(text) || text == "—" || text == "---") return;
        // Route through the shared helper so copy works on Android too (no MainWindow there).
        await Helpers.ClipboardHelper.SetTextAsync(text);
    }

    private static List<NetworkAdapterInfo> BuildAdapters()
    {
        var result = new List<NetworkAdapterInfo>();
        NetworkInterface[] interfaces;
        try { interfaces = NetworkInterface.GetAllNetworkInterfaces(); }
        catch { return result; }   // whole enumeration can throw on Android / restricted platforms

        foreach (var ni in interfaces)
        {
            try
            {
                string v4 = "—", subnet = "—", ipv6 = "—", gw = "—", dns = "—", mac = "—";

                // IP addresses work on Android; the Gateway/DNS sub-properties do NOT (.NET-for-Android
                // throws PlatformNotSupportedException), so each is guarded separately and falls back to "—".
                try
                {
                    var props = ni.GetIPProperties();

                    var v4Info = props.UnicastAddresses
                        .FirstOrDefault(x => x.Address.AddressFamily == AddressFamily.InterNetwork);
                    if (v4Info != null) { v4 = v4Info.Address.ToString(); subnet = PrefixToMask(v4Info.PrefixLength); }

                    var v6Addrs = props.UnicastAddresses
                        .Where(x => x.Address.AddressFamily == AddressFamily.InterNetworkV6)
                        .Select(x => x.Address).ToList();
                    var v6 = v6Addrs.FirstOrDefault(a => !a.IsIPv6LinkLocal) ?? v6Addrs.FirstOrDefault();
                    if (v6 != null) ipv6 = v6.ToString();

                    try { gw = props.GatewayAddresses.FirstOrDefault()?.Address.ToString() ?? "—"; } catch { }
                    try
                    {
                        var dl = props.DnsAddresses.Select(d => d.ToString()).ToList();
                        if (dl.Count > 0) dns = string.Join(", ", dl);
                    }
                    catch { }
                }
                catch { /* GetIPProperties unsupported for this interface — keep name/type/status */ }

                // MAC: unavailable on Android 6+ (returns empty / 02:00:00:00:00:00 by OS privacy policy).
                try
                {
                    var m = ni.GetPhysicalAddress().ToString();
                    if (m.Length == 12) mac = string.Join(":", Enumerable.Range(0, 6).Select(i => m.Substring(i * 2, 2)));
                    else if (m.Length > 0) mac = m;
                }
                catch { }

                result.Add(new NetworkAdapterInfo
                {
                    Name = ni.Name,
                    Model = SafeGet(() => ni.Description, ni.Name),
                    Status = SafeGet(() => ni.OperationalStatus.ToString(), "Unknown"),
                    IsUp = SafeGet(() => ni.OperationalStatus == OperationalStatus.Up, false),
                    Type = FriendlyType(SafeGet(() => ni.NetworkInterfaceType, NetworkInterfaceType.Unknown)),
                    Speed = FormatSpeed(SafeSpeed(ni)),
                    IPv4 = v4,
                    IPv6 = ipv6,
                    Subnet = subnet,
                    Gateway = gw,
                    Dns = dns,
                    MacAddress = mac
                });
            }
            catch { /* skip an interface that fails to build entirely */ }
        }

        // Active (Up) adapters first, then alphabetically — the ones the user cares about on top.
        return result
            .OrderByDescending(a => a.IsUp)
            .ThenBy(a => a.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static T SafeGet<T>(Func<T> get, T fallback)
    {
        try { return get(); } catch { return fallback; }
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
