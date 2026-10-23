using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

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

    // --- Ports (listening + active connections) ---
    [ObservableProperty] private ObservableCollection<PortEntry> _ports = new();
    [ObservableProperty] private bool _portsHasRows;
    [ObservableProperty] private string _portsNote = string.Empty;

    // --- Neighbors (ARP cache) ---
    [ObservableProperty] private ObservableCollection<Neighbor> _neighbors = new();
    [ObservableProperty] private bool _neighborsHasRows;
    [ObservableProperty] private string _neighborsNote = string.Empty;

    // --- Routing table ---
    [ObservableProperty] private ObservableCollection<RouteEntry> _routes = new();
    [ObservableProperty] private bool _routesHasRows;
    [ObservableProperty] private string _routesNote = string.Empty;

    /// <summary>The sub-tab shown (0 Interfaces · 1 Wi-Fi · 2 Neighbors · 3 Ports · 4 Routing): the one used last, unless
    /// this platform doesn't show it.</summary>
    [ObservableProperty] private int _tabIndex = ShownTab(ProfileService.Instance.GetInt(TabKey, 0));
    private const string TabKey = "net.tab";

    partial void OnTabIndexChanged(int value)
    {
        if (value >= 0 && ProfileService.Instance.GetInt(TabKey, 0) != value)
            ProfileService.Instance.SetSetting(TabKey, value.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    // The tabs this platform can fill: a tab that could only say "not available" isn't shown. Phones keep the Wi-Fi scan,
    // ARP, socket and routing tables from apps, so they show Interfaces alone (and no tab strip for it); macOS has no
    // Wi-Fi, ARP or routing reader here.
    public bool ShowWifiTab => WifiScanner.IsAvailable;
    public bool ShowNeighborsTab => NetTables.CanReadNeighbors;
    public bool ShowPortsTab => NetTables.CanReadPorts;
    public bool ShowRoutesTab => NetTables.CanReadRoutes;
    public bool ShowTabStrip => ShowWifiTab || ShowNeighborsTab || ShowPortsTab || ShowRoutesTab;

    private static int ShownTab(int index) => index switch
    {
        1 when WifiScanner.IsAvailable => 1,
        2 when NetTables.CanReadNeighbors => 2,
        3 when NetTables.CanReadPorts => 3,
        4 when NetTables.CanReadRoutes => 4,
        _ => 0,
    };

    /// <summary>Android / iOS: the fields the OS keeps from apps (every card shows "—" for them), said once.</summary>
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasHiddenFieldsNote))] private string _hiddenFieldsNote = string.Empty;
    public bool HasHiddenFieldsNote => HiddenFieldsNote.Length > 0;

    public NetworkInfoViewModel()
    {
        RestoreWifiSort();
        _ = RefreshAsync();
        if (ShowPortsTab) _ = RefreshPorts();
        if (ShowNeighborsTab) _ = RefreshNeighbors();
        if (ShowRoutesTab) _ = RefreshRoutes();
    }

    [RelayCommand]
    private async Task Refresh() => await RefreshAsync();

    [RelayCommand]
    private async Task RefreshPorts()
    {
        var r = await Task.Run(NetTables.GetPorts);
        Ports = new ObservableCollection<PortEntry>(r.Rows);
        PortsHasRows = r.Supported && r.Rows.Count > 0;
        PortsNote = !r.Supported ? (r.Note ?? "Not available on this platform.") : "No open ports found.";
    }

    [RelayCommand]
    private async Task RefreshNeighbors()
    {
        var r = await Task.Run(NetTables.GetNeighbors);
        Neighbors = new ObservableCollection<Neighbor>(r.Rows);
        NeighborsHasRows = r.Supported && r.Rows.Count > 0;
        NeighborsNote = !r.Supported
            ? (r.Note ?? "Not available on this platform.")
            : "No neighbors in the ARP cache yet — ping a device on your LAN, then refresh.";
    }

    [RelayCommand]
    private async Task RefreshRoutes()
    {
        var r = await Task.Run(NetTables.GetRoutes);
        Routes = new ObservableCollection<RouteEntry>(r.Rows);
        RoutesHasRows = r.Supported && r.Rows.Count > 0;
        RoutesNote = !r.Supported ? (r.Note ?? "Not available on this platform.") : "No routes found.";
    }

    private async Task RefreshAsync()
    {
        // Adapter enumeration hits blocking OS/driver calls (speed, DNS list) — do it off the
        // UI thread and swap in the finished collection on the UI thread. Guarded so a platform
        // that can't enumerate (or throws mid-build) leaves an empty list instead of crashing.
        try
        {
            var list = await Task.Run(BuildAdapters);
            Adapters = new ObservableCollection<NetworkAdapterInfo>(list);
            HiddenFieldsNote = HiddenFields(list);
        }
        catch
        {
            Adapters = new ObservableCollection<NetworkAdapterInfo>();
            HiddenFieldsNote = string.Empty;
        }
    }

    // Android and iOS withhold some fields from apps, and every card then shows "—" for them: name those (the ones no
    // adapter has) once, so the dashes don't read as a fault. Desktops have no such rule.
    private static string HiddenFields(List<NetworkAdapterInfo> list)
    {
        string os = OperatingSystem.IsAndroid() ? "Android" : OperatingSystem.IsIOS() ? "iOS" : string.Empty;
        if (os.Length == 0 || list.Count == 0) return string.Empty;
        var hidden = new List<string>();
        if (list.All(a => a.Gateway == "—")) hidden.Add("gateway");
        if (list.All(a => a.Dns == "—")) hidden.Add("DNS servers");
        if (list.All(a => a.MacAddress == "—")) hidden.Add("MAC");
        if (hidden.Count == 0) return string.Empty;
        string what = hidden.Count == 1 ? hidden[0] : string.Join(", ", hidden.Take(hidden.Count - 1)) + " and " + hidden[^1];
        return $"{os} hides the {what} from apps.";   // "Android hides the gateway, DNS servers and MAC from apps."
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

                // MAC: unavailable on Android 6+ and iOS (empty, or the 02:00:00:00:00:00 placeholder by OS privacy
                // policy): the placeholder shows as "—", not as an address.
                try
                {
                    var m = ni.GetPhysicalAddress().ToString();
                    if (m == "020000000000") m = string.Empty;
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

        // Active (Up) adapters with an IPv4 address first, then the other active ones, then alphabetically — the ones
        // the user cares about on top. (Android reports its virtual dummy0 / ifb0 / tunnel devices as Up with no address,
        // which used to push wlan0 below them.)
        return result
            .OrderByDescending(a => a.IsUp)
            .ThenByDescending(a => System.Net.IPAddress.TryParse(a.IPv4, out _))
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
