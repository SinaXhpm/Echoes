using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Echoes.Helpers;

/// <summary>
/// The IPv4 addresses of the network adapters that are up (loopback left out), read once and shared for a second.
/// Enumerating adapters costs ~20 ms on a machine with many virtual / VPN adapters, and a tab switch to Web Server or
/// Proxy used to do it two or three times on the UI thread (bind list, share URLs, catcher URLs).
/// <para>Ordered for a person on the same network: Wi-Fi and Ethernet first, virtual adapters next, cellular, VPN and
/// tunnel interfaces last. The share link and QR code take the first one: an iPhone lists its cellular interfaces
/// (pdp_ip*) before Wi-Fi (en0), so with mobile data on the QR code pointed at the carrier's address and a laptop on the
/// Wi-Fi never got the page.</para>
/// </summary>
public static class NicSnapshot
{
    private static (long At, (string Name, IPAddress Address)[] V4, HashSet<IPAddress> Wan)? s_last;
    private static readonly object s_gate = new();

    public static (string Name, IPAddress Address)[] UpIPv4() => Read().V4;

    /// <summary>Whether <paramref name="address"/> belongs to a cellular, VPN or tunnel interface (or is a link-local /
    /// CLAT address): reachable for nobody on the local network, and changing often.</summary>
    public static bool IsWanLike(IPAddress address) => Read().Wan.Contains(address);

    private static ((string Name, IPAddress Address)[] V4, HashSet<IPAddress> Wan) Read()
    {
        lock (s_gate)
        {
            if (s_last is { } last && Environment.TickCount64 - last.At < 1000) return (last.V4, last.Wan);
        }
        var list = new List<(string Name, IPAddress Address, int Rank)>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                    if (ua.Address.AddressFamily == AddressFamily.InterNetwork)
                        list.Add((ni.Name, ua.Address, Rank(ni.Name, ni.NetworkInterfaceType, ua.Address)));
            }
        }
        catch { /* GetIPProperties can throw on restricted platforms: callers keep loopback / "all" */ }
        var v4 = list.OrderBy(e => e.Rank).Select(e => (e.Name, e.Address)).ToArray();   // stable: ties keep the OS order
        var wan = list.Where(e => e.Rank == WanRank).Select(e => e.Address).ToHashSet();
        lock (s_gate) s_last = (Environment.TickCount64, v4, wan);
        return (v4, wan);
    }

    private const int WanRank = 2;

    // 0 = Wi-Fi / Ethernet, 1 = virtual or unknown, 2 = cellular / VPN / tunnel / link-local (last, and never the default).
    private static int Rank(string name, NetworkInterfaceType type, IPAddress address)
    {
        var b = address.GetAddressBytes();
        if (b[0] == 169 && b[1] == 254) return WanRank;                                // link-local (no DHCP answer)
        if (b[0] == 192 && b[1] == 0 && b[2] == 0 && b[3] < 8) return WanRank;          // 192.0.0.0/29: iOS / Android CLAT
        string n = name.ToLowerInvariant();
        if (type is NetworkInterfaceType.Tunnel or NetworkInterfaceType.Ppp or NetworkInterfaceType.Wwanpp or NetworkInterfaceType.Wwanpp2)
            return WanRank;
        string[] wan = { "pdp_ip", "rmnet", "ccmni", "v4-", "clat", "wwan", "radio", "ipsec", "utun", "tun", "tap", "ppp", "wg",
                         "awdl", "llw", "zt", "tailscale", "wireguard", "openvpn", "nordlynx", "proton" };
        foreach (string p in wan) if (n.StartsWith(p, StringComparison.Ordinal)) return WanRank;
        string[] virt = { "vethernet", "vmware", "virtualbox", "vboxnet", "docker", "veth", "virbr", "br-", "hyper-v", "vmnet", "bluetooth" };
        foreach (string p in virt) if (n.StartsWith(p, StringComparison.Ordinal) || n.Contains(p, StringComparison.Ordinal)) return 1;
        if (type is NetworkInterfaceType.Wireless80211 or NetworkInterfaceType.Ethernet or NetworkInterfaceType.GigabitEthernet
            or NetworkInterfaceType.FastEthernetT or NetworkInterfaceType.FastEthernetFx) return 0;
        string[] lan = { "en", "eth", "wlan", "wl", "swlan", "ap", "softap", "bridge", "wi-fi", "wifi", "ethernet" };
        foreach (string p in lan) if (n.StartsWith(p, StringComparison.Ordinal)) return 0;
        return 1;
    }
}
