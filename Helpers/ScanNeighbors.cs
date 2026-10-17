using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace Echoes.Helpers;

/// <summary>
/// The OS neighbor cache (ARP for IPv4, NDP for IPv6) as the scanner needs it: the MAC of every on-link host, and
/// whether the OS confirmed the entry recently. Windows: GetIpNetTable2 (both families, with the neighbor
/// state). Linux: /proc/net/arp (IPv4, complete entries; no state). Empty elsewhere — macOS has no table API we use
/// and the Android sandbox hides it. Read-only, no elevation; never throws.
/// </summary>
public static class ScanNeighbors
{
    /// <summary>A neighbor entry. <paramref name="Confirmed"/>: the host answered ARP/NDP recently (Windows'
    /// "reachable"); a stale entry only says it was there once — not proof it is up now.</summary>
    public readonly record struct Entry(string Mac, bool Confirmed);

    /// <summary>IP literal → entry, for unicast host MACs only (no broadcast / multicast / all-zero entries).</summary>
    public static Dictionary<string, Entry> Snapshot()
    {
        var map = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (OperatingSystem.IsWindows()) ReadWindows(map);
            else if (OperatingSystem.IsLinux() && !OperatingSystem.IsAndroid()) ReadLinux(map);
        }
        catch { /* best-effort: no table, no MACs */ }
        return map;
    }

    /// <summary>This machine's own addresses → its NIC's MAC (scanning yourself has no neighbor entry). Never throws.</summary>
    public static Dictionary<string, string> LocalMacs()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                byte[] mac;
                try { mac = ni.GetPhysicalAddress().GetAddressBytes(); } catch { continue; }
                if (mac.Length != 6) continue;
                string text = string.Join(":", mac.Select(b => b.ToString("X2")));
                // Android hides the real MAC behind this placeholder.
                if (!ScanOui.IsHostMac(text) || text == "02:00:00:00:00:00") continue;
                try
                {
                    foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                        map.TryAdd(ua.Address.ToString(), text);
                }
                catch { }
            }
        }
        catch { }
        return map;
    }

    private static void ReadLinux(Dictionary<string, Entry> map)
    {
        const string path = "/proc/net/arp";
        if (!File.Exists(path)) return;
        // IP address  HW type  Flags  HW address  Mask  Device — flags 0x2 = complete
        foreach (var line in File.ReadLines(path).Skip(1))
        {
            var c = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (c.Length < 6 || c[2] == "0x0" || !ScanOui.IsHostMac(c[3])) continue;
            map[c[0]] = new Entry(ScanOui.Format(c[3]), Confirmed: false);
        }
    }

    // ---- Windows: GetIpNetTable2 ----
    // MIB_IPNET_TABLE2 { ULONG NumEntries; (pad to 8) MIB_IPNET_ROW2 Table[]; }, MIB_IPNET_ROW2 (88 bytes):
    //   SOCKADDR_INET Address @0 (28) · InterfaceIndex @28 · NET_LUID @32 · PhysicalAddress[32] @40 ·
    //   PhysicalAddressLength @72 · NL_NEIGHBOR_STATE State @76 · Flags @80 (bit 1 IsUnreachable) · ReachabilityTime @84
    private const int RowSize = 88, TableOffset = 8;
    private const int NlnsReachable = 5;
    private const ushort WinAfInet = 2, WinAfInet6 = 23;

    [DllImport("iphlpapi.dll")]
    private static extern int GetIpNetTable2(ushort family, out IntPtr table);

    [DllImport("iphlpapi.dll")]
    private static extern void FreeMibTable(IntPtr memory);

    private static void ReadWindows(Dictionary<string, Entry> map)
    {
        if (GetIpNetTable2(0 /* AF_UNSPEC */, out IntPtr table) != 0 || table == IntPtr.Zero) return;
        try
        {
            int count = Marshal.ReadInt32(table);
            var row = new byte[RowSize];
            for (int i = 0; i < count; i++)
            {
                Marshal.Copy(table + TableOffset + i * RowSize, row, 0, RowSize);

                ushort family = BitConverter.ToUInt16(row, 0);
                IPAddress addr;
                if (family == WinAfInet) addr = new IPAddress(row.AsSpan(4, 4));
                else if (family == WinAfInet6) addr = new IPAddress(row.AsSpan(8, 16), BitConverter.ToUInt32(row, 24));
                else continue;

                int macLen = BitConverter.ToInt32(row, 72);
                int state = BitConverter.ToInt32(row, 76);
                bool unreachable = (row[80] & 0x02) != 0;
                if (macLen != 6 || unreachable || state is 0 or 1) continue;   // unreachable / incomplete
                string mac = $"{row[40]:X2}:{row[41]:X2}:{row[42]:X2}:{row[43]:X2}:{row[44]:X2}:{row[45]:X2}";
                if (!ScanOui.IsHostMac(mac)) continue;   // broadcast / multicast / all-zero placeholders

                // The scope id is part of an IPv6 literal ("fe80::1%12"); targets are matched without it.
                string key = addr.AddressFamily == AddressFamily.InterNetworkV6 && addr.ScopeId != 0
                    ? new IPAddress(addr.GetAddressBytes()).ToString() : addr.ToString();
                map[key] = new Entry(mac, Confirmed: state == NlnsReachable);
            }
        }
        finally { FreeMibTable(table); }
    }
}
