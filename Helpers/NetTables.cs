using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace Echoes.Helpers;

/// <summary>
/// Read-only views of the OS's local network state — listening/active ports, the ARP neighbor
/// cache, and the IPv4 routing table — for the Network tab.
///
/// <para>Ports use the managed <see cref="IPGlobalProperties"/> (works on all desktops). Neighbors
/// and routes have no BCL API, so they use light P/Invoke on Windows (iphlpapi) and <c>/proc/net/*</c>
/// on Linux; every other platform (macOS, Android sandbox) reports <c>Supported = false</c> and the
/// UI shows a "not available on this platform" notice instead of an empty list.</para>
///
/// <para>No external binaries, no elevation, no drivers — just managed calls, so it stays within the
/// app's standalone constraint on the platforms it does support.</para>
/// </summary>
public sealed record NetResult<T>(bool Supported, List<T> Rows, string? Note = null);

public sealed class PortEntry
{
    public string Proto { get; init; } = "";
    public string Local { get; init; } = "";
    public string Remote { get; init; } = "";
    public string State { get; init; } = "";
    public string Process { get; init; } = "—";
    public int Pid { get; init; }
    public bool IsListen => State == "LISTEN";
}

public sealed class Neighbor
{
    public string Ip { get; init; } = "";
    public string Mac { get; init; } = "";
    public string Kind { get; init; } = "";   // dynamic / static / …
    public string Iface { get; init; } = "";
}

public sealed class RouteEntry
{
    public string Destination { get; init; } = "";
    public string Gateway { get; init; } = "";
    public string Iface { get; init; } = "";
    public string Metric { get; init; } = "";
    public bool IsDefault => Destination.StartsWith("0.0.0.0", StringComparison.Ordinal);
}

public static class NetTables
{
    // ---------------------------------------------------------------- Ports

    public static NetResult<PortEntry> GetPorts()
    {
        try
        {
            List<PortEntry> rows;
            if (OperatingSystem.IsWindows())
            {
                // Prefer the owner-PID tables so we can show which process holds each port. If the
                // iphlpapi entry points are ever missing, fall back to the process-less managed list.
                try { rows = WindowsPortsWithPid(); }
                catch { rows = ManagedPorts(); }
            }
            else
            {
                rows = ManagedPorts();
            }

            // Listening sockets first, then by protocol/port — the ones people scan for on top.
            rows = rows
                .OrderByDescending(r => r.IsListen)
                .ThenBy(r => r.Proto, StringComparer.Ordinal)
                .ThenBy(r => PortOf(r.Local))
                .ToList();
            return new NetResult<PortEntry>(true, rows);
        }
        catch (Exception ex)
        {
            // Android restricts /proc/net/tcp for non-system apps → this throws; report unsupported.
            return new NetResult<PortEntry>(false, new List<PortEntry>(), Note(ex));
        }
    }

    // Cross-platform port list via the managed BCL. No owning-process info (that needs OS-specific
    // calls), so Process stays "—". Used everywhere except the Windows fast path below.
    private static List<PortEntry> ManagedPorts()
    {
        var g = IPGlobalProperties.GetIPGlobalProperties();
        var rows = new List<PortEntry>();
        foreach (var c in g.GetActiveTcpConnections())
            rows.Add(new PortEntry { Proto = "TCP", Local = c.LocalEndPoint.ToString(), Remote = c.RemoteEndPoint.ToString(), State = TcpStateText(c.State) });
        foreach (var l in g.GetActiveTcpListeners())
            rows.Add(new PortEntry { Proto = "TCP", Local = l.ToString(), Remote = "*", State = "LISTEN" });
        foreach (var u in g.GetActiveUdpListeners())
            rows.Add(new PortEntry { Proto = "UDP", Local = u.ToString(), Remote = "*", State = "—" });
        return rows;
    }

    private static int PortOf(string endpoint)
    {
        int i = endpoint.LastIndexOf(':');
        return i >= 0 && int.TryParse(endpoint.AsSpan(i + 1), out int p) ? p : 0;
    }

    private static string TcpStateText(TcpState s) => s switch
    {
        TcpState.Listen => "LISTEN",
        TcpState.Established => "ESTABLISHED",
        TcpState.TimeWait => "TIME_WAIT",
        TcpState.CloseWait => "CLOSE_WAIT",
        TcpState.SynSent => "SYN_SENT",
        TcpState.SynReceived => "SYN_RECV",
        TcpState.FinWait1 => "FIN_WAIT_1",
        TcpState.FinWait2 => "FIN_WAIT_2",
        TcpState.LastAck => "LAST_ACK",
        TcpState.Closing => "CLOSING",
        TcpState.Closed => "CLOSED",
        _ => s.ToString().ToUpperInvariant(),
    };

    // ---------------------------------------------------------------- Neighbors (ARP)

    public static NetResult<Neighbor> GetNeighbors()
    {
        try
        {
            if (OperatingSystem.IsWindows()) return new NetResult<Neighbor>(true, WindowsArp());
            if (OperatingSystem.IsLinux() && !OperatingSystem.IsAndroid()) return LinuxArp();
        }
        catch (Exception ex) { return new NetResult<Neighbor>(false, new List<Neighbor>(), Note(ex)); }

        return new NetResult<Neighbor>(false, new List<Neighbor>(),
            "The neighbor (ARP) table isn't available on this platform.");
    }

    private static NetResult<Neighbor> LinuxArp()
    {
        const string path = "/proc/net/arp";
        if (!File.Exists(path))
            return new NetResult<Neighbor>(false, new List<Neighbor>(), "ARP table not exposed on this platform.");

        var rows = new List<Neighbor>();
        // IP address  HW type  Flags  HW address  Mask  Device
        foreach (var line in File.ReadLines(path).Skip(1))
        {
            var c = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (c.Length < 6) continue;
            bool complete = c[2] != "0x0";                 // flag 0x2 = complete; 0x0 = incomplete
            string mac = c[3];
            if (!complete || mac == "00:00:00:00:00:00") continue;
            rows.Add(new Neighbor { Ip = c[0], Mac = mac.ToUpperInvariant(), Kind = "dynamic", Iface = c[5] });
        }
        return new NetResult<Neighbor>(true, SortByIp(rows));
    }

    // ---------------------------------------------------------------- Routes

    public static NetResult<RouteEntry> GetRoutes()
    {
        try
        {
            if (OperatingSystem.IsWindows()) return new NetResult<RouteEntry>(true, WindowsRoutes());
            if (OperatingSystem.IsLinux() && !OperatingSystem.IsAndroid()) return LinuxRoutes();
        }
        catch (Exception ex) { return new NetResult<RouteEntry>(false, new List<RouteEntry>(), Note(ex)); }

        return new NetResult<RouteEntry>(false, new List<RouteEntry>(),
            "The routing table isn't available on this platform.");
    }

    private static NetResult<RouteEntry> LinuxRoutes()
    {
        const string path = "/proc/net/route";
        if (!File.Exists(path))
            return new NetResult<RouteEntry>(false, new List<RouteEntry>(), "Routing table not exposed on this platform.");

        var rows = new List<RouteEntry>();
        // Iface Destination Gateway Flags RefCnt Use Metric Mask …   (all addresses little-endian hex)
        foreach (var line in File.ReadLines(path).Skip(1))
        {
            var c = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (c.Length < 8) continue;
            if (!TryHexIp(c[1], out var dest) || !TryHexIp(c[2], out var gw) || !TryHexIp(c[7], out var mask))
                continue;
            rows.Add(new RouteEntry
            {
                Destination = $"{dest}/{MaskToPrefix(mask)}",
                Gateway = gw.Equals(IPAddress.Any) ? "on-link" : gw.ToString(),
                Iface = c[0],
                Metric = c[6],
            });
        }
        return new NetResult<RouteEntry>(true, rows.OrderBy(r => !r.IsDefault).ToList());
    }

    // Linux /proc addresses are the 32-bit value printed as little-endian hex → low byte is first octet.
    private static bool TryHexIp(string hex, out IPAddress ip)
    {
        ip = IPAddress.Any;
        if (!uint.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out uint v)) return false;
        ip = new IPAddress(new byte[] { (byte)(v & 0xff), (byte)((v >> 8) & 0xff), (byte)((v >> 16) & 0xff), (byte)((v >> 24) & 0xff) });
        return true;
    }

    private static int MaskToPrefix(IPAddress mask)
    {
        int bits = 0;
        foreach (var b in mask.GetAddressBytes())
            for (int i = 7; i >= 0; i--) if ((b & (1 << i)) != 0) bits++;
        return bits;
    }

    // ---------------------------------------------------------------- Windows P/Invoke (iphlpapi)

    [DllImport("iphlpapi.dll")]
    private static extern int GetIpNetTable(IntPtr pIpNetTable, ref int pdwSize, bool bOrder);

    [DllImport("iphlpapi.dll")]
    private static extern int GetIpForwardTable(IntPtr pIpForwardTable, ref int pdwSize, bool bOrder);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTable, ref int size, bool order, int af, int tableClass, int reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr pTable, ref int size, bool order, int af, int tableClass, int reserved);

    private const int ERROR_INSUFFICIENT_BUFFER = 122;
    private const int AF_INET = 2, AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5, UDP_TABLE_OWNER_PID = 1;

    // Windows: the *_OWNER_PID tables give every endpoint plus the PID that owns it, which we resolve
    // to a process name. Any failure here bubbles up so GetPorts() can fall back to the managed list.
    private static List<PortEntry> WindowsPortsWithPid()
    {
        var rows = new List<PortEntry>();
        var nameCache = new Dictionary<int, string>();
        ReadTcpTable(AF_INET, false, rows, nameCache);
        ReadTcpTable(AF_INET6, true, rows, nameCache);
        ReadUdpTable(AF_INET, false, rows, nameCache);
        ReadUdpTable(AF_INET6, true, rows, nameCache);
        return rows;
    }

    private static void ReadTcpTable(int af, bool v6, List<PortEntry> rows, Dictionary<int, string> cache)
    {
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, true, af, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size == 0) return;
        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buf, ref size, true, af, TCP_TABLE_OWNER_PID_ALL, 0) != 0) return;
            int count = Marshal.ReadInt32(buf);
            int rowSize = v6 ? 56 : 24;
            for (int i = 0; i < count; i++)
            {
                long p = buf.ToInt64() + 4 + (long)i * rowSize;
                int state, lport, rport, pid; string local, remote;
                if (v6)
                {
                    // MIB_TCP6ROW_OWNER_PID: localAddr[16] localScope(4) localPort(4) remoteAddr[16] remoteScope(4) remotePort(4) state(4) pid(4)
                    var la = Bytes(p + 0, 16); lport = PortAt(p + 20);
                    var ra = Bytes(p + 24, 16); rport = PortAt(p + 44);
                    state = Marshal.ReadInt32((IntPtr)(p + 48)); pid = Marshal.ReadInt32((IntPtr)(p + 52));
                    local = $"[{new IPAddress(la)}]:{lport}"; remote = $"[{new IPAddress(ra)}]:{rport}";
                }
                else
                {
                    // MIB_TCPROW_OWNER_PID: state(4) localAddr(4) localPort(4) remoteAddr(4) remotePort(4) pid(4)
                    state = Marshal.ReadInt32((IntPtr)(p + 0));
                    var la = Bytes(p + 4, 4); lport = PortAt(p + 8);
                    var ra = Bytes(p + 12, 4); rport = PortAt(p + 16);
                    pid = Marshal.ReadInt32((IntPtr)(p + 20));
                    local = $"{new IPAddress(la)}:{lport}"; remote = $"{new IPAddress(ra)}:{rport}";
                }
                bool listen = state == 2; // MIB_TCP_STATE_LISTEN
                rows.Add(new PortEntry
                {
                    Proto = "TCP",
                    Local = local,
                    Remote = listen ? "*" : remote,
                    State = MibTcpStateText(state),
                    Process = ProcName(pid, cache),
                    Pid = pid,
                });
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static void ReadUdpTable(int af, bool v6, List<PortEntry> rows, Dictionary<int, string> cache)
    {
        int size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, true, af, UDP_TABLE_OWNER_PID, 0);
        if (size == 0) return;
        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedUdpTable(buf, ref size, true, af, UDP_TABLE_OWNER_PID, 0) != 0) return;
            int count = Marshal.ReadInt32(buf);
            int rowSize = v6 ? 28 : 12;
            for (int i = 0; i < count; i++)
            {
                long p = buf.ToInt64() + 4 + (long)i * rowSize;
                string local; int pid;
                if (v6)
                {
                    // MIB_UDP6ROW_OWNER_PID: localAddr[16] scope(4) localPort(4) pid(4)
                    var la = Bytes(p + 0, 16); int lport = PortAt(p + 20); pid = Marshal.ReadInt32((IntPtr)(p + 24));
                    local = $"[{new IPAddress(la)}]:{lport}";
                }
                else
                {
                    // MIB_UDPROW_OWNER_PID: localAddr(4) localPort(4) pid(4)
                    var la = Bytes(p + 0, 4); int lport = PortAt(p + 4); pid = Marshal.ReadInt32((IntPtr)(p + 8));
                    local = $"{new IPAddress(la)}:{lport}";
                }
                rows.Add(new PortEntry { Proto = "UDP", Local = local, Remote = "*", State = "—", Process = ProcName(pid, cache), Pid = pid });
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static byte[] Bytes(long addr, int n) { var b = new byte[n]; Marshal.Copy((IntPtr)addr, b, 0, n); return b; }

    // The port DWORD holds the port in network byte order in its low 16 bits.
    private static int PortAt(long addr) { uint d = (uint)Marshal.ReadInt32((IntPtr)addr); return (int)(((d & 0xFF) << 8) | ((d >> 8) & 0xFF)); }

    private static string MibTcpStateText(int s) => s switch
    {
        1 => "CLOSED", 2 => "LISTEN", 3 => "SYN_SENT", 4 => "SYN_RECV", 5 => "ESTABLISHED",
        6 => "FIN_WAIT_1", 7 => "FIN_WAIT_2", 8 => "CLOSE_WAIT", 9 => "CLOSING",
        10 => "LAST_ACK", 11 => "TIME_WAIT", 12 => "DELETE_TCB", _ => s.ToString(),
    };

    // Resolve a PID to a process name, cached. Never throws — access-denied / exited processes just
    // show "pid N" so a locked-down box or a race with a closing process can't crash the list.
    private static string ProcName(int pid, Dictionary<int, string> cache)
    {
        if (pid == 0) return "System Idle";
        if (pid == 4) return "System";
        if (cache.TryGetValue(pid, out var cached)) return cached;
        string name;
        try { using var pr = System.Diagnostics.Process.GetProcessById(pid); name = pr.ProcessName; }
        catch { name = $"pid {pid}"; }
        cache[pid] = name;
        return name;
    }

    private static List<Neighbor> WindowsArp()
    {
        var rows = new List<Neighbor>();
        var names = IfIndexNames();
        int size = 0;
        if (GetIpNetTable(IntPtr.Zero, ref size, false) != ERROR_INSUFFICIENT_BUFFER || size == 0) return rows;

        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            if (GetIpNetTable(buf, ref size, false) != 0) return rows;
            int count = Marshal.ReadInt32(buf);
            // MIB_IPNETROW: dwIndex(4) dwPhysAddrLen(4) bPhysAddr(8) dwAddr(4) dwType(4) = 24 bytes
            const int rowSize = 24;
            for (int i = 0; i < count; i++)
            {
                long p = buf.ToInt64() + 4 + (long)i * rowSize;
                int ifIndex = Marshal.ReadInt32((IntPtr)p);
                int physLen = Marshal.ReadInt32((IntPtr)(p + 4));
                var macBytes = new byte[8];
                Marshal.Copy((IntPtr)(p + 8), macBytes, 0, 8);
                var addr = new byte[4];
                Marshal.Copy((IntPtr)(p + 16), addr, 0, 4);
                int type = Marshal.ReadInt32((IntPtr)(p + 20));

                if (physLen is < 1 or > 8) continue;
                if (type is 2) continue;                       // 2 = invalid entry
                string mac = string.Join(":", macBytes.Take(physLen).Select(b => b.ToString("X2")));
                rows.Add(new Neighbor
                {
                    Ip = new IPAddress(addr).ToString(),
                    Mac = mac,
                    Kind = type == 4 ? "static" : type == 3 ? "dynamic" : "other",
                    Iface = names.TryGetValue(ifIndex, out var n) ? n : ifIndex.ToString(),
                });
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
        return SortByIp(rows);
    }

    private static List<RouteEntry> WindowsRoutes()
    {
        var rows = new List<RouteEntry>();
        var names = IfIndexNames();
        int size = 0;
        if (GetIpForwardTable(IntPtr.Zero, ref size, true) != ERROR_INSUFFICIENT_BUFFER || size == 0) return rows;

        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            if (GetIpForwardTable(buf, ref size, true) != 0) return rows;
            int count = Marshal.ReadInt32(buf);
            // MIB_IPFORWARDROW: dest, mask, policy, nexthop, ifindex, type, proto, age, nexthopAS,
            // metric1..5 = 14 DWORDs = 56 bytes. We read dest(0) mask(4) nexthop(12) ifindex(16) metric1(36).
            const int rowSize = 56;
            for (int i = 0; i < count; i++)
            {
                long p = buf.ToInt64() + 4 + (long)i * rowSize;
                var dest = new byte[4]; Marshal.Copy((IntPtr)(p + 0), dest, 0, 4);
                var mask = new byte[4]; Marshal.Copy((IntPtr)(p + 4), mask, 0, 4);
                var next = new byte[4]; Marshal.Copy((IntPtr)(p + 12), next, 0, 4);
                int ifIndex = Marshal.ReadInt32((IntPtr)(p + 16));
                int metric = Marshal.ReadInt32((IntPtr)(p + 36));

                var gw = new IPAddress(next);
                rows.Add(new RouteEntry
                {
                    Destination = $"{new IPAddress(dest)}/{MaskToPrefix(new IPAddress(mask))}",
                    Gateway = gw.Equals(IPAddress.Any) ? "on-link" : gw.ToString(),
                    Iface = names.TryGetValue(ifIndex, out var n) ? n : ifIndex.ToString(),
                    Metric = metric.ToString(),
                });
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
        return rows.OrderBy(r => !r.IsDefault).ToList();
    }

    // ---------------------------------------------------------------- shared helpers

    private static Dictionary<int, string> IfIndexNames()
    {
        var map = new Dictionary<int, string>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                try
                {
                    var p = ni.GetIPProperties();
                    var idx = p.GetIPv4Properties()?.Index ?? -1;
                    if (idx > 0 && !map.ContainsKey(idx)) map[idx] = ni.Name;
                }
                catch { }
            }
        }
        catch { }
        return map;
    }

    private static List<Neighbor> SortByIp(List<Neighbor> rows) =>
        rows.OrderBy(r => IPAddress.TryParse(r.Ip, out var a) ? BitConverter.ToUInt32(a.GetAddressBytes().Reverse().ToArray(), 0) : uint.MaxValue).ToList();

    private static string Note(Exception ex) =>
        ex is PlatformNotSupportedException ? "Not supported on this platform." : "Couldn't read this table.";
}
