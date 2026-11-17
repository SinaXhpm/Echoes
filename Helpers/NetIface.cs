using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace Echoes.Helpers;

/// <summary>
/// One network interface that is up, as a tool needs it to send through that interface instead of wherever the routing
/// table points: <c>ping -I</c> / <c>-S</c>, <c>mtr -I</c>, <c>nmap -e</c>, <c>curl --interface</c>.
/// <para><see cref="TryBind"/> ties a socket to it before it connects or sends:</para>
/// <list type="bullet">
/// <item>Windows: IP_UNICAST_IF / IPV6_UNICAST_IF (the outgoing interface by index) and, for IPv4, the interface's
/// address as the source. Windows sends a packet only from the interface that owns its source address (the strong host
/// model), so either would do; both together leave nothing to the routing table.</item>
/// <item>Linux / Android: SO_BINDTODEVICE, as ping -I does. Any user may set it since Linux 5.7; before that only
/// root, and then the source address is set instead (the route still follows the system's table, the note says so).</item>
/// <item>macOS / iOS: IP_BOUND_IF / IPV6_BOUND_IF (the interface by index), which any app may set.</item>
/// </list>
/// Names are resolved by the system resolver as always: only the probes themselves go through the interface.
/// </summary>
/// <param name="Name">The system's name: "Wi-Fi" on Windows, "eth0" / "en0" elsewhere. What the choice is saved as.</param>
/// <param name="Description">The adapter's own description (Windows: the hardware's name); the name where there is none.</param>
/// <param name="Id">Windows: the adapter's GUID ("{…}", what Npcap names its device after); elsewhere the name.</param>
/// <param name="Index">The interface index (also an IPv6 link-local address's scope id); 0 = not known.</param>
/// <param name="V4">Its IPv4 address, if it has one.</param>
/// <param name="V6">Its IPv6 address for the internet (global or unique-local), if it has one.</param>
/// <param name="V6Link">Its IPv6 link-local address (fe80::…, with the scope id), if it has one.</param>
public sealed record NetIface(string Name, string Description, string Id, int Index,
                              IPAddress? V4, IPAddress? V6, IPAddress? V6Link, bool IsLoopback)
{
    public bool HasV4 => V4 is not null;
    public bool HasV6 => V6 is not null || V6Link is not null;

    /// <summary>The length of <see cref="V4"/>'s subnet prefix (24 for 255.255.255.0); 0 = not known.</summary>
    public int Prefix4 { get; init; }

    /// <summary>The adapter's own MAC ("A8:5E:45:BB:13:7D"), where the system shows it.</summary>
    public string? Mac { get; init; }

    /// <summary>The DNS servers to ask through this interface, in the system's order; empty where the system keeps
    /// them from apps. Windows keeps a list per interface (DHCP, or set by hand): this is that list. Linux and macOS
    /// keep one list for the whole system (resolv.conf), so there every interface has the same one, less the
    /// servers that can't be reached from an interface at all (see <see cref="DnsIsLocalOnly"/>).</summary>
    public IReadOnlyList<IPAddress> DnsServers { get; init; } = Array.Empty<IPAddress>();

    /// <summary>The system's DNS is a program on this computer (systemd-resolved at 127.0.0.53, dnsmasq at 127.0.0.1),
    /// which answers on the loopback interface only, and what it forwards to isn't known: <see cref="DnsServers"/> is
    /// empty for that reason, not because the interface has none.</summary>
    public bool DnsIsLocalOnly { get; init; }

    /// <summary>The IPv4 gateway of this interface, if it has one.</summary>
    public IPAddress? Gateway4 { get; init; }

    /// <summary>The interface's IPv4 network and the host addresses in it, for a sweep: at most <paramref name="max"/>
    /// of them (a bigger subnet gives the block of that size around this interface's own address, and
    /// <paramref name="whole"/> is false). Null without an IPv4 address or a known prefix.</summary>
    public (IPAddress Network, int Prefix, List<IPAddress> Hosts)? Subnet4(int max, out bool whole)
    {
        whole = true;
        if (V4 is null || Prefix4 is < 1 or > 30) return null;
        uint own = ToUInt(V4);
        int prefix = Prefix4;
        // the smallest prefix whose host count fits: /22 for max 1022
        while (prefix < 30 && (1L << (32 - prefix)) - 2 > max) { prefix++; whole = false; }
        uint mask = prefix == 0 ? 0u : 0xFFFFFFFFu << (32 - prefix);
        uint network = own & mask, broadcast = network | ~mask;
        var hosts = new List<IPAddress>((int)(broadcast - network));
        for (uint a = network + 1; a < broadcast; a++) hosts.Add(FromUInt(a));
        return (FromUInt(network), prefix, hosts);
    }

    /// <summary>True when <paramref name="address"/> is in this interface's IPv4 subnet.</summary>
    public bool OnLink4(IPAddress address)
    {
        if (V4 is null || Prefix4 is < 1 or > 32 || address.AddressFamily != AddressFamily.InterNetwork) return false;
        uint mask = 0xFFFFFFFFu << (32 - Prefix4);
        return (ToUInt(address) & mask) == (ToUInt(V4) & mask);
    }

    private static uint ToUInt(IPAddress a)
    {
        var b = a.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    private static IPAddress FromUInt(uint v) => new(new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v });

    /// <summary>"Wi-Fi · 192.168.1.2" (the IPv6 address where there is no IPv4 one).</summary>
    public string Label => (V4 ?? V6 ?? V6Link) is { } a ? Name + " · " + Unscoped(a) : Name;

    /// <summary>The address a probe to <paramref name="target"/> leaves from, or null when the interface has none of
    /// that kind (a link-local target is reached from the link-local address).</summary>
    public IPAddress? SourceFor(IPAddress target)
    {
        if (target.AddressFamily != AddressFamily.InterNetworkV6) return V4;
        return target.IsIPv6LinkLocal ? V6Link ?? V6 : V6 ?? V6Link;
    }

    /// <summary>Why a probe to <paramref name="target"/> can't leave from this interface, or null when it can:
    /// "Wi-Fi has no IPv6 address".</summary>
    public string? Missing(IPAddress target)
    {
        if (SourceFor(target) is not null) return null;
        return $"{Name} has no {(target.AddressFamily == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4")} address";
    }

    /// <summary>A name that has both kinds of address: the kind this interface can reach. An interface with IPv4 keeps
    /// <paramref name="asked"/> (Auto prefers IPv4, as ping does); one with IPv6 only turns Auto into IPv6.</summary>
    public IpPreference Prefer(IpPreference asked)
        => asked == IpPreference.Auto && !HasV4 && HasV6 ? IpPreference.IPv6 : asked;

    /// <summary>A link-local target typed without its zone ("fe80::1") gets this interface's: there is no other way to
    /// say which link it is on.</summary>
    public IPAddress Scoped(IPAddress target)
        => target.AddressFamily == AddressFamily.InterNetworkV6 && target.IsIPv6LinkLocal && target.ScopeId == 0 && Index > 0
            ? new IPAddress(target.GetAddressBytes(), Index)
            : target;

    /// <summary>
    /// Ties <paramref name="socket"/> (not yet connected or bound) to this interface. True: what it sends leaves from
    /// here; <paramref name="note"/> is then null, or says that only the source address could be set. False: nothing
    /// may be sent (it would take the default route), and <paramref name="note"/> says why. Never throws.
    /// </summary>
    public bool TryBind(Socket socket, out string? note)
    {
        note = null;
        bool v6 = socket.AddressFamily == AddressFamily.InterNetworkV6;
        try
        {
            if (OperatingSystem.IsWindows())
            {
                if (Index <= 0) { note = $"{Name} has no interface index"; return false; }
                if (v6) socket.SetSocketOption(SocketOptionLevel.IPv6, (SocketOptionName)IPV6_UNICAST_IF, Index);
                else
                {
                    // the one option of its kind that wants the index in network byte order
                    socket.SetSocketOption(SocketOptionLevel.IP, (SocketOptionName)IP_UNICAST_IF, IPAddress.HostToNetworkOrder(Index));
                    if (V4 is null) { note = $"{Name} has no IPv4 address"; return false; }
                    socket.Bind(new IPEndPoint(V4, 0));
                }
                return true;
            }

            if (OperatingSystem.IsLinux() || OperatingSystem.IsAndroid())
            {
                try
                {
                    socket.SetRawSocketOption(SOL_SOCKET, SO_BINDTODEVICE, Encoding.UTF8.GetBytes(Name + "\0"));
                    return true;
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AccessDenied)
                {
                    // Before Linux 5.7 only root may choose the device (some Android builds too). The source address
                    // still can be set: replies come back to this interface, the way out stays the routing table's.
                    var source = v6 ? V6 ?? V6Link : V4;
                    if (source is null) { note = $"{Name} has no {(v6 ? "IPv6" : "IPv4")} address"; return false; }
                    socket.Bind(new IPEndPoint(source, 0));
                    note = $"This system lets only root choose the interface: the source address of {Name} was set instead, so the route is still the system's.";
                    return true;
                }
            }

            // macOS / iOS (and the other BSDs): the interface by index
            uint index = Index > 0 ? (uint)Index : IndexOf(Name);
            if (index == 0) { note = $"{Name} isn't there any more"; return false; }
            socket.SetRawSocketOption(v6 ? IPPROTO_IPV6 : IPPROTO_IP, v6 ? IPV6_BOUND_IF : IP_BOUND_IF, BitConverter.GetBytes((int)index));
            return true;
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException or InvalidOperationException or NotSupportedException)
        {
            note = ex is SocketException se ? Describe(se) : $"can't send through {Name}: {ex.Message}";
            return false;
        }
    }

    /// <summary>Why a TCP connect from this interface failed, when the socket error is one the interface explains
    /// (the start of a sentence, no full stop); else null: the error is the target's.</summary>
    public string? ConnectProblem(SocketError error, string target) => error switch
    {
        // Windows reports this for a socket tied to an interface whose connection a program on this computer redirects
        // to itself (127.0.0.1): a VPN or proxy client's driver. Such a socket can't follow the redirect.
        SocketError.AddressNotAvailable when OperatingSystem.IsWindows()
            => $"Windows can't connect from {Name}; a VPN or proxy program that redirects this computer's connections does this",
        SocketError.NetworkUnreachable or SocketError.HostUnreachable or SocketError.NetworkDown
            => $"there is no route to {target} from {Name}",
        _ => null,
    };

    /// <summary>
    /// <see cref="TryBind"/> for a socket that sends to a multicast group or the subnet's broadcast address (mDNS,
    /// SSDP, a NetBIOS broadcast): those leave from the interface a socket names for multicast, which the unicast
    /// options don't set.
    /// </summary>
    public bool TryBindMulticast(Socket socket, out string? note)
    {
        if (!TryBind(socket, out note)) return false;
        try
        {
            if (socket.AddressFamily == AddressFamily.InterNetwork)
            {
                if (V4 is null) { note = $"{Name} has no IPv4 address"; return false; }
                socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, V4.GetAddressBytes());
            }
            else if (Index > 0) socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastInterface, Index);
            return true;
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException or InvalidOperationException or NotSupportedException)
        {
            note = $"can't send multicast through {Name}: {ex.Message}";
            return false;
        }
    }

    private string Describe(SocketException ex) => ex.SocketErrorCode switch
    {
        SocketError.AddressNotAvailable => $"{Name} has lost its address (disconnected?)",
        SocketError.AccessDenied => $"choosing the interface isn't permitted here ({Name})",
        SocketError.NetworkDown or SocketError.NetworkUnreachable => $"{Name} is down",
        _ when ex.NativeErrorCode == ENODEV && !OperatingSystem.IsWindows() => $"{Name} isn't there any more",
        _ => $"can't send through {Name}: {ex.Message}",
    };

    private static string Unscoped(IPAddress a)
        => a.AddressFamily == AddressFamily.InterNetworkV6 && a.ScopeId != 0 ? new IPAddress(a.GetAddressBytes()).ToString() : a.ToString();

    private const int IP_UNICAST_IF = 31, IPV6_UNICAST_IF = 31;         // Windows
    private const int SOL_SOCKET = 1, SO_BINDTODEVICE = 25, ENODEV = 19; // Linux
    private const int IPPROTO_IP = 0, IPPROTO_IPV6 = 41, IP_BOUND_IF = 25, IPV6_BOUND_IF = 125;   // Darwin

    [DllImport("libc", EntryPoint = "if_nametoindex")]
    private static extern uint IfNameToIndexLinux(byte[] name);

    // (macOS and iOS name their C library by its path, as DeviceInfoApple does)
    [DllImport("/usr/lib/libSystem.dylib", EntryPoint = "if_nametoindex")]
    private static extern uint IfNameToIndexApple(byte[] name);

    /// <summary>The interface index of a Unix interface name; 0 when there is none (or the call isn't there).</summary>
    internal static uint IndexOf(string name)
    {
        if (OperatingSystem.IsWindows()) return 0;
        byte[] text = Encoding.UTF8.GetBytes(name + "\0");
        try { return OperatingSystem.IsLinux() || OperatingSystem.IsAndroid() ? IfNameToIndexLinux(text) : IfNameToIndexApple(text); }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException) { return 0; }
    }
}

/// <summary>A connection couldn't be made from the interface the user chose: the message is a whole sentence saying
/// why, and no other server or address would fare better.</summary>
public sealed class NetIfaceException(string message, Exception? inner = null) : System.IO.IOException(message, inner)
{
    /// <summary>"there is no route …" → "There is no route ….": a reason as a sentence. One that starts with the
    /// interface's own name ("eth0 has no IPv6 address") keeps it as the system writes it.</summary>
    public static NetIfaceException From(NetIface via, string reason, Exception? inner = null)
    {
        string text = reason.TrimEnd('.');
        if (text.Length > 0 && !text.StartsWith(via.Name, StringComparison.Ordinal)) text = char.ToUpperInvariant(text[0]) + text[1..];
        return new NetIfaceException(text + ".", inner);
    }
}

/// <summary>The interfaces a tool can send through or listen on, read when asked (the picker reads them as it opens,
/// a run as it starts).</summary>
public static class NetIfaces
{
    /// <summary>Every interface that is up and has an IPv4 address or an IPv6 one beyond link-local (an fe80:: address
    /// alone doesn't count: see below), the ones a person means first: Wi-Fi and Ethernet,
    /// then virtual adapters, then cellular / VPN / tunnel interfaces (<see cref="NicSnapshot"/>'s order), loopback
    /// last and only when asked for. Empty where the system keeps the list from apps.</summary>
    public static IReadOnlyList<NetIface> Up(bool withLoopback = false)
    {
        var list = new List<(NetIface Iface, int Rank)>();
        try
        {
            var all = NetworkInterface.GetAllNetworkInterfaces();
            var local = LoopbackAddresses(all);
            List<IPAddress>? uplinks = null;   // read once, and only where it is needed
            foreach (var ni in all)
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                bool loopback = ni.NetworkInterfaceType == NetworkInterfaceType.Loopback;
                if (loopback && !withLoopback) continue;

                IPAddress? v4 = null, v4Link = null, v6 = null, v6Link = null;
                int prefix4 = 0, prefixLink = 0;
                IPInterfaceProperties props;
                try { props = ni.GetIPProperties(); }
                catch (Exception) { continue; }
                foreach (var ua in props.UnicastAddresses)
                {
                    var a = ua.Address;
                    if (a.AddressFamily == AddressFamily.InterNetwork)
                    {
                        var b = a.GetAddressBytes();
                        int prefix = 0;
                        try { prefix = ua.PrefixLength; } catch (Exception) { }   // not on every platform
                        if (b[0] == 169 && b[1] == 254) { if (v4Link is null) { v4Link = a; prefixLink = prefix; } }   // no DHCP answer: only when there is nothing better
                        else if (v4 is null) { v4 = a; prefix4 = prefix; }
                    }
                    else if (a.AddressFamily == AddressFamily.InterNetworkV6)
                    {
                        if (a.IsIPv6LinkLocal) v6Link ??= a;
                        else if (!a.IsIPv6Multicast) v6 ??= a;
                    }
                }
                if (v4 is null) { v4 = v4Link; prefix4 = prefixLink; }
                // An IPv6 link-local address alone doesn't make an interface one to send through: every device the kernel
                // makes gets one. Android's ifb0-2 and dummy0 (traffic shaping, a black hole), macOS / iOS's utun0-3,
                // awdl0, llw0 and anpi0, a container's veth on Linux are all up with nothing else, and would fill the
                // pickers with names no one can use. A link-local target typed with its zone (fe80::1%eth1) still works.
                if (v4 is null && v6 is null) continue;

                int index = IndexOf(ni, props, v4 is not null);
                // A link-local source needs its zone on every system; .NET fills it in on Windows only.
                if (v6Link is { ScopeId: 0 } && index > 0) v6Link = new IPAddress(v6Link.GetAddressBytes(), index);

                string name = ni.Name;
                string description = string.IsNullOrWhiteSpace(ni.Description) ? name : ni.Description;
                int rank = loopback ? 9 : NicSnapshot.Rank(name, ni.NetworkInterfaceType, v4 ?? IPAddress.None);
                var dns = DnsOf(props, loopback, local, ref uplinks, out bool localOnly);
                list.Add((new NetIface(name, description, ni.Id, index, v4, v6, v6Link, loopback)
                {
                    Prefix4 = prefix4,
                    Mac = MacOf(ni),
                    DnsServers = dns,
                    DnsIsLocalOnly = localOnly,
                    Gateway4 = GatewayOf(props),
                }, rank));
            }
        }
        catch (Exception) { /* restricted platforms: no list, the tools keep the default route */ }
        return list.OrderBy(e => e.Rank).Select(e => e.Iface).ToArray();   // stable: ties keep the system's order
    }

    /// <summary>The interface saved as <paramref name="name"/>, if it is up now.</summary>
    public static NetIface? Find(string? name, bool withLoopback = false)
    {
        if (string.IsNullOrEmpty(name)) return null;
        foreach (var i in Up(withLoopback))
            if (string.Equals(i.Name, name, StringComparison.Ordinal)) return i;
        return null;
    }

    // Each of these is withheld on some platforms (Android, iOS): none of them may cost the interface its place in the list.
    private static string? MacOf(NetworkInterface ni)
    {
        try
        {
            byte[] mac = ni.GetPhysicalAddress().GetAddressBytes();
            if (mac.Length != 6) return null;
            string text = string.Join(":", mac.Select(b => b.ToString("X2")));
            return ScanOui.IsHostMac(text) && text != "02:00:00:00:00:00" ? text : null;   // Android's placeholder
        }
        catch (Exception) { return null; }
    }

    // Linux and macOS have one DNS list for the whole system, which .NET reports on every interface. Where that list is
    // a resolver on this computer itself (systemd-resolved's stub 127.0.0.53 on most desktop Linux, dnsmasq's 127.0.0.1,
    // WSL's address on its loopback device), a socket tied to another interface can't reach it: those entries are left
    // out, and on Linux the servers systemd-resolved forwards to take their place where it says what they are.
    private static IReadOnlyList<IPAddress> DnsOf(IPInterfaceProperties props, bool loopback, HashSet<IPAddress> local,
                                                  ref List<IPAddress>? uplinks, out bool localOnly)
    {
        localOnly = false;
        if (OperatingSystem.IsAndroid()) return Array.Empty<IPAddress>();   // not told to apps there (the call would throw)
        try
        {
            // (Windows lists the deprecated site-local fec0:0:0:ffff::1-3 on adapters that have no IPv6 DNS: not servers)
            var servers = props.DnsAddresses.Where(a => !a.IsIPv6SiteLocal).ToList();
            if (loopback || OperatingSystem.IsWindows() || servers.Count == 0) return servers;
            int before = servers.Count;
            servers.RemoveAll(a => IPAddress.IsLoopback(a) || local.Contains(a));
            if (servers.Count == before) return servers;
            if (servers.Count == 0)
            {
                uplinks ??= OperatingSystem.IsLinux() ? ResolvedUplinks(local) : new List<IPAddress>();
                servers.AddRange(uplinks);
                localOnly = servers.Count == 0;
            }
            return servers;
        }
        catch (Exception) { return Array.Empty<IPAddress>(); }
    }

    // The addresses of this computer's loopback interfaces (WSL puts its DNS relay's address on one).
    private static HashSet<IPAddress> LoopbackAddresses(NetworkInterface[] all)
    {
        var set = new HashSet<IPAddress>();
        foreach (var ni in all)
        {
            try
            {
                if (ni.NetworkInterfaceType != NetworkInterfaceType.Loopback) continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses) set.Add(ua.Address);
            }
            catch (Exception) { }
        }
        return set;
    }

    // The servers systemd-resolved forwards to: it keeps them in a file of resolv.conf's format for programs that ask
    // DNS servers themselves (systemd-resolved(8), "/run/systemd/resolve/resolv.conf").
    private static List<IPAddress> ResolvedUplinks(HashSet<IPAddress> local)
    {
        var list = new List<IPAddress>();
        try
        {
            const string file = "/run/systemd/resolve/resolv.conf";
            if (!System.IO.File.Exists(file)) return list;
            foreach (string line in System.IO.File.ReadLines(file))
            {
                var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2 || parts[0] != "nameserver") continue;
                // (an IPv6 server may carry its zone, "fe80::1%eth0": the query adds the chosen interface's own)
                if (!IPAddress.TryParse(parts[1].Split('%')[0], out var a) || IPAddress.IsLoopback(a) || local.Contains(a) || list.Contains(a)) continue;
                list.Add(a);
                if (list.Count == 6) break;
            }
        }
        catch (Exception) { }
        return list;
    }

    private static IPAddress? GatewayOf(IPInterfaceProperties props)
    {
        if (OperatingSystem.IsAndroid()) return null;   // as above
        try
        {
            return props.GatewayAddresses.Select(g => g.Address)
                        .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any));
        }
        catch (Exception) { return null; }
    }

    private static int IndexOf(NetworkInterface ni, IPInterfaceProperties props, bool hasV4)
    {
        if (!OperatingSystem.IsWindows()) return (int)NetIface.IndexOf(ni.Name);
        // Windows: the same number for both protocols, asked from the one the interface has
        try { if (hasV4) return props.GetIPv4Properties().Index; }
        catch (Exception) { }
        try { return props.GetIPv6Properties().Index; }
        catch (Exception) { return 0; }
    }
}
