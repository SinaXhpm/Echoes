using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Echoes.Helpers;
using Echoes.Tests.Support;

namespace Echoes.Tests;

/// <summary>
/// Choosing the interface a socket sends from, on this computer's own system: IP_UNICAST_IF and a bound address on
/// Windows, SO_BINDTODEVICE on Linux, IP_BOUND_IF on macOS. The loopback interface stands in for "an interface": a
/// socket tied to it reaches a listener on 127.0.0.1, and the listener sees where it came from.
/// </summary>
[Collection(Live.Collection)]
public class NetIfaceLiveTests
{
    [Fact]
    public void The_interfaces_that_are_up_are_listed_with_what_a_socket_needs()
    {
        var all = NetIfaces.Up(withLoopback: true);
        Assert.NotEmpty(all);
        foreach (var i in all)
        {
            Assert.False(string.IsNullOrWhiteSpace(i.Name));
            Assert.False(string.IsNullOrWhiteSpace(i.Description));
            Assert.False(string.IsNullOrWhiteSpace(i.Id));
            // a link-local address alone doesn't list an interface (Android's ifb0 / dummy0, macOS's utun0 / awdl0)
            Assert.True(i.V4 is not null || i.V6 is not null, $"{i.Name} is listed with no address beyond link-local");
            // the index is what Windows and macOS choose the interface by, and what a link-local address needs as its zone
            Assert.True(i.Index > 0, $"{i.Name} has no interface index");
            if (i.V4 is { } v4)
            {
                Assert.Equal(AddressFamily.InterNetwork, v4.AddressFamily);
                Assert.InRange(i.Prefix4, 0, 32);
            }
            if (i.V6 is { } v6) Assert.False(v6.IsIPv6LinkLocal);
            if (i.V6Link is { } link)
            {
                Assert.True(link.IsIPv6LinkLocal);
                Assert.Equal(i.Index, link.ScopeId);
            }
            if (i.Mac is { } mac) Assert.Matches("^([0-9A-F]{2}:){5}[0-9A-F]{2}$", mac);
            Assert.DoesNotContain(i.DnsServers, a => a.IsIPv6SiteLocal);
            // a resolver on this computer itself (127.0.0.53) can't be asked from another interface: it isn't listed for one
            if (!i.IsLoopback && !OperatingSystem.IsWindows()) Assert.DoesNotContain(i.DnsServers, IPAddress.IsLoopback);
            if (i.DnsIsLocalOnly) Assert.Empty(i.DnsServers);
            Assert.Contains(i.Name, i.Label);
            // ...and it is found again by its name, which is what a tool saves
            var again = NetIfaces.Find(i.Name, withLoopback: true);
            Assert.NotNull(again);
            Assert.Equal(i.Index, again!.Index);
        }
        Assert.Equal(all.Count, all.Select(i => i.Name).Distinct().Count());
    }

    [Fact]
    public void Loopback_is_listed_only_when_asked_for()
    {
        Assert.DoesNotContain(NetIfaces.Up(), i => i.IsLoopback);
        var lo = Live.Loopback();
        Assert.Equal(IPAddress.Loopback, lo.V4);
        Assert.Null(NetIfaces.Find(lo.Name));
        Assert.NotNull(NetIfaces.Find(lo.Name, withLoopback: true));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("echoes-no-such-interface")]
    public void A_name_that_is_no_interface_finds_nothing(string? name) => Assert.Null(NetIfaces.Find(name, withLoopback: true));

    [Fact]
    public void The_index_is_the_systems_own()
    {
        // asked a second way: Linux publishes it as a file; elsewhere .NET's own list has it (which on macOS comes from
        // another system call than the one NetIface makes)
        int compared = 0;
        foreach (var i in NetIfaces.Up(withLoopback: true))
        {
            int? index = null;
            string file = $"/sys/class/net/{i.Name}/ifindex";
            if (OperatingSystem.IsLinux() && File.Exists(file)) index = int.Parse(File.ReadAllText(file).Trim());
            else
            {
                var props = NetworkInterface.GetAllNetworkInterfaces().First(n => n.Name == i.Name).GetIPProperties();
                try { index = i.HasV4 ? props.GetIPv4Properties().Index : props.GetIPv6Properties().Index; }
                catch (Exception e) when (e is PlatformNotSupportedException or NetworkInformationException) { }
            }
            if (index is not { } known) continue;
            Assert.Equal(known, i.Index);
            compared++;
        }
        Assert.True(compared > 0, "no interface's index could be asked a second way");
        if (!OperatingSystem.IsWindows()) Assert.Equal(0u, NetIface.IndexOf("echoes-no-such-interface"));
    }

    // ------------------------------------------------------------------ a tied socket

    [Fact]
    public async Task A_udp_socket_tied_to_loopback_sends_from_it_and_hears_the_answer()
    {
        var lo = Live.LoopbackForSockets();
        using var deadline = Live.Deadline();
        using var server = Live.UdpListener(IPAddress.Loopback);
        using var client = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

        Assert.True(lo.TryBind(client, out string? note), note);
        // (a note here means an old Linux kernel let only root choose the device, and the source address was set instead)
        byte[] ping = "echoes-udp-ping"u8.ToArray(), pong = "echoes-udp-pong"u8.ToArray();
        await client.SendToAsync(ping, SocketFlags.None, server.LocalEndPoint!, deadline.Token);

        var buffer = new byte[64];
        var got = await server.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), deadline.Token);
        Assert.Equal(ping, buffer[..got.ReceivedBytes]);
        Assert.Equal(IPAddress.Loopback, ((IPEndPoint)got.RemoteEndPoint).Address);

        await server.SendToAsync(pong, SocketFlags.None, got.RemoteEndPoint, deadline.Token);
        int n = await client.ReceiveAsync(buffer, SocketFlags.None, deadline.Token);
        Assert.Equal(pong, buffer[..n]);
    }

    [Fact]
    public async Task A_tcp_socket_tied_to_loopback_connects_from_it()
    {
        var lo = Live.LoopbackForSockets();
        using var deadline = Live.Deadline();
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            Assert.True(lo.TryBind(client, out string? note), note);
            await client.ConnectAsync(listener.LocalEndpoint, deadline.Token);
            using var accepted = await listener.AcceptSocketAsync(deadline.Token);
            Assert.Equal(IPAddress.Loopback, ((IPEndPoint)accepted.RemoteEndPoint!).Address);

            await client.SendAsync("hello"u8.ToArray(), SocketFlags.None, deadline.Token);
            var buffer = new byte[16];
            int n = await accepted.ReceiveAsync(buffer, SocketFlags.None, deadline.Token);
            Assert.Equal("hello"u8.ToArray(), buffer[..n]);
        }
        finally { listener.Stop(); }
    }

    [Fact]
    public async Task Ipv6_sockets_are_tied_the_same_way()
    {
        var lo = Live.Loopback();
        Assert.SkipUnless(Socket.OSSupportsIPv6 && lo.V6 is not null, "the loopback interface has no IPv6 address here");
        using var deadline = Live.Deadline();
        using var server = Live.UdpListener(IPAddress.IPv6Loopback);
        using var client = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);

        Assert.True(lo.TryBind(client, out string? note), note);
        await client.SendToAsync("six"u8.ToArray(), SocketFlags.None, server.LocalEndPoint!, deadline.Token);
        var buffer = new byte[16];
        var got = await server.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.IPv6Any, 0), deadline.Token);
        Assert.Equal("six"u8.ToArray(), buffer[..got.ReceivedBytes]);
        Assert.Equal(IPAddress.IPv6Loopback, ((IPEndPoint)got.RemoteEndPoint).Address);
    }

    [Fact]
    public void An_interface_that_is_not_there_is_refused_with_a_reason()
    {
        // a name and an index no system has, and an address that is nobody's (TEST-NET-1)
        var gone = new NetIface("echoes-none0", "gone", "{00000000-0000-0000-0000-000000000000}", 987654, IPAddress.Parse("192.0.2.77"), null, null, false) { Prefix4 = 24 };
        foreach (var (family, type, protocol) in new[]
                 {
                     (AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp),
                     (AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp),
                 })
        {
            using var socket = new Socket(family, type, protocol);
            Assert.False(gone.TryBind(socket, out string? note));
            Assert.False(string.IsNullOrWhiteSpace(note));
            Assert.Contains("echoes-none0", note);
            Assert.False(gone.TryBindMulticast(socket, out note));
            Assert.False(string.IsNullOrWhiteSpace(note));
        }
    }

    [Fact]
    public void A_socket_that_cannot_be_tied_is_a_no_not_an_exception()
    {
        var lo = Live.Loopback();
        var closed = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        closed.Dispose();
        Assert.False(lo.TryBind(closed, out string? note));
        Assert.False(string.IsNullOrWhiteSpace(note));

        // an interface with no address of the socket's kind
        var noV4 = lo with { V4 = null };
        if (OperatingSystem.IsWindows())
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            Assert.False(noV4.TryBind(socket, out note));
            Assert.Contains("has no IPv4 address", note);
        }
        using var multicast = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        Assert.False(noV4.TryBindMulticast(multicast, out note));
        Assert.Contains("has no IPv4 address", note);
    }

    [Fact]
    public void A_socket_for_multicast_names_the_interface_it_sends_from()
    {
        var nic = Live.Network();
        var system = NetworkInterface.GetAllNetworkInterfaces().First(n => n.Name == nic.Name);
        Assert.SkipUnless(system.SupportsMulticast, $"{nic.Name} doesn't do multicast");
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        Assert.True(nic.TryBindMulticast(socket, out string? note), note);
        // what the socket itself now says: multicast leaves from this interface's address
        var chosen = (byte[])socket.GetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, 4);
        Assert.Equal(nic.V4, new IPAddress(chosen));
    }

    // ------------------------------------------------------------------ TCP ping

    [Fact]
    public async Task Tcp_ping_from_loopback_tells_an_open_port_from_a_closed_one()
    {
        var lo = Live.LoopbackForSockets();
        using var deadline = Live.Deadline();
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            int open = ((IPEndPoint)listener.LocalEndpoint).Port;
            var connected = await TcpPinger.ConnectAsync(IPAddress.Loopback, open, 5000, deadline.Token, lo);
            Assert.True(connected.Success, $"{connected.Status}: {connected.Detail}");

            int closed = Live.ClosedTcpPort(IPAddress.Loopback);
            var refused = await TcpPinger.ConnectAsync(IPAddress.Loopback, closed, 5000, deadline.Token, lo);
            Assert.Equal(TcpPinger.Status.Refused, refused.Status);
        }
        finally { listener.Stop(); }
    }

    [Fact]
    public async Task Tcp_ping_from_an_interface_without_that_kind_of_address_never_leaves()
    {
        var lo = Live.Loopback();
        using var deadline = Live.Deadline();
        var v4Only = lo with { V6 = null, V6Link = null };
        var r = await TcpPinger.ConnectAsync(IPAddress.IPv6Loopback, 9, 2000, deadline.Token, v4Only);
        Assert.Equal(TcpPinger.Status.LocalError, r.Status);
        Assert.Equal(lo.Name + " has no IPv6 address", r.Detail);
    }
}
