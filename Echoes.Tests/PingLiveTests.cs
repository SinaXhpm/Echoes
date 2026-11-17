using System.Net;
using System.Net.Sockets;
using Echoes.Helpers;
using Echoes.Tests.Support;

namespace Echoes.Tests;

/// <summary>Ping from a chosen interface, on this system's own path: IcmpSendEcho2Ex with a source address on
/// Windows, a tied ICMP datagram socket on Linux and macOS, and the UDP probe everywhere.</summary>
[Collection(Live.Collection)]
public class PingLiveTests
{
    private static string Why(IcmpPinger.PingResult r) => $"{r.Method}: {r.Error} (not sent: {r.NotSent}, permission denied: {r.PermissionDenied})";

    [Fact]
    public async Task A_ping_from_the_loopback_interface_is_answered()
    {
        var lo = Live.Loopback();
        using var deadline = Live.Deadline(30);
        // without an interface first: where this user can't ping at all, there is nothing to compare with
        var plain = await IcmpPinger.SendAsync(IPAddress.Loopback, 3000, deadline.Token);
        Assert.SkipUnless(plain.Success, $"this user can't ping here at all ({plain.Error})");

        // the Ping tab's probe (with its packet settings)...
        var r = await IcmpPinger.SendAsync(IPAddress.Loopback, 3000, new IcmpProbeOptions(Via: lo), deadline.Token);
        Assert.True(r.Success, Why(r));
        Assert.False(r.NotSent);
        Assert.Equal(IPAddress.Loopback, r.Address);

        // ...and the classic one, which traceroute and MTR send (here with a hop limit of one, as their first probe has)
        var classic = await IcmpPinger.SendAsync(IPAddress.Loopback, 3000, deadline.Token, via: lo);
        Assert.True(classic.Success, Why(classic));
        var firstHop = await IcmpPinger.SendAsync(IPAddress.Loopback, 3000, deadline.Token, ttl: 1, via: lo);
        Assert.True(firstHop.Success, Why(firstHop));
    }

    [Fact]
    public async Task A_bigger_ping_from_the_loopback_interface_is_answered()
    {
        var lo = Live.Loopback();
        using var deadline = Live.Deadline(30);
        var plain = await IcmpPinger.SendAsync(IPAddress.Loopback, 3000, new IcmpProbeOptions(PayloadSize: 1200), deadline.Token, PingMethod.Icmp);
        Assert.SkipUnless(plain.Success, $"ICMP itself isn't permitted for this user here ({plain.Error})");

        var r = await IcmpPinger.SendAsync(IPAddress.Loopback, 3000, new IcmpProbeOptions(PayloadSize: 1200, Via: lo), deadline.Token, PingMethod.Icmp);
        // Linux with its ICMP ping sockets turned off (net.ipv4.ping_group_range "1 0": minimal systems, containers)
        // still pings without an interface, through the system's ping program or a root's raw socket; neither can be
        // told which interface to use. That is said, and the automatic method sends its UDP probe instead (the test
        // above). Anything else that is refused is a failure.
        Assert.SkipWhen(OperatingSystem.IsLinux() && r.PermissionDenied && plain.Success,
                        $"ICMP ping sockets are off on this system, so ICMP can't be sent from a chosen interface ({r.Error})");
        Assert.True(r.Success, Why(r));
        Assert.Equal(PingMethod.Icmp, r.Method);
        // the size is applied wherever it was without an interface
        Assert.Equal(plain.Applied.HasFlag(IcmpApplied.Size), r.Applied.HasFlag(IcmpApplied.Size));
    }

    [Fact]
    public async Task A_udp_probe_from_the_loopback_interface_is_answered_by_the_closed_port()
    {
        var lo = Live.Loopback();
        using var deadline = Live.Deadline(30);
        int port;
        using (var free = Live.UdpListener(IPAddress.Loopback)) port = ((IPEndPoint)free.LocalEndPoint!).Port;   // closed again: nothing listens there

        var plain = await IcmpPinger.SendAsync(IPAddress.Loopback, 3000, new IcmpProbeOptions(), deadline.Token, PingMethod.Udp, port);
        Assert.SkipUnless(plain.Success, $"a closed UDP port isn't reported to its sender here ({plain.Error})");

        var r = await IcmpPinger.SendAsync(IPAddress.Loopback, 3000, new IcmpProbeOptions(Via: lo), deadline.Token, PingMethod.Udp, port);
        Assert.True(r.Success, Why(r));
        Assert.Equal(PingMethod.Udp, r.Method);
        Assert.False(r.NotSent);
    }

    [Fact]
    public async Task Ipv6_ping_from_the_loopback_interface_is_answered()
    {
        var lo = Live.Loopback();
        Assert.SkipUnless(Socket.OSSupportsIPv6 && lo.V6 is not null, "the loopback interface has no IPv6 address here");
        using var deadline = Live.Deadline(30);
        var plain = await IcmpPinger.SendAsync(IPAddress.IPv6Loopback, 3000, deadline.Token);
        Assert.SkipUnless(plain.Success, $"this user can't ping over IPv6 here at all ({plain.Error})");

        var r = await IcmpPinger.SendAsync(IPAddress.IPv6Loopback, 3000, new IcmpProbeOptions(Via: lo), deadline.Token);
        Assert.True(r.Success, Why(r));
        Assert.Equal(IPAddress.IPv6Loopback, r.Address);
    }

    [Theory]
    [InlineData(PingMethod.Auto)]
    [InlineData(PingMethod.Icmp)]
    [InlineData(PingMethod.Udp)]
    public async Task A_probe_from_an_interface_without_that_kind_of_address_never_leaves(PingMethod method)
    {
        var lo = Live.Loopback();
        using var deadline = Live.Deadline();
        var v4Only = lo with { V6 = null, V6Link = null };
        var r = await IcmpPinger.SendAsync(IPAddress.IPv6Loopback, 2000, new IcmpProbeOptions(Via: v4Only), deadline.Token, method);
        Assert.False(r.Success);
        Assert.True(r.NotSent, Why(r));
        Assert.Equal(lo.Name + " has no IPv6 address", r.Error);

        var v6Only = lo with { V4 = null };
        var classic = await IcmpPinger.SendAsync(IPAddress.Loopback, 2000, deadline.Token, method: method, via: v6Only);
        Assert.True(classic.NotSent, Why(classic));
        Assert.Equal(lo.Name + " has no IPv4 address", classic.Error);
    }

    [Fact]
    public async Task A_probe_from_an_interface_that_is_gone_never_leaves_and_says_why()
    {
        var gone = new NetIface("echoes-none0", "gone", "{00000000-0000-0000-0000-000000000000}", 987654, IPAddress.Parse("192.0.2.77"), null, null, false) { Prefix4 = 24 };
        using var deadline = Live.Deadline();
        foreach (var method in new[] { PingMethod.Icmp, PingMethod.Udp })
        {
            var r = await IcmpPinger.SendAsync(IPAddress.Loopback, 1500, new IcmpProbeOptions(Via: gone), deadline.Token, method);
            Assert.False(r.Success, "a probe was answered although its interface doesn't exist");
            Assert.False(string.IsNullOrWhiteSpace(r.Error));
            // not sent, or (where this user may not open the socket at all) refused: never a plain timeout
            Assert.True(r.NotSent || r.PermissionDenied, Why(r));
        }
    }
}
