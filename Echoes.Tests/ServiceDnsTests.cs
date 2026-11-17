using System.Net;
using System.Net.Sockets;
using Echoes.Helpers;

namespace Echoes.Tests;

/// <summary>Which answers ServiceDns takes for a service's name, and the order a measured connection (the Speed Test's)
/// tries the addresses in (no network).</summary>
public class ServiceDnsTests
{
    [Theory]
    // an IPv6-only network's DNS64 answers an IPv4-only name (github.com) with NAT64 addresses: the service's own
    [InlineData("64:ff9b::808:808", true)]
    [InlineData("64:ff9b::8c52:7004", true)]
    [InlineData("64:ff9b:1::808:808", true)]        // a local-use NAT64 prefix
    [InlineData("1.1.1.1", true)]
    [InlineData("2606:4700:4700::1111", true)]
    // a filter's, private or loopback address stays a blocking resolver's answer, inside NAT64 too
    [InlineData("64:ff9b::a0a:2223", false)]        // 10.10.34.35
    [InlineData("64:ff9b::c0a8:101", false)]        // 192.168.1.1
    [InlineData("64:ff9b::7f00:1", false)]          // 127.0.0.1
    [InlineData("10.10.34.35", false)]
    [InlineData("100.64.0.1", false)]               // a carrier's NAT inside: no service has one
    [InlineData("0.0.0.0", false)]
    [InlineData("::", false)]
    [InlineData("::1", false)]
    [InlineData("fd00::1", false)]
    [InlineData("::ffff:10.0.0.1", false)]
    public void A_service_address_is_usable_only_when_it_is_on_the_internet(string address, bool usable)
        => Assert.Equal(usable, ServiceDns.Usable(IPAddress.Parse(address)));

    private static IPAddress[] Ips(params string[] s) => s.Select(IPAddress.Parse).ToArray();
    private static string[] Text(IEnumerable<IPAddress> a) => a.Select(x => x.ToString()).ToArray();

    [Fact]
    public void A_measured_connection_keeps_the_systems_order_with_the_families_taking_turns()
    {
        var order = new ServiceDns.MeasuredOrder();
        // the system prefers IPv6 (most dual-stack networks): IPv6 first, never two IPv6 attempts before an IPv4 one
        Assert.Equal(new[] { "2606:4700::1", "104.16.1.1", "2606:4700::2", "104.16.1.2" },
                     Text(order.Of(Ips("2606:4700::1", "2606:4700::2", "104.16.1.1", "104.16.1.2"))));
        // an answer that puts IPv4 first (a DoH answer, or a system that prefers it) stays so
        Assert.Equal(new[] { "104.16.1.1", "2606:4700::1", "104.16.1.2" },
                     Text(order.Of(Ips("104.16.1.1", "104.16.1.2", "2606:4700::1"))));
        Assert.Empty(order.Of(Array.Empty<IPAddress>()));
    }

    [Fact]
    public void After_a_connection_got_through_its_family_goes_first()
    {
        var order = new ServiceDns.MeasuredOrder();
        var answer = Ips("2606:4700::1", "2606:4700::2", "104.16.1.1", "104.16.1.2");
        order.GotThrough(IPAddress.Parse("104.16.1.1"));   // the IPv6 attempt didn't connect, IPv4 did
        Assert.Equal(new[] { "104.16.1.1", "2606:4700::1", "104.16.1.2", "2606:4700::2" }, Text(order.Of(answer)));
        // an answer without that family keeps its own order
        Assert.Equal(new[] { "2606:4700::1", "2606:4700::2" }, Text(order.Of(Ips("2606:4700::1", "2606:4700::2"))));
        order.GotThrough(IPAddress.Parse("2606:4700::2"));
        Assert.Equal(AddressFamily.InterNetworkV6, order.Of(answer).First().AddressFamily);
    }
}
