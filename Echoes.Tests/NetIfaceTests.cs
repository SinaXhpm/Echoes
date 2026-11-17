using System.Net;
using System.Net.Sockets;
using Echoes.Helpers;

namespace Echoes.Tests;

/// <summary>What an interface record works out by itself (no sockets): its subnet, which of its addresses a probe
/// leaves from, how it is written.</summary>
public class NetIfaceTests
{
    private static NetIface Make(string name = "eth0", string? v4 = "192.168.1.20", int prefix = 24, string? v6 = null, string? v6Link = null,
                                 int index = 3, bool loopback = false)
        => new(name, name, name, index, v4 is null ? null : IPAddress.Parse(v4), v6 is null ? null : IPAddress.Parse(v6),
               v6Link is null ? null : new IPAddress(IPAddress.Parse(v6Link).GetAddressBytes(), index), loopback) { Prefix4 = prefix };

    // ------------------------------------------------------------------ the subnet to sweep

    [Fact]
    public void A_slash_24_gives_its_254_hosts()
    {
        var net = Make().Subnet4(1022, out bool whole);
        Assert.NotNull(net);
        Assert.True(whole);
        Assert.Equal(IPAddress.Parse("192.168.1.0"), net!.Value.Network);
        Assert.Equal(24, net.Value.Prefix);
        Assert.Equal(254, net.Value.Hosts.Count);
        Assert.Equal(IPAddress.Parse("192.168.1.1"), net.Value.Hosts[0]);
        Assert.Equal(IPAddress.Parse("192.168.1.254"), net.Value.Hosts[^1]);
        Assert.Contains(IPAddress.Parse("192.168.1.20"), net.Value.Hosts);   // this device's own address is one of them
    }

    [Theory]
    [InlineData("10.1.2.3", 30, "10.1.2.0", 2)]
    [InlineData("10.1.2.3", 29, "10.1.2.0", 6)]
    [InlineData("172.16.5.9", 22, "172.16.4.0", 1022)]
    [InlineData("192.168.1.200", 25, "192.168.1.128", 126)]
    public void Small_networks_are_swept_whole(string address, int prefix, string network, int hosts)
    {
        var net = Make(v4: address, prefix: prefix).Subnet4(1022, out bool whole);
        Assert.True(whole);
        Assert.Equal(IPAddress.Parse(network), net!.Value.Network);
        Assert.Equal(prefix, net.Value.Prefix);
        Assert.Equal(hosts, net.Value.Hosts.Count);
    }

    [Theory]
    [InlineData("10.20.30.40", 8, "10.20.28.0")]
    [InlineData("172.16.200.9", 16, "172.16.200.0")]
    [InlineData("127.0.0.1", 8, "127.0.0.0")]
    [InlineData("100.64.3.200", 10, "100.64.0.0")]
    public void A_big_network_gives_the_block_around_this_device(string address, int prefix, string block)
    {
        var net = Make(v4: address, prefix: prefix).Subnet4(1022, out bool whole);
        Assert.False(whole);
        Assert.Equal(22, net!.Value.Prefix);
        Assert.Equal(IPAddress.Parse(block), net.Value.Network);
        Assert.Equal(1022, net.Value.Hosts.Count);
        Assert.Contains(IPAddress.Parse(address), net.Value.Hosts);
        Assert.Equal(net.Value.Hosts.Count, net.Value.Hosts.Distinct().Count());
    }

    [Theory]
    [InlineData(254, 24)]
    [InlineData(253, 25)]
    [InlineData(2, 30)]
    [InlineData(1, 30)]     // never smaller than a /30
    public void The_limit_decides_how_much_of_a_big_network_is_swept(int max, int prefix)
    {
        var net = Make(v4: "10.0.0.77", prefix: 16).Subnet4(max, out bool whole);
        Assert.False(whole);
        Assert.Equal(prefix, net!.Value.Prefix);
    }

    [Theory]
    [InlineData("192.168.1.20", 31)]    // a point-to-point link: no other hosts
    [InlineData("192.168.1.20", 32)]
    [InlineData("192.168.1.20", 0)]     // the prefix isn't known
    [InlineData(null, 24)]
    public void A_network_with_nothing_to_sweep_gives_none(string? address, int prefix)
    {
        Assert.Null(Make(v4: address, prefix: prefix).Subnet4(1022, out _));
    }

    [Theory]
    [InlineData("192.168.1.1", true)]
    [InlineData("192.168.1.255", true)]
    [InlineData("192.168.2.1", false)]
    [InlineData("8.8.8.8", false)]
    [InlineData("fe80::1", false)]
    public void On_link_means_inside_the_ipv4_subnet(string address, bool expected)
        => Assert.Equal(expected, Make().OnLink4(IPAddress.Parse(address)));

    [Fact]
    public void On_link_needs_an_address_and_a_prefix()
    {
        Assert.False(Make(v4: null).OnLink4(IPAddress.Parse("192.168.1.1")));
        Assert.False(Make(prefix: 0).OnLink4(IPAddress.Parse("192.168.1.1")));
        Assert.True(Make(prefix: 32).OnLink4(IPAddress.Parse("192.168.1.20")));
        Assert.False(Make(prefix: 32).OnLink4(IPAddress.Parse("192.168.1.21")));
    }

    // ------------------------------------------------------------------ addresses

    [Fact]
    public void A_probe_leaves_from_the_address_of_the_targets_kind()
    {
        var both = Make(v6: "2001:db8::20", v6Link: "fe80::20");
        Assert.Equal(IPAddress.Parse("192.168.1.20"), both.SourceFor(IPAddress.Parse("1.1.1.1")));
        Assert.Equal(IPAddress.Parse("2001:db8::20"), both.SourceFor(IPAddress.Parse("2606:4700::1111")));
        // a link-local target is reached from the link-local address, and the other way round where one is missing
        Assert.True(both.SourceFor(IPAddress.Parse("fe80::1"))!.IsIPv6LinkLocal);
        Assert.True(Make(v6Link: "fe80::20").SourceFor(IPAddress.Parse("2606:4700::1111"))!.IsIPv6LinkLocal);
        Assert.Equal(IPAddress.Parse("2001:db8::20"), Make(v6: "2001:db8::20").SourceFor(IPAddress.Parse("fe80::1")));
    }

    [Fact]
    public void A_missing_address_is_said_in_words()
    {
        var v4Only = Make(name: "Wi-Fi");
        Assert.Null(v4Only.Missing(IPAddress.Parse("1.1.1.1")));
        Assert.Equal("Wi-Fi has no IPv6 address", v4Only.Missing(IPAddress.Parse("2606:4700::1111")));
        var v6Only = Make(name: "tun0", v4: null, v6: "2001:db8::20");
        Assert.Equal("tun0 has no IPv4 address", v6Only.Missing(IPAddress.Parse("1.1.1.1")));
        Assert.Null(v6Only.Missing(IPAddress.Parse("2606:4700::1111")));
    }

    [Fact]
    public void A_name_with_both_kinds_of_address_is_asked_for_the_kind_the_interface_has()
    {
        Assert.Equal(IpPreference.Auto, Make().Prefer(IpPreference.Auto));
        Assert.Equal(IpPreference.IPv6, Make(v4: null, v6: "2001:db8::20").Prefer(IpPreference.Auto));
        Assert.Equal(IpPreference.IPv6, Make(v4: null, v6Link: "fe80::20").Prefer(IpPreference.Auto));
        // what the user asked for outright stays (the run then says the interface has no such address)
        Assert.Equal(IpPreference.IPv4, Make(v4: null, v6: "2001:db8::20").Prefer(IpPreference.IPv4));
        Assert.Equal(IpPreference.IPv6, Make().Prefer(IpPreference.IPv6));
    }

    [Fact]
    public void A_link_local_target_without_a_zone_gets_the_interfaces()
    {
        var iface = Make(index: 7, v6Link: "fe80::20");
        var scoped = iface.Scoped(IPAddress.Parse("fe80::1"));
        Assert.Equal(7, scoped.ScopeId);
        Assert.Equal(IPAddress.Parse("fe80::1").GetAddressBytes(), scoped.GetAddressBytes());
        // a zone that was typed stays, and other addresses are not touched
        Assert.Equal(4, iface.Scoped(new IPAddress(IPAddress.Parse("fe80::1").GetAddressBytes(), 4)).ScopeId);
        Assert.Equal(0, iface.Scoped(IPAddress.Parse("2001:db8::1")).ScopeId);
        Assert.Equal(IPAddress.Parse("10.0.0.1"), iface.Scoped(IPAddress.Parse("10.0.0.1")));
        Assert.Equal(0, Make(index: 0).Scoped(IPAddress.Parse("fe80::1")).ScopeId);
    }

    [Fact]
    public void The_label_shows_the_name_and_one_address_without_a_zone()
    {
        Assert.Equal("eth0 · 192.168.1.20", Make(v6: "2001:db8::20").Label);
        Assert.Equal("eth0 · 2001:db8::20", Make(v4: null, v6: "2001:db8::20").Label);
        Assert.Equal("eth0 · fe80::20", Make(v4: null, v6Link: "fe80::20").Label);
        Assert.Equal("eth0", Make(v4: null).Label);
        Assert.True(Make().HasV4);
        Assert.False(Make().HasV6);
        Assert.True(Make(v4: null, v6Link: "fe80::20").HasV6);
    }

    // ------------------------------------------------------------------ messages

    [Fact]
    public void A_reason_becomes_a_sentence_and_an_interface_name_keeps_its_case()
    {
        var eth0 = Make();
        Assert.Equal("There is no route to 1.1.1.1 from eth0.", NetIfaceException.From(eth0, "there is no route to 1.1.1.1 from eth0").Message);
        Assert.Equal("eth0 has no IPv6 address.", NetIfaceException.From(eth0, "eth0 has no IPv6 address").Message);
        Assert.Equal("Already a sentence.", NetIfaceException.From(eth0, "Already a sentence.").Message);
        var inner = new SocketException((int)SocketError.NetworkUnreachable);
        Assert.Same(inner, NetIfaceException.From(eth0, "x", inner).InnerException);
        Assert.IsAssignableFrom<IOException>(NetIfaceException.From(eth0, "x"));
    }

    [Fact]
    public void Only_errors_the_interface_explains_are_blamed_on_it()
    {
        var eth0 = Make();
        Assert.Equal("there is no route to example.com from eth0", eth0.ConnectProblem(SocketError.NetworkUnreachable, "example.com"));
        Assert.Equal("there is no route to example.com from eth0", eth0.ConnectProblem(SocketError.HostUnreachable, "example.com"));
        Assert.Equal("there is no route to example.com from eth0", eth0.ConnectProblem(SocketError.NetworkDown, "example.com"));
        // the target's own answers are the target's
        Assert.Null(eth0.ConnectProblem(SocketError.ConnectionRefused, "example.com"));
        Assert.Null(eth0.ConnectProblem(SocketError.TimedOut, "example.com"));
        // "address not available" means a redirecting program only on Windows
        Assert.Equal(OperatingSystem.IsWindows(), eth0.ConnectProblem(SocketError.AddressNotAvailable, "example.com") is not null);
    }

    // ------------------------------------------------------------------ packet addresses

    [Theory]
    [InlineData("10.1.2.3")]
    [InlineData("255.255.255.255")]
    [InlineData("0.0.0.0")]
    [InlineData("2001:db8::1")]
    [InlineData("fe80::dead:beef:1:2")]
    [InlineData("::")]
    [InlineData("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")]
    public void An_address_key_gives_its_address_back(string text)
    {
        var address = IPAddress.Parse(text);
        var key = IpKey.Of(address);
        Assert.Equal(address, key.ToAddress());
        Assert.Equal(address.AddressFamily == AddressFamily.InterNetworkV6, key.V6);
    }

    [Theory]
    [InlineData("10.1.2.3", "10.0.0.0", 8, true)]
    [InlineData("11.1.2.3", "10.0.0.0", 8, false)]
    [InlineData("10.1.2.3", "10.1.2.3", 32, true)]
    [InlineData("10.1.2.4", "10.1.2.3", 32, false)]
    [InlineData("10.1.2.3", "10.1.2.2", 31, true)]
    [InlineData("200.1.2.3", "128.0.0.0", 1, true)]
    [InlineData("100.1.2.3", "128.0.0.0", 1, false)]
    [InlineData("200.1.2.3", "9.9.9.9", 0, true)]
    [InlineData("2001:db8::1", "2001:db8::", 32, true)]
    [InlineData("2001:db9::1", "2001:db8::", 32, false)]
    [InlineData("2001:db8:0:1::5", "2001:db8:0:1::", 64, true)]
    [InlineData("2001:db8:0:2::5", "2001:db8:0:1::", 64, false)]
    [InlineData("2001:db8::8000:0:0:1", "2001:db8::8000:0:0:0", 65, true)]
    [InlineData("2001:db8::1", "2001:db8::8000:0:0:0", 65, false)]
    [InlineData("2001:db8::1", "2001:db8::", 127, true)]
    [InlineData("2001:db8::2", "2001:db8::", 127, false)]
    [InlineData("2001:db8::1", "2001:db8::1", 128, true)]
    [InlineData("2001:db8::2", "2001:db8::1", 128, false)]
    [InlineData("2001:db8::1", "::", 0, true)]
    [InlineData("10.1.2.3", "::", 0, false)]              // never across the two kinds
    [InlineData("::ffff:10.1.2.3", "10.0.0.0", 8, false)]
    public void An_address_is_inside_a_network_by_its_prefix(string address, string network, int prefix, bool expected)
        => Assert.Equal(expected, IpKey.Of(IPAddress.Parse(address)).In(IpKey.Of(IPAddress.Parse(network)), prefix));
}
