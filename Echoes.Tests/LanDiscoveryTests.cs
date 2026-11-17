using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Text;
using Echoes.Helpers;
using Echoes.Tests.Support;

namespace Echoes.Tests;

/// <summary>The device finder's readers of what devices send back (mDNS, SSDP, UPnP descriptions, NetBIOS): the
/// right names out of well-formed replies, and nothing but an empty result out of damaged ones.</summary>
public class LanDiscoveryParserTests
{
    private static byte[] U16(int v) => new[] { (byte)(v >> 8), (byte)v };

    // A DNS record with its owner written out (no compression).
    private static byte[] Rr(string name, int type, byte[] data)
        => Frames.Join(Frames.DnsName(name), U16(type), U16(1), new byte[] { 0, 0, 0, 120 }, U16(data.Length), data);

    private static byte[] Message(int questions, params byte[][] records)
        => Frames.Join(new byte[] { 0, 0, 0x84, 0 }, U16(questions), U16(records.Length), U16(0), U16(0), Frames.Join(records));

    [Fact]
    public void A_question_is_one_name_one_type_and_the_unicast_bit_when_asked()
    {
        var q = LanDiscovery.Question("_services._dns-sd._udp.local", 12, 0x1234, unicastReply: true);
        Assert.Equal(new byte[] { 0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 }, q[..12]);
        Assert.Equal(Frames.DnsName("_services._dns-sd._udp.local"), q[12..^4]);
        Assert.Equal(new byte[] { 0, 12, 0x80, 1 }, q[^4..]);
        Assert.Equal(new byte[] { 0, 1, 0x00, 1 }, LanDiscovery.Question("host.local", 1, 0, unicastReply: false)[^4..]);
        // a name DNS can't carry still gives a message (the root), never an exception
        Assert.NotEmpty(LanDiscovery.Question(new string('x', 300), 12, 0, false));
    }

    [Fact]
    public void An_mdns_answer_gives_its_addresses_pointers_and_services()
    {
        var srv = Frames.Join(U16(0), U16(0), U16(7000), Frames.DnsName("living-room.local"));
        var m = Message(0,
            Rr("_services._dns-sd._udp.local", 12, Frames.DnsName("_airplay._tcp.local")),
            Rr("_airplay._tcp.local", 12, Frames.DnsName("Living Room TV._airplay._tcp.local")),
            Rr("Living Room TV._airplay._tcp.local", 33, srv),
            Rr("living-room.local", 1, new byte[] { 192, 168, 1, 30 }),
            Rr("living-room.local", 28, IPAddress.Parse("fe80::1").GetAddressBytes()),
            Rr("30.1.168.192.in-addr.arpa", 12, Frames.DnsName("living-room.local")));
        var records = LanDiscovery.Records(m);
        Assert.Equal(6, records.Count);
        Assert.Equal("_airplay._tcp.local", records[0].Target);
        Assert.Equal("Living Room TV._airplay._tcp.local", records[1].Target);
        Assert.Equal(33, records[2].Type);
        Assert.Equal("living-room.local", records[2].Target);
        Assert.Equal(IPAddress.Parse("192.168.1.30"), records[3].Address);
        Assert.Null(records[4].Address);   // only IPv4 addresses are used
        Assert.Equal("30.1.168.192.in-addr.arpa", records[5].Name);
        Assert.Equal("living-room.local", records[5].Target);
    }

    [Fact]
    public void Records_after_a_question_and_with_compressed_names_are_read()
    {
        // a question for host.local, then an A record whose owner points back at it
        var m = Frames.Join(new byte[] { 0, 0, 0x84, 0, 0, 1, 0, 1, 0, 0, 0, 0 }, Frames.DnsName("host.local"), new byte[] { 0, 1, 0, 1 },
                            Frames.DnsRecord(1, new byte[] { 10, 0, 0, 7 }));
        var records = LanDiscovery.Records(m);
        var only = Assert.Single(records);
        Assert.Equal("host.local", only.Name);
        Assert.Equal(IPAddress.Parse("10.0.0.7"), only.Address);
    }

    [Fact]
    public void A_damaged_answer_gives_what_came_before_the_damage()
    {
        var good = Rr("a.local", 1, new byte[] { 10, 0, 0, 1 });
        var whole = Message(0, good, Rr("b.local", 1, new byte[] { 10, 0, 0, 2 }));
        for (int length = 0; length <= whole.Length; length++)
        {
            var records = LanDiscovery.Records(whole.AsSpan(0, length));
            Assert.InRange(records.Count, 0, 2);
            if (length < 12 + good.Length) Assert.Empty(records);
        }
        // counts no real answer has are not walked at all
        Assert.Empty(LanDiscovery.Records(new byte[] { 0, 0, 0x84, 0, 0xFF, 0xFF, 0, 1, 0, 0, 0, 0, 0 }));
        Assert.Empty(LanDiscovery.Records(new byte[] { 0, 0, 0x84, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0 }));

        var random = new Random(9);
        for (int i = 0; i < 20_000; i++)
        {
            var bytes = (byte[])whole.Clone();
            for (int c = random.Next(1, 5); c > 0; c--) bytes[random.Next(bytes.Length)] = (byte)random.Next(256);
            foreach (var r in LanDiscovery.Records(bytes)) Assert.NotNull(r.Name);
        }
    }

    [Theory]
    [InlineData("20.1.168.192.in-addr.arpa", "192.168.1.20")]
    [InlineData("1.0.0.10.IN-ADDR.ARPA", "10.0.0.1")]
    [InlineData("255.255.255.255.in-addr.arpa", "255.255.255.255")]
    public void A_reverse_name_is_read_back_into_its_address(string name, string address)
        => Assert.Equal(IPAddress.Parse(address), LanDiscovery.ArpaAddress(name));

    [Theory]
    [InlineData("")]
    [InlineData("in-addr.arpa")]
    [InlineData("1.168.192.in-addr.arpa")]
    [InlineData("256.1.168.192.in-addr.arpa")]
    [InlineData("a.b.c.d.in-addr.arpa")]
    [InlineData("-1.1.168.192.in-addr.arpa")]
    public void What_is_not_a_reverse_ipv4_name_gives_no_address(string name) => Assert.Null(LanDiscovery.ArpaAddress(name));

    [Theory]
    [InlineData("_airplay._tcp.local", "AirPlay")]
    [InlineData("_googlecast._tcp.local", "Chromecast")]
    [InlineData("_ipp._tcp.local", "Printer")]
    [InlineData("_smb._tcp.local", "File sharing (SMB)")]
    [InlineData("_SSH._tcp.local", "SSH")]
    [InlineData("_my-own-thing._udp.local", "my-own-thing")]
    public void A_service_type_is_named_in_words(string type, string label) => Assert.Equal(label, LanDiscovery.ServiceLabel(type));

    [Fact]
    public void A_service_type_no_table_knows_is_cleaned_and_cut()
    {
        string label = LanDiscovery.ServiceLabel("_" + new string('x', 200) + "\u001b[31m._tcp.local");
        Assert.True(label.Length <= 33);
        Assert.DoesNotContain('\u001b', label);
    }

    private const string SsdpReply =
        "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLocation: http://192.168.1.1:5000/rootDesc.xml\r\n"
        + "SERVER: Linux/5.10 UPnP/1.1 MiniUPnPd/2.2\r\nST: upnp:rootdevice\r\nUSN:uuid:1234::upnp:rootdevice\r\n\r\n";

    [Fact]
    public void An_ssdp_header_is_found_whatever_its_case_and_spacing()
    {
        Assert.Equal("http://192.168.1.1:5000/rootDesc.xml", LanDiscovery.Header(SsdpReply, "LOCATION"));
        Assert.Equal("Linux/5.10 UPnP/1.1 MiniUPnPd/2.2", LanDiscovery.Header(SsdpReply, "server"));
        Assert.Equal("uuid:1234::upnp:rootdevice", LanDiscovery.Header(SsdpReply, "USN"));
        Assert.Null(LanDiscovery.Header(SsdpReply, "NT"));
        Assert.Null(LanDiscovery.Header(SsdpReply, "LOC"));        // a header whose name only starts the same
        Assert.Null(LanDiscovery.Header(string.Empty, "LOCATION"));
    }

    [Fact]
    public void An_ssdp_header_is_cleaned_and_cut()
    {
        string hostile = "SERVER: evil\u001b[2J\u202Etxt." + new string('A', 5000) + "\r\n";
        string value = LanDiscovery.Header(hostile, "SERVER")!;
        Assert.DoesNotContain('\u001b', value);
        Assert.DoesNotContain('\u202E', value);
        Assert.True(value.Length <= 201);
    }

    [Fact]
    public void A_upnp_description_gives_its_plain_text_fields()
    {
        const string xml = "<?xml version=\"1.0\"?><root><device><friendlyName> Living &amp; Dining &lt;TV&gt; </friendlyName>"
                           + "<manufacturer>ACME</manufacturer><modelName>X&apos;1 &quot;Pro&quot;</modelName></device></root>";
        Assert.Equal("Living & Dining <TV>", LanDiscovery.Element(xml, "friendlyName"));
        Assert.Equal("ACME", LanDiscovery.Element(xml, "MANUFACTURER"));
        Assert.Equal("X'1 \"Pro\"", LanDiscovery.Element(xml, "modelName"));
        Assert.Equal(string.Empty, LanDiscovery.Element(xml, "serialNumber"));
        Assert.Equal(string.Empty, LanDiscovery.Element("<friendlyName>never closed", "friendlyName"));
        Assert.Equal(string.Empty, LanDiscovery.Element(string.Empty, "friendlyName"));
    }

    [Fact]
    public void A_upnp_field_that_is_too_long_or_hostile_is_not_shown_as_sent()
    {
        Assert.Equal(string.Empty, LanDiscovery.Element("<friendlyName>" + new string('x', 400) + "</friendlyName>", "friendlyName"));
        string value = LanDiscovery.Element("<friendlyName>a\u0007b\u202Ec" + new string('y', 200) + "</friendlyName>", "friendlyName");
        Assert.StartsWith("a?b?c", value);
        Assert.True(value.Length <= 81);
        // an entity that isn't one of XML's five stays as text: nothing is fetched or expanded
        Assert.Equal("&xxe;", LanDiscovery.Element("<friendlyName>&xxe;</friendlyName>", "friendlyName"));
    }

    // A NetBIOS node status answer: header, the name asked (34 bytes), type/class/ttl/length, a count, then 18 bytes a name.
    private static byte[] NodeStatus(params (string Name, byte Suffix, bool Group)[] names)
    {
        var header = new byte[] { 0x12, 0x34, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0 };
        var asked = Frames.Join(new byte[] { 0x20 }, Encoding.ASCII.GetBytes("CK" + new string('A', 30)), new byte[] { 0 });   // "*", encoded
        var fixedPart = Frames.Join(U16(0x21), U16(1), new byte[4], U16(1 + names.Length * 18 + 6), new[] { (byte)names.Length });
        var entries = names.Select(n => Frames.Join(Encoding.ASCII.GetBytes(n.Name.PadRight(15)), new[] { n.Suffix }, new byte[] { (byte)(n.Group ? 0x84 : 0x04), 0 })).ToArray();
        return Frames.Join(header, asked, fixedPart, Frames.Join(entries), new byte[6]);
    }

    [Fact]
    public void A_netbios_status_gives_the_computer_name_and_its_workgroup()
    {
        var reply = NodeStatus(("DESKTOP-ABC", 0x00, false), ("WORKGROUP", 0x00, true), ("DESKTOP-ABC", 0x20, false), ("WORKGROUP", 0x1E, true));
        Assert.Equal(("DESKTOP-ABC", "WORKGROUP"), LanDiscovery.Nbstat(reply));
        // the names can come in any order, and a file-server entry alone names nothing
        Assert.Equal(("NAS", "HOME"), LanDiscovery.Nbstat(NodeStatus(("HOME", 0x00, true), ("NAS", 0x20, false), ("NAS", 0x00, false))));
        Assert.Equal((string.Empty, string.Empty), LanDiscovery.Nbstat(NodeStatus(("NAS", 0x20, false))));
    }

    [Fact]
    public void A_damaged_netbios_status_gives_no_name_and_no_exception()
    {
        var whole = NodeStatus(("DESKTOP-ABC", 0x00, false), ("WORKGROUP", 0x00, true));
        for (int length = 0; length <= whole.Length; length++) _ = LanDiscovery.Nbstat(whole.AsSpan(0, length));
        var random = new Random(3);
        for (int i = 0; i < 20_000; i++)
        {
            var bytes = (byte[])whole.Clone();
            for (int c = random.Next(1, 4); c > 0; c--) bytes[random.Next(bytes.Length)] = (byte)random.Next(256);
            var (host, group) = LanDiscovery.Nbstat(bytes.AsSpan(0, random.Next(bytes.Length + 1)));
            Assert.True(host.Length <= 33 && group.Length <= 33);
            Assert.DoesNotContain('\u001b', host);
        }
    }
}

/// <summary>Telling a router that answers ARP for every address (proxy ARP: cloud networks, some hotspots) from
/// devices, so that a search doesn't list a "device" for every address of the subnet.</summary>
public class ProxyArpFilterTests
{
    private const string Router = "76:AE:4E:17:06:6D";

    [Fact]
    public void Devices_with_their_own_macs_are_all_devices()
    {
        var filter = new ProxyArpFilter();
        for (int i = 1; i <= 200; i++)
        {
            Assert.True(filter.Accept($"10.0.0.{i}", $"02:00:00:00:00:{i:X2}", out var withdraw));
            Assert.Empty(withdraw);
        }
        Assert.Equal(0, filter.Dropped);
    }

    [Fact]
    public void A_device_with_a_few_addresses_keeps_them()
    {
        var filter = new ProxyArpFilter();
        for (int i = 1; i <= ProxyArpFilter.Limit; i++) Assert.True(filter.Accept($"10.0.0.{i}", Router, out _));
        // the neighbor table is read again and again during a search: the same answer doesn't count twice
        for (int round = 0; round < 5; round++)
            for (int i = 1; i <= ProxyArpFilter.Limit; i++) Assert.True(filter.Accept($"10.0.0.{i}", Router, out _));
        Assert.Equal(0, filter.Dropped);
    }

    [Fact]
    public void One_mac_answering_for_everybody_is_a_router_and_its_answers_are_taken_back()
    {
        var filter = new ProxyArpFilter();
        for (int i = 1; i <= ProxyArpFilter.Limit; i++) Assert.True(filter.Accept($"10.0.1.{i}", Router, out _));

        // the address that passes the limit isn't a device, and neither are the ones accepted before it
        Assert.False(filter.Accept("10.0.1.200", Router, out var withdraw));
        Assert.Equal(Enumerable.Range(1, ProxyArpFilter.Limit).Select(i => $"10.0.1.{i}"), withdraw);
        Assert.Equal(ProxyArpFilter.Limit + 1, filter.Dropped);

        // from then on every answer of that MAC is left out (however it is written), with nothing more to take back
        for (int i = 0; i < 500; i++)
        {
            Assert.False(filter.Accept($"10.0.2.{i % 250}", Router.ToLowerInvariant(), out withdraw));
            Assert.Empty(withdraw);
        }
        Assert.Equal(ProxyArpFilter.Limit + 1 + 500, filter.Dropped);

        // a real device on the same network is still one
        Assert.True(filter.Accept("10.0.1.77", "02:00:00:00:00:77", out withdraw));
        Assert.Empty(withdraw);
    }
}

/// <summary>A device search as a whole: what it refuses, and (when allowed, see <see cref="Live.LanSwitch"/>) a real
/// search of this computer's own network.</summary>
[Collection(Live.Collection)]
public class LanDiscoveryLiveTests
{
    private static NetIface Fake(string? v4, int prefix)
        => new("eth9", "eth9", "eth9", 9, v4 is null ? null : IPAddress.Parse(v4), null, null, false) { Prefix4 = prefix };

    [Fact]
    public async Task A_network_that_cannot_be_searched_is_refused_in_words()
    {
        var token = TestContext.Current.CancellationToken;
        var noAddress = await Assert.ThrowsAsync<NetIfaceException>(() => LanDiscovery.RunAsync(Fake(null, 0), _ => { }, token));
        Assert.Contains("eth9 has no IPv4 address", noAddress.Message);
        var pointToPoint = await Assert.ThrowsAsync<NetIfaceException>(() => LanDiscovery.RunAsync(Fake("10.0.0.1", 32), _ => { }, token));
        Assert.Contains("no other addresses", pointToPoint.Message);
    }

    [Fact]
    public void A_search_is_offered_where_the_neighbor_table_can_be_read()
        => Assert.Equal(OperatingSystem.IsWindows() || OperatingSystem.IsLinux(), LanDiscovery.IsAvailable);

    [Fact]
    public void The_neighbor_table_is_read_without_an_error_and_only_holds_devices()
    {
        foreach (var via in new[] { null, NetIfaces.Up().FirstOrDefault() })
        {
            var table = ScanNeighbors.Snapshot(via);
            foreach (var (ip, entry) in table)
            {
                Assert.True(IPAddress.TryParse(ip, out _), ip);
                Assert.True(ScanOui.IsHostMac(entry.Mac), entry.Mac);
            }
        }
    }

    [Fact]
    public async Task A_search_of_this_computers_network_finds_this_computer_and_ends_in_time()
    {
        Assert.SkipUnless(Live.LanAllowed, $"set {Live.LanSwitch}=1 to let the tests search this computer's network");
        Assert.SkipUnless(LanDiscovery.IsAvailable, $"{Live.SystemName} gives apps no neighbor table to search with");
        var nic = Live.Network();
        Assert.SkipWhen(nic.Subnet4(LanDiscovery.MaxAddresses, out _) is null, $"{nic.Name} has no network to search (/{nic.Prefix4})");

        var devices = new ConcurrentDictionary<string, LanDevice>();
        using var deadline = Live.Deadline(40);
        var clock = Stopwatch.StartNew();
        var result = await LanDiscovery.RunAsync(nic, d => { if (d.Withdrawn) devices.TryRemove(d.Ip, out _); else devices[d.Ip] = d; }, deadline.Token);

        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(25), $"the search took {clock.Elapsed.TotalSeconds:0.0} s");
        Assert.InRange(result.Addresses, 1, LanDiscovery.MaxAddresses);
        Assert.Equal(devices.Count, result.Devices);
        var own = Assert.Single(devices.Values, d => d.IsThisDevice);
        Assert.Equal(nic.V4!.ToString(), own.Ip);
        Assert.True(own.Answered);
        foreach (var d in devices.Values)
        {
            Assert.True(nic.OnLink4(IPAddress.Parse(d.Ip)), $"{d.Ip} isn't on {nic.Name}'s network");
            Assert.False(string.IsNullOrEmpty(d.FoundBy));
            Assert.DoesNotContain('\n', d.Name + d.Details);
        }
    }

    [Fact]
    public async Task A_search_that_is_stopped_ends_soon_and_keeps_what_it_found()
    {
        Assert.SkipUnless(Live.LanAllowed, $"set {Live.LanSwitch}=1 to let the tests search this computer's network");
        Assert.SkipUnless(LanDiscovery.IsAvailable, $"{Live.SystemName} gives apps no neighbor table to search with");
        var nic = Live.Network();
        Assert.SkipWhen(nic.Subnet4(LanDiscovery.MaxAddresses, out _) is null, $"{nic.Name} has no network to search (/{nic.Prefix4})");

        using var stop = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var devices = new ConcurrentDictionary<string, LanDevice>();
        var clock = Stopwatch.StartNew();
        stop.CancelAfter(400);
        try
        {
            var result = await LanDiscovery.RunAsync(nic, d => { if (d.Withdrawn) devices.TryRemove(d.Ip, out _); else devices[d.Ip] = d; }, stop.Token);
            Assert.True(result.Devices >= 1);
        }
        catch (OperationCanceledException) { }
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(4), $"stopping took {clock.Elapsed.TotalSeconds:0.0} s");
        Assert.Contains(devices.Values, d => d.IsThisDevice);
    }
}
