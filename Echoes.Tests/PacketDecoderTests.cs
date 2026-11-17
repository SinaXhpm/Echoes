using System.Net;
using System.Text;
using Echoes.Helpers;
using Echoes.Tests.Support;
using static Echoes.Tests.Support.Frames;

namespace Echoes.Tests;

/// <summary>The Capture tool's packet reader: what it says about well-formed packets, and that nothing a packet can
/// hold makes it throw.</summary>
public class PacketDecoderTests
{
    private static string Text(IPAddress a) => a.ToString();

    [Fact]
    public void Arp_request_says_who_is_asked_and_who_asks()
    {
        var p = Record(Ethernet(Broadcast, MacA, EtherArp, Arp(1, MacA, "192.168.1.20", new byte[6], "192.168.1.1")));
        Assert.Equal("ARP", p.Protocol);
        Assert.Equal(PacketL3.Arp, p.L3);
        Assert.Equal("Who has 192.168.1.1? Tell 192.168.1.20", p.Info);
        // the addresses it is about are the packet's addresses, so an address filter finds it
        Assert.True(p.HasIp);
        Assert.Equal(IPAddress.Parse("192.168.1.20"), p.Src.ToAddress());
        Assert.Equal(IPAddress.Parse("192.168.1.1"), p.Dst.ToAddress());
        Assert.False(p.Alert);
    }

    [Fact]
    public void Arp_reply_and_gratuitous_arp()
    {
        var reply = Record(Ethernet(MacA, MacB, EtherArp, Arp(2, MacB, "192.168.1.1", MacA, "192.168.1.20")));
        Assert.StartsWith("192.168.1.1 is at ", reply.Info);
        Assert.EndsWith("02:00:00:00:00:0b", reply.Info, StringComparison.OrdinalIgnoreCase);

        var gratuitous = Record(Ethernet(Broadcast, MacA, EtherArp, Arp(1, MacA, "192.168.1.20", new byte[6], "192.168.1.20")));
        Assert.Equal("Gratuitous ARP for 192.168.1.20", gratuitous.Info);
    }

    [Fact]
    public void Tcp_syn_over_ipv4()
    {
        var p = Record(Ethernet(EtherIpv4, Ipv4("10.0.0.1", "10.0.0.2", 6, Tcp(50000, 443, Syn, seq: 77), ttl: 57)));
        Assert.Equal("TCP", p.Protocol);
        Assert.Equal(PacketL3.IPv4, p.L3);
        Assert.Equal(PacketL4.Tcp, p.L4);
        Assert.Equal(6, p.IpProto);
        Assert.Equal("10.0.0.1", p.Source);
        Assert.Equal("10.0.0.2", p.Destination);
        Assert.Equal(50000, p.SrcPort);
        Assert.Equal(443, p.DstPort);
        Assert.Equal(Syn, p.TcpFlags);
        Assert.Equal(57, p.Ttl);
        Assert.True(p.HasMac);
        Assert.Equal(0x02000000000AUL, p.SrcMac);
        Assert.Equal(0x02000000000BUL, p.DstMac);
        Assert.Contains("[SYN]", p.Info);
        Assert.Contains("Seq=77", p.Info);
        Assert.StartsWith("50000", p.Info);
        Assert.False(p.Alert);
    }

    [Fact]
    public void A_tcp_reset_is_marked()
    {
        var p = Record(Ethernet(EtherIpv4, Ipv4("10.0.0.2", "10.0.0.1", 6, Tcp(443, 50000, Rst | Ack))));
        Assert.Equal("TCP", p.Protocol);
        Assert.True(p.Alert);
        Assert.Contains("RST", p.Info);
    }

    [Fact]
    public void A_vlan_tag_changes_nothing_but_the_offset()
    {
        var inner = Ipv4("10.0.0.1", "10.0.0.2", 6, Tcp(50000, 443, Syn));
        var plain = Record(Ethernet(MacB, MacA, EtherIpv4, inner));
        var tagged = Record(Ethernet(MacB, MacA, EtherIpv4, inner, vlan: 42));
        Assert.Equal(plain.Protocol, tagged.Protocol);
        Assert.Equal(plain.Info, tagged.Info);
        Assert.Equal(plain.Source, tagged.Source);
        Assert.Equal(plain.DstPort, tagged.DstPort);
        var ethernet = PacketDecoder.Describe(tagged).Single(l => l.Title == "Ethernet II");
        Assert.Contains(ethernet.Fields, f => f.Name == "VLAN" && f.Value == "42");
    }

    [Theory]
    [InlineData(LinkKind.RawIp)]
    [InlineData(LinkKind.Null)]
    [InlineData(LinkKind.LinuxSll)]
    public void The_other_link_layers_lead_to_the_same_packet(LinkKind link)
    {
        var ip = Ipv4("10.0.0.1", "8.8.8.8", 17, Udp(5000, 53, DnsQuery(1, "example.com", 1)));
        byte[] frame = link switch
        {
            LinkKind.RawIp => ip,
            // BSD loopback: the protocol family in the capturing machine's byte order (2 = IPv4)
            LinkKind.Null => Join(new byte[] { 2, 0, 0, 0 }, ip),
            // Linux cooked capture: packet type, ARPHRD, address length, 8 address bytes, the EtherType
            _ => Join(new byte[] { 0, 4, 0, 1, 0, 6 }, MacA, new byte[] { 0, 0 }, new byte[] { 0x08, 0x00 }, ip),
        };
        var p = Record(frame, link);
        Assert.Equal("DNS", p.Protocol);
        Assert.Equal("10.0.0.1", p.Source);
        Assert.Equal("8.8.8.8", p.Destination);
        Assert.Equal("example.com", p.Name);
        Assert.Equal(53, p.DstPort);
    }

    [Fact]
    public void Loopback_frames_are_read_by_the_ip_version_whatever_the_family_number()
    {
        // IPv6 has four family numbers (10 Linux, 23 Windows, 24/28/30 the BSDs and macOS), in either byte order
        var ip6 = Ipv6("::1", "::1", 17, Udp(5000, 53, DnsQuery(1, "example.com", 28)));
        foreach (var family in new[] { new byte[] { 30, 0, 0, 0 }, new byte[] { 0, 0, 0, 30 }, new byte[] { 23, 0, 0, 0 }, new byte[] { 10, 0, 0, 0 } })
        {
            var p = Record(Join(family, ip6), LinkKind.Null);
            Assert.Equal(PacketL3.IPv6, p.L3);
            Assert.Equal("DNS", p.Protocol);
            Assert.Equal("::1", p.Source);
        }
    }

    [Fact]
    public void Dns_query_and_answers_over_ipv6()
    {
        var query = Record(Ethernet(EtherIpv6, Ipv6("2001:db8::1", "2001:db8::53", 17, Udp(40000, 53, DnsQuery(0xBEEF, "example.com", 28)))));
        Assert.Equal("DNS", query.Protocol);
        Assert.Equal(PacketL3.IPv6, query.L3);
        Assert.Equal(PacketL4.Udp, query.L4);
        Assert.Equal("2001:db8::1", query.Source);
        Assert.Equal("example.com", query.Name);
        Assert.Contains("Standard query 0xbeef AAAA example.com", query.Info);

        var answer = DnsResponse(0xBEEF, "example.com", 1, 0, DnsRecord(1, new byte[] { 93, 184, 216, 34 }), DnsRecord(1, new byte[] { 93, 184, 216, 35 }));
        var response = Record(Ethernet(EtherIpv4, Ipv4("8.8.8.8", "10.0.0.1", 17, Udp(53, 40000, answer))));
        Assert.Equal("DNS", response.Protocol);
        Assert.Contains("response", response.Info);
        Assert.Contains("93.184.216.34, 93.184.216.35", response.Info);
        Assert.False(response.Alert);

        var missing = Record(Ethernet(EtherIpv4, Ipv4("8.8.8.8", "10.0.0.1", 17, Udp(53, 40000, DnsResponse(7, "nope.example", 1, rcode: 3)))));
        Assert.Contains("no such name", missing.Info);
    }

    [Theory]
    [InlineData(5353, "224.0.0.251", "mDNS")]
    [InlineData(5355, "224.0.0.252", "LLMNR")]
    public void The_local_relatives_of_dns_are_named(int port, string group, string protocol)
    {
        var p = Record(Ethernet(EtherIpv4, Ipv4("192.168.1.20", group, 17, Udp((ushort)port, (ushort)port, DnsQuery(0, "printer.local", 1, recursionDesired: false)))));
        Assert.Equal(protocol, p.Protocol);
        Assert.Equal("printer.local", p.Name);
    }

    [Fact]
    public void Tls_client_hello_gives_the_server_name()
    {
        var p = Record(Ethernet(EtherIpv4, Ipv4("10.0.0.9", "1.1.1.1", 6, Tcp(50001, 443, Psh | Ack, ClientHello("one.one.one.one"), ack: 1))));
        Assert.Equal("TLS", p.Protocol);
        Assert.Equal("one.one.one.one", p.Name);
        Assert.Contains("Client Hello", p.Info);
    }

    [Fact]
    public void Http_request_gives_the_request_line_and_host()
    {
        var p = Record(Ethernet(EtherIpv4, Ipv4("10.0.0.9", "10.0.0.80", 6,
                                                Tcp(50002, 80, Psh | Ack, Http("GET /a/b?c=1 HTTP/1.1\nHost: test.example\nAccept: */*\n\n"), ack: 1))));
        Assert.Equal("HTTP", p.Protocol);
        Assert.Equal("test.example", p.Name);
        Assert.Contains("GET /a/b?c=1 HTTP/1.1", p.Info);
    }

    [Fact]
    public void Text_from_a_packet_is_cleaned_before_it_is_shown()
    {
        // a Host header that tries to redraw the row: an escape sequence and a right-to-left override
        string host = "evil\u001b[2J\u202Eexample";
        var request = Join(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: "), Encoding.Latin1.GetBytes("evil\u001b[2J"),
                           Encoding.ASCII.GetBytes("example\r\n\r\n"));
        var p = Record(Ethernet(EtherIpv4, Ipv4("10.0.0.9", "10.0.0.80", 6, Tcp(50002, 80, Psh | Ack, request, ack: 1))));
        Assert.Equal("HTTP", p.Protocol);
        Assert.NotNull(p.Name);
        Assert.DoesNotContain('\u001b', p.Name);
        Assert.DoesNotContain('\u001b', p.Info);
        Assert.False(host.Equals(p.Name, StringComparison.Ordinal));

        // a DNS label that holds control characters and a bidi override (as UTF-8)
        var label = Encoding.UTF8.GetBytes("a\u0007b\u202Ec");
        var name = Join(new[] { (byte)label.Length }, label, new byte[] { 3, (byte)'c', (byte)'o', (byte)'m', 0 });
        var query = Join(new byte[] { 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 }, name, new byte[] { 0, 1, 0, 1 });
        var dns = Record(Ethernet(EtherIpv4, Ipv4("10.0.0.1", "8.8.8.8", 17, Udp(5000, 53, query))));
        Assert.Equal("DNS", dns.Protocol);
        Assert.Equal("a?b?c.com", dns.Name);
    }

    [Fact]
    public void Icmp_echo_and_errors()
    {
        var request = Record(Ethernet(EtherIpv4, Ipv4("10.0.0.2", "10.0.0.1", 1, Icmp(8, 0, 0x0102, 7, new byte[32]), ttl: 3)));
        Assert.Equal("ICMP", request.Protocol);
        Assert.Equal(PacketL4.Icmp, request.L4);
        Assert.Equal("Echo (ping) request id=0x0102, seq=7, ttl=3", request.Info);
        Assert.False(request.Alert);

        var reply = Record(Ethernet(EtherIpv4, Ipv4("10.0.0.1", "10.0.0.2", 1, Icmp(0, 0, 0x0102, 7, new byte[32]))));
        Assert.StartsWith("Echo (ping) reply", reply.Info);

        // port unreachable, quoting the datagram that caused it
        var quoted = Ipv4("10.0.0.2", "10.0.0.1", 17, Udp(40000, 33434, new byte[8]));
        var unreachable = Record(Ethernet(EtherIpv4, Ipv4("10.0.0.1", "10.0.0.2", 1, Icmp(3, 3, 0, 0, quoted))));
        Assert.True(unreachable.Alert);
        Assert.Contains("port unreachable", unreachable.Info);

        var expired = Record(Ethernet(EtherIpv4, Ipv4("10.0.0.254", "10.0.0.2", 1, Icmp(11, 0, 0, 0, quoted))));
        Assert.True(expired.Alert);
        Assert.Contains("Time-to-live exceeded", expired.Info);
    }

    [Fact]
    public void A_later_fragment_is_not_read_as_a_transport_header()
    {
        // the second fragment of a UDP datagram starts with payload bytes, not ports
        var p = Record(Ethernet(EtherIpv4, Ipv4("10.0.0.1", "10.0.0.2", 17, new byte[64], fragmentOffset: 185)));
        Assert.Equal("IPv4", p.Protocol);
        Assert.Contains("Fragment of a UDP packet", p.Info);
        Assert.Equal(0, p.SrcPort);
        Assert.Equal(0, p.DstPort);
    }

    [Fact]
    public void An_unknown_link_type_is_shown_as_bytes()
    {
        var p = Record(new byte[40], LinkKind.Unknown);
        Assert.Equal("?", p.Protocol);
        Assert.Contains("isn't decoded", p.Info);
    }

    [Fact]
    public void Describe_lists_every_layer_outermost_first()
    {
        var p = Record(Ethernet(EtherIpv4, Ipv4("10.0.0.1", "8.8.8.8", 17, Udp(5000, 53, DnsQuery(0xBEEF, "example.com", 1)))), number: 9);
        var layers = PacketDecoder.Describe(p);
        Assert.Equal("Frame 9", layers[0].Title);
        Assert.Equal("Ethernet II", layers[1].Title);
        Assert.Contains("Version 4", layers[2].Title);
        Assert.Equal("Domain Name System", layers[^1].Title);
        Assert.Contains(layers[^1].Fields, f => f.Name == "Question" && f.Value == "A example.com");
        Assert.All(layers, l => Assert.NotEmpty(l.Fields));
    }

    // ------------------------------------------------------------------ names

    [Fact]
    public void A_compressed_name_is_followed_and_the_reader_ends_after_the_pointer()
    {
        // offset 0: "example.com"; offset 13: "www" + a pointer to offset 0
        var m = Join(DnsName("example.com"), new byte[] { 3, (byte)'w', (byte)'w', (byte)'w', 0xC0, 0x00 }, new byte[] { 0xAA });
        int at = 13;
        Assert.Equal("www.example.com", PacketDecoder.DnsName(m, ref at));
        Assert.Equal(19, at);
    }

    [Fact]
    public void A_name_that_loops_or_leaves_the_message_is_refused()
    {
        int at = 0;
        Assert.Null(PacketDecoder.DnsName(new byte[] { 0xC0, 0x00 }, ref at));                    // a pointer to itself
        at = 0;
        Assert.Null(PacketDecoder.DnsName(new byte[] { 0xC0, 0x02, 0xC0, 0x00 }, ref at));        // two that point at each other
        at = 0;
        Assert.Null(PacketDecoder.DnsName(new byte[] { 0xC0, 0x40 }, ref at));                    // a pointer past the end
        at = 0;
        Assert.Null(PacketDecoder.DnsName(new byte[] { 5, (byte)'a', (byte)'b' }, ref at));       // a label longer than what is left
        at = 0;
        Assert.Null(PacketDecoder.DnsName(new byte[] { 0x41, (byte)'a', 0 }, ref at));            // a length with a reserved bit
        at = 0;
        Assert.Null(PacketDecoder.DnsName(new byte[] { 3, (byte)'a', (byte)'b', (byte)'c' }, ref at));   // no end
        at = 0;
        Assert.Null(PacketDecoder.DnsName(Array.Empty<byte>(), ref at));
    }

    [Fact]
    public void A_name_longer_than_dns_allows_is_refused()
    {
        // five 63-byte labels: 319 characters, more than the 255 a name may have
        var label = Join(new byte[] { 63 }, Enumerable.Repeat((byte)'a', 63).ToArray());
        var m = Join(label, label, label, label, label, new byte[] { 0 });
        int at = 0;
        Assert.Null(PacketDecoder.DnsName(m, ref at));
    }

    [Fact]
    public void A_service_instance_name_keeps_its_spaces_and_letters()
    {
        var label = Encoding.UTF8.GetBytes("Living Room TV é");
        var m = Join(new[] { (byte)label.Length }, label, DnsName("_airplay._tcp.local"));
        int at = 0;
        Assert.Equal("Living Room TV é._airplay._tcp.local", PacketDecoder.DnsName(m, ref at));
        Assert.Equal(m.Length, at);
    }

    // ------------------------------------------------------------------ damage

    public static IEnumerable<object[]> SampleNumbers() => Enumerable.Range(0, 6).Select(i => new object[] { i });

    /// <summary>A capture can stop a packet anywhere (a snap length, a damaged file): every prefix of every sample is
    /// read without an exception, by the table's reader and the detail pane's.</summary>
    [Theory]
    [MemberData(nameof(SampleNumbers))]
    public void A_packet_cut_anywhere_is_read_without_an_exception(int sample)
    {
        var whole = Samples()[sample].Data;
        var decoder = new PacketDecoder();
        for (int length = 0; length <= whole.Length; length++)
        {
            var p = new PacketRecord { Number = 1, Data = whole[..length], WireLength = whole.Length, Link = LinkKind.Ethernet };
            decoder.Summarize(p);
            Assert.NotEmpty(p.Protocol);
            Assert.NotNull(p.Info);
            Assert.NotEmpty(PacketDecoder.Describe(p));
        }
    }

    /// <summary>Random damage to real packets, and random bytes, over every link type. The seed is fixed: a failure
    /// here is the same failure on every computer.</summary>
    [Fact]
    public void Damaged_and_random_packets_never_throw()
    {
        var random = new Random(20261115);
        var samples = Samples().Select(p => p.Data).ToArray();
        var links = new[] { LinkKind.Ethernet, LinkKind.RawIp, LinkKind.Null, LinkKind.LinuxSll, LinkKind.Unknown };
        var decoder = new PacketDecoder();
        for (int i = 0; i < 60_000; i++)
        {
            byte[] data;
            if (i % 4 == 3)
            {
                data = new byte[random.Next(0, 160)];
                random.NextBytes(data);
            }
            else
            {
                data = (byte[])samples[random.Next(samples.Length)].Clone();
                int changes = random.Next(1, 6);
                for (int c = 0; c < changes; c++) data[random.Next(data.Length)] = (byte)random.Next(256);
                if (random.Next(3) == 0) data = data[..random.Next(data.Length + 1)];
            }
            var p = new PacketRecord { Number = i, Data = data, WireLength = data.Length, Link = links[random.Next(links.Length)] };
            decoder.Summarize(p);
            Assert.NotEmpty(p.Protocol);
            if (i % 16 == 0) Assert.NotEmpty(PacketDecoder.Describe(p));
            // what reaches the table is one clean line
            Assert.DoesNotContain('\n', p.Info);
            Assert.DoesNotContain('\u001b', p.Info);
            if (p.Name is not null) Assert.DoesNotContain('\u001b', p.Name);
        }
    }
}
