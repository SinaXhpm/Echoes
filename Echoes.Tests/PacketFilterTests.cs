using Echoes.Helpers;
using Echoes.Tests.Support;

namespace Echoes.Tests;

/// <summary>The Capture tool's display filter, over the six sample packets of <see cref="Frames.Samples"/>
/// (1 TCP SYN to :443, 2 DNS query, 3 ARP request, 4 ICMP echo, 5 HTTP over IPv6, 6 TLS Client Hello to :443).</summary>
public class PacketFilterTests
{
    private static readonly List<PacketRecord> Packets = Frames.Samples();

    private static string Matching(string filter)
    {
        Assert.True(PacketFilter.TryParse(filter, out var parsed, out var error), $"\"{filter}\" wasn't understood: {error}");
        Assert.NotNull(parsed);
        return string.Join(",", Packets.Where(parsed!.Matches).Select(p => p.Number));
    }

    [Theory]
    // protocols
    [InlineData("tcp", "1,5,6")]
    [InlineData("udp", "2")]
    [InlineData("arp", "3")]
    [InlineData("icmp", "4")]
    [InlineData("ip", "1,2,4,6")]
    [InlineData("ipv6", "5")]
    [InlineData("ip6", "5")]
    [InlineData("dns", "2")]
    [InlineData("http", "5")]
    [InlineData("tls", "6")]
    [InlineData("ssl", "6")]
    [InlineData("TCP", "1,5,6")]
    // tcpdump style
    [InlineData("host 10.0.0.2", "1,4")]
    [InlineData("src host 10.0.0.2", "4")]
    [InlineData("dst host 10.0.0.2", "1")]
    [InlineData("src 10.0.0.2", "4")]
    [InlineData("dst 10.0.0.2", "1")]
    [InlineData("net 10.0.0.0/8", "1,2,4,6")]
    [InlineData("src net 10.0.0.0/30", "1,2,4")]
    [InlineData("dst net 2001:db8::/32", "5")]
    [InlineData("host 192.168.1.1", "3")]
    [InlineData("port 443", "1,6")]
    [InlineData("tcp port 443", "1,6")]
    [InlineData("udp port 443", "")]
    [InlineData("src port 53", "")]
    [InlineData("dst port 53", "2")]
    [InlineData("portrange 50-80", "2,5")]
    [InlineData("src portrange 1000-6000", "2,5")]
    [InlineData("less 60", "1,3")]
    [InlineData("greater 100", "5,6")]
    // Wireshark style
    [InlineData("ip.addr == 10.0.0.1", "1,2,4")]
    [InlineData("ip.addr==10.0.0.1", "1,2,4")]
    [InlineData("ip.addr eq 10.0.0.1", "1,2,4")]
    [InlineData("ip.addr != 10.0.0.1", "3,5,6")]
    [InlineData("ip.src == 10.0.0.0/8", "1,2,4,6")]
    [InlineData("ip.dst == 10.0.0.1", "4")]
    [InlineData("ipv6.addr == 2001:db8::2", "5")]
    [InlineData("ip.addr", "1,2,3,4,5,6")]
    [InlineData("tcp.port == 443", "1,6")]
    [InlineData("tcp.port != 443", "5")]                         // as in Wireshark: TCP packets only (it was "2,3,4,5")
    [InlineData("tcp.port != 80", "1,6")]
    [InlineData("udp.port != 53", "")]
    [InlineData("!(tcp.port == 443)", "2,3,4,5")]                // "not that" for every packet
    [InlineData("name != example.com", "5,6")]                   // packets that carry a name
    [InlineData("tcp.dstport >= 400", "1,6")]
    [InlineData("tcp.srcport < 2000", "5")]
    [InlineData("udp.port == 53", "2")]
    [InlineData("udp.srcport gt 4000", "2")]
    [InlineData("tcp.port", "1,5,6")]
    [InlineData("frame.len > 100", "5,6")]
    [InlineData("frame.len <= 54", "1,3")]
    [InlineData("frame.number == 3", "3")]
    [InlineData("frame.number >= 5", "5,6")]
    [InlineData("ip.ttl < 10", "4")]
    [InlineData("ip.proto == 17", "2")]
    [InlineData("tcp.flags.syn", "1")]
    [InlineData("tcp.flags.syn == 1", "1")]
    [InlineData("tcp.flags.syn == 0", "5,6")]
    [InlineData("tcp.flags.ack", "5,6")]
    [InlineData("tcp.flags.reset", "")]
    [InlineData("eth.addr == 02:00:00:00:00:0a", "1,2,3,4,5,6")]
    [InlineData("eth.src == 02-00-00-00-00-0B", "4")]
    [InlineData("eth.dst == ff:ff:ff:ff:ff:ff", "3")]
    [InlineData("eth.dst != ff:ff:ff:ff:ff:ff", "1,2,4,5,6")]
    [InlineData("dns.name contains example", "2")]             // not packet 5, whose HTTP host is test.example
    [InlineData("dns.qry.name == EXAMPLE.COM", "2")]
    [InlineData("dns.name != example.com", "")]
    [InlineData("tls.sni == one.one.one.one", "6")]
    [InlineData("tls.sni", "6")]
    [InlineData("http.host contains test", "5")]
    [InlineData("name contains example", "2,5")]
    [InlineData("name", "2,5,6")]
    [InlineData("info contains \"Who has\"", "3")]
    [InlineData("proto == arp", "3")]
    // joined
    [InlineData("not tcp", "2,3,4")]
    [InlineData("!tcp", "2,3,4")]
    [InlineData("not not tcp", "1,5,6")]
    [InlineData("tcp and not port 443", "5")]
    [InlineData("tcp && ip6", "5")]
    [InlineData("tcp or udp", "1,2,5,6")]
    [InlineData("arp || icmp", "3,4")]
    [InlineData("(tcp or udp) and host 10.0.0.1", "1,2")]
    [InlineData("tcp or udp and host 10.0.0.1", "1,2,5,6")]   // "and" binds tighter than "or"
    [InlineData("not (arp or icmp) and not ip6", "1,2,6")]
    [InlineData("TCP AND PORT 443", "1,6")]
    // bare values and words
    [InlineData("10.0.0.2", "1,4")]
    [InlineData("10.0.0.0/8", "1,2,4,6")]
    [InlineData("2001:db8::1", "5")]
    [InlineData("443", "1,6")]
    [InlineData("example", "2,5")]
    [InlineData("\"Who has\"", "3")]
    [InlineData("'Client Hello'", "6")]
    [InlineData("\"\"", "1,2,3,4,5,6")]
    public void A_filter_shows_these_packets(string filter, string expected) => Assert.Equal(expected, Matching(filter));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void No_text_is_no_filter(string? text)
    {
        Assert.True(PacketFilter.TryParse(text, out var filter, out var error));
        Assert.Null(filter);
        Assert.Null(error);
    }

    [Theory]
    [InlineData("host")]
    [InlineData("host example.com")]            // names aren't looked up
    [InlineData("port abc")]
    [InlineData("port 70000")]
    [InlineData("portrange 90-80")]
    [InlineData("ip.addr >")]
    [InlineData("ip.addr > 10.0.0.1")]
    [InlineData("ip.addr == 10.0.0.0/33")]
    [InlineData("(tcp")]
    [InlineData("tcp)")]
    [InlineData("\"unclosed")]
    [InlineData("tcp &")]
    [InlineData("tcp and")]
    [InlineData("not")]
    [InlineData("== 5")]
    [InlineData("tcp.flags.syn > 1")]
    [InlineData("eth.addr == 12")]
    [InlineData("eth.addr == zz:zz:zz:zz:zz:zz")]
    [InlineData("frame.len contains 5")]
    [InlineData("frame.len == big")]
    [InlineData("less")]
    public void What_is_not_understood_gives_a_reason_not_an_exception(string filter)
    {
        Assert.False(PacketFilter.TryParse(filter, out var parsed, out var error), $"\"{filter}\" was accepted");
        Assert.Null(parsed);
        Assert.False(string.IsNullOrWhiteSpace(error));
        Assert.True(error!.Length < 120, "the reason is a few words: " + error);
    }

    [Fact]
    public void A_filter_is_bounded_in_length_and_nesting()
    {
        // long but legal
        Assert.True(PacketFilter.TryParse(string.Join(" or ", Enumerable.Repeat("tcp", 200)), out var many, out _));
        Assert.Equal("1,5,6", string.Join(",", Packets.Where(many!.Matches).Select(p => p.Number)));
        Assert.False(PacketFilter.TryParse(new string('a', 2001), out _, out var tooLong));
        Assert.Contains("too long", tooLong);

        // 40 brackets are read; 400 are refused with a reason (not a stack overflow)
        Assert.True(PacketFilter.TryParse(new string('(', 40) + "tcp" + new string(')', 40), out var nested, out _));
        Assert.Equal("1,5,6", string.Join(",", Packets.Where(nested!.Matches).Select(p => p.Number)));
        Assert.False(PacketFilter.TryParse(new string('(', 400) + "tcp" + new string(')', 400), out _, out var tooDeep));
        Assert.Contains("inside each other", tooDeep);
        Assert.False(PacketFilter.TryParse(string.Concat(Enumerable.Repeat("not ", 400)) + "tcp", out _, out tooDeep));
        Assert.Contains("inside each other", tooDeep);
    }

    [Fact]
    public void The_filter_keeps_its_text_trimmed()
    {
        Assert.True(PacketFilter.TryParse("  tcp port 443 ", out var filter, out _));
        Assert.Equal("tcp port 443", filter!.Text);
    }

    /// <summary>Whatever is typed, parsing answers yes or no, and a parsed filter can be asked about any packet.</summary>
    [Fact]
    public void Random_filters_never_throw()
    {
        string[] words =
        {
            "tcp", "udp", "arp", "icmp", "ip", "ip6", "dns", "host", "src", "dst", "net", "port", "portrange", "less", "greater",
            "and", "or", "not", "(", ")", "!", "==", "!=", ">", "<", ">=", "<=", "=", "&&", "||", "contains", "eq", "ne", "gt",
            "ip.addr", "ip.src", "tcp.port", "udp.dstport", "frame.len", "frame.number", "ip.ttl", "tcp.flags.syn", "eth.addr", "info",
            "dns.name", "10.0.0.1", "10.0.0.0/8", "2001:db8::/32", "::1", "443", "0", "65535", "65536", "8000-8100", "1", "true",
            "02:00:00:00:00:0a", "\"who has\"", "'x'", "\"", "&", "|", "example", "-1", "1e9", "99999999999999999999", "/", "[::1]",
        };
        var random = new Random(4242);
        int accepted = 0;
        for (int i = 0; i < 40_000; i++)
        {
            int count = random.Next(1, 9);
            string text = string.Join(random.Next(4) == 0 ? "" : " ", Enumerable.Range(0, count).Select(_ => words[random.Next(words.Length)]));
            if (!PacketFilter.TryParse(text, out var filter, out var error))
            {
                Assert.False(string.IsNullOrEmpty(error));
                continue;
            }
            accepted++;
            foreach (var p in Packets) _ = filter!.Matches(p);
        }
        Assert.InRange(accepted, 1000, 39_000);   // the soup is neither all noise nor all valid
    }
}
