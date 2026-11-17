using System.Buffers.Binary;
using System.Net;
using System.Text;
using Echoes.Helpers;

namespace Echoes.Tests.Support;

/// <summary>
/// Packets built byte by byte from the protocols' own layouts (the RFCs), not with the code under test: what the
/// decoder, the filter and the capture files are given to read.
/// </summary>
internal static class Frames
{
    public static readonly byte[] MacA = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x0A };
    public static readonly byte[] MacB = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x0B };
    public static readonly byte[] Broadcast = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    public const ushort EtherIpv4 = 0x0800, EtherArp = 0x0806, EtherIpv6 = 0x86DD;
    public const byte Fin = 0x01, Syn = 0x02, Rst = 0x04, Psh = 0x08, Ack = 0x10;

    public static byte[] Join(params byte[][] parts)
    {
        var all = new byte[parts.Sum(p => p.Length)];
        int at = 0;
        foreach (var p in parts) { p.CopyTo(all, at); at += p.Length; }
        return all;
    }

    private static byte[] U16(int v) => new[] { (byte)(v >> 8), (byte)v };
    private static byte[] U32(uint v) => new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v };

    /// <summary>An Ethernet II frame; <paramref name="vlan"/> adds an 802.1Q tag.</summary>
    public static byte[] Ethernet(byte[] dst, byte[] src, ushort etherType, byte[] payload, int? vlan = null)
        => vlan is { } id
            ? Join(dst, src, U16(0x8100), U16(id & 0xFFF), U16(etherType), payload)
            : Join(dst, src, U16(etherType), payload);

    /// <summary>MacA → MacB, the usual wrapping of the samples.</summary>
    public static byte[] Ethernet(ushort etherType, byte[] payload) => Ethernet(MacB, MacA, etherType, payload);

    /// <summary>An IPv4 packet with a 20-byte header. <paramref name="fragmentOffset"/> in 8-byte units.</summary>
    public static byte[] Ipv4(string src, string dst, byte protocol, byte[] payload, byte ttl = 64, ushort id = 0x1234,
                              int fragmentOffset = 0, bool moreFragments = false, bool dontFragment = false)
    {
        var h = new byte[20];
        h[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(2), (ushort)(20 + payload.Length));
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(4), id);
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(6), (ushort)((dontFragment ? 0x4000 : 0) | (moreFragments ? 0x2000 : 0) | (fragmentOffset & 0x1FFF)));
        h[8] = ttl;
        h[9] = protocol;
        IPAddress.Parse(src).GetAddressBytes().CopyTo(h, 12);
        IPAddress.Parse(dst).GetAddressBytes().CopyTo(h, 16);
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(10), Checksum(h));
        return Join(h, payload);
    }

    /// <summary>An IPv6 packet with no extension headers.</summary>
    public static byte[] Ipv6(string src, string dst, byte next, byte[] payload, byte hopLimit = 64)
    {
        var h = new byte[40];
        h[0] = 0x60;
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(4), (ushort)payload.Length);
        h[6] = next;
        h[7] = hopLimit;
        IPAddress.Parse(src).GetAddressBytes().CopyTo(h, 8);
        IPAddress.Parse(dst).GetAddressBytes().CopyTo(h, 24);
        return Join(h, payload);
    }

    /// <summary>A TCP segment with a 20-byte header (the checksum is left zero: nothing here verifies it).</summary>
    public static byte[] Tcp(ushort sourcePort, ushort destPort, byte flags, byte[]? payload = null, uint seq = 1000, uint ack = 0,
                             ushort window = 64240)
    {
        var h = new byte[20];
        BinaryPrimitives.WriteUInt16BigEndian(h, sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(2), destPort);
        BinaryPrimitives.WriteUInt32BigEndian(h.AsSpan(4), seq);
        BinaryPrimitives.WriteUInt32BigEndian(h.AsSpan(8), ack);
        h[12] = 5 << 4;
        h[13] = flags;
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(14), window);
        return Join(h, payload ?? Array.Empty<byte>());
    }

    public static byte[] Udp(ushort sourcePort, ushort destPort, byte[] payload)
    {
        var h = new byte[8];
        BinaryPrimitives.WriteUInt16BigEndian(h, sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(2), destPort);
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(4), (ushort)(8 + payload.Length));
        return Join(h, payload);
    }

    /// <summary>An ICMP message: type, code, checksum, then four bytes (an echo's id and sequence) and the data.</summary>
    public static byte[] Icmp(byte type, byte code, ushort id = 0, ushort sequence = 0, byte[]? data = null)
    {
        var m = Join(new byte[] { type, code, 0, 0 }, U16(id), U16(sequence), data ?? Array.Empty<byte>());
        BinaryPrimitives.WriteUInt16BigEndian(m.AsSpan(2), Checksum(m));
        return m;
    }

    /// <summary>An ARP packet for Ethernet / IPv4. <paramref name="operation"/>: 1 request, 2 reply.</summary>
    public static byte[] Arp(int operation, byte[] senderMac, string senderIp, byte[] targetMac, string targetIp)
        => Join(U16(1), U16(EtherIpv4), new byte[] { 6, 4 }, U16(operation),
                senderMac, IPAddress.Parse(senderIp).GetAddressBytes(), targetMac, IPAddress.Parse(targetIp).GetAddressBytes());

    // ------------------------------------------------------------------ DNS

    /// <summary>A domain name as DNS writes it: length-prefixed labels and a zero.</summary>
    public static byte[] DnsName(string name)
    {
        var b = new List<byte>();
        foreach (string label in name.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            var text = Encoding.UTF8.GetBytes(label);
            b.Add((byte)text.Length);
            b.AddRange(text);
        }
        b.Add(0);
        return b.ToArray();
    }

    public static byte[] DnsQuery(ushort id, string name, ushort type, bool recursionDesired = true)
        => Join(U16(id), U16(recursionDesired ? 0x0100 : 0), U16(1), U16(0), U16(0), U16(0), DnsName(name), U16(type), U16(1));

    /// <summary>One resource record whose owner is a pointer to the question's name (offset 12).</summary>
    public static byte[] DnsRecord(ushort type, byte[] data, uint ttl = 300)
        => Join(new byte[] { 0xC0, 0x0C }, U16(type), U16(1), U32(ttl), U16(data.Length), data);

    /// <summary>A response to a one-question query. <paramref name="rcode"/>: 0 no error, 3 no such name.</summary>
    public static byte[] DnsResponse(ushort id, string name, ushort type, int rcode = 0, params byte[][] answers)
        => Join(U16(id), U16(0x8180 | (rcode & 0xF)), U16(1), U16(answers.Length), U16(0), U16(0), DnsName(name), U16(type), U16(1),
                Join(answers));

    // ------------------------------------------------------------------ TLS / HTTP

    /// <summary>A TLS 1.2-style Client Hello record that names <paramref name="serverName"/> (RFC 6066 section 3).</summary>
    public static byte[] ClientHello(string serverName)
    {
        var name = Encoding.ASCII.GetBytes(serverName);
        var sni = Join(U16(0), U16(name.Length + 5), U16(name.Length + 3), new byte[] { 0 }, U16(name.Length), name);
        var body = Join(new byte[] { 0x03, 0x03 }, new byte[32],          // version, random
                        new byte[] { 0 },                                  // session id length
                        U16(2), new byte[] { 0x13, 0x01 },                 // one cipher suite
                        new byte[] { 1, 0 },                               // one compression method: none
                        U16(sni.Length), sni);
        var handshake = Join(new byte[] { 0x01, 0, (byte)(body.Length >> 8), (byte)body.Length }, body);
        return Join(new byte[] { 0x16, 0x03, 0x01 }, U16(handshake.Length), handshake);
    }

    public static byte[] Http(string request) => Encoding.ASCII.GetBytes(request.Replace("\n", "\r\n"));

    // ------------------------------------------------------------------ records

    /// <summary>A packet record of <paramref name="data"/>, read by <paramref name="decoder"/> (or a new one).</summary>
    public static PacketRecord Record(byte[] data, LinkKind link = LinkKind.Ethernet, long number = 1, PacketDecoder? decoder = null,
                                      int? wireLength = null)
    {
        var p = new PacketRecord
        {
            Number = number,
            TimeUtc = new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc).AddTicks(number * 10),
            Data = data,
            WireLength = wireLength ?? data.Length,
            Link = link,
        };
        (decoder ?? new PacketDecoder()).Summarize(p);
        return p;
    }

    /// <summary>The Internet checksum (RFC 1071) of <paramref name="data"/>, whose checksum field is zero.</summary>
    public static ushort Checksum(ReadOnlySpan<byte> data)
    {
        uint sum = 0;
        for (int i = 0; i + 1 < data.Length; i += 2) sum += (uint)((data[i] << 8) | data[i + 1]);
        if ((data.Length & 1) != 0) sum += (uint)(data[^1] << 8);
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }

    // ------------------------------------------------------------------ the sample capture

    /// <summary>
    /// Six packets of different kinds, numbered 1-6, that the filter and file tests share:
    /// 1 a TCP SYN 10.0.0.1:50000 → 10.0.0.2:443; 2 a DNS query for example.com 10.0.0.1:5000 → 8.8.8.8:53;
    /// 3 an ARP request for 192.168.1.1 from 192.168.1.20; 4 an ICMP echo request 10.0.0.2 → 10.0.0.1 (TTL 3);
    /// 5 an HTTP GET over IPv6 [2001:db8::1]:1234 → [2001:db8::2]:80 for host test.example;
    /// 6 a TLS Client Hello 10.0.0.9:50001 → 1.1.1.1:443 naming one.one.one.one.
    /// </summary>
    public static List<PacketRecord> Samples()
    {
        var decoder = new PacketDecoder();
        var frames = new[]
        {
            Ethernet(EtherIpv4, Ipv4("10.0.0.1", "10.0.0.2", 6, Tcp(50000, 443, Syn))),
            Ethernet(EtherIpv4, Ipv4("10.0.0.1", "8.8.8.8", 17, Udp(5000, 53, DnsQuery(0xBEEF, "example.com", 1)))),
            Ethernet(Broadcast, MacA, EtherArp, Arp(1, MacA, "192.168.1.20", new byte[6], "192.168.1.1")),
            Ethernet(MacA, MacB, EtherIpv4, Ipv4("10.0.0.2", "10.0.0.1", 1, Icmp(8, 0, 0x0102, 7, new byte[32]), ttl: 3)),
            Ethernet(EtherIpv6, Ipv6("2001:db8::1", "2001:db8::2", 6,
                                     Tcp(1234, 80, Psh | Ack, Http("GET /index.html HTTP/1.1\nHost: test.example\nUser-Agent: t\n\n"), ack: 1))),
            Ethernet(EtherIpv4, Ipv4("10.0.0.9", "1.1.1.1", 6, Tcp(50001, 443, Psh | Ack, ClientHello("one.one.one.one"), ack: 1))),
        };
        var list = new List<PacketRecord>(frames.Length);
        for (int i = 0; i < frames.Length; i++) list.Add(Record(frames[i], LinkKind.Ethernet, i + 1, decoder));
        return list;
    }
}
