using System;
using System.Collections.Generic;
using System.Net;

namespace Echoes.Helpers;

/// <summary>What a captured frame starts with (the capture's data-link type).</summary>
public enum LinkKind
{
    /// <summary>An Ethernet header (also Wi-Fi as most systems hand it over, and Linux's loopback).</summary>
    Ethernet,
    /// <summary>The IP header itself: tunnels, PPP, and what Windows' raw sockets deliver.</summary>
    RawIp,
    /// <summary>BSD loopback: four bytes naming the protocol family (macOS's lo0, Npcap's loopback adapter).</summary>
    Null,
    /// <summary>Linux "cooked" capture: a 16-byte pseudo header.</summary>
    LinuxSll,
    Unknown,
}

public enum PacketL3 : byte { None, IPv4, IPv6, Arp, Other }

public enum PacketL4 : byte { None, Tcp, Udp, Icmp, Icmp6, Other }

/// <summary>An IPv4 or IPv6 address as two numbers: compared and masked without an allocation per packet.</summary>
public readonly record struct IpKey(ulong Hi, ulong Lo, bool V6)
{
    public static IpKey V4Of(ReadOnlySpan<byte> d, int o)
        => new(0, ((ulong)d[o] << 24) | ((ulong)d[o + 1] << 16) | ((ulong)d[o + 2] << 8) | d[o + 3], false);

    public static IpKey V6Of(ReadOnlySpan<byte> d, int o)
    {
        ulong hi = 0, lo = 0;
        for (int i = 0; i < 8; i++) hi = (hi << 8) | d[o + i];
        for (int i = 8; i < 16; i++) lo = (lo << 8) | d[o + i];
        return new IpKey(hi, lo, true);
    }

    public static IpKey Of(IPAddress a)
    {
        var b = a.GetAddressBytes();
        return b.Length == 4 ? V4Of(b, 0) : V6Of(b, 0);
    }

    public IPAddress ToAddress()
    {
        if (!V6) return new IPAddress(new[] { (byte)(Lo >> 24), (byte)(Lo >> 16), (byte)(Lo >> 8), (byte)Lo });
        var b = new byte[16];
        for (int i = 0; i < 8; i++) b[i] = (byte)(Hi >> (56 - 8 * i));
        for (int i = 0; i < 8; i++) b[8 + i] = (byte)(Lo >> (56 - 8 * i));
        return new IPAddress(b);
    }

    /// <summary>True when this address is inside <paramref name="net"/>/<paramref name="prefix"/> (same family).</summary>
    public bool In(IpKey net, int prefix)
    {
        if (V6 != net.V6) return false;
        if (!V6)
        {
            if (prefix <= 0) return true;
            ulong mask = prefix >= 32 ? 0xFFFFFFFFUL : (0xFFFFFFFFUL << (32 - prefix)) & 0xFFFFFFFFUL;
            return (Lo & mask) == (net.Lo & mask);
        }
        if (prefix <= 0) return true;
        if (prefix <= 64)
        {
            ulong mask = prefix == 64 ? ulong.MaxValue : ulong.MaxValue << (64 - prefix);
            return (Hi & mask) == (net.Hi & mask);
        }
        ulong low = prefix >= 128 ? ulong.MaxValue : ulong.MaxValue << (128 - prefix);
        return Hi == net.Hi && (Lo & low) == (net.Lo & low);
    }
}

/// <summary>
/// One captured packet: its bytes as they were on the interface, and what <see cref="PacketDecoder.Summarize"/> read
/// from them for the table and the filter (addresses, protocol, ports, one line of what it is).
/// </summary>
public sealed class PacketRecord
{
    /// <summary>1-based, in arrival order.</summary>
    public long Number;
    public DateTime TimeUtc;
    /// <summary>Seconds since the capture's first packet.</summary>
    public double Seconds;
    /// <summary>The captured bytes.</summary>
    public byte[] Data = Array.Empty<byte>();
    /// <summary>The packet's length on the wire (the capture may hold fewer bytes).</summary>
    public int WireLength;
    public LinkKind Link;

    // ---- decoded (PacketDecoder.Summarize) ----
    // (properties, not fields, where the table binds to them)
    public string Source { get; set; } = string.Empty;
    public string Destination { get; set; } = string.Empty;
    public string Protocol { get; set; } = string.Empty;
    public string Info { get; set; } = string.Empty;
    public PacketL3 L3;
    public PacketL4 L4;
    /// <summary>The IP protocol number (6 TCP, 17 UDP …); 0 when there is no IP header.</summary>
    public byte IpProto;
    public bool HasIp;
    public IpKey Src, Dst;
    public ushort SrcPort, DstPort;
    /// <summary>TCP flags (FIN 1, SYN 2, RST 4, PSH 8, ACK 16, URG 32).</summary>
    public byte TcpFlags;
    public byte Ttl;
    public bool HasMac;
    public ulong SrcMac, DstMac;
    /// <summary>A host name the packet carries: a DNS question, a TLS server name (SNI), an HTTP Host header.</summary>
    public string? Name;
    /// <summary>Something is wrong with it (a TCP reset, an ICMP error, a malformed header): the row is marked.</summary>
    public bool Alert { get; set; }

    /// <summary>The table's Time column: seconds since the first packet, to the microsecond.</summary>
    public string TimeText => Seconds.ToString("0.000000", System.Globalization.CultureInfo.InvariantCulture);
    public string LengthText => WireLength.ToString(System.Globalization.CultureInfo.InvariantCulture);
    public string NumberText => Number.ToString(System.Globalization.CultureInfo.InvariantCulture);

    // The colour of the Protocol cell, by kind (a packet marked Alert is red whatever it is):
    /// <summary>Name lookups: DNS and its local relatives.</summary>
    public bool ToneNames => !Alert && Protocol is "DNS" or "mDNS" or "LLMNR" or "NBNS";
    /// <summary>Encrypted sessions.</summary>
    public bool ToneSecure => !Alert && Protocol is "TLS" or "QUIC" or "SSH" or "WireGuard" or "IPsec";
    /// <summary>The network talking about itself: ARP, ICMP, DHCP, neighbor discovery.</summary>
    public bool ToneControl => !Alert && (L3 == PacketL3.Arp || L4 is PacketL4.Icmp or PacketL4.Icmp6 || Protocol is "DHCP" or "DHCPv6" or "IGMP" or "STP");
}

/// <summary>One protocol layer of a packet, for the detail pane: "Internet Protocol Version 4" and its fields.</summary>
public sealed record PacketLayer(string Title, IReadOnlyList<PacketField> Fields);

public sealed record PacketField(string Name, string Value);
