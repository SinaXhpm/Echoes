using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Echoes.Helpers;

/// <summary>
/// Reads a captured packet the way a packet analyser's table does: the addresses, the highest protocol it recognises
/// and one line saying what the packet is (<see cref="Summarize"/>), and, for the packet that is selected, every
/// layer with its fields (<see cref="Describe"/>).
/// <para>Link layers: Ethernet (with VLAN tags), raw IP, BSD loopback and Linux cooked capture. Above them ARP, IPv4,
/// IPv6 (with its extension headers), TCP, UDP, ICMP, ICMPv6 and IGMP, and what can be told from the first bytes of a
/// payload: DNS / mDNS / LLMNR, TLS (the server name of a Client Hello), HTTP, SSH, QUIC, DHCP, NTP, SSDP, STUN and
/// WireGuard. Nothing is reassembled: each packet is read on its own, which is what keeps this quick.</para>
/// <para>Every length comes from the packet, so every read is checked against what was captured; text taken from a
/// packet (names, request lines) goes through <see cref="RemoteText"/>. An instance keeps a small cache of address
/// texts and is used by one thread at a time.</para>
/// </summary>
public sealed class PacketDecoder
{
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;
    private const string Arrow = " → ";

    private readonly Dictionary<IpKey, string> _ipText = new();
    private readonly Dictionary<ulong, string> _macText = new();

    /// <summary>Fills the decoded fields of <paramref name="p"/> from its bytes. Never throws.</summary>
    public void Summarize(PacketRecord p)
    {
        try { Walk(p.Data, p, null); }
        catch (Exception e) when (e is IndexOutOfRangeException or ArgumentOutOfRangeException)
        {
            Malformed(p, p.Protocol.Length > 0 ? p.Protocol : "?");
        }
        if (p.Protocol.Length == 0) p.Protocol = "?";
    }

    /// <summary>Every layer of <paramref name="p"/> with its fields, outermost first. Never throws.</summary>
    public static IReadOnlyList<PacketLayer> Describe(PacketRecord p)
    {
        var layers = new List<PacketLayer>(6);
        var frame = new List<PacketField>(4)
        {
            new("Arrival", p.TimeUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss.ffffff", Inv)),
            new("Length", p.WireLength == p.Data.Length
                ? $"{p.WireLength} bytes"
                : $"{p.WireLength} bytes on the wire, {p.Data.Length} captured"),
        };
        layers.Add(new PacketLayer($"Frame {p.Number}", frame));
        var scratch = new PacketRecord { Data = p.Data, Link = p.Link, WireLength = p.WireLength };
        try { new PacketDecoder().Walk(p.Data, scratch, layers); }
        catch (Exception e) when (e is IndexOutOfRangeException or ArgumentOutOfRangeException)
        {
            layers.Add(new PacketLayer("Malformed", new[] { new PacketField("Note", "The packet ends before its headers do") }));
        }
        return layers;
    }

    // ------------------------------------------------------------------ link layer

    private void Walk(ReadOnlySpan<byte> d, PacketRecord p, List<PacketLayer>? layers)
    {
        int o;
        int etherType;
        switch (p.Link)
        {
            case LinkKind.Ethernet:
            {
                if (d.Length < 14) { Malformed(p, "Ethernet"); return; }
                p.DstMac = Mac48(d, 0);
                p.SrcMac = Mac48(d, 6);
                p.HasMac = true;
                p.Source = MacText(p.SrcMac);
                p.Destination = MacText(p.DstMac);
                etherType = U16(d, 12);
                o = 14;
                int vlan = -1;
                while (etherType is 0x8100 or 0x88A8 && d.Length >= o + 4)
                {
                    vlan = U16(d, o) & 0xFFF;
                    etherType = U16(d, o + 2);
                    o += 4;
                }
                if (layers is not null)
                {
                    var f = new List<PacketField>(4)
                    {
                        new("Destination", MacText(p.DstMac) + MacNote(p.DstMac)),
                        new("Source", MacText(p.SrcMac)),
                        new("Type", etherType < 0x0600 ? $"802.3 length {etherType}" : $"0x{etherType:x4} ({EtherName(etherType)})"),
                    };
                    if (vlan >= 0) f.Add(new("VLAN", vlan.ToString(Inv)));
                    layers.Add(new PacketLayer("Ethernet II", f));
                }
                if (etherType < 0x0600)
                {
                    // an 802.3 frame with an LLC header: spanning tree and its relatives
                    bool stp = p.DstMac == 0x0180C2000000UL;
                    p.Protocol = stp ? "STP" : "LLC";
                    p.Info = stp ? "Spanning tree BPDU" : $"802.3 frame, {etherType} bytes";
                    return;
                }
                break;
            }
            case LinkKind.LinuxSll:
            {
                if (d.Length < 16) { Malformed(p, "SLL"); return; }
                int kind = U16(d, 0), addrLen = U16(d, 4);
                etherType = U16(d, 14);
                if (addrLen == 6)
                {
                    p.SrcMac = Mac48(d, 6);
                    p.Source = MacText(p.SrcMac);
                }
                o = 16;
                layers?.Add(new PacketLayer("Linux cooked capture", new[]
                {
                    new PacketField("Packet type", kind switch { 0 => "To this host", 1 => "Broadcast", 2 => "Multicast", 3 => "To another host", 4 => "Sent by this host", _ => kind.ToString(Inv) }),
                    new PacketField("Protocol", $"0x{etherType:x4} ({EtherName(etherType)})"),
                }));
                break;
            }
            case LinkKind.Null:
            {
                if (d.Length < 4) { Malformed(p, "Loopback"); return; }
                // the protocol family, in the byte order of the machine that captured it: 2 = IPv4; 10 / 23 / 24 / 28 / 30
                // = IPv6 on Linux / Windows / the BSDs / macOS. The IP version nibble settles what the family doesn't.
                o = 4;
                etherType = d.Length > 4 ? (d[4] >> 4) switch { 4 => 0x0800, 6 => 0x86DD, _ => 0 } : 0;
                layers?.Add(new PacketLayer("Loopback", new[] { new PacketField("Family", etherType == 0x0800 ? "IPv4" : etherType == 0x86DD ? "IPv6" : "Unknown") }));
                break;
            }
            case LinkKind.RawIp:
                o = 0;
                etherType = d.Length > 0 ? (d[0] >> 4) switch { 4 => 0x0800, 6 => 0x86DD, _ => 0 } : 0;
                break;
            default:
                p.Protocol = "?";
                p.Info = $"{d.Length} bytes (this link type isn't decoded)";
                return;
        }

        switch (etherType)
        {
            case 0x0800: Ipv4(d, o, p, layers); break;
            case 0x86DD: Ipv6(d, o, p, layers); break;
            case 0x0806: Arp(d, o, p, layers); break;
            default:
                p.L3 = PacketL3.Other;
                p.Protocol = EtherName(etherType);
                p.Info = etherType == 0 ? $"{d.Length - o} bytes, not IP" : $"{EtherName(etherType)} frame, {d.Length - o} bytes";
                break;
        }
    }

    private static string EtherName(int type) => type switch
    {
        0x0800 => "IPv4",
        0x86DD => "IPv6",
        0x0806 => "ARP",
        0x8100 => "VLAN",
        0x88CC => "LLDP",
        0x888E => "EAPOL",
        0x8863 or 0x8864 => "PPPoE",
        0x8847 or 0x8848 => "MPLS",
        0x88E1 => "HomePlug",
        0x8899 => "Realtek",
        0 => "?",
        _ => $"0x{type:x4}",
    };

    // ------------------------------------------------------------------ ARP

    private void Arp(ReadOnlySpan<byte> d, int o, PacketRecord p, List<PacketLayer>? layers)
    {
        p.L3 = PacketL3.Arp;
        p.Protocol = "ARP";
        if (d.Length < o + 28 || d[o + 4] != 6 || d[o + 5] != 4) { p.Info = "ARP (not Ethernet / IPv4)"; return; }
        int op = U16(d, o + 6);
        ulong senderMac = Mac48(d, o + 8), targetMac = Mac48(d, o + 18);
        var sender = IpKey.V4Of(d, o + 14);
        var target = IpKey.V4Of(d, o + 24);
        // the addresses it is about, so "host 192.168.1.1" finds it
        p.Src = sender;
        p.Dst = target;
        p.HasIp = true;
        string who = IpText(sender), about = IpText(target);
        p.Info = op switch
        {
            1 when sender == target => $"Gratuitous ARP for {who}",
            1 => $"Who has {about}? Tell {who}",
            2 => $"{who} is at {MacText(senderMac)}",
            _ => $"ARP operation {op}",
        };
        layers?.Add(new PacketLayer("Address Resolution Protocol", new[]
        {
            new PacketField("Operation", op switch { 1 => "Request (1)", 2 => "Reply (2)", _ => op.ToString(Inv) }),
            new PacketField("Sender", $"{who} ({MacText(senderMac)})"),
            new PacketField("Target", $"{about} ({MacText(targetMac)})"),
        }));
    }

    // ------------------------------------------------------------------ IP

    private void Ipv4(ReadOnlySpan<byte> d, int o, PacketRecord p, List<PacketLayer>? layers)
    {
        p.L3 = PacketL3.IPv4;
        if (d.Length < o + 20 || (d[o] >> 4) != 4) { Malformed(p, "IPv4"); return; }
        int ihl = (d[o] & 0xF) * 4;
        if (ihl < 20 || d.Length < o + ihl) { Malformed(p, "IPv4"); return; }
        int total = U16(d, o + 2), id = U16(d, o + 4), frag = U16(d, o + 6);
        bool df = (frag & 0x4000) != 0, more = (frag & 0x2000) != 0;
        int offset = (frag & 0x1FFF) * 8;
        byte ttl = d[o + 8], proto = d[o + 9];
        p.Src = IpKey.V4Of(d, o + 12);
        p.Dst = IpKey.V4Of(d, o + 16);
        p.HasIp = true;
        p.Source = IpText(p.Src);
        p.Destination = IpText(p.Dst);
        p.Ttl = ttl;
        p.IpProto = proto;
        // The header's own length ends the packet (Ethernet pads short frames). 0: a packet this computer handed to the
        // network card to split (segmentation offload), captured before that; then what was captured is the packet.
        int end = total >= ihl ? Math.Min(d.Length, o + total) : d.Length;

        layers?.Add(new PacketLayer("Internet Protocol Version 4", new[]
        {
            new PacketField("Source", p.Source),
            new PacketField("Destination", p.Destination),
            new PacketField("Protocol", $"{ProtoName(proto)} ({proto})"),
            new PacketField("Time to live", ttl.ToString(Inv)),
            new PacketField("Total length", total == 0 ? "0 (segmentation offload)" : total.ToString(Inv)),
            new PacketField("Identification", $"0x{id:x4}"),
            new PacketField("Flags", (df ? "Don't fragment" : "May fragment") + (more ? ", more fragments" : string.Empty) + (offset > 0 ? $", offset {offset}" : string.Empty)),
            new PacketField("Header length", $"{ihl} bytes" + ((d[o + 1] >> 2) != 0 ? $", DSCP {d[o + 1] >> 2}" : string.Empty)),
        }));

        if (offset > 0)
        {
            // a later fragment has no transport header of its own
            p.Protocol = "IPv4";
            p.Info = $"Fragment of a {ProtoName(proto)} packet (offset {offset}, id 0x{id:x4})";
            return;
        }
        Transport(d[..end], o + ihl, proto, p, layers);
        if (more) p.Info += " [first fragment]";
    }

    private void Ipv6(ReadOnlySpan<byte> d, int o, PacketRecord p, List<PacketLayer>? layers)
    {
        p.L3 = PacketL3.IPv6;
        if (d.Length < o + 40 || (d[o] >> 4) != 6) { Malformed(p, "IPv6"); return; }
        int payload = U16(d, o + 4);
        byte next = d[o + 6], hop = d[o + 7];
        p.Src = IpKey.V6Of(d, o + 8);
        p.Dst = IpKey.V6Of(d, o + 24);
        p.HasIp = true;
        p.Source = IpText(p.Src);
        p.Destination = IpText(p.Dst);
        p.Ttl = hop;
        int at = o + 40;
        int end = payload > 0 ? Math.Min(d.Length, at + payload) : d.Length;   // 0: segmentation offload, as for IPv4

        // extension headers, up to the transport header
        string? extensions = null;
        for (int guard = 0; guard < 8; guard++)
        {
            if (next is 0 or 43 or 60)
            {
                if (end < at + 8) break;
                extensions = Join(extensions, next switch { 0 => "Hop-by-hop options", 43 => "Routing", _ => "Destination options" });
                int len = (d[at + 1] + 1) * 8;
                next = d[at];
                at += len;
            }
            else if (next == 44)
            {
                if (end < at + 8) break;
                int offset = U16(d, at + 2) & 0xFFF8;
                extensions = Join(extensions, "Fragment");
                next = d[at];
                at += 8;
                if (offset > 0)
                {
                    p.IpProto = next;
                    p.Protocol = "IPv6";
                    p.Info = $"Fragment of a {ProtoName(next)} packet (offset {offset})";
                    AddV6Layer(layers, p, next, hop, payload, extensions);
                    return;
                }
            }
            else if (next == 51)
            {
                if (end < at + 8) break;
                extensions = Join(extensions, "Authentication header");
                int len = (d[at + 1] + 2) * 4;
                next = d[at];
                at += len;
            }
            else break;
        }
        p.IpProto = next;
        AddV6Layer(layers, p, next, hop, payload, extensions);
        if (at > end) { Malformed(p, "IPv6"); return; }
        Transport(d[..end], at, next, p, layers);
    }

    private static void AddV6Layer(List<PacketLayer>? layers, PacketRecord p, byte next, byte hop, int payload, string? extensions)
    {
        if (layers is null) return;
        var f = new List<PacketField>(6)
        {
            new("Source", p.Source),
            new("Destination", p.Destination),
            new("Next header", $"{ProtoName(next)} ({next})"),
            new("Hop limit", hop.ToString(Inv)),
            new("Payload length", payload.ToString(Inv)),
        };
        if (extensions is not null) f.Add(new("Extension headers", extensions));
        layers.Add(new PacketLayer("Internet Protocol Version 6", f));
    }

    private static string Join(string? list, string item) => list is null ? item : list + ", " + item;

    private static string ProtoName(byte proto) => proto switch
    {
        1 => "ICMP",
        2 => "IGMP",
        4 => "IPIP",
        6 => "TCP",
        17 => "UDP",
        41 => "IPv6-in-IP",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        59 => "No next header",
        89 => "OSPF",
        103 => "PIM",
        112 => "VRRP",
        132 => "SCTP",
        _ => "Protocol " + proto.ToString(Inv),
    };

    // ------------------------------------------------------------------ transport

    private void Transport(ReadOnlySpan<byte> d, int o, byte proto, PacketRecord p, List<PacketLayer>? layers)
    {
        switch (proto)
        {
            case 6: Tcp(d, o, p, layers); break;
            case 17: Udp(d, o, p, layers); break;
            case 1: Icmp(d, o, p, layers); break;
            case 58: Icmp6(d, o, p, layers); break;
            case 2:
                p.L4 = PacketL4.Other;
                p.Protocol = "IGMP";
                p.Info = d.Length > o ? d[o] switch
                {
                    0x11 => "Membership query",
                    0x12 or 0x16 or 0x22 => "Membership report",
                    0x17 => "Leave group",
                    _ => $"IGMP type 0x{d[o]:x2}",
                } : "IGMP";
                break;
            default:
                p.L4 = PacketL4.Other;
                p.Protocol = proto is 50 or 51 ? "IPsec" : ProtoName(proto);
                p.Info = $"{ProtoName(proto)}, {Math.Max(0, d.Length - o)} bytes";
                break;
        }
    }

    private void Tcp(ReadOnlySpan<byte> d, int o, PacketRecord p, List<PacketLayer>? layers)
    {
        p.L4 = PacketL4.Tcp;
        p.Protocol = "TCP";
        if (d.Length < o + 20) { p.Info = "TCP header cut short"; p.Alert = true; return; }
        ushort sp = (ushort)U16(d, o), dp = (ushort)U16(d, o + 2);
        uint seq = U32(d, o + 4), ack = U32(d, o + 8);
        int header = (d[o + 12] >> 4) * 4;
        byte flags = d[o + 13];
        int window = U16(d, o + 14);
        p.SrcPort = sp;
        p.DstPort = dp;
        p.TcpFlags = flags;
        if (header < 20 || d.Length < o + header) { p.Info = $"{sp}{Arrow}{dp} TCP header cut short"; p.Alert = true; return; }
        int at = o + header, length = d.Length - at;
        bool isAck = (flags & 0x10) != 0;
        if ((flags & 0x04) != 0) p.Alert = true;   // a reset
        string flagText = FlagText(flags);
        p.Info = $"{sp}{Arrow}{dp} [{flagText}] Seq={seq}{(isAck ? " Ack=" + ack.ToString(Inv) : string.Empty)} Win={window} Len={length}";

        if (layers is not null)
        {
            var f = new List<PacketField>(8)
            {
                new("Source port", sp.ToString(Inv) + PortNote(sp)),
                new("Destination port", dp.ToString(Inv) + PortNote(dp)),
                new("Flags", $"{flagText} (0x{flags:x2})"),
                new("Sequence number", seq.ToString(Inv)),
            };
            if (isAck) f.Add(new("Acknowledgment number", ack.ToString(Inv)));
            f.Add(new("Window", window.ToString(Inv)));
            if (header > 20 && TcpOptions(d.Slice(o + 20, header - 20)) is { Length: > 0 } options) f.Add(new("Options", options));
            f.Add(new("Payload", $"{length} bytes"));
            layers.Add(new PacketLayer("Transmission Control Protocol", f));
        }
        if (length > 0) TcpPayload(d[at..], sp, dp, p, layers);
    }

    private static string FlagText(byte flags)
    {
        var sb = new StringBuilder(24);
        void Add(int bit, string name)
        {
            if ((flags & bit) == 0) return;
            if (sb.Length > 0) sb.Append(", ");
            sb.Append(name);
        }
        Add(0x02, "SYN");
        Add(0x01, "FIN");
        Add(0x04, "RST");
        Add(0x08, "PSH");
        Add(0x10, "ACK");
        Add(0x20, "URG");
        Add(0x40, "ECE");
        Add(0x80, "CWR");
        return sb.Length == 0 ? "none" : sb.ToString();
    }

    private static string TcpOptions(ReadOnlySpan<byte> o)
    {
        var sb = new StringBuilder(48);
        void Add(string s)
        {
            if (sb.Length > 0) sb.Append(", ");
            sb.Append(s);
        }
        for (int i = 0; i < o.Length;)
        {
            byte kind = o[i];
            if (kind == 0) break;
            if (kind == 1) { i++; continue; }
            if (i + 1 >= o.Length) break;
            int len = o[i + 1];
            if (len < 2 || i + len > o.Length) break;
            switch (kind)
            {
                case 2 when len == 4: Add("MSS " + U16(o, i + 2).ToString(Inv)); break;
                case 3 when len == 3: Add("window scale " + o[i + 2].ToString(Inv)); break;
                case 4: Add("SACK permitted"); break;
                case 5: Add("SACK"); break;
                case 8 when len == 10: Add("timestamps"); break;
                case 30: Add("multipath TCP"); break;
                case 34: Add("fast open"); break;
                default: Add("option " + kind.ToString(Inv)); break;
            }
            i += len;
        }
        return sb.ToString();
    }

    private static void TcpPayload(ReadOnlySpan<byte> pl, ushort sp, ushort dp, PacketRecord p, List<PacketLayer>? layers)
    {
        string ports = $"{sp}{Arrow}{dp}  ";

        // TLS: a record header (type 20-23, version 3.x), most often at the start of a segment
        if (pl.Length >= 5 && pl[0] is >= 20 and <= 23 && pl[1] == 3 && pl[2] <= 4)
        {
            string what = TlsRecord(pl, out string? sni, out string? detail);
            p.Protocol = "TLS";
            p.Info = ports + what;
            if (sni is not null) p.Name = sni;
            if (layers is not null)
            {
                var f = new List<PacketField>(3) { new("Record", what), new("Version", TlsVersion(pl[1], pl[2])) };
                if (sni is not null) f.Add(new("Server name", sni));
                if (detail is not null) f.Add(new("Handshake", detail));
                layers.Add(new PacketLayer("Transport Layer Security", f));
            }
            return;
        }

        // HTTP: a request line or a status line in plain text
        if (HttpLine(pl) is { } line)
        {
            p.Protocol = "HTTP";
            p.Info = ports + line;
            string? host = HttpHeader(pl, "Host");
            if (host is not null) p.Name = host;
            if (layers is not null)
            {
                var f = new List<PacketField>(6) { new(line.StartsWith("HTTP/", StringComparison.Ordinal) ? "Status" : "Request", line) };
                foreach (string h in new[] { "Host", "User-Agent", "Content-Type", "Content-Length", "Server", "Location" })
                    if (HttpHeader(pl, h) is { } v) f.Add(new(h, v));
                layers.Add(new PacketLayer("Hypertext Transfer Protocol", f));
            }
            return;
        }

        if (pl.Length >= 4 && pl[0] == 'S' && pl[1] == 'S' && pl[2] == 'H' && pl[3] == '-')
        {
            string banner = FirstLine(pl, 80);
            p.Protocol = "SSH";
            p.Info = ports + banner;
            layers?.Add(new PacketLayer("Secure Shell", new[] { new PacketField("Banner", banner) }));
            return;
        }

        // DNS over TCP: a two-byte length, then the message
        if ((sp == 53 || dp == 53) && pl.Length > 14 && U16(pl, 0) <= pl.Length - 2
            && Dns(pl[2..], false, out string dns, out string? qname, layers))
        {
            p.Protocol = "DNS";
            p.Info = ports + dns;
            p.Name = qname;
        }
    }

    private void Udp(ReadOnlySpan<byte> d, int o, PacketRecord p, List<PacketLayer>? layers)
    {
        p.L4 = PacketL4.Udp;
        p.Protocol = "UDP";
        if (d.Length < o + 8) { p.Info = "UDP header cut short"; p.Alert = true; return; }
        ushort sp = (ushort)U16(d, o), dp = (ushort)U16(d, o + 2);
        p.SrcPort = sp;
        p.DstPort = dp;
        var pl = d[(o + 8)..];
        p.Info = $"{sp}{Arrow}{dp} Len={pl.Length}";
        layers?.Add(new PacketLayer("User Datagram Protocol", new[]
        {
            new PacketField("Source port", sp.ToString(Inv) + PortNote(sp)),
            new PacketField("Destination port", dp.ToString(Inv) + PortNote(dp)),
            new PacketField("Payload", $"{pl.Length} bytes"),
        }));
        if (pl.Length > 0) UdpPayload(pl, sp, dp, p, layers);
    }

    private static void UdpPayload(ReadOnlySpan<byte> pl, ushort sp, ushort dp, PacketRecord p, List<PacketLayer>? layers)
    {
        string ports = $"{sp}{Arrow}{dp}  ";
        bool Port(int n) => sp == n || dp == n;

        if (Port(53) || Port(5353) || Port(5355))
        {
            bool mdns = Port(5353);
            if (Dns(pl, mdns, out string dns, out string? qname, layers))
            {
                p.Protocol = mdns ? "mDNS" : Port(5355) ? "LLMNR" : "DNS";
                p.Info = ports + dns;
                p.Name = qname;
            }
            return;
        }
        if (Port(137))
        {
            p.Protocol = "NBNS";
            p.Info = ports + (pl.Length > 2 && (pl[2] & 0x80) != 0 ? "NetBIOS name response" : "NetBIOS name query");
            return;
        }
        if ((Port(67) || Port(68)) && pl.Length >= 240 && U32(pl, 236) == 0x63825363)
        {
            string type = DhcpType(pl, out string? requested, out string? hostName);
            p.Protocol = "DHCP";
            p.Info = ports + "DHCP " + type + (requested is not null ? " for " + requested : string.Empty);
            if (layers is not null)
            {
                var f = new List<PacketField>(5)
                {
                    new("Message", type),
                    new("Client hardware address", MacTextStatic(Mac48(pl, 28))),
                };
                var yours = IpKey.V4Of(pl, 16);
                if (yours.Lo != 0) f.Add(new("Your address", yours.ToAddress().ToString()));
                if (requested is not null) f.Add(new("Requested address", requested));
                if (hostName is not null) f.Add(new("Host name", hostName));
                layers.Add(new PacketLayer("Dynamic Host Configuration Protocol", f));
            }
            return;
        }
        if (Port(546) || Port(547))
        {
            p.Protocol = "DHCPv6";
            p.Info = ports + (pl[0] switch { 1 => "Solicit", 2 => "Advertise", 3 => "Request", 5 => "Renew", 7 => "Reply", 8 => "Release", 11 => "Information request", _ => "DHCPv6 message " + pl[0].ToString(Inv) });
            return;
        }
        if (Port(123) && pl.Length >= 48)
        {
            int version = (pl[0] >> 3) & 7, mode = pl[0] & 7;
            p.Protocol = "NTP";
            p.Info = ports + $"NTP v{version} " + mode switch { 1 => "symmetric active", 2 => "symmetric passive", 3 => "client", 4 => "server", 5 => "broadcast", _ => "mode " + mode.ToString(Inv) };
            return;
        }
        if (Port(1900) && HttpLine(pl) is { } ssdp)
        {
            p.Protocol = "SSDP";
            p.Info = ports + ssdp;
            return;
        }
        if (pl.Length >= 20 && U32(pl, 4) == 0x2112A442 && (pl[0] & 0xC0) == 0)
        {
            int type = U16(pl, 0);
            p.Protocol = "STUN";
            p.Info = ports + ((type & 0x3EEF) == 1 ? "Binding " : "STUN ") + (type & 0x0110) switch { 0x0000 => "request", 0x0010 => "indication", 0x0100 => "success response", _ => "error response" };
            return;
        }
        // WireGuard: a message type, three zero bytes, and each handshake message's exact size
        if (pl.Length >= 32 && pl[1] == 0 && pl[2] == 0 && pl[3] == 0 && pl[0] is >= 1 and <= 4)
        {
            string? wg = pl[0] switch
            {
                1 when pl.Length == 148 => "Handshake initiation",
                2 when pl.Length == 92 => "Handshake response",
                3 when pl.Length == 64 => "Cookie reply",
                4 when (pl.Length - 32) % 16 == 0 => pl.Length == 32 ? "Keepalive" : $"Transport data, {pl.Length - 32} bytes",
                _ => null,
            };
            if (wg is not null)
            {
                p.Protocol = "WireGuard";
                p.Info = ports + wg;
                return;
            }
        }
        // QUIC: a long header (handshake packets, with a version), or anything else on UDP 443
        if (pl.Length >= 7 && (pl[0] & 0xC0) == 0xC0 && (Port(443) || U32(pl, 1) is 1 or 0x6b3343cf or 0xff00001d))
        {
            uint version = U32(pl, 1);
            string type = ((pl[0] >> 4) & 3) switch { 0 => "Initial", 1 => "0-RTT", 2 => "Handshake", _ => "Retry" };
            p.Protocol = "QUIC";
            p.Info = ports + (version == 0 ? "Version negotiation" : $"{type} (version {(version == 1 ? "1" : version == 0x6b3343cf ? "2" : "0x" + version.ToString("x8", Inv))})");
            return;
        }
        if (Port(443) && (pl[0] & 0x80) == 0 && (pl[0] & 0x40) != 0)
        {
            p.Protocol = "QUIC";
            p.Info = ports + $"Protected payload, {pl.Length} bytes";
        }
    }

    // ------------------------------------------------------------------ ICMP

    private void Icmp(ReadOnlySpan<byte> d, int o, PacketRecord p, List<PacketLayer>? layers)
    {
        p.L4 = PacketL4.Icmp;
        p.Protocol = "ICMP";
        if (d.Length < o + 8) { p.Info = "ICMP header cut short"; p.Alert = true; return; }
        byte type = d[o], code = d[o + 1];
        string what;
        switch (type)
        {
            case 0 or 8:
                what = $"Echo (ping) {(type == 8 ? "request" : "reply")} id=0x{U16(d, o + 4):x4}, seq={U16(d, o + 6)}, ttl={p.Ttl}";
                break;
            case 3:
                p.Alert = true;
                what = "Destination unreachable (" + code switch
                {
                    0 => "network unreachable",
                    1 => "host unreachable",
                    2 => "protocol unreachable",
                    3 => "port unreachable",
                    4 => $"fragmentation needed, MTU {U16(d, o + 6)}",
                    9 or 10 or 13 => "administratively prohibited",
                    _ => "code " + code.ToString(Inv),
                } + ")";
                break;
            case 11:
                p.Alert = true;
                what = code == 0 ? "Time-to-live exceeded in transit" : "Fragment reassembly time exceeded";
                break;
            case 5: what = "Redirect"; break;
            case 4: what = "Source quench"; break;
            case 9: what = "Router advertisement"; break;
            case 10: what = "Router solicitation"; break;
            case 13 or 14: what = type == 13 ? "Timestamp request" : "Timestamp reply"; break;
            default: what = $"Type {type}, code {code}"; break;
        }
        p.Info = what;
        layers?.Add(new PacketLayer("Internet Control Message Protocol", new[]
        {
            new PacketField("Type", $"{type} ({what})"),
            new PacketField("Code", code.ToString(Inv)),
        }));
    }

    private void Icmp6(ReadOnlySpan<byte> d, int o, PacketRecord p, List<PacketLayer>? layers)
    {
        p.L4 = PacketL4.Icmp6;
        p.Protocol = "ICMPv6";
        if (d.Length < o + 4) { p.Info = "ICMPv6 header cut short"; p.Alert = true; return; }
        byte type = d[o], code = d[o + 1];
        // neighbor discovery names the address it is about
        string target = type is 135 or 136 && d.Length >= o + 24 ? " " + IpText(IpKey.V6Of(d, o + 8)) : string.Empty;
        string what;
        switch (type)
        {
            case 128 or 129:
                what = d.Length >= o + 8
                    ? $"Echo (ping) {(type == 128 ? "request" : "reply")} id=0x{U16(d, o + 4):x4}, seq={U16(d, o + 6)}, hop limit={p.Ttl}"
                    : "Echo (ping)";
                break;
            case 1:
                p.Alert = true;
                what = "Destination unreachable (" + code switch { 0 => "no route", 1 => "administratively prohibited", 3 => "address unreachable", 4 => "port unreachable", _ => "code " + code.ToString(Inv) } + ")";
                break;
            case 2:
                p.Alert = true;
                what = d.Length >= o + 8 ? $"Packet too big, MTU {U32(d, o + 4)}" : "Packet too big";
                break;
            case 3:
                p.Alert = true;
                what = "Hop limit exceeded in transit";
                break;
            case 133: what = "Router solicitation"; break;
            case 134: what = "Router advertisement"; break;
            case 135: what = "Neighbor solicitation for" + target; break;
            case 136: what = "Neighbor advertisement:" + target; break;
            case 130: what = "Multicast listener query"; break;
            case 131 or 143: what = "Multicast listener report"; break;
            case 132: what = "Multicast listener done"; break;
            default: what = $"Type {type}, code {code}"; break;
        }
        p.Info = what;
        layers?.Add(new PacketLayer("Internet Control Message Protocol v6", new[]
        {
            new PacketField("Type", $"{type} ({what})"),
            new PacketField("Code", code.ToString(Inv)),
        }));
    }

    // ------------------------------------------------------------------ application payloads

    /// <summary>A DNS message in one line ("Standard query 0x1a2b A example.com", "… response … → 93.184.216.34").</summary>
    private static bool Dns(ReadOnlySpan<byte> m, bool multicast, out string info, out string? name, List<PacketLayer>? layers)
    {
        info = string.Empty;
        name = null;
        if (m.Length < 12) return false;
        int id = U16(m, 0), flags = U16(m, 2), questions = U16(m, 4), answers = U16(m, 6);
        bool response = (flags & 0x8000) != 0;
        int opcode = (flags >> 11) & 0xF, rcode = flags & 0xF;
        if (questions > 64 || answers > 512) return false;   // not DNS: something else on the port

        int at = 12;
        int qtype = 0;
        for (int q = 0; q < questions; q++)
        {
            string? n = DnsName(m, ref at);
            if (n is null || at + 4 > m.Length) return false;
            if (q == 0)
            {
                name = n;
                qtype = U16(m, at);
            }
            at += 4;
        }

        var sb = new StringBuilder(96);
        sb.Append(opcode switch { 0 => "Standard query", 4 => "Notify", 5 => "Dynamic update", _ => "Opcode " + opcode.ToString(Inv) });
        if (response) sb.Append(" response");
        if (!multicast) sb.Append(" 0x").Append(id.ToString("x4", Inv));
        if (name is not null) sb.Append(' ').Append(DnsType(qtype)).Append(' ').Append(name.Length == 0 ? "<root>" : name);

        var found = layers is null ? null : new List<string>();
        if (response)
        {
            if (rcode != 0)
                sb.Append(": ").Append(rcode switch { 1 => "format error", 2 => "server failure", 3 => "no such name", 4 => "not implemented", 5 => "refused", _ => "error " + rcode.ToString(Inv) });
            else
            {
                int shown = 0;
                for (int a = 0; a < answers && at < m.Length; a++)
                {
                    if (DnsName(m, ref at) is null || at + 10 > m.Length) break;
                    int type = U16(m, at), length = U16(m, at + 8);
                    at += 10;
                    if (at + length > m.Length) break;
                    string? value = type switch
                    {
                        1 when length == 4 => IpKey.V4Of(m, at).ToAddress().ToString(),
                        28 when length == 16 => IpKey.V6Of(m, at).ToAddress().ToString(),
                        5 or 2 or 12 => NameAt(m, at),
                        _ => null,
                    };
                    at += length;
                    string text = value is null ? DnsType(type) : type is 1 or 28 ? value : DnsType(type) + " " + value;
                    found?.Add(text);
                    if (shown < 3) sb.Append(shown == 0 ? Arrow : ", ").Append(text);
                    shown++;
                }
                if (shown > 3) sb.Append(", +").Append(shown - 3);
                if (answers == 0 && name is not null && !multicast) sb.Append(": no answer");
            }
        }
        info = sb.ToString();

        if (layers is not null)
        {
            var f = new List<PacketField>(5)
            {
                new("Message", (response ? "Response" : "Query") + $", ID 0x{id:x4}"),
            };
            if (name is not null) f.Add(new("Question", $"{DnsType(qtype)} {(name.Length == 0 ? "<root>" : name)}"));
            if (response) f.Add(new("Reply code", rcode == 0 ? "No error" : rcode.ToString(Inv)));
            if (found is { Count: > 0 }) f.Add(new("Answers", string.Join(", ", found)));
            f.Add(new("Flags", ((flags & 0x0400) != 0 ? "authoritative, " : string.Empty) + ((flags & 0x0200) != 0 ? "truncated, " : string.Empty)
                               + ((flags & 0x0100) != 0 ? "recursion desired" : "no recursion") + ((flags & 0x0080) != 0 ? ", recursion available" : string.Empty)));
            layers.Add(new PacketLayer("Domain Name System", f));
        }
        return true;

        static string? NameAt(ReadOnlySpan<byte> msg, int offset)
        {
            int o = offset;
            return DnsName(msg, ref o);
        }
    }

    // A (possibly compressed) domain name; null when it runs off the message or loops. (LanDiscovery reads mDNS and
    // LLMNR answers with it too.)
    internal static string? DnsName(ReadOnlySpan<byte> m, ref int at)
    {
        var sb = new StringBuilder(48);
        int pos = at, jumps = 0;
        bool jumped = false;
        while (true)
        {
            if (pos >= m.Length) return null;
            int len = m[pos];
            if (len == 0)
            {
                if (!jumped) at = pos + 1;
                break;
            }
            if ((len & 0xC0) == 0xC0)
            {
                if (pos + 1 >= m.Length || ++jumps > 32) return null;
                if (!jumped) at = pos + 2;
                jumped = true;
                pos = ((len & 0x3F) << 8) | m[pos + 1];
                continue;
            }
            if ((len & 0xC0) != 0 || pos + 1 + len > m.Length || sb.Length + len > 255) return null;
            if (sb.Length > 0) sb.Append('.');
            // A label is bytes: host names are ASCII, but the instance names of DNS-SD ("Living Room TV") have spaces
            // and UTF-8. Decoded as UTF-8; control characters and the ones that reorder text become '?'.
            foreach (char c in Encoding.UTF8.GetString(m.Slice(pos + 1, len)))
                sb.Append(char.IsControl(c) || c is >= (char)0x2028 and <= (char)0x202E || c is >= (char)0x2066 and <= (char)0x2069 || c == (char)0xFFFD ? '?' : c);
            pos += len + 1;
        }
        return sb.ToString();
    }

    private static string DnsType(int type) => type switch
    {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        41 => "OPT",
        43 => "DS",
        46 => "RRSIG",
        48 => "DNSKEY",
        64 => "SVCB",
        65 => "HTTPS",
        255 => "ANY",
        257 => "CAA",
        _ => "TYPE" + type.ToString(Inv),
    };

    private static string TlsVersion(byte major, byte minor) => (major, minor) switch
    {
        (3, 0) => "SSL 3.0",
        (3, 1) => "TLS 1.0",
        (3, 2) => "TLS 1.1",
        (3, 3) => "TLS 1.2",
        (3, 4) => "TLS 1.3",
        _ => $"{major}.{minor}",
    };

    // The first TLS record of a segment in words; a Client Hello's server name when it is there.
    private static string TlsRecord(ReadOnlySpan<byte> r, out string? sni, out string? detail)
    {
        sni = null;
        detail = null;
        int length = U16(r, 3);
        switch (r[0])
        {
            case 20: return "Change Cipher Spec";
            case 21: return "Alert";
            case 23: return $"Application Data, {length} bytes";
        }
        if (r.Length < 10) return "Handshake";
        byte type = r[5];
        switch (type)
        {
            case 1:
                sni = ClientHelloName(r[5..], out detail);
                return sni is null ? "Client Hello" : $"Client Hello (SNI={sni})";
            case 2: return "Server Hello";
            case 4: return "New Session Ticket";
            case 11: return "Certificate";
            case 12: return "Server Key Exchange";
            case 14: return "Server Hello Done";
            case 16: return "Client Key Exchange";
            case 20: return "Finished";
            default: return "Handshake (encrypted)";
        }
    }

    // The server_name extension of a Client Hello (the handshake message from its type byte on).
    private static string? ClientHelloName(ReadOnlySpan<byte> h, out string? detail)
    {
        detail = null;
        // type(1) length(3) version(2) random(32) session id, cipher suites, compression, extensions
        int at = 4 + 2 + 32;
        if (h.Length < at + 1) return null;
        string version = TlsVersion(h[4], h[5]);
        at += 1 + h[at];
        if (h.Length < at + 2) return null;
        int suites = U16(h, at);
        at += 2 + suites;
        if (h.Length < at + 1) return null;
        at += 1 + h[at];
        if (h.Length < at + 2) return null;
        int end = Math.Min(h.Length, at + 2 + U16(h, at));
        at += 2;
        string? name = null;
        bool tls13 = false;
        string? alpn = null;
        while (at + 4 <= end)
        {
            int type = U16(h, at), len = U16(h, at + 2);
            at += 4;
            if (at + len > end) break;
            if (type == 0 && len >= 5 && h[at + 2] == 0)
            {
                int nameLen = U16(h, at + 3);
                if (nameLen > 0 && at + 5 + nameLen <= end)
                    name = RemoteText.Clean(Encoding.ASCII.GetString(h.Slice(at + 5, nameLen)), 255);
            }
            else if (type == 43) tls13 = h.Slice(at, len).IndexOf(new byte[] { 3, 4 }) >= 0;
            else if (type == 16 && len >= 4)
            {
                int first = h[at + 2];
                if (first > 0 && at + 3 + first <= end) alpn = RemoteText.Clean(Encoding.ASCII.GetString(h.Slice(at + 3, first)), 32);
            }
            at += len;
        }
        detail = $"{suites / 2} cipher suites, offers {(tls13 ? "TLS 1.3" : version)}" + (alpn is not null ? ", ALPN " + alpn : string.Empty);
        return name;
    }

    private static readonly string[] HttpStarts =
        { "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "HTTP/1.", "M-SEARCH ", "NOTIFY " };

    // The request or status line when the payload starts like HTTP; else null.
    private static string? HttpLine(ReadOnlySpan<byte> pl)
    {
        if (pl.Length < 12) return null;
        foreach (string start in HttpStarts)
        {
            if (pl.Length < start.Length) continue;
            bool same = true;
            for (int i = 0; i < start.Length && same; i++) same = pl[i] == start[i];
            if (same) return FirstLine(pl, 140);
        }
        return null;
    }

    private static string FirstLine(ReadOnlySpan<byte> pl, int max)
    {
        int end = pl.IndexOfAny((byte)'\r', (byte)'\n');
        if (end < 0) end = pl.Length;
        return RemoteText.Clean(Encoding.Latin1.GetString(pl[..Math.Min(end, max * 2)]), max);
    }

    // A header of the first block of an HTTP message ("Host: example.com").
    private static string? HttpHeader(ReadOnlySpan<byte> pl, string name)
    {
        var text = pl[..Math.Min(pl.Length, 2048)];
        int at = 0;
        while (at < text.Length)
        {
            int eol = text[at..].IndexOf((byte)'\n');
            var line = eol < 0 ? text[at..] : text.Slice(at, eol);
            if (line.Length <= 1) break;   // the blank line: the body follows
            if (line.Length > name.Length + 1 && line[name.Length] == ':')
            {
                bool same = true;
                for (int i = 0; i < name.Length && same; i++) same = (line[i] | 0x20) == (name[i] | 0x20);
                if (same) return RemoteText.Clean(Encoding.Latin1.GetString(line[(name.Length + 1)..]).Trim(), 160);
            }
            if (eol < 0) break;
            at += eol + 1;
        }
        return null;
    }

    private static string DhcpType(ReadOnlySpan<byte> pl, out string? requested, out string? hostName)
    {
        requested = null;
        hostName = null;
        int type = 0;
        for (int at = 240; at + 1 < pl.Length;)
        {
            byte code = pl[at];
            if (code == 255) break;
            if (code == 0) { at++; continue; }
            int len = pl[at + 1];
            if (at + 2 + len > pl.Length) break;
            if (code == 53 && len == 1) type = pl[at + 2];
            else if (code == 50 && len == 4) requested = IpKey.V4Of(pl, at + 2).ToAddress().ToString();
            else if (code == 12 && len > 0) hostName = RemoteText.Clean(Encoding.ASCII.GetString(pl.Slice(at + 2, len)), 64);
            at += 2 + len;
        }
        return type switch
        {
            1 => "Discover",
            2 => "Offer",
            3 => "Request",
            4 => "Decline",
            5 => "ACK",
            6 => "NAK",
            7 => "Release",
            8 => "Inform",
            _ => pl[0] == 1 ? "request" : "reply",
        };
    }

    // ------------------------------------------------------------------ small helpers

    private static void Malformed(PacketRecord p, string protocol)
    {
        p.Protocol = protocol;
        p.Info = "Malformed packet (cut short)";
        p.Alert = true;
    }

    private static int U16(ReadOnlySpan<byte> d, int o) => (d[o] << 8) | d[o + 1];

    private static uint U32(ReadOnlySpan<byte> d, int o) => ((uint)d[o] << 24) | ((uint)d[o + 1] << 16) | ((uint)d[o + 2] << 8) | d[o + 3];

    private static ulong Mac48(ReadOnlySpan<byte> d, int o)
    {
        ulong v = 0;
        for (int i = 0; i < 6; i++) v = (v << 8) | d[o + i];
        return v;
    }

    internal static string MacTextStatic(ulong mac)
    {
        Span<char> c = stackalloc char[17];
        const string hex = "0123456789abcdef";
        for (int i = 0; i < 6; i++)
        {
            int b = (int)(mac >> (40 - 8 * i)) & 0xFF;
            c[i * 3] = hex[b >> 4];
            c[i * 3 + 1] = hex[b & 0xF];
            if (i < 5) c[i * 3 + 2] = ':';
        }
        return new string(c);
    }

    private static string MacNote(ulong mac)
        => mac == 0xFFFFFFFFFFFFUL ? " (broadcast)" : (mac & 0x010000000000UL) != 0 ? " (multicast)" : string.Empty;

    private string MacText(ulong mac)
    {
        if (_macText.TryGetValue(mac, out var s)) return s;
        if (_macText.Count > 4096) _macText.Clear();
        return _macText[mac] = MacTextStatic(mac);
    }

    private string IpText(IpKey ip)
    {
        if (_ipText.TryGetValue(ip, out var s)) return s;
        if (_ipText.Count > 8192) _ipText.Clear();
        return _ipText[ip] = ip.ToAddress().ToString();
    }

    private static string PortNote(int port) => port switch
    {
        20 or 21 => " (FTP)",
        22 => " (SSH)",
        23 => " (Telnet)",
        25 or 465 or 587 => " (SMTP)",
        53 => " (DNS)",
        67 or 68 => " (DHCP)",
        80 => " (HTTP)",
        110 or 995 => " (POP3)",
        123 => " (NTP)",
        143 or 993 => " (IMAP)",
        443 => " (HTTPS)",
        445 => " (SMB)",
        853 => " (DNS over TLS)",
        1900 => " (SSDP)",
        3306 => " (MySQL)",
        3389 => " (RDP)",
        5353 => " (mDNS)",
        5432 => " (PostgreSQL)",
        6379 => " (Redis)",
        8080 or 8443 => " (HTTP alternate)",
        _ => string.Empty,
    };
}
