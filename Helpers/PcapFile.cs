using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;

namespace Echoes.Helpers;

/// <summary>A capture file that can't be read; <see cref="Exception.Message"/> says why in plain words.</summary>
public sealed class PcapFormatException(string message) : Exception(message);

/// <summary>
/// Capture files, the two formats every packet tool reads and writes: classic pcap (tcpdump's, one link type per
/// file) and pcapng (Wireshark's default, an interface block per link type).
/// <para>Writing: pcap when every packet has the same link type (the usual case, and the format the most tools
/// open), pcapng otherwise. Reading: both, either byte order, micro- or nanosecond stamps; of pcapng the enhanced
/// and simple packet blocks, everything else skipped. Packets of a link type Echoes doesn't decode are still read
/// (their bytes show in the hex view).</para>
/// </summary>
public static class PcapFile
{
    private const uint MagicMicro = 0xA1B2C3D4, MagicNano = 0xA1B23C4D, MagicNg = 0x0A0D0D0A, ByteOrderMagic = 0x1A2B3C4D;
    private const int SnapLength = 262144;
    // The most one packet (or a pcapng block holding one) may take: far above any real packet, and what is allocated
    // for one before the file has shown it really has that much.
    private const int MaxBlock = 16 * 1024 * 1024;

    /// <summary>One packet as a file holds it.</summary>
    public readonly record struct Entry(DateTime TimeUtc, int WireLength, byte[] Data, LinkKind Link);

    // ---- link types (the numbers of the pcap file formats) ----

    private static int LinkNumber(LinkKind kind) => kind switch
    {
        LinkKind.Ethernet => 1,
        LinkKind.Null => 0,
        LinkKind.LinuxSll => 113,
        _ => 101,   // raw IP
    };

    /// <summary>The link kind of a file's (or a live capture's) data-link number. 12 and 14 are what some systems
    /// call raw IP while capturing; 108 is OpenBSD's loopback, read like the BSD one.</summary>
    public static LinkKind LinkOf(int number) => number switch
    {
        1 => LinkKind.Ethernet,
        0 or 108 => LinkKind.Null,
        101 or 12 or 14 or 228 or 229 => LinkKind.RawIp,
        113 => LinkKind.LinuxSll,
        _ => LinkKind.Unknown,
    };

    // ---- writing ----

    /// <summary>Writes <paramref name="packets"/> to <paramref name="stream"/>: pcap, or pcapng when they don't all
    /// share one link type. Returns the number written.</summary>
    public static int Write(Stream stream, IReadOnlyList<PacketRecord> packets)
    {
        bool mixed = false;
        for (int i = 1; i < packets.Count && !mixed; i++) mixed = packets[i].Link != packets[0].Link;
        return mixed ? WriteNg(stream, packets) : WriteClassic(stream, packets);
    }

    private static int WriteClassic(Stream stream, IReadOnlyList<PacketRecord> packets)
    {
        Span<byte> h = stackalloc byte[24];
        BinaryPrimitives.WriteUInt32LittleEndian(h, MagicMicro);
        BinaryPrimitives.WriteUInt16LittleEndian(h[4..], 2);
        BinaryPrimitives.WriteUInt16LittleEndian(h[6..], 4);
        BinaryPrimitives.WriteUInt32LittleEndian(h[16..], SnapLength);
        BinaryPrimitives.WriteUInt32LittleEndian(h[20..], (uint)LinkNumber(packets.Count > 0 ? packets[0].Link : LinkKind.Ethernet));
        stream.Write(h);

        Span<byte> r = stackalloc byte[16];
        foreach (var p in packets)
        {
            var (seconds, micros) = Stamp(p.TimeUtc);
            BinaryPrimitives.WriteUInt32LittleEndian(r, (uint)seconds);
            BinaryPrimitives.WriteUInt32LittleEndian(r[4..], (uint)micros);
            BinaryPrimitives.WriteUInt32LittleEndian(r[8..], (uint)p.Data.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(r[12..], (uint)Math.Max(p.WireLength, p.Data.Length));
            stream.Write(r);
            stream.Write(p.Data);
        }
        return packets.Count;
    }

    private static int WriteNg(Stream stream, IReadOnlyList<PacketRecord> packets)
    {
        // section header: block type, length, byte-order magic, version 1.0, section length unknown (-1), length again
        Span<byte> shb = stackalloc byte[28];
        BinaryPrimitives.WriteUInt32LittleEndian(shb, MagicNg);
        BinaryPrimitives.WriteUInt32LittleEndian(shb[4..], 28);
        BinaryPrimitives.WriteUInt32LittleEndian(shb[8..], ByteOrderMagic);
        BinaryPrimitives.WriteUInt16LittleEndian(shb[12..], 1);
        BinaryPrimitives.WriteInt64LittleEndian(shb[16..], -1);
        BinaryPrimitives.WriteUInt32LittleEndian(shb[24..], 28);
        stream.Write(shb);

        // an interface block per link type, in the order the types first appear (timestamps in microseconds, the default)
        var interfaces = new List<LinkKind>(2);
        foreach (var p in packets)
            if (!interfaces.Contains(p.Link)) interfaces.Add(p.Link);
        Span<byte> idb = stackalloc byte[20];
        foreach (var kind in interfaces)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(idb, 1);
            BinaryPrimitives.WriteUInt32LittleEndian(idb[4..], 20);
            BinaryPrimitives.WriteUInt16LittleEndian(idb[8..], (ushort)LinkNumber(kind));
            BinaryPrimitives.WriteUInt16LittleEndian(idb[10..], 0);
            BinaryPrimitives.WriteUInt32LittleEndian(idb[12..], SnapLength);
            BinaryPrimitives.WriteUInt32LittleEndian(idb[16..], 20);
            stream.Write(idb);
        }

        Span<byte> head = stackalloc byte[28];
        Span<byte> tail = stackalloc byte[4];
        Span<byte> pad = stackalloc byte[3];
        pad.Clear();
        foreach (var p in packets)
        {
            int padding = (4 - p.Data.Length % 4) % 4;
            uint total = (uint)(32 + p.Data.Length + padding);
            var (seconds, micros) = Stamp(p.TimeUtc);
            ulong stamp = (ulong)seconds * 1_000_000UL + (ulong)micros;
            BinaryPrimitives.WriteUInt32LittleEndian(head, 6);
            BinaryPrimitives.WriteUInt32LittleEndian(head[4..], total);
            BinaryPrimitives.WriteUInt32LittleEndian(head[8..], (uint)interfaces.IndexOf(p.Link));
            BinaryPrimitives.WriteUInt32LittleEndian(head[12..], (uint)(stamp >> 32));
            BinaryPrimitives.WriteUInt32LittleEndian(head[16..], (uint)stamp);
            BinaryPrimitives.WriteUInt32LittleEndian(head[20..], (uint)p.Data.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(head[24..], (uint)Math.Max(p.WireLength, p.Data.Length));
            stream.Write(head);
            stream.Write(p.Data);
            if (padding > 0) stream.Write(pad[..padding]);
            BinaryPrimitives.WriteUInt32LittleEndian(tail, total);
            stream.Write(tail);
        }
        return packets.Count;
    }

    private static (long Seconds, long Micros) Stamp(DateTime utc)
    {
        long ticks = Math.Max(0, utc.Ticks - DateTime.UnixEpoch.Ticks);
        return (ticks / TimeSpan.TicksPerSecond, ticks % TimeSpan.TicksPerSecond / 10);
    }

    // ---- reading ----

    /// <summary>
    /// Reads a pcap or pcapng file: at most <paramref name="maxPackets"/> packets and <paramref name="maxBytes"/> of
    /// packet data (<paramref name="truncated"/> says when the file had more). Throws
    /// <see cref="PcapFormatException"/> for a file that isn't one of the two, and whatever the stream throws.
    /// </summary>
    public static List<Entry> Read(Stream stream, int maxPackets, long maxBytes, out bool truncated)
    {
        truncated = false;
        var list = new List<Entry>();
        Span<byte> four = stackalloc byte[4];
        if (!Fill(stream, four)) throw new PcapFormatException("The file is empty.");
        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(four);
        long bytes = 0;

        if (magic == MagicNg)
        {
            ReadNg(stream, list, maxPackets, maxBytes, ref bytes, ref truncated);
            return list;
        }

        bool swapped, nano;
        switch (magic)
        {
            case MagicMicro: swapped = false; nano = false; break;
            case MagicNano: swapped = false; nano = true; break;
            case 0xD4C3B2A1: swapped = true; nano = false; break;
            case 0x4D3CB2A1: swapped = true; nano = true; break;
            default: throw new PcapFormatException("Not a capture file: it is neither pcap nor pcapng.");
        }
        Span<byte> rest = stackalloc byte[20];
        if (!Fill(stream, rest)) throw new PcapFormatException("The capture file is cut off inside its header.");
        var link = LinkOf((int)(U32(rest[16..], swapped) & 0x0FFFFFFF));

        Span<byte> r = stackalloc byte[16];
        while (Fill(stream, r))
        {
            uint seconds = U32(r, swapped), fraction = U32(r[4..], swapped), captured = U32(r[8..], swapped), wire = U32(r[12..], swapped);
            if (captured > MaxBlock) throw new PcapFormatException("The capture file is damaged (a packet of impossible size).");
            if (list.Count >= maxPackets || bytes + captured > maxBytes) { truncated = true; break; }
            var data = new byte[captured];
            if (!Fill(stream, data)) break;   // cut off mid-packet (a capture still being written): what came before stands
            list.Add(new Entry(Time(seconds, nano ? fraction / 100 : fraction * 10L), (int)Math.Min(wire, int.MaxValue), data, link));
            bytes += captured;
        }
        return list;
    }

    private static void ReadNg(Stream stream, List<Entry> list, int maxPackets, long maxBytes, ref long bytes, ref bool truncated)
    {
        // (the block type was read already: this starts at the section header's length)
        var interfaces = new List<(LinkKind Link, bool Binary, int Exponent)>();
        bool swapped = false;
        bool first = true;
        Span<byte> four = stackalloc byte[4];
        uint type = MagicNg;
        while (true)
        {
            if (!first)
            {
                if (!Fill(stream, four)) return;
                type = BinaryPrimitives.ReadUInt32LittleEndian(four);
                if (type != MagicNg && swapped) type = BinaryPrimitives.ReverseEndianness(type);
            }
            first = false;
            if (!Fill(stream, four)) return;
            uint rawLength = BinaryPrimitives.ReadUInt32LittleEndian(four);

            if (type == MagicNg)
            {
                // a new section: its byte-order magic says how to read everything up to the next one
                if (!Fill(stream, four)) return;
                uint order = BinaryPrimitives.ReadUInt32LittleEndian(four);
                swapped = order switch
                {
                    ByteOrderMagic => false,
                    0x4D3C2B1A => true,
                    _ => throw new PcapFormatException("The capture file is damaged (unknown byte order)."),
                };
                uint length = swapped ? BinaryPrimitives.ReverseEndianness(rawLength) : rawLength;
                if (length < 28 || length > 16 * 1024 * 1024) throw new PcapFormatException("The capture file is damaged (a section header of impossible size).");
                if (!Skip(stream, length - 12)) return;
                interfaces.Clear();
                continue;
            }

            uint blockLength = swapped ? BinaryPrimitives.ReverseEndianness(rawLength) : rawLength;
            if (blockLength < 12) throw new PcapFormatException("The capture file is damaged (a block of impossible size).");
            if (type is not (1 or 3 or 6))
            {
                // statistics, name resolution, decryption secrets, a tool's own blocks: passed over unread, whatever their size
                if (!Skip(stream, (long)blockLength - 8)) return;
                continue;
            }
            if (blockLength > MaxBlock) throw new PcapFormatException("The capture file is damaged (a packet of impossible size).");
            int body = (int)blockLength - 12;
            var block = new byte[body];
            if (!Fill(stream, block)) return;
            if (!Fill(stream, four)) return;   // the trailing length

            switch (type)
            {
                case 1 when body >= 8:   // interface description: link type, then options (if_tsresol = 9)
                {
                    var link = LinkOf(U16(block, swapped));
                    bool binary = false;
                    int exponent = 6;   // microseconds unless said otherwise
                    for (int at = 8; at + 4 <= body;)
                    {
                        int code = U16(block.AsSpan(at), swapped), len = U16(block.AsSpan(at + 2), swapped);
                        if (code == 0) break;
                        if (code == 9 && len == 1 && at + 5 <= body)
                        {
                            // the unit of this interface's stamps: 10^-n seconds, or 2^-n with the top bit set
                            binary = (block[at + 4] & 0x80) != 0;
                            exponent = block[at + 4] & 0x7F;
                        }
                        at += 4 + ((len + 3) & ~3);
                    }
                    interfaces.Add((link, binary, exponent));
                    break;
                }
                case 6 when body >= 20:   // enhanced packet
                {
                    uint iface = U32(block, swapped), high = U32(block.AsSpan(4), swapped), low = U32(block.AsSpan(8), swapped);
                    uint captured = U32(block.AsSpan(12), swapped), wire = U32(block.AsSpan(16), swapped);
                    if (captured > body - 20) break;
                    if (list.Count >= maxPackets || bytes + captured > maxBytes) { truncated = true; return; }
                    var (link, binary, exponent) = iface < interfaces.Count ? interfaces[(int)iface] : (LinkKind.Unknown, false, 6);
                    ulong stamp = ((ulong)high << 32) | low;
                    list.Add(new Entry(Time(Ticks(stamp, binary, exponent)), (int)Math.Min(wire, int.MaxValue), block.AsSpan(20, (int)captured).ToArray(), link));
                    bytes += captured;
                    break;
                }
                case 3 when body >= 4:   // simple packet: no time, the first interface
                {
                    uint wire = U32(block, swapped);
                    int captured = (int)Math.Min(wire, (uint)(body - 4));
                    if (list.Count >= maxPackets || bytes + captured > maxBytes) { truncated = true; return; }
                    var link = interfaces.Count > 0 ? interfaces[0].Link : LinkKind.Unknown;
                    list.Add(new Entry(DateTime.UnixEpoch, (int)Math.Min(wire, int.MaxValue), block.AsSpan(4, captured).ToArray(), link));
                    bytes += captured;
                    break;
                }
            }
        }
    }

    private static DateTime Time(uint seconds, long ticks) => Time(seconds * TimeSpan.TicksPerSecond + ticks);

    // (a stamp past the calendar's last day reads as 1970, like a packet that has no time)
    private static DateTime Time(long ticksSinceEpoch)
        => ticksSinceEpoch >= 0 && ticksSinceEpoch <= DateTime.MaxValue.Ticks - DateTime.UnixEpoch.Ticks
            ? new DateTime(DateTime.UnixEpoch.Ticks + ticksSinceEpoch, DateTimeKind.Utc)
            : DateTime.UnixEpoch;

    // A pcapng stamp as ticks (100 ns) since 1970, exactly. Its unit is 10^-exponent or 2^-exponent seconds, and one
    // that isn't a whole number of ticks (1/1024 s) drifts by hours over the decades since 1970 when it is rounded
    // first; so the stamp is multiplied out in 128 bits and divided once.
    private static long Ticks(ulong stamp, bool binary, int exponent)
    {
        UInt128 ticks;
        if (binary) ticks = ((UInt128)stamp * (ulong)TimeSpan.TicksPerSecond) >> exponent;   // exponent: 0-127
        else if (exponent <= 7) ticks = (UInt128)stamp * Pow10(7 - exponent);
        else ticks = exponent - 7 > 19 ? 0 : stamp / Pow10(exponent - 7);
        return ticks > (UInt128)long.MaxValue ? long.MaxValue : (long)ticks;
    }

    private static ulong Pow10(int n)
    {
        ulong v = 1;
        for (int i = 0; i < n; i++) v *= 10;
        return v;
    }

    private static uint U32(ReadOnlySpan<byte> b, bool swapped)
        => swapped ? BinaryPrimitives.ReadUInt32BigEndian(b) : BinaryPrimitives.ReadUInt32LittleEndian(b);

    private static int U16(ReadOnlySpan<byte> b, bool swapped)
        => swapped ? BinaryPrimitives.ReadUInt16BigEndian(b) : BinaryPrimitives.ReadUInt16LittleEndian(b);

    // Reads exactly buffer.Length bytes; false at the end of the stream.
    private static bool Fill(Stream stream, Span<byte> buffer)
    {
        int got = 0;
        while (got < buffer.Length)
        {
            int n = stream.Read(buffer[got..]);
            if (n <= 0) return false;
            got += n;
        }
        return true;
    }

    private static bool Skip(Stream stream, long count)
    {
        Span<byte> scratch = stackalloc byte[512];
        while (count > 0)
        {
            int n = stream.Read(scratch[..(int)Math.Min(count, scratch.Length)]);
            if (n <= 0) return false;
            count -= n;
        }
        return true;
    }
}
