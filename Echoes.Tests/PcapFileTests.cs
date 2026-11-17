using System.Buffers.Binary;
using Echoes.Helpers;
using Echoes.Tests.Support;

namespace Echoes.Tests;

/// <summary>Capture files: what Echoes writes is what other tools read (the formats' own layouts, checked byte by
/// byte), what other tools write is read (either byte order, every timestamp unit), and no file makes the reader
/// throw anything but "this isn't a capture file".</summary>
public class PcapFileTests
{
    private static readonly DateTime T0 = new(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc);
    private static uint Unix(DateTime t) => (uint)(t - DateTime.UnixEpoch).TotalSeconds;

    private static byte[] Written(IReadOnlyList<PacketRecord> packets)
    {
        using var ms = new MemoryStream();
        Assert.Equal(packets.Count, PcapFile.Write(ms, packets));
        return ms.ToArray();
    }

    private static List<PcapFile.Entry> Read(byte[] file, out bool truncated, int maxPackets = 100_000, long maxBytes = 64L << 20)
        => PcapFile.Read(new MemoryStream(file), maxPackets, maxBytes, out truncated);

    private static List<PcapFile.Entry> Read(byte[] file) => Read(file, out _);

    private static PacketRecord Packet(byte[] data, LinkKind link, DateTime time, int? wire = null)
        => new() { Data = data, Link = link, TimeUtc = time, WireLength = wire ?? data.Length };

    // ------------------------------------------------------------------ writing

    [Fact]
    public void One_link_type_is_written_as_classic_pcap()
    {
        var packets = Frames.Samples();
        var file = Written(packets);
        // magic (microseconds, little-endian), version 2.4, zone 0, accuracy 0, snap length, link type 1 (Ethernet)
        Assert.Equal(new byte[] { 0xD4, 0xC3, 0xB2, 0xA1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, file[..16]);
        Assert.Equal(262144u, BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(16)));
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(20)));
        Assert.Equal(24 + packets.Sum(p => 16 + p.Data.Length), file.Length);
        // the first record: seconds, microseconds, captured, original, then the packet itself
        Assert.Equal(Unix(packets[0].TimeUtc), BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(24)));
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(28)));   // sample 1 is one microsecond past the second
        Assert.Equal((uint)packets[0].Data.Length, BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(32)));
        Assert.Equal((uint)packets[0].Data.Length, BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(36)));
        Assert.Equal(packets[0].Data, file[40..(40 + packets[0].Data.Length)]);
    }

    [Theory]
    [InlineData(LinkKind.Ethernet, 1)]
    [InlineData(LinkKind.RawIp, 101)]
    [InlineData(LinkKind.Null, 0)]
    [InlineData(LinkKind.LinuxSll, 113)]
    public void The_link_type_is_the_number_other_tools_know(LinkKind link, int number)
    {
        var file = Written(new[] { Packet(new byte[20], link, T0) });
        Assert.Equal((uint)number, BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(20)));
        Assert.Equal(link, PcapFile.LinkOf(number));
        Assert.Equal(link, Read(file)[0].Link);
    }

    [Fact]
    public void What_is_written_is_read_back()
    {
        var packets = Frames.Samples();
        var back = Read(Written(packets), out bool truncated);
        Assert.False(truncated);
        Assert.Equal(packets.Count, back.Count);
        for (int i = 0; i < packets.Count; i++)
        {
            Assert.Equal(packets[i].Data, back[i].Data);
            Assert.Equal(packets[i].WireLength, back[i].WireLength);
            Assert.Equal(packets[i].TimeUtc, back[i].TimeUtc);
            Assert.Equal(DateTimeKind.Utc, back[i].TimeUtc.Kind);
            Assert.Equal(LinkKind.Ethernet, back[i].Link);
        }
    }

    [Fact]
    public void Mixed_link_types_are_written_as_pcapng_and_read_back()
    {
        var packets = new[]
        {
            Packet(new byte[] { 1, 2, 3, 4, 5 }, LinkKind.Ethernet, T0),                       // 5 bytes: padded to 8 in the block
            Packet(new byte[] { 0x45, 0, 0, 20 }, LinkKind.RawIp, T0.AddTicks(12_345_670)),
            Packet(new byte[64], LinkKind.Null, T0.AddSeconds(2)),
            Packet(new byte[] { 9 }, LinkKind.Ethernet, T0.AddSeconds(3), wire: 1500),
            Packet(new byte[17], LinkKind.LinuxSll, T0.AddSeconds(4)),
        };
        var file = Written(packets);
        Assert.Equal(new byte[] { 0x0A, 0x0D, 0x0D, 0x0A }, file[..4]);
        Assert.Equal(0x1A2B3C4Du, BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(8)));
        Assert.Equal(0, file.Length % 4);   // every block is a multiple of four bytes

        var back = Read(file, out bool truncated);
        Assert.False(truncated);
        Assert.Equal(packets.Length, back.Count);
        for (int i = 0; i < packets.Length; i++)
        {
            Assert.Equal(packets[i].Data, back[i].Data);
            Assert.Equal(packets[i].WireLength, back[i].WireLength);
            Assert.Equal(packets[i].TimeUtc, back[i].TimeUtc);
            Assert.Equal(packets[i].Link, back[i].Link);
        }
    }

    [Fact]
    public void The_length_on_the_wire_is_kept_and_never_smaller_than_what_was_captured()
    {
        var back = Read(Written(new[]
        {
            Packet(new byte[60], LinkKind.Ethernet, T0, wire: 1514),   // a snapped packet
            Packet(new byte[60], LinkKind.Ethernet, T0, wire: 10),     // a nonsense length is not written
        }));
        Assert.Equal(1514, back[0].WireLength);
        Assert.Equal(60, back[1].WireLength);
    }

    [Fact]
    public void An_empty_capture_is_a_file_with_only_a_header()
    {
        var file = Written(Array.Empty<PacketRecord>());
        Assert.Equal(24, file.Length);
        Assert.Empty(Read(file, out bool truncated));
        Assert.False(truncated);
    }

    [Fact]
    public void A_time_before_1970_is_written_as_1970()
    {
        var back = Read(Written(new[] { Packet(new byte[4], LinkKind.Ethernet, default) }));
        Assert.Equal(DateTime.UnixEpoch, back[0].TimeUtc);
    }

    // ------------------------------------------------------------------ reading other tools' files

    private static void W16(byte[] b, int at, int v, bool big)
    {
        if (big) BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(at), (ushort)v);
        else BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(at), (ushort)v);
    }

    private static void W32(byte[] b, int at, uint v, bool big)
    {
        if (big) BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(at), v);
        else BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(at), v);
    }

    /// <summary>A classic pcap file as libpcap writes it on a machine of the given byte order.</summary>
    private static byte[] Classic(bool big, bool nano, int link, params (uint Seconds, uint Fraction, byte[] Data, uint Wire)[] packets)
    {
        var header = new byte[24];
        W32(header, 0, nano ? 0xA1B23C4Du : 0xA1B2C3D4u, big);
        W16(header, 4, 2, big);
        W16(header, 6, 4, big);
        W32(header, 16, 65535, big);
        W32(header, 20, (uint)link, big);
        var parts = new List<byte[]> { header };
        foreach (var (seconds, fraction, data, wire) in packets)
        {
            var r = new byte[16];
            W32(r, 0, seconds, big);
            W32(r, 4, fraction, big);
            W32(r, 8, (uint)data.Length, big);
            W32(r, 12, wire, big);
            parts.Add(r);
            parts.Add(data);
        }
        return Frames.Join(parts.ToArray());
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void Classic_files_of_either_byte_order_and_time_unit_are_read(bool bigEndian, bool nanoseconds)
    {
        var data = Frames.Samples()[1].Data;
        uint fraction = nanoseconds ? 123_456_700u : 123_456u;
        var file = Classic(bigEndian, nanoseconds, 1, (Unix(T0), fraction, data, (uint)data.Length), (Unix(T0) + 1, 0, new byte[] { 1, 2, 3 }, 900));
        var back = Read(file, out bool truncated);
        Assert.False(truncated);
        Assert.Equal(2, back.Count);
        Assert.Equal(data, back[0].Data);
        Assert.Equal(LinkKind.Ethernet, back[0].Link);
        Assert.Equal(T0.AddTicks(nanoseconds ? 1_234_567 : 1_234_560), back[0].TimeUtc);
        Assert.Equal(T0.AddSeconds(1), back[1].TimeUtc);
        Assert.Equal(900, back[1].WireLength);
        // and it decodes to the same packet as the one it was made from
        var p = Frames.Record(back[0].Data, back[0].Link);
        Assert.Equal("DNS", p.Protocol);
    }

    // ---- pcapng, block by block (draft-ietf-opsawg-pcapng) ----

    private static byte[] Block(uint type, byte[] body, bool big = false)
    {
        int padding = (4 - body.Length % 4) % 4;
        uint total = (uint)(12 + body.Length + padding);
        var b = new byte[total];
        W32(b, 0, type, big);
        W32(b, 4, total, big);
        body.CopyTo(b, 8);
        W32(b, (int)total - 4, total, big);
        return b;
    }

    private static byte[] SectionHeader(bool big = false)
    {
        var body = new byte[16];
        W32(body, 0, 0x1A2B3C4D, big);
        W16(body, 4, 1, big);
        for (int i = 8; i < 16; i++) body[i] = 0xFF;   // section length: not given
        return Block(0x0A0D0D0A, body, big);
    }

    /// <summary>An interface description block; <paramref name="resolution"/> adds the if_tsresol option.</summary>
    private static byte[] Interface(int link, byte? resolution = null, bool big = false)
    {
        var body = new byte[resolution is null ? 8 : 20];
        W16(body, 0, link, big);
        W32(body, 4, 262144, big);
        if (resolution is { } r)
        {
            W16(body, 8, 9, big);    // if_tsresol
            W16(body, 10, 1, big);
            body[12] = r;            // (three bytes of padding, then the end-of-options option, all zero)
        }
        return Block(1, body, big);
    }

    private static byte[] Enhanced(uint iface, ulong stamp, byte[] data, uint? wire = null, bool big = false)
    {
        var body = new byte[20 + data.Length];
        W32(body, 0, iface, big);
        W32(body, 4, (uint)(stamp >> 32), big);
        W32(body, 8, (uint)stamp, big);
        W32(body, 12, (uint)data.Length, big);
        W32(body, 16, wire ?? (uint)data.Length, big);
        data.CopyTo(body, 20);
        return Block(6, body, big);
    }

    private static byte[] Simple(byte[] data, bool big = false)
    {
        var body = new byte[4 + data.Length];
        W32(body, 0, (uint)data.Length, big);
        data.CopyTo(body, 4);
        return Block(3, body, big);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Pcapng_is_read_in_either_byte_order(bool big)
    {
        ulong micros = (ulong)Unix(T0) * 1_000_000 + 250_000;
        var file = Frames.Join(
            SectionHeader(big),
            Interface(1, big: big),
            Interface(101, big: big),
            Block(5, new byte[24], big),                                       // interface statistics: passed over
            Enhanced(0, micros, new byte[] { 1, 2, 3, 4, 5, 6, 7 }, wire: 70, big: big),
            Block(0x00000BAD, new byte[40], big),                              // a block type nobody knows: passed over
            Enhanced(1, micros + 1, new byte[] { 0x45, 0, 0, 20 }, big: big),
            Simple(new byte[] { 9, 9, 9 }, big));
        var back = Read(file, out bool truncated);
        Assert.False(truncated);
        Assert.Equal(3, back.Count);
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5, 6, 7 }, back[0].Data);
        Assert.Equal(70, back[0].WireLength);
        Assert.Equal(LinkKind.Ethernet, back[0].Link);
        Assert.Equal(T0.AddMilliseconds(250), back[0].TimeUtc);
        Assert.Equal(LinkKind.RawIp, back[1].Link);
        Assert.Equal(T0.AddMilliseconds(250).AddTicks(10), back[1].TimeUtc);
        // a simple packet block has no time and belongs to the first interface
        Assert.Equal(new byte[] { 9, 9, 9 }, back[2].Data);
        Assert.Equal(LinkKind.Ethernet, back[2].Link);
        Assert.Equal(DateTime.UnixEpoch, back[2].TimeUtc);
    }

    [Theory]
    [InlineData(6, 1_000_000UL)]         // microseconds, said outright
    [InlineData(9, 1_000_000_000UL)]     // nanoseconds (Wireshark on Linux)
    [InlineData(3, 1_000UL)]             // milliseconds
    [InlineData(0, 1UL)]                 // whole seconds
    [InlineData(0x80 | 10, 1024UL)]      // a power of two: 1/1024 s
    public void An_interface_says_what_its_timestamps_count(int resolution, ulong unitsPerSecond)
    {
        ulong stamp = (ulong)Unix(T0) * unitsPerSecond + unitsPerSecond / 2;   // half a second past T0
        var file = Frames.Join(SectionHeader(), Interface(1, (byte)resolution), Enhanced(0, stamp, new byte[8]));
        var back = Read(file);
        Assert.Single(back);
        // exactly: a unit that isn't a whole number of ticks (1/1024 s) must not drift over the 56 years since 1970
        Assert.Equal(resolution == 0 ? T0 : T0.AddMilliseconds(500), back[0].TimeUtc);
    }

    [Fact]
    public void A_second_section_starts_over_with_its_own_byte_order_and_interfaces()
    {
        var file = Frames.Join(
            SectionHeader(big: false), Interface(1), Enhanced(0, 1_000_000, new byte[] { 1 }),
            SectionHeader(big: true), Interface(113, big: true), Enhanced(0, 2_000_000, new byte[] { 2, 2 }, big: true));
        var back = Read(file);
        Assert.Equal(2, back.Count);
        Assert.Equal(LinkKind.Ethernet, back[0].Link);
        Assert.Equal(LinkKind.LinuxSll, back[1].Link);
        Assert.Equal(new byte[] { 2, 2 }, back[1].Data);
        Assert.Equal(DateTime.UnixEpoch.AddSeconds(2), back[1].TimeUtc);
    }

    [Fact]
    public void A_packet_of_an_interface_the_file_never_described_is_still_read()
    {
        var back = Read(Frames.Join(SectionHeader(), Interface(1), Enhanced(7, 0, new byte[] { 1, 2, 3 })));
        Assert.Single(back);
        Assert.Equal(LinkKind.Unknown, back[0].Link);
        Assert.Equal(new byte[] { 1, 2, 3 }, back[0].Data);
    }

    [Fact]
    public void A_link_type_echoes_does_not_decode_is_read_as_bytes()
    {
        var back = Read(Classic(false, false, 127, (1, 0, new byte[] { 1, 2, 3 }, 3)));   // 127: 802.11 with a radiotap header
        Assert.Equal(LinkKind.Unknown, back[0].Link);
        Assert.Equal("?", Frames.Record(back[0].Data, back[0].Link).Protocol);
    }

    // ------------------------------------------------------------------ limits and damage

    [Fact]
    public void A_file_cut_off_mid_packet_keeps_the_packets_before_it()
    {
        var packets = Frames.Samples();
        var file = Written(packets);
        var cut = file[..^5];
        var back = Read(cut, out bool truncated);
        Assert.Equal(packets.Count - 1, back.Count);
        Assert.False(truncated);
        Assert.Equal(packets[^2].Data, back[^1].Data);

        // the same for pcapng, cut inside the last block
        var ng = Frames.Join(SectionHeader(), Interface(1), Enhanced(0, 0, new byte[40]), Enhanced(0, 0, new byte[40]));
        Assert.Single(Read(ng[..^9]));
    }

    [Fact]
    public void The_reader_stops_at_the_packet_and_byte_limits_and_says_so()
    {
        var file = Written(Frames.Samples());
        Assert.Equal(2, Read(file, out bool truncated, maxPackets: 2).Count);
        Assert.True(truncated);

        // the first two samples are 54 and 71 bytes: a 100-byte limit holds one
        Assert.Single(Read(file, out truncated, maxBytes: 100));
        Assert.True(truncated);

        var ng = Frames.Join(SectionHeader(), Interface(1), Enhanced(0, 0, new byte[40]), Enhanced(0, 0, new byte[40]), Simple(new byte[40]));
        Assert.Equal(2, Read(ng, out truncated, maxPackets: 2).Count);
        Assert.True(truncated);
        Assert.Single(Read(ng, out truncated, maxBytes: 50));
        Assert.True(truncated);
    }

    public static IEnumerable<object[]> NotCaptureFiles() => new[]
    {
        new object[] { "empty", Array.Empty<byte>() },
        new object[] { "three bytes", new byte[] { 0xD4, 0xC3, 0xB2 } },
        new object[] { "text", "this is not a capture file, it is a text file"u8.ToArray() },
        new object[] { "a pcap header cut short", new byte[] { 0xD4, 0xC3, 0xB2, 0xA1, 2, 0, 4, 0 } },
        new object[] { "a pcap packet of 2 GB", Classic(false, false, 1, (1, 0, Array.Empty<byte>(), 0))[..24].Concat(new byte[] { 1, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0x7F, 0, 0, 0, 0 }).ToArray() },
        new object[] { "pcapng with an unknown byte order", new byte[] { 0x0A, 0x0D, 0x0D, 0x0A, 28, 0, 0, 0, 1, 2, 3, 4, 0, 0, 0, 0 } },
        new object[] { "pcapng with a section header of 8 bytes", new byte[] { 0x0A, 0x0D, 0x0D, 0x0A, 8, 0, 0, 0, 0x4D, 0x3C, 0x2B, 0x1A, 0, 0, 0, 0 } },
        new object[] { "pcapng with a block shorter than a block", Frames.Join(SectionHeader(), new byte[] { 6, 0, 0, 0, 4, 0, 0, 0 }) },
        new object[] { "pcapng with a packet block of 1 GB", Frames.Join(SectionHeader(), new byte[] { 6, 0, 0, 0, 0, 0, 0, 0x40 }) },
    };

    [Theory]
    [MemberData(nameof(NotCaptureFiles))]
    public void What_is_not_a_capture_file_is_refused_in_words(string what, byte[] file)
    {
        var ex = Assert.Throws<PcapFormatException>(() => Read(file));
        Assert.False(string.IsNullOrWhiteSpace(ex.Message), what);
        Assert.EndsWith(".", ex.Message);
    }

    [Fact]
    public void A_huge_block_that_is_not_a_packet_is_passed_over_without_reading_it_into_memory()
    {
        // a 1 GB name-resolution block the file doesn't really hold: the reader runs out of file and keeps what it has
        var file = Frames.Join(SectionHeader(), Interface(1), Enhanced(0, 0, new byte[] { 1 }), new byte[] { 4, 0, 0, 0, 0, 0, 0, 0x40 }, new byte[64]);
        // (this thread's allocations only: the reader is synchronous, and other test classes run at the same time)
        long before = GC.GetAllocatedBytesForCurrentThread();
        Assert.Single(Read(file));
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.True(allocated < 8 * 1024 * 1024, $"reading the file allocated {allocated:N0} bytes");
    }

    /// <summary>A stream that hands over a byte at a time (a slow device, a pipe): the same packets.</summary>
    private sealed class Trickle(byte[] data) : Stream
    {
        private int _at;
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_at >= data.Length || count == 0) return 0;
            buffer[offset] = data[_at++];
            return 1;
        }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    [Fact]
    public void A_stream_that_gives_one_byte_at_a_time_reads_the_same()
    {
        var packets = Frames.Samples();
        foreach (var file in new[] { Written(packets), Frames.Join(SectionHeader(), Interface(1), Enhanced(0, 5, new byte[33]), Simple(new byte[5])) })
        {
            var whole = Read(file);
            var slow = PcapFile.Read(new Trickle(file), 1000, 1 << 20, out bool truncated);
            Assert.False(truncated);
            Assert.Equal(whole.Count, slow.Count);
            for (int i = 0; i < whole.Count; i++) Assert.Equal(whole[i].Data, slow[i].Data);
        }
    }

    [Fact]
    public void Timestamps_no_calendar_holds_are_read_as_some_time_not_an_error()
    {
        ulong[] stamps = { 0, 1, uint.MaxValue, (ulong)long.MaxValue / 16, (ulong)long.MaxValue, (ulong)long.MaxValue + 1, ulong.MaxValue - 1, ulong.MaxValue,
                           0x7FFF_FFFF_0000_0000, 0x0123_4567_89AB_CDEF, 922_337_203_685UL, 922_337_203_686UL, 315_537_897_600UL };
        for (int resolution = 0; resolution < 256; resolution++)
            foreach (ulong stamp in stamps)
            {
                var file = Frames.Join(SectionHeader(), Interface(1, (byte)resolution), Enhanced(0, stamp, new byte[] { 1 }));
                var back = Read(file);
                Assert.Single(back);
                Assert.InRange(back[0].TimeUtc, DateTime.UnixEpoch, DateTime.MaxValue);
            }
        // classic: the largest seconds and fractions a record can hold
        foreach (bool nano in new[] { false, true })
            Assert.Single(Read(Classic(false, nano, 1, (uint.MaxValue, uint.MaxValue, new byte[] { 1 }, 1))));
    }

    /// <summary>Random damage to good files of both formats (a fixed seed). The reader either reads what it can or
    /// says the file is damaged: nothing else may come out of it, and it must not take long.</summary>
    [Fact]
    public void Damaged_files_are_read_or_refused_and_nothing_else()
    {
        var packets = Frames.Samples();
        var mixed = new[] { Packet(new byte[30], LinkKind.Ethernet, T0), Packet(new byte[21], LinkKind.RawIp, T0), Packet(new byte[9], LinkKind.Null, T0) };
        byte[][] good =
        {
            Written(packets),
            Written(mixed),
            Classic(true, true, 113, (5, 6, new byte[40], 40), (7, 8, new byte[3], 3)),
            Frames.Join(SectionHeader(true), Interface(1, 9, true), Enhanced(0, 123456789, new byte[50], big: true), Simple(new byte[6], true),
                        Block(4, new byte[12], true), SectionHeader(), Interface(0, 0x83), Enhanced(0, 1, new byte[4])),
        };
        var random = new Random(77);
        int refused = 0;
        for (int i = 0; i < 12_000; i++)
        {
            var file = (byte[])good[random.Next(good.Length)].Clone();
            int changes = random.Next(1, 5);
            for (int c = 0; c < changes; c++)
            {
                int at = random.Next(file.Length);
                // mostly small values and all-ones, the ones that make lengths interesting
                file[at] = random.Next(3) switch { 0 => (byte)random.Next(256), 1 => (byte)random.Next(8), _ => 0xFF };
            }
            if (random.Next(4) == 0) file = file[..random.Next(file.Length + 1)];
            try
            {
                var back = PcapFile.Read(new MemoryStream(file), 1000, 1 << 20, out _);
                Assert.All(back, e => Assert.InRange(e.TimeUtc, DateTime.UnixEpoch, DateTime.MaxValue));
                Assert.All(back, e => Assert.True(e.WireLength >= 0));
            }
            catch (PcapFormatException) { refused++; }
        }
        Assert.InRange(refused, 1, 11_999);
    }
}
