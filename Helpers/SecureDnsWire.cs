using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Text;

namespace Echoes.Helpers;

/// <summary>A DNS message that breaks the wire format (truncated, a looping compression pointer, a length past the
/// end, an over-long name …). The message is safe to show: it never carries the packet bytes.</summary>
public sealed class DnsWireException(string message) : Exception(message);

/// <summary>One parsed answer record. <see cref="Value"/> is the presentation text the DNS view shows (names end with
/// a dot, like DnsClient's); TXT records also keep their character-strings, unjoined, in <see cref="Texts"/>.</summary>
public sealed record DnsWireRecord(string Name, ushort Type, uint Ttl, string Value, IReadOnlyList<string>? Texts = null);

/// <summary>The parts of a DNS response the encrypted transports need: header, the question, the answer section.</summary>
public sealed class DnsWireMessage
{
    public ushort Id { get; init; }
    public bool IsResponse { get; init; }
    public int Opcode { get; init; }
    public bool Truncated { get; init; }
    public int Rcode { get; init; }
    public int QuestionCount { get; init; }
    public string? QuestionName { get; init; }
    public ushort QuestionType { get; init; }
    /// <summary>ANCOUNT as the server sent it (the parser stops at <see cref="DnsWire.MaxAnswersParsed"/>).</summary>
    public int AnswerCount { get; init; }
    public List<DnsWireRecord> Answers { get; } = new();
}

/// <summary>
/// RFC 1035 wire format for DNS-over-HTTPS / DNS-over-TLS: a query writer and a strict, bounded response parser.
/// <para>The parser never trusts a length: every read is checked against the message end, names are capped at 255
/// wire bytes / 127 labels, a compression pointer must point strictly backwards (to before where the current run of
/// labels started — so a loop can't exist) and at most <see cref="MaxPointerJumps"/> are followed, RDATA must end
/// exactly where RDLENGTH says, and only the first <see cref="MaxAnswersParsed"/> answers are decoded.</para>
/// </summary>
public static class DnsWire
{
    public const int MaxMessageBytes = 65535;
    public const int MaxAnswersParsed = 500;
    public const int MaxPointerJumps = 64;
    private const int MaxNameWireBytes = 255;
    private const int MaxTxtChars = 8192;
    private const int UdpPayloadSize = 1232;   // the EDNS0 size advertised (DNS flag day 2020); irrelevant over TCP/HTTPS

    // ---------------------------------------------------------------- query writer

    /// <summary>
    /// A standard recursive query (RD set) for <paramref name="name"/> / <paramref name="type"/>, class IN, with an EDNS0
    /// OPT record. <paramref name="padBlock"/> &gt; 0 adds EDNS0 padding (RFC 7830 / 8467) so the encrypted query's size
    /// doesn't give the name away. The name must already be ASCII (punycode for IDNs). Throws <see cref="DnsWireException"/>
    /// for a name that can't be sent (empty label, a label over 63 bytes, over 255 bytes, non-ASCII / control chars).
    /// </summary>
    public static byte[] BuildQuery(string name, ushort type, ushort id, int padBlock = 128)
    {
        var buf = new List<byte>(128);
        WriteU16(buf, id);
        WriteU16(buf, 0x0100);   // QR=0, opcode QUERY, RD=1
        WriteU16(buf, 1);        // QDCOUNT
        WriteU16(buf, 0);        // ANCOUNT
        WriteU16(buf, 0);        // NSCOUNT
        WriteU16(buf, 1);        // ARCOUNT (the OPT record)
        EncodeName(name, buf);
        WriteU16(buf, type);
        WriteU16(buf, 1);        // class IN

        // OPT pseudo-record: root name, TYPE 41, CLASS = UDP payload size, TTL = ext-rcode/version/flags (all 0)
        buf.Add(0);
        WriteU16(buf, 41);
        WriteU16(buf, UdpPayloadSize);
        WriteU16(buf, 0); WriteU16(buf, 0);
        if (padBlock > 0)
        {
            int withOpt = buf.Count + 2 + 4;   // + RDLENGTH + the padding option's code/length
            int pad = (padBlock - withOpt % padBlock) % padBlock;
            WriteU16(buf, (ushort)(4 + pad));
            WriteU16(buf, 12);                 // option PADDING
            WriteU16(buf, (ushort)pad);
            for (int i = 0; i < pad; i++) buf.Add(0);
        }
        else WriteU16(buf, 0);
        return buf.ToArray();
    }

    /// <summary>Appends <paramref name="name"/> in wire form. "" or "." is the root. One trailing dot is allowed.</summary>
    public static void EncodeName(string name, List<byte> buf)
    {
        string n = (name ?? "").Trim();
        if (n.EndsWith('.')) n = n[..^1];
        if (n.Length == 0) { buf.Add(0); return; }
        int wire = 1;
        foreach (string label in n.Split('.'))
        {
            if (label.Length == 0) throw new DnsWireException("the name has an empty label (two dots in a row)");
            if (label.Length > 63) throw new DnsWireException("a label is longer than 63 characters");
            wire += label.Length + 1;
            if (wire > MaxNameWireBytes) throw new DnsWireException("the name is longer than 255 bytes");
            buf.Add((byte)label.Length);
            foreach (char c in label)
            {
                if (c <= 0x20 || c >= 0x7F) throw new DnsWireException("the name has a character DNS can't carry here (spaces, control or non-ASCII characters)");
                buf.Add((byte)c);
            }
        }
        buf.Add(0);
    }

    private static void WriteU16(List<byte> b, ushort v) { b.Add((byte)(v >> 8)); b.Add((byte)v); }

    // ---------------------------------------------------------------- response parser

    /// <summary>Parses the header, the question(s) and the answer section. Throws <see cref="DnsWireException"/> on
    /// anything malformed; never reads outside <paramref name="msg"/>.</summary>
    public static DnsWireMessage Parse(ReadOnlySpan<byte> msg)
    {
        if (msg.Length < 12) throw new DnsWireException("the answer is shorter than a DNS header");
        if (msg.Length > MaxMessageBytes) throw new DnsWireException("the answer is larger than 64 KB");
        ushort id = U16(msg, 0);
        ushort flags = U16(msg, 2);
        int qd = U16(msg, 4), an = U16(msg, 6);
        if (qd > 4) throw new DnsWireException($"the answer claims {qd} questions");

        int pos = 12;
        string? qName = null; ushort qType = 0;
        for (int i = 0; i < qd; i++)
        {
            string n = ReadName(msg, ref pos);
            Need(msg, pos, 4);
            ushort t = U16(msg, pos);
            pos += 4;   // type + class
            if (i == 0) { qName = n; qType = t; }
        }

        var m = new DnsWireMessage
        {
            Id = id,
            IsResponse = (flags & 0x8000) != 0,
            Opcode = (flags >> 11) & 0xF,
            Truncated = (flags & 0x0200) != 0,
            Rcode = flags & 0xF,
            QuestionCount = qd,
            QuestionName = qName,
            QuestionType = qType,
            AnswerCount = an,
        };

        int parse = Math.Min(an, MaxAnswersParsed);
        for (int i = 0; i < parse; i++)
        {
            string owner = ReadName(msg, ref pos);
            Need(msg, pos, 10);
            ushort type = U16(msg, pos);
            uint ttl = (uint)(U16(msg, pos + 4) << 16 | U16(msg, pos + 6));
            int rdLen = U16(msg, pos + 8);
            pos += 10;
            Need(msg, pos, rdLen);
            int rdEnd = pos + rdLen;
            var (value, texts) = DecodeRdata(msg, pos, rdEnd, type);
            m.Answers.Add(new DnsWireRecord(owner, type, ttl > int.MaxValue ? 0 : ttl, value, texts));
            pos = rdEnd;
        }
        return m;
    }

    /// <summary>
    /// Reads a (possibly compressed) name at <paramref name="pos"/> and moves <paramref name="pos"/> past it.
    /// A pointer must point strictly before the start of the label run that contains it, so every jump goes
    /// backwards and a loop is impossible; the jump count is capped as well.
    /// </summary>
    public static string ReadName(ReadOnlySpan<byte> msg, ref int pos)
    {
        var sb = new StringBuilder();
        int p = pos, end = -1, jumps = 0, wire = 1, labels = 0;
        int runStart = p;
        while (true)
        {
            if (p >= msg.Length) throw new DnsWireException("a name runs past the end of the answer");
            byte len = msg[p];
            if ((len & 0xC0) == 0xC0)
            {
                if (p + 1 >= msg.Length) throw new DnsWireException("a compression pointer is cut off");
                int target = ((len & 0x3F) << 8) | msg[p + 1];
                if (end < 0) end = p + 2;
                if (target >= runStart) throw new DnsWireException("a compression pointer points forward (loop)");
                if (++jumps > MaxPointerJumps) throw new DnsWireException("too many compression pointers");
                p = runStart = target;
                continue;
            }
            if ((len & 0xC0) != 0) throw new DnsWireException("unsupported label type");
            if (len == 0)
            {
                if (end < 0) end = p + 1;
                break;
            }
            wire += len + 1;
            if (wire > MaxNameWireBytes || ++labels > 127) throw new DnsWireException("a name is longer than 255 bytes");
            if (p + 1 + len > msg.Length) throw new DnsWireException("a label runs past the end of the answer");
            AppendLabel(sb, msg.Slice(p + 1, len));
            sb.Append('.');
            p += 1 + len;
        }
        pos = end;
        return sb.Length == 0 ? "." : sb.ToString();
    }

    // presentation form: printable ASCII as is; '.' and '\' escaped; anything else as \DDD (RFC 1035 §5.1)
    private static void AppendLabel(StringBuilder sb, ReadOnlySpan<byte> label)
    {
        foreach (byte b in label)
        {
            if (b is (byte)'.' or (byte)'\\') sb.Append('\\').Append((char)b);
            else if (b is > 0x20 and < 0x7F) sb.Append((char)b);
            else sb.Append('\\').Append(b.ToString("000", CultureInfo.InvariantCulture));
        }
    }

    private static (string value, IReadOnlyList<string>? texts) DecodeRdata(ReadOnlySpan<byte> msg, int start, int end, ushort type)
    {
        int len = end - start;
        switch (type)
        {
            case 1:   // A
                if (len != 4) throw new DnsWireException("an A record isn't 4 bytes");
                return (new IPAddress(msg.Slice(start, 4)).ToString(), null);
            case 28:  // AAAA
                if (len != 16) throw new DnsWireException("an AAAA record isn't 16 bytes");
                return (new IPAddress(msg.Slice(start, 16)).ToString(), null);
            case 2: case 5: case 12: case 39:   // NS, CNAME, PTR, DNAME
            {
                int p = start;
                string n = ReadName(msg, ref p);
                ExpectEnd(p, end);
                return (n, null);
            }
            case 15:  // MX
            {
                Need(msg, start, 2, end);
                int p = start + 2;
                string n = ReadName(msg, ref p);
                ExpectEnd(p, end);
                return ($"{U16(msg, start)}  {n}", null);
            }
            case 16:  // TXT: one or more <length><bytes> strings
            {
                var parts = new List<string>();
                int p = start, total = 0;
                while (p < end)
                {
                    int l = msg[p];
                    if (p + 1 + l > end) throw new DnsWireException("a TXT string runs past its record");
                    string s = Encoding.UTF8.GetString(msg.Slice(p + 1, l));
                    total += s.Length;
                    if (total > MaxTxtChars) throw new DnsWireException("a TXT record is too long");
                    parts.Add(s);
                    p += 1 + l;
                }
                return (string.Join(" ", parts), parts);
            }
            case 6:   // SOA
            {
                int p = start;
                string mname = ReadName(msg, ref p);
                string rname = ReadName(msg, ref p);
                Need(msg, p, 20, end);
                uint serial = (uint)(U16(msg, p) << 16 | U16(msg, p + 2));
                ExpectEnd(p + 20, end);
                return ($"{mname} {rname} (serial {serial})", null);
            }
            case 33:  // SRV
            {
                Need(msg, start, 6, end);
                int p = start + 6;
                string target = ReadName(msg, ref p);
                ExpectEnd(p, end);
                return ($"{U16(msg, start)} {U16(msg, start + 2)} {U16(msg, start + 4)} {target}", null);
            }
            case 257: // CAA: flags, tag length, tag, value
            {
                Need(msg, start, 2, end);
                int tagLen = msg[start + 1];
                if (tagLen == 0 || start + 2 + tagLen > end) throw new DnsWireException("a CAA record is malformed");
                string tag = Encoding.ASCII.GetString(msg.Slice(start + 2, tagLen));
                string val = Encoding.UTF8.GetString(msg.Slice(start + 2 + tagLen, end - start - 2 - tagLen));
                return ($"{msg[start]} {tag} {val}", null);
            }
            default:  // RFC 3597 generic form, first 64 bytes
            {
                int shown = Math.Min(len, 64);
                string hex = Convert.ToHexString(msg.Slice(start, shown)).ToLowerInvariant();
                return ($"\\# {len} {hex}{(shown < len ? "…" : "")}", null);
            }
        }
    }

    public static string TypeName(ushort type) => type switch
    {
        1 => "A", 2 => "NS", 5 => "CNAME", 6 => "SOA", 12 => "PTR", 15 => "MX", 16 => "TXT", 28 => "AAAA",
        33 => "SRV", 39 => "DNAME", 41 => "OPT", 43 => "DS", 46 => "RRSIG", 47 => "NSEC", 48 => "DNSKEY",
        50 => "NSEC3", 52 => "TLSA", 64 => "SVCB", 65 => "HTTPS", 257 => "CAA",
        _ => "TYPE" + type.ToString(CultureInfo.InvariantCulture),
    };

    /// <summary>"4.4.8.8.in-addr.arpa" / nibble form under ip6.arpa — the PTR name for an address.</summary>
    public static string ArpaName(IPAddress ip)
    {
        byte[] b = ip.GetAddressBytes();
        var sb = new StringBuilder(80);
        if (b.Length == 4)
        {
            for (int i = 3; i >= 0; i--) sb.Append(b[i].ToString(CultureInfo.InvariantCulture)).Append('.');
            return sb.Append("in-addr.arpa").ToString();
        }
        const string hex = "0123456789abcdef";
        for (int i = b.Length - 1; i >= 0; i--)
            sb.Append(hex[b[i] & 0xF]).Append('.').Append(hex[b[i] >> 4]).Append('.');
        return sb.Append("ip6.arpa").ToString();
    }

    private static ushort U16(ReadOnlySpan<byte> m, int at) => (ushort)(m[at] << 8 | m[at + 1]);

    private static void Need(ReadOnlySpan<byte> m, int at, int count, int limit = -1)
    {
        int lim = limit < 0 ? m.Length : limit;
        if (at < 0 || count < 0 || at + count > lim) throw new DnsWireException("the answer is cut off");
    }

    private static void ExpectEnd(int p, int end)
    {
        if (p != end) throw new DnsWireException("a record's data doesn't match its length");
    }
}
