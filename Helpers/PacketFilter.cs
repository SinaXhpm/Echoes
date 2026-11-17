using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Text;

namespace Echoes.Helpers;

/// <summary>
/// The Capture tool's display filter: which packets of a capture are shown. It takes what people already type into
/// tcpdump and Wireshark, and plain words:
/// <list type="bullet">
/// <item>a protocol: <c>tcp</c>, <c>udp</c>, <c>icmp</c>, <c>arp</c>, <c>dns</c>, <c>tls</c>, <c>http</c>, <c>ip</c>, <c>ipv6</c> …</item>
/// <item>tcpdump style: <c>host 1.1.1.1</c>, <c>src 10.0.0.5</c>, <c>dst net 10.0.0.0/8</c>, <c>port 443</c>,
/// <c>src port 53</c>, <c>portrange 8000-8100</c>, <c>less 100</c>, <c>greater 1000</c></item>
/// <item>Wireshark style: <c>ip.addr == 1.1.1.1</c>, <c>ip.src != 10.0.0.0/8</c>, <c>tcp.port == 443</c>,
/// <c>frame.len &gt; 1000</c>, <c>tcp.flags.syn</c>, <c>dns.name contains google</c>, <c>info contains "hello"</c></item>
/// <item>a bare address, network or port number: <c>1.1.1.1</c>, <c>10.0.0.0/8</c>, <c>443</c></item>
/// <item>any other word, or text in quotes: packets whose addresses, protocol, info line or host name contain it</item>
/// </list>
/// joined with <c>and</c> / <c>&amp;&amp;</c>, <c>or</c> / <c>||</c>, <c>not</c> / <c>!</c> and brackets; two terms side
/// by side mean <c>and</c> (<c>tcp port 443</c>). An address or port test matches either end of a packet, and its
/// <c>!=</c> means "neither end", which is what people expect of it. As in Wireshark, a field's <c>!=</c> matches only
/// packets that have the field (<c>tcp.port != 443</c> is TCP not on 443, not every UDP and ARP packet too); "not
/// that" for every packet is <c>!(tcp.port == 443)</c>.
/// </summary>
public sealed class PacketFilter
{
    private readonly Func<PacketRecord, bool> _test;

    private PacketFilter(string text, Func<PacketRecord, bool> test)
    {
        Text = text;
        _test = test;
    }

    /// <summary>The filter as typed (trimmed).</summary>
    public string Text { get; }

    public bool Matches(PacketRecord p) => _test(p);

    /// <summary>Parses <paramref name="text"/>. Empty text is no filter (<paramref name="filter"/> null, true). False:
    /// <paramref name="error"/> says what isn't understood, in a few words.</summary>
    public static bool TryParse(string? text, out PacketFilter? filter, out string? error)
    {
        filter = null;
        error = null;
        string t = text?.Trim() ?? string.Empty;
        if (t.Length == 0) return true;
        if (t.Length > MaxLength)
        {
            error = $"the filter is too long (more than {MaxLength} characters)";
            return false;
        }
        try
        {
            var parser = new Parser(Tokenize(t));
            var test = parser.Expression();
            if (!parser.AtEnd) throw new FormatException($"\"{parser.Peek!.Text}\" isn't expected there");
            filter = new PacketFilter(t, test);
            return true;
        }
        catch (FormatException ex)
        {
            error = ex.Message;
            return false;
        }
    }

    // A filter is typed by hand, but it also comes back from the history and from a restored backup: its size and its
    // nesting are bounded, so no text can run the parser out of stack.
    private const int MaxLength = 2000, MaxDepth = 48;

    // ------------------------------------------------------------------ tokens

    private sealed record Token(string Text, bool Quoted, bool Symbol);

    private static List<Token> Tokenize(string s)
    {
        var tokens = new List<Token>();
        int i = 0;
        while (i < s.Length)
        {
            char c = s[i];
            if (char.IsWhiteSpace(c)) { i++; continue; }
            if (c is '"' or '\'')
            {
                int end = s.IndexOf(c, i + 1);
                if (end < 0) throw new FormatException("a quote isn't closed");
                tokens.Add(new Token(s.Substring(i + 1, end - i - 1), true, false));
                i = end + 1;
                continue;
            }
            if (c is '(' or ')') { tokens.Add(new Token(c.ToString(), false, true)); i++; continue; }
            if (i + 1 < s.Length && s.Substring(i, 2) is "==" or "!=" or ">=" or "<=" or "&&" or "||")
            {
                tokens.Add(new Token(s.Substring(i, 2), false, true));
                i += 2;
                continue;
            }
            if (c is '!' or '<' or '>' or '=') { tokens.Add(new Token(c.ToString(), false, true)); i++; continue; }
            int start = i;
            while (i < s.Length && !char.IsWhiteSpace(s[i]) && s[i] is not ('(' or ')' or '!' or '<' or '>' or '=' or '"' or '\'' or '&' or '|')) i++;
            if (i == start) throw new FormatException($"\"{c}\" isn't understood");   // a lone & or |
            tokens.Add(new Token(s[start..i], false, false));
        }
        return tokens;
    }

    // ------------------------------------------------------------------ grammar

    private sealed class Parser(List<Token> tokens)
    {
        private int _at;

        public bool AtEnd => _at >= tokens.Count;
        public Token? Peek => AtEnd ? null : tokens[_at];
        private Token Next() => tokens[_at++];

        private bool Word(string w) => Peek is { Quoted: false, Symbol: false } t && t.Text.Equals(w, StringComparison.OrdinalIgnoreCase);
        private bool Symbol(string s) => Peek is { Symbol: true } t && t.Text == s;

        public Func<PacketRecord, bool> Expression()
        {
            var left = And();
            while (Word("or") || Symbol("||"))
            {
                Next();
                var a = left;
                var b = And();
                left = p => a(p) || b(p);
            }
            return left;
        }

        private Func<PacketRecord, bool> And()
        {
            var left = Not();
            while (!AtEnd && !Symbol(")") && !Word("or") && !Symbol("||"))
            {
                if (Word("and") || Symbol("&&")) Next();   // or nothing: side by side means "and"
                var a = left;
                var b = Not();
                left = p => a(p) && b(p);
            }
            return left;
        }

        private int _depth;

        private Func<PacketRecord, bool> Not()
        {
            if (Word("not") || Symbol("!"))
            {
                Next();
                var inner = Nested(Not);
                return p => !inner(p);
            }
            if (Symbol("("))
            {
                Next();
                var inner = Nested(Expression);
                if (!Symbol(")")) throw new FormatException("a bracket isn't closed");
                Next();
                return inner;
            }
            return Term();
        }

        private Func<PacketRecord, bool> Nested(Func<Func<PacketRecord, bool>> parse)
        {
            if (++_depth > MaxDepth) throw new FormatException("too many brackets or nots inside each other");
            try { return parse(); }
            finally { _depth--; }
        }

        private Func<PacketRecord, bool> Term()
        {
            if (AtEnd) throw new FormatException("something is missing at the end");
            var t = Next();
            if (t.Symbol) throw new FormatException($"\"{t.Text}\" isn't expected there");
            if (t.Quoted) return Contains(t.Text);
            string w = t.Text.ToLowerInvariant();

            // "field op value" (Wireshark), or a bare boolean field
            if (Field(w) is { } field)
            {
                if (Peek is { Symbol: true } op && op.Text is "==" or "!=" or ">" or ">=" or "<" or "<=" or "=")
                {
                    Next();
                    return field(op.Text == "=" ? "==" : op.Text, Value());
                }
                if (Word("contains") || Word("eq") || Word("ne") || Word("gt") || Word("lt") || Word("ge") || Word("le"))
                {
                    string name = Next().Text.ToLowerInvariant();
                    return field(name switch { "eq" => "==", "ne" => "!=", "gt" => ">", "lt" => "<", "ge" => ">=", "le" => "<=", _ => "contains" }, Value());
                }
                return field("present", string.Empty);
            }

            // tcpdump: [src|dst] [host|net|port|portrange] value
            switch (w)
            {
                case "src" or "dst":
                {
                    bool source = w == "src";
                    if (Word("host")) { Next(); return Address(Value(), source, !source, exact: true); }
                    if (Word("net")) { Next(); return Address(Value(), source, !source, exact: false); }
                    if (Word("port")) { Next(); return Port(Value(), source, !source); }
                    if (Word("portrange")) { Next(); return Port(Value(), source, !source); }
                    return Address(Value(), source, !source, exact: false);
                }
                case "host": return Address(Value(), true, true, exact: true);
                case "net": return Address(Value(), true, true, exact: false);
                case "port" or "portrange": return Port(Value(), true, true);
                case "less": { int n = Number(Value()); return p => p.WireLength <= n; }
                case "greater": { int n = Number(Value()); return p => p.WireLength >= n; }
            }

            if (Protocol(w) is { } protocol) return protocol;

            // a bare address / network, or a bare port number
            if (TryNet(t.Text, out var net, out int prefix)) return p => p.HasIp && (p.Src.In(net, prefix) || p.Dst.In(net, prefix));
            if (int.TryParse(w, NumberStyles.None, CultureInfo.InvariantCulture, out int port) && port is >= 0 and <= 65535)
                return p => p.L4 is PacketL4.Tcp or PacketL4.Udp && (p.SrcPort == port || p.DstPort == port);

            return Contains(t.Text);
        }

        private string Value()
        {
            if (AtEnd) throw new FormatException("a value is missing at the end");
            var t = Next();
            if (t.Symbol) throw new FormatException($"a value is expected before \"{t.Text}\"");
            return t.Text;
        }
    }

    // ------------------------------------------------------------------ tests

    private static Func<PacketRecord, bool> Contains(string text)
    {
        if (text.Length == 0) return _ => true;
        // (the name too: an HTTP request's Host isn't in its info line)
        return p => Has(p.Info, text) || Has(p.Source, text) || Has(p.Destination, text) || Has(p.Protocol, text) || Has(p.Name, text);
    }

    private static bool Has(string? where, string what) => where is not null && where.Contains(what, StringComparison.OrdinalIgnoreCase);

    private static Func<PacketRecord, bool>? Protocol(string w)
    {
        switch (w)
        {
            case "tcp": return p => p.L4 == PacketL4.Tcp;
            case "udp": return p => p.L4 == PacketL4.Udp;
            case "icmp": return p => p.L4 == PacketL4.Icmp;
            case "icmp6" or "icmpv6": return p => p.L4 == PacketL4.Icmp6;
            case "ip" or "ipv4" or "ip4": return p => p.L3 == PacketL3.IPv4;
            case "ip6" or "ipv6": return p => p.L3 == PacketL3.IPv6;
            case "arp": return p => p.L3 == PacketL3.Arp;
            case "ssl": w = "tls"; break;
            case "bootp": w = "dhcp"; break;
        }
        foreach (string name in KnownProtocols)
            if (name.Equals(w, StringComparison.OrdinalIgnoreCase))
                return p => p.Protocol.Equals(name, StringComparison.OrdinalIgnoreCase);
        return null;
    }

    private static readonly string[] KnownProtocols =
    {
        "DNS", "mDNS", "LLMNR", "NBNS", "TLS", "HTTP", "SSH", "QUIC", "DHCP", "DHCPv6", "NTP", "SSDP", "STUN", "WireGuard",
        "IGMP", "STP", "LLC", "LLDP", "EAPOL", "PPPoE", "GRE", "IPsec", "OSPF", "SCTP",
    };

    // A named field: given the operator and the value, the test. Null: not a field name.
    private static Func<string, string, Func<PacketRecord, bool>>? Field(string name)
    {
        switch (name)
        {
            case "ip.addr" or "ipv6.addr" or "addr": return (op, v) => AddressOp(op, v, true, true);
            case "ip.src" or "ipv6.src" or "ip.src_host": return (op, v) => AddressOp(op, v, true, false);
            case "ip.dst" or "ipv6.dst" or "ip.dst_host": return (op, v) => AddressOp(op, v, false, true);
            case "tcp.port": return (op, v) => PortOp(op, v, true, true, PacketL4.Tcp);
            case "udp.port": return (op, v) => PortOp(op, v, true, true, PacketL4.Udp);
            case "tcp.srcport": return (op, v) => PortOp(op, v, true, false, PacketL4.Tcp);
            case "tcp.dstport": return (op, v) => PortOp(op, v, false, true, PacketL4.Tcp);
            case "udp.srcport": return (op, v) => PortOp(op, v, true, false, PacketL4.Udp);
            case "udp.dstport": return (op, v) => PortOp(op, v, false, true, PacketL4.Udp);
            case "frame.len" or "len" or "length": return (op, v) => NumberOp(op, v, p => p.WireLength);
            case "frame.number" or "no": return (op, v) => NumberOp(op, v, p => p.Number);
            case "ip.ttl" or "ttl" or "ipv6.hlim": return (op, v) => NumberOp(op, v, p => p.HasIp && p.L3 != PacketL3.Arp ? p.Ttl : -1);
            case "ip.proto": return (op, v) => NumberOp(op, v, p => p.L3 is PacketL3.IPv4 or PacketL3.IPv6 ? p.IpProto : -1);
            case "tcp.flags.syn": return (op, v) => FlagOp(op, v, 0x02);
            case "tcp.flags.fin": return (op, v) => FlagOp(op, v, 0x01);
            case "tcp.flags.rst" or "tcp.flags.reset": return (op, v) => FlagOp(op, v, 0x04);
            case "tcp.flags.push" or "tcp.flags.psh": return (op, v) => FlagOp(op, v, 0x08);
            case "tcp.flags.ack": return (op, v) => FlagOp(op, v, 0x10);
            case "eth.addr": return (op, v) => MacOp(op, v, true, true);
            case "eth.src": return (op, v) => MacOp(op, v, true, false);
            case "eth.dst": return (op, v) => MacOp(op, v, false, true);
            case "info": return (op, v) => TextOp(op, v, p => p.Info);
            case "proto" or "protocol" or "frame.protocols": return (op, v) => TextOp(op, v, p => p.Protocol);
            // the host name a packet carries: of any kind, or of one protocol (a DNS question isn't a TLS server name)
            case "name": return (op, v) => TextOp(op, v, p => p.Name);
            case "dns.name" or "dns.qry.name": return (op, v) => NameOp(op, v, p => p.Protocol is "DNS" or "mDNS" or "LLMNR");
            case "tls.sni" or "tls.handshake.extensions_server_name": return (op, v) => NameOp(op, v, p => p.Protocol == "TLS");
            case "http.host": return (op, v) => NameOp(op, v, p => p.Protocol == "HTTP");
            default: return null;
        }
    }

    private static Func<PacketRecord, bool> AddressOp(string op, string value, bool src, bool dst)
    {
        switch (op)
        {
            case "==": return Address(value, src, dst, exact: false);
            case "!=":
            {
                var same = Address(value, src, dst, exact: false);
                return p => p.HasIp && !same(p);
            }
            case "present": return p => p.HasIp;
            case "contains": return p => (src && Has(p.Source, value)) || (dst && Has(p.Destination, value));
            default: throw new FormatException($"an address can't be compared with \"{op}\"");
        }
    }

    private static Func<PacketRecord, bool> Address(string value, bool src, bool dst, bool exact)
    {
        if (!TryNet(value, out var net, out int prefix))
            throw new FormatException($"\"{Short(value)}\" isn't an IP address{(exact ? string.Empty : " or network")} (names aren't looked up)");
        return p => p.HasIp && ((src && p.Src.In(net, prefix)) || (dst && p.Dst.In(net, prefix)));
    }

    // "1.2.3.4", "10.0.0.0/8", "2001:db8::/32"
    private static bool TryNet(string text, out IpKey net, out int prefix)
    {
        net = default;
        prefix = 0;
        string address = text;
        int slash = text.IndexOf('/');
        int bits = -1;
        if (slash > 0)
        {
            if (!int.TryParse(text.AsSpan(slash + 1), NumberStyles.None, CultureInfo.InvariantCulture, out bits)) return false;
            address = text[..slash];
        }
        // (IPAddress.TryParse takes "443" as 0.0.1.187: an IPv4 address here has its dots)
        if (!address.Contains('.') && !address.Contains(':')) return false;
        if (!IPAddress.TryParse(address.Trim('[', ']'), out var ip)) return false;
        net = IpKey.Of(ip);
        int max = net.V6 ? 128 : 32;
        prefix = bits < 0 ? max : bits;
        return prefix <= max;
    }

    private static Func<PacketRecord, bool> PortOp(string op, string value, bool src, bool dst, PacketL4 l4)
    {
        if (op == "present") return p => p.L4 == l4;
        if (op is "==" or "!=")
        {
            var same = Port(value, src, dst, l4);
            return op == "==" ? same : p => p.L4 == l4 && !same(p);
        }
        int n = Number(value);
        Func<int, bool> cmp = Compare(op, n);
        return p => p.L4 == l4 && ((src && cmp(p.SrcPort)) || (dst && cmp(p.DstPort)));
    }

    // "443" or a range "8000-8100"
    private static Func<PacketRecord, bool> Port(string value, bool src, bool dst, PacketL4? only = null)
    {
        int low, high;
        int dash = value.IndexOf('-');
        if (dash > 0) { low = Number(value[..dash]); high = Number(value[(dash + 1)..]); }
        else low = high = Number(value);
        if (low > high || high > 65535) throw new FormatException($"\"{Short(value)}\" isn't a port (0-65535)");
        return p => (only is null ? p.L4 is PacketL4.Tcp or PacketL4.Udp : p.L4 == only)
                    && ((src && p.SrcPort >= low && p.SrcPort <= high) || (dst && p.DstPort >= low && p.DstPort <= high));
    }

    private static Func<PacketRecord, bool> NumberOp(string op, string value, Func<PacketRecord, long> get)
    {
        if (op == "present") return p => get(p) >= 0;
        var cmp = Compare(op, Number(value));
        return p =>
        {
            long v = get(p);
            return v >= 0 && cmp((int)Math.Min(v, int.MaxValue));
        };
    }

    private static Func<int, bool> Compare(string op, int n) => op switch
    {
        "==" => v => v == n,
        "!=" => v => v != n,
        ">" => v => v > n,
        ">=" => v => v >= n,
        "<" => v => v < n,
        "<=" => v => v <= n,
        _ => throw new FormatException($"a number can't be compared with \"{op}\""),
    };

    private static Func<PacketRecord, bool> FlagOp(string op, string value, byte bit)
    {
        bool want = op switch
        {
            "present" => true,
            "==" => value is "1" or "true",
            "!=" => value is not ("1" or "true"),
            _ => throw new FormatException($"a flag is tested with == 1 or == 0, not \"{op}\""),
        };
        return p => p.L4 == PacketL4.Tcp && ((p.TcpFlags & bit) != 0) == want;
    }

    private static Func<PacketRecord, bool> MacOp(string op, string value, bool src, bool dst)
    {
        if (op == "present") return p => p.HasMac;
        var hex = new StringBuilder(12);
        foreach (char c in value)
            if (Uri.IsHexDigit(c)) hex.Append(c);
            else if (c is not (':' or '-' or '.')) throw new FormatException($"\"{Short(value)}\" isn't a MAC address");
        if (hex.Length != 12) throw new FormatException($"\"{Short(value)}\" isn't a MAC address");
        ulong mac = ulong.Parse(hex.ToString(), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        Func<PacketRecord, bool> same = p => p.HasMac && ((src && p.SrcMac == mac) || (dst && p.DstMac == mac));
        return op switch
        {
            "==" => same,
            "!=" => p => p.HasMac && !same(p),
            _ => throw new FormatException($"a MAC address can't be compared with \"{op}\""),
        };
    }

    private static Func<PacketRecord, bool> TextOp(string op, string value, Func<PacketRecord, string?> get) => op switch
    {
        "present" => p => !string.IsNullOrEmpty(get(p)),
        "contains" => p => Has(get(p), value),
        "==" => p => string.Equals(get(p), value, StringComparison.OrdinalIgnoreCase),
        "!=" => p => !string.IsNullOrEmpty(get(p)) && !string.Equals(get(p), value, StringComparison.OrdinalIgnoreCase),
        _ => throw new FormatException($"text is tested with contains or ==, not \"{op}\""),
    };

    private static Func<PacketRecord, bool> NameOp(string op, string value, Func<PacketRecord, bool> ofProtocol)
    {
        var test = TextOp(op, value, p => p.Name);
        return p => ofProtocol(p) && test(p);
    }

    private static int Number(string value)
        => int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int n)
            ? n
            : throw new FormatException($"\"{Short(value)}\" isn't a number");

    private static string Short(string s) => s.Length > 24 ? s[..24] + "…" : s;
}
