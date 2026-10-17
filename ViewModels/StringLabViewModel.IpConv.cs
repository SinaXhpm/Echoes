using System;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Echoes.ViewModels;

// IP CONV: one address in every notation people paste (dotted, integer, hex, binary, IPv6 forms),
// its reverse-DNS name, and what kind of range it belongs to.
public partial class StringLabViewModel
{
    [ObservableProperty] private string _ipConvInput = string.Empty;
    [ObservableProperty] private string _ipConvOutput = string.Empty;

    [RelayCommand]
    private void RunIpConv()
    {
        try
        {
            ResetError();
            string s = IpConvInput.Trim();
            if (s.Length == 0) return;

            string? note = null;
            int slash = s.IndexOf('/');
            if (slash > 0) { note = $"prefix {s[slash..]} ignored — use SUBNET for ranges"; s = s[..slash].Trim(); }
            // "1.2.3.4:8080" / "[2001:db8::1]:443" — drop the port
            int colon = s.IndexOf(':');
            if (colon > 0 && colon == s.LastIndexOf(':') && s.IndexOf('.') is > 0 and var dot && dot < colon)
            { note = $"port {s[(colon + 1)..]} ignored"; s = s[..colon]; }
            else if (s.StartsWith('[') && s.IndexOf("]:", StringComparison.Ordinal) is > 0 and var close)
            { note = $"port {s[(close + 2)..]} ignored"; s = s[..(close + 1)]; }
            if (s.StartsWith('[') && s.EndsWith(']')) s = s[1..^1];

            if (!TryParseAnyIp(s, out var ip, out string how))
            {
                ErrorMessage = "Not an IP address. Try 192.168.1.10, 3232235786, 0xC0A8010A, 11000000.10101000.00000001.00001010 or an IPv6 address.";
                return;
            }

            var sb = new StringBuilder();
            Row2(sb, "Input as", how);
            if (note != null) Row2(sb, "Note", note);
            sb.AppendLine();
            if (ip.AddressFamily == AddressFamily.InterNetwork) DescribeV4(sb, ip);
            else DescribeV6(sb, ip);
            IpConvOutput = sb.ToString().TrimEnd();
        }
        catch (Exception ex) { ErrorMessage = ex.Message; }
    }

    private static bool TryParseAnyIp(string s, out IPAddress ip, out string how)
    {
        ip = IPAddress.None;
        how = string.Empty;

        // IPv6 (any textual form, incl. ::ffff:a.b.c.d and %zone)
        if (s.Contains(':'))
        {
            if (IPAddress.TryParse(s, out var v6) && v6.AddressFamily == AddressFamily.InterNetworkV6) { ip = v6; how = "IPv6"; return true; }
            return false;
        }

        // plain integer → IPv4 when it fits 32 bits, else IPv6 (128-bit)
        if (s.All(char.IsAsciiDigit))
        {
            // 2^128 - 1 has 39 digits. A longer paste was BigInteger-parsed anyway, on the UI thread and quadratic on
            // .NET 8: 1 M digits froze the window 2 s, 2 M digits 8 s.
            var digits = s.AsSpan().TrimStart('0');
            if (digits.Length > 39) return false;
            if (!BigInteger.TryParse(digits.IsEmpty ? "0" : digits, NumberStyles.None, CultureInfo.InvariantCulture, out var n)) return false;
            return FromInteger(n, "integer", out ip, out how);
        }

        // 0x… hex integer
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && !s.Contains('.'))
        {
            string hex = s[2..].Replace("_", "");
            if (hex.Length is 0 or > 32 || !hex.All(Uri.IsHexDigit)) return false;
            var n = BigInteger.Parse("0" + hex, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
            return FromInteger(n, "hex integer", out ip, out how);
        }

        var parts = s.Split('.');
        if (parts.Length == 4)
        {
            // binary dotted: four groups of exactly 8 bits
            if (parts.All(p => p.Length == 8 && p.All(c => c is '0' or '1')))
            {
                ip = new IPAddress(parts.Select(p => Convert.ToByte(p, 2)).ToArray());
                how = "IPv4 (binary dotted)";
                return true;
            }
            // strict dotted decimal (no leading zeros, which inet_aton would read as octal)
            var bytes = new byte[4];
            bool strict = true;
            for (int i = 0; i < 4 && strict; i++)
                strict = parts[i].Length is >= 1 and <= 3 && (parts[i].Length == 1 || parts[i][0] != '0')
                         && byte.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out bytes[i]);
            if (strict) { ip = new IPAddress(bytes); how = "IPv4 (dotted decimal)"; return true; }
        }

        // continuous 32-bit binary
        if (s.Length == 32 && s.All(c => c is '0' or '1'))
        {
            ip = new IPAddress(Enumerable.Range(0, 4).Select(i => Convert.ToByte(s.Substring(i * 8, 8), 2)).ToArray());
            how = "IPv4 (32-bit binary)";
            return true;
        }

        // Last resort: inet_aton rules — "127.1", octal "0300.0250.0.1", hex parts "0xC0.0xA8.1.1".
        if (IPAddress.TryParse(s, out var aton) && aton.AddressFamily == AddressFamily.InterNetwork)
        {
            ip = aton;
            how = "IPv4 (inet_aton shorthand — leading 0 = octal, 0x = hex, missing parts fill from the right)";
            return true;
        }
        return false;
    }

    private static bool FromInteger(BigInteger n, string kind, out IPAddress ip, out string how)
    {
        ip = IPAddress.None;
        how = string.Empty;
        if (n.Sign < 0) return false;
        if (n <= uint.MaxValue)
        {
            uint v = (uint)n;
            ip = new IPAddress(new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v });
            how = $"IPv4 ({kind})";
            return true;
        }
        if (n >= BigInteger.One << 128) return false;
        byte[] raw = n.ToByteArray(isUnsigned: true, isBigEndian: true);
        var bytes = new byte[16];
        raw.CopyTo(bytes, 16 - raw.Length);
        ip = new IPAddress(bytes);
        how = $"IPv6 (128-bit {kind})";
        return true;
    }

    private static void DescribeV4(StringBuilder sb, IPAddress ip)
    {
        byte[] b = ip.GetAddressBytes();
        uint v = (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);

        Row2(sb, "Dotted", ip.ToString());
        Row2(sb, "Integer", v.ToString(CultureInfo.InvariantCulture));
        Row2(sb, "Hex", "0x" + v.ToString("X8", CultureInfo.InvariantCulture));
        Row2(sb, "Hex dotted", string.Join(".", b.Select(x => x.ToString("X2", CultureInfo.InvariantCulture))));
        Row2(sb, "Octal dotted", string.Join(".", b.Select(x => x == 0 ? "0" : "0" + Convert.ToString(x, 8))));
        Row2(sb, "Octal", "0" + Convert.ToString(v, 8));
        Row2(sb, "Binary dotted", string.Join(".", b.Select(x => Convert.ToString(x, 2).PadLeft(8, '0'))));
        Row2(sb, "IPv4-mapped", $"::ffff:{ip}   (::ffff:{(b[0] << 8 | b[1]):x}:{(b[2] << 8 | b[3]):x})");
        Row2(sb, "PTR", $"{b[3]}.{b[2]}.{b[1]}.{b[0]}.in-addr.arpa");
        Row2(sb, "Class", b[0] < 128 ? "A" : b[0] < 192 ? "B" : b[0] < 224 ? "C" : b[0] < 240 ? "D (multicast)" : "E (reserved)");
        Row2(sb, "Scope", ClassifyV4(b));
    }

    private static string ClassifyV4(byte[] b)
    {
        uint v = (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
        bool In(string net, int bits)
        {
            var nb = IPAddress.Parse(net).GetAddressBytes();
            uint n = (uint)(nb[0] << 24 | nb[1] << 16 | nb[2] << 8 | nb[3]);
            uint mask = bits == 0 ? 0 : uint.MaxValue << (32 - bits);
            return (v & mask) == (n & mask);
        }

        if (v == 0) return "Unspecified (0.0.0.0)";
        if (v == uint.MaxValue) return "Limited broadcast";
        if (In("0.0.0.0", 8)) return "\"This network\" (0.0.0.0/8) — not routable";
        if (In("10.0.0.0", 8)) return "Private (RFC 1918, 10/8)";
        if (In("100.64.0.0", 10)) return "CGNAT shared address space (RFC 6598, 100.64/10)";
        if (In("127.0.0.0", 8)) return "Loopback (127/8)";
        if (In("169.254.0.0", 16)) return "Link-local / APIPA (169.254/16)";
        if (In("172.16.0.0", 12)) return "Private (RFC 1918, 172.16/12)";
        if (In("192.0.0.0", 24)) return "IETF protocol assignments (192.0.0/24)";
        if (In("192.0.2.0", 24)) return "Documentation (TEST-NET-1, 192.0.2/24)";
        if (In("192.88.99.0", 24)) return "6to4 relay anycast (deprecated)";
        if (In("192.168.0.0", 16)) return "Private (RFC 1918, 192.168/16)";
        if (In("198.18.0.0", 15)) return "Benchmarking (RFC 2544, 198.18/15)";
        if (In("198.51.100.0", 24)) return "Documentation (TEST-NET-2, 198.51.100/24)";
        if (In("203.0.113.0", 24)) return "Documentation (TEST-NET-3, 203.0.113/24)";
        if (In("224.0.0.0", 24)) return "Multicast — local network control (224.0.0/24)";
        if (In("224.0.0.0", 4)) return "Multicast (224/4)";
        if (In("240.0.0.0", 4)) return "Reserved (Class E, 240/4)";
        return "Public (global unicast)";
    }

    private static void DescribeV6(StringBuilder sb, IPAddress ip)
    {
        byte[] b = ip.GetAddressBytes();
        var noScope = new IPAddress(b);
        var groups = Enumerable.Range(0, 8).Select(i => (b[i * 2] << 8 | b[i * 2 + 1]).ToString("x4", CultureInfo.InvariantCulture));
        var n = new BigInteger(b, isUnsigned: true, isBigEndian: true);

        Row2(sb, "Compressed", noScope.ToString());
        Row2(sb, "Expanded", string.Join(":", groups));
        if (ip.ScopeId != 0) Row2(sb, "Zone / scope", "%" + ip.ScopeId.ToString(CultureInfo.InvariantCulture));
        Row2(sb, "Integer", n.ToString(CultureInfo.InvariantCulture));
        Row2(sb, "Hex", "0x" + Convert.ToHexString(b));
        // ip6.arpa: every nibble, least significant first
        var nibbles = new StringBuilder(72);
        for (int i = 15; i >= 0; i--)
            nibbles.Append((b[i] & 0xF).ToString("x")).Append('.').Append((b[i] >> 4).ToString("x")).Append('.');
        Row2(sb, "PTR", nibbles + "ip6.arpa");
        Row2(sb, "Scope", ClassifyV6(b));

        if (ip.IsIPv4MappedToIPv6)
        {
            var v4 = ip.MapToIPv4();
            sb.AppendLine();
            Row2(sb, "IPv4 (mapped)", v4.ToString());
            Row2(sb, "IPv4 scope", ClassifyV4(v4.GetAddressBytes()));
        }
    }

    private static string ClassifyV6(byte[] b)
    {
        bool Prefix(string net, int bits)
        {
            var nb = IPAddress.Parse(net).GetAddressBytes();
            for (int i = 0; i < 16 && bits > 0; i++, bits -= 8)
            {
                int mask = bits >= 8 ? 0xFF : (0xFF << (8 - bits)) & 0xFF;
                if ((b[i] & mask) != (nb[i] & mask)) return false;
            }
            return true;
        }

        if (b.All(x => x == 0)) return "Unspecified (::)";
        if (Prefix("::1", 128)) return "Loopback (::1)";
        if (Prefix("::ffff:0:0", 96)) return "IPv4-mapped (::ffff:0:0/96)";
        if (Prefix("64:ff9b::", 96)) return "NAT64 well-known prefix (64:ff9b::/96)";
        if (Prefix("2001:db8::", 32)) return "Documentation (2001:db8::/32)";
        if (Prefix("2001::", 32)) return "Teredo tunnelling (2001::/32)";
        if (Prefix("2002::", 16)) return "6to4 (2002::/16)";
        if (Prefix("fe80::", 10)) return "Link-local (fe80::/10)";
        if (Prefix("fec0::", 10)) return "Site-local (deprecated, fec0::/10)";
        if (Prefix("fc00::", 7)) return "Unique local / private (ULA, fc00::/7)";
        if (Prefix("ff00::", 8))
        {
            string scope = (b[1] & 0xF) switch
            {
                1 => "interface-local", 2 => "link-local", 4 => "admin-local", 5 => "site-local",
                8 => "organization-local", 0xE => "global", _ => "scope " + (b[1] & 0xF).ToString("x")
            };
            return $"Multicast ({scope})";
        }
        if (Prefix("2000::", 3)) return "Global unicast (2000::/3)";
        return "Reserved / unassigned";
    }
}
