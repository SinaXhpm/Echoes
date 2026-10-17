using System;
using System.Net;
using System.Text;

namespace Echoes.Helpers;

public static class SubnetCalc
{
    /// <summary>Returns a formatted IPv4 subnet breakdown for "ip" or "ip/prefix". Throws on invalid input.</summary>
    public static string Describe(string input)
    {
        input = input.Trim();
        var parts = input.Split('/');

        if (!TryParseIPv4(parts[0].Trim(), allowShorthand: parts.Length > 1, out var ip))
            throw new ArgumentException("Enter a valid IPv4 address (e.g. 192.168.1.0/24).");

        int prefix = 32;
        if (parts.Length > 1 && !int.TryParse(parts[1].Trim(), out prefix))
            throw new ArgumentException("Invalid prefix length.");
        if (prefix < 0 || prefix > 32)
            throw new ArgumentException("Prefix must be 0-32.");

        uint ipv = ToUint(ip);
        uint mask = prefix == 0 ? 0u : 0xFFFFFFFFu << (32 - prefix);
        uint network = ipv & mask;
        uint broadcast = network | ~mask;
        uint wildcard = ~mask;
        long total = 1L << (32 - prefix);

        string hostMin, hostMax;
        long usable;
        if (prefix >= 31)
        {
            hostMin = ToIp(network);
            hostMax = ToIp(broadcast);
            usable = prefix == 32 ? 1 : 2;
        }
        else
        {
            hostMin = ToIp(network + 1);
            hostMax = ToIp(broadcast - 1);
            usable = total - 2;
        }

        var sb = new StringBuilder();
        Line(sb, "CIDR", $"{ToIp(network)}/{prefix}");
        Line(sb, "Netmask", ToIp(mask));
        Line(sb, "Wildcard", ToIp(wildcard));
        sb.AppendLine();
        Line(sb, "Network", ToIp(network));
        Line(sb, "Broadcast", ToIp(broadcast));
        Line(sb, "Host Min", hostMin);
        Line(sb, "Host Max", hostMax);
        sb.AppendLine();
        Line(sb, "Usable Hosts", usable.ToString("N0"));
        Line(sb, "Total IPs", total.ToString("N0"));
        Line(sb, "Class", IpClass(network));
        Line(sb, "Type", IpType(ip));
        return sb.ToString().TrimEnd();
    }

    // Strict dotted-decimal instead of IPAddress.TryParse, which follows inet_aton: "172.16" becomes
    // 172.0.0.16 and "192.168.001.010" is read as octal (192.168.1.8) — a silently wrong network.
    // Octets are always base-10 here; with a /prefix the usual CIDR shorthand is accepted by padding the
    // missing trailing octets with zeros ("10/8" → 10.0.0.0/8, "172.16/12" → 172.16.0.0/12).
    private static bool TryParseIPv4(string s, bool allowShorthand, out IPAddress ip)
    {
        ip = IPAddress.None;
        var oct = s.Split('.');
        if (oct.Length > 4 || (oct.Length < 4 && !allowShorthand)) return false;
        var b = new byte[4];
        for (int i = 0; i < oct.Length; i++)
        {
            string o = oct[i];
            if (o.Length is 0 or > 3) return false;
            int v = 0;
            foreach (char c in o)
            {
                if (!char.IsAsciiDigit(c)) return false;
                v = v * 10 + (c - '0');
            }
            if (v > 255) return false;
            b[i] = (byte)v;
        }
        ip = new IPAddress(b);
        return true;
    }

    private static void Line(StringBuilder sb, string label, string value)
        => sb.AppendLine($"{label,-14}: {value}");

    private static uint ToUint(IPAddress ip)
    {
        byte[] b = ip.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    private static string ToIp(uint v)
        => $"{(v >> 24) & 0xFF}.{(v >> 16) & 0xFF}.{(v >> 8) & 0xFF}.{v & 0xFF}";

    private static string IpClass(uint network)
    {
        byte first = (byte)((network >> 24) & 0xFF);
        if (first < 128) return "A";
        if (first < 192) return "B";
        if (first < 224) return "C";
        if (first < 240) return "D (Multicast)";
        return "E (Reserved)";
    }

    private static string IpType(IPAddress ip)
    {
        byte[] b = ip.GetAddressBytes();
        if (b[0] == 10) return "Private";
        if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return "Private";
        if (b[0] == 192 && b[1] == 168) return "Private";
        if (b[0] == 127) return "Loopback";
        if (b[0] == 169 && b[1] == 254) return "Link-Local (APIPA)";
        if (b[0] >= 224 && b[0] <= 239) return "Multicast";
        // Not publicly routable either — these were all reported as "Public".
        if (b[0] == 0) return "\"This network\" (0/8)";
        if (b[0] == 100 && (b[1] & 0xC0) == 64) return "CGNAT shared (100.64/10)";
        if (b[0] == 198 && (b[1] & 0xFE) == 18) return "Benchmarking (198.18/15)";
        if ((b[0], b[1], b[2]) is (192, 0, 2) or (198, 51, 100) or (203, 0, 113)) return "Documentation (TEST-NET)";
        if (b[0] >= 240) return b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255 ? "Broadcast" : "Reserved (240/4)";
        return "Public";
    }
}
