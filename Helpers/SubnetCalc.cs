using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Echoes.Helpers;

public static class SubnetCalc
{
    /// <summary>Returns a formatted IPv4 subnet breakdown for "ip" or "ip/prefix". Throws on invalid input.</summary>
    public static string Describe(string input)
    {
        input = input.Trim();
        var parts = input.Split('/');

        if (!IPAddress.TryParse(parts[0].Trim(), out var ip) || ip.AddressFamily != AddressFamily.InterNetwork)
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
        return "Public";
    }
}
