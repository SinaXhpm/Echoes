using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace Echoes.Helpers;

/// <summary>
/// What kind of address a DNS answer is, for the Doctor's tampering test: a public name must resolve to public unicast
/// addresses, so a private / reserved / bogon answer (or one of the known filter addresses) gives a filter away.
/// </summary>
public static class DoctorIp
{
    // Iran's national filter answers blocked names with these (A) / d0::11 (AAAA); its block page lives on 10.10.34.34.
    private static readonly IPAddress[] KnownFilter =
    {
        IPAddress.Parse("10.10.34.34"), IPAddress.Parse("10.10.34.35"), IPAddress.Parse("10.10.34.36"),
        IPAddress.Parse("d0::11"),
    };

    /// <summary>Set by the test harness only: loopback addresses count as public, so a scenario served on 127.0.0.1 can
    /// play a real site. Never set by the app.</summary>
    internal static bool LoopbackIsPublic { get; set; }

    public static bool IsKnownFilter(IPAddress a)
    {
        var n = Normal(a);
        foreach (var f in KnownFilter) if (f.Equals(n)) return true;
        return false;
    }

    /// <summary>A routable public unicast address (what a public name should resolve to).</summary>
    public static bool IsPublic(IPAddress a) => Kind(a) == null;

    /// <summary>Why the address can't be a public site's ("private", "loopback", …), or null when it is public.</summary>
    public static string? Kind(IPAddress a)
    {
        var n = Normal(a);
        if (IsKnownFilter(n)) return "the filter's address";
        if (n.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] b = n.GetAddressBytes();
            if (b[0] == 127) return LoopbackIsPublic ? null : "loopback";
            if (b[0] == 0) return "reserved";
            if (b[0] == 10 || (b[0] == 172 && (b[1] & 0xF0) == 16) || (b[0] == 192 && b[1] == 168)) return "private";
            if (b[0] == 100 && (b[1] & 0xC0) == 64) return "carrier NAT";
            if (b[0] == 169 && b[1] == 254) return "link-local";
            if (b[0] == 192 && b[1] == 0 && (b[2] == 0 || b[2] == 2)) return "reserved";
            if (b[0] == 198 && (b[1] & 0xFE) == 18) return "reserved";
            if ((b[0] == 198 && b[1] == 51 && b[2] == 100) || (b[0] == 203 && b[1] == 0 && b[2] == 113)) return "reserved";
            if (b[0] >= 224 && b[0] <= 239) return "multicast";
            if (b[0] >= 240) return "reserved";
            return null;
        }
        if (n.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (n.Equals(IPAddress.IPv6Loopback)) return LoopbackIsPublic ? null : "loopback";
            byte[] b = n.GetAddressBytes();
            if (b[0] == 0xFF) return "multicast";
            if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return "link-local";
            if ((b[0] & 0xFE) == 0xFC) return "private";
            if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8) return "reserved";
            if ((b[0] & 0xE0) != 0x20) return "reserved";   // global unicast is 2000::/3 only
            return null;
        }
        return "reserved";
    }

    /// <summary>The IPv4 form of an IPv4-mapped IPv6 address, or of one in the well-known NAT64 prefix (what DNS64 answers
    /// for an IPv4-only site on an IPv6-only network); anything else unchanged.</summary>
    public static IPAddress Normal(IPAddress a) => a.IsIPv4MappedToIPv6 ? a.MapToIPv4() : FromNat64(a, null) ?? a;

    // NAT64 (RFC 6052): an IPv6-only network reaches IPv4 hosts at addresses that carry the IPv4 one in their last 32 bits,
    // under the well-known 64:ff9b::/96 or a /96 of the network's own (RFC 7050 finds it through ipv4only.arpa).
    public static readonly IPAddress WellKnownNat64 = IPAddress.Parse("64:ff9b::");
    private static readonly byte[] WellKnownNat64Bytes = WellKnownNat64.GetAddressBytes();

    /// <summary>The IPv4 address inside <paramref name="a"/> when it lies in the NAT64 /96 <paramref name="prefix"/> or the
    /// well-known one; else null.</summary>
    public static IPAddress? FromNat64(IPAddress a, IPAddress? prefix)
    {
        if (a.AddressFamily != AddressFamily.InterNetworkV6) return null;
        byte[] b = a.GetAddressBytes();
        if (!SamePrefix96(b, WellKnownNat64Bytes) && (prefix is null || !SamePrefix96(b, prefix.GetAddressBytes()))) return null;
        return new IPAddress(b.AsSpan(12, 4));
    }

    /// <summary>IPv4 <paramref name="v4"/> as an IPv6-only network dials it: inside the NAT64 /96 <paramref name="prefix"/>.</summary>
    public static IPAddress ViaNat64(IPAddress v4, IPAddress prefix)
    {
        byte[] b = prefix.GetAddressBytes();
        v4.GetAddressBytes().CopyTo(b, 12);
        return new IPAddress(b);
    }

    /// <summary>The NAT64 /96 prefix of a DNS64 answer for ipv4only.arpa (whose IPv4 addresses are 192.0.0.170 and .171),
    /// or null for any other address.</summary>
    public static IPAddress? Nat64PrefixOf(IPAddress a)
    {
        if (a.AddressFamily != AddressFamily.InterNetworkV6) return null;
        byte[] b = a.GetAddressBytes();
        if (b[12] != 192 || b[13] != 0 || b[14] != 0 || b[15] is not (170 or 171)) return null;
        b[12] = b[13] = b[14] = b[15] = 0;
        return new IPAddress(b);
    }

    private static bool SamePrefix96(byte[] a, byte[] prefix)
    {
        for (int i = 0; i < 12; i++) if (a[i] != prefix[i]) return false;
        return true;
    }

    /// <summary>Same /24 (IPv4) or /48 (IPv6): close enough to be the same operator's servers.</summary>
    public static bool SameNetwork(IPAddress a, IPAddress b)
    {
        a = Normal(a);
        b = Normal(b);
        if (a.AddressFamily != b.AddressFamily) return false;
        byte[] x = a.GetAddressBytes(), y = b.GetAddressBytes();
        int n = a.AddressFamily == AddressFamily.InterNetwork ? 3 : 6;
        for (int i = 0; i < n; i++) if (x[i] != y[i]) return false;
        return true;
    }

    /// <summary>IPv4 first (what the checks connect to), duplicates removed.</summary>
    public static List<IPAddress> Ordered(IEnumerable<IPAddress> addrs)
        => addrs.Select(Normal).Distinct().OrderBy(a => a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1).ToList();

    /// <summary>"1.2.3.4, 5.6.7.8 +2" for a detail line.</summary>
    public static string List(IReadOnlyCollection<IPAddress> addrs, int max = 2)
    {
        if (addrs.Count == 0) return "no addresses";
        var shown = addrs.Take(max).Select(a => a.ToString());
        string s = string.Join(", ", shown);
        return addrs.Count > max ? $"{s} +{addrs.Count - max}" : s;
    }

    /// <summary>"[v6]:port" / "v4:port".</summary>
    public static string EndPoint(IPAddress a, int port)
        => a.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{a}]:{port}" : $"{a}:{port}";
}
