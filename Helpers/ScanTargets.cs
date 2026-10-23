using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Numerics;

namespace Echoes.Helpers;

/// <summary>
/// Parses the TARGETS box into concrete IP addresses (IPv4 and IPv6). Handles single literals,
/// "a-b" ranges (only when the left side is an IP — so hostnames like "my-host.example.com" are
/// never mistaken for ranges), CIDR blocks (v4 any prefix, v6 only ≥/112 to keep the sweep sane),
/// and URL / host:port / user@host tokens via <see cref="HostExtractor"/>. Bare names that aren't
/// literals are handed back as <see cref="Result.Hostnames"/> for the caller to resolve; genuinely
/// unparseable tokens are collected in <see cref="Result.Errors"/> instead of being dropped.
/// </summary>
public static class ScanTargets
{
    public const int MaxHosts = 65536;

    public sealed class Result
    {
        public readonly List<IPAddress> Ips = new();     // literals + expanded ranges/CIDRs (deduped)
        public readonly List<string> Hostnames = new();  // bare names needing DNS
        public readonly List<string> Errors = new();     // unparseable / "IPv6 range too large"
        public bool Capped;                              // hit MaxHosts
    }

    public static Result Parse(string? input)
    {
        var r = new Result();
        if (string.IsNullOrWhiteSpace(input)) return r;

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // Accept comma, whitespace, newline and semicolon as separators (the Arabic comma and semicolon too).
        var tokens = input.Split(new[] { ',', ';', ' ', '\t', '\r', '\n', '\u060C', '\u061B' }, StringSplitOptions.RemoveEmptyEntries);

        foreach (var raw in tokens)
        {
            // (No early break at the host cap: AddIp/Expand enforce it per address, and hostnames
            // after the cap must still be collected so BuildTargets can report them.)
            string tok = raw.Trim().Trim('"', '\'', '`');
            if (!LocalDigits.HasNonAsciiLetter(tok)) tok = LocalDigits.Fold(tok);   // Persian / Arabic digits: an IP, not a name
            if (tok.Length == 0) continue;

            try
            {
                // CIDR — only when it's really "ip/prefix" (so a URL like http://host/path isn't
                // mistaken for one; it falls through to HostExtractor below).
                if (tok.Contains('/'))
                {
                    var cp = tok.Split('/');
                    if (cp.Length == 2 && TryParseIp(cp[0].Trim(), out _) && int.TryParse(cp[1].Trim(), out _))
                    { AddCidr(tok, r, seen); continue; }
                }

                // Range "a-b" — but ONLY when the left side is an IP literal (A2). Otherwise a
                // hyphenated hostname would be silently swallowed as a range.
                int dash = tok.IndexOf('-');
                if (dash > 0 && TryParseIp(tok[..dash].Trim(), out _))
                {
                    AddRange(tok, r, seen);
                    continue;
                }

                // Bare IP literal (v4 or v6)?
                if (TryParseIp(tok, out var ip)) { AddIp(ip, r, seen); continue; }

                // URL / host:port / user@host / [v6]:port → pull out the bare host.
                string host = HostExtractor.Extract(tok);
                if (TryParseIp(host, out var ip2)) { AddIp(ip2, r, seen); continue; }

                if (host.Length > 0 && LooksLikeHostname(host)) r.Hostnames.Add(host);
                else r.Errors.Add(tok);
            }
            catch { r.Errors.Add(tok); }
        }

        // (Capped is set only when an address was actually dropped — an exact /16 = 65,536 fits.)
        return r;
    }

    /// <summary>
    /// Strict IP-literal test. <see cref="IPAddress.TryParse(string, out IPAddress)"/> is inet_aton-lenient:
    /// "20" parses as 0.0.0.20 and "10.0.0" as 10.0.0.0 — which silently turned the range shorthand
    /// "10.0.0.1-20" into the empty range 10.0.0.1..0.0.0.20. IPv4 must be a dotted quad of decimal
    /// octets; IPv6 must contain ':'. IPv4-mapped IPv6 (::ffff:a.b.c.d) is unwrapped to plain IPv4 so
    /// it can be dialled from an IPv4 socket.
    /// </summary>
    public static bool TryParseIp(string? s, out IPAddress ip)
    {
        ip = IPAddress.None;
        if (string.IsNullOrWhiteSpace(s)) return false;
        s = s.Trim();
        if (s.Contains(':'))
        {
            if (!IPAddress.TryParse(s, out var v6) || v6.AddressFamily != AddressFamily.InterNetworkV6) return false;
            ip = v6.IsIPv4MappedToIPv6 ? v6.MapToIPv4() : v6;
            return true;
        }
        int dots = 0;
        foreach (char c in s)
        {
            if (c == '.') dots++;
            else if (c is < '0' or > '9') return false;
        }
        if (dots != 3 || !IPAddress.TryParse(s, out var v4) || v4.AddressFamily != AddressFamily.InterNetwork) return false;
        ip = v4;
        return true;
    }

    private static void AddIp(IPAddress ip, Result r, HashSet<string> seen)
    {
        string key = ip.ToString();
        if (seen.Contains(key)) return;                            // duplicates never count as "capped"
        if (r.Ips.Count >= MaxHosts) { r.Capped = true; return; }
        seen.Add(key);
        r.Ips.Add(ip);
    }

    private static void AddRange(string token, Result r, HashSet<string> seen)
    {
        int dash = token.IndexOf('-');
        string leftStr = token[..dash].Trim();
        string rightStr = token[(dash + 1)..].Trim();
        if (!TryParseIp(leftStr, out var start)) { r.Errors.Add(token); return; }

        BigInteger lo = ToBig(start), hi;
        // Shorthand first ("192.168.1.10-20": a bare last octet); TryParseIp's strictness is what
        // keeps "20" from being read as the address 0.0.0.20.
        if (start.AddressFamily == AddressFamily.InterNetwork && byte.TryParse(rightStr, out byte lastOctet))
            hi = (lo & ~(BigInteger)0xFF) | lastOctet;
        else if (TryParseIp(rightStr, out var endIp) && endIp.AddressFamily == start.AddressFamily)
            hi = ToBig(endIp);
        else { r.Errors.Add(token); return; }

        if (hi < lo) { r.Errors.Add(token + " (reversed range)"); return; }
        Expand(lo, hi, start.AddressFamily, r, seen);
    }

    private static void AddCidr(string token, Result r, HashSet<string> seen)
    {
        var parts = token.Split('/');
        if (parts.Length != 2 || !TryParseIp(parts[0].Trim(), out var ip)
            || !int.TryParse(parts[1].Trim(), out int prefix)) { r.Errors.Add(token); return; }

        bool v6 = ip.AddressFamily == AddressFamily.InterNetworkV6;
        int bits = v6 ? 128 : 32;
        if (prefix < 0 || prefix > bits) { r.Errors.Add(token); return; }

        // An IPv6 block wider than /112 (>65k hosts) would blow past the cap — refuse it explicitly
        // so the user sees why nothing was scanned instead of a silent truncation.
        if (v6 && prefix < 112) { r.Errors.Add($"{token} (IPv6 range too large — use ≥ /112)"); return; }

        BigInteger addr = ToBig(ip);
        BigInteger full = (BigInteger.One << bits) - 1;
        BigInteger mask = prefix == 0 ? BigInteger.Zero : (full << (bits - prefix)) & full;
        BigInteger network = addr & mask;
        BigInteger broadcast = network | (full & ~mask);
        Expand(network, broadcast, ip.AddressFamily, r, seen);
    }

    private static void Expand(BigInteger lo, BigInteger hi, AddressFamily family, Result r, HashSet<string> seen)
    {
        if (hi < lo) return;
        int len = family == AddressFamily.InterNetworkV6 ? 16 : 4;
        BigInteger cur = lo;
        while (cur <= hi)
        {
            if (r.Ips.Count >= MaxHosts) { r.Capped = true; return; }
            AddIp(FromBig(cur, len), r, seen);
            cur += 1;
        }
    }

    // Big-endian bytes <-> unsigned BigInteger (isUnsigned + isBigEndian keeps ordering intuitive).
    private static BigInteger ToBig(IPAddress ip) => new(ip.GetAddressBytes(), isUnsigned: true, isBigEndian: true);

    private static IPAddress FromBig(BigInteger v, int len)
    {
        var bytes = v.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (bytes.Length == len) return new IPAddress(bytes);
        var buf = new byte[len];                                   // left-pad to the address width
        Array.Copy(bytes, 0, buf, len - bytes.Length, bytes.Length);
        return new IPAddress(buf);
    }

    // A hostname we'll bother to resolve: a letter or a dot, only DNS-legal characters, and no empty or over-long label
    // ("bad..x" is a typo to report, not a name to look up).
    private static bool LooksLikeHostname(string h)
    {
        bool hasLetter = false;
        foreach (char c in h)
        {
            if (char.IsLetter(c)) hasLetter = true;
            else if (!(char.IsDigit(c) || c is '.' or '-' or '_')) return false;
        }
        foreach (var label in h.TrimEnd('.').Split('.'))
            if (label.Length is 0 or > 63) return false;
        return hasLetter || h.Contains('.');
    }
}

/// <summary>
/// Orders IP addresses numerically: IPv4 before IPv6, then by big-endian address bytes — so
/// "10.0.0.2" sorts before "10.0.0.10" (a plain string sort gets that backwards).
/// </summary>
public sealed class IpAddressComparer : System.Collections.Generic.IComparer<IPAddress?>
{
    public static readonly IpAddressComparer Instance = new();

    public int Compare(IPAddress? a, IPAddress? b)
    {
        if (ReferenceEquals(a, b)) return 0;
        if (a is null) return -1;
        if (b is null) return 1;
        if (a.AddressFamily != b.AddressFamily)
            return a.AddressFamily == AddressFamily.InterNetwork ? -1 : 1;   // v4 before v6
        // Allocation-free (the report/CSV snapshot sorts up to a few hundred thousand rows, and
        // GetAddressBytes() would allocate two arrays per comparison).
        Span<byte> ba = stackalloc byte[16], bb = stackalloc byte[16];
        a.TryWriteBytes(ba, out int la);
        b.TryWriteBytes(bb, out int lb);
        int c = ba[..la].SequenceCompareTo(bb[..lb]);
        if (c != 0 || a.AddressFamily != AddressFamily.InterNetworkV6) return c;
        return a.ScopeId.CompareTo(b.ScopeId);   // (ScopeId throws on IPv4 — v6 only)
    }
}
