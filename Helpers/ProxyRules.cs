using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Echoes.Helpers;

/// <summary>
/// The proxy server's own rules, as the user writes them in three boxes: who may connect (allowed clients), which
/// ports may be reached (allowed ports) and where nothing may go (blocked hosts). An empty box is no rule. They come
/// on top of what <see cref="ProxyServer"/> always refuses for clients on other devices (this device's own addresses,
/// other private networks and mail ports without a password): a rule here can only refuse more, never allow those.
/// <para>Entries are separated by commas, semicolons, spaces or new lines:</para>
/// <list type="bullet">
/// <item>An address, a subnet, a range or a wildcard: <c>192.168.1.20</c>, <c>192.168.1.0/24</c>, <c>2001:db8::/32</c>,
/// <c>192.168.1.10-192.168.1.50</c>, <c>192.168.1.10-50</c>, <c>192.168.1.*</c>, <c>10.*</c>.</item>
/// <item>Blocked hosts also take names: <c>example.com</c> (the name and everything under it), <c>*.example.com</c>
/// (only what is under it) and wildcards anywhere (<c>ads*.example.com</c>, <c>*tracker*</c>). A pasted URL counts as
/// its host. An address there is checked against every address a name resolves to as well.</item>
/// <item>Ports: <c>80</c>, <c>443</c>, <c>8000-8100</c>.</item>
/// </list>
/// Immutable once parsed: the server reads it from many connections at once.
/// </summary>
public sealed class ProxyRules
{
    /// <summary>No rule at all.</summary>
    public static readonly ProxyRules None = new();

    /// <summary>The most entries one box may hold: every connection is checked against all of them.</summary>
    public const int MaxEntries = 2000;

    // Addresses as their raw 128 bits (IPv4 in IPv4-mapped form), as ProxyServer's own-address set keeps them.
    private readonly List<(UInt128 Lo, UInt128 Hi)> _clients = new();
    private readonly List<(UInt128 Lo, UInt128 Hi)> _blockedIps = new();
    private readonly HashSet<string> _blockedNames = new(StringComparer.Ordinal);      // the name and what is under it
    private readonly HashSet<string> _blockedUnder = new(StringComparer.Ordinal);      // only what is under it
    private readonly List<string> _blockedPatterns = new();                            // with a '*' somewhere else
    private readonly List<(int Lo, int Hi)> _ports = new();

    private ProxyRules() { }

    /// <summary>Only the listed clients may connect (this device itself always may).</summary>
    public bool LimitsClients => _clients.Count > 0;

    /// <summary>Only the listed ports may be reached.</summary>
    public bool LimitsPorts => _ports.Count > 0;

    /// <summary>Addresses or subnets are blocked: a name must be looked up to be judged.</summary>
    public bool BlocksAddresses => _blockedIps.Count > 0;

    /// <summary>How many hosts, patterns and address ranges are blocked.</summary>
    public int BlockedCount => _blockedIps.Count + _blockedNames.Count + _blockedUnder.Count + _blockedPatterns.Count;

    public bool IsEmpty => !LimitsClients && !LimitsPorts && BlockedCount == 0;

    /// <summary>
    /// Reads the three boxes. <paramref name="problem"/> is null when everything in them was understood; otherwise a
    /// sentence naming the box and the first entry that wasn't (the rules returned are then not to be used: a server
    /// started with half a list would let in, or through, what the user meant to keep out).
    /// </summary>
    public static ProxyRules Parse(string? allowedClients, string? blockedHosts, string? allowedPorts, out string? problem)
    {
        var rules = new ProxyRules();
        problem = null;

        var clients = Split(allowedClients);
        var blocked = Split(blockedHosts);
        var ports = Split(allowedPorts);
        if (clients.Length > MaxEntries) { problem = TooMany("Allowed clients"); return rules; }
        if (blocked.Length > MaxEntries) { problem = TooMany("Blocked hosts"); return rules; }
        if (ports.Length > MaxEntries) { problem = TooMany("Allowed ports"); return rules; }

        foreach (string entry in clients)
        {
            if (TryRange(entry, out var range)) rules._clients.Add(range);
            else { problem = $"Allowed clients: \"{Shown(entry)}\" isn't an address, a subnet (192.168.1.0/24) or a range (192.168.1.10-50)."; return rules; }
        }

        foreach (string entry in blocked)
        {
            if (TryRange(entry, out var range)) { rules._blockedIps.Add(range); continue; }
            string? name = HostOf(entry);
            if (name is null) { problem = $"Blocked hosts: \"{Shown(entry)}\" isn't a host name, an address or a subnet."; return rules; }
            if (name.StartsWith("*.", StringComparison.Ordinal) && name.IndexOf('*', 2) < 0) rules._blockedUnder.Add(name[2..]);
            else if (name.Contains('*')) rules._blockedPatterns.Add(name);
            else rules._blockedNames.Add(name);
        }

        foreach (string entry in ports)
        {
            if (TryPorts(entry, out var range)) rules._ports.Add(range);
            else { problem = $"Allowed ports: \"{Shown(entry)}\" isn't a port (443) or a range of ports (8000-8100)."; return rules; }
        }
        return rules;
    }

    private static string TooMany(string box) => $"{box}: more than {MaxEntries} entries. Use subnets or ranges to shorten the list.";

    // What an entry is quoted as in a message: cut, so a pasted page doesn't become the status line.
    private static string Shown(string entry) => entry.Length <= 40 ? entry : entry[..40] + "…";

    private static string[] Split(string? text)
        => string.IsNullOrWhiteSpace(text)
            ? Array.Empty<string>()
            : text.Split(new[] { ',', ';', ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    // ------------------------------------------------------------------ what the server asks

    /// <summary>May this client connect? Always true without a client list. <paramref name="client"/> null (its
    /// address couldn't be read) is nobody on the list.</summary>
    public bool ClientAllowed(IPAddress? client)
    {
        if (_clients.Count == 0) return true;
        return client is not null && TryKey(client, out var key) && In(_clients, key);
    }

    /// <summary>Is this host name blocked? (An address is asked with <see cref="AddressBlocked"/>.)</summary>
    public bool HostBlocked(string host)
    {
        if (_blockedNames.Count == 0 && _blockedUnder.Count == 0 && _blockedPatterns.Count == 0) return false;
        string name = host.Trim().TrimEnd('.').ToLowerInvariant();
        if (name.Length == 0) return false;
        // A name in another script is judged in its xn-- form: the form the entries are kept in, and the one it goes
        // on in to an upstream proxy, so "bücher.example" can't pass a block on "xn--bcher-kva.example".
        if (name.AsSpan().IndexOfAnyExceptInRange('\0', '\x7F') >= 0)
        {
            try { name = new IdnMapping().GetAscii(name); }
            catch (Exception) { /* not a name in any script (or no IDN support here): judged as it is */ }
        }
        // the name itself, then each parent: "a.b.example.com" → "b.example.com" → "example.com" → "com"
        for (int at = 0; at >= 0 && at < name.Length;)
        {
            var part = name[at..];
            if (_blockedNames.Contains(part)) return true;
            if (at > 0 && _blockedUnder.Contains(part)) return true;
            int dot = name.IndexOf('.', at);
            at = dot < 0 ? -1 : dot + 1;
        }
        foreach (string pattern in _blockedPatterns)
            if (Matches(pattern, name)) return true;
        return false;
    }

    /// <summary>Is this address in a blocked range? Asked for an address a client names and for every address a name
    /// resolves to.</summary>
    public bool AddressBlocked(IPAddress address)
        => _blockedIps.Count > 0 && TryKey(address, out var key) && In(_blockedIps, key);

    /// <summary>May this port be reached? Always true without a port list.</summary>
    public bool PortAllowed(int port)
    {
        if (_ports.Count == 0) return true;
        foreach (var (lo, hi) in _ports)
            if (port >= lo && port <= hi) return true;
        return false;
    }

    private static bool In(List<(UInt128 Lo, UInt128 Hi)> ranges, UInt128 key)
    {
        foreach (var (lo, hi) in ranges)
            if (key >= lo && key <= hi) return true;
        return false;
    }

    // '*' = any run of characters (none too). Both sides are lower case already.
    internal static bool Matches(string pattern, string text)
    {
        int p = 0, t = 0, star = -1, mark = 0;
        while (t < text.Length)
        {
            if (p < pattern.Length && pattern[p] == '*') { star = p++; mark = t; }
            else if (p < pattern.Length && pattern[p] == text[t]) { p++; t++; }
            else if (star >= 0) { p = star + 1; t = ++mark; }
            else return false;
        }
        while (p < pattern.Length && pattern[p] == '*') p++;
        return p == pattern.Length;
    }

    // ------------------------------------------------------------------ reading entries

    /// <summary>An address, a subnet, a range or an IPv4 wildcard as the first and last address it covers.</summary>
    internal static bool TryRange(string entry, out (UInt128 Lo, UInt128 Hi) range)
    {
        range = default;
        if (entry.Length == 0 || entry.Length > 100) return false;

        // 192.168.1.* · 10.*.*.* · 10.* : the stars must be the last parts, and the parts left out are stars too
        // ("192.168.*" is 192.168.0.0/16, as people write it)
        if (entry.Contains('*'))
        {
            string[] parts = entry.Split('.');
            if (parts.Length is < 2 or > 4) return false;
            int fixedParts = Array.IndexOf(parts, "*");
            if (fixedParts < 1) return false;
            for (int i = fixedParts; i < parts.Length; i++) if (parts[i] != "*") return false;
            var whole = new string[4];
            for (int i = 0; i < 4; i++) whole[i] = i < fixedParts ? parts[i] : "0";
            return TryStrictV4(string.Join('.', whole), out var net) && TrySubnet(net, fixedParts * 8, out range);
        }

        int slash = entry.IndexOf('/');
        if (slash > 0)
        {
            if (!TryAddress(entry[..slash], out var net)
                || !int.TryParse(entry.AsSpan(slash + 1), NumberStyles.None, CultureInfo.InvariantCulture, out int prefix)) return false;
            return TrySubnet(net, prefix, out range);
        }

        // a range: both ends whole, or the last part alone ("192.168.1.10-50"). Not for IPv6 (a '-' has no place in one).
        int dash = entry.IndexOf('-');
        if (dash > 0)
        {
            string first = entry[..dash], last = entry[(dash + 1)..];
            if (!TryStrictV4(first, out var a)) return false;
            if (!last.Contains('.'))
            {
                int cut = first.LastIndexOf('.');
                last = first[..(cut + 1)] + last;
            }
            if (!TryStrictV4(last, out var b) || !TryKey(a, out var lo) || !TryKey(b, out var hi) || hi < lo) return false;
            range = (lo, hi);
            return true;
        }

        if (!TryAddress(entry, out var one) || !TryKey(one, out var key)) return false;
        range = (key, key);
        return true;
    }

    private static bool TrySubnet(IPAddress network, int prefix, out (UInt128 Lo, UInt128 Hi) range)
    {
        range = default;
        bool v4 = network.AddressFamily == AddressFamily.InterNetwork;
        if (prefix < 0 || prefix > (v4 ? 32 : 128) || !TryKey(network, out var key)) return false;
        int bits = v4 ? prefix + 96 : prefix;   // counted on the 128-bit key
        UInt128 mask = bits == 0 ? UInt128.Zero : UInt128.MaxValue << (128 - bits);
        range = (key & mask, (key & mask) | ~mask);
        return true;
    }

    // An IPv4 address in the four-part form only ("10.1" or "0x7f.1" are addresses to IPAddress.Parse, and typos here),
    // or an IPv6 address (brackets and a zone are taken off).
    private static bool TryAddress(string text, out IPAddress address)
    {
        address = IPAddress.None;
        if (text.Contains(':'))
        {
            string bare = text.Trim('[', ']');
            int zone = bare.IndexOf('%');
            if (zone >= 0) bare = bare[..zone];
            if (!IPAddress.TryParse(bare, out var v6) || v6.AddressFamily != AddressFamily.InterNetworkV6) return false;
            address = v6;
            return true;
        }
        return TryStrictV4(text, out address);
    }

    private static bool TryStrictV4(string text, out IPAddress address)
    {
        address = IPAddress.None;
        string[] parts = text.Split('.');
        if (parts.Length != 4) return false;
        Span<byte> bytes = stackalloc byte[4];
        for (int i = 0; i < 4; i++)
        {
            if (parts[i].Length is 0 or > 3 || !byte.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out bytes[i])) return false;
        }
        address = new IPAddress(bytes);
        return true;
    }

    private static bool TryPorts(string entry, out (int Lo, int Hi) range)
    {
        range = default;
        int dash = entry.IndexOf('-');
        string first = dash > 0 ? entry[..dash] : entry, last = dash > 0 ? entry[(dash + 1)..] : entry;
        if (!int.TryParse(first, NumberStyles.None, CultureInfo.InvariantCulture, out int lo)
            || !int.TryParse(last, NumberStyles.None, CultureInfo.InvariantCulture, out int hi)
            || lo < 1 || hi > 65535 || hi < lo) return false;
        range = (lo, hi);
        return true;
    }

    // A blocked-host entry as the lower-case ASCII name a client's request carries: the host of a pasted URL, without
    // a port; a name in another script in its xn-- form. Null when it can't be a host name or a pattern of one.
    private static string? HostOf(string entry)
    {
        string s = entry.Trim();
        int scheme = s.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0) s = s[(scheme + 3)..];
        int end = s.IndexOfAny(new[] { '/', '?', '#' });
        if (end >= 0) s = s[..end];
        int at = s.LastIndexOf('@');
        if (at >= 0) s = s[(at + 1)..];
        int colon = s.LastIndexOf(':');
        if (colon >= 0)
        {
            if (s.IndexOf(':') != colon || !int.TryParse(s.AsSpan(colon + 1), NumberStyles.None, CultureInfo.InvariantCulture, out _)) return null;
            s = s[..colon];
        }
        s = s.TrimEnd('.').ToLowerInvariant();
        if (s.StartsWith('.')) s = s[1..];   // ".example.com" is "example.com" (the name and what is under it)
        if (s.Length is 0 or > 253) return null;

        bool ascii = true;
        foreach (char c in s) if (c > 0x7F) { ascii = false; break; }
        if (!ascii)
        {
            if (s.Contains('*')) return null;   // a pattern is matched on the ASCII form: write the xn-- name
            try { s = new IdnMapping().GetAscii(s); }
            catch (Exception) { return null; }   // not a name in any script (or no IDN support here)
        }
        foreach (char c in s)
            if (!(c is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-' or '_' or '*')) return null;
        if (s.Contains("..", StringComparison.Ordinal)) return null;
        // all digits and dots: a mistyped address ("192.168.1"), not a name
        if (s.AsSpan().IndexOfAnyExcept("0123456789.") < 0) return null;
        // numbers and stars only: an address wildcard that isn't one ("192.*.1.*"; TryRange has taken those whose
        // stars are the last parts). As a name pattern it would never match the address a client asks for.
        if (s.Contains('.') && Array.TrueForAll(s.Split('.'), part => part == "*" || (part.Length > 0 && part.AsSpan().IndexOfAnyExcept("0123456789") < 0)))
            return null;
        return s;
    }

    /// <summary>An address as its raw 128 bits: IPv4 in IPv4-mapped form, so a.b.c.d and ::ffff:a.b.c.d are one key,
    /// and no zone (it isn't part of the address).</summary>
    internal static bool TryKey(IPAddress address, out UInt128 key)
    {
        Span<byte> b = stackalloc byte[16];
        key = default;
        if (!address.TryWriteBytes(b, out int n)) return false;
        if (n == 4) key = new UInt128(0, 0xFFFF_0000_0000UL | BinaryPrimitives.ReadUInt32BigEndian(b));
        else if (n == 16) key = new UInt128(BinaryPrimitives.ReadUInt64BigEndian(b), BinaryPrimitives.ReadUInt64BigEndian(b[8..]));
        else return false;
        return true;
    }
}
