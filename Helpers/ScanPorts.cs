using System;
using System.Collections.Generic;

namespace Echoes.Helpers;

/// <summary>
/// The PORTS box, nmap's -p syntax: "22,80,443", ranges "1-1024" (and the open-ended "1024-", "-100", "-" = all),
/// "top-100" (the most common ports of each protocol, so TCP and UDP each get their own top list), and the protocol
/// prefixes "T:" / "U:" that apply to every item after them ("T:1-1000,U:53,161"). Unprefixed items follow the TCP /
/// UDP check boxes; prefixed ones name their protocol, so "U:53" scans UDP 53 even with the UDP box unticked.
/// </summary>
public sealed class ScanPortSpec
{
    public List<int> Tcp { get; } = new();
    public List<int> Udp { get; } = new();
    public List<string> Errors { get; } = new();

    public static ScanPortSpec Parse(string? input, bool tcp, bool udp)
    {
        var spec = new ScanPortSpec();
        if (string.IsNullOrWhiteSpace(input)) return spec;
        var seenTcp = new HashSet<int>();
        var seenUdp = new HashSet<int>();
        bool useTcp = tcp, useUdp = udp;

        foreach (var raw in input.Split(new[] { ',', ';', ' ', '\t', '\r', '\n', '\u060C', '\u061B' }, StringSplitOptions.RemoveEmptyEntries))
        {
            string item = LocalDigits.Fold(raw.Trim());   // digits typed in the phone's language
            if (item.Length >= 2 && item[1] == ':' && item[0] is 'T' or 't' or 'U' or 'u')
            {
                useTcp = item[0] is 'T' or 't';
                useUdp = !useTcp;
                item = item[2..].Trim();
                if (item.Length == 0) continue;
            }

            if (TryTop(item, out int n))
            {
                if (useTcp) AddAll(NmapData.TopPorts(n, ScanProto.Tcp), spec.Tcp, seenTcp);
                if (useUdp) AddAll(NmapData.TopPorts(n, ScanProto.Udp), spec.Udp, seenUdp);
                continue;
            }

            if (!TryRange(item, out int lo, out int hi)) { spec.Errors.Add(raw.Trim()); continue; }
            for (int p = lo; p <= hi; p++)
            {
                if (useTcp && seenTcp.Add(p)) spec.Tcp.Add(p);
                if (useUdp && seenUdp.Add(p)) spec.Udp.Add(p);
            }
        }
        return spec;
    }

    public int Total => Tcp.Count + Udp.Count;

    /// <summary>"1,000 TCP + 100 UDP ports" / "443/tcp" — for the status line and the report header.</summary>
    public string Describe()
    {
        static string One(List<int> l, string proto) =>
            l.Count == 1 ? $"{l[0]}/{proto.ToLowerInvariant()}" : $"{l.Count:N0} {proto} ports";
        if (Tcp.Count > 0 && Udp.Count > 0) return $"{One(Tcp, "TCP")} + {One(Udp, "UDP")}";
        return Tcp.Count > 0 ? One(Tcp, "TCP") : One(Udp, "UDP");
    }

    private static void AddAll(List<int> ports, List<int> into, HashSet<int> seen)
    {
        foreach (int p in ports) if (seen.Add(p)) into.Add(p);
    }

    // "top-100" or "top100".
    private static bool TryTop(string s, out int n)
    {
        n = 0;
        if (!s.StartsWith("top", StringComparison.OrdinalIgnoreCase)) return false;
        var rest = s.AsSpan(3).TrimStart('-');
        return int.TryParse(rest, out n) && n > 0;
    }

    private static bool TryRange(string s, out int lo, out int hi)
    {
        lo = hi = 0;
        int dash = s.IndexOf('-');
        if (dash < 0)
        {
            if (!int.TryParse(s, out lo) || lo is < 1 or > 65535) return false;
            hi = lo;
            return true;
        }
        string a = s[..dash].Trim(), b = s[(dash + 1)..].Trim();
        lo = a.Length == 0 ? 1 : int.TryParse(a, out int x) ? x : -1;
        hi = b.Length == 0 ? 65535 : int.TryParse(b, out int y) ? y : -1;
        if (lo < 0 || hi < 0) return false;
        // Wholly out of range ("70000-80000", "0-0") is an error, not a scan of port 65535; a partial overlap is trimmed.
        if (hi < 1 || lo > 65535) return false;
        lo = Math.Max(lo, 1);
        hi = Math.Min(hi, 65535);
        return lo <= hi;
    }
}
