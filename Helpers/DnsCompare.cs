using DnsClient;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>How far a resolver can be trusted for the compared name.</summary>
public enum CompareVerdict
{
    Pending,
    /// <summary>Answered, and its answers agree with the encrypted resolvers (or nothing to check against).</summary>
    Ok,
    /// <summary>Answered only some of the rounds.</summary>
    Unstable,
    /// <summary>Public addresses / values, none shared with the encrypted majority (a CDN's other servers, a proxy DNS, or tampering).</summary>
    Differs,
    /// <summary>"No such name" / no records / 0.0.0.0 while the encrypted resolvers answer.</summary>
    Filtered,
    /// <summary>Redirects to a private or known censorship address (10.10.34.x …).</summary>
    Tampered,
    /// <summary>No usable answer in any round (timeout, TLS failure, SERVFAIL, REFUSED …).</summary>
    Failed,
}

/// <summary>Everything one resolver did over the rounds, and the verdict once all are in.</summary>
public sealed class CompareStats
{
    public CompareStats(ResolverSpec spec) => Spec = spec;
    public ResolverSpec Spec { get; }
    public int Attempts { get; set; }
    /// <summary>Rounds that brought a usable response (NOERROR, or NXDOMAIN).</summary>
    public int Successes { get; set; }
    public List<double> Times { get; } = new();
    public string Via { get; set; } = "";
    /// <summary>Values of the queried type, in first-seen order, over all rounds.</summary>
    public List<string> Values { get; } = new();
    public bool SawNxDomain { get; set; }
    public bool SawEmpty { get; set; }
    public string? LastError { get; set; }
    public string? LastShortError { get; set; }

    public CompareVerdict Verdict { get; set; } = CompareVerdict.Pending;
    /// <summary>Why the verdict (one line).</summary>
    public string Note { get; set; } = "";
    public bool IsBest { get; set; }

    public double? Median
    {
        get
        {
            if (Times.Count == 0) return null;
            var t = Times.OrderBy(x => x).ToList();
            int n = t.Count;
            return n % 2 == 1 ? t[n / 2] : (t[n / 2 - 1] + t[n / 2]) / 2;
        }
    }

    public bool Trustworthy => Verdict == CompareVerdict.Ok && Successes > 0;

    /// <summary>Folds one round's result in.</summary>
    public void Add(DnsResult r, string type)
    {
        Attempts++;
        if (r.Via.Length > 0) Via = r.Via;
        if (!r.Answered) { LastError = r.Error; LastShortError = r.ShortError; return; }
        if (r.Rcode is not (0 or 3))
        {
            LastError = r.RcodeText;
            LastShortError = r.Rcode switch { 2 => "SERVFAIL", 5 => "REFUSED", 1 => "FORMERR", 4 => "NOTIMP", _ => "RCODE " + r.Rcode };
            return;
        }
        Successes++;
        Times.Add(r.RttMs);
        if (r.Rcode == 3) { SawNxDomain = true; return; }
        bool any = false;
        foreach (var a in r.OfType(type))
        {
            any = true;
            string v = DnsCompare.Normalize(a.Value, type);
            if (!Values.Contains(v) && Values.Count < 64) Values.Add(v);
        }
        if (!any) SawEmpty = true;
    }
}

/// <summary>
/// "Compare resolvers": one name asked of every resolver a few times. Speed is the median round trip; trust is
/// checked against the encrypted resolvers (DoH / DoT), whose answers a network in between can't rewrite —
/// a plain resolver that answers with a censorship address, "no such name", or addresses no encrypted resolver
/// gives is flagged.
/// </summary>
public static class DnsCompare
{
    public const int Rounds = 3;
    public const int MaxResolvers = 40;
    private const int Parallel = 10;

    /// <summary>Runs <see cref="Rounds"/> rounds against every resolver (each resolver's rounds in order, several
    /// resolvers at once), reporting each result as it lands, then sets every verdict (<see cref="Analyze"/>).</summary>
    public static async Task<List<CompareStats>> RunAsync(IReadOnlyList<ResolverSpec> specs, string name, QueryType type,
                                                          Action<CompareStats, int>? onRound, CancellationToken ct)
    {
        var stats = specs.Take(MaxResolvers).Select(s => new CompareStats(s)).ToList();
        string typeName = type.ToString();
        using var gate = new SemaphoreSlim(Parallel);
        var tasks = stats.Select(async st =>
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                // plain: 2.5 s is generous for one UDP round trip; encrypted: the first round also connects + handshakes
                using var session = new DnsSession(st.Spec, st.Spec.IsEncrypted ? TimeSpan.FromSeconds(4) : TimeSpan.FromSeconds(2.5));
                for (int round = 1; round <= Rounds; round++)
                {
                    ct.ThrowIfCancellationRequested();
                    var r = await session.QueryAsync(name, type, ct).ConfigureAwait(false);
                    lock (st) st.Add(r, typeName);
                    onRound?.Invoke(st, round);
                    // a resolver that didn't answer at all in round 1 (blocked / unreachable) is very likely to time
                    // out again: one more try, not two, so a dead entry doesn't hold the run up
                    if (round == 1 && !r.Answered && r.ShortError == "timeout") { round++; }
                }
            }
            finally { gate.Release(); }
        }).ToList();
        await Task.WhenAll(tasks).ConfigureAwait(false);
        Analyze(stats, typeName);
        return stats;
    }

    /// <summary>
    /// Sets each resolver's verdict + note and marks the fastest trustworthy one (<see cref="CompareStats.IsBest"/>).
    /// Pure: the harness checks it on canned data.
    /// </summary>
    public static void Analyze(IReadOnlyList<CompareStats> stats, string type)
    {
        bool isAddress = type is "A" or "AAAA";
        var encrypted = stats.Where(s => s.Spec.IsEncrypted && s.Successes > 0).ToList();
        // the reference: what the encrypted resolvers said (bogus addresses excluded — an encrypted resolver that
        // filters, like AdGuard's 0.0.0.0, doesn't make 0.0.0.0 "the truth")
        var refValues = new HashSet<string>(encrypted.SelectMany(s => s.Values).Where(v => !isAddress || !IsBogus(v)));
        int encWithValues = encrypted.Count(s => s.Values.Any(v => !isAddress || !IsBogus(v)));
        int encNx = encrypted.Count(s => s.Values.Count == 0 && (s.SawNxDomain || s.SawEmpty));
        bool refSaysExists = encWithValues > 0 && encWithValues >= encNx;

        foreach (var s in stats)
        {
            s.IsBest = false;
            if (s.Successes == 0)
            {
                s.Verdict = CompareVerdict.Failed;
                s.Note = s.LastError ?? "no answer";
                continue;
            }

            var bogus = isAddress ? s.Values.Where(IsBogus).ToList() : new List<string>();
            if (bogus.Count > 0)
            {
                string first = bogus[0];
                bool censor = IsCensorAddress(first);
                bool sinkhole = first is "0.0.0.0" or "::" || first.StartsWith("127.", StringComparison.Ordinal) || first == "::1";
                s.Verdict = censor || !sinkhole ? CompareVerdict.Tampered : CompareVerdict.Filtered;
                s.Note = censor
                    ? $"answers {first} — a censorship / filtering address, not the real one"
                    : sinkhole
                        ? $"answers {first} — the name is blocked by this resolver"
                        : $"answers {first} — a private address for a public name (redirected)";
                continue;
            }

            if (refSaysExists)
            {
                if (s.Values.Count == 0)
                {
                    s.Verdict = CompareVerdict.Filtered;
                    s.Note = s.SawNxDomain
                        ? "says the name doesn't exist (NXDOMAIN) while the encrypted resolvers answer it"
                        : "returns no records while the encrypted resolvers do";
                    continue;
                }
                // its values vs. the reference: an encrypted resolver is compared with the OTHER encrypted ones
                var reference = s.Spec.IsEncrypted
                    ? new HashSet<string>(encrypted.Where(o => o != s).SelectMany(o => o.Values).Where(v => !isAddress || !IsBogus(v)))
                    : refValues;
                if (reference.Count > 0 && !Overlaps(s.Values, reference, isAddress))
                {
                    s.Verdict = CompareVerdict.Differs;
                    s.Note = "answers differ from the encrypted resolvers (a CDN's other servers, a proxy DNS, or tampering)";
                    continue;
                }
            }
            else if (encWithValues == 0 && encNx > 0 && s.Values.Count > 0 && !s.Spec.IsEncrypted)
            {
                // encrypted resolvers say the name doesn't exist; this one invents addresses for it
                s.Verdict = CompareVerdict.Differs;
                s.Note = "answers a name the encrypted resolvers say doesn't exist";
                continue;
            }

            if (s.Successes < s.Attempts)
            {
                s.Verdict = CompareVerdict.Unstable;
                s.Note = $"answered {s.Successes} of {s.Attempts} tries" + (s.LastShortError != null ? $" ({s.LastShortError})" : "");
                continue;
            }
            s.Verdict = CompareVerdict.Ok;
            s.Note = encrypted.Count == 0 && !s.Spec.IsEncrypted
                ? "answered; not cross-checked (no encrypted resolver answered)"
                : s.Spec.IsEncrypted ? "encrypted — answers can't be rewritten on the way" : "answers match the encrypted resolvers";
        }

        var best = stats.Where(s => s.Trustworthy && s.Median != null).OrderBy(s => s.Median).FirstOrDefault();
        if (best != null) best.IsBest = true;
    }

    /// <summary>One sentence for the top of the results: the fastest trustworthy resolver (and the fastest encrypted
    /// one when that isn't it), or why there is none.</summary>
    public static string Recommendation(IReadOnlyList<CompareStats> stats)
    {
        if (stats.Count == 0) return "";
        var best = stats.FirstOrDefault(s => s.IsBest);
        if (best == null)
        {
            if (stats.All(s => s.Successes == 0))
            {
                var reasons = stats.GroupBy(s => s.LastShortError ?? "no answer")
                    .OrderByDescending(g => g.Count()).Select(g => $"{g.Key} ×{g.Count()}");
                return "No resolver answered — check the connection (" + string.Join(", ", reasons) + ").";
            }
            return "No resolver answered every round with trustworthy answers — see the flags below.";
        }
        string text = $"Fastest trustworthy: {Name(best)} — {Ms(best.Median)} median, {best.Successes}/{best.Attempts} answered.";
        if (!best.Spec.IsEncrypted)
        {
            var enc = stats.Where(s => s.Trustworthy && s.Spec.IsEncrypted && s.Median != null).OrderBy(s => s.Median).FirstOrDefault();
            text += enc != null
                ? $" Fastest encrypted: {Name(enc)} — {Ms(enc.Median)}."
                : stats.Any(s => s.Spec.IsEncrypted && s.Successes > 0) ? " No encrypted resolver passed." : "";
        }
        if (!stats.Any(s => s.Spec.IsEncrypted && s.Successes > 0) && stats.Any(s => !s.Spec.IsEncrypted))
            text += " No encrypted resolver answered, so plain answers couldn't be checked for tampering.";
        return text;
    }

    public static string Name(CompareStats s)
        => s.Spec.Label == s.Spec.Short ? $"{s.Spec.Short} ({s.Spec.TransportLabel})" : $"{s.Spec.Label} {s.Spec.TransportLabel} ({s.Spec.Short})";

    public static string Ms(double? ms) => ms is not { } v ? "—" : v < 10 ? $"{v:0.0} ms" : $"{v:0} ms";

    /// <summary>A value as compared: addresses in canonical form, names lower-case without the trailing dot.</summary>
    public static string Normalize(string value, string type)
    {
        string v = value.Trim();
        if (type is "A" or "AAAA" && IPAddress.TryParse(v, out var ip)) return ip.ToString();
        return v.TrimEnd('.').ToLowerInvariant();
    }

    // shares a value; or (addresses) shares a /24 (IPv4) or /48 (IPv6) — a CDN rotating within its block is agreement
    private static bool Overlaps(List<string> values, HashSet<string> reference, bool isAddress)
    {
        if (values.Any(reference.Contains)) return true;
        if (!isAddress) return false;
        var nets = new HashSet<string>(reference.Select(Prefix).Where(p => p != null)!);
        return values.Select(Prefix).Any(p => p != null && nets.Contains(p));
    }

    private static string? Prefix(string addr)
    {
        if (!IPAddress.TryParse(addr, out var ip)) return null;
        byte[] b = ip.GetAddressBytes();
        return b.Length == 4 ? $"{b[0]}.{b[1]}.{b[2]}" : Convert.ToHexString(b, 0, 6);
    }

    /// <summary>Iran's national filtering redirect range (10.10.34.0/24): a censored name resolves there.</summary>
    public static bool IsCensorAddress(string addr)
        => IPAddress.TryParse(addr, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork
           && ip.GetAddressBytes() is [10, 10, 34, _];

    /// <summary>An address no public name should resolve to: unspecified, loopback, private, link-local, CGNAT, multicast,
    /// reserved, the IPv6 equivalents (ULA, link-local, documentation).</summary>
    public static bool IsBogus(string addr)
    {
        if (!IPAddress.TryParse(addr, out var ip)) return false;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        byte[] b = ip.GetAddressBytes();
        if (b.Length == 4)
        {
            return b[0] == 0 || b[0] == 10 || b[0] == 127
                   || (b[0] == 100 && b[1] >= 64 && b[1] <= 127)      // 100.64/10 CGNAT
                   || (b[0] == 169 && b[1] == 254)
                   || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                   || (b[0] == 192 && b[1] == 168)
                   || (b[0] == 192 && b[1] == 0 && b[2] == 2)          // TEST-NET-1
                   || (b[0] == 198 && (b[1] == 18 || b[1] == 19))      // benchmarking
                   || b[0] >= 224;                                     // multicast + reserved
        }
        if (ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.IPv6Loopback)) return true;
        return (b[0] & 0xFE) == 0xFC                                   // fc00::/7 ULA
               || (b[0] == 0xFE && (b[1] & 0xC0) == 0x80)              // fe80::/10
               || b[0] == 0xFF                                         // multicast
               || (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8);   // 2001:db8::/32
    }

    /// <summary>The whole comparison as text (Copy).</summary>
    public static string Report(string name, string type, IReadOnlyList<CompareStats> stats)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"Compare resolvers: {name} {type}, {Rounds} rounds — {DateTime.Now.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)}");
        string rec = Recommendation(stats);
        if (rec.Length > 0) sb.AppendLine(rec);
        sb.AppendLine();
        foreach (var s in Sorted(stats))
        {
            sb.Append(s.IsBest ? "* " : "  ");
            sb.Append($"{s.Spec.Text,-44} {s.Spec.TransportLabel,-6} {Ms(s.Median),9}  {s.Successes}/{s.Attempts}  {VerdictText(s.Verdict),-9}");
            if (s.Values.Count > 0) sb.Append("  ").Append(string.Join(", ", s.Values.Take(6).Select(v => RemoteText.Clean(v, 200)))).Append(s.Values.Count > 6 ? " …" : "");
            else if (s.SawNxDomain) sb.Append("  NXDOMAIN");
            sb.AppendLine();
            if (s.Verdict is not (CompareVerdict.Ok or CompareVerdict.Pending)) sb.AppendLine("      " + RemoteText.Clean(s.Note, 400));
        }
        return sb.ToString();
    }

    /// <summary>Fastest first; resolvers without a time at the end.</summary>
    public static IEnumerable<CompareStats> Sorted(IEnumerable<CompareStats> stats)
        => stats.OrderBy(s => s.Median == null ? 1 : 0).ThenBy(s => s.Median ?? double.MaxValue);

    public static string VerdictText(CompareVerdict v) => v switch
    {
        CompareVerdict.Ok => "ok",
        CompareVerdict.Unstable => "unstable",
        CompareVerdict.Differs => "differs",
        CompareVerdict.Filtered => "filtered",
        CompareVerdict.Tampered => "tampered",
        CompareVerdict.Failed => "failed",
        _ => "…",
    };
}
