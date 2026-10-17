using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;

namespace Echoes.Helpers;

/// <summary>Where a node's check stands. Warning: an answer that isn't clean (packet loss, an HTTP error status, a UDP port
/// that stayed silent); Stopped: the user stopped the run before the node reported.</summary>
public enum CheckHostState { Pending, Ok, Warning, Failed, Stopped }

/// <summary>One ping reply: "OK", "TIMEOUT" or "MALFORMED", and its round trip (ms).</summary>
public readonly record struct CheckHostReply(string Status, double? Ms)
{
    public bool IsOk => Status == "OK";
}

/// <summary>
/// A node's result, read from check-host.net's /check-result payload. The formats (https://check-host.net/about/api):
/// <list type="bullet">
/// <item>ping: <c>[[["OK", 0.044, "94.242.206.94"], ["TIMEOUT", 3.005], ["MALFORMED", 0.045], ["OK", 0.0433]]]</c>;
/// <c>[[null]]</c> = the node couldn't resolve the name</item>
/// <item>HTTP: <c>[[1, 0.13, "OK", "200", "94.242.206.94"]]</c>, <c>[[0, 0.17, "Not Found", "404", "…"]]</c>,
/// <c>[[0, 0.07, "No such device or address", null, null]]</c></item>
/// <item>TCP: <c>[{"time": 0.03, "address": "…"}]</c> or <c>[{"error": "Connection timed out"}]</c></item>
/// <item>UDP: <c>[{"time": …, "address": …}]</c>, <c>[{"timeout": 1, "address": …}]</c> (no reply) or an error</item>
/// <item>DNS: <c>[{"A": ["…"], "AAAA": ["…"], "TTL": 299}]</c>; empty lists = not resolved</item>
/// </list>
/// A node that is still working is <c>null</c>. Times are seconds in the API and milliseconds here.
/// </summary>
public sealed class CheckHostResult
{
    public CheckHostKind Kind { get; init; }
    public CheckHostState State { get; init; }
    /// <summary>The node got an answer from the target (a ping reply, an HTTP status, a TCP connect, a UDP reply, DNS records).</summary>
    public bool Reached { get; init; }
    /// <summary>The figure the node is ranked by: the ping average, the HTTP response time, the TCP / UDP connect time.</summary>
    public double? LatencyMs { get; init; }
    /// <summary>The address the node resolved the target to.</summary>
    public string Address { get; init; } = "";
    /// <summary>The short verdict: "4/4", "200 OK", "Connected", "No reply", "2 records", "Timeout", "Unresolved".</summary>
    public string Status { get; init; } = "";
    /// <summary>The node's own error text ("Connection timed out"), or why there is no result.</summary>
    public string Error { get; init; } = "";
    /// <summary>The node's entry as check-host.net sent it.</summary>
    public string Raw { get; init; } = "";

    // ping
    public IReadOnlyList<CheckHostReply> Replies { get; init; } = Array.Empty<CheckHostReply>();
    public int Sent { get; init; }
    public int Received { get; init; }
    public double? LossPercent { get; init; }
    public double? MinMs { get; init; }
    public double? AvgMs { get; init; }
    public double? MaxMs { get; init; }
    /// <summary>Mean difference between consecutive replies.</summary>
    public double? JitterMs { get; init; }

    // HTTP
    public int? HttpCode { get; init; }
    public string HttpReason { get; init; } = "";

    // UDP: the port stayed silent (open or filtered — UDP can't tell)
    public bool NoReply { get; init; }

    // DNS: every record list the node returned (A, AAAA, …) and the TTL
    public IReadOnlyList<KeyValuePair<string, string[]>> Records { get; init; } = Array.Empty<KeyValuePair<string, string[]>>();
    public long? Ttl { get; init; }
    public int RecordCount => Records.Sum(r => r.Value.Length);

    /// <summary>The DNS answer without its TTL, so nodes that agree compare equal ("" when there are no records).</summary>
    public string AnswerKey => string.Join(" | ", Records.Where(r => r.Value.Length > 0)
        .OrderBy(r => r.Key, StringComparer.Ordinal)
        .Select(r => r.Key + " " + string.Join(",", r.Value.OrderBy(v => v, StringComparer.OrdinalIgnoreCase))));

    /// <summary>The node's result, or null while it is still working.</summary>
    public static CheckHostResult? Parse(CheckHostKind kind, JsonElement value)
    {
        if (value.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined) return null;
        string raw = value.GetRawText();
        if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() == 0) return null;
        var p = value[0];
        if (p.ValueKind is JsonValueKind.Null) return null;
        try
        {
            return kind switch
            {
                CheckHostKind.Ping => Ping(p, raw),
                CheckHostKind.Http => Http(p, raw),
                CheckHostKind.Tcp => Tcp(p, raw),
                CheckHostKind.Udp => Udp(p, raw),
                _ => Dns(p, raw),
            } ?? Unreadable(kind, raw);
        }
        catch (Exception ex) when (ex is InvalidOperationException or FormatException or JsonException or IndexOutOfRangeException)
        {
            return Unreadable(kind, raw);
        }
    }

    /// <summary>A node that never reported before the run's time limit.</summary>
    public static CheckHostResult NoResult(CheckHostKind kind, TimeSpan waited) => new()
    {
        Kind = kind,
        State = CheckHostState.Failed,
        Status = "No result",
        Error = $"The node didn't report a result within {Math.Round(waited.TotalSeconds)} s.",
    };

    private static CheckHostResult Unreadable(CheckHostKind kind, string raw) => new()
    {
        Kind = kind,
        State = CheckHostState.Failed,
        Status = "Bad data",
        Error = "check-host.net sent a result this version can't read (see the raw value).",
        Raw = raw,
    };

    private static double? Seconds(JsonElement e) =>
        e.ValueKind == JsonValueKind.Number && e.TryGetDouble(out double s) && double.IsFinite(s) && s >= 0 ? s * 1000 : null;

    private static string Str(JsonElement e) => e.ValueKind == JsonValueKind.String ? (e.GetString() ?? "").Trim() : "";

    private static CheckHostResult? Ping(JsonElement p, string raw)
    {
        if (p.ValueKind != JsonValueKind.Array) return null;
        // [[null]]: the node couldn't resolve the host name
        if (p.GetArrayLength() == 0 || p[0].ValueKind == JsonValueKind.Null)
            return new CheckHostResult
            {
                Kind = CheckHostKind.Ping, State = CheckHostState.Failed, Status = "Unresolved", Raw = raw,
                Error = "The node couldn't resolve the host name.",
            };

        var replies = new List<CheckHostReply>(p.GetArrayLength());
        string address = "";
        foreach (var r in p.EnumerateArray())
        {
            if (r.ValueKind != JsonValueKind.Array || r.GetArrayLength() == 0) { replies.Add(new CheckHostReply("NO DATA", null)); continue; }
            string status = Str(r[0]).ToUpperInvariant();
            if (status.Length == 0) status = "NO DATA";
            double? ms = r.GetArrayLength() > 1 ? Seconds(r[1]) : null;
            if (address.Length == 0 && r.GetArrayLength() > 2) address = Str(r[2]);
            replies.Add(new CheckHostReply(status, ms));
        }
        var ok = replies.Where(r => r.IsOk && r.Ms is not null).Select(r => r.Ms!.Value).ToList();
        int sent = replies.Count, received = replies.Count(r => r.IsOk);
        double? jitter = null;
        if (ok.Count >= 2)
        {
            double sum = 0;
            for (int i = 1; i < ok.Count; i++) sum += Math.Abs(ok[i] - ok[i - 1]);
            jitter = sum / (ok.Count - 1);
        }
        bool malformed = replies.Any(r => r.Status == "MALFORMED");
        var state = received == sent ? CheckHostState.Ok
            : received > 0 || malformed ? CheckHostState.Warning
            : CheckHostState.Failed;
        string statusText = received > 0 ? $"{received}/{sent}"
            : malformed ? "Malformed"
            : replies.All(r => r.Status == "TIMEOUT") ? "Timeout"
            : $"0/{sent}";
        string error = received == sent ? ""
            : received == 0 && malformed ? "Only malformed replies came back."
            : received == 0 ? "No reply to any ping."
            : "";
        return new CheckHostResult
        {
            Kind = CheckHostKind.Ping,
            State = state,
            Reached = received > 0 || malformed,
            LatencyMs = ok.Count > 0 ? ok.Average() : null,
            Address = address,
            Status = statusText,
            Error = error,
            Raw = raw,
            Replies = replies,
            Sent = sent,
            Received = received,
            LossPercent = sent > 0 ? 100.0 * (sent - received) / sent : null,
            MinMs = ok.Count > 0 ? ok.Min() : null,
            AvgMs = ok.Count > 0 ? ok.Average() : null,
            MaxMs = ok.Count > 0 ? ok.Max() : null,
            JitterMs = jitter,
        };
    }

    private static CheckHostResult? Http(JsonElement p, string raw)
    {
        if (p.ValueKind != JsonValueKind.Array || p.GetArrayLength() == 0) return null;
        int n = p.GetArrayLength();
        bool success = p[0].ValueKind switch
        {
            JsonValueKind.Number => p[0].TryGetInt32(out int s) && s == 1,
            JsonValueKind.True => true,
            _ => false,
        };
        double? ms = n > 1 ? Seconds(p[1]) : null;
        string message = n > 2 ? Str(p[2]) : "";
        int? code = null;
        if (n > 3)
        {
            if (p[3].ValueKind == JsonValueKind.String && int.TryParse(Str(p[3]), NumberStyles.None, CultureInfo.InvariantCulture, out int c)) code = c;
            else if (p[3].ValueKind == JsonValueKind.Number && p[3].TryGetInt32(out int c2)) code = c2;
        }
        string address = n > 4 ? Str(p[4]) : "";
        if (code is not null)
        {
            string head = message.Length > 0 ? $"{code} {message}" : code.Value.ToString(CultureInfo.InvariantCulture);
            var state = success ? CheckHostState.Ok : code >= 500 ? CheckHostState.Failed : CheckHostState.Warning;
            return new CheckHostResult
            {
                Kind = CheckHostKind.Http, State = state, Reached = true, LatencyMs = ms, Address = address, Raw = raw,
                Status = head, HttpCode = code, HttpReason = message,
                Error = success ? "" : $"The server answered {head}.",
            };
        }
        if (success)   // a success without a status code (not seen in practice): still a working answer
            return new CheckHostResult
            {
                Kind = CheckHostKind.Http, State = CheckHostState.Ok, Reached = true, LatencyMs = ms, Address = address, Raw = raw,
                Status = message.Length > 0 ? message : "OK", HttpReason = message,
            };
        // no HTTP answer at all: a network error, in the node's words
        return new CheckHostResult
        {
            Kind = CheckHostKind.Http, State = CheckHostState.Failed, LatencyMs = null, Address = address, Raw = raw,
            Status = ShortError(message), Error = message.Length > 0 ? message : "The request failed.",
        };
    }

    private static CheckHostResult? Tcp(JsonElement p, string raw)
    {
        if (p.ValueKind != JsonValueKind.Object) return null;
        string address = p.TryGetProperty("address", out var a) ? Str(a) : "";
        if (p.TryGetProperty("error", out var err) && err.ValueKind != JsonValueKind.Null)
        {
            string e = err.ValueKind == JsonValueKind.String ? Str(err) : err.GetRawText();
            return new CheckHostResult
            {
                Kind = CheckHostKind.Tcp, State = CheckHostState.Failed, Address = address, Raw = raw,
                Status = ShortError(e), Error = e.Length > 0 ? e : "The connection failed.",
            };
        }
        if (p.TryGetProperty("time", out var t) && Seconds(t) is double ms)
            return new CheckHostResult
            {
                Kind = CheckHostKind.Tcp, State = CheckHostState.Ok, Reached = true, LatencyMs = ms, Address = address, Raw = raw,
                Status = "Connected",
            };
        return null;
    }

    private static CheckHostResult? Udp(JsonElement p, string raw)
    {
        if (p.ValueKind != JsonValueKind.Object) return null;
        string address = p.TryGetProperty("address", out var a) ? Str(a) : "";
        if (p.TryGetProperty("error", out var err) && err.ValueKind != JsonValueKind.Null)
        {
            string e = err.ValueKind == JsonValueKind.String ? Str(err) : err.GetRawText();
            return new CheckHostResult
            {
                Kind = CheckHostKind.Udp, State = CheckHostState.Failed, Address = address, Raw = raw,
                Status = ShortError(e), Error = e.Length > 0 ? e : "The check failed.",
            };
        }
        if (p.TryGetProperty("time", out var t) && Seconds(t) is double ms)
            return new CheckHostResult
            {
                Kind = CheckHostKind.Udp, State = CheckHostState.Ok, Reached = true, LatencyMs = ms, Address = address, Raw = raw,
                Status = "Replied",
            };
        if (p.TryGetProperty("timeout", out var to) && to.ValueKind is not (JsonValueKind.Null or JsonValueKind.False))
            return new CheckHostResult
            {
                Kind = CheckHostKind.Udp, State = CheckHostState.Warning, Address = address, Raw = raw, NoReply = true,
                Status = "No reply", Error = "No UDP reply — the port is open or filtered (a silent UDP service and a firewall look the same).",
            };
        return null;
    }

    private static CheckHostResult? Dns(JsonElement p, string raw)
    {
        if (p.ValueKind != JsonValueKind.Object) return null;
        var records = new List<KeyValuePair<string, string[]>>();
        long? ttl = null;
        foreach (var prop in p.EnumerateObject())
        {
            if (string.Equals(prop.Name, "TTL", StringComparison.OrdinalIgnoreCase))
            {
                if (prop.Value.ValueKind == JsonValueKind.Number && prop.Value.TryGetInt64(out long t)) ttl = t;
                continue;
            }
            if (prop.Value.ValueKind == JsonValueKind.Array)
            {
                var values = prop.Value.EnumerateArray()
                    .Select(v => v.ValueKind == JsonValueKind.String ? (v.GetString() ?? "").Trim() : v.ValueKind is JsonValueKind.Null ? "" : v.GetRawText())
                    .Where(v => v.Length > 0).ToArray();
                records.Add(new KeyValuePair<string, string[]>(prop.Name, values));
            }
            else if (prop.Value.ValueKind == JsonValueKind.String && Str(prop.Value) is { Length: > 0 } single)
                records.Add(new KeyValuePair<string, string[]>(prop.Name, new[] { single }));
        }
        // A and AAAA first (as the site shows them), then any other type in the API's order
        records = records.OrderBy(r => r.Key switch { "A" => 0, "AAAA" => 1, _ => 2 }).ToList();
        int count = records.Sum(r => r.Value.Length);
        if (count == 0)
            return new CheckHostResult
            {
                Kind = CheckHostKind.Dns, State = CheckHostState.Failed, Raw = raw, Records = records, Ttl = ttl,
                Status = "Unresolved", Error = "The node's resolver returned no records for this name.",
            };
        string first = records.FirstOrDefault(r => r.Key is "A" or "AAAA" && r.Value.Length > 0).Value?.FirstOrDefault() ?? "";
        return new CheckHostResult
        {
            Kind = CheckHostKind.Dns, State = CheckHostState.Ok, Reached = true, Raw = raw, Records = records, Ttl = ttl,
            Address = first, Status = count == 1 ? "1 record" : $"{count} records",
        };
    }

    /// <summary>A node's error message as a one- or two-word verdict for the result pill.</summary>
    public static string ShortError(string message)
    {
        bool Has(string s) => message.Contains(s, StringComparison.OrdinalIgnoreCase);
        if (message.Length == 0) return "Failed";
        if (Has("timed out") || Has("timeout")) return "Timeout";
        if (Has("refused")) return "Refused";
        if (Has("No such device or address") || Has("not known") || Has("Unknown host") || Has("nodename nor servname")
            || Has("No address associated") || Has("name resolution") || Has("resolve") || Has("NXDOMAIN"))
            return "Unresolved";
        if (Has("unreachable") || Has("No route")) return "Unreachable";
        if (Has("reset")) return "Reset";
        if (Has("certificate") || Has("SSL") || Has("TLS")) return "TLS error";
        if (Has("redirect")) return "Redirects";
        return "Failed";
    }
}

/// <summary>A node of a run with its result so far.</summary>
public sealed class CheckHostEntry
{
    public CheckHostEntry(CheckHostNode node, CheckHostKind kind)
    {
        Node = node;
        Kind = kind;
    }

    public CheckHostNode Node { get; }
    public CheckHostKind Kind { get; }
    public CheckHostResult? Result { get; private set; }
    private bool _stopped;

    public CheckHostState State => Result?.State ?? (_stopped ? CheckHostState.Stopped : CheckHostState.Pending);
    public bool IsFinal => Result is not null || _stopped;
    public double? LatencyMs => Result?.LatencyMs;

    public void SetResult(CheckHostResult result)
    {
        Result = result;
        _stopped = false;
    }

    /// <summary>The run was stopped before this node reported.</summary>
    public void MarkStopped()
    {
        if (Result is null) _stopped = true;
    }
}

/// <summary>The figures over all nodes of a run: counts, latency spread, fastest / slowest, coverage, DNS agreement.</summary>
public sealed class CheckHostSummary
{
    public int Total { get; private init; }
    public int Ok { get; private init; }
    public int Warning { get; private init; }
    public int Failed { get; private init; }
    public int Pending { get; private init; }
    public int Stopped { get; private init; }
    /// <summary>Nodes that got an answer from the target.</summary>
    public int Reached { get; private init; }
    /// <summary>Nodes with a final result (not pending, not stopped).</summary>
    public int Reported => Ok + Warning + Failed;

    public double? MinMs { get; private init; }
    public double? AvgMs { get; private init; }
    public double? MedianMs { get; private init; }
    public double? MaxMs { get; private init; }
    public CheckHostEntry? Fastest { get; private init; }
    public CheckHostEntry? Slowest { get; private init; }

    public int Countries { get; private init; }
    public IReadOnlyList<string> Regions { get; private init; } = Array.Empty<string>();

    /// <summary>Ping: the share of all pings sent that got no OK reply.</summary>
    public double? LossPercent { get; private init; }

    /// <summary>DNS: how many different answers the nodes got (TTL aside); 1 = they all agree.</summary>
    public int AnswerSets { get; private init; }
    /// <summary>DNS: the answer most nodes got, when they don't all agree and one answer is clearly the most common (null on a
    /// tie): the others are marked as different — a geo-DNS split, a stale cache or a resolver that rewrites answers.</summary>
    public string? MajorityAnswer { get; private init; }
    public long? TtlMin { get; private init; }
    public long? TtlMax { get; private init; }
    /// <summary>DNS: the record types seen with how many distinct values each ("A 1 · AAAA 1").</summary>
    public IReadOnlyList<KeyValuePair<string, int>> RecordTypes { get; private init; } = Array.Empty<KeyValuePair<string, int>>();

    public static CheckHostSummary Compute(IReadOnlyCollection<CheckHostEntry> entries)
    {
        int ok = 0, warn = 0, fail = 0, pending = 0, stopped = 0, reached = 0, sent = 0, received = 0;
        var timed = new List<CheckHostEntry>();
        var answers = new Dictionary<string, int>(StringComparer.Ordinal);
        var types = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        var typeOrder = new List<string>();
        long? ttlMin = null, ttlMax = null;
        foreach (var e in entries)
        {
            switch (e.State)
            {
                case CheckHostState.Ok: ok++; break;
                case CheckHostState.Warning: warn++; break;
                case CheckHostState.Failed: fail++; break;
                case CheckHostState.Stopped: stopped++; break;
                default: pending++; break;
            }
            if (e.Result is not { } r) continue;
            if (r.Reached) reached++;
            if (r.LatencyMs is not null) timed.Add(e);
            if (r.Kind == CheckHostKind.Ping) { sent += r.Sent; received += r.Received; }
            if (r.Kind == CheckHostKind.Dns)
            {
                if (r.AnswerKey is { Length: > 0 } key) answers[key] = answers.GetValueOrDefault(key) + 1;
                if (r.Ttl is long t && r.RecordCount > 0)
                {
                    ttlMin = ttlMin is null ? t : Math.Min(ttlMin.Value, t);
                    ttlMax = ttlMax is null ? t : Math.Max(ttlMax.Value, t);
                }
                foreach (var rec in r.Records)
                {
                    if (rec.Value.Length == 0) continue;
                    if (!types.TryGetValue(rec.Key, out var set)) { types[rec.Key] = set = new HashSet<string>(StringComparer.OrdinalIgnoreCase); typeOrder.Add(rec.Key); }
                    foreach (var v in rec.Value) set.Add(v);
                }
            }
        }
        // fastest / slowest: ties go to the node listed first in a stable (location) order
        var byLatency = timed.OrderBy(e => e.LatencyMs!.Value).ThenBy(e => e.Node.Id, StringComparer.Ordinal).ToList();
        double? median = null;
        if (byLatency.Count > 0)
        {
            int mid = byLatency.Count / 2;
            median = byLatency.Count % 2 == 1 ? byLatency[mid].LatencyMs : (byLatency[mid - 1].LatencyMs + byLatency[mid].LatencyMs) / 2;
        }
        var regions = entries.Select(e => e.Node.Region).Distinct().OrderBy(CheckHostRegions.Rank).ToList();
        // the most common DNS answer — only when it clearly is one (two answers seen by two nodes each name no majority)
        var byCount = answers.OrderByDescending(a => a.Value).ToList();
        string? majority = byCount.Count > 1 && byCount[0].Value > byCount[1].Value ? byCount[0].Key : null;
        return new CheckHostSummary
        {
            Total = entries.Count,
            Ok = ok,
            Warning = warn,
            Failed = fail,
            Pending = pending,
            Stopped = stopped,
            Reached = reached,
            MinMs = byLatency.Count > 0 ? byLatency[0].LatencyMs : null,
            MaxMs = byLatency.Count > 0 ? byLatency[^1].LatencyMs : null,
            AvgMs = byLatency.Count > 0 ? byLatency.Average(e => e.LatencyMs!.Value) : null,
            MedianMs = median,
            Fastest = byLatency.Count > 0 ? byLatency[0] : null,
            Slowest = byLatency.Count > 1 ? byLatency[^1] : null,
            Countries = entries.Select(e => e.Node.CountryCode.Length > 0 ? e.Node.CountryCode : e.Node.Country).Where(c => c.Length > 0)
                               .Distinct(StringComparer.OrdinalIgnoreCase).Count(),
            Regions = regions,
            LossPercent = sent > 0 ? 100.0 * (sent - received) / sent : null,
            AnswerSets = answers.Count,
            MajorityAnswer = majority,
            TtlMin = ttlMin,
            TtlMax = ttlMax,
            RecordTypes = typeOrder.OrderBy(t => t switch { "A" => 0, "AAAA" => 1, _ => 2 })
                                   .Select(t => new KeyValuePair<string, int>(t, types[t].Count)).ToList(),
        };
    }
}

/// <summary>How the node list is ordered.</summary>
public enum CheckHostSort
{
    /// <summary>Grouped by region, then country and city (the default: reads like a map).</summary>
    Region,
    Country,
    Fastest,
    Slowest,
    /// <summary>Failures first, then warnings, then the rest (slowest first within each).</summary>
    Status,
    Node,
}

public static class CheckHostOrder
{
    public static readonly CheckHostSort[] All = { CheckHostSort.Region, CheckHostSort.Country, CheckHostSort.Fastest, CheckHostSort.Slowest, CheckHostSort.Status, CheckHostSort.Node };

    /// <summary>What the sort box says (closed, it must read as an order, not as a region filter).</summary>
    public static string Label(this CheckHostSort sort) => sort switch
    {
        CheckHostSort.Country => "Sort by country",
        CheckHostSort.Fastest => "Fastest first",
        CheckHostSort.Slowest => "Slowest first",
        CheckHostSort.Status => "Failures first",
        CheckHostSort.Node => "Sort by node",
        _ => "Group by region",
    };

    public static string Key(this CheckHostSort sort) => sort.ToString().ToLowerInvariant();

    public static bool TryParse(string? key, out CheckHostSort sort)
    {
        foreach (var s in All)
            if (string.Equals(s.Key(), key, StringComparison.OrdinalIgnoreCase)) { sort = s; return true; }
        sort = CheckHostSort.Region;
        return false;
    }

    public static IComparer<CheckHostEntry> Comparer(CheckHostSort sort) => new Cmp(sort);

    private static int Location(CheckHostEntry a, CheckHostEntry b)
    {
        int c = string.Compare(a.Node.Country, b.Node.Country, StringComparison.OrdinalIgnoreCase);
        if (c == 0) c = string.Compare(a.Node.City, b.Node.City, StringComparison.OrdinalIgnoreCase);
        if (c == 0) c = CheckHostNode.CompareIds(a.Node.Id, b.Node.Id);
        return c;
    }

    // failures first: failed, warning, ok, then nodes without a result
    private static int StatusRank(CheckHostState s) => s switch
    {
        CheckHostState.Failed => 0,
        CheckHostState.Warning => 1,
        CheckHostState.Ok => 2,
        CheckHostState.Stopped => 3,
        _ => 4,
    };

    private sealed class Cmp(CheckHostSort sort) : IComparer<CheckHostEntry>
    {
        public int Compare(CheckHostEntry? a, CheckHostEntry? b)
        {
            if (ReferenceEquals(a, b)) return 0;
            if (a is null) return -1;
            if (b is null) return 1;
            int c;
            switch (sort)
            {
                case CheckHostSort.Region:
                    c = CheckHostRegions.Rank(a.Node.Region).CompareTo(CheckHostRegions.Rank(b.Node.Region));
                    return c != 0 ? c : Location(a, b);
                case CheckHostSort.Fastest:
                case CheckHostSort.Slowest:
                    // nodes without a time last, in either direction
                    if (a.LatencyMs is null || b.LatencyMs is null)
                        return a.LatencyMs is null && b.LatencyMs is null ? Location(a, b) : a.LatencyMs is null ? 1 : -1;
                    c = a.LatencyMs.Value.CompareTo(b.LatencyMs.Value);
                    if (sort == CheckHostSort.Slowest) c = -c;
                    return c != 0 ? c : Location(a, b);
                case CheckHostSort.Status:
                    c = StatusRank(a.State).CompareTo(StatusRank(b.State));
                    if (c == 0 && a.LatencyMs is double x && b.LatencyMs is double y) c = y.CompareTo(x);
                    return c != 0 ? c : Location(a, b);
                case CheckHostSort.Node:
                    return CheckHostNode.CompareIds(a.Node.Id, b.Node.Id);
                default:
                    return Location(a, b);
            }
        }
    }
}
