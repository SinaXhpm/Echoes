using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>One check-host.net node's view of the target.</summary>
public sealed record DoctorNodeView(string Place, string CountryCode, bool Reached, bool Good, int? HttpCode, string Why, string Address);

/// <summary>The outside view: the same target checked from check-host.net's nodes in other countries.</summary>
public sealed class DoctorOutsideResult
{
    /// <summary>Why the check couldn't run (check-host.net unreachable, refused, …); null when it ran.</summary>
    public string? Error { get; set; }
    public CheckHostKind Kind { get; init; }
    public string Target { get; init; } = "";
    public List<DoctorNodeView> Nodes { get; } = new();
    public int Assigned { get; set; }

    public bool Ran => Error == null && Nodes.Count > 0;
    /// <summary>Nodes that got an answer from the target (any HTTP status, a TCP connect).</summary>
    public int Reached => Nodes.Count(n => n.Reached);
    /// <summary>Nodes whose answer was a working one (HTTP 2xx / 3xx, a TCP connect).</summary>
    public int Good => Nodes.Count(n => n.Good);
    /// <summary>Most nodes can use the site.</summary>
    public bool WorksOutside => Ran && Good * 2 > Nodes.Count;
    /// <summary>No node can reach the site at all.</summary>
    public bool DownEverywhere => Ran && Reached == 0;
    /// <summary>Every node reached it, but its answers were errors (5xx).</summary>
    public bool ErrorsEverywhere => Ran && Reached > 0 && Good == 0;
}

/// <summary>Runs one check-host.net check of the target from a handful of nodes, with a short deadline.</summary>
public static class DoctorOutside
{
    public const int Nodes = 7;

    internal static CheckHostPolling Polling { get; set; } = new()
    {
        FirstDelay = TimeSpan.FromSeconds(2),
        Interval = TimeSpan.FromSeconds(1.5),
        SlowAfter = TimeSpan.FromSeconds(8),
        SlowInterval = TimeSpan.FromSeconds(2),
        Deadline = TimeSpan.FromSeconds(12),
        MaxFailures = 3,
        RateLimitBackoff = TimeSpan.FromSeconds(3),
    };

    public static async Task<DoctorOutsideResult> RunAsync(Uri? baseUri, CheckHostKind kind, string target, CancellationToken ct)
    {
        var res = new DoctorOutsideResult { Kind = kind, Target = target };
        var sink = new Sink();
        try
        {
            using var http = HttpHelper.Create(timeout: TimeSpan.FromSeconds(8));
            var client = new CheckHostClient(http, baseUri);
            await CheckHostRun.RunAsync(client, kind, target, Nodes, Array.Empty<string>(), sink, Polling, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (CheckHostException e) { if (sink.Got.Count == 0) res.Error = e.Message; }
        catch (Exception e) { if (sink.Got.Count == 0) res.Error = "check-host.net couldn't be asked: " + DoctorDns.Short(e) + "."; }

        res.Assigned = sink.Nodes.Count;
        foreach (var (id, r) in sink.Got)
        {
            sink.Nodes.TryGetValue(id, out var node);
            string place = node?.Country is { Length: > 0 } c ? c : node?.ShortId ?? CheckHostNode.Short(id);
            bool good = r.State == CheckHostState.Ok || (kind == CheckHostKind.Http && r.HttpCode is >= 200 and < 400);
            res.Nodes.Add(new DoctorNodeView(place, node?.CountryCode ?? "", r.Reached, good, r.HttpCode,
                                             r.Error.Length > 0 ? r.Error : r.Status, r.Address));
        }
        if (res.Error == null && res.Nodes.Count == 0) res.Error = "no check-host.net node reported in time.";
        return res;
    }

    /// <summary>"Germany, Finland, USA" — distinct places, at most <paramref name="max"/>.</summary>
    public static string Places(IEnumerable<DoctorNodeView> nodes, int max = 3)
    {
        var places = nodes.Select(n => n.Place).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        return places.Count <= max ? string.Join(", ", places) : string.Join(", ", places.Take(max)) + $" +{places.Count - max}";
    }

    private sealed class Sink : ICheckHostSink
    {
        public readonly Dictionary<string, CheckHostNode> Nodes = new(StringComparer.Ordinal);
        public readonly List<(string Id, CheckHostResult Result)> Got = new();

        public void Started(CheckHostStart start)
        {
            lock (this) foreach (var n in start.Nodes) Nodes[n.Id] = n;
        }

        public void Results(IReadOnlyList<KeyValuePair<string, CheckHostResult>> batch)
        {
            lock (this) foreach (var kv in batch) Got.Add((kv.Key, kv.Value));
        }

        public void PollProblem(string? problem) { }
    }
}
