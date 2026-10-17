using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>When the results are polled. The API has no push: each poll is one small GET of every node's result so far.</summary>
public sealed class CheckHostPolling
{
    /// <summary>The wait before the first poll (most nodes answer within a second or two).</summary>
    public TimeSpan FirstDelay { get; init; } = TimeSpan.FromSeconds(1.5);
    public TimeSpan Interval { get; init; } = TimeSpan.FromSeconds(1.5);
    /// <summary>After this long, poll less often: what's left is timeouts running out (a ping waits 3 s per reply).</summary>
    public TimeSpan SlowAfter { get; init; } = TimeSpan.FromSeconds(12);
    public TimeSpan SlowInterval { get; init; } = TimeSpan.FromSeconds(3);
    /// <summary>The longest a run waits for its nodes; the ones still silent then are reported as "no result".</summary>
    public TimeSpan Deadline { get; init; } = TimeSpan.FromSeconds(40);
    /// <summary>Polls that may fail in a row (network blips) before the run gives up.</summary>
    public int MaxFailures { get; init; } = 4;
    /// <summary>The extra wait after check-host.net said "too many requests".</summary>
    public TimeSpan RateLimitBackoff { get; init; } = TimeSpan.FromSeconds(5);

    public static readonly CheckHostPolling Default = new();
}

/// <summary>Receives a run's progress. Called on a worker thread, in order; implementations only hand off.</summary>
public interface ICheckHostSink
{
    void Started(CheckHostStart start);
    /// <summary>Nodes that reported since the last batch (each node once).</summary>
    void Results(IReadOnlyList<KeyValuePair<string, CheckHostResult>> batch);
    /// <summary>A poll failed and will be retried (<paramref name="problem"/> says why), or null after a good poll.</summary>
    void PollProblem(string? problem);
}

public enum CheckHostEnd
{
    /// <summary>Every node reported.</summary>
    Complete,
    /// <summary>The time limit passed with nodes still silent.</summary>
    Deadline,
}

/// <summary>
/// One check from start to the last result: starts it, then polls /check-result until every node has reported or the
/// deadline passes. Runs on the thread pool; cancel the token to stop (an <see cref="OperationCanceledException"/> ends
/// it). Failures that end the run come out as <see cref="CheckHostException"/>.
/// </summary>
public static class CheckHostRun
{
    public static async Task<CheckHostEnd> RunAsync(CheckHostClient client, CheckHostKind kind, string target, int maxNodes,
                                                    IReadOnlyList<string> nodes, ICheckHostSink sink, CheckHostPolling polling,
                                                    CancellationToken ct)
    {
        var clock = Stopwatch.StartNew();
        var start = await client.StartAsync(kind, target, maxNodes, nodes, ct).ConfigureAwait(false);
        sink.Started(start);

        var waiting = new HashSet<string>(start.Nodes.Select(n => n.Id), StringComparer.Ordinal);
        int failures = 0;
        await Task.Delay(polling.FirstDelay, ct).ConfigureAwait(false);
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            TimeSpan wait;
            try
            {
                using var doc = await client.ResultsAsync(start.RequestId, ct).ConfigureAwait(false);
                failures = 0;
                var batch = Collect(kind, doc.RootElement, waiting);
                sink.PollProblem(null);
                if (batch.Count > 0) sink.Results(batch);
                if (waiting.Count == 0) return CheckHostEnd.Complete;
                wait = clock.Elapsed < polling.SlowAfter ? polling.Interval : polling.SlowInterval;
            }
            catch (CheckHostException ex)
            {
                // a blip: keep the results so far and try again; enough of them in a row end the run
                if (++failures >= polling.MaxFailures)
                    throw new CheckHostException("Lost contact with check-host.net while collecting results — " + Lower(ex.Message), ex, ex.RateLimited);
                sink.PollProblem(ex.Message);
                wait = ex.RateLimited ? polling.RateLimitBackoff : polling.Interval;
            }
            if (clock.Elapsed + wait > polling.Deadline)
            {
                // one last look at the deadline itself, so a node that reports in the final second still counts
                var remaining = polling.Deadline - clock.Elapsed;
                if (remaining > TimeSpan.Zero) await Task.Delay(remaining, ct).ConfigureAwait(false);
                try
                {
                    using var doc = await client.ResultsAsync(start.RequestId, ct).ConfigureAwait(false);
                    var batch = Collect(kind, doc.RootElement, waiting);
                    if (batch.Count > 0) sink.Results(batch);
                }
                catch (CheckHostException) { }
                return waiting.Count == 0 ? CheckHostEnd.Complete : CheckHostEnd.Deadline;
            }
            await Task.Delay(wait, ct).ConfigureAwait(false);
        }
    }

    /// <summary>The nodes in <paramref name="waiting"/> that have a result now (removed from it).</summary>
    public static List<KeyValuePair<string, CheckHostResult>> Collect(CheckHostKind kind, JsonElement root, HashSet<string> waiting)
    {
        var batch = new List<KeyValuePair<string, CheckHostResult>>();
        if (root.ValueKind != JsonValueKind.Object) return batch;
        foreach (var prop in root.EnumerateObject())
        {
            if (!waiting.Contains(prop.Name)) continue;
            if (CheckHostResult.Parse(kind, prop.Value) is not { } result) continue;
            waiting.Remove(prop.Name);
            batch.Add(new KeyValuePair<string, CheckHostResult>(prop.Name, result));
        }
        return batch;
    }

    private static string Lower(string s) => s.Length > 1 && char.IsUpper(s[0]) && !char.IsUpper(s[1]) ? char.ToLowerInvariant(s[0]) + s[1..] : s;
}
