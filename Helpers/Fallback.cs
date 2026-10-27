using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>
/// One answer from many sources: the web services a tool leans on, any of which can be down or blocked (on some networks
/// a different one each hour). Sources start one after another, a head start apart, so the next one is already on its way
/// while one hangs, and at once when one fails; the first good answer wins and the others are cancelled. The source that
/// answered last goes first next time (per chain, for this session). On a healthy network the first source answers
/// within its head start and nothing else is asked.
/// </summary>
public static class Fallback
{
    /// <summary>A source: its name (for the error line, and to remember who answered) and how to ask it. Fetch returns
    /// null for "nothing here" (the next source is asked) and throws for a failure (its reason is kept).</summary>
    public sealed record Source<T>(string Name, Func<CancellationToken, Task<T?>> Fetch) where T : class;

    /// <summary>The winning answer and its source, or no value and every source's reason.</summary>
    public sealed record Result<T>(T? Value, string? Source, IReadOnlyList<string> Errors) where T : class;

    private static readonly ConcurrentDictionary<string, string> s_lastGood = new();

    /// <summary>
    /// Asks <paramref name="sources"/> in order (the chain's last winner first) until one answers. Each source gets
    /// <paramref name="perSource"/> (8 s), the next starts after <paramref name="headStart"/> (1.5 s) or when one fails,
    /// and at most <paramref name="maxConcurrent"/> run at once. Never throws for a source's failure; throws
    /// <see cref="OperationCanceledException"/> when <paramref name="ct"/> is cancelled.
    /// </summary>
    public static async Task<Result<T>> FirstAsync<T>(string chain, IReadOnlyList<Source<T>> sources, CancellationToken ct,
        TimeSpan? headStart = null, TimeSpan? perSource = null, int maxConcurrent = 3) where T : class
    {
        var order = sources.ToList();
        if (s_lastGood.TryGetValue(chain, out var last) && order.FindIndex(s => s.Name == last) is > 0 and var at)
        {
            var winner = order[at];
            order.RemoveAt(at);
            order.Insert(0, winner);
        }
        TimeSpan lead = headStart ?? TimeSpan.FromSeconds(1.5);
        TimeSpan each = perSource ?? TimeSpan.FromSeconds(8);

        using var all = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var running = new List<(Task<T?> Task, Source<T> Source, CancellationTokenSource Cts)>();
        var errors = new List<string>();
        int next = 0;

        void Start(Source<T> source)
        {
            var cts = CancellationTokenSource.CreateLinkedTokenSource(all.Token);
            cts.CancelAfter(each);
            Task<T?> task;
            try { task = source.Fetch(cts.Token); }
            catch (Exception ex) { task = Task.FromException<T?>(ex); }
            // a source still running when another wins ends cancelled or failed; nobody awaits it
            _ = task.ContinueWith(static t => _ = t.Exception, CancellationToken.None,
                                  TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            running.Add((task, source, cts));
        }

        try
        {
            if (order.Count > 0) Start(order[next++]);
            while (running.Count > 0)
            {
                var waits = running.Select(r => (Task)r.Task).ToList();
                Task? turn = next < order.Count && running.Count < maxConcurrent ? Task.Delay(lead, all.Token) : null;
                if (turn != null) waits.Add(turn);
                Task done = await Task.WhenAny(waits).ConfigureAwait(false);
                ct.ThrowIfCancellationRequested();
                if (done == turn)
                {
                    Start(order[next++]);
                    continue;
                }

                var entry = running.First(r => r.Task == done);
                running.Remove(entry);
                try
                {
                    if (await entry.Task.ConfigureAwait(false) is { } value)
                    {
                        s_lastGood[chain] = entry.Source.Name;
                        return new Result<T>(value, entry.Source.Name, errors);
                    }
                    errors.Add($"{entry.Source.Name}: no answer");
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception ex) { errors.Add($"{entry.Source.Name}: {Reason(ex)}"); }
                finally { entry.Cts.Dispose(); }

                // a failure: the next source starts now rather than after its head start
                if (next < order.Count && running.Count < maxConcurrent) Start(order[next++]);
            }
            return new Result<T>(null, null, errors);
        }
        finally
        {
            // the sources still running are cancelled; their own token sources are left to them, a fetch may still be
            // unwinding with one
            all.Cancel();
        }
    }

    /// <summary>A few words for an error line: why a source didn't answer.</summary>
    public static string Reason(Exception ex)
    {
        var e = SocketErrors.Unwrap(ex);
        if (e is HttpRequestException { InnerException: { } inner } && inner is not HttpRequestException) e = SocketErrors.Unwrap(inner);
        if (e is IOException { InnerException: AuthenticationException tls }) e = tls;
        return e switch
        {
            OperationCanceledException or TimeoutException => "timed out",
            HttpRequestException { StatusCode: { } code } => $"HTTP {(int)code}",
            AuthenticationException => "TLS failed",
            SocketException { SocketErrorCode: SocketError.ConnectionRefused } => "refused",
            SocketException { SocketErrorCode: SocketError.ConnectionReset } => "connection reset",
            SocketException { SocketErrorCode: SocketError.HostNotFound or SocketError.NoData or SocketError.TryAgain } => "host unknown",
            SocketException { SocketErrorCode: SocketError.NetworkUnreachable or SocketError.HostUnreachable or SocketError.NetworkDown } => "unreachable",
            System.Text.Json.JsonException => "unreadable answer",
            InvalidDataException => e.Message,
            IOException => "connection reset",
            _ => RemoteText.Clean(e.Message.ReplaceLineEndings(" ").Trim(), 120),
        };
    }
}
