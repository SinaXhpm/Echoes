using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>Tuning for an <see cref="MtrSession"/>. The defaults are mtr's own pace: one probe per hop per second, at most
/// 30 hops.</summary>
public sealed class MtrOptions
{
    public int MaxTtl { get; init; } = 30;
    public int IntervalMs { get; init; } = 1000;
    public int TimeoutMs { get; init; } = 2500;

    /// <summary>Probes in flight at once (a silent hop keeps each of its probes out for the whole timeout).</summary>
    public int MaxConcurrent { get; init; } = 32;

    /// <summary>Spacing of a round's probes, so a round is a short ramp rather than a burst (at most half the interval in all).</summary>
    public int StaggerMs { get; init; } = 25;

    /// <summary>While the destination hasn't answered: TTLs probed past the last hop that did...</summary>
    public int ProbeAhead { get; init; } = 3;

    /// <summary>...and every this many rounds a full 1..<see cref="MaxTtl"/> sweep, which finds hops behind a stretch of silent ones.</summary>
    public int SweepEvery { get; init; } = 10;

    /// <summary>Recent results kept per hop, for the row's graph.</summary>
    public int HistoryLength { get; init; } = 40;

    /// <summary>Replaces the network (tests): (target, ttl, timeoutMs, token) → result, like <see cref="IcmpPinger.SendAsync"/>.</summary>
    public Func<IPAddress, int, int, CancellationToken, Task<IcmpPinger.PingResult>>? Probe { get; init; }
}

/// <summary>One row of an MTR table at one moment.</summary>
public sealed class MtrHopSnapshot
{
    public int Ttl { get; init; }

    /// <summary>The hop's latest responder; null while it has never answered ("???").</summary>
    public IPAddress? Address { get; init; }

    /// <summary>Other addresses that answered at this TTL recently (equal-cost multipath), newest first.</summary>
    public IReadOnlyList<IPAddress> Others { get; init; } = Array.Empty<IPAddress>();

    public bool IsDestination { get; init; }

    /// <summary>Why the path ends at this hop ("Destination net unreachable"…), or null.</summary>
    public string? Error { get; init; }

    public int Sent { get; init; }
    public int Received { get; init; }
    public int Lost { get; init; }
    public int InFlight { get; init; }

    /// <summary>Lost / completed probes in percent (probes still in flight don't count yet); NaN before any completed.</summary>
    public double LossPercent { get; init; } = double.NaN;

    /// <summary>The latest answer's round trip (as mtr's Last); NaN before the first.</summary>
    public double LastMs { get; init; } = double.NaN;
    public double AvgMs { get; init; } = double.NaN;
    public double BestMs { get; init; } = double.NaN;
    public double WorstMs { get; init; } = double.NaN;
    public double StDevMs { get; init; } = double.NaN;

    /// <summary>Recent results, oldest first; NaN = no answer.</summary>
    public double[] Recent { get; init; } = Array.Empty<double>();

    /// <summary>Changes whenever any of the above does.</summary>
    public int Version { get; init; }
}

public sealed class MtrSnapshot
{
    public IPAddress Target { get; init; } = IPAddress.None;
    public IReadOnlyList<MtrHopSnapshot> Hops { get; init; } = Array.Empty<MtrHopSnapshot>();

    /// <summary>Rounds started so far.</summary>
    public int Rounds { get; init; }
    public bool DestinationReached { get; init; }

    /// <summary>The probes go out as UDP datagrams (ICMP isn't permitted here, IcmpPinger fell back).</summary>
    public bool UsesUdp { get; init; }

    /// <summary>No probe can work here (ICMP refused, the UDP fallback too): the session stopped with this error.</summary>
    public string? Fatal { get; init; }
}

/// <summary>
/// mtr: traceroute and ping combined. The first round sweeps TTL 1..30 (staggered, stopping where the destination — or a
/// router's "unreachable" — answers); then every hop up to there gets one probe per second, all in parallel (bounded),
/// each timed on its own. Probes go through <see cref="IcmpPinger.SendAsync"/>: ICMP echo, and UDP datagrams wherever
/// ICMP isn't permitted.
///
/// <para>The path is kept honest as it changes: the destination answering at a lower TTL trims the rows past it; routers
/// answering where the destination used to (a longer path) make the session probe further again; a silent destination
/// keeps a few TTLs past the last answering hop probed, plus a full sweep every <see cref="MtrOptions.SweepEvery"/>
/// rounds. Several responders at one TTL (equal-cost multipath) are all kept; the latest is the hop's address.</para>
///
/// <para>Thread-safe: probes complete on pool threads and update the hops under one lock; <see cref="Changed"/> fires
/// after each update and <see cref="Snapshot"/> copies the table out, so a UI coalesces the events and reads at its own
/// pace.</para>
/// </summary>
public sealed class MtrSession
{
    private readonly object _gate = new();
    private readonly Hop[] _hops;
    private readonly Func<IPAddress, int, int, CancellationToken, Task<IcmpPinger.PingResult>> _probe;
    private readonly HashSet<Task> _pending = new();
    private int _destTtl, _unreachTtl, _lastAnswered, _round = -1, _destMisses, _unreachMisses;
    private bool _udp;
    private string? _fatal;
    private CancellationTokenSource? _run;

    // A responder this many rounds old no longer counts as a current multipath branch.
    private const int ResponderMemoryRounds = 30;
    // Routers answering this many times in a row at the destination's TTL: the path got longer.
    private const int DestinationMissesToReprobe = 4;
    // ...and at the TTL of an "unreachable": the dead end is gone.
    private const int UnreachableMissesToReprobe = 3;

    public MtrSession(IPAddress target, MtrOptions? options = null)
    {
        Target = target;
        Options = options ?? new MtrOptions();
        int max = Math.Clamp(Options.MaxTtl, 1, 64);
        _hops = new Hop[max];
        for (int i = 0; i < max; i++) _hops[i] = new Hop(Options.HistoryLength);
        _probe = Options.Probe ?? ((addr, ttl, timeout, ct) => IcmpPinger.SendAsync(addr, timeout, ct, ttl));
    }

    public IPAddress Target { get; }
    public MtrOptions Options { get; }

    /// <summary>Raised on a pool thread after every change (a probe sent or completed, a round started). Coalesce it.</summary>
    public event Action? Changed;

    /// <summary>Probes until <paramref name="token"/> is cancelled or no probe can work here (<see cref="MtrSnapshot.Fatal"/>).
    /// Returns once every probe still in flight has ended, so a snapshot taken afterwards is final.</summary>
    public async Task RunAsync(CancellationToken token)
    {
        using var run = CancellationTokenSource.CreateLinkedTokenSource(token);
        lock (_gate) _run = run;
        var ct = run.Token;
        var slots = new SemaphoreSlim(Math.Max(1, Options.MaxConcurrent));
        try
        {
            for (int round = 0; ; round++)
            {
                long start = Stopwatch.GetTimestamp();
                int limit;
                lock (_gate)
                {
                    _round = round;
                    bool sweep = round == 0 || (Options.SweepEvery > 0 && round % Options.SweepEvery == 0 && PathEndLocked() == 0);
                    limit = sweep ? _hops.Length : ProbeLimitLocked();
                }
                Changed?.Invoke();

                double spacing = limit > 1 ? Math.Min(Options.StaggerMs, Options.IntervalMs * 0.5 / (limit - 1)) : 0;
                for (int ttl = 1; ttl <= limit; ttl++)
                {
                    if (ttl > 1)
                    {
                        // Due times are relative to the round's start, so timer granularity doesn't add up over 30 hops.
                        double due = (ttl - 1) * spacing - Stopwatch.GetElapsedTime(start).TotalMilliseconds;
                        if (due >= 1) await Task.Delay(TimeSpan.FromMilliseconds(due), ct).ConfigureAwait(false);
                        int end;
                        lock (_gate) end = PathEndLocked();
                        if (end > 0 && ttl > end) break;   // the destination (or a dead end) answered meanwhile: nothing past it
                    }
                    await slots.WaitAsync(ct).ConfigureAwait(false);
                    Track(ProbeAsync(ttl, slots, ct));
                }

                double wait = Options.IntervalMs - Stopwatch.GetElapsedTime(start).TotalMilliseconds;
                if (wait >= 1) await Task.Delay(TimeSpan.FromMilliseconds(wait), ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            try { run.Cancel(); } catch (ObjectDisposedException) { }
            Task[] pending;
            lock (_gate)
            {
                _run = null;
                pending = _pending.ToArray();
            }
            // The cancelled probes end at once (IcmpPinger honours the token); don't wait on a stuck one forever.
            try { await Task.WhenAll(pending).WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false); }
            catch (Exception) { }
        }
    }

    private void Track(Task probe)
    {
        lock (_gate)
        {
            if (probe.IsCompleted) return;
            _pending.Add(probe);
        }
        probe.ContinueWith(t => { lock (_gate) _pending.Remove(t); }, CancellationToken.None,
                           TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }

    private async Task ProbeAsync(int ttl, SemaphoreSlim slots, CancellationToken ct)
    {
        var hop = _hops[ttl - 1];
        int generation;
        lock (_gate)
        {
            generation = hop.Generation;
            hop.Sent++;
            hop.InFlight++;
            hop.Version++;
        }

        IcmpPinger.PingResult r = default;
        double rtt = 0;
        bool cancelled = false;
        try
        {
            long t0 = Stopwatch.GetTimestamp();
            r = await _probe(Target, ttl, Options.TimeoutMs, ct).ConfigureAwait(false);
            rtt = PreciseRtt(r.RoundtripMs, Stopwatch.GetElapsedTime(t0).TotalMilliseconds);
            cancelled = ct.IsCancellationRequested;   // raced the stop: counted neither way
        }
        catch (OperationCanceledException) { cancelled = true; }
        catch (Exception ex) { r = new IcmpPinger.PingResult(false, 0, null, -1, ex.Message, false); }
        finally { slots.Release(); }

        Complete(ttl, hop, generation, r, rtt, cancelled);
    }

    // IcmpPinger reports whole milliseconds (Windows' own figure for an echo reply, elsewhere a stopwatch's truncated
    // value): the true value lies in [ms, ms + 1). The wall time around the call adds only microseconds on Linux, so
    // inside that interval it is the precise figure; beyond it the call's own overhead dominates (Windows' managed Ping
    // completes through a wait thread, ~1 ms), and the interval's middle is the better estimate.
    private static double PreciseRtt(long wholeMs, double wallMs)
    {
        double whole = Math.Max(0, wholeMs);
        return wallMs >= whole && wallMs < whole + 1 ? wallMs : whole + 0.5;
    }

    private void Complete(int ttl, Hop hop, int generation, IcmpPinger.PingResult r, double rtt, bool cancelled)
    {
        bool stop = false;
        lock (_gate)
        {
            if (hop.Generation != generation) return;   // the hop was reset meanwhile (trimmed off the path)
            hop.InFlight--;
            hop.Version++;
            if (cancelled)
            {
                hop.Sent--;   // stopped mid-flight: neither an answer nor a loss
            }
            else if (r.PermissionDenied)
            {
                hop.Sent--;
                if (_fatal is null)
                {
                    _fatal = string.IsNullOrEmpty(r.Error) ? "ICMP isn't permitted here" : r.Error;
                    stop = true;
                }
            }
            else
            {
                if (r.Method == PingMethod.Udp) _udp = true;
                Classify(ttl, hop, r, rtt);
            }
        }
        // Outside the lock: Cancel runs the run loop's continuations, which take the lock themselves.
        if (stop)
        {
            CancellationTokenSource? run;
            lock (_gate) run = _run;
            try { run?.Cancel(); } catch (ObjectDisposedException) { }
        }
        Changed?.Invoke();
    }

    // Caller holds _gate.
    private void Classify(int ttl, Hop hop, IcmpPinger.PingResult r, double rtt)
    {
        if (r.Success)
        {
            // The destination itself: an echo reply, or (UDP) its "port unreachable".
            Answer(ttl, hop, r.Address ?? Target, rtt);
            hop.Error = null;
            _unreachTtl = 0;   // it's reachable: any dead end seen before is gone
            _unreachMisses = 0;
            if (_destTtl == 0 || ttl < _destTtl)
            {
                _destTtl = ttl;
                Trim(ttl);   // answering at a lower TTL than before: the rows past it are not on the path
            }
            if (ttl == _destTtl) _destMisses = 0;
        }
        else if (MtrReply.IsHop(r.Address) && MtrReply.IsTtlExpired(r.Error))
        {
            // A router's "time exceeded": the hop at this TTL.
            Answer(ttl, hop, r.Address!, rtt);
            hop.Error = null;
            // Routers keep answering where the destination did: the path got longer (or this is a longer multipath
            // branch). After a few in a row, probe past it again.
            if (ttl == _destTtl && ++_destMisses >= DestinationMissesToReprobe)
            {
                _destTtl = 0;
                _destMisses = 0;
            }
            if (ttl == _unreachTtl && ++_unreachMisses >= UnreachableMissesToReprobe)
            {
                _unreachTtl = 0;
                _unreachMisses = 0;
            }
        }
        else if (MtrReply.IsHop(r.Address) && !MtrReply.IsTimeout(r.Error))
        {
            // A router's "unreachable" (net / host / prohibited, or UDP filtered on the way): nothing past this hop
            // can answer — traceroute's !N / !H / !X. The path ends here.
            Answer(ttl, hop, r.Address!, rtt);
            hop.Error = MtrReply.Describe(r.Error);
            if (ttl == _unreachTtl) _unreachMisses = 0;
            if (_unreachTtl == 0 || ttl < _unreachTtl)
            {
                _unreachTtl = ttl;
                _unreachMisses = 0;
                Trim(PathEndLocked());
            }
        }
        else
        {
            // Timed out, or failed without anyone answering (no route right now, a local send error). Last keeps the
            // latest answer, as in mtr: the loss shows in Loss% and in the graph.
            hop.Lost++;
            hop.Push(double.NaN);
        }
    }

    // Caller holds _gate.
    private void Answer(int ttl, Hop hop, IPAddress from, double rtt)
    {
        hop.Stats.Add(rtt);
        hop.Last = rtt;
        hop.Push(rtt);
        hop.Address = from;

        Responder? known = null;
        foreach (var x in hop.Responders)
            if (x.Address.Equals(from)) { known = x; break; }
        if (known is null)
        {
            if (hop.Responders.Count >= 8)
            {
                // keep the list short: forget the longest-unheard one
                var oldest = hop.Responders[0];
                foreach (var x in hop.Responders) if (x.LastRound < oldest.LastRound) oldest = x;
                hop.Responders.Remove(oldest);
            }
            known = new Responder(from);
            hop.Responders.Add(known);
        }
        known.Count++;
        known.LastRound = Math.Max(0, _round);
        if (ttl > _lastAnswered) _lastAnswered = ttl;
    }

    // Caller holds _gate. Forget every hop past `end` (its in-flight probes are ignored when they return).
    private void Trim(int end)
    {
        if (end <= 0) return;
        for (int t = end + 1; t <= _hops.Length; t++)
        {
            var h = _hops[t - 1];
            if (h.Sent > 0 || h.Address is not null) h.Reset();
        }
        if (_lastAnswered > end) _lastAnswered = end;
    }

    // Caller holds _gate. Where the path ends: the destination's TTL, or a hop that said "unreachable" (whichever is
    // nearer); 0 = not known.
    private int PathEndLocked()
    {
        int end = _destTtl;
        if (_unreachTtl > 0 && (end == 0 || _unreachTtl < end)) end = _unreachTtl;
        return end;
    }

    private int ProbeLimitLocked()
    {
        int end = PathEndLocked();
        return end > 0 ? end : Math.Clamp(_lastAnswered + Math.Max(1, Options.ProbeAhead), 1, _hops.Length);
    }

    // Rows shown: up to the end of the path, or (destination silent) one "???" row past the last hop that answered —
    // what mtr shows.
    private int DisplayCountLocked()
    {
        int end = PathEndLocked();
        return end > 0 ? end : Math.Clamp(_lastAnswered + 1, 1, _hops.Length);
    }

    public MtrSnapshot Snapshot()
    {
        lock (_gate)
        {
            int count = DisplayCountLocked();
            var rows = new MtrHopSnapshot[count];
            for (int i = 0; i < count; i++) rows[i] = SnapshotHop(i + 1, _hops[i]);
            return new MtrSnapshot
            {
                Target = Target,
                Hops = rows,
                Rounds = _round + 1,
                DestinationReached = _destTtl > 0,
                UsesUdp = _udp,
                Fatal = _fatal,
            };
        }
    }

    // Caller holds _gate.
    private MtrHopSnapshot SnapshotHop(int ttl, Hop h)
    {
        int completed = h.Stats.Count + h.Lost;
        var others = new List<IPAddress>();
        if (h.Responders.Count > 1)
        {
            int since = _round - ResponderMemoryRounds;
            foreach (var x in h.Responders.OrderByDescending(x => x.LastRound))
                if (x.LastRound >= since && (h.Address is null || !x.Address.Equals(h.Address))) others.Add(x.Address);
        }
        bool any = h.Stats.Count > 0;
        return new MtrHopSnapshot
        {
            Ttl = ttl,
            Address = h.Address,
            Others = others,
            IsDestination = h.Address is not null && MtrReply.SameAddress(h.Address, Target),
            Error = h.Error,
            Sent = h.Sent,
            Received = h.Stats.Count,
            Lost = h.Lost,
            InFlight = h.InFlight,
            LossPercent = completed > 0 ? 100.0 * h.Lost / completed : double.NaN,
            LastMs = h.Last,
            AvgMs = any ? h.Stats.Mean : double.NaN,
            BestMs = any ? h.Stats.Best : double.NaN,
            WorstMs = any ? h.Stats.Worst : double.NaN,
            StDevMs = any ? h.Stats.StDev : double.NaN,
            Recent = h.RecentArray(),
            Version = h.Version,
        };
    }

    private sealed class Hop
    {
        public Hop(int history) => _recent = new double[Math.Max(1, history)];

        public int Generation, Version;
        public int Sent, InFlight, Lost;
        public RttStats Stats;
        public double Last = double.NaN;
        public IPAddress? Address;
        public string? Error;
        public readonly List<Responder> Responders = new();
        private readonly double[] _recent;
        private int _recentStart, _recentCount;

        public void Push(double v)
        {
            if (_recentCount < _recent.Length) _recent[(_recentStart + _recentCount++) % _recent.Length] = v;
            else
            {
                _recent[_recentStart] = v;
                _recentStart = (_recentStart + 1) % _recent.Length;
            }
        }

        public double[] RecentArray()
        {
            var a = new double[_recentCount];
            for (int i = 0; i < _recentCount; i++) a[i] = _recent[(_recentStart + i) % _recent.Length];
            return a;
        }

        public void Reset()
        {
            Generation++;
            Version++;
            Sent = InFlight = Lost = 0;
            Stats = default;
            Last = double.NaN;
            Address = null;
            Error = null;
            Responders.Clear();
            _recentStart = _recentCount = 0;
        }
    }

    private sealed class Responder(IPAddress address)
    {
        public IPAddress Address { get; } = address;
        public int Count;
        public int LastRound;
    }
}

/// <summary>How to read an <see cref="IcmpPinger.PingResult"/> that isn't a plain echo reply (the same rules the Ping tab's
/// traceroute uses).</summary>
public static class MtrReply
{
    /// <summary>A real responder, not the unspecified-address placeholder of a timeout (0.0.0.0, or :: on Windows).</summary>
    public static bool IsHop(IPAddress? a)
        => a != null && !a.Equals(IPAddress.Any) && !a.Equals(IPAddress.IPv6Any);

    /// <summary>Errors come as IcmpPinger's own text or, from the managed Ping, an IPStatus name.</summary>
    public static bool IsTimeout(string? e)
        => string.IsNullOrEmpty(e) || e == "Request timed out" || e == nameof(IPStatus.TimedOut);

    public static bool IsTtlExpired(string? e)
        => e is "TTL expired" or nameof(IPStatus.TtlExpired) or nameof(IPStatus.TimeExceeded);

    /// <summary>"DestinationHostUnreachable" (an IPStatus name) → "Destination host unreachable"; plain text stays as it is.</summary>
    public static string Describe(string? e)
    {
        if (string.IsNullOrEmpty(e)) return "No reply";
        if (IsTtlExpired(e)) return "TTL expired";
        if (e.Contains(' ') || !char.IsUpper(e[0])) return e;
        var sb = new System.Text.StringBuilder(e.Length + 8).Append(e[0]);
        for (int i = 1; i < e.Length; i++)
        {
            if (char.IsUpper(e[i])) sb.Append(' ').Append(char.ToLowerInvariant(e[i]));
            else sb.Append(e[i]);
        }
        return sb.ToString();
    }

    /// <summary>Same host, ignoring an IPv6 scope id (an ICMP error's offender address carries none).</summary>
    public static bool SameAddress(IPAddress a, IPAddress b)
        => a.AddressFamily == b.AddressFamily && a.GetAddressBytes().AsSpan().SequenceEqual(b.GetAddressBytes());
}
