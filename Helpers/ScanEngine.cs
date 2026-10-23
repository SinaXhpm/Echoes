using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>
/// The port scanner's engine: host discovery, TCP connect and UDP probes classified the way nmap does, adaptive
/// timeouts and retries, service detection, and the checks that keep the results honest — hosts that answer every
/// port, SYN-ACKs that come from a local proxy, ICMP rate limiting that would otherwise turn closed UDP ports into
/// "open|filtered". UI-agnostic: results go to an <see cref="IScanSink"/>, progress to <see cref="Progress"/>.
/// One instance per scan (Start → Stop); <see cref="RunPassAsync"/> once per pass of a repeating scan.
/// </summary>
public sealed class ScanEngine : IDisposable
{
    /// <summary>Ceiling on simultaneous probe sockets whatever the template says. A phone has a far tighter per-app fd
    /// budget; a macOS GUI app starts with 256 fds; past a few hundred on Windows/Linux more parallelism buys
    /// EMFILE / ephemeral-port errors rather than speed.</summary>
    public static int MaxParallelism => AppPlatform.IsMobile ? 128 : OperatingSystem.IsMacOS() ? 256 : 512;

    // Rows kept for the export and the final listing. Open rows are what people scan for; the bulk kinds (closed,
    // filtered, open|filtered) are capped lower — a -Pn /16 × 10 ports is ~650k of them. The per-host tallies stay exact.
    public const int MaxRetainOpen = 200_000;
    public const int MaxRetainOther = 50_000;

    private const int ControlPorts = 3;

    private readonly ScanOptions _o;
    private readonly IScanSink _sink;
    private readonly CancellationTokenSource _cts = new();
    private readonly ConcurrentDictionary<Socket, byte> _sockets = new();
    private readonly HostRtt _sweepRtt = new();       // one estimator per discovery sweep (kept across passes)
    private readonly ScanNames _names;
    private readonly List<Task> _background = new();  // accept-all checks started mid-scan (lock it)
    private readonly bool _rstTimingValid;             // see NoteRst

    // per pass
    private ConcurrentBag<PortFinding> _all = new();
    private long _retainedOpen, _retainedOther, _dropped, _sent, _unknownProbes;
    private int[] _controlPorts = Array.Empty<int>();

    public ScanEngine(ScanOptions options, IScanSink sink)
    {
        _o = options;
        _sink = sink;
        _names = new ScanNames(AppPlatform.IsMobile ? 2 : 4, h => _sink.HostChanged(h));
        // Windows retries a SYN after a RST unless retransmissions are off (the fast templates turn them off), which
        // stretches a refusal to ~1 s and would make every SYN-ACK look suspiciously fast next to it.
        _rstTimingValid = !OperatingSystem.IsWindows() || _o.Timing.Level >= 2;
    }

    public ScanProgress Progress { get; } = new();

    /// <summary>The reverse-DNS lookups; they can still be finishing after the scan ends.</summary>
    public ScanNames Names => _names;
    public CancellationToken Token => _cts.Token;

    /// <summary>Cancel and tear the sockets down. The pass in flight returns soon after, with what it has.</summary>
    public void Stop()
    {
        try { _cts.Cancel(); } catch (ObjectDisposedException) { }
        foreach (var s in _sockets.Keys) { try { s.Close(); } catch { } }
    }

    public void Dispose()
    {
        Stop();
        _cts.Dispose();
    }

    public async Task<ScanPass> RunPassAsync(IReadOnlyList<ScanHost> targets, ScanPortSpec ports)
    {
        var ct = _cts.Token;
        var clock = Stopwatch.StartNew();
        var pass = new ScanPass
        {
            StartedUtc = DateTime.UtcNow, Options = _o, Targets = targets,
            TcpPorts = ports.Tcp.Count, UdpPorts = ports.Udp.Count,
        };
        _all = new ConcurrentBag<PortFinding>();
        _retainedOpen = _retainedOther = _dropped = _sent = _unknownProbes = 0;
        foreach (var h in targets) h.BeginPass();
        Progress.ResetCounts();

        try
        {
            // ---- host discovery (skipped with -Pn) ----
            if (!_o.SkipDiscovery)
            {
                var neighborsBefore = ScanNeighbors.Snapshot();
                Progress.StartPhase(ScanProgress.Stage.Discovery, targets.Count);
                await DiscoverAsync(targets, ct).ConfigureAwait(false);
                if (!ct.IsCancellationRequested) RescueByArp(targets, neighborsBefore);
            }

            // A single target is scanned even when it seemed down — the user named it (nmap would need -Pn).
            pass.Scanned = _o.PingOnly ? new List<ScanHost>()
                : _o.SkipDiscovery || targets.Count == 1 ? targets.ToList()
                : targets.Where(h => h.Status == HostStatus.Up).ToList();

            // ---- port scan ----
            if (pass.Scanned.Count > 0 && ports.Total > 0 && !ct.IsCancellationRequested)
            {
                _controlPorts = ports.Tcp.Count > 0 ? PickControlPorts(ports.Tcp) : Array.Empty<int>();
                Progress.StartPhase(ScanProgress.Stage.Ports, (long)pass.Scanned.Count * ports.Total);
                await ScanPortsAsync(pass.Scanned, ports, ct).ConfigureAwait(false);
                Task[] checks;
                lock (_background) { checks = _background.ToArray(); _background.Clear(); }
                try { await Task.WhenAll(checks).ConfigureAwait(false); } catch { }
                if (ports.Udp.Count > 0) await SettleSilentUdpAsync(pass, ct).ConfigureAwait(false);
            }

            Progress.Phase = ScanProgress.Stage.Finishing;
            FinishHosts(pass);
            ApplyNeighbors(targets);
            await _names.WaitAsync(TimeSpan.FromMilliseconds(1500), ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { }

        pass.Stopped = ct.IsCancellationRequested;
        pass.Elapsed = clock.Elapsed;
        pass.FinishedUtc = DateTime.UtcNow;
        pass.ProbesSent = Interlocked.Read(ref _sent);
        pass.DroppedRows = Interlocked.Read(ref _dropped);
        pass.UnknownProbes = Interlocked.Read(ref _unknownProbes);
        pass.UnknownHosts = Interlocked.Read(ref Progress.HostErrors);
        pass.HostsUp = targets.Count(h => h.Status == HostStatus.Up);
        var rows = _all.ToArray();
        Array.Sort(rows, FindingOrder.Instance);
        pass.Findings = new List<PortFinding>(rows);
        pass.UbiquitousPorts = UbiquitousPorts(pass);
        return pass;
    }

    // ================================================================ discovery

    private async Task DiscoverAsync(IReadOnlyList<ScanHost> targets, CancellationToken ct)
    {
        // The ceiling: once live hosts answer, the sweep estimator brings each probe's timeout down to
        // ~SRTT + 4·RTTVAR (≥150 ms) — a dead host no longer costs the full timeout.
        int ceiling = Math.Max(500, _o.TimeoutMs);
        var options = new ParallelOptions
        {
            // Each host check fires ~6 probes at once, so the host fan-out stays below the template: 256 hosts
            // (~1,500 sockets) on desktop, 100 on a phone, where more would pass many devices' fd limit.
            MaxDegreeOfParallelism = Math.Clamp(_o.Concurrency, 1, AppPlatform.IsMobile ? 100 : 256),
            CancellationToken = ct,
        };
        bool smallSweep = targets.Count <= ScanDiscovery.LanFloorMaxHosts;   // LAN hosts then get the longer floor
        try
        {
            await Parallel.ForEachAsync(targets, options, async (h, c) =>
            {
                var st = await ScanDiscovery.DiscoverAsync(h.Address, h.Rtt, _sweepRtt, ceiling, c, smallSweep).ConfigureAwait(false);
                Interlocked.Add(ref _sent, ScanDiscovery.ProbesPerHost);
                if (!st.Up && c.IsCancellationRequested) return;   // an aborted check isn't evidence of anything
                if (st.Up) MarkUp(h, st.Reason, st.LatencyMs);
                else if (st.LocalError) { h.Status = HostStatus.Unknown; h.Reason = "socket-limit"; Interlocked.Increment(ref Progress.HostErrors); }
                else { h.Status = HostStatus.Down; h.Reason = "no-response"; }
                Interlocked.Increment(ref Progress.Done);
            }).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { }
    }

    // A LAN host can drop ICMP and every probed TCP port yet still answer ARP — and our probes just made the OS ask.
    // Proof is a neighbor entry the OS confirmed (Windows' "reachable" state) or one that appeared during this sweep;
    // a stale entry only says the host was there once (a phone that left an hour ago).
    private void RescueByArp(IReadOnlyList<ScanHost> targets, Dictionary<string, ScanNeighbors.Entry> before)
    {
        if (targets.All(h => h.Status == HostStatus.Up)) return;
        var after = ScanNeighbors.Snapshot();
        if (after.Count == 0) return;
        foreach (var h in targets)
        {
            if (h.Status == HostStatus.Up || !after.TryGetValue(h.NeighborKey, out var entry)) continue;
            if (!entry.Confirmed && before.ContainsKey(h.NeighborKey)) continue;
            MarkUp(h, "arp-response", 0);
        }
    }

    private void MarkUp(ScanHost h, string reason, double latencyMs)
    {
        h.Status = HostStatus.Up;
        h.Reason = reason;
        if (latencyMs > 0) h.LatencyMs = latencyMs;
        h.Evidence = true;
        Interlocked.Increment(ref Progress.HostsUp);
        _names.Queue(h);
        if (Interlocked.Exchange(ref h.Reported, 1) == 0) _sink.HostChanged(h);
    }

    // First answer from a host that discovery didn't vouch for (-Pn, or the single target): it's up.
    private void NoteEvidence(ScanHost h)
    {
        if (h.Evidence) return;
        h.Evidence = true;
        _names.Queue(h);
        if (Interlocked.Exchange(ref h.Reported, 1) == 0) _sink.HostChanged(h);
    }

    // ================================================================ port scan

    private async Task ScanPortsAsync(List<ScanHost> hosts, ScanPortSpec ports, CancellationToken ct)
    {
        var options = new ParallelOptions { MaxDegreeOfParallelism = _o.Concurrency, CancellationToken = ct };
        try
        {
            await Parallel.ForEachAsync(WorkItems(hosts, ports), options, async (w, c) =>
            {
                if (w.Proto == ScanProto.Tcp) await ScanTcpAsync(w.Host, w.Port, c).ConfigureAwait(false);
                else await ScanUdpAsync(w.Host, w.Port, c).ConfigureAwait(false);
            }).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { }
    }

    // Port-major order: each port across all hosts, then the next. With many hosts every host sees its probes spread
    // out instead of in one burst — gentler on per-host rate limits (ICMP errors, SYN floods) and on IDS alike.
    private static IEnumerable<(ScanHost Host, int Port, ScanProto Proto)> WorkItems(List<ScanHost> hosts, ScanPortSpec ports)
    {
        foreach (int p in ports.Tcp)
            foreach (var h in hosts) yield return (h, p, ScanProto.Tcp);
        foreach (int p in ports.Udp)
            foreach (var h in hosts) yield return (h, p, ScanProto.Udp);
    }

    // Never throws: an exception escaping a Parallel.ForEachAsync body would abort the whole scan.
    private async Task ScanTcpAsync(ScanHost h, int port, CancellationToken ct)
    {
        if (h.AcceptsAll)   // its answers mean nothing: don't spend probes on it
        {
            Interlocked.Increment(ref h.SkippedTcp);
            Interlocked.Increment(ref Progress.Done);
            return;
        }
        var r = await ProbeTcpAsync(h, port, ct).ConfigureAwait(false);
        if (r is not { } probe) return;   // stopped

        var f = new PortFinding(h, port, ScanProto.Tcp) { State = probe.State, Reason = probe.Reason, LatencyMs = probe.Ms };
        if (probe.Socket is { } socket)
        {
            try
            {
                StartControlCheck(h);
                // The host's accept-all verdict (one round trip) comes first: a tarpit has no services to identify.
                if (_o.ServiceDetection && h.ControlCheck is { } check) await check.ConfigureAwait(false);
                if (_o.ServiceDetection && !h.AcceptsAll && !ct.IsCancellationRequested)
                {
                    var info = await ServiceScanner.ProbeAsync(h.Address, port, socket, h.Name ?? "",
                                                               Math.Max(_o.TimeoutMs, 1500), ct).ConfigureAwait(false);
                    if (info.ServiceLabel is { Length: > 0 } and not "unknown") f.Service = info.ServiceLabel;
                    f.Version = info.VersionText;
                    f.Detail = info.Detail;
                    f.Interceptor = info.Interceptor;
                }
            }
            catch { }
            finally
            {
                // RST, not FIN: no TIME_WAIT pile-up / ephemeral-port exhaustion on big scans.
                ScanSocket.AbortiveClose(socket);
                _sockets.TryRemove(socket, out _);
                try { socket.Dispose(); } catch { }
            }
        }
        Record(f);
    }

    private readonly record struct Probe(PortState State, string Reason, double Ms, Socket? Socket = null);

    private async Task<Probe?> ProbeTcpAsync(ScanHost h, int port, CancellationToken ct)
    {
        var remote = new IPEndPoint(h.Address, port);
        int attempt = 0, localRetries = 0;
        while (!ct.IsCancellationRequested)
        {
            int timeout = h.Rtt.ProbeTimeout(_o.TimeoutMs, attempt);
            Socket? socket = null;
            bool keep = false;
            try
            {
                SocketError err;
                double ms = 0;
                ScanIcmp.Error? icmp = null;
                try
                {
                    socket = new Socket(h.Address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                    _sockets.TryAdd(socket, 0);
                    // Fast templates turn SYN retransmissions off so a Windows RST surfaces at once and a lost SYN is
                    // covered by our own retry; the slow ones keep them to wait past Windows' ~3 s RTO ceiling.
                    if (_o.Timing.Level >= 2) ScanSocket.DisableSynRetransmissions(socket, timeout);
                    ScanIcmp.Enable(socket);
                    Interlocked.Increment(ref _sent);
                    using var op = new ScanOp();
                    long t0 = Stopwatch.GetTimestamp();
                    err = await op.ConnectAsync(socket, remote, timeout, ct).ConfigureAwait(false);
                    ms = Stopwatch.GetElapsedTime(t0, op.CompletedTicks).TotalMilliseconds;
                    if (err is not (SocketError.Success or SocketError.TimedOut or SocketError.OperationAborted))
                        icmp = ScanIcmp.Read(socket);
                }
                catch (SocketException se) { err = se.SocketErrorCode; }   // creating the socket: out of fds, no IPv6
                if (ct.IsCancellationRequested) return null;   // stopped: no result at all

                switch (err)
                {
                    case SocketError.Success:
                        h.Rtt.AddSample(ms);
                        NoteAnswer(h, attempt);
                        keep = true;
                        return new Probe(PortState.Open, "syn-ack", ms, socket);
                    case SocketError.ConnectionRefused when icmp is null:
                        // The host's own RST: closed.
                        h.Rtt.AddSample(ms);
                        NoteAnswer(h, attempt);
                        NoteRst(h, ms);
                        return new Probe(PortState.Closed, "conn-refused", ms);
                    case SocketError.TimedOut or SocketError.OperationAborted:
                        break;   // no response: maybe retry
                    case var e when ScanSocket.IsLocalExhaustion(e):
                        // Our side is out of fds / ports: the SYN never left. Back off and retry without spending one
                        // of the port's own retries; still failing → undetermined, never "filtered".
                        if (localRetries >= ScanSocket.MaxLocalRetries) return Unknown();
                        if (!await ScanSocket.BackoffAsync(localRetries++, ct).ConfigureAwait(false)) return null;
                        continue;
                    case SocketError.AddressFamilyNotSupported or SocketError.ProtocolNotSupported:
                        return Unknown("no-ipv6");   // a fact about this machine, not the port
                    default:
                        // An ICMP error (Linux / Android say which: a firewall's "port unreachable" is filtered, as
                        // nmap's SYN scan reports it), or an OS error such as host / net unreachable.
                        if (icmp?.From is { } from && ScanDiscovery.SameAddress(from, h.Address)) NoteEvidence(h);
                        return new Probe(PortState.Filtered, icmp?.Reason ?? ReasonFor(err), ms);
                }
            }
            finally
            {
                if (!keep && socket is not null)
                {
                    _sockets.TryRemove(socket, out _);
                    try { socket.Dispose(); } catch { }
                }
            }

            if (attempt >= AllowedRetries(h)) return new Probe(PortState.Filtered, "no-response", 0);
            attempt++;
        }
        return null;
    }

    private Probe Unknown(string reason = "socket-limit")
    {
        Interlocked.Increment(ref _unknownProbes);
        return new Probe(PortState.Unknown, reason, 0);
    }

    // nmap's adaptive retransmission: a silent port gets the template's base retries, more on a host where some port
    // only answered on a retry (a lossy or rate-limiting path), never more than the template's cap.
    private int AllowedRetries(ScanHost h) =>
        Math.Min(_o.Timing.RetryCap, Math.Max(_o.Timing.MaxRetries, Volatile.Read(ref h.MaxAnsweredAttempt) + 1));

    private void NoteAnswer(ScanHost h, int attempt)
    {
        int seen;
        while (attempt > (seen = Volatile.Read(ref h.MaxAnsweredAttempt))
               && Interlocked.CompareExchange(ref h.MaxAnsweredAttempt, attempt, seen) != seen) { }
        NoteEvidence(h);
    }

    // The fastest RST is this host's real round trip — the yardstick for SYN-ACKs from a proxy on the path.
    private void NoteRst(ScanHost h, double ms)
    {
        if (!_rstTimingValid) return;
        Interlocked.Increment(ref h.RstCount);
        lock (h.Gate) { if (ms < h.MinRstMs) h.MinRstMs = ms; }
    }

    // ---- accept-all (SYN proxy / tarpit / transparent proxy) ----
    // On a host's first open port, probe a few ports that should be closed. A host that SYN-ACKs all of them answers
    // indiscriminately: its "open" ports are meaningless, so they are folded and its remaining ports aren't probed.
    // Lazy, so a sweep pays for it only on hosts with open ports; loopback can't be behind a middlebox.
    private void StartControlCheck(ScanHost h)
    {
        if (h.IsLoopback || _controlPorts.Length == 0 || Volatile.Read(ref h.ControlCheck) is not null) return;
        // The task is published before the check starts, so every open port of this host waits for the same verdict.
        var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        if (Interlocked.CompareExchange(ref h.ControlCheck, done.Task, null) is not null) return;
        lock (_background) _background.Add(done.Task);
        _ = ControlCheckAsync(h, done, _cts.Token);
    }

    private async Task ControlCheckAsync(ScanHost h, TaskCompletionSource done, CancellationToken ct)
    {
        try
        {
            var answers = await Task.WhenAll(_controlPorts.Select(p => ControlProbeAsync(h, p, ct))).ConfigureAwait(false);
            if (answers.All(a => a) && !ct.IsCancellationRequested)
            {
                h.AcceptsAll = true;
                _sink.HostChanged(h);
            }
        }
        catch { }
        finally { done.TrySetResult(); }
    }

    private async Task<bool> ControlProbeAsync(ScanHost h, int port, CancellationToken ct)
    {
        Socket? socket = null;
        try
        {
            socket = new Socket(h.Address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            _sockets.TryAdd(socket, 0);
            int timeout = Math.Clamp(h.Rtt.ProbeTimeout(_o.TimeoutMs, 1), 400, 3000);
            if (_o.Timing.Level >= 2) ScanSocket.DisableSynRetransmissions(socket, timeout);
            Interlocked.Increment(ref _sent);
            using var op = new ScanOp();
            bool open = await op.ConnectAsync(socket, new IPEndPoint(h.Address, port), timeout, ct).ConfigureAwait(false) == SocketError.Success;
            if (open) ScanSocket.AbortiveClose(socket);
            return open;   // refused / timeout / unreachable / stopped: not accept-all evidence
        }
        catch { return false; }
        finally
        {
            if (socket is not null) { _sockets.TryRemove(socket, out _); try { socket.Dispose(); } catch { } }
        }
    }

    // Three high ports unlikely to host anything, excluding the ones being scanned; random so a tarpit can't be
    // tuned against a fixed set.
    private static int[] PickControlPorts(List<int> scanned)
    {
        var skip = new HashSet<int>(scanned);
        var list = new List<int>(ControlPorts);
        for (int guard = 0; list.Count < ControlPorts && guard < 64; guard++)
        {
            int p = Random.Shared.Next(49200, 65500);
            if (!skip.Contains(p) && !list.Contains(p)) list.Add(p);
        }
        return list.ToArray();
    }

    // ================================================================ UDP

    // Sweep pass: a reply → open, port unreachable → closed, another ICMP error → filtered. Silence is decided
    // after the sweep (SettleSilentUdpAsync), once it's known whether the host rate-limits its ICMP errors.
    private async Task ScanUdpAsync(ScanHost h, int port, CancellationToken ct)
    {
        long now = Stopwatch.GetTimestamp();
        Interlocked.CompareExchange(ref h.UdpFirstTicks, now, 0);
        // A UDP reply is the service's own answer — a resolver recursing, an SNMP agent — not a kernel's RST: give it
        // at least half a second (doubled per retry) whatever the host's round trip.
        var r = await ProbeUdpAsync(h, port, _o.Timing.MaxRetries,
                                    attempt => Math.Max(h.Rtt.ProbeTimeout(_o.TimeoutMs, attempt), Math.Min(_o.TimeoutMs, 500 << attempt)), ct)
            .ConfigureAwait(false);
        InterlockedMax(ref h.UdpLastTicks, Stopwatch.GetTimestamp());
        if (r is not { } f) return;   // stopped
        if (f.State == PortState.OpenFiltered)
        {
            h.SilentUdp.Enqueue(port);
            Interlocked.Increment(ref Progress.Done);
            return;
        }
        Record(f);
    }

    private async Task<PortFinding?> ProbeUdpAsync(ScanHost h, int port, int retries, Func<int, int> timeoutFor, CancellationToken ct)
    {
        byte[] payload = ScanPayloads.Udp(port);
        var remote = new IPEndPoint(h.Address, port);
        // Pooled: a UDP sweep is one buffer per port. Returned only once the receive has completed.
        byte[] buffer = ArrayPool<byte>.Shared.Rent(2048);
        try
        {
            int attempt = 0, localRetries = 0;
            while (!ct.IsCancellationRequested)
            {
                Socket? socket = null;
                SocketError err;
                double ms = 0;
                int received = 0;
                ScanIcmp.Error? icmp = null;
                try
                {
                    socket = new Socket(h.Address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                    _sockets.TryAdd(socket, 0);
                    ScanIcmp.Enable(socket);
                    // A connected UDP socket gets the ICMP errors for its flow: that's how closed is told apart.
                    // (Connecting sends nothing; it can only fail on a missing route — a fact about the target.)
                    socket.Connect(remote);
                    Interlocked.Increment(ref _sent);
                    long t0 = Stopwatch.GetTimestamp();
                    socket.Send(payload);
                    using var op = new ScanOp();
                    err = await op.ReceiveAsync(socket, buffer, timeoutFor(attempt), ct).ConfigureAwait(false);
                    ms = Stopwatch.GetElapsedTime(t0, op.CompletedTicks).TotalMilliseconds;
                    received = op.BytesTransferred;
                    if (err is not (SocketError.Success or SocketError.TimedOut or SocketError.OperationAborted))
                        icmp = ScanIcmp.Read(socket);
                }
                catch (SocketException se) { err = se.SocketErrorCode; }
                catch (ObjectDisposedException) { err = SocketError.OperationAborted; }   // stopped
                catch (Exception)
                {
                    Interlocked.Increment(ref _unknownProbes);
                    return new PortFinding(h, port, ScanProto.Udp) { State = PortState.Unknown, Reason = "error" };
                }
                finally
                {
                    if (socket is not null)
                    {
                        _sockets.TryRemove(socket, out _);
                        try { socket.Dispose(); } catch { }
                    }
                }

                if (ct.IsCancellationRequested) return null;
                switch (err)
                {
                    // Windows reports a reply bigger than the buffer as WSAEMSGSIZE — still a reply.
                    case SocketError.Success or SocketError.MessageSize:
                        return Answered(h, port, attempt, ms, buffer.AsSpan(0, err == SocketError.Success ? received : 0));
                    case SocketError.TimedOut or SocketError.OperationAborted:
                        break;   // silence: maybe retry
                    case var e when ScanSocket.IsLocalExhaustion(e):
                        // Out of fds, or ENOBUFS from a send queue a fast sweep filled: the datagram never left.
                        if (localRetries >= ScanSocket.MaxLocalRetries)
                        {
                            Interlocked.Increment(ref _unknownProbes);
                            return new PortFinding(h, port, ScanProto.Udp) { State = PortState.Unknown, Reason = "socket-limit" };
                        }
                        if (!await ScanSocket.BackoffAsync(localRetries++, ct).ConfigureAwait(false)) return null;
                        continue;
                    case SocketError.AddressFamilyNotSupported or SocketError.ProtocolNotSupported:
                        Interlocked.Increment(ref _unknownProbes);
                        return new PortFinding(h, port, ScanProto.Udp) { State = PortState.Unknown, Reason = "no-ipv6" };
                    default:
                    {
                        // Port unreachable → closed (Windows: WSAECONNRESET; Linux: ECONNREFUSED + the queued ICMP error).
                        bool portUnreach = icmp is { } ie ? ie.PortUnreachable
                            : err is SocketError.ConnectionReset or SocketError.ConnectionRefused;
                        var f = new PortFinding(h, port, ScanProto.Udp) { LatencyMs = ms };
                        if (portUnreach)
                        {
                            f.State = PortState.Closed;
                            f.Reason = "port-unreach";
                            NoteUnreach(h, ms);
                            h.Rtt.AddSample(ms);
                            NoteAnswer(h, attempt);
                        }
                        else
                        {
                            f.State = PortState.Filtered;
                            f.Reason = icmp?.Reason ?? ReasonFor(err);
                            if (icmp?.From is { } from && ScanDiscovery.SameAddress(from, h.Address)) NoteEvidence(h);
                        }
                        return f;
                    }
                }

                if (attempt >= retries) return new PortFinding(h, port, ScanProto.Udp) { State = PortState.OpenFiltered, Reason = "no-response" };
                attempt++;
            }
            return null;
        }
        finally { ArrayPool<byte>.Shared.Return(buffer); }
    }

    private PortFinding Answered(ScanHost h, int port, int attempt, double ms, ReadOnlySpan<byte> reply)
    {
        h.Rtt.AddSample(ms);
        NoteAnswer(h, attempt);
        var f = new PortFinding(h, port, ScanProto.Udp) { State = PortState.Open, Reason = "udp-response", LatencyMs = ms };
        var (service, version) = ScanPayloads.Describe(port, reply);
        if (service.Length > 0) f.Service = service;
        f.Version = version;
        return f;
    }

    private static void NoteUnreach(ScanHost h, double ms)
    {
        Interlocked.Increment(ref h.UdpUnreach);
        Volatile.Write(ref h.LastUnreachTicks, Stopwatch.GetTimestamp());
        lock (h.Gate) { if (ms < h.MinUnreachMs) h.MinUnreachMs = ms; }
    }

    // ---- silent UDP ports: rate-limited ICMP ----
    // Linux (and Android) send at most ~1 ICMP error per second per peer after a burst of 6, so a fast sweep of a Linux
    // host hears "port unreachable" for a handful of closed ports and silence for the rest — which would read as
    // open|filtered. nmap slows down until the answers come back (a 1,000-port UDP scan of Linux takes ~18 minutes).
    // Here: a host that sent some port-unreachables but at a rate a limiter allows gets its silent ports re-checked
    // one at a time, paced by a model of the limiter's token bucket (6 burst, 1/s), so a closed port is only probed
    // when the host can answer. Silence then really means open|filtered. Hosts that sent no ICMP at all, or answered
    // faster than a limiter allows, keep their silence as is.
    private async Task SettleSilentUdpAsync(ScanPass pass, CancellationToken ct)
    {
        var recheck = new List<(ScanHost Host, List<int> Ports)>();
        foreach (var h in pass.Scanned)
        {
            if (!h.HasSilentUdp) continue;   // (doesn't create the queue for the hosts that never had one)
            var silent = h.SilentUdp.ToList();
            silent.Sort();
            h.SilentUdp.Clear();
            int unreach = Volatile.Read(ref h.UdpUnreach);
            double sweepSeconds = (h.UdpLastTicks - h.UdpFirstTicks) / (double)Stopwatch.Frequency;
            bool limited = unreach > 0 && (unreach <= 8 + 2 * sweepSeconds || silent.Count <= 16);
            if (!limited || ct.IsCancellationRequested) { RecordSilent(h, silent); continue; }

            int cap = _o.Timing.UdpRecheck;
            if (silent.Count > cap)
            {
                RecordSilent(h, silent.GetRange(cap, silent.Count - cap));
                pass.RecheckSkipped += silent.Count - cap;
                silent.RemoveRange(cap, silent.Count - cap);
            }
            recheck.Add((h, silent));
        }
        if (recheck.Count == 0) return;

        pass.RecheckedHosts = recheck.Count;
        Progress.RecheckHosts = recheck.Count;
        Progress.StartPhase(ScanProgress.Stage.UdpRecheck, recheck.Sum(r => (long)r.Ports.Count));
        var options = new ParallelOptions { MaxDegreeOfParallelism = Math.Clamp(_o.Concurrency, 1, 64), CancellationToken = ct };
        try
        {
            await Parallel.ForEachAsync(recheck, options, async (r, c) => await RecheckHostAsync(r.Host, r.Ports, c).ConfigureAwait(false))
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) { }
    }

    private async Task RecheckHostAsync(ScanHost h, List<int> ports, CancellationToken ct)
    {
        const double Burst = 6, RefillMs = 1050;   // Linux: XRLIM_BURST_FACTOR 6, icmp_ratelimit 1000 ms (+ margin)
        // The sweep emptied the bucket; it has been refilling since the last port-unreachable.
        double tokens = 0;
        long since = Volatile.Read(ref h.LastUnreachTicks);
        if (since == 0) since = Stopwatch.GetTimestamp();
        double Tokens(long now) => Math.Min(Burst, tokens + (now - since) * 1000.0 / Stopwatch.Frequency / RefillMs);
        // An answer arrives within a few round trips when the host can send it.
        double unreachMs = h.MinUnreachMs == double.MaxValue ? 50 : h.MinUnreachMs;
        int wait = (int)Math.Clamp(4 * unreachMs + 150, 250, Math.Max(_o.TimeoutMs, 1000));

        int i = 0;
        try
        {
            while (i < ports.Count && !ct.IsCancellationRequested)
            {
                long now = Stopwatch.GetTimestamp();
                double tk = Tokens(now);
                if (tk < 1)
                {
                    await Task.Delay(TimeSpan.FromMilliseconds((1 - tk) * RefillMs + 5), ct).ConfigureAwait(false);
                    now = Stopwatch.GetTimestamp();
                    tk = Tokens(now);
                }
                // As many probes at once as the host can answer right now.
                int batch = Math.Max(1, Math.Min((int)tk, ports.Count - i));
                tokens = tk; since = now;
                var results = await Task.WhenAll(ports.Skip(i).Take(batch)
                    .Select(p => ProbeUdpAsync(h, p, 0, _ => wait, ct))).ConfigureAwait(false);
                i += batch;
                foreach (var f in results)
                {
                    if (f is null) continue;
                    if (f.State == PortState.Closed) tokens -= 1;
                    Record(f);
                }
            }
        }
        catch (OperationCanceledException) { }
        // Stopped part-way: the rest are still what the sweep heard — nothing.
        if (i < ports.Count) RecordSilent(h, ports.GetRange(i, ports.Count - i));
    }

    // Silence that stands (progress was counted when the sweep heard it).
    private void RecordSilent(ScanHost h, List<int> ports)
    {
        foreach (int p in ports)
            Record(new PortFinding(h, p, ScanProto.Udp) { State = PortState.OpenFiltered, Reason = "no-response" },
                   countProgress: false);
    }

    // ================================================================ bookkeeping

    // Deposit a finished probe: exact tallies, the retained row set (bounded), the UI.
    private void Record(PortFinding f, bool countProgress = true)
    {
        var h = f.Host;
        Interlocked.Increment(ref h.Tally[(int)f.Proto * 5 + (int)f.State]);
        if (f.State != PortState.Open)
            h.CountReason(f.State, f.Proto, f.Reason ?? "");
        switch (f.State)
        {
            case PortState.Open: Interlocked.Increment(ref Progress.Open); break;
            case PortState.OpenFiltered: Interlocked.Increment(ref Progress.OpenFiltered); break;
            case PortState.Closed: Interlocked.Increment(ref Progress.Closed); break;
            case PortState.Filtered: Interlocked.Increment(ref Progress.Filtered); break;
        }
        if (countProgress) Interlocked.Increment(ref Progress.Done);

        bool keep = f.State == PortState.Open
            ? Interlocked.Increment(ref _retainedOpen) <= MaxRetainOpen
            : Interlocked.Increment(ref _retainedOther) <= MaxRetainOther;
        if (keep) _all.Add(f); else Interlocked.Increment(ref _dropped);
        _sink.PortFound(f);
    }

    // After the pass: host states from the evidence, and the SYN-ACKs that came back faster than the host can answer.
    private void FinishHosts(ScanPass pass)
    {
        var scanned = new HashSet<ScanHost>(pass.Scanned);
        foreach (var h in pass.Targets)
        {
            if (h.Status != HostStatus.Up && h.Evidence)
            {
                // -Pn or the single target: something answered, so it's up whatever discovery thought.
                h.Status = HostStatus.Up;
                h.Reason = h.Count(ScanProto.Tcp, PortState.Open) > 0 ? "syn-ack"
                    : h.Count(ScanProto.Tcp, PortState.Closed) > 0 ? "conn-refused"
                    : h.Count(ScanProto.Udp, PortState.Open) > 0 ? "udp-response"
                    : h.Count(ScanProto.Udp, PortState.Closed) > 0 ? "port-unreach" : "icmp-error";
                Interlocked.Increment(ref Progress.HostsUp);
            }
            else if (h.Status == HostStatus.Unknown && scanned.Contains(h) && h.Reason != "socket-limit")
            {
                h.Status = HostStatus.Down;
                h.Reason = "no-response";
            }
            // No discovery latency (-Pn, a single target): the fastest RST or ICMP port-unreachable is the round trip.
            double rtt = Math.Min(h.MinRstMs, h.MinUnreachMs);
            if (h.LatencyMs <= 0 && rtt < double.MaxValue) h.LatencyMs = Math.Max(rtt, 0.1);
        }

        // A local proxy, VPN client or antivirus completes the handshake itself, at once, while the host's own RSTs
        // take the real round trip: SYN-ACKs at a quarter of that (and ≥ 20 ms quicker) didn't come from the host.
        var fast = new Dictionary<ScanHost, List<int>>();
        foreach (var f in _all)
        {
            if (f.State != PortState.Open || f.Proto != ScanProto.Tcp) continue;
            var h = f.Host;
            if (h.IsLoopback || h.RstCount == 0 || h.MinRstMs < 20) continue;
            if (f.LatencyMs <= h.MinRstMs / 4 && h.MinRstMs - f.LatencyMs >= 20)
            {
                f.AnsweredFast = true;
                if (!fast.TryGetValue(h, out var list)) fast[h] = list = new List<int>();
                list.Add(f.Port);
            }
        }
        foreach (var (h, list) in fast)
        {
            list.Sort();
            h.LocalAnswerPorts = string.Join(", ", list.Take(8)) + (list.Count > 8 ? $" (+{list.Count - 8})" : "");
        }
    }

    // MAC + maker for on-link hosts (the probes just refreshed the neighbor cache); this machine's own addresses
    // take its NIC's MAC.
    private void ApplyNeighbors(IReadOnlyList<ScanHost> targets)
    {
        var up = targets.Where(h => h.Status == HostStatus.Up && !h.IsLoopback).ToList();
        if (up.Count == 0) return;
        var table = ScanNeighbors.Snapshot();
        var local = ScanNeighbors.LocalMacs();
        foreach (var h in up)
        {
            string? mac = table.TryGetValue(h.NeighborKey, out var e) ? e.Mac : local.TryGetValue(h.NeighborKey, out var own) ? own : null;
            if (mac is null || mac == h.Mac) continue;
            h.Mac = mac;
            h.Vendor = ScanOui.Vendor(mac);
            _sink.HostChanged(h);
        }
    }

    // Scan-wide: a transparent proxy on the path (an ISP's, a VPN's) makes one port "open" on every address of a sweep,
    // including addresses with nothing behind them — and that port is then their only sign of life: no other open
    // port, no RST from a closed one. A port open on ≥ 90% of ≥ 8 hosts, most of which show nothing else, is flagged.
    // (A LAN of Windows PCs has 445 open everywhere too, but next to other ports and RSTs: not flagged.)
    private static List<int> UbiquitousPorts(ScanPass pass)
    {
        var hosts = pass.Scanned.Where(h => !h.IsLoopback).ToList();
        if (hosts.Count < 8) return new List<int>();
        return pass.Findings.Where(f => f.State == PortState.Open && f.Proto == ScanProto.Tcp && !f.Host.IsLoopback)
                            .GroupBy(f => f.Port)
                            .Where(g =>
                            {
                                var on = g.Select(f => f.Host).Distinct().ToList();
                                int alone = on.Count(h => h.Count(PortState.Open) == 1 && h.RstCount == 0
                                                          && h.Count(ScanProto.Tcp, PortState.Closed) == 0);
                                return on.Count >= hosts.Count * 0.9 && alone >= on.Count * 0.8;
                            })
                            .Select(g => g.Key).OrderBy(p => p).ToList();
    }

    private static string ReasonFor(SocketError e) => e switch
    {
        SocketError.HostUnreachable => "host-unreach",
        SocketError.NetworkUnreachable => "net-unreach",
        SocketError.HostDown => "host-down",
        SocketError.NetworkDown => "net-down",
        SocketError.AccessDenied => "admin-prohibited",
        SocketError.AddressNotAvailable => "invalid-address",   // Windows: a broadcast / unspecified destination
        _ => "no-response",
    };

    private static void InterlockedMax(ref long target, long value)
    {
        long seen;
        while (value > (seen = Volatile.Read(ref target)) && Interlocked.CompareExchange(ref target, value, seen) != seen) { }
    }
}

/// <summary>Address (numerically), then port, then TCP before UDP.</summary>
public sealed class FindingOrder : IComparer<PortFinding>
{
    public static readonly FindingOrder Instance = new();

    public int Compare(PortFinding? a, PortFinding? b)
    {
        if (ReferenceEquals(a, b)) return 0;
        if (a is null) return -1;
        if (b is null) return 1;
        int c = IpAddressComparer.Instance.Compare(a.Host.Address, b.Host.Address);
        if (c != 0) return c;
        c = a.Port.CompareTo(b.Port);
        return c != 0 ? c : a.Proto.CompareTo(b.Proto);
    }
}
