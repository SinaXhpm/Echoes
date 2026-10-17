using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Threading;

namespace Echoes.Helpers;

/// <summary>
/// nmap's port states. <see cref="OpenFiltered"/>: no reply and no ICMP error (UDP) — open, or dropped by a filter.
/// <see cref="Unknown"/>: never really probed, because our side ran out of sockets — says nothing about the port.
/// Declared in display order (the state sort and the report list open first).
/// </summary>
public enum PortState : byte { Open, OpenFiltered, Filtered, Closed, Unknown }

public enum ScanProto : byte { Tcp, Udp }

public enum HostStatus : byte { Unknown, Up, Down }

/// <summary>A result's change against the previous pass of a repeating scan.</summary>
public enum ScanChange : byte { None, New, Gone }

public static class ScanText
{
    public static string State(PortState s) => s switch
    {
        PortState.Open => "open",
        PortState.OpenFiltered => "open|filtered",
        PortState.Filtered => "filtered",
        PortState.Closed => "closed",
        _ => "unknown",
    };

    public static string Proto(ScanProto p) => p == ScanProto.Udp ? "udp" : "tcp";

    public static string Status(HostStatus s) => s switch { HostStatus.Up => "up", HostStatus.Down => "down", _ => "unknown" };

    /// <summary>"0.4 ms", "12 ms", "1.2 s"; "" when there's no measurement.</summary>
    public static string Latency(double ms) => ms <= 0 ? "" : ms < 10 ? $"{ms:0.0} ms" : ms < 1000 ? $"{ms:0} ms" : $"{ms / 1000:0.0} s";
}

/// <summary>Every setting a scan reads, captured once at Start — the workers never touch bound properties.</summary>
public sealed record ScanOptions(
    bool Tcp, bool Udp, bool ServiceDetection, bool PingOnly, bool SkipDiscovery,
    int TimeoutMs, int Concurrency, TimingTemplate Timing);

/// <summary>A scan target: its address, the name it was typed as (if any), and what a pass learned about it.</summary>
public sealed class ScanHost
{
    public ScanHost(IPAddress address, string? name)
    {
        Address = address;
        Name = name;
        Ip = address.ToString();
        IsLoopback = IPAddress.IsLoopback(address);
    }

    public IPAddress Address { get; }
    public string Ip { get; }                  // the address literal; also the dedupe / lookup key
    public string? Name { get; }               // the hostname it was typed as
    public bool IsLoopback { get; }

    /// <summary>A hostname's other addresses (not scanned), for nmap's "Other addresses for …" report line.</summary>
    public IReadOnlyList<IPAddress>? OtherAddresses { get; init; }

    // Enrichment, kept across repeat passes (written by the engine before it announces the host).
    public string? ReverseName { get; internal set; }   // PTR record
    public string? Mac { get; internal set; }           // on-link hosts only
    public string? Vendor { get; internal set; }

    /// <summary>The RTT estimator; deliberately kept across repeat passes — a warm estimator is the point.</summary>
    public HostRtt Rtt { get; } = new();

    // ---- per pass ----
    public HostStatus Status { get; internal set; }
    public string Reason { get; internal set; } = "";
    public double LatencyMs { get; internal set; }
    /// <summary>Every control port (should be closed) answered SYN-ACK: a SYN proxy / tarpit — its "open" ports mean nothing.</summary>
    public bool AcceptsAll { get; internal set; }
    /// <summary>Open ports whose SYN-ACK came back far faster than this host's own round trip: answered by a local
    /// proxy / VPN / antivirus on the path, not the host ("" when none).</summary>
    public string LocalAnswerPorts { get; internal set; } = "";

    // Exact per-host tallies [proto * 5 + state] — the report's counts and nmap's "Not shown" lines, kept apart
    // from the retained rows so they stay exact when rows are capped.
    internal readonly int[] Tally = new int[10];

    // "state|proto|reason" → count, for the "Not shown: 95 closed tcp ports (conn-refused)" breakdown. It and SilentUdp
    // are created on first use: an empty ConcurrentDictionary costs ~1 KB (its lock array grows with the core count) and
    // an empty ConcurrentQueue ~0.4 KB, and a /16 target list is 65,536 hosts that mostly never answer — ~117 MB held
    // before the first probe.
    private ConcurrentDictionary<string, int>? _reasonTally;
    internal ConcurrentDictionary<string, int> ReasonTally
        => Volatile.Read(ref _reasonTally) ?? Create(ref _reasonTally, new ConcurrentDictionary<string, int>(StringComparer.Ordinal));

    /// <summary>The reason breakdown, without creating it (empty when nothing was tallied).</summary>
    internal IEnumerable<KeyValuePair<string, int>> Reasons
        => (IEnumerable<KeyValuePair<string, int>>?)Volatile.Read(ref _reasonTally) ?? Array.Empty<KeyValuePair<string, int>>();

    private static T Create<T>(ref T? field, T made) where T : class
        => Interlocked.CompareExchange(ref field, made, null) ?? made;   // racing threads all get the one that won

    internal readonly object Gate = new();   // guards the double minimums below
    internal int SkippedTcp;              // TCP ports not probed once the host proved to answer everything
    internal System.Threading.Tasks.Task? ControlCheck;   // the accept-all check, once started
    internal int MaxAnsweredAttempt;      // highest retry that ever got an answer (adaptive retries)
    internal int RstCount;
    internal double MinRstMs = double.MaxValue;   // fastest RST: this host's real round trip
    internal int UdpUnreach;              // ICMP port-unreachables seen in the UDP sweep
    internal double MinUnreachMs = double.MaxValue;
    internal long UdpFirstTicks, UdpLastTicks, LastUnreachTicks;
    // UDP ports with no answer at all (re-checked if rate-limited); created on first use (see ReasonTally).
    private ConcurrentQueue<int>? _silentUdp;
    internal ConcurrentQueue<int> SilentUdp => Volatile.Read(ref _silentUdp) ?? Create(ref _silentUdp, new ConcurrentQueue<int>());
    internal bool HasSilentUdp => Volatile.Read(ref _silentUdp) is { IsEmpty: false };
    internal bool Evidence;               // anything at all came back (a reply, a refusal, an ICMP error from it)
    internal int Reported;                // 1 once the host has been announced in this pass

    public int Count(ScanProto proto, PortState state) => Volatile.Read(ref Tally[(int)proto * 5 + (int)state]);
    public int Count(PortState state) => Count(ScanProto.Tcp, state) + Count(ScanProto.Udp, state);

    internal void BeginPass()
    {
        Status = HostStatus.Unknown;
        Reason = "";
        LatencyMs = 0;
        AcceptsAll = false;
        LocalAnswerPorts = "";
        Array.Clear(Tally);
        Volatile.Write(ref _reasonTally, null);   // (no probe of this host runs yet: nothing writes to it meanwhile)
        SkippedTcp = 0; ControlCheck = null; RstCount = 0;
        MinRstMs = double.MaxValue;
        UdpUnreach = 0; MinUnreachMs = double.MaxValue;
        UdpFirstTicks = UdpLastTicks = LastUnreachTicks = 0;
        Volatile.Write(ref _silentUdp, null);
        Evidence = false;
        Reported = 0;
        // MaxAnsweredAttempt is kept: a lossy path stays lossy between passes.
    }

    /// <summary>"scanme.nmap.org (45.33.32.156)" — nmap's order; the bare address without a name.</summary>
    public string Display => string.IsNullOrEmpty(Name) ? Ip : $"{Name} ({Ip})";

    /// <summary>The address as the neighbor table keys it (an IPv6 literal without its "%scope").</summary>
    internal string NeighborKey => Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && Address.ScopeId != 0
        ? new IPAddress(Address.GetAddressBytes()).ToString() : Ip;   // (ScopeId throws on IPv4: family first)
}

/// <summary>One probed port.</summary>
public sealed class PortFinding
{
    public PortFinding(ScanHost host, int port, ScanProto proto)
    {
        Host = host; Port = port; Proto = proto;
        Service = NmapData.ServiceName(port, proto);
    }

    public ScanHost Host { get; }
    public int Port { get; }
    public ScanProto Proto { get; }
    public PortState State { get; internal set; }
    public string Reason { get; internal set; } = "";
    public double LatencyMs { get; internal set; }
    public string Service { get; internal set; }
    public string Version { get; internal set; } = "";   // "nginx 1.24.0 (Ubuntu)" — the nmap VERSION column
    public string Detail { get; internal set; } = "";    // longer extras: page title, certificate, redirect
    public ScanChange Change { get; internal set; }
    internal bool AnsweredFast;                           // SYN-ACK suspiciously quicker than the host's RST round trip
    /// <summary>Who answered in the server's place for -sV (an antivirus web / TLS shield, a filter), "" when nobody.</summary>
    public string Interceptor { get; internal set; } = "";

    public string PortLabel => $"{Port}/{ScanText.Proto(Proto)}";

    /// <summary>Stable key of (host, proto, port) for the repeat diff.</summary>
    public long Key => KeyOf(Port, Proto);
    public static long KeyOf(int port, ScanProto proto) => ((long)proto << 16) | (uint)port;
}

/// <summary>Live counters of a running pass, polled by the UI timer (Interlocked / volatile only).</summary>
public sealed class ScanProgress
{
    public enum Stage { Idle, Resolving, Discovery, Ports, UdpRecheck, Finishing }

    public volatile Stage Phase;
    public long Done, Total;
    public long Open, OpenFiltered, Closed, Filtered;
    public long HostsUp, HostErrors;
    public int RecheckHosts;
    public readonly System.Diagnostics.Stopwatch PhaseClock = new();

    internal void ResetCounts()
    {
        Interlocked.Exchange(ref Done, 0);
        Interlocked.Exchange(ref Total, 0);
        Interlocked.Exchange(ref Open, 0);
        Interlocked.Exchange(ref OpenFiltered, 0);
        Interlocked.Exchange(ref Closed, 0);
        Interlocked.Exchange(ref Filtered, 0);
        Interlocked.Exchange(ref HostsUp, 0);
        Interlocked.Exchange(ref HostErrors, 0);
        RecheckHosts = 0;
    }

    internal void StartPhase(Stage stage, long total)
    {
        Phase = stage;
        Interlocked.Exchange(ref Done, 0);
        Interlocked.Exchange(ref Total, total);
        PhaseClock.Restart();
    }
}

/// <summary>What the engine tells the UI as it goes. Called from worker threads — implementations queue, never block.</summary>
public interface IScanSink
{
    void HostChanged(ScanHost host);
    void PortFound(PortFinding finding);
}

/// <summary>The outcome of one pass.</summary>
public sealed class ScanPass
{
    public DateTime StartedUtc { get; init; }
    public DateTime FinishedUtc { get; internal set; }
    public TimeSpan Elapsed { get; internal set; }
    public bool Stopped { get; internal set; }
    public required ScanOptions Options { get; init; }
    public required IReadOnlyList<ScanHost> Targets { get; init; }
    public int TcpPorts { get; init; }
    public int UdpPorts { get; init; }
    /// <summary>Hosts that were port-scanned (all targets with -Pn or a single target; else the ones found up).</summary>
    public List<ScanHost> Scanned { get; internal set; } = new();
    /// <summary>Retained rows, sorted by address, port, protocol (capped — the tallies on each host stay exact).</summary>
    public List<PortFinding> Findings { get; internal set; } = new();
    public long DroppedRows { get; internal set; }
    public long ProbesSent { get; internal set; }
    public int HostsUp { get; internal set; }
    public long UnknownProbes { get; internal set; }   // left undetermined by local socket errors
    public long UnknownHosts { get; internal set; }
    /// <summary>Hosts whose silent UDP ports were re-checked slowly because they rate-limit ICMP errors.</summary>
    public int RecheckedHosts { get; internal set; }
    public int RecheckSkipped { get; internal set; }   // silent ports past the template's re-check cap
    /// <summary>Ports open on (nearly) every scanned host — a proxy on the path rather than real services.</summary>
    public List<int> UbiquitousPorts { get; internal set; } = new();
}
