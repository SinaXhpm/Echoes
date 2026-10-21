using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>
/// Fast, parallel host discovery (nmap's "is this host up?" phase, and the -sn ping scan). Fires an ICMP echo and
/// TCP connects to a few always-interesting ports at once and returns the moment one of them proves the host is
/// alive — a refused connection counts too, since only a live host sends a RST. Every reply feeds the host's RTT
/// estimator (so the port scan starts warm) and a sweep-wide one that shortens later hosts' probes once the live
/// ones have answered.
/// </summary>
public static class ScanDiscovery
{
    // nmap's unprivileged ping uses 80 and 443; three more catch the usual Linux and Windows boxes.
    private static readonly int[] Ports = { 80, 443, 22, 445, 3389 };

    /// <summary>Probes one host check sends (an ICMP echo + the TCP ports).</summary>
    public static int ProbesPerHost => Ports.Length + 1;

    // Sweep timeout = clamp(SRTT + 4·RTTVAR, floor, ceiling) once this many replies are in.
    private const int WarmSamples = 5;
    private const double FloorMs = 150;
    // On a home or office LAN most hosts answer in 1-5 ms, so the estimate sank to the floor, while phones and IoT devices
    // in Wi-Fi power save answer 100-400 ms late: they were reported down. A LAN sweep of up to a few thousand hosts keeps
    // a floor they fit under; a bigger one keeps the short floor (a private /16 would take minutes longer).
    private const double LanFloorMs = 600;
    public const int LanFloorMaxHosts = 4096;

    /// <summary><paramref name="LocalError"/>: nothing proved the host up AND a probe could not be sent (out of
    /// sockets / ephemeral ports) — the host is undetermined, never "down".</summary>
    public readonly record struct HostState(bool Up, string Reason, double LatencyMs, bool LocalError = false);

    /// <param name="hostRtt">The host's own estimator (warms the port scan that follows).</param>
    /// <param name="sweepRtt">One estimator for the whole sweep; once warm it replaces the fixed per-probe timeout
    /// (a /16 at 1.5 s per dead host took ~16 min).</param>
    /// <param name="timeoutMs">The ceiling — the user's timeout.</param>
    /// <param name="smallSweep">At most <see cref="LanFloorMaxHosts"/> targets: a host on the local network then gets the
    /// longer floor (power-save devices).</param>
    public static async Task<HostState> DiscoverAsync(IPAddress addr, HostRtt hostRtt, HostRtt sweepRtt, int timeoutMs, CancellationToken ct,
                                                      bool smallSweep = false)
    {
        int timeout = sweepRtt.AdaptiveTimeout(timeoutMs, WarmSamples, smallSweep && IsLocalNetwork(addr) ? LanFloorMs : FloorMs);

        // A private linked source so the first positive can cancel the probes still running.
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var tasks = new List<Task<HostState>>(Ports.Length + 1) { IcmpProbe(addr, sweepRtt, timeout, linked.Token) };
        foreach (int p in Ports) tasks.Add(TcpProbe(addr, p, hostRtt, sweepRtt, timeout, linked.Token));

        bool localError = false;
        try
        {
            while (tasks.Count > 0)
            {
                var done = await Task.WhenAny(tasks).ConfigureAwait(false);
                tasks.Remove(done);
                HostState st = await done.ConfigureAwait(false);   // probes never throw
                if (st.Up) return st;
                localError |= st.LocalError;
            }
        }
        finally { try { linked.Cancel(); } catch { } }

        // "Down" only when every probe actually went out: the one that couldn't may have been the one that answers.
        return localError ? new HostState(false, "socket-limit", 0, LocalError: true)
                          : new HostState(false, "no-response", 0);
    }

    private static async Task<HostState> IcmpProbe(IPAddress addr, HostRtt sweepRtt, int timeoutMs, CancellationToken ct)
    {
        try
        {
            // Our own deadline too: the OS ping may round a short (adaptive) timeout up, and the host check waits
            // for every probe.
            using var to = CancellationTokenSource.CreateLinkedTokenSource(ct);
            to.CancelAfter(timeoutMs);
            var ping = await IcmpPinger.SendAsync(addr, timeoutMs, to.Token).ConfigureAwait(false);
            // The reply must come from the target: an echo to a subnet's broadcast address is answered by its
            // neighbours, which made x.x.x.255 look like a live host.
            if (ping.Success && (ping.Address is null || SameAddress(ping.Address, addr)))
            {
                sweepRtt.AddSample(ping.RoundtripMs);
                // Without ICMP permission the probe was a UDP datagram to a closed port (IcmpPinger's fallback),
                // answered by the host's "port unreachable" — nmap's -PU reason.
                return new HostState(true, ping.Method == PingMethod.Udp ? "port-unreach" : "echo-reply",
                                     Math.Max(ping.RoundtripMs, 0.1));
            }
        }
        catch { /* cancelled by a sibling's win, or ping unavailable */ }
        return new HostState(false, "icmp", 0);
    }

    private static async Task<HostState> TcpProbe(IPAddress addr, int port, HostRtt hostRtt, HostRtt sweepRtt,
                                                  int timeoutMs, CancellationToken ct)
    {
        for (int retry = 0; ; retry++)
        {
            Socket? socket = null;
            try
            {
                SocketError err;
                double ms = 0;
                try
                {
                    // Created inside the try: new Socket(InterNetworkV6) throws without IPv6 (and EMFILE when out of fds).
                    socket = new Socket(addr.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                    ScanSocket.DisableSynRetransmissions(socket, timeoutMs);   // else a Windows RST takes ~1 s to surface
                    ScanIcmp.Enable(socket);
                    using var op = new ScanOp();
                    long t0 = Stopwatch.GetTimestamp();
                    err = await op.ConnectAsync(socket, new IPEndPoint(addr, port), timeoutMs, ct).ConfigureAwait(false);
                    ms = Stopwatch.GetElapsedTime(t0, op.CompletedTicks).TotalMilliseconds;
                }
                catch (SocketException se) { err = se.SocketErrorCode; }

                if (err == SocketError.Success)
                {
                    hostRtt.AddSample(ms);
                    sweepRtt.AddSample(ms);
                    ScanSocket.AbortiveClose(socket!);
                    return new HostState(true, $"syn-ack ({port}/tcp)", Math.Max(ms, 0.1));
                }
                if (err == SocketError.ConnectionRefused)
                {
                    // Linux / Android also report a firewall's ICMP "port unreachable" as a refusal. From the host
                    // itself it still proves the host is up; from a router or firewall on the way it proves nothing.
                    if (ScanIcmp.Read(socket!) is { } icmp && icmp.From is { } from && !SameAddress(from, addr))
                        return new HostState(false, "tcp", 0);
                    hostRtt.AddSample(ms);
                    sweepRtt.AddSample(ms);
                    return new HostState(true, $"conn-refused ({port}/tcp)", Math.Max(ms, 0.1));
                }
                // Out of sockets / ports on our side: no evidence either way — retried below. Anything else: no proof.
                if (!ScanSocket.IsLocalExhaustion(err) || ct.IsCancellationRequested) return new HostState(false, "tcp", 0);
            }
            catch { return new HostState(false, "tcp", 0); }
            finally { try { socket?.Dispose(); } catch { } }

            if (retry >= ScanSocket.MaxLocalRetries) return new HostState(false, "socket-limit", 0, LocalError: true);
            if (!await ScanSocket.BackoffAsync(retry, ct).ConfigureAwait(false)) return new HostState(false, "tcp", 0);
        }
    }

    /// <summary>Same host, ignoring an IPv6 scope id (an ICMP error's sender carries none) and v4-mapped forms.</summary>
    public static bool SameAddress(IPAddress a, IPAddress b)
    {
        if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
        if (b.IsIPv4MappedToIPv6) b = b.MapToIPv4();
        if (a.AddressFamily != b.AddressFamily) return false;
        Span<byte> x = stackalloc byte[16], y = stackalloc byte[16];
        a.TryWriteBytes(x, out int lx);
        b.TryWriteBytes(y, out int ly);
        return x[..lx].SequenceEqual(y[..ly]);
    }

    // A LAN address: 10/8, 172.16/12, 192.168/16, link-local 169.254/16; IPv6 unique local fc00::/7 and link-local fe80::/10.
    private static bool IsLocalNetwork(IPAddress a)
    {
        if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
        var b = a.GetAddressBytes();
        if (a.AddressFamily == AddressFamily.InterNetwork)
            return b[0] == 10 || (b[0] == 172 && (b[1] & 0xF0) == 16) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254);
        return b.Length == 16 && ((b[0] & 0xFE) == 0xFC || (b[0] == 0xFE && (b[1] & 0xC0) == 0x80));
    }
}

/// <summary>Socket tweaks shared by the port scan and host discovery.</summary>
public static class ScanSocket
{
    /// <summary>Retries after a local socket error (<see cref="IsLocalExhaustion"/>) before a probe is given up as undetermined.</summary>
    public const int MaxLocalRetries = 3;

    /// <summary>
    /// True when a socket error means OUR side ran out of something — file descriptors (EMFILE; a macOS GUI app starts
    /// with a 256-fd limit), socket buffers, ephemeral ports — rather than anything the target did. Such a probe proves
    /// nothing: retry it, and never report it as filtered / down.
    /// </summary>
    public static bool IsLocalExhaustion(SocketError e) => e switch
    {
        SocketError.TooManyOpenSockets or SocketError.NoBufferSpaceAvailable or SocketError.ProcessLimit
            or SocketError.AddressAlreadyInUse => true,
        // EADDRNOTAVAIL is how Linux/macOS/Android say "no free ephemeral port"; Windows raises it for an invalid
        // destination instead (0.0.0.0, a subnet broadcast) — a fact about the target there.
        SocketError.AddressNotAvailable => !OperatingSystem.IsWindows(),
        _ => false,
    };

    /// <summary>
    /// Brief, jittered pause before retrying after a local socket error (50-99 / 100-149 / 150-199 ms): long enough for
    /// in-flight sockets to close, short enough not to stall the scan, jittered so a burst of failures doesn't retry in
    /// lockstep. False when cancelled meanwhile.
    /// </summary>
    public static async Task<bool> BackoffAsync(int retry, CancellationToken ct)
    {
        int ms = 50 * (Math.Clamp(retry, 0, 2) + 1) + Random.Shared.Next(50);
        try
        {
            await Task.Delay(ms, ct).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException) { return false; }
    }

    /// <summary>
    /// Windows retries the SYN after a RST, so a closed port takes ~1 s to be refused and reads as filtered whenever the
    /// timeout is shorter. Turning SYN retransmissions off makes the RST surface at once; the scanner's own retries
    /// cover a lost SYN. <paramref name="timeoutMs"/> becomes the initial RTO — with no retransmissions Windows fails
    /// the connect after it, and the default (1 s) silently cut every longer timeout short (Windows clamps it to
    /// ~0.3-3 s, so the slow templates leave retransmissions on). Windows only; failures are swallowed.
    /// </summary>
    public static void DisableSynRetransmissions(Socket socket, int timeoutMs)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            // SIO_TCP_INITIAL_RTO with TCP_INITIAL_RTO_PARAMETERS { USHORT Rtt (ms); UCHAR MaxSynRetransmissions =
            // 0xFE (TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS); pad }.
            int rtt = Math.Clamp(timeoutMs, 1, 0xFFFE);
            socket.IOControl(unchecked((int)0x98000011), new byte[] { (byte)rtt, (byte)(rtt >> 8), 0xFE, 0x00 }, null);
        }
        catch { /* not supported on this stack — keep the OS default */ }
    }

    /// <summary>Close with a RST (linger on, 0 s) instead of a FIN, so a big scan doesn't pile up TIME_WAIT sockets
    /// and run out of ephemeral ports. The caller still disposes the socket.</summary>
    public static void AbortiveClose(Socket socket)
    {
        try { socket.LingerState = new LingerOption(true, 0); } catch { }
    }
}
