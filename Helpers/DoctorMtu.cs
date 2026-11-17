using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>The path MTU result: the largest packet that got through unfragmented, or why it couldn't be measured, and
/// every probe on the way (the search, step by step).</summary>
public sealed record DoctorMtuResult(int? Mtu, bool Exact, string? Skipped, IReadOnlyList<DoctorMtuProbe>? Probes = null);

/// <summary>One probe of the search: a packet of <paramref name="Size"/> bytes with Don't-Fragment, and what became of it
/// ("passes", "too big", "lost", "not permitted").</summary>
public sealed record DoctorMtuProbe(int Size, string Result);

/// <summary>
/// Path MTU to the target: the largest IPv4 packet that passes with Don't-Fragment set, by binary search with ping.
/// Windows: the system's ICMP API (managed Ping, DontFragment) — no admin needed. Linux / Android: an unprivileged ICMP
/// datagram socket with IP_MTU_DISCOVER = IP_PMTUDISC_DO, so an oversized probe fails with EMSGSIZE or never returns.
/// Elsewhere (macOS: the ping utility won't take a custom payload) it is skipped with a note.
/// </summary>
public static class DoctorMtu
{
    private enum Probe { Fits, TooBig, Lost, Denied }

    public const int Full = 1500;
    /// <summary>Below this a tunnel is on the way (1480–1499 is a DSL / PPPoE line: normal, routers clamp TCP for it).</summary>
    public const int Small = 1480;
    private const int Headers = 28;   // IPv4 20 + ICMP 8

    public static async Task<DoctorMtuResult> MeasureAsync(IPAddress addr, int budgetMs, CancellationToken ct)
    {
        addr = DoctorIp.Normal(addr);
        if (addr.AddressFamily != AddressFamily.InterNetwork) return new(null, false, "measured for IPv4 targets only");
        if (!(OperatingSystem.IsWindows() || OperatingSystem.IsLinux() || OperatingSystem.IsAndroid()))
            return new(null, false, "not measured on this system");
        if (DoctorNet.From?.Missing(addr) is { } missing) return new(null, false, missing);   // the chosen interface has no IPv4

        var clock = Stopwatch.StartNew();
        int timeout = 1000;
        var probes = new List<DoctorMtuProbe>();
        async Task<Probe> Try(int size, bool twice)
        {
            var r = twice ? await SendTwiceAsync(addr, size, timeout, ct).ConfigureAwait(false) : await SendAsync(addr, size, timeout, ct).ConfigureAwait(false);
            probes.Add(new DoctorMtuProbe(size, r switch { Probe.Fits => "passes", Probe.TooBig => "too big", Probe.Lost => "lost", _ => "not permitted" }));
            return r;
        }

        // does the target answer ping at all (twice: one loss shouldn't decide)
        var first = await Try(128, twice: false).ConfigureAwait(false);
        if (first == Probe.Lost) first = await Try(128, twice: false).ConfigureAwait(false);
        if (first == Probe.Denied) return new(null, false, "ICMP isn't permitted for this app here", probes);
        if (first != Probe.Fits) return new(null, false, "the target doesn't answer ping, so it can't be measured", probes);

        if (await Try(Full, twice: true).ConfigureAwait(false) == Probe.Fits) return new(Full, true, null, probes);

        int lo = 128, hi = Full;
        while (hi - lo > 1)
        {
            if (clock.ElapsedMilliseconds > budgetMs) return new(lo, false, null, probes);
            int mid = (lo + hi) / 2;
            var r = await Try(mid, twice: true).ConfigureAwait(false);
            if (r == Probe.Denied) return new(null, false, "ICMP isn't permitted for this app here", probes);
            if (r == Probe.Fits) lo = mid;
            else hi = mid;   // too big, or silently dropped twice (a black hole)
        }
        return new(lo, true, null, probes);
    }

    // a lost probe is tried once more before it counts as "too big"
    private static async Task<Probe> SendTwiceAsync(IPAddress addr, int size, int timeout, CancellationToken ct)
    {
        var r = await SendAsync(addr, size, timeout, ct).ConfigureAwait(false);
        return r == Probe.Lost ? await SendAsync(addr, size, timeout, ct).ConfigureAwait(false) : r;
    }

    private static Task<Probe> SendAsync(IPAddress addr, int size, int timeout, CancellationToken ct)
    {
        if (OperatingSystem.IsWindows())
            return DoctorNet.From is { } via ? FromAsync(via, addr, size, timeout, ct) : WindowsAsync(addr, size, timeout, ct);
        if (OperatingSystem.IsLinux() || OperatingSystem.IsAndroid()) return DatagramAsync(addr, size, timeout, ct);
        return Task.FromResult(Probe.Denied);
    }

    // Windows, from a chosen interface: the managed Ping can't send from one, the pinger can (with the same size and
    // Don't-Fragment, as an ICMP probe only: a UDP fallback measures nothing here)
    private static async Task<Probe> FromAsync(NetIface via, IPAddress addr, int size, int timeout, CancellationToken ct)
    {
        var r = await IcmpPinger.SendAsync(addr, timeout, new IcmpProbeOptions(size - Headers, 64, DontFragment: true, Via: via), ct,
                                           PingMethod.Icmp).ConfigureAwait(false);
        if (r.Success) return Probe.Fits;
        if (r.Error == IcmpPinger.PacketTooBig) return Probe.TooBig;
        return r.PermissionDenied ? Probe.Denied : Probe.Lost;
    }

    [SupportedOSPlatform("windows")]
    private static async Task<Probe> WindowsAsync(IPAddress addr, int size, int timeout, CancellationToken ct)
    {
        using var ping = new Ping();
        try
        {
            var reply = await ping.SendPingAsync(addr, TimeSpan.FromMilliseconds(timeout), new byte[size - Headers],
                                                 new PingOptions(64, dontFragment: true)).WaitAsync(ct).ConfigureAwait(false);
            return reply.Status switch
            {
                IPStatus.Success => Probe.Fits,
                IPStatus.PacketTooBig => Probe.TooBig,
                _ => Probe.Lost,
            };
        }
        catch (OperationCanceledException) { throw; }
        catch (PingException e) when (e.InnerException is SocketException { SocketErrorCode: SocketError.AccessDenied }) { return Probe.Denied; }
        catch { return Probe.Lost; }
    }

    // Linux / Android: the ping socket (no privileges) with Don't-Fragment forced on.
    private const int SolIp = 0, IpMtuDiscover = 10, IpPmtuDiscDo = 2;

    private static async Task<Probe> DatagramAsync(IPAddress addr, int size, int timeout, CancellationToken ct)
    {
        Socket s;
        try
        {
            s = DoctorNet.NewSocket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Icmp);
        }
        catch (SocketException) { return Probe.Denied; }
        catch (NetIfaceException) { return Probe.Lost; }   // the chosen interface went away meanwhile
        using (s)
        {
            try { s.SetRawSocketOption(SolIp, IpMtuDiscover, BitConverter.GetBytes(IpPmtuDiscDo)); }
            catch (SocketException) { return Probe.Denied; }

            byte[] packet = new byte[size - 20];   // ICMP header + payload; the kernel adds the IP header
            packet[0] = 8;                         // echo request (the kernel sets the id and the checksum)
            ushort seq = (ushort)Random.Shared.Next(1, 65535);
            packet[6] = (byte)(seq >> 8);
            packet[7] = (byte)seq;
            for (int i = 8; i < packet.Length; i++) packet[i] = (byte)('a' + i % 23);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            var ep = new IPEndPoint(addr, 0);
            try
            {
                await s.SendToAsync(packet, SocketFlags.None, ep, cts.Token).ConfigureAwait(false);
                var buf = new byte[2048];
                while (true)
                {
                    var r = await s.ReceiveFromAsync(buf, SocketFlags.None, ep, cts.Token).ConfigureAwait(false);
                    if (r.ReceivedBytes > 0 && buf[0] == 0) return Probe.Fits;   // echo reply
                }
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return Probe.Lost; }
            catch (OperationCanceledException) { throw; }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.MessageSize) { return Probe.TooBig; }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.AccessDenied) { return Probe.Denied; }
            catch { return Probe.Lost; }
        }
    }
}
