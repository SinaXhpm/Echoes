using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>The path MTU result: the largest packet that got through unfragmented, or why it couldn't be measured.</summary>
public sealed record DoctorMtuResult(int? Mtu, bool Exact, string? Skipped);

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

        var clock = Stopwatch.StartNew();
        int timeout = 1000;

        // does the target answer ping at all (twice: one loss shouldn't decide)
        var first = await SendAsync(addr, 128, timeout, ct).ConfigureAwait(false);
        if (first == Probe.Lost) first = await SendAsync(addr, 128, timeout, ct).ConfigureAwait(false);
        if (first == Probe.Denied) return new(null, false, "ICMP isn't permitted for this app here");
        if (first != Probe.Fits) return new(null, false, "the target doesn't answer ping, so it can't be measured");

        if (await SendTwiceAsync(addr, Full, timeout, ct).ConfigureAwait(false) == Probe.Fits) return new(Full, true, null);

        int lo = 128, hi = Full;
        while (hi - lo > 1)
        {
            if (clock.ElapsedMilliseconds > budgetMs) return new(lo, false, null);
            int mid = (lo + hi) / 2;
            var r = await SendTwiceAsync(addr, mid, timeout, ct).ConfigureAwait(false);
            if (r == Probe.Denied) return new(null, false, "ICMP isn't permitted for this app here");
            if (r == Probe.Fits) lo = mid;
            else hi = mid;   // too big, or silently dropped twice (a black hole)
        }
        return new(lo, true, null);
    }

    // a lost probe is tried once more before it counts as "too big"
    private static async Task<Probe> SendTwiceAsync(IPAddress addr, int size, int timeout, CancellationToken ct)
    {
        var r = await SendAsync(addr, size, timeout, ct).ConfigureAwait(false);
        return r == Probe.Lost ? await SendAsync(addr, size, timeout, ct).ConfigureAwait(false) : r;
    }

    private static Task<Probe> SendAsync(IPAddress addr, int size, int timeout, CancellationToken ct)
    {
        if (OperatingSystem.IsWindows()) return WindowsAsync(addr, size, timeout, ct);
        if (OperatingSystem.IsLinux() || OperatingSystem.IsAndroid()) return DatagramAsync(addr, size, timeout, ct);
        return Task.FromResult(Probe.Denied);
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
            s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Icmp);
        }
        catch (SocketException) { return Probe.Denied; }
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
