using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>
/// Cross-platform ICMP echo ("ping") that works without root.
///
/// On Windows/macOS it uses the managed <see cref="Ping"/> class (reliable, no
/// privileges needed). On Linux/Android it opens an unprivileged ICMP *datagram*
/// socket (SOCK_DGRAM, IPPROTO_ICMP) and builds the echo packet by hand — Android
/// keeps net.ipv4.ping_group_range open for all apps, so this works in the sandbox
/// with only the INTERNET permission, and on desktop Linux it avoids needing sudo
/// wherever ping_group_range allows the caller's gid.
/// </summary>
public static class IcmpPinger
{
    public readonly record struct PingResult(
        bool Success,
        long RoundtripMs,
        IPAddress? Address,
        int Ttl,            // -1 when unknown (datagram sockets don't expose the reply TTL)
        string? Error,
        bool PermissionDenied);

    // 32-byte payload, like classic ping ('a'..).
    private static readonly byte[] DefaultPayload =
        Enumerable.Range(0, 32).Select(i => (byte)('a' + (i % 23))).ToArray();

    public const int PayloadSize = 32;

    private static int _seq;

    public static async Task<IPAddress> ResolveAsync(string host, CancellationToken token)
    {
        if (IPAddress.TryParse(host, out var ip)) return ip;
        var addrs = await Dns.GetHostAddressesAsync(host, token);
        // Prefer IPv4 — the datagram path below is IPv4-only.
        return addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
               ?? addrs.FirstOrDefault()
               ?? throw new SocketException((int)SocketError.HostNotFound);
    }

    public static Task<PingResult> SendAsync(IPAddress addr, int timeoutMs, CancellationToken token, int ttl = 0)
    {
        // Windows/macOS: managed Ping is privilege-free and gives us the reply TTL.
        // IPv6 also falls back to managed Ping (datagram path is IPv4-only).
        if (OperatingSystem.IsWindows() || OperatingSystem.IsMacOS()
            || addr.AddressFamily != AddressFamily.InterNetwork)
            return SendManagedAsync(addr, timeoutMs, ttl, token);

        return SendDatagramAsync(addr, timeoutMs, ttl, token);
    }

    private static async Task<PingResult> SendManagedAsync(IPAddress addr, int timeoutMs, int ttl, CancellationToken token)
    {
        using var ping = new Ping();
        try
        {
            var options = ttl > 0 ? new PingOptions(ttl, true) : null;
            PingReply reply = options != null
                ? await ping.SendPingAsync(addr, timeoutMs, DefaultPayload, options).WaitAsync(token)
                : await ping.SendPingAsync(addr, timeoutMs, DefaultPayload).WaitAsync(token);

            bool ok = reply.Status == IPStatus.Success;
            return new PingResult(ok, reply.RoundtripTime, reply.Address ?? addr,
                reply.Options?.Ttl ?? -1, ok ? null : reply.Status.ToString(), false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            var e = ex is PingException pe && pe.InnerException != null ? pe.InnerException : ex;
            bool perm = IsPermissionError(e);
            return new PingResult(false, 0, null, -1, e.Message, perm);
        }
    }

    private static async Task<PingResult> SendDatagramAsync(IPAddress addr, int timeoutMs, int ttl, CancellationToken token)
    {
        Socket? sock = null;
        try
        {
            sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Icmp);
            if (ttl > 0) sock.Ttl = (short)ttl;

            var ep = new IPEndPoint(addr, 0);
            ushort id = (ushort)(Environment.ProcessId & 0xFFFF); // kernel overrides this for datagram sockets
            ushort seq = (ushort)(Interlocked.Increment(ref _seq) & 0xFFFF);
            byte[] packet = BuildEchoRequest(id, seq, DefaultPayload);

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeoutCts.CancelAfter(timeoutMs);

            var sw = Stopwatch.StartNew();
            await sock.SendToAsync(packet, SocketFlags.None, ep, timeoutCts.Token);

            var buffer = new byte[1024];
            while (true)
            {
                var r = await sock.ReceiveFromAsync(buffer, SocketFlags.None, ep, timeoutCts.Token);
                long elapsed = sw.ElapsedMilliseconds;
                if (r.ReceivedBytes < 1) continue;

                byte type = buffer[0]; // datagram socket: payload starts at the ICMP header (no IP header)
                var from = (r.RemoteEndPoint as IPEndPoint)?.Address ?? addr;

                if (type == 0)  return new PingResult(true, elapsed, from, -1, null, false);   // echo reply
                if (type == 11) return new PingResult(false, elapsed, from, -1, "TTL expired", false); // time exceeded
                // anything else: ignore and keep waiting until the deadline fires the token
            }
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        {
            return new PingResult(false, timeoutMs, null, -1, "Request timed out", false);
        }
        catch (OperationCanceledException) { throw; }
        catch (SocketException ex) when (IsPermissionError(ex))
        {
            return new PingResult(false, 0, null, -1, ex.Message, true);
        }
        catch (Exception ex)
        {
            return new PingResult(false, 0, null, -1, ex.Message, false);
        }
        finally
        {
            sock?.Dispose();
        }
    }

    private static byte[] BuildEchoRequest(ushort id, ushort seq, byte[] payload)
    {
        int len = 8 + payload.Length;
        var p = new byte[len];
        p[0] = 8;            // type: echo request
        p[1] = 0;            // code
        p[2] = 0; p[3] = 0;  // checksum (filled below; kernel recomputes for datagram sockets too)
        p[4] = (byte)(id >> 8);  p[5] = (byte)(id & 0xFF);
        p[6] = (byte)(seq >> 8); p[7] = (byte)(seq & 0xFF);
        Array.Copy(payload, 0, p, 8, payload.Length);

        ushort cs = Checksum(p);
        p[2] = (byte)(cs >> 8);
        p[3] = (byte)(cs & 0xFF);
        return p;
    }

    private static ushort Checksum(byte[] data)
    {
        uint sum = 0;
        int i = 0;
        for (; i + 1 < data.Length; i += 2)
            sum += (uint)((data[i] << 8) | data[i + 1]);
        if (i < data.Length)
            sum += (uint)(data[i] << 8);
        while ((sum >> 16) != 0)
            sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }

    private static bool IsPermissionError(Exception e)
    {
        if (e is SocketException s &&
            (s.SocketErrorCode == SocketError.AccessDenied ||
             s.SocketErrorCode == SocketError.SocketError))
            return true;

        var msg = e.Message;
        return msg.Contains("Operation not permitted", StringComparison.OrdinalIgnoreCase)
            || msg.Contains("Permission denied", StringComparison.OrdinalIgnoreCase)
            || msg.Contains("Access denied", StringComparison.OrdinalIgnoreCase)
            || msg.Contains("not allowed", StringComparison.OrdinalIgnoreCase);
    }
}
