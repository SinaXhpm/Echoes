using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>
/// TCP "ping" (the Ping tab's TCP mode): one TCP connect per probe, timed from the SYN to the SYN/ACK (the moment the
/// connect completes), then closed. Needs no ICMP and no privileges, so it works on Android and wherever ping is
/// blocked. Built from the port scanner's own pieces — <see cref="ScanOp"/> (an exception-free connect, timestamped
/// when the OS completes it), <see cref="ScanSocket.DisableSynRetransmissions"/> (one SYN per probe; a Windows RST
/// surfaces at once) and <see cref="ScanIcmp"/> (Linux / Android: who sent an ICMP error) — without changing the
/// scanner: it only calls them.
/// </summary>
public static class TcpPinger
{
    public enum Status
    {
        /// <summary>SYN/ACK: the port is open; <see cref="Result.Ms"/> is the connect time.</summary>
        Connected,
        /// <summary>The host answered with a RST: it is up, the port is closed.</summary>
        Refused,
        /// <summary>Someone on the way (a firewall, a router) answered with an ICMP error instead (Linux / Android).</summary>
        Rejected,
        /// <summary>No answer before the timeout: dropped or filtered on the way, or the host is down.</summary>
        Timeout,
        /// <summary>No route: host / network unreachable (this computer or a router said so).</summary>
        Unreachable,
        /// <summary>Our side ran out of sockets / ports: no SYN left this computer.</summary>
        LocalError,
        /// <summary>This computer can't connect to this kind of address at all (no IPv6): no later probe can work.</summary>
        Unsupported,
        /// <summary>Anything else; <see cref="Result.Detail"/> says what.</summary>
        Failed,
    }

    /// <param name="Status">How the probe ended.</param>
    /// <param name="Ms">Connect time (SYN → SYN/ACK) or, for a refusal, the RST's round trip; the time waited otherwise.</param>
    /// <param name="From">Who sent an ICMP error (Linux / Android), else null.</param>
    /// <param name="Detail">A short plain-English reason for anything but <see cref="Status.Connected"/>.</param>
    public readonly record struct Result(Status Status, double Ms, IPAddress? From, string Detail)
    {
        public bool Success => Status == Status.Connected;
    }

    /// <summary>One TCP connect to <paramref name="addr"/>:<paramref name="port"/>, closed again at once (a normal FIN
    /// close). Never throws except <see cref="OperationCanceledException"/> when <paramref name="ct"/> is cancelled.</summary>
    public static async Task<Result> ConnectAsync(IPAddress addr, int port, int timeoutMs, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        timeoutMs = Math.Max(1, timeoutMs);
        Socket? socket = null;
        try
        {
            SocketError err;
            double ms = 0;
            ScanIcmp.Error? icmp = null;
            try
            {
                // Created inside the try: new Socket(InterNetworkV6) throws without IPv6 (and EMFILE when out of fds).
                socket = new Socket(addr.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                // One SYN per probe: a lost SYN is a lost probe, as with an ICMP echo. On Windows this also makes a
                // RST surface at once (it otherwise retries the SYN and reports the refusal only after ~1 s).
                ScanSocket.DisableSynRetransmissions(socket, timeoutMs);
                ScanIcmp.Enable(socket);
                using var op = new ScanOp();
                long t0 = Stopwatch.GetTimestamp();
                err = await op.ConnectAsync(socket, new IPEndPoint(addr, Math.Clamp(port, 1, 65535)), timeoutMs, ct).ConfigureAwait(false);
                ms = Stopwatch.GetElapsedTime(t0, op.CompletedTicks).TotalMilliseconds;
                if (err is not (SocketError.Success or SocketError.TimedOut or SocketError.OperationAborted))
                    icmp = ScanIcmp.Read(socket);
            }
            catch (SocketException se) { err = se.SocketErrorCode; }
            ct.ThrowIfCancellationRequested();
            if (ms < 0) ms = 0;

            switch (err)
            {
                case SocketError.Success:
                    return new Result(Status.Connected, ms, null, string.Empty);
                case SocketError.ConnectionRefused:
                    // Linux / Android also report an ICMP "port unreachable" as a refusal: from the host itself it is
                    // still "closed"; from anyone else it's a firewall on the way rejecting the SYN.
                    if (icmp is { } ie && ie.From is { } from && !ScanDiscovery.SameAddress(from, addr))
                        return new Result(Status.Rejected, ms, from, Reason(ie));
                    return new Result(Status.Refused, ms, null, "RST: port closed");
                case SocketError.TimedOut or SocketError.OperationAborted:
                    return new Result(Status.Timeout, ms, null, "no SYN/ACK: dropped or filtered");
                case SocketError.HostUnreachable or SocketError.NetworkUnreachable or SocketError.HostDown or SocketError.NetworkDown:
                    return new Result(Status.Unreachable, ms, icmp?.From,
                        icmp is { } u ? Reason(u)
                        : err == SocketError.NetworkUnreachable || err == SocketError.NetworkDown ? "network unreachable" : "host unreachable");
                case SocketError.AddressFamilyNotSupported or SocketError.ProtocolNotSupported or SocketError.ProtocolFamilyNotSupported:
                    return new Result(Status.Unsupported, 0, null,
                        addr.AddressFamily == AddressFamily.InterNetworkV6 ? "this computer has no IPv6" : "this address type isn't supported here");
                case var e when ScanSocket.IsLocalExhaustion(e):
                    return new Result(Status.LocalError, 0, null, "out of sockets or ports on this computer: no SYN was sent");
                case SocketError.AccessDenied:
                    return new Result(Status.Failed, ms, null, "blocked on this computer (firewall or permission)");
                default:
                    return new Result(Status.Failed, ms, icmp?.From, icmp is { } o ? Reason(o) : Describe(err));
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { return new Result(Status.Failed, 0, null, ex.Message); }
        finally
        {
            try { socket?.Dispose(); } catch { }
        }
    }

    // An ICMP error in words (nmap's reason names are for the scanner's table, not for a sentence).
    private static string Reason(ScanIcmp.Error e) => e.Type switch
    {
        3 => e.Code switch
        {
            0 or 6 => "ICMP network unreachable",
            1 or 7 => "ICMP host unreachable",
            3 => "ICMP port unreachable: a firewall rejected it",
            9 or 10 or 13 => "ICMP administratively prohibited: a firewall rejected it",
            _ => "ICMP destination unreachable",
        },
        11 => "ICMP time exceeded",
        _ => "ICMP error",
    };

    // "HostNotFound" → "host not found"
    private static string Describe(SocketError e)
    {
        string s = e.ToString();
        var sb = new System.Text.StringBuilder(s.Length + 8);
        for (int i = 0; i < s.Length; i++)
        {
            if (i > 0 && char.IsUpper(s[i])) sb.Append(' ');
            sb.Append(char.ToLowerInvariant(s[i]));
        }
        return sb.ToString();
    }
}
