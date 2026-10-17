using Echoes.Helpers;
using System;
using System.Diagnostics;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

// TCP mode: a TCP connect to host:port every interval, timed SYN → SYN/ACK, then closed (TcpPinger). Same statistics,
// graph, log and up / down alerts as ICMP ping; a refused connection, a silent drop and a failed DNS lookup each say so.
public partial class PingViewModel
{
    /// <summary>Replaces the network in TCP mode (tests): (address, port, timeoutMs, token) → result.</summary>
    internal Func<IPAddress, int, int, CancellationToken, Task<TcpPinger.Result>>? TcpProbe { get; set; }

    private async Task RunTcpLoop(string host, int port, IpPreference ip, CancellationToken token)
    {
        IPAddress addr;
        try
        {
            addr = await PingTarget.ResolveAsync(host, ip, token);
        }
        catch (OperationCanceledException) { return; }
        catch (Exception ex)
        {
            UpdateLog("Error: " + ex.Message, token);
            return;
        }

        string ep = PingTarget.Endpoint(addr, port);
        string label = host + ":" + port;
        UpdateLog($"TCP PING {host} ({addr}) port {port}: connect time, SYN to SYN/ACK", token);
        NoteIpMismatch(host, addr, ip, token);

        var probe = TcpProbe ?? TcpPinger.ConnectAsync;
        bool finished = false;
        for (long seq = 1; !token.IsCancellationRequested; seq++)
        {
            var s = _settings;
            long t0 = Stopwatch.GetTimestamp();
            _sent++;

            TcpPinger.Result r;
            try { r = await probe(addr, port, s.TimeoutMs, token); }
            catch (OperationCanceledException) { break; }
            if (token.IsCancellationRequested) break;

            string ms = Ms(r.Ms);
            switch (r.Status)
            {
                case TcpPinger.Status.Connected:
                    _received++;
                    UpdateLog($"Connected to {ep}: seq={seq} time={ms} ms", token);
                    break;
                case TcpPinger.Status.Refused:
                    UpdateLog($"Refused by {ep}: seq={seq} time={ms} ms (RST: host up, port closed)", token);
                    break;
                case TcpPinger.Status.Rejected:
                    UpdateLog($"Rejected by {r.From}: seq={seq} ({r.Detail})", token);
                    break;
                case TcpPinger.Status.Timeout:
                    // the timeout set, unless the system gave up sooner (Windows caps a single SYN's wait at ~3 s)
                    int waited = r.Ms + 50 < s.TimeoutMs ? (int)Math.Round(r.Ms / 100) * 100 : s.TimeoutMs;
                    UpdateLog($"Timeout {ep}: seq={seq} (no answer in {PingSettings.Seconds(Math.Max(100, waited))}: dropped or filtered)", token);
                    break;
                case TcpPinger.Status.Unreachable:
                    UpdateLog(r.From is { } via
                        ? $"From {via}: seq={seq} {r.Detail} (to {ep})"
                        : $"Unreachable {ep}: seq={seq} ({r.Detail})", token);
                    break;
                case TcpPinger.Status.LocalError:
                    UpdateLog($"Not sent: seq={seq} ({r.Detail})", token);
                    break;
                case TcpPinger.Status.Unsupported:
                    // no later probe can work (no IPv6 here): one clear error, not one per interval
                    _sent--;
                    UpdateLog($"Error: can't connect to {addr}: {r.Detail}.", token);
                    return;
                default:
                    UpdateLog($"Failed {ep}: seq={seq} ({r.Detail})", token);
                    break;
            }

            UpdateStats(token, label, r.Success ? r.Ms : double.NaN, tcp: true);
            HandleAlerts(r.Success);

            if (s.Count > 0 && seq >= s.Count) { finished = true; break; }
            await WaitInterval(t0, token);
        }
        if (finished) LogSummary(token);
    }
}
