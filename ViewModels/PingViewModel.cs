using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;

namespace Echoes.ViewModels;

public partial class PingViewModel : ObservableObject
{
    [ObservableProperty] private string _targetHost = string.Empty;
    [ObservableProperty] private bool _isPinging;
    [ObservableProperty] private bool _isTraceRoute;
    [ObservableProperty] private bool _notifyOnline;
    [ObservableProperty] private bool _notifyOffline;
    [ObservableProperty] private string _statsSummary = "Packets: Sent = 0, Received = 0, Lost = 0";

    public ObservableCollection<string> LogItems { get; } = new();

    public ObservableCollection<string> TargetHostHistory => HistoryService.Instance.Get("ping.host");

    public PingViewModel()
    {
        if (HistoryService.Instance.Last("ping.host") is { } last) TargetHost = last;
    }

    private CancellationTokenSource? _cts;
    private bool? _lastStatus;
    private long _sent;
    private long _received;

    [RelayCommand]
    private void TogglePing()
    {
        if (IsPinging) Stop();
        else Start();
    }

    [RelayCommand]
    private async Task CopyLog()
        => await Helpers.ClipboardHelper.SetTextAsync(string.Join(Environment.NewLine, LogItems));

    private void Start()
    {
        // Accept a pasted URL / "host:port" / "user@host" and reduce it to the bare host.
        TargetHost = HostExtractor.Extract(TargetHost);
        if (string.IsNullOrWhiteSpace(TargetHost)) return;

        HistoryService.Instance.Add("ping.host", TargetHost);

        Stop();

        _sent = 0;
        _received = 0;
        Dispatcher.UIThread.Invoke(() => LogItems.Clear());
        StatsSummary = "Packets: Sent = 0, Received = 0, Lost = 0";

        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        IsPinging = true;
        Task.Run(() => RunProcess(token), token);
    }

    private void Stop()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
        IsPinging = false;
    }

    private async Task RunProcess(CancellationToken token)
    {
        try
        {
            if (IsTraceRoute) await RunTraceRoute(token);
            else await RunPingLoop(token);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (token.IsCancellationRequested) return;

            var e = ex is PingException pe && pe.InnerException != null ? pe.InnerException : ex;
            string message = e switch
            {
                System.Net.Sockets.SocketException s when s.SocketErrorCode == System.Net.Sockets.SocketError.HostNotFound => "Host not found",
                System.Net.Sockets.SocketException s when s.SocketErrorCode == System.Net.Sockets.SocketError.AddressFamilyNotSupported => "Invalid address",
                System.Net.Sockets.SocketException s when s.SocketErrorCode == System.Net.Sockets.SocketError.NetworkUnreachable => "Network unreachable",
                _ => e.Message
            };
            UpdateLog($"Error: {message}", token);
            if (IsPermissionError(e)) UpdateLog(PermissionHint, token);
        }
        finally
        {
            if (!token.IsCancellationRequested)
            {
                Dispatcher.UIThread.Post(() => IsPinging = false);
            }
        }
    }

    private async Task RunPingLoop(CancellationToken token)
    {
        System.Net.IPAddress addr;
        try
        {
            addr = await IcmpPinger.ResolveAsync(TargetHost, token);
        }
        catch (OperationCanceledException) { return; }
        catch
        {
            UpdateLog("Error: Host not found", token);
            return;
        }

        int bytes = IcmpPinger.PayloadSize + 28; // ICMP header + IP header, classic ping accounting
        UpdateLog($"PING {TargetHost} ({addr}) {IcmpPinger.PayloadSize}({bytes}) bytes of data.", token);

        int seq = 1;
        while (!token.IsCancellationRequested)
        {
            _sent++;

            var r = await IcmpPinger.SendAsync(addr, 1500, token);
            if (token.IsCancellationRequested) break;

            if (r.PermissionDenied)
            {
                UpdateLog($"Ping error: {r.Error}", token);
                UpdateLog(PermissionHint, token);
                break;
            }

            if (r.Success)
            {
                _received++;
                string ttl = r.Ttl >= 0 ? r.Ttl.ToString() : "?";
                UpdateLog($"{bytes} bytes from {r.Address}: icmp_seq={seq} ttl={ttl} time={r.RoundtripMs} ms", token);
            }
            else
            {
                string extra = !string.IsNullOrEmpty(r.Error) && r.Error != "Request timed out" ? $" ({r.Error})" : "";
                UpdateLog($"Request timeout from {TargetHost}: icmp_seq={seq}{extra}", token);
            }

            UpdateStats(token);
            HandleAlerts(r.Success);

            seq++;
            await Task.Delay(1000, token);
        }
    }

    private async Task RunTraceRoute(CancellationToken token)
    {
        UpdateLog($"Tracing route to {TargetHost} over a maximum of 30 hops:", token);

        System.Net.IPAddress target;
        try
        {
            target = await IcmpPinger.ResolveAsync(TargetHost, token);
        }
        catch (OperationCanceledException) { return; }
        catch (Exception ex)
        {
            UpdateLog($"Unable to resolve {TargetHost}: {ex.Message}", token);
            return;
        }

        for (int ttl = 1; ttl <= 30; ttl++)
        {
            if (token.IsCancellationRequested) break;

            IcmpPinger.PingResult r;
            try
            {
                // Unprivileged ICMP that also works on Android/Linux without root (raw Ping needs it).
                r = await IcmpPinger.SendAsync(target, 2000, token, ttl);
            }
            catch (OperationCanceledException) { break; }

            if (r.PermissionDenied)
            {
                UpdateLog("Traceroute needs ICMP permission, which isn't available on this platform.", token);
                break;
            }

            // A real intermediate hop is any responder that isn't the 0.0.0.0 placeholder used for timeouts.
            bool hasHop = r.Address != null && !r.Address.Equals(System.Net.IPAddress.Any);
            if (r.Success)
            {
                UpdateLog($"{ttl}\t{r.RoundtripMs} ms\t{r.Address}", token);
                UpdateLog("Trace complete.", token);
                break;
            }

            if (hasHop)
                UpdateLog($"{ttl}\t{r.RoundtripMs} ms\t{r.Address}", token);
            else
                UpdateLog($"{ttl}\t*\tRequest timed out.", token);

            await Task.Delay(100, token);
        }
    }

    private void UpdateStats(CancellationToken token)
    {
        long lost = _sent - _received;
        double lossPercent = _sent > 0 ? ((double)lost / _sent) * 100 : 0;
        var text = $"Packets: Sent = {_sent}, Received = {_received}, Lost = {lost} ({lossPercent:F0}% loss)";
        // StatsSummary is data-bound; this runs from the background ping loop, so marshal it.
        // Skip if this session was cancelled — a stale post must not overwrite a newer run.
        Dispatcher.UIThread.Post(() => { if (!token.IsCancellationRequested) StatsSummary = text; });
    }

    private void HandleAlerts(bool current)
    {
        if (_lastStatus.HasValue && _lastStatus != current)
        {
            if ((current && NotifyOnline) || (!current && NotifyOffline))
            {
                SoundHelper.PlayNotify(current);
            }
        }
        _lastStatus = current;
    }

    private static readonly string PermissionHint =
        OperatingSystem.IsLinux()
            ? "Hint: ICMP on Linux needs privileges. Run:  sudo sysctl -w net.ipv4.ping_group_range=\"0 2147483647\"  (or launch Echoes with sudo)."
            : "Hint: raw ICMP sockets require elevated privileges on this platform.";

    private static bool IsPermissionError(Exception e)
    {
        if (e is System.Net.Sockets.SocketException s &&
            s.SocketErrorCode == System.Net.Sockets.SocketError.AccessDenied)
            return true;

        var msg = e.Message;
        return msg.Contains("Operation not permitted", StringComparison.OrdinalIgnoreCase)
            || msg.Contains("Permission denied", StringComparison.OrdinalIgnoreCase)
            || msg.Contains("Access denied", StringComparison.OrdinalIgnoreCase)
            || msg.Contains("not allowed", StringComparison.OrdinalIgnoreCase);
    }

    private const int MaxLogItems = 5000;

    private void UpdateLog(string m, CancellationToken token)
    {
        Dispatcher.UIThread.Post(() =>
        {
            // A stray line queued by a just-cancelled session must NOT land after the next run cleared
            // the list — otherwise old lines linger and mix with the new run's output.
            if (token.IsCancellationRequested) return;
            LogItems.Add(m);
            while (LogItems.Count > MaxLogItems) LogItems.RemoveAt(0);
        });
    }
}