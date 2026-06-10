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
    private List<long> _times = new();

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
        if (string.IsNullOrWhiteSpace(TargetHost)) return;

        HistoryService.Instance.Add("ping.host", TargetHost);

        Stop();

        _sent = 0;
        _received = 0;
        _times.Clear();
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
            UpdateLog($"Error: {message}");
            if (IsPermissionError(e)) UpdateLog(PermissionHint);
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
            UpdateLog("Error: Host not found");
            return;
        }

        int bytes = IcmpPinger.PayloadSize + 28; // ICMP header + IP header, classic ping accounting
        UpdateLog($"PING {TargetHost} ({addr}) {IcmpPinger.PayloadSize}({bytes}) bytes of data.");

        int seq = 1;
        while (!token.IsCancellationRequested)
        {
            _sent++;

            var r = await IcmpPinger.SendAsync(addr, 1500, token);
            if (token.IsCancellationRequested) break;

            if (r.PermissionDenied)
            {
                UpdateLog($"Ping error: {r.Error}");
                UpdateLog(PermissionHint);
                break;
            }

            if (r.Success)
            {
                _received++;
                _times.Add(r.RoundtripMs);
                string ttl = r.Ttl >= 0 ? r.Ttl.ToString() : "?";
                UpdateLog($"{bytes} bytes from {r.Address}: icmp_seq={seq} ttl={ttl} time={r.RoundtripMs} ms");
            }
            else
            {
                string extra = !string.IsNullOrEmpty(r.Error) && r.Error != "Request timed out" ? $" ({r.Error})" : "";
                UpdateLog($"Request timeout from {TargetHost}: icmp_seq={seq}{extra}");
            }

            UpdateStats();
            HandleAlerts(r.Success);

            seq++;
            await Task.Delay(1000, token);
        }
    }

    private async Task RunTraceRoute(CancellationToken token)
    {
        UpdateLog($"Tracing route to {TargetHost} over a maximum of 30 hops:");
        using var pinger = new Ping();
        var buffer = new byte[32];

        for (int ttl = 1; ttl <= 30; ttl++)
        {
            if (token.IsCancellationRequested) break;

            try
            {
                var options = new PingOptions(ttl, true);
                var sw = System.Diagnostics.Stopwatch.StartNew();
                var reply = await pinger.SendPingAsync(TargetHost, 2000, buffer, options).WaitAsync(token);
                sw.Stop();

                long elapsed = reply.Status == IPStatus.TimedOut ? 0 : sw.ElapsedMilliseconds;
                string timeStr = reply.Status == IPStatus.TimedOut ? "*" : $"{elapsed} ms";
                string addr = reply.Status == IPStatus.TimedOut ? "Request timed out." : reply.Address?.ToString() ?? "*";
                UpdateLog($"{ttl}\t{timeStr}\t{addr}");

                if (reply.Status == IPStatus.Success)
                {
                    UpdateLog("Trace complete.");
                    break;
                }
            }
            catch (OperationCanceledException) { break; }

            await Task.Delay(100, token);
        }
    }

    private void UpdateStats()
    {
        long lost = _sent - _received;
        double lossPercent = _sent > 0 ? ((double)lost / _sent) * 100 : 0;
        StatsSummary = $"Packets: Sent = {_sent}, Received = {_received}, Lost = {lost} ({lossPercent:F0}% loss)";
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
            (s.SocketErrorCode == System.Net.Sockets.SocketError.AccessDenied ||
             s.SocketErrorCode == System.Net.Sockets.SocketError.SocketError))
            return true;

        var msg = e.Message;
        return msg.Contains("Operation not permitted", StringComparison.OrdinalIgnoreCase)
            || msg.Contains("Permission denied", StringComparison.OrdinalIgnoreCase)
            || msg.Contains("Access denied", StringComparison.OrdinalIgnoreCase)
            || msg.Contains("not allowed", StringComparison.OrdinalIgnoreCase);
    }

    private const int MaxLogItems = 5000;

    private void UpdateLog(string m)
    {
        Dispatcher.UIThread.Post(() =>
        {
            LogItems.Add(m);
            while (LogItems.Count > MaxLogItems) LogItems.RemoveAt(0);
        });
    }
}