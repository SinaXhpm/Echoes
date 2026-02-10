using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

public partial class PingViewModel : ObservableObject
{
    [ObservableProperty] private string _targetHost = string.Empty;
    [ObservableProperty] private string _logText = string.Empty;
    [ObservableProperty] private bool _isPinging;
    [ObservableProperty] private bool _isTraceRoute;
    [ObservableProperty] private bool _notifyOnline;
    [ObservableProperty] private bool _notifyOffline;
    [ObservableProperty] private string _statsSummary = "Packets: Sent = 0, Received = 0, Lost = 0";

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

    private void Start()
    {
        if (string.IsNullOrWhiteSpace(TargetHost)) return;
        IsPinging = true;
        _sent = 0; _received = 0; _times.Clear();
        LogText = string.Empty;
        _cts = new CancellationTokenSource();
        Task.Run(() => RunProcess(_cts.Token));
    }

    private void Stop()
    {
        _cts?.Cancel();
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
            var e = ex is System.Net.NetworkInformation.PingException pe && pe.InnerException != null ? pe.InnerException : ex;

            string message = e switch
            {
                System.Net.Sockets.SocketException s when s.SocketErrorCode == System.Net.Sockets.SocketError.HostNotFound => "Host not found",
                System.Net.Sockets.SocketException s when s.SocketErrorCode == System.Net.Sockets.SocketError.AddressFamilyNotSupported => "Invalid address",
                System.Net.Sockets.SocketException s when s.SocketErrorCode == System.Net.Sockets.SocketError.NetworkUnreachable => "Network unreachable",
                _ => e.Message
            };

            UpdateLog($"Error: {message}");
        }
        finally
        {
            IsPinging = false;
        }
    }

    private async Task RunPingLoop(CancellationToken token)
    {
        using var pinger = new Ping();
        UpdateLog($"PING {TargetHost} ({TargetHost}) 32(60) bytes of data.");

        int seq = 1;
        while (!token.IsCancellationRequested)
        {
            _sent++;
            var reply = await pinger.SendPingAsync(TargetHost, 1500);
            bool success = reply.Status == IPStatus.Success;

            if (success)
            {
                _received++;
                _times.Add(reply.RoundtripTime);
                UpdateLog($"{reply.Buffer.Length + 28} bytes from {reply.Address}: icmp_seq={seq} ttl={reply.Options?.Ttl} time={reply.RoundtripTime} ms");
            }
            else
            {
                UpdateLog($"Request timeout for icmp_seq {seq}");
            }

            UpdateStats();
            HandleAlerts(success);
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

            var options = new PingOptions(ttl, true);
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var reply = await pinger.SendPingAsync(TargetHost, 2000, buffer, options);
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
    }

    private void UpdateStats()
    {
        long lost = _sent - _received;
        StatsSummary = $"Packets: Sent = {_sent}, Received = {_received}, Lost = {lost} ({((double)lost / _sent) * 100:F0}% loss)";
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

    private void UpdateLog(string m) => LogText += $"{m}{Environment.NewLine}";
}