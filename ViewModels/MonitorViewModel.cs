using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

public partial class MonitorTarget : ObservableObject
{
    [ObservableProperty] private string _address = string.Empty;
    [ObservableProperty] private string _pingStatus = "-";
    [ObservableProperty] private string _tcpStatus = "-";
    [ObservableProperty] private string _httpStatus = "-";
    [ObservableProperty] private int _failedCount = 0;
    [ObservableProperty] private bool _isSuccess;

    public string Host { get; set; } = string.Empty;
    public int Port { get; set; } = 80;
    public string HttpUrl { get; set; } = string.Empty;
}

public partial class MonitorViewModel : ObservableObject
{
    private CancellationTokenSource? _cts;
    private readonly HttpClient _httpClient = new() { Timeout = TimeSpan.FromSeconds(3) };

    [ObservableProperty] private string _inputAddresses = "google.com\n1.1.1.1:53\nhttps://api.ipify.org";
    [ObservableProperty] private int _interval = 2;
    [ObservableProperty] private bool _isMonitoring;
    [ObservableProperty] private bool _checkPing = true;
    [ObservableProperty] private bool _checkTcp = true;
    [ObservableProperty] private bool _checkHttp = true;
    [ObservableProperty] private ObservableCollection<MonitorTarget> _targets = new();

    [RelayCommand(AllowConcurrentExecutions = true)]
    private async Task ToggleMonitor()
    {
        if (IsMonitoring)
        {
            _cts?.Cancel();
            IsMonitoring = false;
            return;
        }

        PrepareTargets();
        if (Targets.Count == 0) return;

        IsMonitoring = true;
        _cts = new CancellationTokenSource();

        try
        {
            while (!_cts.Token.IsCancellationRequested)
            {
                var tasks = Targets.Select(t => UpdateTargetStatus(t, _cts.Token));
                await Task.WhenAll(tasks);

                await Task.Delay(Math.Max(1, Interval) * 1000, _cts.Token);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception) { IsMonitoring = false; }
        finally
        {
            IsMonitoring = false;
            _cts?.Dispose();
            _cts = null;
        }
    }

    private void PrepareTargets()
    {
        Targets.Clear();
        var lines = InputAddresses.Split(new[] { '\n', '\r', ',' }, StringSplitOptions.RemoveEmptyEntries);

        foreach (var line in lines.Select(l => l.Trim()))
        {
            var target = new MonitorTarget { Address = line };
            if (line.StartsWith("http"))
            {
                target.HttpUrl = line;
                target.Host = new Uri(line).Host;
            }
            else if (line.Contains(":"))
            {
                var parts = line.Split(':');
                target.Host = parts[0];
                int.TryParse(parts[1], out var p);
                target.Port = p > 0 ? p : 80;
                target.HttpUrl = $"http://{line}";
            }
            else
            {
                target.Host = line;
                target.HttpUrl = $"http://{line}";
            }
            Targets.Add(target);
        }
    }

    private async Task UpdateTargetStatus(MonitorTarget target, CancellationToken ct)
    {
        var pingTask = CheckPing ? RunPing(target.Host, ct) : Task.FromResult("-");
        var tcpTask = CheckTcp ? RunTcp(target.Host, target.Port, ct) : Task.FromResult("-");
        var httpTask = CheckHttp ? RunHttp(target.HttpUrl, ct) : Task.FromResult("-");

        await Task.WhenAll(pingTask, tcpTask, httpTask);

        target.PingStatus = pingTask.Result;
        target.TcpStatus = tcpTask.Result;
        target.HttpStatus = httpTask.Result;

        bool currentSuccess = (!CheckPing || !target.PingStatus.Contains("ERR")) &&
                              (!CheckTcp || target.TcpStatus.Contains("ms")) &&
                              (!CheckHttp || (!target.HttpStatus.Contains("FAIL") && !target.HttpStatus.Contains("Err")));

        target.IsSuccess = currentSuccess;
        if (!currentSuccess) target.FailedCount++;
    }

    private async Task<string> RunPing(string host, CancellationToken ct)
    {
        try
        {
            using var p = new Ping();
            var reply = await p.SendPingAsync(host, 2000);
            if (ct.IsCancellationRequested) return "-";
            return reply.Status == IPStatus.Success ? $"{reply.RoundtripTime}ms" : "ERR";
        }
        catch { return "ERR"; }
    }

    private async Task<string> RunTcp(string host, int port, CancellationToken ct)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            using var client = new TcpClient();
            var connectTask = client.ConnectAsync(host, port, ct).AsTask();
            var delayTask = Task.Delay(2000, ct);
            if (await Task.WhenAny(connectTask, delayTask) == connectTask)
            {
                sw.Stop();
                return $"{sw.ElapsedMilliseconds}ms";
            }
            return "TIMEOUT";
        }
        catch { return "FAIL"; }
    }

    private async Task<string> RunHttp(string url, CancellationToken ct)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            var response = await _httpClient.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
            sw.Stop();
            return $"{(int)response.StatusCode} ({sw.ElapsedMilliseconds}ms)";
        }
        catch { return "FAIL"; }
    }
}