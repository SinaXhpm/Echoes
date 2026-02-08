using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

public class MonitorResult
{
    public string Time { get; set; } = string.Empty;
    public string Url { get; set; } = string.Empty;
    public string HttpStatus { get; set; } = string.Empty;
    public string HttpLatency { get; set; } = string.Empty;
    public string PingStatus { get; set; } = string.Empty;
    public string PingLatency { get; set; } = string.Empty;
    public bool IsSuccess { get; set; }
}

public partial class MonitorViewModel : ObservableObject
{
    private CancellationTokenSource? _cts;
    private readonly HttpClient _httpClient = new() { Timeout = TimeSpan.FromSeconds(5) };
    private bool? _lastState;

    [ObservableProperty] private string _targetUrl = "https://api.ipify.org";
    [ObservableProperty] private int _interval = 1;
    [ObservableProperty] private string _successCodes = "200, 201, 204";
    [ObservableProperty] private bool _isMonitoring;
    [ObservableProperty] private bool _enableSound = true;
    [ObservableProperty] private ObservableCollection<MonitorResult> _results = new();

    [RelayCommand(AllowConcurrentExecutions = true)]
    private async Task ToggleMonitor()
    {
        if (IsMonitoring)
        {
            _cts?.Cancel();
            IsMonitoring = false;
            _lastState = null;
            return;
        }

        IsMonitoring = true;
        _cts = new CancellationTokenSource();

        try
        {
            while (!_cts.Token.IsCancellationRequested)
            {
                var res = await PerformCheck();

                if (EnableSound && _lastState.HasValue && _lastState.Value != res.IsSuccess)
                {
                    SoundHelper.PlayNotify(res.IsSuccess);
                }
                _lastState = res.IsSuccess;

                Dispatcher.UIThread.Post(() =>
                {
                    Results.Insert(0, res);
                    if (Results.Count > 100) Results.RemoveAt(Results.Count - 1);
                });

                await Task.Delay(Math.Max(1, Interval) * 1000, _cts.Token);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception) { IsMonitoring = false; }
        finally { IsMonitoring = false; }
    }

    private async Task<MonitorResult> PerformCheck()
    {
        var res = new MonitorResult { Time = DateTime.Now.ToString("HH:mm:ss"), Url = TargetUrl };
        var validCodes = SuccessCodes.Split(',').Select(x => x.Trim()).ToList();

        try
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            using var response = await _httpClient.GetAsync(TargetUrl, HttpCompletionOption.ResponseHeadersRead);
            sw.Stop();
            res.HttpStatus = ((int)response.StatusCode).ToString();
            res.HttpLatency = $"{sw.ElapsedMilliseconds}ms";
            res.IsSuccess = validCodes.Contains(res.HttpStatus);
        }
        catch { res.HttpStatus = "FAIL"; res.IsSuccess = false; res.HttpLatency = "-"; }

        try
        {
            var ping = new Ping();
            var uri = new Uri(TargetUrl);
            var reply = await ping.SendPingAsync(uri.Host, 2000);
            res.PingStatus = reply.Status.ToString();
            res.PingLatency = reply.Status == IPStatus.Success ? $"{reply.RoundtripTime}ms" : "-";
        }
        catch { res.PingStatus = "ERR"; res.PingLatency = "-"; }

        return res;
    }
}