using Avalonia.Platform.Storage;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

public partial class PortScannerViewModel : ObservableObject
{
    [ObservableProperty] private string _targetInput = "";
    [ObservableProperty] private string _portInput = "1-512";
    [ObservableProperty] private bool _useTcp = true;
    [ObservableProperty] private bool _useUdp = false;
    [ObservableProperty] private int _timeoutMs = 1000;
    [ObservableProperty] private bool _isScanning = false;
    [ObservableProperty] private bool _repeat = false;
    [ObservableProperty] private int _repeatInterval = 5;
    [ObservableProperty] private ObservableCollection<PortResult> _results = new();

    private CancellationTokenSource? _cts;
    private readonly List<Socket> _activeSockets = new();

    [RelayCommand]
    private void SortBy(string criteria)
    {
        var sorted = criteria switch
        {
            "IP" => Results.OrderBy(r => r.IP).ToList(),
            "Port" => Results.OrderBy(r => r.Port).ToList(),
            "Status" => Results.OrderBy(r => r.Status).ToList(),
            _ => Results.ToList()
        };
        Results = new ObservableCollection<PortResult>(sorted);
    }

    [RelayCommand]
    private void StopScan()
    {
        _cts?.Cancel();
        IsScanning = false;

        lock (_activeSockets)
        {
            foreach (var socket in _activeSockets.ToList())
            {
                try { socket.Close(); } catch { }
            }
            _activeSockets.Clear();
        }
    }

    [RelayCommand(AllowConcurrentExecutions = true)]
    private async Task ToggleScan()
    {
        if (IsScanning)
        {
            StopScan();
        }
        else
        {
            await StartScan();
        }
    }
    [RelayCommand]
    private async Task StartScan()
    {
        if (IsScanning) return;

        var ips = ParseIPs(TargetInput);
        var ports = ParsePorts(PortInput);

        if (ips.Count == 0 || ports.Count == 0) return;

        try
        {
            IsScanning = true;
            _cts = new CancellationTokenSource();
            var token = _cts.Token;

            do
            {
                Results.Clear();
                foreach (var ip in ips)
                {
                    if (token.IsCancellationRequested) break;
                    var tasks = new List<Task>();

                    foreach (var port in ports)
                    {
                        if (token.IsCancellationRequested) break;

                        if (UseTcp) tasks.Add(ScanTcp(ip, port, token));
                        if (UseUdp) tasks.Add(ScanUdp(ip, port, token));

                        if (tasks.Count >= 20)
                        {
                            await Task.WhenAll(tasks);
                            tasks.Clear();
                        }
                    }
                    if (tasks.Count > 0) await Task.WhenAll(tasks);
                }

                if (Repeat && !token.IsCancellationRequested)
                {
                    try { await Task.Delay(RepeatInterval * 1000, token); }
                    catch { break; }
                }
            } while (Repeat && !token.IsCancellationRequested);
        }
        catch { }
        finally
        {
            IsScanning = false;
            _cts?.Dispose();
            _cts = null;

            lock (_activeSockets)
            {
                _activeSockets.Clear();
            }
        }
    }

    private async Task ScanTcp(string ip, int port, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;
        var result = new PortResult { IP = ip, Port = port, Protocol = "TCP" };
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

        lock (_activeSockets) _activeSockets.Add(socket);

        try
        {
            var connectTask = socket.ConnectAsync(new IPEndPoint(IPAddress.Parse(ip), port), ct).AsTask();
            var delayTask = Task.Delay(TimeoutMs, ct);

            if (await Task.WhenAny(connectTask, delayTask) == connectTask && socket.Connected)
            {
                result.Status = "OPEN";
            }
            else
            {
                result.Status = "TIMEOUT";
                try { socket.Close(); } catch { }
            }
        }
        catch { result.Status = "CLOSED"; }
        finally
        {
            lock (_activeSockets) _activeSockets.Remove(socket);
            socket.Dispose();
        }

        if (!ct.IsCancellationRequested)
        {
            Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                if (result.Status == "OPEN") Results.Insert(0, result);
                else Results.Add(result);
            });
        }
    }

    private async Task ScanUdp(string ip, int port, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;
        var result = new PortResult { IP = ip, Port = port, Protocol = "UDP" };
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

        lock (_activeSockets) _activeSockets.Add(socket);

        try
        {
            byte[] data = new byte[] { 0x00 };
            await socket.SendToAsync(data, SocketFlags.None, new IPEndPoint(IPAddress.Parse(ip), port));
            result.Status = "SENT";
        }
        catch { result.Status = "FILTERED"; }
        finally
        {
            lock (_activeSockets) _activeSockets.Remove(socket);
            socket.Dispose();
        }

        if (!ct.IsCancellationRequested)
        {
            Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                if (result.Status == "SENT") Results.Insert(0, result);
                else Results.Add(result);
            });
        }
    }

    private List<string> ParseIPs(string input)
    {
        var list = new List<string>();
        if (string.IsNullOrWhiteSpace(input)) return list;
        var items = input.Split(new[] { ',', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var item in items)
        {
            string clean = item.Trim();
            try
            {
                if (clean.Contains("/")) list.AddRange(GetIpsFromCidr(clean));
                else if (clean.Contains("-")) list.AddRange(GetIpsFromRange(clean));
                else list.Add(clean);
            }
            catch { }
        }
        return list.Distinct().ToList();
    }

    private List<string> GetIpsFromRange(string range)
    {
        var parts = range.Split('-');
        uint start = BitConverter.ToUInt32(IPAddress.Parse(parts[0].Trim()).GetAddressBytes().Reverse().ToArray(), 0);
        uint end = BitConverter.ToUInt32(IPAddress.Parse(parts[1].Trim()).GetAddressBytes().Reverse().ToArray(), 0);
        var ips = new List<string>();
        for (uint i = start; i <= end; i++)
            ips.Add(new IPAddress(BitConverter.GetBytes(i).Reverse().ToArray()).ToString());
        return ips;
    }

    private List<string> GetIpsFromCidr(string cidr)
    {
        var parts = cidr.Split('/');
        uint ipAsUint = BitConverter.ToUInt32(IPAddress.Parse(parts[0]).GetAddressBytes().Reverse().ToArray(), 0);
        uint maskAsUint = uint.MaxValue << (32 - int.Parse(parts[1]));
        uint start = ipAsUint & maskAsUint;
        uint end = ipAsUint | ~maskAsUint;
        var ips = new List<string>();
        for (uint i = start; i <= end; i++)
            ips.Add(new IPAddress(BitConverter.GetBytes(i).Reverse().ToArray()).ToString());
        return ips;
    }

    private List<int> ParsePorts(string input)
    {
        var list = new List<int>();
        if (string.IsNullOrWhiteSpace(input)) return list;
        foreach (var item in input.Split(','))
        {
            string clean = item.Trim();
            try
            {
                if (clean.Contains("-"))
                {
                    var parts = clean.Split('-');
                    for (int i = int.Parse(parts[0]); i <= int.Parse(parts[1]); i++) list.Add(i);
                }
                else if (int.TryParse(clean, out int p)) list.Add(p);
            }
            catch { }
        }
        return list.Distinct().ToList();
    }

    [RelayCommand]
    public async Task ExportResults(IStorageProvider storageProvider)
    {
        if (Results == null || !Results.Any()) return;
        var file = await storageProvider.SaveFilePickerAsync(new FilePickerSaveOptions { Title = "Save Results", DefaultExtension = ".csv" });
        if (file is not null)
        {
            await using var stream = await file.OpenWriteAsync();
            using var writer = new StreamWriter(stream);
            await writer.WriteLineAsync("IP,Port,Protocol,Status");
            foreach (var res in Results) await writer.WriteLineAsync($"{res.IP},{res.Port},{res.Protocol},{res.Status}");
        }
    }
}

public class PortResult
{
    public string IP { get; set; } = string.Empty;
    public int Port { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
}