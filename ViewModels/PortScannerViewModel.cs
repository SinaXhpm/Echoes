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
    [ObservableProperty] private string _statusMessage = string.Empty;

    private const int MaxHosts = 65536;
    private const int MaxConcurrency = 100;

    public ObservableCollection<string> TargetHistory => Helpers.HistoryService.Instance.Get("portscan.target");
    public ObservableCollection<string> PortHistory => Helpers.HistoryService.Instance.Get("portscan.ports");

    public PortScannerViewModel()
    {
        if (Helpers.HistoryService.Instance.Last("portscan.target") is { } t) TargetInput = t;
        if (Helpers.HistoryService.Instance.Last("portscan.ports") is { } p) PortInput = p;
    }

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

        Helpers.HistoryService.Instance.Add("portscan.target", TargetInput);
        Helpers.HistoryService.Instance.Add("portscan.ports", PortInput);

        StatusMessage = ips.Count >= MaxHosts
            ? $"⚠ Target range capped at {MaxHosts:N0} hosts × {ports.Count} ports"
            : $"Scanning {ips.Count} host(s) × {ports.Count} port(s)";

        try
        {
            IsScanning = true;
            _cts = new CancellationTokenSource();
            var token = _cts.Token;

            var options = new ParallelOptions { MaxDegreeOfParallelism = MaxConcurrency, CancellationToken = token };

            do
            {
                Results.Clear();

                // Lazily stream (ip, port) pairs so we never materialize a huge task list.
                var targets = ips.SelectMany(ip => ports.Select(port => (ip, port)));

                try
                {
                    await Parallel.ForEachAsync(targets, options, async (t, ct) =>
                    {
                        if (UseTcp) await ScanTcp(t.ip, t.port, ct);
                        if (UseUdp) await ScanUdp(t.ip, t.port, ct);
                    });
                }
                catch (OperationCanceledException) { break; }

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
            // A connected UDP socket surfaces ICMP "port unreachable" as a socket error,
            // which is how we distinguish CLOSED from OPEN|FILTERED.
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Parse(ip), port), ct);
            await socket.SendAsync(UdpProbe(port), SocketFlags.None, ct);

            using var recvCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            recvCts.CancelAfter(TimeoutMs);

            try
            {
                var buffer = new byte[512];
                await socket.ReceiveAsync(buffer, SocketFlags.None, recvCts.Token);
                result.Status = "OPEN";                 // got a reply
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                result.Status = "OPEN|FILTERED";        // no reply, no ICMP error
            }
        }
        catch (SocketException ex) when (
            ex.SocketErrorCode == SocketError.ConnectionReset ||
            ex.SocketErrorCode == SocketError.ConnectionRefused)
        {
            result.Status = "CLOSED";                   // ICMP port unreachable
        }
        catch (OperationCanceledException) { return; }
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
                if (result.Status == "OPEN") Results.Insert(0, result);
                else Results.Add(result);
            });
        }
    }

    private static byte[] UdpProbe(int port) => port switch
    {
        // Minimal DNS A-query for "google.com" — elicits a reply from real DNS servers.
        53 => new byte[]
        {
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x06, (byte)'g', (byte)'o', (byte)'o', (byte)'g', (byte)'l', (byte)'e',
            0x03, (byte)'c', (byte)'o', (byte)'m', 0x00, 0x00, 0x01, 0x00, 0x01
        },
        _ => new byte[] { 0x00, 0x00, 0x00, 0x00 }
    };

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

    private static List<string> GetIpsFromRange(string range)
    {
        var parts = range.Split('-');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0].Trim(), out var startIp))
            return new List<string>();

        uint start = IpToUint(startIp);
        string endStr = parts[1].Trim();
        uint end;

        if (IPAddress.TryParse(endStr, out var endIp))
            end = IpToUint(endIp);
        else if (byte.TryParse(endStr, out byte lastOctet))     // shorthand: 192.168.1.10-20
            end = (start & 0xFFFFFF00u) | lastOctet;
        else
            return new List<string>();

        return ExpandRange(start, end);
    }

    private static List<string> GetIpsFromCidr(string cidr)
    {
        var parts = cidr.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0].Trim(), out var ipAddr)
            || !int.TryParse(parts[1].Trim(), out int prefix) || prefix < 0 || prefix > 32)
            return new List<string>();

        uint ip = IpToUint(ipAddr);
        uint mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);   // /0 must be 0, not 0xFFFFFFFF
        return ExpandRange(ip & mask, ip | ~mask);
    }

    private static List<string> ExpandRange(uint start, uint end)
    {
        var ips = new List<string>();
        if (end < start) return ips;

        long count = Math.Min((long)end - start + 1, MaxHosts);   // hard cap to avoid OOM
        uint cur = start;
        for (long k = 0; k < count; k++)
        {
            ips.Add(UintToIp(cur));
            cur++;
        }
        return ips;
    }

    private static uint IpToUint(IPAddress ip)
    {
        byte[] b = ip.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    private static string UintToIp(uint v)
        => $"{(v >> 24) & 0xFF}.{(v >> 16) & 0xFF}.{(v >> 8) & 0xFF}.{v & 0xFF}";

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