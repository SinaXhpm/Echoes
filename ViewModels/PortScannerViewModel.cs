using Avalonia.Platform.Storage;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
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

    // --- nmap-style options ---
    [ObservableProperty] private bool _serviceDetection = false;              // -sV
    [ObservableProperty] private bool _pingScanOnly = false;                  // -sn (host discovery only)
    [ObservableProperty] private bool _showReason = false;                    // --reason
    [ObservableProperty] private TimingTemplate _selectedTiming = NmapData.Timing(3);
    [ObservableProperty] private string _reportText = string.Empty;

    public IReadOnlyList<TimingTemplate> TimingOptions { get; } = NmapData.Timings;

    // Picking a timing template sets the matching per-port timeout (still editable afterwards).
    partial void OnSelectedTimingChanged(TimingTemplate value) => TimeoutMs = value.TimeoutMs;

    private const int MaxHosts = 65536;
    private const int MaxResults = 5000;   // bound the bound-collection so huge ranges can't OOM the UI

    // Add a result to the bound collection, keeping OPEN/UP rows (newest on top) and capping the
    // rest so a hosts×ports scan can't grow the collection without limit. UI-thread only.
    private void AddResult(PortResult result)
    {
        bool keepTop = result.Status.StartsWith("OPEN", StringComparison.Ordinal) || result.Status == "UP";
        if (keepTop)
            Results.Insert(0, result);
        else if (Results.Count < MaxResults)
            Results.Add(result);

        while (Results.Count > MaxResults)
            Results.RemoveAt(Results.Count - 1);
    }

    public ObservableCollection<string> TargetHistory => Helpers.HistoryService.Instance.Get("portscan.target");
    public ObservableCollection<string> PortHistory => Helpers.HistoryService.Instance.Get("portscan.ports");

    public PortScannerViewModel()
    {
        if (Helpers.HistoryService.Instance.Last("portscan.target") is { } t) TargetInput = t;
        if (Helpers.HistoryService.Instance.Last("portscan.ports") is { } p) PortInput = p;
    }

    // Common ready-made port sets shown as suggestions in the PORTS box; the box stays fully
    // editable so custom comma/range input works too. "top-N" expands to the most common ports.
    // Kept lean — only the most-used sets: a quick top-20, the classic top-100, common web ports,
    // the well-known range, and a full sweep. (Custom typing covers everything else.)
    public IReadOnlyList<PortPreset> PortPresets { get; } = new PortPreset[]
    {
        new("Top 20",     "21,22,23,25,53,80,110,139,143,443,445,993,995,1723,3306,3389,5900,8080"),
        new("Top 100",    "top-100"),
        new("Web",        "80,443,8080,8443,8000,8888,3000,5000"),
        new("Well-Known", "1-1023"),
        new("Full",       "1-65535"),
    };

    // PORTS is ONE unified field (an AutoCompleteBox): typing = custom list/range, or open the
    // dropdown and pick a preset — its Ports string (ValueMemberBinding) fills the same box.

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
            "Service" => Results.OrderBy(r => r.ServiceDisplay).ToList(),
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
        if (IsScanning) StopScan();
        else await StartScan();
    }

    [RelayCommand]
    private async Task StartScan()
    {
        if (IsScanning) return;

        var ips = ParseIPs(TargetInput);
        var ports = PingScanOnly ? new List<int>() : ParsePorts(PortInput);

        if (ips.Count == 0 || (!PingScanOnly && ports.Count == 0)) return;
        if (!PingScanOnly && !UseTcp && !UseUdp) { StatusMessage = "Select TCP and/or UDP."; return; }

        Helpers.HistoryService.Instance.Add("portscan.target", TargetInput);
        if (!PingScanOnly) Helpers.HistoryService.Instance.Add("portscan.ports", PortInput);

        StatusMessage = PingScanOnly
            ? $"Ping scan — {ips.Count} host(s)"
            : ips.Count >= MaxHosts
                ? $"⚠ Target range capped at {MaxHosts:N0} hosts × {ports.Count} ports"
                : $"Scanning {ips.Count} host(s) × {ports.Count} port(s)  ·  {SelectedTiming.Label}{(ServiceDetection ? "  · -sV" : "")}";

        try
        {
            IsScanning = true;
            _cts = new CancellationTokenSource();
            var token = _cts.Token;

            // Keep the process alive for the scan so backgrounding the Android app doesn't kill an
            // in-flight sweep (no-op on desktop).
            Helpers.BackgroundGuard.Acquire(PingScanOnly ? "Ping scan" : "Scanning ports");

            var options = new ParallelOptions
            {
                MaxDegreeOfParallelism = Math.Max(1, SelectedTiming.Concurrency),
                CancellationToken = token,
            };

            do
            {
                Results.Clear();

                try
                {
                    if (PingScanOnly)
                    {
                        await Parallel.ForEachAsync(ips, options, async (ip, ct) => await HostDiscover(ip, ct));
                    }
                    else
                    {
                        // Lazily stream (ip, port) pairs so we never materialize a huge task list.
                        var targets = ips.SelectMany(ip => ports.Select(port => (ip, port)));
                        await Parallel.ForEachAsync(targets, options, async (t, ct) =>
                        {
                            if (UseTcp) await ScanTcp(t.ip, t.port, ct);
                            if (UseUdp) await ScanUdp(t.ip, t.port, ct);
                        });
                    }
                }
                catch (OperationCanceledException) { break; }

                // Build the nmap-style report AFTER the queued AddResult posts have drained (FIFO).
                if (!token.IsCancellationRequested)
                {
                    int hc = ips.Count, pc = ports.Count;
                    Avalonia.Threading.Dispatcher.UIThread.Post(() => BuildReport(Results.ToList(), hc, pc));
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
            Helpers.BackgroundGuard.Release();

            lock (_activeSockets) _activeSockets.Clear();
        }
    }

    private async Task ScanTcp(string ip, int port, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;
        var result = new PortResult { IP = ip, Port = port, Protocol = "TCP", Service = NmapData.ServiceName(port) };
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

        lock (_activeSockets) _activeSockets.Add(socket);
        var sw = Stopwatch.StartNew();

        try
        {
            // Linked CTS so completing/timing-out one side cancels the other — no orphaned
            // Task.Delay timer when connect wins, no leaked pending connect when the timeout wins.
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var connectTask = socket.ConnectAsync(new IPEndPoint(IPAddress.Parse(ip), port), linked.Token).AsTask();
            _ = connectTask.ContinueWith(static t => { _ = t.Exception; },
                CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default);

            var delayTask = Task.Delay(TimeoutMs, linked.Token);
            var winner = await Task.WhenAny(connectTask, delayTask);
            linked.Cancel();

            if (winner == connectTask && !connectTask.IsFaulted && socket.Connected)
            {
                sw.Stop();
                result.Status = "OPEN"; result.Reason = "syn-ack"; result.Latency = sw.ElapsedMilliseconds;
            }
            else if (connectTask.IsFaulted &&
                     connectTask.Exception?.InnerException is SocketException se)
            {
                if (se.SocketErrorCode == SocketError.ConnectionRefused)
                { result.Status = "CLOSED"; result.Reason = "conn-refused"; }
                else
                { result.Status = "FILTERED"; result.Reason = ReasonFor(se.SocketErrorCode); }
                try { socket.Close(); } catch { }
            }
            else
            {
                result.Status = "FILTERED"; result.Reason = "no-response";
                try { socket.Close(); } catch { }
            }
        }
        catch (SocketException se) when (se.SocketErrorCode == SocketError.ConnectionRefused)
        { result.Status = "CLOSED"; result.Reason = "conn-refused"; }
        catch { result.Status = "FILTERED"; result.Reason = "no-response"; }
        finally
        {
            lock (_activeSockets) _activeSockets.Remove(socket);
            socket.Dispose();
        }

        // -sV: probe open ports for service + version.
        if (ServiceDetection && result.Status == "OPEN" && !ct.IsCancellationRequested)
        {
            try
            {
                var info = await ServiceScanner.ProbeAsync(ip, port, Math.Max(TimeoutMs, 1500), aggressive: true, ct);
                if (info.ServiceLabel is { Length: > 0 } and not "unknown") result.Service = info.ServiceLabel;
                if (info.VersionText.Length > 0) result.Version = info.VersionText;
            }
            catch { }
        }

        if (!ct.IsCancellationRequested)
            Avalonia.Threading.Dispatcher.UIThread.Post(() => AddResult(result));
    }

    private async Task ScanUdp(string ip, int port, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;
        var result = new PortResult { IP = ip, Port = port, Protocol = "UDP", Service = NmapData.ServiceName(port) };
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
                result.Status = "OPEN"; result.Reason = "udp-response";
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                result.Status = "OPEN|FILTERED"; result.Reason = "no-response";
            }
        }
        catch (SocketException ex) when (
            ex.SocketErrorCode == SocketError.ConnectionReset ||
            ex.SocketErrorCode == SocketError.ConnectionRefused)
        {
            result.Status = "CLOSED"; result.Reason = "port-unreach";
        }
        catch (OperationCanceledException) { return; }
        catch { result.Status = "FILTERED"; result.Reason = "no-response"; }
        finally
        {
            lock (_activeSockets) _activeSockets.Remove(socket);
            socket.Dispose();
        }

        if (!ct.IsCancellationRequested)
            Avalonia.Threading.Dispatcher.UIThread.Post(() => AddResult(result));
    }

    // Host discovery (-sn): ICMP echo, then a TCP-ping fallback to common ports. Up if any replies.
    private async Task HostDiscover(string ip, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;
        var result = new PortResult { IP = ip, Port = 0, Protocol = "—", Service = "host" };
        int timeout = Math.Max(500, TimeoutMs);

        try
        {
            if (IPAddress.TryParse(ip, out var addr))
            {
                var ping = await IcmpPinger.SendAsync(addr, timeout, ct);
                if (ping.Success)
                {
                    result.Status = "UP"; result.Reason = "echo-reply"; result.Latency = ping.RoundtripMs;
                }
            }

            if (result.Status != "UP")
            {
                foreach (int p in new[] { 80, 443, 22, 445, 3389 })
                {
                    if (ct.IsCancellationRequested) return;
                    if (await TcpPing(ip, p, timeout, ct))
                    {
                        result.Status = "UP"; result.Reason = $"tcp-{p}"; break;
                    }
                }
            }
        }
        catch { }

        if (result.Status != "UP") { result.Status = "DOWN"; result.Reason = "no-response"; }

        if (!ct.IsCancellationRequested)
            Avalonia.Threading.Dispatcher.UIThread.Post(() => AddResult(result));
    }

    private async Task<bool> TcpPing(string ip, int port, int timeoutMs, CancellationToken ct)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var connect = socket.ConnectAsync(new IPEndPoint(IPAddress.Parse(ip), port), linked.Token).AsTask();
            _ = connect.ContinueWith(static t => { _ = t.Exception; },
                CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default);
            var winner = await Task.WhenAny(connect, Task.Delay(timeoutMs, linked.Token));
            linked.Cancel();
            return winner == connect && !connect.IsFaulted && socket.Connected;
        }
        catch (SocketException se) when (se.SocketErrorCode == SocketError.ConnectionRefused)
        {
            return true;   // refused still proves the host is up
        }
        catch { return false; }
    }

    private static string ReasonFor(SocketError e) => e switch
    {
        SocketError.HostUnreachable => "host-unreach",
        SocketError.NetworkUnreachable => "net-unreach",
        SocketError.TimedOut => "no-response",
        SocketError.TryAgain or SocketError.HostNotFound => "no-route",
        _ => "no-response",
    };

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

    // ---- nmap-style report ----
    private void BuildReport(List<PortResult> snapshot, int hostCount, int portCount)
    {
        var sb = new StringBuilder();
        int openTotal = snapshot.Count(r => r.Status.StartsWith("OPEN", StringComparison.Ordinal));
        int upTotal = snapshot.Count(r => r.Status == "UP");

        string flags = PingScanOnly ? "-sn"
            : string.Concat(UseTcp ? "-sT " : "", UseUdp ? "-sU " : "", ServiceDetection ? "-sV " : "").Trim();
        sb.AppendLine($"# Echoes scan — {hostCount} host(s), {(PingScanOnly ? "" : portCount + " port(s)/host, ")}{SelectedTiming.Label}");
        sb.AppendLine($"# {flags}   {(PingScanOnly ? upTotal + " host(s) up" : openTotal + " open port(s)")}");
        sb.AppendLine();

        foreach (var host in snapshot.GroupBy(r => r.IP).OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase))
        {
            if (PingScanOnly)
            {
                var hostRow = host.FirstOrDefault();
                bool up = hostRow?.Status == "UP";
                string lat = up && hostRow!.Latency > 0 ? $" ({hostRow.Latency}ms)" : "";
                sb.AppendLine($"Host {host.Key} is {(up ? "up" : "down")}{lat}  [{hostRow?.Reason}]");
                continue;
            }

            var open = host.Where(r => r.Status.StartsWith("OPEN", StringComparison.Ordinal))
                           .OrderBy(r => r.Port).ToList();
            sb.AppendLine($"Host: {host.Key}   ({(open.Count > 0 ? "up" : "no open ports")})");
            if (open.Count == 0) { sb.AppendLine(); continue; }

            sb.AppendLine(ShowReason
                ? "  PORT        STATE          SERVICE         REASON         VERSION"
                : "  PORT        STATE          SERVICE         VERSION");
            foreach (var r in open)
            {
                string portCol = $"{r.Port}/{r.Protocol.ToLowerInvariant()}".PadRight(11);
                string state = r.Status.ToLowerInvariant().PadRight(14);
                string svc = (r.ServiceDisplay.Length > 0 ? r.ServiceDisplay : "unknown").PadRight(15);
                string line = ShowReason
                    ? $"  {portCol} {state} {svc} {(r.Reason.Length > 0 ? r.Reason : "-").PadRight(14)} {r.Version}"
                    : $"  {portCol} {state} {svc} {r.Version}";
                sb.AppendLine(line.TrimEnd());
            }
            sb.AppendLine();
        }

        ReportText = sb.ToString().TrimEnd();
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
        const int minPort = 1, maxPort = 65535;
        var list = new List<int>();
        if (string.IsNullOrWhiteSpace(input)) return list;
        foreach (var item in input.Split(','))
        {
            string clean = item.Trim();
            if (clean.Length == 0) continue;

            // "top-100" / "top1000" → the most common ports.
            var top = Regex.Match(clean, @"^top-?(\d+)$", RegexOptions.IgnoreCase);
            if (top.Success && int.TryParse(top.Groups[1].Value, out int n))
            {
                list.AddRange(NmapData.TopPorts(n));
                continue;
            }

            if (clean.Contains('-'))
            {
                var parts = clean.Split('-');
                // Validate + clamp both endpoints before looping. Without this, a typo like
                // "1-2147483647" grows the list toward billions of entries and hangs/OOMs the app.
                if (parts.Length != 2
                    || !int.TryParse(parts[0].Trim(), out int lo)
                    || !int.TryParse(parts[1].Trim(), out int hi)) continue;
                lo = Math.Clamp(lo, minPort, maxPort);
                hi = Math.Clamp(hi, minPort, maxPort);
                if (lo > hi) continue;   // ignore reversed ranges (e.g. "70000-1")
                for (int i = lo; i <= hi; i++) list.Add(i);
            }
            else if (int.TryParse(clean, out int p) && p >= minPort && p <= maxPort)
            {
                list.Add(p);
            }
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
            await writer.WriteLineAsync("IP,Port,Protocol,Status,Service,Version,Reason,LatencyMs");
            foreach (var res in Results)
                await writer.WriteLineAsync(
                    $"{res.IP},{res.Port},{res.Protocol},{res.Status},{Csv(res.ServiceDisplay)},{Csv(res.Version)},{res.Reason},{res.Latency}");
        }
    }

    private static string Csv(string v) => v.Contains(',') || v.Contains('"')
        ? "\"" + v.Replace("\"", "\"\"") + "\"" : v;
}

public class PortResult
{
    public string IP { get; set; } = string.Empty;
    public int Port { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string Service { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string Reason { get; set; } = string.Empty;
    public long Latency { get; set; }

    // Service column: detected service, else the well-known name for the port.
    public string ServiceDisplay => Service.Length > 0 ? Service : Helpers.NmapData.ServiceName(Port);
    // "22/tcp" style label for the port column.
    public string PortLabel => Port > 0 ? $"{Port}/{Protocol.ToLowerInvariant()}" : "—";
}

public sealed record PortPreset(string Name, string Ports);
