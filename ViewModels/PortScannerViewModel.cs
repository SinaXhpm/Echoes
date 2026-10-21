using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>
/// The Port Scanner tool: setup, the scan loop (one or repeating passes), live progress and the summary. The scanning
/// itself is <see cref="ScanEngine"/>; the result listing, filter and exports are in PortScannerViewModel.Results.cs.
/// </summary>
public partial class PortScannerViewModel : ObservableObject
{
    // ---- setup ----
    [ObservableProperty] private string _targetInput = "";
    [ObservableProperty] private string _portInput = "top-100";
    [ObservableProperty] private bool _useTcp = true;
    [ObservableProperty] private bool _useUdp;
    [ObservableProperty] private bool _serviceDetection = true;    // -sV
    [ObservableProperty] private bool _pingScanOnly;               // -sn
    [ObservableProperty] private bool _skipDiscovery;              // -Pn
    [ObservableProperty] private bool _repeat;
    [ObservableProperty] private int _repeatInterval = 30;
    [ObservableProperty] private TimingTemplate _selectedTiming = NmapData.Timing(3);
    [ObservableProperty] private int _timeoutMs = NmapData.Timing(3).TimeoutMs;

    // ---- run state ----
    [ObservableProperty] private bool _isScanning;
    [ObservableProperty] private string _statusMessage = "";
    [ObservableProperty] private bool _statusIsError;
    [ObservableProperty] private double _progress;                  // 0..1
    [ObservableProperty] private string _progressText = "";
    [ObservableProperty] private string _warningText = "";
    [ObservableProperty] private string _reportText = "";

    public IReadOnlyList<TimingTemplate> TimingOptions => NmapData.Timings;

    // Picking a timing template sets its per-probe timeout (still editable afterwards).
    partial void OnSelectedTimingChanged(TimingTemplate value) => TimeoutMs = value.TimeoutMs;

    /// <summary>Raised when a scan starts, so the view can bring the results forward.</summary>
    public event Action? ScanStarted;

    public PortScannerViewModel()
    {
        if (HistoryService.Instance.Last("portscan.target") is { } t) TargetInput = t;
        if (HistoryService.Instance.Last("portscan.ports") is { } p) PortInput = p;
        RestoreOptions();
        _loaded = true;
    }

    // ---- remembered options: every change is saved (the profile coalesces the writes in the background) ----
    private bool _loaded;
    private static readonly HashSet<string> PersistProps = new()
    {
        nameof(UseTcp), nameof(UseUdp), nameof(ServiceDetection), nameof(PingScanOnly), nameof(SkipDiscovery),
        nameof(Repeat), nameof(RepeatInterval), nameof(SelectedTiming), nameof(TimeoutMs), nameof(ViewMode),
    };

    private void RestoreOptions()
    {
        var ps = ProfileService.Instance;
        UseTcp = ps.GetBool("portscan.tcp", true);
        UseUdp = ps.GetBool("portscan.udp");
        ServiceDetection = ps.GetBool("portscan.sv", true);
        PingScanOnly = ps.GetBool("portscan.pingOnly");
        SkipDiscovery = ps.GetBool("portscan.skipDiscovery");
        Repeat = ps.GetBool("portscan.repeat");
        RepeatInterval = Math.Clamp(ps.GetInt("portscan.repeatEvery", 30), 1, 86_400);
        SelectedTiming = NmapData.Timing(ps.GetInt("portscan.timing", 3));   // sets that template's timeout...
        TimeoutMs = Math.Clamp(ps.GetInt("portscan.timeout", SelectedTiming.TimeoutMs), 50, 120_000);   // ...then the saved one
        // "Open only" (a ping scan lists hosts, not ports: it starts on All). "Changes" belongs to one repeating run.
        if (ps.GetSetting("portscan.view") == "open" && !PingScanOnly) ViewMode = "open";
    }

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (!_loaded || e.PropertyName is not { } n || !PersistProps.Contains(n)) return;
        var inv = System.Globalization.CultureInfo.InvariantCulture;
        ProfileService.Instance.SetMany(
            ("portscan.tcp", UseTcp ? "true" : "false"), ("portscan.udp", UseUdp ? "true" : "false"),
            ("portscan.sv", ServiceDetection ? "true" : "false"), ("portscan.pingOnly", PingScanOnly ? "true" : "false"),
            ("portscan.skipDiscovery", SkipDiscovery ? "true" : "false"), ("portscan.repeat", Repeat ? "true" : "false"),
            ("portscan.repeatEvery", RepeatInterval.ToString(inv)), ("portscan.timing", (SelectedTiming?.Level ?? 3).ToString(inv)),
            ("portscan.timeout", TimeoutMs.ToString(inv)), ("portscan.view", ViewMode == "open" ? "open" : "all"));
    }

    // Ready-made port sets for the PORTS box (it stays freely editable). "top-N" is the N most common ports of each
    // ticked protocol; T: / U: limit what follows to one protocol.
    public IReadOnlyList<PortPreset> PortPresets { get; } = new PortPreset[]
    {
        new("Top 100", "top-100"),
        new("Top 1000", "top-1000"),
        new("Top 20", "top-20"),
        new("Web", "80,443,8000,8008,8080,8081,8443,8888,3000,5000,9000,9443"),
        new("Remote access", "22,23,3389,5900-5902,5800,5938,4899,6568"),
        new("Mail", "25,110,143,465,587,993,995,2525"),
        new("File sharing", "20,21,69,139,445,548,873,2049,990,989"),
        new("Databases", "1433,1521,3306,5432,5984,6379,7000,8086,9042,9200,9300,11211,27017"),
        new("Windows / AD", "53,88,135,139,389,445,464,636,3268,3269,3389,5985,5986,9389"),
        new("VPN / proxy", "T:1080,1723,3128,8080,8118,8388,9050,U:500,1194,1701,4500,51820"),
        new("IoT / camera", "80,554,1883,5683,8000,8080,8554,9000,37777,49152"),
        new("Containers", "2375,2376,2377,5000,6443,8001,9099,10250,10255"),
        new("UDP services", "U:53,67,69,123,137,161,500,514,1900,5353"),
        new("Well-known", "1-1023"),
        new("All ports", "1-65535"),
    };

    // The scan in flight (UI thread only).
    private ScanEngine? _engine;

    // Ceiling on DNS lookups for hostname targets (bounded parallel, each with a deadline).
    private const int DnsParallel = 16;
    private const int DnsTimeoutMs = 5000;

    [RelayCommand(AllowConcurrentExecutions = true)]
    private async Task ToggleScan()
    {
        if (IsScanning) StopScan();
        else await StartScan();
    }

    [RelayCommand]
    private void StopScan()
    {
        // Cancels and tears the sockets down; IsScanning flips in StartScan's finally, once the scan has drained.
        _stopRequested = true;
        try { _resolveCts?.Cancel(); } catch (ObjectDisposedException) { }
        // the reverse-DNS lookups still waiting go too: Stop means stop (they ran on for hours after a big sweep, a few at a
        // time with a timer polling them; the handful already with the OS end on their own)
        _engine?.Names.Cancel();
        _engine?.Stop();
    }

    private bool _stopRequested;

    private async Task StartScan()
    {
        // IsScanning gates re-entry; set synchronously before any await so a double-click can't start two scans.
        if (IsScanning) return;
        IsScanning = true;
        _stopRequested = false;
        StatusIsError = false;
        WarningText = "";
        Progress = 0;
        ProgressText = "";
        StatusMessage = "Preparing…";

        // Snapshot every setting the workers read: a box ticked mid-scan must not change a scan half-way. (Repeat and
        // its interval stay live on purpose: unticking Repeat ends the loop after this pass.)
        var timing = SelectedTiming;
        var options = new ScanOptions(
            Tcp: UseTcp, Udp: UseUdp, ServiceDetection: ServiceDetection, PingOnly: PingScanOnly,
            SkipDiscovery: SkipDiscovery && !PingScanOnly, TimeoutMs: Math.Clamp(TimeoutMs, 50, 120_000),
            Concurrency: Math.Clamp(timing.Concurrency, 1, ScanEngine.MaxParallelism), Timing: timing);
        string targetText = TargetInput, portText = PortInput;

        ScanEngine? engine = null;
        Avalonia.Threading.DispatcherTimer? timer = null;
        bool guarded = false;
        try
        {
            // Parse off the UI thread: a /16 expands to 65,536 addresses and "1-65535" to as many ports.
            var (parsed, ports) = await Task.Run(() =>
                (ScanTargets.Parse(targetText), ScanPortSpec.Parse(options.PingOnly ? "" : portText, options.Tcp, options.Udp)));

            string? invalid = Validate(parsed, ports, options);
            if (invalid is not null) { Fail(invalid); return; }
            if (_stopRequested) { StatusMessage = "Stopped."; return; }
            ScanStarted?.Invoke();   // the input is good: bring the results forward

            // T:/U: prefixes can name a protocol whose box is unticked: what's scanned is what the ports say.
            options = options with { Tcp = ports.Tcp.Count > 0, Udp = ports.Udp.Count > 0 };
            HistoryService.Instance.Add("portscan.target", targetText);
            if (!options.PingOnly) HistoryService.Instance.Add("portscan.ports", portText);

            if (parsed.Hostnames.Count > 0) StatusMessage = $"Resolving {parsed.Hostnames.Count:N0} name(s)…";
            var cts = new CancellationTokenSource();
            _resolveCts = cts;
            List<ScanHost> targets;
            try { targets = await Task.Run(() => BuildTargetsAsync(parsed, cts.Token)); }
            finally { _resolveCts = null; cts.Dispose(); }
            if (_stopRequested) { StatusMessage = "Stopped."; return; }
            if (targets.Count == 0)
            {
                Fail("Couldn't resolve " + string.Join(", ", parsed.Errors.Take(4)) + (parsed.Errors.Count > 4 ? $" (+{parsed.Errors.Count - 4} more)" : "") + ".");
                return;
            }

            string skipped = parsed.Errors.Count == 0 ? ""
                : "  ·  skipped " + string.Join(", ", parsed.Errors.Take(3)) + (parsed.Errors.Count > 3 ? $" (+{parsed.Errors.Count - 3})" : "");
            string capped = parsed.Capped ? $"  ·  capped at {ScanTargets.MaxHosts:N0} hosts" : "";
            string portsText = options.PingOnly ? "" : ports.Describe();

            var sink = new Sink();
            engine = new ScanEngine(options, sink);
            _engine = engine;
            if (_stopRequested) engine.Stop();
            BeginRun(sink, targets.Count);

            // Live results and progress every 200 ms while a pass runs (stopped between passes: the final listing,
            // counters and countdown then come from the pass itself).
            timer = new Avalonia.Threading.DispatcherTimer { Interval = TimeSpan.FromMilliseconds(200) };
            timer.Tick += (_, _) => Tick(engine);
            BackgroundGuard.Acquire(options.PingOnly ? "Finding live hosts" : "Scanning ports");
            guarded = true;

            ScanSnapshot? previous = null;
            do
            {
                BeginPass(previous is not null);
                Progress = 0;
                StatusMessage = (options.PingOnly
                        ? $"Finding live hosts among {targets.Count:N0} address(es)"
                        : $"Scanning {Hosts(targets.Count)} · {portsText} · {timing.Label}" + (options.ServiceDetection ? " · versions" : ""))
                    + skipped + capped;
                timer.Start();
                var pass = await Task.Run(() => engine.RunPassAsync(targets, ports));
                timer.Stop();

                ScanDiff? diff = previous is not null && !pass.Stopped ? previous.Compare(pass) : null;
                await FinishPassAsync(pass, diff, portsText);
                if (!pass.Stopped) previous = ScanSnapshot.Of(pass);

                string done = Summary(pass) + (diff is null ? "" : diff.Any ? $" · changed: {diff.Summary}" : " · no changes")
                              + skipped + capped;
                StatusMessage = done;
                if (pass.Stopped || !Repeat) break;

                // Wait in ≤1 s slices, re-reading Repeat: unticking it (or Stop) ends the scan now, not after the interval.
                var interval = TimeSpan.FromSeconds(Math.Clamp(RepeatInterval, 1, 86_400));
                var waited = Stopwatch.StartNew();
                try
                {
                    for (TimeSpan left; Repeat && (left = interval - waited.Elapsed) > TimeSpan.Zero;)
                    {
                        ProgressText = $"Next pass in {Math.Ceiling(left.TotalSeconds):0} s";
                        StatusMessage = done + $"  ·  next pass in {Math.Ceiling(left.TotalSeconds):0} s";
                        await Task.Delay(left < TimeSpan.FromSeconds(1) ? left : TimeSpan.FromSeconds(1), engine.Token);
                    }
                }
                catch (OperationCanceledException) { }
                StatusMessage = done;
                if (engine.Token.IsCancellationRequested || !Repeat) break;
            } while (true);
        }
        catch (Exception ex)
        {
            Fail("The scan failed: " + ex.Message);
        }
        finally
        {
            timer?.Stop();
            if (engine is not null)
            {
                Drain(final: true);
                FollowLateNames(engine.Names);   // names still on their way
                engine.Dispose();
            }
            _engine = null;
            Progress = 1;
            IsScanning = false;
            if (guarded) BackgroundGuard.Release();
        }
    }

    private CancellationTokenSource? _resolveCts;

    private static string Hosts(int n) => n == 1 ? "1 host" : $"{n:N0} hosts";

    private void Fail(string message)
    {
        StatusMessage = message;
        StatusIsError = true;
    }

    // One clear sentence for whatever stops a scan before it starts.
    private static string? Validate(ScanTargets.Result parsed, ScanPortSpec ports, ScanOptions o)
    {
        if (parsed.Ips.Count == 0 && parsed.Hostnames.Count == 0)
            return parsed.Errors.Count > 0
                ? "No valid targets — couldn't read " + string.Join(", ", parsed.Errors.Take(4)) + ". Use an IP, a host name, a range (10.0.0.1-50) or a CIDR block (10.0.0.0/24)."
                : "Add a target: an IP, a host, a range or a CIDR block.";
        if (o.PingOnly) return null;
        if (!o.Tcp && !o.Udp && ports.Total == 0) return "Tick TCP and/or UDP.";
        if (ports.Total == 0)
            return ports.Errors.Count > 0
                ? "Couldn't read the ports: " + string.Join(", ", ports.Errors.Take(4)) + ". Use 80,443 · 1-1024 · top-100 · U:53."
                : "Add ports to scan, or pick a preset.";
        return null;
    }

    // "Done in 4.2 s · 1 of 1 host up · 3 open · 1,234 probes (300/s)"
    private static string Summary(ScanPass pass)
    {
        double s = pass.Elapsed.TotalSeconds;
        string time = s < 60 ? $"{s:0.0} s" : $"{(int)(s / 60)} min {s % 60:00} s";
        string head = pass.Stopped ? $"Stopped after {time}" : $"Done in {time}";
        string hosts = $"{pass.HostsUp:N0} of {Hosts(pass.Targets.Count)} up";
        if (pass.Options.PingOnly)
            return $"{head} · {hosts} · {pass.ProbesSent:N0} probes";
        int open = pass.Targets.Sum(h => h.AcceptsAll ? h.Count(ScanProto.Udp, PortState.Open) : h.Count(PortState.Open));
        string tail = $" · {open:N0} open · {pass.ProbesSent:N0} probes" + (s > 0.5 ? $" ({pass.ProbesSent / s:N0}/s)" : "");
        if (pass.Scanned.Count == 0 && !pass.Stopped)
            return $"{head} · no live hosts among {Hosts(pass.Targets.Count)}"
                   + (pass.Options.SkipDiscovery ? "" : " — tick Skip ping (-Pn) to scan them anyway");
        return head + " · " + hosts + tail;
    }

    // ---- live progress (UI-thread timer) ----

    private void Tick(ScanEngine engine)
    {
        Drain(final: false);
        var p = engine.Progress;
        long done = Interlocked.Read(ref p.Done), total = Interlocked.Read(ref p.Total);
        OpenCount = Interlocked.Read(ref p.Open);
        OpenFilteredCount = Interlocked.Read(ref p.OpenFiltered);
        ClosedCount = Interlocked.Read(ref p.Closed);
        FilteredCount = Interlocked.Read(ref p.Filtered);
        HostsUpCount = Interlocked.Read(ref p.HostsUp);

        double frac = total > 0 ? Math.Clamp((double)done / total, 0, 1) : 0;
        double secs = p.PhaseClock.Elapsed.TotalSeconds;
        double rate = secs > 0.3 ? done / secs : 0;
        string eta = rate > 0 && total > done ? " · ETA " + FormatEta((total - done) / rate) : "";
        switch (p.Phase)
        {
            case ScanProgress.Stage.Discovery:
                Progress = frac * 0.15;
                ProgressText = $"Finding live hosts · {done:N0} / {total:N0} checked · {HostsUpCount:N0} up{eta}";
                break;
            case ScanProgress.Stage.Ports:
                Progress = 0.15 + frac * 0.85;
                ProgressText = $"{done:N0} / {total:N0} probes · {rate:N0}/s{eta}";
                break;
            case ScanProgress.Stage.UdpRecheck:
                Progress = frac;
                ProgressText = $"Re-checking silent UDP ports slowly — {Hosts(p.RecheckHosts)} rate-limit ICMP replies · {done:N0} / {total:N0}{eta}";
                break;
            case ScanProgress.Stage.Finishing:
                Progress = 1;
                ProgressText = "Finishing — names and MAC addresses…";
                break;
        }
    }

    private static string FormatEta(double seconds)
    {
        if (double.IsNaN(seconds) || double.IsInfinity(seconds) || seconds < 0) return "0:00";
        var ts = TimeSpan.FromSeconds(Math.Min(seconds, 359_999));
        return ts.TotalHours >= 1 ? $"{(int)ts.TotalHours}:{ts.Minutes:00}:{ts.Seconds:00}" : $"{ts.Minutes}:{ts.Seconds:00}";
    }

    // ---- targets ----

    // Resolve hostname targets (bounded, with a deadline), then merge with the literal IPs into a deduped, address-
    // ordered list. A name resolves once: the first address is scanned (IPv4 preferred, v4-mapped unwrapped), the rest
    // are listed in the report (nmap's "Other addresses"). Unresolvable names go to parsed.Errors with the reason.
    private static async Task<List<ScanHost>> BuildTargetsAsync(ScanTargets.Result parsed, CancellationToken ct)
    {
        var byIp = new Dictionary<string, ScanHost>(StringComparer.OrdinalIgnoreCase);
        foreach (var ip in parsed.Ips)
        {
            var h = new ScanHost(ip, null);
            byIp.TryAdd(h.Ip, h);
        }

        if (parsed.Hostnames.Count > 0)
        {
            var resolved = new ConcurrentBag<(IPAddress Addr, string Name, List<IPAddress> Others)>();
            var failed = new ConcurrentBag<string>();
            using var slots = new SemaphoreSlim(DnsParallel);
            var tasks = parsed.Hostnames.Distinct(StringComparer.OrdinalIgnoreCase).Select(async name =>
            {
                await slots.WaitAsync(ct);
                try
                {
                    // Punycode an internationalized name: getaddrinfo on Linux/Android/macOS fails on raw UTF-8.
                    var addrs = await Dns.GetHostAddressesAsync(IcmpPinger.AsciiHost(name), ct)
                                         .WaitAsync(TimeSpan.FromMilliseconds(DnsTimeoutMs), ct);
                    var all = addrs.Select(x => x.IsIPv4MappedToIPv6 ? x.MapToIPv4() : x).Distinct().ToList();
                    var a = all.FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetwork) ?? all.FirstOrDefault();
                    if (a is not null) resolved.Add((a, name, all.Where(x => !x.Equals(a)).ToList()));
                    else failed.Add($"{name} (no address records)");
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
                catch (TimeoutException) { failed.Add($"{name} (DNS timed out)"); }
                catch (SocketException se) { failed.Add($"{name} ({DnsReason(se.SocketErrorCode)})"); }
                catch (Exception) { failed.Add($"{name} (unresolved)"); }
                finally { slots.Release(); }
            }).ToList();
            try { await Task.WhenAll(tasks); } catch (OperationCanceledException) { }

            foreach (var (addr, name, others) in resolved.OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase))
            {
                var h = new ScanHost(addr, name) { OtherAddresses = others.Count > 0 ? others : null };
                if (byIp.TryGetValue(h.Ip, out var existing))
                {
                    if (existing.Name is null) byIp[h.Ip] = h;   // the same address typed as a literal too: keep the name
                    continue;
                }
                if (byIp.Count >= ScanTargets.MaxHosts) { parsed.Capped = true; break; }
                byIp[h.Ip] = h;
            }
            parsed.Errors.AddRange(failed.OrderBy(x => x, StringComparer.OrdinalIgnoreCase));
        }
        return byIp.Values.OrderBy(h => h.Address, IpAddressComparer.Instance).ToList();
    }

    private static string DnsReason(SocketError e) => e switch
    {
        SocketError.HostNotFound => "no such host",
        SocketError.NoData => "no address records",
        SocketError.TryAgain => "DNS server not answering",
        SocketError.NetworkUnreachable or SocketError.NetworkDown => "no network",
        _ => "unresolved",
    };
}

public sealed record PortPreset(string Name, string Ports);
