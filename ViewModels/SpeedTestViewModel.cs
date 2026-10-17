using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>
/// The Speed Test tab: pick a destination (Cloudflare, a public test-file host in one of many cities, or one of the
/// user's own) and the number of parallel connections, then Start / Stop. The
/// engine (<see cref="SpeedTestEngine"/>) runs off the UI thread and reports ~10 times a second; only the newest report
/// is applied (one pending post at a time). A finished test goes to the top of a short history kept in the profile.
/// </summary>
public partial class SpeedTestViewModel : ObservableObject
{
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;
    internal const string Intro = "Pick a server, then press Start.";
    internal const string ConnectionsKey = "speed.connections";

    /// <summary>Tests / screenshots: shorten the engine's phases (the connection count still comes from the tab).</summary>
    public SpeedTestOptions? Options { get; set; }

    /// <summary>Tests / screenshots: where a destination's traffic really goes (a loopback stand-in), its name kept.</summary>
    internal Func<SpeedTestDestination, SpeedTestDestination>? Route { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanEditSetup))]
    private bool _isRunning;

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasStatus))] private string _status = Intro;

    public bool HasStatus => !string.IsNullOrEmpty(Status);

    // ---- gauge + big number ----
    [ObservableProperty] private double _gaugeValue;
    [ObservableProperty] private double _gaugeMax = 1000;
    [ObservableProperty] private bool _gaugeIsUpload;
    [ObservableProperty] private string _bigNumber = "—";
    [ObservableProperty] private string _bigUnit = "Mbps";
    [ObservableProperty] private string _bigCaption = "Download";

    // ---- phase steps (0..1 each) ----
    [ObservableProperty] private double _pingProgress;
    [ObservableProperty] private double _downloadProgress;
    [ObservableProperty] private double _uploadProgress;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(LatencyStepOn), nameof(DownloadStepOn), nameof(UploadStepOn))]
    private int _activeStep = -1;   // 0 latency, 1 download, 2 upload; -1 none

    public bool LatencyStepOn => ActiveStep == 0;
    public bool DownloadStepOn => ActiveStep == 1;
    public bool UploadStepOn => ActiveStep == 2;

    // ---- figures ----
    [ObservableProperty] private string _downloadText = "—";
    [ObservableProperty] private string _uploadText = "—";
    [ObservableProperty] private string _pingText = "—";
    [ObservableProperty] private string _jitterText = "—";
    [ObservableProperty] private string _loadedDownText = "—";
    [ObservableProperty] private string _loadedUpText = "—";
    /// <summary>The server of the shown result takes no uploads: the Upload tile says so instead of a number.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(UploadHasValue), nameof(UploadStepCaption), nameof(UploadTip))]
    private bool _uploadNa;

    public bool UploadHasValue => !UploadNa;
    public string UploadStepCaption => UploadNa ? "Upload · n/a" : "Upload";
    public string UploadTip => UploadNa
        ? "Upload: not supported by this server (it only serves downloads)"
        : "Upload: what the server acknowledged receiving";

    partial void OnUploadNaChanged(bool value)
    {
        if (value) LoadedUpText = "n/a";
        else if (LoadedUpText == "n/a") LoadedUpText = "—";
    }

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasGrade))] private string? _grade;
    [ObservableProperty] private string? _gradeTip;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(GradeGood), nameof(GradeFair), nameof(GradePoor))]
    private int _gradeLevel;   // 0 good, 1 fair, 2 poor

    public bool GradeGood => GradeLevel == 0;
    public bool GradeFair => GradeLevel == 1;
    public bool GradePoor => GradeLevel == 2;
    [ObservableProperty] private string _serverText = "—";
    [ObservableProperty] private string _clientText = "—";
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasResult))] private string? _resultTime;

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasError))] private string? _error;

    public bool HasGrade => !string.IsNullOrEmpty(Grade);
    public bool HasError => !string.IsNullOrEmpty(Error);
    public bool HasResult => !string.IsNullOrEmpty(ResultTime);
    public bool CanEditSetup => !IsRunning;

    // ---- connections (the user's one tuning knob) ----
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ConnectionsTip))]
    private int _connections = SpeedTestOptions.DefaultConnections;

    public string ConnectionsHint => "6 suits most links; 1 = a single download";

    public string ConnectionsTip
        => $"Parallel connections for the download (1 to 16; 6 is what web speed tests use). More connections fill a fast or distant link; " +
           $"1 shows what a single download gets. The upload uses {SpeedTestOptions.UploadStreamsFor(Connections)}.";

    partial void OnConnectionsChanged(int value)
    {
        int clamped = Math.Clamp(value, SpeedTestOptions.MinConnections, SpeedTestOptions.MaxConnections);
        if (clamped != value)
        {
            Connections = clamped;
            return;
        }
        if (_loaded) ProfileService.Instance.SetSetting(ConnectionsKey, value.ToString(Inv));
    }

    public ObservableCollection<SpeedHistoryRow> History { get; } = new();
    public bool HasHistory => History.Count > 0;

    private readonly List<SpeedTestRecord> _records;
    private string _resultConnections = "";
    private SpeedTestDestination _runDestination = SpeedTestDestinations.Cloudflare;
    private CancellationTokenSource? _cts;
    private int _run;
    private bool _loaded;

    public SpeedTestViewModel()
    {
        History.CollectionChanged += (_, _) => OnPropertyChanged(nameof(HasHistory));
        _records = SpeedTestHistory.Load();
        foreach (var r in _records) History.Add(new SpeedHistoryRow(r));
        Connections = Math.Clamp(ProfileService.Instance.GetInt(ConnectionsKey, SpeedTestOptions.DefaultConnections),
                                 SpeedTestOptions.MinConnections, SpeedTestOptions.MaxConnections);
        ProfileService.Instance.Remove("speed.mode");   // the local network mode is gone
        LoadDestinations();
        _loaded = true;
        if (_records.FirstOrDefault() is { } last) ShowRecord(last);
    }

    // Concurrent executions allowed: the same button stops the test while the run (this command's task) goes on.
    [RelayCommand(AllowConcurrentExecutions = true)]
    private Task Toggle()
    {
        if (IsRunning)
        {
            _cts?.Cancel();
            return Task.CompletedTask;
        }
        return RunAsync();
    }

    /// <summary>One test run: the button turns into Stop, the figures reset, and whatever goes wrong ends as ONE error
    /// (a stop as "Stopped.").</summary>
    private async Task RunAsync()
    {
        var destination = SelectedDestination;
        var target = Route?.Invoke(destination) ?? destination;
        var options = (Options ?? new SpeedTestOptions()) with { Connections = Connections };
        int run = ++_run;
        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        var token = _cts.Token;
        IsRunning = true;
        Error = null;
        ResetFigures();
        UploadNa = destination.HasUpload == false;
        _runDestination = destination;
        ServerText = ServerLabel(destination, null, null);
        Status = $"Connecting to {destination.Name}…";

        try
        {
            var engine = new SpeedTestEngine(target, options);
            var result = await Task.Run(() => engine.RunAsync(p => Report(run, p), token), token);
            if (run != _run) return;
            ApplyFinal(result, destination);
            Remember(result, destination);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            if (run == _run) Status = "Stopped.";
        }
        catch (SpeedTestException ex)
        {
            if (run == _run) Fail(ex.Message);
        }
        catch (Exception ex)
        {
            if (run == _run) Fail($"The speed test failed: {ex.Message}");
        }
        finally
        {
            if (run == _run)
            {
                IsRunning = false;
                ActiveStep = -1;
            }
        }
    }

    // One message, the error itself (the status line stays empty beside it).
    private void Fail(string message)
    {
        Error = message;
        Status = string.Empty;
        GaugeValue = 0;
        BigNumber = "—";
    }

    // ---------- live reports (pool thread → UI, newest only) ----------

    private SpeedTestProgress? _pending;
    private int _queued;

    private void Report(int run, SpeedTestProgress p)
    {
        Volatile.Write(ref _pending, p);
        if (Interlocked.Exchange(ref _queued, 1) == 1) return;
        Dispatcher.UIThread.Post(() =>
        {
            Interlocked.Exchange(ref _queued, 0);
            var latest = Volatile.Read(ref _pending);
            if (latest is null || run != _run || !IsRunning) return;
            Apply(latest);
        }, DispatcherPriority.Background);
    }

    private void Apply(SpeedTestProgress p)
    {
        if (p.Endpoint is { } ep)
        {
            UploadNa = !ep.Upload;
            ServerText = ServerLabel(_runDestination, ep, p.Server);
        }
        switch (p.Phase)
        {
            case SpeedTestPhase.Connecting:
                Status = $"Connecting to {_runDestination.Name}…";
                break;
            case SpeedTestPhase.Latency:
                Status = "Measuring latency…";
                ActiveStep = 0;
                PingProgress = p.PhaseFraction;
                BigCaption = "Ping";
                BigUnit = "ms";
                BigNumber = Ms(p.CurrentLatencyMs);
                GaugeValue = 0;
                break;
            case SpeedTestPhase.Download:
                Status = p.Endpoint is { } d ? $"Measuring download over {Plural(d.DownloadStreams, "connection")}…" : "Measuring download…";
                ActiveStep = 1;
                PingProgress = 1;
                DownloadProgress = p.PhaseFraction;
                ShowLive(p.CurrentMbps, upload: false);
                if (!double.IsNaN(p.CurrentMbps)) DownloadText = Mbps(p.CurrentMbps);
                LoadedDownText = WithMs(p.LoadedDownMs);
                break;
            case SpeedTestPhase.Upload:
                Status = p.Endpoint is { } u ? $"Measuring upload over {Plural(u.UploadStreams, "connection")}…" : "Measuring upload…";
                ActiveStep = 2;
                PingProgress = DownloadProgress = 1;
                UploadProgress = p.PhaseFraction;
                ShowLive(p.CurrentMbps, upload: true);
                DownloadText = Mbps(p.DownloadMbps);
                if (!double.IsNaN(p.CurrentMbps)) UploadText = Mbps(p.CurrentMbps);
                LoadedDownText = WithMs(p.LoadedDownMs);
                LoadedUpText = WithMs(p.LoadedUpMs);
                break;
        }
        if (!double.IsNaN(p.LatencyMs)) PingText = Ms(p.LatencyMs);
        if (!double.IsNaN(p.JitterMs)) JitterText = Ms(p.JitterMs);
        if (p.Server is { } s) ShowClient(s);
    }

    private void ShowLive(double mbps, bool upload)
    {
        GaugeIsUpload = upload;
        BigCaption = upload ? "Upload" : "Download";
        BigUnit = "Mbps";
        if (double.IsNaN(mbps))
        {
            BigNumber = "…";
            return;
        }
        if (mbps > GaugeMax * 0.95 && GaugeMax < 10000) GaugeMax = 10000;   // past a gigabit: the 10 Gbps scale
        GaugeValue = mbps;
        BigNumber = Mbps(mbps);
    }

    private void ResetFigures()
    {
        GaugeValue = 0;
        GaugeMax = 1000;
        GaugeIsUpload = false;
        BigNumber = "—";
        BigUnit = "Mbps";
        BigCaption = "Download";
        PingProgress = DownloadProgress = UploadProgress = 0;
        ActiveStep = -1;
        DownloadText = UploadText = PingText = JitterText = LoadedDownText = LoadedUpText = "—";
        UploadNa = false;
        Grade = null;
        GradeTip = null;
        ResultTime = null;
        ServerText = ClientText = "—";
        _resultConnections = "";
    }

    private void ApplyFinal(SpeedTestResult r, SpeedTestDestination destination)
    {
        var ep = r.Endpoint;
        PingProgress = DownloadProgress = 1;
        UploadProgress = ep.Upload ? 1 : 0;
        UploadNa = !ep.Upload;
        DownloadText = Mbps(r.DownloadMbps);
        UploadText = Mbps(r.UploadMbps);
        PingText = Ms(r.LatencyMs);
        JitterText = Ms(r.JitterMs);
        LoadedDownText = WithMs(r.LoadedDownMs);
        LoadedUpText = UploadNa ? "n/a" : WithMs(r.LoadedUpMs);
        SetGrade(r.LatencyMs, r.LoadedDownMs, r.LoadedUpMs);
        ServerText = ServerLabel(destination, ep, r.Server);
        ClientText = "—";
        if (r.Server is { } s) ShowClient(s);
        GaugeIsUpload = false;
        if (r.DownloadMbps > GaugeMax * 0.95 && GaugeMax < 10000) GaugeMax = 10000;
        GaugeValue = double.IsNaN(r.DownloadMbps) ? 0 : r.DownloadMbps;
        BigCaption = "Download";
        BigUnit = "Mbps";
        BigNumber = Mbps(r.DownloadMbps);
        ResultTime = r.Time.ToLocalTime().ToString("yyyy-MM-dd HH:mm", Inv);
        _resultConnections = ConnectionsText(ep.DownloadStreams, ep.Upload ? ep.UploadStreams : 0);
        Status = $"Done · {ResultTime} · {_resultConnections}";
    }

    // The last saved result fills the card when the tab opens.
    private void ShowRecord(SpeedTestRecord r)
    {
        DownloadText = Mbps(r.DownloadMbps);
        UploadText = Mbps(r.UploadMbps);
        UploadNa = r.NoUpload;
        PingText = Ms(r.LatencyMs);
        JitterText = Ms(r.JitterMs);
        LoadedDownText = WithMs(r.LoadedDownMs);
        LoadedUpText = UploadNa ? "n/a" : WithMs(r.LoadedUpMs);
        SetGrade(r.LatencyMs, r.LoadedDownMs, r.LoadedUpMs);
        ServerText = string.IsNullOrEmpty(r.Server) ? "—" : r.Server;
        ClientText = string.IsNullOrEmpty(r.Isp) ? "—" : r.Isp;
        ResultTime = r.Time.ToLocalTime().ToString("yyyy-MM-dd HH:mm", Inv);
        _resultConnections = r.Connections > 0 ? ConnectionsText(r.Connections, r.NoUpload ? 0 : SpeedTestOptions.UploadStreamsFor(r.Connections)) : "";
        PingProgress = DownloadProgress = 1;
        UploadProgress = r.NoUpload ? 0 : 1;
        GaugeMax = r.DownloadMbps > 950 ? 10000 : 1000;
        GaugeIsUpload = false;
        GaugeValue = double.IsNaN(r.DownloadMbps) ? 0 : r.DownloadMbps;
        BigCaption = "Download";
        BigUnit = "Mbps";
        BigNumber = Mbps(r.DownloadMbps);
        Status = $"Last test · {ResultTime}";
    }

    /// <summary>"Leaseweb · Amsterdam, NL", "Cloudflare · Frankfurt-am-Main (FRA)", "My NAS (files.example.com)"; " · HTTP"
    /// when it ran over plain HTTP.</summary>
    internal static string ServerLabel(SpeedTestDestination d, SpeedTestEndpoint? ep, SpeedTestServer? server)
    {
        string label;
        if (d.Kind == SpeedTestKind.Cloudflare && d.Place.Length == 0)
            label = server is { } s && (s.Colo is not null || s.ColoCity is not null) ? $"{d.Provider} · {s.ServerLabel}" : d.Provider;
        else if (d.Saved && d.Kind != SpeedTestKind.Speedtest)
            label = d.Provider.Equals(d.Url.Host, StringComparison.OrdinalIgnoreCase) ? d.Provider : $"{d.Provider} ({d.Url.Host})";
        else
            label = d.CountryCode.Length > 0 ? $"{d.Name}, {d.CountryCode}" : d.Name;
        bool secure = ep?.Secure ?? d.Secure;
        return secure ? label : label + " · HTTP";
    }

    private void ShowClient(SpeedTestServer s)
    {
        var parts = new List<string>();
        if (!string.IsNullOrEmpty(s.ClientIp)) parts.Add(s.ClientIp!);
        string isp = s.Isp is { Length: > 0 } name ? (s.Asn > 0 ? $"{name} (AS{s.Asn})" : name) : s.Asn > 0 ? $"AS{s.Asn}" : string.Empty;
        if (isp.Length > 0) parts.Add(isp);
        string where = string.Join(", ", new[] { s.ClientCity, s.ClientCountry }.Where(x => !string.IsNullOrEmpty(x)));
        if (where.Length > 0) parts.Add(where);
        ClientText = parts.Count > 0 ? string.Join(" · ", parts) : "—";
    }

    // Bufferbloat: how much latency grows under load (the worse of download / upload), graded the way the common
    // bufferbloat tests do it: A+ < 5 ms, A < 30, B < 60, C < 200, D < 400, F beyond.
    private void SetGrade(double idle, double loadedDown, double loadedUp)
    {
        double worst = Math.Max(double.IsNaN(loadedDown) ? double.MinValue : loadedDown, double.IsNaN(loadedUp) ? double.MinValue : loadedUp);
        if (double.IsNaN(idle) || worst == double.MinValue)
        {
            Grade = null;
            GradeTip = null;
            return;
        }
        double increase = Math.Max(0, worst - idle);
        (Grade, GradeLevel) = BufferbloatGrade(increase);
        GradeTip = $"Bufferbloat {Grade}: latency grows by {Ms(increase)} ms when the link is busy " +
                   "(A+ under 5 ms, A under 30, B under 60, C under 200, D under 400).";
    }

    /// <summary>The grade for a latency increase under load (ms), and its level: 0 good, 1 fair, 2 poor.</summary>
    internal static (string Grade, int Level) BufferbloatGrade(double increaseMs) => increaseMs switch
    {
        < 5 => ("A+", 0),
        < 30 => ("A", 0),
        < 60 => ("B", 1),
        < 200 => ("C", 1),
        < 400 => ("D", 2),
        _ => ("F", 2),
    };

    // ---------- history ----------

    private void Remember(SpeedTestResult r, SpeedTestDestination destination)
    {
        var ep = r.Endpoint;
        var record = new SpeedTestRecord(r.Time, r.DownloadMbps, r.UploadMbps, r.LatencyMs, r.JitterMs, r.LoadedDownMs, r.LoadedUpMs,
                                         ServerLabel(destination, ep, r.Server), r.Server?.IspLabel is { Length: > 0 } isp ? isp : null,
                                         ep.DownloadStreams, !ep.Upload);
        _records.Insert(0, record);
        if (_records.Count > SpeedTestHistory.Capacity) _records.RemoveRange(SpeedTestHistory.Capacity, _records.Count - SpeedTestHistory.Capacity);
        History.Insert(0, new SpeedHistoryRow(record));
        while (History.Count > SpeedTestHistory.Capacity) History.RemoveAt(History.Count - 1);
        SpeedTestHistory.Save(_records);
    }

    [RelayCommand]
    private void ClearHistory()
    {
        _records.Clear();
        History.Clear();
        SpeedTestHistory.Save(_records);
    }

    // ---------- copy ----------

    [RelayCommand]
    private async Task CopyResult()
    {
        if (!HasResult) return;
        await ClipboardHelper.SetTextAsync(BuildResultText());
    }

    /// <summary>The result card as plain text.</summary>
    public string BuildResultText()
    {
        var sb = new StringBuilder();
        sb.Append("Speed test · ").Append(ResultTime).Append(" · ").Append(ServerText);
        if (_resultConnections.Length > 0) sb.Append(" · ").Append(_resultConnections);
        sb.AppendLine();
        sb.Append("Download        ").Append(Unit(DownloadText, "Mbps")).AppendLine();
        sb.Append("Upload          ").Append(UploadNa ? "not supported by this server" : Unit(UploadText, "Mbps")).AppendLine();
        sb.Append("Ping            ").Append(Unit(PingText, "ms")).Append(" (jitter ").Append(Unit(JitterText, "ms")).Append(')').AppendLine();
        sb.Append("Loaded latency  download ").Append(LoadedDownText);
        if (!UploadNa) sb.Append(" · upload ").Append(LoadedUpText);
        if (HasGrade) sb.Append(" (bufferbloat ").Append(Grade).Append(')');
        sb.AppendLine();
        if (ClientText != "—") sb.Append("Client          ").Append(ClientText).AppendLine();
        return sb.ToString().TrimEnd();

        static string Unit(string v, string unit) => v == "—" ? v : v + " " + unit;
    }

    // ---------- formatting ----------

    internal static string Plural(int n, string what) => n == 1 ? $"1 {what}" : $"{n.ToString(Inv)} {what}s";

    /// <summary>"6 connections (3 up)": the download's and the upload's; "1 connection"; "4 connections" (no upload).</summary>
    internal static string ConnectionsText(int down, int up)
        => up > 0 && up != down ? $"{Plural(down, "connection")} ({up.ToString(Inv)} up)" : Plural(down, "connection");

    /// <summary>Three significant figures, like Cloudflare's page: 8.45 / 45.3 / 245 / 1250.</summary>
    internal static string Mbps(double v)
    {
        if (double.IsNaN(v) || v < 0) return "—";
        return v >= 100 ? v.ToString("0", Inv) : v >= 10 ? v.ToString("0.0", Inv) : v.ToString("0.00", Inv);
    }

    internal static string Ms(double v)
    {
        if (double.IsNaN(v) || v < 0) return "—";
        return v >= 10 ? v.ToString("0", Inv) : v.ToString("0.0", Inv);
    }

    /// <summary>"77 ms", or a bare "—" while unknown.</summary>
    internal static string WithMs(double v) => double.IsNaN(v) || v < 0 ? "—" : Ms(v) + " ms";
}

/// <summary>One line of the speed test history.</summary>
public sealed class SpeedHistoryRow
{
    public SpeedHistoryRow(SpeedTestRecord r)
    {
        Record = r;
        DateText = r.Time.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
        DownloadText = SpeedTestViewModel.Mbps(r.DownloadMbps);
        UploadText = r.NoUpload ? "n/a" : SpeedTestViewModel.Mbps(r.UploadMbps);
        PingText = SpeedTestViewModel.Ms(r.LatencyMs);
        JitterText = SpeedTestViewModel.Ms(r.JitterMs);
        ServerText = string.IsNullOrEmpty(r.Server) ? "—" : r.Server!;
        IspText = r.Isp ?? string.Empty;
        var tip = new StringBuilder();
        tip.Append(DateText).Append(" · ").Append(ServerText);
        if (IspText.Length > 0) tip.Append(" · ").Append(IspText);
        if (r.Connections > 0)
            tip.AppendLine().Append(SpeedTestViewModel.ConnectionsText(r.Connections, r.NoUpload ? 0 : SpeedTestOptions.UploadStreamsFor(r.Connections)));
        tip.AppendLine().Append("Loaded latency: download ").Append(SpeedTestViewModel.Ms(r.LoadedDownMs)).Append(" ms");
        if (r.NoUpload) tip.AppendLine().Append("Upload: not supported by this server");
        else tip.Append(", upload ").Append(SpeedTestViewModel.Ms(r.LoadedUpMs)).Append(" ms");
        Tip = tip.ToString();
    }

    public SpeedTestRecord Record { get; }
    public string DateText { get; }
    public string DownloadText { get; }
    public string UploadText { get; }
    public string PingText { get; }
    public string JitterText { get; }
    public string ServerText { get; }
    public string IspText { get; }
    public string Tip { get; }
}
