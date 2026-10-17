using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using Renci.SshNet;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>
/// The Server sub-tab: host, OS, uptime, load, CPU, memory / swap, disks and the top processes — from ONE exec command
/// batch (no agent on the server), refreshed every ~5 s only while the view is on screen and the session is up.
/// </summary>
public partial class SshViewModel
{
    /// <summary>Time between refreshes (a test shortens it).</summary>
    internal static TimeSpan HealthInterval { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>Set by the view: the Server sub-tab is attached (shown).</summary>
    [ObservableProperty] private bool _serverViewShown;

    /// <summary>Optional check from the view before each refresh (e.g. the page is hidden on a phone).</summary>
    public Func<bool>? ServerViewProbe { get; set; }

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(ShowHealthLoading))] private bool _hasHealth;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(ShowHealthLoading))] private bool _healthBusy;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasHealthError), nameof(ShowHealthLoading))] private string _healthError = string.Empty;
    [ObservableProperty] private string _healthHost = string.Empty;
    [ObservableProperty] private string _healthOs = string.Empty;
    [ObservableProperty] private string _healthUptime = string.Empty;
    [ObservableProperty] private string _healthUpdated = string.Empty;

    [ObservableProperty] private double _cpuPercent;
    [ObservableProperty] private string _cpuText = "—";
    [ObservableProperty] private string _cpuDetail = string.Empty;
    [ObservableProperty] private string _loadText = "—";
    [ObservableProperty] private string _loadDetail = "1 · 5 · 15 min";
    [ObservableProperty] private double _memPercent;
    [ObservableProperty] private string _memText = "—";
    [ObservableProperty] private string _memDetail = string.Empty;
    [ObservableProperty] private double _swapPercent;
    [ObservableProperty] private string _swapText = "—";
    [ObservableProperty] private string _swapDetail = string.Empty;
    [ObservableProperty] private bool _cpuHigh;
    [ObservableProperty] private bool _memHigh;
    [ObservableProperty] private bool _swapHigh;
    [ObservableProperty] private IReadOnlyList<SshDiskRow> _disks = Array.Empty<SshDiskRow>();
    [ObservableProperty] private IReadOnlyList<SshProcRow> _processes = Array.Empty<SshProcRow>();
    /// <summary>Not Linux: some parts (memory, CPU) can't be read without /proc.</summary>
    [ObservableProperty] private string _healthNote = string.Empty;

    public bool HasHealthError => HealthError.Length > 0;
    public bool ShowHealthLoading => !HasHealth && HealthError.Length == 0;

    /// <summary>Completed refreshes (tests: polling stops while the view is hidden).</summary>
    public int HealthRefreshCount { get; private set; }

    private CancellationTokenSource? _healthCts;
    private DateTime _healthStamp;

    partial void OnServerViewShownChanged(bool value) => UpdateHealthLoop();

    // Starts / stops the polling loop: only while connected AND the Server view is shown.
    private void UpdateHealthLoop()
    {
        bool want = IsConnected && ServerViewShown && _session is not null;
        if (want && _healthCts is null)
        {
            var cts = _healthCts = new CancellationTokenSource();
            _ = HealthLoopAsync(_session!, cts);
        }
        else if (!want && _healthCts is { } running)
        {
            running.Cancel();
            _healthCts = null;
        }
    }

    // UI thread (awaits hop back to it).
    private async Task HealthLoopAsync(SshSession s, CancellationTokenSource cts)
    {
        var ct = cts.Token;
        try
        {
            while (!ct.IsCancellationRequested && ReferenceEquals(_session, s))
            {
                if (ServerViewProbe?.Invoke() != false) await RefreshHealthAsync(s, ct);
                UpdateAge();
                await Task.Delay(HealthInterval, ct);
            }
        }
        catch (OperationCanceledException) { }
        finally { cts.Dispose(); }
    }

    /// <summary>Refresh now (the Server view's button).</summary>
    [RelayCommand]
    private Task RefreshHealth() => _session is { } s ? RefreshHealthAsync(s, CancellationToken.None) : Task.CompletedTask;

    private async Task RefreshHealthAsync(SshSession s, CancellationToken ct)
    {
        if (HealthBusy) return;
        HealthBusy = true;
        try
        {
            bool twoSamples = s.LastCpu is null;
            var snap = await Task.Run(() =>
            {
                string output = RunCapped(s.Client, SshHealth.Command(twoSamples), ct);
                return SshHealth.Parse(output);
            }, ct);
            if (!ReferenceEquals(_session, s)) return;
            ApplyHealth(s, snap);
            HealthRefreshCount++;
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (ReferenceEquals(_session, s)) HealthError = "Couldn't read the server's status: " + ex.Message;
        }
        finally { HealthBusy = false; }
    }

    // The batch's output, read as it arrives and capped (a misbehaving server can't make us buffer without end).
    private static string RunCapped(SshClient client, string command, CancellationToken ct)
    {
        using var cmd = client.CreateCommand(command);
        cmd.CommandTimeout = TimeSpan.FromSeconds(20);
        var ar = cmd.BeginExecute();
        using var reg = ct.Register(() => { try { cmd.CancelAsync(); } catch { } });
        var sb = new StringBuilder();
        using (var reader = new StreamReader(cmd.OutputStream, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 8192, leaveOpen: true))
        {
            var buf = new char[8192];
            int n;
            while ((n = reader.Read(buf, 0, buf.Length)) > 0)
            {
                int room = SshHealth.MaxOutputChars - sb.Length;
                sb.Append(buf, 0, Math.Min(n, room));
                if (n >= room) { try { cmd.CancelAsync(); } catch { } break; }
            }
        }
        try { cmd.EndExecute(ar); }
        catch (Exception) when (ct.IsCancellationRequested || sb.Length > 0) { }
        ct.ThrowIfCancellationRequested();
        return sb.ToString();
    }

    private void ApplyHealth(SshSession s, SshHealthSnapshot snap)
    {
        if (!snap.Recognized)
        {
            HealthError = "This server didn't answer the status commands (they need a Linux or Unix shell).";
            return;
        }
        HealthError = string.Empty;
        HealthHost = snap.Hostname.Length > 0 ? snap.Hostname : s.Login.Host;
        HealthOs = string.Join(" · ", new[] { snap.Os, snap.Kernel }.Where(x => x.Length > 0));
        HealthUptime = snap.UptimeSeconds is double up ? "up " + SshHealth.Uptime(up) : snap.UptimeText.Length > 0 ? "up " + snap.UptimeText : string.Empty;

        // CPU: against the previous refresh (≈5 s), or the batch's own two readings on the first one.
        double? cpu = snap.Cpu2 is not null ? SshHealth.CpuPercent(snap.Cpu1, snap.Cpu2) : SshHealth.CpuPercent(s.LastCpu, snap.Cpu1);
        s.LastCpu = snap.Cpu2 ?? snap.Cpu1;
        CpuPercent = cpu ?? 0;
        CpuText = cpu is double c ? c.ToString("0", CultureInfo.InvariantCulture) + "%" : "—";
        CpuHigh = cpu >= 85;
        CpuDetail = snap.Cpus > 0 ? (snap.Cpus == 1 ? "1 core" : $"{snap.Cpus} cores") : string.Empty;

        LoadText = snap.Load is { } l ? string.Join("  ", l.Select(x => x.ToString("0.00", CultureInfo.InvariantCulture))) : "—";
        LoadDetail = "1 · 5 · 15 min";

        if (snap.MemTotalKb > 0 && snap.MemAvailableKb >= 0)
        {
            long used = Math.Max(0, snap.MemTotalKb - snap.MemAvailableKb);
            MemPercent = 100.0 * used / snap.MemTotalKb;
            MemText = MemPercent.ToString("0", CultureInfo.InvariantCulture) + "%";
            MemDetail = $"{SshHealth.Kb(used)} of {SshHealth.Kb(snap.MemTotalKb)}";
            MemHigh = MemPercent >= 90;
        }
        else { MemPercent = 0; MemText = "—"; MemDetail = string.Empty; MemHigh = false; }

        if (snap.SwapTotalKb > 0 && snap.SwapFreeKb >= 0)
        {
            long used = Math.Max(0, snap.SwapTotalKb - snap.SwapFreeKb);
            SwapPercent = 100.0 * used / snap.SwapTotalKb;
            SwapText = SwapPercent.ToString("0", CultureInfo.InvariantCulture) + "%";
            SwapDetail = $"{SshHealth.Kb(used)} of {SshHealth.Kb(snap.SwapTotalKb)}";
            SwapHigh = SwapPercent >= 50;
        }
        else if (snap.SwapTotalKb == 0) { SwapPercent = 0; SwapText = "off"; SwapDetail = "no swap"; SwapHigh = false; }
        else { SwapPercent = 0; SwapText = "—"; SwapDetail = string.Empty; SwapHigh = false; }

        Disks = snap.Disks.Select(d => new SshDiskRow(d)).ToList();
        Processes = snap.Processes.Select(p => new SshProcRow(p)).ToList();
        HealthNote = snap.HasProcStat ? string.Empty : "No /proc on this server: CPU and memory aren't available.";
        HasHealth = true;
        _healthStamp = DateTime.UtcNow;
        UpdateAge();
    }

    private void UpdateAge()
    {
        if (!HasHealth) { HealthUpdated = string.Empty; return; }
        int secs = (int)Math.Max(0, (DateTime.UtcNow - _healthStamp).TotalSeconds);
        HealthUpdated = secs < 2 ? "updated just now" : $"updated {secs} s ago";
    }

    private void ResetHealth()
    {
        HasHealth = false;
        HealthError = string.Empty;
        HealthHost = HealthOs = HealthUptime = HealthUpdated = HealthNote = string.Empty;
        CpuPercent = MemPercent = SwapPercent = 0;
        CpuText = MemText = SwapText = LoadText = "—";
        CpuDetail = MemDetail = SwapDetail = string.Empty;
        CpuHigh = MemHigh = SwapHigh = false;
        Disks = Array.Empty<SshDiskRow>();
        Processes = Array.Empty<SshProcRow>();
    }
}
