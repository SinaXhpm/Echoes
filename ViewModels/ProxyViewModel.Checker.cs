using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

/// <summary>One proxy in the checker's table.</summary>
public partial class ProxyCheckRow : ObservableObject
{
    public ProxyCheckRow(ProxyCheckEntry entry, int index)
    {
        Entry = entry;
        Index = index;
        Display = entry.Display;
        _protocol = entry.Kind switch
        {
            ProxyKind.Http => "HTTP",
            ProxyKind.Socks4 => "SOCKS4",
            ProxyKind.Socks4a => "SOCKS4a",
            ProxyKind.Socks5 => "SOCKS5",
            _ => string.Empty,
        };
        UpdateLine();
    }

    public ProxyCheckEntry Entry { get; }
    /// <summary>Its place in the pasted list ("Input order").</summary>
    public int Index { get; }
    /// <summary>scheme://user@host:port — never the password.</summary>
    public string Display { get; }

    public ProxyCheckStatus Status { get; private set; } = ProxyCheckStatus.Waiting;
    public int? ConnectMs { get; private set; }
    public int? FirstByteMs { get; private set; }

    [ObservableProperty] private string _statusText = "Waiting";
    [ObservableProperty] private string _protocol;
    [ObservableProperty] private string _connectText = string.Empty;
    [ObservableProperty] private string _firstByteText = string.Empty;
    [ObservableProperty] private string _exitIp = string.Empty;
    [ObservableProperty] private string _country = string.Empty;
    [ObservableProperty] private string _detail = string.Empty;
    /// <summary>The phone layout's second line: "SOCKS5 · 12 ms · 240 ms · 203.0.113.9".</summary>
    [ObservableProperty] private string _line = string.Empty;
    [ObservableProperty] private bool _isOk;
    [ObservableProperty] private bool _isWarn;
    [ObservableProperty] private bool _isBad;
    [ObservableProperty] private bool _isBusy;

    public string Tip => Detail.Length > 0 ? Display + " — " + Detail : Display;

    partial void OnDetailChanged(string value) => OnPropertyChanged(nameof(Tip));

    internal void MarkChecking()
    {
        Status = ProxyCheckStatus.Checking;
        StatusText = "Checking…";
        IsBusy = true;
    }

    internal void MarkStopped()
    {
        if (Status is not (ProxyCheckStatus.Waiting or ProxyCheckStatus.Checking)) return;
        Status = ProxyCheckStatus.Cancelled;
        StatusText = "Stopped";
        IsBusy = false;
    }

    internal void Apply(ProxyCheckResult r)
    {
        Status = r.Status;
        ConnectMs = r.ConnectMs;
        FirstByteMs = r.FirstByteMs;
        if (r.Protocol.Length > 0) Protocol = r.Protocol == "HTTP (no CONNECT)" ? "HTTP GET" : r.Protocol;
        ConnectText = r.ConnectMs is int c ? Ms(c) : string.Empty;
        FirstByteText = r.FirstByteMs is int f ? Ms(f) : string.Empty;
        ExitIp = r.ExitIp;
        Country = r.Country;
        Detail = r.Protocol == "HTTP (no CONNECT)" && r.Detail.Length == 0
            ? "A plain-HTTP proxy: it relays http:// requests but refuses CONNECT (no HTTPS tunnels)."
            : r.Detail;
        StatusText = Label(r.Status);
        IsBusy = false;
        IsOk = r.Status == ProxyCheckStatus.Working;
        IsWarn = r.Status is ProxyCheckStatus.AuthRequired or ProxyCheckStatus.AuthFailed;
        IsBad = !IsOk && !IsWarn;
        UpdateLine();
    }

    private void UpdateLine()
    {
        // most telling first: what it is, where it exits, how fast a request through it starts answering — or why not
        var parts = new List<string>();
        if (Protocol.Length > 0) parts.Add(Protocol);
        if (Status == ProxyCheckStatus.Working)
        {
            if (ExitIp.Length > 0) parts.Add(ExitIp);
            if (FirstByteText.Length > 0) parts.Add(FirstByteText);
        }
        else if (Detail.Length > 0) parts.Add(Detail);
        Line = string.Join(" · ", parts);
    }

    private static string Ms(int ms) => ms.ToString(CultureInfo.InvariantCulture) + " ms";

    public static string Label(ProxyCheckStatus s) => s switch
    {
        ProxyCheckStatus.Working => "Working",
        ProxyCheckStatus.AuthRequired => "Needs login",
        ProxyCheckStatus.AuthFailed => "Wrong login",
        ProxyCheckStatus.NotProxy => "Not a proxy",
        ProxyCheckStatus.Refused => "Refused",
        ProxyCheckStatus.Timeout => "Timed out",
        ProxyCheckStatus.Unreachable => "Unreachable",
        ProxyCheckStatus.Failed => "Failed",
        ProxyCheckStatus.Cancelled => "Stopped",
        ProxyCheckStatus.Checking => "Checking…",
        _ => "Waiting",
    };
}

/// <summary>
/// The "Check proxies" view: paste a list in any common format, test them all (16 at a time, cancellable) for
/// reachability, protocol, login, connect time, time to first byte and exit IP / country (<see cref="ProxyCheckEngine"/>),
/// then sort, copy the working ones as they were written, or export the results.
/// </summary>
public partial class ProxyViewModel
{
    public const int MaxParallelChecks = 16;
    public const int MaxInputChars = 200_000;

    /// <summary>0 = Server, 1 = Check proxies.</summary>
    [ObservableProperty] private int _viewIndex;

    [ObservableProperty] private string _checkInput = string.Empty;
    [ObservableProperty] private string _checkSummary = "One per line, or paste any text that has them.";

    /// <summary>What the table shows: the rows in the chosen order (replaced as a whole on a re-sort).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasCheckRows))]
    private IReadOnlyList<ProxyCheckRow> _checkRows = Array.Empty<ProxyCheckRow>();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CheckButtonText))]
    private bool _isChecking;

    [ObservableProperty] private int _workingCount;
    [ObservableProperty] private int _failedCount;
    [ObservableProperty] private int _leftCount;

    public string[] SortOptions { get; } = { "Input order", "Status", "Latency", "Country" };
    [ObservableProperty] private int _sortIndex;

    public bool HasCheckRows => CheckRows.Count > 0;
    public string CheckButtonText => IsChecking ? "Stop" : "Check proxies";

    private List<ProxyCheckRow> _allRows = new();
    private CancellationTokenSource? _checkCts;
    private DispatcherTimer? _previewTimer;

    partial void OnCheckInputChanged(string value)
    {
        if (IsChecking) return;
        // a quick count of what was pasted, a moment after typing stops
        _previewTimer ??= new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(350) };
        _previewTimer.Stop();
        _previewTimer.Tick -= OnPreviewTick;
        _previewTimer.Tick += OnPreviewTick;
        _previewTimer.Start();
    }

    private void OnPreviewTick(object? sender, EventArgs e)
    {
        _previewTimer?.Stop();
        if (IsChecking) return;
        CheckSummary = Describe(ProxyCheckParser.Parse(TextLimit.Cap(CheckInput, MaxInputChars)), ready: true);
    }

    private static string Describe(ProxyCheckParser.Result p, bool ready)
    {
        if (p.Entries.Count == 0) return "No proxies found yet: host:port, scheme://user:pass@host:port or host:port:user:pass.";
        string s = $"{p.Entries.Count} prox{(p.Entries.Count == 1 ? "y" : "ies")}";
        if (p.Duplicates > 0) s += $" · {p.Duplicates} duplicate{(p.Duplicates == 1 ? "" : "s")} skipped";
        if (p.OverCap > 0) s += $" · {p.OverCap} over the {ProxyCheckParser.DefaultCap} limit skipped";
        return ready ? s + "." : s;
    }

    partial void OnSortIndexChanged(int value)
    {
        if (!_restoring && value >= 0) SaveInt(KSort, value);
        ApplySort();
    }

    private void ApplySort()
    {
        IEnumerable<ProxyCheckRow> rows = _allRows;
        rows = SortIndex switch
        {
            1 => rows.OrderBy(r => StatusRank(r.Status)).ThenBy(r => r.FirstByteMs ?? int.MaxValue).ThenBy(r => r.Index),
            2 => rows.OrderBy(r => r.FirstByteMs is null ? 1 : 0).ThenBy(r => r.FirstByteMs ?? int.MaxValue)
                     .ThenBy(r => r.ConnectMs ?? int.MaxValue).ThenBy(r => r.Index),
            3 => rows.OrderBy(r => r.Country.Length == 0 ? 1 : 0).ThenBy(r => r.Country, StringComparer.Ordinal)
                     .ThenBy(r => r.FirstByteMs ?? int.MaxValue).ThenBy(r => r.Index),
            _ => rows.OrderBy(r => r.Index),
        };
        CheckRows = rows.ToList();
    }

    private static int StatusRank(ProxyCheckStatus s) => s switch
    {
        ProxyCheckStatus.Working => 0,
        ProxyCheckStatus.AuthRequired or ProxyCheckStatus.AuthFailed => 1,
        ProxyCheckStatus.Failed => 2,
        ProxyCheckStatus.Timeout => 3,
        ProxyCheckStatus.NotProxy => 4,
        ProxyCheckStatus.Refused => 5,
        ProxyCheckStatus.Unreachable => 6,
        ProxyCheckStatus.Checking => 7,
        _ => 8,
    };

    [RelayCommand(AllowConcurrentExecutions = true)]   // the same button stops while it runs (a plain async command disables it until the run ends)
    private Task ToggleCheck()
    {
        if (IsChecking)
        {
            StopChecks();
            return Task.CompletedTask;
        }
        return RunChecksAsync();
    }

    /// <summary>Stop a running check (the Stop button, and app shutdown).</summary>
    public void StopChecks() => _checkCts?.Cancel();

    private async Task RunChecksAsync()
    {
        if (IsChecking) return;
        var parsed = ProxyCheckParser.Parse(TextLimit.Cap(CheckInput, MaxInputChars));
        if (parsed.Entries.Count == 0)
        {
            CheckSummary = "No proxies found. Paste host:port, scheme://user:pass@host:port or host:port:user:pass, one per line.";
            return;
        }
        _previewTimer?.Stop();
        SaveCheckList(CheckInput);
        var rows = parsed.Entries.Select((e, i) => new ProxyCheckRow(e, i)).ToList();
        _allRows = rows;
        ApplySort();
        WorkingCount = 0;
        FailedCount = 0;
        LeftCount = rows.Count;
        string found = Describe(parsed, ready: false);
        CheckSummary = $"Checking {found}…";
        IsChecking = true;
        _checkCts?.Dispose();
        var cts = _checkCts = new CancellationTokenSource();
        var ct = cts.Token;

        using var gate = new SemaphoreSlim(MaxParallelChecks);
        var tasks = rows.Select(row => Task.Run(async () =>
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                Dispatcher.UIThread.Post(row.MarkChecking);
                ProxyCheckResult r;
                try { r = await ProxyCheckEngine.CheckAsync(row.Entry, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
                catch (Exception ex) { r = new ProxyCheckResult { Status = ProxyCheckStatus.Failed, Detail = "Unexpected error: " + ex.Message }; }
                if (ct.IsCancellationRequested) return;
                Dispatcher.UIThread.Post(() =>
                {
                    if (!ReferenceEquals(_allRows, rows)) return;   // a newer run replaced the table
                    row.Apply(r);
                    LeftCount = Math.Max(0, LeftCount - 1);
                    if (r.Status == ProxyCheckStatus.Working) WorkingCount++;
                    else FailedCount++;
                });
            }
            finally { gate.Release(); }
        }, ct)).ToList();

        try { await Task.WhenAll(tasks); }
        catch (OperationCanceledException) { }

        // after every queued row update (same priority, posted earlier)
        Dispatcher.UIThread.Post(() =>
        {
            if (!ReferenceEquals(_checkCts, cts)) return;
            bool stopped = ct.IsCancellationRequested;
            foreach (var r in rows) r.MarkStopped();
            IsChecking = false;
            if (SortIndex != 0) ApplySort();
            int other = rows.Count - WorkingCount - FailedCount;
            CheckSummary = stopped
                ? $"Stopped: {WorkingCount} working, {FailedCount} failed, {other} not checked."
                : $"Done: {WorkingCount} of {rows.Count} working."
                  + (rows.Any(r => r.Status == ProxyCheckStatus.AuthRequired) ? " Some need a login: add user:pass to those lines." : string.Empty);
        });
    }

    [RelayCommand]
    private async Task PasteProxies()
    {
        try
        {
            string? text = await ClipboardHelper.GetTextAsync();
            if (string.IsNullOrWhiteSpace(text)) return;
            CheckInput = TextLimit.Cap(CheckInput.Length > 0 ? CheckInput.TrimEnd() + Environment.NewLine + text : text, MaxInputChars);
        }
        catch (Exception ex) { CheckSummary = "Couldn't paste: " + ex.Message; }
    }

    [RelayCommand]
    private void ClearCheck()
    {
        StopChecks();
        _checkCts = null;   // the stopped run's wrap-up then leaves the cleared page alone
        CheckInput = string.Empty;
        _allRows = new List<ProxyCheckRow>();
        CheckRows = Array.Empty<ProxyCheckRow>();
        WorkingCount = FailedCount = LeftCount = 0;
        IsChecking = false;
        CheckSummary = "One per line, or paste any text that has them.";
    }

    /// <summary>The working proxies as they were written (one per line), in the table's order.</summary>
    public string WorkingText()
        => string.Join(Environment.NewLine, CheckRows.Where(r => r.Status == ProxyCheckStatus.Working).Select(r => r.Entry.Original));

    public int WorkingTotal => _allRows.Count(r => r.Status == ProxyCheckStatus.Working);

    [RelayCommand]
    private async Task CopyWorking()
    {
        string text = WorkingText();
        if (text.Length == 0) { CheckSummary = "No working proxy to copy yet."; return; }
        try
        {
            await ClipboardHelper.SetTextAsync(text);
            int n = WorkingTotal;
            CheckSummary = $"Copied {n} working prox{(n == 1 ? "y" : "ies")} as written.";
        }
        catch (Exception ex) { CheckSummary = "Couldn't copy: " + ex.Message; }
    }

    /// <summary>Every result as CSV (the proxy without its password), in the table's order.</summary>
    public string ResultsCsv()
    {
        var sb = new StringBuilder("proxy,protocol,status,connect_ms,first_byte_ms,exit_ip,country,detail\r\n");
        foreach (var r in CheckRows)
        {
            sb.Append(Csv(r.Display)).Append(',')
              .Append(Csv(r.Protocol)).Append(',')
              .Append(Csv(r.StatusText)).Append(',')
              .Append(r.ConnectMs?.ToString(CultureInfo.InvariantCulture) ?? string.Empty).Append(',')
              .Append(r.FirstByteMs?.ToString(CultureInfo.InvariantCulture) ?? string.Empty).Append(',')
              .Append(Csv(r.ExitIp)).Append(',')
              .Append(Csv(r.Country)).Append(',')
              .Append(Csv(r.Detail)).Append("\r\n");
        }
        return sb.ToString();
    }

    // Quoted when needed; a leading = + - @ is defused so a spreadsheet never runs it as a formula.
    private static string Csv(string s)
    {
        if (s.Length > 0 && s[0] is '=' or '+' or '-' or '@') s = "'" + s;
        return s.IndexOfAny(new[] { ',', '"', '\r', '\n' }) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
    }

    /// <summary>The view saved an export: say so.</summary>
    public void ReportExport(string what, string fileName) => CheckSummary = $"{what} saved to {fileName}.";
}
