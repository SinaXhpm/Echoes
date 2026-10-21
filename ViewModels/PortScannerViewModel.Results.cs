using Avalonia.Platform.Storage;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

// The result listing: host headers with their ports beneath, kept sorted as results stream in; the filter and the
// All / Open / Changes views; the summary counters; and the exports.
public partial class PortScannerViewModel
{
    // Rows the list holds at most (each host's ports past nmap's collapse threshold are summarized anyway); the
    // exports always have everything.
    private const int MaxListed = 20_000;
    // Open rows taken live per pass before the end-of-pass listing (a tarpit can SYN-ACK thousands before it's caught).
    private const int MaxLive = 5_000;

    [ObservableProperty] private ObservableCollection<ScanRow> _rows = new();
    [ObservableProperty] private string _filterText = "";
    [ObservableProperty] private string _viewMode = "all";   // all | open | changes

    [ObservableProperty] private long _openCount;
    [ObservableProperty] private long _openFilteredCount;
    [ObservableProperty] private long _closedCount;
    [ObservableProperty] private long _filteredCount;
    [ObservableProperty] private long _hostsUpCount;
    [ObservableProperty] private int _hostsTotal;
    [ObservableProperty] private string _changesText = "";
    [ObservableProperty] private string _hiddenText = "";
    [ObservableProperty] private bool _hasResults;
    [ObservableProperty] private bool _isPingScan;
    [ObservableProperty] private bool _canExport;

    /// <summary>More than one target, or a ping scan: the hosts-up badge is worth showing.</summary>
    public bool MultiHost => HostsTotal > 1 || IsPingScan;
    partial void OnHostsTotalChanged(int value) => OnPropertyChanged(nameof(MultiHost));

    public bool HasOpenFiltered => OpenFilteredCount > 0;
    public bool HasFiltered => FilteredCount > 0;
    public bool HasClosed => ClosedCount > 0;
    public bool HasChanges => ChangesText.Length > 0;
    public bool HasWarning => WarningText.Length > 0;
    partial void OnOpenFilteredCountChanged(long value) => OnPropertyChanged(nameof(HasOpenFiltered));
    partial void OnFilteredCountChanged(long value) => OnPropertyChanged(nameof(HasFiltered));
    partial void OnClosedCountChanged(long value) => OnPropertyChanged(nameof(HasClosed));
    partial void OnChangesTextChanged(string value) => OnPropertyChanged(nameof(HasChanges));
    partial void OnWarningTextChanged(string value) => OnPropertyChanged(nameof(HasWarning));

    /// <summary>The Results tab's count: open ports, or live hosts for a ping scan.</summary>
    public string BadgeText => IsPingScan ? HostsUpCount.ToString("N0") : OpenCount.ToString("N0");
    partial void OnOpenCountChanged(long value) => OnPropertyChanged(nameof(BadgeText));
    partial void OnHostsUpCountChanged(long value) => OnPropertyChanged(nameof(BadgeText));
    partial void OnIsPingScanChanged(bool value)
    {
        OnPropertyChanged(nameof(BadgeText));
        OnPropertyChanged(nameof(MultiHost));
    }

    // The empty list explains itself: before a scan, while one runs, and after one that found nothing.
    public string EmptyTitle => IsScanning ? "Scanning…" : !CanExport ? "No results yet"
        : _lastPass is { Stopped: true } ? "Stopped" : "Nothing to list";
    public string EmptyText => IsScanning
        ? "Open ports appear as they're found; the rest when the pass ends."
        : !CanExport ? "Add targets on Setup and press Start scan."
        : _lastPass is { Stopped: true } ? "The scan was stopped before anything was found."
        : "No host answered. To scan hosts that block pings, tick Skip ping.";
    partial void OnIsScanningChanged(bool value) { OnPropertyChanged(nameof(EmptyTitle)); OnPropertyChanged(nameof(EmptyText)); }
    partial void OnCanExportChanged(bool value) { OnPropertyChanged(nameof(EmptyTitle)); OnPropertyChanged(nameof(EmptyText)); }

    public bool ViewAll => ViewMode == "all";
    public bool ViewOpen => ViewMode == "open";
    public bool ViewChanges => ViewMode == "changes";

    // Column heads with the sort direction ("Port ↑").
    public string PortHeader => SortHead("Port");
    public string StateHeader => SortHead("State");
    public string ServiceHeader => SortHead("Service");
    private string SortHead(string column) => _order.Column == column ? $"{column} {(_order.Descending ? "↓" : "↑")}" : column;

    private readonly List<ScanRow> _listed = new();   // every listed row, sorted (Rows is this, filtered)
    private readonly Dictionary<string, ScanHostRow> _hostRows = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<(string Ip, long Key), ScanPortRow> _portRows = new();
    private readonly ScanRowOrder _order = new();
    private Sink? _sink;
    private bool _singleTarget;
    private int _live;

    // The last finished pass, for the exports.
    private ScanPass? _lastPass;
    private ScanDiff? _lastDiff;
    private string _lastPortsText = "";

    /// <summary>Engine → UI hand-off. Called from worker threads; only queues.</summary>
    private sealed class Sink : IScanSink
    {
        public readonly ConcurrentQueue<ScanHost> Hosts = new();
        public readonly ConcurrentQueue<PortFinding> Ports = new();
        private int _queued;

        public void HostChanged(ScanHost host) => Hosts.Enqueue(host);

        public void PortFound(PortFinding f)
        {
            // Only open ports are listed live; everything else is placed when the pass ends (nmap's collapse rule
            // needs the final counts). Bounded, so a host that SYN-ACKs everything can't flood the queue.
            if (f.State != PortState.Open || Interlocked.Increment(ref _queued) > MaxLive) return;
            Ports.Enqueue(f);
        }

        public void ResetBudget() => Interlocked.Exchange(ref _queued, 0);
    }

    private void BeginRun(Sink sink, int targets)
    {
        // The previous scan's results go now: its reverse-DNS lookups still queued have nothing left to name.
        _lateNamesSource?.Cancel();
        _lateNamesSource = null;
        _sink = sink;
        _singleTarget = targets == 1;
        HostsTotal = targets;
        IsPingScan = PingScanOnly;
        _lastPass = null;
        _lastDiff = null;
        CanExport = false;
        ChangesText = "";
        ReportText = "";
    }

    private void BeginPass(bool repeating)
    {
        _sink?.ResetBudget();
        _live = 0;
        HiddenText = "";
        OpenCount = OpenFilteredCount = ClosedCount = FilteredCount = HostsUpCount = 0;
        // A repeating scan keeps the last pass on screen and updates it in place; the first pass starts empty.
        if (repeating) return;
        _listed.Clear();
        _hostRows.Clear();
        _portRows.Clear();
        Rows = new ObservableCollection<ScanRow>();
        HasResults = false;
    }

    // Move queued engine events into the list. UI thread.
    private void Drain(bool final)
    {
        var sink = _sink;
        if (sink is null) return;
        int budget = final ? int.MaxValue : 400;   // per 200 ms tick, so the UI thread never stalls on a burst
        bool rebuild = false;
        while (budget-- > 0 && sink.Hosts.TryDequeue(out var h)) rebuild |= UpsertHost(h);
        while (budget-- > 0 && sink.Ports.TryDequeue(out var f)) rebuild |= UpsertPort(f);
        if (rebuild) _viewStale = true;
        // With a filter or the Open / Changes view on, new rows mean rebuilding the filtered list (up to 20,000 rows, and a
        // reset that re-creates the visible rows and drops the selection): at most once a second while results stream in
        // (it was every 200 ms tick), and at once at the end.
        if (_viewStale && (final || Environment.TickCount64 - _viewBuiltAt >= 1000)) RebuildView();
        HasResults = _listed.Count > 0;
    }

    private bool _viewStale;
    private long _viewBuiltAt;

    // The pass is over and its final listing replaces the live one: what's still queued would only be redrawn twice.
    private void DiscardQueued()
    {
        if (_sink is not { } sink) return;
        while (sink.Hosts.TryDequeue(out _)) { }
        while (sink.Ports.TryDequeue(out _)) { }
    }

    // Returns true when the filtered view needs rebuilding (rows were added while a filter is on).
    private bool UpsertHost(ScanHost h)
    {
        if (_hostRows.TryGetValue(h.Ip, out var row))
        {
            row.Refresh();
            if (h.AcceptsAll) return FoldAcceptAll(h);
            return false;
        }
        if (h.Status != HostStatus.Up && !h.Evidence && !_singleTarget) return false;
        // The row cap holds for host headers too: a sweep behind a transparent proxy (every address SYN-ACKs 80/443, so
        // discovery finds a whole /16 "up") inserted 65,536 headers live and froze the end of the pass for ~0.6 s.
        if (_listed.Count >= MaxListed) return false;
        return Insert(_hostRows[h.Ip] = new ScanHostRow(h));
    }

    private bool UpsertPort(PortFinding f)
    {
        if (f.Host.AcceptsAll && f.Proto == ScanProto.Tcp) return false;
        if (_portRows.TryGetValue((f.Host.Ip, f.Key), out var existing))
        {
            existing.Update(f);
            return false;
        }
        if (_live++ >= MaxLive || _listed.Count >= MaxListed) return false;
        bool rebuild = false;
        if (!_hostRows.ContainsKey(f.Host.Ip)) rebuild |= Insert(_hostRows[f.Host.Ip] = new ScanHostRow(f.Host));
        return Insert(_portRows[(f.Host.Ip, f.Key)] = new ScanPortRow(f)) | rebuild;
    }

    // A host just proved to answer everything: its open TCP rows go.
    private bool FoldAcceptAll(ScanHost h)
    {
        var gone = _listed.OfType<ScanPortRow>()
                          .Where(r => ReferenceEquals(r.Host, h) && r.Finding.Proto == ScanProto.Tcp && r.Finding.State == PortState.Open).ToList();
        if (gone.Count == 0) return false;
        foreach (var r in gone)
        {
            _listed.Remove(r);
            _portRows.Remove((h.Ip, r.Finding.Key));
        }
        return true;
    }

    // Sorted insert into the full list; mirrored into the view directly when no filter is on.
    private bool Insert(ScanRow row)
    {
        int i = _listed.BinarySearch(row, _order);
        if (i < 0) i = ~i;
        _listed.Insert(i, row);
        if (FilterText.Length == 0 && ViewMode == "all" && Rows.Count == _listed.Count - 1)
        {
            Rows.Insert(i, row);
            return false;
        }
        return true;
    }

    // The end of a pass: the final listing (open ports, nmap's few-enough-to-list states, the repeat changes),
    // counters, warnings and the report.
    private async Task FinishPassAsync(ScanPass pass, ScanDiff? diff, string portsText)
    {
        DiscardQueued();
        _lastPass = pass;
        _lastDiff = diff;
        _lastPortsText = portsText;
        CanExport = true;

        var report = Task.Run(() => ScanReport.BuildText(pass, portsText, diff));

        var listed = new List<ScanRow>();
        var hostRows = new Dictionary<string, ScanHostRow>(StringComparer.OrdinalIgnoreCase);
        var portRows = new Dictionary<(string, long), ScanPortRow>();
        int hidden = 0;

        ScanHostRow HostRow(ScanHost h)
        {
            if (hostRows.TryGetValue(h.Ip, out var r)) return r;
            if (!_hostRows.TryGetValue(h.Ip, out r)) r = new ScanHostRow(h);
            r.Change = ScanChange.None;
            hostRows[h.Ip] = r;
            listed.Add(r);
            return r;
        }

        void Port(PortFinding f)
        {
            if (listed.Count >= MaxListed) { hidden++; return; }
            HostRow(f.Host);
            if (_portRows.TryGetValue((f.Host.Ip, f.Key), out var row) && f.Change != ScanChange.Gone) row.Update(f);
            else row = new ScanPortRow(f);
            portRows[(f.Host.Ip, f.Key)] = row;
            listed.Add(row);
        }

        // One host: nmap's listing (every state with few enough ports). A sweep lists the open ports; each host's header
        // counts the rest, and the report / exports keep every row.
        bool sweep = pass.Scanned.Count > 1;
        foreach (var f in pass.Findings)
        {
            if (f.Host.AcceptsAll && f.Proto == ScanProto.Tcp && f.State == PortState.Open) continue;
            if (sweep ? f.State != PortState.Open && f.Change == ScanChange.None : !ScanReport.Listed(f)) continue;
            Port(f);
        }
        if (diff is not null) foreach (var f in diff.Gone) Port(f);
        foreach (var h in pass.Targets)
            if (h.Status == HostStatus.Up || _singleTarget) Header(h);
        if (diff is not null)
        {
            foreach (var h in diff.HostsUp) if (Header(h) is { } up) up.Change = ScanChange.New;
            foreach (var h in diff.HostsDown) if (Header(h) is { } down) down.Change = ScanChange.Gone;
        }

        // A host's header without a port listed under it: within the row cap, like the ports.
        ScanHostRow? Header(ScanHost h)
        {
            if (!hostRows.ContainsKey(h.Ip) && listed.Count >= MaxListed) { hidden++; return null; }
            return HostRow(h);
        }
        listed.Sort(_order);
        foreach (var r in listed) r.Refresh();

        _listed.Clear();
        _listed.AddRange(listed);
        _hostRows.Clear();
        foreach (var kv in hostRows) _hostRows[kv.Key] = kv.Value;
        _portRows.Clear();
        foreach (var kv in portRows) _portRows[kv.Key] = kv.Value;
        RebuildView();
        HasResults = _listed.Count > 0;
        HiddenText = hidden > 0 ? $"{hidden:N0} more row(s) not listed — export for everything" : "";

        OpenCount = pass.Targets.Sum(h => (long)(h.AcceptsAll ? h.Count(ScanProto.Udp, PortState.Open) : h.Count(PortState.Open)));
        OpenFilteredCount = pass.Targets.Sum(h => (long)h.Count(PortState.OpenFiltered));
        ClosedCount = pass.Targets.Sum(h => (long)h.Count(PortState.Closed));
        FilteredCount = pass.Targets.Sum(h => (long)h.Count(PortState.Filtered));
        HostsUpCount = pass.HostsUp;
        ChangesText = diff is { Any: true } ? diff.Summary : "";
        WarningText = Warnings(pass);
        ReportText = await report;
    }

    // Reverse-DNS names can still be arriving when the scan ends (a /24's lookups take a while): keep showing them as
    // they land, and rebuild the report once they're all in. Ends when a new scan starts.
    private Avalonia.Threading.DispatcherTimer? _lateNames;
    private ScanNames? _lateNamesSource;

    private void FollowLateNames(ScanNames names)
    {
        _lateNames?.Stop();
        if (!names.Busy) return;
        _lateNamesSource = names;   // (its queue is dropped when the next scan starts)
        if (_lastPass is not { } pass || _sink is not { } sink) return;
        var timer = new Avalonia.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _lateNames = timer;
        timer.Tick += async (_, _) =>
        {
            if (IsScanning || !ReferenceEquals(sink, _sink)) { timer.Stop(); return; }
            Drain(final: true);
            if (names.Busy) return;
            timer.Stop();
            var diff = _lastDiff;
            string portsText = _lastPortsText;
            string text = await Task.Run(() => ScanReport.BuildText(pass, portsText, diff));
            // a big report takes seconds: a scan started meanwhile has cleared the report, and this one isn't about it
            if (IsScanning || !ReferenceEquals(sink, _sink)) return;
            ReportText = text;
        };
        timer.Start();
    }

    // The callout: why some results can't be taken at face value. One line per cause.
    private static string Warnings(ScanPass pass)
    {
        var lines = new List<string>();
        static string Few(IEnumerable<ScanHost> hs)
        {
            var l = hs.Select(h => h.Ip).ToList();
            return string.Join(", ", l.Take(3)) + (l.Count > 3 ? $" (+{l.Count - 3})" : "");
        }
        var acceptAll = pass.Targets.Where(h => h.AcceptsAll).ToList();
        if (acceptAll.Count > 0)
            lines.Add($"{Few(acceptAll)} answer{(acceptAll.Count == 1 ? "s" : "")} every TCP port (a SYN proxy or tarpit), so the open TCP ports there aren't real and aren't listed.");
        var local = pass.Targets.Where(h => h.LocalAnswerPorts.Length > 0).ToList();
        if (local.Count > 0)
            lines.Add($"On {Few(local)} some ports answered faster than the host itself can — a local proxy, VPN or antivirus completed those connections, so they may not really be open.");
        var intercepted = pass.Findings.Where(f => f.Interceptor.Length > 0).ToList();
        if (intercepted.Count > 0)
        {
            var who = intercepted.Select(f => f.Interceptor).Distinct().ToList();
            string where = string.Join(", ", intercepted.Take(3).Select(f => $"{f.Host.Ip}:{f.Port}")) + (intercepted.Count > 3 ? $" (+{intercepted.Count - 3})" : "");
            lines.Add($"{string.Join(" / ", who)} answered in the server's place on {where} — those ports are open, but their version and "
                      + "certificate details come from it, not from the server.");
        }
        foreach (int port in pass.UbiquitousPorts.Take(3))
            lines.Add($"Port {port}/tcp is open on nearly every host scanned — likely a transparent proxy or ISP interception on the path, not a service on each host.");
        if (pass.UnknownProbes > 0 || pass.UnknownHosts > 0)
            lines.Add($"The OS ran out of sockets: {(pass.UnknownProbes > 0 ? $"{pass.UnknownProbes:N0} probe(s)" : "")}"
                      + (pass.UnknownProbes > 0 && pass.UnknownHosts > 0 ? " and " : "")
                      + (pass.UnknownHosts > 0 ? $"{pass.UnknownHosts:N0} host check(s)" : "")
                      + " couldn't be sent, so their state is unknown — try a slower timing template.");
        if (pass.RecheckSkipped > 0)
            lines.Add($"{pass.RecheckSkipped:N0} silent UDP port(s) stay open|filtered unchecked: the host rate-limits its ICMP replies and re-checking that many would take too long — scan fewer UDP ports for an exact answer.");
        return string.Join("\n", lines);
    }

    // ---- filter / view / sort ----

    partial void OnFilterTextChanged(string value) => RebuildView();

    partial void OnViewModeChanged(string value)
    {
        OnPropertyChanged(nameof(ViewAll));
        OnPropertyChanged(nameof(ViewOpen));
        OnPropertyChanged(nameof(ViewChanges));
        RebuildView();
    }

    [RelayCommand] private void SetView(string mode) => ViewMode = mode;
    [RelayCommand] private void ClearFilter() => FilterText = "";

    private void RebuildView()
    {
        _viewStale = false;
        _viewBuiltAt = Environment.TickCount64;
        string f = FilterText.Trim();
        if (f.Length == 0 && ViewMode == "all")
        {
            Rows = new ObservableCollection<ScanRow>(_listed);
            return;
        }
        // A port row stays when it fits the view and the text (or its host matches the text); a header stays when it
        // matches itself (in the "all" view) or one of its ports stayed.
        var keep = new List<ScanRow>(_listed.Count);
        ScanHostRow? header = null;
        bool headerAdded = false, headerMatches = false;
        foreach (var row in _listed)
        {
            if (row is ScanHostRow h)
            {
                header = h;
                headerAdded = false;
                headerMatches = f.Length == 0 || h.Matches(f);
                bool headerView = ViewMode switch { "all" => true, "changes" => h.Change != ScanChange.None, _ => false };
                if (headerView && headerMatches) { keep.Add(h); headerAdded = true; }
                continue;
            }
            var p = (ScanPortRow)row;
            bool inView = ViewMode switch
            {
                "open" => p.Finding.State == PortState.Open,
                "changes" => p.Finding.Change != ScanChange.None,
                _ => true,
            };
            if (!inView || !(headerMatches || p.Matches(f))) continue;
            if (!headerAdded && header is not null && ReferenceEquals(header.Host, p.Host)) { keep.Add(header); headerAdded = true; }
            keep.Add(p);
        }
        Rows = new ObservableCollection<ScanRow>(keep);
    }

    [RelayCommand]
    private void SortBy(string column)
    {
        if (_order.Column == column) _order.Descending = !_order.Descending;
        else { _order.Column = column; _order.Descending = false; }
        _listed.Sort(_order);
        RebuildView();
        OnPropertyChanged(nameof(PortHeader));
        OnPropertyChanged(nameof(StateHeader));
        OnPropertyChanged(nameof(ServiceHeader));
    }

    // ---- exports ----

    [RelayCommand]
    private Task CopyReport() => ClipboardHelper.SetTextAsync(ReportText);

    /// <summary>Save the last finished pass as "json", "csv" or "txt" (the report).</summary>
    public async Task ExportAsync(IStorageProvider storage, string format)
    {
        var pass = _lastPass;
        if (pass is null)
        {
            StatusMessage = IsScanning ? "Nothing to export yet — the first pass is still running." : "Nothing to export yet — run a scan first.";
            return;
        }
        var diff = _lastDiff;
        string portsText = _lastPortsText;
        string report = ReportText;
        var (ext, label, pattern) = format switch
        {
            "csv" => (".csv", "CSV", "*.csv"),
            "txt" => (".txt", "Text report", "*.txt"),
            _ => (".json", "JSON", "*.json"),
        };
        string stamp = pass.StartedUtc.ToLocalTime().ToString("yyyyMMdd-HHmm");
        var file = await storage.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Export scan results",
            SuggestedFileName = $"echoes-scan-{stamp}{ext}",
            DefaultExtension = ext,
            FileTypeChoices = new[] { new FilePickerFileType(label) { Patterns = new[] { pattern } } },
        });
        if (file is null) return;

        await using var stream = await file.OpenWriteAsync();
        if (stream.CanSeek) stream.SetLength(0);   // overwriting a longer file must not leave its tail behind
        // Up to a few hundred thousand rows: format and write off the UI thread.
        await Task.Run(() =>
        {
            switch (format)
            {
                case "csv": ScanReport.WriteCsv(stream, pass, diff); break;
                case "txt":
                    using (var w = new System.IO.StreamWriter(stream, new System.Text.UTF8Encoding(false), 1 << 16, leaveOpen: true))
                        w.Write(report);
                    break;
                default: ScanReport.WriteJson(stream, pass, portsText, diff); break;
            }
        });
    }
}
