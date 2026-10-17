using Avalonia.Platform.Storage;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

// The result listing: one row per node (region headings when sorted by region), kept in order as results stream in; the
// summary tiles over all nodes; the filter and the All / OK / Warning / Failed views; copy and export.
public partial class CheckHostViewModel
{
    /// <summary>What the list shows: the current run's rows, filtered and in order.</summary>
    public ObservableCollection<CheckHostRow> Rows { get; } = new();

    private readonly List<CheckHostNodeRow> _all = new();
    private readonly Dictionary<string, CheckHostNodeRow> _byId = new(StringComparer.Ordinal);
    private readonly Dictionary<string, CheckHostGroupRow> _groups = new(StringComparer.Ordinal);
    private CheckHostKind _runKind;
    private string _runTarget = "";
    private string _runChoice = "Automatic";
    private DateTimeOffset _runStarted;
    private TimeSpan? _runDuration;
    private bool _runStopped;
    private CheckHostSummary _summary = CheckHostSummary.Compute(Array.Empty<CheckHostEntry>());

    [ObservableProperty] private string _requestId = "";
    [ObservableProperty] private string _permalink = "";
    [ObservableProperty] private string _filterText = "";
    [ObservableProperty] private string _viewMode = "all";   // all | ok | warning | failed
    [ObservableProperty] private int _sortIndex;             // CheckHostOrder.All
    [ObservableProperty] private bool _hasRun;               // a run has nodes to show (tiles, toolbar, list)

    public ObservableCollection<string> SortOptions { get; } = new(CheckHostOrder.All.Select(s => s.Label()));
    public CheckHostSort Sort => CheckHostOrder.All[Math.Clamp(SortIndex, 0, CheckHostOrder.All.Length - 1)];
    public bool HasPermalink => Permalink.Length > 0;
    public bool CanExport => _all.Count > 0;

    partial void OnPermalinkChanged(string value) => OnPropertyChanged(nameof(HasPermalink));
    partial void OnFilterTextChanged(string value) => RebuildView();
    partial void OnViewModeChanged(string value)
    {
        OnPropertyChanged(nameof(ViewAll));
        OnPropertyChanged(nameof(ViewOk));
        OnPropertyChanged(nameof(ViewWarning));
        OnPropertyChanged(nameof(ViewFailed));
        RebuildView();
    }
    partial void OnSortIndexChanged(int value)
    {
        OnPropertyChanged(nameof(Sort));
        OnPropertyChanged(nameof(LocationHead));
        OnPropertyChanged(nameof(NodeHead));
        OnPropertyChanged(nameof(ResultHead));
        OnPropertyChanged(nameof(LatencyHead));
        OnPropertyChanged(nameof(SortIsRegion));
        OnPropertyChanged(nameof(SortIsCountry));
        OnPropertyChanged(nameof(SortIsFastest));
        OnPropertyChanged(nameof(SortIsSlowest));
        OnPropertyChanged(nameof(SortIsStatus));
        OnPropertyChanged(nameof(SortIsNode));
        RebuildView();
    }

    // the phone's sort menu marks the current order
    public bool SortIsRegion => Sort == CheckHostSort.Region;
    public bool SortIsCountry => Sort == CheckHostSort.Country;
    public bool SortIsFastest => Sort == CheckHostSort.Fastest;
    public bool SortIsSlowest => Sort == CheckHostSort.Slowest;
    public bool SortIsStatus => Sort == CheckHostSort.Status;
    public bool SortIsNode => Sort == CheckHostSort.Node;

    [RelayCommand]
    private void SetSort(string key)
    {
        if (CheckHostOrder.TryParse(key, out var sort)) SortIndex = Array.IndexOf(CheckHostOrder.All, sort);
    }

    // ---- the summary tiles ----

    public int TotalCount => _summary.Total;
    public int OkCount => _summary.Ok;
    public int WarningCount => _summary.Warning;
    public int FailedCount => _summary.Failed;
    public int PendingCount => _summary.Pending;
    public int StoppedCount => _summary.Stopped;
    /// <summary>The status bar's neutral part: nodes still waiting, or stopped before they reported.</summary>
    public int RestCount => _summary.Pending + _summary.Stopped;
    public bool HasWarnings => _summary.Warning > 0;

    /// <summary>"Reachable", "Responded", "Connected", "Replied", "Resolved".</summary>
    public string ReachCaption => CheckHostFormat.ReachedCaption(_runKind);
    /// <summary>"18 / 20"</summary>
    public string ReachValue => $"{_summary.Reached} / {_summary.Total}";
    /// <summary>"17 ok · 1 warning · 2 failed"</summary>
    public string? ReachCounts => _summary.Total == 0 ? null : CheckHostFormat.Counts(_summary);

    public string SpreadCaption => _runKind == CheckHostKind.Dns ? "Answers" : "Min · avg · max";
    public string SpreadValue => _runKind == CheckHostKind.Dns ? CheckHostFormat.Answers(_summary)
        : CheckHostFormat.TripleShort(_summary.MinMs, _summary.AvgMs, _summary.MaxMs);
    public string SpreadTip => _runKind switch
    {
        CheckHostKind.Dns => "Whether every node's resolver returned the same records (TTL aside)",
        CheckHostKind.Ping => "Average round trip of each node, across the nodes: lowest, mean and highest"
                              + (_summary.LossPercent is double l ? $" · {CheckHostFormat.Pct(l)} of all pings were lost" : ""),
        CheckHostKind.Http => "Response time of each node's request, across the nodes",
        _ => "Connect time of each node, across the nodes",
    };

    // Fastest / slowest: the time leads (it never trims), the place follows in muted text and trims when the tile is narrow.
    public string BestCaption => _runKind == CheckHostKind.Dns ? "Records" : "Fastest";
    public string BestValue => _runKind == CheckHostKind.Dns ? CheckHostFormat.RecordTypes(_summary)
        : _summary.Fastest is { } f ? CheckHostFormat.MsShort(f.LatencyMs) : "–";
    public string BestPlace => _runKind != CheckHostKind.Dns && _summary.Fastest is { } f ? Short(f.Node) : "";
    public string BestFlag => _runKind == CheckHostKind.Dns ? "" : _summary.Fastest?.Node.CountryCode ?? "";
    public string? BestTip => _summary.Fastest is { } f && _runKind != CheckHostKind.Dns
        ? $"{f.Node.Location} ({f.Node.ShortId}) · {CheckHostFormat.Ms(f.LatencyMs)}" : null;

    public string WorstCaption => _runKind == CheckHostKind.Dns ? "TTL" : "Slowest";
    public string WorstValue => _runKind == CheckHostKind.Dns ? CheckHostFormat.TtlRange(_summary)
        : _summary.Slowest is { } s ? CheckHostFormat.MsShort(s.LatencyMs) : "–";
    public string WorstPlace => _runKind != CheckHostKind.Dns && _summary.Slowest is { } s ? Short(s.Node) : "";
    public string WorstFlag => _runKind == CheckHostKind.Dns ? "" : _summary.Slowest?.Node.CountryCode ?? "";
    public string? WorstTip => _summary.Slowest is { } s && _runKind != CheckHostKind.Dns
        ? $"{s.Node.Location} ({s.Node.ShortId}) · {CheckHostFormat.Ms(s.LatencyMs)}" : null;

    public string CountriesValue => _summary.Countries.ToString(CultureInfo.InvariantCulture);
    public string? CountriesTip => _summary.Regions.Count == 0 ? null : string.Join(", ", _summary.Regions);
    public string RegionsText => _summary.Regions.Count == 0 ? "" : CheckHostFormat.Plural(_summary.Regions.Count, "region", "regions");

    /// <summary>The city alone fits a tile; the country when there is no city.</summary>
    private static string Short(CheckHostNode n) => n.City.Length > 0 ? n.City : n.Location;

    // ---- column heads (the sort shows on the active one) ----

    public string LocationHead => Sort switch { CheckHostSort.Region => "Location · by region", CheckHostSort.Country => "Location ↑", _ => "Location" };
    public string NodeHead => Sort == CheckHostSort.Node ? "Node ↑" : "Node";
    public string ResultHead => Sort == CheckHostSort.Status ? "Result · failures first" : "Result";
    public string LatencyHead => (_runKind == CheckHostKind.Dns ? "TTL" : "Latency")
                                 + Sort switch { CheckHostSort.Fastest => " ↑", CheckHostSort.Slowest => " ↓", _ => "" };

    /// <summary>The filter box's hint (a phone's box is narrower).</summary>
    public string FilterPlaceholder => AppPlatform.IsMobile ? "Country, city, node, IP…" : "Filter: country, city, node, IP, result…";

    public bool ViewAll => ViewMode == "all";
    public bool ViewOk => ViewMode == "ok";
    public bool ViewWarning => ViewMode == "warning";
    public bool ViewFailed => ViewMode == "failed";

    // ---- the empty list explains itself ----

    public bool ShowEmpty => Rows.Count == 0;
    public string EmptyTitle => IsWorking && _all.Count == 0 ? "Contacting check-host.net…"
        : _all.Count > 0 ? "No nodes match"
        : "Check a host from around the world";
    public string EmptyText => IsWorking && _all.Count == 0 ? "Results appear as each node reports."
        : _all.Count > 0 ? "Try another filter or view."
        : "Ping, HTTP, TCP, UDP or DNS from check-host.net nodes, side by side.";

    private void OnEmptyStateChanged()
    {
        OnPropertyChanged(nameof(ShowEmpty));
        OnPropertyChanged(nameof(EmptyTitle));
        OnPropertyChanged(nameof(EmptyText));
    }

    // ---- the run's life cycle (UI thread) ----

    private void BeginRun(CheckHostKind kind, string target, CheckHostNodeChoice choice)
    {
        _runKind = kind;
        _runTarget = target;
        _runChoice = choice.Label(_catalog);
        _runStarted = DateTimeOffset.Now;
        _runDuration = null;
        _runStopped = false;
        _all.Clear();
        _byId.Clear();
        _groups.Clear();
        RequestId = "";
        Permalink = "";
        HasRun = false;
        Rows.Clear();
        UpdateSummary();
        OnPropertyChanged(nameof(CanExport));
        OnEmptyStateChanged();
    }

    private void OnStarted(CheckHostStart start)
    {
        RequestId = start.RequestId;
        Permalink = start.Permalink;
        foreach (var node in start.Nodes)
        {
            if (_byId.ContainsKey(node.Id)) continue;
            var row = new CheckHostNodeRow(new CheckHostEntry(node, _runKind));
            _all.Add(row);
            _byId[node.Id] = row;
        }
        MergeCatalog(start.Nodes);
        HasRun = _all.Count > 0;
        StatusMessage = $"Waiting for {CheckHostFormat.Plural(_all.Count, "node", "nodes")}…";
        UpdateSummary();
        RebuildView();
        OnPropertyChanged(nameof(CanExport));
    }

    private void OnResults(IReadOnlyList<KeyValuePair<string, CheckHostResult>> batch)
    {
        foreach (var (id, result) in batch)
            if (_byId.TryGetValue(id, out var row)) row.SetResult(result);
        int reported = _all.Count(r => r.Entry.IsFinal);
        if (IsWorking) StatusMessage = reported < _all.Count ? $"{reported} of {_all.Count} nodes reported…" : "All nodes reported";
        UpdateSummary();
        RebuildView();
    }

    private void OnPollProblem(string? problem)
    {
        if (problem is null || !IsWorking) return;
        int reported = _all.Count(r => r.Entry.IsFinal);
        StatusMessage = $"{reported} of {_all.Count} nodes reported · retrying ({Lower(problem).TrimEnd('.')})";
    }

    private void FinishRun(TimeSpan elapsed, bool stopped)
    {
        _runDuration = elapsed;
        _runStopped = stopped;
        UpdateSummary();
        RebuildView();
        OnPropertyChanged(nameof(CanExport));
    }

    private void UpdateSummary()
    {
        _summary = CheckHostSummary.Compute(_all.Select(r => r.Entry).ToList());
        foreach (var row in _all) row.SetMajority(_summary.MajorityAnswer);   // DNS: mark the answers that differ
        OnPropertyChanged(nameof(TotalCount));
        OnPropertyChanged(nameof(OkCount));
        OnPropertyChanged(nameof(WarningCount));
        OnPropertyChanged(nameof(FailedCount));
        OnPropertyChanged(nameof(PendingCount));
        OnPropertyChanged(nameof(StoppedCount));
        OnPropertyChanged(nameof(RestCount));
        OnPropertyChanged(nameof(HasWarnings));
        OnPropertyChanged(nameof(ReachCaption));
        OnPropertyChanged(nameof(ReachValue));
        OnPropertyChanged(nameof(ReachCounts));
        OnPropertyChanged(nameof(SpreadCaption));
        OnPropertyChanged(nameof(SpreadValue));
        OnPropertyChanged(nameof(SpreadTip));
        OnPropertyChanged(nameof(BestCaption));
        OnPropertyChanged(nameof(BestValue));
        OnPropertyChanged(nameof(BestPlace));
        OnPropertyChanged(nameof(BestFlag));
        OnPropertyChanged(nameof(BestTip));
        OnPropertyChanged(nameof(WorstCaption));
        OnPropertyChanged(nameof(WorstValue));
        OnPropertyChanged(nameof(WorstPlace));
        OnPropertyChanged(nameof(WorstFlag));
        OnPropertyChanged(nameof(WorstTip));
        OnPropertyChanged(nameof(CountriesValue));
        OnPropertyChanged(nameof(CountriesTip));
        OnPropertyChanged(nameof(RegionsText));
        OnPropertyChanged(nameof(LatencyHead));
        // the Warning chip hides while there are no warnings: its view can't stay selected unseen
        if (ViewMode == "warning" && _summary.Warning == 0) ViewMode = "all";
    }

    // ---- filter / view / sort ----

    [RelayCommand] private void SetView(string mode) => ViewMode = mode;
    [RelayCommand] private void ClearFilter() => FilterText = "";

    /// <summary>A column head: Location toggles region ↔ country, Latency fastest ↔ slowest; Result is failures first.</summary>
    [RelayCommand]
    private void SortBy(string column)
    {
        var next = column switch
        {
            "location" => Sort == CheckHostSort.Region ? CheckHostSort.Country : CheckHostSort.Region,
            "latency" => Sort == CheckHostSort.Fastest ? CheckHostSort.Slowest : CheckHostSort.Fastest,
            "result" => CheckHostSort.Status,
            "node" => CheckHostSort.Node,
            _ => Sort,
        };
        SortIndex = Array.IndexOf(CheckHostOrder.All, next);
    }

    private bool InView(CheckHostNodeRow r) => ViewMode switch
    {
        "ok" => r.State == CheckHostState.Ok,
        "warning" => r.State == CheckHostState.Warning,
        "failed" => r.State == CheckHostState.Failed,
        _ => true,
    };

    /// <summary>The ordered rows (without headings), every node — what the exports list.</summary>
    private List<CheckHostNodeRow> Ordered()
    {
        var cmp = CheckHostOrder.Comparer(Sort);
        var list = _all.ToList();
        list.Sort((a, b) => cmp.Compare(a.Entry, b.Entry));
        return list;
    }

    private void RebuildView()
    {
        string f = FilterText.Trim();
        var visible = Ordered().Where(r => InView(r) && (f.Length == 0 || r.Matches(f))).ToList();
        var want = new List<CheckHostRow>(visible.Count + 8);
        if (Sort == CheckHostSort.Region)
        {
            foreach (var g in visible.GroupBy(r => r.Node.Region))
            {
                if (!_groups.TryGetValue(g.Key, out var head)) _groups[g.Key] = head = new CheckHostGroupRow(g.Key);
                head.Update(g.Select(r => r.Entry).ToList());
                want.Add(head);
                want.AddRange(g);
            }
        }
        else want.AddRange(visible);
        Sync(Rows, want);
        OnEmptyStateChanged();
    }

    /// <summary>Make <paramref name="target"/> equal to <paramref name="want"/> with moves, inserts and removals — not a
    /// reset — so the selection and scroll position survive a live re-sort and the list only re-lays the lines that moved.</summary>
    internal static void Sync<T>(ObservableCollection<T> target, IReadOnlyList<T> want) where T : class
    {
        var keep = new HashSet<T>(want, ReferenceEqualityComparer.Instance);
        for (int i = target.Count - 1; i >= 0; i--)
            if (!keep.Contains(target[i])) target.RemoveAt(i);
        for (int i = 0; i < want.Count; i++)
        {
            if (i < target.Count && ReferenceEquals(target[i], want[i])) continue;
            int at = -1;
            for (int j = i + 1; j < target.Count; j++)
                if (ReferenceEquals(target[j], want[i])) { at = j; break; }
            if (at >= 0) target.Move(at, i);
            else target.Insert(i, want[i]);
        }
        while (target.Count > want.Count) target.RemoveAt(target.Count - 1);
    }

    // ---- copy / export ----

    private CheckHostRunInfo RunInfo() => new()
    {
        Kind = _runKind,
        Target = _runTarget,
        RequestId = RequestId,
        Permalink = Permalink,
        Started = _runStarted,
        Duration = _runDuration,
        NodeChoice = _runChoice,
        Stopped = _runStopped,
    };

    private List<CheckHostEntry> Entries() => Ordered().Select(r => r.Entry).ToList();

    /// <summary>The whole run as an aligned text report (every node, in the list's order).</summary>
    public string BuildReport() => _all.Count == 0 ? "" : CheckHostReport.Text(RunInfo(), Entries(), _summary, Sort == CheckHostSort.Region);
    public string BuildCsv() => _all.Count == 0 ? "" : CheckHostReport.Csv(RunInfo(), Entries(), _summary.MajorityAnswer);
    public string BuildJson() => _all.Count == 0 ? "" : CheckHostReport.Json(RunInfo(), Entries(), _summary);

    [RelayCommand] private Task CopyReport() => ClipboardHelper.SetTextAsync(BuildReport());
    [RelayCommand] private Task CopyCsv() => ClipboardHelper.SetTextAsync(BuildCsv());
    [RelayCommand] private Task CopyJson() => ClipboardHelper.SetTextAsync(BuildJson());
    [RelayCommand] private Task CopyPermalink() => ClipboardHelper.SetTextAsync(Permalink);
    [RelayCommand] private void OpenPermalink() => LinkHelper.Open(Permalink);

    /// <summary>A file name for an export: "check-host-ping-scanme.nmap.org-20261013-2142.csv".</summary>
    public string SuggestedFileName(string ext)
    {
        var sb = new StringBuilder();
        foreach (char c in _runTarget)
            sb.Append(char.IsAsciiLetterOrDigit(c) || c is '.' or '-' ? c : '_');
        string name = sb.ToString().Trim('_', '.');
        if (name.Length > 60) name = name[..60];
        return $"check-host-{_runKind.Api()}-{(name.Length > 0 ? name : "result")}-{_runStarted.ToLocalTime():yyyyMMdd-HHmm}{ext}";
    }

    /// <summary>What an export of "txt" (the report), "csv" or "json" holds — as of now: a run still in progress exports
    /// what has arrived.</summary>
    public string ExportContent(string format) => format switch { "csv" => BuildCsv(), "json" => BuildJson(), _ => BuildReport() };

    /// <summary>Save the run as "txt", "csv" or "json". Throws on an I/O failure (the view reports it).</summary>
    public async Task ExportAsync(IStorageProvider storage, string format)
    {
        if (_all.Count == 0) return;
        var (ext, label, pattern, mime) = format switch
        {
            "csv" => (".csv", "CSV", "*.csv", "text/csv"),
            "json" => (".json", "JSON", "*.json", "application/json"),
            _ => (".txt", "Text report", "*.txt", "text/plain"),
        };
        string content = ExportContent(format);
        var file = await storage.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Export the check",
            SuggestedFileName = SuggestedFileName(ext),
            DefaultExtension = ext.TrimStart('.'),
            ShowOverwritePrompt = true,
            FileTypeChoices = new[] { new FilePickerFileType(label) { Patterns = new[] { pattern }, MimeTypes = new[] { mime } } },
        });
        if (file is null) return;
        await using var stream = await file.OpenWriteAsync();
        await WriteExportAsync(stream, content);
    }

    /// <summary>UTF-8 without a BOM; an existing longer file is cut to the new length.</summary>
    internal static async Task WriteExportAsync(System.IO.Stream stream, string content)
    {
        if (stream.CanSeek) stream.SetLength(0);   // overwriting a longer file must not leave its tail behind
        byte[] bytes = new UTF8Encoding(false).GetBytes(content);
        await stream.WriteAsync(bytes);
        await stream.FlushAsync();
    }
}
