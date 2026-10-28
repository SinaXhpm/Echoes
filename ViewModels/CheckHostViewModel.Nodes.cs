using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>A region preset in the node picker ("Europe 27").</summary>
public sealed partial class CheckHostPickRegion : ObservableObject
{
    private readonly Action<string> _toggle;

    public CheckHostPickRegion(string name, int count, Action<string> toggle)
    {
        Name = name;
        Count = count;
        _toggle = toggle;
    }

    public string Name { get; }
    public int Count { get; }
    [ObservableProperty] private bool _isOn;

    [RelayCommand] private void Toggle() => _toggle(Name);
}

/// <summary>A region heading in the picker's node list.</summary>
public sealed class CheckHostPickHeader
{
    public CheckHostPickHeader(string region, int count)
    {
        Region = region;
        Count = count;
    }

    public string Region { get; }
    public int Count { get; }
    public string Text => $"{Region} · {CheckHostFormat.Plural(Count, "node", "nodes")}";
}

/// <summary>A node in the picker, ticked when the current choice includes it.</summary>
public sealed partial class CheckHostPickNode : ObservableObject
{
    private readonly Action<CheckHostPickNode> _toggled;

    public CheckHostPickNode(CheckHostNode node, Action<CheckHostPickNode> toggled)
    {
        Node = node;
        _toggled = toggled;
    }

    public CheckHostNode Node { get; }
    public string Location => Node.Location;
    /// <summary>"de4 · AS34549"</summary>
    public string Meta => string.Join(" · ", new[] { Node.ShortId, Node.Asn }.Where(s => s.Length > 0));
    public string CountryCode => Node.CountryCode;
    public bool HasFlag => Node.HasFlag;

    [ObservableProperty] private bool _isChecked;
    internal bool Syncing;

    partial void OnIsCheckedChanged(bool value)
    {
        if (!Syncing) _toggled(this);
    }
}

// The node choice: Automatic (check-host.net picks up to "max nodes"), regions, or nodes ticked one by one — with the
// picker that edits it. The node list comes from /nodes/hosts, loaded once per session when it is first needed; while it
// can't be loaded, the picker shows the saved copy (CheckHostSnapshot) and the next look tries the live list again.
public partial class CheckHostViewModel
{
    private CheckHostNodeChoice _nodeChoice = CheckHostNodeChoice.Automatic;
    private IReadOnlyList<CheckHostNode>? _catalog;
    private bool _catalogIsSnapshot;
    private Task<(IReadOnlyList<CheckHostNode>?, CheckHostException?)>? _catalogLoad;

    public ObservableCollection<CheckHostPickRegion> PickRegions { get; } = new();
    /// <summary>Headings (<see cref="CheckHostPickHeader"/>) and nodes (<see cref="CheckHostPickNode"/>), filtered.</summary>
    public ObservableCollection<object> PickItems { get; } = new();
    private readonly List<CheckHostPickNode> _pickNodes = new();

    [ObservableProperty] private string _pickFilter = "";
    [ObservableProperty] private bool _pickLoading;
    /// <summary>Why the picker shows the saved list ("" when it shows check-host.net's own).</summary>
    [ObservableProperty] private string _pickNote = "";

    public CheckHostNodeChoice NodeChoice
    {
        get => _nodeChoice;
        private set
        {
            if (ReferenceEquals(_nodeChoice, value)) return;
            _nodeChoice = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(NodeChoiceText));
            OnPropertyChanged(nameof(PickIsAuto));
            OnPropertyChanged(nameof(PickSummary));
            if (_loaded) SchedulePersist();
        }
    }

    /// <summary>The node button's label: "Automatic", "Europe", "Germany · 3 nodes", "5 nodes".</summary>
    public string NodeChoiceText => _nodeChoice.Label(_catalog);
    public bool PickIsAuto => _nodeChoice.IsAutomatic;
    public bool HasPickNote => PickNote.Length > 0;
    public bool PickReady => _catalog is not null;

    /// <summary>What a run with the current choice will do.</summary>
    public string PickSummary
    {
        get
        {
            if (_nodeChoice.IsAutomatic) return $"check-host.net picks up to {MaxNodes} nodes for each check.";
            if (_catalog is null) return $"{NodeChoiceText} · up to {MaxNodes} nodes";
            int covered = _nodeChoice.Covered(_catalog).Count;
            int runs = Math.Min(covered, Math.Clamp(MaxNodes, 1, 100));
            string what = _nodeChoice.Mode == CheckHostNodeChoice.ChoiceMode.Regions
                ? $"{CheckHostFormat.Plural(covered, "node", "nodes")} in {NodeChoiceText}"
                : $"{covered} selected";
            return covered > runs ? $"{what} · runs on {runs} (max nodes), spread over their countries" : $"{what} · runs on {runs}";
        }
    }

    partial void OnPickNoteChanged(string value) => OnPropertyChanged(nameof(HasPickNote));
    partial void OnPickFilterChanged(string value) => RebuildPickItems();
    partial void OnMaxNodesChanged(int value) => OnPropertyChanged(nameof(PickSummary));

    /// <summary>The picker opened: make sure the node list is there (loaded through the proxy when one is set).</summary>
    public async Task EnsureCatalogAsync()
    {
        if (_catalog is not null && !_catalogIsSnapshot) { SyncPickChecks(); return; }
        MoveProxyCredentials(whileTyping: false);   // the list loads through the proxy: its credentials belong in the fields
        PickLoading = true;
        try
        {
            var (live, failure) = await LoadCatalogAsync(CancellationToken.None);
            PickNote = live is null ? $"Saved list · check-host.net: {CheckHostErrors.Short(failure!)}" : "";
        }
        finally { PickLoading = false; }
    }

    /// <summary>check-host.net's live node list, loaded once per session; callers at the same time share the request, and a
    /// failed load is tried again by the next caller. Returns it, or null and why not — the picker then has the saved copy.
    /// <paramref name="wait"/>: the longest this caller waits (the load itself goes on for the next one). UI thread.</summary>
    private async Task<(IReadOnlyList<CheckHostNode>? Live, CheckHostException? Failure)> LoadCatalogAsync(CancellationToken ct, TimeSpan? wait = null)
    {
        if (_catalog is not null && !_catalogIsSnapshot) return (_catalog, null);
        if (_catalogLoad is null || (_catalogLoad.IsCompleted && _catalogLoad.Result.Item1 is null))
            _catalogLoad = Fetch(ProxyOrNull, ProxyUser, ProxyPass);
        IReadOnlyList<CheckHostNode>? list;
        CheckHostException? failure;
        try { (list, failure) = wait is { } w ? await _catalogLoad.WaitAsync(w, ct) : await _catalogLoad.WaitAsync(ct); }
        catch (TimeoutException ex)
        {
            (list, failure) = (null, new CheckHostException($"check-host.net's node list didn't load within {CheckHostErrors.Seconds(wait!.Value)}"
                                                            + " — it may be slow or blocked on this network.", ex));
        }
        if (list is not null)
        {
            if (_catalog is null || _catalogIsSnapshot) SetCatalog(list, snapshot: false);
            return (_catalog, null);
        }
        if (_catalog is null) SetCatalog(CheckHostSnapshot.Nodes, snapshot: true);
        return (null, failure);

        // its own client (proxy settings as they are now), so a stopped run can't pull it out from under a shared load
        static async Task<(IReadOnlyList<CheckHostNode>?, CheckHostException?)> Fetch(string? proxy, string user, string pass)
        {
            try
            {
                using var http = HttpHelper.Create(proxy, user, pass, timeout: RequestTimeout, serviceDns: true);
                var client = new CheckHostClient(http, ApiBase, viaProxy: proxy is not null);
                return (await client.NodesAsync(CancellationToken.None).ConfigureAwait(false), null);
            }
            catch (CheckHostException ex) { return (null, ex); }
            catch (ArgumentException ex) { return (null, new CheckHostException(ex.Message, ex)); }   // an invalid proxy address: already one sentence
            catch (Exception ex) { return (null, new CheckHostException("Couldn't load the node list: " + ex.Message, ex)); }
        }
    }

    private void SetCatalog(IReadOnlyList<CheckHostNode> list, bool snapshot)
    {
        _catalog = list;
        _catalogIsSnapshot = snapshot;
        if (!snapshot) PickNote = "";
        PickRegions.Clear();
        foreach (var g in list.GroupBy(n => n.Region).OrderBy(g => CheckHostRegions.Rank(g.Key)))
            PickRegions.Add(new CheckHostPickRegion(g.Key, g.Count(), PickRegion));
        _pickNodes.Clear();
        foreach (var n in list.OrderBy(n => CheckHostRegions.Rank(n.Region))
                              .ThenBy(n => n.Country, StringComparer.OrdinalIgnoreCase)
                              .ThenBy(n => n.City, StringComparer.OrdinalIgnoreCase)
                              .ThenBy(n => n.Id, Comparer<string>.Create(CheckHostNode.CompareIds)))
            _pickNodes.Add(new CheckHostPickNode(n, OnPickToggled));
        SyncPickChecks();
        RebuildPickItems();
        OnPropertyChanged(nameof(PickReady));
        OnPropertyChanged(nameof(NodeChoiceText));
        OnPropertyChanged(nameof(PickSummary));
    }

    /// <summary>Nodes a run reported that the list doesn't have yet (a node added since it was loaded) — none dropped.</summary>
    private void MergeCatalog(IReadOnlyList<CheckHostNode> nodes)
    {
        if (_catalog is null || nodes.All(n => _catalog.Any(c => c.Id == n.Id))) return;
        SetCatalog(_catalog.Concat(nodes.Where(n => _catalog.All(c => c.Id != n.Id))).ToList(), _catalogIsSnapshot);
    }

    private void RebuildPickItems()
    {
        string f = PickFilter.Trim();
        var shown = _pickNodes.Where(p => f.Length == 0 || PickMatches(p.Node, f)).ToList();
        var items = new List<object>(shown.Count + 8);
        foreach (var g in shown.GroupBy(p => p.Node.Region))
        {
            items.Add(new CheckHostPickHeader(g.Key, g.Count()));
            items.AddRange(g);
        }
        PickItems.Clear();
        foreach (var item in items) PickItems.Add(item);
    }

    private static bool PickMatches(CheckHostNode n, string f) =>
        (f.Length == 2 && string.Equals(n.CountryCode, f, StringComparison.OrdinalIgnoreCase))
        || n.Location.Contains(f, StringComparison.OrdinalIgnoreCase) || n.Id.Contains(f, StringComparison.OrdinalIgnoreCase)
        || n.Region.Contains(f, StringComparison.OrdinalIgnoreCase) || n.Asn.Contains(f, StringComparison.OrdinalIgnoreCase);

    /// <summary>Ticks follow the choice: every node it covers (Automatic: none); region chips light up for chosen regions.</summary>
    private void SyncPickChecks()
    {
        var covered = _catalog is null ? new HashSet<string>() : _nodeChoice.Covered(_catalog).Select(n => n.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var p in _pickNodes)
        {
            p.Syncing = true;
            p.IsChecked = covered.Contains(p.Node.Id);
            p.Syncing = false;
        }
        foreach (var r in PickRegions)
            r.IsOn = _nodeChoice.Mode == CheckHostNodeChoice.ChoiceMode.Regions && _nodeChoice.Regions.Contains(r.Name, StringComparer.OrdinalIgnoreCase);
    }

    // A node ticked or unticked: the choice becomes exactly the ticked nodes (Automatic when none are left).
    private void OnPickToggled(CheckHostPickNode _)
    {
        NodeChoice = CheckHostNodeChoice.ForNodes(_pickNodes.Where(p => p.IsChecked).Select(p => p.Node.Id));
        SyncPickChecks();
    }

    [RelayCommand]
    private void PickAutomatic()
    {
        NodeChoice = CheckHostNodeChoice.Automatic;
        SyncPickChecks();
    }

    /// <summary>A region chip: adds the region to (or takes it out of) the chosen regions; picked nodes give way to it.</summary>
    [RelayCommand]
    private void PickRegion(string region)
    {
        var regions = _nodeChoice.Mode == CheckHostNodeChoice.ChoiceMode.Regions ? _nodeChoice.Regions.ToList() : new List<string>();
        if (regions.RemoveAll(r => string.Equals(r, region, StringComparison.OrdinalIgnoreCase)) == 0) regions.Add(region);
        NodeChoice = CheckHostNodeChoice.ForRegions(regions);
        SyncPickChecks();
    }

    [RelayCommand] private void ClearPickFilter() => PickFilter = "";

    /// <summary>Tick every node the filter shows ("germany" → all German nodes).</summary>
    [RelayCommand]
    private void PickShown()
    {
        var ids = _pickNodes.Where(p => p.IsChecked).Select(p => p.Node.Id)
                            .Concat(PickItems.OfType<CheckHostPickNode>().Select(p => p.Node.Id));
        NodeChoice = CheckHostNodeChoice.ForNodes(ids);
        SyncPickChecks();
    }
}
