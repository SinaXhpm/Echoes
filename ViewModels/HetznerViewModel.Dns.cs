using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>
/// DNS: the project's zones (status, record count, delegation: when the registrar doesn't point at Hetzner yet, the
/// name servers to set there), a zone's record sets with search and a type filter, the record set editor (values are
/// replaced with set_records, the TTL with change_ttl; a protected set is read-only), delete (asks first), a new zone,
/// and the zone file: exported to a file, or imported (it REPLACES every record set, so it asks for a tick).
/// </summary>
public partial class HetznerViewModel
{
    public const string AllTypes = "All types";
    /// <summary>The largest zone file taken for an import.</summary>
    public const int MaxZoneFileBytes = 1024 * 1024;

    public ObservableCollection<HzZone> Zones { get; } = new();
    public ObservableCollection<HzRrset> VisibleRrsets { get; } = new();
    public ObservableCollection<string> TypeFilters { get; } = new() { AllTypes };
    public IReadOnlyList<string> RrTypeOptions { get; } = HetznerApi.RrTypes.Where(t => t != "SOA").ToList();

    private readonly List<HzRrset> _rrsets = new();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasZone))]
    private HzZone? _selectedZone;
    [ObservableProperty] private bool _zonesLoaded;
    [ObservableProperty] private bool _isLoadingZones;
    [ObservableProperty] private bool _showZonesEmpty;
    [ObservableProperty] private bool _isLoadingRrsets;
    [ObservableProperty] private string _searchText = string.Empty;
    [ObservableProperty] private string _selectedTypeFilter = AllTypes;
    [ObservableProperty] private string _rrsetCountText = string.Empty;
    [ObservableProperty] private string _rrsetsEmptyText = string.Empty;
    [ObservableProperty] private bool _showRrsetsEmpty;

    // the record set editor
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsOverlayOpen))]
    private bool _isRrsetEditorOpen;
    [ObservableProperty] private bool _isNewRrset;
    [ObservableProperty] private string _editRrName = string.Empty;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(EditRrHint), nameof(ShowRrDdns))]
    private string _editRrType = "A";
    [ObservableProperty] private string _editRrTtl = string.Empty;
    [ObservableProperty] private string _editRrValues = string.Empty;
    [ObservableProperty] private bool _editRrDdns;
    [ObservableProperty] private string _rrsetEditorError = string.Empty;
    [ObservableProperty] private bool _isSavingRrset;
    private HzRrset? _editingRrset;
    private HzZone? _editorZone;   // the zone the editor was opened for

    // a new zone
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsOverlayOpen))]
    private bool _isAddZoneOpen;
    [ObservableProperty] private string _newZoneName = string.Empty;
    [ObservableProperty] private string _newZoneTtl = "3600";
    [ObservableProperty] private string _addZoneError = string.Empty;
    [ObservableProperty] private bool _isAddingZone;

    // a zone file import
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsOverlayOpen))]
    private bool _isImportOpen;
    [ObservableProperty] private string _importFileName = string.Empty;
    [ObservableProperty] private string _importPreview = string.Empty;
    [ObservableProperty] private string _importSummary = string.Empty;
    [ObservableProperty] private string _importWarning = string.Empty;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanImport))]
    private bool _importConfirmed;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanImport))]
    private bool _isImporting;
    private string _importText = string.Empty;
    private HzZone? _importZone;   // the zone the file was opened for

    public bool HasZone => SelectedZone != null;
    public bool CanImport => ImportConfirmed && !IsImporting && _importText.Length > 0;
    public bool HasImportWarning => ImportWarning.Length > 0;
    public bool ShowRrDdns => EditRrType is "A" or "AAAA";

    public string EditRrHint => EditRrType switch
    {
        "A" => "One IPv4 address per line.",
        "AAAA" => "One IPv6 address per line.",
        "CNAME" => "One name, ending with a dot (target.example.com.).",
        "MX" => "Priority and mail server per line (10 mail.example.com.).",
        "TXT" => "One text per line. Quotes are added when missing.",
        "NS" => "One name server per line, ending with a dot.",
        "SRV" => "Priority, weight, port and target per line (10 5 443 host.example.com.).",
        "CAA" => "Flags, tag and value per line (0 issue \"letsencrypt.org\").",
        _ => "One value per line, in zone file form.",
    };

    partial void OnImportWarningChanged(string value) => OnPropertyChanged(nameof(HasImportWarning));

    private void ClearDns()
    {
        Zones.Clear();
        SelectedZone = null;
        _rrsets.Clear();
        VisibleRrsets.Clear();
        ZonesLoaded = false;
        ShowZonesEmpty = false;
        ShowRrsetsEmpty = false;
        RrsetCountText = string.Empty;
        IsRrsetEditorOpen = false;
        IsAddZoneOpen = false;
        IsImportOpen = false;
    }

    private async Task LoadZonesAsync(long? keepZoneId)
    {
        if (Api() is not { } api) return;
        var (ct, gen) = Session();
        IsLoadingZones = true;
        BeginBusy();
        SetStatus("Loading DNS zones…");
        try
        {
            HzListResponse r;
            try { r = await Task.Run(() => api.GetAllAsync("/zones", "zones", ct), ct); }
            catch (OperationCanceledException) { return; }
            if (Stale(gen)) return;
            if (!r.Success)
            {
                Report(r, "load the DNS zones");
                return;
            }
            var list = LastById(r.Items.Select(HzZone.From).Where(z => z != null).Select(z => z!), z => z.Id)
                       .OrderBy(z => z.Name, StringComparer.Ordinal).ToList();
            long keep = keepZoneId ?? SelectedZone?.Id ?? 0;
            Zones.Clear();
            foreach (var z in list) Zones.Add(z);
            ZonesLoaded = true;
            ShowZonesEmpty = Zones.Count == 0;
            // a fresh object every time, so the selection changes and its record sets load again
            SelectedZone = Zones.FirstOrDefault(z => z.Id == keep) ?? Zones.FirstOrDefault();
            if (Zones.Count == 0) SetStatus("No DNS zones in this project yet. Add one with +.");
        }
        finally
        {
            if (!Stale(gen)) IsLoadingZones = false;
            EndBusy(gen);
        }
    }

    partial void OnSelectedZoneChanged(HzZone? value)
    {
        _rrsets.Clear();
        VisibleRrsets.Clear();
        RrsetCountText = string.Empty;
        ShowRrsetsEmpty = false;
        // The editor and an import act on the zone they were opened for: another zone closes them (a reload that brings
        // the same zone back as a new object doesn't).
        if (IsRrsetEditorOpen && !IsSavingRrset && _editorZone?.Id != value?.Id)
        {
            IsRrsetEditorOpen = false;
            _zoneNotice = "The record set editor was closed: another zone was chosen. Nothing was saved.";
            SetStatus(_zoneNotice);
        }
        if (IsImportOpen && !IsImporting && _importZone?.Id != value?.Id)
        {
            IsImportOpen = false;
            _importText = string.Empty;
            _zoneNotice = "The zone file import was closed: another zone was chosen. Nothing was imported.";
            SetStatus(_zoneNotice);
        }
        if (value != null) Fire(LoadRrsetsAsync, "load the record sets");
    }

    [RelayCommand]
    private Task ReloadRrsets() => LoadRrsetsAsync();

    private async Task LoadRrsetsAsync()
    {
        if (SelectedZone is not { } zone || Api() is not { } api) return;
        var (ct, gen) = Session();
        // this load's number: an earlier load (another zone) that ends later must not clear the flag of this one
        int run = ++_rrsetLoad;
        IsLoadingRrsets = true;
        BeginBusy();
        try
        {
            HzListResponse r;
            try { r = await Task.Run(() => api.GetAllAsync(HetznerApi.ZonePath(zone.Id) + "/rrsets", "rrsets", ct), ct); }
            catch (OperationCanceledException) { return; }
            if (Stale(gen) || SelectedZone?.Id != zone.Id) return;
            if (!r.Success)
            {
                Report(r, $"load the records of {zone.Name}");
                RrsetsEmptyText = "The records couldn't be loaded. Details below.";
                ShowRrsetsEmpty = true;
                return;
            }
            _rrsets.Clear();
            // by id, the last one read winning: a list that changed while it was paged can repeat a set
            var byId = new Dictionary<string, HzRrset>(StringComparer.Ordinal);
            foreach (var n in r.Items)
                if (HzRrset.From(n, zone.Name, zone.Ttl) is { } set) byId[set.Id] = set;
            _rrsets.AddRange(byId.Values);
            _rrsets.Sort(CompareRrsets);
            RefreshTypeFilters();
            ApplyFilter();
            ApplyDdnsMarks();
            // the note of an editor or import closed by the zone change stays in front of the count
            string notice = _zoneNotice.Length > 0 ? _zoneNotice + " " : string.Empty;
            _zoneNotice = string.Empty;
            SetStatus($"{notice}{zone.Name}: {RrsetCountText}{(r.Truncated ? " (the first ones)" : string.Empty)}.");
        }
        finally
        {
            if (!Stale(gen) && run == _rrsetLoad) IsLoadingRrsets = false;
            EndBusy(gen);
        }
    }

    private int _rrsetLoad;
    private string _zoneNotice = string.Empty;

    // the apex first, then by name; SOA and NS of a name before its other types
    private static int CompareRrsets(HzRrset a, HzRrset b)
    {
        int byApex = (a.Name == "@" ? 0 : 1).CompareTo(b.Name == "@" ? 0 : 1);
        if (byApex != 0) return byApex;
        int byName = string.CompareOrdinal(a.Name, b.Name);
        if (byName != 0) return byName;
        static int Rank(string t) => t switch { "SOA" => 0, "NS" => 1, _ => 2 };
        int byRank = Rank(a.Type).CompareTo(Rank(b.Type));
        return byRank != 0 ? byRank : string.CompareOrdinal(a.Type, b.Type);
    }

    private void RefreshTypeFilters()
    {
        string keep = SelectedTypeFilter;
        var types = _rrsets.Select(r => r.Type).Distinct().OrderBy(t => Array.IndexOf(HetznerApi.RrTypes, t)).ToList();
        TypeFilters.Clear();
        TypeFilters.Add(AllTypes);
        foreach (var t in types) TypeFilters.Add(t);
        SelectedTypeFilter = TypeFilters.Contains(keep) ? keep : AllTypes;
    }

    partial void OnSearchTextChanged(string value) => ApplyFilter();
    partial void OnSelectedTypeFilterChanged(string value) => ApplyFilter();

    private void ApplyFilter()
    {
        string q = (SearchText ?? string.Empty).Trim();
        string type = SelectedTypeFilter ?? AllTypes;
        var shown = _rrsets.Where(r => (type == AllTypes || r.Type == type)
                                       && (q.Length == 0 || r.FullName.Contains(q, StringComparison.OrdinalIgnoreCase)
                                           || r.Values.Any(v => v.Value.Contains(q, StringComparison.OrdinalIgnoreCase))))
                           .ToList();
        VisibleRrsets.Clear();
        foreach (var r in shown) VisibleRrsets.Add(r);
        RrsetCountText = shown.Count == _rrsets.Count ? Count(_rrsets.Count) : $"{shown.Count} of {_rrsets.Count}";
        ShowRrsetsEmpty = shown.Count == 0;
        RrsetsEmptyText = _rrsets.Count == 0 ? "This zone has no record sets yet." : "No record set matches.";

        static string Count(int n) => n == 1 ? "1 record set" : $"{n} record sets";
    }

    [RelayCommand]
    private async Task CopyNameServers()
    {
        if (SelectedZone is not { Assigned.Count: > 0 } z) return;
        await ClipboardHelper.SetTextAsync(string.Join(Environment.NewLine, z.Assigned));
        SetStatus("Name servers copied.");
    }

    // ---------- the record set editor ----------

    [RelayCommand]
    private void NewRrset()
    {
        if (SelectedZone is not { IsPrimary: true } zone) { SetError("Records of a secondary zone come from its primary server."); return; }
        _editorZone = zone;
        _editingRrset = null;
        IsNewRrset = true;
        EditRrName = string.Empty;
        EditRrType = "A";
        EditRrTtl = string.Empty;
        EditRrValues = string.Empty;
        EditRrDdns = false;
        RrsetEditorError = string.Empty;
        IsRrsetEditorOpen = true;
    }

    [RelayCommand]
    private void EditRrset(HzRrset? set)
    {
        if (set is null || SelectedZone is not { } zone) return;
        if (!set.IsEditable)
        {
            SetStatus(set.Protected ? $"{set.FullName} ({set.Type}) is protected: change it in the Hetzner Console after turning protection off."
                : set.Type == "SOA" ? "Hetzner keeps the SOA record itself."
                : $"{set.FullName} ({set.Type}) holds values this editor can't show as they are (a line break, or very many). Change it in the Hetzner Console.");
            return;
        }
        _editorZone = zone;
        _editingRrset = set;
        IsNewRrset = false;
        EditRrName = set.Name;
        EditRrType = set.Type;
        EditRrTtl = set.Ttl is int t ? t.ToString(CultureInfo.InvariantCulture) : string.Empty;
        EditRrValues = set.AllValuesText;
        EditRrDdns = set.DdnsOn;
        RrsetEditorError = string.Empty;
        IsRrsetEditorOpen = true;
    }

    [RelayCommand]
    private void CancelRrset()
    {
        if (IsSavingRrset) return;
        IsRrsetEditorOpen = false;
    }

    // A new A / AAAA set with "Keep updated" ticked and no address yet: fill in the public IP.
    partial void OnEditRrDdnsChanged(bool value)
    {
        if (value && IsRrsetEditorOpen && IsNewRrset && ShowRrDdns && EditRrValues.Trim().Length == 0) Fire(FillRrIpAsync, "look up your public IP");
    }

    private async Task FillRrIpAsync()
    {
        var fam = EditRrType == "AAAA" ? DdnsFamily.V6 : DdnsFamily.V4;
        var known = fam == DdnsFamily.V4 ? DdnsService.Instance.LastIpv4 : DdnsService.Instance.LastIpv6;
        string? ip = known is { Address: { } a } && known.At > DateTimeOffset.UtcNow.AddMinutes(-10) ? a : null;
        if (ip is null)
        {
            DdnsIpResult r;
            try { r = await Task.Run(() => DdnsIpDetector.DetectAsync(fam, System.Threading.CancellationToken.None)); }
            catch (Exception ex) { r = new DdnsIpResult { Error = ex.Message }; }
            ip = r.Address;
            if (ip is null && IsRrsetEditorOpen && IsNewRrset && EditRrDdns) RrsetEditorError = r.Error;
        }
        if (ip != null && IsRrsetEditorOpen && IsNewRrset && EditRrDdns && EditRrValues.Trim().Length == 0) EditRrValues = ip;
    }

    /// <summary>The values typed (one per line) checked for the type: A / AAAA must be addresses of that family; a TXT
    /// value is quoted when it isn't. Null with a reason.</summary>
    internal static List<string>? ParseValues(string type, string text, out string error)
    {
        error = string.Empty;
        var values = new List<string>();
        foreach (var raw in (text ?? string.Empty).Split('\n'))
        {
            string v = raw.Trim();
            if (v.Length == 0) continue;
            if (type is "A" or "AAAA")
            {
                var fam = type == "A" ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;
                // IPAddress.TryParse also takes "203.0.113" (203.0.0.113), "22" and octal "010": an IPv4 address must be
                // four dotted decimals, no leading zeros
                bool shape = type == "A" ? HostExtractor.IsStrictIPv4(v) : v.Contains(':');
                if (!shape || !IPAddress.TryParse(v, out var ip) || ip.AddressFamily != fam || v.Contains('%') || v.Contains('/'))
                {
                    error = $"\"{(v.Length > 45 ? v[..45] + "…" : v)}\" isn't an {(type == "A" ? "IPv4" : "IPv6")} address.";
                    return null;
                }
                v = ip.ToString();
            }
            else if (type == "TXT") v = QuoteTxt(v);
            if (v.Length > 4096) { error = "A value is at most 4096 characters."; return null; }
            if (!values.Contains(v)) values.Add(v);
        }
        if (values.Count == 0) { error = "Enter at least one value."; return null; }
        if (values.Count > 200) { error = "A record set holds at most 200 values here."; return null; }
        if (type == "CNAME" && values.Count > 1) { error = "A CNAME has exactly one value."; return null; }
        return values;
    }

    /// <summary>A TXT value in zone file form: kept when it is already quoted, otherwise quoted (backslashes and quotes
    /// escaped) and cut into strings of at most 255 bytes, as DNS requires.</summary>
    internal static string QuoteTxt(string v)
    {
        if (v.Length >= 2 && v[0] == '"' && v[^1] == '"') return v;
        var parts = new List<string>();
        var sb = new StringBuilder();
        int bytes = 0;
        foreach (var rune in v.EnumerateRunes())
        {
            int n = rune.Utf8SequenceLength;
            if (bytes + n > 255)
            {
                parts.Add(sb.ToString());
                sb.Clear();
                bytes = 0;
            }
            string s = rune.ToString();
            sb.Append(s is "\"" or "\\" ? "\\" + s : s);
            bytes += n;
        }
        parts.Add(sb.ToString());
        return string.Join(" ", parts.Select(p => "\"" + p + "\""));
    }

    /// <summary>
    /// The records a save sends for <paramref name="values"/>: a value that stays keeps its comment, and when a set of
    /// one value gets another single value, its comment goes with it (as dynamic DNS does). Comments go back exactly as
    /// Hetzner had them.
    /// </summary>
    internal static JsonArray RecordsToWrite(HzRrset? old, IReadOnlyList<string> values)
    {
        var records = new JsonArray();
        foreach (var v in values)
        {
            var rec = new JsonObject { ["value"] = v };
            string? comment = old?.Values.FirstOrDefault(o => o.Value == v)?.Comment;
            if (comment is null && old is { Values.Count: 1 } && values.Count == 1) comment = old.Values[0].Comment;
            if (!string.IsNullOrEmpty(comment)) rec["comment"] = comment;
            records.Add((JsonNode)rec);
        }
        return records;
    }

    private static string ChangedElsewhereText(HzRrset now)
    {
        string holds = now.Values.Count == 0 ? "no values" : HetznerApi.Clip(string.Join(", ", now.Values.Select(v => v.Value)), 300);
        return $"This record set was changed elsewhere since you opened it, so nothing was saved. It now holds {holds} (TTL {now.TtlText})"
               + (now.Protected ? " and is protected" : string.Empty)
               + ". Your values are still here: check them, then save again.";
    }

    // a set read again replaces its row (same name and type)
    private void ReplaceRrset(HzRrset fresh)
    {
        int i = _rrsets.FindIndex(r => r.Id == fresh.Id);
        if (i < 0) return;
        _rrsets[i] = fresh;
        ApplyFilter();
        ApplyDdnsMarks();
    }

    private static bool TryTtl(string text, out int? ttl)
    {
        ttl = null;
        string t = (text ?? string.Empty).Trim();
        if (t.Length == 0) return true;   // the zone's default
        if (int.TryParse(t, NumberStyles.None, CultureInfo.InvariantCulture, out int v) && v >= 60) { ttl = v; return true; }
        return false;
    }

    /// <summary>Save the editor: a new set (POST), or new values (set_records) and a new TTL (change_ttl).</summary>
    /// <remarks>An edit reads the set again first. When it changed elsewhere since the editor opened (the Console,
    /// another tool), nothing is written: the editor says what the set holds now and keeps what was typed, so a save
    /// never undoes a change the user didn't see.</remarks>
    [RelayCommand]
    private async Task SaveRrsetAsync()
    {
        if (IsSavingRrset || Api() is not { } api) return;
        RrsetEditorError = string.Empty;
        // the zone the editor was opened for, and only while it is still the one shown
        if (_editorZone is not { } zone || SelectedZone?.Id != zone.Id)
        {
            RrsetEditorError = "The zone changed after this editor was opened, so nothing was saved. Cancel, then open the record set again from the zone you mean.";
            return;
        }
        string type = EditRrType;
        if (!HetznerApi.IsRrType(type) || type == "SOA") { RrsetEditorError = "Choose a record type."; return; }
        string? name;
        string nameError = string.Empty;
        if (IsNewRrset) name = HetznerApi.NormalizeRrName(EditRrName, zone.Name, out nameError);
        else name = _editingRrset?.Name;
        if (name is null) { RrsetEditorError = IsNewRrset ? nameError : "This record set is gone."; return; }
        if (ParseValues(type, EditRrValues, out string valueError) is not { } values) { RrsetEditorError = valueError; return; }
        if (!TryTtl(EditRrTtl, out int? ttl)) { RrsetEditorError = "The TTL is a number of seconds, 60 or more (empty: the zone's default)."; return; }
        if (IsNewRrset && _rrsets.Any(r => r.Name == name && r.Type == type))
        {
            RrsetEditorError = $"{HetznerApi.FullName(name, zone.Name)} already has {type} records. Edit that record set instead.";
            return;
        }
        bool wantDdns = ShowRrDdns && EditRrDdns;
        if (wantDdns && values.Count > 1)
        {
            RrsetEditorError = "Dynamic DNS keeps exactly one value on your IP. Leave one value, or untick Keep updated with my IP.";
            return;
        }

        var (ct, gen) = Session();
        IsSavingRrset = true;
        BeginBusy();
        try
        {
            string path = HetznerApi.RrsetPath(zone.Id, name, type);
            var old = _editingRrset;
            if (!IsNewRrset)
            {
                if (old is null) { RrsetEditorError = "This record set is gone."; return; }
                HzResponse cur;
                try { cur = await Task.Run(() => api.GetAsync(path, ct), ct); }
                catch (OperationCanceledException) { return; }
                if (Stale(gen)) return;
                if (!cur.Success)
                {
                    RrsetEditorError = cur.NotFound
                        ? "This record set was deleted elsewhere since you opened it, so nothing was saved. Cancel, then add it again if you still want it."
                        : "Couldn't check the record set before saving, so nothing was saved: " + cur.Error;
                    return;
                }
                if (HzRrset.From(cur.Body?["rrset"], zone.Name, zone.Ttl) is not { } now)
                {
                    RrsetEditorError = "Hetzner's answer for this record set couldn't be read, so nothing was saved.";
                    return;
                }
                if (!now.SameAs(old))
                {
                    // what the next save compares with: the set as it is now (the typed values stay in the editor)
                    _editingRrset = now;
                    ReplaceRrset(now);
                    RrsetEditorError = ChangedElsewhereText(now);
                    return;
                }
            }
            var records = RecordsToWrite(old, values);
            var steps = new List<(string Path, JsonObject Body)>();
            if (IsNewRrset)
            {
                var body = new JsonObject { ["name"] = name, ["type"] = type, ["records"] = records };
                if (ttl is int t) body["ttl"] = t;
                steps.Add((HetznerApi.ZonePath(zone.Id) + "/rrsets", body));
            }
            else
            {
                bool valuesChanged = old is null || !old.Values.Select(v => v.Value).SequenceEqual(values);
                if (valuesChanged) steps.Add((path + "/actions/set_records", new JsonObject { ["records"] = records }));
                if (old?.Ttl != ttl) steps.Add((path + "/actions/change_ttl", new JsonObject { ["ttl"] = ttl }));   // null: the zone's default
            }

            foreach (var (stepPath, body) in steps)
            {
                HzResponse r;
                try { r = await Task.Run(() => api.PostAsync(stepPath, body, ct), ct); }
                catch (OperationCanceledException) { return; }
                if (Stale(gen)) return;
                if (!r.Success)
                {
                    if (r.ReadOnly) MarkReadOnly(true);
                    RrsetEditorError = r.Error;
                    return;
                }
                WriteWorked();
                if (HzAction.From(r.Body?["action"]) is { IsSuccess: false } action)
                {
                    HzActionResult done;
                    try { done = await Task.Run(() => api.WaitActionAsync("zones", action, null, ct, TimeSpan.FromSeconds(60)), ct); }
                    catch (OperationCanceledException) { return; }
                    if (Stale(gen)) return;
                    if (!done.Ok && !done.StillRunning) { RrsetEditorError = "Hetzner couldn't apply it: " + done.Error; return; }
                }
            }

            IsRrsetEditorOpen = false;
            string full = HetznerApi.FullName(name, zone.Name);
            string? ddnsNote = ApplyEditorDdns(zone, name, type, full, values, wantDdns);
            SetStatus((steps.Count == 0 ? $"{full} ({type}) didn't change." : $"{full} ({type}) saved.") + (ddnsNote is null ? string.Empty : " " + ddnsNote));
            await LoadRrsetsAsync();
        }
        finally
        {
            if (!Stale(gen)) IsSavingRrset = false;
            EndBusy(gen);
        }
    }

    // ---------- delete ----------

    [RelayCommand]
    private void RequestDeleteRrset(HzRrset? set)
    {
        if (set is null) return;
        if (!set.IsEditable) { EditRrset(set); return; }
        foreach (var r in VisibleRrsets) r.PendingDelete = false;
        set.PendingDelete = true;
    }

    [RelayCommand]
    private void CancelDeleteRrset(HzRrset? set)
    {
        if (set != null) set.PendingDelete = false;
    }

    [RelayCommand]
    private async Task DeleteRrset(HzRrset? set)
    {
        if (set is null || !set.IsEditable || SelectedZone is not { } zone || Api() is not { } api) return;
        set.PendingDelete = false;
        var (ct, gen) = Session();
        set.IsBusy = true;
        BeginBusy();
        try
        {
            HzResponse r;
            try { r = await Task.Run(() => api.DeleteAsync(HetznerApi.RrsetPath(zone.Id, set.Name, set.Type), ct), ct); }
            catch (OperationCanceledException) { return; }
            if (Stale(gen)) return;
            if (!r.Success && !r.NotFound)
            {
                Report(r, $"delete {set.FullName} ({set.Type})");
                return;
            }
            WriteWorked();
            if (HzAction.From(r.Body?["action"]) is { IsSuccess: false } action)
            {
                try { await Task.Run(() => api.WaitActionAsync("zones", action, null, ct, TimeSpan.FromSeconds(60)), ct); }
                catch (OperationCanceledException) { return; }
                if (Stale(gen)) return;
            }
            _rrsets.Remove(set);
            ApplyFilter();
            bool hadDdns = DdnsService.Instance.RemoveRecord(DdnsProvider.Hetzner, zone.Id.ToString(CultureInfo.InvariantCulture), set.Id);
            SetStatus($"{set.FullName} ({set.Type}) was deleted." + (hadDdns ? " It no longer follows your public IP." : string.Empty));
        }
        finally
        {
            set.IsBusy = false;
            EndBusy(gen);
        }
    }

    // ---------- a new zone ----------

    [RelayCommand]
    private void OpenAddZone()
    {
        NewZoneName = string.Empty;
        NewZoneTtl = "3600";
        AddZoneError = string.Empty;
        IsAddZoneOpen = true;
    }

    [RelayCommand]
    private void CloseAddZone()
    {
        if (!IsAddingZone) IsAddZoneOpen = false;
    }

    [RelayCommand]
    private async Task CreateZoneAsync()
    {
        if (IsAddingZone || Api() is not { } api) return;
        AddZoneError = string.Empty;
        if (HetznerApi.NormalizeZoneName(NewZoneName, out string nameError) is not { } name) { AddZoneError = nameError; return; }
        if (!TryTtl(NewZoneTtl, out int? ttl)) { AddZoneError = "The TTL is a number of seconds, 60 or more."; return; }
        var (ct, gen) = Session();
        IsAddingZone = true;
        BeginBusy();
        try
        {
            var body = new JsonObject { ["name"] = name, ["mode"] = "primary" };
            if (ttl is int t) body["ttl"] = t;
            HzResponse r;
            try { r = await Task.Run(() => api.PostAsync("/zones", body, ct), ct); }
            catch (OperationCanceledException) { return; }
            if (Stale(gen)) return;
            if (!r.Success)
            {
                if (r.ReadOnly) MarkReadOnly(true);
                AddZoneError = r.Error;
                return;
            }
            WriteWorked();
            long? id = HzZone.From(r.Body?["zone"])?.Id;
            if (HzAction.From(r.Body?["action"]) is { IsSuccess: false } action)
            {
                try { await Task.Run(() => api.WaitActionAsync("zones", action, null, ct, TimeSpan.FromSeconds(60)), ct); }
                catch (OperationCanceledException) { return; }
                if (Stale(gen)) return;
            }
            IsAddZoneOpen = false;
            SetStatus($"{name} was added. Set its name servers at your registrar (shown with the zone).");
            await LoadZonesAsync(keepZoneId: id);
        }
        finally
        {
            if (!Stale(gen)) IsAddingZone = false;
            EndBusy(gen);
        }
    }

    // ---------- zone file ----------

    /// <summary>The selected zone's zone file for the view to save, or null (the status line says why).</summary>
    public async Task<(string FileName, string Text)?> ExportZoneFileAsync()
    {
        if (SelectedZone is not { } zone || Api() is not { } api) return null;
        var (ct, gen) = Session();
        BeginBusy();
        try
        {
            HzResponse r;
            try { r = await Task.Run(() => api.GetAsync(HetznerApi.ZonePath(zone.Id) + "/zonefile", ct), ct); }
            catch (OperationCanceledException) { return null; }
            if (Stale(gen)) return null;
            if (!r.Success) { Report(r, $"export {zone.Name}"); return null; }
            string text = CfJson.Str(r.Body?["zonefile"]);
            if (text.Length == 0) { SetError("Hetzner sent an empty zone file."); return null; }
            // the zone name is checked (letters, digits, '-' and dots), so it is safe as a file name
            return (zone.Name + ".zone", text);
        }
        finally { EndBusy(gen); }
    }

    public void ReportSaved(string what, string fileName) => SetStatus($"{what} saved as {fileName}.");
    public void ReportFileError(string message) => SetError(message);

    /// <summary>A zone file was picked: check it is text, then show what the import would do (it asks first).</summary>
    public void OpenZoneImport(byte[] data, string fileName)
    {
        if (SelectedZone is not { } zone) return;
        if (!zone.IsPrimary) { SetError("A zone file can only be imported into a primary zone."); return; }
        if (data.Length > MaxZoneFileBytes) { SetError($"The file is larger than {MaxZoneFileBytes / 1024} KB."); return; }
        string text;
        try { text = new UTF8Encoding(false, true).GetString(data); }
        catch (DecoderFallbackException) { SetError("That file isn't a text zone file."); return; }
        if (text.Length > 0 && text[0] == (char)0xFEFF) text = text[1..];   // a byte order mark
        if (text.Contains('\0') || text.Trim().Length == 0) { SetError("That file isn't a text zone file."); return; }
        var lines = text.Split('\n');
        _importText = text;
        ImportFileName = HetznerApi.Clip(fileName, 120);
        ImportSummary = $"{lines.Length} lines. Every record set of {zone.Name} is replaced by the file's.";
        ImportPreview = string.Join("\n", lines.Take(40).Select(l => HetznerApi.Clip(l.TrimEnd('\r'), 200))) + (lines.Length > 40 ? "\n…" : string.Empty);
        bool soa = lines.Any(l => System.Text.RegularExpressions.Regex.IsMatch(l, @"\sSOA\s", System.Text.RegularExpressions.RegexOptions.IgnoreCase));
        bool ns = zone.Assigned.All(a => text.Contains(a.TrimEnd('.'), StringComparison.OrdinalIgnoreCase));
        ImportWarning = !soa ? "The file has no SOA record; Hetzner requires one."
            : !ns ? "Hetzner requires its assigned name servers as NS records: " + string.Join(", ", zone.Assigned) + "."
            : string.Empty;
        ImportConfirmed = false;
        _importZone = zone;
        IsImportOpen = true;
        OnPropertyChanged(nameof(CanImport));
    }

    [RelayCommand]
    private void CloseImport()
    {
        if (IsImporting) return;
        IsImportOpen = false;
        _importText = string.Empty;
        _importZone = null;
    }

    [RelayCommand]
    private async Task ImportZoneFileAsync()
    {
        if (!CanImport || Api() is not { } api) return;
        // the zone the file was opened for, and only while it is still the one shown
        if (_importZone is not { } zone || SelectedZone?.Id != zone.Id)
        {
            IsImportOpen = false;
            _importText = string.Empty;
            SetError("Nothing was imported: the zone changed after the file was opened. Open the file again from the zone you mean.");
            return;
        }
        var (ct, gen) = Session();
        IsImporting = true;
        BeginBusy();
        try
        {
            HzResponse r;
            try { r = await Task.Run(() => api.PostAsync(HetznerApi.ZonePath(zone.Id) + "/actions/import_zonefile", new JsonObject { ["zonefile"] = _importText }, ct), ct); }
            catch (OperationCanceledException) { return; }
            if (Stale(gen)) return;
            if (!r.Success)
            {
                IsImportOpen = false;
                Report(r, $"import into {zone.Name}");
                return;
            }
            WriteWorked();
            if (HzAction.From(r.Body?["action"]) is { IsSuccess: false } action)
            {
                HzActionResult done;
                try { done = await Task.Run(() => api.WaitActionAsync("zones", action, null, ct, TimeSpan.FromSeconds(120)), ct); }
                catch (OperationCanceledException) { return; }
                if (Stale(gen)) return;
                if (!done.Ok && !done.StillRunning)
                {
                    IsImportOpen = false;
                    SetError($"The import into {zone.Name} failed: {done.Error}");
                    return;
                }
            }
            IsImportOpen = false;
            _importText = string.Empty;
            SetStatus($"{ImportFileName} was imported into {zone.Name}.");
            await LoadZonesAsync(keepZoneId: zone.Id);
        }
        finally
        {
            if (!Stale(gen)) IsImporting = false;
            EndBusy(gen);
        }
    }
}
