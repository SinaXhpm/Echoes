using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

// DNS records: the list (search, type filter, proxied pill, inline delete) and the record editor.
public partial class CloudflareViewModel
{
    public const string AllTypes = "All types";

    /// <summary>Every record of the selected zone (sorted by type, then name).</summary>
    public ObservableCollection<CfRecord> Records { get; } = new();

    /// <summary>What the list shows: <see cref="Records"/> through the search box and the type filter. Replaced as a
    /// whole on every change (one reset for the virtualized list instead of one event per row).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(RecordCountText), nameof(ShowRecordsEmpty), nameof(RecordsEmptyText))]
    private IReadOnlyList<CfRecord> _visibleRecords = Array.Empty<CfRecord>();

    [ObservableProperty] private CfRecord? _selectedRecord;
    [ObservableProperty] private string _searchText = string.Empty;

    /// <summary>"All types" + the types present in the zone.</summary>
    public ObservableCollection<string> TypeFilters { get; } = new() { AllTypes };
    [ObservableProperty] private string? _selectedTypeFilter = AllTypes;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(RecordsEmptyText), nameof(CanBackup))]
    private bool _isLoadingRecords;

    private string _recordsZoneId = string.Empty;   // the zone whose records Records holds (fully loaded)

    private string RecordsZoneId
    {
        set
        {
            if (_recordsZoneId == value) return;
            _recordsZoneId = value;
            OnPropertyChanged(nameof(CanBackup));
            OnPropertyChanged(nameof(RecordsEmptyText));
        }
    }
    private Task? _recordsTask;
    private CancellationTokenSource? _recordsCts;
    private int _recordsGen;
    private CfRecord? _pendingDelete;
    private bool _rebuildingFilters;
    private bool _recordsFailed;      // the last load of this zone's records failed (the empty list says so)

    public string RecordCountText
    {
        get
        {
            int all = Records.Count, shown = VisibleRecords.Count;
            if (all == 0) return string.Empty;
            return shown == all ? $"{all} record{(all == 1 ? "" : "s")}" : $"{shown} of {all}";
        }
    }

    public bool ShowRecordsEmpty => VisibleRecords.Count == 0;

    public string RecordsEmptyText => IsLoadingRecords ? "Loading records…"
        : _recordsFailed ? "Couldn't load the records. The status line says why."
        : Records.Count == 0
            ? (_recordsZoneId.Length == 0 ? "The zone's records show up here." : "No DNS records yet. Add one or restore a backup.")
            : "No records match the search.";

    // ---------- loading ----------

    private Task LoadRecordsAsync(CfZone zone)
    {
        _recordsCts?.Cancel();
        _recordsCts?.Dispose();
        _recordsCts = CancellationTokenSource.CreateLinkedTokenSource(_sessionCts.Token);
        var task = LoadRecordsCoreAsync(zone, ++_recordsGen, _recordsCts.Token);
        _recordsTask = task;
        return task;
    }

    [RelayCommand]
    private Task ReloadRecords() => SelectedZone is { } zone ? LoadRecordsAsync(zone) : Task.CompletedTask;

    private async Task LoadRecordsCoreAsync(CfZone zone, int gen, CancellationToken ct)
    {
        var api = Api(out string error);
        if (api is null) { SetError(error); return; }
        int session = _sessionGen;
        RecordsZoneId = string.Empty;
        _recordsFailed = false;
        Records.Clear();
        RefreshVisible();
        IsLoadingRecords = true;
        BeginBusy();
        SetStatus($"Loading the DNS records of {zone.Name}…");
        CfListResponse r;
        try { r = await api.GetAllAsync(CloudflareApi.ZonePath(zone.Id) + "/dns_records", 500, CfPermission.DnsEdit, ct); }
        catch (OperationCanceledException) { return; }
        finally
        {
            EndBusy(session);
            if (gen == _recordsGen) IsLoadingRecords = false;
        }
        if (gen != _recordsGen || session != _sessionGen || !ReferenceEquals(zone, SelectedZone)) return;
        if (!r.Success)
        {
            _recordsFailed = true;
            OnPropertyChanged(nameof(RecordsEmptyText));
            SetError($"Couldn't load the DNS records of {zone.Name}: {r.Error}");
            return;
        }

        // Parsing (each record's data is deep-copied) and sorting off the UI thread: a zone can hold 100,000 records
        // (GetAllAsync allows 200 pages of 500), and every load and zone switch froze the window while they ran.
        var items = r.Items;
        var list = await Task.Run(() =>
        {
            var parsed = items.Select(CfRecord.FromApi).OfType<CfRecord>().ToList();
            parsed.Sort(CompareRecords);
            return parsed;
        });
        if (gen != _recordsGen || session != _sessionGen || !ReferenceEquals(zone, SelectedZone)) return;   // switched meanwhile
        foreach (var rec in list) Records.Add(rec);
        RecordsZoneId = zone.Id;
        RebuildTypeFilters();
        RefreshVisible();
        SetStatus(r.Truncated
            ? $"{zone.Name}: showing the first {Records.Count} records."
            : $"{zone.Name}: {Records.Count} DNS record{(Records.Count == 1 ? "" : "s")}.");
    }

    private static int CompareRecords(CfRecord a, CfRecord b)
    {
        int c = string.CompareOrdinal(a.Type, b.Type);
        if (c != 0) return c;
        c = string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
        return c != 0 ? c : string.CompareOrdinal(a.Content, b.Content);
    }

    private void InsertSorted(CfRecord rec)
    {
        int i = 0;
        while (i < Records.Count && CompareRecords(Records[i], rec) <= 0) i++;
        Records.Insert(i, rec);
    }

    // Leaving a zone: stop its load and drop everything shown for it.
    private void ResetZoneScopedUi()
    {
        _recordsCts?.Cancel();
        _recordsGen++;
        IsLoadingRecords = false;
        RecordsZoneId = string.Empty;
        _recordsFailed = false;
        _pendingDelete = null;
        Records.Clear();
        _rebuildingFilters = true;
        SearchText = string.Empty;
        TypeFilters.Clear();
        TypeFilters.Add(AllTypes);
        SelectedTypeFilter = AllTypes;
        _rebuildingFilters = false;
        RefreshVisible();
        PurgeAllConfirm = false;
        PauseConfirm = false;
        PurgeUrlsError = string.Empty;
        // the IP access form and the inline confirmations belong to the zone that was open
        AccessError = string.Empty;
        AccessInput = string.Empty;
        AccessNote = string.Empty;
        RequestDeleteAccess(null);
        RequestDeleteRule(null);
    }

    // ---------- search + type filter ----------

    partial void OnSearchTextChanged(string value) => RefreshVisible();

    partial void OnSelectedTypeFilterChanged(string? value) => RefreshVisible();

    private void RefreshVisible()
    {
        if (_rebuildingFilters) return;
        string q = (SearchText ?? string.Empty).Trim();
        string? type = SelectedTypeFilter is { } f && f != AllTypes ? f : null;
        var list = new List<CfRecord>(Records.Count);
        foreach (var r in Records)
        {
            if (type != null && r.Type != type) continue;
            if (q.Length > 0 && !r.Name.Contains(q, StringComparison.OrdinalIgnoreCase)
                             && !r.Content.Contains(q, StringComparison.OrdinalIgnoreCase)) continue;
            list.Add(r);
        }
        // the same rows as shown (a keystroke that matched the same records): the list isn't reset and rebuilt
        if (list.Count == VisibleRecords.Count && list.SequenceEqual(VisibleRecords)) return;
        VisibleRecords = list;
    }

    private void RebuildTypeFilters()
    {
        string? keep = SelectedTypeFilter;
        _rebuildingFilters = true;
        TypeFilters.Clear();
        TypeFilters.Add(AllTypes);
        foreach (var t in Records.Select(r => r.Type).Where(t => t.Length > 0).Distinct().OrderBy(t => t, StringComparer.Ordinal))
            TypeFilters.Add(t);
        SelectedTypeFilter = keep != null && TypeFilters.Contains(keep) ? keep : AllTypes;
        _rebuildingFilters = false;
    }

    // ---------- proxied pill ----------

    /// <summary>The proxied pill: flips the orange cloud with a PATCH of just {"proxied"} (A / AAAA / CNAME only).</summary>
    [RelayCommand]
    private async Task ToggleProxied(CfRecord? rec)
    {
        if (rec is null || !rec.CanProxy || rec.IsBusy || SelectedZone is not { } zone) return;
        var api = Api(out string error);
        if (api is null) { SetError(error); return; }
        bool want = !rec.Proxied;
        int session = _sessionGen;
        rec.IsBusy = true;
        CfResponse r;
        try
        {
            r = await api.PatchAsync(CloudflareApi.RecordPath(zone.Id, rec.Id), new JsonObject { ["proxied"] = want },
                                     CfPermission.DnsEdit, _sessionCts.Token);
        }
        catch (OperationCanceledException) { return; }
        finally { rec.IsBusy = false; }
        if (session != _sessionGen) return;
        if (!r.Success) { SetError($"Couldn't change {rec.Name}: {r.Error}"); return; }
        if (CfRecord.FromApi(r.Result) is { } saved) rec.CopyFrom(saved);
        else rec.Proxied = want;
        SetStatus($"{rec.Name} ({rec.Type}) is {(rec.Proxied ? "proxied through Cloudflare" : "DNS only")} now.");
    }

    // ---------- delete (inline confirm) ----------

    [RelayCommand]
    private void RequestDeleteRecord(CfRecord? rec)
    {
        if (_pendingDelete != null) _pendingDelete.PendingDelete = false;
        _pendingDelete = rec;
        if (rec != null) rec.PendingDelete = true;
    }

    [RelayCommand]
    private void CancelDeleteRecord(CfRecord? rec)
    {
        if (rec != null) rec.PendingDelete = false;
        if (ReferenceEquals(rec, _pendingDelete)) _pendingDelete = null;
    }

    [RelayCommand]
    private Task DeleteRecord(CfRecord? rec) => rec is null ? Task.CompletedTask : DeleteRecordCoreAsync(rec);

    private async Task<bool> DeleteRecordCoreAsync(CfRecord rec)
    {
        if (rec.IsBusy || SelectedZone is not { } zone) return false;
        var api = Api(out string error);
        if (api is null) { SetError(error); return false; }
        int session = _sessionGen;
        rec.IsBusy = true;
        BeginBusy();
        CfResponse r;
        try { r = await api.DeleteAsync(CloudflareApi.RecordPath(zone.Id, rec.Id), CfPermission.DnsEdit, _sessionCts.Token); }
        catch (OperationCanceledException) { return false; }
        finally
        {
            rec.IsBusy = false;
            EndBusy(session);
        }
        if (session != _sessionGen) return false;
        rec.PendingDelete = false;
        if (ReferenceEquals(rec, _pendingDelete)) _pendingDelete = null;
        if (!r.Success)
        {
            SetError($"Couldn't delete {rec.Name}: {r.Error}");
            return false;
        }
        Records.Remove(rec);
        RebuildTypeFilters();
        RefreshVisible();
        SetStatus($"Deleted the {rec.Type} record {rec.Name}.");
        return true;
    }

    // ================================================================ record editor

    /// <summary>Types the editor can create.</summary>
    public string[] RecordTypes { get; } = { "A", "AAAA", "CNAME", "TXT", "MX", "NS", "PTR", "CAA", "SRV" };
    /// <summary>CAA tags offered; a record using another (contactemail, …) adds its own when opened.</summary>
    public ObservableCollection<string> CaaTags { get; } = new() { "issue", "issuewild", "iodef" };

    /// <summary>The type picker of a NEW record. An existing record's type is fixed (shown read-only) and may not be in
    /// <see cref="RecordTypes"/> at all (HTTPS, TLSA…): the picker must never write its "no selection" back into it.</summary>
    public string? NewRecordType
    {
        get => IsNewRecord ? EditType : null;
        set
        {
            if (value != null && IsNewRecord && Array.IndexOf(RecordTypes, value) >= 0) EditType = value;
        }
    }

    private static readonly (int Seconds, string Label)[] TtlChoices =
    {
        (1, "Auto"), (60, "1 min"), (120, "2 min"), (300, "5 min"), (600, "10 min"), (900, "15 min"), (1800, "30 min"),
        (3600, "1 hr"), (7200, "2 hr"), (18000, "5 hr"), (43200, "12 hr"), (86400, "1 day"),
    };
    public ObservableCollection<CfOption> TtlOptions { get; } = new();

    [ObservableProperty] private bool _isEditorOpen;
    private CfRecord? _editing;   // null while adding a record

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsNewRecord), nameof(NewRecordType))]
    private string _editRecordId = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsKnownType), nameof(ShowContentField), nameof(ShowTxtField), nameof(ShowReadOnlyContent),
                              nameof(ShowPriorityField), nameof(ShowCaaFields), nameof(ShowSrvFields), nameof(ShowProxiedField),
                              nameof(ContentLabel), nameof(ContentPlaceholder), nameof(NamePlaceholder), nameof(CanEditTtl),
                              nameof(NewRecordType))]
    private string _editType = "A";

    [ObservableProperty] private string _editName = string.Empty;
    [ObservableProperty] private string _editContent = string.Empty;
    [ObservableProperty] private CfOption? _editTtl;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanEditTtl))]
    private bool _editProxied;

    /// <summary>A proxied record's TTL is always automatic, so the TTL picker is off while Proxied is on.</summary>
    public bool CanEditTtl => !(ShowProxiedField && EditProxied);
    [ObservableProperty] private string _editPriority = "10";
    [ObservableProperty] private string _editComment = string.Empty;
    // CAA (data: flags, tag, value)
    [ObservableProperty] private string _editCaaFlags = "0";
    [ObservableProperty] private string _editCaaTag = "issue";
    [ObservableProperty] private string _editCaaValue = string.Empty;
    // SRV (data: priority, weight, port, target)
    [ObservableProperty] private string _editSrvPriority = "10";
    [ObservableProperty] private string _editSrvWeight = "5";
    [ObservableProperty] private string _editSrvPort = "443";
    [ObservableProperty] private string _editSrvTarget = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasEditorError))]
    private string _editorError = string.Empty;
    [ObservableProperty] private bool _editorDeleteConfirm;
    [ObservableProperty] private bool _isSaving;

    public bool HasEditorError => EditorError.Length > 0;
    public bool IsNewRecord => EditRecordId.Length == 0;
    public bool IsKnownType => Array.IndexOf(RecordTypes, EditType) >= 0;
    public bool ShowContentField => EditType is "A" or "AAAA" or "CNAME" or "MX" or "NS" or "PTR";
    public bool ShowTxtField => EditType == "TXT";
    /// <summary>A type this editor has no fields for (HTTPS, TLSA, …): its content is shown, never sent.</summary>
    public bool ShowReadOnlyContent => !IsKnownType;
    public bool ShowPriorityField => EditType == "MX";
    public bool ShowCaaFields => EditType == "CAA";
    public bool ShowSrvFields => EditType == "SRV";
    public bool ShowProxiedField => CloudflareBackup.Proxiable(EditType);

    public string ContentLabel => EditType switch
    {
        "A" => "IPv4 address",
        "AAAA" => "IPv6 address",
        "CNAME" => "Target",
        "MX" => "Mail server",
        "NS" => "Name server",
        "PTR" => "Domain name",
        _ => "Content",
    };

    public string ContentPlaceholder => EditType switch
    {
        "A" => "192.0.2.1",
        "AAAA" => "2001:db8::1",
        "CNAME" => "target.example.com",
        "MX" => "mail.example.com",
        "NS" => "ns1.example.net",
        "PTR" => "host.example.com",
        "TXT" => "v=spf1 include:_spf.example.com ~all",
        _ => string.Empty,
    };

    public string NamePlaceholder => EditType == "SRV" ? "_service._tcp or _service._tcp.sub" : "www, sub.example.com or @";

    private void InitRecordEditor()
    {
        foreach (var (s, l) in TtlChoices) TtlOptions.Add(new CfOption(s.ToString(CultureInfo.InvariantCulture), l));
        EditTtl = TtlOptions[0];
        InitDdns();   // dynamic DNS (.Ddns)
    }

    private CfOption TtlOption(int ttl)
    {
        if (ttl < 1) ttl = 1;
        string v = ttl.ToString(CultureInfo.InvariantCulture);
        var o = TtlOptions.FirstOrDefault(x => x.Value == v);
        if (o != null) return o;
        o = new CfOption(v, CloudflareBackup.TtlText(ttl));   // a TTL set elsewhere (API, Enterprise 30 s, …)
        int i = 0;
        while (i < TtlOptions.Count && int.Parse(TtlOptions[i].Value, CultureInfo.InvariantCulture) < ttl) i++;
        TtlOptions.Insert(i, o);
        return o;
    }

    [RelayCommand]
    private void NewRecord()
    {
        if (SelectedZone is null) return;
        _editing = null;
        EditRecordId = string.Empty;
        EditType = "A";
        EditName = string.Empty;
        EditContent = string.Empty;
        EditTtl = TtlOption(1);
        EditProxied = false;
        EditPriority = "10";
        EditComment = string.Empty;
        EditCaaFlags = "0";
        EditCaaTag = "issue";
        EditCaaValue = string.Empty;
        EditSrvPriority = "10";
        EditSrvWeight = "5";
        EditSrvPort = "443";
        EditSrvTarget = string.Empty;
        EditorError = string.Empty;
        EditorDeleteConfirm = false;
        EditDdns = false;
        IsEditorOpen = true;
    }

    /// <summary>Open the editor on a record (row edit button, double-click, Enter).</summary>
    [RelayCommand]
    private void EditRecord(CfRecord? rec)
    {
        if (rec is null || SelectedZone is null) return;
        RequestDeleteRecord(null);
        _editing = rec;
        EditRecordId = rec.Id;
        EditType = rec.Type;
        EditName = rec.Name;
        EditContent = rec.Content;
        EditTtl = TtlOption(rec.Ttl);
        EditProxied = rec.Proxied;
        EditPriority = (rec.Priority ?? 10).ToString(CultureInfo.InvariantCulture);
        EditComment = rec.Comment;
        EditorError = string.Empty;
        EditorDeleteConfirm = false;
        EditDdns = rec.DdnsOn;

        if (rec.Type == "CAA")
        {
            var d = rec.Data;
            string[] parts = rec.Content.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
            EditCaaFlags = (CfJson.Int(d?["flags"]) ?? (parts.Length == 3 && int.TryParse(parts[0], out int f) ? f : 0)).ToString(CultureInfo.InvariantCulture);
            string tag = CfJson.StrOrNull(d?["tag"]) ?? (parts.Length == 3 ? parts[1] : "issue");
            if (tag.Length > 0 && !CaaTags.Contains(tag)) CaaTags.Add(tag);   // the picker must be able to show it
            EditCaaTag = tag;
            EditCaaValue = CfJson.StrOrNull(d?["value"]) ?? (parts.Length == 3 ? parts[2].Trim('"') : string.Empty);
        }
        else if (rec.Type == "SRV")
        {
            var d = rec.Data;
            string[] parts = rec.Content.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            string? Part(int fromEnd) => parts.Length >= fromEnd ? parts[^fromEnd] : null;
            EditSrvPriority = (CfJson.Int(d?["priority"]) ?? rec.Priority ?? (parts.Length == 4 && int.TryParse(parts[0], out int p) ? p : 10)).ToString(CultureInfo.InvariantCulture);
            EditSrvWeight = CfJson.Int(d?["weight"])?.ToString(CultureInfo.InvariantCulture) ?? Part(3) ?? "5";
            EditSrvPort = CfJson.Int(d?["port"])?.ToString(CultureInfo.InvariantCulture) ?? Part(2) ?? string.Empty;
            EditSrvTarget = CfJson.StrOrNull(d?["target"]) ?? Part(1) ?? string.Empty;
        }
        IsEditorOpen = true;
    }

    /// <summary>Enter on the list: edit the highlighted record.</summary>
    [RelayCommand]
    private void EditSelected() => EditRecord(SelectedRecord);

    [RelayCommand]
    private void CancelEdit()
    {
        IsEditorOpen = false;
        EditorDeleteConfirm = false;
        _editing = null;
    }

    [RelayCommand]
    private async Task SaveRecord()
    {
        if (IsSaving) return;
        if (SelectedZone is not { } zone) { EditorError = "Select a zone first."; return; }
        var editing = _editing;
        bool wantDdns = EditDdns && ShowDdnsField;   // "Keep updated with my IP" (.Ddns), applied once the record is saved
        string? invalid = BuildRecordBody(editing, zone, out var body);
        if (invalid != null) { EditorError = invalid; return; }
        if (editing != null && body.Count == 0)
        {
            string? ddnsNote = ApplyEditorDdns(editing, zone, wantDdns);
            CancelEdit();
            SetStatus(ddnsNote is null ? "No changes to save." : $"{editing.Name}: {ddnsNote}");
            return;
        }
        var api = Api(out string error);
        if (api is null) { EditorError = error; return; }

        int session = _sessionGen;
        IsSaving = true;
        EditorError = string.Empty;
        BeginBusy();
        CfResponse r;
        try
        {
            r = editing is null
                ? await api.PostAsync(CloudflareApi.ZonePath(zone.Id) + "/dns_records", body, CfPermission.DnsEdit, _sessionCts.Token)
                : await api.PatchAsync(CloudflareApi.RecordPath(zone.Id, editing.Id), body, CfPermission.DnsEdit, _sessionCts.Token);
        }
        catch (OperationCanceledException) { return; }
        finally
        {
            IsSaving = false;
            EndBusy(session);
        }
        if (session != _sessionGen || !ReferenceEquals(zone, SelectedZone)) return;
        if (!r.Success) { EditorError = r.Error; return; }   // the editor stays open with what was typed

        var saved = CfRecord.FromApi(r.Result);
        string label = saved?.Name ?? EditName.Trim();
        if (editing is null)
        {
            if (saved != null && _recordsZoneId == zone.Id) InsertSorted(saved);
            else _ = LoadRecordsAsync(zone);
        }
        else if (saved != null)
        {
            editing.CopyFrom(saved);
        }
        RebuildTypeFilters();
        RefreshVisible();
        string? ddns = (editing ?? saved) is { } target ? ApplyEditorDdns(target, zone, wantDdns) : null;
        CancelEdit();
        SetStatus((editing is null ? $"Created the {saved?.Type ?? EditType} record {label}." : $"Saved {label}.")
                  + (ddns is null ? string.Empty : " " + ddns));
    }

    // Validate the form and build the request body. New record: every field the form has. Existing record: ONLY the
    // fields this editor owns AND that changed (PATCH), so fields it doesn't show (tags, settings, data keys it doesn't
    // know, the content of types it can't edit) are never sent and never clobbered.
    private string? BuildRecordBody(CfRecord? orig, CfZone zone, out JsonObject body)
    {
        body = new JsonObject();
        string type = orig?.Type ?? EditType;
        string name = EditName.Trim();
        if (name.Length == 0) return "Enter a name: www, sub.example.com, or @ for the zone itself.";
        if (name.Length > 253 || name.Any(c => char.IsWhiteSpace(c) || char.IsControl(c))) return "The name can't contain spaces.";

        bool proxiable = CloudflareBackup.Proxiable(type);
        bool proxied = proxiable && EditProxied;
        int ttl = int.TryParse(EditTtl?.Value, NumberStyles.None, CultureInfo.InvariantCulture, out int t) ? t : 1;
        if (proxied) ttl = 1;   // a proxied record's TTL is always automatic
        string comment = EditComment.Trim();
        if (comment.Length > 500) return "A comment can be at most 500 characters (100 on the Free plan).";
        if (comment.Any(char.IsControl)) return "The comment can't contain line breaks.";

        string? content = null;
        JsonObject? data = null;
        int? priority = null;
        switch (type)
        {
            case "A":
                content = EditContent.Trim();
                if (!CloudflareBackup.IsIPv4(content)) return "Enter an IPv4 address, like 192.0.2.1.";
                break;
            case "AAAA":
                content = EditContent.Trim();
                if (!CloudflareBackup.IsIPv6(content)) return "Enter an IPv6 address, like 2001:db8::1.";
                break;
            case "CNAME":
            case "NS":
            case "PTR":
                content = EditContent.Trim();
                if (!IsHostName(content)) return "Enter a host name, like target.example.com.";
                break;
            case "MX":
                content = EditContent.Trim();
                if (!IsHostName(content)) return "Enter the mail server's host name, like mail.example.com.";
                if (!TryRange(EditPriority, 0, 65535, out int mxp)) return "The priority must be a number from 0 to 65535.";
                priority = mxp;
                break;
            case "TXT":
                content = EditContent.Trim();
                if (content.Length == 0) return "Enter the text.";
                if (content.Length > 4096) return "The text can be at most 4096 characters.";
                if (content.Any(char.IsControl)) return "The text can't contain line breaks.";
                break;
            case "CAA":
            {
                if (!TryRange(EditCaaFlags, 0, 255, out int flags)) return "Flags must be a number from 0 to 255 (usually 0).";
                string tag = (EditCaaTag ?? string.Empty).Trim();
                if (tag.Length is 0 or > 15 || !tag.All(char.IsAsciiLetterOrDigit)) return "Pick a tag: issue, issuewild or iodef.";
                string value = EditCaaValue.Trim();
                if (value.Length == 0) return tag == "iodef" ? "Enter where to report (mailto: or https: URL)." : "Enter the certificate authority's domain, like letsencrypt.org.";
                if (value.Length > 1024 || value.Any(char.IsControl)) return "The value is too long or contains line breaks.";
                data = (orig?.Data?.DeepClone() as JsonObject) ?? new JsonObject();
                data["flags"] = flags;
                data["tag"] = tag;
                data["value"] = value;
                break;
            }
            case "SRV":
            {
                if (!TryRange(EditSrvPriority, 0, 65535, out int sp)) return "The priority must be a number from 0 to 65535.";
                if (!TryRange(EditSrvWeight, 0, 65535, out int sw)) return "The weight must be a number from 0 to 65535.";
                if (!TryRange(EditSrvPort, 0, 65535, out int port)) return "The port must be a number from 0 to 65535.";
                string target = EditSrvTarget.Trim();
                if (target != "." && !IsHostName(target)) return "Enter the target host name, like sip.example.com.";
                data = (orig?.Data?.DeepClone() as JsonObject) ?? new JsonObject();
                data["priority"] = sp;
                data["weight"] = sw;
                data["port"] = port;
                data["target"] = target;
                break;
            }
            default:
                if (orig is null) return "Pick a record type.";
                break;   // a type without fields here: its content / data are left exactly as they are
        }

        if (orig is null)
        {
            body["type"] = type;
            body["name"] = name;
            if (data != null) body["data"] = data;
            else body["content"] = content;
            body["ttl"] = ttl;
            if (proxiable) body["proxied"] = proxied;
            if (priority is int p) body["priority"] = p;
            if (comment.Length > 0) body["comment"] = comment;
            return null;
        }

        if (!SameName(name, orig.Name, zone.Name)) body["name"] = name;
        if (content != null && !string.Equals(content, orig.Content, StringComparison.Ordinal)) body["content"] = content;
        if (data != null && !JsonNode.DeepEquals(data, orig.Data)) body["data"] = data;
        if (proxiable && proxied != orig.Proxied) body["proxied"] = proxied;
        if (!proxied && ttl != orig.Ttl) body["ttl"] = ttl;
        if (priority is int pr && pr != orig.Priority) body["priority"] = pr;
        if (!string.Equals(comment, orig.Comment, StringComparison.Ordinal)) body["comment"] = comment;
        return null;
    }

    private static bool SameName(string typed, string current, string zone)
    {
        string a = typed.Trim().TrimEnd('.'), b = current.Trim().TrimEnd('.');
        if (a == "@") a = zone;
        return string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryRange(string? text, int min, int max, out int value)
        => int.TryParse(LocalDigits.Fold((text ?? string.Empty).Trim()), NumberStyles.None, CultureInfo.InvariantCulture, out value)
           && value >= min && value <= max;

    private static bool IsHostName(string s)
    {
        string h = s.TrimEnd('.');
        if (h.Length is 0 or > 253) return false;
        foreach (string label in h.Split('.'))
        {
            if (label.Length is 0 or > 63) return false;
            foreach (char c in label)
                if (char.IsWhiteSpace(c) || char.IsControl(c) || c is '/' or '\\' or '@' or ':' or '"' or '\'' or ',' or ';' or '<' or '>') return false;
        }
        return true;
    }

    // Delete from inside the editor: same inline confirmation as the rows.
    [RelayCommand]
    private void RequestEditorDelete() => EditorDeleteConfirm = true;

    [RelayCommand]
    private void CancelEditorDelete() => EditorDeleteConfirm = false;

    [RelayCommand]
    private async Task DeleteEditedRecord()
    {
        if (_editing is not { } rec) return;
        if (await DeleteRecordCoreAsync(rec)) CancelEdit();
        else
        {
            EditorDeleteConfirm = false;
            EditorError = StatusIsError ? StatusMessage : string.Empty;
        }
    }
}
