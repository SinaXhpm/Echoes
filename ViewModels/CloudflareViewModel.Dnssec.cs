using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

// DNSSEC (Zone → DNS : Edit):   GET /zones/{id}/dnssec · PATCH {"status": "active" | "disabled"}
// BIND import (Zone → DNS : Edit): POST /zones/{id}/dns_records/import, multipart "file" + "proxied"; the preview is
// built here (Helpers/CloudflareZoneFile) and only the records it lists as new are sent.
public partial class CloudflareViewModel
{
    // ================================================================ DNSSEC

    [ObservableProperty] private bool _isDnssecOpen;

    public CfDnssec? CurrentDnssec => CurrentExtras?.Dnssec;

    partial void OnCurrentExtrasChanged(CfZoneExtras? value) => OnPropertyChanged(nameof(CurrentDnssec));

    [RelayCommand]
    private void OpenDnssec()
    {
        if (SelectedZone is not { } zone) return;
        var d = ExtrasFor(zone).Dnssec;
        d.ConfirmDisable = false;
        IsDnssecOpen = true;
        _ = EnsureDnssecAsync(zone, force: d.HasError);
    }

    [RelayCommand]
    private void CloseDnssec() => IsDnssecOpen = false;

    private async Task EnsureDnssecAsync(CfZone zone, bool force)
    {
        var d = ExtrasFor(zone).Dnssec;
        if (d.IsLoading || d.IsBusy || (d.IsLoaded && !force)) { zone.DnssecStatus = d.IsLoaded ? d.Status : zone.DnssecStatus; return; }
        var api = Api(out string error);
        if (api is null) { d.Error = error; return; }
        int session = _sessionGen;
        d.IsLoading = true;
        CfResponse r;
        try { r = await api.GetAsync(CloudflareApi.ZonePath(zone.Id) + "/dnssec", CfPermission.DnsEdit, _sessionCts.Token); }
        catch (OperationCanceledException) { return; }
        finally
        {
            if (session == _sessionGen) d.IsLoading = false;
        }
        if (session != _sessionGen) return;
        if (!r.Success)
        {
            d.Error = LoadProblem("DNSSEC needs", "Couldn't read the DNSSEC status: ", r.Denied, r.Error, CfPermission.DnsEdit);
            d.IsLoaded = true;
            return;
        }
        d.Load(r.Result);
        zone.DnssecStatus = d.Status;
        if (SelectedZone is { } z && z.Id == zone.Id) z.DnssecStatus = d.Status;
    }

    [RelayCommand]
    private Task EnableDnssec() => SelectedZone is { } zone ? SetDnssecAsync(zone, enable: true) : Task.CompletedTask;

    [RelayCommand]
    private void RequestDisableDnssec()
    {
        if (CurrentDnssec is { } d) d.ConfirmDisable = true;
    }

    [RelayCommand]
    private void CancelDisableDnssec()
    {
        if (CurrentDnssec is { } d) d.ConfirmDisable = false;
    }

    [RelayCommand]
    private Task DisableDnssec() => SelectedZone is { } zone ? SetDnssecAsync(zone, enable: false) : Task.CompletedTask;

    private async Task SetDnssecAsync(CfZone zone, bool enable)
    {
        var d = ExtrasFor(zone).Dnssec;
        d.ConfirmDisable = false;
        if (d.IsBusy) return;
        var api = Api(out string error);
        if (api is null) { d.Error = error; return; }
        int session = _sessionGen;
        d.IsBusy = true;
        d.Error = string.Empty;
        CfResponse r;
        try
        {
            r = await api.PatchAsync(CloudflareApi.ZonePath(zone.Id) + "/dnssec", new JsonObject { ["status"] = enable ? "active" : "disabled" },
                                     CfPermission.DnsEdit, _sessionCts.Token);
        }
        catch (OperationCanceledException) { return; }
        finally
        {
            if (session == _sessionGen) d.IsBusy = false;
        }
        if (session != _sessionGen) return;
        bool current = SelectedZone?.Id == zone.Id;
        if (!r.Success)
        {
            d.Error = (enable ? "DNSSEC wasn't turned on: " : "DNSSEC wasn't turned off: ") + r.Error;
            if (current) SetError(d.Error);
            return;
        }
        d.Load(r.Result);
        zone.DnssecStatus = d.Status;
        if (SelectedZone is { } z && z.Id == zone.Id) z.DnssecStatus = d.Status;
        if (current)
            SetStatus(enable
                ? $"DNSSEC is signing {zone.Name}. Add the DS record at your registrar to finish."
                : $"DNSSEC is turning off for {zone.Name}. Remove the DS record at your registrar too.");
    }

    /// <summary>Copy one value (a DS field, a name server) to the clipboard.</summary>
    [RelayCommand]
    private async Task CopyField(CfField? field)
    {
        if (field is null) return;
        try
        {
            await ClipboardHelper.SetTextAsync(field.Value);
            SetStatus($"{field.Label} copied.");
        }
        catch (Exception ex) { SetError("Couldn't copy: " + ex.Message); }
    }

    // ================================================================ BIND import

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsImportPreview))]
    private bool _isImportOpen;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsImportPreview))]
    private bool _isImporting;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsImportPreview))]
    private bool _isImportDone;

    public bool IsImportPreview => IsImportOpen && !IsImporting && !IsImportDone;

    [ObservableProperty] private string _importSource = string.Empty;
    [ObservableProperty] private int _importNew;
    [ObservableProperty] private int _importExisting;
    [ObservableProperty] private int _importSkipped;
    [ObservableProperty] private string _importNotes = string.Empty;
    [ObservableProperty] private bool _importProxied;
    [ObservableProperty] private string _importSummary = string.Empty;
    [ObservableProperty] private bool _importFailed;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanApplyImport), nameof(ApplyImportLabel))]
    private int _importChanges;

    public ObservableCollection<CfRestoreRow> ImportRows { get; } = new();
    [ObservableProperty] private string _importRowsMore = string.Empty;

    public bool CanApplyImport => ImportChanges > 0;
    public string ApplyImportLabel => ImportChanges == 1 ? "Import 1 record" : $"Import {ImportChanges} records";

    private List<CloudflareZoneFile.Entry> _importKeep = new();
    private List<(string Origin, string Text)> _importGenerates = new();
    private CfZone? _importZone;

    /// <summary>
    /// A zone file was picked: parse it (untrusted text, size-capped), compare it with the zone's records and show what
    /// would be added. Nothing is sent until the user confirms.
    /// </summary>
    public async Task OpenImportAsync(byte[] bytes, string fileName)
    {
        if (IsLocked || SelectedZone is not { } zone) return;
        if (bytes.Length > CloudflareZoneFile.MaxBytes)
        {
            SetError($"Import: the file is larger than {CloudflareZoneFile.MaxBytes / 1024} KB, Cloudflare's limit for a zone file.");
            return;
        }
        string text;
        try { text = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(bytes); }
        catch (DecoderFallbackException) { SetError("Import: the file isn't UTF-8 text, so it isn't a BIND zone file."); return; }

        CloudflareZoneFile.Parsed parsed;
        try { parsed = CloudflareZoneFile.Parse(text, zone.Name); }
        catch (FormatException ex) { SetError("Import: " + ex.Message); return; }
        if (parsed.Entries.Count == 0 && parsed.Generates.Count == 0)
        {
            SetError(parsed.Unreadable.Count > 0
                ? $"Import: no record could be read from the file (line {parsed.Unreadable[0].Line}: {parsed.Unreadable[0].Reason})."
                : "Import: the file has no DNS records.");
            return;
        }

        // The comparison needs the zone's current records.
        if (_recordsZoneId != zone.Id)
        {
            var pending = _recordsTask;
            if (pending is null || pending.IsCompleted) pending = LoadRecordsAsync(zone);
            try { await pending; } catch { /* reported by the load itself */ }
            if (!ReferenceEquals(zone, SelectedZone)) return;
            if (_recordsZoneId != zone.Id)
            {
                SetError("Import: the zone's current records couldn't be loaded, so nothing can be compared.");
                return;
            }
        }

        _importZone = zone;
        BuildImportPlan(zone, parsed);
        ImportSource = $"{SafeFileName(fileName)} · {parsed.Entries.Count} record{(parsed.Entries.Count == 1 ? "" : "s")}";
        ImportProxied = false;
        ImportSummary = string.Empty;
        ImportFailed = false;
        IsImportDone = false;
        IsImporting = false;
        IsImportOpen = true;
        SetStatus($"Review the import of {SafeFileName(fileName)}: nothing has changed yet.");
    }

    private void BuildImportPlan(CfZone zone, CloudflareZoneFile.Parsed parsed)
    {
        var existing = new HashSet<string>(Records.Select(r => CloudflareBackup.Key(r.Type, r.Name, r.Content)), StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var keep = new List<CloudflareZoneFile.Entry>();
        var rows = new List<CfRestoreRow>();
        int present = 0, skipped = 0;
        string apex = CloudflareBackup.NormName(zone.Name);
        foreach (var e in parsed.Entries)
        {
            string? skip = null;
            if (e.Type == "SOA") skip = "Cloudflare manages the SOA record";
            else if (e.Type == "NS" && e.Name == apex) skip = "Cloudflare's own name servers answer for the zone";
            else if (!CloudflareBackup.InZone(e.Name, apex)) skip = $"not part of {apex}";
            else if (!CloudflareBackup.AllowedTypes.Contains(e.Type)) skip = $"Cloudflare doesn't serve {e.Type} records";
            string key = CloudflareBackup.Key(e.Type, e.Name, e.Content);
            if (skip is null && !seen.Add(key)) skip = "listed twice in the file";
            if (skip is null && existing.Contains(key))
            {
                present++;
                rows.Add(new CfRestoreRow { Action = "Exists", IsSkip = true, Type = e.Type, Name = e.Name, Content = e.Display, Detail = "already in the zone" });
                continue;
            }
            if (skip != null)
            {
                skipped++;
                rows.Add(new CfRestoreRow { Action = "Skip", IsSkip = true, Type = e.Type, Name = e.Name, Content = e.Display, Detail = skip });
                continue;
            }
            keep.Add(e);
            bool? tag = CloudflareZoneFile.ProxiedTag(e.Tags);
            rows.Add(new CfRestoreRow
            {
                Action = "Add", IsAdd = true, Type = e.Type, Name = e.Name, Content = e.Display,
                Detail = tag is bool p ? (p ? "proxied (cf_tags in the file)" : "DNS only (cf_tags in the file)") : string.Empty,
            });
        }
        // $GENERATE lines go up as written and Cloudflare expands each into many records: list them with the adds, so the
        // preview shows everything the import sends (a hostile file's $GENERATE used to be just a count in the notes).
        foreach (var (origin, text) in parsed.Generates)
            rows.Add(new CfRestoreRow
            {
                Action = "Add", IsAdd = true, Type = "GEN", Name = "$GENERATE under " + origin, Content = text,
                Detail = "Cloudflare creates one record per number in its range.",
            });
        foreach (var bad in parsed.Unreadable)
        {
            skipped++;
            rows.Add(new CfRestoreRow { Action = "Unread", IsFailed = true, Name = $"Line {bad.Line}", Content = bad.Text, Detail = bad.Reason });
        }

        _importKeep = keep;
        _importGenerates = parsed.Generates.ToList();
        ImportNew = keep.Count;
        ImportExisting = present;
        ImportSkipped = skipped;
        ImportChanges = keep.Count + parsed.Generates.Count;

        var notes = new List<string>();
        if (parsed.Generates.Count > 0)
            notes.Add($"{parsed.Generates.Count} $GENERATE line{(parsed.Generates.Count == 1 ? "" : "s")} (GEN below): Cloudflare expands {(parsed.Generates.Count == 1 ? "it" : "each")} into one record per number of the range.");
        if (keep.Any(e => e.Type is "CNAME" or "MX" or "NS" or "PTR" or "SRV"))
            notes.Add("Host names in CNAME, MX, NS, PTR and SRV records are sent fully qualified, as Cloudflare requires.");
        ImportNotes = string.Join("\n", notes);

        ImportRows.Clear();
        // what will happen first: additions, then skips, then unreadable lines
        foreach (var row in rows.OrderBy(r => r.IsAdd ? 0 : r.IsFailed ? 2 : 1).Take(MaxPreviewRows)) ImportRows.Add(row);
        ImportRowsMore = rows.Count > MaxPreviewRows ? $"+ {rows.Count - MaxPreviewRows} more" : string.Empty;
    }

    [RelayCommand]
    private void CancelImport() => CloseImport();

    [RelayCommand]
    private void FinishImport()
    {
        bool reload = IsImportDone && !ImportFailed && SelectedZone is { } z && ReferenceEquals(z, _importZone);
        CloseImport();
        if (reload && SelectedZone is { } zone) _ = LoadRecordsAsync(zone);
    }

    private void CloseImport()
    {
        IsImportOpen = false;
        IsImporting = false;
        IsImportDone = false;
        _importKeep = new();
        _importGenerates = new();
        _importZone = null;
        ImportRows.Clear();
        ImportRowsMore = string.Empty;
    }

    [RelayCommand]
    private async Task ApplyImport()
    {
        if (IsImporting || !IsImportPreview || _importZone is not { } zone || !ReferenceEquals(zone, SelectedZone) || ImportChanges == 0) return;
        var api = Api(out string error);
        if (api is null) { SetError(error); return; }
        string upload = CloudflareZoneFile.BuildUpload(_importKeep, _importGenerates);
        byte[] file = Encoding.UTF8.GetBytes(upload);
        if (file.Length > CloudflareZoneFile.MaxBytes)
        {
            SetError("Import: the records to add are more than Cloudflare's 256 KB per file. Split the zone file and import it in parts.");
            return;
        }
        int session = _sessionGen;
        IsImporting = true;
        BeginBusy();
        CfResponse r;
        try
        {
            r = await api.PostFileAsync(CloudflareApi.ZonePath(zone.Id) + "/dns_records/import", "file", SafeFileName(zone.Name + ".txt"), file,
                                        new[] { ("proxied", ImportProxied ? "true" : "false") }, CfPermission.DnsEdit, _sessionCts.Token);
        }
        catch (OperationCanceledException) { return; }
        finally { EndBusy(session); }
        if (session != _sessionGen || !IsImportOpen) return;
        IsImporting = false;
        IsImportDone = true;
        if (!r.Success)
        {
            ImportFailed = true;
            ImportSummary = "Nothing was imported: " + r.Error;
            SetError("Import into " + zone.Name + " failed: " + r.Error);
            return;
        }
        int added = CfJson.Int(r.Result?["recs_added"]) ?? 0;
        int parsedCount = CfJson.Int(r.Result?["total_records_parsed"]) ?? _importKeep.Count;
        ImportFailed = false;
        ImportSummary = added == parsedCount
            ? $"Cloudflare added {added} record{(added == 1 ? "" : "s")} to {zone.Name}."
            : $"Cloudflare added {added} of {parsedCount} records to {zone.Name}; it refused the others (already there, or invalid for Cloudflare).";
        ImportRows.Clear();
        ImportRowsMore = string.Empty;
        SetStatus("Import: " + ImportSummary);
    }
}
