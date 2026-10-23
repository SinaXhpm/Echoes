using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

// DNS backup (JSON), BIND zone export, and restore with a preview. The file pickers live in the view's code-behind;
// everything else (format, validation, matching, applying) is here and in Helpers/CloudflareBackup.
public partial class CloudflareViewModel
{
    /// <summary>The selected zone's records are fully loaded, so a backup would be complete.</summary>
    public bool CanBackup => SelectedZone is { } z && _recordsZoneId == z.Id && !IsLoadingRecords;

    /// <summary>The backup file of the selected zone: whitelisted record fields only (never ids, timestamps or
    /// credentials). Null (with the reason in the status line) when the records aren't loaded.</summary>
    public async Task<(byte[] Data, string FileName, int Count)?> BuildBackupAsync()
    {
        if (SelectedZone is not { } zone || !CanBackup)
        {
            SetError("Wait until the zone's records have loaded, then back them up.");
            return null;
        }
        var entries = Records.Select(r => r.ToEntry()).ToList();
        // writing (and validating) every record of a big zone off the UI thread
        byte[] data = await Task.Run(() => CloudflareBackup.Write(zone.Name, entries, DateTimeOffset.UtcNow));
        return (data, CloudflareBackup.SuggestedFileName(zone.Name, DateTime.Now, "dns") + ".json", entries.Count);
    }

    /// <summary>The view saved a backup / export file.</summary>
    public void ReportSaved(string what, string fileName) => SetStatus($"{what} saved to {fileName}.");

    public void ReportFileError(string message) => SetError(message);

    /// <summary>The zone as a BIND file (GET …/dns_records/export). Null with the reason in the status line on failure.</summary>
    public async Task<(string Text, string FileName)?> ExportZoneFileAsync()
    {
        if (SelectedZone is not { } zone) return null;
        var api = Api(out string error);
        if (api is null) { SetError(error); return null; }
        int session = _sessionGen;
        BeginBusy();
        SetStatus($"Exporting {zone.Name} as a BIND zone file…");
        CfResponse r;
        try { r = await api.GetTextAsync(CloudflareApi.ZonePath(zone.Id) + "/dns_records/export", CfPermission.DnsEdit, _sessionCts.Token); }
        catch (OperationCanceledException) { return null; }
        finally { EndBusy(session); }
        if (session != _sessionGen) return null;
        if (!r.Success) { SetError("Couldn't export the zone file: " + r.Error); return null; }
        SetStatus($"Zone file of {zone.Name} is ready to save.");
        return (r.Text, CloudflareBackup.SuggestedFileName(zone.Name, DateTime.Now, "zone") + ".txt");
    }

    // ================================================================ restore

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsRestorePreview))]
    private bool _isRestoreOpen;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsRestorePreview))]
    private bool _isRestoring;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsRestorePreview))]
    private bool _isRestoreDone;

    public bool IsRestorePreview => IsRestoreOpen && !IsRestoring && !IsRestoreDone;

    [ObservableProperty] private string _restoreSource = string.Empty;     // "file.json · example.com · exported … · 42 records"
    [ObservableProperty] private string _restoreTarget = string.Empty;     // the zone it goes into

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(RestoreRenameText))]
    private bool _restoreZoneDiffers;

    /// <summary>Move the backup's names to the selected zone (old.com → new.com). On by default when the zones differ.</summary>
    [ObservableProperty] private bool _restoreRename = true;

    public string RestoreRenameText => _restoreBackup is null || SelectedZone is null ? string.Empty
        : $"Rename {_restoreBackup.Zone} → {SelectedZone.Name} in record names";

    [ObservableProperty] private int _restoreAdds;
    [ObservableProperty] private int _restoreUpdates;
    [ObservableProperty] private int _restorePresent;
    [ObservableProperty] private int _restoreSkipped;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanApplyRestore), nameof(ApplyRestoreLabel))]
    private int _restoreChanges;

    /// <summary>Notes under the counts: invalid entries, tags left out, the zone rename.</summary>
    [ObservableProperty] private string _restoreNotes = string.Empty;

    /// <summary>Preview: the adds / updates / skips. Summary: the failures.</summary>
    public ObservableCollection<CfRestoreRow> RestoreRows { get; } = new();
    [ObservableProperty] private string _restoreRowsMore = string.Empty;   // "+ 120 more"

    [ObservableProperty] private double _restoreProgress;
    [ObservableProperty] private string _restoreProgressText = string.Empty;
    [ObservableProperty] private string _restoreSummary = string.Empty;
    [ObservableProperty] private int _restoreFailed;

    public bool CanApplyRestore => RestoreChanges > 0;
    public string ApplyRestoreLabel => RestoreChanges == 1 ? "Apply 1 change" : $"Apply {RestoreChanges} changes";

    private CloudflareBackup.Parsed? _restoreBackup;
    private CloudflareBackup.Plan? _restorePlan;
    private CfZone? _restoreZone;
    private CancellationTokenSource? _restoreCts;
    private const int MaxPreviewRows = 300;

    /// <summary>
    /// A backup file was picked: validate it (it's untrusted), compare it with the selected zone and show the preview.
    /// Nothing changes until the user applies it.
    /// </summary>
    public async Task OpenRestoreAsync(byte[] bytes, string fileName)
    {
        if (IsLocked || SelectedZone is not { } zone) return;
        CloudflareBackup.Parsed parsed;
        // up to 5 MB and 20,000 entries, each validated: off the UI thread
        try { parsed = await Task.Run(() => CloudflareBackup.Parse(bytes)); }
        catch (FormatException ex)
        {
            SetError("Restore: " + ex.Message);
            return;
        }
        if (IsLocked || !ReferenceEquals(zone, SelectedZone)) return;

        // The comparison needs the zone's current records.
        if (_recordsZoneId != zone.Id)
        {
            var pending = _recordsTask;
            if (pending is null || pending.IsCompleted) pending = LoadRecordsAsync(zone);
            try { await pending; } catch { /* reported by the load itself */ }
            if (!ReferenceEquals(zone, SelectedZone)) return;
            if (_recordsZoneId != zone.Id)
            {
                SetError("Restore: the zone's current records couldn't be loaded, so nothing can be compared.");
                return;
            }
        }

        _restoreBackup = parsed;
        _restoreZone = zone;
        string exported = parsed.ExportedAt is { } at ? " · exported " + at.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) : string.Empty;
        RestoreSource = $"{SafeFileName(fileName)} · {parsed.Zone}{exported} · {parsed.Total} record{(parsed.Total == 1 ? "" : "s")}";
        RestoreTarget = zone.Name;
        RestoreZoneDiffers = !string.Equals(CloudflareBackup.NormName(parsed.Zone), CloudflareBackup.NormName(zone.Name), StringComparison.Ordinal);
        _restoreRenameSync = true;
        RestoreRename = RestoreZoneDiffers;
        _restoreRenameSync = false;
        OnPropertyChanged(nameof(RestoreRenameText));
        RestoreSummary = string.Empty;
        RestoreFailed = 0;
        RestoreProgress = 0;
        RestoreProgressText = string.Empty;
        IsRestoreDone = false;
        IsRestoring = false;
        BuildRestorePlan();
        IsRestoreOpen = true;
        SetStatus($"Review the restore of {SafeFileName(fileName)}: nothing has changed yet.");
    }

    private bool _restoreRenameSync;

    partial void OnRestoreRenameChanged(bool value)
    {
        if (!_restoreRenameSync && IsRestorePreview) BuildRestorePlan();
    }

    private void BuildRestorePlan()
    {
        if (_restoreBackup is not { } backup || _restoreZone is not { } zone) return;
        var existing = Records.Select(r => r.ToExisting()).ToList();
        var plan = CloudflareBackup.BuildPlan(backup.Entries, backup.Zone, zone.Name, RestoreZoneDiffers && RestoreRename,
                                              existing, leaveOutTags: zone.IsFreePlan);
        _restorePlan = plan;
        RestoreAdds = plan.Adds;
        RestoreUpdates = plan.Updates;
        RestorePresent = plan.Present;
        RestoreSkipped = plan.Skipped + backup.InvalidCount;
        RestoreChanges = plan.Adds + plan.Updates;

        var notes = new List<string>();
        if (backup.InvalidCount > 0)
            notes.Add($"{backup.InvalidCount} entr{(backup.InvalidCount == 1 ? "y" : "ies")} in the file failed validation and will be ignored.");
        if (RestoreZoneDiffers)
            notes.Add(RestoreRename
                ? $"Names move from {backup.Zone} to {zone.Name}; record contents are kept as they are."
                : $"The backup is from {backup.Zone}: its names outside {zone.Name} are skipped.");
        if (plan.TagsLeftOut) notes.Add("Tags are left out: the Free plan doesn't support record tags.");
        RestoreNotes = string.Join("\n", notes);

        RestoreRows.Clear();
        int shown = 0, total = 0;
        foreach (var item in plan.Items)
        {
            if (item.Action == CloudflareBackup.Action.Present) continue;
            total++;
            if (shown >= MaxPreviewRows) continue;
            shown++;
            RestoreRows.Add(new CfRestoreRow
            {
                Action = item.Action switch { CloudflareBackup.Action.Add => "Add", CloudflareBackup.Action.Update => "Update", _ => "Skip" },
                IsAdd = item.Action == CloudflareBackup.Action.Add,
                IsUpdate = item.Action == CloudflareBackup.Action.Update,
                IsSkip = item.Action == CloudflareBackup.Action.Skip,
                Type = item.Entry.Type,
                Name = item.Name,
                Content = item.Entry.Content,
                Detail = item.Detail,
            });
        }
        foreach (var bad in backup.Invalid)
        {
            total++;
            if (shown >= MaxPreviewRows) continue;
            shown++;
            RestoreRows.Add(new CfRestoreRow { Action = "Invalid", IsSkip = true, Name = bad });
        }
        RestoreRowsMore = total > shown ? $"+ {total - shown} more" : string.Empty;
    }

    [RelayCommand]
    private void CancelRestore() => CloseRestore();

    /// <summary>Closes the restore page (after a restore: reloads the zone so the list shows the result).</summary>
    [RelayCommand]
    private void FinishRestore()
    {
        bool reload = IsRestoreDone && SelectedZone is { } z && ReferenceEquals(z, _restoreZone);
        CloseRestore();
        if (reload && SelectedZone is { } zone) _ = LoadRecordsAsync(zone);
    }

    private void CloseRestore()
    {
        _restoreCts?.Cancel();
        IsRestoreOpen = false;
        IsRestoring = false;
        IsRestoreDone = false;
        _restoreBackup = null;
        _restorePlan = null;
        _restoreZone = null;
        RestoreRows.Clear();
        RestoreRowsMore = string.Empty;
    }

    [RelayCommand]
    private void StopRestore() => _restoreCts?.Cancel();

    /// <summary>
    /// Apply the plan: POST each add, PATCH each update (only the differing fields), one at a time; an error on one
    /// record is recorded and the rest continue. Never deletes anything.
    /// </summary>
    [RelayCommand]
    private async Task ApplyRestore()
    {
        if (IsRestoring || _restorePlan is not { } plan || _restoreZone is not { } zone || !ReferenceEquals(zone, SelectedZone)) return;
        var api = Api(out string error);
        if (api is null) { SetError(error); return; }

        var work = plan.Items.Where(i => i.Action is CloudflareBackup.Action.Add or CloudflareBackup.Action.Update && i.Body != null).ToList();
        if (work.Count == 0) return;
        int session = _sessionGen;
        _restoreCts?.Dispose();
        _restoreCts = CancellationTokenSource.CreateLinkedTokenSource(_sessionCts.Token);
        var ct = _restoreCts.Token;

        IsRestoring = true;
        BeginBusy();
        int added = 0, updated = 0, done = 0, tagsDropped = 0;
        var failures = new List<CfRestoreRow>();
        bool stopped = false;
        string zonePath = CloudflareApi.ZonePath(zone.Id);
        try
        {
            foreach (var item in work)
            {
                if (ct.IsCancellationRequested) { stopped = true; break; }
                RestoreProgressText = $"Applying {done + 1} of {work.Count}…";
                CfResponse r;
                if (item.Action == CloudflareBackup.Action.Add)
                {
                    r = await api.PostAsync(zonePath + "/dns_records", item.Body!, CfPermission.DnsEdit, ct);
                    // A plan without record tags (Free) refuses them: try once more without, rather than lose the record.
                    if (!r.Success && item.Body!.ContainsKey("tags") && r.Error.Contains("tag", StringComparison.OrdinalIgnoreCase))
                    {
                        var retry = item.Body.DeepClone().AsObject();
                        retry.Remove("tags");
                        r = await api.PostAsync(zonePath + "/dns_records", retry, CfPermission.DnsEdit, ct);
                        if (r.Success) tagsDropped++;
                    }
                    if (r.Success) added++;
                }
                else
                {
                    r = await api.PatchAsync(CloudflareApi.RecordPath(zone.Id, item.ExistingId!), item.Body!, CfPermission.DnsEdit, ct);
                    if (r.Success) updated++;
                }
                if (!r.Success)
                    failures.Add(new CfRestoreRow
                    {
                        Action = "Failed", IsFailed = true, Type = item.Entry.Type, Name = item.Name,
                        Content = item.Entry.Content, Detail = r.Error,
                    });
                done++;
                RestoreProgress = (double)done / work.Count;
                if (session != _sessionGen) return;
            }
        }
        catch (OperationCanceledException) { stopped = true; }
        finally { EndBusy(session); }
        if (session != _sessionGen || !IsRestoreOpen) return;

        int skipped = plan.Skipped + (_restoreBackup?.InvalidCount ?? 0);
        int notDone = work.Count - done;
        var sb = new StringBuilder();
        sb.Append($"Added {added} · updated {updated} · {plan.Present} already there");
        if (skipped > 0) sb.Append($" · {skipped} skipped");
        sb.Append($" · {failures.Count} failed");
        if (stopped && notDone > 0) sb.Append($" · stopped with {notDone} not applied");
        sb.Append('.');
        if (tagsDropped > 0) sb.Append($" {tagsDropped} record{(tagsDropped == 1 ? " was" : "s were")} added without tags (not available on this plan).");
        RestoreSummary = sb.ToString();
        RestoreFailed = failures.Count;
        RestoreRows.Clear();
        foreach (var f in failures.Take(MaxPreviewRows)) RestoreRows.Add(f);
        RestoreRowsMore = failures.Count > MaxPreviewRows ? $"+ {failures.Count - MaxPreviewRows} more" : string.Empty;
        RestoreProgressText = string.Empty;
        IsRestoring = false;
        IsRestoreDone = true;
        if (failures.Count > 0) SetError($"Restore into {zone.Name}: {RestoreSummary}");
        else SetStatus($"Restore into {zone.Name}: {RestoreSummary}");
    }

    // A picked file's display name, without anything that could pass for a path or a control sequence.
    private static string SafeFileName(string name)
    {
        var sb = new StringBuilder();
        foreach (char c in System.IO.Path.GetFileName(name ?? string.Empty))
            sb.Append(char.IsControl(c) ? '?' : c);
        string s = sb.ToString();
        return s.Length == 0 ? "backup" : s.Length > 80 ? s[..80] + "…" : s;
    }
}
