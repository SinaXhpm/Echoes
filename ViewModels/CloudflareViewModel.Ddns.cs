using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>A DNS record row: whether it follows this device's public IP (dynamic DNS).</summary>
public partial class CfRecord
{
    /// <summary>A dynamic-DNS job keeps this record on the public IP.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DdnsTip))]
    private bool _ddnsOn;

    /// <summary>…and its last check failed.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DdnsTip))]
    private bool _ddnsError;

    /// <summary>Only A (IPv4) and AAAA (IPv6) records can follow the public IP.</summary>
    public bool CanDdns => Type is "A" or "AAAA";

    public string DdnsTip => !DdnsOn
        ? "Keep updated with my IP (dynamic DNS)"
        : DdnsError
            ? "Kept updated with your public IP, but the last check failed (Dynamic DNS… says why). Click to stop."
            : "Kept updated with your public IP. Click to stop.";
}

/// <summary>One line of the dynamic DNS panel.</summary>
public partial class CfDdnsRow : ObservableObject
{
    public CfDdnsRow(DdnsJobInfo info)
    {
        Id = info.Id;
        _info = info;
        Apply();
    }

    public string Id { get; }
    private DdnsJobInfo _info;
    public DdnsJobInfo Info => _info;

    [ObservableProperty] private string _title = string.Empty;
    [ObservableProperty] private string _type = string.Empty;
    [ObservableProperty] private string _where = string.Empty;
    [ObservableProperty] private string _ipText = string.Empty;
    [ObservableProperty] private string _statusText = string.Empty;
    [ObservableProperty] private bool _isOk;
    [ObservableProperty] private bool _isWarn;
    [ObservableProperty] private bool _isBad;
    [ObservableProperty] private string _whenText = string.Empty;
    [ObservableProperty] private string _message = string.Empty;
    [ObservableProperty] private bool _hasMessage;

    public void Update(DdnsJobInfo info)
    {
        _info = info;
        Apply();
    }

    /// <summary>Re-render the relative times ("2 min ago").</summary>
    public void Apply()
    {
        var i = _info;
        Title = i.RecordName.Length > 0 ? i.RecordName : "(record)";
        Type = i.Type;
        Where = i.Account.Length > 0 ? $"{i.ZoneName} · {i.Account}" : i.ZoneName;
        IpText = i.RecordIp.Length > 0 ? i.RecordIp : "–";
        StatusText = i.Busy ? "Checking…" : i.State switch
        {
            DdnsState.UpToDate => "Up to date",
            DdnsState.Updated => "Updated",
            DdnsState.NoIp => "No public IP",
            DdnsState.Error => "Error",
            _ => "Waiting",
        };
        IsOk = !i.Busy && i.State is DdnsState.UpToDate or DdnsState.Updated;
        IsWarn = !i.Busy && i.State == DdnsState.NoIp;
        IsBad = !i.Busy && i.State == DdnsState.Error;

        var parts = new List<string>();
        parts.Add(i.LastCheck is { } c ? "checked " + CloudflareViewModel.Ago(c) : "not checked yet");
        if (i.LastChange is { } ch)
            parts.Add("changed " + CloudflareViewModel.Ago(ch) + (i.PreviousIp.Length > 0 ? $" (was {i.PreviousIp})" : string.Empty));
        if (i.Failures > 0 && i.NextAttempt is { } next && next > DateTimeOffset.UtcNow)
            parts.Add("next try " + CloudflareViewModel.In(next));
        string when = string.Join(" · ", parts);
        WhenText = char.ToUpperInvariant(when[0]) + when[1..];

        // the plain "Up to date (…)" / "Checking…" adds nothing to the status badge; errors and changes say more
        Message = i.Busy || i.State is DdnsState.UpToDate or DdnsState.Pending ? string.Empty : i.Message;
        HasMessage = Message.Length > 0;
    }
}

/// <summary>
/// Dynamic DNS in the Cloudflare tool: the ↻ action on A / AAAA rows, the editor's "Keep updated with my IP", the
/// zone-line chip and the panel listing every record kept on this device's public IP. The work itself is done by
/// <see cref="DdnsService"/>, which runs without the vault (see there); this side adds and removes jobs and keeps each
/// job's copy of its account in step with the vault: a changed token or proxy is copied over, a removed account takes
/// its jobs (and their saved token copies) with it.
/// </summary>
public partial class CloudflareViewModel
{
    /// <summary>Every record kept updated (all zones and accounts), for the panel.</summary>
    public ObservableCollection<CfDdnsRow> DdnsRows { get; } = new();

    [ObservableProperty] private bool _isDdnsOpen;

    /// <summary>The zone-line chip: shown once any record follows the public IP.</summary>
    [ObservableProperty] private bool _hasDdns;
    [ObservableProperty] private string _ddnsChipText = "DDNS";
    [ObservableProperty] private bool _ddnsAllOk;
    [ObservableProperty] private bool _ddnsHasProblem;
    /// <summary>"Public IPv4 203.0.113.9 · checked 2 min ago".</summary>
    [ObservableProperty] private string _ddnsPublicText = string.Empty;
    /// <summary>The saved jobs exist but can't be opened in this run.</summary>
    [ObservableProperty] private bool _ddnsUnreadable;

    /// <summary>The record editor's "Keep updated with my IP" (applied with Save).</summary>
    [ObservableProperty] private bool _editDdns;

    public bool ShowDdnsField => EditType is "A" or "AAAA";

    private Dictionary<string, DdnsJobInfo> _ddnsByRecord = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<CfProfile, string> _ddnsKeys = new();   // account → its credentials' fingerprint (UI thread)
    private readonly HashSet<CfProfile> _ddnsDirty = new();
    private bool _ddnsSyncPosted;
    private int _ddnsRefreshPosted;
    private DispatcherTimer? _ddnsTimer;

    // Called once from the constructor (InitRecordEditor).
    private void InitDdns()
    {
        // The app starts the updater at launch; this covers a head that doesn't (idempotent, returns at once).
        DdnsService.Start();
        var svc = DdnsService.Instance;
        svc.Changed += () =>
        {
            if (Interlocked.Exchange(ref _ddnsRefreshPosted, 1) == 0)
                Dispatcher.UIThread.Post(() =>
                {
                    Volatile.Write(ref _ddnsRefreshPosted, 0);
                    RefreshDdns();
                }, DispatcherPriority.Background);
        };
        Records.CollectionChanged += OnRecordsChangedForDdns;
        Profiles.CollectionChanged += OnProfilesChangedForDdns;
        Dispatcher.UIThread.Post(RefreshDdns, DispatcherPriority.Background);
    }

    private static string DdnsRecordKey(string zoneId, string recordId) => zoneId + "|" + recordId;

    private static DdnsService.Credentials DdnsCred(CfProfile p)
    {
        bool proxy = p.UseProxy && !string.IsNullOrWhiteSpace(p.ProxyAddress);
        return new DdnsService.Credentials(p.UseApiToken, p.ApiToken, p.ApiEmail, p.ApiKey,
                                           proxy ? p.ProxyAddress : null, proxy ? p.ProxyUser : null, proxy ? p.ProxyPass : null);
    }

    // ---------- the service's state → rows, chip, record marks ----------

    private void RefreshDdns()
    {
        var svc = DdnsService.Instance;
        var jobs = svc.Jobs;
        _ddnsByRecord = new Dictionary<string, DdnsJobInfo>(StringComparer.OrdinalIgnoreCase);
        foreach (var j in jobs) _ddnsByRecord[DdnsRecordKey(j.ZoneId, j.RecordId)] = j;

        if (DdnsRows.Count == jobs.Count && DdnsRows.Select(r => r.Id).SequenceEqual(jobs.Select(j => j.Id)))
            for (int i = 0; i < jobs.Count; i++) DdnsRows[i].Update(jobs[i]);
        else
        {
            DdnsRows.Clear();
            foreach (var j in jobs) DdnsRows.Add(new CfDdnsRow(j));
        }

        string zone = SelectedZone?.Id ?? string.Empty;
        foreach (var r in Records) ApplyDdnsMark(r, zone);

        HasDdns = jobs.Count > 0;
        DdnsChipText = jobs.Count > 0 ? $"DDNS {jobs.Count}" : "DDNS";
        DdnsHasProblem = jobs.Any(j => !j.Busy && j.State is DdnsState.Error or DdnsState.NoIp);
        DdnsAllOk = jobs.Count > 0 && !DdnsHasProblem && jobs.All(j => j.State is DdnsState.UpToDate or DdnsState.Updated);
        DdnsUnreadable = svc.IsUnreadable;
        RefreshDdnsPublicText();
    }

    private void RefreshDdnsPublicText()
    {
        var svc = DdnsService.Instance;
        var parts = new List<string>();
        DateTimeOffset? at = null;
        foreach (var ip in new[] { svc.LastIpv4, svc.LastIpv6 })
        {
            if (ip is null) continue;
            string fam = ip.Family == DdnsFamily.V4 ? "IPv4" : "IPv6";
            parts.Add(ip.Address is { } a ? $"{fam} {a}" : $"{fam} unknown");
            if (at is null || ip.At > at) at = ip.At;
        }
        DdnsPublicText = parts.Count == 0
            ? "Your public IP is looked up when a record is due."
            : "Public " + string.Join(" · ", parts) + " · checked " + Ago(at!.Value);
    }

    private void ApplyDdnsMark(CfRecord r, string zoneId)
    {
        if (!r.CanDdns) return;
        bool on = _ddnsByRecord.TryGetValue(DdnsRecordKey(zoneId, r.Id), out var job);
        r.DdnsOn = on;
        r.DdnsError = on && job!.State is DdnsState.Error or DdnsState.NoIp;
        // the background update changed the record: show what it holds now
        if (on && job!.State is DdnsState.UpToDate or DdnsState.Updated && job.RecordIp.Length > 0 && !r.IsBusy
            && DdnsIpDetector.Canonical(r.Content) != job.RecordIp)
            r.Content = job.RecordIp;
    }

    private void OnRecordsChangedForDdns(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (e.NewItems is null) return;
        string zone = SelectedZone?.Id ?? string.Empty;
        foreach (CfRecord r in e.NewItems) ApplyDdnsMark(r, zone);
    }

    // ---------- the vault's accounts → the jobs' copies ----------

    private void OnProfilesChangedForDdns(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (e.Action == NotifyCollectionChangedAction.Reset)
        {
            // a lock or a restore empties the list: the jobs keep running on their own copies
            foreach (var p in _ddnsKeys.Keys) p.PropertyChanged -= OnProfileEditedForDdns;
            _ddnsKeys.Clear();
            _ddnsDirty.Clear();
            return;
        }
        if (e.OldItems != null)
            foreach (CfProfile p in e.OldItems)
            {
                p.PropertyChanged -= OnProfileEditedForDdns;
                _ddnsDirty.Remove(p);
                // Removed from Echoes (not a lock): its jobs go too, with their saved token copies.
                if (_ddnsKeys.Remove(p, out var key) && e.Action == NotifyCollectionChangedAction.Remove && !IsLocked
                    && !_ddnsKeys.ContainsValue(key))
                    DdnsService.Instance.RemoveAccount(key);
            }
        if (e.NewItems != null)
            foreach (CfProfile p in e.NewItems)
            {
                p.PropertyChanged += OnProfileEditedForDdns;
                var cred = DdnsCred(p);
                _ddnsKeys[p] = cred.AccountKey;
                // the vault was opened (or an account added): jobs of this account take its current token / proxy / name
                if (cred.IsUsable) DdnsService.Instance.UpdateAccount(cred.AccountKey, cred, p.ToString());
            }
    }

    private void OnProfileEditedForDdns(object? sender, PropertyChangedEventArgs e)
    {
        if (sender is not CfProfile p || IsLocked) return;
        if (e.PropertyName is not (nameof(CfProfile.Name) or nameof(CfProfile.UseApiToken) or nameof(CfProfile.ApiToken)
            or nameof(CfProfile.ApiEmail) or nameof(CfProfile.ApiKey) or nameof(CfProfile.UseProxy) or nameof(CfProfile.ProxyAddress)
            or nameof(CfProfile.ProxyUser) or nameof(CfProfile.ProxyPass))) return;
        // An edit sets the fields one by one: copy the finished result once.
        _ddnsDirty.Add(p);
        if (_ddnsSyncPosted) return;
        _ddnsSyncPosted = true;
        Dispatcher.UIThread.Post(SyncEditedDdnsAccounts);
    }

    private void SyncEditedDdnsAccounts()
    {
        _ddnsSyncPosted = false;
        foreach (var p in _ddnsDirty)
        {
            if (!_ddnsKeys.TryGetValue(p, out var oldKey)) continue;
            var cred = DdnsCred(p);
            if (!cred.IsUsable) continue;
            DdnsService.Instance.UpdateAccount(oldKey, cred, p.ToString());
            _ddnsKeys[p] = cred.AccountKey;
        }
        _ddnsDirty.Clear();
    }

    // ---------- actions ----------

    /// <summary>The ↻ button on an A / AAAA row: start or stop keeping it on the public IP.</summary>
    [RelayCommand]
    private void ToggleDdns(CfRecord? rec)
    {
        if (rec is null || !rec.CanDdns || SelectedZone is not { } zone || IsLocked) return;
        var svc = DdnsService.Instance;
        if (svc.Has(zone.Id, rec.Id))
        {
            svc.RemoveRecord(zone.Id, rec.Id);
            rec.DdnsOn = false;
            rec.DdnsError = false;
            SetStatus($"{rec.Name} ({rec.Type}) no longer follows your public IP; its saved token copy was deleted.");
            return;
        }
        string? error = AddDdns(rec, zone);
        if (error != null)
        {
            SetError(error);
            return;
        }
        rec.DdnsOn = true;
        SetStatus($"{rec.Name} ({rec.Type}) now follows your public {(rec.Type == "AAAA" ? "IPv6" : "IPv4")}: checked now, then every 5 minutes {DdnsWhile}.");
    }

    // When the 5-minute checks run: iOS suspends Echoes soon after it leaves the screen, and Android stops them with the
    // process (the desktop keeps them going in the tray).
    private static string DdnsWhile => OperatingSystem.IsIOS() ? "while Echoes is on screen"
        : OperatingSystem.IsAndroid() ? "while Android keeps Echoes running"
        : "while Echoes runs";

    private string? AddDdns(CfRecord rec, CfZone zone)
    {
        if (IsLocked || SelectedProfile is not { } p) return "Unlock and pick an account first.";
        var cred = DdnsCred(p);
        if (!cred.IsUsable) return "This account has no API token or key yet.";
        _ddnsKeys[p] = cred.AccountKey;
        return DdnsService.Instance.Add(cred, p.ToString(), zone.Id, zone.Name, rec.Id, rec.Name, rec.Type, rec.Content);
    }

    /// <summary>
    /// The editor's checkbox, applied after a save (or a save with nothing else to change). Returns a sentence for the
    /// status line, or null when dynamic DNS didn't change.
    /// </summary>
    private string? ApplyEditorDdns(CfRecord rec, CfZone zone, bool want)
    {
        if (!rec.CanDdns) return null;
        var svc = DdnsService.Instance;
        bool has = svc.Has(zone.Id, rec.Id);
        if (want == has) return null;
        if (!want)
        {
            svc.RemoveRecord(zone.Id, rec.Id);
            rec.DdnsOn = false;
            rec.DdnsError = false;
            return "It no longer follows your public IP.";
        }
        string? error = AddDdns(rec, zone);
        if (error != null) return "Dynamic DNS wasn't turned on: " + error;
        rec.DdnsOn = true;
        return "It now follows your public IP.";
    }

    partial void OnEditTypeChanged(string value) => OnPropertyChanged(nameof(ShowDdnsField));

    // A new A / AAAA record with "Keep updated" ticked and no address yet: fill in the public IP.
    partial void OnEditDdnsChanged(bool value)
    {
        if (value && IsEditorOpen && IsNewRecord && ShowDdnsField && EditContent.Trim().Length == 0) _ = FillMyIpAsync();
    }

    private async Task FillMyIpAsync()
    {
        string type = EditType;
        var family = type == "AAAA" ? DdnsFamily.V6 : DdnsFamily.V4;
        var svc = DdnsService.Instance;
        var known = family == DdnsFamily.V4 ? svc.LastIpv4 : svc.LastIpv6;
        string? ip = known is { Address: { } a } && known.At > DateTimeOffset.UtcNow.AddMinutes(-10) ? a : null;
        if (ip is null)
        {
            DdnsIpResult r;
            try { r = await Task.Run(() => DdnsIpDetector.DetectAsync(family, CancellationToken.None)); }
            catch (Exception ex) { r = new DdnsIpResult { Error = ex.Message }; }
            ip = r.Address;
            if (ip is null && IsEditorOpen && IsNewRecord && EditDdns && EditContent.Trim().Length == 0)
                EditorError = r.Error;
        }
        if (ip != null && IsEditorOpen && IsNewRecord && EditDdns && EditType == type && EditContent.Trim().Length == 0)
            EditContent = ip;
    }

    [RelayCommand]
    private void OpenDdns()
    {
        if (IsLocked) return;
        RefreshDdns();
        IsDdnsOpen = true;
    }

    [RelayCommand]
    private void CloseDdns() => IsDdnsOpen = false;

    [RelayCommand]
    private void DdnsCheckNow()
    {
        DdnsService.Instance.CheckNow();
        SetStatus(DdnsRows.Count == 0 ? "No record follows your public IP yet." : "Checking your public IP and the records now…");
    }

    /// <summary>The panel's remove: the record stays as it is in DNS; only the updating (and its token copy) stops.</summary>
    [RelayCommand]
    private void RemoveDdns(CfDdnsRow? row)
    {
        if (row is null) return;
        if (!DdnsService.Instance.Remove(row.Id)) return;
        if (Records.FirstOrDefault(r => r.Id == row.Info.RecordId && SelectedZone?.Id == row.Info.ZoneId) is { } rec)
        {
            rec.DdnsOn = false;
            rec.DdnsError = false;
        }
        SetStatus($"{row.Title} ({row.Type}) no longer follows your public IP; its saved token copy was deleted.");
    }

    partial void OnIsDdnsOpenChanged(bool value)
    {
        _ddnsTimer?.Stop();
        _ddnsTimer = null;
        if (!value) return;
        // "2 min ago" keeps moving while the panel is open
        _ddnsTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
        _ddnsTimer.Tick += (_, _) =>
        {
            foreach (var r in DdnsRows) r.Apply();
            RefreshDdnsPublicText();
        };
        _ddnsTimer.Start();
    }

    // The vault locked (or a restore): the panel belongs to the unlocked page.
    partial void OnIsLockedChanged(bool value)
    {
        if (value) IsDdnsOpen = false;
    }

    // ---------- time text ----------

    internal static string Ago(DateTimeOffset t)
    {
        var d = DateTimeOffset.UtcNow - t;
        if (d < TimeSpan.FromSeconds(45)) return "just now";
        if (d < TimeSpan.FromMinutes(90)) return $"{Math.Max(1, (int)Math.Round(d.TotalMinutes))} min ago";
        if (d < TimeSpan.FromHours(24)) return $"{(int)Math.Round(d.TotalHours)} h ago";
        return t.ToLocalTime().ToString("MMM d, HH:mm", CultureInfo.InvariantCulture);
    }

    internal static string In(DateTimeOffset t)
    {
        var d = t - DateTimeOffset.UtcNow;
        if (d < TimeSpan.FromSeconds(45)) return "now";
        if (d < TimeSpan.FromMinutes(90)) return $"in {Math.Max(1, (int)Math.Round(d.TotalMinutes))} min";
        return $"in {(int)Math.Round(d.TotalHours)} h";
    }
}
