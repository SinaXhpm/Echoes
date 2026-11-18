using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Threading;

namespace Echoes.ViewModels;

/// <summary>
/// Dynamic DNS in the Hetzner tool: the ↻ action on A / AAAA record sets, the editor's "Keep updated with my IP", and the
/// panel listing this tool's jobs. The work is done by <see cref="DdnsService"/> (the same background updater the
/// Cloudflare tool uses), which keeps its own sealed copy of the project's token so it runs with nothing open. A job
/// keeps a record set holding ONE value: one with several values is refused here and by the service.
/// </summary>
public partial class HetznerViewModel
{
    /// <summary>This tool's jobs (every project), for the panel. The rows are the Cloudflare tool's own kind.</summary>
    public ObservableCollection<CfDdnsRow> DdnsRows { get; } = new();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsOverlayOpen))]
    private bool _isDdnsOpen;
    [ObservableProperty] private bool _hasDdns;
    [ObservableProperty] private string _ddnsChipText = "DDNS";
    [ObservableProperty] private bool _ddnsAllOk;
    [ObservableProperty] private bool _ddnsHasProblem;
    [ObservableProperty] private string _ddnsPublicText = string.Empty;
    [ObservableProperty] private bool _ddnsUnreadable;

    private Dictionary<string, DdnsJobInfo> _ddnsBySet = new(StringComparer.Ordinal);
    private int _ddnsRefreshPosted;
    private DispatcherTimer? _ddnsTimer;

    private void InitDdns()
    {
        DdnsService.Start();   // idempotent: the app starts it at launch
        DdnsService.Instance.Changed += () =>
        {
            if (Interlocked.Exchange(ref _ddnsRefreshPosted, 1) == 0)
                Dispatcher.UIThread.Post(() =>
                {
                    Volatile.Write(ref _ddnsRefreshPosted, 0);
                    RefreshDdns();
                }, DispatcherPriority.Background);
        };
        Dispatcher.UIThread.Post(RefreshDdns, DispatcherPriority.Background);
    }

    private static string SetKey(string zoneId, string setId) => zoneId + "|" + setId;

    private void RefreshDdns()
    {
        var svc = DdnsService.Instance;
        var jobs = svc.Jobs.Where(j => j.Provider == DdnsProvider.Hetzner).ToList();
        _ddnsBySet = new Dictionary<string, DdnsJobInfo>(StringComparer.Ordinal);
        foreach (var j in jobs) _ddnsBySet[SetKey(j.ZoneId, j.RecordId)] = j;

        if (DdnsRows.Count == jobs.Count && DdnsRows.Select(r => r.Id).SequenceEqual(jobs.Select(j => j.Id)))
            for (int i = 0; i < jobs.Count; i++) DdnsRows[i].Update(jobs[i]);
        else
        {
            DdnsRows.Clear();
            foreach (var j in jobs) DdnsRows.Add(new CfDdnsRow(j));
        }
        ApplyDdnsMarks();

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
            ? "Your public IP is looked up when a record set is due."
            : "Public " + string.Join(" · ", parts) + " · checked " + CloudflareViewModel.Ago(at!.Value);
    }

    private void ApplyDdnsMarks()
    {
        string zone = SelectedZone?.Id.ToString(CultureInfo.InvariantCulture) ?? string.Empty;
        foreach (var r in _rrsets)
        {
            if (!r.CanDdns) continue;
            bool on = _ddnsBySet.TryGetValue(SetKey(zone, r.Id), out var job);
            r.DdnsOn = on;
            r.DdnsError = on && job!.State is DdnsState.Error or DdnsState.NoIp;
        }
    }

    // While Echoes is on screen (iOS), while Android keeps it running, or while it runs (the desktop's tray).
    private static string DdnsWhile => OperatingSystem.IsIOS() ? "while Echoes is on screen"
        : OperatingSystem.IsAndroid() ? "while Android keeps Echoes running"
        : "while Echoes runs";

    /// <summary>The ↻ button on an A / AAAA record set: start or stop keeping it on the public IP.</summary>
    [RelayCommand]
    private void ToggleDdns(HzRrset? set)
    {
        if (set is null || !set.CanDdns || SelectedZone is not { } zone) return;
        string zoneId = zone.Id.ToString(CultureInfo.InvariantCulture);
        var svc = DdnsService.Instance;
        if (svc.Has(DdnsProvider.Hetzner, zoneId, set.Id))
        {
            svc.RemoveRecord(DdnsProvider.Hetzner, zoneId, set.Id);
            set.DdnsOn = false;
            set.DdnsError = false;
            SetStatus($"{set.FullName} ({set.Type}) no longer follows your public IP; its saved token copy was deleted.");
            return;
        }
        if (AddDdns(zone, set.Name, set.Type, set.FullName, set.Values.Select(v => v.Value).ToList()) is { } error)
        {
            SetError(error);
            return;
        }
        set.DdnsOn = true;
        SetStatus($"{set.FullName} ({set.Type}) now follows your public {(set.Type == "AAAA" ? "IPv6" : "IPv4")}: checked now, then every 5 minutes {DdnsWhile}.");
    }

    private string? AddDdns(HzZone zone, string name, string type, string fullName, IReadOnlyList<string> values)
    {
        if (SelectedProject is not { } p) return "Pick a project first.";
        if (p.Restored) return "This project came from a backup. Confirm it is yours (the note above) before dynamic DNS uses its token.";
        if (values.Count > 1)
            return $"{fullName} ({type}) holds {values.Count} values. Dynamic DNS keeps exactly one value on your IP: leave one value first.";
        var cred = DdnsCred(p.Data);
        if (!cred.IsUsable) return "This project has no API token.";
        return DdnsService.Instance.Add(cred, p.Name, zone.Id.ToString(CultureInfo.InvariantCulture), zone.Name, name + "/" + type, fullName, type,
                                        values.Count == 1 ? values[0] : null);
    }

    /// <summary>The editor's checkbox, after a save. A sentence for the status line, or null when nothing changed.</summary>
    private string? ApplyEditorDdns(HzZone zone, string name, string type, string fullName, IReadOnlyList<string> values, bool want)
    {
        if (type is not ("A" or "AAAA")) return null;
        string zoneId = zone.Id.ToString(CultureInfo.InvariantCulture);
        var svc = DdnsService.Instance;
        bool has = svc.Has(DdnsProvider.Hetzner, zoneId, name + "/" + type);
        if (want == has) return null;
        if (!want)
        {
            svc.RemoveRecord(DdnsProvider.Hetzner, zoneId, name + "/" + type);
            return "It no longer follows your public IP.";
        }
        string? error = AddDdns(zone, name, type, fullName, values);
        return error != null ? "Dynamic DNS wasn't turned on: " + error : "It now follows your public IP.";
    }

    [RelayCommand]
    private void OpenDdns()
    {
        RefreshDdns();
        IsDdnsOpen = true;
    }

    [RelayCommand]
    private void CloseDdns() => IsDdnsOpen = false;

    [RelayCommand]
    private void DdnsCheckNow()
    {
        DdnsService.Instance.CheckNow();
        SetStatus(DdnsRows.Count == 0 ? "No record set follows your public IP yet." : "Checking your public IP and the record sets now…");
    }

    /// <summary>The panel's remove: the record set stays as it is in DNS; only the updating (and its token copy) stops.</summary>
    [RelayCommand]
    private void RemoveDdns(CfDdnsRow? row)
    {
        if (row is null || !DdnsService.Instance.Remove(row.Id)) return;
        if (_rrsets.FirstOrDefault(r => r.Id == row.Info.RecordId && SelectedZone?.Id.ToString(CultureInfo.InvariantCulture) == row.Info.ZoneId) is { } set)
        {
            set.DdnsOn = false;
            set.DdnsError = false;
        }
        SetStatus($"{row.Title} ({row.Type}) no longer follows your public IP; its saved token copy was deleted.");
    }

    partial void OnIsDdnsOpenChanged(bool value)
    {
        _ddnsTimer?.Stop();
        _ddnsTimer = null;
        if (!value) return;
        _ddnsTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
        _ddnsTimer.Tick += (_, _) =>
        {
            foreach (var r in DdnsRows) r.Apply();
            RefreshDdnsPublicText();
        };
        _ddnsTimer.Start();
    }
}
