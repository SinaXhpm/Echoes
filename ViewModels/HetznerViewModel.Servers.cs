using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>
/// Servers: the project's server list, the selected server's details (addresses with copy, reverse DNS, networks,
/// traffic, protection, labels, firewalls) and its power actions. Power on, shutdown and reboot run at once (shutdown
/// and reboot are ACPI requests the OS may ignore); power off and reset cut the power and ask first. A running action
/// shows its progress until Hetzner says it ended, then the server is read again.
/// </summary>
public partial class HetznerViewModel
{
    public ObservableCollection<HzServer> Servers { get; } = new();
    public ObservableCollection<HzField> ServerFields { get; } = new();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasServer))]
    private HzServer? _selectedServer;
    [ObservableProperty] private bool _isLoadingServers;
    [ObservableProperty] private string _serverCountText = string.Empty;
    [ObservableProperty] private string _serversEmptyText = string.Empty;
    [ObservableProperty] private bool _showServersEmpty;

    /// <summary>A hard power action (power off, reset) waits for this confirmation: "poweroff" or "reset".</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsConfirmingHard), nameof(ConfirmHardText), nameof(ConfirmHardButton))]
    private string _confirmHard = string.Empty;

    /// <summary>A power action is running on the selected server.</summary>
    [ObservableProperty] private bool _isPowerRunning;
    [ObservableProperty] private string _powerText = string.Empty;
    [ObservableProperty] private int _powerProgress;

    /// <summary>Phones: the selected server's details are shown in place of the list (a tap opens them).</summary>
    [ObservableProperty] private bool _serverDetailOpen;

    public bool HasServer => SelectedServer != null;
    public bool IsConfirmingHard => ConfirmHard.Length > 0;
    public string ConfirmHardButton => ConfirmHard == "reset" ? "Reset" : "Power off";
    public string ConfirmHardText => ConfirmHard switch
    {
        "poweroff" => $"Power off {SelectedServer?.Name}? This cuts the power at once, like pulling the plug: unsaved data can be lost.",
        "reset" => $"Reset {SelectedServer?.Name}? This is a hard restart without shutting down: unsaved data can be lost.",
        _ => string.Empty,
    };

    // firewall names by id, for a server's details (filled whenever the firewalls load)
    private readonly Dictionary<long, string> _firewallNames = new();
    private int _powerRun;   // the power action whose progress is shown

    private void ClearServers()
    {
        Servers.Clear();
        SelectedServer = null;
        ServerFields.Clear();
        ServerCountText = string.Empty;
        ShowServersEmpty = false;
        ServerDetailOpen = false;
        ConfirmHard = string.Empty;
        IsPowerRunning = false;
        PowerText = string.Empty;
        _firewallNames.Clear();
        _powerRun++;
    }

    /// <summary>Read the server list. False when it couldn't be read (the connection's check fails with it).</summary>
    private async Task<bool> LoadServersAsync()
    {
        if (Api() is not { } api) return false;
        var (ct, gen) = Session();
        long keep = SelectedServer?.Id ?? 0;
        IsLoadingServers = true;
        BeginBusy();
        SetStatus("Loading servers…");
        try
        {
            HzListResponse r;
            try { r = await Task.Run(() => api.GetAllAsync("/servers", "servers", ct), ct); }
            catch (OperationCanceledException) { return false; }
            if (Stale(gen)) return false;
            if (!r.Success)
            {
                if (!IsConnected) ConnectProblem = r.AuthFailed ? "auth" : "other";
                Report(r, "load the servers");
                return false;
            }
            var list = LastById(r.Items.Select(HzServer.From).Where(s => s != null).Select(s => s!), s => s.Id)
                       .OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase).ToList();
            // the list emptied clears the selection for a moment: a phone's open details stay open for the same server
            _replacingServers = true;
            try
            {
                Servers.Clear();
                foreach (var s in list) Servers.Add(s);
                SelectedServer = Servers.FirstOrDefault(s => s.Id == keep) ?? Servers.FirstOrDefault();
            }
            finally { _replacingServers = false; }
            if (SelectedServer?.Id != keep) ServerDetailOpen = false;
            ServerCountText = Servers.Count == 1 ? "1 server" : $"{Servers.Count} servers";
            ShowServersEmpty = Servers.Count == 0;
            ServersEmptyText = "This project has no servers yet. Create one in the Hetzner Console; it shows up here.";
            SetStatus(r.Truncated ? $"Showing the first {Servers.Count} servers." : $"{SelectedProject?.Name}: {ServerCountText}.");
            // the firewalls' names for the details (one more request, only the first time)
            if (_firewallNames.Count == 0 && Servers.Any(s => s.Firewalls.Count > 0) && !FirewallsLoaded) Fire(LoadFirewallNamesAsync, "load the firewall names");
            return true;
        }
        finally
        {
            if (!Stale(gen)) IsLoadingServers = false;
            EndBusy(gen);
        }
    }

    private async Task LoadFirewallNamesAsync()
    {
        if (Api() is not { } api) return;
        var (ct, gen) = Session();
        HzListResponse r;
        try { r = await Task.Run(() => api.GetAllAsync("/firewalls", "firewalls", ct), ct); }
        catch (OperationCanceledException) { return; }
        if (Stale(gen)) return;
        if (!r.Success)
        {
            // the servers are there; only the details' firewall names are missing
            SetError("The servers loaded, but their firewalls' names couldn't be: " + r.Error);
            return;
        }
        foreach (var n in r.Items)
            if (CfJson.Long(n["id"]) is long id) _firewallNames[id] = HetznerApi.Clip(CfJson.Str(n["name"]), 80);
        BuildServerFields();
    }

    private bool _replacingServers;   // the list is being refilled: a selection cleared meanwhile isn't the user's

    partial void OnSelectedServerChanged(HzServer? value)
    {
        ConfirmHard = string.Empty;
        if (value is null && !_replacingServers) ServerDetailOpen = false;
        BuildServerFields();
    }

    /// <summary>Phones: a tap on a server shows its details.</summary>
    public void OpenServerDetails()
    {
        if (SelectedServer != null) ServerDetailOpen = true;
    }

    [RelayCommand]
    private void CloseServerDetails() => ServerDetailOpen = false;

    private void BuildServerFields()
    {
        ServerFields.Clear();
        if (SelectedServer is not { } s) return;
        if (s.Ipv4.Length > 0) ServerFields.Add(new HzField("IPv4", s.Ipv4 + (s.Ipv4Blocked ? "  (blocked)" : string.Empty)));
        if (s.Ipv4Ptr.Length > 0) ServerFields.Add(new HzField("Reverse DNS", s.Ipv4Ptr));
        if (s.Ipv6.Length > 0) ServerFields.Add(new HzField("IPv6", s.Ipv6));
        foreach (var ptr in s.Ipv6Ptrs) ServerFields.Add(new HzField("Reverse DNS", ptr));
        foreach (var net in s.PrivateNets) ServerFields.Add(new HzField("Private", net));
        ServerFields.Add(new HzField("Type", $"{s.TypeName} · {s.TypeText}", mono: false, copy: false));
        ServerFields.Add(new HzField("Location", s.LocationCode.Length > 0 ? $"{s.Location} ({s.LocationCode})" : s.Location, mono: false, copy: false));
        ServerFields.Add(new HzField("Image", s.ImageText, mono: false, copy: false));
        ServerFields.Add(new HzField("Traffic", s.TrafficText, mono: false, copy: false));
        string prot = s.ProtectDelete && s.ProtectRebuild ? "delete, rebuild" : s.ProtectDelete ? "delete" : s.ProtectRebuild ? "rebuild" : "none";
        ServerFields.Add(new HzField("Protection", prot, mono: false, copy: false));
        if (s.Firewalls.Count > 0)
            ServerFields.Add(new HzField("Firewalls", string.Join(", ", s.Firewalls.Select(f =>
                (_firewallNames.TryGetValue(f.Id, out var n) ? n : "firewall " + f.Id.ToString(CultureInfo.InvariantCulture))
                + (f.Status is "pending" ? " (pending)" : string.Empty))), mono: false, copy: false));
        if (s.Labels.Count > 0) ServerFields.Add(new HzField("Labels", string.Join(", ", s.Labels)));
        var flags = new List<string>();
        if (s.Rescue) flags.Add("rescue system on");
        if (s.Locked) flags.Add("locked by a running action");
        if (flags.Count > 0) ServerFields.Add(new HzField("State", string.Join(", ", flags), mono: false, copy: false));
        if (s.Created.Length > 0) ServerFields.Add(new HzField("Created", s.Created, mono: false, copy: false));
    }

    [RelayCommand]
    private async Task CopyField(HzField? field)
    {
        if (field is null || !field.CanCopy) return;
        // "203.0.113.4  (blocked)" copies the address only
        string text = field.Value;
        int cut = text.IndexOf("  (", StringComparison.Ordinal);
        if (cut > 0) text = text[..cut];
        await ClipboardHelper.SetTextAsync(text);
        SetStatus($"{field.Label} copied.");
    }

    // ---------- other tools ----------

    [RelayCommand]
    private void PingServer()
    {
        if (SelectedServer is { HasHost: true } s) _links?.Ping(s.HostAddress);
    }

    [RelayCommand]
    private void SshServer()
    {
        if (SelectedServer is { HasHost: true } s) _links?.Ssh(s.HostAddress);
    }

    [RelayCommand]
    private void WhoisServer()
    {
        if (SelectedServer is { HasHost: true } s) _links?.Whois(s.HostAddress);
    }

    public bool HasLinks => _links != null;

    // ---------- power ----------

    [RelayCommand]
    private Task PowerOn() => RunPowerAsync("poweron");

    [RelayCommand]
    private Task Shutdown() => RunPowerAsync("shutdown");

    [RelayCommand]
    private Task Reboot() => RunPowerAsync("reboot");

    [RelayCommand]
    private void RequestPowerOff() => ConfirmHard = SelectedServer is null ? string.Empty : "poweroff";

    [RelayCommand]
    private void RequestReset() => ConfirmHard = SelectedServer is null ? string.Empty : "reset";

    [RelayCommand]
    private void CancelHard() => ConfirmHard = string.Empty;

    [RelayCommand]
    private Task ConfirmHardAction()
    {
        string what = ConfirmHard;
        ConfirmHard = string.Empty;
        return what is "poweroff" or "reset" ? RunPowerAsync(what) : Task.CompletedTask;
    }

    private static string PowerWord(string command) => command switch
    {
        "poweron" => "Powering on",
        "shutdown" => "Shutting down",
        "reboot" => "Rebooting",
        "poweroff" => "Powering off",
        "reset" => "Resetting",
        _ => "Working",
    };

    /// <summary>Start a power action on the selected server, follow it to its end, then read the server again.</summary>
    private async Task RunPowerAsync(string command)
    {
        if (SelectedServer is not { } server || Api() is not { } api) return;
        if (command is not ("poweron" or "shutdown" or "reboot" or "poweroff" or "reset")) return;
        if (IsPowerRunning)
        {
            // one action at a time (the confirmed power off / reset included): say so rather than do nothing
            SetError($"{PowerWord(command)} {server.Name} wasn't started: another power action is still running. Wait for it to finish, then try again.");
            return;
        }
        var (ct, gen) = Session();
        int run = ++_powerRun;
        IsPowerRunning = true;
        PowerProgress = 0;
        PowerText = $"{PowerWord(command)} {server.Name}…";
        BeginBusy();
        try
        {
            HzResponse r;
            try { r = await Task.Run(() => api.PostAsync(HetznerApi.ServerPath(server.Id) + "/actions/" + command, null, ct), ct); }
            catch (OperationCanceledException) { return; }
            if (Stale(gen)) return;
            if (!r.Success)
            {
                Report(r, $"{command switch { "poweron" => "power on", "poweroff" => "power off", _ => command }} {server.Name}");
                return;
            }
            WriteWorked();
            if (HzAction.From(r.Body?["action"]) is { } action)
            {
                HzActionResult done;
                try
                {
                    done = await Task.Run(() => api.WaitActionAsync("servers", action, a => OnUi(() =>
                    {
                        if (Stale(gen) || run != _powerRun) return;
                        PowerProgress = a.Progress;
                        PowerText = $"{PowerWord(command)} {server.Name}… {a.Progress}%";
                    }), ct), ct);
                }
                catch (OperationCanceledException) { return; }
                if (Stale(gen)) return;
                if (done.Ok) SetStatus(command switch
                {
                    "shutdown" => $"{server.Name} was asked to shut down. Its operating system decides when.",
                    "reboot" => $"{server.Name} was asked to reboot. Its operating system decides when.",
                    _ => $"{PowerWord(command)} {server.Name}: done.",
                });
                else if (done.StillRunning) SetStatus($"{PowerWord(command)} {server.Name}: still running at Hetzner. Refresh in a moment.");
                else SetError($"{PowerWord(command)} {server.Name} failed: {done.Error}");
            }
            await RefreshServerAsync(server.Id);
        }
        finally
        {
            if (!Stale(gen) && run == _powerRun)
            {
                IsPowerRunning = false;
                PowerText = string.Empty;
            }
            EndBusy(gen);
        }
    }

    /// <summary>Read one server again and update its row (and the details when it is selected).</summary>
    private async Task RefreshServerAsync(long id)
    {
        if (Api() is not { } api) return;
        var (ct, gen) = Session();
        HzResponse r;
        try { r = await Task.Run(() => api.GetAsync(HetznerApi.ServerPath(id), ct), ct); }
        catch (OperationCanceledException) { return; }
        if (Stale(gen) || !r.Success || HzServer.From(r.Body?["server"]) is not { } fresh) return;
        int i = Servers.ToList().FindIndex(s => s.Id == id);
        if (i < 0) return;
        bool selected = SelectedServer?.Id == id;
        // replacing the selected row clears the list's selection for a moment: it is put back, and a phone's open
        // details stay open
        _replacingServers = true;
        try
        {
            Servers[i] = fresh;
            if (selected) SelectedServer = fresh;
        }
        finally { _replacingServers = false; }
    }
}
