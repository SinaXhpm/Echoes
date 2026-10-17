using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;

namespace Echoes.ViewModels;

/// <summary>
/// Saved servers: the picker fills the whole connection (host, port, user, password / key + passphrase, proxy, SOCKS
/// tunnel, forwards); Save stores the form as the picked server (or a new one), Delete asks first. Secrets are sealed
/// per server with SecretProtector (see <see cref="SshServerStore"/>) and never go into the history.
/// </summary>
public partial class SshViewModel
{
    public ObservableCollection<SshServerEntry> SavedServers { get; } = new();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanDeleteServer), nameof(DeleteServerPrompt), nameof(SaveServerTip))]
    [NotifyCanExecuteChangedFor(nameof(RequestDeleteServerCommand))]
    private SshServerEntry? _selectedServer;

    /// <summary>The form's "Name" (what Save stores the server as; empty → "user@host").</summary>
    [ObservableProperty] private string _serverName = string.Empty;

    [ObservableProperty] private bool _deleteServerConfirm;

    /// <summary>Feedback of the last save / delete ("Saved \"web-1\"."), or a problem with it.</summary>
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasServerNote))] private string _serverNote = string.Empty;

    public bool HasServerNote => ServerNote.Length > 0;
    public bool HasSavedServers => SavedServers.Count > 0;
    public string PickerPlaceholder => SavedServers.Count > 0 ? "Saved servers" : "No saved servers";
    public bool CanDeleteServer => SelectedServer is not null && CanEditConnection;
    public string DeleteServerPrompt => SelectedServer is { } s ? $"Delete \"{s.Name}\"? Its saved password goes with it." : string.Empty;
    public string SaveServerTip => SelectedServer is { } s ? $"Save changes to \"{s.Name}\"" : "Save as a new server";

    private bool _filling;                 // the form is being filled from a saved server: no side effects
    private bool _passwordUnreadable;      // the picked server's stored password couldn't be opened this run
    private bool _passphraseUnreadable;

    private void LoadSavedServers(string? selectedId)
    {
        foreach (var e in SshServerStore.Load().OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase)) SavedServers.Add(e);
        SavedServers.CollectionChanged += (_, _) => { OnPropertyChanged(nameof(HasSavedServers)); OnPropertyChanged(nameof(PickerPlaceholder)); };
        if (string.IsNullOrEmpty(selectedId) || SavedServers.FirstOrDefault(s => s.Id == selectedId) is not { } sel) return;
        // Restore the pick without overwriting the form (it may hold unsaved edits); its secrets come back only when the
        // form still is that server.
        _filling = true;
        try
        {
            SelectedServer = sel;
            ServerName = sel.Name;
            if (string.Equals(sel.Host, Host.Trim(), StringComparison.OrdinalIgnoreCase) && sel.Port == Port && sel.User == Username.Trim())
            {
                var (pw, pp, pwBad, ppBad) = SshServerStore.OpenSecrets(sel.Id);
                Password = pw;
                KeyPassphrase = pp;
                _passwordUnreadable = pwBad;
                _passphraseUnreadable = ppBad;
            }
        }
        finally { _filling = false; }
    }

    partial void OnSelectedServerChanged(SshServerEntry? value)
    {
        DeleteServerConfirm = false;
        if (_filling) return;
        ServerNote = string.Empty;
        if (value is null) return;
        if (!CanEditConnection) return;   // the picker is locked while connected; nothing to fill
        Fill(value);
    }

    private void Fill(SshServerEntry e)
    {
        var (pw, pp, pwBad, ppBad) = SshServerStore.OpenSecrets(e.Id);
        _filling = true;
        try
        {
            ServerName = e.Name;
            Host = e.Host;
            Port = e.Port;
            Username = e.User;
            Password = pw;
            KeyPath = e.KeyPath;
            KeyPassphrase = pp;
            ConnectViaProxy = e.UseProxy;
            ProxyInHost = e.ProxyHost;
            ProxyInPort = e.ProxyPort;
            EnableSocksTunnel = e.Tunnel;
            TunnelHost = e.TunnelHost;
            TunnelPort = e.TunnelPort;
            Forwards.Clear();
            foreach (var spec in e.Forwards) Forwards.Add(new SshForwardRule(spec));
            ConnectError = string.Empty;
            ForwardError = string.Empty;
        }
        finally { _filling = false; }
        _passwordUnreadable = pwBad;
        _passphraseUnreadable = ppBad;
        if (pwBad || ppBad)
            ServerNote = "Its saved password couldn't be opened on this device: enter it again and save.";
    }

    /// <summary>Saves the form as the picked server, or as a new one when none is picked.</summary>
    [RelayCommand]
    private void SaveServer()
    {
        DeleteServerConfirm = false;
        string host = Host.Trim();
        if (host.Length == 0) { ServerNote = "Enter a host before saving."; return; }
        if (Port is < 1 or > 65535) { ServerNote = "The port must be between 1 and 65535."; return; }

        var entry = SelectedServer;
        bool isNew = entry is null;
        entry ??= new SshServerEntry();
        string user = Username.Trim();
        string name = ServerName.Trim();
        if (name.Length == 0) name = user.Length > 0 ? $"{user}@{host}" : host;
        name = UniqueName(name, entry);

        entry.Name = name;
        entry.Host = host;
        entry.Port = Port;
        entry.User = user;
        entry.KeyPath = KeyPath.Trim();
        entry.UseProxy = ConnectViaProxy;
        entry.ProxyHost = ProxyInHost.Trim();
        entry.ProxyPort = ProxyInPort;
        entry.Tunnel = EnableSocksTunnel;
        entry.TunnelHost = TunnelHost.Trim();
        entry.TunnelPort = TunnelPort;
        entry.Forwards = Forwards.Select(r => r.Spec).ToList();

        // A stored secret that couldn't be opened this run is kept as it is, unless something new was typed over it.
        SshServerStore.SaveSecrets(entry.Id,
            _passwordUnreadable && Password.Length == 0 ? null : Password,
            _passphraseUnreadable && KeyPassphrase.Length == 0 ? null : (entry.KeyPath.Length > 0 ? KeyPassphrase : string.Empty));

        _filling = true;
        try
        {
            if (isNew)
            {
                int at = 0;
                while (at < SavedServers.Count && string.Compare(SavedServers[at].Name, name, StringComparison.OrdinalIgnoreCase) <= 0) at++;
                SavedServers.Insert(at, entry);
                SelectedServer = entry;
            }
            ServerName = name;
        }
        finally { _filling = false; }
        SshServerStore.SaveList(SavedServers);
        OnPropertyChanged(nameof(DeleteServerPrompt));
        OnPropertyChanged(nameof(SaveServerTip));
        SchedulePersist();
        ServerNote = isNew ? $"Saved as \"{name}\"." : $"Saved \"{name}\".";
    }

    private string UniqueName(string name, SshServerEntry self)
    {
        bool Taken(string n) => SavedServers.Any(s => !ReferenceEquals(s, self) && string.Equals(s.Name, n, StringComparison.OrdinalIgnoreCase));
        if (!Taken(name)) return name;
        for (int i = 2; i < 1000; i++)
            if (!Taken($"{name} ({i})")) return $"{name} ({i})";
        return name + " " + Guid.NewGuid().ToString("N")[..4];
    }

    /// <summary>An empty form for a new server (nothing saved changes).</summary>
    [RelayCommand]
    private void NewServer()
    {
        if (!CanEditConnection) return;
        _filling = true;
        try
        {
            SelectedServer = null;
            ServerName = string.Empty;
            Host = string.Empty;
            Port = 22;
            Username = "root";
            Password = string.Empty;
            KeyPath = string.Empty;
            KeyPassphrase = string.Empty;
            ConnectViaProxy = false;
            EnableSocksTunnel = false;
            Forwards.Clear();
            ConnectError = string.Empty;
            ForwardError = string.Empty;
        }
        finally { _filling = false; }
        _passwordUnreadable = _passphraseUnreadable = false;
        DeleteServerConfirm = false;
        ServerNote = string.Empty;
        SchedulePersist();
    }

    [RelayCommand(CanExecute = nameof(CanDeleteServer))]
    private void RequestDeleteServer()
    {
        if (!CanDeleteServer) return;
        ServerNote = string.Empty;
        DeleteServerConfirm = true;
    }

    [RelayCommand]
    private void CancelDeleteServer() => DeleteServerConfirm = false;

    /// <summary>Only through the confirmation strip.</summary>
    [RelayCommand]
    private void ConfirmDeleteServer()
    {
        var entry = SelectedServer;
        if (entry is null || !DeleteServerConfirm || !CanEditConnection) return;
        DeleteServerConfirm = false;
        SshServerStore.DeleteSecrets(entry.Id);
        _filling = true;
        try
        {
            SavedServers.Remove(entry);
            SelectedServer = null;
            ServerName = string.Empty;
        }
        finally { _filling = false; }
        _passwordUnreadable = _passphraseUnreadable = false;
        SshServerStore.SaveList(SavedServers);
        SchedulePersist();
        ServerNote = $"Deleted \"{entry.Name}\".";
    }

    partial void OnIsConnectedChanged(bool value)
    {
        RequestDeleteServerCommand.NotifyCanExecuteChanged();
        if (value) { DeleteServerConfirm = false; ServerNote = string.Empty; }
    }

    partial void OnIsConnectingChanged(bool value) => RequestDeleteServerCommand.NotifyCanExecuteChanged();
}
