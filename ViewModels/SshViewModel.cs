using Avalonia.Threading;
using Avalonia.Platform.Storage;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using Renci.SshNet;
using Renci.SshNet.Sftp;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>
/// The SSH tool: one connection (password and/or private key, keyboard-interactive fallback; host keys pinned on first
/// use; optional SOCKS5 proxy) with four views of it — a command terminal, an SFTP file browser, port forwards
/// (-L / -R / -D) and a server health view. Saved servers fill the connection form in one pick.
/// Partials: .Terminal (shell output), .Saved (saved servers), .Files (SFTP), .Forwarding, .Server (health), .Models.
/// </summary>
public partial class SshViewModel : ObservableObject
{
    // ===================================================================== connection form
    [ObservableProperty] private string _host = string.Empty;
    [ObservableProperty] private int _port = 22;
    [ObservableProperty] private string _username = "root";
    [ObservableProperty] private string _password = string.Empty;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasKeyPath))] private string _keyPath = string.Empty;
    [ObservableProperty] private string _keyPassphrase = string.Empty;

    [ObservableProperty] private bool _connectViaProxy;
    [ObservableProperty] private string _proxyInHost = "127.0.0.1";
    [ObservableProperty] private int _proxyInPort = 1080;

    public bool HasKeyPath => KeyPath.Trim().Length > 0;

    // ===================================================================== connection state
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowForm), nameof(CanEditConnection), nameof(StatusText), nameof(ConnectLabel), nameof(IsSessionActive), nameof(CanDeleteServer))]
    private bool _isConnected;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanEditConnection), nameof(StatusText), nameof(ConnectLabel), nameof(IsSessionActive), nameof(CanDeleteServer))]
    private bool _isConnecting;

    /// <summary>The one clear sentence why the last connect failed (empty: it didn't).</summary>
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasConnectError), nameof(StatusText))] private string _connectError = string.Empty;

    /// <summary>"echotest@host:22 · key (ed25519) · via proxy" while connected.</summary>
    [ObservableProperty] private string _connectionSummary = string.Empty;

    /// <summary>Sub-tab: 0 Terminal, 1 Files, 2 Forwarding, 3 Server.</summary>
    [ObservableProperty] private int _selectedTab;

    public const int TabTerminal = 0, TabFiles = 1, TabForwarding = 2, TabServer = 3;

    public bool HasConnectError => ConnectError.Length > 0;
    public bool ShowForm => !IsConnected;
    public bool CanEditConnection => !IsConnected && !IsConnecting;
    public bool IsSessionActive => IsConnected || IsConnecting;
    public string ConnectLabel => IsConnecting ? "Cancel" : IsConnected ? "Disconnect" : "Connect";
    public string StatusText => IsConnecting ? "Connecting…" : IsConnected ? "Connected" : HasConnectError ? "Failed" : "Offline";

    public ObservableCollection<string> HostHistory => HistoryService.Instance.Get("ssh.host");
    public ObservableCollection<string> UserHistory => HistoryService.Instance.Get("ssh.user");

    // ===================================================================== persistence
    private bool _loaded;
    // NOTE: the password / passphrase of the form are never persisted; a SAVED server keeps them sealed (SecretProtector).
    private static readonly HashSet<string> PersistProps = new()
    { nameof(Host), nameof(Port), nameof(Username), nameof(KeyPath), nameof(ConnectViaProxy), nameof(ProxyInHost), nameof(ProxyInPort),
      nameof(EnableSocksTunnel), nameof(TunnelHost), nameof(TunnelPort), nameof(SelectedServer), nameof(SelectedTab) };

    public SshViewModel()
    {
        var ps = ProfileService.Instance;
        ps.Remove("ssh.pass");   // purge any password saved by an earlier build
        Host = ps.GetSetting("ssh.host") ?? (HistoryService.Instance.Last("ssh.host") ?? string.Empty);
        Port = ps.GetInt("ssh.port", 22);
        Username = ps.GetSetting("ssh.user") ?? (HistoryService.Instance.Last("ssh.user") ?? "root");
        KeyPath = ps.GetSetting("ssh.keyPath") ?? string.Empty;
        ConnectViaProxy = ps.GetBool("ssh.inEnabled");
        ProxyInHost = ps.GetSetting("ssh.inHost") ?? "127.0.0.1";
        ProxyInPort = ps.GetInt("ssh.inPort", 1080);
        EnableSocksTunnel = ps.GetBool("ssh.outEnabled");
        TunnelHost = ps.GetSetting("ssh.outHost") ?? "127.0.0.1";
        TunnelPort = ps.GetInt("ssh.outPort", 8080);
        SelectedTab = Math.Clamp(ps.GetInt("ssh.tab", TabTerminal), TabTerminal, TabServer);
        try
        {
            foreach (var spec in SshForwardSpec.ListFromJson(JsonNode.Parse(ps.GetSetting("ssh.forwards") is { Length: > 0 } f ? f : "[]")))
                Forwards.Add(new SshForwardRule(spec));
        }
        catch (Exception) { /* a damaged list: start without forwards */ }
        Forwards.CollectionChanged += (_, _) => { OnPropertyChanged(nameof(HasForwards)); if (_loaded) SchedulePersist(); };
        LoadSavedServers(ps.GetSetting("ssh.server"));
        _loaded = true;
    }

    private CancellationTokenSource? _persistCts;
    private bool _persistPending;   // UI thread only

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (_loaded && e.PropertyName is { } n && PersistProps.Contains(n))
            SchedulePersist();
    }

    // Typing into Host/User/… raises PropertyChanged per keystroke; debounce so we don't
    // re-serialize + rewrite the whole profile file on the UI thread on every character.
    // App exit / backgrounding flush a pending one (FlushPendingSave): an edit made just before was lost.
    private void SchedulePersist()
    {
        _persistPending = true;
        _persistCts?.Cancel();
        _persistCts?.Dispose();
        var cts = _persistCts = new CancellationTokenSource();
        _ = Task.Delay(600, cts.Token).ContinueWith(t =>
        {
            // Values are read back on the UI thread at write time, so the latest edit always wins.
            if (!t.IsCanceled) Dispatcher.UIThread.Post(FlushPendingSave);
        }, TaskScheduler.Default);
    }

    /// <summary>Persist a pending (debounced) settings change now. No-op when nothing is pending. UI thread only.</summary>
    public void FlushPendingSave()
    {
        _persistCts?.Cancel();
        if (!_persistPending) return;
        _persistPending = false;
        var specs = new List<SshForwardSpec>(Forwards.Count);
        foreach (var r in Forwards) specs.Add(r.Spec);
        ProfileService.Instance.SetMany(
            ("ssh.host", Host), ("ssh.port", Port.ToString()), ("ssh.user", Username), ("ssh.keyPath", KeyPath),
            ("ssh.inEnabled", ConnectViaProxy ? "true" : "false"), ("ssh.inHost", ProxyInHost), ("ssh.inPort", ProxyInPort.ToString()),
            ("ssh.outEnabled", EnableSocksTunnel ? "true" : "false"), ("ssh.outHost", TunnelHost), ("ssh.outPort", TunnelPort.ToString()),
            ("ssh.forwards", SshForwardSpec.ToJson(specs).ToJsonString()), ("ssh.server", SelectedServer?.Id ?? string.Empty),
            ("ssh.tab", Math.Clamp(SelectedTab, TabTerminal, TabServer).ToString()));
    }

    partial void OnPasswordChanged(string value) { if (!_filling) _passwordUnreadable = false; }
    partial void OnKeyPassphraseChanged(string value) { if (!_filling) _passphraseUnreadable = false; }
    partial void OnHostChanged(string value) { if (!_filling && !IsConnecting) ConnectError = string.Empty; }

    // ===================================================================== session
    /// <summary>A live connection and everything hanging off it. Only ever swapped with Interlocked.</summary>
    internal sealed class SshSession
    {
        public required SshClient Client { get; init; }
        public required SshLogin Login { get; init; }
        public required byte[] HostKey { get; init; }
        public required string HostId { get; init; }
        public required string LegacyId { get; init; }
        public string AuthUsed { get; init; } = string.Empty;
        public ShellStream? Shell { get; set; }
        public ForwardedPortDynamic? Dynamic { get; set; }
        public SftpClient? Sftp { get; set; }
        public SemaphoreSlim SftpGate { get; } = new(1, 1);
        /// <summary>Remote forwards are global requests whose replies SSH.NET matches by ORDER: two in flight at once
        /// could each take the other's answer. Start / stop them one at a time.</summary>
        public object RemoteForwardGate { get; } = new();
        public SshCpuTimes? LastCpu { get; set; }
        public volatile bool Closed;
    }

    private SshSession? _session;
    private CancellationTokenSource? _connectCts;
    private readonly Dictionary<string, Avalonia.Platform.Storage.IStorageFile> _pickedKeys = new(StringComparer.Ordinal);

    /// <summary>True while a session is live (tests, the view).</summary>
    internal bool HasSession => _session is not null;

    /// <summary>Connect / Cancel / Disconnect. Synchronous on purpose: an async [RelayCommand] disables itself while it
    /// runs, and Cancel (during the connect) must stay clickable.</summary>
    [RelayCommand]
    private void ToggleConnect()
    {
        if (IsConnecting) { _connectCts?.Cancel(); return; }
        if (IsConnected) { Disconnect(); return; }
        _ = ConnectAsync();
    }

    /// <summary>Tears the session down off the UI thread: SSH.NET's Disconnect/Dispose block until TCP teardown, which on
    /// a half-open connection (dropped Wi-Fi) would freeze the window.</summary>
    public void Disconnect()
    {
        if (_session is { } s) _ = Task.Run(() => StopSession(s));
        else PostDisconnectedState();
    }

    /// <summary>A key picked through the platform picker (Android: a content URI with no file path).</summary>
    public void SetPickedKey(string path, Avalonia.Platform.Storage.IStorageFile? file)
    {
        if (file is not null) lock (_pickedKeys) _pickedKeys[path] = file;
        KeyPath = path;
    }

    private Func<Stream>? KeyOpenerFor(string path)
    {
        Avalonia.Platform.Storage.IStorageFile? file;
        lock (_pickedKeys) _pickedKeys.TryGetValue(path, out file);
        if (file is null || file.TryGetLocalPath() is not null) return null;   // a real path is read directly
        return () => file.OpenReadAsync().GetAwaiter().GetResult();            // called on the thread pool
    }

    /// <summary>Validates the form and connects (UI thread). Errors end up in <see cref="ConnectError"/>.</summary>
    internal async Task ConnectAsync()
    {
        if (IsConnecting || IsConnected) return;
        ConnectError = string.Empty;
        string host = Host.Trim(), user = Username.Trim(), keyPath = KeyPath.Trim();
        if (host.Length == 0) { ConnectError = "Enter the server's host name or IP."; return; }
        if (user.Length == 0) { ConnectError = "Enter the user name."; return; }
        if (Port is < 1 or > 65535) { ConnectError = "The port must be between 1 and 65535."; return; }
        if (Password.Length == 0 && keyPath.Length == 0) { ConnectError = "Enter a password or pick a key file."; return; }
        if (ConnectViaProxy && (ProxyInHost.Trim().Length == 0 || ProxyInPort is < 1 or > 65535))
        { ConnectError = "Enter the proxy's host and port, or turn the proxy off."; return; }

        HistoryService.Instance.Add("ssh.host", host);
        HistoryService.Instance.Add("ssh.user", user);

        var login = new SshLogin
        {
            Host = host, Port = Port, User = user, Password = Password,
            KeyPath = keyPath, Passphrase = KeyPassphrase, KeyOpener = keyPath.Length > 0 ? KeyOpenerFor(keyPath) : null,
            UseProxy = ConnectViaProxy, ProxyHost = ProxyInHost.Trim(), ProxyPort = ProxyInPort,
        };
        // Pin by a normalized id, so "Host", "host" and "host." share one pin: an alias spelling must not count as a
        // first use and silently trust a different key. legacyId is the as-typed key earlier builds pinned under.
        string hostId = SshHostKeyCheck.PinId(host, Port), legacyId = $"{Host}:{Port}";

        var cts = new CancellationTokenSource();
        _connectCts = cts;
        IsConnecting = true;
        AppendToTerminal($"# Connecting to {login.Endpoint} as {user}{(login.UseProxy ? $" via {SshText.Endpoint(login.ProxyHost, login.ProxyPort)}" : "")}…\n");

        SshSession? session = null;
        string? error = null;
        try { session = await Task.Run(() => OpenSessionAsync(login, hostId, legacyId, cts.Token)); }
        catch (Exception ex) { error = ex.Message; }

        bool cancelled = cts.IsCancellationRequested;
        if (ReferenceEquals(_connectCts, cts)) _connectCts = null;
        cts.Dispose();
        IsConnecting = false;

        if (session is null || cancelled)
        {
            if (session is not null) { var s = session; _ = Task.Run(() => CloseQuietly(s)); }
            else login.Dispose();
            ConnectError = cancelled ? string.Empty : error ?? "Couldn't connect.";
            AppendToTerminal($"# {(cancelled ? "Cancelled." : ConnectError)}\n");
            FlushTerminal();
            return;
        }
        BeginSession(session);
    }

    // Worker thread: authenticate (key → password → keyboard-interactive), verify the host key, open the shell.
    private async Task<SshSession> OpenSessionAsync(SshLogin login, string hostId, string legacyId, CancellationToken ct)
    {
        var log = new SshAuthLog();
        var check = new SshHostKeyCheck { HostId = hostId, LegacyId = legacyId, Note = AppendToTerminal };
        ConnectionInfo ci = login.CreateConnectionInfo(log);   // loads the key; throws SshLoginException with nothing to log in with
        var client = new SshClient(ci);
        client.HostKeyReceived += check.OnHostKey;
        try
        {
            await client.ConnectAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            try { client.Dispose(); } catch { }
            throw new SshLoginException(SshErrors.Explain(ex, login, log, check));
        }
        finally
        {
            log.Wipe();   // the password buffers: SSH.NET doesn't need them again for this connection
            foreach (var m in ci.AuthenticationMethods) { try { m.Dispose(); } catch { } }
        }
        if (login.KeyProblem is { } kp)
            AppendToTerminal($"# Key not used: {kp} Logged in with the password.\n");

        var session = new SshSession
        {
            Client = client, Login = login, HostKey = check.Received ?? Array.Empty<byte>(), HostId = hostId, LegacyId = legacyId,
            AuthUsed = log.Used == "key" && login.KeyKind.Length > 0 ? $"key ({login.KeyKind})" : log.Used,
        };
        try { session.Shell = client.CreateShellStream("vt100", 80, 24, 800, 600, 1024); }
        catch (Exception ex)
        {
            // e.g. an sftp-only account (ForceCommand internal-sftp): files and forwards still work
            AppendToTerminal($"# The server didn't open a shell: {ex.Message}\n");
        }
        return session;
    }

    // UI thread: the session is up.
    private void BeginSession(SshSession s)
    {
        _session = s;
        var login = s.Login;
        ConnectionSummary = $"{login.User}@{login.Endpoint} · {s.AuthUsed}" +
                            (login.UseProxy ? $" · via {SshText.Endpoint(login.ProxyHost, login.ProxyPort)}" : string.Empty);

        // A dropped link is reported here but doesn't always raise the Disconnected event that disposes the
        // ShellStream, so the reader would block forever while the UI still shows Disconnect and live forwards.
        s.Client.ErrorOccurred += (_, e) =>
        {
            if (!ReferenceEquals(_session, s)) return;
            AppendToTerminal($"\n# {e.Exception.Message}\n");
            _ = Task.Run(() => StopSession(s));   // never Disconnect on SSH.NET's own listener thread
        };
        IsConnected = true;

        // Dedicated thread: ShellStream.Read blocks for the whole session.
        if (s.Shell is { } shell)
            _ = Task.Factory.StartNew(() => ReadFromStream(shell, s), CancellationToken.None,
                TaskCreationOptions.LongRunning, TaskScheduler.Default);

        OnSessionStarted(s);
    }

    // Each feature resets / starts its part (files listing, forwards, health polling).
    private void OnSessionStarted(SshSession s)
    {
        StartForwardsFor(s);
        ResetFiles();
        if (FilesViewShown) _ = LoadDirAsync(string.Empty);
        UpdateHealthLoop();
    }

    // session == null: Disconnect / a failure path — tear down whatever is current. Otherwise a late callback (reader
    // exit, ErrorOccurred) only tears down the session it came from, never a newer one. Any thread.
    private void StopSession(SshSession? target)
    {
        SshSession? s;
        if (target is null) s = Interlocked.Exchange(ref _session, null);
        else if (ReferenceEquals(Interlocked.CompareExchange(ref _session, null, target), target)) s = target;
        else return;   // that session is already gone
        if (s is null)
        {
            PostDisconnectedState();   // nothing to tear down, but the UI must still return to Connect
            return;
        }
        CloseQuietly(s);
        AppendToTerminal("\n# Disconnected.\n");
        PostDisconnectedState();   // after the message, so the final flush includes it
    }

    private static void CloseQuietly(SshSession s)
    {
        s.Closed = true;
        ForwardedPort[] ports;
        try { ports = System.Linq.Enumerable.ToArray(s.Client.ForwardedPorts); }
        catch (Exception) { ports = Array.Empty<ForwardedPort>(); }
        foreach (var port in ports)
        {
            try { port.Stop(); } catch { }
        }
        try { s.Sftp?.Dispose(); } catch { }
        try { s.Shell?.Dispose(); } catch { }      // also wakes the blocked reader (Read returns 0)
        try { s.Client.Disconnect(); } catch { }
        try { s.Client.Dispose(); } catch { }
        s.Login.Dispose();
    }

    // StopSession runs on worker threads, so marshal bound state. Disconnect can block for seconds: skip the reset if a
    // newer session has been started meanwhile.
    private void PostDisconnectedState() => Dispatcher.UIThread.Post(() =>
    {
        if (_session is not null) return;
        IsConnected = false;
        ConnectionSummary = string.Empty;
        OnSessionEnded();
        // Show the tail now and stop the timer. Safe against stragglers (a late reader chunk): disarming happens under
        // the buffer lock, so their next append simply re-arms it.
        FlushTerminal(final: true);
    });

    private void OnSessionEnded()
    {
        ResetTunnelState();
        foreach (var r in Forwards) r.SetOff();
        CancelFilesWork();
        ResetFiles();
        UpdateHealthLoop();
        ResetHealth();
    }
}
