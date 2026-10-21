using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Collections;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

public enum SocketEntryKind { Sent, Received, Info, Error }

public enum SocketState { Idle, Connecting, Connected, Listening }

/// <summary>
/// One transcript entry: data sent / received (with its peer and size) or an info / error line. Immutable apart
/// from the "connect anyway" action; the display text is built once, on first use (only realized rows ever ask).
/// </summary>
public sealed partial class SocketEntry : ObservableObject
{
    /// <summary>Longest text shown for one entry (the whole data still goes to copy / save). Laying out wrapped text
    /// costs the UI thread up to ~1 s per 4,000 characters of Persian or mixed-direction text, so a peer's long
    /// message must not decide how long the window freezes.</summary>
    public const int MaxTextChars = 2_048;
    /// <summary>Persian, Arabic and other text that is mostly non-ASCII costs the layout ~0.12 ms a character (several
    /// times Latin text): such an entry shows fewer characters, so one message stays within ~50 ms.</summary>
    public const int MaxComplexTextChars = 400;
    /// <summary>Most lines shown for one entry (a message of short lines is just as costly).</summary>
    public const int MaxTextLines = 200;

    private string? _text;
    private bool? _binary;

    public SocketEntry(SocketEntryKind kind, DateTime time, byte[]? data, string? message, string? peer)
    {
        Kind = kind;
        Time = time;
        Data = data;
        Message = message;
        Peer = peer;
        LastChunk = time;
    }

    public SocketEntryKind Kind { get; }
    public DateTime Time { get; }
    public byte[]? Data { get; }
    public string? Message { get; }
    /// <summary>Who it came from / went to in the server modes ("10.0.0.5:51234", "all 3 clients").</summary>
    public string? Peer { get; }

    // TCP chunks arriving back to back are merged into one entry
    internal SocketPeer? PeerRef { get; init; }
    internal DateTime LastChunk { get; init; }

    /// <summary>SHA-256 of a rejected TLS certificate: the entry offers "Connect anyway".</summary>
    public string? CertSha256 { get; init; }
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasAction))] private bool _actionUsed;
    public bool HasAction => CertSha256 != null && !ActionUsed;

    /// <summary>WebSocket frame kind ("text", "bin", "ping", "pong"); null for TCP / UDP data and notes.</summary>
    public string? Tag { get; init; }
    /// <summary>A muted line under the data: a ping's round trip, "3 frames", "first 4 MB of 9 MB".</summary>
    public string? Detail { get; init; }
    /// <summary>Shown as hex whatever it contains (a WebSocket binary message).</summary>
    public bool ForceBinary { get; init; }

    public bool IsSent => Kind == SocketEntryKind.Sent;
    public bool IsReceived => Kind == SocketEntryKind.Received;
    public bool IsInfo => Kind == SocketEntryKind.Info;
    public bool IsError => Kind == SocketEntryKind.Error;
    public bool IsData => Data != null;
    public bool IsNote => Data == null;
    public bool HasPeer => !string.IsNullOrEmpty(Peer);
    public bool HasTag => !string.IsNullOrEmpty(Tag);
    public bool IsControlFrame => Tag is "ping" or "pong";
    public bool HasDetail => !string.IsNullOrEmpty(Detail);

    public string TimeText => Time.ToString("HH:mm:ss.fff", CultureInfo.InvariantCulture);
    public string Arrow => Kind switch
    {
        SocketEntryKind.Sent => "→",
        SocketEntryKind.Received => "←",
        SocketEntryKind.Error => "!",
        _ => "·",
    };
    public string SizeText => Data != null ? SocketPayload.FormatBytes(Data.Length) : string.Empty;
    public int DataLength => Data?.Length ?? 0;

    /// <summary>Binary-looking data shows as a hex dump even in the text view.</summary>
    public bool LooksBinary => _binary ??= Data is { Length: > 0 } && (ForceBinary || !SocketPayload.LooksLikeText(Data));

    public string Text => _text ??= BuildText();

    private string BuildText()
    {
        if (Data == null) return Message ?? string.Empty;
        if (Data.Length == 0) return Tag is "ping" or "pong" ? "(no payload)" : "(empty)";
        string t = SocketPayload.ToDisplayText(Data, IsMostlyNonAscii(Data) ? MaxComplexTextChars : MaxTextChars, out int shown, MaxTextLines);
        if (t.Length == 0) return Data.Length <= 2 ? "(line break)" : "(line breaks)";
        if (shown < Data.Length) t += $"\n… {SocketPayload.FormatBytes(Data.Length - shown)} more — copy or save the transcript for all of it";
        return t;
    }

    // judged on the part an entry can show at most: over a quarter of the bytes are UTF-8 sequences
    private static bool IsMostlyNonAscii(byte[] d)
    {
        int n = Math.Min(d.Length, MaxTextChars * 2), high = 0;
        for (int i = 0; i < n; i++) if (d[i] >= 0x80) high++;
        return high * 4 > n;
    }

    internal SocketEntry Merge(byte[] more, DateTime at)
    {
        var all = new byte[Data!.Length + more.Length];
        Buffer.BlockCopy(Data, 0, all, 0, Data.Length);
        Buffer.BlockCopy(more, 0, all, Data.Length, more.Length);
        return new SocketEntry(Kind, Time, all, Message, Peer) { PeerRef = PeerRef, LastChunk = at };
    }
}

/// <summary>A row of the server modes' client / sender list; the first row (no peer) means "all clients" / "last sender".</summary>
public sealed partial class SocketPeerRow : ObservableObject
{
    public SocketPeerRow(SocketPeer? peer, string label, bool canDisconnect)
    {
        Peer = peer;
        _label = label;
        CanDisconnect = canDisconnect;
    }

    public SocketPeer? Peer { get; }
    [ObservableProperty] private string _label;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ComboSuffix), nameof(HasDetail))]
    private string _detail = string.Empty;
    public bool IsAll => Peer == null;
    public bool HasDetail => Detail.Length > 0;
    /// <summary>The phone's picker shows one line: "Last sender · 10.0.0.5:5353".</summary>
    public string ComboSuffix => IsAll && Detail.Length > 0 ? " · " + Detail : string.Empty;
    public bool CanDisconnect { get; }
    public override string ToString() => Label;
}

/// <summary>
/// The Socket tool — a netcat-like TCP / UDP client and server, plus a WebSocket client (SocketViewModel.WebSocket.cs). Sessions run on socket threads and only queue what
/// happens; a 100 ms UI timer drains the queue in one batch (TCP chunks that arrive back to back become one entry),
/// so a flood never posts a UI job per packet. The transcript is capped (entries and bytes) and virtualized.
/// </summary>
public partial class SocketViewModel : ObservableObject
{
    private const string KMode = "socket.mode", KPort = "socket.port", KListenPort = "socket.listenPort",
        KBind = "socket.bind", KTls = "socket.tls", KHex = "socket.hex", KEol = "socket.eol", KView = "socket.view";
    private const string HTarget = "socket.target";

    private const int MaxEntries = 2000;
    private const long MaxRetainedBytes = 16L * 1024 * 1024;
    private const long MaxPendingBytes = 8L * 1024 * 1024;
    // Events one 100 ms tick takes: each becomes a transcript row, and adding / trimming thousands of rows a tick kept
    // the UI thread busy longer than the tick itself under a flood (the rest is counted in the "Skipped" note).
    private const int MaxQueuedEvents = 300;
    private const int MergeLimit = 64 * 1024;
    private const double MergeWindowMs = 150;

    private readonly bool _restoring;

    // ---------------- settings ----------------
    /// <summary>0 TCP client · 1 TCP server · 2 UDP client · 3 UDP server · 4 WebSocket client.</summary>
    [ObservableProperty] private int _modeIndex;
    [ObservableProperty] private string _host = string.Empty;
    [ObservableProperty] private string _port = string.Empty;
    [ObservableProperty] private bool _useTls;
    [ObservableProperty] private string _listenPort = "9000";
    [ObservableProperty] private BindOption? _selectedBind;
    public ObservableCollection<BindOption> BindOptions { get; } = new();
    public ObservableCollection<string> TargetHistory => HistoryService.Instance.Get(HTarget);

    // ---------------- session ----------------
    [ObservableProperty] private SocketState _state;
    [ObservableProperty] private string _statusText = "Not connected";
    [ObservableProperty] private string _trafficText = string.Empty;

    // ---------------- transcript + send box ----------------
    public AvaloniaList<SocketEntry> Entries { get; } = new() { ResetBehavior = ResetBehavior.Reset };
    public ObservableCollection<SocketPeerRow> Peers { get; } = new();
    [ObservableProperty] private SocketPeerRow? _selectedPeer;
    [ObservableProperty] private string _input = string.Empty;
    [ObservableProperty] private bool _inputIsHex;
    [ObservableProperty] private int _lineEndingIndex = 1;
    /// <summary>0 text (hex for binary data) · 1 hex · 2 both.</summary>
    [ObservableProperty] private int _viewIndex;
    [ObservableProperty] private string? _inputError;

    public string[] LineEndings { get; } = { "None", "LF", "CRLF" };

    private TcpClientSession? _tcpClient;
    private TcpServerSession? _tcpServer;
    private UdpClientSession? _udpClient;
    private UdpServerSession? _udpServer;
    private int _sessionMode;
    private CancellationTokenSource? _connectCts;
    private int _gen;
    private bool _guardHeld;
    private SocketPeer? _lastSender;

    private readonly ConcurrentQueue<Ev> _queue = new();
    private long _pendingBytes, _droppedBytes;
    private int _droppedChunks;
    // 100 ms while data flows, once a second when quiet (the peers' idle times and the traffic line still move)
    private PacedTimer? _timer;
    private long _sentBytes, _recvBytes, _retainedBytes;
    private int _trimmedEntries;
    private string? _lastTraffic;

    private readonly List<string> _sendHistory = new();
    private int _historyIndex = -1;

    public SocketViewModel()
    {
        _restoring = true;
        var p = ProfileService.Instance;
        ModeIndex = Math.Clamp(p.GetInt(KMode, 0), 0, 4);
        UseTls = p.GetBool(KTls);
        InputIsHex = p.GetBool(KHex);
        InputIsJson = !InputIsHex && ModeIndex == 4 && p.GetBool(KJson);
        RestoreWsSettings(p);
        LineEndingIndex = Math.Clamp(p.GetInt(KEol, 1), 0, 2);
        ViewIndex = Math.Clamp(p.GetInt(KView, 0), 0, 2);
        ListenPort = p.GetSetting(KListenPort) is { Length: > 0 } lp ? lp : "9000";
        Port = p.GetSetting(KPort) ?? string.Empty;
        if (HistoryService.Instance.Last(HTarget) is { } last && SplitTarget(last, out var h, out int pt))
        {
            Host = h;
            if (pt > 0) Port = pt.ToString(CultureInfo.InvariantCulture);
        }
        RebuildBindOptions(p.GetSetting(KBind));
        _restoring = false;
        ResetPeers();
        UpdateIdleStatus();
        UpdateTraffic();
    }

    // ================================================================ derived state

    public bool IsClientMode => ModeIndex is 0 or 2;
    public bool IsServerMode => ModeIndex is 1 or 3;
    public bool IsTcpClientMode => ModeIndex == 0;
    public bool IsTcpServerMode => ModeIndex == 1;
    public bool IsUdpServerMode => ModeIndex == 3;

    public bool IsIdle => State == SocketState.Idle;
    public bool IsBusy => State == SocketState.Connecting;
    public bool IsActive => State is SocketState.Connected or SocketState.Listening;
    public bool IsRunning => State != SocketState.Idle;
    public bool CanSend => IsActive && !_wsClosing;

    public bool IsHexView => ViewIndex == 1;
    public bool IsBothView => ViewIndex == 2;
    public bool HasEntries => Entries.Count > 0;

    /// <summary>The main button: Connect / Listen, Cancel while connecting, Disconnect / Stop while running.</summary>
    public string ActionText => State switch
    {
        SocketState.Connecting => "Cancel",
        SocketState.Connected => "Disconnect",
        SocketState.Listening => "Stop",
        _ => IsServerMode ? "Listen" : "Connect",
    };

    public string PeersTitle => IsUdpServerMode ? "Senders" : "Clients";
    public int PeerCount => Math.Max(0, Peers.Count - 1);

    public string EmptyTitle => ModeIndex switch
    {
        1 => "Not listening",
        3 => "Not listening",
        _ => "Not connected",
    };

    public string EmptyHint => ModeIndex switch
    {
        1 => "Listen, then connect, e.g. nc <this IP> <port>.",
        2 => "Pick a host and port; datagrams and replies show up here.",
        3 => "Listen on a port; datagrams show up with their sender.",
        4 => "Connect to a ws:// or wss:// URL; messages show up here.",
        _ => "Connect to a host and port; traffic shows up here.",
    };

    partial void OnModeIndexChanged(int value)
    {
        OnPropertyChanged(nameof(IsClientMode));
        OnPropertyChanged(nameof(IsServerMode));
        OnPropertyChanged(nameof(IsTcpClientMode));
        OnPropertyChanged(nameof(IsTcpServerMode));
        OnPropertyChanged(nameof(IsUdpServerMode));
        OnPropertyChanged(nameof(IsWsMode));
        OnPropertyChanged(nameof(ShowLineEnding));
        OnPropertyChanged(nameof(ShowJsonFormat));
        OnPropertyChanged(nameof(ShowWsOptions));
        OnPropertyChanged(nameof(InputPlaceholder));
        if (value != 4 && InputIsJson && !_restoring && State == SocketState.Idle) InputIsJson = false;
        OnPropertyChanged(nameof(ActionText));
        OnPropertyChanged(nameof(PeersTitle));
        OnPropertyChanged(nameof(EmptyTitle));
        OnPropertyChanged(nameof(EmptyHint));
        if (_restoring) return;
        if (State != SocketState.Idle && value != _sessionMode)
        {
            // the mode can't change under a running session (the switch is disabled then; this guards any other
            // path that writes the index): put it back
            Dispatcher.UIThread.Post(() => { if (State != SocketState.Idle) ModeIndex = _sessionMode; });
            return;
        }
        ProfileService.Instance.SetSetting(KMode, value.ToString(CultureInfo.InvariantCulture));
        InputError = null;
        if (IsServerMode) RebuildBindOptions(ProfileService.Instance.GetSetting(KBind));
        ResetPeers();
        UpdateIdleStatus();
    }

    partial void OnStateChanged(SocketState value)
    {
        OnPropertyChanged(nameof(IsIdle));
        OnPropertyChanged(nameof(IsBusy));
        OnPropertyChanged(nameof(IsActive));
        OnPropertyChanged(nameof(IsRunning));
        OnPropertyChanged(nameof(CanSend));
        OnPropertyChanged(nameof(CanPing));
        OnPropertyChanged(nameof(ShowWsOptions));
        OnPropertyChanged(nameof(ActionText));
        if (value == SocketState.Idle) UpdateIdleStatus();
    }

    /// <summary>The send box's Text / Hex (/ JSON in WebSocket mode) switch.</summary>
    public int InputModeIndex
    {
        get => InputIsHex ? 1 : InputIsJson ? 2 : 0;
        set
        {
            if (value is < 0 or > 2) return;
            if (value == 2 && !IsWsMode) value = 0;
            InputIsHex = value == 1;
            InputIsJson = value == 2;
        }
    }

    public string InputPlaceholder => InputIsHex
        ? IsWsMode ? "Hex, e.g. 48 65 6c 6c 6f" : "Hex, e.g. 48 65 6c 6c 6f 0d 0a"
        : InputIsJson && IsWsMode ? "JSON, e.g. {\"type\":\"ping\"}"
        : AppPlatform.IsMobile ? "Message" : "Message (Enter sends)";

    partial void OnUseTlsChanged(bool value) { if (!_restoring) ProfileService.Instance.SetBool(KTls, value); }

    partial void OnInputIsHexChanged(bool value)
    {
        OnPropertyChanged(nameof(InputModeIndex));
        OnPropertyChanged(nameof(InputPlaceholder));
        OnPropertyChanged(nameof(ShowLineEnding));
        if (!_restoring) ProfileService.Instance.SetBool(KHex, value);
        InputError = null;
    }

    partial void OnInputIsJsonChanged(bool value)
    {
        OnPropertyChanged(nameof(InputModeIndex));
        OnPropertyChanged(nameof(InputPlaceholder));
        OnPropertyChanged(nameof(ShowJsonFormat));
        if (!_restoring) ProfileService.Instance.SetBool(KJson, value);
        InputError = null;
    }
    partial void OnLineEndingIndexChanged(int value) { if (!_restoring) ProfileService.Instance.SetSetting(KEol, value.ToString(CultureInfo.InvariantCulture)); }
    partial void OnInputChanged(string value) { if (InputError != null) InputError = null; }

    partial void OnViewIndexChanged(int value)
    {
        OnPropertyChanged(nameof(IsHexView));
        OnPropertyChanged(nameof(IsBothView));
        if (!_restoring) ProfileService.Instance.SetSetting(KView, value.ToString(CultureInfo.InvariantCulture));
    }

    partial void OnSelectedBindChanged(BindOption? value)
    {
        if (_restoring || _rebuildingBinds || value is null) return;
        ProfileService.Instance.SetSetting(KBind, value.Kind == "iface" ? value.Address.ToString() : value.Kind);
    }

    private void UpdateIdleStatus()
    {
        if (State != SocketState.Idle) return;
        StatusText = IsServerMode ? "Not listening" : "Not connected";
    }

    // ================================================================ bind options

    private bool _rebuildingBinds;

    /// <summary>All interfaces (one dual-stack socket), this device only, or one interface's IPv4 address.</summary>
    public void RebuildBindOptions(string? preferred = null)
    {
        string? want = preferred ?? (SelectedBind is { } cur ? (cur.Kind == "iface" ? cur.Address.ToString() : cur.Kind) : null);
        var list = new List<BindOption>
        {
            new("All interfaces (IPv4 + IPv6)", IPAddress.IPv6Any, "all"),
            new("This device only (127.0.0.1)", IPAddress.Loopback, "loopback"),
        };
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                    if (ua.Address.AddressFamily == AddressFamily.InterNetwork)
                        list.Add(new BindOption($"{ua.Address}  ({ni.Name})", ua.Address, "iface"));
            }
        }
        catch { /* restricted platform: all + loopback are enough */ }

        _rebuildingBinds = true;
        try
        {
            BindOptions.Clear();
            foreach (var o in list) BindOptions.Add(o);
            // a picked interface that went away: this device only, never all interfaces behind the user's back
            SelectedBind = BindOptions.FirstOrDefault(o => o.Kind != "iface" ? o.Kind == want : o.Address.ToString() == want)
                           ?? (IPAddress.TryParse(want, out _) ? BindOptions.First(o => o.Kind == "loopback") : BindOptions[0]);
        }
        finally { _rebuildingBinds = false; }
    }

    // ================================================================ start / stop

    [RelayCommand(AllowConcurrentExecutions = true)]   // the same button cancels / stops while it runs
    private async Task ToggleSession()
    {
        switch (State)
        {
            case SocketState.Idle: await StartAsync(null); break;
            case SocketState.Connecting: _connectCts?.Cancel(); break;
            default: Stop(); break;
        }
    }

    /// <summary>Retry the TLS connection, accepting exactly the certificate this entry reported.</summary>
    [RelayCommand]
    private async Task ConnectAnyway(SocketEntry? entry)
    {
        if (entry?.CertSha256 is not { } sha || State != SocketState.Idle) return;
        entry.ActionUsed = true;
        await StartAsync(sha);
    }

    private async Task StartAsync(string? acceptSha)
    {
        InputError = null;
        int mode = ModeIndex;
        int gen = ++_gen;
        var sink = new Sink(this, gen);
        _sessionMode = mode;
        _lastSender = null;

        if (mode == 4)
        {
            await StartWsAsync(gen, acceptSha);
            return;
        }

        if (mode is 0 or 2)
        {
            if (!TryTarget(out string host, out int port, out string? error)) { AddNote(SocketEntryKind.Error, error!); return; }
            string target = SocketNet.Target(host, port);
            bool tls = mode == 0 && UseTls;
            State = SocketState.Connecting;
            StatusText = $"Connecting to {(mode == 2 ? "udp " : "")}{target}…";
            AddNote(SocketEntryKind.Info, mode == 2
                ? $"Opening udp {target}…"
                : $"Connecting to {target}{(tls ? " with TLS" : "")}{(acceptSha != null ? " (accepting the certificate you allowed)" : "")}…");
            _connectCts = new CancellationTokenSource();
            try
            {
                if (mode == 0)
                {
                    var s = await TcpClientSession.ConnectAsync(host, port,
                        new TcpConnectOptions { UseTls = tls, AcceptCertSha256 = acceptSha }, sink, _connectCts.Token);
                    if (gen != _gen) { s.Close(); return; }
                    _tcpClient = s;
                    State = SocketState.Connected;
                    string tlsText = s.TlsDescription is { } d ? " · " + d : string.Empty;
                    string warn = s.CertificateOverridden ? " · untrusted certificate (you allowed it)" : string.Empty;
                    StatusText = $"Connected to {SocketNet.Label(s.Remote)}{tlsText}{warn}";
                    AddNote(SocketEntryKind.Info, $"Connected to {SocketNet.Label(s.Remote)} from local port {s.Local.Port}{tlsText}{warn}.");
                    s.Start();
                }
                else
                {
                    var u = await UdpClientSession.OpenAsync(host, port, sink, _connectCts.Token);
                    if (gen != _gen) { u.Close(); return; }
                    _udpClient = u;
                    State = SocketState.Connected;
                    StatusText = $"Ready · udp {SocketNet.Label(u.Remote)} from local port {u.Local.Port}";
                    AddNote(SocketEntryKind.Info, $"Ready — datagrams go to udp {SocketNet.Label(u.Remote)} from local port {u.Local.Port}; replies show up here.");
                    u.Start();
                }
                HistoryService.Instance.Add(HTarget, target);
                ProfileService.Instance.SetSetting(KPort, port.ToString(CultureInfo.InvariantCulture));
                SessionStarted();
            }
            catch (SocketFailure f) when (f.CertSha256 != null)
            {
                if (gen != _gen) return;
                State = SocketState.Idle;
                Commit(new List<SocketEntry> { new(SocketEntryKind.Error, DateTime.Now, null, f.Message, null) { CertSha256 = f.CertSha256 } });
            }
            catch (OperationCanceledException)
            {
                if (gen != _gen) return;
                State = SocketState.Idle;
                AddNote(SocketEntryKind.Info, "Canceled.");
            }
            catch (Exception ex)
            {
                if (gen != _gen) return;
                State = SocketState.Idle;
                AddNote(SocketEntryKind.Error, ex is SocketFailure ? ex.Message : SocketErrors.Describe(ex, SocketAction.Connect, target, port));
            }
            finally
            {
                _connectCts?.Dispose();
                _connectCts = null;
            }
            return;
        }

        // ---- server modes
        if (!TryPort(ListenPort, out int lport, out string? perr)) { AddNote(SocketEntryKind.Error, perr!); return; }
        var bind = SelectedBind ?? BindOptions.FirstOrDefault() ?? new BindOption("All interfaces", IPAddress.IPv6Any, "all");
        string where = bind.Kind switch
        {
            "all" => $"port {lport} on all interfaces (IPv4 + IPv6)",
            "loopback" => $"127.0.0.1:{lport} (this device only)",
            _ => $"{bind.Address}:{lport}",
        };
        string example = bind.Kind == "iface" ? bind.Address.ToString() : "127.0.0.1";
        try
        {
            if (mode == 1)
            {
                var srv = TcpServerSession.Listen(bind.Address, lport, sink);
                _tcpServer = srv;
                State = SocketState.Listening;
                AddNote(SocketEntryKind.Info, $"Listening on {where} — try: nc {example} {lport}");
                srv.Start();
            }
            else
            {
                var srv = UdpServerSession.Listen(bind.Address, lport, sink);
                _udpServer = srv;
                State = SocketState.Listening;
                AddNote(SocketEntryKind.Info, $"Listening on udp {where} — try: nc -u {example} {lport}");
                srv.Start();
            }
            ProfileService.Instance.SetSetting(KListenPort, lport.ToString(CultureInfo.InvariantCulture));
            ResetPeers();
            SessionStarted();
            UpdateServerStatus();
        }
        catch (Exception ex)
        {
            _tcpServer = null;
            _udpServer = null;
            State = SocketState.Idle;
            AddNote(SocketEntryKind.Error, SocketErrors.Describe(ex, SocketAction.Listen, mode == 3 ? "udp " + where : where, lport));
        }
    }

    private void SessionStarted()
    {
        if (!_guardHeld) { BackgroundGuard.Acquire("Socket session"); _guardHeld = true; }
        _timer ??= new PacedTimer(100, 1000, Drain);
        _timer.Start();
    }

    /// <summary>The user stopped the session: show what already arrived, then close quietly.</summary>
    private void Stop()
    {
        Drain();
        if (State == SocketState.Idle) return;   // it had just ended by itself (the drain said why)
        if (_sessionMode == 4 && BeginWsClose()) return;   // the close handshake reports the end
        int clients = _tcpServer?.ClientCount ?? 0;
        int mode = _sessionMode;
        CloseSessions();
        _gen++;   // anything a closing socket still queues is ignored
        State = SocketState.Idle;
        AddNote(SocketEntryKind.Info, mode switch
        {
            1 => clients > 0 ? $"Stopped listening — {Plural(clients, "client")} disconnected." : "Stopped listening.",
            3 => "Stopped listening.",
            _ => "Disconnected.",
        });
        SessionEnded();
    }

    private void CloseSessions()
    {
        try { _connectCts?.Cancel(); } catch { }
        _tcpClient?.Close();
        _tcpServer?.Stop();
        _udpClient?.Close();
        _udpServer?.Stop();
        _ws?.Connection.Abort();
        _tcpClient = null;
        _tcpServer = null;
        _udpClient = null;
        _udpServer = null;
        _ws = null;
        if (_wsClosing)
        {
            _wsClosing = false;
            OnPropertyChanged(nameof(CanSend));
        }
    }

    private void SessionEnded()
    {
        _timer?.Stop();
        if (_guardHeld) { BackgroundGuard.Release(); _guardHeld = false; }
        _lastSender = null;
        ResetPeers();
        UpdateTraffic();
    }

    // ================================================================ sending

    [RelayCommand(AllowConcurrentExecutions = true)]   // Enter keeps sending while a slow write is pending (writes queue in order)
    private async Task Send()
    {
        InputError = null;
        if (!IsActive)
        {
            InputError = IsServerMode ? "Start listening first." : "Connect first.";
            return;
        }
        if (_sessionMode == 4)
        {
            await SendWsInputAsync();
            return;
        }
        byte[] data;
        try
        {
            data = InputIsHex ? SocketPayload.FromHex(Input) : SocketPayload.FromText(Input, (LineEnding)LineEndingIndex);
        }
        catch (FormatException fe)
        {
            InputError = fe.Message;
            return;
        }
        if (data.Length == 0)
        {
            InputError = InputIsHex ? "Type the bytes to send, e.g. 48 65 6c 6c 6f." : "Type something to send — or pick a line ending to send an empty line.";
            return;
        }
        if (!TryResolveTarget(out var target, out var label)) return;
        // the box empties now, not after the write: a slow peer (full TCP window) mustn't eat what's typed meanwhile
        RememberInput(Input);
        Input = string.Empty;
        await SendTo(target, label, data);
    }

    /// <summary>Sends an earlier message's exact bytes again (the transcript's context menu).</summary>
    public async Task Resend(SocketEntry entry)
    {
        if (_sessionMode == 4)
        {
            if (entry.Data is { } d && entry.Tag is "text" or "bin" && CanSend) await SendWsAsync(d, entry.Tag == "bin");
            return;
        }
        if (entry.Data is { Length: > 0 } data && IsActive && TryResolveTarget(out var target, out var label))
            await SendTo(target, label, data);
    }

    // Who a message goes to: the one remote (clients), the picked / every client (TCP server), the picked / last
    // sender (UDP server). False when there is nobody (InputError says why).
    private bool TryResolveTarget(out SocketPeer? target, out string? label)
    {
        target = null;
        label = null;
        switch (_sessionMode)
        {
            case 1:
            {
                if (SelectedPeer?.Peer is { } p)
                {
                    if (!p.IsOpen) { InputError = $"{p.Label} has disconnected."; return false; }
                    target = p;
                    label = p.Label;
                }
                else
                {
                    var clients = _tcpServer?.Clients ?? Array.Empty<SocketPeer>();
                    if (clients.Count == 0) { InputError = "No clients are connected yet."; return false; }
                    label = clients.Count == 1 ? clients.First().Label : $"all {clients.Count} clients";
                }
                break;
            }
            case 3:
                target = SelectedPeer?.Peer ?? _lastSender;
                if (target == null) { InputError = "Nobody has sent a datagram yet — replies go to the last sender, or the one picked in the list."; return false; }
                label = target.Label;
                break;
        }
        return true;
    }

    private async Task SendTo(SocketPeer? target, string? label, byte[] data)
    {
        Drain();
        _timer?.Wake();   // the reply should show at the fast pace

        Commit(new List<SocketEntry> { new(SocketEntryKind.Sent, DateTime.Now, data, null, label) });
        _sentBytes += data.Length;

        switch (_sessionMode)
        {
            case 0 when _tcpClient is { } c: await c.SendAsync(data); break;
            case 1 when _tcpServer is { } s: await s.SendAsync(target, data); break;
            case 2 when _udpClient is { } u: await u.SendAsync(data); break;
            case 3 when _udpServer is { } us && target != null: await us.SendToAsync(target, data); break;
        }
        Drain();   // a send error shows right away
    }

    /// <summary>After the view saved the transcript: one line saying where, or why it failed.</summary>
    public void ReportSaved(string? fileName, string? error)
        => AddNote(error == null ? SocketEntryKind.Info : SocketEntryKind.Error,
                   error == null ? $"Transcript saved to {fileName}." : "Couldn't save the transcript: " + error);

    private void RememberInput(string text)
    {
        if (string.IsNullOrEmpty(text)) return;
        _sendHistory.Remove(text);
        _sendHistory.Add(text);
        if (_sendHistory.Count > 50) _sendHistory.RemoveAt(0);
        _historyIndex = -1;
    }

    /// <summary>Up: the previous message sent (like a shell). True when it changed the input.</summary>
    public bool HistoryUp()
    {
        if (_sendHistory.Count == 0) return false;
        _historyIndex = _historyIndex < 0 ? _sendHistory.Count - 1 : Math.Max(0, _historyIndex - 1);
        Input = _sendHistory[_historyIndex];
        return true;
    }

    public bool HistoryDown()
    {
        if (_historyIndex < 0) return false;
        if (_historyIndex >= _sendHistory.Count - 1) { _historyIndex = -1; Input = string.Empty; return true; }
        _historyIndex++;
        Input = _sendHistory[_historyIndex];
        return true;
    }

    // ================================================================ peers

    private void ResetPeers()
    {
        Peers.Clear();
        if (IsServerMode)
            Peers.Add(new SocketPeerRow(null, IsUdpServerMode ? "Last sender" : "All clients", false));
        SelectedPeer = Peers.FirstOrDefault();
        OnPropertyChanged(nameof(PeerCount));
    }

    [RelayCommand]
    private void DisconnectPeer(SocketPeerRow? row)
    {
        if (row?.Peer is { } p && _tcpServer is { } s) s.Disconnect(p);
    }

    private void UpdatePeerRows()
    {
        foreach (var row in Peers)
        {
            if (row.Peer is not { } p)
            {
                int n = Peers.Count - 1;
                if (IsUdpServerMode)
                {
                    row.Label = "Last sender";
                    row.Detail = _lastSender?.Label ?? "nobody yet";
                }
                else row.Label = n > 0 ? $"All clients ({n})" : "All clients";
                continue;
            }
            string d = $"↓ {SocketPayload.FormatBytes(p.BytesIn)} · ↑ {SocketPayload.FormatBytes(p.BytesOut)}";
            if (row.Detail != d) row.Detail = d;
        }
    }

    private void UpdateServerStatus()
    {
        if (State != SocketState.Listening) return;
        int n = Math.Max(0, Peers.Count - 1);
        if (_tcpServer is { } t)
            StatusText = $"Listening on {ListenLabel(t.LocalEndPoint)} · {Plural(n, "client")}";
        else if (_udpServer is { } u)
            StatusText = $"Listening on udp {ListenLabel(u.LocalEndPoint)} · {Plural(n, "sender")}";
    }

    private static string ListenLabel(IPEndPoint ep)
        => ep.Address.Equals(IPAddress.IPv6Any) || ep.Address.Equals(IPAddress.Any) ? $"port {ep.Port}" : SocketNet.Label(ep);

    // ================================================================ queue → transcript

    private enum EvKind { Received, Info, Error, PeerJoined, PeerLeft, Ended, WsData }

    /// <summary>A queued event. WebSocket frames (WsData) carry their kind in <see cref="Tag"/>, a round trip / frame
    /// count in <see cref="Detail"/>, and <see cref="Flag"/> = binary. <see cref="Until"/>: the last chunk's time when
    /// the drain joined several reads into one.</summary>
    private sealed record Ev(EvKind Kind, int Gen, SocketPeer? Peer, byte[]? Data, string? Text, bool Flag, DateTime Time,
                             string? Tag = null, string? Detail = null, DateTime? Until = null);

    /// <summary>Per-session sink: events of a session the user already closed carry an old generation and are dropped.</summary>
    private sealed class Sink : ISocketSink
    {
        private readonly SocketViewModel _vm;
        private readonly int _gen;
        public Sink(SocketViewModel vm, int gen) { _vm = vm; _gen = gen; }

        public void OnReceived(SocketPeer? peer, byte[] data) => _vm.EnqueueData(new Ev(EvKind.Received, _gen, peer, data, null, false, DateTime.Now));
        public void OnInfo(string text) => _vm._queue.Enqueue(new Ev(EvKind.Info, _gen, null, null, text, false, DateTime.Now));
        public void OnError(string text) => _vm._queue.Enqueue(new Ev(EvKind.Error, _gen, null, null, text, false, DateTime.Now));
        public void OnPeerJoined(SocketPeer peer) => _vm._queue.Enqueue(new Ev(EvKind.PeerJoined, _gen, peer, null, null, false, DateTime.Now));
        public void OnPeerLeft(SocketPeer peer, string? reason) => _vm._queue.Enqueue(new Ev(EvKind.PeerLeft, _gen, peer, null, reason, false, DateTime.Now));
        public void OnEnded(string reason, bool isError) => _vm._queue.Enqueue(new Ev(EvKind.Ended, _gen, null, null, reason, isError, DateTime.Now));
    }

    // socket threads: a reader far ahead of the UI only counts what it can't queue
    private void EnqueueData(Ev ev)
    {
        int len = ev.Data!.Length;
        // A flood of tiny datagrams / reads barely moves the byte cap below (1-byte packets would queue millions of
        // events before it trips): count them too.
        if (_queue.Count >= MaxQueuedEvents)
        {
            Interlocked.Add(ref _droppedBytes, len);
            Interlocked.Increment(ref _droppedChunks);
            return;
        }
        if (Interlocked.Add(ref _pendingBytes, len) > MaxPendingBytes)
        {
            Interlocked.Add(ref _pendingBytes, -len);
            Interlocked.Add(ref _droppedBytes, len);
            Interlocked.Increment(ref _droppedChunks);
            return;
        }
        _queue.Enqueue(ev);
    }

    /// <summary>UI thread: moves everything queued into the transcript in one batch. True when anything was queued.</summary>
    internal bool Drain()
    {
        List<SocketEntry>? batch = null;
        bool peersChanged = false;
        List<Ev>? evs = null;
        while (_queue.TryDequeue(out var e)) (evs ??= new List<Ev>()).Add(e);
        if (evs is { Count: > 1 } && _sessionMode is 0 or 1) JoinReads(evs);
        int count = evs?.Count ?? 0;
        // A client that connects AND leaves within one batch never gets a list row (its notes still go to the
        // transcript): a connect/close flood would otherwise add and remove a ListBox row per connection on the UI thread.
        HashSet<SocketPeer>? goneInBatch = null;
        for (int k = 0; k < count; k++)
            if (evs![k] is { Kind: EvKind.PeerLeft } e && e.Gen == _gen) (goneInBatch ??= new()).Add(e.Peer!);
        for (int k = 0; k < count; k++)
        {
            var ev = evs![k];
            if (ev.Data != null) Interlocked.Add(ref _pendingBytes, -ev.Data.Length);
            if (ev.Gen != _gen) continue;
            batch ??= new List<SocketEntry>();
            switch (ev.Kind)
            {
                case EvKind.Received:
                    _recvBytes += ev.Data!.Length;
                    if (ev.Peer != null && _sessionMode == 3) _lastSender = ev.Peer;
                    AddReceived(batch, ev);
                    break;
                case EvKind.WsData:
                    if (ev.Tag is "text" or "bin") _recvBytes += ev.Data!.Length;
                    batch.Add(new SocketEntry(SocketEntryKind.Received, ev.Time, ev.Data, null, null)
                        { Tag = ev.Tag, Detail = ev.Detail, ForceBinary = ev.Flag });
                    break;
                case EvKind.Info:
                    batch.Add(new SocketEntry(SocketEntryKind.Info, ev.Time, null, ev.Text, null));
                    break;
                case EvKind.Error:
                    batch.Add(new SocketEntry(SocketEntryKind.Error, ev.Time, null, ev.Text, null));
                    break;
                case EvKind.PeerJoined:
                    if (goneInBatch?.Contains(ev.Peer!) != true)
                    {
                        Peers.Add(new SocketPeerRow(ev.Peer, ev.Peer!.Label, _sessionMode == 1));
                        peersChanged = true;
                    }
                    if (_sessionMode == 1) batch.Add(new SocketEntry(SocketEntryKind.Info, ev.Time, null, $"{ev.Peer!.Label} connected.", null));
                    break;
                case EvKind.PeerLeft:
                {
                    var row = Peers.FirstOrDefault(r => ReferenceEquals(r.Peer, ev.Peer));
                    if (row != null)
                    {
                        if (ReferenceEquals(SelectedPeer, row)) SelectedPeer = Peers.FirstOrDefault();
                        Peers.Remove(row);
                        peersChanged = true;
                    }
                    if (ReferenceEquals(_lastSender, ev.Peer)) _lastSender = null;
                    if (ev.Text != null) batch.Add(new SocketEntry(SocketEntryKind.Info, ev.Time, null, $"{ev.Peer!.Label} {ev.Text}.", null));
                    break;
                }
                case EvKind.Ended:
                    batch.Add(new SocketEntry(ev.Flag ? SocketEntryKind.Error : SocketEntryKind.Info, ev.Time, null, ev.Text, null));
                    CloseSessions();
                    _gen++;
                    State = SocketState.Idle;
                    SessionEnded();
                    break;
            }
        }

        int dropped = Interlocked.Exchange(ref _droppedChunks, 0);
        if (dropped > 0)
        {
            long bytes = Interlocked.Exchange(ref _droppedBytes, 0);
            _recvBytes += bytes;
            (batch ??= new List<SocketEntry>()).Add(new SocketEntry(SocketEntryKind.Info, DateTime.Now, null,
                $"Skipped {SocketPayload.FormatBytes(bytes)} ({Plural(dropped, "read")}) that arrived faster than the transcript can show — the ↓ counter includes it.", null));
        }

        if (batch is { Count: > 0 }) Commit(batch);
        if (peersChanged) OnPropertyChanged(nameof(PeerCount));
        if (IsServerMode && Peers.Count > 0) UpdatePeerRows();
        UpdateServerStatus();
        UpdateTraffic();
        return count > 0 || dropped > 0;
    }

    // TCP is a byte stream: chunks of the same peer arriving within MergeWindowMs read as one message
    private void AddReceived(List<SocketEntry> batch, Ev ev)
    {
        bool tcp = _sessionMode is 0 or 1;
        if (tcp)
        {
            bool inBatch = batch.Count > 0;
            var prev = inBatch ? batch[^1] : Entries.Count > 0 ? Entries[^1] : null;
            if (prev is { Kind: SocketEntryKind.Received } && ReferenceEquals(prev.PeerRef, ev.Peer)
                && prev.DataLength + ev.Data!.Length <= MergeLimit
                && (ev.Time - prev.LastChunk).TotalMilliseconds <= MergeWindowMs)
            {
                var merged = prev.Merge(ev.Data, ev.Until ?? ev.Time);
                if (inBatch) batch[^1] = merged;
                else
                {
                    // the shown entry moves into this batch: a trickle costs one remove + add (one re-layout) a tick,
                    // not a replace per chunk
                    Entries.RemoveAt(Entries.Count - 1);
                    _retainedBytes -= prev.DataLength;
                    batch.Add(merged);
                }
                return;
            }
        }
        batch.Add(new SocketEntry(SocketEntryKind.Received, ev.Time, ev.Data, null, ev.Peer?.Label) { PeerRef = ev.Peer, LastChunk = ev.Until ?? ev.Time });
    }

    // Back-to-back reads of one peer (within MergeWindowMs, up to MergeLimit) become one array here, once per drain:
    // merging them into the entry one by one copied the whole entry per read (4,000 small reads a tick allocated ~128 MB).
    private static void JoinReads(List<Ev> evs)
    {
        int w = 0;
        for (int r = 0; r < evs.Count;)
        {
            var first = evs[r];
            int end = r + 1;
            long total = first.Data?.Length ?? 0;
            if (first.Kind == EvKind.Received)
                while (end < evs.Count && evs[end] is { Kind: EvKind.Received } n && n.Gen == first.Gen && ReferenceEquals(n.Peer, first.Peer)
                       && total + n.Data!.Length <= MergeLimit && (n.Time - evs[end - 1].Time).TotalMilliseconds <= MergeWindowMs)
                {
                    total += n.Data.Length;
                    end++;
                }
            if (end - r > 1)
            {
                var all = new byte[total];
                int at = 0;
                for (int k = r; k < end; k++)
                {
                    evs[k].Data!.CopyTo(all, at);
                    at += evs[k].Data!.Length;
                }
                first = first with { Data = all, Until = evs[end - 1].Time };
            }
            evs[w++] = first;
            r = end;
        }
        evs.RemoveRange(w, evs.Count - w);
    }

    private void Commit(List<SocketEntry> batch)
    {
        if (batch.Count == 0) return;
        bool wasEmpty = Entries.Count == 0;
        foreach (var e in batch) _retainedBytes += e.DataLength;
        Entries.AddRange(batch);

        // caps: entries (trimmed to 90 % so it doesn't trim on every tick) and retained bytes
        int remove = Entries.Count > MaxEntries ? Entries.Count - MaxEntries * 9 / 10 : 0;
        long bytes = _retainedBytes;
        for (int i = 0; i < remove; i++) bytes -= Entries[i].DataLength;
        while (bytes > MaxRetainedBytes && remove < Entries.Count - 1) { bytes -= Entries[remove].DataLength; remove++; }
        if (remove > 0)
        {
            Entries.RemoveRange(0, remove);
            _retainedBytes = bytes;
            _trimmedEntries += remove;
        }
        if (wasEmpty) OnPropertyChanged(nameof(HasEntries));
    }

    private void AddNote(SocketEntryKind kind, string text)
    {
        Drain();
        Commit(new List<SocketEntry> { new(kind, DateTime.Now, null, text, null) });
    }

    private void UpdateTraffic()
    {
        string t = $"↑ {SocketPayload.FormatBytes(_sentBytes)}   ↓ {SocketPayload.FormatBytes(_recvBytes)}"
                   + (_trimmedEntries > 0 ? "   · older entries trimmed" : string.Empty);
        if (t != _lastTraffic) { _lastTraffic = t; TrafficText = t; }
    }

    [RelayCommand]
    private void Clear()
    {
        Entries.Clear();
        _retainedBytes = 0;
        _trimmedEntries = 0;
        _sentBytes = 0;
        _recvBytes = 0;
        OnPropertyChanged(nameof(HasEntries));
        UpdateTraffic();
    }

    // ================================================================ copy / save

    [RelayCommand]
    private async Task CopyTranscript()
    {
        if (Entries.Count == 0) return;
        var snap = Entries.ToArray();
        int view = ViewIndex;
        string text = await Task.Run(() => FormatTranscript(snap, view, header: null));
        await ClipboardHelper.SetTextAsync(text);
    }

    /// <summary>Copy one entry (the transcript's context menu): "text", "hex" (dump), "hexstring" or "escaped".</summary>
    public async Task CopyEntry(SocketEntry entry, string what)
    {
        string text = what switch
        {
            "hex" when entry.Data != null => SocketPayload.HexDump(entry.Data),
            "hexstring" when entry.Data != null => SocketPayload.ToHexString(entry.Data),
            "escaped" when entry.Data != null => SocketPayload.ToEscaped(entry.Data),
            _ when entry.Data != null => SocketPayload.ToDisplayText(entry.Data, int.MaxValue, out _),
            _ => entry.Message ?? string.Empty,
        };
        await ClipboardHelper.SetTextAsync(text);
    }

    public string SuggestedFileName
    {
        get
        {
            string what = _sessionMode switch
            {
                1 or 3 => "listen-" + (ListenPort ?? ""),
                4 => "ws-" + (WebSocketClient.TryNormalizeUrl(WsUrl, out var u, out _) ? u!.IdnHost.Trim('[', ']') : "session"),
                _ => (Host ?? "").Length > 0 ? $"{Host}-{Port}" : "session",
            };
            return SocketPayload.SafeFileName($"socket-{what}-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
        }
    }

    /// <summary>Writes the whole transcript (every retained entry, untruncated) as text.</summary>
    public async Task SaveTranscriptAsync(Stream stream)
    {
        var snap = Entries.ToArray();
        int view = ViewIndex;
        string mode = ModeIndex switch { 1 => "TCP server", 2 => "UDP client", 3 => "UDP server", 4 => "WebSocket client", _ => "TCP client" };
        string header = $"# Echoes socket transcript — {mode} — {StatusText} — saved {DateTime.Now:yyyy-MM-dd HH:mm:ss}";
        await Task.Run(() =>
        {
            using var w = new StreamWriter(stream, new UTF8Encoding(false), 1 << 16, leaveOpen: true);
            w.Write(FormatTranscript(snap, view, header));
            w.Flush();
        });
    }

    internal static string FormatTranscript(IReadOnlyList<SocketEntry> entries, int view, string? header)
    {
        var sb = new StringBuilder(entries.Sum(e => e.DataLength * (view == 0 ? 1 : 4)) + entries.Count * 48 + 128);
        if (header != null) sb.Append(header).Append('\n');
        foreach (var e in entries)
        {
            sb.Append('[').Append(e.TimeText).Append("] ").Append(e.Arrow);
            if (e.HasTag) sb.Append(' ').Append(e.Tag);
            if (e.HasPeer) sb.Append(' ').Append(e.Peer);
            if (e.Data != null)
            {
                sb.Append(' ').Append(e.SizeText);
                if (e.HasDetail) sb.Append(" (").Append(e.Detail).Append(')');
                sb.Append('\n');
                bool hex = view == 1 || view == 2 || e.LooksBinary;
                bool text = view == 0 ? !e.LooksBinary : view == 2;
                // data lines are indented: a peer's own "\n[12:00:00.000] ← …" can't pass for an entry of the transcript
                if (text) sb.Append("  ").Append(SocketPayload.ToDisplayText(e.Data, int.MaxValue, out _).Replace("\n", "\n  ")).Append('\n');
                if (hex) sb.Append(SocketPayload.HexDump(e.Data)).Append('\n');
            }
            else sb.Append(' ').Append(e.Message?.Replace("\n", "\n  ")).Append('\n');
        }
        return sb.ToString();
    }

    // ================================================================ input parsing

    /// <summary>Applies a history pick ("host:port") to the two boxes.</summary>
    public void ApplyTarget(string? item)
    {
        if (string.IsNullOrWhiteSpace(item) || !SplitTarget(item, out var h, out int p)) return;
        Host = h;
        if (p > 0) Port = p.ToString(CultureInfo.InvariantCulture);
    }

    private static bool SplitTarget(string raw, out string host, out int port)
    {
        host = raw.Trim();
        port = 0;
        if (host.Length == 0) return false;
        if (HostExtractor.Best(host) is { } f && (f.Via is "host:port" or "url" || f.Host == host))
        {
            host = f.Host;
            port = f.Port ?? 0;
        }
        return true;
    }

    private bool TryTarget(out string host, out int port, out string? error)
    {
        host = string.Empty;
        port = 0;
        string raw = (Host ?? string.Empty).Trim();
        if (raw.Length == 0) { error = "Enter a host name or IP address."; return false; }
        if (HostExtractor.Best(raw) is { } f)
        {
            host = f.Host;
            if (f.Port is int p) Port = p.ToString(CultureInfo.InvariantCulture);
        }
        else host = raw;
        if (host != raw) Host = host;
        return TryPort(Port, out port, out error);
    }

    private static bool TryPort(string? text, out int port, out string? error)
    {
        error = null;
        if (int.TryParse((text ?? string.Empty).Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out port) && port is >= 1 and <= 65535)
            return true;
        error = string.IsNullOrWhiteSpace(text) ? "Enter a port (1–65535)." : $"\"{text!.Trim()}\" isn't a port — use a number from 1 to 65535.";
        return false;
    }

    private static string Plural(int n, string unit) => n == 1 ? $"1 {unit}" : $"{n} {unit}s";
}
