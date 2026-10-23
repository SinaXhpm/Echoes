using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

/// <summary>
/// The Socket tool's WebSocket client mode (ModeIndex 4): a ws:// / wss:// URL, optional subprotocols, request headers
/// and an HTTP / SOCKS5 proxy; text, binary (typed as hex) or checked JSON messages; pings with their round trip; the
/// close handshake with its code and reason. Frames go through the same queue → batched transcript as TCP / UDP.
/// </summary>
public partial class SocketViewModel
{
    private const string KJson = "socket.json", KWsProto = "socket.wsProto", KWsHeaders = "socket.wsHeaders",
        KWsProxy = "socket.wsProxy";
    private const string HWsUrl = "socket.ws";

    /// <summary>Largest message kept whole in the transcript (the rest is counted); see also MaxRetainedBytes.</summary>
    public const int WsMaxMessageBytes = 4 * 1024 * 1024;

    [ObservableProperty] private string _wsUrl = string.Empty;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(WsOptionsLabel))] private string _wsSubprotocols = string.Empty;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(WsOptionsLabel))] private string _wsHeaders = string.Empty;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(WsOptionsLabel))] private string _wsProxy = string.Empty;
    [ObservableProperty] private bool _isWsOptionsOpen;
    [ObservableProperty] private bool _inputIsJson;

    public ObservableCollection<string> WsUrlHistory => HistoryService.Instance.Get(HWsUrl);

    private WsClientSession? _ws;
    private bool _wsClosing;

    public bool IsWsMode => ModeIndex == 4;
    public bool ShowLineEnding => ModeIndex != 4;
    public bool ShowJsonFormat => ModeIndex == 4 && InputIsJson;
    public bool CanPing => _ws != null && State == SocketState.Connected && !_wsClosing;
    /// <summary>The options panel is open in WebSocket mode with no session (a phone then lets the page grow).</summary>
    public bool ShowWsOptions => ModeIndex == 4 && IsWsOptionsOpen && State == SocketState.Idle;

    partial void OnIsWsOptionsOpenChanged(bool value) => OnPropertyChanged(nameof(ShowWsOptions));

    /// <summary>"Options" — or "Options · 3" when headers / subprotocols / a proxy are set.</summary>
    public string WsOptionsLabel
    {
        get
        {
            int n = 0;
            if (WebSocketClient.TryParseHeaders(WsHeaders, out var h, out _)) n += h.Count;
            if (WebSocketClient.TryParseSubprotocols(WsSubprotocols, out var p, out _)) n += p.Count;
            if (!string.IsNullOrWhiteSpace(WsProxy)) n++;
            return n == 0 ? "Options" : $"Options · {n}";
        }
    }

    private void RestoreWsSettings(ProfileService p)
    {
        WsSubprotocols = p.GetSetting(KWsProto) ?? string.Empty;
        WsHeaders = Open(p.GetSetting(KWsHeaders));
        WsProxy = Open(p.GetSetting(KWsProxy));
        WsUrl = HistoryService.Instance.Last(HWsUrl) ?? string.Empty;

        static string Open(string? stored) => SecretProtector.IsProtected(stored) ? SecretProtector.Unprotect(stored) : stored ?? string.Empty;
    }

    // Headers can hold tokens (Authorization, Cookie) and a proxy address a password: both are sealed at rest.
    partial void OnWsSubprotocolsChanged(string value) { if (!_restoring) ProfileService.Instance.SetSetting(KWsProto, (value ?? string.Empty).Trim()); }
    partial void OnWsHeadersChanged(string value)
    {
        if (!_restoring) ProfileService.Instance.SetSetting(KWsHeaders, string.IsNullOrWhiteSpace(value) ? null : SecretProtector.Protect(value));
    }
    partial void OnWsProxyChanged(string value)
    {
        if (!_restoring) ProfileService.Instance.SetSetting(KWsProxy, string.IsNullOrWhiteSpace(value) ? null : value.Contains('@') ? SecretProtector.Protect(value.Trim()) : value.Trim());
    }

    [RelayCommand]
    private void ToggleWsOptions() => IsWsOptionsOpen = !IsWsOptionsOpen;

    // ================================================================ connect

    private async Task StartWsAsync(int gen, string? acceptSha)
    {
        if (!WebSocketClient.TryNormalizeUrl(WsUrl, out var uri, out string? error)) { AddNote(SocketEntryKind.Error, error!); return; }
        string url = uri!.OriginalString;
        if (url != (WsUrl ?? string.Empty).Trim()) WsUrl = url;   // show what a pasted http(s):// became
        if (!WebSocketClient.TryParseHeaders(WsHeaders, out var headers, out error)
            || !WebSocketClient.TryParseSubprotocols(WsSubprotocols, out var protos, out error))
        {
            IsWsOptionsOpen = true;
            AddNote(SocketEntryKind.Error, error!);
            return;
        }
        string? proxy = string.IsNullOrWhiteSpace(WsProxy) ? null : WsProxy.Trim();

        var sink = new WsSinkImpl(this, gen);
        State = SocketState.Connecting;
        StatusText = $"Connecting to {Shorten(url)}…";
        string viaText = proxy != null ? " through " + HttpHelper.WithoutUserInfo(proxy) : string.Empty;
        AddNote(SocketEntryKind.Info, $"Connecting to {url}{viaText}{(acceptSha != null ? " (accepting the certificate you allowed)" : "")}…");
        _connectCts = new CancellationTokenSource();
        try
        {
            var s = await WebSocketClient.ConnectAsync(new WsConnectOptions
            {
                Uri = uri,
                Subprotocols = protos,
                Headers = headers,
                Proxy = proxy,
                AcceptCertSha256 = acceptSha,
                MaxMessageBytes = WsMaxMessageBytes,
            }, sink, _connectCts.Token);
            if (gen != _gen) { s.Connection.Abort(); return; }
            _ws = s;
            _wsClosing = false;
            State = SocketState.Connected;
            OnPropertyChanged(nameof(CanPing));

            var parts = new List<string> { s.StatusLine };
            if (s.Subprotocol != null) parts.Add("subprotocol " + s.Subprotocol);
            if (s.Server != null) parts.Add("server " + s.Server);
            string where = s.Via != null ? $" via {s.Via}" : s.Remote != null ? $" ({SocketNet.Label(s.Remote)})" : string.Empty;
            AddNote(SocketEntryKind.Info, $"Connected to {url}{where} — {string.Join(" · ", parts)}.");
            if (s.TlsDescription != null)
            {
                string warn = s.CertificateOverridden ? " · untrusted certificate (you allowed it)" : string.Empty;
                AddNote(SocketEntryKind.Info, $"TLS: {s.TlsDescription}{(s.CertificateText != null ? " · certificate " + s.CertificateText : "")}{warn}.");
            }
            StatusText = $"Connected to {uri.Scheme}://{uri.Authority}"
                         + (s.TlsDescription != null ? " · " + s.TlsDescription.Split(" · ")[0] : string.Empty)
                         + (s.Subprotocol != null ? " · " + s.Subprotocol : string.Empty)
                         + (s.CertificateOverridden ? " · untrusted certificate" : string.Empty);
            s.Connection.Start();
            HistoryService.Instance.Add(HWsUrl, ForHistory(url));
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
            AddNote(SocketEntryKind.Error, ex is SocketFailure ? ex.Message : SocketErrors.Describe(ex, SocketAction.Connect, Shorten(url)));
        }
        finally
        {
            _connectCts?.Dispose();
            _connectCts = null;
            OnPropertyChanged(nameof(CanPing));
        }
    }

    private static string Shorten(string url) => WsProtocol.Short(url, 72);

    // Query values that look like credentials (?token=…, &key=…) don't go into the plain-text history.
    internal static string ForHistory(string url) => UrlSecrets.Redact(url);

    // ================================================================ close

    /// <summary>Starts the close handshake (1000). False when a close is already under way — the caller then aborts.</summary>
    private bool BeginWsClose()
    {
        if (_ws is not { } s || _wsClosing) return false;
        _wsClosing = true;
        OnPropertyChanged(nameof(CanSend));
        OnPropertyChanged(nameof(CanPing));
        StatusText = "Closing…";
        AddNote(SocketEntryKind.Info, "Sent close 1000 normal closure — waiting for the server's answer (press Disconnect again to drop it now)…");
        _ = s.Connection.CloseAsync(1000, string.Empty, 3000);
        return true;
    }

    // ================================================================ send / ping

    private async Task SendWsInputAsync()
    {
        string text = (Input ?? string.Empty).Replace("\r\n", "\n");
        byte[] data;
        bool binary = InputIsHex;
        if (binary)
        {
            try { data = SocketPayload.FromHex(Input); }
            catch (FormatException fe) { InputError = fe.Message; return; }
            if (data.Length == 0) { InputError = "Type the bytes to send, e.g. 48 65 6c 6c 6f."; return; }
        }
        else
        {
            if (text.Length == 0) { InputError = InputIsJson ? "Type the JSON to send." : "Type a message to send."; return; }
            data = Encoding.UTF8.GetBytes(text);
            if (InputIsJson && CatcherFormat.PrettyJson(data, out string? err) == null)
            {
                InputError = $"Not valid JSON ({err}) — fix it or switch to Text to send it anyway.";
                return;
            }
        }
        RememberInput(Input ?? string.Empty);
        Input = string.Empty;
        await SendWsAsync(data, binary);
    }

    private async Task SendWsAsync(byte[] data, bool binary)
    {
        if (_ws is not { } s) return;
        Drain();
        Commit(new List<SocketEntry> { new(SocketEntryKind.Sent, DateTime.Now, data, null, null) { Tag = binary ? "bin" : "text", ForceBinary = binary } });
        _sentBytes += data.Length;
        try { await s.Connection.SendAsync(binary ? WsOpcode.Binary : WsOpcode.Text, data); }
        catch (Exception ex) when (ReferenceEquals(s, _ws)) { AddNote(SocketEntryKind.Error, ex.Message); }
        catch { /* that session is gone */ }
        Drain();
    }

    [RelayCommand]
    private async Task Ping()
    {
        if (_ws is not { } s || !CanPing) return;
        Drain();
        try
        {
            byte[] payload = await s.Connection.PingAsync();
            Commit(new List<SocketEntry> { new(SocketEntryKind.Sent, DateTime.Now, payload, null, null) { Tag = "ping" } });
        }
        catch (Exception ex) when (ReferenceEquals(s, _ws)) { AddNote(SocketEntryKind.Error, "Ping failed: " + ex.Message); }
        catch { }
    }

    /// <summary>Pretty-prints the JSON in the send box (or says where it's broken).</summary>
    [RelayCommand]
    private void FormatJson()
    {
        string text = Input ?? string.Empty;
        if (text.Trim().Length == 0) return;
        string? pretty = CatcherFormat.PrettyJson(Encoding.UTF8.GetBytes(text), out string? err);
        if (pretty == null) { InputError = $"Not valid JSON ({err})."; return; }
        Input = pretty;
    }

    // ================================================================ events (read thread → queue)

    // A server can send tiny frames (empty messages, pings) far faster than the transcript shows them, and the queue's
    // byte cap doesn't count them: a 1.5 s busy UI let 450,000 empty frames pile up (45 MB) and the next drain froze the
    // UI. Past this many queued events a frame is counted as skipped instead (the drain reports it, the ↓ counter has it).
    private const int MaxQueuedWsEvents = 300;

    private bool AdmitWs(int bytes)
    {
        if (_queue.Count < MaxQueuedWsEvents) return true;
        Interlocked.Add(ref _droppedBytes, bytes);
        Interlocked.Increment(ref _droppedChunks);
        return false;
    }

    private sealed class WsSinkImpl : IWsSink
    {
        private readonly SocketViewModel _vm;
        private readonly int _gen;
        public WsSinkImpl(SocketViewModel vm, int gen) { _vm = vm; _gen = gen; }

        public void OnMessage(WsConnection connection, WsMessage m)
        {
            if (!_vm.AdmitWs(m.Data.Length)) return;
            string? detail = null;
            if (m.Truncated) detail = $"first {SocketPayload.FormatBytes(m.Data.Length)} of {SocketPayload.FormatBytes(m.Length)} kept";
            else if (m.Frames > 1) detail = $"{m.Frames} frames";
            _vm.EnqueueData(new Ev(EvKind.WsData, _gen, null, m.Data, null, !m.IsText, DateTime.Now, m.IsText ? "text" : "bin", detail));
        }

        public void OnControl(WsConnection connection, WsOpcode opcode, byte[] payload, double? rttMs)
        {
            if (!_vm.AdmitWs(payload.Length)) return;   // the pong itself still goes out (WsConnection answers every ping)
            string detail = opcode == WsOpcode.Ping
                ? "answered with a pong"
                : rttMs is double ms ? $"round trip {ms.ToString(ms < 10 ? "0.0" : "0", CultureInfo.InvariantCulture)} ms" : "unasked";
            // Through EnqueueData like any data: the drain subtracts every event's bytes from the pending count, so an
            // uncounted ping / pong would drive it below zero and loosen the 8 MB cap for the rest of the session.
            _vm.EnqueueData(new Ev(EvKind.WsData, _gen, null, payload, null, false, DateTime.Now,
                                   opcode == WsOpcode.Ping ? "ping" : "pong", detail));
        }

        public void OnClosed(WsConnection connection, WsCloseInfo info)
        {
            string reason = info.Reason.Length > 0 ? $" — \"{WsProtocol.Short(WebSocketClient.Clean(info.Reason), 120)}\"" : string.Empty;
            string text;
            bool error;
            if (info.Error != null && info.Code == 1006)
            {
                text = info.Error.StartsWith("Connection lost", StringComparison.Ordinal) ? info.Error + " (1006)" : $"Connection lost (1006 abnormal closure): {info.Error}";
                error = true;
            }
            else if (info.Error != null)
            {
                text = info.ByPeer ? $"Closed: {info.Error}" : $"Closed with {info.CodeText}: {info.Error}";
                error = true;
            }
            else if (info.ByPeer)
            {
                text = $"The server closed the connection: {info.CodeText}{reason}.";
                error = info.Code is not (1000 or 1001 or 1005);
            }
            else if (info.Clean)
            {
                var sent = connection.SentClose;
                text = $"Disconnected — sent {WsProtocol.CloseCodeText(sent?.Code ?? 1000)}, the server answered {info.CodeText}{reason}.";
                error = false;
            }
            else
            {
                text = connection.SentClose != null ? "Disconnected — the server hung up without answering the close." : "Disconnected.";
                error = false;
            }
            _vm.Queue(new Ev(EvKind.Ended, _gen, null, null, text, error, DateTime.Now));
        }
    }
}
