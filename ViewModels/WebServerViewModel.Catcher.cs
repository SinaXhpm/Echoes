using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Collections;
using Avalonia.Media.Imaging;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

/// <summary>One row of the catcher's request list (newest first). Built on the UI thread from a captured request.</summary>
public sealed partial class CatcherRow : ObservableObject
{
    public CatcherRow(CapturedRequest r)
    {
        Request = r;
        TimeText = r.Time.ToString("HH:mm:ss", CultureInfo.InvariantCulture);
        Method = r.Kind switch
        {
            CaptureKind.WsMessage => r.IsText ? "WS" : "WS·B",
            CaptureKind.WsClose => "WS",
            _ => r.IsPreflight ? "OPTIONS" : RequestCatcher.Printable(WsProtocol.Short(r.Method, 10)),
        };
        PathText = r.Kind switch
        {
            CaptureKind.WsMessage => (r.IsText ? "text " : "binary ") + RequestCatcher.Printable(WsProtocol.Short(r.Path, 200)),
            CaptureKind.WsClose => "close " + RequestCatcher.Printable(WsProtocol.Short(r.Path, 200)),
            _ => RequestCatcher.Printable(WsProtocol.Short(r.Target, 300)),
        };
        ClientText = r.ClientIp;
        // what the row keeps alive: the body plus the head's strings (UTF-16; a head may be 32 KB of Latin-1)
        long head = r.Target.Length;
        foreach (var h in r.Headers) head += h.Key.Length + h.Value.Length;
        Weight = r.Body.Length + 2 * head;
        Refresh();
    }

    public CapturedRequest Request { get; }
    /// <summary>Bytes the row holds (body + head), counted into <see cref="WebServerViewModel.MaxRetainedBodyBytes"/>.</summary>
    public long Weight { get; }
    public string TimeText { get; }
    public string Method { get; }
    public string PathText { get; }
    public string ClientText { get; }
    [ObservableProperty] private string _statusText = "…";
    [ObservableProperty] private string _sizeText = string.Empty;
    /// <summary>"ok" 2xx/101 · "redirect" 3xx · "client" 4xx · "server" 5xx · "none" (no reply).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsOk), nameof(IsRedirect), nameof(IsClientError), nameof(IsServerError))]
    private string _statusKind = "none";

    public bool IsOk => StatusKind == "ok";
    public bool IsRedirect => StatusKind == "redirect";
    public bool IsClientError => StatusKind == "client";
    public bool IsServerError => StatusKind == "server";

    public bool IsWs => Request.Kind != CaptureKind.Http;
    public bool IsPreflight => Request.IsPreflight;
    public bool IsGet => Method is "GET" or "HEAD";
    public bool IsPost => Method is "POST";
    public bool IsWrite => Method is "PUT" or "PATCH";
    public bool IsDelete => Method is "DELETE";

    /// <summary>Re-reads the status / size after the reply went out.</summary>
    public void Refresh()
    {
        var r = Request;
        int s = r.Status;
        SizeText = r.BodyLength > 0 ? SocketPayload.FormatBytes(r.BodyLength) : r.Kind == CaptureKind.WsMessage ? "0 B" : "—";
        if (r.Kind == CaptureKind.WsMessage)
        {
            StatusText = r.Delivered > 1 ? $"→{r.Delivered}" : "echo";
            StatusKind = "ok";
            return;
        }
        if (r.Kind == CaptureKind.WsClose)
        {
            StatusText = s > 0 ? s.ToString(CultureInfo.InvariantCulture) : "—";
            StatusKind = s is 1000 or 1001 or 1005 ? "ok" : "client";
            return;
        }
        StatusText = s > 0 ? s.ToString(CultureInfo.InvariantCulture) : r.Note != null ? "—" : "…";
        StatusKind = s switch
        {
            0 => "none",
            < 300 => "ok",
            < 400 => "redirect",
            < 500 => "client",
            _ => "server",
        };
    }
}

/// <summary>What the details pane shows for the selected request.</summary>
public sealed class CatcherDetail
{
    public required CatcherRow Row { get; init; }
    public string RequestLine { get; init; } = string.Empty;
    public string Meta { get; init; } = string.Empty;
    public string? Note { get; init; }
    public IReadOnlyList<CatcherField> Headers { get; init; } = Array.Empty<CatcherField>();
    public IReadOnlyList<CatcherField> Query { get; init; } = Array.Empty<CatcherField>();
    public required CatcherBodyView Body { get; init; }

    public bool HasNote => !string.IsNullOrEmpty(Note);
    public bool HasHeaders => Headers.Count > 0;
    public bool HasQuery => Query.Count > 0;
    public string HeadersTitle => $"Headers ({Headers.Count})";
    public string QueryTitle => $"Query ({Query.Count})";
    public bool BodyIsText => Body.Text != null;
    public bool BodyIsFields => Body.Fields != null;
    public bool BodyIsHex => Body.Bytes != null;
    public bool BodyIsNone => Body.Kind == CatcherBodyKind.None;
    public bool HasBodyNote => !string.IsNullOrEmpty(Body.Note);
    public bool CanCopyCurl => Row.Request.Kind is CaptureKind.Http or CaptureKind.WsUpgrade;
    public bool CanCopyBody => Row.Request.Body.Length > 0;
}

/// <summary>
/// The Web Server tool's second mode, "Catch requests" — a webhook inspector on <see cref="RequestCatcher"/>. Requests are
/// queued by connection threads and drained into the list by a 200 ms UI timer (one batch per tick, whatever the load);
/// the list is capped and virtualized; the details of the selected one are built off the UI thread.
/// </summary>
public partial class WebServerViewModel : ICatcherSink
{
    private const string KMode = "webserver.mode", KCatchPort = "catch.port", KCatchBind = "catch.bind",
        KReplyStatus = "catch.status", KReplyType = "catch.type", KReplyBody = "catch.body", KReplyDelay = "catch.delay";
    public const int MaxRows = 500;
    /// <summary>Bodies and heads the list keeps in all (a body is at most 1 MB): past this the oldest rows go.</summary>
    public const long MaxRetainedBodyBytes = 64L * 1024 * 1024;
    private const int MaxPending = 2000;
    private const long MaxPendingBodyBytes = 32L * 1024 * 1024;
    private long _catchPendingBytes, _retainedBodyBytes;

    /// <summary>0 share files · 1 catch requests.</summary>
    [ObservableProperty] private int _modeIndex;

    [ObservableProperty] private int _catchPort = 8090;
    public ObservableCollection<BindOption> CatchBindOptions { get; } = new();
    [ObservableProperty] private BindOption? _selectedCatchBind;
    [ObservableProperty] private bool _isCatching;
    [ObservableProperty] private string _catchStatus = "Start to get a URL that catches any request.";
    [ObservableProperty] private bool _catchError;
    public ObservableCollection<string> CatchUrls { get; } = new();
    [ObservableProperty] private string? _selectedCatchUrl;
    [ObservableProperty] private Bitmap? _catchQr;

    // reply
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(ReplySummary))] private int _replyStatus = 200;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(ReplySummary))] private string _replyContentType = "application/json";
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(ReplySummary))] private string _replyBody = "{\"ok\":true}";
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(ReplySummary))] private int _replyDelayMs;
    [ObservableProperty] private bool _isReplyOpen;
    [ObservableProperty] private string? _replyError;

    public string[] ContentTypes { get; } =
    {
        "application/json", "text/plain; charset=utf-8", "text/html; charset=utf-8", "application/xml", "application/x-www-form-urlencoded",
    };

    // requests
    public AvaloniaList<CatcherRow> Requests { get; } = new() { ResetBehavior = ResetBehavior.Reset };
    [ObservableProperty] private CatcherRow? _selectedRequest;
    [ObservableProperty] private CatcherDetail? _detail;
    [ObservableProperty] private int _detailTabIndex;
    [ObservableProperty] private bool _isDetailOpen;
    [ObservableProperty] private string _catchCounts = string.Empty;

    private RequestCatcher? _catcher;
    private ListenerWatch? _catchWatch;
    private IPAddress? _catchBindActive;
    private int _catchPortActive;
    private readonly ConcurrentQueue<(CapturedRequest Req, bool Replied)> _catchQueue = new();
    private int _catchPending, _catchDropped;
    private int _shownDropped;   // the skipped count the line shows: once a flood is over, the drain is idle again
    private PacedTimer? _catchTimer;
    private readonly Dictionary<long, CatcherRow> _rowsById = new();
    private long _catchTotal;
    private int _detailGen;
    private bool _restoringCatch;

    public bool IsShareMode => ModeIndex == 0;
    public bool IsCatchMode => ModeIndex == 1;
    public bool IsBodyTab => DetailTabIndex == 0;
    public bool IsHeadersTab => DetailTabIndex == 1;
    public bool IsQueryTab => DetailTabIndex == 2;

    partial void OnDetailTabIndexChanged(int value)
    {
        OnPropertyChanged(nameof(IsBodyTab));
        OnPropertyChanged(nameof(IsHeadersTab));
        OnPropertyChanged(nameof(IsQueryTab));
    }
    public bool HasRequests => Requests.Count > 0;
    public bool HasDetail => Detail != null;
    public bool HasCatchUrls => CatchUrls.Count > 0;

    public string ReplySummary
    {
        get
        {
            string type = (ReplyContentType ?? string.Empty).Split(';')[0].Trim();
            string delay = ReplyDelayMs > 0 ? $" · {ReplyDelayMs} ms delay" : string.Empty;
            int bytes = Encoding.UTF8.GetByteCount(ReplyBody ?? string.Empty);
            string body = ReplyStatus is 204 or 304 ? "no body" : bytes == 0 ? "empty body" : $"{type} · {SocketPayload.FormatBytes(bytes)}";
            return $"Replies {ReplyStatus} · {body}{delay} · CORS on";
        }
    }

    private void InitCatcher()
    {
        _restoringCatch = true;
        var p = ProfileService.Instance;
        ModeIndex = Math.Clamp(p.GetInt(KMode, 0), 0, 1);
        int port = p.GetInt(KCatchPort, 8090);
        CatchPort = port is >= 1 and <= 65535 ? port : 8090;
        int st = p.GetInt(KReplyStatus, 200);
        ReplyStatus = st is >= 200 and <= 599 ? st : 200;
        ReplyContentType = p.GetSetting(KReplyType) is { Length: > 0 } t ? t : "application/json";
        ReplyBody = p.GetSetting(KReplyBody) ?? "{\"ok\":true}";
        ReplyDelayMs = Math.Clamp(p.GetInt(KReplyDelay, 0), 0, RequestCatcher.MaxDelayMs);
        RebuildCatchBinds(p.GetSetting(KCatchBind));
        _restoringCatch = false;
        UpdateCatchCounts();
    }

    partial void OnModeIndexChanged(int value)
    {
        OnPropertyChanged(nameof(IsShareMode));
        OnPropertyChanged(nameof(IsCatchMode));
        if (!_restoringCatch) ProfileService.Instance.SetSetting(KMode, value.ToString(CultureInfo.InvariantCulture));
    }

    partial void OnCatchPortChanged(int value)
    {
        if (!_restoringCatch && value is >= 1 and <= 65535) ProfileService.Instance.SetSetting(KCatchPort, value.ToString(CultureInfo.InvariantCulture));
        if (!IsCatching) RefreshCatchUrls();
    }

    partial void OnSelectedCatchBindChanged(BindOption? value)
    {
        if (_restoringCatch || _rebuildingCatchBinds || value is null) return;
        ProfileService.Instance.SetSetting(KCatchBind, value.Kind == "iface" ? value.Address.ToString() : value.Kind);
        if (!IsCatching) RefreshCatchUrls();
    }

    partial void OnReplyStatusChanged(int value) => PushReply();
    partial void OnReplyContentTypeChanged(string value) => PushReply();
    partial void OnReplyBodyChanged(string value) => PushReply();
    partial void OnReplyDelayMsChanged(int value) => PushReply();

    [RelayCommand]
    private void ToggleReply() => IsReplyOpen = !IsReplyOpen;

    // The live catcher picks the new reply up at once (an immutable object swapped in).
    private void PushReply()
    {
        string? err = null;
        if (ReplyStatus is < 200 or > 599) err = "Status must be 200–599.";
        else if (ReplyDelayMs is < 0 or > RequestCatcher.MaxDelayMs) err = "Delay must be 0–60000 ms.";
        else if ((ReplyContentType ?? "").Any(c => c < 0x20 || c >= 0x7F)) err = "The content type must be plain ASCII.";
        else if (Encoding.UTF8.GetByteCount(ReplyBody ?? string.Empty) > RequestCatcher.MaxStoredBody) err = "The reply body is limited to 1 MB.";
        ReplyError = err;
        if (err != null) return;
        // remembered for next time (a body over 64 KB only for this session — the profile stays small)
        if (!_restoringCatch)
            ProfileService.Instance.SetMany(
                (KReplyStatus, ReplyStatus.ToString(CultureInfo.InvariantCulture)), (KReplyType, ReplyContentType),
                (KReplyBody, (ReplyBody ?? string.Empty).Length <= 64 * 1024 ? ReplyBody : null),
                (KReplyDelay, ReplyDelayMs.ToString(CultureInfo.InvariantCulture)));
        if (_catcher != null) _catcher.Reply = BuildReply();
    }

    private CatcherReply BuildReply() => new()
    {
        Status = ReplyStatus is >= 200 and <= 599 ? ReplyStatus : 200,
        ContentType = string.IsNullOrWhiteSpace(ReplyContentType) ? "text/plain; charset=utf-8" : ReplyContentType.Trim(),
        Body = Encoding.UTF8.GetBytes(ReplyBody ?? string.Empty),
        DelayMs = Math.Clamp(ReplyDelayMs, 0, RequestCatcher.MaxDelayMs),
    };

    // ================================================================ bind + URLs

    private bool _rebuildingCatchBinds;

    /// <summary>Every interface (loopback + LAN, IPv4 + IPv6), this device only, or one interface's IPv4 address.</summary>
    public void RebuildCatchBinds(string? preferred = null)
    {
        string? want = preferred ?? (SelectedCatchBind is { } cur ? (cur.Kind == "iface" ? cur.Address.ToString() : cur.Kind) : null);
        var list = new List<BindOption>
        {
            new("All interfaces (IPv4 + IPv6)", IPAddress.IPv6Any, "all"),
            new("This device only (127.0.0.1)", IPAddress.Loopback, "loopback"),
        };
        foreach (var (addr, name) in LanAddresses()) list.Add(new BindOption($"{addr}  ({name})", addr, "iface"));
        _rebuildingCatchBinds = true;
        try
        {
            CatchBindOptions.Clear();
            foreach (var o in list) CatchBindOptions.Add(o);
            // nothing picked yet, or a picked interface that went away: this device only — all interfaces (anyone on the
            // network can send, read the reply and join the WebSocket echo) only when the user picks it
            SelectedCatchBind = CatchBindOptions.FirstOrDefault(o => o.Kind != "iface" ? o.Kind == want : o.Address.ToString() == want)
                                ?? CatchBindOptions.First(o => o.Kind == "loopback");
        }
        finally { _rebuildingCatchBinds = false; }
        RefreshCatchUrls();
    }

    private static List<(IPAddress Addr, string Name)> LanAddresses()
    {
        var list = new List<(IPAddress, string)>();
        foreach (var (name, address) in NicSnapshot.UpIPv4()) list.Add((address, name));   // empty on restricted platforms: loopback is enough
        return list;
    }

    /// <summary>The URL(s) to send to: 127.0.0.1 first, then each LAN address the catcher is reachable on.</summary>
    public void RefreshCatchUrls()
    {
        string? keep = SelectedCatchUrl;
        var bind = IsCatching ? _catchBindActive : SelectedCatchBind?.Address;
        int port = IsCatching ? _catchPortActive : CatchPort;
        CatchUrls.Clear();
        if (bind is null || port is < 1 or > 65535) { OnPropertyChanged(nameof(HasCatchUrls)); SelectedCatchUrl = null; return; }
        string P(IPAddress a) => $"http://{a}:{port.ToString(CultureInfo.InvariantCulture)}/";
        if (bind.Equals(IPAddress.IPv6Any) || bind.Equals(IPAddress.Any))
        {
            CatchUrls.Add(P(IPAddress.Loopback));
            foreach (var (addr, _) in LanAddresses()) CatchUrls.Add(P(addr));
        }
        else CatchUrls.Add(P(bind));
        OnPropertyChanged(nameof(HasCatchUrls));
        SelectedCatchUrl = keep != null && CatchUrls.Contains(keep) ? keep : CatchUrls.FirstOrDefault();
    }

    partial void OnSelectedCatchUrlChanged(string? value) => UpdateCatchQr();
    partial void OnIsCatchingChanged(bool value) => UpdateCatchQr();

    // Only while catching (the URL row shows then) — typing a port while stopped doesn't render a QR per keystroke.
    private void UpdateCatchQr()
    {
        var old = CatchQr;
        CatchQr = IsCatching && !string.IsNullOrEmpty(SelectedCatchUrl) ? BuildQr(SelectedCatchUrl!) : null;
        old?.Dispose();
    }

    [RelayCommand]
    private async Task CopyCatchUrl()
    {
        if (!string.IsNullOrEmpty(SelectedCatchUrl)) await ClipboardHelper.SetTextAsync(SelectedCatchUrl);
    }

    // ================================================================ start / stop

    [RelayCommand]
    private void ToggleCatcher()
    {
        if (IsCatching) StopCatcher();
        else StartCatcher();
    }

    private void StartCatcher()
    {
        CatchError = false;
        if (CatchPort is < 1 or > 65535) { CatchStatus = "Port must be between 1 and 65535."; CatchError = true; return; }
        if (ReplyError != null) { CatchStatus = "Fix the reply first: " + ReplyError; CatchError = true; IsReplyOpen = true; return; }
        var bind = SelectedCatchBind ?? CatchBindOptions.FirstOrDefault(o => o.Kind == "loopback") ?? new BindOption("This device only (127.0.0.1)", IPAddress.Loopback, "loopback");
        var c = new RequestCatcher(this, maxConnections: 64) { Reply = BuildReply() };
        try
        {
            c.Start(bind.Address, CatchPort);
        }
        catch (Exception ex)
        {
            c.Dispose();
            string where = bind.Kind switch { "all" => $"port {CatchPort}", "loopback" => $"127.0.0.1:{CatchPort}", _ => $"{bind.Address}:{CatchPort}" };
            CatchStatus = "Couldn't start: " + SocketErrors.Describe(ex, SocketAction.Listen, where, CatchPort);
            CatchError = true;
            return;
        }
        _catcher = c;
        _catchWatch = new ListenerWatch(bind.Address, CatchPort, reason => RestartCatcher(c, reason));
        c.ListenerLost += _catchWatch.Lost;
        _catchBindActive = bind.Address;
        _catchPortActive = CatchPort;
        IsCatching = true;
        BackgroundGuard.Acquire("Catching requests");
        RefreshCatchUrls();
        bool lan = !bind.Address.Equals(IPAddress.Loopback);
        CatchStatus = lan
            ? "Anyone on your network can send here too."
            : "Only this device can send here.";
        _catchTimer ??= new PacedTimer(200, 1000, DrainCatcher);   // 5 a second while requests arrive, then once a second
        _catchTimer.Start();
    }

    /// <summary>Stops catching (also called on app exit through <see cref="StopServer"/>).</summary>
    public void StopCatcher()
    {
        if (_catcher is null) return;
        try { _catcher.Dispose(); } catch { }
        _catcher = null;
        _catchWatch?.Dispose();
        _catchWatch = null;
        _catchTimer?.Stop();
        DrainCatcher();
        IsCatching = false;
        BackgroundGuard.Release("Catching requests");
        _catchBindActive = null;
        RefreshCatchUrls();
        CatchStatus = $"Stopped — {Plural(_catchTotal, "request")} caught.";
        UpdateCatchCounts();
    }

    // The listening socket is gone (iOS reclaims a suspended app's): catching starts again on the same address and port.
    private void RestartCatcher(RequestCatcher catcher, string reason)
    {
        if (!ReferenceEquals(_catcher, catcher)) return;
        StopCatcher();
        StartCatcher();
        if (IsCatching) CatchStatus = $"Started again: the listening socket had closed ({reason}).";
    }

    // ================================================================ catcher events

    void ICatcherSink.OnRequest(CapturedRequest request) => EnqueueCatch(request, false);
    void ICatcherSink.OnReplied(CapturedRequest request) => EnqueueCatch(request, true);

    // connection threads: a flood past MaxPending is counted, not queued; bodies past MaxPendingBodyBytes are dropped
    // (the request is still listed, with a note)
    private void EnqueueCatch(CapturedRequest r, bool replied)
    {
        if (Interlocked.Increment(ref _catchPending) > MaxPending)
        {
            Interlocked.Decrement(ref _catchPending);
            if (!replied) Interlocked.Increment(ref _catchDropped);
            return;
        }
        if (!replied && r.Body.Length > 0 && Interlocked.Add(ref _catchPendingBytes, r.Body.Length) > MaxPendingBodyBytes)
        {
            Interlocked.Add(ref _catchPendingBytes, -r.Body.Length);
            r.Body = Array.Empty<byte>();
            r.Note ??= "The body wasn't kept — too much was arriving at once.";
        }
        _catchQueue.Enqueue((r, replied));
        _catchTimer?.Poke();   // the first request after a quiet spell is listed at once
    }

    /// <summary>UI thread: moves what arrived into the list in one batch (newest first, capped). True when anything had
    /// arrived (the paced timer then keeps its fast interval).</summary>
    internal bool DrainCatcher()
    {
        int dropped = Volatile.Read(ref _catchDropped);
        if (_catchQueue.IsEmpty && dropped == _shownDropped) return false;
        _shownDropped = dropped;
        var fresh = new List<CatcherRow>();
        bool selectedChanged = false;
        while (_catchQueue.TryDequeue(out var item))
        {
            Interlocked.Decrement(ref _catchPending);
            if (!item.Replied)
            {
                Interlocked.Add(ref _catchPendingBytes, -item.Req.Body.Length);
                if (_rowsById.ContainsKey(item.Req.Id)) continue;
                var row = new CatcherRow(item.Req);
                _rowsById[item.Req.Id] = row;
                _retainedBodyBytes += row.Weight;
                fresh.Add(row);
                _catchTotal++;
            }
            else if (_rowsById.TryGetValue(item.Req.Id, out var row))
            {
                row.Refresh();
                if (ReferenceEquals(row, SelectedRequest)) selectedChanged = true;
            }
        }
        if (fresh.Count > 0)
        {
            fresh.Reverse();   // newest first
            Requests.InsertRange(0, fresh);
            // caps: rows, and the bodies + heads they hold (oldest go first)
            int keep = Math.Min(Requests.Count, MaxRows);
            long bytes = _retainedBodyBytes;
            for (int i = Requests.Count - 1; i >= keep; i--) bytes -= Requests[i].Weight;
            while (bytes > MaxRetainedBodyBytes && keep > 1) bytes -= Requests[--keep].Weight;
            if (keep < Requests.Count)
            {
                for (int i = keep; i < Requests.Count; i++)
                {
                    _rowsById.Remove(Requests[i].Request.Id);
                    if (ReferenceEquals(Requests[i], SelectedRequest)) SelectedRequest = null;
                }
                Requests.RemoveRange(keep, Requests.Count - keep);
                _retainedBodyBytes = bytes;
            }
            OnPropertyChanged(nameof(HasRequests));
        }
        if (selectedChanged) BuildDetail();
        UpdateCatchCounts();
        return true;
    }

    private void UpdateCatchCounts()
    {
        int dropped = Volatile.Read(ref _catchDropped);
        string t = $"{Plural(_catchTotal, "request")}" + (Requests.Count < _catchTotal ? $" · newest {Requests.Count} kept" : string.Empty)
                   + (dropped > 0 ? $" · {dropped} skipped (flood)" : string.Empty);
        if (t != CatchCounts) CatchCounts = t;
    }

    [RelayCommand]
    private void ClearRequests()
    {
        Requests.Clear();
        _rowsById.Clear();
        _retainedBodyBytes = 0;
        _catchTotal = 0;
        Interlocked.Exchange(ref _catchDropped, 0);
        _shownDropped = 0;
        SelectedRequest = null;
        OnPropertyChanged(nameof(HasRequests));
        UpdateCatchCounts();
    }

    // ================================================================ details

    partial void OnSelectedRequestChanged(CatcherRow? value)
    {
        if (value is null) { Detail = null; IsDetailOpen = false; return; }
        IsDetailOpen = true;
        BuildDetail();
    }

    partial void OnDetailChanged(CatcherDetail? value) => OnPropertyChanged(nameof(HasDetail));

    [RelayCommand]
    private void CloseDetail()
    {
        IsDetailOpen = false;
        SelectedRequest = null;
    }

    // Formatting a 1 MB JSON body takes a moment: done on the pool, the newest selection wins.
    private void BuildDetail()
    {
        var row = SelectedRequest;
        if (row is null) { Detail = null; return; }
        int gen = ++_detailGen;
        _ = Task.Run(() =>
        {
            CatcherDetail d;
            try { d = MakeDetail(row); }
            catch (Exception ex) { CrashLog.Write("Catcher.Detail", ex); return; }
            Dispatcher.UIThread.Post(() => { if (gen == _detailGen) Detail = d; });
        });
    }

    internal static CatcherDetail MakeDetail(CatcherRow row)
    {
        var r = row.Request;
        string line = r.Kind switch
        {
            CaptureKind.WsMessage => $"WebSocket {(r.IsText ? "text" : "binary")} message · {RequestCatcher.Printable(r.Path)}",
            CaptureKind.WsClose => $"WebSocket close · {RequestCatcher.Printable(r.Path)}",
            _ => $"{RequestCatcher.Printable(r.Method)} {RequestCatcher.Printable(WsProtocol.Short(r.Target, 2000))} {r.Version}",
        };
        var meta = new List<string>
        {
            r.Time.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture),
            "from " + SocketNet.Label(new IPEndPoint(IPAddress.TryParse(r.ClientIp, out var ip) ? ip : IPAddress.None, r.ClientPort)),
        };
        if (r.Kind == CaptureKind.Http || r.Kind == CaptureKind.WsUpgrade)
            meta.Add(r.Status > 0 ? $"answered {r.Status}{(r.IsPreflight ? " (CORS preflight)" : "")}" : "not answered");
        if (r.Kind == CaptureKind.WsMessage) meta.Add(r.Delivered == 1 ? "echoed back" : $"echoed to {r.Delivered} clients");
        var headers = r.Headers.Select(h => new CatcherField(RequestCatcher.Printable(WsProtocol.Short(h.Key, CatcherFormat.MaxNameChars)),
                                                             RequestCatcher.Printable(WsProtocol.Short(h.Value, CatcherFormat.MaxValueChars)))).ToList();
        var query = r.Query.Length > 0
            ? CatcherFormat.Pairs(r.Query, plusIsSpace: true).Select(kv => new CatcherField(WsProtocol.Short(kv.Key, CatcherFormat.MaxNameChars),
                                                                                             WsProtocol.Short(kv.Value, CatcherFormat.MaxValueChars))).ToList()
            : new List<CatcherField>();
        return new CatcherDetail
        {
            Row = row,
            RequestLine = line,
            Meta = string.Join(" · ", meta),
            Note = r.Note,
            Headers = headers,
            Query = query,
            Body = CatcherFormat.Body(r),
        };
    }

    [RelayCommand]
    private async Task CopyCurl()
    {
        if (Detail is not { CanCopyCurl: true } d) return;
        string fallback = SelectedCatchUrl is { } u && Uri.TryCreate(u, UriKind.Absolute, out var uri) ? uri.Authority : "127.0.0.1:" + CatchPort;
        await ClipboardHelper.SetTextAsync(CatcherFormat.Curl(d.Row.Request, fallback));
    }

    [RelayCommand]
    private async Task CopyBody()
    {
        if (Detail is not { CanCopyBody: true } d) return;
        var b = d.Row.Request.Body;
        string text = SocketPayload.LooksLikeText(b) ? Encoding.UTF8.GetString(b) : SocketPayload.HexDump(b);
        await ClipboardHelper.SetTextAsync(text);
    }

    private static string Plural(long n, string unit) => n == 1 ? $"1 {unit}" : $"{n.ToString("N0", CultureInfo.InvariantCulture)} {unit}s";
}
