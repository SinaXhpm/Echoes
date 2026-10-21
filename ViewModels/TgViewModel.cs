using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>
/// Telegram Bot API workbench: connect a bot (getMe), pick a method from a grouped, searchable list, fill a form built
/// from the method's parameters (or edit the request as raw JSON), send it (multipart when a local file is attached),
/// and read the response: status, timing, pretty JSON, and for getUpdates a list of updates whose chat can be used in
/// the form. Calls of this session are kept in a history to re-open or send again.
///
/// <para>The bot token is never logged and never shown: the endpoint reads api.telegram.org/bot•••/method, and every
/// error and body is redacted (<see cref="TelegramApi"/>). It is kept so it needn't be pasted again — only sealed with
/// the install key (SecretProtector "enc2:"; without that key it stays in memory), like the proxy password; an old
/// plain-text copy ("tg.token") is purged. Persisted too: the method, its form values (minus secret ones: see
/// MayRemember), the editor mode and the proxy address / user.</para>
/// </summary>
public partial class TgViewModel : ObservableObject
{
    // ===================================================================== connection

    /// <summary>The bot token. Never logged or displayed; stored only sealed ("tg.botToken").</summary>
    [ObservableProperty] private string _botToken = string.Empty;
    [ObservableProperty] private bool _useProxy;
    [ObservableProperty] private string _proxyAddress = string.Empty;
    [ObservableProperty] private string _proxyUser = string.Empty;
    /// <summary>Stored only sealed ("tg.proxyPass").</summary>
    [ObservableProperty] private string _proxyPass = string.Empty;
    private const string KeyToken = "tg.botToken", KeyProxyPass = "tg.proxyPass";

    public ObservableCollection<string> ProxyHistory => HistoryService.Instance.Get("tg.proxy");

    private enum Conn { None, Checking, Connected, InvalidToken, NetworkError }
    private Conn _conn = Conn.None;

    [ObservableProperty] private string _connBadge = "Not connected";
    [ObservableProperty] private bool _connOk;
    [ObservableProperty] private bool _connBad;
    [ObservableProperty] private bool _connWarn;
    [ObservableProperty] private bool _connBusy;
    /// <summary>A plain-words problem with the token or the connection (replaces the token hint).</summary>
    [ObservableProperty] private string _connMessage = string.Empty;
    [ObservableProperty] private bool _isConnecting;
    [ObservableProperty] private bool _isConnected;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasBot), nameof(BotName), nameof(BotUsername), nameof(BotIdText), nameof(BotInitial),
                              nameof(CanJoinGroups), nameof(CanReadAllMessages), nameof(SupportsInline), nameof(StatusLine))]
    private TgBotIdentity? _bot;

    public bool HasBot => Bot is not null;
    public string BotName => Bot?.FirstName ?? string.Empty;
    public string BotUsername => Bot is { Username.Length: > 0 } b ? "@" + b.Username : string.Empty;
    public string BotIdText => Bot is { } b ? "id " + b.Id.ToString(CultureInfo.InvariantCulture) : string.Empty;
    public string BotInitial => Bot is { FirstName.Length: > 0 } b ? char.ToUpperInvariant(b.FirstName[0]).ToString() : "B";
    public bool CanJoinGroups => Bot?.CanJoinGroups == true;
    public bool CanReadAllMessages => Bot?.CanReadAllGroupMessages == true;
    public bool SupportsInline => Bot?.SupportsInlineQueries == true;

    /// <summary>The line under the token while no bot is shown: a problem, or what the token box expects.</summary>
    public string StatusLine
    {
        get
        {
            if (ConnMessage.Length > 0) return ConnMessage;
            string t = BotToken.Trim();
            if (t.Length == 0) return "Paste a token from @BotFather (saved encrypted).";
            if (!TelegramApi.IsTokenFormat(t)) return "Not a bot token: those look like 123456789:AAH…";
            return $"Token for bot {TelegramApi.BotIdOf(t)}. Press Connect to check it.";
        }
    }

    // ===================================================================== send state

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowEmptyState), nameof(ShowWaiting))]
    private bool _isSending;
    [ObservableProperty] private bool _isUploading;
    [ObservableProperty] private double _uploadPercent;
    [ObservableProperty] private string _sendingText = string.Empty;
    /// <summary>Phone layout: 0 = request, 1 = response.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowResponseOnPhone))]
    private int _phoneTabIndex;
    public bool ShowResponseOnPhone => PhoneTabIndex == 1;

    public ObservableCollection<TgHistoryItem> History { get; } = new();
    private const int MaxHistory = 50;
    private const int MaxHistoryJsonChars = 256 * 1024;

    // ===================================================================== lifetime + persistence

    private bool _loaded;
    // Persisted on change (debounced). The two secrets only sealed (FlushPendingSave).
    private static readonly HashSet<string> PersistProps = new()
    {
        nameof(UseProxy), nameof(ProxyAddress), nameof(ProxyUser), nameof(CustomMethodName), nameof(ShowOptional),
        nameof(BotToken), nameof(ProxyPass),
    };

    // ToolViews creates this VM itself (it has no MainViewModel slot), so live instances register here for
    // MainViewModel.FlushPersistence (app exit / backgrounded).
    private static readonly List<WeakReference<TgViewModel>> Live = new();

    public TgViewModel()
    {
        var ps = ProfileService.Instance;
        ps.Remove("tg.token");   // an earlier build's plain-text token: never kept that way (the sealed one is tg.botToken)
        BotToken = OpenSealed(ps.GetSetting(KeyToken));
        ProxyPass = OpenSealed(ps.GetSetting(KeyProxyPass));

        string savedProxy = ps.GetSetting("tg.proxy") ?? string.Empty;
        // Earlier builds had no switch: a saved proxy address meant "use it".
        UseProxy = ps.GetSetting("tg.useProxy") is { } up ? up == "true" : savedProxy.Trim().Length > 0;
        ProxyAddress = savedProxy.Length > 0 ? savedProxy : HistoryService.Instance.Last("tg.proxy") ?? string.Empty;
        ProxyUser = ps.GetSetting("tg.proxyUser") ?? string.Empty;
        ShowOptional = ps.GetBool("tg.optional");
        CustomMethodName = ps.GetSetting("tg.custom") ?? string.Empty;

        string methodKey = ps.GetSetting("tg.method") ?? "getMe";
        // An earlier build remembered every form value, secret ones included (a secret_token, a webhook URL with the
        // token in it): those stay in this session's form, and the stored copy is re-written without them below.
        bool purgeSecrets = LoadFormMemory(ps.GetSetting("tg.form"));
        // Earlier builds kept one "key=value" text box for the last method: carry it over as that method's values.
        if (ps.GetSetting("tg.params") is { Length: > 0 } legacy) MigrateLegacyParams(methodKey, legacy);
        ps.Remove("tg.params");

        InitNav();
        SelectKey(methodKey);
        if (ps.GetSetting("tg.mode") == "json") EditorModeIndex = 1;

        _loaded = true;
        if (purgeSecrets) SchedulePersist();
        lock (Live) Live.Add(new WeakReference<TgViewModel>(this));
    }

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (_loaded && e.PropertyName is { } n && PersistProps.Contains(n)) SchedulePersist();
    }

    // Debounced like CheckHostViewModel: the boxes update on every keystroke. Write once typing pauses; Send and app
    // exit / background flush a pending one.
    private CancellationTokenSource? _persistCts;
    private bool _persistPending;   // UI thread only

    private void SchedulePersist()
    {
        if (!_loaded) return;
        _persistPending = true;
        _persistCts?.Cancel();
        _persistCts?.Dispose();
        var cts = _persistCts = new CancellationTokenSource();
        _ = Task.Delay(600, cts.Token).ContinueWith(t =>
        {
            // Values are read back on the UI thread at write time, so the latest edit always wins.
            if (!t.IsCanceled) Avalonia.Threading.Dispatcher.UIThread.Post(FlushPendingSave);
        }, TaskScheduler.Default);
    }

    /// <summary>Persist a pending (debounced) settings change now. No-op when nothing is pending. UI thread only.
    /// The token and the proxy password go in sealed only (and not at all without the install key).</summary>
    public void FlushPendingSave()
    {
        _persistCts?.Cancel();
        if (!_persistPending) return;
        _persistPending = false;
        StashForm();
        // A login typed inline (socks5://bob:pw@host:1080) is saved like one typed into the fields: the user in
        // tg.proxyUser, the password sealed. The address itself is saved without it, so it would be lost on restart.
        var (inlineUser, inlinePass) = InlineCredentials(ProxyAddress);
        string saveUser = ProxyUser.Trim().Length > 0 ? ProxyUser.Trim() : inlineUser;
        string savePass = ProxyPass.Length > 0 ? ProxyPass : inlinePass;
        var items = new List<(string, string?)>
        {
            ("tg.method", _currentKey),
            ("tg.custom", CustomMethodName.Trim()),
            ("tg.mode", EditorModeIndex == 1 ? "json" : "form"),
            ("tg.optional", ShowOptional ? "true" : "false"),
            ("tg.useProxy", UseProxy ? "true" : "false"),
            ("tg.proxy", WithoutUserInfo(ProxyAddress)),   // a password typed inline is never saved
            ("tg.proxyUser", saveUser),
            ("tg.form", SerializeFormMemory()),
        };
        if (SecretProtector.IsKeyAvailable)
        {
            items.Add((KeyToken, SecretProtector.Protect(BotToken.Trim())));
            items.Add((KeyProxyPass, SecretProtector.Protect(savePass)));
        }
        ProfileService.Instance.SetMany(items.ToArray());
    }

    // Only a value sealed with this install's key counts (a plain or legacy-sealed one is ignored, not trusted).
    private static string OpenSealed(string? stored)
        => stored is { Length: > 0 } && stored.StartsWith("enc2:", StringComparison.Ordinal) ? SecretProtector.Unprotect(stored) : string.Empty;

    /// <summary><see cref="FlushPendingSave"/> on every live instance. UI thread only.</summary>
    public static void FlushAll()
    {
        lock (Live)
        {
            Live.RemoveAll(w => !w.TryGetTarget(out _));
            foreach (var w in Live)
                if (w.TryGetTarget(out var vm)) vm.FlushPendingSave();
        }
    }

    // ===================================================================== API client lifetime

    private TelegramApi? _api;
    private readonly List<TelegramApi> _retired = new();
    private int _inFlight;
    // Bumped whenever the token or the proxy changes: a call that started before reports into nothing stale.
    private int _apiGeneration;

    partial void OnBotTokenChanged(string value)
    {
        RetireApi();
        // A different token is a different bot: forget the identity and the verdict about the old one.
        _conn = Conn.None;
        Bot = null;
        ConnMessage = string.Empty;
        ApplyConnBadge();
        OnPropertyChanged(nameof(StatusLine));
    }

    partial void OnUseProxyChanged(bool value) => RetireApi();
    partial void OnProxyAddressChanged(string value) => RetireApi();
    partial void OnProxyUserChanged(string value) => RetireApi();
    partial void OnProxyPassChanged(string value) => RetireApi();
    partial void OnConnMessageChanged(string value) => OnPropertyChanged(nameof(StatusLine));

    // The client is rebuilt on the next call; one still in use is disposed when its call ends.
    private void RetireApi()
    {
        _apiGeneration++;
        if (_api is null) return;
        if (_inFlight == 0) _api.Dispose();
        else _retired.Add(_api);
        _api = null;
    }

    /// <summary>The client for the current token + proxy, or null with <paramref name="problem"/> in plain words.</summary>
    private TelegramApi? GetApi(out string? problem)
    {
        problem = null;
        if (_api is not null) return _api;
        try
        {
            _api = TelegramApi.Create(BotToken,
                UseProxy ? ProxyAddress : null, UseProxy ? ProxyUser : null, UseProxy ? ProxyPass : null);
            return _api;
        }
        catch (ArgumentException ex)
        {
            problem = TelegramApi.RedactStatic(ex.Message);
            return null;
        }
    }

    private void BeginCall() => _inFlight++;

    private void EndCall()
    {
        if (--_inFlight > 0) return;
        foreach (var a in _retired) a.Dispose();
        _retired.Clear();
    }

    // ===================================================================== connect (getMe)

    private CancellationTokenSource? _connectCts;

    [RelayCommand]
    private Task Connect() => Guarded(() => ConnectAsync(silent: false), "Telegram.Connect");

    /// <summary>Run a flow so nothing escapes it: a failure becomes a message, and the crash log gets a copy with
    /// anything token-shaped removed (exception texts can quote the request URL).</summary>
    private async Task Guarded(Func<Task> flow, string source)
    {
        try { await flow(); }
        catch (Exception ex)
        {
            IsSending = false;
            IsUploading = false;
            IsConnecting = false;
            string safe = (_api?.Redact(ex.Message) ?? TelegramApi.RedactStatic(ex.Message));
            ShowFormMessage("Something went wrong: " + safe, error: true);
            CrashLog.Write(source, new InvalidOperationException(TelegramApi.RedactStatic(_api?.Redact(ex.ToString()) ?? ex.ToString())));
        }
    }

    private async Task ConnectAsync(bool silent)
    {
        if (IsConnecting) return;
        var api = GetApi(out string? problem);
        if (api is null)
        {
            if (silent) return;
            _conn = BotToken.Trim().Length == 0 ? Conn.None : problem!.StartsWith("Invalid proxy", StringComparison.Ordinal) ? Conn.NetworkError : Conn.InvalidToken;
            ConnMessage = problem ?? string.Empty;
            ApplyConnBadge();
            return;
        }

        IsConnecting = true;
        int generation = _apiGeneration;
        _conn = Conn.Checking;
        ConnMessage = string.Empty;
        ApplyConnBadge();
        var cts = _connectCts = new CancellationTokenSource();
        BeginCall();
        TgCallResult result;
        try { result = await api.CallAsync(new TgRequest("getMe"), TelegramApi.DefaultTimeout, null, cts.Token); }
        finally { EndCall(); }

        bool viaProxy = UseProxy;
        var state = await Task.Run(() => BuildState("getMe", result, viaProxy));
        IsConnecting = false;
        _connectCts = null;
        cts.Dispose();
        if (generation != _apiGeneration)
        {
            // the token / proxy changed meanwhile: this verdict is about another bot. A new token resets the badge itself, a
            // new proxy doesn't: don't leave it on "Checking…" (a later send would then skip its own silent connect).
            if (_conn == Conn.Checking) { _conn = Conn.None; ApplyConnBadge(); }
            return;
        }
        if (result.Outcome == TgOutcome.Cancelled) { _conn = Conn.None; ApplyConnBadge(); return; }
        UpdateConnection("getMe", state);
        if (state.IsOk) RememberProxy();
    }

    /// <summary>Fold a call's outcome into the connection badge: getMe decides, and a 401 from any method means the token
    /// is bad.</summary>
    private void UpdateConnection(string method, TgResponseState s)
    {
        if (s.Outcome == TgOutcome.ApiError && s.ErrorCode == 401)
        {
            _conn = Conn.InvalidToken;
            Bot = null;
            ConnMessage = "Telegram rejected this token. Copy it again from @BotFather: it changes when it's revoked.";
        }
        else if (IsMethod(method, "getMe"))
        {
            switch (s.Outcome)
            {
                case TgOutcome.Ok when s.Bot is not null:
                    _conn = Conn.Connected;
                    Bot = s.Bot;
                    ConnMessage = string.Empty;
                    break;
                case TgOutcome.ApiError when s.ErrorCode == 404:
                    _conn = Conn.InvalidToken;
                    Bot = null;
                    ConnMessage = "Telegram doesn't recognize this token. Check that you copied all of it.";
                    break;
                case TgOutcome.ApiError:
                    _conn = Conn.NetworkError;
                    ConnMessage = s.Title + (s.Hint.Length > 0 ? " " + s.Hint : string.Empty);
                    break;
                case TgOutcome.Cancelled:
                    break;
                default:
                    _conn = Conn.NetworkError;
                    Bot = null;
                    ConnMessage = s.Title + (s.Hint.Length > 0 ? " " + s.Hint : string.Empty);
                    break;
            }
        }
        ApplyConnBadge();
    }

    private void ApplyConnBadge()
    {
        ConnBadge = _conn switch
        {
            Conn.Checking => "Checking…",
            Conn.Connected => "Connected",
            Conn.InvalidToken => "Invalid token",
            Conn.NetworkError => "Network error",
            _ => "Not connected",
        };
        ConnOk = _conn == Conn.Connected;
        ConnBad = _conn == Conn.InvalidToken;
        ConnWarn = _conn == Conn.NetworkError;
        ConnBusy = _conn == Conn.Checking;
        IsConnected = _conn == Conn.Connected;
    }

    // The proxy goes into the shared input history without any user:password@ part.
    private void RememberProxy()
    {
        if (!UseProxy || string.IsNullOrWhiteSpace(ProxyAddress)) return;
        HistoryService.Instance.Add("tg.proxy", WithoutUserInfo(ProxyAddress));
    }

    // ===================================================================== send

    private CancellationTokenSource? _sendCts;

    /// <summary>Send the current request, or stop the one in flight.</summary>
    [RelayCommand]
    private void Send()
    {
        if (IsSending) { _sendCts?.Cancel(); return; }
        _ = Guarded(SendAsync, "Telegram.Send");
    }

    private async Task SendAsync()
    {
        if (IsSending) return;
        FlushPendingSave();
        ClearFormMessage();

        var api = GetApi(out string? problem);
        if (api is null)
        {
            ShowFormMessage(BotToken.Trim().Length == 0 ? "Paste your bot token first (top of the page)." : problem ?? "Check the token.", error: true);
            if (BotToken.Trim().Length > 0 && problem is not null && !problem.StartsWith("Invalid proxy", StringComparison.Ordinal))
            {
                _conn = Conn.InvalidToken;
                ConnMessage = problem;
                ApplyConnBadge();
            }
            return;
        }

        var request = BuildRequest(out string? invalid);
        if (request is null)
        {
            ShowFormMessage(invalid ?? "Check the highlighted fields.", error: true);
            PhoneTabIndex = 0;
            return;
        }

        var snapshot = SnapshotForm();
        string method = request.Method;

        // Connect quietly alongside the first call for this token, so the badge and the bot's name fill in (a getMe
        // being sent does that itself).
        if (_conn == Conn.None && !IsMethod(method, "getMe")) _ = Guarded(() => ConnectAsync(silent: true), "Telegram.Connect");
        long uploadTotal = 0;
        foreach (var f in request.Files) uploadTotal += f.Value.Length ?? 0;

        IsSending = true;
        IsUploading = request.IsMultipart;
        UploadPercent = 0;
        SendingText = request.IsMultipart ? "Uploading…" : $"Sending {method}…";
        var cts = _sendCts = new CancellationTokenSource();
        IProgress<long>? progress = null;
        if (request.IsMultipart)
        {
            int lastPct = -1;
            progress = new Progress<long>(sent =>
            {
                if (!IsSending) return;
                if (uploadTotal <= 0) { SendingText = $"Uploading… {TelegramApi.FormatBytes(sent)}"; return; }
                int pct = (int)Math.Min(100, sent * 100 / uploadTotal);
                if (pct == lastPct) return;
                lastPct = pct;
                UploadPercent = pct;
                SendingText = pct >= 100 ? "Waiting for Telegram…" : $"Uploading… {pct}%";
            });
        }

        int generation = _apiGeneration;
        bool viaProxy = UseProxy;
        TgCallResult result;
        BeginCall();
        try { result = await api.CallAsync(request, TimeoutFor(request), progress, cts.Token); }
        finally { EndCall(); }

        // Pretty-printing and parsing the updates can take a moment on a big result: off the UI thread.
        TgResponseState state = await Task.Run(() => BuildState(method, result, viaProxy));
        IsSending = false;
        IsUploading = false;
        SendingText = string.Empty;
        _sendCts = null;
        cts.Dispose();

        ApplyResponse(state);
        if (generation == _apiGeneration)
        {
            UpdateConnection(method, state);
            if (state.IsOk) RememberProxy();
        }
        AddHistory(snapshot, state);
        PhoneTabIndex = 1;
    }

    // Long polling: getUpdates waits up to its "timeout" for news, so the call may take that long plus some slack.
    private TimeSpan TimeoutFor(TgRequest request)
    {
        int poll = 0;
        if (IsMethod(request.Method, "getUpdates"))
        {
            if (FindField("timeout") is { } f && int.TryParse(f.Value.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int t)) poll = t;
            if (EditorModeIndex == 1 && JsonInt(RawJson, "timeout") is int jt) poll = jt;
        }
        double seconds = Math.Clamp(poll + 20, TelegramApi.DefaultTimeout.TotalSeconds, TelegramApi.MaxTimeout.TotalSeconds);
        return TimeSpan.FromSeconds(seconds);
    }

    // ===================================================================== history

    private void AddHistory(TgSnapshot request, TgResponseState response)
    {
        var item = new TgHistoryItem
        {
            Method = response.Method,
            Time = DateTime.Now.ToString("HH:mm:ss", CultureInfo.InvariantCulture),
            StatusText = response.IsOk ? "OK" : response.Badge,
            Summary = Summarize(request),
            ElapsedText = response.Elapsed.TotalMilliseconds < 1 ? "–" : FormatElapsed(response.Elapsed),
            IsOk = response.IsOk,
            IsWarn = response.IsWarn,
            IsError = response.IsError,
            Request = request,
            Response = response.Json.Length > MaxHistoryJsonChars ? Trimmed(response) : response,
        };
        History.Insert(0, item);
        while (History.Count > MaxHistory) History.RemoveAt(History.Count - 1);
        OnHistoryChanged();
    }

    private void OnHistoryChanged()
    {
        OnPropertyChanged(nameof(HasHistory));
        OnPropertyChanged(nameof(HistoryCountText));
        OnPropertyChanged(nameof(ShowHistoryEmpty));
    }

    public bool HasHistory => History.Count > 0;
    public string HistoryCountText => History.Count.ToString(CultureInfo.InvariantCulture);

    private static TgResponseState Trimmed(TgResponseState s) => new()
    {
        Method = s.Method, Outcome = s.Outcome, HttpStatus = s.HttpStatus, ErrorCode = s.ErrorCode, Badge = s.Badge,
        Title = s.Title, Hint = s.Hint, Meta = s.Meta, Updates = s.Updates, NextOffset = s.NextOffset, FilePath = s.FilePath,
        Bot = s.Bot, Elapsed = s.Elapsed,
        Json = s.Json[..MaxHistoryJsonChars] + "\n\n… [kept in history: the first 256 KB; send it again for the full response]",
    };

    private static string Summarize(TgSnapshot s)
    {
        var parts = new List<string>();
        foreach (var (k, v) in s.Values)
        {
            if (parts.Count == 3) break;
            // No credentials in the list: a secret parameter is masked, and a token / user:password@ is redacted BEFORE
            // the cut (a cut-off token no longer looks like one).
            string shown = IsSecretName(k) ? "•••" : TelegramApi.RedactStatic(v).ReplaceLineEndings(" ").Trim();
            if (shown.Length > 24) shown = shown[..24] + "…";
            parts.Add($"{k}={shown}");
        }
        foreach (var (k, u) in s.Uploads)
            if (parts.Count < 4) parts.Add($"{k}={u.FileName}");
        if (s.JsonMode) return "Raw JSON" + (parts.Count > 0 ? " · " + string.Join(" · ", parts) : string.Empty);
        return parts.Count > 0 ? string.Join(" · ", parts) : "No parameters";
    }

    /// <summary>Re-open a history entry: its request in the form, its response in the panel.</summary>
    public void Reopen(TgHistoryItem item)
    {
        LoadSnapshot(item.Request);
        ApplyResponse(item.Response);
        IsBrowsing = false;
        PhoneTabIndex = 0;
        ShowFormMessage($"Re-opened {item.Method} from {item.Time}.", error: false);
    }

    [RelayCommand]
    private void Rerun(TgHistoryItem? item)
    {
        if (item is null || IsSending) return;
        LoadSnapshot(item.Request);
        IsBrowsing = false;
        _ = Guarded(SendAsync, "Telegram.Send");
    }

    [RelayCommand]
    private void ClearHistory()
    {
        History.Clear();
        OnHistoryChanged();
    }

    // ===================================================================== getFile download

    /// <summary>Download the getFile result shown in the panel into <paramref name="destination"/>. Null on success, else
    /// the reason (redacted).</summary>
    public async Task<string?> DownloadFileAsync(Stream destination)
    {
        if (RespFilePath is not { Length: > 0 } path) return "Run getFile first.";
        var api = GetApi(out string? problem);
        if (api is null) return problem;
        BeginCall();
        try { return await api.DownloadAsync(path, destination); }
        finally { EndCall(); }
    }

    /// <summary>The outcome of Save file (the view runs the save dialog).</summary>
    public void ReportFileSaved(string? fileName, string? error)
    {
        if (error is null) ShowFormMessage($"Saved {fileName}.", error: false);
        else ShowFormMessage(error, error: true);
    }

    // ===================================================================== small helpers

    /// <summary>Bot API method names are case-insensitive.</summary>
    private static bool IsMethod(string method, string name) => string.Equals(method, name, StringComparison.OrdinalIgnoreCase);

    /// <summary>A proxy address without any user:password@ part (for the profile and the input history).</summary>
    /// <summary>The user and password written into a proxy address (scheme://user:pass@host:port), unescaped; empty when none.</summary>
    internal static (string User, string Pass) InlineCredentials(string proxy)
    {
        string p = proxy.Trim();
        int scheme = p.IndexOf("://", StringComparison.Ordinal);
        int start = scheme >= 0 ? scheme + 3 : 0;
        int at = p.LastIndexOf('@');
        if (at < start) return (string.Empty, string.Empty);
        string info = p[start..at];
        int colon = info.IndexOf(':');
        return colon >= 0
            ? (Uri.UnescapeDataString(info[..colon]), Uri.UnescapeDataString(info[(colon + 1)..]))
            : (Uri.UnescapeDataString(info), string.Empty);
    }

    internal static string WithoutUserInfo(string proxy)
    {
        string p = proxy.Trim();
        int scheme = p.IndexOf("://", StringComparison.Ordinal);
        int start = scheme >= 0 ? scheme + 3 : 0;
        int at = p.LastIndexOf('@');
        return at >= start ? p[..start] + p[(at + 1)..] : p;
    }

    internal static string FormatElapsed(TimeSpan t)
        => t.TotalMilliseconds < 1000
            ? ((int)Math.Round(t.TotalMilliseconds)).ToString(CultureInfo.InvariantCulture) + " ms"
            : t.TotalSeconds.ToString("0.0#", CultureInfo.InvariantCulture) + " s";
}
