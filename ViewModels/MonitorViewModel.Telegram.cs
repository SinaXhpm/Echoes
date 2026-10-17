using System;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

// Telegram alerts: the settings (bot token, chat, optional proxy), "Find my chat", "Send test message", and handing the
// down / up / warning alerts to the background sender (Helpers/MonitorNotify.cs).
//
// Secrets: the bot token and the proxy password are stored only sealed by SecretProtector ("enc2:", this install's own
// key) — never in plain text; where no key file can be made they are kept for this session only. Neither is ever put in
// a status line, an event, the input history or a log: the token shows as "…7Kx3" once saved.
public sealed partial class MonitorViewModel
{
    private const string KeyTgEnabled = "monitor.tg.enabled", KeyTgToken = "monitor.tg.token", KeyTgBot = "monitor.tg.bot",
        KeyTgChat = "monitor.tg.chat", KeyTgChatName = "monitor.tg.chatName",
        // ends in ".useProxy": a backup import brings it in switched off (ProfileService's risky toggles)
        KeyTgUseProxy = "monitor.tg.useProxy", KeyTgProxy = "monitor.tg.proxy", KeyTgProxyUser = "monitor.tg.proxyUser",
        KeyTgProxyPass = "monitor.tg.proxyPass";
    private const int MaxChatIdLength = 64;

    private MonitorNotifier _notifier = null!;   // created in LoadTelegramSettings (the constructor)
    private string _tgToken = string.Empty;      // plain text, in memory only
    private string _tgBot = string.Empty;        // "@echoes_bot" from getMe (not secret)
    private CancellationTokenSource? _tgCts;     // the running Find my chat / test / token check
    private bool _settingChat;                   // TgChatId set from a found chat: keep its name
    private bool _tgProxyPassUnreadable;         // the stored proxy password didn't open this run: keep it until one is typed

    [ObservableProperty] private bool _tgEnabled;
    /// <summary>The paste box for a new token (never persisted; emptied once saved).</summary>
    [ObservableProperty] private string _tgTokenInput = string.Empty;
    [ObservableProperty] private bool _hasTgToken;
    /// <summary>"@echoes_bot · …7Kx3": the saved token, masked.</summary>
    [ObservableProperty] private string _tgTokenMasked = string.Empty;
    [ObservableProperty] private bool _isEditingTgToken;
    [ObservableProperty] private string _tgChatId = string.Empty;
    [ObservableProperty] private string _tgChatName = string.Empty;
    [ObservableProperty] private MonitorTelegramChat? _tgSelectedChat;
    [ObservableProperty] private bool _showTgChatPicker;
    [ObservableProperty] private bool _tgUseProxy;
    [ObservableProperty] private string _tgProxy = string.Empty;
    [ObservableProperty] private string _tgProxyUser = string.Empty;
    [ObservableProperty] private string _tgProxyPass = string.Empty;
    [ObservableProperty] private string _tgStatus = string.Empty;
    [ObservableProperty] private bool _tgStatusIsError;
    [ObservableProperty] private bool _tgStatusIsOk;
    [ObservableProperty] private bool _isTgBusy;

    /// <summary>The chats "Find my chat" found, when there is more than one to pick from.</summary>
    public ObservableCollection<MonitorTelegramChat> TgChats { get; } = new();

    public bool HasTgStatus => TgStatus.Length > 0;
    public bool ShowTgTokenBox => !HasTgToken || IsEditingTgToken;
    public bool ShowTgTokenSaved => HasTgToken && !IsEditingTgToken;
    public bool CanCancelTgToken => HasTgToken && IsEditingTgToken;
    public bool HasTgChatName => TgChatName.Length > 0;
    public bool CanFindTgChat => HasTgToken && !IsTgBusy;
    public bool CanSendTgTest => HasTgToken && TgChatId.Trim().Length > 0 && !IsTgBusy;

    /// <summary>One line under the switch: what is still missing, or where alerts go.</summary>
    public string TgHint => !TgEnabled ? "Down, up and warning alerts from your own bot."
        : !HasTgToken ? "Paste your bot's token (create a bot with @BotFather)."
        : TgChatId.Trim().Length == 0 ? "Send your bot any message, then press Find my chat."
        : !IsChatId(TgChatId.Trim()) ? "The chat ID is a number (like 123456789) or a @channel name."
        : $"Alerts go to {(TgChatName.Length > 0 ? TgChatName : "chat " + TgChatId.Trim())}.";

    /// <summary>The background sender (tests read its counters and shorten its timing).</summary>
    internal MonitorNotifier Notifier => _notifier;

    private void LoadTelegramSettings(ProfileService ps)
    {
        _notifier = new MonitorNotifier(
            (text, failure) => Dispatcher.UIThread.Post(() => AddEvent(null, MonitorEventKind.Telegram, text, failure)),
            id => Dispatcher.UIThread.Post(() => { _settingChat = true; try { TgChatId = id; } finally { _settingChat = false; } }));

        TgEnabled = ps.GetBool(KeyTgEnabled, false);
        _tgBot = ps.GetSetting(KeyTgBot) ?? string.Empty;
        string stored = ps.GetSetting(KeyTgToken) ?? string.Empty;
        if (stored.Length > 0)
        {
            string plain = SecretProtector.Unprotect(stored);
            if (plain.Length == 0)
            {
                // Sealed with a key this install doesn't have (another machine / user, a restored profile): left as it is
                // on disk until a new token is saved.
                SetTgStatus("The saved bot token can't be opened on this device. Paste it again.", error: true);
            }
            else if (!TelegramApi.IsTokenFormat(plain)) ps.Remove(KeyTgToken);
            else
            {
                _tgToken = plain;
                ResealIfNeeded(ps, KeyTgToken, stored, plain);
            }
        }
        HasTgToken = _tgToken.Length > 0;
        UpdateTokenMask();

        _settingChat = true;
        try
        {
            TgChatId = ps.GetSetting(KeyTgChat) ?? string.Empty;
            TgChatName = ps.GetSetting(KeyTgChatName) ?? string.Empty;
        }
        finally { _settingChat = false; }
        TgUseProxy = ps.GetBool(KeyTgUseProxy, false);
        TgProxy = ps.GetSetting(KeyTgProxy) ?? string.Empty;
        TgProxyUser = ps.GetSetting(KeyTgProxyUser) ?? string.Empty;
        string pass = ps.GetSetting(KeyTgProxyPass) ?? string.Empty;
        TgProxyPass = SecretProtector.Unprotect(pass);
        if (TgProxyPass.Length > 0) ResealIfNeeded(ps, KeyTgProxyPass, pass, TgProxyPass);
        // Sealed with a key this run doesn't have (none loaded this run, or another device's): left as it is on disk
        // until a password is typed — an edit of the address or the switch must not erase it.
        else _tgProxyPassUnreadable = pass.Length > 0;
        ReconfigureNotifier();
    }

    // Plain text (hand-edited) is never left on disk: sealed, or else kept for this session only. The legacy "enc1:" seal
    // is upgraded only when this install's key is there (otherwise it stays as it is — still sealed — rather than lost).
    private static void ResealIfNeeded(ProfileService ps, string key, string stored, string plain)
    {
        if (!SecretProtector.IsProtected(stored)) StoreSecret(ps, key, plain);
        else if (SecretProtector.IsLegacy(stored) && SecretProtector.IsKeyAvailable) StoreSecret(ps, key, plain);
    }

    /// <summary>
    /// Stores a secret sealed with this install's key ("enc2:"). Where that key can't be had, the old machine-derived
    /// seal is not good enough: nothing is stored (the secret lasts this session) and false comes back.
    /// </summary>
    private static bool StoreSecret(ProfileService ps, string key, string plain)
    {
        if (plain.Length == 0) { ps.Remove(key); return true; }
        string sealedValue = SecretProtector.Protect(plain);
        if (!SecretProtector.IsProtected(sealedValue) || SecretProtector.IsLegacy(sealedValue))
        {
            ps.Remove(key);
            return false;
        }
        ps.SetSetting(key, sealedValue);
        return true;
    }

    private void UpdateTokenMask()
    {
        if (_tgToken.Length == 0) { TgTokenMasked = string.Empty; return; }
        // The tail first: on a phone the line trims at its end, and the bot's name is the part that can go.
        string tail = "…" + _tgToken[^4..];
        TgTokenMasked = _tgBot.Length > 0 ? $"{tail} · {_tgBot}" : tail;
    }

    private void SetTgStatus(string text, bool error = false, bool ok = false)
    {
        TgStatusIsError = error;
        TgStatusIsOk = ok && !error;
        TgStatus = text;
    }

    // ================================================================ commands

    /// <summary>Saves the pasted token (sealed), then checks it with getMe to show the bot's name.</summary>
    [RelayCommand]
    private async Task SaveTgToken()
    {
        string token = (TgTokenInput ?? string.Empty).Trim();
        if (token.Length == 0) { SetTgStatus("Paste the bot token from @BotFather first.", error: true); return; }
        // Never echo what was typed: a near-miss is still most of a secret.
        if (!TelegramApi.IsTokenFormat(token))
        {
            SetTgStatus("That doesn't look like a bot token. It looks like 123456789:AAH… (from @BotFather).", error: true);
            return;
        }
        var ps = ProfileService.Instance;
        bool stored = StoreSecret(ps, KeyTgToken, token);
        _tgToken = token;
        _tgBot = string.Empty;
        ps.Remove(KeyTgBot);
        TgTokenInput = string.Empty;
        IsEditingTgToken = false;
        HasTgToken = true;
        UpdateTokenMask();
        ReconfigureNotifier();
        SetTgStatus(stored ? "Bot token saved. Checking it…" : "Bot token kept for this session only: this device can't store secrets safely.");
        await CheckTokenAsync(stored);
    }

    private async Task CheckTokenAsync(bool stored)
    {
        if (BuildTgConfig(requireChat: false, out var problem) is not { } cfg) { SetTgStatus(problem!, error: true); return; }
        var ct = BeginTgCall();
        try
        {
            var (bot, error) = await Task.Run(() => MonitorTelegram.GetMeAsync(cfg, ct), ct);
            if (ct.IsCancellationRequested) return;
            if (bot is not null)
            {
                _tgBot = bot;
                ProfileService.Instance.SetSetting(KeyTgBot, bot);
                UpdateTokenMask();
                SetTgStatus(stored ? $"Bot token saved: {bot}." : $"Token works ({bot}), kept for this session only.", ok: true);
            }
            else SetTgStatus("Bot token saved, but checking it failed: " + error, error: true);
        }
        catch (OperationCanceledException) { }
        finally { EndTgCall(ct); }
    }

    [RelayCommand]
    private void ChangeTgToken()
    {
        TgTokenInput = string.Empty;
        IsEditingTgToken = true;
    }

    [RelayCommand]
    private void CancelTgToken()
    {
        TgTokenInput = string.Empty;
        IsEditingTgToken = false;
    }

    [RelayCommand]
    private void RemoveTgToken()
    {
        _tgCts?.Cancel();
        _tgToken = string.Empty;
        _tgBot = string.Empty;
        var ps = ProfileService.Instance;
        ps.Remove(KeyTgToken);
        ps.Remove(KeyTgBot);
        TgTokenInput = string.Empty;
        IsEditingTgToken = false;
        HasTgToken = false;
        UpdateTokenMask();
        TgChats.Clear();
        ShowTgChatPicker = false;
        ReconfigureNotifier();
        SetTgStatus("Bot token removed.");
    }

    /// <summary>getUpdates: the chats that wrote to the bot. One → taken; several → picked from a list.</summary>
    [RelayCommand]
    private async Task FindTgChat()
    {
        if (BuildTgConfig(requireChat: false, out var problem) is not { } cfg) { SetTgStatus(problem!, error: true); return; }
        var ct = BeginTgCall();
        SetTgStatus("Looking for chats that wrote to your bot…");
        TgChats.Clear();
        ShowTgChatPicker = false;
        try
        {
            var (chats, error) = await Task.Run(() => MonitorTelegram.FindChatsAsync(cfg, ct), ct);
            if (ct.IsCancellationRequested) return;
            if (chats is null) { SetTgStatus(error ?? "Couldn't read the bot's messages.", error: true); return; }
            if (chats.Count == 0)
            {
                SetTgStatus("No messages yet. Open your bot in Telegram, send it any message (like /start), then press Find my chat again.");
                return;
            }
            if (chats.Count == 1)
            {
                UseChat(chats[0]);
                SetTgStatus($"Found {chats[0].Label}. Alerts go there.", ok: true);
                return;
            }
            foreach (var c in chats) TgChats.Add(c);
            TgSelectedChat = null;
            ShowTgChatPicker = true;
            SetTgStatus($"Found {chats.Count} chats. Pick the one for alerts.");
        }
        catch (OperationCanceledException) { }
        finally { EndTgCall(ct); }
    }

    partial void OnTgSelectedChatChanged(MonitorTelegramChat? value)
    {
        if (value is null) return;
        UseChat(value);
        ShowTgChatPicker = false;
        SetTgStatus($"Alerts go to {value.Label}.", ok: true);
    }

    private void UseChat(MonitorTelegramChat chat)
    {
        _settingChat = true;
        try
        {
            TgChatId = chat.Id;
            TgChatName = chat.Label;
        }
        finally { _settingChat = false; }
    }

    [RelayCommand]
    private async Task SendTgTest()
    {
        if (BuildTgConfig(requireChat: true, out var problem) is not { } cfg) { SetTgStatus(problem!, error: true); return; }
        var ct = BeginTgCall();
        SetTgStatus("Sending a test message…");
        try
        {
            string text = "✅ Echoes monitor: test message\nAlerts for your monitors will arrive in this chat.";
            string? error = await Task.Run(() => MonitorTelegram.SendOnceAsync(cfg, text, ct), ct);
            if (ct.IsCancellationRequested) return;
            if (error is null)
                SetTgStatus($"Test message sent at {DateTime.Now.ToString("HH:mm:ss", CultureInfo.InvariantCulture)}. Check Telegram.", ok: true);
            else SetTgStatus("Test message not sent: " + error, error: true);
        }
        catch (OperationCanceledException) { }
        finally { EndTgCall(ct); }
    }

    private CancellationToken BeginTgCall()
    {
        _tgCts?.Cancel();
        var cts = new CancellationTokenSource();
        _tgCts = cts;
        IsTgBusy = true;
        return cts.Token;
    }

    private void EndTgCall(CancellationToken ct)
    {
        if (_tgCts is { } cts && cts.Token == ct)
        {
            _tgCts = null;
            cts.Dispose();
            IsTgBusy = false;
        }
    }

    // ================================================================ config

    /// <summary>The current settings as one config, or null with the reason (no token, no chat, a bad proxy address).</summary>
    private MonitorTelegramConfig? BuildTgConfig(bool requireChat, out string? problem)
    {
        problem = null;
        if (_tgToken.Length == 0) { problem = "Save the bot token first."; return null; }
        string chat = TgChatId.Trim();
        if (requireChat && chat.Length == 0) { problem = "Pick the chat first: send your bot a message, then press Find my chat."; return null; }
        if (requireChat && !IsChatId(chat)) { problem = "The chat ID is a number (like 123456789 or -1001234567890) or a @channel name."; return null; }
        string? proxy = null;
        if (TgUseProxy && TgProxy.Trim().Length > 0)
        {
            if (!HttpHelper.TryParseProxy(TgProxy.Trim(), out _))
            {
                problem = "Invalid proxy address. Use host:port, e.g. 127.0.0.1:1080 or socks5://127.0.0.1:1080.";
                return null;
            }
            proxy = TgProxy.Trim();
        }
        return new MonitorTelegramConfig(_tgToken, chat, proxy,
            proxy is null ? null : NullIfEmpty(TgProxyUser.Trim()), proxy is null ? null : NullIfEmpty(TgProxyPass));
    }

    private static string? NullIfEmpty(string s) => s.Length == 0 ? null : s;

    internal static bool IsChatId(string s)
    {
        if (s.Length is 0 or > MaxChatIdLength) return false;
        if (s[0] == '@')
        {
            if (s.Length < 2) return false;
            for (int i = 1; i < s.Length; i++) if (!(char.IsAsciiLetterOrDigit(s[i]) || s[i] == '_')) return false;
            return true;
        }
        return long.TryParse(s, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out _);
    }

    /// <summary>Alerts go out only while the switch is on and a token and a valid chat are set.</summary>
    private void ReconfigureNotifier()
    {
        if (_notifier is null) return;
        var cfg = TgEnabled && IsChatId(TgChatId.Trim()) ? BuildTgConfigLenient() : null;
        _notifier.Configure(cfg);
    }

    // As BuildTgConfig, but a bad proxy address still configures the sender: its failure then shows in the events log.
    private MonitorTelegramConfig? BuildTgConfigLenient()
    {
        if (_tgToken.Length == 0) return null;
        bool useProxy = TgUseProxy && TgProxy.Trim().Length > 0;
        return new MonitorTelegramConfig(_tgToken, TgChatId.Trim(), useProxy ? TgProxy.Trim() : null,
            useProxy ? NullIfEmpty(TgProxyUser.Trim()) : null, useProxy ? NullIfEmpty(TgProxyPass) : null);
    }

    /// <summary>Hands one alert to the sender (no-op while Telegram alerts are off).</summary>
    private void Alert(MonitorAlertKind kind, MonitorTarget t, string reason, DateTime time)
    {
        if (_notifier is { IsConfigured: true }) _notifier.Enqueue(new MonitorAlert(kind, t.DisplayName, reason, time));
    }

    // ================================================================ persistence of the plain settings

    partial void OnTgEnabledChanged(bool value)
    {
        OnPropertyChanged(nameof(TgHint));
        if (!_loaded) return;
        ProfileService.Instance.SetBool(KeyTgEnabled, value);
        ReconfigureNotifier();
    }

    partial void OnTgChatIdChanged(string value)
    {
        if (!_settingChat && TgChatName.Length > 0) TgChatName = string.Empty;   // typed by hand: the old name no longer applies
        OnTgFieldsChanged();
        if (!_loaded) return;
        string chat = value.Trim();
        ProfileService.Instance.SetMany((KeyTgChat, chat.Length > MaxChatIdLength ? chat[..MaxChatIdLength] : chat), (KeyTgChatName, TgChatName));
        ReconfigureNotifier();
    }

    partial void OnTgChatNameChanged(string value)
    {
        OnPropertyChanged(nameof(HasTgChatName));
        OnPropertyChanged(nameof(TgHint));
        if (_loaded) ProfileService.Instance.SetSetting(KeyTgChatName, value);
    }

    partial void OnTgUseProxyChanged(bool value) => PersistTgProxy();
    partial void OnTgProxyChanged(string value) => PersistTgProxy();
    partial void OnTgProxyUserChanged(string value) => PersistTgProxy();
    partial void OnTgProxyPassChanged(string value)
    {
        if (_loaded) _tgProxyPassUnreadable = false;   // typed (or cleared) by the user: that is the password now
        PersistTgProxy();
    }

    // The address is stored without any user:password@ (that goes to the user / sealed password keys instead).
    private void PersistTgProxy()
    {
        if (!_loaded) return;
        var ps = ProfileService.Instance;
        string address = TgProxy.Trim();
        string user = TgProxyUser.Trim(), pass = TgProxyPass;
        if (user.Length == 0 && HttpHelper.TryParseProxy(address, out var uri) && uri.UserInfo.Length > 0)
        {
            string[] ui = uri.UserInfo.Split(':', 2);
            user = Uri.UnescapeDataString(ui[0]);
            pass = ui.Length > 1 ? Uri.UnescapeDataString(ui[1]) : string.Empty;
        }
        ps.SetMany((KeyTgUseProxy, TgUseProxy ? "true" : "false"), (KeyTgProxy, HttpHelper.WithoutUserInfo(address)), (KeyTgProxyUser, user));
        if (pass.Length > 0 || !_tgProxyPassUnreadable) StoreSecret(ps, KeyTgProxyPass, pass);
        ReconfigureNotifier();
    }

    partial void OnHasTgTokenChanged(bool value) => OnTgFieldsChanged();
    partial void OnIsEditingTgTokenChanged(bool value) => OnTgFieldsChanged();
    partial void OnIsTgBusyChanged(bool value) => OnTgFieldsChanged();
    partial void OnTgStatusChanged(string value) => OnPropertyChanged(nameof(HasTgStatus));

    private void OnTgFieldsChanged()
    {
        OnPropertyChanged(nameof(ShowTgTokenBox));
        OnPropertyChanged(nameof(ShowTgTokenSaved));
        OnPropertyChanged(nameof(CanCancelTgToken));
        OnPropertyChanged(nameof(CanFindTgChat));
        OnPropertyChanged(nameof(CanSendTgTest));
        OnPropertyChanged(nameof(TgHint));
    }
}
