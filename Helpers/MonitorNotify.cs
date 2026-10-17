using System;
using System.Buffers;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

public enum MonitorAlertKind { Down, Up, Warning }

/// <summary>One thing worth a Telegram message: a monitor went down, came back, or has a new warning.</summary>
public sealed record MonitorAlert(MonitorAlertKind Kind, string Target, string Reason, DateTime Time);

/// <summary>Where alerts go: a bot token, a chat, and an optional proxy for the Bot API calls. Never logged.</summary>
public sealed record MonitorTelegramConfig(string Token, string ChatId, string? Proxy, string? ProxyUser, string? ProxyPass)
{
    // A record prints its members: keep the token / password out of any accidental ToString (logs, debugger displays).
    public override string ToString() => $"Telegram chat {ChatId}";
}

/// <summary>A chat the bot has seen (getUpdates), for "Find my chat".</summary>
public sealed record MonitorTelegramChat(string Id, string Name, string Type)
{
    public string Label => Type == "private" ? $"{Name} (private chat)" : $"{Name} ({Type})";
}

/// <summary>
/// The Bot API calls the monitor makes — getMe, getUpdates, sendMessage — through <see cref="TelegramApi"/> (redirects
/// off, token only in the request path, every text redacted, loopback-only <see cref="TelegramApi.BaseUrl"/> test hook).
/// Never throws: failures come back as plain-words text that never contains the token or the proxy password.
/// </summary>
public static class MonitorTelegram
{
    public static readonly TimeSpan CallTimeout = TimeSpan.FromSeconds(20);
    public const int MaxMessageChars = 4000;   // the Bot API takes 4096

    private static readonly JsonWriterOptions Json = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    /// <summary>The client for <paramref name="cfg"/>, or null with the reason (bad token format / proxy address).</summary>
    public static TelegramApi? Create(MonitorTelegramConfig cfg, out string? problem)
    {
        problem = null;
        try { return TelegramApi.Create(cfg.Token, cfg.Proxy, cfg.ProxyUser, cfg.ProxyPass); }
        catch (ArgumentException ex) { problem = TelegramApi.RedactStatic(ex.Message); return null; }
    }

    /// <summary>"@bot_name" (getMe), or null with the reason.</summary>
    public static async Task<(string? Username, string? Error)> GetMeAsync(MonitorTelegramConfig cfg, CancellationToken ct)
    {
        using var api = Create(cfg, out var problem);
        if (api is null) return (null, problem);
        var r = await api.CallAsync(new TgRequest("getMe"), CallTimeout, null, ct).ConfigureAwait(false);
        using (r.Json)
        {
            if (!r.Ok) return (null, Explain(r, cfg));
            if (r.Json?.RootElement.TryGetProperty("result", out var me) == true && me.ValueKind == JsonValueKind.Object
                && me.TryGetProperty("username", out var u) && u.ValueKind == JsonValueKind.String)
                return ("@" + u.GetString(), null);
            return ("your bot", null);
        }
    }

    /// <summary>The chats that wrote to the bot recently (newest first), from getUpdates — without confirming the updates,
    /// so whatever else reads this bot still gets them.</summary>
    public static async Task<(List<MonitorTelegramChat>? Chats, string? Error)> FindChatsAsync(MonitorTelegramConfig cfg, CancellationToken ct)
    {
        using var api = Create(cfg, out var problem);
        if (api is null) return (null, problem);
        var req = new TgRequest("getUpdates") { JsonBody = "{\"limit\":100,\"timeout\":0}" };
        var r = await api.CallAsync(req, CallTimeout, null, ct).ConfigureAwait(false);
        using (r.Json)
        {
            if (!r.Ok)
            {
                if (r.ErrorCode == 409 || r.HttpStatus == 409)
                    return (null, "This bot has a webhook, so its messages can't be read here. Type the chat ID instead.");
                return (null, Explain(r, cfg));
            }
            var chats = new List<MonitorTelegramChat>();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            if (r.Json?.RootElement.TryGetProperty("result", out var updates) == true && updates.ValueKind == JsonValueKind.Array)
            {
                // Newest update last in the array: walk it backwards so the latest chat comes first.
                var list = new List<JsonElement>();
                foreach (var u in updates.EnumerateArray()) list.Add(u);
                for (int i = list.Count - 1; i >= 0; i--)
                {
                    if (list[i].ValueKind != JsonValueKind.Object) continue;
                    foreach (var p in list[i].EnumerateObject())
                    {
                        if (p.Value.ValueKind != JsonValueKind.Object) continue;
                        var holder = p.Value;
                        if (p.Name == "callback_query" && holder.TryGetProperty("message", out var m)) holder = m;
                        if (holder.ValueKind != JsonValueKind.Object || !holder.TryGetProperty("chat", out var chat)
                            || chat.ValueKind != JsonValueKind.Object) continue;
                        if (ChatOf(chat) is { } c && seen.Add(c.Id)) chats.Add(c);
                    }
                }
            }
            return (chats, null);
        }
    }

    private static MonitorTelegramChat? ChatOf(JsonElement chat)
    {
        if (!chat.TryGetProperty("id", out var idEl) || idEl.ValueKind != JsonValueKind.Number || !idEl.TryGetInt64(out long id)) return null;
        string type = Str(chat, "type") ?? "chat";
        string? name = Str(chat, "title");
        if (name is null)
        {
            string first = Str(chat, "first_name") ?? string.Empty, last = Str(chat, "last_name") ?? string.Empty;
            name = (first + " " + last).Trim();
            if (Str(chat, "username") is { } user) name = name.Length > 0 ? $"{name} @{user}" : "@" + user;
        }
        if (string.IsNullOrWhiteSpace(name)) name = id.ToString(CultureInfo.InvariantCulture);
        if (name.Length > 60) name = name[..60] + "…";
        return new MonitorTelegramChat(id.ToString(CultureInfo.InvariantCulture), name, type);
    }

    private static string? Str(JsonElement o, string name)
        => o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() is { Length: > 0 } s ? s : null;

    /// <summary>sendMessage (plain text, no link previews). The raw result: callers read RetryAfter / MigrateToChatId.</summary>
    public static async Task<TgCallResult> SendAsync(TelegramApi api, string chatId, string text, CancellationToken ct)
    {
        var req = new TgRequest("sendMessage") { JsonBody = MessageJson(chatId, text) };
        return await api.CallAsync(req, CallTimeout, null, ct).ConfigureAwait(false);
    }

    /// <summary>One sendMessage with its own client: "Send test message".</summary>
    public static async Task<string?> SendOnceAsync(MonitorTelegramConfig cfg, string text, CancellationToken ct)
    {
        using var api = Create(cfg, out var problem);
        if (api is null) return problem;
        var r = await SendAsync(api, cfg.ChatId, text, ct).ConfigureAwait(false);
        using (r.Json) return r.Ok ? null : Explain(r, cfg);
    }

    internal static string MessageJson(string chatId, string text)
    {
        var buffer = new ArrayBufferWriter<byte>(256 + text.Length * 2);
        using (var w = new Utf8JsonWriter(buffer, Json))
        {
            w.WriteStartObject();
            // A numeric id goes as a number, "@channel" as a string.
            if (long.TryParse(chatId, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out long id)) w.WriteNumber("chat_id", id);
            else w.WriteString("chat_id", chatId);
            w.WriteString("text", text);
            w.WriteStartObject("link_preview_options");
            w.WriteBoolean("is_disabled", true);
            w.WriteEndObject();
            w.WriteEndObject();
        }
        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    /// <summary>A failed call in plain words, with what to do about it (redacted by <see cref="TelegramApi"/>).</summary>
    public static string Explain(TgCallResult r, MonitorTelegramConfig cfg)
    {
        string d = r.Description.TrimEnd('.');
        switch (r.Outcome)
        {
            case TgOutcome.ApiError when r.ErrorCode is 401 or 404:
                return "Telegram rejected the bot token. Copy it again from @BotFather.";
            case TgOutcome.ApiError when r.ErrorCode == 400 && d.Contains("chat not found", StringComparison.OrdinalIgnoreCase):
                return "Chat not found. Send your bot a message first, then use Find my chat.";
            case TgOutcome.ApiError when r.ErrorCode == 403:
                return "The bot can't write to that chat (" + d + "). Start the bot or add it to the group again.";
            case TgOutcome.ApiError when r.ErrorCode == 429:
                return $"Telegram asked to slow down (too many requests){(r.RetryAfter is int s ? $", retry in {s} s" : "")}.";
            case TgOutcome.NetworkError or TgOutcome.Timeout:
                return string.IsNullOrWhiteSpace(cfg.Proxy)
                    ? d + ". If Telegram is blocked where you are, use a proxy."
                    : d + ". Check the proxy.";
            default:
                return d.Length > 0 ? d + "." : "Telegram didn't accept the request.";
        }
    }

    /// <summary>Worth trying again later: no answer, a server error, or "too many requests".</summary>
    public static bool IsTransient(TgCallResult r)
        => r.Outcome is TgOutcome.NetworkError or TgOutcome.Timeout
           || (r.Outcome == TgOutcome.HttpError && (r.HttpStatus >= 500 || r.HttpStatus == 429 || r.HttpStatus == 0))
           || (r.Outcome == TgOutcome.ApiError && (r.ErrorCode == 429 || r.ErrorCode >= 500));

    // ---------------------------------------------------------------- message text

    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    private static string Mark(MonitorAlertKind k) => k switch
    {
        MonitorAlertKind.Down => "🔴 DOWN",
        MonitorAlertKind.Up => "🟢 UP",
        _ => "🟠 WARNING",
    };

    private static string When(DateTime t, DateTime now)
        => t.Date == now.Date ? t.ToString("HH:mm:ss", Inv) : t.ToString("MMM d, HH:mm:ss", Inv);

    /// <summary>
    /// The text of one message: a single alert as three short lines (what · target / reason / time), several as a header
    /// plus one line each — capped below Telegram's 4096 characters (the rest counted in a last line).
    /// </summary>
    public static string BuildText(IReadOnlyList<MonitorAlert> alerts, DateTime now, int dropped = 0)
    {
        if (alerts.Count == 1 && dropped == 0)
        {
            var a = alerts[0];
            string reason = a.Reason.Length > 600 ? a.Reason[..600] + "…" : a.Reason;
            return $"{Mark(a.Kind)} · {a.Target}\n{reason}\n{a.Time.ToString("MMM d, HH:mm:ss", Inv)}";
        }

        int down = 0, up = 0, warn = 0;
        foreach (var a in alerts)
        {
            if (a.Kind == MonitorAlertKind.Down) down++;
            else if (a.Kind == MonitorAlertKind.Up) up++;
            else warn++;
        }
        var parts = new List<string>(3);
        if (down > 0) parts.Add($"{down} down");
        if (up > 0) parts.Add($"{up} up");
        if (warn > 0) parts.Add($"{warn} warning{(warn == 1 ? "" : "s")}");
        var sb = new StringBuilder();
        sb.Append("Echoes monitor: ").Append(string.Join(", ", parts)).Append('\n');
        int shown = 0;
        foreach (var a in alerts)
        {
            string reason = a.Reason.Length > 200 ? a.Reason[..200] + "…" : a.Reason;
            string line = $"{Mark(a.Kind)} · {a.Target} — {reason} ({When(a.Time, now)})";
            if (sb.Length + line.Length + 40 > MaxMessageChars) break;
            sb.Append('\n').Append(line);
            shown++;
        }
        int more = alerts.Count - shown + dropped;
        if (more > 0) sb.Append('\n').Append($"…and {more} more (see Events in Echoes)");
        return sb.ToString();
    }
}

/// <summary>
/// Sends the monitor's alerts to Telegram without ever holding up a check: alerts are queued on the UI thread and a single
/// background worker sends them. Alerts that come within <see cref="CoalesceWindow"/> of each other go out as ONE
/// message; messages are at least <see cref="MinGap"/> apart (a network drop flipping 50 monitors is one message, not 50);
/// a failure without an answer, a server error or a 429 is retried with backoff (Telegram's retry_after respected, alerts
/// that arrive meanwhile join the pending message); every failure is reported through the callback (the events log).
/// Never throws into the caller.
/// </summary>
public sealed class MonitorNotifier : IDisposable
{
    public const int MaxQueued = 200;

    // Timing (internal: the harness shortens it).
    internal TimeSpan CoalesceWindow = TimeSpan.FromSeconds(4);
    internal TimeSpan MinGap = TimeSpan.FromSeconds(10);
    internal TimeSpan[] Backoff = { TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(45), TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(5) };
    internal TimeSpan MaxRetryAfter = TimeSpan.FromMinutes(15);

    private readonly object _gate = new();
    private readonly List<MonitorAlert> _queue = new();
    private readonly SemaphoreSlim _signal = new(0, int.MaxValue);
    private readonly CancellationTokenSource _cts = new();
    private readonly Action<string, bool> _report;
    private readonly Action<string>? _chatMigrated;
    private MonitorTelegramConfig? _cfg;
    private TelegramApi? _api;
    private MonitorTelegramConfig? _apiFor;
    private int _dropped;
    private DateTime _lastSentUtc = DateTime.MinValue;
    private Task? _worker;

    /// <param name="report">(text, isFailure) for the events log — called on the worker's thread.</param>
    /// <param name="chatMigrated">The group became a supergroup: the new chat id to keep (worker's thread).</param>
    public MonitorNotifier(Action<string, bool> report, Action<string>? chatMigrated = null)
    {
        _report = report;
        _chatMigrated = chatMigrated;
    }

    /// <summary>Messages sent so far (diagnostics / tests).</summary>
    public int SentCount { get; private set; }

    public bool IsConfigured { get { lock (_gate) return _cfg is not null; } }

    /// <summary>Where alerts go now; null switches them off (queued alerts are dropped).</summary>
    public void Configure(MonitorTelegramConfig? cfg)
    {
        lock (_gate)
        {
            _cfg = cfg;
            if (cfg is null) { _queue.Clear(); _dropped = 0; }
        }
    }

    /// <summary>Queues an alert (UI thread; returns at once).</summary>
    public void Enqueue(MonitorAlert alert)
    {
        lock (_gate)
        {
            if (_cfg is null || _cts.IsCancellationRequested) return;
            if (_queue.Count >= MaxQueued) _dropped++;
            else _queue.Add(alert);
            _worker ??= Task.Run(WorkerAsync);
        }
        _signal.Release();
    }

    public void Dispose()
    {
        _cts.Cancel();
        lock (_gate) { _api?.Dispose(); _api = null; }
    }

    private async Task WorkerAsync()
    {
        var token = _cts.Token;
        try
        {
            while (!token.IsCancellationRequested)
            {
                await _signal.WaitAsync(token).ConfigureAwait(false);
                // Let the burst finish (one round flips many monitors), and keep messages apart.
                await Task.Delay(CoalesceWindow, token).ConfigureAwait(false);
                var gap = _lastSentUtc + MinGap - DateTime.UtcNow;
                if (gap > TimeSpan.Zero) await Task.Delay(gap, token).ConfigureAwait(false);

                // Signals first, then the queue: an alert queued in between keeps its own signal for the next pass.
                while (_signal.CurrentCount > 0) _signal.Wait(0);
                var batch = new List<MonitorAlert>();
                int dropped = Drain(batch);
                if (batch.Count == 0) continue;
                await SendBatchAsync(batch, dropped, token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            // Never a crash: report it; the next alert starts a fresh worker (the app keeps monitoring).
            try { _report("Telegram alert not sent after an internal error: " + TelegramApi.RedactStatic(ex.Message), true); } catch { }
        }
        finally
        {
            lock (_gate) _worker = null;
        }
    }

    private int Drain(List<MonitorAlert> into)
    {
        lock (_gate)
        {
            into.AddRange(_queue);
            _queue.Clear();
            int d = _dropped;
            _dropped = 0;
            return d;
        }
    }

    private async Task SendBatchAsync(List<MonitorAlert> batch, int dropped, CancellationToken token)
    {
        for (int attempt = 0; ; attempt++)
        {
            MonitorTelegramConfig? cfg;
            lock (_gate) cfg = _cfg;
            if (cfg is null) return;   // switched off meanwhile

            var api = ApiFor(cfg, out string? problem);
            if (api is null)
            {
                _report($"Telegram alert not sent: {problem}", true);
                return;
            }

            string text = MonitorTelegram.BuildText(batch, DateTime.Now, dropped);
            var r = await MonitorTelegram.SendAsync(api, cfg.ChatId, text, token).ConfigureAwait(false);
            r.Json?.Dispose();
            if (r.Outcome == TgOutcome.Cancelled) return;
            if (r.Ok)
            {
                _lastSentUtc = DateTime.UtcNow;
                SentCount++;
                if (attempt > 0) _report($"Telegram alert sent after {attempt + 1} tries.", false);
                return;
            }

            // A group upgraded to a supergroup has a new id: keep it and send there.
            if (r.MigrateToChatId is long newId && attempt < 2)
            {
                string id = newId.ToString(CultureInfo.InvariantCulture);
                lock (_gate) if (_cfg is not null) _cfg = _cfg with { ChatId = id };
                _chatMigrated?.Invoke(id);
                continue;
            }

            string why = MonitorTelegram.Explain(r, cfg);
            int alerts = batch.Count + dropped;
            string what = alerts == 1 ? "Telegram alert" : $"Telegram message ({alerts} alerts)";
            if (!MonitorTelegram.IsTransient(r))
            {
                _report($"{what} not sent: {why}", true);
                return;
            }
            if (attempt >= Backoff.Length)
            {
                _report($"{what} dropped after {attempt + 1} tries: {why}", true);
                return;
            }

            TimeSpan wait = Backoff[attempt];
            if (r.RetryAfter is int ra && ra > 0)
                wait = TimeSpan.FromSeconds(Math.Min(ra, MaxRetryAfter.TotalSeconds));
            if (attempt == 0) _report($"{what} not sent: {why} Trying again in {MonitorFormat.Duration(wait)}.", true);
            await Task.Delay(wait, token).ConfigureAwait(false);

            // Alerts that came in meanwhile ride along with the retry.
            while (_signal.CurrentCount > 0) _signal.Wait(0);
            dropped += Drain(batch);
            if (batch.Count > MaxQueued) { dropped += batch.Count - MaxQueued; batch.RemoveRange(MaxQueued, batch.Count - MaxQueued); }
        }
    }

    private TelegramApi? ApiFor(MonitorTelegramConfig cfg, out string? problem)
    {
        problem = null;
        lock (_gate)
        {
            if (_api is not null && Equals(_apiFor, cfg with { ChatId = string.Empty })) return _api;
            _api?.Dispose();
            _api = MonitorTelegram.Create(cfg, out problem);
            _apiFor = _api is null ? null : cfg with { ChatId = string.Empty };
            return _api;
        }
    }
}
