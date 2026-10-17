using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

// The response panel: status, timing, pretty JSON, getUpdates as a list, and plain-words hints for common errors.
public partial class TgViewModel
{
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowEmptyState), nameof(ShowWaiting), nameof(HasRespProblem), nameof(ShowJson),
                              nameof(ShowUpdatesList), nameof(ShowNoUpdates), nameof(ShowNoBody))]
    private bool _hasResponse;

    [ObservableProperty] private string _respMethod = string.Empty;
    [ObservableProperty] private string _respBadge = string.Empty;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasRespProblem))]
    private bool _respOk;
    [ObservableProperty] private bool _respWarn;
    [ObservableProperty] private bool _respError;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasRespTitle))]
    private string _respTitle = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasRespHint))]
    private string _respHint = string.Empty;

    [ObservableProperty] private string _respMeta = string.Empty;
    /// <summary>The whole pretty-printed response (Copy takes this; the box shows a capped part).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowJson), nameof(ShowNoBody))]
    private string _respJson = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(UpdatesTabText), nameof(ShowUpdatesList), nameof(ShowNoUpdates))]
    private IReadOnlyList<TgUpdateRow> _updates = Array.Empty<TgUpdateRow>();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowJson), nameof(ShowUpdatesList), nameof(ShowNoUpdates))]
    private bool _isUpdatesResponse;

    /// <summary>getUpdates: 0 = the parsed list, 1 = JSON.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowJson), nameof(ShowUpdatesList), nameof(ShowNoUpdates))]
    private int _respViewIndex;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasNextOffset), nameof(NextOffsetText))]
    private long? _respNextOffset;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanDownload), nameof(DownloadUrlText), nameof(DownloadName))]
    private string? _respFilePath;

    public bool HasRespTitle => RespTitle.Length > 0;
    public bool HasRespHint => RespHint.Length > 0;
    public bool HasRespProblem => HasResponse && !RespOk;
    public bool ShowJson => HasResponse && (!IsUpdatesResponse || RespViewIndex == 1) && RespJson.Length > 0;
    /// <summary>A failure with nothing to show (no response arrived).</summary>
    public bool ShowNoBody => HasResponse && RespJson.Length == 0;
    public bool ShowUpdatesList => HasResponse && IsUpdatesResponse && RespViewIndex == 0 && Updates.Count > 0;
    public bool ShowNoUpdates => HasResponse && IsUpdatesResponse && RespViewIndex == 0 && Updates.Count == 0;
    public bool ShowEmptyState => !HasResponse && !IsSending;
    public bool ShowWaiting => !HasResponse && IsSending;
    public string UpdatesTabText => Updates.Count == 1 ? "1 update" : $"{Updates.Count} updates";
    public bool HasNextOffset => RespNextOffset is not null;
    public string NextOffsetText => RespNextOffset is long n ? "Use offset " + n.ToString(CultureInfo.InvariantCulture) : string.Empty;
    public bool CanDownload => RespFilePath is { Length: > 0 };
    public string DownloadUrlText => RespFilePath is { Length: > 0 } p ? $"{TelegramApi.DisplayHost}/file/bot•••/{p}" : string.Empty;
    /// <summary>A file name for the save dialog: the last segment of the server's file_path, reduced to a plain name. A
    /// '\' or '..' in it must not make the dialog suggest another folder (it resolves a typed relative path), and
    /// characters a file system refuses become '_'.</summary>
    public string DownloadName
    {
        get
        {
            const string Fallback = "telegram-file";
            if (RespFilePath is not { Length: > 0 } p) return Fallback;
            int slash = p.LastIndexOfAny(new[] { '/', '\\' });
            string name = slash >= 0 ? p[(slash + 1)..] : p;
            var sb = new StringBuilder(name.Length);
            foreach (char c in name)
                sb.Append(c < ' ' || c is '<' or '>' or ':' or '"' or '|' or '?' or '*' ? '_' : c);
            name = sb.ToString().Trim().TrimEnd('.');
            return name.Length is > 0 and <= 200 ? name : Fallback;
        }
    }

    private void ApplyResponse(TgResponseState s)
    {
        RespMethod = s.Method;
        RespBadge = s.Badge;
        RespOk = s.IsOk;
        RespWarn = s.IsWarn;
        RespError = s.IsError;
        RespTitle = s.Title;
        RespHint = s.Hint;
        RespMeta = s.Meta;
        RespJson = s.Json;
        Updates = s.Updates ?? (IReadOnlyList<TgUpdateRow>)Array.Empty<TgUpdateRow>();
        IsUpdatesResponse = s.Updates is not null;
        RespViewIndex = 0;
        RespNextOffset = s.NextOffset;
        RespFilePath = s.FilePath;
        HasResponse = true;
    }

    [RelayCommand]
    private void ClearResponse()
    {
        HasResponse = false;
        RespJson = string.Empty;
        Updates = Array.Empty<TgUpdateRow>();
        IsUpdatesResponse = false;
        RespNextOffset = null;
        RespFilePath = null;
        RespTitle = string.Empty;
        RespHint = string.Empty;
    }

    /// <summary>Briefly true after Copy: the button shows a check mark instead of the copy glyph.</summary>
    [ObservableProperty] private bool _justCopied;
    private int _copyTicket;

    [RelayCommand]
    private async Task CopyResponse()
    {
        if (string.IsNullOrEmpty(RespJson)) return;
        await ClipboardHelper.SetTextAsync(RespJson);
        int ticket = ++_copyTicket;
        JustCopied = true;
        await Task.Delay(1500);
        if (ticket == _copyTicket) JustCopied = false;
    }

    // ===================================================================== building the state (thread pool)

    internal static TgResponseState BuildState(string method, TgCallResult r, bool viaProxy)
    {
        try
        {
            string json = r.Json is not null ? TelegramApi.Pretty(r.Json, r.Body) : r.Body;
            IReadOnlyList<TgUpdateRow>? updates = null;
            long? next = null;
            string? filePath = null;
            TgBotIdentity? bot = null;
            // Bot API method names are case-insensitive.
            if (r.Ok && r.Json is not null && r.Json.RootElement.TryGetProperty("result", out var result))
            {
                if (method.Equals("getUpdates", StringComparison.OrdinalIgnoreCase) && result.ValueKind == JsonValueKind.Array)
                    (updates, next) = ParseUpdates(result);
                else if (method.Equals("getMe", StringComparison.OrdinalIgnoreCase) && result.ValueKind == JsonValueKind.Object)
                    bot = ParseBot(result);
                else if (method.Equals("getFile", StringComparison.OrdinalIgnoreCase) && result.ValueKind == JsonValueKind.Object
                         && result.TryGetProperty("file_path", out var fp) && fp.ValueKind == JsonValueKind.String)
                    filePath = fp.GetString();
            }

            string badge = r.Outcome switch
            {
                TgOutcome.Ok => "OK",
                TgOutcome.ApiError => "Error " + r.ErrorCode.ToString(CultureInfo.InvariantCulture),
                TgOutcome.HttpError => "HTTP " + r.HttpStatus.ToString(CultureInfo.InvariantCulture),
                TgOutcome.NetworkError => "Network error",
                TgOutcome.Timeout => "Timed out",
                TgOutcome.Cancelled => "Stopped",
                _ => "Not sent",
            };
            string title = r.Outcome == TgOutcome.Ok ? OkSummary(method, updates, bot, filePath) : r.Description;
            string meta = r.HttpStatus > 0
                ? $"HTTP {r.HttpStatus} · {FormatElapsed(r.Elapsed)} · {TelegramApi.FormatBytes(r.Bytes)}"
                : FormatElapsed(r.Elapsed);

            return new TgResponseState
            {
                Method = method, Outcome = r.Outcome, HttpStatus = r.HttpStatus, ErrorCode = r.ErrorCode,
                Badge = badge, Title = title, Hint = HintFor(method, r, viaProxy), Meta = meta,
                Json = json.Length > 0 ? json : (r.Outcome == TgOutcome.Ok ? "(empty response)" : string.Empty),
                Updates = updates, NextOffset = next, FilePath = filePath, Bot = bot, Elapsed = r.Elapsed,
            };
        }
        finally { r.Json?.Dispose(); }
    }

    private static string OkSummary(string method, IReadOnlyList<TgUpdateRow>? updates, TgBotIdentity? bot, string? filePath)
    {
        if (updates is not null) return updates.Count == 1 ? "1 update" : $"{updates.Count} updates";
        if (bot is not null) return bot.Username.Length > 0 ? $"@{bot.Username}" : bot.FirstName;
        if (filePath is not null) return filePath;
        return string.Empty;
    }

    /// <summary>What to do about a failure, in plain words; empty when Telegram's own description says enough.</summary>
    private static string HintFor(string method, TgCallResult r, bool viaProxy)
    {
        string d = r.Description;
        bool Has(string s) => d.Contains(s, StringComparison.OrdinalIgnoreCase);
        switch (r.Outcome)
        {
            case TgOutcome.ApiError:
                if (r.ErrorCode == 401) return "Telegram rejected the token. Copy it again from @BotFather: it changes when it's revoked.";
                if (r.ErrorCode == 404)
                    return method.Equals("getMe", StringComparison.OrdinalIgnoreCase)
                        ? "Telegram doesn't recognize this token. Check that you copied all of it."
                        : "No such method, or the token is malformed. Check the method's spelling.";
                if (r.ErrorCode == 429)
                    return r.RetryAfter is int s
                        ? $"Too many requests: Telegram asks to wait {s} s before the next call."
                        : "Too many requests: wait a little, then try again.";
                if (r.ErrorCode == 409 && Has("webhook"))
                    return "A webhook is set, so getUpdates is blocked. Run deleteWebhook first, or check getWebhookInfo.";
                if (r.ErrorCode == 409)
                    return "Something else is polling this bot right now (another program or server running it).";
                if (r.MigrateToChatId is long migrated)
                    return $"The group became a supergroup: use chat_id {migrated.ToString(CultureInfo.InvariantCulture)}.";
                if (Has("chat not found"))
                    return "The bot can't see this chat. Open the bot and press Start, or add it to the group, then try again.";
                if (Has("bot was blocked")) return "This user blocked the bot.";
                if (Has("bot was kicked") || Has("not a member")) return "The bot isn't a member of this chat.";
                if (Has("not enough rights") || Has("administrator") || Has("have no rights"))
                    return "The bot needs admin rights in this chat to do that.";
                if (Has("can't parse entities"))
                    return "The text isn't valid for the chosen parse_mode. Fix the markup, or clear parse_mode.";
                if (Has("message text is empty")) return "text can't be empty.";
                if (Has("message to edit not found") || Has("message to delete not found") || Has("message to forward not found") || Has("message to copy not found"))
                    return "Check message_id: there's no such message in that chat (or it's too old).";
                if (Has("message is not modified")) return "The new content is the same as the old one.";
                if (Has("wrong file identifier") || Has("wrong remote file") || Has("failed to get http url content") || Has("wrong type of the web page content"))
                    return "Telegram couldn't use that file_id or URL. A file_id only works for the bot that received it.";
                if (r.ErrorCode == 413 || Has("too large") || Has("too big")) return "The file is too large for the Bot API.";
                if (Has("query is too old") || Has("query id is invalid"))
                    return "Callback queries must be answered within about 15 seconds of the button press.";
                return string.Empty;
            case TgOutcome.NetworkError:
                if (Has("didn't resolve") || Has("host not found"))
                    return viaProxy ? "Check the proxy, or your DNS." : "Check your DNS, or turn on Proxy if Telegram is blocked here.";
                if (Has("TLS")) return "Something on the network may be intercepting the connection: try a proxy.";
                if (Has("proxy")) return "Check the proxy address, its type (HTTP / SOCKS5) and its user / password.";
                return viaProxy
                    ? "Check that the proxy is running and its address, or turn Proxy off."
                    : "Check your connection. If Telegram is blocked on this network, turn on Proxy.";
            case TgOutcome.Timeout:
                return method.Equals("getUpdates", StringComparison.OrdinalIgnoreCase)
                    ? "With a long-poll timeout Telegram waits that long for news. Otherwise check your connection or proxy."
                    : viaProxy ? "Check the proxy, or turn it off." : "Check your connection, or use a proxy.";
            default:
                return string.Empty;
        }
    }

    private static TgBotIdentity ParseBot(JsonElement r) => new()
    {
        Id = r.TryGetProperty("id", out var id) && Num(id, out long i) ? i : 0,
        FirstName = Str(r, "first_name"),
        Username = Str(r, "username"),
        CanJoinGroups = Bool(r, "can_join_groups"),
        CanReadAllGroupMessages = Bool(r, "can_read_all_group_messages"),
        SupportsInlineQueries = Bool(r, "supports_inline_queries"),
    };

    // ---------------------------------------------------------------- getUpdates

    private const int MaxUpdateRows = 1000;

    private static (IReadOnlyList<TgUpdateRow> Rows, long? Next) ParseUpdates(JsonElement result)
    {
        var rows = new List<TgUpdateRow>();
        long? maxId = null;
        foreach (var u in result.EnumerateArray())
        {
            if (u.ValueKind != JsonValueKind.Object) continue;
            long updateId = u.TryGetProperty("update_id", out var uid) && Num(uid, out long x) ? x : 0;
            if (maxId is null || updateId > maxId) maxId = updateId;
            if (rows.Count >= MaxUpdateRows) continue;

            string kind = string.Empty;
            JsonElement payload = default;
            foreach (var p in u.EnumerateObject())
            {
                if (p.NameEquals("update_id")) continue;
                kind = p.Name;
                payload = p.Value;
                break;
            }
            rows.Add(Row(updateId, kind, payload));
        }
        return (rows, maxId + 1);
    }

    private static TgUpdateRow Row(long updateId, string kind, JsonElement p)
    {
        JsonElement chat = default, from = default;
        string text = string.Empty;
        long date = 0;
        if (p.ValueKind == JsonValueKind.Object)
        {
            switch (kind)
            {
                case "message" or "edited_message" or "channel_post" or "edited_channel_post"
                     or "business_message" or "edited_business_message":
                    p.TryGetProperty("chat", out chat);
                    if (!p.TryGetProperty("from", out from)) p.TryGetProperty("sender_chat", out from);
                    text = MessageText(p);
                    date = Long(p, "date");
                    break;
                case "callback_query":
                    p.TryGetProperty("from", out from);
                    if (p.TryGetProperty("message", out var m) && m.ValueKind == JsonValueKind.Object)
                    {
                        m.TryGetProperty("chat", out chat);
                        date = Long(m, "date");
                    }
                    text = "button: " + Str(p, "data");
                    break;
                case "inline_query":
                    p.TryGetProperty("from", out from);
                    text = "inline: " + Str(p, "query");
                    break;
                case "chosen_inline_result":
                    p.TryGetProperty("from", out from);
                    text = "chose " + Str(p, "result_id");
                    break;
                case "my_chat_member" or "chat_member":
                    p.TryGetProperty("chat", out chat);
                    p.TryGetProperty("from", out from);
                    date = Long(p, "date");
                    text = MemberChange(p);
                    break;
                case "chat_join_request":
                    p.TryGetProperty("chat", out chat);
                    p.TryGetProperty("from", out from);
                    date = Long(p, "date");
                    text = "asks to join";
                    break;
                case "message_reaction" or "message_reaction_count":
                    p.TryGetProperty("chat", out chat);
                    if (!p.TryGetProperty("user", out from)) p.TryGetProperty("actor_chat", out from);
                    date = Long(p, "date");
                    text = "reacted to message " + Long(p, "message_id").ToString(CultureInfo.InvariantCulture);
                    break;
                case "poll":
                    text = "poll: " + Str(p, "question");
                    break;
                case "poll_answer":
                    p.TryGetProperty("user", out from);
                    text = "answered a poll";
                    break;
                case "pre_checkout_query" or "shipping_query":
                    p.TryGetProperty("from", out from);
                    text = kind == "shipping_query" ? "shipping query" : "pre-checkout query";
                    break;
            }
        }

        long? chatId = chat.ValueKind == JsonValueKind.Object && chat.TryGetProperty("id", out var cid) && Num(cid, out long c) ? c : null;
        return new TgUpdateRow
        {
            UpdateId = updateId,
            KindText = KindText(kind),
            ChatTitle = chat.ValueKind == JsonValueKind.Object ? ChatTitle(chat) : string.Empty,
            ChatType = chat.ValueKind == JsonValueKind.Object ? Str(chat, "type") : string.Empty,
            ChatId = chatId,
            From = from.ValueKind == JsonValueKind.Object ? PersonName(from) : string.Empty,
            Text = OneLine(text),
            Time = date > 0 ? FormatDate(date) : string.Empty,
        };
    }

    private static string KindText(string kind) => kind switch
    {
        "message" => "Message",
        "edited_message" => "Edited",
        "channel_post" => "Channel post",
        "edited_channel_post" => "Edited post",
        "business_message" => "Business",
        "edited_business_message" => "Business edit",
        "callback_query" => "Button",
        "inline_query" => "Inline query",
        "chosen_inline_result" => "Inline result",
        "my_chat_member" => "Bot status",
        "chat_member" => "Member",
        "chat_join_request" => "Join request",
        "message_reaction" or "message_reaction_count" => "Reaction",
        "poll" => "Poll",
        "poll_answer" => "Poll answer",
        "pre_checkout_query" => "Checkout",
        "shipping_query" => "Shipping",
        "" => "Update",
        _ => kind.Replace('_', ' '),
    };

    private static string MessageText(JsonElement m)
    {
        string t = Str(m, "text");
        if (t.Length > 0) return t;
        string caption = Str(m, "caption");
        string media =
            m.TryGetProperty("photo", out _) ? "[photo]" :
            m.TryGetProperty("video", out _) ? "[video]" :
            m.TryGetProperty("animation", out _) ? "[GIF]" :
            m.TryGetProperty("document", out var doc) ? "[file " + Str(doc, "file_name") + "]" :
            m.TryGetProperty("audio", out _) ? "[audio]" :
            m.TryGetProperty("voice", out _) ? "[voice message]" :
            m.TryGetProperty("video_note", out _) ? "[video message]" :
            m.TryGetProperty("sticker", out var st) ? "[sticker " + Str(st, "emoji") + "]" :
            m.TryGetProperty("location", out _) ? "[location]" :
            m.TryGetProperty("contact", out _) ? "[contact]" :
            m.TryGetProperty("poll", out var poll) ? "[poll] " + Str(poll, "question") :
            m.TryGetProperty("new_chat_members", out _) ? "[joined]" :
            m.TryGetProperty("left_chat_member", out _) ? "[left]" :
            m.TryGetProperty("new_chat_title", out _) ? "[new title] " + Str(m, "new_chat_title") :
            m.TryGetProperty("pinned_message", out _) ? "[pinned a message]" :
            m.TryGetProperty("group_chat_created", out _) || m.TryGetProperty("supergroup_chat_created", out _) ? "[group created]" :
            string.Empty;
        return caption.Length > 0 ? (media.Length > 0 ? media + " " + caption : caption) : media;
    }

    private static string MemberChange(JsonElement p)
    {
        string before = p.TryGetProperty("old_chat_member", out var o) ? Str(o, "status") : string.Empty;
        string after = p.TryGetProperty("new_chat_member", out var n) ? Str(n, "status") : string.Empty;
        return before.Length > 0 || after.Length > 0 ? $"{before} → {after}" : "membership changed";
    }

    private static string ChatTitle(JsonElement chat)
    {
        string title = Str(chat, "title");
        if (title.Length > 0) return title;
        string name = (Str(chat, "first_name") + " " + Str(chat, "last_name")).Trim();
        if (name.Length > 0) return name;
        string user = Str(chat, "username");
        return user.Length > 0 ? "@" + user : string.Empty;
    }

    private static string PersonName(JsonElement who)
    {
        string name = (Str(who, "first_name") + " " + Str(who, "last_name")).Trim();
        if (name.Length == 0) name = Str(who, "title");
        string user = Str(who, "username");
        if (user.Length > 0) return name.Length > 0 ? $"{name} (@{user})" : "@" + user;
        return name;
    }

    private static string FormatDate(long unix)
    {
        try
        {
            var t = DateTimeOffset.FromUnixTimeSeconds(unix).ToLocalTime();
            return t.Date == DateTime.Today
                ? t.ToString("HH:mm", CultureInfo.InvariantCulture)
                : t.ToString("MMM d, HH:mm", CultureInfo.InvariantCulture);
        }
        catch (ArgumentOutOfRangeException) { return string.Empty; }
    }

    private static string OneLine(string s)
    {
        if (s.Length > 300) s = s[..300] + "…";
        var sb = new StringBuilder(s.Length);
        foreach (char ch in s) sb.Append(ch is '\r' or '\n' or '\t' ? ' ' : ch);
        return sb.ToString().Trim();
    }

    private static string Str(JsonElement e, string name)
        => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? string.Empty : string.Empty;

    private static bool Bool(JsonElement e, string name)
        => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;

    private static long Long(JsonElement e, string name)
        => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && Num(v, out long l) ? l : 0;

    // JsonElement.TryGetInt64 throws on anything but a number.
    private static bool Num(JsonElement e, out long value)
    {
        value = 0;
        return e.ValueKind == JsonValueKind.Number && e.TryGetInt64(out value);
    }
}
