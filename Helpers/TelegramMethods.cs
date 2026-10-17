using System;
using System.Collections.Generic;

namespace Echoes.Helpers;

/// <summary>How a Bot API parameter is edited, validated and encoded.</summary>
public enum TgParamKind
{
    /// <summary>One line of text.</summary>
    Text,
    /// <summary>Several lines of text (message text, captions).</summary>
    LongText,
    /// <summary>A whole number (ids, counts, unix times).</summary>
    Integer,
    /// <summary>A decimal number (latitude, longitude).</summary>
    Float,
    /// <summary>True / false; left unset, Telegram's default applies.</summary>
    Bool,
    /// <summary>A JSON value (reply_markup, allowed_updates, commands…), checked before sending.</summary>
    Json,
    /// <summary>A numeric chat id or a @channelusername.</summary>
    ChatId,
    /// <summary>A file: a local upload (multipart), or a file_id / HTTP URL as text.</summary>
    File,
    /// <summary>One of a fixed set of values (parse_mode, chat actions).</summary>
    Choice,
}

/// <summary>One known parameter of a Bot API method.</summary>
public sealed class TgParamDef
{
    public TgParamDef(string name, TgParamKind kind, bool required = false, string? placeholder = null,
                      string? tip = null, string[]? options = null, long maxUploadBytes = 0)
    {
        Name = name;
        Kind = kind;
        Required = required;
        Placeholder = placeholder ?? string.Empty;
        Tip = tip ?? string.Empty;
        Options = options ?? Array.Empty<string>();
        MaxUploadBytes = maxUploadBytes > 0 ? maxUploadBytes : TelegramApi.MaxUploadBytes;
    }

    public string Name { get; }
    public TgParamKind Kind { get; }
    public bool Required { get; }
    public string Placeholder { get; }
    public string Tip { get; }
    public string[] Options { get; }
    /// <summary>Largest local file this parameter accepts (photos: 10 MB, other uploads: 50 MB).</summary>
    public long MaxUploadBytes { get; }

    /// <summary>The short type hint shown next to the name.</summary>
    public string TypeHint => Kind switch
    {
        TgParamKind.Text or TgParamKind.LongText => "text",
        TgParamKind.Integer or TgParamKind.Float => "number",
        TgParamKind.Bool => "bool",
        TgParamKind.Json => "JSON",
        TgParamKind.ChatId => "chat id",
        TgParamKind.File => "file",
        TgParamKind.Choice => "choice",
        _ => "text",
    };
}

/// <summary>A Bot API method the workbench knows: its category, a one-line description and its common parameters.</summary>
public sealed class TgMethodDef
{
    public TgMethodDef(string name, string category, string description, params TgParamDef[] parameters)
    {
        Name = name;
        Category = category;
        Description = description;
        Params = parameters;
    }

    public string Name { get; }
    public string Category { get; }
    public string Description { get; }
    public IReadOnlyList<TgParamDef> Params { get; }

    /// <summary>The method takes chat_id + message_id OR inline_message_id (the edit* methods).</summary>
    public bool EitherMessageOrInline { get; init; }

    public bool HasFileParam
    {
        get
        {
            foreach (var p in Params) if (p.Kind == TgParamKind.File) return true;
            return false;
        }
    }

    public TgParamDef? Find(string name)
    {
        foreach (var p in Params)
            if (string.Equals(p.Name, name, StringComparison.Ordinal)) return p;
        return null;
    }
}

/// <summary>
/// The Bot API methods the workbench offers in its picker, grouped by category, with the parameters people set most.
/// Anything else is still reachable: extra key/value parameters, Raw JSON mode, and the "Custom method" entry.
/// </summary>
public static class TelegramMethods
{
    public const string Messages = "Messages";
    public const string Updates = "Updates & webhook";
    public const string Chats = "Chats";
    public const string BotSettings = "Bot settings";
    public const string Files = "Files";
    public const string Other = "Other";

    /// <summary>Category order in the picker.</summary>
    public static readonly string[] Categories = { Messages, Updates, Chats, BotSettings, Files, Other };

    private const long PhotoMax = 10L * 1024 * 1024;

    // ---- shared parameter shapes ----
    private static TgParamDef ChatId(bool required = true, string name = "chat_id", string? tip = null)
        => new(name, TgParamKind.ChatId, required, "-1001234567890 or @channel",
               tip ?? "The chat's numeric id, or @username of a public channel. Tip: run getUpdates and pick a chat from the list.");
    private static TgParamDef ParseMode()
        => new("parse_mode", TgParamKind.Choice, options: new[] { "HTML", "MarkdownV2", "Markdown" },
               tip: "How Telegram reads formatting in the text.");
    private static TgParamDef ReplyMarkup()
        => new("reply_markup", TgParamKind.Json, placeholder: "{\"inline_keyboard\":[[{\"text\":\"Open\",\"url\":\"https://t.me\"}]]}",
               tip: "Buttons under the message: an inline keyboard, a reply keyboard, or a remove / force-reply object.");
    private static TgParamDef ReplyParameters()
        => new("reply_parameters", TgParamKind.Json, placeholder: "{\"message_id\": 42}", tip: "Reply to a message: its id (and chat).");
    private static TgParamDef ThreadId()
        => new("message_thread_id", TgParamKind.Integer, placeholder: "Forum topic id", tip: "Send into a topic of a forum group.");
    private static TgParamDef Silent()
        => new("disable_notification", TgParamKind.Bool, tip: "Deliver without a sound.");
    private static TgParamDef Protect()
        => new("protect_content", TgParamKind.Bool, tip: "Block forwarding and saving.");
    private static TgParamDef MessageId(bool required = true)
        => new("message_id", TgParamKind.Integer, required, "42", "The message's id in that chat.");
    private static TgParamDef UserId()
        => new("user_id", TgParamKind.Integer, true, "123456789", "The user's numeric id (from.id in an update).");
    private static TgParamDef Caption()
        => new("caption", TgParamKind.LongText, placeholder: "Caption", tip: "Up to 1024 characters.");
    private static TgParamDef Upload(string name, string what, long max = 0)
        => new(name, TgParamKind.File, true, "file_id or https:// URL",
               $"Choose a {what} to upload, or paste a file_id Telegram gave you, or an HTTP URL Telegram can download.", maxUploadBytes: max);
    private static TgParamDef Scope()
        => new("scope", TgParamKind.Json, placeholder: "{\"type\": \"default\"}", tip: "Which users see these commands (BotCommandScope).");
    private static TgParamDef LanguageCode()
        => new("language_code", TgParamKind.Text, placeholder: "en", tip: "Two-letter language code; empty applies to everyone.");
    private static TgParamDef AllowedUpdates()
        => new("allowed_updates", TgParamKind.Json, placeholder: "[\"message\", \"callback_query\"]",
               tip: "Update types to receive. Leave empty to keep the current setting.");

    public static readonly IReadOnlyList<TgMethodDef> All = new List<TgMethodDef>
    {
        // ---------------- Messages ----------------
        new("sendMessage", Messages, "Send a text message.",
            ChatId(), new("text", TgParamKind.LongText, true, "Message text", "1-4096 characters."),
            ParseMode(), ReplyMarkup(), ReplyParameters(),
            new("link_preview_options", TgParamKind.Json, placeholder: "{\"is_disabled\": true}", tip: "Turn off or tune the link preview."),
            ThreadId(), Silent(), Protect()),
        new("forwardMessage", Messages, "Forward a message, keeping its origin.",
            ChatId(), ChatId(name: "from_chat_id", tip: "The chat the original message is in."), MessageId(),
            ThreadId(), Silent(), Protect()),
        new("copyMessage", Messages, "Copy a message without the forward header.",
            ChatId(), ChatId(name: "from_chat_id", tip: "The chat the original message is in."), MessageId(),
            Caption(), ParseMode(), ReplyMarkup(), ThreadId(), Silent(), Protect()),
        new("editMessageText", Messages, "Change the text of a message the bot sent.",
            ChatId(required: false), MessageId(required: false),
            new("inline_message_id", TgParamKind.Text, placeholder: "Inline message id", tip: "Instead of chat_id + message_id, for inline messages."),
            new("text", TgParamKind.LongText, true, "New text", "1-4096 characters."),
            ParseMode(), ReplyMarkup(),
            new("link_preview_options", TgParamKind.Json, placeholder: "{\"is_disabled\": true}", tip: "Turn off or tune the link preview."))
        { EitherMessageOrInline = true },
        new("deleteMessage", Messages, "Delete a message.",
            ChatId(), MessageId()),
        new("sendLocation", Messages, "Send a point on the map.",
            ChatId(),
            new("latitude", TgParamKind.Float, true, "35.6892"),
            new("longitude", TgParamKind.Float, true, "51.3890"),
            new("horizontal_accuracy", TgParamKind.Float, placeholder: "Meters, 0-1500"),
            new("live_period", TgParamKind.Integer, placeholder: "Seconds (live location)"),
            ReplyMarkup(), ThreadId(), Silent(), Protect()),
        new("sendPoll", Messages, "Send a poll or a quiz.",
            ChatId(),
            new("question", TgParamKind.Text, true, "Poll question", "1-300 characters."),
            new("options", TgParamKind.Json, true, "[{\"text\": \"Yes\"}, {\"text\": \"No\"}]", "A JSON list of 2-12 answers."),
            new("is_anonymous", TgParamKind.Bool, tip: "Anonymous by default."),
            new("type", TgParamKind.Choice, options: new[] { "regular", "quiz" }),
            new("allows_multiple_answers", TgParamKind.Bool),
            new("correct_option_id", TgParamKind.Integer, placeholder: "0-based, quizzes only"),
            new("explanation", TgParamKind.Text, placeholder: "Shown after a wrong quiz answer"),
            new("open_period", TgParamKind.Integer, placeholder: "Seconds, 5-600"),
            ReplyMarkup(), ThreadId(), Silent(), Protect()),
        new("sendChatAction", Messages, "Show “typing…” or a similar status for 5 seconds.",
            ChatId(),
            new("action", TgParamKind.Choice, true, options: new[]
            {
                "typing", "upload_photo", "record_video", "upload_video", "record_voice", "upload_voice",
                "upload_document", "choose_sticker", "find_location", "record_video_note", "upload_video_note",
            }),
            ThreadId()),
        new("answerCallbackQuery", Messages, "Answer an inline button press.",
            new("callback_query_id", TgParamKind.Text, true, "From callback_query.id", "The id in the callback_query update."),
            new("text", TgParamKind.Text, placeholder: "Notification text", tip: "0-200 characters, shown at the top or as an alert."),
            new("show_alert", TgParamKind.Bool, tip: "An alert the user has to close, instead of a toast."),
            new("url", TgParamKind.Text, placeholder: "t.me/your_bot?start=…"),
            new("cache_time", TgParamKind.Integer, placeholder: "Seconds")),

        // ---------------- Updates & webhook ----------------
        new("getUpdates", Updates, "Fetch incoming messages and other updates.",
            new("offset", TgParamKind.Integer, placeholder: "Last update_id + 1", tip: "Confirms (drops) every update before it."),
            new("limit", TgParamKind.Integer, placeholder: "1-100 (100)"),
            new("timeout", TgParamKind.Integer, placeholder: "Seconds to wait (long polling)", tip: "0 returns at once; up to 50 waits for a new update."),
            AllowedUpdates()),
        new("setWebhook", Updates, "Send updates to your HTTPS URL instead.",
            new("url", TgParamKind.Text, true, "https://example.com/bot", "HTTPS URL; an empty string removes the webhook."),
            new("secret_token", TgParamKind.Text, placeholder: "Sent back in X-Telegram-Bot-Api-Secret-Token"),
            new("max_connections", TgParamKind.Integer, placeholder: "1-100 (40)"),
            AllowedUpdates(),
            new("drop_pending_updates", TgParamKind.Bool),
            new("ip_address", TgParamKind.Text, placeholder: "Fixed IP instead of DNS"),
            new("certificate", TgParamKind.File, placeholder: "Self-signed certificate (PEM)",
                tip: "Only for a self-signed certificate: upload its public key (PEM).")),
        new("deleteWebhook", Updates, "Remove the webhook to use getUpdates again.",
            new TgParamDef("drop_pending_updates", TgParamKind.Bool, tip: "Also drop updates waiting to be delivered.")),
        new("getWebhookInfo", Updates, "Webhook URL, pending updates and last error."),

        // ---------------- Chats ----------------
        new("getChat", Chats, "Get current information about a chat.", ChatId()),
        new("getChatMember", Chats, "Get a member's status in a chat.", ChatId(), UserId()),
        new("getChatMemberCount", Chats, "Count the members of a chat.", ChatId()),
        new("getChatAdministrators", Chats, "List a chat's administrators.", ChatId()),
        new("banChatMember", Chats, "Ban a user from a group or channel.",
            ChatId(), UserId(),
            new("until_date", TgParamKind.Integer, placeholder: "Unix time; empty = forever"),
            new("revoke_messages", TgParamKind.Bool, tip: "Also delete the user's messages (groups).")),
        new("unbanChatMember", Chats, "Lift a ban so the user can join again.",
            ChatId(), UserId(),
            new("only_if_banned", TgParamKind.Bool, tip: "Do nothing if the user isn't banned (else they're removed).")),
        new("leaveChat", Chats, "Make the bot leave a group or channel.", ChatId()),

        // ---------------- Bot settings ----------------
        new("getMe", BotSettings, "Check the token and show the bot's identity."),
        new("setMyCommands", BotSettings, "Set the command list shown in the menu.",
            new("commands", TgParamKind.Json, true, "[{\"command\": \"start\", \"description\": \"Start the bot\"}]",
                "A JSON list of up to 100 commands."),
            Scope(), LanguageCode()),
        new("getMyCommands", BotSettings, "Get the bot's current command list.", Scope(), LanguageCode()),
        new("deleteMyCommands", BotSettings, "Clear the command list.", Scope(), LanguageCode()),

        // ---------------- Files ----------------
        new("sendPhoto", Files, "Send a photo: upload one, or use a file_id or URL.",
            ChatId(), Upload("photo", "photo (up to 10 MB)", PhotoMax), Caption(), ParseMode(),
            new("has_spoiler", TgParamKind.Bool, tip: "Blur the photo until tapped."),
            ReplyMarkup(), ThreadId(), Silent(), Protect()),
        new("sendDocument", Files, "Send any file as a document.",
            ChatId(), Upload("document", "file (up to 50 MB)"), Caption(), ParseMode(),
            new("disable_content_type_detection", TgParamKind.Bool),
            ReplyMarkup(), ThreadId(), Silent(), Protect()),
        new("sendVideo", Files, "Send a video (MP4).",
            ChatId(), Upload("video", "video (up to 50 MB)"), Caption(), ParseMode(),
            new("supports_streaming", TgParamKind.Bool),
            new("duration", TgParamKind.Integer, placeholder: "Seconds"),
            new("has_spoiler", TgParamKind.Bool),
            ReplyMarkup(), ThreadId(), Silent(), Protect()),
        new("sendAudio", Files, "Send a music file for the player.",
            ChatId(), Upload("audio", "MP3 or M4A file (up to 50 MB)"), Caption(), ParseMode(),
            new("performer", TgParamKind.Text), new("title", TgParamKind.Text),
            new("duration", TgParamKind.Integer, placeholder: "Seconds"),
            ReplyMarkup(), ThreadId(), Silent(), Protect()),
        new("getFile", Files, "Get the download path of a file_id.",
            new TgParamDef("file_id", TgParamKind.Text, true, "AgACAgIAAxkBAAI…", "Any file_id from a message (photo, document…).")),
    };

    private static readonly Dictionary<string, TgMethodDef> ByName = Index();

    private static Dictionary<string, TgMethodDef> Index()
    {
        var d = new Dictionary<string, TgMethodDef>(StringComparer.OrdinalIgnoreCase);
        foreach (var m in All) d[m.Name] = m;
        return d;
    }

    /// <summary>The known method by name (case-insensitive), or null.</summary>
    public static TgMethodDef? Find(string? name)
        => !string.IsNullOrEmpty(name) && ByName.TryGetValue(name, out var m) ? m : null;
}
