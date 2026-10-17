using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using Echoes.Helpers;

namespace Echoes.ViewModels;

/// <summary>One known parameter in the request form (text, number, chat id or JSON; see the subclasses for the rest).</summary>
public partial class TgField : ObservableObject
{
    public TgField(TgParamDef def) => Def = def;

    public TgParamDef Def { get; }
    public string Name => Def.Name;
    public string TypeHint => Def.TypeHint;
    public bool Required => Def.Required;
    public TgParamKind Kind => Def.Kind;
    public string Placeholder => Def.Placeholder;
    public string? Tip => string.IsNullOrEmpty(Def.Tip) ? null : Def.Tip;
    /// <summary>A taller box: message text, captions and JSON.</summary>
    public bool IsMultiline => Def.Kind is TgParamKind.LongText or TgParamKind.Json;
    public bool IsMono => Def.Kind is TgParamKind.Json or TgParamKind.Integer or TgParamKind.Float or TgParamKind.ChatId;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasValue))]
    private string _value = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasError))]
    private string? _error;

    public bool HasError => !string.IsNullOrEmpty(Error);
    public virtual bool HasValue => !string.IsNullOrWhiteSpace(Value);

    /// <summary>Raised on any edit (the view-model persists and re-counts the optional values).</summary>
    public event Action<TgField>? Changed;

    partial void OnValueChanged(string value)
    {
        Error = null;
        ValueSet(value);
        Changed?.Invoke(this);
    }

    protected virtual void ValueSet(string value) { }

    protected void RaiseChanged()
    {
        OnPropertyChanged(nameof(HasValue));
        Changed?.Invoke(this);
    }
}

/// <summary>A bool or a fixed choice (parse_mode, chat action): a drop-down; "Not set" leaves Telegram's default.</summary>
public sealed partial class TgChoiceField : TgField
{
    public const string NotSet = "Not set";

    public TgChoiceField(TgParamDef def) : base(def)
    {
        Options = new ObservableCollection<string>();
        if (!def.Required) Options.Add(NotSet);
        if (def.Kind == TgParamKind.Bool) { Options.Add("true"); Options.Add("false"); }
        else foreach (var o in def.Options) Options.Add(o);
        _syncing = true;
        Selected = Options.Count > 0 ? Options[0] : NotSet;
        _syncing = false;
        if (def.Required && Options.Count > 0) Value = Options[0];   // a required choice starts on its first option
    }

    public ObservableCollection<string> Options { get; }

    [ObservableProperty] private string? _selected;

    private bool _syncing;

    partial void OnSelectedChanged(string? value)
    {
        if (_syncing) return;
        _syncing = true;
        try { Value = value is null || value == NotSet ? string.Empty : value; }
        finally { _syncing = false; }
    }

    // A value set from code (restored form, Raw JSON → form) selects the matching option; an unknown one is added, so
    // nothing typed in JSON is silently dropped.
    protected override void ValueSet(string value)
    {
        if (_syncing) return;
        _syncing = true;
        try
        {
            string v = value.Trim();
            if (v.Length == 0) { Selected = Options.Count > 0 && Options[0] == NotSet ? NotSet : (Options.Count > 0 ? Options[0] : null); return; }
            foreach (var o in Options)
                if (string.Equals(o, v, StringComparison.OrdinalIgnoreCase)) { Selected = o; return; }
            Options.Add(v);
            Selected = v;
        }
        finally { _syncing = false; }
    }
}

/// <summary>A file parameter: a local file (sent as multipart/form-data), or a file_id / URL typed as text.</summary>
public sealed partial class TgFileField : TgField
{
    public TgFileField(TgParamDef def) : base(def) { }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasUpload), nameof(ShowText), nameof(UploadName), nameof(UploadSize))]
    private TgUpload? _upload;

    public bool HasUpload => Upload is not null;
    public bool ShowText => Upload is null;
    public string UploadName => Upload?.FileName ?? string.Empty;
    public string UploadSize => Upload?.SizeText ?? string.Empty;
    public override bool HasValue => Upload is not null || base.HasValue;

    partial void OnUploadChanged(TgUpload? value)
    {
        Error = null;
        RaiseChanged();
    }

    [CommunityToolkit.Mvvm.Input.RelayCommand]
    private void ClearUpload() => Upload = null;
}

/// <summary>An extra key / value parameter the form doesn't list.</summary>
public sealed partial class TgExtraParam : ObservableObject
{
    public TgExtraParam(string key = "", string value = "")
    {
        Key = key;
        Value = value;
    }

    [ObservableProperty] private string _key = string.Empty;
    [ObservableProperty] private string _value = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasError))]
    private string? _error;

    public bool HasError => !string.IsNullOrEmpty(Error);
    public bool IsBlank => string.IsNullOrWhiteSpace(Key) && string.IsNullOrWhiteSpace(Value);

    public event Action? Changed;

    partial void OnKeyChanged(string value) { Error = null; Changed?.Invoke(); }
    partial void OnValueChanged(string value) { Error = null; Changed?.Invoke(); }
}

/// <summary>A row of the method picker: a category header, a method, or the "Custom method" entry.</summary>
public sealed class TgNavRow
{
    public const string CustomKey = "#custom";

    private TgNavRow(bool header, string title, string description, TgMethodDef? method, bool custom)
    {
        IsHeader = header;
        Title = title;
        Description = description;
        Method = method;
        IsCustom = custom;
    }

    public static TgNavRow Header(string category) => new(true, category, string.Empty, null, false);
    public static TgNavRow For(TgMethodDef m) => new(false, m.Name, m.Description, m, false);
    public static TgNavRow Custom() => new(false, "Custom method", "Call any Bot API method by name.", null, true);

    public bool IsHeader { get; }
    public bool IsItem => !IsHeader;
    public string Title { get; }
    public string Description { get; }
    public TgMethodDef? Method { get; }
    public bool IsCustom { get; }
    /// <summary>The method name, or <see cref="CustomKey"/>.</summary>
    public string Key => IsCustom ? CustomKey : Method?.Name ?? Title;
    public string Category => IsCustom ? TelegramMethods.Other : Method?.Category ?? Title;
}

/// <summary>A parsed entry of a getUpdates result.</summary>
public sealed class TgUpdateRow
{
    public long UpdateId { get; init; }
    public string UpdateIdText => "#" + UpdateId.ToString(System.Globalization.CultureInfo.InvariantCulture);
    public string KindText { get; init; } = string.Empty;
    public string ChatTitle { get; init; } = string.Empty;
    public string ChatType { get; init; } = string.Empty;
    public long? ChatId { get; init; }
    public string ChatIdText => ChatId?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
    public bool HasChat => ChatId is not null;
    public string From { get; init; } = string.Empty;
    public string Text { get; init; } = string.Empty;
    public string Time { get; init; } = string.Empty;
    /// <summary>"Sina (@sina): Hello" — who and what, on one line.</summary>
    public string Line => From.Length > 0 && Text.Length > 0 ? From + ": " + Text : From.Length > 0 ? From : Text;
    public string Title => ChatTitle.Length > 0 ? ChatTitle : From.Length > 0 ? From : KindText;
}

/// <summary>What the response panel shows for one call (also kept in the history).</summary>
public sealed class TgResponseState
{
    public string Method { get; init; } = string.Empty;
    public TgOutcome Outcome { get; init; }
    public int HttpStatus { get; init; }
    public int ErrorCode { get; init; }
    /// <summary>"OK", "Error 400", "HTTP 502", "Network error"…</summary>
    public string Badge { get; init; } = string.Empty;
    /// <summary>Telegram's description / the failure, for anything but OK.</summary>
    public string Title { get; init; } = string.Empty;
    /// <summary>What to do about it, in plain words (may be empty).</summary>
    public string Hint { get; init; } = string.Empty;
    /// <summary>"200 · 182 ms · 1.2 KB".</summary>
    public string Meta { get; init; } = string.Empty;
    public string Json { get; init; } = string.Empty;
    public IReadOnlyList<TgUpdateRow>? Updates { get; init; }
    public long? NextOffset { get; init; }
    /// <summary>getFile's file_path (download it with Save file).</summary>
    public string? FilePath { get; init; }
    public TgBotIdentity? Bot { get; init; }
    public TimeSpan Elapsed { get; init; }

    public bool IsOk => Outcome == TgOutcome.Ok;
    public bool IsWarn => Outcome is TgOutcome.NetworkError or TgOutcome.Timeout or TgOutcome.Cancelled
                          || (Outcome == TgOutcome.ApiError && ErrorCode == 429);
    public bool IsError => !IsOk && !IsWarn;
}

/// <summary>getMe's result, for the identity strip.</summary>
public sealed class TgBotIdentity
{
    public long Id { get; init; }
    public string FirstName { get; init; } = string.Empty;
    public string Username { get; init; } = string.Empty;
    public bool CanJoinGroups { get; init; }
    public bool CanReadAllGroupMessages { get; init; }
    public bool SupportsInlineQueries { get; init; }
}

/// <summary>A request as it was sent: enough to re-open the form or send it again.</summary>
public sealed class TgSnapshot
{
    public string MethodKey { get; init; } = string.Empty;
    public string CustomName { get; init; } = string.Empty;
    public bool JsonMode { get; init; }
    public string RawJson { get; init; } = string.Empty;
    public Dictionary<string, string> Values { get; init; } = new(StringComparer.Ordinal);
    public Dictionary<string, TgUpload> Uploads { get; init; } = new(StringComparer.Ordinal);
    public List<KeyValuePair<string, string>> Extras { get; init; } = new();
}

/// <summary>One sent call in the session history.</summary>
public sealed class TgHistoryItem
{
    public string Method { get; init; } = string.Empty;
    public string Time { get; init; } = string.Empty;
    public string StatusText { get; init; } = string.Empty;
    public string Summary { get; init; } = string.Empty;
    public string ElapsedText { get; init; } = string.Empty;
    public bool IsOk { get; init; }
    public bool IsWarn { get; init; }
    public bool IsError { get; init; }
    public TgSnapshot Request { get; init; } = new();
    public TgResponseState Response { get; init; } = new();
}
