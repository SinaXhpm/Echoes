using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Echoes.ViewModels;

// The method picker, the parameter form, Raw JSON mode, validation and building the request.
public partial class TgViewModel
{
    // ===================================================================== method picker

    private readonly List<TgNavRow> _allRows = new();
    private readonly Dictionary<string, TgNavRow> _rowByKey = new(StringComparer.Ordinal);

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasNoMatches), nameof(CanCallSearchAsCustom))]
    private IReadOnlyList<TgNavRow> _navRows = Array.Empty<TgNavRow>();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(NoMatchText), nameof(CallSearchAsCustomText), nameof(CanCallSearchAsCustom))]
    private string _methodSearch = string.Empty;

    /// <summary>Narrow layouts: the method picker is open in place of the form.</summary>
    [ObservableProperty] private bool _isBrowsing;

    /// <summary>The navigator's tab: 0 = methods, 1 = history.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowMethods), nameof(ShowHistory), nameof(ShowNoMatches), nameof(ShowHistoryEmpty))]
    private int _navTabIndex;

    public bool ShowMethods => NavTabIndex == 0;
    public bool ShowHistory => NavTabIndex == 1;
    public bool HasNoMatches => NavRows.Count == 0;
    public bool ShowNoMatches => ShowMethods && HasNoMatches;
    public bool ShowHistoryEmpty => ShowHistory && !HasHistory;
    public string NoMatchText => CanCallSearchAsCustom
        ? $"No method matches “{MethodSearch.Trim()}”. You can still call it by name:"
        : $"No method matches “{MethodSearch.Trim()}”.";
    public bool CanCallSearchAsCustom => HasNoMatches && TelegramApi.IsMethodName(MethodSearch.Trim());
    public string CallSearchAsCustomText => $"Call {MethodSearch.Trim()}";

    private TgNavRow? _selectedNavRow;

    /// <summary>The picker's selection = the current method. Headers and "nothing" (a filtered list) are ignored.</summary>
    public TgNavRow? SelectedNavRow
    {
        get => _selectedNavRow;
        set
        {
            if (value is not { IsHeader: false } || ReferenceEquals(value, _selectedNavRow)) return;
            _selectedNavRow = value;
            OnPropertyChanged();
            if (!string.Equals(value.Key, _currentKey, StringComparison.Ordinal)) SelectKey(value.Key);
        }
    }

    private void InitNav()
    {
        foreach (var cat in TelegramMethods.Categories)
        {
            var header = TgNavRow.Header(cat);
            bool any = false;
            foreach (var m in TelegramMethods.All)
            {
                if (!string.Equals(m.Category, cat, StringComparison.Ordinal)) continue;
                if (!any) { _allRows.Add(header); any = true; }
                var row = TgNavRow.For(m);
                _allRows.Add(row);
                _rowByKey[row.Key] = row;
            }
            if (cat == TelegramMethods.Other)
            {
                if (!any) _allRows.Add(header);
                var custom = TgNavRow.Custom();
                _allRows.Add(custom);
                _rowByKey[custom.Key] = custom;
            }
        }
        ApplyFilter();
    }

    partial void OnMethodSearchChanged(string value) => ApplyFilter();

    private void ApplyFilter()
    {
        string q = MethodSearch.Trim();
        var list = new List<TgNavRow>(_allRows.Count);
        TgNavRow? pendingHeader = null;
        foreach (var row in _allRows)
        {
            if (row.IsHeader) { pendingHeader = row; continue; }
            if (q.Length > 0 && !Matches(row, q)) continue;
            if (pendingHeader is not null) { list.Add(pendingHeader); pendingHeader = null; }
            list.Add(row);
        }
        NavRows = list;
        // The list was replaced: show the current method selected again (when it's in the filtered list).
        OnPropertyChanged(nameof(SelectedNavRow));
        OnPropertyChanged(nameof(ShowNoMatches));
    }

    private static bool Matches(TgNavRow row, string q)
        => row.Title.Contains(q, StringComparison.OrdinalIgnoreCase)
           || row.Description.Contains(q, StringComparison.OrdinalIgnoreCase)
           || row.Category.Contains(q, StringComparison.OrdinalIgnoreCase);

    /// <summary>A tap / Enter on a picker row: open that method and close the picker (narrow layouts).</summary>
    public void PickRow(TgNavRow? row)
    {
        if (row is not { IsHeader: false }) return;
        if (!string.Equals(row.Key, _currentKey, StringComparison.Ordinal)) SelectKey(row.Key);
        IsBrowsing = false;
    }

    [RelayCommand]
    private void PickFirstMatch()
    {
        foreach (var r in NavRows)
            if (!r.IsHeader) { PickRow(r); return; }
        if (CanCallSearchAsCustom) CallSearchAsCustom();
    }

    [RelayCommand]
    private void CallSearchAsCustom()
    {
        string name = MethodSearch.Trim();
        if (!TelegramApi.IsMethodName(name)) return;
        var known = TelegramMethods.Find(name);
        MethodSearch = string.Empty;
        if (known is not null) { SelectKey(known.Name); IsBrowsing = false; return; }
        CustomMethodName = name;
        SelectKey(TgNavRow.CustomKey);
        IsBrowsing = false;
    }

    [RelayCommand]
    private void Browse()
    {
        NavTabIndex = 0;
        IsBrowsing = true;
        PhoneTabIndex = 0;
    }

    [RelayCommand]
    private void BrowseHistory()
    {
        NavTabIndex = 1;
        IsBrowsing = true;
        PhoneTabIndex = 0;
    }

    [RelayCommand]
    private void CloseBrowse() => IsBrowsing = false;

    // ===================================================================== the current method

    private TgMethodDef? _def;
    private string _currentKey = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TakesNoParams))]
    private bool _isCustom;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasCustomNameError))]
    private string? _customNameError;
    public bool HasCustomNameError => !string.IsNullOrEmpty(CustomNameError);

    [ObservableProperty] private string _customMethodName = string.Empty;
    [ObservableProperty] private string _methodTitle = "getMe";
    [ObservableProperty] private string _methodDescription = string.Empty;
    [ObservableProperty] private string _methodCategory = string.Empty;
    [ObservableProperty] private string _endpointText = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasRequired), nameof(TakesNoParams))]
    private IReadOnlyList<TgField> _requiredFields = Array.Empty<TgField>();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasOptional), nameof(TakesNoParams))]
    private IReadOnlyList<TgField> _optionalFields = Array.Empty<TgField>();

    public ObservableCollection<TgExtraParam> ExtraParams { get; } = new();

    /// <summary>Remembered preference: open the optional parameters by default.</summary>
    [ObservableProperty] private bool _showOptional;
    [ObservableProperty] private bool _isOptionalOpen;
    [ObservableProperty] private string _optionalHeader = string.Empty;

    public bool HasRequired => RequiredFields.Count > 0;
    public bool HasOptional => OptionalFields.Count > 0;

    /// <summary>A rule about the first section (the edit* methods: one of two ways to name the message).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasRequiredNote))]
    private string? _requiredNote;
    public bool HasRequiredNote => !string.IsNullOrEmpty(RequiredNote);
    public bool TakesNoParams => !IsCustom && RequiredFields.Count == 0 && OptionalFields.Count == 0;

    private IEnumerable<TgField> AllFields => RequiredFields.Concat(OptionalFields);

    private TgField? FindField(string name)
    {
        foreach (var f in RequiredFields) if (string.Equals(f.Name, name, StringComparison.Ordinal)) return f;
        foreach (var f in OptionalFields) if (string.Equals(f.Name, name, StringComparison.Ordinal)) return f;
        return null;
    }

    partial void OnCustomMethodNameChanged(string value)
    {
        CustomNameError = null;
        if (!IsCustom) return;
        MethodTitle = value.Trim().Length > 0 ? value.Trim() : "Custom method";
        RefreshFormComputed();
    }

    // Values per method for this session (and, minus files, across sessions): switching methods keeps what was typed.
    private readonly Dictionary<string, TgSnapshot> _memory = new(StringComparer.Ordinal);
    private bool _suppress;

    /// <summary>Open a method (a known name or <see cref="TgNavRow.CustomKey"/>), with <paramref name="apply"/>'s values
    /// or the ones remembered for it.</summary>
    private void SelectKey(string key, TgSnapshot? apply = null)
    {
        StashForm();
        bool custom = key == TgNavRow.CustomKey;
        var def = custom ? null : TelegramMethods.Find(key);
        if (!custom && def is null) { def = TelegramMethods.Find("getMe")!; }
        key = custom ? TgNavRow.CustomKey : def!.Name;

        foreach (var f in AllFields) f.Changed -= OnFieldChanged;
        foreach (var x in ExtraParams) x.Changed -= OnExtraChanged;
        ExtraParams.Clear();

        var required = new List<TgField>();
        var optional = new List<TgField>();
        // The edit* methods need chat_id + message_id OR inline_message_id: those three lead the form (with a note),
        // instead of hiding in the folded optional section.
        bool either = def is { EitherMessageOrInline: true };
        if (def is not null)
            foreach (var p in def.Params)
                (p.Required || (either && p.Name is "chat_id" or "message_id" or "inline_message_id") ? required : optional).Add(CreateField(p));
        RequiredNote = either ? "Set chat_id + message_id, or inline_message_id." : null;

        _def = def;
        _currentKey = key;
        IsCustom = custom;
        CustomNameError = null;

        var values = apply ?? (_memory.TryGetValue(key, out var m) ? m : null);
        _suppress = true;
        try
        {
            if (values is not null)
            {
                foreach (var (name, v) in values.Values)
                {
                    var f = required.Concat(optional).FirstOrDefault(x => x.Name == name);
                    if (f is not null) f.Value = v;
                    else AddExtraRow(name, v);
                }
                foreach (var f in required.Concat(optional))
                    if (f is TgFileField ff && values.Uploads.TryGetValue(f.Name, out var up)) ff.Upload = up;
                foreach (var (k, v) in values.Extras) AddExtraRow(k, v);
                if (custom && values.CustomName.Length > 0) CustomMethodName = values.CustomName;
            }
        }
        finally { _suppress = false; }

        foreach (var f in required.Concat(optional)) f.Changed += OnFieldChanged;
        RequiredFields = required;
        OptionalFields = optional;
        IsOptionalOpen = ShowOptional || required.Count == 0 || optional.Any(f => f.HasValue);

        if (custom)
        {
            MethodTitle = CustomMethodName.Trim().Length > 0 ? CustomMethodName.Trim() : "Custom method";
            MethodDescription = "Call any Bot API method by name.";
            MethodCategory = TelegramMethods.Other;
        }
        else
        {
            MethodTitle = def!.Name;
            MethodDescription = def.Description;
            MethodCategory = def.Category;
        }

        // Raw JSON mode shows this method's request as JSON (what was typed there, if it was left in JSON).
        if (_editorModeIndex == 1)
            RawJson = values is { JsonMode: true, RawJson.Length: > 0 } ? values.RawJson : FormToJson(indented: true);
        JsonError = null;
        ClearFormMessage();

        _selectedNavRow = _rowByKey.TryGetValue(key, out var row) ? row : null;
        OnPropertyChanged(nameof(SelectedNavRow));
        RefreshFormComputed();
        SchedulePersist();
    }

    private static TgField CreateField(TgParamDef p) => p.Kind switch
    {
        TgParamKind.Bool or TgParamKind.Choice => new TgChoiceField(p),
        TgParamKind.File => new TgFileField(p),
        _ => new TgField(p),
    };

    private void AddExtraRow(string key, string value)
    {
        var x = new TgExtraParam(key, value);
        x.Changed += OnExtraChanged;
        ExtraParams.Add(x);
    }

    private void OnFieldChanged(TgField f)
    {
        if (_suppress) return;
        RefreshFormComputed();
        SchedulePersist();
    }

    private void OnExtraChanged()
    {
        if (_suppress) return;
        RefreshFormComputed();
        SchedulePersist();
    }

    private void RefreshFormComputed()
    {
        int set = OptionalFields.Count(f => f.HasValue);
        OptionalHeader = set > 0
            ? $"Optional ({OptionalFields.Count} · {set} set)"
            : $"Optional ({OptionalFields.Count})";

        string name = IsCustom ? (TelegramApi.IsMethodName(CustomMethodName.Trim()) ? CustomMethodName.Trim() : "…") : _def?.Name ?? "getMe";
        string body;
        if (_editorModeIndex == 1)
            body = RawJson.Trim() is "" or "{}" ? "no body" : "JSON";
        else if (AllFields.Any(f => f is TgFileField { HasUpload: true }))
            body = "multipart upload";
        else
            body = AllFields.Any(f => f.HasValue) || ExtraParams.Any(x => !x.IsBlank) ? "JSON" : "no body";
        EndpointText = $"POST {TelegramApi.DisplayEndpoint(name)} · {body}";
    }

    [RelayCommand]
    private void ToggleOptional()
    {
        IsOptionalOpen = !IsOptionalOpen;
        ShowOptional = IsOptionalOpen;
    }

    [RelayCommand]
    private void AddExtra()
    {
        AddExtraRow(string.Empty, string.Empty);
        RefreshFormComputed();
    }

    [RelayCommand]
    private void RemoveExtra(TgExtraParam? x)
    {
        if (x is null) return;
        x.Changed -= OnExtraChanged;
        ExtraParams.Remove(x);
        RefreshFormComputed();
        SchedulePersist();
    }

    /// <summary>Clear this method's values (and attached files).</summary>
    [RelayCommand]
    private void ResetForm()
    {
        _suppress = true;
        try
        {
            foreach (var f in AllFields)
            {
                if (f is TgChoiceField { Required: true } cf && cf.Options.Count > 0) cf.Value = cf.Options[0];
                else f.Value = string.Empty;
                if (f is TgFileField ff) ff.Upload = null;
                f.Error = null;
            }
            foreach (var x in ExtraParams) x.Changed -= OnExtraChanged;
            ExtraParams.Clear();
        }
        finally { _suppress = false; }
        if (_editorModeIndex == 1) RawJson = FormToJson(indented: true);
        JsonError = null;
        CustomNameError = null;
        ClearFormMessage();
        RefreshFormComputed();
        SchedulePersist();
    }

    // ===================================================================== Form | Raw JSON

    private int _editorModeIndex;

    /// <summary>0 = form, 1 = raw JSON. Switching converts between them; invalid JSON keeps the JSON editor open.</summary>
    public int EditorModeIndex
    {
        get => _editorModeIndex;
        set
        {
            if (value == _editorModeIndex || value is < 0 or > 1) return;
            if (value == 1)
            {
                RawJson = FormToJson(indented: true);
                JsonError = null;
            }
            else if (!JsonToForm(RawJson, out string? problem))
            {
                JsonError = problem;
                ShowFormMessage("Fix the JSON to go back to the form.", error: true);
                // The switch already moved: put it back once this change has gone through.
                Avalonia.Threading.Dispatcher.UIThread.Post(() => OnPropertyChanged(nameof(EditorModeIndex)));
                return;
            }
            _editorModeIndex = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(IsFormMode));
            OnPropertyChanged(nameof(IsJsonMode));
            OnPropertyChanged(nameof(JsonModeUploadNote));
            ClearFormMessage();
            RefreshFormComputed();
            SchedulePersist();
        }
    }

    public bool IsFormMode => _editorModeIndex == 0;
    public bool IsJsonMode => _editorModeIndex == 1;

    [ObservableProperty] private string _rawJson = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasJsonError))]
    private string? _jsonError;
    public bool HasJsonError => !string.IsNullOrEmpty(JsonError);

    /// <summary>JSON mode can't carry a local file: say so when the form has one attached.</summary>
    public string? JsonModeUploadNote
    {
        get
        {
            if (_editorModeIndex != 1) return null;
            var f = AllFields.OfType<TgFileField>().FirstOrDefault(x => x.HasUpload);
            return f is null ? null : $"{f.UploadName} is only sent from the Form tab.";
        }
    }

    partial void OnRawJsonChanged(string value)
    {
        JsonError = null;
        if (_editorModeIndex == 1 && !_suppress)
        {
            RefreshFormComputed();
            SchedulePersist();
        }
    }

    [RelayCommand]
    private void FormatJson()
    {
        string text = RawJson.Trim();
        if (text.Length == 0) { RawJson = "{}"; return; }
        try
        {
            using var doc = JsonDocument.Parse(text, ReadOptions);
            RawJson = Write(doc.RootElement, indented: true);
            JsonError = null;
        }
        catch (JsonException ex) { JsonError = JsonProblem(ex); }
    }

    private static readonly JsonWriterOptions IndentedJson = new() { Indented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
    private static readonly JsonWriterOptions CompactJson = new() { Indented = false, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
    // Lenient for what people type (comments, trailing commas); the request itself is re-written as strict JSON.
    private static readonly JsonDocumentOptions ReadOptions = new() { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip, MaxDepth = 64 };

    private static readonly Regex IntegerRx = new(@"^-?[0-9]{1,19}$", RegexOptions.CultureInvariant);
    private static readonly Regex JsonNumberRx = new(@"^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$", RegexOptions.CultureInvariant);
    private static readonly Regex ChannelRx = new(@"^@[A-Za-z][A-Za-z0-9_]{3,31}$", RegexOptions.CultureInvariant);
    private static readonly Regex ParamNameRx = new(@"^[A-Za-z_][A-Za-z0-9_]{0,63}$", RegexOptions.CultureInvariant);

    private static string Write(JsonElement e, bool indented)
    {
        var buffer = new ArrayBufferWriter<byte>(256);
        using (var w = new Utf8JsonWriter(buffer, indented ? IndentedJson : CompactJson)) e.WriteTo(w);
        return TelegramApi.Readable(Encoding.UTF8.GetString(buffer.WrittenSpan));
    }

    /// <summary>The form as a JSON object (typed: numbers, booleans and JSON values are written as such).</summary>
    private string FormToJson(bool indented)
    {
        var buffer = new ArrayBufferWriter<byte>(512);
        using (var w = new Utf8JsonWriter(buffer, indented ? IndentedJson : CompactJson))
        {
            w.WriteStartObject();
            foreach (var f in AllFields)
            {
                if (f is TgFileField { HasUpload: true } || !f.HasValue) continue;
                WriteValue(w, f.Name, f.Kind, f.Value);
            }
            foreach (var x in ExtraParams)
            {
                string k = x.Key.Trim();
                if (k.Length == 0 || x.IsBlank) continue;
                WriteValue(w, k, TgParamKind.Text, x.Value, extra: true);
            }
            w.WriteEndObject();
        }
        return TelegramApi.Readable(Encoding.UTF8.GetString(buffer.WrittenSpan));
    }

    private static void WriteValue(Utf8JsonWriter w, string name, TgParamKind kind, string raw, bool extra = false)
    {
        string v = kind is TgParamKind.Text or TgParamKind.LongText ? raw : raw.Trim();
        switch (kind)
        {
            case TgParamKind.Integer or TgParamKind.Float or TgParamKind.ChatId when JsonNumberRx.IsMatch(v):
                w.WritePropertyName(name);
                w.WriteRawValue(v);
                return;
            case TgParamKind.Bool when v is "true" or "false":
                w.WriteBoolean(name, v == "true");
                return;
            case TgParamKind.Json:
                if (TryParse(v, out var doc))
                {
                    using (doc) { w.WritePropertyName(name); doc!.RootElement.WriteTo(w); }
                    return;
                }
                break;
        }
        // An extra value that is a JSON object / array goes in as one (reply_markup typed as an extra).
        string t = v.Trim();
        if (extra && t.Length > 1 && (t[0] == '{' || t[0] == '[') && TryParse(t, out var obj))
        {
            using (obj) { w.WritePropertyName(name); obj!.RootElement.WriteTo(w); }
            return;
        }
        w.WriteString(name, v);
    }

    private static bool TryParse(string text, out JsonDocument? doc)
    {
        doc = null;
        if (string.IsNullOrWhiteSpace(text)) return false;
        try { doc = JsonDocument.Parse(text, ReadOptions); return true; }
        catch (JsonException) { return false; }
    }

    /// <summary>A JSON value as the form shows it: strings as-is, numbers as written, objects / arrays as compact JSON.</summary>
    private static string ValueText(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.String => e.GetString() ?? string.Empty,
        JsonValueKind.Number => e.GetRawText(),
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        JsonValueKind.Null or JsonValueKind.Undefined => string.Empty,
        _ => Write(e, indented: false),
    };

    /// <summary>Raw JSON → the form: known parameters into their fields, the rest into extra rows.</summary>
    private bool JsonToForm(string json, out string? problem)
    {
        problem = null;
        JsonDocument? doc = null;
        string text = json.Trim();
        if (text.Length > 0)
        {
            try { doc = JsonDocument.Parse(text, ReadOptions); }
            catch (JsonException ex) { problem = JsonProblem(ex); return false; }
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                doc.Dispose();
                problem = "The request must be a JSON object: { \"name\": value, … }.";
                return false;
            }
        }

        using (doc)
        {
            _suppress = true;
            try
            {
                foreach (var f in AllFields)
                {
                    if (f is TgChoiceField { Required: true } cf && cf.Options.Count > 0) cf.Value = cf.Options[0];
                    else f.Value = string.Empty;
                    f.Error = null;
                }
                foreach (var x in ExtraParams) x.Changed -= OnExtraChanged;
                ExtraParams.Clear();
                if (doc is not null)
                    foreach (var p in doc.RootElement.EnumerateObject())
                    {
                        string v = ValueText(p.Value);
                        if (FindField(p.Name) is { } f)
                        {
                            f.Value = v;
                            // JSON names the file as text: that wins over a file attached in the form.
                            if (f is TgFileField ff && v.Length > 0) ff.Upload = null;
                        }
                        else AddExtraRow(p.Name, v);
                    }
            }
            finally { _suppress = false; }
        }
        if (OptionalFields.Any(f => f.HasValue)) IsOptionalOpen = true;
        RefreshFormComputed();
        return true;
    }

    private static string JsonProblem(JsonException ex)
    {
        string why = PlainJsonReason(ex.Message);
        return ex.LineNumber is long line
            ? $"Not valid JSON (line {line + 1}, position {(ex.BytePositionInLine ?? 0) + 1}): {why}."
            : $"Not valid JSON: {why}.";
    }

    // System.Text.Json's reader messages, said plainly.
    private static string PlainJsonReason(string m)
    {
        bool Has(string s) => m.Contains(s, StringComparison.Ordinal);
        if (Has("Expected depth to be zero")) return "a { or [ isn't closed";
        if (Has("does not contain any JSON tokens")) return "it's empty";
        if (Has("Expected end of string")) return "a string isn't closed (a \" is missing)";
        if (Has("but instead reached end of data")) return "it ends too early";
        if (Has("is invalid after a value")) return "a comma, } or ] is missing";
        if (Has("is invalid after a property name")) return "a : is missing after a name";
        if (Has("is an invalid start of a property name")) return "names need double quotes: \"name\": value";
        if (Has("is an invalid start of a value"))
        {
            int q = m.IndexOf('\'', 1);
            string what = m.StartsWith('\'') && q > 1 ? m[1..q] : "text";
            return $"unexpected {what}: text values need double quotes";
        }
        if (Has("is invalid within a JSON string")) return "a string holds a raw line break or tab: write \\n or \\t";
        if (Has("escapable character") || Has("is not a hex digit")) return "a \\ escape in a string isn't valid";
        if (Has("without a matching open")) return "a } or ] has no opening one";
        if (Has("is an invalid JSON literal")) return "only true, false and null go without quotes";
        if (Has("after a single JSON value")) return "there's extra text after the JSON";
        if (Has("maximum configured depth")) return "it's nested too deeply";
        if (Has("leading zero")) return "numbers can't start with 0";
        string why = m;
        int cut = why.IndexOf(" Path:", StringComparison.Ordinal);
        if (cut < 0) cut = why.IndexOf(" LineNumber:", StringComparison.Ordinal);
        if (cut > 0) why = why[..cut];
        int dot = why.IndexOf(". ", StringComparison.Ordinal);
        if (dot > 0) why = why[..dot];
        return why.TrimEnd(' ', '.');
    }

    private static string? JsonProblemOf(string text)
    {
        try { using var _ = JsonDocument.Parse(text, ReadOptions); return null; }
        catch (JsonException ex) { return JsonProblem(ex); }
    }

    /// <summary>An integer property of a JSON object text (null when absent / not an integer / not JSON).</summary>
    private static int? JsonInt(string json, string name)
    {
        if (!TryParse(json, out var doc)) return null;
        using (doc)
        {
            if (doc!.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.TryGetProperty(name, out var v))
            {
                if (v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out int i)) return i;
                if (v.ValueKind == JsonValueKind.String && int.TryParse(v.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int s)) return s;
            }
        }
        return null;
    }

    /// <summary>Set one property of the Raw JSON request (added first when missing). False when the JSON isn't an object.</summary>
    private bool SetJsonProperty(string name, Action<Utf8JsonWriter> writeValue)
    {
        JsonDocument? doc = null;
        if (RawJson.Trim().Length > 0)
        {
            if (!TryParse(RawJson, out doc) || doc!.RootElement.ValueKind != JsonValueKind.Object) { doc?.Dispose(); return false; }
        }
        using (doc)
        {
            var buffer = new ArrayBufferWriter<byte>(256);
            using (var w = new Utf8JsonWriter(buffer, IndentedJson))
            {
                w.WriteStartObject();
                bool written = false;
                if (doc is null || !doc.RootElement.TryGetProperty(name, out _))
                {
                    w.WritePropertyName(name);
                    writeValue(w);
                    written = true;
                }
                if (doc is not null)
                    foreach (var p in doc.RootElement.EnumerateObject())
                    {
                        if (p.NameEquals(name))
                        {
                            if (written) continue;
                            w.WritePropertyName(name);
                            writeValue(w);
                            written = true;
                            continue;
                        }
                        p.WriteTo(w);
                    }
                w.WriteEndObject();
            }
            RawJson = TelegramApi.Readable(Encoding.UTF8.GetString(buffer.WrittenSpan));
        }
        return true;
    }

    // ===================================================================== messages under the form

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasFormMessage))]
    private string _formMessage = string.Empty;
    [ObservableProperty] private bool _formMessageIsError;
    public bool HasFormMessage => FormMessage.Length > 0;

    private void ShowFormMessage(string text, bool error)
    {
        FormMessage = text;
        FormMessageIsError = error;
    }

    private void ClearFormMessage()
    {
        FormMessage = string.Empty;
        FormMessageIsError = false;
    }

    // ===================================================================== using response data in the form

    /// <summary>Put an update's chat id into the form (switching to sendMessage when this method has no chat_id).</summary>
    [RelayCommand]
    private void UseChat(TgUpdateRow? row)
    {
        if (row?.ChatId is not long id) return;
        string idText = row.ChatIdText;
        // getUpdates & co. take no chat_id: the next step is nearly always writing to that chat.
        bool switched = false;
        if (!IsCustom && FindField("chat_id") is null)
        {
            SelectKey("sendMessage");
            switched = true;
        }
        if (_editorModeIndex == 1)
        {
            if (!SetJsonProperty("chat_id", w => w.WriteNumberValue(id)))
            {
                ShowFormMessage("Fix the JSON first: chat_id couldn't be added to it.", error: true);
                return;
            }
        }
        else if (FindField("chat_id") is { } field)
        {
            field.Value = idText;
        }
        else
        {
            var x = ExtraParams.FirstOrDefault(e => e.Key.Trim() == "chat_id");
            if (x is not null) x.Value = idText;
            else { AddExtraRow("chat_id", idText); RefreshFormComputed(); }
        }
        ShowFormMessage(switched
            ? $"sendMessage opened with chat_id {idText} ({row.Title})."
            : $"chat_id set to {idText} ({row.Title}).", error: false);
        IsBrowsing = false;
        PhoneTabIndex = 0;
    }

    /// <summary>getUpdates: set offset to the last update_id + 1, so the next call confirms these and skips them.</summary>
    [RelayCommand]
    private void UseNextOffset()
    {
        if (RespNextOffset is not long next) return;
        if (!string.Equals(_currentKey, "getUpdates", StringComparison.Ordinal)) SelectKey("getUpdates");
        string text = next.ToString(CultureInfo.InvariantCulture);
        if (_editorModeIndex == 1)
        {
            if (!SetJsonProperty("offset", w => w.WriteNumberValue(next)))
            {
                ShowFormMessage("Fix the JSON first: offset couldn't be added to it.", error: true);
                return;
            }
        }
        else if (FindField("offset") is { } f)
        {
            f.Value = text;
            IsOptionalOpen = true;
        }
        ShowFormMessage($"offset set to {text}: the next getUpdates confirms these updates and skips them.", error: false);
        IsBrowsing = false;
        PhoneTabIndex = 0;
    }

    // ===================================================================== validation + the request

    private static bool IsChatId(string v) => (IntegerRx.IsMatch(v) && long.TryParse(v, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out _)) || ChannelRx.IsMatch(v);

    /// <summary>Check every field; mark the bad ones. Returns how many are bad.</summary>
    private int ValidateForm()
    {
        int errors = 0;
        void Fail(TgField f, string message) { f.Error = message; errors++; }

        foreach (var f in AllFields)
        {
            f.Error = null;
            if (f is TgFileField { Upload: { } up })
            {
                if (up.Length is long len && len > f.Def.MaxUploadBytes)
                    Fail(f, $"{up.FileName} is {TelegramApi.FormatBytes(len)}: the limit here is {TelegramApi.FormatBytes(f.Def.MaxUploadBytes)}.");
                continue;
            }
            string v = f.Value.Trim();
            if (v.Length == 0)
            {
                if (f.Required) Fail(f, f.Kind == TgParamKind.File ? "Choose a file, or paste a file_id or URL." : "Required.");
                continue;
            }
            switch (f.Kind)
            {
                case TgParamKind.Integer when !(IntegerRx.IsMatch(v) && long.TryParse(v, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out _)):
                    Fail(f, "Enter a whole number, like 42.");
                    break;
                case TgParamKind.Float when !(double.TryParse(v, NumberStyles.Float, CultureInfo.InvariantCulture, out double d) && double.IsFinite(d)):
                    Fail(f, "Enter a number, like 35.6892.");
                    break;
                case TgParamKind.ChatId when !IsChatId(v):
                    Fail(f, "Use a numeric chat id (like -1001234567890) or @channelname.");
                    break;
                case TgParamKind.Json when JsonProblemOf(v) is { } problem:
                    Fail(f, problem);
                    break;
            }
        }

        if (_def is { EitherMessageOrInline: true } && FindField("inline_message_id")?.HasValue != true)
            foreach (var name in new[] { "chat_id", "message_id" })
                if (FindField(name) is { HasValue: false, HasError: false } f) Fail(f, "Required (or set inline_message_id).");

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var x in ExtraParams)
        {
            x.Error = null;
            if (x.IsBlank) continue;
            string k = x.Key.Trim();
            if (k.Length == 0) { x.Error = "Name this parameter."; errors++; }
            else if (!ParamNameRx.IsMatch(k)) { x.Error = "Names use letters, digits and _ only."; errors++; }
            else if (FindField(k) is not null) { x.Error = $"{k} has its own field above."; errors++; }
            else if (!seen.Add(k)) { x.Error = $"{k} is set twice."; errors++; }
        }
        return errors;
    }

    /// <summary>The request to send, or null with <paramref name="problem"/> (the bad fields are marked).</summary>
    private TgRequest? BuildRequest(out string? problem)
    {
        problem = null;
        CustomNameError = null;
        string method = IsCustom ? CustomMethodName.Trim() : _def?.Name ?? "getMe";
        if (IsCustom && !TelegramApi.IsMethodName(method))
        {
            CustomNameError = method.Length == 0
                ? "Enter the method's name, like getMyName."
                : "Method names use letters, digits and _ only, like setMyDescription.";
            problem = "Enter a valid method name.";
            return null;
        }
        var request = new TgRequest(method);

        if (_editorModeIndex == 1)
        {
            string text = RawJson.Trim();
            JsonDocument? doc = null;
            if (text.Length > 0)
            {
                try { doc = JsonDocument.Parse(text, ReadOptions); }
                catch (JsonException ex) { JsonError = JsonProblem(ex); problem = "Fix the JSON first."; return null; }
            }
            using (doc)
            {
                if (doc is not null && doc.RootElement.ValueKind != JsonValueKind.Object)
                {
                    JsonError = "The request must be a JSON object: { \"name\": value, … }.";
                    problem = "Fix the JSON first.";
                    return null;
                }
                if (_def is not null)
                {
                    var missing = new List<string>();
                    foreach (var p in _def.Params)
                    {
                        if (!p.Required) continue;
                        bool has = doc is not null && doc.RootElement.TryGetProperty(p.Name, out var v) && ValueText(v).Trim().Length > 0;
                        if (!has) missing.Add(p.Name);
                    }
                    if (missing.Count > 0)
                    {
                        JsonError = "Missing " + string.Join(", ", missing) + ".";
                        problem = missing.Count == 1 ? $"{missing[0]} is required." : $"{string.Join(", ", missing)} are required.";
                        return null;
                    }
                    if (_def.EitherMessageOrInline)
                    {
                        bool Has(string n) => doc is not null && doc.RootElement.TryGetProperty(n, out var v) && ValueText(v).Trim().Length > 0;
                        if (!Has("inline_message_id") && !(Has("chat_id") && Has("message_id")))
                        {
                            JsonError = "Set chat_id and message_id, or inline_message_id.";
                            problem = "Name the message to edit.";
                            return null;
                        }
                    }
                }
                // Re-written as strict JSON: the editor accepts comments and trailing commas, Telegram doesn't.
                if (doc is not null && doc.RootElement.EnumerateObject().Any())
                    request.JsonBody = Write(doc.RootElement, indented: false);
            }
            return request;
        }

        int errors = ValidateForm();
        if (errors > 0)
        {
            if (OptionalFields.Any(f => f.HasError)) IsOptionalOpen = true;
            problem = errors == 1 ? "Fix the highlighted field." : $"Fix the {errors} highlighted fields.";
            return null;
        }

        if (AllFields.Any(f => f is TgFileField { HasUpload: true }))
        {
            foreach (var f in AllFields)
            {
                if (f is TgFileField { Upload: { } up }) { request.Files.Add(new(f.Name, up)); continue; }
                if (!f.HasValue) continue;
                request.Fields.Add(new(f.Name, PartValue(f)));
            }
            foreach (var x in ExtraParams)
                if (!x.IsBlank) request.Fields.Add(new(x.Key.Trim(), x.Value));
        }
        else
        {
            string json = FormToJson(indented: false);
            if (json != "{}") request.JsonBody = json;
        }
        return request;
    }

    // multipart sends every value as text: Telegram reads JSON-typed parameters from their JSON text.
    private static string PartValue(TgField f)
    {
        if (f.Kind is TgParamKind.Text or TgParamKind.LongText) return f.Value;
        string v = f.Value.Trim();
        if (f.Kind == TgParamKind.Json && TryParse(v, out var doc))
            using (doc) return Write(doc!.RootElement, indented: false);
        return v;
    }

    // ===================================================================== snapshots + remembered values

    private void StashForm()
    {
        if (_currentKey.Length == 0) return;
        _memory[_currentKey] = SnapshotForm();
    }

    /// <summary>The current request: method, values (from the JSON in JSON mode), files and extra rows.</summary>
    private TgSnapshot SnapshotForm()
    {
        var s = new TgSnapshot
        {
            MethodKey = _currentKey,
            CustomName = CustomMethodName.Trim(),
            JsonMode = _editorModeIndex == 1,
            RawJson = _editorModeIndex == 1 ? RawJson : string.Empty,
        };
        if (_editorModeIndex == 1)
        {
            if (TryParse(RawJson, out var doc))
                using (doc)
                    if (doc!.RootElement.ValueKind == JsonValueKind.Object)
                        foreach (var p in doc.RootElement.EnumerateObject())
                            s.Values[p.Name] = ValueText(p.Value);
        }
        else
        {
            foreach (var f in AllFields)
                if (f.Value.Length > 0) s.Values[f.Name] = f.Value;
            foreach (var x in ExtraParams)
                if (!x.IsBlank) s.Extras.Add(new(x.Key.Trim(), x.Value));
        }
        foreach (var f in AllFields)
            if (f is TgFileField { Upload: { } up }) s.Uploads[f.Name] = up;
        return s;
    }

    /// <summary>Open a request from the history: its method, values and editor mode.</summary>
    private void LoadSnapshot(TgSnapshot s)
    {
        if (s.JsonMode != (_editorModeIndex == 1))
        {
            // Switch the editor without converting the current method's form: the snapshot replaces it anyway.
            _editorModeIndex = s.JsonMode ? 1 : 0;
            OnPropertyChanged(nameof(EditorModeIndex));
            OnPropertyChanged(nameof(IsFormMode));
            OnPropertyChanged(nameof(IsJsonMode));
        }
        if (s.MethodKey == TgNavRow.CustomKey && s.CustomName.Length > 0) CustomMethodName = s.CustomName;
        SelectKey(s.MethodKey, s);
        if (s.JsonMode) RawJson = s.RawJson;
        OnPropertyChanged(nameof(JsonModeUploadNote));
    }

    private const int MaxRememberedChars = 2000;
    private const int MaxRememberedTotal = 24 * 1024;

    /// <summary>
    /// Whether a form value may be written to the profile (plaintext). Not a parameter that is itself a credential
    /// (setWebhook's secret_token, sendInvoice's provider_token…), and not a value with a bot token or a user:password@
    /// in it: a webhook URL often carries the token in its path, and the token is never persisted. Such values stay in
    /// this session's form only.
    /// </summary>
    private static bool MayRemember(string name, string value)
        => !IsSecretName(name) && string.Equals(TelegramApi.RedactStatic(value), value, StringComparison.Ordinal);

    /// <summary>A parameter that is itself a credential: secret_token, provider_token, …password.</summary>
    private static bool IsSecretName(string name)
        => name.Contains("token", StringComparison.OrdinalIgnoreCase)
           || name.Contains("secret", StringComparison.OrdinalIgnoreCase)
           || name.Contains("password", StringComparison.OrdinalIgnoreCase);

    /// <summary>Load the remembered form values. True when the stored text holds values <see cref="MayRemember"/>
    /// refuses (written by an earlier build): the caller re-writes it without them.</summary>
    private bool LoadFormMemory(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return false;
        bool secrets = false;
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return false;
            foreach (var method in doc.RootElement.EnumerateObject())
            {
                if (method.Value.ValueKind != JsonValueKind.Object) continue;
                var s = new TgSnapshot { MethodKey = method.Name };
                if (method.Value.TryGetProperty("v", out var values) && values.ValueKind == JsonValueKind.Object)
                    foreach (var p in values.EnumerateObject())
                        if (p.Value.ValueKind == JsonValueKind.String) s.Values[p.Name] = p.Value.GetString() ?? string.Empty;
                if (method.Value.TryGetProperty("x", out var extras) && extras.ValueKind == JsonValueKind.Array)
                    foreach (var pair in extras.EnumerateArray())
                        if (pair.ValueKind == JsonValueKind.Array && pair.GetArrayLength() == 2
                            && pair[0].ValueKind == JsonValueKind.String && pair[1].ValueKind == JsonValueKind.String)
                            s.Extras.Add(new(pair[0].GetString() ?? string.Empty, pair[1].GetString() ?? string.Empty));
                foreach (var (k, v) in s.Values) secrets |= !MayRemember(k, v);
                foreach (var (k, v) in s.Extras) secrets |= !MayRemember(k, v);
                _memory[method.Name] = s;
            }
        }
        catch (JsonException) { /* a damaged value only costs the remembered form values */ }
        return secrets;
    }

    // {"sendMessage": {"v": {"chat_id": "…"}, "x": [["key", "value"]]}, …} — text values only, never files or secrets
    // (MayRemember), capped.
    private string SerializeFormMemory()
    {
        var buffer = new ArrayBufferWriter<byte>(1024);
        using (var w = new Utf8JsonWriter(buffer, CompactJson))
        {
            w.WriteStartObject();
            foreach (var (key, s) in _memory)
            {
                if (s.Values.Count == 0 && s.Extras.Count == 0) continue;
                if (buffer.WrittenCount > MaxRememberedTotal) break;
                w.WritePropertyName(key);
                w.WriteStartObject();
                w.WritePropertyName("v");
                w.WriteStartObject();
                foreach (var (name, v) in s.Values)
                    if (v.Length <= MaxRememberedChars && MayRemember(name, v)) w.WriteString(name, v);
                w.WriteEndObject();
                if (s.Extras.Count > 0)
                {
                    w.WritePropertyName("x");
                    w.WriteStartArray();
                    foreach (var (k, v) in s.Extras)
                    {
                        if (v.Length > MaxRememberedChars || !MayRemember(k, v)) continue;
                        w.WriteStartArray();
                        w.WriteStringValue(k);
                        w.WriteStringValue(v);
                        w.WriteEndArray();
                    }
                    w.WriteEndArray();
                }
                w.WriteEndObject();
                w.Flush();
            }
            w.WriteEndObject();
        }
        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    // Earlier builds: "key=value" lines for the last method.
    private void MigrateLegacyParams(string methodKey, string legacy)
    {
        var s = new TgSnapshot { MethodKey = methodKey };
        foreach (var line in legacy.Split('\n'))
        {
            var parts = line.Split('=', 2);
            if (parts.Length != 2) continue;
            string k = parts[0].Trim(), v = parts[1].Trim();
            if (k.Length > 0 && v.Length > 0 && ParamNameRx.IsMatch(k)) s.Values[k] = v;
        }
        if (s.Values.Count > 0 && !_memory.ContainsKey(methodKey)) _memory[methodKey] = s;
    }
}
