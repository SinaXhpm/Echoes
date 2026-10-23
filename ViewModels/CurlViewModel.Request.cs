using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

// The request builder: URL ⇄ query params, headers, body (raw / form / multipart / file), auth, cookies, options.
public partial class CurlViewModel
{
    public ObservableCollection<string> HttpMethods { get; } = new() { "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS" };

    [ObservableProperty] private string _url = "https://";
    [ObservableProperty] private string _httpMethod = "GET";

    public CurlKvList Params { get; }
    public CurlKvList Headers { get; }
    public CurlKvList Cookies { get; }
    public CurlKvList FormFields { get; }
    public CurlPartList Parts { get; }

    public ObservableCollection<string> UrlHistory => HistoryService.Instance.Get("curl.url");
    public ObservableCollection<string> ProxyHistory => HistoryService.Instance.Get("curl.proxy");
    public static IReadOnlyList<string> CommonHeaderNames => CurlHeaderHints.Names;

    // ---- tab badges
    public string ParamsBadge => Badge(Params.ActiveCount);
    public string HeadersBadge => Badge(Headers.ActiveCount);
    public string CookiesBadge => Badge(Cookies.ActiveCount);
    public string BodyBadge => BodyModeIndex switch { 1 => RawTypes[Math.Clamp(RawTypeIndex, 0, RawTypes.Length - 1)], 2 => "Form", 3 => "Multipart", 4 => "File", _ => string.Empty };
    public string AuthBadge => AuthModeIndex switch { 1 => "Basic", 2 => "Bearer", _ => string.Empty };
    private static string Badge(int n) => n > 0 ? n.ToString() : string.Empty;

    // Raised only when a badge really changes (every keystroke in the builder ends up here).
    private readonly string[] _badges = { string.Empty, string.Empty, string.Empty, string.Empty, string.Empty };
    private void RefreshBadges()
    {
        Notify(0, ParamsBadge, nameof(ParamsBadge));
        Notify(1, HeadersBadge, nameof(HeadersBadge));
        Notify(2, CookiesBadge, nameof(CookiesBadge));
        Notify(3, BodyBadge, nameof(BodyBadge));
        Notify(4, AuthBadge, nameof(AuthBadge));

        void Notify(int i, string value, string name)
        {
            if (_badges[i] == value) return;
            _badges[i] = value;
            OnPropertyChanged(name);
        }
    }

    // ---- any change to what would be sent
    private void RequestChanged()
    {
        if (!_loaded) return;
        RefreshBadges();
        RefreshAutoHeaders();
        RefreshChips();
        ScheduleSnippet();
    }

    partial void OnHttpMethodChanged(string value)
    {
        if (!string.IsNullOrEmpty(value) && !HttpMethods.Contains(value)) HttpMethods.Add(value);
        OnPropertyChanged(nameof(BodyIgnoredNote));
        OnPropertyChanged(nameof(HasBodyIgnoredNote));
        RequestChanged();
    }

    // ================================================================== URL ⇄ params

    private bool _syncing;

    partial void OnUrlChanged(string value)
    {
        if (!_loaded) return;
        if (!_syncing) SyncParamsFromUrl();
        RequestChanged();
    }

    // The URL was edited: its query becomes the rows (written as typed — no decoding); rows switched off stay at the end.
    // While the shape stays the same (typing inside a value) the rows are updated in place, not rebuilt per keystroke.
    private void SyncParamsFromUrl()
    {
        var (_, query, _) = CurlRequest.SplitUrl(Url);
        var current = Params.ToPairs();
        var enabledNow = current.Where(p => p.Enabled).ToList();
        _syncing = true;
        try
        {
            if (enabledNow.Count == query.Count && Params.UpdateEnabledInPlace(query)) { }
            else Params.Load(query.Concat(current.Where(p => !p.Enabled)), notify: false);
        }
        finally { _syncing = false; }
        RefreshBadges();
    }

    // A row was edited: the URL is rebuilt from the enabled rows.
    private void OnParamsChanged()
    {
        if (_syncing || !_loaded) return;
        var (baseUrl, _, fragment) = CurlRequest.SplitUrl(Url);
        _syncing = true;
        try { Url = CurlRequest.JoinUrl(baseUrl, Params.ToPairs(), fragment); }
        finally { _syncing = false; }
        RequestChanged();
    }

    private void OnHeadersChanged() => RequestChanged();
    private void OnCookiesChanged() => RequestChanged();
    private void OnBodyChanged() => RequestChanged();

    // ================================================================== headers: bulk edit

    [ObservableProperty] private bool _headersBulk;
    [ObservableProperty] private string _headersBulkText = string.Empty;

    private bool _dropBulk;

    // Rows → "Name: value" lines ("# " = switched off); and back when leaving the editor.
    partial void OnHeadersBulkChanged(bool value)
    {
        if (value)
        {
            HeadersBulkText = string.Join("\n", Headers.ToPairs().Where(p => p.Name.Length > 0 || p.Value.Length > 0)
                .Select(p => (p.Enabled ? "" : "# ") + p.Name + ": " + p.Value));
        }
        else if (!_dropBulk) ApplyBulkHeaders();
    }

    partial void OnHeadersBulkTextChanged(string value) => RequestChanged();

    // "Name: value" lines → rows ("# " / "//" = switched off). While the text editor is open it IS the headers.
    private static List<CurlPair> ParseBulkHeaders(string text)
    {
        var pairs = new List<CurlPair>();
        foreach (var raw in text.Split('\n'))
        {
            string line = raw.Trim().TrimEnd('\r');
            if (line.Length == 0) continue;
            bool on = true;
            if (line.StartsWith('#') || line.StartsWith("//", StringComparison.Ordinal))
            {
                on = false;
                line = line.TrimStart('#', '/').Trim();
            }
            int colon = line.IndexOf(':');
            if (colon <= 0) { pairs.Add(new CurlPair(line, string.Empty, on)); continue; }
            pairs.Add(new CurlPair(line[..colon].Trim(), line[(colon + 1)..].Trim(), on));
        }
        return pairs;
    }

    private void ApplyBulkHeaders()
    {
        var pairs = ParseBulkHeaders(HeadersBulkText);
        // a pasted "Cookie:" line belongs to the Cookies tab, as on import
        var cookieLines = pairs.Where(p => p.Name.Equals("Cookie", StringComparison.OrdinalIgnoreCase) && p.Enabled).ToList();
        if (cookieLines.Count > 0)
        {
            var cookies = Cookies.ToPairs();
            foreach (var c in cookieLines)
            {
                pairs.Remove(c);
                foreach (var piece in c.Value.Split(';'))
                {
                    string p = piece.Trim();
                    if (p.Length == 0) continue;
                    int eq = p.IndexOf('=');
                    cookies.Add(eq > 0 ? new CurlPair(p[..eq].Trim(), p[(eq + 1)..].Trim()) : new CurlPair(p, string.Empty));
                }
            }
            Cookies.Load(cookies);
        }
        Headers.Load(pairs);
    }

    [RelayCommand]
    private void ToggleHeadersBulk() => HeadersBulk = !HeadersBulk;

    /// <summary>"Added automatically: Content-Type: application/json · Authorization (Basic) · Cookie (2)".</summary>
    [ObservableProperty] private string _autoHeadersText = string.Empty;
    public bool HasAutoHeaders => AutoHeadersText.Length > 0;
    partial void OnAutoHeadersTextChanged(string value) => OnPropertyChanged(nameof(HasAutoHeaders));

    private void RefreshAutoHeaders()
    {
        var model = BuildModel();
        var auto = new List<string>();
        var effective = model.EffectiveHeaders(auto);
        var bits = new List<string>();
        foreach (var name in auto)
        {
            string v = effective.LastOrDefault(h => h.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).Value ?? string.Empty;
            bits.Add(name switch
            {
                "Authorization" => model.Auth == CurlAuthMode.Basic ? "Authorization: Basic …" : "Authorization: Bearer …",
                "Cookie" => model.Cookies.Count(c => c.Enabled && c.Name.Length > 0) is var n && n == 1 ? "Cookie (1 cookie)" : $"Cookie ({model.Cookies.Count(c => c.Enabled && c.Name.Length > 0)} cookies)",
                _ => $"{name}: {v}",
            });
        }
        if (model.EffectiveBodyMode == CurlBodyMode.Multipart) bits.Add("Content-Type: multipart/form-data");
        if (model.Compressed && !effective.Any(h => h.Name.Equals("Accept-Encoding", StringComparison.OrdinalIgnoreCase)))
            bits.Add("Accept-Encoding (compressed)");
        AutoHeadersText = bits.Count == 0 ? string.Empty : "Added automatically: " + string.Join(" · ", bits);
    }

    // ================================================================== body

    public static readonly string[] RawTypes = { "JSON", "XML", "Text", "HTML", "JavaScript" };
    private static readonly string[] RawTypeKeys = { "json", "xml", "text", "html", "javascript" };
    public string[] RawTypeNames => RawTypes;

    /// <summary>0 None · 1 Raw · 2 Form (url-encoded) · 3 Multipart · 4 File.</summary>
    [ObservableProperty] private int _bodyModeIndex;
    [ObservableProperty] private int _rawTypeIndex;
    [ObservableProperty] private string _requestBody = string.Empty;
    [ObservableProperty] private string _bodyFilePath = string.Empty;

    public bool BodyIsNone => BodyModeIndex == 0;
    public bool BodyIsRaw => BodyModeIndex == 1;
    public bool BodyIsForm => BodyModeIndex == 2;
    public bool BodyIsMultipart => BodyModeIndex == 3;
    public bool BodyIsFile => BodyModeIndex == 4;
    public bool HasBodyFile => BodyFilePath.Length > 0;
    public string BodyFileLabel => BodyFilePath.Length == 0 ? string.Empty : CurlPartRow.DisplayName(BodyFilePath);
    public bool CanFormatBody => BodyIsRaw && RawTypeIndex is 0 or 1 && !string.IsNullOrWhiteSpace(RequestBody);

    /// <summary>HEAD never carries a body: said where the body is edited.</summary>
    public string BodyIgnoredNote => HttpMethod == "HEAD" && BodyModeIndex != 0 ? "HEAD requests are sent without a body." : string.Empty;
    public bool HasBodyIgnoredNote => BodyIgnoredNote.Length > 0;

    partial void OnBodyModeIndexChanged(int oldValue, int newValue)
    {
        OnPropertyChanged(nameof(BodyIsNone));
        OnPropertyChanged(nameof(BodyIsRaw));
        OnPropertyChanged(nameof(BodyIsForm));
        OnPropertyChanged(nameof(BodyIsMultipart));
        OnPropertyChanged(nameof(BodyIsFile));
        OnPropertyChanged(nameof(CanFormatBody));
        OnPropertyChanged(nameof(BodyIgnoredNote));
        OnPropertyChanged(nameof(HasBodyIgnoredNote));
        // like curl -d: a body on a GET means POST (an explicit GET with a body can still be chosen afterwards)
        if (_loaded && !_applying && oldValue == 0 && newValue != 0 && HttpMethod == "GET")
        {
            HttpMethod = "POST";
            ShowNote("Method switched to POST — a GET normally has no body (choose GET again to send one anyway).", isError: false);
        }
        ValidateBody();
        RequestChanged();
    }

    partial void OnRawTypeIndexChanged(int value)
    {
        OnPropertyChanged(nameof(CanFormatBody));
        ValidateBody();
        RequestChanged();
    }

    partial void OnRequestBodyChanged(string value)
    {
        OnPropertyChanged(nameof(CanFormatBody));
        ScheduleValidate();
        RequestChanged();
    }

    partial void OnBodyFilePathChanged(string value)
    {
        OnPropertyChanged(nameof(HasBodyFile));
        OnPropertyChanged(nameof(BodyFileLabel));
        RequestChanged();
    }

    [RelayCommand] private void ClearBodyFile() => BodyFilePath = string.Empty;

    // ---- raw body validation (JSON / XML), debounced
    [ObservableProperty] private string _bodyStatus = string.Empty;
    [ObservableProperty] private bool _bodyStatusError;
    public bool HasBodyStatus => BodyStatus.Length > 0;
    partial void OnBodyStatusChanged(string value) => OnPropertyChanged(nameof(HasBodyStatus));

    private Avalonia.Threading.DispatcherTimer? _validateTimer;
    private void ScheduleValidate()
    {
        if (_validateTimer is null)
        {
            _validateTimer = new Avalonia.Threading.DispatcherTimer { Interval = TimeSpan.FromMilliseconds(350) };
            _validateTimer.Tick += (_, _) => { _validateTimer.Stop(); ValidateBody(); };
        }
        _validateTimer.Stop();
        _validateTimer.Start();
    }

    private int _validateGen;
    private async void ValidateBody()
    {
        _validateTimer?.Stop();
        int gen = ++_validateGen;
        string text = RequestBody;
        if (!BodyIsRaw || string.IsNullOrWhiteSpace(text) || RawTypeIndex is not (0 or 1)) { BodyStatus = string.Empty; return; }
        bool json = RawTypeIndex == 0;
        string? error;
        try { error = await Task.Run(() => json ? CurlBody.JsonError(text) : CurlBody.XmlError(text)); }
        catch (Exception ex) { error = ex.Message; }
        if (gen != _validateGen) return;
        BodyStatusError = error != null;
        BodyStatus = error ?? (json ? "Valid JSON" : "Well-formed XML");
    }

    [RelayCommand]
    private async Task FormatBody()
    {
        string text = RequestBody;
        bool json = RawTypeIndex == 0;
        string? pretty = await Task.Run(() => json ? CurlBody.PrettyJson(text) : CurlBody.PrettyXml(text));
        // a big body takes a moment: if it was edited, replaced (a saved request, an imported command) or its type changed
        // meanwhile, the result is for a body that's gone and must not overwrite the new one
        if (!ReferenceEquals(RequestBody, text) || RawTypeIndex != (json ? 0 : 1)) return;
        if (pretty is null) { ValidateBody(); return; }
        RequestBody = pretty;
    }

    // ================================================================== auth

    /// <summary>0 None · 1 Basic · 2 Bearer.</summary>
    [ObservableProperty] private int _authModeIndex;
    [ObservableProperty] private string _authUser = string.Empty;
    [ObservableProperty] private string _authPass = string.Empty;
    [ObservableProperty] private string _authToken = string.Empty;

    public bool AuthIsNone => AuthModeIndex == 0;
    public bool AuthIsBasic => AuthModeIndex == 1;
    public bool AuthIsBearer => AuthModeIndex == 2;

    /// <summary>What the header will look like (the secret shortened).</summary>
    public string AuthPreview
    {
        get
        {
            var value = BuildModel().AuthorizationValue();
            if (value is null) return AuthModeIndex == 0 ? "No Authorization header is added." : "Fill in the fields to add the header.";
            if (Headers.ToPairs().Any(h => h.Enabled && h.Name.Trim().Equals("Authorization", StringComparison.OrdinalIgnoreCase)))
                return "An Authorization header in Headers wins over this.";
            string shown = value.Length > 34 ? value[..30] + "…" : value;
            return "Authorization: " + shown;
        }
    }

    partial void OnAuthModeIndexChanged(int value)
    {
        OnPropertyChanged(nameof(AuthIsNone));
        OnPropertyChanged(nameof(AuthIsBasic));
        OnPropertyChanged(nameof(AuthIsBearer));
        AuthChanged();
    }
    partial void OnAuthUserChanged(string value) => AuthChanged();
    partial void OnAuthPassChanged(string value) => AuthChanged();
    partial void OnAuthTokenChanged(string value) => AuthChanged();

    private void AuthChanged()
    {
        OnPropertyChanged(nameof(AuthPreview));
        RequestChanged();
    }

    // ================================================================== options

    [ObservableProperty] private bool _useDotNetEngine;
    /// <summary>0 Auto · 1 HTTP/1.1 · 2 HTTP/2 · 3 HTTP/3.</summary>
    [ObservableProperty] private int _httpVersionIndex;
    public string[] HttpVersionNames { get; } = { "Auto", "HTTP/1.1", "HTTP/2", "HTTP/3" };
    [ObservableProperty] private int _timeoutSec = 30;
    [ObservableProperty] private bool _followRedirects = true;
    [ObservableProperty] private bool _compressed = true;
    [ObservableProperty] private bool _skipSslVerify;
    [ObservableProperty] private bool _useProxy;
    [ObservableProperty] private string _proxy = string.Empty;
    [ObservableProperty] private string _proxyUser = string.Empty;
    [ObservableProperty] private string _proxyPass = string.Empty;
    [ObservableProperty] private string _overrideIp = string.Empty;

    /// <summary>0 = curl, 1 = .NET (the Options switch).</summary>
    public int EngineIndex
    {
        get => UseDotNetEngine ? 1 : 0;
        set => UseDotNetEngine = value == 1;
    }

    partial void OnUseDotNetEngineChanged(bool value) { OnPropertyChanged(nameof(EngineIndex)); RequestChanged(); }
    partial void OnHttpVersionIndexChanged(int value) => RequestChanged();
    partial void OnTimeoutSecChanged(int value) => RequestChanged();
    partial void OnFollowRedirectsChanged(bool value) => RequestChanged();
    partial void OnCompressedChanged(bool value) => RequestChanged();
    partial void OnSkipSslVerifyChanged(bool value) => RequestChanged();
    partial void OnUseProxyChanged(bool value) => RequestChanged();
    partial void OnProxyChanged(string value) => RequestChanged();
    partial void OnProxyUserChanged(string value) => RequestChanged();
    partial void OnProxyPassChanged(string value) => RequestChanged();
    partial void OnOverrideIpChanged(string value) => RequestChanged();

    // ---- "active option" chips under the URL: what isn't the default, at a glance (a click opens Options)
    [ObservableProperty] private IReadOnlyList<string> _optionChips = Array.Empty<string>();
    public bool HasOptionChips => OptionChips.Count > 0 || HasSavedName;
    partial void OnOptionChipsChanged(IReadOnlyList<string> value) => OnPropertyChanged(nameof(HasOptionChips));

    private void RefreshChips()
    {
        var chips = new List<string>();
        if (UseProxy && !string.IsNullOrWhiteSpace(Proxy)) chips.Add("Proxy " + StripUserInfo(Proxy.Trim()));
        if (!string.IsNullOrWhiteSpace(OverrideIp)) chips.Add("Override " + OverrideIp.Trim());
        if (SelectedNicIp is { } nic) chips.Add("Via " + nic);
        if (SkipSslVerify) chips.Add("Insecure TLS");
        if (HttpVersionIndex is > 0 and < 4) chips.Add(HttpVersionNames[HttpVersionIndex]);
        if (!FollowRedirects) chips.Add("No redirects");
        if (TimeoutSec == 0) chips.Add("No timeout");
        else if (TimeoutSec != 30) chips.Add($"Timeout {TimeoutSec} s");
        if (CanChooseEngine && UseDotNetEngine) chips.Add(".NET engine");
        if (!OptionChips.SequenceEqual(chips)) OptionChips = chips;
        else OnPropertyChanged(nameof(HasOptionChips));
    }

    [RelayCommand]
    private void OpenOptions()
    {
        SectionIndex = 0;
        RequestTabIndex = 5;
    }

    // ================================================================== model ⇄ fields

    /// <summary>The request exactly as the fields describe it — the single source for both engines and the snippets.</summary>
    public CurlRequest BuildModel()
    {
        bool proxyOn = UseProxy && !string.IsNullOrWhiteSpace(Proxy);
        return new CurlRequest
        {
            Method = string.IsNullOrWhiteSpace(HttpMethod) ? "GET" : HttpMethod.Trim(),
            Url = (Url ?? string.Empty).Trim(),
            Headers = HeadersBulk ? ParseBulkHeaders(HeadersBulkText) : Headers.ToPairs(),
            Cookies = Cookies.ToPairs(),
            BodyMode = (CurlBodyMode)Math.Clamp(BodyModeIndex, 0, 4),
            RawBody = RequestBody ?? string.Empty,
            RawType = RawTypeKeys[Math.Clamp(RawTypeIndex, 0, RawTypeKeys.Length - 1)],
            Form = FormFields.ToPairs(),
            Parts = Parts.ToParts(),
            BodyFile = BodyFilePath ?? string.Empty,
            Auth = (CurlAuthMode)Math.Clamp(AuthModeIndex, 0, 2),
            AuthUser = AuthUser ?? string.Empty,
            AuthPass = AuthPass ?? string.Empty,
            AuthToken = AuthToken ?? string.Empty,
            FollowRedirects = FollowRedirects,
            MaxRedirects = _maxRedirects,
            Insecure = SkipSslVerify,
            Compressed = Compressed,
            TimeoutSec = Math.Max(0, TimeoutSec),
            ConnectTimeoutSec = _connectTimeoutSec,
            HttpVersion = (CurlHttpVersion)Math.Clamp(HttpVersionIndex, 0, 3),
            Proxy = proxyOn ? Proxy.Trim() : null,
            ProxyUser = proxyOn && ProxyUser.Length > 0 ? ProxyUser : null,
            ProxyPass = proxyOn && ProxyPass.Length > 0 ? ProxyPass : null,
            OverrideIp = string.IsNullOrWhiteSpace(OverrideIp) ? null : OverrideIp.Trim(),
            InterfaceIp = SelectedNicIp,
        };
    }

    // set by an import / a saved request; not separate fields in the UI (the defaults are fine for typing)
    private int _maxRedirects = CurlRequest.DefaultMaxRedirects;
    private int _connectTimeoutSec;
    private bool _applying;

    /// <summary>Show <paramref name="r"/> in every field (import, a saved request, the history).</summary>
    public void ApplyModel(CurlRequest r, bool includeConnection = true)
    {
        _applying = true;
        _loaded = false;   // one refresh at the end, not one per field
        try
        {
            if (!HttpMethods.Contains(r.Method)) HttpMethods.Add(r.Method);
            HttpMethod = r.Method;
            Url = r.Url;
            Headers.Load(r.Headers, notify: false);
            Cookies.Load(r.Cookies, notify: false);
            RawTypeIndex = Math.Max(0, Array.IndexOf(RawTypeKeys, r.RawType));
            RequestBody = r.RawBody;
            FormFields.Load(r.Form, notify: false);
            Parts.Load(r.Parts, notify: false);
            BodyFilePath = r.BodyFile;
            BodyModeIndex = (int)r.BodyMode;
            AuthModeIndex = (int)r.Auth;
            AuthUser = r.AuthUser;
            AuthPass = r.AuthPass;
            AuthToken = r.AuthToken;
            FollowRedirects = r.FollowRedirects;
            _maxRedirects = r.MaxRedirects;
            SkipSslVerify = r.Insecure;
            Compressed = r.Compressed;
            TimeoutSec = r.TimeoutSec;
            _connectTimeoutSec = r.ConnectTimeoutSec;
            HttpVersionIndex = (int)r.HttpVersion;
            if (includeConnection)
            {
                if (r.Proxy is { Length: > 0 })
                {
                    Proxy = r.Proxy;
                    ProxyUser = r.ProxyUser ?? string.Empty;
                    ProxyPass = r.ProxyPass ?? string.Empty;
                    UseProxy = true;
                    _keepProxy = _keepProxyPass = null;
                }
                OverrideIp = r.OverrideIp ?? string.Empty;
            }
            // _loaded is off here, so OnPropertyChanged doesn't drop the stored values kept as they were (an unreadable
            // key this run): the applied URL / proxy are what the save below must write, not the old sealed ones
            _keepUrl = null;
        }
        finally
        {
            _loaded = true;
            _applying = false;
        }
        if (HeadersBulk)
        {
            _dropBulk = true;   // the rows are the truth now: the bulk text isn't parsed back over them
            try { HeadersBulk = false; }
            finally { _dropBulk = false; }
        }
        SyncParamsFromUrl();
        ValidateBody();
        OnPropertyChanged(nameof(AuthPreview));
        RequestChanged();
        SchedulePersist();
    }

    [RelayCommand]
    private void NewRequest()
    {
        var keep = BuildModel();
        var fresh = new CurlRequest
        {
            Url = "https://", Compressed = true, FollowRedirects = true, TimeoutSec = keep.TimeoutSec,
            Proxy = keep.Proxy, ProxyUser = keep.ProxyUser, ProxyPass = keep.ProxyPass,
        };
        ApplyModel(fresh, includeConnection: false);
        OverrideIp = string.Empty;
        CurrentSavedId = null;
        ClearResponse();
        DismissNote();
        SectionIndex = 0;
        RequestTabIndex = 0;
    }

    // ================================================================== code snippets

    public string[] SnippetLanguages => RequestSnippets.Languages;
    [ObservableProperty] private string _snippetLanguage = "curl";
    [ObservableProperty] private string _snippetCode = string.Empty;
    partial void OnSnippetLanguageChanged(string value) => RegenerateSnippet();

    // Every keystroke used to rebuild the whole snippet (re-escaping a 1 MB body each time): rebuilt once typing pauses,
    // and only while Code is the open section (otherwise when it's opened, or copied).
    private Avalonia.Threading.DispatcherTimer? _snippetTimer;
    private bool _snippetDirty;
    private const int CodeSection = 2;

    private void ScheduleSnippet()
    {
        if (SectionIndex != CodeSection)
        {
            _snippetTimer?.Stop();
            _snippetDirty = true;
            return;
        }
        if (_snippetTimer is null)
        {
            _snippetTimer = new Avalonia.Threading.DispatcherTimer { Interval = TimeSpan.FromMilliseconds(300) };
            _snippetTimer.Tick += (_, _) => RegenerateSnippet();
        }
        _snippetTimer.Stop();
        _snippetTimer.Start();
    }

    private void RegenerateSnippet()
    {
        _snippetTimer?.Stop();
        _snippetDirty = false;
        try { SnippetCode = RequestSnippets.Build(SnippetLanguage, BuildModel()); }
        catch (Exception ex) { SnippetCode = "# " + ex.Message; }
    }

    [RelayCommand]
    private async Task CopySnippet()
    {
        if (_snippetDirty || _snippetTimer is { IsEnabled: true }) RegenerateSnippet();
        await ClipboardHelper.SetTextAsync(SnippetCode);
        Flash("Copied the " + SnippetLanguage + " snippet");
    }

    /// <summary>The ⋯ menu's "Copy as curl": the bash form everyone shares (docs, issues, Postman); Code has cmd / others.</summary>
    [RelayCommand]
    private async Task CopyAsCurl()
    {
        await ClipboardHelper.SetTextAsync(RequestSnippets.Build("curl", BuildModel()));
        Flash("Copied as curl");
    }
}
