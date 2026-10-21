using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

/// <summary>A selectable outgoing network interface. Ip == null means "Auto" (let the OS route).</summary>
public sealed record NicOption(string Display, string? Ip)
{
    public override string ToString() => Display;
}

/// <summary>
/// The cURL tab: a request builder (params, headers, body, auth, cookies, options), curl-command import, two engines
/// (system curl / .NET), a response inspector (pretty body, headers, timing, logs, TLS, preview), code snippets, saved
/// requests and a history. The partial files hold each part; this one holds the shell — sections, persistence, the
/// network interfaces and running a request.
/// </summary>
public partial class CurlViewModel : ObservableObject
{
    // Outer section: 0 Request · 1 Response · 2 Code · 3 Saved
    [ObservableProperty] private int _sectionIndex;
    [ObservableProperty] private int _requestTabIndex;
    [ObservableProperty] private int _responseTabIndex;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsIdle))]
    private bool _isWorking;
    public bool IsIdle => !IsWorking;

    /// <summary>Generation of the current run: a stopped run whose last continuation lands after the next one started
    /// can't publish its result or flip the new one back to idle.</summary>
    private int _runGen;
    private CancellationTokenSource? _runCts;
    private int _sslGen;

    /// <summary>Phones have no curl binary to shell out to: the engine switch is hidden and .NET is used.</summary>
    public bool CanChooseEngine => !OperatingSystem.IsAndroid() && !AppPlatform.IsMobile;

    public CurlViewModel()
    {
        Params = new CurlKvList(OnParamsChanged);
        Headers = new CurlKvList(OnHeadersChanged);
        Cookies = new CurlKvList(OnCookiesChanged);
        FormFields = new CurlKvList(OnBodyChanged);
        Parts = new CurlPartList(OnBodyChanged);

        RestoreSettings();
        LoadInterfaces();
        _loaded = true;
        SyncParamsFromUrl();
        RefreshChips();
        RefreshAutoHeaders();
        RegenerateSnippet();
        LoadLibrary();

        // A debounced edit must not be lost when the window closes within the debounce window.
        // (MainViewModel.FlushPersistence calls FlushPendingSave as well — it's idempotent.)
        if (Avalonia.Application.Current?.ApplicationLifetime is Avalonia.Controls.ApplicationLifetimes.IControlledApplicationLifetime life)
            life.Exit += (_, _) => FlushPendingSave();
    }

    // ================================================================== network interfaces

    [ObservableProperty] private List<NicOption> _interfaces = new();
    [ObservableProperty] private NicOption? _selectedInterface;
    private string? SelectedNicIp => SelectedInterface?.Ip;

    // The adapter the user picked (curl.nicIp). Kept while it is down: a VPN that was off when the tab opened fell back to
    // Auto, and that fallback was saved over the choice for good. It is selected again once it comes back; only the user's
    // own pick changes it.
    private string? _preferredNicIp;
    private bool _applyingNics;

    partial void OnSelectedInterfaceChanged(NicOption? value)
    {
        if (_loaded && !_applyingNics)
        {
            _preferredNicIp = value?.Ip;
            ProfileService.Instance.SetSetting("curl.nicIp", value?.Ip ?? string.Empty);
        }
        RequestChanged();
    }

    /// <summary>Re-enumerate NICs (the cURL tab became visible) so interfaces that came up / went down show; keeps the
    /// selection while it still exists.</summary>
    public void RefreshInterfaces() => LoadInterfaces();

    private void LoadInterfaces()
    {
        var list = new List<NicOption> { new("Auto (default route)", null) };
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    var a = ua.Address;
                    if (a.AddressFamily != AddressFamily.InterNetwork && a.AddressFamily != AddressFamily.InterNetworkV6) continue;
                    if (a.IsIPv6LinkLocal || a.IsIPv6Multicast) continue;   // skip fe80::/link-local noise
                    list.Add(new NicOption($"{ni.Name} — {a}", a.ToString()));
                }
            }
        }
        catch { }

        if (!_loaded) _preferredNicIp = ProfileService.Instance.GetSetting("curl.nicIp");
        string? keep = _preferredNicIp;
        _applyingNics = true;   // a fallback to Auto (the adapter is down) is shown, not saved
        try
        {
            Interfaces = list;
            SelectedInterface = (!string.IsNullOrEmpty(keep) ? list.FirstOrDefault(n => n.Ip == keep) : null) ?? list[0];
        }
        finally { _applyingNics = false; }
    }

    // ================================================================== persistence (debounced)

    private bool _loaded;
    // Headers, body, auth and cookies are deliberately NOT persisted: they carry credentials (Authorization, Cookie, API
    // keys) — a request that should survive a restart is saved explicitly (Saved), which says so. CustomFlags is gone.
    private static readonly HashSet<string> PersistProps = new()
    {
        nameof(Url), nameof(OverrideIp), nameof(Proxy), nameof(ProxyUser), nameof(ProxyPass), nameof(SkipSslVerify),
        nameof(UseDotNetEngine), nameof(HttpMethod), nameof(UseProxy), nameof(WrapBody), nameof(TimeoutSec),
        nameof(FollowRedirects), nameof(Compressed), nameof(HttpVersionIndex), nameof(SnippetLanguage),
    };

    // A stored value that is sealed but doesn't open this run — SecretProtector's key file couldn't be read (a passing
    // condition: SecretProtector caches the miss for the run, the next run may read it) or the profile came from another
    // machine. The field shows its fallback, and the stored value is written back exactly as it was until the user changes
    // THAT field: a save triggered by any other setting (GET → POST, the timeout) used to write the fallback over it — the
    // proxy password became "", a URL with credentials became "https://". UI thread (the snapshot carries them).
    private string? _keepUrl, _keepProxy, _keepProxyPass;

    private void RestoreSettings()
    {
        var ps = ProfileService.Instance;
        // Values that can hold credentials are stored via SecretProtector (see WritePendingPersist). Unprotect passes
        // legacy plaintext straight through (re-saved encrypted on the next change), and a value that can't be decrypted
        // falls back like a missing one — but is kept on disk as stored (see _keepUrl).
        bool migrate = false;
        string Restore(string key, string fallback, out string? unreadable)
        {
            unreadable = null;
            string? raw = ps.GetSetting(key);
            if (raw is null) return fallback;
            string v = SecretProtector.Unprotect(raw);
            if (raw.Length > 0 && v == raw && (key == "curl.proxyPass" || HasUserInfo(raw))) migrate = true;
            if (v.Length > 0 && SecretProtector.IsLegacy(raw)) migrate = true;
            if (v.Length == 0 && raw.Length > 0) { unreadable = raw; return fallback; }   // sealed, and it didn't open here
            return v;
        }
        // _loaded is still false: these sets neither persist nor refresh anything
        Url = Restore("curl.url", HistoryService.Instance.Last("curl.url") ?? "https://", out _keepUrl);
        OverrideIp = ps.GetSetting("curl.overrideIp") ?? string.Empty;
        Proxy = Restore("curl.proxy", HistoryService.Instance.Last("curl.proxy") ?? string.Empty, out _keepProxy);
        ProxyUser = ps.GetSetting("curl.proxyUser") ?? string.Empty;
        ProxyPass = Restore("curl.proxyPass", string.Empty, out _keepProxyPass);
        ps.Remove("curl.flags");   // purge the plaintext header/credential copy earlier builds wrote (no-op once gone)
        SkipSslVerify = ps.GetBool("curl.skipSsl");
        // Android has no curl binary: the managed engine there (a value the user saved still wins on desktop)
        UseDotNetEngine = !CanChooseEngine || ps.GetBool("curl.useDotNet", false);
        HttpMethod = ps.GetSetting("curl.method") is { Length: > 0 } m ? m : "GET";
        UseProxy = ps.GetBool("curl.useProxy");
        WrapBody = ps.GetBool("curl.wrapRawBody");
        TimeoutSec = Math.Clamp(ps.GetInt("curl.timeout", 30), 0, 3600);
        FollowRedirects = ps.GetBool("curl.follow", true);
        Compressed = ps.GetBool("curl.compressed", true);
        HttpVersionIndex = Math.Clamp(ps.GetInt("curl.http", 0), 0, 3);
        SnippetLanguage = ps.GetSetting("curl.snippetLang") is { Length: > 0 } sl && RequestSnippets.Languages.Contains(sl) ? sl : "curl";
        RequestTabIndex = Math.Clamp(ps.GetInt("curl.reqTab", 0), 0, 5);
        LibraryIndex = Math.Clamp(ps.GetInt("curl.library", 0), 0, 1);
        if (migrate) SchedulePersist();
    }

    // Keep*: the stored value to write back as is (see _keepUrl), or null to save the field's own value.
    private sealed record PersistSnapshot(string Url, string OverrideIp, string Proxy, string ProxyUser, string ProxyPass,
        bool SkipSsl, bool UseDotNet, string Method, bool UseProxy, bool Wrap, int Timeout, bool Follow, bool Compressed,
        int Http, string SnippetLang, string? KeepUrl, string? KeepProxy, string? KeepProxyPass);

    private PersistSnapshot? _pendingPersist;              // newest unsaved state (swapped atomically)
    private readonly object _persistWriteGate = new();     // serializes writers so an older snapshot can't land last
    private CancellationTokenSource? _persistCts;

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (!_loaded || e.PropertyName is not { } n) return;
        // Changed after loading (typed, imported, a saved request opened): the field's own value is saved from now on.
        if (n == nameof(Url)) _keepUrl = null;
        else if (n == nameof(Proxy)) _keepProxy = null;
        else if (n == nameof(ProxyPass)) _keepProxyPass = null;
        if (PersistProps.Contains(n)) SchedulePersist();
        // The request's sub-tab and the Saved / History switch come back too (saved at once: one value, no typing).
        else if (n == nameof(RequestTabIndex) && RequestTabIndex >= 0) SaveIndex("curl.reqTab", RequestTabIndex);
        else if (n == nameof(LibraryIndex) && LibraryIndex >= 0) SaveIndex("curl.library", LibraryIndex);
    }

    private static void SaveIndex(string key, int value)
        => ProfileService.Instance.SetSetting(key, value.ToString(System.Globalization.CultureInfo.InvariantCulture));

    // Typing into Url / Proxy / … raises PropertyChanged per keystroke: debounce, so the whole profile isn't re-serialized
    // and atomically rewritten on the UI thread for every character.
    private void SchedulePersist()
    {
        Interlocked.Exchange(ref _pendingPersist, new PersistSnapshot(Url, OverrideIp, Proxy, ProxyUser, ProxyPass,
            SkipSslVerify, UseDotNetEngine, HttpMethod, UseProxy, WrapBody, TimeoutSec, FollowRedirects, Compressed,
            HttpVersionIndex, SnippetLanguage, _keepUrl, _keepProxy, _keepProxyPass));
        _persistCts?.Cancel();
        _persistCts?.Dispose();
        var cts = _persistCts = new CancellationTokenSource();
        _ = Task.Delay(600, cts.Token).ContinueWith(t =>
        {
            if (!t.IsCanceled) WritePendingPersist();
        }, TaskScheduler.Default);
    }

    /// <summary>Write any debounced cURL settings now (app exit / Android pause).</summary>
    public void FlushPendingSave()
    {
        try { _persistCts?.Cancel(); } catch (ObjectDisposedException) { }
        WritePendingPersist();
        FlushLibrary();
    }

    private void WritePendingPersist()
    {
        lock (_persistWriteGate)
        {
            var s = Interlocked.Exchange(ref _pendingPersist, null);
            if (s is null) return;
            try
            {
                // The proxy password is always encrypted at rest; the URL / proxy only when they embed credentials
                // (user:pass@, a ?token= style query value, a Telegram bot token in the path).
                // SecretProtector is machine+user-bound obfuscation, not protection against same-user malware.
                // A stored value that couldn't be opened goes back unchanged (Keep*), never its stand-in.
                ProfileService.Instance.SetMany(
                    ("curl.url", s.KeepUrl ?? (HasUserInfo(s.Url) || UrlSecrets.HasSecrets(s.Url) ? SecretProtector.Protect(s.Url) : s.Url)),
                    ("curl.overrideIp", s.OverrideIp),
                    ("curl.proxy", s.KeepProxy ?? (HasUserInfo(s.Proxy) ? SecretProtector.Protect(s.Proxy) : s.Proxy)),
                    ("curl.proxyUser", s.ProxyUser), ("curl.proxyPass", s.KeepProxyPass ?? SecretProtector.Protect(s.ProxyPass)),
                    ("curl.skipSsl", s.SkipSsl ? "true" : "false"), ("curl.useDotNet", s.UseDotNet ? "true" : "false"),
                    ("curl.method", s.Method), ("curl.useProxy", s.UseProxy ? "true" : "false"),
                    ("curl.wrapRawBody", s.Wrap ? "true" : "false"),
                    ("curl.timeout", s.Timeout.ToString(System.Globalization.CultureInfo.InvariantCulture)),
                    ("curl.follow", s.Follow ? "true" : "false"), ("curl.compressed", s.Compressed ? "true" : "false"),
                    ("curl.http", s.Http.ToString(System.Globalization.CultureInfo.InvariantCulture)),
                    ("curl.snippetLang", s.SnippetLang));
            }
            catch { /* best effort, like every other settings write — never crash a background continuation */ }
        }
    }

    // "scheme://user:pass@host…" or a scheme-less "user:pass@host:port" (accepted for proxies). '?' and '#' are excluded so
    // an '@' in a query ("https://h?mail=a@b") isn't mistaken for credentials.
    private static readonly System.Text.RegularExpressions.Regex UserInfoRx = new(
        @"^((?:[a-z][a-z0-9+.\-]*://)?)[^/?#@\s]+@",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    internal static bool HasUserInfo(string? v) => !string.IsNullOrEmpty(v) && UserInfoRx.IsMatch(v.Trim());
    internal static string StripUserInfo(string v) => UserInfoRx.Replace(v.Trim(), "$1");

    // ================================================================== running a request

    [RelayCommand(AllowConcurrentExecutions = true)]
    private async Task ToggleCurl()
    {
        if (IsWorking) { StopCurl(); return; }
        // a curl command typed (or pasted on one line) into the URL box is imported, not sent
        if (CurlCommand.LooksLikeCurl(Url)) { ImportCurl(Url, fromUrlBox: true); return; }
        try { await SendAsync(); }
        catch (Exception ex)
        {
            // Last line of defence: anything escaping here would be rethrown by the generated command's async void onto
            // the dispatcher and take the whole app down.
            CrashLog.Write("Curl.Send", ex);
            IsWorking = false;
            StopRequestTimer();
            ShowFailure("Request failed", ex.Message, null);
        }
    }

    private async Task SendAsync()
    {
        string url = Url.Trim();
        if (url.Length == 0 || url == "https://" || url == "http://")
        {
            ShowFailure("No URL", "Type a URL, or paste a whole curl command into the URL box.", null);
            SectionIndex = 1;
            return;
        }
        string normalized = CurlRequest.NormalizeUrl(url);
        if (normalized != Url) Url = normalized;   // "example.com" → "http://example.com", as curl reads it

        var req = BuildModel();
        int gen = ++_runGen;
        _runCts?.Cancel();
        var cts = _runCts = new CancellationTokenSource();
        IsWorking = true;
        StartRequestTimer();
        BeginResponse();

        HistoryService.Instance.Add("curl.url", req.Url);
        if (UseProxy && !string.IsNullOrWhiteSpace(Proxy)) HistoryService.Instance.Add("curl.proxy", StripUserInfo(Proxy));

        string? nic = SelectedNicIp;
        _ = RunTlsProbe(req, nic, ++_sslGen);

        var opt = new CurlRunOptions { PreferDotNet = UseDotNetEngine || !CanChooseEngine, NicIp = nic, OpenFile = OpenPickedFile };
        CurlResult res;
        try
        {
            // the whole run on the thread pool (opening a picked file may block on the storage provider)
            res = await Task.Run(() => CurlEngine.RunAsync(req, opt, cts.Token));
        }
        catch (Exception ex)
        {
            res = new CurlResult { ErrorTitle = "Request failed", ErrorDetail = ex.Message };
        }
        if (gen != _runGen) return;   // stopped, or a newer run started
        IsWorking = false;
        StopRequestTimer(res.Timing.TotalMs > 0 ? res.Timing.TotalMs : null);
        await ShowResultAsync(res, req, gen);
        AddRecent(req, res);
    }

    [RelayCommand]
    private void StopCurl()
    {
        if (!IsWorking) return;
        IsWorking = false;
        _runGen++;    // the stopped run may no longer publish anything
        _sslGen++;    // nor its TLS probe
        try { _runCts?.Cancel(); } catch { }
        StopRequestTimer();
        ShowStopped();
    }

    private async Task RunTlsProbe(CurlRequest req, string? nic, int gen)
    {
        SslLog = string.Empty;
        try
        {
            string report = await Task.Run(() => CurlTlsProbe.InspectAsync(req, nic, CancellationToken.None));
            if (gen == _sslGen) SslLog = report;
        }
        catch (Exception ex) { if (gen == _sslGen) SslLog = "  TLS Diagnostic Error: " + ex.Message; }
    }

    // Files picked through the storage provider (Android's content:// URIs have no path): opened by the engine when it sends.
    private readonly Dictionary<string, Avalonia.Platform.Storage.IStorageFile> _pickedFiles = new(StringComparer.Ordinal);

    internal void RegisterPickedFile(string key, Avalonia.Platform.Storage.IStorageFile file)
    {
        lock (_pickedFiles) _pickedFiles[key] = file;
    }

    private Stream OpenPickedFile(string path)
    {
        Avalonia.Platform.Storage.IStorageFile? file;
        lock (_pickedFiles) _pickedFiles.TryGetValue(path, out file);
        if (file != null) return file.OpenReadAsync().GetAwaiter().GetResult();   // called on the thread pool
        return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, useAsync: true);
    }

    // ================================================================== request timer (live while in flight)

    [ObservableProperty] private string _requestTimeText = "—";
    [ObservableProperty] private string _responseSizeText = "—";
    private readonly Stopwatch _reqSw = new();
    private Avalonia.Threading.DispatcherTimer? _reqTimer;

    private void StartRequestTimer()
    {
        ResponseSizeText = "—";
        RequestTimeText = "0 ms";
        _reqSw.Restart();
        _reqTimer ??= CreateReqTimer();
        _reqTimer.Interval = FastTick;
        _reqTimer.Start();
    }

    // Smooth while a request is young; a long wait (a stream, "no timeout", a server that never answers) needn't wake the
    // UI 15 times a second for as long as it lasts, in the background on a phone too.
    private static readonly TimeSpan FastTick = TimeSpan.FromMilliseconds(66), SlowTick = TimeSpan.FromMilliseconds(500);

    private Avalonia.Threading.DispatcherTimer CreateReqTimer()
    {
        var t = new Avalonia.Threading.DispatcherTimer { Interval = FastTick };
        t.Tick += (_, _) =>
        {
            double ms = _reqSw.Elapsed.TotalMilliseconds;
            RequestTimeText = FormatMs(ms);
            if (ms > 2000 && t.Interval != SlowTick) t.Interval = SlowTick;
        };
        return t;
    }

    private void StopRequestTimer(double? engineMs = null)
    {
        _reqTimer?.Stop();
        _reqSw.Stop();
        RequestTimeText = FormatMs(engineMs ?? _reqSw.Elapsed.TotalMilliseconds);
    }

    internal static string FormatMs(double ms) => ms < 1 ? $"{ms:0.##} ms" : ms < 1000 ? $"{ms:0} ms" : $"{ms / 1000.0:0.00} s";
}
