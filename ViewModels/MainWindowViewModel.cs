using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private PingViewModel? _pingVM;
    private DnsViewModel? _dnsVM;
    private CurlViewModel? _curlVM;
    private PortScannerViewModel? _portScannerVM;
    private IpInfoViewModel? _ipInfoVM;
    private SshViewModel? _sshVM;
    private StringLabViewModel? _stringTool;
    private MonitorViewModel? _monitorVM;
    private NetworkInfoViewModel? _networkVM;
    private NoteViewModel? _noteVM;
    private CloudflareViewModel? _cloudflareVM;
    private HistoryViewModel? _historyVM;
    private BackupViewModel? _backupVM;
    private WebServerViewModel? _webServerVM;
    private CheckHostViewModel? _checkHostVM;
    private ProxyViewModel? _proxyVM;
    private DoctorViewModel? _doctorVM;
    public PingViewModel PingVM => _pingVM ??= new();
    public DnsViewModel DnsVM => _dnsVM ??= new();
    public CurlViewModel CurlVM => _curlVM ??= new();
    public PortScannerViewModel PortScannerVM => _portScannerVM ??= new();
    public IpInfoViewModel IpInfoVM => _ipInfoVM ??= new();
    public SshViewModel SshVM => _sshVM ??= new();
    public StringLabViewModel StringTool => _stringTool ??= new();
    public MonitorViewModel MonitorVM => _monitorVM ??= new();
    public NetworkInfoViewModel NetworkVM => _networkVM ??= new();
    public NoteViewModel NoteVM => _noteVM ??= new();
    public CloudflareViewModel CloudflareVM => _cloudflareVM ??= new();
    public HistoryViewModel HistoryVM => _historyVM ??= new();
    public BackupViewModel BackupVM => _backupVM ??= new();
    public WebServerViewModel WebServerVM => _webServerVM ??= new();
    public CheckHostViewModel CheckHostVM => _checkHostVM ??= new();
    public ProxyViewModel ProxyVM => _proxyVM ??= new();
    // Held here (still created on the first visit) so its debounced proxy-settings save is flushed on exit / backgrounding.
    public DoctorViewModel DoctorVM => _doctorVM ??= new();

    // Flush debounced persistence + release the file-share listening socket on shutdown.
    public void FlushOnExit()
    {
        FlushPersistence();
        // Guarded like the flushes: this runs inside ShutdownRequested, and an exception escaping it would stop Quit
        // (and an OS logoff) from completing.
        try { _webServerVM?.StopServer(); } catch (Exception ex) { CrashLog.Write("Exit.WebServer", ex); }
        try { _proxyVM?.StopServer(); } catch (Exception ex) { CrashLog.Write("Exit.Proxy", ex); }
    }

    // Write every debounced edit that hasn't reached disk yet (Cloudflare profiles, note text, Check-Host / IP Info /
    // cURL / SSH / Doctor / Telegram settings, String Lab's choices). Runs on shutdown AND when the app is backgrounded — Android can kill a background process
    // with no further callback. Each flush is a no-op when nothing is pending. UI thread only.
    public void FlushPersistence()
    {
        // Independent stores: one failing must not skip the others (and nothing may escape a shutdown handler).
        try { _cloudflareVM?.FlushPendingSave(); } catch (Exception ex) { CrashLog.Write("Flush.Cloudflare", ex); }
        try { _noteVM?.FlushPendingSave(); } catch (Exception ex) { CrashLog.Write("Flush.Notes", ex); }
        try { _checkHostVM?.FlushPendingSave(); } catch (Exception ex) { CrashLog.Write("Flush.CheckHost", ex); }
        try { _ipInfoVM?.FlushPendingSave(); } catch (Exception ex) { CrashLog.Write("Flush.IpInfo", ex); }
        try { _curlVM?.FlushPendingSave(); } catch (Exception ex) { CrashLog.Write("Flush.Curl", ex); }
        try { _sshVM?.FlushPendingSave(); } catch (Exception ex) { CrashLog.Write("Flush.Ssh", ex); }
        try { _doctorVM?.FlushPendingSave(); } catch (Exception ex) { CrashLog.Write("Flush.Doctor", ex); }
        try { _stringTool?.FlushPendingSave(); } catch (Exception ex) { CrashLog.Write("Flush.StringLab", ex); }
        try { TgViewModel.FlushAll(); } catch (Exception ex) { CrashLog.Write("Flush.Telegram", ex); }
        // LAST: the flushes above only hand their values to the profile, which writes behind — put it on disk now.
        try { ProfileService.Instance.Flush(); } catch (Exception ex) { CrashLog.Write("Flush.Profile", ex); }
    }

    [ObservableProperty] private string _currentVersion;
    [ObservableProperty] private string _latestVersion;
    [ObservableProperty] private bool _isUpdateAvailable;
    [ObservableProperty] private string _latestReleaseUrl = "https://github.com/SinaXhpm/Echoes/releases";
    public static bool IsMac => RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
    public MainViewModel()
    {
        // The informational version follows <Version> (the release build sets it from the tag: -p:Version=0.4.0), with
        // "+commit" build metadata cut off; the assembly version (Major.Minor.Build) is the fallback.
        var asm = System.Reflection.Assembly.GetExecutingAssembly();
        string? info = System.Reflection.CustomAttributeExtensions
            .GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>(asm)?.InformationalVersion;
        if (info is { Length: > 0 } && info.IndexOf('+') is int plus && plus >= 0) info = info[..plus];
        var assemblyVersion = asm.GetName().Version;
        _currentVersion = info is { Length: > 0 } && Version.TryParse(info, out _)
            ? info
            : $"{assemblyVersion?.Major}.{assemblyVersion?.Minor}.{assemblyVersion?.Build}";
        _latestVersion = _currentVersion;
    }

    // GitHub's answer for one release is a few KB (its notes and asset list); anything near this isn't that answer.
    private const int MaxReleaseJsonBytes = 1024 * 1024;

    /// <summary>The release API; a test harness points it at a stand-in server.</summary>
    internal static string LatestReleaseApi { get; set; } = "https://api.github.com/repos/SinaXhpm/Echoes/releases/latest";

    // Uses the GitHub Releases API (the latest published release) as the single source
    // of truth — no hand-maintained version.json to keep in sync.
    // The request and the JSON parse run on the thread pool, not on the UI thread the shell's Loaded calls this from at
    // startup: starting the request there looked up the system proxy on it (a WPAD discovery can take seconds, see
    // HttpHelper), and an answer of any size used to be read and parsed there whole (it's capped now). Only the results
    // are set back here. A failure (offline, GitHub blocked, rate limited) shows only in the About box (the sidebar stays
    // quiet) and is written to the crash log. Runs at startup and from the About box; a second call while one runs is a no-op.
    public async Task CheckForUpdatesAsync()
    {
        // An app store updates the app: no check, and nothing in the UI that points to a release elsewhere.
        if (AppInfo.IsStoreBuild) return;
        if (UpdateState == UpdateCheckState.Checking) return;
        UpdateState = UpdateCheckState.Checking;
        UpdateDetail = "Asking GitHub for the latest release…";
        UpdateDetailTip = null;

        var r = await Task.Run(FetchLatestReleaseAsync);
        _lastUpdateCheck = DateTime.Now;
        string at = _lastUpdateCheck.ToString("HH:mm", System.Globalization.CultureInfo.InvariantCulture);
        if (r.Error is { } error)
        {
            UpdateState = UpdateCheckState.Failed;
            UpdateDetail = $"{error.Short} · {at}";
            UpdateDetailTip = error.Full;
            return;
        }

        if (r.Url is not null) LatestReleaseUrl = r.Url;
        LatestVersion = r.Version!;
        IsUpdateAvailable = Version.TryParse(r.Version, out var latest) && Version.TryParse(CurrentVersion, out var current)
                            && latest > current;
        UpdateState = IsUpdateAvailable ? UpdateCheckState.Available : UpdateCheckState.UpToDate;
        UpdateDetail = IsUpdateAvailable
            ? $"v{LatestVersion} is out (you have v{CurrentVersion}) · {at}"
            : $"Latest release: v{LatestVersion} · checked {at}";
    }

    private readonly record struct ReleaseCheck(string? Version, string? Url, (string Short, string Full)? Error);

    private static async Task<ReleaseCheck> FetchLatestReleaseAsync()
    {
        try
        {
            using var client = HttpHelper.Create(timeout: TimeSpan.FromSeconds(10));
            client.MaxResponseContentBufferSize = MaxReleaseJsonBytes;   // decompressed bytes: a gzip bomb stops here too
            client.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");

            var json = await client.GetStringAsync(LatestReleaseApi).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return Unreadable();

            string tag = root.TryGetProperty("tag_name", out var t) && t.ValueKind == JsonValueKind.String ? t.GetString() ?? string.Empty : string.Empty;
            string clean = tag.TrimStart('v', 'V').Trim();
            if (clean.Length == 0) return Unreadable();
            if (clean.Length > 40) clean = clean[..40];   // shown in the sidebar pill only when it parses as a version anyway

            // The pill opens this page: only ever a release page on github.com (the API's own answer, but a link handed
            // to the browser is checked like one).
            string? url = root.TryGetProperty("html_url", out var u) && u.ValueKind == JsonValueKind.String
                          && Uri.TryCreate(u.GetString(), UriKind.Absolute, out var link) && link.Scheme == Uri.UriSchemeHttps
                          && link.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase)
                ? link.AbsoluteUri : null;
            return new ReleaseCheck(clean, url, null);
        }
        catch (Exception ex)
        {
            // One line, no stack trace: a check that can't reach GitHub is expected (offline, blocked, rate limited) and
            // repeats at every launch; the crash log is what people attach to bug reports.
            var reason = new System.Text.StringBuilder(ex.GetType().Name).Append(": ").Append(ex.Message);
            for (var inner = ex.InnerException; inner is not null; inner = inner.InnerException)
                reason.Append(" → ").Append(inner.GetType().Name).Append(": ").Append(inner.Message);
            CrashLog.Write("UpdateCheck (ignored)", new Exception(reason.ToString()));
            string brief = ex switch
            {
                System.Net.Http.HttpRequestException { StatusCode: System.Net.HttpStatusCode.Forbidden or System.Net.HttpStatusCode.TooManyRequests }
                    => "GitHub's rate limit; try again later",
                System.Net.Http.HttpRequestException { StatusCode: System.Net.HttpStatusCode.NotFound } => "No release published yet",
                System.Net.Http.HttpRequestException { StatusCode: { } code } => $"GitHub answered {(int)code}",
                TaskCanceledException or TimeoutException => "GitHub didn't answer in 10 s",
                System.Net.Http.HttpRequestException => "Can't reach GitHub (offline or blocked?)",
                JsonException => "GitHub's answer couldn't be read",
                _ => "Couldn't check",
            };
            return new ReleaseCheck(null, null, (brief, reason.ToString()));
        }

        static ReleaseCheck Unreadable() => new(null, null, ("GitHub's answer couldn't be read", "No tag_name in the latest release."));
    }

    [RelayCommand]
    private void OpenGitHub() => OpenUrl("https://github.com/SinaXhpm/Echoes");

    // Light / dark, live (sidebar footer on desktop, the drawer on phones).
    [RelayCommand]
    private void ToggleTheme() => Helpers.ThemeService.Toggle();

    [RelayCommand]
    private void OpenReleases() => OpenUrl(LatestReleaseUrl);

    private static void OpenUrl(string url) => Helpers.LinkHelper.Open(url);
}