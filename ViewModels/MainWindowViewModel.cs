using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading;
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
    public PingViewModel PingVM => _pingVM ??= new(this);
    public DnsViewModel DnsVM => _dnsVM ??= new(this);
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

    /// <summary>github.com's own page for the latest release, which redirects to that release's tag: the second source. A
    /// test harness points it at a stand-in server too.</summary>
    internal static string LatestReleasePage { get; set; } = "https://github.com/SinaXhpm/Echoes/releases/latest";

    // GitHub's latest release (the one marked Latest, never a pre-release: each release starts as one, see release.yml) is
    // the single source of truth — no hand-maintained version.json to keep in sync. It comes from the Releases API, or
    // from github.com's release page when the API doesn't answer (Fallback). jsDelivr's resolved version isn't a source:
    // it follows the git tags, so it would offer a release while it is still a pre-release under test.
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

    /// <summary>The latest release as one source names it.</summary>
    private sealed record LatestRelease(string Version, string? Url);

    private static async Task<ReleaseCheck> FetchLatestReleaseAsync()
    {
        // every source's failure: the error line says the API's (it says most), the tooltip and the crash log all of them
        var failures = new ConcurrentQueue<(string Source, Exception Error)>();
        Fallback.Source<LatestRelease> Source(string name, Func<CancellationToken, Task<LatestRelease?>> fetch) => new(name, async ct =>
        {
            try { return await fetch(ct).ConfigureAwait(false); }
            catch (Exception ex)
            {
                failures.Enqueue((name, ex));
                throw;
            }
        });
        // the page waits 3 s for the API: an update check is never urgent, and on a healthy network one request is enough
        var result = await Fallback.FirstAsync("update-check", new[] { Source("api.github.com", FromApiAsync), Source("github.com", FromPageAsync) },
                                               CancellationToken.None, TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(10)).ConfigureAwait(false);
        if (result.Value is { } latest) return new ReleaseCheck(latest.Version, latest.Url, null);

        // One line, no stack trace: a check that can't reach GitHub is expected (offline, blocked, rate limited) and
        // repeats at every launch; the crash log is what people attach to bug reports.
        var all = failures.ToList();
        string full = all.Count == 0 ? "Neither GitHub's API nor its release page named a release."
            : string.Join(" · ", all.Select(f => f.Source + ": " + Chain(f.Error)));
        CrashLog.Write("UpdateCheck (ignored)", new Exception(full));
        var main = all.FirstOrDefault(f => f.Source == "api.github.com").Error ?? all.FirstOrDefault().Error;
        string brief = main switch
        {
            null => "No release published yet",
            HttpRequestException { StatusCode: System.Net.HttpStatusCode.Forbidden or System.Net.HttpStatusCode.TooManyRequests }
                => "GitHub's rate limit; try again later",
            HttpRequestException { StatusCode: System.Net.HttpStatusCode.NotFound } => "No release published yet",
            HttpRequestException { StatusCode: { } code } => $"GitHub answered {(int)code}",
            TaskCanceledException or TimeoutException => "GitHub didn't answer in 10 s",
            HttpRequestException => "Can't reach GitHub (offline or blocked?)",
            JsonException or InvalidDataException => "GitHub's answer couldn't be read",
            _ => "Couldn't check",
        };
        return new ReleaseCheck(null, null, (brief, full));

        static string Chain(Exception ex)
        {
            var reason = new StringBuilder(ex.GetType().Name).Append(": ").Append(ex.Message);
            for (var inner = ex.InnerException; inner is not null; inner = inner.InnerException)
                reason.Append(" → ").Append(inner.GetType().Name).Append(": ").Append(inner.Message);
            return reason.ToString();
        }
    }

    // The Releases API: the latest release's tag_name and html_url.
    private static async Task<LatestRelease?> FromApiAsync(CancellationToken ct)
    {
        using var client = HttpHelper.Create(timeout: TimeSpan.FromSeconds(10), serviceDns: true);
        client.MaxResponseContentBufferSize = MaxReleaseJsonBytes;   // decompressed bytes: a gzip bomb stops here too
        client.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");

        var json = await client.GetStringAsync(LatestReleaseApi, ct).ConfigureAwait(false);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object) throw new JsonException("The answer isn't a release.");
        string tag = root.TryGetProperty("tag_name", out var t) && t.ValueKind == JsonValueKind.String ? t.GetString() ?? string.Empty : string.Empty;
        string version = CleanTag(tag) ?? throw new JsonException("No tag_name in the latest release.");
        string? url = root.TryGetProperty("html_url", out var u) && u.ValueKind == JsonValueKind.String ? ReleasePage(u.GetString()) : null;
        return new LatestRelease(version, url);
    }

    // github.com's latest-release page redirects to the release's tag (…/releases/tag/v1.0.0): the version is read from
    // the Location, and the page it points to isn't fetched. A redirect to the release list instead: none published yet.
    private static async Task<LatestRelease?> FromPageAsync(CancellationToken ct)
    {
        using var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            ConnectCallback = ServiceDns.ConnectAsync,
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("Echoes");
        using var resp = await client.GetAsync(LatestReleasePage, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        int status = (int)resp.StatusCode;
        if (status >= 400) throw new HttpRequestException($"github.com answered {status}.", null, resp.StatusCode);
        if (status < 300 || resp.Headers.Location is not { } location)
            throw new InvalidDataException("github.com's release page didn't redirect to a release.");
        var target = location.IsAbsoluteUri ? location : new Uri(new Uri(LatestReleasePage), location);
        string? page = ReleasePage(target.AbsoluteUri) ?? throw new InvalidDataException("github.com's release page redirected away from github.com.");
        const string TagPath = "/releases/tag/";
        int at = target.AbsolutePath.IndexOf(TagPath, StringComparison.OrdinalIgnoreCase);
        if (at < 0) return null;
        return CleanTag(Uri.UnescapeDataString(target.AbsolutePath[(at + TagPath.Length)..]).TrimEnd('/')) is { } version
            ? new LatestRelease(version, page) : null;
    }

    // "v1.0.1" → "1.0.1", null when empty. Shown in the sidebar pill only when it parses as a version anyway; capped and
    // cleaned, as it is the server's text.
    private static string? CleanTag(string tag)
    {
        string clean = RemoteText.Clean(tag.TrimStart('v', 'V').Trim(), 40);
        return clean.Length == 0 ? null : clean;
    }

    // The pill opens this page: only ever a release page on github.com (a source's own answer, but a link handed to the
    // browser is checked like one).
    private static string? ReleasePage(string? url)
        => Uri.TryCreate(url, UriKind.Absolute, out var link) && link.Scheme == Uri.UriSchemeHttps
           && link.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase)
            ? link.AbsoluteUri : null;

    [RelayCommand]
    private void OpenGitHub() => OpenUrl("https://github.com/SinaXhpm/Echoes");

    // Light / dark, live (sidebar footer on desktop, the drawer on phones).
    [RelayCommand]
    private void ToggleTheme() => Helpers.ThemeService.Toggle();

    [RelayCommand]
    private void OpenReleases() => OpenUrl(LatestReleaseUrl);

    private static void OpenUrl(string url) => Helpers.LinkHelper.Open(url);
}