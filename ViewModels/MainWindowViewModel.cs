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

    // Flush debounced persistence on shutdown so a just-typed edit is never lost on close.
    public void FlushOnExit() => _cloudflareVM?.FlushPendingSave();

    [ObservableProperty] private string _currentVersion;
    [ObservableProperty] private string _latestVersion;
    [ObservableProperty] private bool _isUpdateAvailable;
    [ObservableProperty] private string _latestReleaseUrl = "https://github.com/SinaXhpm/Echoes/releases";
    public static bool IsMac => RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
    public MainViewModel()
    {
        var assemblyVersion = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
        _currentVersion = $"{assemblyVersion?.Major}.{assemblyVersion?.Minor}.{assemblyVersion?.Build}";
        _latestVersion = _currentVersion;
    }

    // Uses the GitHub Releases API (the latest published release) as the single source
    // of truth — no hand-maintained version.json to keep in sync.
    public async Task CheckForUpdatesAsync()
    {
        try
        {
            using var client = HttpHelper.Create(timeout: TimeSpan.FromSeconds(10));
            client.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");

            var json = await client.GetStringAsync("https://api.github.com/repos/SinaXhpm/Echoes/releases/latest");
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            string tag = root.TryGetProperty("tag_name", out var t) ? t.GetString() ?? string.Empty : string.Empty;
            if (string.IsNullOrWhiteSpace(tag)) return;

            if (root.TryGetProperty("html_url", out var u) && u.GetString() is { Length: > 0 } htmlUrl)
                LatestReleaseUrl = htmlUrl;

            string clean = tag.TrimStart('v', 'V').Trim();
            LatestVersion = clean;

            if (Version.TryParse(clean, out var latest) && Version.TryParse(CurrentVersion, out var current))
                IsUpdateAvailable = latest > current;
        }
        catch
        {
        }
    }

    [RelayCommand]
    private void OpenGitHub() => OpenUrl("https://github.com/SinaXhpm/Echoes");

    [RelayCommand]
    private void OpenReleases() => OpenUrl(LatestReleaseUrl);

    private static void OpenUrl(string url)
    {
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                Process.Start("xdg-open", url);
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                Process.Start("open", url);
        }
        catch
        {
        }
    }
}