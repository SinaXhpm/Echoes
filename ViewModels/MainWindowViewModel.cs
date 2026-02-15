using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using System;
using System.Diagnostics;
using System.Net.Http;
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

    public PingViewModel PingVM => _pingVM ??= new();
    public DnsViewModel DnsVM => _dnsVM ??= new();
    public CurlViewModel CurlVM => _curlVM ??= new();
    public PortScannerViewModel PortScannerVM => _portScannerVM ??= new();
    public IpInfoViewModel IpInfoVM => _ipInfoVM ??= new();
    public SshViewModel SshVM => _sshVM ??= new();
    public StringLabViewModel StringTool => _stringTool ??= new();
    public MonitorViewModel MonitorVM => _monitorVM ??= new();
    public NetworkInfoViewModel NetworkVM => _networkVM ??= new();

    [ObservableProperty] private string _currentVersion;
    [ObservableProperty] private string _latestVersion;
    [ObservableProperty] private bool _isUpdateAvailable;
    public static bool IsMac => RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
    public MainViewModel()
    {
        var assemblyVersion = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
        _currentVersion = $"{assemblyVersion?.Major}.{assemblyVersion?.Minor}.{assemblyVersion?.Build}";
        _latestVersion = _currentVersion;
    }

    public async Task CheckForUpdatesAsync()
    {
        try
        {
            using var client = new HttpClient();

            var url = "https://raw.githubusercontent.com/SinaXhpm/Echoes/refs/heads/master/version.json";
            var response = await client.GetStringAsync(url);
            var data = JsonSerializer.Deserialize<VersionData>(response);

            if (data != null)
            {

                LatestVersion = data.version;

                var current = new Version(CurrentVersion);
                var latest = new Version(LatestVersion);

                if (latest > current)
                {
                    IsUpdateAvailable = true;
                }
            }
        }
        catch
        {
        }
    }
    [RelayCommand]
    private void OpenGitHub()
    {
        string url = "https://github.com/SinaXhpm/Echoes";

        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                Process.Start("xdg-open", url);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                Process.Start("open", url);
            }
        }
        catch
        {

        }
    }
}

public class VersionData
{
    public string version { get; set; } = string.Empty;
}