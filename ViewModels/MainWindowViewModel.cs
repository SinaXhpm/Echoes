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
    [ObservableProperty] private PingViewModel _pingVM = new();
    [ObservableProperty] private DnsViewModel _dnsVM = new();
    [ObservableProperty] private CurlViewModel _curlVM = new();
    [ObservableProperty] private PortScannerViewModel _portScannerVM = new();
    [ObservableProperty] private IpInfoViewModel _ipInfoVM = new();
    [ObservableProperty] private SshViewModel _sshVM = new();
    [ObservableProperty] private StringLabViewModel _stringTool = new();
    [ObservableProperty] private MonitorViewModel _monitorVM = new();
    [ObservableProperty] private NetworkInfoViewModel _networkVM = new();
    [ObservableProperty] private string _currentVersion = "0.2.0";
    [ObservableProperty] private string _latestVersion = "0.1.0";
    [ObservableProperty] private bool _isUpdateAvailable;
    public static bool IsMac => RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
    public MainViewModel()
    {
        _ = CheckForUpdatesAsync();
    }

    private async Task CheckForUpdatesAsync()
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