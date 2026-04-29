using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Input.Platform;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Echoes.ViewModels;

public class NetworkAdapterInfo
{
    public string Name { get; set; } = string.Empty;
    public string Model { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string IPv4 { get; set; } = string.Empty;
    public string MacAddress { get; set; } = string.Empty;
    public string Gateway { get; set; } = string.Empty;
}

public partial class NetworkInfoViewModel : ObservableObject
{
    [ObservableProperty]
    private ObservableCollection<NetworkAdapterInfo> _adapters = new();

    public NetworkInfoViewModel()
    {
        LoadNetworkData();
    }

    [RelayCommand]
    private void Refresh() => LoadNetworkData();

    [RelayCommand]
    private async Task CopyToClipboard(string text)
    {
        if (string.IsNullOrEmpty(text) || text == "---") return;

        var clipboard = Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop
                        ? desktop.MainWindow?.Clipboard
                        : null;

        if (clipboard != null)
        {
            await clipboard.SetTextAsync(text);
        }
    }

    private void LoadNetworkData()
    {
        Adapters.Clear();
        var interfaces = NetworkInterface.GetAllNetworkInterfaces();

        foreach (var ni in interfaces)
        {
            var props = ni.GetIPProperties();

            var v4 = props.UnicastAddresses
                .FirstOrDefault(x => x.Address.AddressFamily == AddressFamily.InterNetwork)?.Address.ToString() ?? "---";

            var gw = props.GatewayAddresses
                .FirstOrDefault()?.Address.ToString() ?? "---";

            var mac = ni.GetPhysicalAddress().ToString();
            if (mac.Length == 12)
                mac = string.Join(":", Enumerable.Range(0, 6).Select(i => mac.Substring(i * 2, 2)));

            Adapters.Add(new NetworkAdapterInfo
            {
                Name = ni.Name,
                Model = ni.Description,
                Status = ni.OperationalStatus.ToString(),
                IPv4 = v4,
                Gateway = gw,
                MacAddress = mac
            });
        }
    }
}