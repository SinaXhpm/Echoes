using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

/// <summary>One line of the Devices table: a device a search found, or an entry of the system's ARP cache.</summary>
public sealed partial class DeviceRow : ObservableObject
{
    public DeviceRow(string ip)
    {
        Ip = ip;
        Order = IPAddress.TryParse(ip, out var a) && a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
            ? BitConverter.ToUInt32(a.GetAddressBytes().Reverse().ToArray(), 0) : uint.MaxValue;
    }

    public string Ip { get; }
    /// <summary>The address as a number: the table is kept in address order (IPv6 entries last).</summary>
    public uint Order { get; }

    [ObservableProperty] private string _mac = string.Empty;
    [ObservableProperty] private string _maker = string.Empty;
    /// <summary>Its name; with none, what it said about itself (a UPnP server line, a service).</summary>
    [ObservableProperty] private string _name = string.Empty;
    [ObservableProperty] private bool _nameIsDetail;
    [ObservableProperty] private string _foundBy = string.Empty;
    /// <summary>"this device" / "gateway", beside the address.</summary>
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasRole))] private string _role = string.Empty;
    [ObservableProperty] private string _tip = string.Empty;
    /// <summary>A cached entry that didn't answer this search: it was there not long ago.</summary>
    [ObservableProperty] private bool _isStale;

    public bool HasRole => Role.Length > 0;

    public void Update(LanDevice d)
    {
        Mac = d.Mac;
        Maker = d.Vendor;
        Name = d.Name.Length > 0 ? d.Name : d.Details;
        NameIsDetail = d.Name.Length == 0 && d.Details.Length > 0;
        FoundBy = d.FoundBy;
        Role = d.IsThisDevice ? "this device" : d.IsGateway ? "gateway" : string.Empty;
        IsStale = !d.Answered;
        var tip = new List<string>(4);
        if (d.Name.Length > 0) tip.Add($"{d.Name} (its name by {d.NameSource})");
        if (d.Details.Length > 0) tip.Add(d.Details);
        if (d.Vendor.Length > 0) tip.Add(d.Vendor == "Private address" ? "A private (randomised) MAC address: phones and laptops use one per network" : "Maker of its network adapter: " + d.Vendor);
        tip.Add(d.Answered ? "Found by " + d.FoundBy : "In the ARP cache, but it didn't answer this search");
        Tip = string.Join("\n", tip);
    }

    /// <summary>One line of the copied table.</summary>
    public string Line => $"{Ip,-15}  {Mac,-17}  {Maker,-22}  {(Name.Length > 0 ? Name : "-"),-28}  {FoundBy}{(HasRole ? "  (" + Role + ")" : string.Empty)}";
}

// The Devices tab (it was "Neighbors"): the system's ARP cache as before, and a search of one interface's network
// (LanDiscovery: an ARP sweep, mDNS, SSDP, and names by reverse DNS, NetBIOS and LLMNR). The interface picker chooses
// whose cache is listed and where a search looks.
public partial class NetworkInfoViewModel
{
    /// <summary>The interface whose neighbors are listed and whose network a search covers. "All interfaces": the
    /// whole cache, and a search of the first wired / Wi-Fi interface.</summary>
    public IfacePicker DeviceIface { get; } = new(ProfileService.Instance, "net.devices.iface", "All interfaces",
                                                  "Every interface's ARP cache. Find devices searches the first Ethernet / Wi-Fi network");

    public ObservableCollection<DeviceRow> Devices { get; } = new();

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(FindDevicesText))] private bool _isFindingDevices;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasDevicesStatus))] private string _devicesStatus = string.Empty;
    [ObservableProperty] private bool _devicesStatusIsError;

    public bool HasDevicesStatus => DevicesStatus.Length > 0;
    public bool CanFindDevices => LanDiscovery.IsAvailable;
    public string FindDevicesText => IsFindingDevices ? "Stop" : "Find devices";

    private CancellationTokenSource? _findCts;
    private int _findRun;
    private readonly Dictionary<string, DeviceRow> _deviceRows = new(StringComparer.Ordinal);

    private void WatchDeviceIface() => DeviceIface.Changed += () => { if (!IsFindingDevices) _ = RefreshNeighbors(); };

    // The ARP cache as rows: every interface's, or the chosen one's.
    private void ShowCache(NetResult<Neighbor> cache)
    {
        string? only = DeviceIface.Name;
        _deviceRows.Clear();
        Devices.Clear();
        foreach (var n in cache.Rows)
        {
            if (only is not null && !string.Equals(n.Iface, only, StringComparison.Ordinal)) continue;
            // the cache also maps the broadcast and multicast groups (ff:ff:…, 01:00:5e:…): not devices
            if (!ScanOui.IsHostMac(n.Mac)) continue;
            var row = new DeviceRow(n.Ip)
            {
                Mac = n.Mac,
                Maker = ScanOui.Vendor(n.Mac),
                FoundBy = "ARP cache",
                Tip = $"In the ARP cache of {n.Iface} ({n.Kind})",
            };
            Devices.Add(row);
        }
        NeighborsHasRows = cache.Supported && Devices.Count > 0;
        NeighborsNote = !cache.Supported
            ? (cache.Note ?? "Not available on this platform.")
            : only is null ? "No devices in the ARP cache yet. Find devices searches the network."
            : $"No devices in the ARP cache of {only} yet. Find devices searches its network.";
        DevicesStatus = string.Empty;
        DevicesStatusIsError = false;
    }

    /// <summary>Starts a search of the chosen interface's network, or stops the one that runs.</summary>
    [RelayCommand]
    private async Task FindDevices()
    {
        if (IsFindingDevices)
        {
            _findCts?.Cancel();
            return;
        }

        // The interface as it is now: the chosen one, or (All interfaces) the first with an IPv4 network, which the
        // list puts first when it is wired or Wi-Fi.
        NetIface? iface;
        if (DeviceIface.Name is { } chosen)
        {
            iface = DeviceIface.Resolve();
            if (iface is null) { SetDevicesError($"{chosen} isn't connected: choose another interface."); return; }
        }
        else
        {
            iface = await Task.Run(() => NetIfaces.Up().FirstOrDefault(i => i.V4 is not null && i.Prefix4 is > 0 and <= 30));
            if (iface is null) { SetDevicesError("No connected interface has an IPv4 network to search."); return; }
        }

        int run = ++_findRun;
        _findCts?.Dispose();
        var cts = _findCts = new CancellationTokenSource();
        _deviceRows.Clear();
        Devices.Clear();
        NeighborsHasRows = true;   // the table shows from the first device on (this device itself, at once)
        IsFindingDevices = true;
        DevicesStatusIsError = false;
        string where = iface.Subnet4(LanDiscovery.MaxAddresses, out _) is { } net ? $"{net.Network}/{net.Prefix} on {iface.Name}" : iface.Name;
        DevicesStatus = $"Searching {where}…";
        BackgroundGuard.Acquire("Finding devices", GuardKind.Finite);
        try
        {
            var result = await Task.Run(() => LanDiscovery.RunAsync(iface, d => Dispatcher.UIThread.Post(() => OnDevice(run, d)), cts.Token));
            if (run != _findRun) return;
            // the last updates were posted before this continuation: they are in the table now
            int n = Devices.Count;
            DevicesStatus = (cts.IsCancellationRequested ? "Stopped: " : string.Empty)
                            + $"{n} device{(n == 1 ? string.Empty : "s")} on {iface.Name} ({result.Network}), "
                            + $"{result.Addresses:N0} addresses searched in {result.Elapsed.TotalSeconds.ToString("0.0", CultureInfo.InvariantCulture)} s"
                            + (result.WholeSubnet ? "." : $". The network is bigger: only the {result.Addresses:N0} addresses around this device were searched.")
                            // (cloud networks, hotspots that keep their clients apart: every address "is at" the router)
                            + (result.ProxyAnswers > 0 ? $" A router here answers for every address (proxy ARP): its {result.ProxyAnswers:N0} answers aren't listed as devices." : string.Empty);
        }
        catch (NetIfaceException ex)
        {
            if (run == _findRun) SetDevicesError(ex.Message);
        }
        catch (OperationCanceledException)
        {
            if (run == _findRun) DevicesStatus = "Stopped.";
        }
        catch (Exception ex)
        {
            if (run == _findRun) SetDevicesError("The search failed: " + ex.Message);
        }
        finally
        {
            BackgroundGuard.Release("Finding devices");
            if (run == _findRun)
            {
                IsFindingDevices = false;
                NeighborsHasRows = Devices.Count > 0;
            }
        }
    }

    private void SetDevicesError(string message)
    {
        DevicesStatus = message;
        DevicesStatusIsError = true;
    }

    // UI thread: a device was found, or learned a name.
    private void OnDevice(int run, LanDevice d)
    {
        if (run != _findRun) return;
        if (d.Withdrawn)
        {
            // it was listed and isn't a device after all (a router answered for it)
            if (_deviceRows.Remove(d.Ip, out var gone)) Devices.Remove(gone);
            if (IsFindingDevices) DevicesStatus = DevicesStatus.Split('…')[0] + $"… {Devices.Count} found";
            return;
        }
        if (!_deviceRows.TryGetValue(d.Ip, out var row))
        {
            row = new DeviceRow(d.Ip);
            _deviceRows[d.Ip] = row;
            int at = 0;
            while (at < Devices.Count && Devices[at].Order <= row.Order) at++;   // in address order
            Devices.Insert(at, row);
        }
        row.Update(d);
        if (IsFindingDevices) DevicesStatus = DevicesStatus.Split('…')[0] + $"… {Devices.Count} found";
    }

    /// <summary>The table as text.</summary>
    [RelayCommand]
    private async Task CopyDevices()
    {
        if (Devices.Count == 0) return;
        var sb = new StringBuilder(Devices.Count * 96);
        sb.AppendLine($"{"IP address",-15}  {"MAC",-17}  {"Maker",-22}  {"Name",-28}  Found by");
        foreach (var row in Devices) sb.AppendLine(row.Line);
        if (HasDevicesStatus && !DevicesStatusIsError) sb.AppendLine().AppendLine(DevicesStatus);
        await ClipboardHelper.SetTextAsync(sb.ToString());
    }
}
