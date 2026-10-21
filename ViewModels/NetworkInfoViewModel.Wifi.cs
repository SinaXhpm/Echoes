using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

/// <summary>
/// The Network tool's Wi-Fi view: the current connection, the access points around (sortable, virtualized) and a
/// channel usage chart per band with one recommendation line. Reads happen off the UI thread, only while the view is
/// on screen: when it appears (with a fresh scan), every 10 s after that, and on Refresh. Nothing runs while the tab
/// or the tool is hidden.
/// </summary>
public partial class NetworkInfoViewModel
{
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    /// <summary>Tests / screenshots: replace the platform reader (argument: request a fresh scan).</summary>
    internal Func<bool, WifiScanResult> WifiSource { get; set; } = WifiScanner.Read;

    /// <summary>How long after asking Windows for a scan its results are read again.</summary>
    internal TimeSpan WifiScanSettle { get; set; } = TimeSpan.FromSeconds(4);

    internal static readonly TimeSpan WifiInterval = TimeSpan.FromSeconds(10);

    private DispatcherTimer? _wifiTimer;
    private Func<bool>? _wifiVisible;
    private bool _wifiReading;
    private bool _wifiBandPicked;
    private WifiScanResult? _wifiLast;
    private List<WifiNetwork> _wifiAll = new();

    // ---- state of the view ----
    [ObservableProperty] private bool _wifiLoaded;
    [ObservableProperty] private bool _wifiBusy;
    [ObservableProperty] private bool _wifiSupported = true;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasWifiNote))] private string? _wifiNote;
    [ObservableProperty] private bool _wifiNoteIsLocation;
    [ObservableProperty] private bool _wifiShowConnection;
    [ObservableProperty] private bool _wifiShowData;
    [ObservableProperty] private string _wifiUpdated = "";
    [ObservableProperty] private bool _wifiShowEmpty = true;
    [ObservableProperty] private string _wifiEmptyText = "Reading Wi-Fi…";
    public bool HasWifiNote => !string.IsNullOrEmpty(WifiNote);
    public bool CanOpenLocationSettings => OperatingSystem.IsWindows();

    // ---- the current connection ----
    [ObservableProperty] private bool _wifiConnected;
    [ObservableProperty] private string _wifiSsid = "Not connected";
    [ObservableProperty] private string _wifiBandText = "";
    [ObservableProperty] private string _wifiChannelText = "";
    [ObservableProperty] private string _wifiSecurityText = "";
    [ObservableProperty] private string _wifiStandardText = "";
    [ObservableProperty] private string _wifiSignalText = "—";
    [ObservableProperty] private double _wifiSignalBar;
    [ObservableProperty] private bool _wifiSignalGood;
    [ObservableProperty] private bool _wifiSignalFair;
    [ObservableProperty] private bool _wifiSignalWeak;
    [ObservableProperty] private string _wifiRateText = "—";
    [ObservableProperty] private string _wifiBssidText = "—";
    [ObservableProperty] private string _wifiAdapterText = "—";
    public bool WifiHasBand => WifiBandText.Length > 0;
    public bool WifiHasChannel => WifiChannelText.Length > 0;
    public bool WifiHasSecurity => WifiSecurityText.Length > 0;
    public bool WifiHasStandard => WifiStandardText.Length > 0;
    partial void OnWifiBandTextChanged(string value) => OnPropertyChanged(nameof(WifiHasBand));
    partial void OnWifiChannelTextChanged(string value) => OnPropertyChanged(nameof(WifiHasChannel));
    partial void OnWifiSecurityTextChanged(string value) => OnPropertyChanged(nameof(WifiHasSecurity));
    partial void OnWifiStandardTextChanged(string value) => OnPropertyChanged(nameof(WifiHasStandard));

    // ---- nearby networks ----
    [ObservableProperty] private ObservableCollection<WifiNetwork> _wifiNetworks = new();
    [ObservableProperty] private bool _wifiHasRows;
    [ObservableProperty] private string _wifiListNote = "Looking for networks…";
    [ObservableProperty] private string _wifiSortKey = "signal";
    [ObservableProperty] private bool _wifiSortDesc = true;
    public string SortMarkSsid => Mark("ssid");
    public string SortMarkBssid => Mark("bssid");
    public string SortMarkChannel => Mark("channel");
    public string SortMarkBand => Mark("band");
    public string SortMarkSignal => Mark("signal");
    public string SortMarkSecurity => Mark("security");
    private string Mark(string key) => WifiSortKey == key ? (WifiSortDesc ? " ▼" : " ▲") : "";

    // ---- channel usage ----
    [ObservableProperty] private int _wifiBandIndex;   // 0 = 2.4 GHz, 1 = 5 GHz, 2 = 6 GHz
    [ObservableProperty] private List<WifiChannelBar> _wifiBars = new();
    [ObservableProperty] private string _wifiRecommendation = "";
    [ObservableProperty] private double _wifiChartMinWidth;
    [ObservableProperty] private string _wifiBand24Header = "2.4 GHz";
    [ObservableProperty] private string _wifiBand5Header = "5 GHz";
    [ObservableProperty] private string _wifiBand6Header = "6 GHz";

    private static WifiBand BandAt(int index) => index switch { 1 => WifiBand.Ghz5, 2 => WifiBand.Ghz6, _ => WifiBand.Ghz24 };
    private static int IndexOf(WifiBand band) => band switch { WifiBand.Ghz5 => 1, WifiBand.Ghz6 => 2, _ => 0 };

    // ---------------------------------------------------------------- visibility (from the view)

    /// <summary>The Wi-Fi view came on screen: read now (with a scan), then every 10 s while
    /// <paramref name="stillVisible"/> says it is shown.</summary>
    public void WifiShown(Func<bool> stillVisible)
    {
        _wifiVisible = stillVisible;
        if (_wifiTimer is null)
        {
            _wifiTimer = new DispatcherTimer { Interval = WifiInterval };
            _wifiTimer.Tick += (_, _) =>
            {
                if (_wifiVisible?.Invoke() == true) _ = WifiReadAsync(scan: ScanDue(WifiScanGap), followUp: false);
            };
        }
        _wifiTimer.Start();
        // a quick look back to the view: re-read unless the last read is very recent
        if (_wifiLast is null || DateTimeOffset.Now - _wifiLast.Time > TimeSpan.FromSeconds(5))
            _ = WifiReadAsync(scan: ScanDue(TimeSpan.FromSeconds(30)), followUp: true);
    }

    // An active scan takes the radio off its channel for a moment: with this tab open, Echoes' own pings and speed tests
    // showed it as latency spikes every 10 s. The 10 s ticks read the system's list (the OS keeps it fresh with its own
    // scans); Echoes asks for a scan of its own at most once a minute, and whenever Refresh is pressed.
    internal static readonly TimeSpan WifiScanGap = TimeSpan.FromSeconds(60);
    private long _wifiScanTick = long.MinValue / 2;   // Environment.TickCount64 of the last scan asked for (a clock step can't stall it)

    private bool ScanDue(TimeSpan gap) => Environment.TickCount64 - _wifiScanTick >= (long)gap.TotalMilliseconds;

    /// <summary>The view left the screen (another tab or tool): stop polling.</summary>
    public void WifiHidden()
    {
        _wifiTimer?.Stop();
        _wifiVisible = null;
    }

    [RelayCommand]
    private Task RefreshWifi() => WifiReadAsync(scan: true, followUp: true);

    private async Task WifiReadAsync(bool scan, bool followUp)
    {
        if (_wifiReading) return;
        _wifiReading = true;
        WifiBusy = true;
        if (scan) _wifiScanTick = Environment.TickCount64;
        try
        {
            var source = WifiSource;
            var r = await Task.Run(() => source(scan));
            ApplyWifi(r);
            // Windows scans in the background: the fresh results arrive a few seconds after the request
            if (scan && followUp && r.Supported && r.Note is null && OperatingSystem.IsWindows())
            {
                await Task.Delay(WifiScanSettle);
                if (_wifiVisible?.Invoke() == true)
                    ApplyWifi(await Task.Run(() => source(false)));
            }
        }
        catch (Exception ex)
        {
            ApplyWifi(WifiScanResult.Unsupported($"Couldn't read the Wi-Fi state: {ex.Message.TrimEnd('.')}."));
        }
        finally
        {
            _wifiReading = false;
            WifiBusy = false;
        }
    }

    // ---------------------------------------------------------------- apply a read

    internal void ApplyWifi(WifiScanResult r)
    {
        _wifiLast = r;
        WifiLoaded = true;
        WifiSupported = r.Supported;
        WifiNote = r.Note;
        WifiNoteIsLocation = r.NoteIsLocation;
        WifiShowConnection = r.Supported && (r.Current is not null || r.Note is null || r.NoteIsLocation);
        WifiShowData = r.Supported && (r.Note is null || (r.NoteIsLocation && r.Networks.Count > 0));
        WifiShowEmpty = !WifiShowData && !r.NoteIsLocation;
        WifiEmptyText = r.Note ?? "No Wi-Fi networks found nearby.";
        WifiUpdated = "Updated " + r.Time.ToLocalTime().ToString("HH:mm:ss", Inv);

        ShowConnection(r.Current);

        _wifiAll = r.Networks;
        ApplySort();
        WifiListNote = r.Networks.Count == 0 ? "No Wi-Fi networks found nearby." : "";

        int n24 = r.Networks.Count(n => n.Band == WifiBand.Ghz24), n5 = r.Networks.Count(n => n.Band == WifiBand.Ghz5),
            n6 = r.Networks.Count(n => n.Band == WifiBand.Ghz6);
        WifiBand24Header = n24 > 0 ? $"2.4 GHz · {n24}" : "2.4 GHz";
        WifiBand5Header = n5 > 0 ? $"5 GHz · {n5}" : "5 GHz";
        WifiBand6Header = n6 > 0 ? $"6 GHz · {n6}" : "6 GHz";

        if (!_wifiBandPicked)
        {
            int want = IndexOf(WifiAnalysis.DefaultBand(r.Current, r.Networks));
            if (want != WifiBandIndex)
            {
                _settingBand = true;
                WifiBandIndex = want;
                _settingBand = false;
            }
        }
        BuildChart();
    }

    private bool _settingBand;

    partial void OnWifiBandIndexChanged(int value)
    {
        if (!_settingBand) _wifiBandPicked = true;
        BuildChart();
    }

    private void BuildChart()
    {
        var band = BandAt(WifiBandIndex);
        var nets = _wifiAll;
        var current = _wifiLast?.Current;
        int mine = current is not null && current.Band == band ? current.Channel : 0;
        var bars = WifiAnalysis.Bars(band, nets, mine);
        WifiBars = bars;
        WifiChartMinWidth = bars.Count * (band == WifiBand.Ghz24 ? 30 : 24);
        WifiRecommendation = WifiAnalysis.Recommend(band, nets, current);
    }

    private void ShowConnection(WifiConnection? c)
    {
        WifiConnected = c is not null;
        if (c is null)
        {
            WifiSsid = "Not connected";
            WifiBandText = WifiChannelText = WifiSecurityText = WifiStandardText = "";
            WifiSignalText = WifiRateText = WifiBssidText = "—";
            WifiAdapterText = "—";
            WifiSignalBar = 0;
            WifiSignalGood = WifiSignalFair = WifiSignalWeak = false;
            return;
        }
        WifiSsid = c.SsidHidden ? "Connected (name hidden)" : c.Ssid.Length == 0 ? "(hidden network)" : c.Ssid;
        WifiBandText = c.Band == WifiBand.Unknown ? "" : WifiChannels.BandLabel(c.Band);
        WifiChannelText = c.Channel <= 0 ? "" : c.WidthMhz > 20 ? $"Channel {c.Channel} · {c.WidthMhz} MHz" : $"Channel {c.Channel}";
        WifiSecurityText = c.Security;
        WifiStandardText = c.Standard;
        int pct = c.SignalPercent;
        string dbm = c.RssiDbm < 0 ? (c.RssiEstimated ? $"≈ {c.RssiDbm} dBm" : $"{c.RssiDbm} dBm") : "";
        WifiSignalText = pct >= 0 ? (dbm.Length > 0 ? $"{pct}% · {dbm}" : $"{pct}%") : dbm.Length > 0 ? dbm : "—";
        WifiSignalBar = Math.Clamp(pct, 0, 100) * 0.44;   // the 44 px track
        WifiSignalGood = pct >= 60;
        WifiSignalFair = pct is >= 35 and < 60;
        WifiSignalWeak = pct is >= 0 and < 35;
        WifiRateText = RateText(c.RxMbps, c.TxMbps);
        WifiBssidText = c.Bssid.Length > 0 ? c.Bssid : "—";
        WifiAdapterText = c.Adapter.Length > 0 ? c.Adapter : "—";
    }

    private static string RateText(double rx, double tx)
    {
        static string F(double v) => v >= 100 ? v.ToString("0", Inv) : v.ToString("0.#", Inv);
        bool hasRx = !double.IsNaN(rx) && rx > 0, hasTx = !double.IsNaN(tx) && tx > 0;
        if (hasRx && hasTx)
            return Math.Abs(rx - tx) < 0.5 ? $"{F(rx)} Mbps" : $"↓ {F(rx)} · ↑ {F(tx)} Mbps";
        if (hasRx) return $"{F(rx)} Mbps";
        if (hasTx) return $"{F(tx)} Mbps";
        return "—";
    }

    // ---------------------------------------------------------------- sorting

    [RelayCommand]
    private void SortWifi(string? key)
    {
        if (string.IsNullOrEmpty(key)) return;
        if (WifiSortKey == key) WifiSortDesc = !WifiSortDesc;
        else
        {
            WifiSortKey = key;
            WifiSortDesc = key == "signal";   // strongest first; names / channels A→Z, low→high
        }
        ProfileService.Instance.SetSetting(WifiSortSetting, WifiSortKey + (WifiSortDesc ? ":desc" : ":asc"));
        ApplySort();
    }

    // The column the list was sorted by last ("signal:desc"), restored when the tool opens.
    private const string WifiSortSetting = "net.wifiSort";
    private static readonly string[] WifiSortKeys = { "ssid", "bssid", "channel", "band", "security", "signal" };

    private void RestoreWifiSort()
    {
        string[] parts = (ProfileService.Instance.GetSetting(WifiSortSetting) ?? string.Empty).Split(':');
        if (parts.Length != 2 || Array.IndexOf(WifiSortKeys, parts[0]) < 0) return;
        WifiSortKey = parts[0];
        WifiSortDesc = parts[1] == "desc";
    }

    private void ApplySort()
    {
        IEnumerable<WifiNetwork> q = _wifiAll;
        bool d = WifiSortDesc;
        q = WifiSortKey switch
        {
            "ssid" => Order(q, n => n.Hidden ? "￿" : n.Ssid.ToLowerInvariant(), d).ThenByDescending(n => n.SignalPercent),
            "bssid" => Order(q, n => n.Bssid, d),
            "channel" => Order(q, n => (int)n.Band * 1000 + n.Channel, d).ThenByDescending(n => n.SignalPercent),
            "band" => Order(q, n => (int)n.Band, d).ThenBy(n => n.Channel).ThenByDescending(n => n.SignalPercent),
            "security" => Order(q, n => n.Security, d).ThenByDescending(n => n.SignalPercent),
            _ => Order(q, n => n.RssiDbm < 0 ? n.RssiDbm + 1000 : n.SignalPercent * 10, d),
        };
        WifiNetworks = new ObservableCollection<WifiNetwork>(q);
        WifiHasRows = WifiNetworks.Count > 0;
        OnPropertyChanged(nameof(SortMarkSsid));
        OnPropertyChanged(nameof(SortMarkBssid));
        OnPropertyChanged(nameof(SortMarkChannel));
        OnPropertyChanged(nameof(SortMarkBand));
        OnPropertyChanged(nameof(SortMarkSignal));
        OnPropertyChanged(nameof(SortMarkSecurity));
    }

    private static IOrderedEnumerable<WifiNetwork> Order<TKey>(IEnumerable<WifiNetwork> q, Func<WifiNetwork, TKey> key, bool desc)
        => desc ? q.OrderByDescending(key, Comparer<TKey>.Default) : q.OrderBy(key, Comparer<TKey>.Default);

    // ---------------------------------------------------------------- location settings (Windows)

    [RelayCommand]
    private void OpenLocationSettings()
    {
        if (!OperatingSystem.IsWindows()) return;
        // a fixed ms-settings page, never a URL from anywhere else
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("ms-settings:privacy-location") { UseShellExecute = true })?.Dispose(); }
        catch { }
    }

    [RelayCommand]
    private async Task CopyWifi()
    {
        var c = _wifiLast?.Current;
        if (c is null) return;
        string text = $"{WifiSsid}\n{WifiBandText} {WifiChannelText}  {WifiSecurityText}  {WifiStandardText}\n" +
                      $"Signal: {WifiSignalText}   Link: {WifiRateText}\nBSSID: {WifiBssidText}\nAdapter: {WifiAdapterText}";
        await ClipboardHelper.SetTextAsync(text.Replace("  ", " ").Trim());
    }
}
