using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Globalization;

namespace Echoes.ViewModels;

// The options flyout: packet size, interval, count, timeout, TTL, Don't fragment, IP version, and TCP mode's port.
// Each change is clamped, saved (the profile writes behind, off the UI thread) and swapped in as one immutable
// PingSettings, which a running loop reads before every probe — so size / DF / TTL / interval / count / timeout apply to
// the next probe. The IP version and the port pick the address, so they wait for the next Start (locked while running).
public partial class PingViewModel
{
    private volatile PingSettings _settings = PingSettings.Default;
    private bool _loadingSettings;

    /// <summary>The settings the next probe uses.</summary>
    public PingSettings Settings => _settings;

    [ObservableProperty] private int _payloadSize = PingSettings.DefaultSize;
    [ObservableProperty] private decimal _intervalSec = PingSettings.DefaultIntervalMs / 1000m;
    /// <summary>null (an empty box, or 0) = until stopped.</summary>
    [ObservableProperty] private decimal? _countValue;
    [ObservableProperty] private decimal _timeoutSec = PingSettings.DefaultTimeoutMs / 1000m;
    /// <summary>null (an empty box) = the system's default TTL.</summary>
    [ObservableProperty] private decimal? _ttlValue;
    [ObservableProperty] private bool _dontFragment;
    /// <summary>0 Auto, 1 IPv4, 2 IPv6.</summary>
    [ObservableProperty] private int _ipVersionIndex;

    /// <summary>TCP mode's port (a text box, so a pasted "host:port" can fill it — see InputAssist.PortTarget).</summary>
    [ObservableProperty] private string _tcpPortText = PingSettings.DefaultTcpPort.ToString(CultureInfo.InvariantCulture);

    /// <summary>The non-default values for the button beside "Copy" ("1472 B · DF"); empty = all default.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasOptionsSummary))]
    private string _optionsSummary = string.Empty;

    public bool HasOptionsSummary => OptionsSummary.Length > 0;

    /// <summary>The options button's tooltip: what it holds, then the current non-default values.</summary>
    public string OptionsTip => (IsTcpMode ? "Interval, count, timeout and IP version" : "Packet size, interval, count, timeout, TTL, Don't fragment and IP version")
                                + (HasOptionsSummary ? ". Now: " + OptionsSummary : ". All at their defaults.");

    /// <summary>The system ping can't send a custom size here (no raw-socket rights, macOS / some Linux): learned from
    /// the first probe that tried, the size box is then disabled with the reason in its tooltip.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SizeTip))]
    private bool _sizeLocked = IcmpPinger.CustomSizeUnavailable;

    public string SizeTip => SizeLocked
        ? "This system's ping sends only 32 bytes without raw-socket rights (it uses the ping program)"
        : "Data bytes per ping (0-65500); the packet is 28 more (IPv4). With Don't fragment, the largest size that gets replies + 28 is the path MTU (1472 = 1500)";

    private void LoadSettings()
    {
        var ps = ProfileService.Instance;
        var s = PingSettings.Load(ps);
        _loadingSettings = true;
        try
        {
            PayloadSize = s.Size;
            IntervalSec = s.IntervalMs / 1000m;
            CountValue = s.Count > 0 ? s.Count : null;
            TimeoutSec = s.TimeoutMs / 1000m;
            TtlValue = s.Ttl > 0 ? s.Ttl : null;
            DontFragment = s.DontFragment;
            IpVersionIndex = (int)s.Ip;
            if (ps.GetSetting(PingSettings.KeyTcpPort) is { } port && TryPort(port, out int p)) TcpPortText = p.ToString(CultureInfo.InvariantCulture);
        }
        finally { _loadingSettings = false; }
        _settings = s;
        RefreshSummary();
    }

    partial void OnPayloadSizeChanged(int value) => ApplySettings();
    partial void OnIntervalSecChanged(decimal value) => ApplySettings();
    partial void OnCountValueChanged(decimal? value)
    {
        if (value is decimal v && v <= 0) { CountValue = null; return; }   // 0 = until stopped: the box shows its "∞"
        ApplySettings();
    }
    partial void OnTimeoutSecChanged(decimal value) => ApplySettings();
    partial void OnTtlValueChanged(decimal? value) => ApplySettings();
    partial void OnDontFragmentChanged(bool value) => ApplySettings();
    partial void OnIpVersionIndexChanged(int oldValue, int newValue)
    {
        if (newValue is >= 0 and <= 2)
        {
            ApplySettings();
            return;
        }
        // The selector in the options flyout loses its selection while the flyout is closed and pushes -1 when it
        // opens again: the choice stays (re-selected right after), and nothing is saved.
        int keep = oldValue is >= 0 and <= 2 ? oldValue : (int)_settings.Ip;
        Avalonia.Threading.Dispatcher.UIThread.Post(() => { if (IpVersionIndex is < 0 or > 2) IpVersionIndex = keep; });
    }

    partial void OnTcpPortTextChanged(string value)
    {
        if (_loadingSettings || !TryPort(value, out int p)) return;
        string text = p.ToString(CultureInfo.InvariantCulture);
        if (ProfileService.Instance.GetSetting(PingSettings.KeyTcpPort) != text) ProfileService.Instance.SetSetting(PingSettings.KeyTcpPort, text);
    }

    private void ApplySettings()
    {
        if (_loadingSettings) return;
        var s = new PingSettings
        {
            Size = PayloadSize,
            IntervalMs = (int)Math.Round(IntervalSec * 1000m),
            Count = CountValue is decimal c ? (int)Math.Min(Math.Round(c), PingSettings.MaxCount) : 0,
            TimeoutMs = (int)Math.Round(TimeoutSec * 1000m),
            Ttl = TtlValue is decimal t ? (int)Math.Round(t) : 0,
            DontFragment = DontFragment,
            Ip = (IpPreference)Math.Clamp(IpVersionIndex, 0, 2),
        }.Clamped();
        _settings = s;
        s.Save(ProfileService.Instance);
        RefreshSummary();
    }

    private void RefreshSummary()
    {
        OptionsSummary = _settings.Summary(IsTcpMode);
        OnPropertyChanged(nameof(OptionsTip));
    }

    /// <summary>Every option back to its default (the port stays).</summary>
    [RelayCommand]
    private void ResetOptions()
    {
        _loadingSettings = true;
        try
        {
            PayloadSize = PingSettings.DefaultSize;
            IntervalSec = PingSettings.DefaultIntervalMs / 1000m;
            CountValue = null;
            TimeoutSec = PingSettings.DefaultTimeoutMs / 1000m;
            TtlValue = null;
            DontFragment = false;
            if (!IsPinging) IpVersionIndex = 0;   // picks the address: only between runs
        }
        finally { _loadingSettings = false; }
        ApplySettings();
    }

    private static bool TryPort(string? text, out int port)
        => int.TryParse(text?.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out port) && port is >= 1 and <= 65535;
}
