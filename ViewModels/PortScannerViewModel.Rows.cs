using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>A line of the results list: a host header, or one of its ports beneath it.</summary>
public abstract class ScanRow : ObservableObject
{
    protected ScanRow(ScanHost host) => Host = host;

    public ScanHost Host { get; }

    /// <summary>Case-insensitive match against everything the row shows.</summary>
    internal abstract bool Matches(string filter);

    /// <summary>Re-read every displayed property (the engine updated the underlying host / finding).</summary>
    internal void Refresh() => OnPropertyChanged(string.Empty);

    protected static bool Has(string? s, string filter) => s is { Length: > 0 } && s.Contains(filter, StringComparison.OrdinalIgnoreCase);
}

/// <summary>The header above a host's ports: address, names, MAC / maker, latency and its port counts.</summary>
public sealed partial class ScanHostRow : ScanRow
{
    public ScanHostRow(ScanHost host) : base(host) { }

    public ScanChange Change { get; internal set; }

    public string Address => Host.Ip;

    /// <summary>The typed name, else the PTR name.</summary>
    public string Name => Host.Name ?? Host.ReverseName ?? "";
    public bool HasName => Name.Length > 0;
    public bool HasMac => !string.IsNullOrEmpty(Host.Mac);

    /// <summary>"rDNS mail.example.com · A8:5E:45:BB:13:7D (ASUS) · 0.4 ms"</summary>
    public string Meta
    {
        get
        {
            var parts = new List<string>(3);
            if (Host.Name is not null && Host.ReverseName is { Length: > 0 } rev && !string.Equals(rev, Host.Name, StringComparison.OrdinalIgnoreCase))
                parts.Add("rDNS " + rev);
            if (Host.Mac is { Length: > 0 } mac) parts.Add(Host.Vendor is { Length: > 0 } v ? $"{mac} ({v})" : mac);
            string lat = ScanText.Latency(Host.LatencyMs);
            if (lat.Length > 0) parts.Add(lat);
            return string.Join("  ·  ", parts);
        }
    }

    /// <summary>"3 open · 95 closed · 2 filtered", or the host state for a ping scan / a silent host.</summary>
    public string Counts
    {
        get
        {
            var parts = new List<string>(4);
            void Add(PortState s, string label)
            {
                int n = Host.Count(s);
                if (n > 0) parts.Add($"{n:N0} {label}");
            }
            Add(PortState.Open, "open");
            Add(PortState.OpenFiltered, "open|filtered");
            Add(PortState.Filtered, "filtered");
            Add(PortState.Closed, "closed");
            Add(PortState.Unknown, "unknown");
            if (parts.Count > 0) return string.Join(" · ", parts);
            return Host.Status switch
            {
                HostStatus.Up => Host.Reason.Length > 0 ? $"up · {Host.Reason}" : "up",
                HostStatus.Down => "no response",
                _ => Host.Reason == "socket-limit" ? "undetermined (out of sockets)" : "",
            };
        }
    }

    /// <summary>Why this host's results can't be taken at face value ("" when they can).</summary>
    public string Warning
    {
        get
        {
            if (Host.AcceptsAll) return "Answers every TCP port (SYN proxy / tarpit) — its open TCP ports aren't real and aren't listed.";
            if (Host.LocalAnswerPorts.Length > 0)
                return $"Port {Host.LocalAnswerPorts} answered faster than the host itself can — a local proxy, VPN or antivirus "
                       + "completed the connection; it may not really be open.";
            return "";
        }
    }

    public string ChangeText => Change switch { ScanChange.New => "came up", ScanChange.Gone => "went down", _ => "" };
    public bool HasChange => Change != ScanChange.None;

    internal override bool Matches(string f) =>
        Has(Host.Ip, f) || Has(Host.Name, f) || Has(Host.ReverseName, f) || Has(Host.Mac, f) || Has(Host.Vendor, f);

    [RelayCommand] private Task CopyAddress() => ClipboardHelper.SetTextAsync(Host.Ip);
    [RelayCommand] private Task CopyName() => ClipboardHelper.SetTextAsync(Name);
    [RelayCommand] private Task CopyMac() => ClipboardHelper.SetTextAsync(Host.Mac);
}

/// <summary>One port of a host.</summary>
public sealed partial class ScanPortRow : ScanRow
{
    public ScanPortRow(PortFinding finding) : base(finding.Host) => Finding = finding;

    public PortFinding Finding { get; private set; }

    internal void Update(PortFinding f)
    {
        Finding = f;
        Refresh();
    }

    public string PortLabel => Finding.PortLabel;
    public string StateText => ScanText.State(Finding.State);

    public string Service => Finding.Service;
    public string Version => Finding.Version;
    public string Detail => Finding.Detail;
    public string Reason => Finding.Reason;
    public string LatencyText => ScanText.Latency(Finding.LatencyMs);
    public bool HasVersion => Version.Length > 0;
    public bool HasDetail => Detail.Length > 0;

    /// <summary>The details' warning when a proxy, VPN or security product answered in the server's place ("" otherwise).</summary>
    public string Note => Finding.Interceptor.Length > 0 ? $"Answered by {Finding.Interceptor} — the server's own reply is hidden"
        : Finding.AnsweredFast ? "Answered locally — a proxy, VPN or antivirus completed this connection" : "";
    public bool HasNote => Note.Length > 0;

    public string ChangeText => Finding.Change switch { ScanChange.New => "new", ScanChange.Gone => "was open", _ => "" };
    public bool HasChange => Finding.Change != ScanChange.None;

    [ObservableProperty] private bool _isExpanded;

    [RelayCommand] private void ToggleExpand() => IsExpanded = !IsExpanded;

    // "10.0.0.5:22", "[2001:db8::1]:443"
    public string Endpoint => Host.Address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{Host.Ip}]:{Finding.Port}" : $"{Host.Ip}:{Finding.Port}";

    public bool IsWeb => Finding.State == PortState.Open && Finding.Proto == ScanProto.Tcp
                         && (Service is "http" or "https" or "ssl/http" or "http-proxy" or "http-alt" or "https-alt");

    [RelayCommand] private Task CopyEndpoint() => ClipboardHelper.SetTextAsync(Endpoint);

    [RelayCommand]
    private Task CopyRow() => ClipboardHelper.SetTextAsync(string.Join("\t", new[]
    {
        Host.Ip, PortLabel, StateText, Service, Version, Detail, Reason,
    }).TrimEnd('\t'));

    [RelayCommand]
    private void OpenInBrowser()
    {
        string scheme = Service.Contains("https", StringComparison.Ordinal) || Service.StartsWith("ssl/", StringComparison.Ordinal) ? "https" : "http";
        string host = Host.Name ?? (Host.Address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{Host.Ip}]" : Host.Ip);
        bool defaultPort = (scheme == "http" && Finding.Port == 80) || (scheme == "https" && Finding.Port == 443);
        LinkHelper.Open(defaultPort ? $"{scheme}://{host}/" : $"{scheme}://{host}:{Finding.Port}/");
    }

    internal override bool Matches(string f) =>
        PortLabel.StartsWith(f, StringComparison.OrdinalIgnoreCase) || Has(StateText, f) || Has(Service, f)
        || Has(Version, f) || Has(Detail, f) || Has(ChangeText, f);
}

/// <summary>Hosts in numeric order, each header above its ports; ports ordered by the chosen column.</summary>
internal sealed class ScanRowOrder : IComparer<ScanRow>
{
    public string Column = "Port";
    public bool Descending;

    public int Compare(ScanRow? a, ScanRow? b)
    {
        if (ReferenceEquals(a, b)) return 0;
        if (a is null) return -1;
        if (b is null) return 1;
        int c = ReferenceEquals(a.Host, b.Host) ? 0 : IpAddressComparer.Instance.Compare(a.Host.Address, b.Host.Address);
        if (c != 0) return c;
        if (a is ScanHostRow) return b is ScanHostRow ? 0 : -1;
        if (b is ScanHostRow) return 1;
        var x = ((ScanPortRow)a).Finding;
        var y = ((ScanPortRow)b).Finding;
        c = Column switch
        {
            "State" => x.State.CompareTo(y.State),
            "Service" => string.Compare(x.Service, y.Service, StringComparison.OrdinalIgnoreCase),
            _ => 0,
        };
        if (c == 0) c = x.Port.CompareTo(y.Port);
        if (c == 0) c = x.Proto.CompareTo(y.Proto);
        return Descending ? -c : c;
    }
}
