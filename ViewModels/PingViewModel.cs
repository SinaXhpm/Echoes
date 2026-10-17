using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;

namespace Echoes.ViewModels;

/// <summary>What the Ping tab runs: classic ping, a one-shot traceroute, MTR (every hop probed every second), or TCP
/// ping (a TCP connect to host:port every interval).</summary>
public enum PingMode { Ping = 0, Traceroute = 1, Mtr = 2, Tcp = 3 }

public partial class PingViewModel : ObservableObject
{
    [ObservableProperty] private string _targetHost = string.Empty;
    [ObservableProperty] private bool _isPinging;
    [ObservableProperty] private bool _notifyOnline;
    [ObservableProperty] private bool _notifyOffline;
    [ObservableProperty] private string _statsSummary = "Packets: Sent = 0, Received = 0, Lost = 0";

    /// <summary>The mode switch: 0 Ping, 1 Traceroute, 2 MTR, 3 TCP. Taken at Start (the switch is locked while a run
    /// goes on) and remembered for the next launch.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Mode), nameof(IsTraceRoute), nameof(IsPingMode), nameof(IsMtrMode), nameof(IsLogMode),
                              nameof(IsTcpMode), nameof(IsLoopMode), nameof(PortTargetName), nameof(HostPlaceholder), nameof(EmptyHint))]
    private int _modeIndex;

    public PingMode Mode => ModeIndex switch { 1 => PingMode.Traceroute, 2 => PingMode.Mtr, 3 => PingMode.Tcp, _ => PingMode.Ping };

    /// <summary>Traceroute mode (the mode switch's second segment; kept as a flag for callers that predate it).</summary>
    public bool IsTraceRoute
    {
        get => Mode == PingMode.Traceroute;
        set
        {
            if (value) ModeIndex = (int)PingMode.Traceroute;
            else if (Mode == PingMode.Traceroute) ModeIndex = (int)PingMode.Ping;
        }
    }

    public bool IsPingMode => Mode == PingMode.Ping;
    public bool IsMtrMode => Mode == PingMode.Mtr;
    public bool IsTcpMode => Mode == PingMode.Tcp;

    /// <summary>The probing loops (ICMP and TCP ping): statistics, graph, alerts and the options button.</summary>
    public bool IsLoopMode => Mode is PingMode.Ping or PingMode.Tcp;

    /// <summary>Ping, TCP ping and traceroute write the text log; MTR has its table.</summary>
    public bool IsLogMode => Mode != PingMode.Mtr;

    /// <summary>TCP mode: a port pasted with the host ("host:8080", a URL with a port) goes to the Port box
    /// (InputAssist.PortTarget); the other modes drop it, as they always did.</summary>
    public string? PortTargetName => IsTcpMode ? "TcpPortBox" : null;

    public string HostPlaceholder => AppPlatform.IsMobile ? (IsTcpMode ? "Host" : "Host name or IP")
                                   : IsTcpMode ? "e.g. example.com" : "e.g. 8.8.8.8";

    public string EmptyHint => IsTcpMode ? "Enter a host and a port and press Start." : "Enter a host and press Start.";

    /// <summary>The MTR table and its run.</summary>
    public MtrViewModel Mtr { get; } = new();

    private const string ModeKey = "ping.mode";
    private static readonly string[] ModeNames = { "ping", "traceroute", "mtr", "tcp" };

    partial void OnModeIndexChanged(int value)
    {
        string name = ModeNames[(int)Mode];
        if (ProfileService.Instance.GetSetting(ModeKey) != name) ProfileService.Instance.SetSetting(ModeKey, name);
        RefreshSummary();   // TCP shows only what it uses
    }

    // The two alert switches are remembered like the mode (written only when they differ from what is stored).
    private const string AlertUpKey = "ping.alertUp", AlertDownKey = "ping.alertDown";
    partial void OnNotifyOnlineChanged(bool value) => SaveSwitch(AlertUpKey, value);
    partial void OnNotifyOfflineChanged(bool value) => SaveSwitch(AlertDownKey, value);

    private static void SaveSwitch(string key, bool value)
    {
        if (ProfileService.Instance.GetBool(key) != value) ProfileService.Instance.SetBool(key, value);
    }

    // Probes are ICMP echo, and UDP datagrams to a closed port wherever ICMP isn't permitted (IcmpPinger.SendAsync,
    // Auto) — no setting: the log says when it switched, and why if neither can work.
    private const int UdpPort = IcmpPinger.DefaultUdpPort;

    public ObservableCollection<string> LogItems { get; } = new();

    public ObservableCollection<string> TargetHostHistory => HistoryService.Instance.Get("ping.host");

    /// <summary>Replaces the network in Ping mode (tests): (address, timeoutMs, packet options, token) → result.</summary>
    internal Func<IPAddress, int, IcmpProbeOptions, CancellationToken, Task<IcmpPinger.PingResult>>? IcmpProbe { get; set; }

    public PingViewModel()
    {
        if (HistoryService.Instance.Last("ping.host") is { } last) TargetHost = last;
        LoadSettings();
        int saved = Array.IndexOf(ModeNames, ProfileService.Instance.GetSetting(ModeKey));
        if (saved > 0) ModeIndex = saved;
        NotifyOnline = ProfileService.Instance.GetBool(AlertUpKey);
        NotifyOffline = ProfileService.Instance.GetBool(AlertDownKey);
    }

    private CancellationTokenSource? _cts;
    private bool? _lastStatus;
    private long _sent;
    private long _received;

    [RelayCommand]
    private void TogglePing()
    {
        if (IsPinging) Stop();
        else Start();
    }

    /// <summary>Copies what the current mode shows: the MTR table as an mtr-style report, or the log (a ping run's log
    /// ends with ping's statistics summary).</summary>
    [RelayCommand]
    private async Task CopyLog()
    {
        string text;
        if (Mode == PingMode.Mtr) text = Mtr.BuildReport();
        else
        {
            text = string.Join(Environment.NewLine, LogItems);
            if (Mode == _logMode && _logMode is PingMode.Ping or PingMode.Tcp && !_summaryLogged && _pingSummary is { } summary && LogItems.Count > 0)
                text += Environment.NewLine + Environment.NewLine + summary;
        }
        await Helpers.ClipboardHelper.SetTextAsync(text);
    }

    private PingMode _logMode;          // the mode of the run that wrote the log (UI thread)
    private string? _pingSummary;       // ping's closing statistics for that run, kept current (UI thread)
    private bool _summaryLogged;        // a counted run ended and wrote them into the log itself (UI thread)

    private void Start()
    {
        var mode = Mode;
        int port = 0;
        if (mode == PingMode.Tcp)
        {
            // Keep the port: "host:port", "[v6]:port" or a URL typed into the host box gives the Port box its port
            // (a URL without one: its scheme's, https → 443); the box keeps the bare host.
            var t = PingTarget.Parse(TargetHost);
            TargetHost = t.Host;
            if (t.Port is int p) TcpPortText = p.ToString(CultureInfo.InvariantCulture);
        }
        else
        {
            // Accept a pasted URL / "host:port" / "user@host" and reduce it to the bare host.
            TargetHost = HostExtractor.Extract(TargetHost);
        }
        if (string.IsNullOrWhiteSpace(TargetHost)) return;

        if (mode == PingMode.Tcp && !TryPort(TcpPortText, out port))
        {
            Stop();
            LogItems.Clear();
            ResetPingStats();
            string typed = TcpPortText?.Trim() ?? string.Empty;
            if (typed.Length > 24) typed = typed[..24] + "…";
            LogItems.Add(typed.Length == 0 ? "Error: enter a port (1-65535)." : $"Error: the port must be a number from 1 to 65535, not \"{typed}\".");
            return;
        }

        HistoryService.Instance.Add("ping.host", TargetHost);

        Stop();

        _sent = 0;
        _received = 0;
        _rtt = default;
        _lastStatus = null;   // a new run (maybe another host) must not "flip" against the previous run's last reply
        int mtrRun = 0;
        Dispatcher.UIThread.Invoke(() =>
        {
            LogItems.Clear();
            ResetPingStats();
            if (mode == PingMode.Mtr) mtrRun = Mtr.Reset();
        });
        StatsSummary = "Packets: Sent = 0, Received = 0, Lost = 0";

        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        // Snapshot the target: the box stays editable while the run goes on, and the loop (off the UI thread) would
        // otherwise label every line with whatever is typed there now ("Request timeout from <new text>").
        string host = TargetHost;
        var ip = _settings.Ip;   // picks the address: fixed for the run (the switch is locked meanwhile)
        _logMode = mode;
        _summaryLogged = false;
        IsPinging = true;
        Task.Run(() => RunProcess(host, mode, port, ip, mtrRun, token), token);
    }

    private void Stop()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
        IsPinging = false;
    }

    private async Task RunProcess(string host, PingMode mode, int port, IpPreference ip, int mtrRun, CancellationToken token)
    {
        try
        {
            if (mode == PingMode.Mtr) await Mtr.RunAsync(host, mtrRun, token);
            else if (mode == PingMode.Traceroute) await RunTraceRoute(host, token);
            else if (mode == PingMode.Tcp) await RunTcpLoop(host, port, ip, token);
            else await RunPingLoop(host, ip, token);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (token.IsCancellationRequested) return;

            var e = ex is PingException pe && pe.InnerException != null ? pe.InnerException : ex;
            string message = e switch
            {
                System.Net.Sockets.SocketException s when s.SocketErrorCode == System.Net.Sockets.SocketError.HostNotFound => "Host not found",
                System.Net.Sockets.SocketException s when s.SocketErrorCode == System.Net.Sockets.SocketError.AddressFamilyNotSupported => "Invalid address",
                System.Net.Sockets.SocketException s when s.SocketErrorCode == System.Net.Sockets.SocketError.NetworkUnreachable => "Network unreachable",
                _ => e.Message
            };
            UpdateLog($"Error: {message}", token);
            if (IsPermissionError(e)) UpdateLog(PermissionHint, token);
        }
        finally
        {
            if (!token.IsCancellationRequested)
            {
                // Checked again on the UI thread: a new run started meanwhile cancels this token first (Start → Stop),
                // and must not be shown as stopped by this one's end.
                Dispatcher.UIThread.Post(() => { if (!token.IsCancellationRequested) IsPinging = false; });
            }
        }
    }

    private async Task RunPingLoop(string host, IpPreference ip, CancellationToken token)
    {
        IPAddress addr;
        try
        {
            addr = await PingTarget.ResolveAsync(host, ip, token);
        }
        catch (OperationCanceledException) { return; }
        catch (Exception ex)
        {
            UpdateLog("Error: " + (ex is PingTargetException ? ex.Message : "Host not found"), token);
            return;
        }

        bool v6 = addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        int header = v6 ? 48 : 28;   // ICMP + IP header, classic ping accounting
        var used = _settings;
        UpdateLog($"PING {host} ({addr}) {used.Size}({used.Size + header}) bytes of data{PacketExtras(used)}.", token);
        NoteIpMismatch(host, addr, ip, token);

        var probe = IcmpProbe ?? ((a, t, o, ct) => IcmpPinger.SendAsync(a, t, o, ct));
        long seq = 1;
        bool udpNoted = false, tooBigNoted = false, finished = false;
        var notes = new HashSet<string>();
        // Windows Firewall's default rules let in only ICMPv4 "fragmentation needed" of the unreachables, so should the
        // probes ever go out as UDP there, a remote IPv4 host's "port unreachable" never reaches the socket (on-machine
        // targets, and IPv6, whose "destination unreachable" is allowed, are fine).
        bool firewallNoted = !OperatingSystem.IsWindows() || v6 || IPAddress.IsLoopback(addr);
        while (!token.IsCancellationRequested)
        {
            var s = _settings;
            if (!s.SamePacket(used))
            {
                // the options changed mid-run: they apply from this probe on, and the log says so
                UpdateLog($"Now {s.Size}({s.Size + header}) bytes{PacketExtras(s)}.", token);
                used = s;
            }
            long t0 = Stopwatch.GetTimestamp();
            _sent++;

            var r = await probe(addr, s.TimeoutMs, s.Icmp, token);
            if (token.IsCancellationRequested) break;

            // Neither ICMP nor the UDP fallback can work here: the error says why (both reasons), then how to allow ICMP.
            if (r.PermissionDenied)
            {
                UpdateLog($"Ping error: {r.Error}", token);
                UpdateLog(PermissionHint, token);
                break;
            }

            // ICMP isn't permitted, so the probes went out as UDP: say so once, so the log isn't silently a different method.
            if (r.Method == PingMethod.Udp && !udpNoted)
            {
                udpNoted = true;
                UpdateLog($"ICMP isn't permitted here: pinging with UDP datagrams to port {UdpPort} instead (the reply is the target's \"port unreachable\").", token);
            }

            // An option this system couldn't apply: said once per run, plainly (the probe still went out without it).
            if (r.Note is { } note && notes.Add(note))
            {
                UpdateLog("Note: " + note, token);
                if (IcmpPinger.CustomSizeUnavailable) Dispatcher.UIThread.Post(() => SizeLocked = true);
            }

            if (r.Success && r.Method == PingMethod.Udp)
            {
                _received++;
                UpdateLog($"Reply from {r.Address}: udp port {UdpPort} seq={seq} time={r.RoundtripMs} ms", token);
            }
            else if (r.Success)
            {
                _received++;
                int size = r.Applied.HasFlag(IcmpApplied.Size) ? s.Size : IcmpPinger.PayloadSize;
                string ttl = r.Ttl >= 0 ? r.Ttl.ToString(CultureInfo.InvariantCulture) : "?";
                UpdateLog($"{size + header} bytes from {r.Address}: icmp_seq={seq} ttl={ttl} time={r.RoundtripMs} ms", token);
            }
            else
            {
                string seqLabel = r.Method == PingMethod.Udp ? "seq" : "icmp_seq";
                if (IsPacketTooBig(r.Error))
                {
                    UpdateLog(TooBigLine(seqLabel, seq, s, header, r, addr), token);
                    if (!tooBigNoted && s.DontFragment)
                    {
                        tooBigNoted = true;
                        UpdateLog($"Tip: lower the size until replies come back: the largest that works + {header} = the path MTU.", token);
                    }
                }
                else if (IsTtlExpired(r.Error))
                {
                    string at = IsHop(r.Address) ? r.Address!.ToString() : "a router";
                    UpdateLog($"{seqLabel}={seq} TTL expired at {at}" + (s.Ttl > 0 ? $" (TTL {s.Ttl})" : string.Empty), token);
                }
                else if (IsTimeout(r.Error))
                {
                    // UDP silence can also mean the probe was filtered on the way, not that the host is down.
                    UpdateLog(r.Method == PingMethod.Udp
                        ? $"Request timeout from {host}: seq={seq} (no answer: host down, or UDP filtered)"
                        : $"Request timeout from {host}: icmp_seq={seq}", token);
                    if (r.Method == PingMethod.Udp && !firewallNoted)
                    {
                        firewallNoted = true;
                        UpdateLog("Note: Windows Firewall drops incoming ICMPv4 port-unreachable messages by default, so UDP ping can't hear remote IPv4 hosts.", token);
                    }
                }
                else if (IsHop(r.Address))
                    UpdateLog($"From {r.Address}: {seqLabel}={seq} {Describe(r.Error)}", token);   // a router's verdict, like ping's "From …"
                else
                    UpdateLog($"No reply from {host}: {seqLabel}={seq} ({Describe(r.Error)})", token);
            }

            UpdateStats(token, host, r.Success ? r.RoundtripMs : double.NaN, tcp: false);
            HandleAlerts(r.Success);

            if (s.Count > 0 && seq >= s.Count) { finished = true; break; }
            seq++;
            await WaitInterval(t0, token);
        }
        if (finished) LogSummary(token);
    }

    // ", DF set, TTL 5" for the PING line
    private static string PacketExtras(PingSettings s)
        => (s.DontFragment ? ", DF set" : string.Empty) + (s.Ttl > 0 ? $", TTL {s.Ttl}" : string.Empty);

    // "icmp_seq=4 Packet too big (DF set): 1501 bytes need fragmentation at 10.0.0.1, MTU 1492 (max size 1464)"
    private static string TooBigLine(string seqLabel, long seq, PingSettings s, int header, IcmpPinger.PingResult r, IPAddress target)
    {
        var sb = new System.Text.StringBuilder(96);
        sb.Append(seqLabel).Append('=').Append(seq).Append(' ').Append(IcmpPinger.PacketTooBig)
          .Append(s.DontFragment ? " (DF set): " : ": ").Append(s.Size + header).Append(" bytes need fragmentation");
        if (IsHop(r.Address) && !r.Address!.Equals(target)) sb.Append(" at ").Append(r.Address);
        if (r.Mtu > 0)
        {
            sb.Append(", MTU ").Append(r.Mtu);
            if (r.Mtu > header) sb.Append(" (max size ").Append(r.Mtu - header).Append(')');
        }
        return sb.ToString();
    }

    // An IP literal of the other kind than the options ask for: it's used as given, and the log says why.
    private void NoteIpMismatch(string host, IPAddress addr, IpPreference ip, CancellationToken token)
    {
        if (ip == IpPreference.Auto || !IPAddress.TryParse(host.Trim('[', ']'), out _)) return;
        bool v6 = addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        if (v6 != (ip == IpPreference.IPv6))
            UpdateLog($"Note: {addr} is an {(v6 ? "IPv6" : "IPv4")} address, so the {(ip == IpPreference.IPv6 ? "IPv6" : "IPv4")} option doesn't apply.", token);
    }

    // Start-to-start spacing (classic ping's interval): a probe that took 300 ms of a 1 s interval waits 700 ms; one
    // that took longer than the interval (a timeout) is followed at once. Read live, so a change applies right away.
    private async Task WaitInterval(long t0, CancellationToken token)
    {
        double left = _settings.IntervalMs - Stopwatch.GetElapsedTime(t0).TotalMilliseconds;
        if (left >= 1) await Task.Delay(TimeSpan.FromMilliseconds(left), token);
    }

    private async Task RunTraceRoute(string host, CancellationToken token)
    {
        UpdateLog($"Tracing route to {host} over a maximum of 30 hops:", token);
        bool udpNoted = false;

        System.Net.IPAddress target;
        try
        {
            target = await IcmpPinger.ResolveAsync(host, token);
        }
        catch (OperationCanceledException) { return; }
        catch (Exception ex)
        {
            UpdateLog($"Unable to resolve {host}: {ex.Message}", token);
            return;
        }

        for (int ttl = 1; ttl <= 30; ttl++)
        {
            if (token.IsCancellationRequested) break;

            IcmpPinger.PingResult r;
            try
            {
                // Unprivileged ICMP that also works on Android/Linux without root (raw Ping needs it);
                // there the router's "time exceeded" is read back via IP_RECVERR (see IcmpPinger). Where ICMP isn't
                // permitted Linux / Android trace with UDP datagrams instead, the same way.
                r = await IcmpPinger.SendAsync(target, 2000, token, ttl);
            }
            catch (OperationCanceledException) { break; }

            if (r.PermissionDenied)
            {
                if (IcmpPinger.UdpCanTrace)
                {
                    // ICMP isn't permitted and the UDP fallback failed too: the error says why
                    UpdateLog($"Traceroute error: {r.Error}", token);
                    UpdateLog(PermissionHint, token);
                }
                else
                    UpdateLog("Traceroute needs ICMP permission, which isn't available on this platform.", token);
                break;
            }
            if (r.Method == PingMethod.Udp && !udpNoted)
            {
                udpNoted = true;
                UpdateLog($"ICMP isn't permitted here: tracing with UDP datagrams to port {UdpPort} instead.", token);
            }

            if (r.Success)
            {
                UpdateLog($"{ttl}\t{r.RoundtripMs} ms\t{r.Address}", token);
                UpdateLog("Trace complete.", token);
                break;
            }

            if (IsHop(r.Address))
            {
                // A router that answers "unreachable" instead of "time exceeded" is where the path ends: every higher
                // TTL would get the same answer from it (traceroute's !H / !N / !X), so stop there.
                if (!IsTimeout(r.Error) && !IsTtlExpired(r.Error))
                {
                    UpdateLog($"{ttl}\t{r.RoundtripMs} ms\t{r.Address}\t{Describe(r.Error)}", token);
                    UpdateLog($"Trace stopped: {Describe(r.Error).ToLowerInvariant()} at {r.Address}.", token);
                    break;
                }
                UpdateLog($"{ttl}\t{r.RoundtripMs} ms\t{r.Address}", token);
            }
            else if (!IsTimeout(r.Error))
                UpdateLog($"{ttl}\t*\t{Describe(r.Error)}", token);   // an answer/error without a usable address — say so, not "timed out"
            else
                UpdateLog($"{ttl}\t*\tRequest timed out.", token);

            await Task.Delay(100, token);
        }
    }

    // ---------- Ping / TCP mode statistics ----------
    // ping's min/avg/max/mdev and the loss, plus the recent round trips for the sparkline. The sums belong to the ping
    // loop (one probe at a time); the strings and the series are set on the UI thread.

    private RttStats _rtt;

    /// <summary>The run's recent round trips (NaN = no reply), for the sparkline; redrawn when <see cref="PingSeriesVersion"/> changes.</summary>
    public LatencySeries PingSeries { get; } = new(120);
    [ObservableProperty] private int _pingSeriesVersion;
    [ObservableProperty] private string _sentText = "0";
    [ObservableProperty] private string _receivedText = "0";
    [ObservableProperty] private string _lossText = "—";
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(SomeLoss), nameof(AllLost))] private int _lossLevel;   // 0 none, 1 some, 2 all
    [ObservableProperty] private string _minText = "—";
    [ObservableProperty] private string _avgText = "—";
    [ObservableProperty] private string _maxText = "—";
    [ObservableProperty] private string _mdevText = "—";

    public bool SomeLoss => LossLevel == 1;
    public bool AllLost => LossLevel == 2;

    private sealed record PingStatsText(string Sent, string Received, string Loss, int LossLevel,
                                        string Min, string Avg, string Max, string Mdev, string Summary);

    private void ResetPingStats()
    {
        PingSeries.Clear();
        PingSeriesVersion++;
        _pingSummary = null;
        Apply(new PingStatsText("0", "0", "—", 0, "—", "—", "—", "—", string.Empty));
    }

    private void Apply(PingStatsText s)
    {
        SentText = s.Sent;
        ReceivedText = s.Received;
        LossText = s.Loss;
        LossLevel = s.LossLevel;
        MinText = s.Min;
        AvgText = s.Avg;
        MaxText = s.Max;
        MdevText = s.Mdev;
    }

    private void UpdateStats(CancellationToken token, string host, double rttMs, bool tcp)
    {
        long lost = _sent - _received;
        double lossPercent = _sent > 0 ? ((double)lost / _sent) * 100 : 0;
        var text = $"Packets: Sent = {_sent}, Received = {_received}, Lost = {lost} ({lossPercent:F0}% loss)";

        if (!double.IsNaN(rttMs)) _rtt.Add(rttMs);
        var inv = CultureInfo.InvariantCulture;
        bool any = _rtt.Count > 0;
        string loss = _sent > 0 ? Percent(lossPercent) : "—";
        string rttLine = any ? $"{Environment.NewLine}rtt min/avg/max/mdev = {Ms(_rtt.Best)}/{Ms(_rtt.Mean)}/{Ms(_rtt.Worst)}/{Ms(_rtt.MDev)} ms" : string.Empty;
        var stats = new PingStatsText(
            _sent.ToString(inv), _received.ToString(inv), loss,
            _sent == 0 || lost == 0 ? 0 : _received == 0 ? 2 : 1,
            any ? Ms(_rtt.Best) + " ms" : "—", any ? Ms(_rtt.Mean) + " ms" : "—",
            any ? Ms(_rtt.Worst) + " ms" : "—", any ? Ms(_rtt.MDev) + " ms" : "—",
            // ping's closing lines, for the copied log (TCP: connects instead of packets)
            tcp
                ? $"--- {host} tcp ping statistics ---{Environment.NewLine}" +
                  $"{_sent} probes, {_received} connected, {Percent(lossPercent)} failed" + rttLine
                : $"--- {host} ping statistics ---{Environment.NewLine}" +
                  $"{_sent} packets transmitted, {_received} received, {Percent(lossPercent)} packet loss" + rttLine);

        // StatsSummary is data-bound; this runs from the background ping loop, so marshal it.
        // Skip if this session was cancelled — a stale post must not overwrite a newer run.
        Dispatcher.UIThread.Post(() =>
        {
            if (token.IsCancellationRequested) return;
            StatsSummary = text;
            Apply(stats);
            _pingSummary = stats.Summary;
            PingSeries.Add(rttMs);
            PingSeriesVersion++;
        });
    }

    // A counted run ended: ping's closing statistics go into the log too (and Copy doesn't add them a second time).
    private void LogSummary(CancellationToken token)
    {
        Dispatcher.UIThread.Post(() =>
        {
            if (token.IsCancellationRequested || _pingSummary is not { } summary) return;
            LogItems.Add(string.Empty);
            foreach (var line in summary.Split(Environment.NewLine)) LogItems.Add(line);
            _summaryLogged = true;
        });
    }

    // 12 → "12", 13.25 → "13.3", 0.4 → "0.4"; past 100 ms a tenth is noise.
    private static string Ms(double v)
        => v.ToString(v >= 100 || v == Math.Floor(v) ? "0" : "0.0", CultureInfo.InvariantCulture);

    private static string Percent(double p)
        => (p == Math.Floor(p) ? p.ToString("0", CultureInfo.InvariantCulture) : p.ToString("0.0", CultureInfo.InvariantCulture)) + "%";

    private void HandleAlerts(bool current)
    {
        if (_lastStatus.HasValue && _lastStatus != current)
        {
            if ((current && NotifyOnline) || (!current && NotifyOffline))
            {
                AlertPlayed?.Invoke(current);
                SoundHelper.PlayNotify(current);
            }
        }
        _lastStatus = current;
    }

    /// <summary>Raised (on the probing loop's thread) when an up / down alert sounds: true = up (tests).</summary>
    internal event Action<bool>? AlertPlayed;

    // A real responder, not the unspecified-address placeholder of a timeout: 0.0.0.0, or :: for an IPv6 target on
    // Windows (which printed every silent hop as "N  2000 ms  ::").
    private static bool IsHop(System.Net.IPAddress? a)
        => a != null && !a.Equals(System.Net.IPAddress.Any) && !a.Equals(System.Net.IPAddress.IPv6Any);

    // Errors come as IcmpPinger's own text or, from the managed Ping, an IPStatus name.
    private static bool IsTimeout(string? e)
        => string.IsNullOrEmpty(e) || e == "Request timed out" || e == nameof(IPStatus.TimedOut);

    private static bool IsTtlExpired(string? e)
        => e is "TTL expired" or nameof(IPStatus.TtlExpired) or nameof(IPStatus.TimeExceeded);

    private static bool IsPacketTooBig(string? e)
        => e is IcmpPinger.PacketTooBig or nameof(IPStatus.PacketTooBig);

    // "DestinationHostUnreachable" (an IPStatus name) → "Destination host unreachable"; plain text stays as it is.
    private static string Describe(string? e)
    {
        if (string.IsNullOrEmpty(e)) return "No reply";
        if (IsTtlExpired(e)) return "TTL expired";
        if (e.Contains(' ') || !char.IsUpper(e[0])) return e;
        var sb = new System.Text.StringBuilder(e.Length + 8).Append(e[0]);
        for (int i = 1; i < e.Length; i++)
        {
            if (char.IsUpper(e[i])) sb.Append(' ').Append(char.ToLowerInvariant(e[i]));
            else sb.Append(e[i]);
        }
        return sb.ToString();
    }

    private static readonly string PermissionHint =
        OperatingSystem.IsLinux()
            ? "Hint: ICMP on Linux needs privileges. Run:  sudo sysctl -w net.ipv4.ping_group_range=\"0 2147483647\"  (or launch Echoes with sudo)."
            : "Hint: raw ICMP sockets require elevated privileges on this platform.";

    private static bool IsPermissionError(Exception e)
    {
        if (e is System.Net.Sockets.SocketException s &&
            s.SocketErrorCode == System.Net.Sockets.SocketError.AccessDenied)
            return true;

        var msg = e.Message;
        return msg.Contains("Operation not permitted", StringComparison.OrdinalIgnoreCase)
            || msg.Contains("Permission denied", StringComparison.OrdinalIgnoreCase)
            || msg.Contains("Access denied", StringComparison.OrdinalIgnoreCase)
            || msg.Contains("not allowed", StringComparison.OrdinalIgnoreCase);
    }

    private const int MaxLogItems = 5000;

    private void UpdateLog(string m, CancellationToken token)
    {
        Dispatcher.UIThread.Post(() =>
        {
            // A stray line queued by a just-cancelled session must NOT land after the next run cleared
            // the list — otherwise old lines linger and mix with the new run's output.
            if (token.IsCancellationRequested) return;
            LogItems.Add(m);
            while (LogItems.Count > MaxLogItems) LogItems.RemoveAt(0);
        });
    }
}
