using System.Net;
using System.Net.Sockets;
using Echoes.Helpers;
using Echoes.Tests.Support;

namespace Echoes.Tests;

/// <summary>The port scanner with an interface chosen (nmap's -e): how the choice is written in a report, and a real
/// scan of this computer's own loopback address from the loopback interface.</summary>
[Collection(Live.Collection)]
public class ScanIfaceTests
{
    private sealed class Sink : IScanSink
    {
        public void HostChanged(ScanHost host) { }
        public void PortFound(PortFinding finding) { }
    }

    private static ScanOptions Options(NetIface? via, bool tcp = true, bool udp = false, bool versions = false, bool pingOnly = false, bool skipDiscovery = false)
    {
        var timing = NmapData.Timing(4);
        return new ScanOptions(Tcp: tcp, Udp: udp, ServiceDetection: versions, PingOnly: pingOnly, SkipDiscovery: skipDiscovery,
                               TimeoutMs: 1500, Concurrency: timing.Concurrency, Timing: timing, Via: via);
    }

    private static NetIface Named(string name)
        => new(name, name, name, 4, IPAddress.Parse("192.168.1.20"), null, null, false) { Prefix4 = 24 };

    private static readonly NetIface Gone =
        new("echoes-none0", "gone", "{00000000-0000-0000-0000-000000000000}", 987654, IPAddress.Parse("192.0.2.77"), null, null, false) { Prefix4 = 24 };

    [Fact]
    public void The_interface_is_written_in_the_reports_flags_as_nmap_writes_it()
    {
        Assert.Equal("-sT", ScanReport.Flags(Options(null)));
        Assert.Equal("-sT -e eth0", ScanReport.Flags(Options(Named("eth0"))));
        Assert.Equal("-sT -sU -sV -Pn -e eth0", ScanReport.Flags(Options(Named("eth0"), udp: true, versions: true, skipDiscovery: true)));
        Assert.Equal("-sn -e eth0", ScanReport.Flags(Options(Named("eth0"), pingOnly: true)));
        Assert.Equal("-sn", ScanReport.Flags(Options(null, pingOnly: true)));
        // Windows' names have spaces
        Assert.Equal("-sT -e \"Wi-Fi 2\"", ScanReport.Flags(Options(Named("Wi-Fi 2"))));
    }

    [Fact]
    public void Only_the_two_interface_reasons_are_interface_reasons()
    {
        Assert.True(ScanText.IsIfaceReason(ScanSocket.IfaceUnusable));
        Assert.True(ScanText.IsIfaceReason(ScanSocket.IfaceRedirected));
        Assert.False(ScanText.IsIfaceReason("no-response"));
        Assert.False(ScanText.IsIfaceReason(""));
        Assert.False(ScanText.IsIfaceReason(null));
    }

    private static async Task<(ScanPass Pass, List<ScanHost> Targets)> ScanAsync(ScanOptions options, string ports)
    {
        var targets = ScanTargets.Parse("127.0.0.1").Ips.Select(ip => new ScanHost(ip, null)).ToList();
        var spec = ScanPortSpec.Parse(options.PingOnly ? "" : ports, tcp: true, udp: false);
        var pass = await new ScanEngine(options, new Sink()).RunPassAsync(targets, spec).WaitAsync(TimeSpan.FromSeconds(60), TestContext.Current.CancellationToken);
        return (pass, targets);
    }

    [Fact]
    public async Task A_scan_from_the_loopback_interface_tells_open_from_closed()
    {
        var lo = Live.LoopbackForSockets();
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            int open = ((IPEndPoint)listener.LocalEndpoint).Port, closed = Live.ClosedTcpPort(IPAddress.Loopback);
            var (pass, _) = await ScanAsync(Options(lo, skipDiscovery: true), $"{open},{closed}");

            Assert.Equal(0, pass.UnknownProbes);
            var byPort = pass.Findings.ToDictionary(f => f.Port);
            Assert.Equal(PortState.Open, byPort[open].State);
            Assert.Equal(PortState.Closed, byPort[closed].State);
            Assert.All(pass.Findings, f => Assert.False(ScanText.IsIfaceReason(f.Reason)));
        }
        finally { listener.Stop(); }
    }

    [Fact]
    public async Task Host_discovery_from_the_loopback_interface_finds_this_computer()
    {
        var lo = Live.Loopback();
        var (pass, targets) = await ScanAsync(Options(lo, pingOnly: true), "");
        Assert.Equal(1, pass.HostsUp);
        Assert.Equal(HostStatus.Up, targets[0].Status);
        Assert.Equal(0, pass.UnknownHosts);
    }

    [Fact]
    public async Task A_scan_from_an_interface_that_is_gone_says_undetermined_and_blames_the_interface()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            int open = ((IPEndPoint)listener.LocalEndpoint).Port;
            var (pass, _) = await ScanAsync(Options(Gone, skipDiscovery: true), open.ToString());

            // an open port must not be reported as anything it isn't: not open (nothing was sent), not filtered or closed
            var finding = Assert.Single(pass.Findings);
            Assert.Equal(PortState.Unknown, finding.State);
            Assert.True(ScanText.IsIfaceReason(finding.Reason), finding.Reason);
            Assert.True(pass.UnknownProbes > 0);

            string note = ScanText.UnknownNote(pass, "1 probe(s)");
            Assert.Contains("echoes-none0", note);
            Assert.DoesNotContain("ran out of sockets", note);
        }
        finally { listener.Stop(); }
    }
}
