using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Echoes.Helpers;
using Echoes.Tests.Support;

namespace Echoes.Tests;

/// <summary>
/// Live packet capture with whatever this system captures with: Npcap or a raw socket on Windows, a packet socket on
/// Linux, libpcap on macOS. A datagram with a text nobody else sends is sent through the interface, and the capture
/// has to show it, decoded. Capture needs rights most test runs don't have (root, Npcap): without them the refusal
/// is checked and the test is reported as skipped, with what was missing.
/// </summary>
[Collection(Live.Collection)]
public class CaptureLiveTests
{
    private static bool NpcapInstalled
        => OperatingSystem.IsWindows()
           && (File.Exists(Path.Combine(Environment.SystemDirectory, "Npcap", "wpcap.dll")) || File.Exists(Path.Combine(Environment.SystemDirectory, "wpcap.dll")));

    [Fact]
    public void What_capture_needs_here_is_said_in_one_line()
    {
        Assert.Equal(OperatingSystem.IsWindows() || OperatingSystem.IsLinux() || OperatingSystem.IsMacOS(), PacketCapture.Supported);
        Assert.False(string.IsNullOrWhiteSpace(PacketCapture.Requirement));
        Assert.DoesNotContain('\n', PacketCapture.Requirement);
        if (OperatingSystem.IsWindows()) Assert.Equal(NpcapInstalled, PacketCapture.Requirement.StartsWith("Captures with Npcap", StringComparison.Ordinal));
    }

    // Starts a capture, or skips the test with what this run lacks. A refusal when nothing is lacking fails the test.
    private static PacketCapture Start(NetIface iface, Action<CapturedFrame> onFrame, Action<string?> onEnd)
    {
        try { return PacketCapture.Start(iface, promiscuous: false, onFrame, onEnd); }
        catch (CaptureException ex)
        {
            // Windows: no Npcap and no administrator, or Npcap without its loopback adapter. Elsewhere: not root.
            bool lacking = OperatingSystem.IsWindows() ? (NpcapInstalled ? iface.IsLoopback : !Live.Privileged) : !Live.Privileged;
            Assert.True(lacking, $"capturing on {iface.Name} was refused although this run has what it needs: {ex.Message}");
            Assert.True(ex.Message.Length > 30, "the refusal says what to do: " + ex.Message);
            Assert.Skip($"live capture isn't possible in this run: {ex.Message}");
            throw;
        }
    }

    private static async Task CaptureOwnDatagramAsync(NetIface iface, IPEndPoint target)
    {
        using var deadline = Live.Deadline(30);
        var frames = new ConcurrentQueue<CapturedFrame>();
        int delivered = 0;
        var ended = new TaskCompletionSource<string?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var capture = Start(iface, f => { frames.Enqueue(f); Interlocked.Increment(ref delivered); }, e => ended.TrySetResult(e));
        PacketRecord? seen = null;
        int sourcePort;
        try
        {
            Assert.False(string.IsNullOrWhiteSpace(capture.Engine));
            byte[] marker = Encoding.ASCII.GetBytes("echoes-capture-test-" + Guid.NewGuid().ToString("N"));
            using var sender = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            Assert.True(iface.TryBind(sender, out string? note), note);

            var decoder = new PacketDecoder();
            var clock = Stopwatch.StartNew();
            while (seen is null && clock.Elapsed < TimeSpan.FromSeconds(10))
            {
                // sent again each round: the capture may not be listening yet when the first one leaves
                await sender.SendToAsync(marker, SocketFlags.None, target, deadline.Token);
                await Task.Delay(200, deadline.Token);
                while (seen is null && frames.TryDequeue(out var frame))
                {
                    if (frame.Data.AsSpan().IndexOf(marker) < 0) continue;
                    seen = new PacketRecord { Number = 1, TimeUtc = frame.TimeUtc, Data = frame.Data, WireLength = frame.WireLength, Link = frame.Link };
                    decoder.Summarize(seen);
                }
            }
            sourcePort = ((IPEndPoint)sender.LocalEndPoint!).Port;

            // Windows shows a raw socket this computer's outgoing packets only when its firewall lets the program see
            // them, and the test has no way to make a packet arrive from outside. So without Npcap a capture that
            // started but didn't show the datagram is reported as not checked, with what it did show.
            if (seen is null && capture.Engine.Contains("raw socket", StringComparison.Ordinal))
                Assert.Skip($"{capture.Engine} on {iface.Name} started and delivered {delivered} packet(s), but not the datagram this computer sent (Windows' firewall hides outgoing packets from raw sockets)");
            Assert.True(seen is not null, $"{capture.Engine} on {iface.Name} delivered {delivered} frame(s), none of them the datagram sent to {target}");
        }
        finally { capture.Stop(); }

        // read as what it was: a UDP datagram between these two ends, at about this time, whole
        Assert.Equal(PacketL4.Udp, seen!.L4);
        Assert.Equal(target.Port, seen.DstPort);
        Assert.Equal(sourcePort, seen.SrcPort);
        Assert.Equal(target.Address, seen.Dst.ToAddress());
        Assert.Equal(iface.V4, seen.Src.ToAddress());
        Assert.True(seen.WireLength >= seen.Data.Length);
        Assert.InRange(seen.TimeUtc, DateTime.UtcNow.AddMinutes(-2), DateTime.UtcNow.AddMinutes(2));
        Assert.False(seen.Alert, seen.Info);

        // stopping ends it once, and a stop isn't an error
        string? end = await ended.Task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        Assert.Null(end);
        Assert.True(capture.Dropped >= -1);
    }

    [Fact]
    public async Task A_datagram_over_the_loopback_interface_is_captured_and_decoded()
    {
        var lo = Live.Loopback();
        Assert.SkipWhen(OperatingSystem.IsWindows() && !NpcapInstalled, "without Npcap, Windows shows a capture no loopback traffic");
        using var listener = Live.UdpListener(IPAddress.Loopback);
        await CaptureOwnDatagramAsync(lo, (IPEndPoint)listener.LocalEndPoint!);
    }

    [Fact]
    public async Task A_datagram_leaving_a_network_interface_is_captured_and_decoded()
    {
        var nic = Live.Network();
        // to the gateway's discard port (or the network's first other address): it only has to leave this interface
        var target = nic.Gateway4 is { } gateway && nic.OnLink4(gateway) ? gateway
            : nic.Subnet4(16, out _)?.Hosts.FirstOrDefault(a => !a.Equals(nic.V4));
        Assert.SkipWhen(target is null, $"{nic.Name} has no network to send a datagram into (/{nic.Prefix4})");
        await CaptureOwnDatagramAsync(nic, new IPEndPoint(target!, 9));
    }

    [Fact]
    public void An_interface_that_is_gone_is_refused_in_words()
    {
        var gone = new NetIface("echoes-none0", "gone", "{00000000-0000-0000-0000-000000000000}", 987654, IPAddress.Parse("192.0.2.77"), null, null, false) { Prefix4 = 24 };
        if (!PacketCapture.Supported) return;
        var ex = Assert.Throws<CaptureException>(() => PacketCapture.Start(gone, false, _ => { }, _ => { }));
        Assert.False(string.IsNullOrWhiteSpace(ex.Message));
    }
}
