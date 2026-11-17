using System.Net;
using System.Net.Sockets;
using Echoes.Helpers;

namespace Echoes.Tests.Support;

/// <summary>What the live tests share: this computer's loopback interface (every desktop system has one, and traffic
/// over it disturbs nobody), its first real interface, and whether this user may do the privileged things.</summary>
internal static class Live
{
    /// <summary>The collection every live test class is in: xUnit runs the tests of one collection one after the
    /// other, so two tests never fight over the same interface or see each other's packets.</summary>
    public const string Collection = "Live network";

    /// <summary>Set to 1 to let the tests search this computer's own network for devices (they then send to every
    /// address of its subnet, as the Network tool's Find devices does). CI sets it; a developer's run doesn't.</summary>
    public const string LanSwitch = "ECHOES_TESTS_LAN";

    public static bool LanAllowed => Environment.GetEnvironmentVariable(LanSwitch) == "1";

    /// <summary>The loopback interface with its IPv4 address: "lo", "lo0", "Loopback Pseudo-Interface 1".</summary>
    public static NetIface Loopback()
    {
        var lo = NetIfaces.Up(withLoopback: true).FirstOrDefault(i => i.IsLoopback && i.V4 is not null);
        Assert.SkipWhen(lo is null, "this system lists no loopback interface with an IPv4 address");
        return lo!;
    }

    /// <summary>
    /// <see cref="Loopback"/> for a test that sends TCP or UDP to 127.0.0.1 through it. Skipped on WSL with "mirrored"
    /// networking: there Windows relays TCP and UDP for 127.0.0.1 through a device of its own (policy routing to
    /// loopback0), so what a socket tied to "lo" sends is answered into the relay and never comes back. Linux itself,
    /// WSL's default networking and a network namespace inside a mirrored WSL have none of that.
    /// </summary>
    public static NetIface LoopbackForSockets()
    {
        if (OperatingSystem.IsLinux() && Directory.Exists("/sys/class/net/loopback0") && File.Exists("/proc/sys/kernel/osrelease")
            && File.ReadAllText("/proc/sys/kernel/osrelease").Contains("microsoft", StringComparison.OrdinalIgnoreCase))
            Assert.Skip("WSL's mirrored networking relays TCP and UDP for 127.0.0.1 through Windows, not through lo: run this on Linux itself or in a network namespace");
        return Loopback();
    }

    /// <summary>The first interface that isn't loopback and has an IPv4 address (the list puts Ethernet / Wi-Fi first);
    /// the test is skipped on a computer with none.</summary>
    public static NetIface Network()
    {
        var nic = NetIfaces.Up().FirstOrDefault(i => i.V4 is not null);
        Assert.SkipWhen(nic is null, "this computer has no network interface with an IPv4 address");
        return nic!;
    }

    /// <summary>Root, or an elevated administrator.</summary>
    public static bool Privileged => Environment.IsPrivilegedProcess;

    public static string SystemName => OperatingSystem.IsWindows() ? "Windows" : OperatingSystem.IsMacOS() ? "macOS" : OperatingSystem.IsLinux() ? "Linux" : "this system";

    /// <summary>A UDP socket bound to a free port of <paramref name="address"/>.</summary>
    public static Socket UdpListener(IPAddress address)
    {
        var s = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        s.Bind(new IPEndPoint(address, 0));
        return s;
    }

    /// <summary>A port of <paramref name="address"/> nothing listens on (it was free a moment ago).</summary>
    public static int ClosedTcpPort(IPAddress address)
    {
        var l = new TcpListener(address, 0);
        l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    /// <summary>A token that ends a test's waiting after <paramref name="seconds"/> (and when the run is cancelled).</summary>
    public static CancellationTokenSource Deadline(int seconds = 15)
    {
        var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cts.CancelAfter(TimeSpan.FromSeconds(seconds));
        return cts;
    }
}

/// <summary>Names the collection (the classes are tied to it by <see cref="Live.Collection"/>).</summary>
[CollectionDefinition(Live.Collection)]
public sealed class LiveNetworkCollection;
