using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Echoes.Helpers;
using Echoes.Tests.Support;

namespace Echoes.Tests;

/// <summary>
/// SOCKS5 UDP through an upstream proxy, over this computer's loopback. A second Echoes proxy stands in for the
/// upstream, so what it is asked for shows in its own log. A small fake one stands in where the test must send what a
/// real upstream wouldn't: answers from hosts the client never sent to, and datagrams from outside its relay. Also
/// where the upstream's relay is taken to be, judged without a network.
/// </summary>
public partial class ProxyServerTests
{
    /// <summary>A SOCKS5 upstream that grants one UDP relay and names it as 0.0.0.0 ("where you reached me"). What reaches
    /// the relay is kept; the test answers from <see cref="Relay"/> itself.</summary>
    private sealed class FakeUdpUpstream : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();
        private TcpClient? _control;

        public Socket Relay { get; } = Live.UdpListener(IPAddress.Loopback);
        public int Port { get; }
        public ConcurrentQueue<(IPEndPoint From, byte[] Data)> Got { get; } = new();

        public FakeUdpUpstream()
        {
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _ = Task.Run(async () =>
            {
                try
                {
                    _control = await _listener.AcceptTcpClientAsync(_stop.Token);
                    var s = _control.GetStream();
                    Assert.Equal(new byte[] { 5, 1, 0 }, await ReadAsync(s, 3, _stop.Token));   // no login offered
                    await s.WriteAsync(new byte[] { 5, 0 }, _stop.Token);
                    Assert.Equal(new byte[] { 5, 3, 0, 1, 0, 0, 0, 0, 0, 0 }, await ReadAsync(s, 10, _stop.Token));
                    int port = ((IPEndPoint)Relay.LocalEndPoint!).Port;
                    await s.WriteAsync(new byte[] { 5, 0, 0, 1, 0, 0, 0, 0, (byte)(port >> 8), (byte)port }, _stop.Token);

                    var buf = new byte[65_536];
                    while (true)
                    {
                        var got = await Relay.ReceiveFromAsync(buf, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), _stop.Token);
                        Got.Enqueue(((IPEndPoint)got.RemoteEndPoint, buf[..got.ReceivedBytes]));
                    }
                }
                catch (Exception e) when (e is OperationCanceledException or SocketException or ObjectDisposedException or IOException) { }
            });
        }

        /// <summary>The first datagram that reached the relay.</summary>
        public async Task<(IPEndPoint From, byte[] Data)> FirstAsync(CancellationToken ct)
        {
            while (true)
            {
                if (Got.TryPeek(out var first)) return first;
                await Task.Delay(20, ct);
            }
        }

        public void Dispose()
        {
            _stop.Cancel();
            _listener.Stop();
            _control?.Dispose();
            Relay.Dispose();
        }
    }

    private static ProxyServerOptions UdpThrough(int upstreamPort, ProxyIpVersion ipVersion = ProxyIpVersion.Auto, ProxyRules? rules = null,
                                                 string? user = null, string? pass = null)
        => new()
        {
            Udp = true,
            IpVersion = ipVersion,
            Rules = rules ?? ProxyRules.None,
            Upstream = UpstreamAt($"socks5://127.0.0.1:{upstreamPort}", user, pass),
        };

    private static byte[] Concat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();

    // ------------------------------------------------------------------ through a second proxy

    [Fact]
    public async Task Udp_goes_on_through_a_socks5_upstream()
    {
        using var deadline = Live.Deadline();
        using var echo = new UdpEcho();
        using var parent = new Proxy(new ProxyServerOptions { Udp = true });
        using var proxy = new Proxy(UdpThrough(parent.Port));
        using var control = await proxy.ConnectAsync(deadline.Token);

        var (rep, relay) = await UdpAssociateAsync(control.GetStream(), 0, deadline.Token);
        Assert.Equal(0, rep);
        Assert.Equal(IPAddress.Loopback, relay!.Address);   // the client's relay is this proxy's own

        using var client = Live.UdpListener(IPAddress.Loopback);
        byte[] ping = "a datagram through the upstream"u8.ToArray();
        await client.SendToAsync(Datagram(IPAddress.Loopback, echo.Port, ping), SocketFlags.None, relay, deadline.Token);

        var answer = await ReceiveAsync(client, 5000, deadline.Token);
        Assert.NotNull(answer);
        Assert.Equal(Header(IPAddress.Loopback, echo.Port), answer![..10]);   // who answered...
        Assert.Equal(ping, answer[10..]);                                      // ...and what
        Assert.Equal(ping, Assert.Single(echo.Got).Data);

        // the upstream relayed it (its own log says so), and this proxy says where the datagrams went on to
        Assert.Equal($"127.0.0.1:{echo.Port}", (await parent.EntryAsync(e => e.Proto == "UDP" && e.Ok, deadline.Token)).Target);
        Assert.Contains($"upstream proxy socks5://127.0.0.1:{parent.Port}", (await proxy.EntryAsync(e => e.Status == "UDP associate", deadline.Token)).Detail);
        var row = await proxy.EntryAsync(e => e.Proto == "UDP", deadline.Token);
        Assert.True(row.Ok);
        Assert.Equal($"127.0.0.1:{echo.Port}", row.Target);
        Assert.True(proxy.BytesUp >= ping.Length && proxy.BytesDown >= ping.Length);
    }

    [Fact]
    public async Task A_name_goes_to_the_upstream_as_a_name_unless_this_proxy_needs_the_address()
    {
        using var deadline = Live.Deadline();
        using var echo = new UdpEcho();
        byte[] ping = "by name"u8.ToArray();

        // handed on as it is: the upstream looks it up (IPv4 only there: "localhost" could come as ::1 first, where the
        // echo doesn't listen), and its answer names the address, from the port the client sent to
        using (var parent = new Proxy(new ProxyServerOptions { Udp = true, IpVersion = ProxyIpVersion.IPv4 }))
        using (var proxy = new Proxy(UdpThrough(parent.Port)))
        using (var control = await proxy.ConnectAsync(deadline.Token))
        using (var client = Live.UdpListener(IPAddress.Loopback))
        {
            var (_, relay) = await UdpAssociateAsync(control.GetStream(), 0, deadline.Token);
            await client.SendToAsync(Datagram("localhost", echo.Port, ping), SocketFlags.None, relay!, deadline.Token);
            var answer = await ReceiveAsync(client, 5000, deadline.Token);
            Assert.NotNull(answer);
            Assert.Equal(Header(IPAddress.Loopback, echo.Port), answer![..10]);
            Assert.Equal(ping, answer[10..]);
            Assert.Equal($"localhost:{echo.Port}", (await parent.EntryAsync(e => e.Proto == "UDP", deadline.Token)).Target);
        }

        // with an IP version set here, the name is looked up here and the upstream is handed the address
        using (var parent = new Proxy(new ProxyServerOptions { Udp = true }))
        using (var proxy = new Proxy(UdpThrough(parent.Port, ProxyIpVersion.IPv4)))
        using (var control = await proxy.ConnectAsync(deadline.Token))
        using (var client = Live.UdpListener(IPAddress.Loopback))
        {
            var (_, relay) = await UdpAssociateAsync(control.GetStream(), 0, deadline.Token);
            await client.SendToAsync(Datagram("localhost", echo.Port, ping), SocketFlags.None, relay!, deadline.Token);
            Assert.NotNull(await ReceiveAsync(client, 5000, deadline.Token));
            Assert.Equal($"127.0.0.1:{echo.Port}", (await parent.EntryAsync(e => e.Proto == "UDP", deadline.Token)).Target);
            Assert.Equal($"localhost:{echo.Port}", (await proxy.EntryAsync(e => e.Proto == "UDP", deadline.Token)).Target);
        }
    }

    [Fact]
    public async Task The_upstreams_login_is_used_for_its_udp_relay()
    {
        using var deadline = Live.Deadline();
        using var echo = new UdpEcho();
        using var parent = new Proxy(new ProxyServerOptions { Udp = true, User = "chain", Pass = "upstream-pass-for-the-test" });
        using var proxy = new Proxy(UdpThrough(parent.Port, user: "chain", pass: "upstream-pass-for-the-test"));
        using var control = await proxy.ConnectAsync(deadline.Token);

        var (rep, relay) = await UdpAssociateAsync(control.GetStream(), 0, deadline.Token);
        Assert.Equal(0, rep);
        using var client = Live.UdpListener(IPAddress.Loopback);
        await client.SendToAsync(Datagram(IPAddress.Loopback, echo.Port, "logged in"u8.ToArray()), SocketFlags.None, relay!, deadline.Token);
        Assert.NotNull(await ReceiveAsync(client, 5000, deadline.Token));
        Assert.Equal("chain", (await parent.EntryAsync(e => e.Status == "UDP associate", deadline.Token)).User);
    }

    [Fact]
    public async Task When_the_upstreams_relay_cant_be_had_the_client_hears_why()
    {
        using var deadline = Live.Deadline();

        // an upstream with UDP off: "command not supported", as it said itself
        using (var parent = new Proxy())
        using (var proxy = new Proxy(UdpThrough(parent.Port)))
        using (var control = await proxy.ConnectAsync(deadline.Token))
        {
            Assert.Equal(7, (await UdpAssociateAsync(control.GetStream(), 0, deadline.Token)).Rep);
            var row = await proxy.EntryAsync(e => !e.Ok, deadline.Token);
            Assert.Equal("upstream: no UDP", row.Status);
            Assert.Contains("doesn't relay UDP", row.Detail);
        }

        // an upstream that is down
        int closed = Live.ClosedTcpPort(IPAddress.Loopback);
        using (var proxy = new Proxy(UdpThrough(closed)))
        using (var control = await proxy.ConnectAsync(deadline.Token))
        {
            Assert.Equal(1, (await UdpAssociateAsync(control.GetStream(), 0, deadline.Token)).Rep);
            Assert.Equal("upstream down", (await proxy.EntryAsync(e => !e.Ok, deadline.Token)).Status);
        }
    }

    [Fact]
    public async Task The_relay_ends_when_the_upstream_closes_its_side()
    {
        using var deadline = Live.Deadline();
        using var echo = new UdpEcho();
        var parent = new Proxy(new ProxyServerOptions { Udp = true });
        using var proxy = new Proxy(UdpThrough(parent.Port));
        using var control = await proxy.ConnectAsync(deadline.Token);
        var (_, relay) = await UdpAssociateAsync(control.GetStream(), 0, deadline.Token);
        using var client = Live.UdpListener(IPAddress.Loopback);
        await client.SendToAsync(Datagram(IPAddress.Loopback, echo.Port, "before"u8.ToArray()), SocketFlags.None, relay!, deadline.Token);
        Assert.NotNull(await ReceiveAsync(client, 5000, deadline.Token));

        parent.Dispose();   // its connections close, the one this proxy holds for the relay too

        // the association ends, and with it the client's TCP connection
        int read;
        try { read = await control.GetStream().ReadAsync(new byte[1], deadline.Token); }
        catch (IOException) { read = 0; }
        Assert.Equal(0, read);
        while (proxy.Active > 0) await Task.Delay(20, deadline.Token);
    }

    // ------------------------------------------------------------------ through a fake upstream

    [Fact]
    public async Task Through_an_upstream_only_hosts_the_client_sent_to_may_answer()
    {
        using var deadline = Live.Deadline();
        using var upstream = new FakeUdpUpstream();
        using var proxy = new Proxy(UdpThrough(upstream.Port));
        using var control = await proxy.ConnectAsync(deadline.Token);
        var (rep, relay) = await UdpAssociateAsync(control.GetStream(), 0, deadline.Token);
        Assert.Equal(0, rep);

        using var client = Live.UdpListener(IPAddress.Loopback);
        await client.SendToAsync(Datagram(IPAddress.Loopback, 5300, "ping"u8.ToArray()), SocketFlags.None, relay!, deadline.Token);

        // it reached the upstream's relay (named 0.0.0.0: taken as the address the upstream was reached at) with the
        // header naming where it goes
        var (from, data) = await upstream.FirstAsync(deadline.Token);
        Assert.Equal(Concat(Header(IPAddress.Loopback, 5300), "ping"u8.ToArray()), data);

        // a host the client never sent to, and the right host's header from outside the upstream's relay: dropped
        await upstream.Relay.SendToAsync(Concat(Header(IPAddress.Parse("198.51.100.7"), 53), "stranger"u8.ToArray()), SocketFlags.None, from, deadline.Token);
        using (var outside = Live.UdpListener(IPAddress.Loopback))
            await outside.SendToAsync(Concat(Header(IPAddress.Loopback, 5300), "spoofed"u8.ToArray()), SocketFlags.None, from, deadline.Token);
        // the host it sent to: passed on as it is
        await upstream.Relay.SendToAsync(Concat(Header(IPAddress.Loopback, 5300), "answer"u8.ToArray()), SocketFlags.None, from, deadline.Token);

        var answer = await ReceiveAsync(client, 5000, deadline.Token);
        Assert.Equal(Concat(Header(IPAddress.Loopback, 5300), "answer"u8.ToArray()), answer);
        Assert.Null(await ReceiveAsync(client, 500, deadline.Token));
    }

    [Fact]
    public async Task For_a_name_handed_on_any_host_may_answer_from_that_port()
    {
        using var deadline = Live.Deadline();
        using var upstream = new FakeUdpUpstream();
        using var proxy = new Proxy(UdpThrough(upstream.Port));
        using var control = await proxy.ConnectAsync(deadline.Token);
        var (_, relay) = await UdpAssociateAsync(control.GetStream(), 0, deadline.Token);

        // nothing is looked up here (.invalid never resolves): the name goes to the upstream as it is
        using var client = Live.UdpListener(IPAddress.Loopback);
        await client.SendToAsync(Datagram("relay.example.invalid", 7000, "by name"u8.ToArray()), SocketFlags.None, relay!, deadline.Token);
        var (from, data) = await upstream.FirstAsync(deadline.Token);
        Assert.Equal(Datagram("relay.example.invalid", 7000, "by name"u8.ToArray()), data);

        // the address it had is only the upstream's to know: the port it was sent to is what counts
        await upstream.Relay.SendToAsync(Concat(Header(IPAddress.Parse("203.0.113.9"), 7001), "other port"u8.ToArray()), SocketFlags.None, from, deadline.Token);
        await upstream.Relay.SendToAsync(Concat(Header(IPAddress.Parse("203.0.113.9"), 7000), "answer"u8.ToArray()), SocketFlags.None, from, deadline.Token);
        Assert.Equal(Concat(Header(IPAddress.Parse("203.0.113.9"), 7000), "answer"u8.ToArray()), await ReceiveAsync(client, 5000, deadline.Token));
        Assert.Null(await ReceiveAsync(client, 500, deadline.Token));
    }

    [Fact]
    public async Task The_rules_apply_before_a_datagram_reaches_the_upstream()
    {
        using var deadline = Live.Deadline();
        using var upstream = new FakeUdpUpstream();
        var rules = ProxyRules.Parse(null, "127.0.0.0/8, *.blocked.test", null, out _);
        using var proxy = new Proxy(UdpThrough(upstream.Port, rules: rules));
        using var control = await proxy.ConnectAsync(deadline.Token);
        var (rep, relay) = await UdpAssociateAsync(control.GetStream(), 0, deadline.Token);
        Assert.Equal(0, rep);

        using var client = Live.UdpListener(IPAddress.Loopback);
        await client.SendToAsync(Datagram(IPAddress.Loopback, 5300, "an address"u8.ToArray()), SocketFlags.None, relay!, deadline.Token);
        await client.SendToAsync(Datagram("x.blocked.test", 53, "a name"u8.ToArray()), SocketFlags.None, relay!, deadline.Token);

        Assert.Equal("blocked (rule)", (await proxy.EntryAsync(e => e.Proto == "UDP" && e.Target == "127.0.0.1:5300", deadline.Token)).Status);
        Assert.Equal("blocked (rule)", (await proxy.EntryAsync(e => e.Proto == "UDP" && e.Target == "x.blocked.test:53", deadline.Token)).Status);
        await Task.Delay(200, deadline.Token);
        Assert.Empty(upstream.Got);
    }

    // ------------------------------------------------------------------ where the upstream's relay is

    [Theory]
    [InlineData("127.0.0.1", "127.0.0.1", "127.0.0.1")]          // a proxy program on this device: its relay here too
    [InlineData("127.0.0.1", "0.0.0.0", "127.0.0.1")]            // "where you reached me"
    [InlineData("127.0.0.1", "::", "127.0.0.1")]
    [InlineData("127.0.0.1", null, "127.0.0.1")]                 // a name
    [InlineData("127.0.0.1", "203.0.113.9", "127.0.0.1")]        // a program here naming its public address
    [InlineData("::1", "::1", "::1")]
    [InlineData("192.168.1.5", "192.168.1.5", "192.168.1.5")]
    [InlineData("192.168.1.5", "192.168.1.9", "192.168.1.9")]    // another address on a private network: as near, taken
    [InlineData("192.168.1.5", "127.0.0.1", "192.168.1.5")]      // bound to its loopback: its own side
    [InlineData("192.168.1.5", "203.0.113.9", "192.168.1.5")]    // its public address, from the LAN
    [InlineData("203.0.113.5", "10.0.0.5", "203.0.113.5")]       // behind a NAT
    [InlineData("203.0.113.5", "198.51.100.9", "198.51.100.9")]  // a relay on another server
    [InlineData("2001:db8::5", "fd00::5", "2001:db8::5")]        // a unique local address, from out on the internet
    [InlineData("::ffff:203.0.113.5", "::ffff:0.0.0.0", "203.0.113.5")]
    public void The_upstreams_relay_is_where_it_says_unless_that_cant_be_right_from_here(string hop, string? named, string expected)
        => Assert.Equal(IPAddress.Parse(expected), ProxyServer.ChooseUdpRelay(IPAddress.Parse(hop), named is null ? null : IPAddress.Parse(named), _ => false));

    [Fact]
    public void An_upstream_elsewhere_never_points_the_relay_at_this_device()
    {
        var own = IPAddress.Parse("192.168.1.2");
        bool IsOwn(IPAddress a) => a.Equals(own);
        Assert.Equal(IPAddress.Parse("192.168.1.5"), ProxyServer.ChooseUdpRelay(IPAddress.Parse("192.168.1.5"), own, IsOwn));
        // ...while one on this device may name any address of it
        Assert.Equal(own, ProxyServer.ChooseUdpRelay(IPAddress.Loopback, own, IsOwn));
        Assert.Equal(IPAddress.Loopback, ProxyServer.ChooseUdpRelay(own, IPAddress.Loopback, IsOwn));
    }

    [Fact]
    public void A_link_local_relay_takes_the_upstreams_link()
    {
        var hop = IPAddress.Parse("fe80::1%7");
        var relay = ProxyServer.ChooseUdpRelay(hop, IPAddress.Parse("fe80::2"), _ => false);
        Assert.Equal(7, relay.ScopeId);
        Assert.Equal(IPAddress.Parse("fe80::2%7"), relay);
    }
}
