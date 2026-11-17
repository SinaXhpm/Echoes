using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Echoes.Helpers;
using Echoes.Tests.Support;

namespace Echoes.Tests;

/// <summary>
/// SOCKS5 UDP through the proxy, over this computer's loopback: a UDP echo on 127.0.0.1 stands for a site. Datagrams
/// go through the relay and the answers come back behind the header that names who answered; only the client's own
/// port may use the relay and only hosts it sent to may answer; fragments, rules and a closed TCP connection end
/// what they should. Also the header itself, read without a network. (Through an upstream proxy:
/// ProxyServerTests.UdpUpstream.cs.)
/// </summary>
public partial class ProxyServerTests
{
    /// <summary>A UDP socket on 127.0.0.1 that sends every datagram back to where it came from, and keeps them.</summary>
    private sealed class UdpEcho : IDisposable
    {
        private readonly Socket _socket = Live.UdpListener(IPAddress.Loopback);
        private readonly CancellationTokenSource _stop = new();

        public ConcurrentQueue<(IPEndPoint From, byte[] Data)> Got { get; } = new();
        public int Port => ((IPEndPoint)_socket.LocalEndPoint!).Port;

        public UdpEcho()
        {
            _ = Task.Run(async () =>
            {
                var buf = new byte[65_536];
                while (!_stop.IsCancellationRequested)
                {
                    try
                    {
                        var got = await _socket.ReceiveFromAsync(buf, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), _stop.Token);
                        var data = buf[..got.ReceivedBytes];
                        Got.Enqueue(((IPEndPoint)got.RemoteEndPoint, data));
                        await _socket.SendToAsync(data, SocketFlags.None, got.RemoteEndPoint, _stop.Token);
                    }
                    catch (SocketException) { /* an ICMP answer to an earlier datagram (Windows reports it here) */ }
                    catch (Exception e) when (e is OperationCanceledException or ObjectDisposedException) { return; }
                }
            });
        }

        public void Dispose()
        {
            _stop.Cancel();
            _socket.Dispose();
        }
    }

    /// <summary>SOCKS5 greeting, then UDP ASSOCIATE naming <paramref name="port"/> as the client's (0: not known).
    /// The reply code, and the relay's address when it was granted.</summary>
    private static async Task<(byte Rep, IPEndPoint? Relay)> UdpAssociateAsync(NetworkStream s, int port, CancellationToken ct)
    {
        await s.WriteAsync(new byte[] { 5, 1, 0 }, ct);
        Assert.Equal(new byte[] { 5, 0 }, await ReadAsync(s, 2, ct));
        await s.WriteAsync(new byte[] { 5, 3, 0, 1, 0, 0, 0, 0, (byte)(port >> 8), (byte)port }, ct);
        var reply = await ReadAsync(s, 4, ct);
        Assert.Equal(4, reply.Length);
        Assert.Equal(5, reply[0]);
        int addressLength = reply[3] == 4 ? 16 : 4;
        var rest = await ReadAsync(s, addressLength + 2, ct);
        if (reply[1] != 0) return (reply[1], null);
        return (0, new IPEndPoint(new IPAddress(rest.AsSpan(0, addressLength)), (rest[addressLength] << 8) | rest[addressLength + 1]));
    }

    private static byte[] Datagram(IPAddress to, int port, byte[] data, byte fragment = 0)
    {
        var d = new List<byte> { 0, 0, fragment, (byte)(to.AddressFamily == AddressFamily.InterNetwork ? 1 : 4) };
        d.AddRange(to.GetAddressBytes());
        d.AddRange(PortBytes(port));
        d.AddRange(data);
        return d.ToArray();
    }

    private static byte[] Datagram(string name, int port, byte[] data)
    {
        var d = new List<byte> { 0, 0, 0, 3, (byte)name.Length };
        d.AddRange(Encoding.ASCII.GetBytes(name));
        d.AddRange(PortBytes(port));
        d.AddRange(data);
        return d.ToArray();
    }

    /// <summary>The next datagram within <paramref name="ms"/>, or null.</summary>
    private static async Task<byte[]?> ReceiveAsync(Socket s, int ms, CancellationToken ct)
    {
        using var wait = CancellationTokenSource.CreateLinkedTokenSource(ct);
        wait.CancelAfter(ms);
        var buf = new byte[65_536];
        try
        {
            var got = await s.ReceiveFromAsync(buf, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), wait.Token);
            return buf[..got.ReceivedBytes];
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return null; }
        catch (SocketException) { return null; }   // the relay port is closed (Windows reports the ICMP answer here)
    }

    private static byte[] Header(IPAddress from, int port)
        => new byte[] { 0, 0, 0, 1 }.Concat(from.GetAddressBytes()).Concat(PortBytes(port)).ToArray();

    // ------------------------------------------------------------------ through the relay

    [Fact]
    public async Task Udp_datagrams_go_through_the_relay_and_the_answers_come_back()
    {
        using var deadline = Live.Deadline();
        using var echo = new UdpEcho();
        using var proxy = new Proxy(new ProxyServerOptions { Udp = true });
        using var control = await proxy.ConnectAsync(deadline.Token);

        var (rep, relay) = await UdpAssociateAsync(control.GetStream(), 0, deadline.Token);
        Assert.Equal(0, rep);
        Assert.Equal(IPAddress.Loopback, relay!.Address);   // where the client reached the proxy
        Assert.NotEqual(proxy.Port, relay.Port);

        using var client = Live.UdpListener(IPAddress.Loopback);
        byte[] ping = "a datagram through the relay"u8.ToArray();
        await client.SendToAsync(Datagram(IPAddress.Loopback, echo.Port, ping), SocketFlags.None, relay, deadline.Token);

        var answer = await ReceiveAsync(client, 5000, deadline.Token);
        Assert.NotNull(answer);
        Assert.Equal(Header(IPAddress.Loopback, echo.Port), answer![..10]);   // who answered...
        Assert.Equal(ping, answer[10..]);                                      // ...and what
        Assert.Equal(ping, Assert.Single(echo.Got).Data);                      // the site got the data alone

        var row = await proxy.EntryAsync(e => e.Proto == "UDP", deadline.Token);
        Assert.True(row.Ok);
        Assert.Equal("relayed", row.Status);
        Assert.Equal($"127.0.0.1:{echo.Port}", row.Target);
        Assert.True((await proxy.EntryAsync(e => e.Status == "UDP associate", deadline.Token)).Ok);
        Assert.True(proxy.BytesUp >= ping.Length && proxy.BytesDown >= ping.Length);
    }

    [Fact]
    public async Task A_destination_by_name_is_looked_up_and_answers_name_its_address()
    {
        using var deadline = Live.Deadline();
        using var echo = new UdpEcho();
        // IPv4 only: "localhost" could otherwise come as ::1 first, where the echo doesn't listen
        using var proxy = new Proxy(new ProxyServerOptions { Udp = true, IpVersion = ProxyIpVersion.IPv4 });
        using var control = await proxy.ConnectAsync(deadline.Token);
        var (_, relay) = await UdpAssociateAsync(control.GetStream(), 0, deadline.Token);

        using var client = Live.UdpListener(IPAddress.Loopback);
        byte[] ping = "by name"u8.ToArray();
        await client.SendToAsync(Datagram("localhost", echo.Port, ping), SocketFlags.None, relay!, deadline.Token);

        var answer = await ReceiveAsync(client, 5000, deadline.Token);
        Assert.NotNull(answer);
        Assert.Equal(Header(IPAddress.Loopback, echo.Port), answer![..10]);
        Assert.Equal(ping, answer[10..]);
        Assert.Equal($"localhost:{echo.Port}", (await proxy.EntryAsync(e => e.Proto == "UDP", deadline.Token)).Target);
    }

    [Fact]
    public async Task A_slow_lookup_holds_up_no_other_destination_and_its_datagrams_keep_their_order()
    {
        using var deadline = Live.Deadline();
        using var echo = new UdpEcho();
        var lookedUp = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var proxy = new Proxy(new ProxyServerOptions { Udp = true });
        proxy.LookUp = async (name, ct) =>
        {
            if (name != "slow.test") return await Dns.GetHostAddressesAsync(name, ct);
            await lookedUp.Task.WaitAsync(ct);
            return new[] { IPAddress.Loopback };
        };
        using var control = await proxy.ConnectAsync(deadline.Token);
        var (_, relay) = await UdpAssociateAsync(control.GetStream(), 0, deadline.Token);
        using var client = Live.UdpListener(IPAddress.Loopback);

        // two datagrams to a name whose lookup hasn't ended, then one to an address: that one goes on at once
        await client.SendToAsync(Datagram("slow.test", echo.Port, "first"u8.ToArray()), SocketFlags.None, relay!, deadline.Token);
        await client.SendToAsync(Datagram("slow.test", echo.Port, "second"u8.ToArray()), SocketFlags.None, relay!, deadline.Token);
        await client.SendToAsync(Datagram(IPAddress.Loopback, echo.Port, "by address"u8.ToArray()), SocketFlags.None, relay!, deadline.Token);
        var answer = await ReceiveAsync(client, 5000, deadline.Token);
        Assert.NotNull(answer);
        Assert.Equal("by address"u8.ToArray(), answer![10..]);

        // the lookup ends: the two that waited go on, in the order they came
        lookedUp.SetResult();
        Assert.Equal("first"u8.ToArray(), (await ReceiveAsync(client, 5000, deadline.Token))?[10..]);
        Assert.Equal("second"u8.ToArray(), (await ReceiveAsync(client, 5000, deadline.Token))?[10..]);
        Assert.Equal(new[] { "by address", "first", "second" }, echo.Got.Select(g => Encoding.ASCII.GetString(g.Data)));
        Assert.Equal($"slow.test:{echo.Port}", (await proxy.EntryAsync(e => e.Proto == "UDP" && e.Target.StartsWith("slow"), deadline.Token)).Target);
    }

    [Fact]
    public async Task Only_the_clients_port_may_use_the_relay_and_only_hosts_it_sent_to_may_answer()
    {
        using var deadline = Live.Deadline();
        using var echo = new UdpEcho();
        using var proxy = new Proxy(new ProxyServerOptions { Udp = true });
        using var control = await proxy.ConnectAsync(deadline.Token);
        var (_, relay) = await UdpAssociateAsync(control.GetStream(), 0, deadline.Token);

        // the first datagram fixes the client's port
        using var client = Live.UdpListener(IPAddress.Loopback);
        await client.SendToAsync(Datagram(IPAddress.Loopback, echo.Port, "one"u8.ToArray()), SocketFlags.None, relay!, deadline.Token);
        Assert.NotNull(await ReceiveAsync(client, 5000, deadline.Token));

        // another port of the same address is not the client
        using var other = Live.UdpListener(IPAddress.Loopback);
        await other.SendToAsync(Datagram(IPAddress.Loopback, echo.Port, "two"u8.ToArray()), SocketFlags.None, relay!, deadline.Token);
        Assert.Null(await ReceiveAsync(other, 500, deadline.Token));

        // a host the client never sent to, sending to the relay's own socket (where the echo saw the datagram come
        // from): nothing reaches the client
        var outgoing = echo.Got.First().From;
        using var stranger = Live.UdpListener(IPAddress.Loopback);
        await stranger.SendToAsync("let me in"u8.ToArray(), SocketFlags.None, outgoing, deadline.Token);
        Assert.Null(await ReceiveAsync(client, 500, deadline.Token));

        Assert.Single(echo.Got);   // "two" never left the relay
    }

    [Fact]
    public async Task A_port_the_client_names_is_the_only_one_taken()
    {
        using var deadline = Live.Deadline();
        using var echo = new UdpEcho();
        using var proxy = new Proxy(new ProxyServerOptions { Udp = true });
        using var client = Live.UdpListener(IPAddress.Loopback);
        using var other = Live.UdpListener(IPAddress.Loopback);
        using var control = await proxy.ConnectAsync(deadline.Token);
        var (_, relay) = await UdpAssociateAsync(control.GetStream(), ((IPEndPoint)client.LocalEndPoint!).Port, deadline.Token);

        // the other socket speaks first: not the port the client named
        await other.SendToAsync(Datagram(IPAddress.Loopback, echo.Port, "early"u8.ToArray()), SocketFlags.None, relay!, deadline.Token);
        Assert.Null(await ReceiveAsync(other, 500, deadline.Token));
        await client.SendToAsync(Datagram(IPAddress.Loopback, echo.Port, "named"u8.ToArray()), SocketFlags.None, relay!, deadline.Token);
        Assert.NotNull(await ReceiveAsync(client, 5000, deadline.Token));
        Assert.Equal("named"u8.ToArray(), Assert.Single(echo.Got).Data);
    }

    [Fact]
    public async Task Fragments_are_dropped()
    {
        using var deadline = Live.Deadline();
        using var echo = new UdpEcho();
        using var proxy = new Proxy(new ProxyServerOptions { Udp = true });
        using var control = await proxy.ConnectAsync(deadline.Token);
        var (_, relay) = await UdpAssociateAsync(control.GetStream(), 0, deadline.Token);

        using var client = Live.UdpListener(IPAddress.Loopback);
        await client.SendToAsync(Datagram(IPAddress.Loopback, echo.Port, "part 1"u8.ToArray(), fragment: 1), SocketFlags.None, relay!, deadline.Token);
        Assert.Null(await ReceiveAsync(client, 500, deadline.Token));
        Assert.Empty(echo.Got);
    }

    // ------------------------------------------------------------------ refused, and the end

    [Fact]
    public async Task Udp_is_refused_while_it_is_off_or_the_upstream_cant_carry_it()
    {
        using var deadline = Live.Deadline();

        using (var proxy = new Proxy())   // off unless switched on
        {
            using var control = await proxy.ConnectAsync(deadline.Token);
            Assert.Equal(7, (await UdpAssociateAsync(control.GetStream(), 0, deadline.Token)).Rep);   // command not supported
            Assert.Equal("UDP off", (await proxy.EntryAsync(e => !e.Ok, deadline.Token)).Status);
        }

        // SOCKS4a and HTTP(S) have no UDP, and nothing goes to a site directly while an upstream is set
        using var parent = new Proxy(new ProxyServerOptions { Udp = true });
        foreach (var (address, kind) in new[]
                 {
                     ($"socks4a://127.0.0.1:{parent.Port}", "a SOCKS4a proxy"), ($"http://127.0.0.1:{parent.Port}", "an HTTP proxy"),
                     ($"https://127.0.0.1:{parent.Port}", "an HTTPS proxy"),
                 })
        {
            using var proxy = new Proxy(new ProxyServerOptions { Udp = true, Upstream = UpstreamAt(address) });
            using var control = await proxy.ConnectAsync(deadline.Token);
            Assert.Equal(7, (await UdpAssociateAsync(control.GetStream(), 0, deadline.Token)).Rep);
            var row = await proxy.EntryAsync(e => !e.Ok, deadline.Token);
            Assert.Equal("UDP off (upstream)", row.Status);
            Assert.Contains(kind, row.Detail);
        }
        Assert.Empty(parent.Log);   // and nothing was asked of the upstream
    }

    [Fact]
    public async Task The_rules_and_the_ip_version_apply_to_each_destination()
    {
        using var deadline = Live.Deadline();
        using var echo = new UdpEcho();
        var rules = ProxyRules.Parse(null, "127.0.0.0/8", null, out _);

        using (var proxy = new Proxy(new ProxyServerOptions { Udp = true, Rules = rules }))
        {
            using var control = await proxy.ConnectAsync(deadline.Token);
            var (_, relay) = await UdpAssociateAsync(control.GetStream(), 0, deadline.Token);
            using var client = Live.UdpListener(IPAddress.Loopback);
            await client.SendToAsync(Datagram(IPAddress.Loopback, echo.Port, "blocked"u8.ToArray()), SocketFlags.None, relay!, deadline.Token);
            Assert.Null(await ReceiveAsync(client, 500, deadline.Token));
            var row = await proxy.EntryAsync(e => e.Proto == "UDP", deadline.Token);
            Assert.False(row.Ok);
            Assert.Equal("blocked (rule)", row.Status);
        }

        using (var proxy = new Proxy(new ProxyServerOptions { Udp = true, IpVersion = ProxyIpVersion.IPv6 }))
        {
            using var control = await proxy.ConnectAsync(deadline.Token);
            var (_, relay) = await UdpAssociateAsync(control.GetStream(), 0, deadline.Token);
            using var client = Live.UdpListener(IPAddress.Loopback);
            await client.SendToAsync(Datagram(IPAddress.Loopback, echo.Port, "v4"u8.ToArray()), SocketFlags.None, relay!, deadline.Token);
            Assert.Null(await ReceiveAsync(client, 500, deadline.Token));
            Assert.Equal("no IPv6 address", (await proxy.EntryAsync(e => e.Proto == "UDP", deadline.Token)).Status);
        }
        Assert.Empty(echo.Got);
    }

    [Fact]
    public async Task The_relay_closes_with_the_clients_tcp_connection()
    {
        using var deadline = Live.Deadline();
        using var echo = new UdpEcho();
        using var proxy = new Proxy(new ProxyServerOptions { Udp = true });
        var control = await proxy.ConnectAsync(deadline.Token);
        var (_, relay) = await UdpAssociateAsync(control.GetStream(), 0, deadline.Token);
        using var client = Live.UdpListener(IPAddress.Loopback);
        await client.SendToAsync(Datagram(IPAddress.Loopback, echo.Port, "before"u8.ToArray()), SocketFlags.None, relay!, deadline.Token);
        Assert.NotNull(await ReceiveAsync(client, 5000, deadline.Token));

        control.Dispose();
        while (proxy.Active > 0) await Task.Delay(20, deadline.Token);   // the association has ended

        await client.SendToAsync(Datagram(IPAddress.Loopback, echo.Port, "after"u8.ToArray()), SocketFlags.None, relay!, deadline.Token);
        Assert.Null(await ReceiveAsync(client, 500, deadline.Token));
        Assert.Single(echo.Got);
    }

    // ------------------------------------------------------------------ the header

    [Theory]
    [InlineData(new byte[] { 0, 0, 0, 1, 1, 2, 3, 4, 0, 53, 9 }, "1.2.3.4", 53, 10)]
    [InlineData(new byte[] { 0, 0, 0, 1, 1, 2, 3, 4, 1, 187 }, "1.2.3.4", 443, 10)]   // no data is still a datagram
    [InlineData(new byte[] { 0, 0, 0, 3, 3, (byte)'a', (byte)'.', (byte)'b', 0, 53, 7, 7 }, "a.b", 53, 10)]
    [InlineData(new byte[] { 9, 9, 0, 1, 1, 2, 3, 4, 0, 53 }, "1.2.3.4", 53, 10)]      // RSV is not looked at
    public void A_datagrams_header_names_where_it_goes(byte[] datagram, string host, int port, int dataAt)
    {
        Assert.True(ProxyServer.TryParseUdpHeader(datagram, out string h, out int p, out int at));
        Assert.Equal((host, port, dataAt), (h, p, at));
    }

    [Fact]
    public void A_name_in_another_script_goes_in_a_header_in_its_ascii_form()
    {
        var header = ProxyServer.UdpHeader("bücher.example", 53);
        Assert.True(ProxyServer.TryParseUdpHeader(header, out string host, out int port, out int at));
        Assert.Equal(("xn--bcher-kva.example", 53, header.Length), (host, port, at));
    }

    [Fact]
    public void An_ipv6_destination_is_read_whole()
    {
        var d = new byte[] { 0, 0, 0, 4 }.Concat(IPAddress.Parse("2001:db8::7").GetAddressBytes()).Concat(new byte[] { 0x1F, 0x90, 1 }).ToArray();
        Assert.True(ProxyServer.TryParseUdpHeader(d, out string host, out int port, out int at));
        Assert.Equal(("2001:db8::7", 8080, 22), (host, port, at));
    }

    [Theory]
    [InlineData(new byte[] { })]
    [InlineData(new byte[] { 0, 0, 0 })]
    [InlineData(new byte[] { 0, 0, 1, 1, 1, 2, 3, 4, 0, 53 })]       // a fragment
    [InlineData(new byte[] { 0, 0, 0, 1, 1, 2, 3, 4, 0 })]           // no whole port
    [InlineData(new byte[] { 0, 0, 0, 1, 1, 2, 3, 4, 0, 0 })]        // port 0
    [InlineData(new byte[] { 0, 0, 0, 2, 1, 2, 3, 4, 0, 53 })]       // no such address type
    [InlineData(new byte[] { 0, 0, 0, 3, 0, 0, 53 })]                // an empty name
    [InlineData(new byte[] { 0, 0, 0, 3, 9, (byte)'a', 0, 53 })]     // a name longer than what is there
    [InlineData(new byte[] { 0, 0, 0, 4, 1, 2, 3, 4, 0, 53 })]       // an IPv6 address cut short
    public void What_isnt_a_whole_datagram_is_dropped(byte[] datagram)
        => Assert.False(ProxyServer.TryParseUdpHeader(datagram, out _, out _, out _));
}
