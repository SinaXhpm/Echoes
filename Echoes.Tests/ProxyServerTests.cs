using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Echoes.Helpers;
using Echoes.Tests.Support;

namespace Echoes.Tests;

/// <summary>
/// The proxy server over this computer's loopback: each protocol (SOCKS5, SOCKS4, SOCKS4a, HTTP CONNECT, plain HTTP)
/// carries a connection to a listener on 127.0.0.1, and the server's options do what they say: a protocol switched off,
/// blocked hosts and ports, the IP version, the speed limit, and the outgoing interface (a connection tied to it; none
/// made while it is down, and no fallback to another route).
/// <para>The client here is this computer itself, which the proxy treats as its owner: what it refuses to clients on
/// other devices (and the allowed-clients list, which is about them) is covered by <see cref="ProxyRulesTests"/>.</para>
/// </summary>
[Collection(Live.Collection)]
public partial class ProxyServerTests
{
    // ------------------------------------------------------------------ a proxy, a target, a client

    private sealed class Proxy : IDisposable
    {
        private readonly ProxyServer _server;
        public ConcurrentQueue<ProxyLogEntry> Log { get; } = new();
        public int Port => _server.Port;
        public int Active => _server.ActiveConnections;
        public long BytesUp => _server.BytesUp;
        public long BytesDown => _server.BytesDown;

        /// <summary>Looks target names up in place of the system (a name whose lookup takes its time).</summary>
        public Func<string, CancellationToken, Task<IPAddress[]>>? LookUp
        {
            get => _server.LookUp;
            set => _server.LookUp = value;
        }

        /// <summary>Its clients (this computer, over loopback) count as clients on another device.</summary>
        public bool ClientsAreOthers
        {
            get => _server.ClientsAreOthers;
            set => _server.ClientsAreOthers = value;
        }

        public Proxy(ProxyServerOptions? options = null)
        {
            _server = new ProxyServer(options ?? new ProxyServerOptions(), Log.Enqueue);
            _server.Start(IPAddress.Loopback, 0);
        }

        /// <summary>The log row a connection leaves (written just before or after the reply the client reads).</summary>
        public async Task<ProxyLogEntry> EntryAsync(Func<ProxyLogEntry, bool> which, CancellationToken ct)
        {
            while (true)
            {
                if (Log.FirstOrDefault(which) is { } found) return found;
                await Task.Delay(20, ct);
            }
        }

        public async Task<TcpClient> ConnectAsync(CancellationToken ct)
        {
            var client = new TcpClient(AddressFamily.InterNetwork) { NoDelay = true };
            await client.ConnectAsync(IPAddress.Loopback, Port, ct);
            return client;
        }

        public void Dispose() => _server.Dispose();
    }

    /// <summary>A listener on 127.0.0.1 that sends back what it gets, or (with <paramref name="send"/>) sends that
    /// many bytes and closes.</summary>
    private sealed class Target : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();
        private int _accepted;

        public int Port { get; }
        public int Accepted => Volatile.Read(ref _accepted);

        /// <summary>The count once it has reached <paramref name="atLeast"/> (a connection the proxy reported is
        /// taken off the listener's queue a moment later).</summary>
        public async Task<int> AcceptedAsync(int atLeast, CancellationToken ct)
        {
            while (Accepted < atLeast) await Task.Delay(20, ct);
            return Accepted;
        }

        public Target(int send = 0)
        {
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _ = Task.Run(async () =>
            {
                try
                {
                    while (true)
                    {
                        var client = await _listener.AcceptTcpClientAsync(_stop.Token);
                        Interlocked.Increment(ref _accepted);
                        _ = send > 0 ? SendAsync(client, send) : EchoAsync(client);
                    }
                }
                catch (Exception e) when (e is OperationCanceledException or SocketException or ObjectDisposedException) { }
            });
        }

        private async Task EchoAsync(TcpClient client)
        {
            using (client)
            {
                try
                {
                    var stream = client.GetStream();
                    var buffer = new byte[16 * 1024];
                    int n;
                    while ((n = await stream.ReadAsync(buffer, _stop.Token)) > 0) await stream.WriteAsync(buffer.AsMemory(0, n), _stop.Token);
                }
                catch (Exception e) when (e is OperationCanceledException or IOException or SocketException) { }
            }
        }

        private async Task SendAsync(TcpClient client, int count)
        {
            using (client)
            {
                try
                {
                    var data = new byte[count];
                    new Random(7).NextBytes(data);
                    await client.GetStream().WriteAsync(data, _stop.Token);
                }
                catch (Exception e) when (e is OperationCanceledException or IOException or SocketException) { }
            }
        }

        public void Dispose()
        {
            _stop.Cancel();
            _listener.Stop();
        }
    }

    private static async Task<byte[]> ReadAsync(NetworkStream s, int count, CancellationToken ct)
    {
        var buffer = new byte[count];
        int got = 0;
        while (got < count)
        {
            int n = await s.ReadAsync(buffer.AsMemory(got), ct);
            if (n == 0) break;
            got += n;
        }
        return buffer[..got];
    }

    /// <summary>The whole answer up to the close, as text.</summary>
    private static async Task<string> ReadAllAsync(NetworkStream s, CancellationToken ct)
    {
        using var all = new MemoryStream();
        var buffer = new byte[4096];
        try
        {
            int n;
            while ((n = await s.ReadAsync(buffer, ct)) > 0) all.Write(buffer, 0, n);
        }
        catch (IOException) { /* a reset after the reply: what came is the answer */ }
        return Encoding.Latin1.GetString(all.ToArray());
    }

    private static async Task EchoesAsync(NetworkStream s, CancellationToken ct)
    {
        byte[] ping = "echoes through the proxy"u8.ToArray();
        await s.WriteAsync(ping, ct);
        Assert.Equal(ping, await ReadAsync(s, ping.Length, ct));
    }

    private static byte[] PortBytes(int port) => new[] { (byte)(port >> 8), (byte)port };

    /// <summary>SOCKS5 without a login: greeting, then CONNECT to an address or a name. The reply code (0 = connected).</summary>
    private static async Task<byte> Socks5Async(NetworkStream s, string host, int port, CancellationToken ct)
    {
        await s.WriteAsync(new byte[] { 5, 1, 0 }, ct);
        var method = await ReadAsync(s, 2, ct);
        Assert.Equal(new byte[] { 5, 0 }, method);

        var request = new List<byte> { 5, 1, 0 };
        if (IPAddress.TryParse(host, out var ip))
        {
            request.Add((byte)(ip.AddressFamily == AddressFamily.InterNetwork ? 1 : 4));
            request.AddRange(ip.GetAddressBytes());
        }
        else
        {
            request.Add(3);
            request.Add((byte)host.Length);
            request.AddRange(Encoding.ASCII.GetBytes(host));
        }
        request.AddRange(PortBytes(port));
        await s.WriteAsync(request.ToArray(), ct);

        var reply = await ReadAsync(s, 10, ct);
        Assert.Equal(10, reply.Length);
        Assert.Equal(5, reply[0]);
        return reply[1];
    }

    /// <summary>SOCKS4 (an address) or SOCKS4a (<paramref name="name"/>: the proxy resolves it). The reply code
    /// (0x5A = granted, 0x5B = rejected).</summary>
    private static async Task<byte> Socks4Async(NetworkStream s, int port, string? name, CancellationToken ct, string user = "tester", byte[]? extra = null)
    {
        var request = new List<byte> { 4, 1 };
        request.AddRange(PortBytes(port));
        request.AddRange(name is null ? IPAddress.Loopback.GetAddressBytes() : new byte[] { 0, 0, 0, 1 });
        request.AddRange(Encoding.ASCII.GetBytes(user));
        request.Add(0);
        if (name is not null)
        {
            request.AddRange(Encoding.ASCII.GetBytes(name));
            request.Add(0);
        }
        if (extra is not null) request.AddRange(extra);
        await s.WriteAsync(request.ToArray(), ct);

        var reply = await ReadAsync(s, 8, ct);
        Assert.Equal(8, reply.Length);
        Assert.Equal(0, reply[0]);
        return reply[1];
    }

    /// <summary>An HTTP request head to the proxy; the answer's head (through its blank line).</summary>
    private static async Task<string> HttpHeadAsync(NetworkStream s, string request, CancellationToken ct)
    {
        await s.WriteAsync(Encoding.ASCII.GetBytes(request), ct);
        var head = new StringBuilder();
        var one = new byte[1];
        while (!head.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal))
        {
            if (await s.ReadAsync(one, ct) == 0) break;
            head.Append((char)one[0]);
        }
        return head.ToString();
    }

    // ------------------------------------------------------------------ the protocols

    [Fact]
    public async Task Socks5_carries_a_connection_to_an_address_and_to_a_name()
    {
        using var deadline = Live.Deadline();
        using var target = new Target();
        using var proxy = new Proxy();

        using (var client = await proxy.ConnectAsync(deadline.Token))
        {
            var s = client.GetStream();
            Assert.Equal(0, await Socks5Async(s, "127.0.0.1", target.Port, deadline.Token));
            await EchoesAsync(s, deadline.Token);
        }
        using (var client = await proxy.ConnectAsync(deadline.Token))
        {
            var s = client.GetStream();
            Assert.Equal(0, await Socks5Async(s, "localhost", target.Port, deadline.Token));
            await EchoesAsync(s, deadline.Token);
        }

        var row = await proxy.EntryAsync(e => e.Target == $"localhost:{target.Port}", deadline.Token);
        Assert.Equal("SOCKS5", row.Proto);
        Assert.True(row.Ok);
        Assert.Equal("connected", row.Status);
        Assert.Equal("127.0.0.1", row.Client);
    }

    [Fact]
    public async Task Socks4_carries_a_connection_to_an_address()
    {
        using var deadline = Live.Deadline();
        using var target = new Target();
        using var proxy = new Proxy();
        using var client = await proxy.ConnectAsync(deadline.Token);
        var s = client.GetStream();

        Assert.Equal(0x5A, await Socks4Async(s, target.Port, null, deadline.Token));
        await EchoesAsync(s, deadline.Token);

        var row = await proxy.EntryAsync(e => e.Proto == "SOCKS4", deadline.Token);
        Assert.True(row.Ok);
        Assert.Equal($"127.0.0.1:{target.Port}", row.Target);
        Assert.Equal("tester", row.User);
    }

    [Fact]
    public async Task Socks4a_has_the_proxy_resolve_the_name()
    {
        using var deadline = Live.Deadline();
        using var target = new Target();
        using var proxy = new Proxy();
        using var client = await proxy.ConnectAsync(deadline.Token);
        var s = client.GetStream();

        Assert.Equal(0x5A, await Socks4Async(s, target.Port, "localhost", deadline.Token, user: ""));
        await EchoesAsync(s, deadline.Token);

        var row = await proxy.EntryAsync(e => e.Proto == "SOCKS4a", deadline.Token);
        Assert.True(row.Ok);
        Assert.Equal($"localhost:{target.Port}", row.Target);
        Assert.Equal("—", row.User);
    }

    [Fact]
    public async Task What_a_socks4_client_sends_right_behind_its_request_reaches_the_target()
    {
        using var deadline = Live.Deadline();
        using var target = new Target();
        using var proxy = new Proxy();
        using var client = await proxy.ConnectAsync(deadline.Token);
        var s = client.GetStream();

        byte[] early = "sent before the reply"u8.ToArray();
        Assert.Equal(0x5A, await Socks4Async(s, target.Port, null, deadline.Token, extra: early));
        Assert.Equal(early, await ReadAsync(s, early.Length, deadline.Token));   // the echo of it
    }

    [Fact]
    public async Task Socks4_asks_for_things_the_proxy_doesnt_do_and_is_rejected()
    {
        using var deadline = Live.Deadline();
        using var proxy = new Proxy();

        // BIND (command 2)
        using (var client = await proxy.ConnectAsync(deadline.Token))
        {
            var s = client.GetStream();
            await s.WriteAsync(new byte[] { 4, 2, 0, 80, 127, 0, 0, 1, 0 }, deadline.Token);
            var reply = await ReadAsync(s, 8, deadline.Token);
            Assert.Equal(0x5B, reply[1]);
        }
        // a user id with no end
        using (var client = await proxy.ConnectAsync(deadline.Token))
        {
            var s = client.GetStream();
            var endless = new byte[600];
            Array.Fill(endless, (byte)'u');
            new byte[] { 4, 1, 0, 80, 127, 0, 0, 1 }.CopyTo(endless, 0);
            await s.WriteAsync(endless, deadline.Token);
            var reply = await ReadAsync(s, 8, deadline.Token);
            Assert.Equal(0x5B, reply[1]);
        }
    }

    [Fact]
    public async Task Http_connect_opens_a_tunnel()
    {
        using var deadline = Live.Deadline();
        using var target = new Target();
        using var proxy = new Proxy();
        using var client = await proxy.ConnectAsync(deadline.Token);
        var s = client.GetStream();

        string head = await HttpHeadAsync(s, $"CONNECT 127.0.0.1:{target.Port} HTTP/1.1\r\nHost: 127.0.0.1:{target.Port}\r\n\r\n", deadline.Token);
        Assert.StartsWith("HTTP/1.1 200", head);
        await EchoesAsync(s, deadline.Token);

        var row = await proxy.EntryAsync(e => e.Proto == "HTTPS", deadline.Token);
        Assert.True(row.Ok);
    }

    [Fact]
    public async Task A_connection_nothing_answers_is_reported_in_each_protocols_words()
    {
        using var deadline = Live.Deadline();
        using var proxy = new Proxy();
        int closed = Live.ClosedTcpPort(IPAddress.Loopback);

        using (var client = await proxy.ConnectAsync(deadline.Token))
            Assert.Equal(5, await Socks5Async(client.GetStream(), "127.0.0.1", closed, deadline.Token));   // connection refused
        using (var client = await proxy.ConnectAsync(deadline.Token))
            Assert.Equal(0x5B, await Socks4Async(client.GetStream(), closed, null, deadline.Token));
        using (var client = await proxy.ConnectAsync(deadline.Token))
        {
            string answer = await HttpHeadAsync(client.GetStream(), $"CONNECT 127.0.0.1:{closed} HTTP/1.1\r\n\r\n", deadline.Token);
            Assert.StartsWith("HTTP/1.1 502", answer);
        }

        var row = await proxy.EntryAsync(e => e.Proto == "SOCKS5", deadline.Token);
        Assert.False(row.Ok);
        Assert.Equal("refused", row.Status);
    }

    // ------------------------------------------------------------------ protocols switched off, a login required

    [Fact]
    public async Task A_protocol_switched_off_is_refused_in_its_own_words()
    {
        using var deadline = Live.Deadline();
        using var target = new Target();

        using (var proxy = new Proxy(new ProxyServerOptions { Socks5 = false }))
        {
            using var client = await proxy.ConnectAsync(deadline.Token);
            var s = client.GetStream();
            await s.WriteAsync(new byte[] { 5, 1, 0 }, deadline.Token);
            Assert.Equal(new byte[] { 5, 0xFF }, await ReadAsync(s, 2, deadline.Token));
            Assert.Equal("protocol off", (await proxy.EntryAsync(e => e.Proto == "SOCKS5", deadline.Token)).Status);

            // ...and the others still answer on the same port
            using var other = await proxy.ConnectAsync(deadline.Token);
            Assert.Equal(0x5A, await Socks4Async(other.GetStream(), target.Port, null, deadline.Token));
        }

        using (var proxy = new Proxy(new ProxyServerOptions { Socks4 = false }))
        {
            using var client = await proxy.ConnectAsync(deadline.Token);
            Assert.Equal(0x5B, await Socks4Async(client.GetStream(), target.Port, null, deadline.Token));
            Assert.Equal("protocol off", (await proxy.EntryAsync(e => e.Proto == "SOCKS4", deadline.Token)).Status);

            using var other = await proxy.ConnectAsync(deadline.Token);
            Assert.Equal(0, await Socks5Async(other.GetStream(), "127.0.0.1", target.Port, deadline.Token));
        }

        using (var proxy = new Proxy(new ProxyServerOptions { Http = false }))
        {
            using var client = await proxy.ConnectAsync(deadline.Token);
            string answer = await ReadAllAsync(await SendAsync(client, $"CONNECT 127.0.0.1:{target.Port} HTTP/1.1\r\n\r\n", deadline.Token), deadline.Token);
            Assert.StartsWith("HTTP/1.1 403", answer);
            Assert.Contains("switched off", answer);
            Assert.Equal("protocol off", (await proxy.EntryAsync(e => e.Proto == "HTTP", deadline.Token)).Status);
        }
        Assert.Equal(2, await target.AcceptedAsync(2, deadline.Token));   // only the two that were let through
    }

    private static async Task<NetworkStream> SendAsync(TcpClient client, string text, CancellationToken ct)
    {
        var s = client.GetStream();
        await s.WriteAsync(Encoding.ASCII.GetBytes(text), ct);
        return s;
    }

    [Fact]
    public async Task Socks4_has_no_password_so_a_proxy_that_requires_one_refuses_it()
    {
        using var deadline = Live.Deadline();
        using var target = new Target();
        using var proxy = new Proxy(new ProxyServerOptions { User = "echoes", Pass = "s3cret-for-the-test" });
        using var client = await proxy.ConnectAsync(deadline.Token);

        Assert.Equal(0x5B, await Socks4Async(client.GetStream(), target.Port, null, deadline.Token, user: "echoes"));

        var row = await proxy.EntryAsync(e => e.Proto == "SOCKS4", deadline.Token);
        Assert.False(row.Ok);
        Assert.Equal("no password login", row.Status);
        Assert.Contains("SOCKS5 or HTTP", row.Detail);
        Assert.Equal(0, target.Accepted);
    }

    // ------------------------------------------------------------------ rules

    [Fact]
    public async Task A_blocked_host_is_refused_by_name_and_by_address()
    {
        using var deadline = Live.Deadline();
        using var target = new Target();
        var rules = ProxyRules.Parse(null, "localhost, 127.0.0.0/8", null, out string? problem);
        Assert.Null(problem);
        using var proxy = new Proxy(new ProxyServerOptions { Rules = rules });

        using (var client = await proxy.ConnectAsync(deadline.Token))
            Assert.Equal(2, await Socks5Async(client.GetStream(), "localhost", target.Port, deadline.Token));   // not allowed by ruleset
        using (var client = await proxy.ConnectAsync(deadline.Token))
            Assert.Equal(2, await Socks5Async(client.GetStream(), "127.0.0.1", target.Port, deadline.Token));
        using (var client = await proxy.ConnectAsync(deadline.Token))
            Assert.Equal(0x5B, await Socks4Async(client.GetStream(), target.Port, null, deadline.Token));
        using (var client = await proxy.ConnectAsync(deadline.Token))
        {
            string answer = await ReadAllAsync(await SendAsync(client, $"CONNECT LocalHost:{target.Port} HTTP/1.1\r\n\r\n", deadline.Token), deadline.Token);
            Assert.StartsWith("HTTP/1.1 403", answer);
            Assert.Contains("blocked by the proxy's rules", answer);
        }

        var row = await proxy.EntryAsync(e => e.Target == $"localhost:{target.Port}", deadline.Token);
        Assert.False(row.Ok);
        Assert.Equal("blocked (rule)", row.Status);
        Assert.Equal(0, target.Accepted);
    }

    [Fact]
    public async Task A_name_is_refused_when_every_address_it_has_is_blocked()
    {
        using var deadline = Live.Deadline();
        using var target = new Target();
        // not the name: the addresses it resolves to
        var rules = ProxyRules.Parse(null, "127.0.0.0/8 ::1", null, out _);
        using var proxy = new Proxy(new ProxyServerOptions { Rules = rules });
        using var client = await proxy.ConnectAsync(deadline.Token);

        Assert.Equal(2, await Socks5Async(client.GetStream(), "localhost", target.Port, deadline.Token));
        Assert.Equal(0, target.Accepted);
    }

    [Fact]
    public async Task Only_allowed_ports_are_reached()
    {
        using var deadline = Live.Deadline();
        using var target = new Target();
        using var other = new Target();
        var rules = ProxyRules.Parse(null, null, target.Port.ToString(), out _);
        using var proxy = new Proxy(new ProxyServerOptions { Rules = rules });

        using (var client = await proxy.ConnectAsync(deadline.Token))
        {
            var s = client.GetStream();
            Assert.Equal(0, await Socks5Async(s, "127.0.0.1", target.Port, deadline.Token));
            await EchoesAsync(s, deadline.Token);
        }
        using (var client = await proxy.ConnectAsync(deadline.Token))
            Assert.Equal(2, await Socks5Async(client.GetStream(), "127.0.0.1", other.Port, deadline.Token));

        var row = await proxy.EntryAsync(e => !e.Ok, deadline.Token);
        Assert.Equal("blocked (port)", row.Status);
        Assert.Equal(0, other.Accepted);
    }

    // ------------------------------------------------------------------ IP version

    [Fact]
    public async Task Ipv6_only_connects_to_no_ipv4_address()
    {
        using var deadline = Live.Deadline();
        using var target = new Target();   // listens on 127.0.0.1 only
        using var proxy = new Proxy(new ProxyServerOptions { IpVersion = ProxyIpVersion.IPv6 });
        using var client = await proxy.ConnectAsync(deadline.Token);

        Assert.Equal(3, await Socks5Async(client.GetStream(), "127.0.0.1", target.Port, deadline.Token));   // network unreachable

        var row = await proxy.EntryAsync(e => !e.Ok, deadline.Token);
        Assert.Equal("no IPv6 address", row.Status);
        Assert.Contains("IPv6 only", row.Detail);
        Assert.Equal(0, target.Accepted);
    }

    [Fact]
    public async Task Ipv4_only_takes_a_names_ipv4_address()
    {
        using var deadline = Live.Deadline();
        using var target = new Target();
        using var proxy = new Proxy(new ProxyServerOptions { IpVersion = ProxyIpVersion.IPv4 });

        using (var client = await proxy.ConnectAsync(deadline.Token))
        {
            var s = client.GetStream();
            Assert.Equal(0, await Socks5Async(s, "localhost", target.Port, deadline.Token));
            await EchoesAsync(s, deadline.Token);
        }
        using (var client = await proxy.ConnectAsync(deadline.Token))
            Assert.Equal(3, await Socks5Async(client.GetStream(), "::1", target.Port, deadline.Token));
    }

    // ------------------------------------------------------------------ the outgoing interface

    [Fact]
    public async Task A_connection_tied_to_the_loopback_interface_reaches_a_listener_on_it()
    {
        var lo = Live.LoopbackForSockets();
        using var deadline = Live.Deadline();
        using var target = new Target();

        using var remote = await ProxyServer.ConnectOutAsync(IPAddress.Loopback, target.Port, lo, deadline.Token);
        Assert.Equal(IPAddress.Loopback, ((IPEndPoint)remote.Client.LocalEndPoint!).Address);
        await EchoesAsync(remote.GetStream(), deadline.Token);
    }

    private static readonly NetIface Gone =
        new("echoes-none0", "gone", "{00000000-0000-0000-0000-000000000000}", 987654, IPAddress.Parse("192.0.2.77"), null, null, false) { Prefix4 = 24 };

    [Fact]
    public async Task A_connection_that_cant_be_tied_to_its_interface_is_not_made()
    {
        using var deadline = Live.Deadline();
        using var target = new Target();

        // not connected some other way: the listener is right here on the default route
        var ex = await Assert.ThrowsAsync<ProxyServer.ProxyRouteException>(
            () => ProxyServer.ConnectOutAsync(IPAddress.Loopback, target.Port, Gone, deadline.Token));
        Assert.Contains("echoes-none0", ex.Detail);
        await Task.Delay(100, deadline.Token);
        Assert.Equal(0, target.Accepted);
    }

    [Fact]
    public async Task An_interface_without_an_address_of_the_targets_kind_is_said_so()
    {
        using var deadline = Live.Deadline();
        // (the test's interface has an IPv4 address only)
        var ex = await Assert.ThrowsAsync<ProxyServer.ProxyRouteException>(
            () => ProxyServer.ConnectOutAsync(IPAddress.IPv6Loopback, 80, Gone, deadline.Token));
        Assert.Equal("no IPv6 on interface", ex.Status);
        Assert.Contains("echoes-none0 has no IPv6 address", ex.Detail);
    }

    [Fact]
    public async Task While_the_outgoing_interface_is_down_nothing_leaves_and_the_client_is_told()
    {
        using var deadline = Live.Deadline();
        using var proxy = new Proxy(new ProxyServerOptions { OutInterface = "echoes-no-such-interface" });

        // 192.0.2.1 (TEST-NET-1) stands for a site: with the interface down the proxy answers at once, without trying
        var clock = Stopwatch.StartNew();
        using (var client = await proxy.ConnectAsync(deadline.Token))
            Assert.Equal(3, await Socks5Async(client.GetStream(), "192.0.2.1", 80, deadline.Token));   // network unreachable
        using (var client = await proxy.ConnectAsync(deadline.Token))
        {
            string answer = await ReadAllAsync(await SendAsync(client, "CONNECT 192.0.2.1:443 HTTP/1.1\r\n\r\n", deadline.Token), deadline.Token);
            Assert.StartsWith("HTTP/1.1 502", answer);
            Assert.Contains("interface down", answer);
        }
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(8), $"took {clock.Elapsed.TotalSeconds:0.0} s: it tried to connect");

        var row = await proxy.EntryAsync(e => e.Proto == "SOCKS5", deadline.Token);
        Assert.False(row.Ok);
        Assert.Equal("interface down", row.Status);
        Assert.Contains("echoes-no-such-interface isn't connected", row.Detail);
        Assert.Contains("echoes-no-such-interface", row.Tip);
    }

    [Fact]
    public async Task A_target_on_this_computer_is_reached_whatever_the_outgoing_interface()
    {
        using var deadline = Live.Deadline();
        using var target = new Target();
        // it never leaves the computer, so the interface (here: one that is down) has no say
        using var proxy = new Proxy(new ProxyServerOptions { OutInterface = "echoes-no-such-interface" });
        using var client = await proxy.ConnectAsync(deadline.Token);
        var s = client.GetStream();

        Assert.Equal(0, await Socks5Async(s, "127.0.0.1", target.Port, deadline.Token));
        await EchoesAsync(s, deadline.Token);
    }

    // ------------------------------------------------------------------ limits

    [Fact]
    public async Task A_speed_limit_paces_a_download()
    {
        using var deadline = Live.Deadline(40);
        const int limit = 64 * 1024, size = 4 * limit;
        using var target = new Target(send: size);
        using var proxy = new Proxy(new ProxyServerOptions { SpeedLimit = limit });
        using var client = await proxy.ConnectAsync(deadline.Token);
        var s = client.GetStream();

        Assert.Equal(0, await Socks5Async(s, "127.0.0.1", target.Port, deadline.Token));
        var clock = Stopwatch.StartNew();
        var got = await ReadAsync(s, size, deadline.Token);
        clock.Stop();

        Assert.Equal(size, got.Length);
        var expected = new byte[size];
        new Random(7).NextBytes(expected);
        Assert.Equal(expected, got);
        // four seconds' worth, less the quarter second that passes at once: never under 2 s, whatever the computer's speed
        Assert.True(clock.Elapsed >= TimeSpan.FromSeconds(2), $"{size} bytes came in {clock.Elapsed.TotalSeconds:0.00} s at a limit of {limit} a second");
    }

    [Fact]
    public async Task A_tunnel_waiting_its_turn_under_the_speed_limit_is_not_idle()
    {
        // Nine tunnels send 1 KB each at once under a limit of 1 KB a second, with the shortest idle time (5 s): the last
        // ones wait their turn for up to eight seconds. Meanwhile each target says a byte back, which is traffic too and
        // sets the idle deadline again from then. That must not cut off a tunnel still waiting to send.
        using var deadline = Live.Deadline(40);
        const int tunnels = 9, size = 1024;
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var clients = new List<TcpClient>();
        try
        {
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var received = Task.Run(async () =>
            {
                var sinks = new List<Task<int>>();
                for (int i = 0; i < tunnels; i++) sinks.Add(SinkAsync(await listener.AcceptTcpClientAsync(deadline.Token)));
                return await Task.WhenAll(sinks);
            });
            using var proxy = new Proxy(new ProxyServerOptions { SpeedLimit = size, IdleTimeoutMs = 5000 });
            for (int i = 0; i < tunnels; i++)
            {
                var client = await proxy.ConnectAsync(deadline.Token);
                clients.Add(client);
                Assert.Equal(0, await Socks5Async(client.GetStream(), "127.0.0.1", port, deadline.Token));
            }
            var data = new byte[size];
            foreach (var client in clients) await client.GetStream().WriteAsync(data, deadline.Token);
            Assert.All(await received, got => Assert.Equal(size, got));
        }
        finally
        {
            foreach (var client in clients) client.Dispose();
            listener.Stop();
        }

        // What a tunnel brings, up to the 1 KB; a little over a second after it opened, a byte back.
        async Task<int> SinkAsync(TcpClient target)
        {
            using (target)
            {
                var s = target.GetStream();
                var say = Task.Run(async () =>
                {
                    await Task.Delay(1200, deadline.Token);
                    await s.WriteAsync(new byte[] { 1 }, deadline.Token);
                });
                int total = 0;
                var buffer = new byte[4096];
                try
                {
                    int n;
                    while (total < size && (n = await s.ReadAsync(buffer, deadline.Token)) > 0) total += n;
                }
                catch (IOException) { /* cut off */ }
                try { await say; }
                catch (Exception e) when (e is IOException or OperationCanceledException or ObjectDisposedException) { }
                return total;
            }
        }
    }

    [Fact]
    public async Task Without_a_limit_the_same_download_is_not_paced()
    {
        using var deadline = Live.Deadline(40);
        const int size = 4 * 64 * 1024;
        using var target = new Target(send: size);
        using var proxy = new Proxy();
        using var client = await proxy.ConnectAsync(deadline.Token);
        var s = client.GetStream();

        Assert.Equal(0, await Socks5Async(s, "127.0.0.1", target.Port, deadline.Token));
        var clock = Stopwatch.StartNew();
        var got = await ReadAsync(s, size, deadline.Token);
        Assert.Equal(size, got.Length);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(2), $"took {clock.Elapsed.TotalSeconds:0.00} s");
    }

    [Fact]
    public void The_port_the_system_gave_is_known()
    {
        using var proxy = new Proxy();
        Assert.InRange(proxy.Port, 1, 65535);
    }
}
