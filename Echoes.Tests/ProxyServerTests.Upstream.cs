using System.Net;
using System.Net.Sockets;
using System.Text;
using Echoes.Helpers;
using Echoes.Tests.Support;

namespace Echoes.Tests;

/// <summary>
/// The proxy server with an upstream proxy: a second proxy on this computer's loopback stands in for it, so what it is
/// asked for shows in its own log. Each kind (SOCKS5, SOCKS4a, HTTP) with and without a login, plain http:// handed to
/// an HTTP upstream as a proxy request, names passed on or looked up here, and an upstream that is down or refuses.
/// </summary>
public partial class ProxyServerTests
{
    private static ProxyUpstream UpstreamAt(string address, string? user = null, string? pass = null, bool resolve = true)
    {
        var up = ProxyUpstream.Parse(address, user, pass, resolve, out string? problem);
        Assert.True(up is not null, problem);
        return up!;
    }

    private static ProxyServerOptions Through(ProxyUpstream upstream, ProxyIpVersion ipVersion = ProxyIpVersion.Auto)
        => new() { Upstream = upstream, IpVersion = ipVersion };

    /// <summary>A web server on 127.0.0.1 that answers each request with its request line and Host header.</summary>
    private sealed class HttpOrigin : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();

        public int Port { get; }

        public HttpOrigin()
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
                        _ = AnswerAsync(client);
                    }
                }
                catch (Exception e) when (e is OperationCanceledException or SocketException or ObjectDisposedException) { }
            });
        }

        private async Task AnswerAsync(TcpClient client)
        {
            using (client)
            {
                try
                {
                    var s = client.GetStream();
                    var head = new StringBuilder();
                    var one = new byte[1];
                    while (!head.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal) && await s.ReadAsync(one, _stop.Token) > 0)
                        head.Append((char)one[0]);
                    var lines = head.ToString().Split("\r\n");
                    string host = lines.FirstOrDefault(l => l.StartsWith("Host:", StringComparison.OrdinalIgnoreCase)) ?? "no Host header";
                    byte[] body = Encoding.ASCII.GetBytes(lines[0] + "\n" + host + "\n");
                    await s.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n"), _stop.Token);
                    await s.WriteAsync(body, _stop.Token);
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

    // ------------------------------------------------------------------ the kinds of upstream

    [Fact]
    public async Task A_socks5_upstream_carries_the_connections_and_is_handed_the_name()
    {
        using var deadline = Live.Deadline();
        using var target = new Target();
        using var parent = new Proxy();
        using var proxy = new Proxy(Through(UpstreamAt($"socks5://127.0.0.1:{parent.Port}")));

        using (var client = await proxy.ConnectAsync(deadline.Token))
        {
            var s = client.GetStream();
            Assert.Equal(0, await Socks5Async(s, "localhost", target.Port, deadline.Token));
            await EchoesAsync(s, deadline.Token);
        }

        // the upstream was asked for the name itself: nothing was looked up here
        var asked = await parent.EntryAsync(e => e.Proto == "SOCKS5" && e.Ok, deadline.Token);
        Assert.Equal($"localhost:{target.Port}", asked.Target);
        var row = await proxy.EntryAsync(e => e.Proto == "SOCKS5", deadline.Token);
        Assert.True(row.Ok);
        Assert.Equal("connected", row.Status);
    }

    [Fact]
    public async Task An_upstream_that_wants_a_login_gets_it()
    {
        using var deadline = Live.Deadline();
        using var target = new Target();
        using var parent = new Proxy(new ProxyServerOptions { User = "chain", Pass = "upstream-pass-for-the-test" });

        using (var proxy = new Proxy(Through(UpstreamAt($"socks5://127.0.0.1:{parent.Port}", "chain", "upstream-pass-for-the-test"))))
        using (var client = await proxy.ConnectAsync(deadline.Token))
        {
            var s = client.GetStream();
            Assert.Equal(0, await Socks5Async(s, "127.0.0.1", target.Port, deadline.Token));
            await EchoesAsync(s, deadline.Token);
            Assert.Equal("chain", (await parent.EntryAsync(e => e.Ok, deadline.Token)).User);
        }

        // a wrong one: the client is refused, and the log says it was the upstream's login
        using (var proxy = new Proxy(Through(UpstreamAt($"socks5://127.0.0.1:{parent.Port}", "chain", "wrong"))))
        {
            using var client = await proxy.ConnectAsync(deadline.Token);
            Assert.NotEqual(0, await Socks5Async(client.GetStream(), "127.0.0.1", target.Port, deadline.Token));
            var row = await proxy.EntryAsync(e => !e.Ok, deadline.Token);
            Assert.Equal("upstream login", row.Status);
            Assert.Contains("refused the user name and password", row.Detail);
            Assert.DoesNotContain("wrong", row.Detail);
        }
        // (and without one at all)
        using (var proxy = new Proxy(Through(UpstreamAt($"socks5://127.0.0.1:{parent.Port}"))))
        {
            using var client = await proxy.ConnectAsync(deadline.Token);
            Assert.NotEqual(0, await Socks5Async(client.GetStream(), "127.0.0.1", target.Port, deadline.Token));
            Assert.Equal("upstream login", (await proxy.EntryAsync(e => !e.Ok, deadline.Token)).Status);
        }
    }

    [Fact]
    public async Task A_socks4a_upstream_is_handed_the_name()
    {
        using var deadline = Live.Deadline();
        using var target = new Target();
        using var parent = new Proxy();
        using var proxy = new Proxy(Through(UpstreamAt($"socks4a://127.0.0.1:{parent.Port}")));
        using var client = await proxy.ConnectAsync(deadline.Token);
        var s = client.GetStream();

        Assert.Equal(0, await Socks5Async(s, "localhost", target.Port, deadline.Token));
        await EchoesAsync(s, deadline.Token);
        var asked = await parent.EntryAsync(e => e.Ok, deadline.Token);
        Assert.Equal("SOCKS4a", asked.Proto);
        Assert.Equal($"localhost:{target.Port}", asked.Target);
    }

    [Fact]
    public async Task An_http_upstream_opens_tunnels_with_its_login()
    {
        using var deadline = Live.Deadline();
        using var target = new Target();
        using var parent = new Proxy(new ProxyServerOptions { User = "chain", Pass = "http-upstream-pass" });
        using var proxy = new Proxy(Through(UpstreamAt($"http://127.0.0.1:{parent.Port}", "chain", "http-upstream-pass")));

        // a SOCKS client and an HTTP CONNECT client alike
        using (var client = await proxy.ConnectAsync(deadline.Token))
        {
            var s = client.GetStream();
            Assert.Equal(0, await Socks5Async(s, "127.0.0.1", target.Port, deadline.Token));
            await EchoesAsync(s, deadline.Token);
        }
        using (var client = await proxy.ConnectAsync(deadline.Token))
        {
            var s = client.GetStream();
            Assert.StartsWith("HTTP/1.1 200", await HttpHeadAsync(s, $"CONNECT 127.0.0.1:{target.Port} HTTP/1.1\r\n\r\n", deadline.Token));
            await EchoesAsync(s, deadline.Token);
        }

        var asked = await parent.EntryAsync(e => e.Ok, deadline.Token);
        Assert.Equal("HTTPS", asked.Proto);   // CONNECT, at the upstream
        Assert.Equal("tunnel", asked.Status);
        Assert.Equal("chain", asked.User);
    }

    [Fact]
    public async Task Plain_http_goes_to_an_http_upstream_as_a_proxy_request()
    {
        using var deadline = Live.Deadline();
        using var origin = new HttpOrigin();
        using var parent = new Proxy();
        using var proxy = new Proxy(Through(UpstreamAt($"http://127.0.0.1:{parent.Port}")));
        using var client = await proxy.ConnectAsync(deadline.Token);

        string answer = await ReadAllAsync(await SendAsync(client,
            $"GET http://localhost:{origin.Port}/hello?x=1 HTTP/1.1\r\nHost: localhost:{origin.Port}\r\nUser-Agent: test\r\n\r\n", deadline.Token), deadline.Token);

        Assert.StartsWith("HTTP/1.1 200", answer);
        // the origin got the request as an origin does: its path, and the Host the client wrote
        Assert.Contains("GET /hello?x=1 HTTP/1.1\n", answer);
        Assert.Contains($"Host: localhost:{origin.Port}\n", answer);
        // ...through the upstream as a proxy request (not a CONNECT tunnel: many HTTP proxies tunnel to 443 only)
        var asked = await parent.EntryAsync(e => e.Ok, deadline.Token);
        Assert.Equal("HTTP", asked.Proto);
        Assert.Equal("forward", asked.Status);
        Assert.Equal($"localhost:{origin.Port}/hello", asked.Target);
    }

    [Fact]
    public async Task An_http_upstream_refusing_its_login_on_plain_http_is_a_gateway_error_not_a_login_prompt()
    {
        using var deadline = Live.Deadline();
        using var origin = new HttpOrigin();
        using var parent = new Proxy(new ProxyServerOptions { User = "chain", Pass = "right" });
        using var proxy = new Proxy(Through(UpstreamAt($"http://127.0.0.1:{parent.Port}", "chain", "wrong")));
        using var client = await proxy.ConnectAsync(deadline.Token);

        string answer = await ReadAllAsync(await SendAsync(client, $"GET http://127.0.0.1:{origin.Port}/ HTTP/1.1\r\n\r\n", deadline.Token), deadline.Token);
        Assert.StartsWith("HTTP/1.1 502", answer);
        Assert.DoesNotContain("Proxy-Authenticate", answer);
    }

    // ------------------------------------------------------------------ names, and an upstream that isn't there

    [Fact]
    public async Task Names_are_looked_up_here_when_the_upstream_may_not_do_it()
    {
        using var deadline = Live.Deadline();
        using var target = new Target();
        using var parent = new Proxy();
        using var proxy = new Proxy(Through(UpstreamAt($"socks5://127.0.0.1:{parent.Port}", resolve: false)));
        using var client = await proxy.ConnectAsync(deadline.Token);
        var s = client.GetStream();

        // (localhost may come as ::1 first, where nothing listens: the next address is tried, through the upstream too)
        Assert.Equal(0, await Socks5Async(s, "localhost", target.Port, deadline.Token));
        await EchoesAsync(s, deadline.Token);

        Assert.Equal($"127.0.0.1:{target.Port}", (await parent.EntryAsync(e => e.Ok, deadline.Token)).Target);
        Assert.DoesNotContain(parent.Log, e => e.Target.StartsWith("localhost", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_client_on_another_device_gets_no_name_past_the_vetting_through_a_near_upstream_password_or_not()
    {
        // An upstream on this device would look "localhost" up as this device's own loopback. For a client on another
        // device the name is looked up and vetted here, as without an upstream: its password chooses who may connect,
        // and lets it reach nothing more.
        using var deadline = Live.Deadline();
        using var target = new Target();
        using var parent = new Proxy();
        const string user = "someone", pass = "pass-for-the-test";
        using var proxy = new Proxy(new ProxyServerOptions { Upstream = UpstreamAt($"socks5://127.0.0.1:{parent.Port}"), User = user, Pass = pass });
        proxy.ClientsAreOthers = true;
        using var client = await proxy.ConnectAsync(deadline.Token);

        string login = Convert.ToBase64String(Encoding.UTF8.GetBytes(user + ":" + pass));
        Assert.StartsWith("HTTP/1.1 403", await HttpHeadAsync(client.GetStream(),
            $"CONNECT localhost:{target.Port} HTTP/1.1\r\nProxy-Authorization: Basic {login}\r\n\r\n", deadline.Token));
        Assert.Equal("blocked (local)", (await proxy.EntryAsync(e => !e.Ok, deadline.Token)).Status);
        Assert.Empty(parent.Log);   // nothing was asked of the upstream
        Assert.Equal(0, target.Accepted);
    }

    [Fact]
    public async Task An_ip_version_is_kept_by_looking_names_up_here()
    {
        using var deadline = Live.Deadline();
        using var target = new Target();
        using var parent = new Proxy();
        using var proxy = new Proxy(Through(UpstreamAt($"socks5://127.0.0.1:{parent.Port}"), ProxyIpVersion.IPv4));
        using var client = await proxy.ConnectAsync(deadline.Token);
        var s = client.GetStream();

        Assert.Equal(0, await Socks5Async(s, "localhost", target.Port, deadline.Token));
        await EchoesAsync(s, deadline.Token);
        // the upstream was handed the IPv4 address, not the name (it might have taken IPv6)
        Assert.Equal($"127.0.0.1:{target.Port}", (await parent.EntryAsync(e => e.Ok, deadline.Token)).Target);
        Assert.All(parent.Log, e => Assert.Equal($"127.0.0.1:{target.Port}", e.Target));
    }

    [Fact]
    public async Task An_upstream_that_is_down_is_said_so_and_nothing_goes_direct()
    {
        using var deadline = Live.Deadline();
        using var target = new Target();
        int closed = Live.ClosedTcpPort(IPAddress.Loopback);
        using var proxy = new Proxy(Through(UpstreamAt($"socks5://127.0.0.1:{closed}")));

        using (var client = await proxy.ConnectAsync(deadline.Token))
            Assert.Equal(1, await Socks5Async(client.GetStream(), "127.0.0.1", target.Port, deadline.Token));
        using (var client = await proxy.ConnectAsync(deadline.Token))
        {
            string answer = await ReadAllAsync(await SendAsync(client, $"CONNECT 127.0.0.1:{target.Port} HTTP/1.1\r\n\r\n", deadline.Token), deadline.Token);
            Assert.StartsWith("HTTP/1.1 502", answer);
            Assert.Contains("upstream down", answer);
        }

        var row = await proxy.EntryAsync(e => e.Proto == "SOCKS5", deadline.Token);
        Assert.False(row.Ok);
        Assert.Equal("upstream down", row.Status);
        Assert.Contains($"socks5://127.0.0.1:{closed} can't be reached", row.Detail);
        Assert.Equal(0, target.Accepted);   // never straight to the target instead
    }

    [Fact]
    public async Task What_the_upstream_refuses_is_passed_on_in_socks_words()
    {
        using var deadline = Live.Deadline();
        int closed = Live.ClosedTcpPort(IPAddress.Loopback);
        using var parent = new Proxy();
        using var proxy = new Proxy(Through(UpstreamAt($"socks5://127.0.0.1:{parent.Port}")));
        using var client = await proxy.ConnectAsync(deadline.Token);

        // nothing listens there: the upstream says "connection refused" (5), and so does this proxy
        Assert.Equal(5, await Socks5Async(client.GetStream(), "127.0.0.1", closed, deadline.Token));
        var row = await proxy.EntryAsync(e => !e.Ok, deadline.Token);
        Assert.Equal("upstream: refused", row.Status);
    }

    [Fact]
    public async Task The_rules_still_apply_before_anything_reaches_the_upstream()
    {
        using var deadline = Live.Deadline();
        using var target = new Target();
        using var parent = new Proxy();
        var rules = ProxyRules.Parse(null, "localhost", null, out _);
        using var proxy = new Proxy(new ProxyServerOptions { Upstream = UpstreamAt($"socks5://127.0.0.1:{parent.Port}"), Rules = rules });
        using var client = await proxy.ConnectAsync(deadline.Token);

        Assert.Equal(2, await Socks5Async(client.GetStream(), "localhost", target.Port, deadline.Token));
        await Task.Delay(100, deadline.Token);
        Assert.Empty(parent.Log);
    }
}
