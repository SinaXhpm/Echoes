using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using Echoes.Helpers;

namespace Echoes.Tests;

/// <summary>
/// Which check-host.net failures are the user's own setup (the proxy, nodes no longer listed): those don't move a run on
/// to Globalping, which would fail the same way. Against a stand-in server on this computer's loopback address.
/// </summary>
public class CheckHostFallbackTests
{
    private static CancellationToken Test => TestContext.Current.CancellationToken;

    // One HTTP answer to the first request that comes in, then the connection closes.
    private static async Task<(Uri Base, Task Served)> AnswerOnceAsync(string statusLine)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var uri = new Uri($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        var served = Task.Run(async () =>
        {
            try
            {
                using var client = await listener.AcceptTcpClientAsync(Test);
                using var stream = client.GetStream();
                var buffer = new byte[8192];
                var head = new StringBuilder();
                while (!head.ToString().Contains("\r\n\r\n", StringComparison.Ordinal))
                {
                    int n = await stream.ReadAsync(buffer, Test);
                    if (n == 0) break;
                    head.Append(Encoding.ASCII.GetString(buffer, 0, n));
                }
                await stream.WriteAsync(Encoding.ASCII.GetBytes($"{statusLine}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"), Test);
            }
            finally { listener.Stop(); }
        }, Test);
        await Task.Yield();
        return (uri, served);
    }

    [Fact]
    public async Task A_proxy_that_wants_a_login_is_the_users_side()
    {
        var (baseUri, served) = await AnswerOnceAsync("HTTP/1.1 407 Proxy Authentication Required");
        using var http = new HttpClient();
        var client = new CheckHostClient(http, baseUri, viaProxy: true);
        var ex = await Assert.ThrowsAsync<CheckHostException>(() => client.NodesAsync(Test));
        Assert.Contains("HTTP 407", ex.Message, StringComparison.Ordinal);
        Assert.True(ex.UserSide);
        await served;
    }

    [Fact]
    public async Task A_service_failure_is_not_the_users_side()
    {
        var (baseUri, served) = await AnswerOnceAsync("HTTP/1.1 503 Service Unavailable");
        using var http = new HttpClient();
        var client = new CheckHostClient(http, baseUri);
        var ex = await Assert.ThrowsAsync<CheckHostException>(() => client.NodesAsync(Test));
        Assert.Contains("HTTP 503", ex.Message, StringComparison.Ordinal);
        Assert.False(ex.UserSide);
        await served;
    }

    [Fact]
    public async Task A_proxy_with_nothing_listening_at_its_address_is_the_users_side()
    {
        // a port that was just free: nothing answers there
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        int port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();

        using var viaProxy = HttpHelper.Create($"127.0.0.1:{port}", timeout: TimeSpan.FromSeconds(10));
        var ex = await Assert.ThrowsAsync<CheckHostException>(() => new CheckHostClient(viaProxy, new Uri("http://check-host.invalid/"), viaProxy: true).NodesAsync(Test));
        Assert.True(ex.UserSide, ex.Message);

        // the same refusal from the service itself, no proxy in between, is the service's
        using var direct = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        ex = await Assert.ThrowsAsync<CheckHostException>(() => new CheckHostClient(direct, new Uri($"http://127.0.0.1:{port}/")).NodesAsync(Test));
        Assert.False(ex.UserSide, ex.Message);
    }

    [Fact]
    public void Only_a_proxy_that_cant_be_used_at_all_is_the_users_side()
    {
        var unresolved = new HttpRequestException(HttpRequestError.NameResolutionError, "No such host is known.",
                                                  new SocketException((int)SocketError.HostNotFound));
        Assert.True(CheckHostErrors.AtProxy(unresolved, viaProxy: true));
        Assert.False(CheckHostErrors.AtProxy(unresolved, viaProxy: false));
        // the proxy is up and refused to connect on to the service: another service may get through it
        Assert.False(CheckHostErrors.AtProxy(new HttpRequestException(HttpRequestError.ProxyTunnelError, "The proxy tunnel request failed."), viaProxy: true));
        Assert.False(CheckHostErrors.AtProxy(new TaskCanceledException(), viaProxy: true));
    }
}
