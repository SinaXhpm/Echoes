using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Echoes.Helpers;

namespace Echoes.Tests;

/// <summary>
/// Monitor's HTTP check asks with HEAD when only the status matters (no page downloaded), and with GET when a HEAD fails
/// (a server that refuses HEAD, or one that is down: the detail panel gets the error page). Against a tiny server on
/// 127.0.0.1 that answers by method and writes down every method it was asked.
/// </summary>
public class MonitorHeadTests
{
    // Answers each connection by the request's method: answer(method) → the bytes to write.
    private sealed class MethodServer : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();
        private readonly Task _loop;
        public ConcurrentQueue<string> Methods { get; } = new();

        public MethodServer(Func<string, byte[]> answer)
        {
            _listener.Start();
            _loop = Task.Run(async () =>
            {
                while (!_stop.IsCancellationRequested)
                {
                    TcpClient c;
                    try { c = await _listener.AcceptTcpClientAsync(_stop.Token); }
                    catch { return; }
                    _ = Task.Run(async () =>
                    {
                        using (c)
                        {
                            try
                            {
                                var s = c.GetStream();
                                var buf = new byte[16 * 1024];
                                int got = 0;
                                while (got < buf.Length)
                                {
                                    int n = await s.ReadAsync(buf.AsMemory(got), _stop.Token);
                                    if (n <= 0) break;
                                    got += n;
                                    if (buf.AsSpan(0, got).IndexOf("\r\n\r\n"u8) >= 0) break;
                                }
                                string head = Encoding.ASCII.GetString(buf, 0, got);
                                string method = head.Split(' ', 2)[0];
                                Methods.Enqueue(method);
                                await s.WriteAsync(answer(method), _stop.Token);
                                await s.FlushAsync(_stop.Token);
                                c.Client.Shutdown(SocketShutdown.Send);
                                await Task.Delay(200, _stop.Token);
                            }
                            catch { /* the client went away */ }
                        }
                    });
                }
            });
        }

        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

        public async ValueTask DisposeAsync()
        {
            _stop.Cancel();
            _listener.Stop();
            try { await _loop; } catch { }
            _stop.Dispose();
        }
    }

    // A response; HEAD gets the same status line and headers without the body, as a server sends it.
    private static byte[] Answer(string method, string status, string body)
    {
        byte[] b = Encoding.UTF8.GetBytes(body);
        string head = $"HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {b.Length}\r\nConnection: close\r\n\r\n";
        return method == "HEAD" ? Encoding.ASCII.GetBytes(head) : Encoding.ASCII.GetBytes(head).Concat(b).ToArray();
    }

    private static async Task<CheckResult> CheckAsync(int port, string? keyword = null)
    {
        Assert.True(MonitorEndpoint.TryParse($"http://127.0.0.1:{port}/health", out var ep, out string error), error);
        using var http = MonitorProbe.CreateHttpClient();
        var spec = new MonitorProbeSpec(ep!) { Keyword = keyword, ForceHttp = true };
        return await MonitorProbe.CheckAsync(spec, new MonitorCheckOptions(false, false, true, 5000), http, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task A_plain_check_asks_with_HEAD_and_downloads_no_page()
    {
        string page = new('x', 200 * 1024);   // a GET would have pulled (part of) this
        await using var server = new MethodServer(m => Answer(m, "200 OK", page));
        var r = await CheckAsync(server.Port);
        Assert.True(r.Http.Ok);
        Assert.Equal(200, r.Http.Code);
        Assert.Equal(new[] { "HEAD" }, server.Methods.ToArray());
    }

    [Fact]
    public async Task A_server_that_refuses_HEAD_passes_with_GET_and_gets_GET_from_then_on()
    {
        await using var server = new MethodServer(m => m == "HEAD"
            ? Answer(m, "405 Method Not Allowed", "")
            : Answer(m, "200 OK", "<html>fine</html>"));
        var first = await CheckAsync(server.Port);
        Assert.True(first.Http.Ok);
        Assert.Equal(200, first.Http.Code);
        Assert.Equal(new[] { "HEAD", "GET" }, server.Methods.ToArray());

        var second = await CheckAsync(server.Port);
        Assert.True(second.Http.Ok);
        Assert.Equal(new[] { "HEAD", "GET", "GET" }, server.Methods.ToArray());   // no HEAD any more
    }

    [Fact]
    public async Task A_server_that_is_down_is_asked_again_with_GET_and_keeps_its_error_page()
    {
        await using var server = new MethodServer(m => Answer(m, "503 Service Unavailable", "{\"status\":\"down\"}"));
        var r = await CheckAsync(server.Port);
        Assert.False(r.Http.Ok);
        Assert.Equal(503, r.Http.Code);
        Assert.Equal(new[] { "HEAD", "GET" }, server.Methods.ToArray());
        Assert.NotNull(r.Http.Response);
        Assert.Equal("{\"status\":\"down\"}", Encoding.UTF8.GetString(r.Http.Response.Body, 0, r.Http.Response.Length));

        var again = await CheckAsync(server.Port);   // still down: HEAD first again (only a GET that passes marks GET-only)
        Assert.False(again.Http.Ok);
        Assert.Equal(new[] { "HEAD", "GET", "HEAD", "GET" }, server.Methods.ToArray());
    }

    [Fact]
    public async Task A_keyword_rule_reads_the_page_with_GET()
    {
        await using var server = new MethodServer(m => Answer(m, "200 OK", "<html>Welcome back</html>"));
        var r = await CheckAsync(server.Port, keyword: "Welcome");
        Assert.True(r.Http.Ok);
        Assert.Equal(new[] { "GET" }, server.Methods.ToArray());
    }
}
