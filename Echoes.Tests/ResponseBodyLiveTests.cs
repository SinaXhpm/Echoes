using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using Echoes.Helpers;

namespace Echoes.Tests;

/// <summary>
/// The tools keep the answer they got, against a tiny server on 127.0.0.1 that answers every connection with the same
/// bytes: Doctor's request (a body past its old 64 KB cap, gzip-compressed), Monitor's failing check (an error page, a
/// page a keyword rule fails on; nothing kept for a check that passes), and a refused WebSocket handshake.
/// </summary>
public class ResponseBodyLiveTests
{
    // Answers each connection: reads the request's head, writes `answer`, closes.
    private sealed class OneAnswerServer : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();
        private readonly Task _loop;

        public OneAnswerServer(byte[] answer)
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
                                await s.WriteAsync(answer, _stop.Token);
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

    private static byte[] Answer(string head, byte[] body)
        => Encoding.ASCII.GetBytes(head.Replace("{len}", body.Length.ToString(), StringComparison.Ordinal) + "\r\n\r\n").Concat(body).ToArray();

    private static byte[] Gzip(byte[] data)
    {
        var o = new MemoryStream();
        using (var z = new GZipStream(o, CompressionLevel.Fastest, leaveOpen: true)) z.Write(data);
        return o.ToArray();
    }

    [Fact]
    public async Task Doctor_keeps_the_body_it_got_decompressed_well_past_64_KB()
    {
        byte[] page = Encoding.UTF8.GetBytes(string.Concat(Enumerable.Range(0, 9000).Select(i => $"<p>maintenance, line {i}</p>\n")));
        Assert.True(page.Length > 200 * 1024);
        byte[] wire = Gzip(page);
        await using var server = new OneAnswerServer(Answer(
            "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/html; charset=utf-8\r\nContent-Encoding: gzip\r\nContent-Length: {len}\r\nConnection: close", wire));
        var r = await DoctorHttp.GetAsync(new Uri($"http://localhost:{server.Port}/status"), IPAddress.Loopback,
                                          (_, _) => Task.FromResult<IPAddress?>(null), null, TestContext.Current.CancellationToken);
        Assert.True(r.Answered, r.Error);
        Assert.Equal(503, r.Status);
        Assert.Equal(page.Length, r.BodyBytes);
        Assert.False(r.BodyCut);
        Assert.Equal(page, r.Body.AsSpan(0, r.BodyBytes).ToArray());
    }

    private static async Task<CheckResult> MonitorCheckAsync(int port, string? keyword = null)
    {
        Assert.True(MonitorEndpoint.TryParse($"http://127.0.0.1:{port}/health", out var ep, out string error), error);
        using var http = MonitorProbe.CreateHttpClient();
        var spec = new MonitorProbeSpec(ep!) { Keyword = keyword, ForceHttp = true };
        return await MonitorProbe.CheckAsync(spec, new MonitorCheckOptions(false, false, true, 5000), http, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Monitor_keeps_the_page_a_failing_check_got()
    {
        byte[] body = Encoding.UTF8.GetBytes("{\"status\":\"down\",\"reason\":\"database unreachable\"}");
        await using var server = new OneAnswerServer(Answer(
            "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close", body));
        var r = await MonitorCheckAsync(server.Port);
        Assert.False(r.Http.Ok);
        Assert.Equal(503, r.Http.Code);
        Assert.False(r.Http.Keyword);   // the 503 stays a 503 (reading its page doesn't turn it into a timeout)
        var page = r.Http.Response;
        Assert.NotNull(page);
        Assert.Equal("HTTP/1.1 503 Service Unavailable", page.StatusLine);
        Assert.Equal("application/json", page.ContentType);
        Assert.Equal(body, page.Body.AsSpan(0, page.Length).ToArray());
    }

    [Fact]
    public async Task Monitor_keeps_the_page_a_keyword_rule_failed_on_and_nothing_for_a_check_that_passes()
    {
        byte[] body = Encoding.UTF8.GetBytes("<html>Welcome back</html>");
        await using var server = new OneAnswerServer(Answer(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {len}\r\nConnection: close", body));

        var missing = await MonitorCheckAsync(server.Port, keyword: "Goodbye");
        Assert.False(missing.Http.Ok);
        Assert.True(missing.Http.Keyword);
        Assert.NotNull(missing.Http.Response);
        Assert.Equal(body, missing.Http.Response.Body.AsSpan(0, missing.Http.Response.Length).ToArray());

        var fine = await MonitorCheckAsync(server.Port, keyword: "Welcome");
        Assert.True(fine.Http.Ok);
        Assert.Null(fine.Http.Response);

        var plain = await MonitorCheckAsync(server.Port);
        Assert.True(plain.Http.Ok);
        Assert.Null(plain.Http.Response);
    }

    private sealed class NoSink : IWsSink
    {
        public void OnMessage(WsConnection connection, WsMessage message) { }
        public void OnControl(WsConnection connection, WsOpcode opcode, byte[] payload, double? rttMs) { }
        public void OnClosed(WsConnection connection, WsCloseInfo info) { }
    }

    [Fact]
    public async Task A_refused_WebSocket_handshake_keeps_the_servers_answer()
    {
        byte[] body = Encoding.UTF8.GetBytes("{\"error\":\"bad token\"}");
        await using var server = new OneAnswerServer(Answer(
            "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {len}", body));
        var o = new WsConnectOptions { Uri = new Uri($"ws://127.0.0.1:{server.Port}/socket?token=x"), TimeoutMs = 5000 };
        var f = await Assert.ThrowsAsync<SocketFailure>(() => WebSocketClient.ConnectAsync(o, new NoSink(), TestContext.Current.CancellationToken));
        Assert.Contains("403", f.Message, StringComparison.Ordinal);
        Assert.Contains("bad token", f.Message, StringComparison.Ordinal);   // the excerpt still makes the message
        var a = f.Response;
        Assert.NotNull(a);
        Assert.Equal("HTTP/1.1 403 Forbidden", a.StatusLine);
        Assert.Equal(body, a.Body.AsSpan(0, a.Length).ToArray());
        Assert.False(a.Cut);
        Assert.DoesNotContain("token=x", a.Url ?? "", StringComparison.Ordinal);   // the query (it may hold a token) isn't kept
    }
}
