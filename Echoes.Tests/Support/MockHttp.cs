using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Echoes.Tests.Support;

/// <summary>
/// A small HTTP/1.1 server on the loopback address for API clients under test (Hetzner, Cloudflare, the IP services):
/// every request is recorded and answered by the test's handler. Connections stay open between requests, as a real
/// API's do.
/// </summary>
internal sealed class MockHttp : IDisposable
{
    public sealed record Request(string Method, string Path, string Body, string? Authorization);

    public sealed record Response(int Status, string Body = "", IReadOnlyDictionary<string, string>? Headers = null)
    {
        public static Response Json(string body, int status = 200) => new(status, body);
    }

    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly Func<Request, Response> _handler;
    private readonly ConcurrentQueue<Request> _requests = new();

    public MockHttp(Func<Request, Response> handler)
    {
        _handler = handler;
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        _ = Task.Run(AcceptLoopAsync);
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
    public string Root => $"http://127.0.0.1:{Port}";
    public IReadOnlyList<Request> Requests => _requests.ToList();

    public int Count(string method, string pathStart)
        => _requests.Count(r => r.Method == method && r.Path.StartsWith(pathStart, StringComparison.Ordinal));

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await _listener.AcceptTcpClientAsync(_cts.Token); }
            catch { return; }
            _ = Task.Run(() => ServeAsync(client));
        }
    }

    private async Task ServeAsync(TcpClient client)
    {
        using (client)
        {
            try
            {
                var stream = client.GetStream();
                var buffered = new List<byte>();
                var chunk = new byte[16 * 1024];
                while (!_cts.IsCancellationRequested)
                {
                    int headEnd;
                    while ((headEnd = IndexOfHeadEnd(buffered)) < 0)
                    {
                        int n = await stream.ReadAsync(chunk, _cts.Token);
                        if (n == 0) return;
                        buffered.AddRange(chunk.AsSpan(0, n).ToArray());
                    }
                    string head = Encoding.ASCII.GetString(buffered.GetRange(0, headEnd).ToArray());
                    buffered.RemoveRange(0, headEnd + 4);
                    var lines = head.Split("\r\n");
                    var first = lines[0].Split(' ');
                    var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var line in lines.Skip(1))
                    {
                        int colon = line.IndexOf(':');
                        if (colon > 0) headers[line[..colon].Trim()] = line[(colon + 1)..].Trim();
                    }
                    int length = headers.TryGetValue("Content-Length", out var cl) && int.TryParse(cl, out int l) ? l : 0;
                    while (buffered.Count < length)
                    {
                        int n = await stream.ReadAsync(chunk, _cts.Token);
                        if (n == 0) return;
                        buffered.AddRange(chunk.AsSpan(0, n).ToArray());
                    }
                    string body = Encoding.UTF8.GetString(buffered.GetRange(0, length).ToArray());
                    buffered.RemoveRange(0, length);

                    var request = new Request(first[0], first.Length > 1 ? first[1] : "/", body,
                                              headers.TryGetValue("Authorization", out var auth) ? auth : null);
                    _requests.Enqueue(request);
                    Response response;
                    try { response = _handler(request); }
                    catch (Exception ex) { response = new Response(500, "{\"error\":{\"code\":\"server_error\",\"message\":\"" + ex.GetType().Name + "\"}}"); }

                    byte[] payload = Encoding.UTF8.GetBytes(response.Body);
                    var sb = new StringBuilder();
                    sb.Append("HTTP/1.1 ").Append(response.Status).Append(' ').Append(Reason(response.Status)).Append("\r\n");
                    sb.Append("Content-Type: application/json\r\n");
                    sb.Append("Content-Length: ").Append(payload.Length).Append("\r\n");
                    if (response.Headers != null)
                        foreach (var (k, v) in response.Headers) sb.Append(k).Append(": ").Append(v).Append("\r\n");
                    sb.Append("\r\n");
                    await stream.WriteAsync(Encoding.ASCII.GetBytes(sb.ToString()), _cts.Token);
                    await stream.WriteAsync(payload, _cts.Token);
                }
            }
            catch { /* the client went away, or the server stopped */ }
        }
    }

    private static int IndexOfHeadEnd(List<byte> b)
    {
        for (int i = 0; i + 3 < b.Count; i++)
            if (b[i] == '\r' && b[i + 1] == '\n' && b[i + 2] == '\r' && b[i + 3] == '\n') return i;
        return -1;
    }

    private static string Reason(int status) => status switch
    {
        200 => "OK", 201 => "Created", 302 => "Found", 401 => "Unauthorized", 403 => "Forbidden", 404 => "Not Found",
        422 => "Unprocessable Entity", 429 => "Too Many Requests", 500 => "Internal Server Error", _ => "Status",
    };

    public void Dispose()
    {
        _cts.Cancel();
        _listener.Stop();
    }
}
