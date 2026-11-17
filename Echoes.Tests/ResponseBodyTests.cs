using System.IO.Compression;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Echoes.Helpers;
using Echoes.ViewModels;

namespace Echoes.Tests;

/// <summary>The response viewer's data: a response split out of raw bytes, a body read and decompressed up to a cap,
/// a Globalping probe's answer, and how a body is laid out (no network).</summary>
public class ResponseBodyTests
{
    private static byte[] Bytes(string s) => Encoding.Latin1.GetBytes(s);
    private static string Text(HttpResponseSnapshot r) => Encoding.UTF8.GetString(r.Body, 0, r.Length);

    [Fact]
    public void A_raw_answer_splits_into_its_status_line_headers_and_body()
    {
        var raw = Bytes("HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/html\r\nX-Cache: MISS\r\n\r\n<h1>down</h1>");
        var r = HttpResponseSnapshot.Parse(raw, raw.Length, 1024, more: false, url: "http://example.org/");
        Assert.NotNull(r);
        Assert.Equal("HTTP/1.1 503 Service Unavailable", r.StatusLine);
        Assert.Equal(2, r.Headers.Count);
        Assert.Equal("text/html", r.ContentType);
        Assert.Equal("MISS", r.Header("x-cache"));
        Assert.Equal("<h1>down</h1>", Text(r));
        Assert.False(r.Cut);
        Assert.Equal("HTTP/1.1 503 Service Unavailable\nContent-Type: text/html\nX-Cache: MISS", r.HeadText());
    }

    [Fact]
    public void A_chunked_body_is_put_together_and_one_cut_short_keeps_what_came()
    {
        var whole = Bytes("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
        var r = HttpResponseSnapshot.Parse(whole, whole.Length, 1024, more: false)!;
        Assert.Equal("hello world", Text(r));
        Assert.False(r.Cut);

        var cut = Bytes("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n wo");
        r = HttpResponseSnapshot.Parse(cut, cut.Length, 1024, more: false)!;
        Assert.Equal("hello wo", Text(r));
        Assert.True(r.Cut);
    }

    [Fact]
    public void A_body_past_the_cap_is_cut_there()
    {
        var raw = Bytes("HTTP/1.1 200 OK\r\n\r\n" + new string('x', 100));
        var r = HttpResponseSnapshot.Parse(raw, raw.Length, 10, more: false)!;
        Assert.Equal(10, r.Length);
        Assert.True(r.Cut);
        Assert.Equal("the first 10 B", r.SizeText);
    }

    [Fact]
    public void Bytes_that_are_not_HTTP_are_no_answer()
    {
        var raw = Bytes("SSH-2.0-OpenSSH_9.6\r\n");
        Assert.Null(HttpResponseSnapshot.Parse(raw, raw.Length, 1024, more: false));
    }

    public static TheoryData<string> Codings => new() { "gzip", "deflate", "deflate-raw", "br" };

    private static byte[] Compress(byte[] data, string coding)
    {
        var o = new MemoryStream();
        using (Stream z = coding switch
               {
                   "gzip" => new GZipStream(o, CompressionLevel.Fastest, leaveOpen: true),
                   "deflate" => new ZLibStream(o, CompressionLevel.Fastest, leaveOpen: true),
                   "deflate-raw" => new DeflateStream(o, CompressionLevel.Fastest, leaveOpen: true),
                   _ => new BrotliStream(o, CompressionLevel.Fastest, leaveOpen: true),
               })
            z.Write(data);
        return o.ToArray();
    }

    private static HttpContent Content(byte[] wire, string? coding)
    {
        var c = new ByteArrayContent(wire);
        if (coding != null) c.Headers.ContentEncoding.Add(coding == "deflate-raw" ? "deflate" : coding);
        return c;
    }

    [Theory]
    [MemberData(nameof(Codings))]
    public async Task A_compressed_body_is_decoded_and_capped(string coding)
    {
        byte[] page = Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("<p>Access to this site is restricted.</p>\n", 4000)));
        var all = await HttpBodyReader.ReadAsync(Content(Compress(page, coding), coding), 1024 * 1024, 4 * 1024 * 1024, TestContext.Current.CancellationToken);
        Assert.Equal(page.Length, all.Length);
        Assert.Equal(page, all.Buf.AsSpan(0, all.Length).ToArray());
        Assert.False(all.Cut);
        Assert.Null(all.Undecoded);

        var some = await HttpBodyReader.ReadAsync(Content(Compress(page, coding), coding), 1000, 4 * 1024 * 1024, TestContext.Current.CancellationToken);
        Assert.Equal(1000, some.Length);
        Assert.True(some.Cut);
        Assert.Equal(page.AsSpan(0, 1000).ToArray(), some.Buf.AsSpan(0, 1000).ToArray());
    }

    // A connection that breaks off: some bytes, then a reset.
    private sealed class BreaksOff(byte[] first) : Stream
    {
        private bool _sent;
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            if (_sent) throw new IOException("The response ended prematurely.");
            _sent = true;
            first.CopyTo(buffer);
            return ValueTask.FromResult(first.Length);
        }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => 0; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    [Fact]
    public async Task A_compressed_body_that_breaks_off_keeps_what_decoded()
    {
        byte[] page = Encoding.UTF8.GetBytes(string.Concat(Enumerable.Range(0, 3000).Select(i => $"line {i}\n")));
        byte[] gz = Compress(page, "gzip");
        var content = new StreamContent(new BreaksOff(gz[..(gz.Length / 2)]));
        content.Headers.ContentEncoding.Add("gzip");
        var r = await HttpBodyReader.ReadAsync(content, 1024 * 1024, 1024 * 1024, TestContext.Current.CancellationToken);
        Assert.True(r.Cut);
        Assert.True(r.Length > 0);
        Assert.Equal(page.AsSpan(0, r.Length).ToArray(), r.Buf.AsSpan(0, r.Length).ToArray());
    }

    [Fact]
    public async Task An_encoding_it_cannot_decode_is_kept_as_it_came()
    {
        var c = new ByteArrayContent(new byte[] { 0x28, 0xB5, 0x2F, 0xFD, 1, 2, 3 });
        c.Headers.ContentEncoding.Add("zstd");
        var r = await HttpBodyReader.ReadAsync(c, 1024, 1024, TestContext.Current.CancellationToken);
        Assert.Equal("zstd", r.Undecoded);
        Assert.Equal(7, r.Length);
    }

    // A body that sends a little, then nothing: the time running out keeps what came.
    private sealed class Stalling(byte[] first) : Stream
    {
        private bool _sent;
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            if (!_sent)
            {
                _sent = true;
                first.CopyTo(buffer);
                return first.Length;
            }
            await Task.Delay(Timeout.Infinite, ct);
            return 0;
        }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => 0; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    [Fact]
    public async Task A_body_that_stalls_keeps_what_came_before_the_time_ran_out()
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cts.CancelAfter(300);
        var r = await HttpBodyReader.ReadAsync(new StreamContent(new Stalling(Encoding.ASCII.GetBytes("<html>blocked"))), 1024, 1024, cts.Token);
        Assert.Equal("<html>blocked", Encoding.ASCII.GetString(r.Buf, 0, r.Length));
        Assert.True(r.Cut);
    }

    [Fact]
    public void A_Globalping_HTTP_result_carries_its_answer_and_its_output_keeps_the_head()
    {
        const string json = """
            {
              "status": "finished",
              "rawOutput": "HTTP/1.1 403\nContent-Type: text/html\nServer: filter\n\n<b>blocked</b>",
              "rawHeaders": "Content-Type: text/html\nServer: filter",
              "rawBody": "<b>blocked</b>",
              "truncated": true,
              "statusCode": 403,
              "statusCodeName": "Forbidden",
              "resolvedAddress": "203.0.113.7",
              "timings": { "total": 300, "download": 50 }
            }
            """;
        using var doc = JsonDocument.Parse(json);
        var r = GlobalpingResults.Parse(CheckHostKind.Http, doc.RootElement);
        Assert.NotNull(r);
        Assert.Equal(403, r.HttpCode);
        Assert.Equal(250, r.LatencyMs);   // without the body's download
        Assert.Equal("HTTP/1.1 403\nContent-Type: text/html\nServer: filter", r.Output);
        var a = r.Response;
        Assert.NotNull(a);
        Assert.Equal("HTTP/1.1 403 Forbidden", a.StatusLine);
        Assert.Equal("filter", a.Header("Server"));
        Assert.Equal("<b>blocked</b>", Text(a));
        Assert.True(a.Cut);
        Assert.Equal("The server answered 403 Forbidden.", r.Error);
    }

    [Fact]
    public void A_Globalping_HTTP_check_asks_with_GET()
    {
        var req = GlobalpingRequest.Build(CheckHostKind.Http, "https://example.com/x?y=1", CheckHostNodeChoice.Automatic, 5, null, null);
        string json = req.Json();
        Assert.Contains("\"method\":\"GET\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("HEAD", json, StringComparison.Ordinal);
    }

    [Fact]
    public void A_JSON_body_gets_a_pretty_view_unless_it_was_cut()
    {
        byte[] body = Encoding.UTF8.GetBytes("{\"error\":\"bad token\",\"code\":401}");
        var b = ResponseBodyBuilder.Build(body, body.Length, "application/json", truncated: false, "cut", "[cut]", null);
        Assert.Equal(CurlBodyKind.Json, b.Kind);
        Assert.NotNull(b.Pretty);
        Assert.Contains("\n", b.Pretty!.Text, StringComparison.Ordinal);
        Assert.StartsWith("JSON", b.KindText, StringComparison.Ordinal);

        var cut = ResponseBodyBuilder.Build(body, 10, "application/json", truncated: true, "Showing the first 10 B", "[cut]", null);
        Assert.Null(cut.Pretty);
        Assert.Equal("Showing the first 10 B", cut.Note);
        Assert.EndsWith("[cut]", cut.Text, StringComparison.Ordinal);
    }
}
