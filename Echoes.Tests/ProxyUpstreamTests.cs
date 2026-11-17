using System.Text;
using Echoes.Helpers;

namespace Echoes.Tests;

/// <summary>The proxy server's upstream proxy (Advanced): how its address is read (as the other tools read a proxy),
/// what is refused with a reason, and a login typed into the address.</summary>
public class ProxyUpstreamTests
{
    private static ProxyUpstream Up(string address, string? user = null, string? pass = null, bool resolve = true)
    {
        var up = ProxyUpstream.Parse(address, user, pass, resolve, out string? problem);
        Assert.Null(problem);
        Assert.NotNull(up);
        return up!;
    }

    private static string Basic(string user, string pass)
        => "Proxy-Authorization: Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(user + ":" + pass)) + "\r\n";

    [Theory]
    [InlineData("127.0.0.1:1080", ProxyUpstreamKind.Socks5, "127.0.0.1", 1080, "socks5://127.0.0.1:1080")]   // the usual SOCKS ports
    [InlineData("127.0.0.1:9050", ProxyUpstreamKind.Socks5, "127.0.0.1", 9050, "socks5://127.0.0.1:9050")]
    [InlineData("10.0.0.5:3128", ProxyUpstreamKind.Http, "10.0.0.5", 3128, "http://10.0.0.5:3128")]          // any other: HTTP
    [InlineData(" 10.0.0.5:3128 ", ProxyUpstreamKind.Http, "10.0.0.5", 3128, "http://10.0.0.5:3128")]
    [InlineData("socks5://proxy.example:10808", ProxyUpstreamKind.Socks5, "proxy.example", 10808, "socks5://proxy.example:10808")]
    [InlineData("socks5h://proxy.example:1081", ProxyUpstreamKind.Socks5, "proxy.example", 1081, "socks5://proxy.example:1081")]
    [InlineData("socks://proxy.example:1081", ProxyUpstreamKind.Socks5, "proxy.example", 1081, "socks5://proxy.example:1081")]
    [InlineData("socks4://proxy.example:1080", ProxyUpstreamKind.Socks4a, "proxy.example", 1080, "socks4a://proxy.example:1080")]
    [InlineData("socks4a://proxy.example:1080", ProxyUpstreamKind.Socks4a, "proxy.example", 1080, "socks4a://proxy.example:1080")]
    [InlineData("http://proxy.example:80", ProxyUpstreamKind.Http, "proxy.example", 80, "http://proxy.example:80")]
    [InlineData("http://proxy.example:80/", ProxyUpstreamKind.Http, "proxy.example", 80, "http://proxy.example:80")]
    [InlineData("HTTP://Proxy.Example:8080", ProxyUpstreamKind.Http, "proxy.example", 8080, "http://proxy.example:8080")]
    [InlineData("[::1]:1080", ProxyUpstreamKind.Socks5, "::1", 1080, "socks5://[::1]:1080")]
    [InlineData("socks5://[2001:db8::5]:1080", ProxyUpstreamKind.Socks5, "2001:db8::5", 1080, "socks5://[2001:db8::5]:1080")]
    public void An_address_is_read_as_the_other_tools_read_a_proxy(string address, ProxyUpstreamKind kind, string host, int port, string display)
    {
        var up = Up(address);
        Assert.Equal(kind, up.Kind);
        Assert.Equal(host, up.Host);
        Assert.Equal(port, up.Port);
        Assert.Equal(display, up.Display);
        Assert.False(up.HasLogin);
        Assert.Equal(string.Empty, up.AuthorizationLine());
        Assert.True(up.ResolvesNames);
    }

    [Theory]
    [InlineData("", "Enter the upstream proxy's address")]
    [InlineData("   ", "Enter the upstream proxy's address")]
    [InlineData("ftp://proxy.example:21", "isn't a kind of proxy")]
    [InlineData("proxy.example", "port")]                 // no port: a slip far more often than a proxy on 80
    [InlineData("socks5://proxy.example", "port")]
    [InlineData("https://proxy.example", "port")]
    [InlineData("not a proxy at all", "isn't a proxy address")]
    public void What_isnt_an_upstream_proxy_is_said_so(string address, string expected)
    {
        Assert.Null(ProxyUpstream.Parse(address, null, null, true, out string? problem));
        Assert.NotNull(problem);
        Assert.Contains(expected, problem);
    }

    [Fact]
    public void An_https_proxy_is_an_http_proxy_reached_over_tls()
    {
        var up = Up("https://proxy.example:443");
        Assert.Equal(ProxyUpstreamKind.Http, up.Kind);
        Assert.True(up.Tls);
        Assert.Equal("https://proxy.example:443", up.Display);
        Assert.Equal("HTTPS", up.KindName);
        Assert.False(Up("http://proxy.example:8080").Tls);
        Assert.Equal("HTTP", Up("http://proxy.example:8080").KindName);
        // its login goes as an HTTP proxy's does (inside TLS here)
        Assert.Equal(Basic("u", "p"), Up("https://u:p@proxy.example:8443").AuthorizationLine());
    }

    [Fact]
    public void Socks4_takes_a_user_id_but_no_password()
    {
        Assert.True(Up("socks4a://proxy.example:1080", user: "someone").HasLogin);
        Assert.Null(ProxyUpstream.Parse("socks4a://proxy.example:1080", "someone", "secret", true, out string? problem));
        Assert.Contains("SOCKS4 has no password", problem);
    }

    [Fact]
    public void A_login_longer_than_socks_takes_is_refused()
    {
        Assert.Null(ProxyUpstream.Parse("socks5://proxy.example:1080", new string('u', 256), "p", true, out string? problem));
        Assert.Contains("too long", problem);
        Assert.NotNull(ProxyUpstream.Parse("socks5://proxy.example:1080", new string('u', 255), new string('p', 255), true, out _));
    }

    [Fact]
    public void A_login_in_the_address_is_used_when_the_fields_are_empty_and_never_shown()
    {
        var up = Up("http://alice:s%40cret@proxy.example:8080");
        Assert.True(up.HasLogin);
        Assert.Equal(Basic("alice", "s@cret"), up.AuthorizationLine());
        Assert.Equal("http://proxy.example:8080", up.Display);

        // the fields win over the address
        Assert.Equal(Basic("bob", "pw"), Up("http://alice:x@proxy.example:8080", "bob", "pw").AuthorizationLine());
        Assert.Equal(Basic("bob", ""), Up("http://proxy.example:8080", "bob", "").AuthorizationLine());
        Assert.DoesNotContain("secret", Up("socks5://u:secret@proxy.example:1080").Display);
    }

    [Fact]
    public void Whether_names_go_to_the_upstream_is_kept()
        => Assert.False(Up("socks5://proxy.example:1080", resolve: false).ResolvesNames);

    /// <summary>A connection to an upstream proxy, as a stream: what is written to it is kept, and reads give the
    /// upstream's answer.</summary>
    private sealed class Wire(byte[] answer) : Stream
    {
        private readonly MemoryStream _answer = new(answer);
        public MemoryStream Sent { get; } = new();

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => new(_answer.Read(buffer.Span));
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
        {
            Sent.Write(buffer.Span);
            return ValueTask.CompletedTask;
        }
        public override int Read(byte[] buffer, int offset, int count) => _answer.Read(buffer, offset, count);
        public override void Write(byte[] buffer, int offset, int count) => Sent.Write(buffer, offset, count);
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    [Fact]
    public async Task A_name_in_another_script_goes_to_the_upstream_in_its_ascii_form()
    {
        const string name = "bücher.example", ascii = "xn--bcher-kva.example";
        var ct = TestContext.Current.CancellationToken;
        Assert.Equal(ascii, ProxyUpstream.AsciiHost(name));
        Assert.Equal("example.com", ProxyUpstream.AsciiHost("example.com"));
        Assert.Equal("2001:db8::1", ProxyUpstream.AsciiHost("2001:db8::1"));

        // SOCKS5: the greeting, then CONNECT with ATYP 3, the name's length and the name (not "b?cher.example")
        var socks5 = new Wire(new byte[] { 5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 });
        await Up("socks5://127.0.0.1:1080").OpenTunnelAsync(socks5, name, 443, ct);
        var sent = socks5.Sent.ToArray();
        Assert.Equal(new byte[] { 5, 1, 0, 5, 1, 0, 3, (byte)ascii.Length }, sent[..8]);
        Assert.Equal(ascii, Encoding.ASCII.GetString(sent, 8, ascii.Length));
        Assert.Equal(new byte[] { 1, 187 }, sent[(8 + ascii.Length)..]);

        // SOCKS4a: the name after the (empty) user id
        var socks4 = new Wire(new byte[] { 0, 0x5A, 0, 0, 0, 0, 0, 0 });
        await Up("socks4a://127.0.0.1:1080").OpenTunnelAsync(socks4, name, 443, ct);
        Assert.EndsWith("\0" + ascii + "\0", Encoding.ASCII.GetString(socks4.Sent.ToArray()));

        // HTTP: the CONNECT line and its Host
        var http = new Wire("HTTP/1.1 200 Connection established\r\n\r\n"u8.ToArray());
        await Up("http://127.0.0.1:3128").OpenTunnelAsync(http, name, 443, ct);
        Assert.StartsWith($"CONNECT {ascii}:443 HTTP/1.1\r\nHost: {ascii}:443\r\n", Encoding.ASCII.GetString(http.Sent.ToArray()));
    }

    [Theory]
    [InlineData("user:pass@host.example:8080", "host.example:8080", "user", "pass")]
    [InlineData("socks5://u:p%40ss@h.example:1080", "socks5://h.example:1080", "u", "p@ss")]   // URL syntax: escapes decoded
    [InlineData("u:p%40ss@h.example:1080", "h.example:1080", "u", "p%40ss")]                   // no scheme: as typed
    [InlineData("u:p@ss@h.example:1080", "h.example:1080", "u", "p@ss")]                       // the LAST '@' ends the login
    [InlineData("http://u:p@h.example:8080/path", "http://h.example:8080/path", "u", "p")]
    [InlineData("u@h.example:1", "h.example:1", "u", "")]
    [InlineData("u:p@[::1]:1080", "[::1]:1080", "u", "p")]
    public void A_login_typed_into_the_address_is_taken_out_of_it(string typed, string address, string user, string pass)
    {
        var split = ProxyUpstream.SplitLogin(typed);
        Assert.NotNull(split);
        Assert.Equal((address, user, pass), split!.Value);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("host.example:8080")]
    [InlineData("[::1]:1080")]
    [InlineData("user:pass@host.example")]    // still being typed: no port yet
    [InlineData("user:pass@host.example:")]
    [InlineData("user:pass@")]
    [InlineData("http://host.example:8080/a@b")]   // an '@' in the path is no login
    public void An_address_without_a_finished_login_is_left_alone(string? typed)
        => Assert.Null(ProxyUpstream.SplitLogin(typed));
}
