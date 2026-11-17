using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Echoes.Helpers;
using Echoes.Tests.Support;

namespace Echoes.Tests;

/// <summary>
/// An https:// upstream proxy: TLS on 127.0.0.1 in front of a second proxy stands in for it (a TLS listener whose plain
/// side is an HTTP proxy, as Squid's https_port or Caddy's forward proxy are). Tunnels and plain http:// go through it,
/// its certificate is checked before anything is sent, and a client's half-close passes over TLS with the answer still
/// coming back. Also the half-close straight to a target.
/// </summary>
public partial class ProxyServerTests
{
    /// <summary>TLS on 127.0.0.1 before another listener, with a self-signed certificate for <paramref name="name"/>.
    /// Each side's end (close_notify, FIN) is passed on to the other.</summary>
    private sealed class TlsFront : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();
        private int _handshakes;

        public X509Certificate2 Certificate { get; }
        public int Port { get; }
        public int Handshakes => Volatile.Read(ref _handshakes);

        public TlsFront(int behind, string name = "localhost")
        {
            Certificate = SelfSigned(name);
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _ = Task.Run(async () =>
            {
                try
                {
                    while (true) _ = ServeAsync(await _listener.AcceptTcpClientAsync(_stop.Token), behind);
                }
                catch (Exception e) when (e is OperationCanceledException or SocketException or ObjectDisposedException) { }
            });
        }

        private async Task ServeAsync(TcpClient client, int behind)
        {
            using (client)
            using (var back = new TcpClient(AddressFamily.InterNetwork))
            {
                try
                {
                    using var tls = new SslStream(client.GetStream());
                    await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                    {
                        ServerCertificate = Certificate,
                        ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http11 },
                    }, _stop.Token);
                    Interlocked.Increment(ref _handshakes);
                    await back.ConnectAsync(IPAddress.Loopback, behind, _stop.Token);
                    var plain = back.GetStream();
                    await Task.WhenAll(
                        CopyAsync(tls, plain, () => { back.Client.Shutdown(SocketShutdown.Send); return Task.CompletedTask; }),
                        CopyAsync(plain, tls, () => tls.ShutdownAsync()));
                }
                catch (Exception e) when (e is OperationCanceledException or IOException or SocketException or AuthenticationException or ObjectDisposedException) { }
            }
        }

        private async Task CopyAsync(Stream from, Stream to, Func<Task> end)
        {
            try
            {
                var buf = new byte[16 * 1024];
                int n;
                while ((n = await from.ReadAsync(buf, _stop.Token)) > 0) await to.WriteAsync(buf.AsMemory(0, n), _stop.Token);
                await end();
            }
            catch (Exception e) when (e is OperationCanceledException or IOException or SocketException or ObjectDisposedException) { }
        }

        private static X509Certificate2 SelfSigned(string name)
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName(name);
            request.CertificateExtensions.Add(san.Build());
            var now = DateTimeOffset.UtcNow;
            using var made = request.CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
            // (through a PFX: Windows can't serve TLS with a key that only lives in memory)
#if NET9_0_OR_GREATER
            return X509CertificateLoader.LoadPkcs12(made.Export(X509ContentType.Pfx), null, X509KeyStorageFlags.Exportable);
#else
            return new X509Certificate2(made.Export(X509ContentType.Pfx), (string?)null, X509KeyStorageFlags.Exportable);
#endif
        }

        public void Dispose()
        {
            _stop.Cancel();
            _listener.Stop();
            Certificate.Dispose();
        }
    }

    /// <summary>The test certificate of <paramref name="front"/> trusted as if an authority had issued it. The name it
    /// is for is still checked.</summary>
    private static ProxyUpstream Trusting(ProxyUpstream up, TlsFront front)
    {
        up.CertificateCheck = (certificate, errors) =>
            certificate?.GetCertHashString() == front.Certificate.Thumbprint
            && (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) == SslPolicyErrors.None;
        return up;
    }

    /// <summary>A listener on 127.0.0.1 that reads until the client is done sending (its half-close), then answers with
    /// how much it got: an answer that only comes through a proxy that passes the half-close on and keeps the way back open.</summary>
    private sealed class AfterEof : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();

        public int Port { get; }

        public AfterEof()
        {
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _ = Task.Run(async () =>
            {
                try
                {
                    while (true) _ = AnswerAsync(await _listener.AcceptTcpClientAsync(_stop.Token));
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
                    var buf = new byte[4096];
                    long total = 0;
                    int n;
                    while ((n = await s.ReadAsync(buf, _stop.Token)) > 0) total += n;
                    await s.WriteAsync(Encoding.ASCII.GetBytes($"got {total}"), _stop.Token);
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

    /// <summary>Sends <paramref name="text"/>, says it is done sending, and reads the answer up to the close.</summary>
    private static async Task<string> HalfCloseAsync(TcpClient client, string text, CancellationToken ct)
    {
        var s = client.GetStream();
        await s.WriteAsync(Encoding.ASCII.GetBytes(text), ct);
        client.Client.Shutdown(SocketShutdown.Send);
        return await ReadAllAsync(s, ct);
    }

    // ------------------------------------------------------------------ through an https:// upstream

    [Fact]
    public async Task An_https_upstream_carries_tunnels_over_tls_with_its_login()
    {
        using var deadline = Live.Deadline();
        using var target = new Target();
        using var parent = new Proxy(new ProxyServerOptions { User = "chain", Pass = "https-upstream-pass" });
        using var front = new TlsFront(parent.Port);
        using var proxy = new Proxy(Through(Trusting(UpstreamAt($"https://localhost:{front.Port}", "chain", "https-upstream-pass"), front)));

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

        Assert.Equal(2, front.Handshakes);   // TLS for each, and the CONNECT with its login inside it
        var asked = await parent.EntryAsync(e => e.Ok, deadline.Token);
        Assert.Equal("HTTPS", asked.Proto);
        Assert.Equal("tunnel", asked.Status);
        Assert.Equal("chain", asked.User);
        Assert.Equal("connected", (await proxy.EntryAsync(e => e.Proto == "SOCKS5", deadline.Token)).Status);
    }

    [Fact]
    public async Task Plain_http_goes_to_an_https_upstream_as_a_proxy_request()
    {
        using var deadline = Live.Deadline();
        using var origin = new HttpOrigin();
        using var parent = new Proxy();
        using var front = new TlsFront(parent.Port);
        using var proxy = new Proxy(Through(Trusting(UpstreamAt($"https://localhost:{front.Port}"), front)));
        using var client = await proxy.ConnectAsync(deadline.Token);

        string answer = await ReadAllAsync(await SendAsync(client,
            $"GET http://localhost:{origin.Port}/over-tls HTTP/1.1\r\nHost: localhost:{origin.Port}\r\n\r\n", deadline.Token), deadline.Token);

        Assert.StartsWith("HTTP/1.1 200", answer);
        Assert.Contains("GET /over-tls HTTP/1.1\n", answer);
        var asked = await parent.EntryAsync(e => e.Ok, deadline.Token);
        Assert.Equal("HTTP", asked.Proto);
        Assert.Equal("forward", asked.Status);
        Assert.Equal(1, front.Handshakes);
    }

    [Fact]
    public async Task An_https_upstreams_certificate_is_checked_before_anything_is_sent()
    {
        using var deadline = Live.Deadline();
        using var target = new Target();
        using var parent = new Proxy();

        // self-signed: no authority this device trusts issued it
        using (var front = new TlsFront(parent.Port))
        using (var proxy = new Proxy(Through(UpstreamAt($"https://localhost:{front.Port}"))))
        {
            using (var client = await proxy.ConnectAsync(deadline.Token))
                Assert.Equal(1, await Socks5Async(client.GetStream(), "127.0.0.1", target.Port, deadline.Token));
            var row = await proxy.EntryAsync(e => !e.Ok, deadline.Token);
            Assert.Equal("upstream: bad certificate", row.Status);
            Assert.Contains("isn't from an issuer this device trusts", row.Detail);

            using (var client = await proxy.ConnectAsync(deadline.Token))
            {
                string answer = await ReadAllAsync(await SendAsync(client, $"CONNECT 127.0.0.1:{target.Port} HTTP/1.1\r\n\r\n", deadline.Token), deadline.Token);
                Assert.StartsWith("HTTP/1.1 502", answer);
                Assert.Contains("upstream: bad certificate", answer);
            }
        }

        // trusted, but for another name than the one it was reached by
        using (var front = new TlsFront(parent.Port, "elsewhere.test"))
        using (var proxy = new Proxy(Through(Trusting(UpstreamAt($"https://localhost:{front.Port}"), front))))
        {
            using var client = await proxy.ConnectAsync(deadline.Token);
            Assert.Equal(1, await Socks5Async(client.GetStream(), "127.0.0.1", target.Port, deadline.Token));
            Assert.Contains("for another name than localhost", (await proxy.EntryAsync(e => !e.Ok, deadline.Token)).Detail);
        }

        Assert.Empty(parent.Log);   // nothing got through to the proxy behind
        Assert.Equal(0, target.Accepted);
    }

    [Fact]
    public async Task A_proxy_that_doesnt_speak_tls_written_as_https_is_said_so()
    {
        using var deadline = Live.Deadline();
        using var notTls = new Target(send: 64);   // answers with bytes that aren't TLS
        using var proxy = new Proxy(Through(UpstreamAt($"https://127.0.0.1:{notTls.Port}")));
        using var client = await proxy.ConnectAsync(deadline.Token);

        Assert.Equal(1, await Socks5Async(client.GetStream(), "127.0.0.1", 9, deadline.Token));
        var row = await proxy.EntryAsync(e => !e.Ok, deadline.Token);
        Assert.Equal("upstream: TLS failed", row.Status);
        Assert.Contains("A plain HTTP proxy is http://", row.Detail);
    }

    // ------------------------------------------------------------------ the half-close

    [Fact]
    public async Task A_half_close_passes_through_and_the_answer_still_comes_back()
    {
        using var deadline = Live.Deadline();
        using var target = new AfterEof();

        // straight to the target
        using (var proxy = new Proxy())
        using (var client = await proxy.ConnectAsync(deadline.Token))
        {
            Assert.Equal(0, await Socks5Async(client.GetStream(), "127.0.0.1", target.Port, deadline.Token));
            Assert.Equal("got 5", await HalfCloseAsync(client, "hello", deadline.Token));
        }

        // through an https:// upstream: the end goes over TLS (close_notify), and the answer comes back after it
        using var parent = new Proxy();
        using var front = new TlsFront(parent.Port);
        using (var proxy = new Proxy(Through(Trusting(UpstreamAt($"https://localhost:{front.Port}"), front))))
        using (var client = await proxy.ConnectAsync(deadline.Token))
        {
            Assert.Equal(0, await Socks5Async(client.GetStream(), "127.0.0.1", target.Port, deadline.Token));
            Assert.Equal("got 11", await HalfCloseAsync(client, "hello again", deadline.Token));
        }
    }
}
