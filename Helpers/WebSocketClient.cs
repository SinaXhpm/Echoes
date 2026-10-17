using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>What the Socket tool's WebSocket mode connects with.</summary>
public sealed class WsConnectOptions
{
    public required Uri Uri { get; init; }
    public IReadOnlyList<string> Subprotocols { get; init; } = Array.Empty<string>();
    public IReadOnlyList<KeyValuePair<string, string>> Headers { get; init; } = Array.Empty<KeyValuePair<string, string>>();
    /// <summary>"host:port" (HTTP; 1080 / 1081 / 9050 = SOCKS5), "http://user:pass@host:port", "socks5://host:port".</summary>
    public string? Proxy { get; init; }
    /// <summary>Accept exactly this certificate (SHA-256 hex) although it failed validation — "connect anyway".</summary>
    public string? AcceptCertSha256 { get; init; }
    public int TimeoutMs { get; init; } = 15_000;
    public int MaxMessageBytes { get; init; } = 4 * 1024 * 1024;
}

/// <summary>An open WebSocket client connection and what the handshake told.</summary>
public sealed class WsClientSession
{
    public required WsConnection Connection { get; init; }
    public required Uri Uri { get; init; }
    /// <summary>The TCP peer: the server, or the proxy when one is used.</summary>
    public IPEndPoint? Remote { get; init; }
    public IPEndPoint? Local { get; init; }
    /// <summary>"TLS 1.3 · TLS_AES_256_GCM_SHA384" for wss.</summary>
    public string? TlsDescription { get; init; }
    /// <summary>"echo.example.com · issued by R11 · 61 days left" for wss.</summary>
    public string? CertificateText { get; init; }
    public bool CertificateOverridden { get; init; }
    public string? Subprotocol { get; init; }
    public string StatusLine { get; init; } = string.Empty;
    public string? Server { get; init; }
    /// <summary>"HTTP proxy 127.0.0.1:8080" (no credentials) when connected through a proxy.</summary>
    public string? Via { get; init; }
}

/// <summary>
/// WebSocket client handshake (RFC 6455) over our own TCP / TLS / proxy stack, so the tool can report what a
/// managed ClientWebSocket hides: the TLS version, cipher and certificate, the exact HTTP answer when the upgrade is
/// refused, and real ping round trips. Proxies: HTTP CONNECT and SOCKS5 (names resolved by the proxy), with optional
/// user:password. Every failure is a <see cref="SocketFailure"/> worded for the user.
/// </summary>
public static class WebSocketClient
{
    private const int MaxHeadBytes = 16 * 1024;
    public const int MaxHeaders = 50;

    private static readonly string UserAgent =
        typeof(WebSocketClient).Assembly.GetName().Version is { } v ? $"Echoes/{v.Major}.{v.Minor}.{v.Build}" : "Echoes";

    // Headers the handshake owns: a typed one would break or duplicate it.
    private static readonly string[] Managed =
    {
        "Host", "Upgrade", "Connection", "Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Accept",
        "Sec-WebSocket-Extensions", "Content-Length", "Transfer-Encoding",
    };

    /// <summary>Test hook: a certificate (SHA-256 hex) trusted for loopback hosts only (a self-signed test server).</summary>
    internal static string? TrustedTestCertSha256 { get; set; }

    // ================================================================ input

    /// <summary>
    /// "wss://host/path" as typed, "https://…" / "http://…" converted to wss / ws, a bare "host:port/path" taken as ws://
    /// (wss:// on port 443). False + a one-line reason otherwise.
    /// </summary>
    public static bool TryNormalizeUrl(string? raw, out Uri? uri, out string? error)
    {
        uri = null;
        error = null;
        string s = (raw ?? string.Empty).Trim();
        if (s.Length == 0) { error = "Enter a WebSocket URL, e.g. wss://echo.example.com/ws."; return false; }
        if (s.Any(char.IsWhiteSpace)) { error = "A URL can't contain spaces."; return false; }
        int sep = s.IndexOf("://", StringComparison.Ordinal);
        if (sep < 0)
        {
            bool port443 = s.Split('/')[0].EndsWith(":443", StringComparison.Ordinal);
            s = (port443 ? "wss://" : "ws://") + s;
        }
        else
        {
            string scheme = s[..sep].ToLowerInvariant();
            string rest = s[(sep + 3)..];
            s = scheme switch
            {
                "ws" or "wss" => scheme + "://" + rest,
                "http" => "ws://" + rest,
                "https" => "wss://" + rest,
                _ => string.Empty,
            };
            if (s.Length == 0) { error = $"\"{scheme}://\" isn't a WebSocket URL — use ws:// or wss:// (http:// and https:// are converted)."; return false; }
        }
        int hash = s.IndexOf('#');
        if (hash >= 0) s = s[..hash];   // a fragment is never sent
        if (!Uri.TryCreate(s, UriKind.Absolute, out var u) || string.IsNullOrEmpty(u.Host))
        {
            error = "That isn't a valid URL — e.g. wss://echo.example.com/ws.";
            return false;
        }
        if (!string.IsNullOrEmpty(u.UserInfo))
        {
            error = "Put credentials in a header (Options → Headers, e.g. Authorization), not in the URL.";
            return false;
        }
        uri = u;
        return true;
    }

    /// <summary>"Name: value" per line (blank lines and # comments skipped).</summary>
    public static bool TryParseHeaders(string? text, out List<KeyValuePair<string, string>> headers, out string? error)
    {
        headers = new List<KeyValuePair<string, string>>();
        error = null;
        int lineNo = 0;
        foreach (var raw in (text ?? string.Empty).Replace("\r\n", "\n").Split('\n'))
        {
            lineNo++;
            string line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            int colon = line.IndexOf(':');
            if (colon <= 0) { error = $"Header line {lineNo} needs \"Name: value\"."; return false; }
            string name = line[..colon].Trim();
            string value = line[(colon + 1)..].Trim();
            if (!WsProtocol.IsToken(name)) { error = $"\"{WsProtocol.Short(name, 40)}\" isn't a valid header name (line {lineNo})."; return false; }
            if (value.Any(c => c < 0x20 && c != '\t' || c == 0x7F)) { error = $"The value of {name} has control characters (line {lineNo})."; return false; }
            if (value.Length > 8192) { error = $"The value of {name} is longer than 8 KB."; return false; }
            if (Managed.Any(m => m.Equals(name, StringComparison.OrdinalIgnoreCase)))
            { error = $"{name} is set by the handshake itself — remove that line."; return false; }
            if (name.Equals("Sec-WebSocket-Protocol", StringComparison.OrdinalIgnoreCase))
            { error = "Put subprotocols in the Subprotocols box, not as a header."; return false; }
            headers.Add(new KeyValuePair<string, string>(name, value));
            if (headers.Count > MaxHeaders) { error = $"At most {MaxHeaders} headers."; return false; }
        }
        return true;
    }

    /// <summary>"chat, graphql-ws" → the list (commas or spaces).</summary>
    public static bool TryParseSubprotocols(string? text, out List<string> list, out string? error)
    {
        list = new List<string>();
        error = null;
        foreach (var p in (text ?? string.Empty).Split(new[] { ',', ' ', '\t', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries))
        {
            if (!WsProtocol.IsToken(p)) { error = $"\"{WsProtocol.Short(p, 40)}\" isn't a valid subprotocol name."; return false; }
            if (!list.Contains(p, StringComparer.Ordinal)) list.Add(p);
        }
        if (list.Count > 16) { error = "At most 16 subprotocols."; return false; }
        return true;
    }

    // ================================================================ connect

    public static async Task<WsClientSession> ConnectAsync(WsConnectOptions o, IWsSink sink, CancellationToken ct)
    {
        var uri = o.Uri;
        bool tls = uri.Scheme.Equals("wss", StringComparison.OrdinalIgnoreCase);
        string host = uri.IdnHost.Trim('[', ']');
        int port = uri.IsDefaultPort || uri.Port <= 0 ? (tls ? 443 : 80) : uri.Port;
        string target = SocketNet.Target(host, port);

        using var all = CancellationTokenSource.CreateLinkedTokenSource(ct);
        all.CancelAfter(o.TimeoutMs);

        Socket socket;
        Stream stream;
        string? via = null;
        try
        {
            if (!string.IsNullOrWhiteSpace(o.Proxy))
            {
                var (kind, phost, pport, user, pass, label) = ParseProxy(o.Proxy!);
                via = label;
                try { socket = await SocketNet.ConnectTcpAsync(phost, pport, o.TimeoutMs, all.Token).ConfigureAwait(false); }
                catch (SocketFailure f) { throw new SocketFailure("Couldn't reach the proxy: " + f.Message, f); }
                stream = new NetworkStream(socket, ownsSocket: true);
                try
                {
                    if (kind == "socks5") await Socks5ConnectAsync(stream, host, port, user, pass, all.Token).ConfigureAwait(false);
                    else await HttpConnectAsync(stream, host, port, user, pass, all.Token).ConfigureAwait(false);
                }
                catch
                {
                    stream.Dispose();
                    throw;
                }
            }
            else
            {
                socket = await SocketNet.ConnectTcpAsync(host, port, o.TimeoutMs, all.Token).ConfigureAwait(false);
                stream = new NetworkStream(socket, ownsSocket: true);
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new SocketFailure(via != null
                ? $"Timed out connecting to {target} through the proxy."
                : SocketErrors.Describe(new TimeoutException(), SocketAction.Connect, target, port));
        }
        catch (IOException ex) when (!ct.IsCancellationRequested)
        {
            throw new SocketFailure("The proxy closed the connection: " + SocketErrors.Describe(ex, SocketAction.Receive, "the proxy"), ex);
        }

        IPEndPoint? remote = null, local = null;
        try
        {
            remote = SocketNet.Normalize((IPEndPoint)socket.RemoteEndPoint!);
            local = SocketNet.Normalize((IPEndPoint)socket.LocalEndPoint!);
        }
        catch { /* closed meanwhile: the handshake below reports it */ }

        string? tlsText = null, certText = null;
        bool overridden = false;
        try
        {
            if (tls)
            {
                var r = await TlsAsync(stream, host, target, port, o.AcceptCertSha256, o.TimeoutMs, ct).ConfigureAwait(false);
                stream = r.Stream;
                tlsText = r.Description;
                certText = r.CertText;
                overridden = r.Overridden;
            }
            var hs = await HandshakeAsync(stream, uri, host, port, tls, o, target, all.Token, ct).ConfigureAwait(false);
            var conn = new WsConnection(hs.Leftover.Length > 0 ? new PrefixedStream(stream, hs.Leftover) : stream,
                                        isServer: false, sink, o.MaxMessageBytes);
            return new WsClientSession
            {
                Connection = conn,
                Uri = uri,
                Remote = remote,
                Local = local,
                TlsDescription = tlsText,
                CertificateText = certText,
                CertificateOverridden = overridden,
                Subprotocol = hs.Subprotocol,
                StatusLine = hs.StatusLine,
                Server = hs.Server,
                Via = via,
            };
        }
        catch
        {
            try { stream.Dispose(); } catch { }
            throw;
        }
    }

    // ---------------------------------------------------------------- TLS

    private sealed record TlsResult(Stream Stream, string Description, string? CertText, bool Overridden);

    private static async Task<TlsResult> TlsAsync(Stream inner, string host, string target, int port, string? acceptSha, int timeoutMs, CancellationToken ct)
    {
        string tlsHost = SocketNet.AsciiHost(host);
        bool loopback = IPAddress.TryParse(host, out var ip) ? IPAddress.IsLoopback(ip) : host.Equals("localhost", StringComparison.OrdinalIgnoreCase);
        List<TlsProblem>? problems = null;
        string? sha = null;
        bool overridden = false;
        X509Certificate2? leaf = null;
        var ssl = new SslStream(inner, leaveInnerStreamOpen: false, (_, cert, chain, errors) =>
        {
            try
            {
                if (cert != null) leaf = new X509Certificate2(cert);
                if (errors == SslPolicyErrors.None) return true;
                sha = cert != null ? TlsCertificates.Sha256Hex(cert) : null;
                if (sha != null && (string.Equals(sha, acceptSha, StringComparison.OrdinalIgnoreCase)
                                    || loopback && string.Equals(sha, TrustedTestCertSha256, StringComparison.OrdinalIgnoreCase)))
                {
                    overridden = true;
                    return true;
                }
                var snap = TlsCertificates.Snapshot(cert, chain);
                problems = TlsCertificates.Assess(snap, TlsCertificates.Flags(chain), errors, tlsHost, DateTime.UtcNow);
            }
            catch (Exception ex)
            {
                problems = new List<TlsProblem> { new(TlsSeverity.Error, "The certificate couldn't be checked: " + ex.Message) };
            }
            return false;
        });
        try
        {
            using var hs = CancellationTokenSource.CreateLinkedTokenSource(ct);
            hs.CancelAfter(timeoutMs);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = tlsHost,
                EnabledSslProtocols = SslProtocols.None,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                // WebSocket upgrades are HTTP/1.1: a server that would otherwise pick h2 must not
                ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http11 },
            }, hs.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            ssl.Dispose();
            if (problems != null)   // the summary can quote the certificate's own names: cleaned like any server text
                throw new SocketFailure("Certificate not trusted: " + Clean(TlsCertificates.Summary(problems)), ex) { CertSha256 = sha, CertProblems = problems };
            if (ex is OperationCanceledException && ct.IsCancellationRequested) throw;
            throw new SocketFailure(SocketErrors.Describe(ex, SocketAction.Tls, target, port), ex);
        }

        string cipher = "";
        try { cipher = ssl.NegotiatedCipherSuite.ToString(); } catch { /* not reported on this platform */ }
        string desc = TlsCertificates.ProtocolName(ssl.SslProtocol) + (cipher.Length > 0 ? " · " + cipher : "");
        string? certText = null;
        if (leaf != null)
        {
            try
            {
                // subject / issuer names are whatever the server's certificate says (any characters, any length)
                certText = $"{WsProtocol.Short(Clean(TlsCertificates.ShortName(leaf)), 80)} · issued by {WsProtocol.Short(Clean(TlsCertificates.IssuerText(leaf)), 80)} · {TlsCertificates.ExpiryPhrase(leaf, DateTime.UtcNow)}";
                if (TlsCertificates.IsSelfIssued(leaf)) certText += " · self-signed";
            }
            catch { /* unreadable: the protocol line is enough */ }
            finally { leaf.Dispose(); }
        }
        return new TlsResult(ssl, desc, certText, overridden);
    }

    // ---------------------------------------------------------------- the upgrade

    private sealed record Handshake(string StatusLine, string? Subprotocol, string? Server, byte[] Leftover);

    private static async Task<Handshake> HandshakeAsync(Stream stream, Uri uri, string host, int port, bool tls,
        WsConnectOptions o, string target, CancellationToken token, CancellationToken userCt)
    {
        string key = WsProtocol.NewKey();
        bool defaultPort = port == (tls ? 443 : 80);
        string hostHeader = (host.Contains(':') ? "[" + host + "]" : host) + (defaultPort ? "" : ":" + port.ToString(CultureInfo.InvariantCulture));
        string path = string.IsNullOrEmpty(uri.PathAndQuery) ? "/" : uri.PathAndQuery;

        var sb = new StringBuilder(512);
        sb.Append("GET ").Append(path).Append(" HTTP/1.1\r\n");
        sb.Append("Host: ").Append(hostHeader).Append("\r\n");
        sb.Append("Upgrade: websocket\r\nConnection: Upgrade\r\n");
        sb.Append("Sec-WebSocket-Key: ").Append(key).Append("\r\n");
        sb.Append("Sec-WebSocket-Version: 13\r\n");
        if (o.Subprotocols.Count > 0) sb.Append("Sec-WebSocket-Protocol: ").Append(string.Join(", ", o.Subprotocols)).Append("\r\n");
        bool hasUa = false;
        foreach (var h in o.Headers)
        {
            if (h.Key.Equals("User-Agent", StringComparison.OrdinalIgnoreCase)) hasUa = true;
            sb.Append(h.Key).Append(": ").Append(h.Value).Append("\r\n");
        }
        if (!hasUa) sb.Append("User-Agent: ").Append(UserAgent).Append("\r\n");
        sb.Append("\r\n");

        try
        {
            await stream.WriteAsync(Encoding.UTF8.GetBytes(sb.ToString()), token).ConfigureAwait(false);
            await stream.FlushAsync(token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!userCt.IsCancellationRequested)
        {
            throw new SocketFailure($"Timed out sending the handshake to {target}.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new SocketFailure(SocketErrors.Describe(ex, SocketAction.Send, target), ex);
        }

        HttpHead head;
        try
        {
            head = await ReadHeadAsync(stream, token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!userCt.IsCancellationRequested)
        {
            throw new SocketFailure($"{target} didn't answer the WebSocket handshake within {o.TimeoutMs / 1000} s"
                                    + (tls ? "." : " (if it only speaks TLS, use wss://)."));
        }
        catch (Exception ex) when (ex is not OperationCanceledException and not SocketFailure)
        {
            throw new SocketFailure(SocketErrors.Describe(ex, SocketAction.Receive, target), ex);
        }

        if (head.Status != 101) throw new SocketFailure(Refusal(head, target, tls));

        if (!WsProtocol.HasToken(head.Get("Upgrade"), "websocket"))
            throw new SocketFailure($"{target} answered 101 but not with \"Upgrade: websocket\" — it switched to something else.");
        if (!WsProtocol.HasToken(head.Get("Connection"), "upgrade"))
            throw new SocketFailure($"{target} answered 101 without \"Connection: Upgrade\" — not a valid WebSocket handshake.");
        string? accept = head.Get("Sec-WebSocket-Accept");
        if (!string.Equals(accept?.Trim(), WsProtocol.AcceptFor(key), StringComparison.Ordinal))
            throw new SocketFailure($"{target} answered with a wrong Sec-WebSocket-Accept — something in between (a proxy or filter) may be tampering with the handshake.");
        string? ext = head.Get("Sec-WebSocket-Extensions");
        if (!string.IsNullOrWhiteSpace(ext))
            throw new SocketFailure($"{target} turned on an extension nobody asked for ({WsProtocol.Short(Clean(ext), 60)}).");
        string? proto = head.Get("Sec-WebSocket-Protocol")?.Trim();
        if (!string.IsNullOrEmpty(proto))
        {
            if (!o.Subprotocols.Contains(proto, StringComparer.Ordinal))
                throw new SocketFailure($"{target} picked the subprotocol \"{WsProtocol.Short(Clean(proto), 40)}\", which wasn't offered.");
        }
        else proto = null;
        return new Handshake(Clean(head.StatusLine), proto, head.Get("Server") is { } srv ? WsProtocol.Short(Clean(srv), 60) : null, head.Leftover);
    }

    // Why the server didn't switch: one sentence from the status (and the start of the body, when it's text).
    private static string Refusal(HttpHead head, string target, bool tls)
    {
        int s = head.Status;
        string status = WsProtocol.Short(Clean(head.StatusLine.Length > 9 ? head.StatusLine[9..] : head.StatusLine), 60);
        string body = head.BodyExcerpt is { Length: > 0 } b ? " The server said: \"" + b + "\"" : string.Empty;
        string why = s switch
        {
            200 => $"{target} answered {status} — an ordinary web page, not a WebSocket endpoint. Check the path.",
            301 or 302 or 303 or 307 or 308 => head.Get("Location") is { } loc
                ? $"{target} redirects ({status}) to {WsProtocol.Short(Clean(loc), 120)} — connect to that URL instead."
                : $"{target} answered with a redirect ({status}) but no address.",
            400 => $"{target} rejected the handshake ({status}) — it may expect another path, subprotocol or header.",
            401 => $"{target} wants authentication ({status}) — add an Authorization header in Options.",
            403 => $"{target} refused the connection ({status}) — it may check the Origin header or a token.",
            404 => $"Nothing at this path on {target} ({status}) — check the URL's path.",
            405 => $"{target} doesn't allow a WebSocket upgrade at this path ({status}).",
            426 => $"{target} asks for another protocol version ({status}).",
            429 => $"{target} is rate-limiting this client ({status}) — try again later.",
            >= 500 => $"{target} failed while answering ({status}).",
            _ => $"{target} answered {status} instead of switching to WebSocket.",
        };
        return why + body;
    }

    // ---------------------------------------------------------------- proxies

    private static (string Kind, string Host, int Port, string? User, string? Pass, string Label) ParseProxy(string raw)
    {
        string shown = HttpHelper.WithoutUserInfo(raw);
        if (!HttpHelper.TryParseProxy(raw, out var p))
            throw new SocketFailure($"Invalid proxy address '{WsProtocol.Short(shown, 60)}' — use host:port, http://host:port or socks5://host:port.");
        string scheme = p.Scheme.ToLowerInvariant();
        string kind = scheme switch
        {
            "http" => "http",
            "socks5" or "socks5h" => "socks5",
            "https" => throw new SocketFailure("An HTTPS proxy (TLS to the proxy itself) isn't supported — use http:// or socks5://."),
            "socks4" or "socks4a" => throw new SocketFailure("SOCKS4 isn't supported — use SOCKS5 or an HTTP proxy."),
            _ => throw new SocketFailure($"Unknown proxy type \"{scheme}\" — use http:// or socks5://."),
        };
        int port = p.IsDefaultPort || p.Port <= 0 ? (kind == "socks5" ? 1080 : 8080) : p.Port;
        string? user = null, pass = null;
        if (!string.IsNullOrEmpty(p.UserInfo))
        {
            int c = p.UserInfo.IndexOf(':');
            user = Uri.UnescapeDataString(c >= 0 ? p.UserInfo[..c] : p.UserInfo);
            pass = c >= 0 ? Uri.UnescapeDataString(p.UserInfo[(c + 1)..]) : string.Empty;
        }
        string h = p.IdnHost.Trim('[', ']');
        string label = (kind == "socks5" ? "SOCKS5 proxy " : "HTTP proxy ") + SocketNet.Target(h, port);
        return (kind, h, port, user, pass, label);
    }

    private static async Task HttpConnectAsync(Stream s, string host, int port, string? user, string? pass, CancellationToken ct)
    {
        string authority = SocketNet.Target(host, port);
        var sb = new StringBuilder();
        sb.Append("CONNECT ").Append(authority).Append(" HTTP/1.1\r\nHost: ").Append(authority).Append("\r\n");
        if (user != null)
            sb.Append("Proxy-Authorization: Basic ").Append(Convert.ToBase64String(Encoding.UTF8.GetBytes(user + ":" + pass))).Append("\r\n");
        sb.Append("User-Agent: ").Append(UserAgent).Append("\r\n\r\n");
        await s.WriteAsync(Encoding.ASCII.GetBytes(sb.ToString()), ct).ConfigureAwait(false);
        HttpHead head;
        try { head = await ReadHeadAsync(s, ct, readBody: false).ConfigureAwait(false); }
        catch (SocketFailure f) { throw new SocketFailure("The HTTP proxy didn't answer properly: " + f.Message, f); }
        if (head.Status is >= 200 and < 300) return;
        string status = WsProtocol.Short(Clean(head.StatusLine.Length > 9 ? head.StatusLine[9..] : head.StatusLine), 60);
        throw new SocketFailure(head.Status switch
        {
            407 => user == null
                ? $"The proxy wants a username and password ({status}) — use http://user:password@host:port."
                : $"The proxy rejected the username / password ({status}).",
            403 => $"The proxy doesn't allow a tunnel to {authority} ({status}).",
            502 or 503 or 504 => $"The proxy couldn't reach {authority} ({status}).",
            _ => $"The proxy refused the tunnel to {authority} ({status}).",
        });
    }

    private static async Task Socks5ConnectAsync(Stream s, string host, int port, string? user, string? pass, CancellationToken ct)
    {
        var buf = new byte[600];
        byte[] hello = user != null ? new byte[] { 5, 2, 0, 2 } : new byte[] { 5, 1, 0 };
        await s.WriteAsync(hello, ct).ConfigureAwait(false);
        await ReadExactAsync(s, buf, 2, ct).ConfigureAwait(false);
        if (buf[0] != 5) throw new SocketFailure("That proxy doesn't speak SOCKS5 (wrong reply) — is it an HTTP proxy?");
        if (buf[1] == 0xFF)
            throw new SocketFailure(user == null
                ? "The SOCKS5 proxy wants a username and password — use socks5://user:password@host:port."
                : "The SOCKS5 proxy accepts none of the offered sign-in methods.");
        if (buf[1] == 2)
        {
            if (user == null) throw new SocketFailure("The SOCKS5 proxy wants a username and password — use socks5://user:password@host:port.");
            byte[] u = Encoding.UTF8.GetBytes(user), p = Encoding.UTF8.GetBytes(pass ?? string.Empty);
            if (u.Length > 255 || p.Length > 255) throw new SocketFailure("The proxy username or password is longer than SOCKS5 allows (255 bytes).");
            var auth = new byte[3 + u.Length + p.Length];
            auth[0] = 1;
            auth[1] = (byte)u.Length;
            u.CopyTo(auth, 2);
            auth[2 + u.Length] = (byte)p.Length;
            p.CopyTo(auth, 3 + u.Length);
            await s.WriteAsync(auth, ct).ConfigureAwait(false);
            await ReadExactAsync(s, buf, 2, ct).ConfigureAwait(false);
            if (buf[1] != 0) throw new SocketFailure("The SOCKS5 proxy rejected the username / password.");
        }
        else if (buf[1] != 0) throw new SocketFailure("The SOCKS5 proxy asked for an unsupported sign-in method.");

        // CONNECT: an IP literal as such, a name as a name (resolved by the proxy — no local DNS lookup leaks past it)
        var req = new List<byte> { 5, 1, 0 };
        if (IPAddress.TryParse(host, out var ip))
        {
            req.Add(ip.AddressFamily == AddressFamily.InterNetworkV6 ? (byte)4 : (byte)1);
            req.AddRange(ip.GetAddressBytes());
        }
        else
        {
            byte[] name = Encoding.ASCII.GetBytes(SocketNet.AsciiHost(host));
            if (name.Length > 255) throw new SocketFailure("The host name is too long for SOCKS5.");
            req.Add(3);
            req.Add((byte)name.Length);
            req.AddRange(name);
        }
        req.Add((byte)(port >> 8));
        req.Add((byte)port);
        await s.WriteAsync(req.ToArray(), ct).ConfigureAwait(false);
        await ReadExactAsync(s, buf, 4, ct).ConfigureAwait(false);
        if (buf[1] != 0)
        {
            string target = SocketNet.Target(host, port);
            throw new SocketFailure(buf[1] switch
            {
                1 => $"The SOCKS5 proxy failed to connect to {target} (general failure).",
                2 => $"The SOCKS5 proxy's rules don't allow a connection to {target}.",
                3 => $"The SOCKS5 proxy can't reach {target}'s network.",
                4 => $"The SOCKS5 proxy can't reach {target} (host unreachable).",
                5 => $"Connection refused — nothing is listening on {target} (said the SOCKS5 proxy).",
                6 => $"The SOCKS5 proxy timed out reaching {target}.",
                7 => "The SOCKS5 proxy doesn't support CONNECT.",
                8 => "The SOCKS5 proxy doesn't support this address type.",
                _ => $"The SOCKS5 proxy refused the connection (code {buf[1]}).",
            });
        }
        int rest = buf[3] switch { 1 => 4, 4 => 16, 3 => -1, _ => 0 };
        if (rest == -1)
        {
            await ReadExactAsync(s, buf, 1, ct).ConfigureAwait(false);
            rest = buf[0];
        }
        await ReadExactAsync(s, buf, rest + 2, ct).ConfigureAwait(false);   // bound address + port
    }

    private static async Task ReadExactAsync(Stream s, byte[] buf, int count, CancellationToken ct)
    {
        int got = 0;
        while (got < count)
        {
            int n = await s.ReadAsync(buf.AsMemory(got, count - got), ct).ConfigureAwait(false);
            if (n <= 0) throw new SocketFailure("The proxy closed the connection during the handshake.");
            got += n;
        }
    }

    // ---------------------------------------------------------------- HTTP head

    private sealed class HttpHead
    {
        public string StatusLine = string.Empty;
        public int Status;
        public readonly List<KeyValuePair<string, string>> Headers = new();
        public byte[] Leftover = Array.Empty<byte>();
        public string? BodyExcerpt;
        public string? Get(string name)
        {
            foreach (var h in Headers) if (h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)) return h.Value;
            return null;
        }
    }

    // Reads up to the blank line (at most MaxHeadBytes). The bytes after it stay in Leftover (a server may send its first
    // frame in the same packet as the 101). For a refusal, the start of a text body is kept for the message.
    private static async Task<HttpHead> ReadHeadAsync(Stream s, CancellationToken ct, bool readBody = true)
    {
        var buf = new byte[MaxHeadBytes];
        int len = 0, end = -1;
        while (end < 0)
        {
            if (len >= buf.Length) throw new SocketFailure("The answer's headers are larger than 16 KB.");
            int n = await s.ReadAsync(buf.AsMemory(len, buf.Length - len), ct).ConfigureAwait(false);
            if (n <= 0)
            {
                if (len == 0) throw new SocketFailure("The server closed the connection without answering the handshake (it may want wss://, or this isn't a WebSocket endpoint).");
                throw new SocketFailure("The connection closed in the middle of the answer.");
            }
            int from = Math.Max(0, len - 3);
            len += n;
            int i = buf.AsSpan(from, len - from).IndexOf("\r\n\r\n"u8);
            if (i >= 0) end = from + i;
        }
        string text = Encoding.ASCII.GetString(buf, 0, end);
        var lines = text.Split("\r\n");
        var head = new HttpHead { StatusLine = lines[0] };
        var parts = lines[0].Split(' ', 3);
        if (!lines[0].StartsWith("HTTP/1.", StringComparison.Ordinal) || parts.Length < 2
            || !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out head.Status))
            throw new SocketFailure($"The server didn't answer with HTTP (got \"{WsProtocol.Short(Clean(lines[0]), 50)}\") — is this a WebSocket endpoint?");
        for (int i = 1; i < lines.Length; i++)
        {
            int c = lines[i].IndexOf(':');
            if (c > 0) head.Headers.Add(new KeyValuePair<string, string>(lines[i][..c].Trim(), lines[i][(c + 1)..].Trim()));
        }
        int bodyStart = end + 4;
        head.Leftover = buf.AsSpan(bodyStart, len - bodyStart).ToArray();
        if (readBody && head.Status != 101)
        {
            // the start of a refusal's body: what's already here, or what arrives within a moment
            byte[] body = head.Leftover;
            if (body.Length == 0)
            {
                try
                {
                    using var quick = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    quick.CancelAfter(400);
                    var more = new byte[2048];
                    int n = await s.ReadAsync(more, quick.Token).ConfigureAwait(false);
                    body = more.AsSpan(0, Math.Max(0, n)).ToArray();
                }
                catch { /* nothing more */ }
            }
            if (body.Length > 0 && SocketPayload.LooksLikeText(body.AsSpan(0, Math.Min(body.Length, 512))))
            {
                string t = Clean(Encoding.UTF8.GetString(body, 0, Math.Min(body.Length, 512))).Trim();
                if (t.Length > 0 && !t.StartsWith('<')) head.BodyExcerpt = WsProtocol.Short(t, 120);
            }
        }
        return head;
    }

    // Server text going into a message: control characters, line / paragraph separators and bidi controls replaced.
    internal static string Clean(string s)
    {
        var sb = new StringBuilder(Math.Min(s.Length, 512));
        foreach (char c in s)
        {
            if (sb.Length >= 512) break;
            sb.Append(char.IsControl(c) || c is >= (char)0x2028 and <= (char)0x202E || c is >= (char)0x2066 and <= (char)0x2069 ? ' ' : c);
        }
        return sb.ToString();
    }
}
