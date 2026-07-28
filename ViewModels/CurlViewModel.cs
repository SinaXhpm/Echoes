using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Threading;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

/// <summary>A selectable outgoing network interface. Ip == null means "Auto" (let the OS route).</summary>
public sealed record NicOption(string Display, string? Ip)
{
    public override string ToString() => Display;
}

public partial class CurlViewModel : ObservableObject
{
    private Process? _currentProcess;
    private CancellationTokenSource? _dotNetCts;
    // Generation token so only the latest TLS-diagnostic task may write SslLog.
    // Prevents a slow, fire-and-forget cert probe from an earlier run overwriting
    // the SSL INFO tab after a newer run cleared it (the "SSL doesn't clear" bug).
    private int _sslGen;

    [ObservableProperty] private string _url = "https://";
    [ObservableProperty] private string _overrideIp = string.Empty;
    [ObservableProperty] private string _proxy = string.Empty;
    [ObservableProperty] private string _proxyUser = string.Empty;
    [ObservableProperty] private string _proxyPass = string.Empty;
    [ObservableProperty] private string _customFlags = string.Empty;
    [ObservableProperty] private bool _skipSslVerify;

    // Structured request builder (REQUEST section). Headers = one "Key: Value" per line; Body = raw
    // payload for POST/PUT/PATCH. Timeout + FollowRedirects fold into the command for both engines.
    [ObservableProperty] private string _requestHeaders = string.Empty;
    [ObservableProperty] private string _requestBody = string.Empty;
    [ObservableProperty] private int _timeoutSec = 30;
    [ObservableProperty] private bool _followRedirects = true;

    // Outer REQUEST(0)/RESPONSE(1) section selector — defaults to RESPONSE, auto-jumps there after a run.
    [ObservableProperty] private int _sectionIndex = 1;

    // Full (uncapped) response body — RawBody shown in the UI is capped for smoothness; this backs
    // the "save response" button so the complete source is written to disk without lagging the UI.
    private string _rawBodyFull = string.Empty;
    public string RawBodyFull => _rawBodyFull;

    [ObservableProperty] private string _rawBody = string.Empty;
    [ObservableProperty] private string _sslLog = string.Empty;
    [ObservableProperty] private string _headersLog = string.Empty;
    [ObservableProperty] private string _fullLog = string.Empty;

    // Rendered "web" view (Curl → WEB tab). We render the ACTUAL response body that the configured
    // request returned — through the same proxy / override IP / interface — instead of letting the
    // OS WebView do its own fresh navigation to the URL (which would ignore all of that). WebBaseUri
    // lets the document's relative assets resolve against the original URL. The view (code-behind)
    // renders via NativeWebView.NavigateToString when RenderWebRequested fires.
    public string WebHtml { get; private set; } = string.Empty;
    public Uri? WebBaseUri { get; private set; }
    public event Action? RenderWebRequested;

    // WebView2's NavigateToString caps around 2 MB; keep the rendered document under that (the full
    // body is still available in the BODY tab / save).
    private const int WebRenderCap = 2_000_000;

    private void RenderWeb(string? body, string? url)
    {
        WebHtml = string.IsNullOrEmpty(body) ? string.Empty
                : (body.Length > WebRenderCap ? body[..WebRenderCap] : body);
        WebBaseUri = Uri.TryCreate(url, UriKind.Absolute, out var u) &&
                     (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps) ? u : null;
        RenderWebRequested?.Invoke();
    }

    // Live request timer + response size, shown atop the WEB tab. The timer counts up while the
    // request is in flight (DispatcherTimer), then freezes at the final elapsed time.
    [ObservableProperty] private string _requestTimeText = "—";
    [ObservableProperty] private string _responseSizeText = "—";
    private readonly Stopwatch _reqSw = new();
    private Avalonia.Threading.DispatcherTimer? _reqTimer;

    [ObservableProperty] private string _htmlPath = "about:blank";
    [ObservableProperty] private bool _isWorking;

    [ObservableProperty] private bool _useDotNetEngine;
    [ObservableProperty] private string _httpMethod = "GET";
    [ObservableProperty] private bool _useProxy;

    [ObservableProperty] private bool _wrapRawBody;
    // Drives the RAW BODY pane's TextWrapping (overrides the read-only NoWrap style).
    public Avalonia.Media.TextWrapping RawBodyWrapping
        => WrapRawBody ? Avalonia.Media.TextWrapping.Wrap : Avalonia.Media.TextWrapping.NoWrap;
    partial void OnWrapRawBodyChanged(bool value) => OnPropertyChanged(nameof(RawBodyWrapping));

    // ---- CODE tab: the current request as a copyable snippet, in sync with what would be sent ----
    public string[] SnippetLanguages => Echoes.Helpers.RequestSnippets.Languages;
    [ObservableProperty] private string _snippetLanguage = "curl";
    [ObservableProperty] private string _snippetCode = string.Empty;
    partial void OnSnippetLanguageChanged(string value) => RegenerateSnippet();
    partial void OnRequestBodyChanged(string value) => RegenerateSnippet();

    private void RegenerateSnippet()
    {
        try
        {
            var headers = RequestHeaders.Split('\n')
                .Select(h => h.Trim().TrimEnd('\r'))
                .Where(l => l.Length > 0 && l.Contains(':'))
                .Select(l => { int i = l.IndexOf(':'); return (l[..i].Trim(), l[(i + 1)..].Trim()); })
                .ToList();
            var spec = new Echoes.Helpers.RequestSnippets.Spec(
                string.IsNullOrEmpty(HttpMethod) ? "GET" : HttpMethod, Url, headers,
                string.IsNullOrEmpty(RequestBody) ? null : RequestBody,
                string.IsNullOrWhiteSpace(Proxy) ? null : Proxy, ProxyUser, ProxyPass,
                SkipSslVerify, FollowRedirects, TimeoutSec,
                string.IsNullOrWhiteSpace(OverrideIp) ? null : OverrideIp);
            SnippetCode = Echoes.Helpers.RequestSnippets.Build(SnippetLanguage, spec);
        }
        catch (Exception ex) { SnippetCode = "# " + ex.Message; }
    }

    [RelayCommand]
    private async Task CopySnippet() => await Echoes.Helpers.ClipboardHelper.SetTextAsync(SnippetCode);

    // Outgoing network interface (source IP binding). Auto = let the OS route.
    [ObservableProperty] private List<NicOption> _interfaces = new();
    [ObservableProperty] private NicOption? _selectedInterface;
    private string? SelectedNicIp => SelectedInterface?.Ip;

    partial void OnSelectedInterfaceChanged(NicOption? value)
    {
        if (_loaded) Echoes.Helpers.ProfileService.Instance.SetSetting("curl.nicIp", value?.Ip ?? string.Empty);
        UpdateCommand();
    }

    // Re-enumerate NICs (e.g. when the cURL tab becomes visible) so newly up/down
    // interfaces appear; keeps the current selection if it still exists.
    public void RefreshInterfaces() => LoadInterfaces();

    private void LoadInterfaces()
    {
        var list = new List<NicOption> { new("Auto (default route)", null) };
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    var a = ua.Address;
                    if (a.AddressFamily != AddressFamily.InterNetwork && a.AddressFamily != AddressFamily.InterNetworkV6) continue;
                    if (a.IsIPv6LinkLocal || a.IsIPv6Multicast) continue;   // skip fe80::/link-local noise
                    list.Add(new NicOption($"{ni.Name} — {a}", a.ToString()));
                }
            }
        }
        catch { }

        Interfaces = list;
        string? savedIp = Echoes.Helpers.ProfileService.Instance.GetSetting("curl.nicIp");
        SelectedInterface = (!string.IsNullOrEmpty(savedIp) ? list.FirstOrDefault(n => n.Ip == savedIp) : null) ?? list[0];
    }

    public List<string> HttpMethods { get; } = new() { "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS" };

    partial void OnHttpMethodChanged(string value) => UpdateCommand();

    public ObservableCollection<string> UrlHistory => HistoryService.Instance.Get("curl.url");
    public ObservableCollection<string> ProxyHistory => HistoryService.Instance.Get("curl.proxy");

    private bool _loaded;
    private static readonly System.Collections.Generic.HashSet<string> PersistProps = new()
    { "Url", "OverrideIp", "Proxy", "ProxyUser", "ProxyPass", "CustomFlags", "SkipSslVerify", "UseDotNetEngine", "HttpMethod", "UseProxy", "WrapRawBody" };

    public CurlViewModel()
    {
        var ps = Echoes.Helpers.ProfileService.Instance;
        Url = ps.GetSetting("curl.url") ?? (HistoryService.Instance.Last("curl.url") ?? "https://");
        OverrideIp = ps.GetSetting("curl.overrideIp") ?? string.Empty;
        Proxy = ps.GetSetting("curl.proxy") ?? (HistoryService.Instance.Last("curl.proxy") ?? string.Empty);
        ProxyUser = ps.GetSetting("curl.proxyUser") ?? string.Empty;
        ProxyPass = ps.GetSetting("curl.proxyPass") ?? string.Empty;
        CustomFlags = ps.GetSetting("curl.flags") ?? string.Empty;
        SkipSslVerify = ps.GetBool("curl.skipSsl");
        // Android has no `curl` binary to shell out to, so default it to the managed .NET engine there
        // (otherwise the very first request fails with "curl not found"). Desktop keeps native curl,
        // which ships on Windows 10+/macOS/Linux. A value the user explicitly saved still wins.
        UseDotNetEngine = ps.GetBool("curl.useDotNet", OperatingSystem.IsAndroid());
        HttpMethod = ps.GetSetting("curl.method") ?? "GET";
        UseProxy = ps.GetBool("curl.useProxy");
        WrapRawBody = ps.GetBool("curl.wrapRawBody");
        LoadInterfaces();
        _loaded = true;
        RegenerateSnippet();   // populate the CODE tab from the restored request
    }

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (_loaded && e.PropertyName is { } n && PersistProps.Contains(n))
            Echoes.Helpers.ProfileService.Instance.SetMany(
                ("curl.url", Url), ("curl.overrideIp", OverrideIp), ("curl.proxy", Proxy),
                ("curl.proxyUser", ProxyUser), ("curl.proxyPass", ProxyPass), ("curl.flags", CustomFlags),
                ("curl.skipSsl", SkipSslVerify ? "true" : "false"), ("curl.useDotNet", UseDotNetEngine ? "true" : "false"),
                ("curl.method", HttpMethod), ("curl.useProxy", UseProxy ? "true" : "false"),
                ("curl.wrapRawBody", WrapRawBody ? "true" : "false"));
    }

    partial void OnUrlChanged(string value) => UpdateCommand();
    partial void OnOverrideIpChanged(string value) => UpdateCommand();
    partial void OnProxyChanged(string value) => UpdateCommand();
    partial void OnProxyUserChanged(string value) => UpdateCommand();
    partial void OnProxyPassChanged(string value) => UpdateCommand();
    partial void OnSkipSslVerifyChanged(bool value) => UpdateCommand();
    partial void OnRequestHeadersChanged(string value) => UpdateCommand();
    partial void OnTimeoutSecChanged(int value) => UpdateCommand();
    partial void OnFollowRedirectsChanged(bool value) => UpdateCommand();

    private void UpdateCommand()
    {
        var args = new List<string> { "-v", "-s" };
        if (FollowRedirects) args.Add("-L");
        if (TimeoutSec > 0) args.Add($"--max-time {TimeoutSec}");

        if (!string.IsNullOrEmpty(HttpMethod) && HttpMethod != "GET") args.Add($"-X {HttpMethod}");
        if (SkipSslVerify) args.Add("-k");

        // structured request headers (one "Key: Value" per line)
        foreach (var h in RequestHeaders.Split('\n'))
        {
            var line = h.Trim().TrimEnd('\r');
            if (line.Length > 0) args.Add($"-H \"{line.Replace("\"", "\\\"")}\"");
        }
        if (!string.IsNullOrEmpty(SelectedNicIp)) args.Add($"--interface {SelectedNicIp}");
        if (!string.IsNullOrWhiteSpace(Proxy))
        {
            args.Add($"-x \"{Proxy}\"");
            if (!string.IsNullOrWhiteSpace(ProxyUser) || !string.IsNullOrWhiteSpace(ProxyPass))
                args.Add($"-U \"{ProxyUser}:{ProxyPass}\"");
        }

        if (!string.IsNullOrWhiteSpace(OverrideIp) && Uri.TryCreate(Url, UriKind.Absolute, out var uri))
        {
            int urlPort = uri.Port > 0 ? uri.Port : (uri.Scheme == "https" ? 443 : 80);

            string ipPart = OverrideIp.Trim();
            int targetPort = urlPort;

            // Only treat a trailing ":port" as a port when the value isn't a bare IP (keeps IPv6 intact).
            if (!System.Net.IPAddress.TryParse(ipPart, out _))
            {
                int idx = ipPart.LastIndexOf(':');
                if (idx > ipPart.LastIndexOf(']') && int.TryParse(ipPart[(idx + 1)..], out int p))
                {
                    targetPort = p;
                    ipPart = ipPart[..idx];
                }
            }
            ipPart = ipPart.Trim('[', ']');

            // --resolve pins host:port to the IP (keeps Host/SNI/cert) for the common case;
            // --connect-to is used only when redirecting to a different port.
            if (targetPort == urlPort)
                args.Add($"--resolve \"{uri.Host}:{urlPort}:{ipPart}\"");
            else
            {
                // curl needs an IPv6 literal bracketed in the --connect-to host2 field.
                string h2 = ipPart.Contains(':') ? $"[{ipPart}]" : ipPart;
                args.Add($"--connect-to \"{uri.Host}:{urlPort}:{h2}:{targetPort}\"");
            }
        }

        args.Add($"\"{Url}\"");
        CustomFlags = string.Join(" ", args);

        RegenerateSnippet();   // keep the CODE tab in sync with every request-field change
    }

    [RelayCommand]
    private void StopCurl()
    {
        IsWorking = false;
        _sslGen++;   // invalidate any in-flight TLS probe so its late write is ignored
        try { _dotNetCts?.Cancel(); } catch { }
        try
        {
            if (_currentProcess != null && !_currentProcess.HasExited)
            {
                _currentProcess.Kill(true);
            }
        }
        catch { }
        _currentProcess?.Dispose();   // release the OS handle now instead of leaving it for the finalizer
        _currentProcess = null;
    }

    private async Task GetCertificateDetails(string url, int gen)
    {
        // Only write if this is still the current run (guards against stale races).
        void SetSsl(string text) { if (gen == _sslGen) SslLog = text; }

        try
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return;
            if (uri.Scheme != Uri.UriSchemeHttps) { SetSsl("  Not an HTTPS URL — no TLS certificate to inspect."); return; }

            int port = uri.Port > 0 ? uri.Port : 443;

            // Bounded: never hang the SSL probe on an unreachable host.
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(12));

            // Reach the server exactly the way the request does: through the proxy (HTTP CONNECT or
            // SOCKS5), pinned to the override IP, and/or bound to the chosen interface. Without this
            // the cert came from a fresh direct connection over the default NIC — not the request path.
            var (probeStream, via) = await OpenProbeConnectionAsync(uri, port, cts.Token);

            var policyErrors = SslPolicyErrors.None;
            using var sslStream = new SslStream(probeStream, false,
                (sender, certificate, chain, errors) => { policyErrors = errors; return true; });

            var sslOptions = new SslClientAuthenticationOptions
            {
                TargetHost = uri.Host,
                ApplicationProtocols = new List<SslApplicationProtocol>
                {
                    SslApplicationProtocol.Http2,
                    SslApplicationProtocol.Http11
                }
            };
            await sslStream.AuthenticateAsClientAsync(sslOptions, cts.Token);

            var sb = new StringBuilder();

            Section(sb, $"TLS CONNECTION — {uri.Host}:{port}");
            Row(sb, "Route", via);
            Row(sb, "Protocol", ProtocolName(sslStream.SslProtocol));
            TryRow(sb, "Cipher Suite", () => sslStream.NegotiatedCipherSuite.ToString());
            TryRow(sb, "Cipher", () => $"{sslStream.CipherAlgorithm} ({sslStream.CipherStrength}-bit)");
            TryRow(sb, "Key Exchange", () => sslStream.KeyExchangeAlgorithm.ToString());
            TryRow(sb, "MAC / Hash", () => sslStream.HashAlgorithm.ToString());
            string alpn = sslStream.NegotiatedApplicationProtocol.ToString();
            Row(sb, "ALPN", string.IsNullOrEmpty(alpn) ? "(none)" : alpn);

            if (sslStream.RemoteCertificate is X509Certificate2 cert)
            {
                Section(sb, "CERTIFICATE — SUBJECT");
                Row(sb, "Common Name", DnPart(cert.Subject, "CN"));
                AppendIf(sb, "Organization", DnPart(cert.Subject, "O"));
                Row(sb, "Alt Names (SAN)", GetSubjectAltNames(cert));

                Section(sb, "CERTIFICATE — ISSUER");
                Row(sb, "Common Name", DnPart(cert.Issuer, "CN"));
                AppendIf(sb, "Organization", DnPart(cert.Issuer, "O"));

                Section(sb, "VALIDITY");
                Row(sb, "Not Before", cert.NotBefore.ToUniversalTime().ToString("MMM dd HH:mm:ss yyyy 'UTC'"));
                Row(sb, "Not After", cert.NotAfter.ToUniversalTime().ToString("MMM dd HH:mm:ss yyyy 'UTC'"));
                Row(sb, "Status", ValidityStatus(cert));

                Section(sb, "KEY & SIGNATURE");
                Row(sb, "Public Key", PublicKeyInfo(cert));
                Row(sb, "Signature Algo", cert.SignatureAlgorithm.FriendlyName ?? cert.SignatureAlgorithm.Value ?? "—");
                Row(sb, "Serial Number", Colonize(cert.SerialNumber));
                Row(sb, "SHA-1 Thumb", Colonize(cert.Thumbprint));
                Row(sb, "SHA-256", Colonize(Convert.ToHexString(cert.GetCertHash(HashAlgorithmName.SHA256))));

                Section(sb, "EXTENSIONS");
                AppendExtensions(sb, cert);

                Section(sb, "CHAIN");
                AppendChain(sb, cert, policyErrors);
            }

            SetSsl(TextLimit.Cap(sb.ToString().TrimStart('\r', '\n')));
        }
        catch (OperationCanceledException)
        {
            SetSsl("  TLS Diagnostic: connection timed out.");
        }
        catch (Exception ex)
        {
            SetSsl($"  TLS Diagnostic Error: {ex.Message}{Environment.NewLine}");
        }
    }

    // Open a raw TCP stream to the target the SAME way the request reaches it: via the proxy
    // (HTTP CONNECT or SOCKS5), pinned to the override IP, and/or bound to the selected NIC. Returns
    // the connected stream plus a short human description of the route (shown in the SSL tab).
    private async Task<(System.IO.Stream stream, string via)> OpenProbeConnectionAsync(Uri uri, int port, CancellationToken ct)
    {
        string host = uri.Host;
        string nicSuffix = string.IsNullOrEmpty(SelectedNicIp) ? "" : $" · nic {SelectedNicIp}";

        if (!string.IsNullOrWhiteSpace(Proxy))
        {
            var (scheme, pHost, pPort) = ParseProxyEndpoint(Proxy);
            var sock = await DialSocketAsync(pHost, pPort, ct);
            var ns = new NetworkStream(sock, ownsSocket: true);
            try
            {
                if (scheme.StartsWith("socks", StringComparison.Ordinal))
                    await Socks5ConnectAsync(ns, host, port, ProxyUser, ProxyPass, ct);
                else
                    await HttpConnectAsync(ns, host, port, ProxyUser, ProxyPass, ct);
            }
            catch { ns.Dispose(); throw; }
            return (ns, $"proxy {Proxy}{nicSuffix}");
        }

        var ov = ParseOverrideTarget(uri, port);
        string dialHost = ov?.ip ?? host;
        int dialPort = ov?.port ?? port;
        var s = await DialSocketAsync(dialHost, dialPort, ct);
        string via = ov != null ? $"override {ov.Value.ip}:{ov.Value.port}{nicSuffix}"
                                 : (string.IsNullOrEmpty(SelectedNicIp) ? "direct" : $"direct{nicSuffix}");
        return (new NetworkStream(s, ownsSocket: true), via);
    }

    private async Task<Socket> DialSocketAsync(string host, int port, CancellationToken ct)
    {
        IPAddress? bindIp = null;
        if (!string.IsNullOrEmpty(SelectedNicIp)) IPAddress.TryParse(SelectedNicIp, out bindIp);
        var family = bindIp?.AddressFamily ?? AddressFamily.InterNetworkV6;
        var socket = new Socket(family, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        if (bindIp == null) socket.DualMode = true;   // default dual-stack when not binding a NIC
        try
        {
            if (bindIp != null) socket.Bind(new IPEndPoint(bindIp, 0));
            await socket.ConnectAsync(host, port, ct);
            return socket;
        }
        catch { socket.Dispose(); throw; }
    }

    private static (string scheme, string host, int port) ParseProxyEndpoint(string proxy)
    {
        string norm = HttpHelper.NormalizeProxy(proxy);
        if (Uri.TryCreate(norm, UriKind.Absolute, out var u))
        {
            string scheme = u.Scheme.ToLowerInvariant();
            int port = u.Port > 0 ? u.Port : (scheme.StartsWith("socks", StringComparison.Ordinal) ? 1080 : 8080);
            return (scheme, u.Host, port);
        }
        return ("http", proxy, 8080);
    }

    // Mirror UpdateCommand's --resolve/--connect-to parsing: OverrideIp may carry a trailing :port.
    private (string ip, int port)? ParseOverrideTarget(Uri uri, int urlPort)
    {
        if (string.IsNullOrWhiteSpace(OverrideIp)) return null;
        string ipPart = OverrideIp.Trim();
        int targetPort = urlPort;
        if (!IPAddress.TryParse(ipPart, out _))
        {
            int idx = ipPart.LastIndexOf(':');
            if (idx > ipPart.LastIndexOf(']') && int.TryParse(ipPart[(idx + 1)..], out int p))
            {
                targetPort = p;
                ipPart = ipPart[..idx];
            }
        }
        ipPart = ipPart.Trim('[', ']');
        return (ipPart, targetPort);
    }

    private static async Task HttpConnectAsync(System.IO.Stream stream, string host, int port, string? user, string? pass, CancellationToken ct)
    {
        var sb = new StringBuilder();
        sb.Append($"CONNECT {host}:{port} HTTP/1.1\r\n");
        sb.Append($"Host: {host}:{port}\r\n");
        if (!string.IsNullOrEmpty(user))
        {
            string token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user}:{pass}"));
            sb.Append($"Proxy-Authorization: Basic {token}\r\n");
        }
        sb.Append("Proxy-Connection: keep-alive\r\n\r\n");
        var reqBytes = Encoding.ASCII.GetBytes(sb.ToString());
        await stream.WriteAsync(reqBytes, ct);
        await stream.FlushAsync(ct);

        var resp = new StringBuilder();
        var one = new byte[1];
        while (!resp.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal))
        {
            int n = await stream.ReadAsync(one.AsMemory(0, 1), ct);
            if (n == 0) break;
            resp.Append((char)one[0]);
            if (resp.Length > 8192) break;
        }
        string statusLine = resp.ToString().Split('\r')[0];
        if (!statusLine.Contains(" 200")) throw new Exception("proxy CONNECT rejected: " + statusLine);
    }

    private static async Task Socks5ConnectAsync(System.IO.Stream stream, string host, int port, string? user, string? pass, CancellationToken ct)
    {
        bool wantAuth = !string.IsNullOrEmpty(user);
        byte[] greet = wantAuth ? new byte[] { 0x05, 0x02, 0x00, 0x02 } : new byte[] { 0x05, 0x01, 0x00 };
        await stream.WriteAsync(greet, ct);

        var sel = await ReadExactAsync(stream, 2, ct);
        if (sel[0] != 0x05) throw new Exception("SOCKS5: bad version");
        if (sel[1] == 0x02)
        {
            if (!wantAuth) throw new Exception("SOCKS5: proxy requires username/password");
            var u = Encoding.UTF8.GetBytes(user!);
            var p = Encoding.UTF8.GetBytes(pass ?? string.Empty);
            var authReq = new byte[3 + u.Length + p.Length];
            authReq[0] = 0x01; authReq[1] = (byte)u.Length;
            Array.Copy(u, 0, authReq, 2, u.Length);
            authReq[2 + u.Length] = (byte)p.Length;
            Array.Copy(p, 0, authReq, 3 + u.Length, p.Length);
            await stream.WriteAsync(authReq, ct);
            var ar = await ReadExactAsync(stream, 2, ct);
            if (ar[1] != 0x00) throw new Exception("SOCKS5: authentication failed");
        }
        else if (sel[1] != 0x00) throw new Exception("SOCKS5: no acceptable auth method");

        var hb = Encoding.UTF8.GetBytes(host);
        var req = new byte[7 + hb.Length];
        req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03; req[4] = (byte)hb.Length;
        Array.Copy(hb, 0, req, 5, hb.Length);
        req[5 + hb.Length] = (byte)(port >> 8);
        req[6 + hb.Length] = (byte)(port & 0xFF);
        await stream.WriteAsync(req, ct);

        var rep = await ReadExactAsync(stream, 4, ct);
        if (rep[1] != 0x00) throw new Exception($"SOCKS5: connect failed (reply 0x{rep[1]:X2})");
        int addrLen = rep[3] switch
        {
            0x01 => 4,
            0x04 => 16,
            0x03 => (await ReadExactAsync(stream, 1, ct))[0],
            _ => throw new Exception("SOCKS5: unexpected address type")
        };
        await ReadExactAsync(stream, addrLen + 2, ct);   // bound addr + port, discarded
    }

    private static async Task<byte[]> ReadExactAsync(System.IO.Stream s, int n, CancellationToken ct)
    {
        var buf = new byte[n];
        int off = 0;
        while (off < n)
        {
            int r = await s.ReadAsync(buf.AsMemory(off, n - off), ct);
            if (r == 0) throw new Exception("connection closed by peer");
            off += r;
        }
        return buf;
    }

    private static void Section(StringBuilder sb, string title)
    {
        sb.AppendLine();
        sb.AppendLine("══════════════════════════════════════════════════");
        sb.AppendLine("  " + title);
        sb.AppendLine("══════════════════════════════════════════════════");
    }

    private static void Row(StringBuilder sb, string label, string value)
        => sb.AppendLine($"  {label,-16}: {(string.IsNullOrEmpty(value) ? "—" : value)}");

    private static void AppendIf(StringBuilder sb, string label, string value)
    {
        if (!string.IsNullOrWhiteSpace(value)) Row(sb, label, value);
    }

    private static void TryRow(StringBuilder sb, string label, Func<string> getter)
    {
        try { Row(sb, label, getter()); } catch { }
    }

    private static string ProtocolName(SslProtocols p) => p switch
    {
        SslProtocols.Tls13 => "TLS 1.3",
        SslProtocols.Tls12 => "TLS 1.2",
#pragma warning disable SYSLIB0039
        SslProtocols.Tls11 => "TLS 1.1",
        SslProtocols.Tls => "TLS 1.0",
#pragma warning restore SYSLIB0039
        _ => p.ToString()
    };

    private static string ValidityStatus(X509Certificate2 cert)
    {
        var now = DateTime.Now;
        if (now < cert.NotBefore) return "NOT YET VALID";
        if (now > cert.NotAfter) return "EXPIRED";
        return $"VALID — {(cert.NotAfter - now).Days} days remaining";
    }

    private static string PublicKeyInfo(X509Certificate2 cert)
    {
        using var rsa = cert.GetRSAPublicKey();
        if (rsa != null) return $"RSA {rsa.KeySize}-bit";
        using var ecdsa = cert.GetECDsaPublicKey();
        if (ecdsa != null) return $"ECDSA {ecdsa.KeySize}-bit";
        return cert.PublicKey.Oid.FriendlyName ?? "Unknown";
    }

    private static string DnPart(string dn, string key)
    {
        if (string.IsNullOrEmpty(dn)) return "";
        foreach (var raw in dn.Split(','))
        {
            var part = raw.Trim();
            if (part.StartsWith(key + "=", StringComparison.OrdinalIgnoreCase))
                return part.Substring(key.Length + 1).Trim().Trim('"');
        }
        return "";
    }

    private static string Colonize(string hex)
    {
        if (string.IsNullOrEmpty(hex) || hex.Length % 2 != 0) return hex;
        var parts = new List<string>(hex.Length / 2);
        for (int i = 0; i < hex.Length; i += 2) parts.Add(hex.Substring(i, 2));
        return string.Join(":", parts);
    }

    private static string GetSubjectAltNames(X509Certificate2 cert)
    {
        var ext = cert.Extensions["2.5.29.17"];
        if (ext == null) return "";
        try
        {
            var san = new X509SubjectAlternativeNameExtension(ext.RawData);
            var names = san.EnumerateDnsNames().ToList();
            if (names.Count > 0) return string.Join(", ", names);
        }
        catch { }
        return ext.Format(false).Replace("DNS Name=", "").Replace(Environment.NewLine, ", ").Trim();
    }

    private static void AppendExtensions(StringBuilder sb, X509Certificate2 cert)
    {
        bool any = false;
        foreach (var ext in cert.Extensions)
        {
            switch (ext)
            {
                case X509BasicConstraintsExtension bc:
                    Row(sb, "Basic Constr.", $"CA={bc.CertificateAuthority}" + (bc.HasPathLengthConstraint ? $", PathLen={bc.PathLengthConstraint}" : ""));
                    any = true;
                    break;
                case X509KeyUsageExtension ku:
                    Row(sb, "Key Usage", ku.KeyUsages.ToString());
                    any = true;
                    break;
                case X509EnhancedKeyUsageExtension eku:
                    var usages = eku.EnhancedKeyUsages.Cast<Oid>().Select(o => o.FriendlyName ?? o.Value ?? "");
                    Row(sb, "Ext Key Usage", string.Join(", ", usages));
                    any = true;
                    break;
            }
        }
        if (!any) sb.AppendLine("  (no notable extensions)");
    }

    private static void AppendChain(StringBuilder sb, X509Certificate2 cert, SslPolicyErrors policyErrors)
    {
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            chain.Build(cert);

            int i = 0;
            int last = chain.ChainElements.Count - 1;
            foreach (var element in chain.ChainElements)
            {
                string role = i == 0 ? "leaf" : (i == last ? "root" : "intermediate");
                string cn = DnPart(element.Certificate.Subject, "CN");
                if (string.IsNullOrEmpty(cn)) cn = element.Certificate.Subject;
                sb.AppendLine($"  [{i}] {cn}  ({role})");
                i++;
            }
        }
        catch (Exception ex)
        {
            sb.AppendLine($"  Chain build error: {ex.Message}");
        }

        Row(sb, "Validation", policyErrors == SslPolicyErrors.None ? "OK (trusted)" : policyErrors.ToString());
    }

    [RelayCommand]
    private async Task ExecuteCurl()
    {
        if (string.IsNullOrWhiteSpace(CustomFlags) || IsWorking) return;
        IsWorking = true;

        HistoryService.Instance.Add("curl.url", Url);
        if (!string.IsNullOrWhiteSpace(Proxy)) HistoryService.Instance.Add("curl.proxy", Proxy);

        RawBody = SslLog = HeadersLog = FullLog = string.Empty;

        _ = GetCertificateDetails(Url, ++_sslGen);

        // -v is required for the verbose parser; it's normally already in CustomFlags, so don't duplicate it.
        string finalArgs = System.Text.RegularExpressions.Regex.IsMatch(CustomFlags, @"(^|\s)-v(\s|$)")
            ? CustomFlags
            : $"{CustomFlags} -v";

        // Send the request body (if any) via stdin — robust for JSON/quotes/newlines, no shell quoting.
        bool hasBody = !string.IsNullOrEmpty(RequestBody);
        if (hasBody) finalArgs += " --data-binary @-";

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "curl",
                Arguments = finalArgs,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardInput = hasBody,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8
            };

            _currentProcess = Process.Start(psi);

            if (_currentProcess != null)
            {
                if (hasBody)
                {
                    await _currentProcess.StandardInput.WriteAsync(RequestBody);
                    _currentProcess.StandardInput.Close();
                }
                // Bound stdout so a huge download can't balloon memory; stderr stays small (the -v trace).
                var outputTask = ReadCappedDrainAsync(_currentProcess.StandardOutput);
                var errorTask = _currentProcess.StandardError.ReadToEndAsync();

                await Task.WhenAll(outputTask, errorTask);

                if (!IsWorking) return;

                _rawBodyFull = outputTask.Result;
                RawBody = TextLimit.Cap(outputTask.Result, 60_000);   // smaller cap keeps the UI smooth
                RenderWeb(_rawBodyFull, Url);
                SetResponseSize(outputTask.Result);
                SectionIndex = 1;   // jump to the RESPONSE section
                string stdErr = errorTask.Result;

                await _currentProcess.WaitForExitAsync();

                if (!string.IsNullOrEmpty(stdErr))
                {
                    ParseTraceLog(stdErr);
                }
            }
        }
        catch (System.ComponentModel.Win32Exception)
        {
            if (IsWorking)
                FullLog = "* 'curl' was not found on this system.\n" +
                          "* The cURL Client requires the curl binary to be installed and on PATH.\n" +
                          "*   Windows 10+/macOS: bundled by default.\n" +
                          "*   Linux (Debian/Ubuntu): sudo apt install curl\n" +
                          "*   Linux (Fedora):        sudo dnf install curl";
        }
        catch (Exception ex)
        {
            if (IsWorking) FullLog = $"* Execution Error: {ex.Message}";
        }
        finally
        {
            IsWorking = false;
            _currentProcess?.Dispose();
            _currentProcess = null;
        }
    }

    private void ParseTraceLog(string stdErr)
    {
        // curl -v emits stderr lines prefixed with: '*' info/connection, '>' request, '<' response.
        var conn = new List<string>();
        var reqHeaders = new List<string>();
        var resHeaders = new List<string>();

        foreach (var rawLine in stdErr.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None))
        {
            if (rawLine.Length == 0) continue;
            char tag = rawLine[0];
            string content = rawLine.Length > 1 ? rawLine[1..].TrimStart() : string.Empty;
            if (content.Length == 0) continue;

            switch (tag)
            {
                case '*': conn.Add(content); break;
                case '>': reqHeaders.Add(content); break;
                case '<': resHeaders.Add(content); break;
                // '{' '}' are body-size markers; ignore.
            }
        }

        var headers = new StringBuilder();
        if (reqHeaders.Count > 0)
        {
            headers.AppendLine("┌─ REQUEST ───────────────────────────────");
            foreach (var l in reqHeaders) headers.AppendLine("> " + l);
        }
        if (resHeaders.Count > 0)
        {
            if (headers.Length > 0) headers.AppendLine();
            headers.AppendLine("┌─ RESPONSE ──────────────────────────────");
            foreach (var l in resHeaders) headers.AppendLine("< " + l);
        }
        HeadersLog = TextLimit.Cap(headers.ToString().TrimEnd());

        var full = new StringBuilder();
        if (conn.Count > 0)
        {
            full.AppendLine("══ CONNECTION ════════════════════════════");
            foreach (var l in conn) full.AppendLine(l);
        }
        if (reqHeaders.Count > 0)
        {
            if (full.Length > 0) full.AppendLine();
            full.AppendLine("══ REQUEST HEADERS ═══════════════════════");
            foreach (var l in reqHeaders) full.AppendLine("> " + l);
        }
        if (resHeaders.Count > 0)
        {
            if (full.Length > 0) full.AppendLine();
            full.AppendLine("══ RESPONSE HEADERS ══════════════════════");
            foreach (var l in resHeaders) full.AppendLine("< " + l);
        }
        FullLog = TextLimit.Cap(full.ToString().TrimEnd());
    }

    [RelayCommand(AllowConcurrentExecutions = true)]
    private async Task ToggleCurl()
    {
        if (IsWorking) { StopCurl(); return; }
        StartRequestTimer();
        try
        {
            if (UseDotNetEngine) await ExecuteDotNet();
            else await ExecuteCurl();
        }
        finally { StopRequestTimer(); }
    }

    // ---- request timer + response size (shown atop the WEB tab) ----

    private void StartRequestTimer()
    {
        ResponseSizeText = "—";
        RequestTimeText = "0 ms";
        _reqSw.Restart();
        _reqTimer ??= CreateReqTimer();
        _reqTimer.Start();
    }

    private Avalonia.Threading.DispatcherTimer CreateReqTimer()
    {
        var t = new Avalonia.Threading.DispatcherTimer { Interval = TimeSpan.FromMilliseconds(66) };
        t.Tick += (_, _) => RequestTimeText = FormatMs(_reqSw.ElapsedMilliseconds);
        return t;
    }

    private void StopRequestTimer()
    {
        _reqTimer?.Stop();
        _reqSw.Stop();
        RequestTimeText = FormatMs(_reqSw.ElapsedMilliseconds);
    }

    private void SetResponseSize(string? body)
        => ResponseSizeText = FileHttpServer.HumanSize(Encoding.UTF8.GetByteCount(body ?? string.Empty));

    private static string FormatMs(long ms) => ms < 1000 ? $"{ms} ms" : $"{ms / 1000.0:0.00} s";

    private async Task ExecuteDotNet()
    {
        if (string.IsNullOrWhiteSpace(CustomFlags) || IsWorking) return;
        IsWorking = true;
        RawBody = SslLog = HeadersLog = FullLog = string.Empty;

        var spec = CurlFlagParser.Parse(CustomFlags);
        if (string.IsNullOrWhiteSpace(spec.Url) || !Uri.TryCreate(spec.Url, UriKind.Absolute, out var uri))
        {
            FullLog = "* No valid URL found in the command.";
            IsWorking = false;
            return;
        }

        // structured body from the REQUEST section (overrides any --data parsed from the flags)
        if (!string.IsNullOrEmpty(RequestBody)) spec.Body = RequestBody;

        HistoryService.Instance.Add("curl.url", spec.Url);
        if (!string.IsNullOrWhiteSpace(spec.Proxy)) HistoryService.Instance.Add("curl.proxy", spec.Proxy);

        _ = GetCertificateDetails(spec.Url, ++_sslGen);   // populates SSL INFO tab (cross-platform)

        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = spec.FollowRedirects,
            AutomaticDecompression = spec.Compressed ? DecompressionMethods.All : DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(spec.ConnectTimeoutSec ?? 30)
        };

        if (spec.Insecure)
            handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;

        if (!string.IsNullOrWhiteSpace(spec.Proxy))
        {
            var proxy = new WebProxy(HttpHelper.NormalizeProxy(spec.Proxy));
            if (!string.IsNullOrEmpty(spec.ProxyUser))
                proxy.Credentials = new NetworkCredential(spec.ProxyUser, spec.ProxyPass ?? string.Empty);
            handler.Proxy = proxy;
            handler.UseProxy = true;
        }

        IPAddress? bindIp = null;
        if (!string.IsNullOrEmpty(SelectedNicIp)) IPAddress.TryParse(SelectedNicIp, out bindIp);

        if (spec.Overrides.Count > 0 || bindIp != null)
        {
            // curl --resolve / --connect-to: dial the override IP but keep Host/SNI from the URL.
            // --interface: bind the outgoing socket to the chosen NIC's source IP.
            handler.ConnectCallback = async (ctx, ct) =>
            {
                string host = ctx.DnsEndPoint.Host;
                string target = spec.Overrides.TryGetValue(host, out var ip) ? ip : host;

                var family = bindIp?.AddressFamily ?? AddressFamily.InterNetworkV6;
                var socket = new Socket(family, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                if (bindIp == null) socket.DualMode = true;   // keep default dual-stack when not binding
                try
                {
                    if (bindIp != null) socket.Bind(new IPEndPoint(bindIp, 0));
                    await socket.ConnectAsync(target, ctx.DnsEndPoint.Port, ct);
                    return new NetworkStream(socket, true);
                }
                catch { socket.Dispose(); throw; }
            };
        }

        try
        {
            _dotNetCts?.Dispose();
            _dotNetCts = new CancellationTokenSource();
            // curl -m/--max-time bounds the whole operation (not just connect); default 100s.
            int overallSec = spec.MaxTimeSec is > 0 ? spec.MaxTimeSec.Value : 100;
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(overallSec) };
            using var req = new HttpRequestMessage(new HttpMethod(spec.Method), uri);

            if (spec.Body != null)
                req.Content = new StringContent(spec.Body, Encoding.UTF8);

            foreach (var (name, value) in spec.Headers)
            {
                if (!req.Headers.TryAddWithoutValidation(name, value))
                    req.Content?.Headers.TryAddWithoutValidation(name, value);
            }
            if (spec.UserAgent != null) { req.Headers.Remove("User-Agent"); req.Headers.TryAddWithoutValidation("User-Agent", spec.UserAgent); }
            if (spec.Cookie != null) req.Headers.TryAddWithoutValidation("Cookie", spec.Cookie);
            if (spec.Referer != null) req.Headers.TryAddWithoutValidation("Referer", spec.Referer);
            if (spec.BasicUser != null)
            {
                string token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{spec.BasicUser}:{spec.BasicPass}"));
                req.Headers.TryAddWithoutValidation("Authorization", "Basic " + token);
            }

            var sw = Stopwatch.StartNew();
            // Stream the response and cap how much we pull into memory — an unbounded ReadAsStringAsync
            // on a multi-GB body would OOM the app (especially on Android).
            using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, _dotNetCts.Token);
            string body = await ReadCappedAsync(resp.Content, _dotNetCts.Token);
            sw.Stop();

            if (!IsWorking) return;

            _rawBodyFull = body;
            RawBody = TextLimit.Cap(body, 60_000);   // smaller cap keeps the UI smooth
            RenderWeb(body, spec.Url);
            SetResponseSize(body);
            SectionIndex = 1;   // jump to the RESPONSE section
            BuildDotNetLogs(spec, req, resp, sw.ElapsedMilliseconds);
        }
        catch (Exception ex)
        {
            if (IsWorking) FullLog = $"* .NET Engine Error: {ex.Message}";
        }
        finally
        {
            IsWorking = false;
        }
    }

    // Safety cap on how much of a response we hold in memory. Big enough for real API/HTML payloads,
    // small enough that a rogue multi-GB body can't OOM the app (matters most on Android).
    private const int MaxResponseBytes = 16 * 1024 * 1024;

    // Read an HttpContent stream up to MaxResponseBytes, decoding with the response's charset (UTF-8
    // fallback), and mark truncation. Uses ResponseHeadersRead upstream so nothing is pre-buffered.
    private static async Task<string> ReadCappedAsync(HttpContent content, CancellationToken ct)
    {
        await using var stream = await content.ReadAsStreamAsync(ct);
        using var ms = new System.IO.MemoryStream();
        var buf = new byte[64 * 1024];
        bool truncated = false;
        while (true)
        {
            long room = MaxResponseBytes - ms.Length;
            if (room <= 0) { truncated = await stream.ReadAsync(buf, ct) > 0; break; }
            int read = await stream.ReadAsync(buf.AsMemory(0, (int)Math.Min(buf.Length, room)), ct);
            if (read == 0) break;
            ms.Write(buf, 0, read);
        }

        var enc = ResolveCharset(content.Headers.ContentType?.CharSet);
        string text = enc.GetString(ms.GetBuffer(), 0, (int)ms.Length);
        if (truncated) text += $"\n\n… [response truncated at {MaxResponseBytes / (1024 * 1024)} MB]";
        return text;
    }

    private static Encoding ResolveCharset(string? charset)
    {
        if (!string.IsNullOrWhiteSpace(charset))
        {
            try { return Encoding.GetEncoding(charset.Trim().Trim('"')); } catch { }
        }
        return Encoding.UTF8;
    }

    // Read a text pipe up to MaxResponseBytes chars but KEEP draining past the cap so the child process
    // never blocks on a full stdout pipe (which would deadlock the concurrent stderr read).
    private static async Task<string> ReadCappedDrainAsync(System.IO.TextReader reader)
    {
        var sb = new StringBuilder();
        var buf = new char[64 * 1024];
        int read;
        while ((read = await reader.ReadAsync(buf, 0, buf.Length)) > 0)
        {
            if (sb.Length < MaxResponseBytes)
                sb.Append(buf, 0, Math.Min(read, MaxResponseBytes - sb.Length));
            // past the cap: keep reading to drain the pipe, but drop the overflow
        }
        return sb.ToString();
    }

    private void BuildDotNetLogs(HttpRequestSpec spec, HttpRequestMessage req, HttpResponseMessage resp, long ms)
    {
        var headers = new StringBuilder();
        headers.AppendLine("┌─ REQUEST ───────────────────────────────");
        headers.AppendLine($"> {spec.Method} {req.RequestUri?.PathAndQuery} HTTP/{req.Version}");
        headers.AppendLine($"> Host: {req.RequestUri?.Host}");
        foreach (var h in req.Headers)
            headers.AppendLine($"> {h.Key}: {string.Join(", ", h.Value)}");
        if (req.Content != null)
            foreach (var h in req.Content.Headers)
                headers.AppendLine($"> {h.Key}: {string.Join(", ", h.Value)}");

        headers.AppendLine();
        headers.AppendLine("┌─ RESPONSE ──────────────────────────────");
        headers.AppendLine($"< HTTP/{resp.Version} {(int)resp.StatusCode} {resp.ReasonPhrase}");
        foreach (var h in resp.Headers)
            headers.AppendLine($"< {h.Key}: {string.Join(", ", h.Value)}");
        foreach (var h in resp.Content.Headers)
            headers.AppendLine($"< {h.Key}: {string.Join(", ", h.Value)}");

        HeadersLog = TextLimit.Cap(headers.ToString().TrimEnd());

        var full = new StringBuilder();
        full.AppendLine("══ CONNECTION ════════════════════════════");
        full.AppendLine($"* Engine: .NET HttpClient");
        full.AppendLine($"* Resolved via: {(spec.Overrides.Count > 0 ? "override IP (" + string.Join(", ", spec.Overrides.Values) + ")" : "system DNS")}");
        full.AppendLine($"* TLS verification: {(spec.Insecure ? "DISABLED (-k)" : "enabled")}");
        full.AppendLine($"* Status: {(int)resp.StatusCode} {resp.ReasonPhrase}  ({ms} ms)");
        full.AppendLine();
        full.Append(headers);
        FullLog = TextLimit.Cap(full.ToString().TrimEnd());
    }
}