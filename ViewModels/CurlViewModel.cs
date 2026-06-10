using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
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

public partial class CurlViewModel : ObservableObject
{
    private Process? _currentProcess;
    private CancellationTokenSource? _dotNetCts;

    [ObservableProperty] private string _url = "https://";
    [ObservableProperty] private string _overrideIp = string.Empty;
    [ObservableProperty] private string _proxy = string.Empty;
    [ObservableProperty] private string _proxyUser = string.Empty;
    [ObservableProperty] private string _proxyPass = string.Empty;
    [ObservableProperty] private string _customFlags = string.Empty;
    [ObservableProperty] private bool _skipSslVerify;

    [ObservableProperty] private string _rawBody = string.Empty;
    [ObservableProperty] private string _sslLog = string.Empty;
    [ObservableProperty] private string _headersLog = string.Empty;
    [ObservableProperty] private string _fullLog = string.Empty;

    [ObservableProperty] private string _htmlPath = "about:blank";
    [ObservableProperty] private bool _isWorking;

    [ObservableProperty] private bool _useDotNetEngine;
    [ObservableProperty] private string _httpMethod = "GET";

    public List<string> HttpMethods { get; } = new() { "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS" };

    partial void OnHttpMethodChanged(string value) => UpdateCommand();

    public ObservableCollection<string> UrlHistory => HistoryService.Instance.Get("curl.url");
    public ObservableCollection<string> ProxyHistory => HistoryService.Instance.Get("curl.proxy");

    public CurlViewModel()
    {
        if (HistoryService.Instance.Last("curl.url") is { } u) Url = u;
        if (HistoryService.Instance.Last("curl.proxy") is { } p) Proxy = p;
    }

    partial void OnUrlChanged(string value) => UpdateCommand();
    partial void OnOverrideIpChanged(string value) => UpdateCommand();
    partial void OnProxyChanged(string value) => UpdateCommand();
    partial void OnProxyUserChanged(string value) => UpdateCommand();
    partial void OnProxyPassChanged(string value) => UpdateCommand();
    partial void OnSkipSslVerifyChanged(bool value) => UpdateCommand();

    private void UpdateCommand()
    {
        var args = new List<string> { "-v", "-s", "-L" };

        if (!string.IsNullOrEmpty(HttpMethod) && HttpMethod != "GET") args.Add($"-X {HttpMethod}");
        if (SkipSslVerify) args.Add("-k");
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
                args.Add($"--connect-to \"{uri.Host}:{urlPort}:{ipPart}:{targetPort}\"");
        }

        args.Add($"\"{Url}\"");
        CustomFlags = string.Join(" ", args);
    }

    [RelayCommand]
    private void StopCurl()
    {
        IsWorking = false;
        try { _dotNetCts?.Cancel(); } catch { }
        try
        {
            if (_currentProcess != null && !_currentProcess.HasExited)
            {
                _currentProcess.Kill(true);
            }
        }
        catch { }
        _currentProcess = null;
    }

    private async Task GetCertificateDetails(string url)
    {
        try
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return;
            if (uri.Scheme != Uri.UriSchemeHttps) { SslLog = "  Not an HTTPS URL — no TLS certificate to inspect."; return; }

            int port = uri.Port > 0 ? uri.Port : 443;

            using var client = new TcpClient();
            await client.ConnectAsync(uri.Host, port);

            var policyErrors = SslPolicyErrors.None;
            using var sslStream = new SslStream(client.GetStream(), false,
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
            await sslStream.AuthenticateAsClientAsync(sslOptions);

            var sb = new StringBuilder();

            Section(sb, $"TLS CONNECTION — {uri.Host}:{port}");
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

            SslLog = TextLimit.Cap(sb.ToString().TrimStart('\r', '\n'));
        }
        catch (Exception ex)
        {
            SslLog = $"  TLS Diagnostic Error: {ex.Message}{Environment.NewLine}";
        }
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

        _ = GetCertificateDetails(Url);

        // -v is required for the verbose parser; it's normally already in CustomFlags, so don't duplicate it.
        string finalArgs = System.Text.RegularExpressions.Regex.IsMatch(CustomFlags, @"(^|\s)-v(\s|$)")
            ? CustomFlags
            : $"{CustomFlags} -v";

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "curl",
                Arguments = finalArgs,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8
            };

            _currentProcess = Process.Start(psi);

            if (_currentProcess != null)
            {
                var outputTask = _currentProcess.StandardOutput.ReadToEndAsync();
                var errorTask = _currentProcess.StandardError.ReadToEndAsync();

                await Task.WhenAll(outputTask, errorTask);

                if (!IsWorking) return;

                RawBody = TextLimit.Cap(outputTask.Result);
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
        if (IsWorking) StopCurl();
        else if (UseDotNetEngine) await ExecuteDotNet();
        else await ExecuteCurl();
    }

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

        HistoryService.Instance.Add("curl.url", spec.Url);
        if (!string.IsNullOrWhiteSpace(spec.Proxy)) HistoryService.Instance.Add("curl.proxy", spec.Proxy);

        _ = GetCertificateDetails(spec.Url);   // populates SSL INFO tab (cross-platform)

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

        if (spec.Overrides.Count > 0)
        {
            // curl --resolve / --connect-to: dial the override IP but keep Host/SNI from the URL.
            handler.ConnectCallback = async (ctx, ct) =>
            {
                string host = ctx.DnsEndPoint.Host;
                string target = spec.Overrides.TryGetValue(host, out var ip) ? ip : host;
                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try { await socket.ConnectAsync(target, ctx.DnsEndPoint.Port, ct); return new NetworkStream(socket, true); }
                catch { socket.Dispose(); throw; }
            };
        }

        try
        {
            _dotNetCts = new CancellationTokenSource();
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(100) };
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
            using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseContentRead, _dotNetCts.Token);
            string body = await resp.Content.ReadAsStringAsync(_dotNetCts.Token);
            sw.Stop();

            if (!IsWorking) return;

            RawBody = TextLimit.Cap(body);
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