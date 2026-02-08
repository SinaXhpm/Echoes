using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Echoes.ViewModels;

public partial class CurlViewModel : ObservableObject
{
    private Process? _currentProcess;

    [ObservableProperty] private string _url = "https://api.ipify.org";
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

    [RelayCommand]
    private void StopCurl()
    {
        IsWorking = false;
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

    private async Task GetWindowsCertificateDetails(string url)
    {
        try
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return;

            using var client = new TcpClient();
            await client.ConnectAsync(uri.Host, uri.Port > 0 ? uri.Port : 443);

            using var sslStream = new SslStream(client.GetStream(), false, (sender, certificate, chain, sslPolicyErrors) => true);
            await sslStream.AuthenticateAsClientAsync(uri.Host);

            if (sslStream.RemoteCertificate is X509Certificate2 cert)
            {
                var sb = new StringBuilder();
                sb.AppendLine("* Windows Native Certificate Info:");
                sb.AppendLine($"* Subject: {cert.Subject}");
                sb.AppendLine($"* Issuer: {cert.Issuer}");
                sb.AppendLine($"* Algorithm: {cert.SignatureAlgorithm.FriendlyName}");
                sb.AppendLine($"* Validity: {cert.NotBefore:MMM dd HH:mm:ss yyyy} to {cert.NotAfter:MMM dd HH:mm:ss yyyy}");

                int keySize = 0;
                using (var rsa = cert.GetRSAPublicKey()) { if (rsa != null) keySize = rsa.KeySize; }
                if (keySize == 0) { using (var ecdsa = cert.GetECDsaPublicKey()) { if (ecdsa != null) keySize = ecdsa.KeySize; } }

                sb.AppendLine($"* Key Size: {keySize} bits");
                sb.AppendLine("* --------------------------------------------------");

                SslLog = sb.ToString();
            }
        }
        catch (Exception ex)
        {
            SslLog = $"* Windows SSL Diagnostic Error: {ex.Message}{Environment.NewLine}";
        }
    }

    [RelayCommand]
    private async Task ExecuteCurl()
    {
        if (string.IsNullOrWhiteSpace(Url) || IsWorking) return;
        IsWorking = true;

        RawBody = SslLog = HeadersLog = FullLog = string.Empty;

        _ = GetWindowsCertificateDetails(Url);

        string guid = Guid.NewGuid().ToString();
        string traceFile = Path.Combine(Path.GetTempPath(), $"echoes_trace_{guid}.txt");

        var args = new List<string> { "-v", "-s", "-L", $"--trace-ascii \"{traceFile}\"" };

        if (SkipSslVerify) args.Add("-k");
        if (!string.IsNullOrWhiteSpace(Proxy))
        {
            args.Add($"-x \"{Proxy}\"");
            if (!string.IsNullOrWhiteSpace(ProxyUser) || !string.IsNullOrWhiteSpace(ProxyPass))
                args.Add($"-U \"{ProxyUser}:{ProxyPass}\"");
        }

        if (!string.IsNullOrWhiteSpace(OverrideIp) && Uri.TryCreate(Url, UriKind.Absolute, out var uri))
        {
            int port = uri.Port > 0 ? uri.Port : (uri.Scheme == "https" ? 443 : 80);
            args.Add($"--resolve \"{uri.Host}:{port}:{OverrideIp}\"");
        }

        if (!string.IsNullOrWhiteSpace(CustomFlags)) args.Add(CustomFlags);
        args.Add($"\"{Url}\"");

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "curl",
                Arguments = string.Join(" ", args),
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

                RawBody = outputTask.Result;
                string stdErr = errorTask.Result;

                await _currentProcess.WaitForExitAsync();

                if (File.Exists(traceFile))
                {
                    var traceLines = await File.ReadAllLinesAsync(traceFile);
                    ParseTraceLog(traceLines, stdErr);
                }
                else if (!string.IsNullOrEmpty(stdErr))
                {
                    FullLog = stdErr;
                }
            }
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
            try { if (File.Exists(traceFile)) File.Delete(traceFile); } catch { }
        }
    }

    private void ParseTraceLog(string[] lines, string stdErr)
    {
        var full = new StringBuilder();
        if (!string.IsNullOrEmpty(stdErr))
        {
            full.AppendLine("* CLI Standard Error Output:");
            full.AppendLine(stdErr);
            full.AppendLine("* --------------------------------------------------");
        }

        var ssl = new StringBuilder(SslLog);
        var headers = new StringBuilder();
        string? lastSection = null;

        foreach (var line in lines)
        {
            if (line.StartsWith("== Info:"))
            {
                string infoLine = line.Replace("== Info:", "*");
                full.AppendLine(infoLine);
                ssl.AppendLine(infoLine);
                lastSection = "SSL";
            }
            else if (line.StartsWith("=> Send header")) { lastSection = "REQ_HEAD"; }
            else if (line.StartsWith("<= Recv header")) { lastSection = "RES_HEAD"; }
            else if (line.StartsWith("=> Send data") || line.StartsWith("<= Recv data")) { lastSection = "DATA"; }
            else if (line.StartsWith("0000:") || line.StartsWith("0010:") || line.StartsWith("0020:"))
            {
                if (line.Length < 7) continue;
                string cleanLine = line.Substring(6).Trim();
                if (string.IsNullOrEmpty(cleanLine)) continue;

                if (lastSection == "REQ_HEAD") { full.AppendLine($"> {cleanLine}"); headers.AppendLine($"> {cleanLine}"); }
                else if (lastSection == "RES_HEAD") { full.AppendLine($"< {cleanLine}"); headers.AppendLine($"< {cleanLine}"); }
                else if (lastSection == "SSL") { full.AppendLine($"* {cleanLine}"); ssl.AppendLine($"* {cleanLine}"); }
            }
        }

        FullLog = full.ToString();
        SslLog = ssl.ToString();
        HeadersLog = headers.ToString();
    }

    [RelayCommand(AllowConcurrentExecutions = true)]
    private async Task ToggleCurl()
    {
        if (IsWorking) StopCurl();
        else await ExecuteCurl();
    }
}