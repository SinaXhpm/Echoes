using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>Where the time went, in milliseconds. With redirects each phase is summed over every request (as curl's
/// -w timers are), so the phases still add up to about <see cref="TotalMs"/>.</summary>
public sealed class CurlTiming
{
    public double? DnsMs, ConnectMs, TlsMs, WaitMs, DownloadMs;
    public double TotalMs;
    public int Requests = 1;
}

/// <summary>One request/response of a redirect chain (the last one is the final response).</summary>
public sealed class CurlHop
{
    public string Method = "GET";
    public string Url = string.Empty;
    public int Status;
    public string Reason = string.Empty;
    public string? Location;
}

/// <summary>Everything one run produced — the same shape from both engines.</summary>
public sealed class CurlResult
{
    public string Engine = string.Empty;
    public bool Responded;
    public bool Cancelled;
    public int Status;
    public string Reason = string.Empty;
    public string HttpVersion = string.Empty;   // "HTTP/1.1", "HTTP/2", "HTTP/3"
    public List<(string Name, string Value)> Headers = new();
    public List<(string Name, string Value)> RequestHeaders = new();
    public List<CurlHop> Hops = new();
    public byte[] Body = Array.Empty<byte>();
    public int BodyLength;
    public bool Truncated;
    public string? ContentEncodingDecoded;      // set when the body was decompressed here
    public CurlTiming Timing = new();
    public string? RemoteAddress;
    public string FinalUrl = string.Empty;
    public string? ErrorTitle;
    public string? ErrorDetail;
    public string? ErrorHint;
    public string HeadersLog = string.Empty;
    public string FullLog = string.Empty;
    public List<string> Notes = new();

    public bool Failed => ErrorTitle != null;

    public string? Header(string name)
    {
        foreach (var (n, v) in Headers) if (n.Equals(name, StringComparison.OrdinalIgnoreCase)) return v;
        return null;
    }
}

public sealed class CurlRunOptions
{
    /// <summary>The Engine switch is on .NET (always so where there's no curl binary, e.g. Android).</summary>
    public bool PreferDotNet;
    /// <summary>Bind the outgoing socket to this local address (the Interface picker), or null.</summary>
    public string? NicIp;
    /// <summary>Opens a body / multipart file by the path the request names (default: the local file system). Android
    /// picks files through the storage provider and hands them in here.</summary>
    public Func<string, Stream>? OpenFile;
}

/// <summary>The system curl binary's version and the features its build has.</summary>
public sealed record CurlFeatures(string Path, string Version, bool Http2, bool Http3, bool Libz, bool Brotli);

/// <summary>
/// Runs a <see cref="CurlRequest"/> with the system curl binary or with .NET's HttpClient and returns one
/// <see cref="CurlResult"/>. UI-free (the test harness drives it directly). The engine switch is a preference: a request
/// that needs what the chosen engine lacks (no curl installed, a curl built without HTTP/2 or HTTP/3) goes through the
/// other one, with a note saying so.
/// </summary>
public static class CurlEngine
{
    /// <summary>How much of a response body is kept in memory (a rogue multi-GB body can't OOM the app).</summary>
    public const int MaxResponseBytes = 16 * 1024 * 1024;

    // ================================================================== entry

    public static async Task<CurlResult> RunAsync(CurlRequest request, CurlRunOptions opt, CancellationToken ct)
    {
        var r = request.Clone();
        r.Url = CurlRequest.NormalizeUrl(r.Url);
        if (r.Url.Length == 0) return Fail("No URL", "Type a URL, or paste a whole curl command into the URL box.");
        if (!Uri.TryCreate(r.Url, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            return Fail("Invalid URL", $"\"{Shorten(r.Url, 80)}\" isn't an http:// or https:// URL.");
        if (r.Proxy is { Length: > 0 } && !HttpHelper.TryParseProxy(r.Proxy, out _))
            // the address as typed may carry user:pass@ — never echo that into the UI (screenshots, copied errors)
            return Fail("Invalid proxy", $"\"{HttpHelper.WithoutUserInfo(r.Proxy)}\" isn't a proxy address — use host:port (e.g. 127.0.0.1:8080) or scheme://host:port.");

        var notes = new List<string>();
        bool canCurl = !OperatingSystem.IsAndroid() && !OperatingSystem.IsIOS() && !OperatingSystem.IsBrowser();
        bool useCurl = canCurl && !opt.PreferDotNet;
        CurlFeatures? feats = null;
        if (useCurl)
        {
            feats = await GetCurlFeaturesAsync().ConfigureAwait(false);
            if (feats is null) { useCurl = false; notes.Add("curl isn't installed here — sent with the .NET engine"); }
            else if (r.HttpVersion == CurlHttpVersion.Http2 && !feats.Http2)
            { useCurl = false; notes.Add($"This curl ({feats.Version}) is built without HTTP/2 — sent with the .NET engine"); }
            else if (r.HttpVersion == CurlHttpVersion.Http3 && !feats.Http3)
            { useCurl = false; notes.Add($"This curl ({feats.Version}) is built without HTTP/3 — sent with the .NET engine"); }
        }

        CurlResult res;
        try
        {
            res = useCurl ? await RunCurlAsync(r, uri, opt, feats!, ct).ConfigureAwait(false)
                          : await RunDotNetAsync(r, uri, opt, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            res = new CurlResult { Cancelled = true, Engine = useCurl ? "curl" : ".NET" };
        }
        catch (Exception ex)
        {
            res = Fail("Request failed", Innermost(ex).Message);
        }
        res.Notes.InsertRange(0, notes);
        return res;
    }

    private static CurlResult Fail(string title, string detail, string? hint = null)
        => new() { ErrorTitle = title, ErrorDetail = detail, ErrorHint = hint };

    private static string Shorten(string s, int max) => s.Length <= max ? s : s[..max] + "…";

    private static Exception Innermost(Exception ex)
    {
        while (ex.InnerException != null) ex = ex.InnerException;
        return ex;
    }

    /// <summary>The override (--resolve / --connect-to) for the URL's host: dial Addr (and Port, when set) instead.</summary>
    private static HostOverride? OverrideFor(CurlRequest r, Uri uri)
    {
        int urlPort = uri.Port > 0 ? uri.Port : (uri.Scheme == "https" ? 443 : 80);
        if (!CurlFlagParser.TryParseOverride(r.OverrideIp, urlPort, out var ip, out var port)) return null;
        return new HostOverride(ip, port == urlPort ? null : port, urlPort);
    }

    private static Stream OpenFile(CurlRunOptions opt, string path)
    {
        if (opt.OpenFile != null) return opt.OpenFile(path);
        return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, useAsync: true);
    }

    // ================================================================== curl binary

    private static Task<CurlFeatures?>? _features;
    private static readonly object FeaturesGate = new();

    /// <summary>The system curl (path, version, HTTP/2 / HTTP/3 support) — probed once with "curl -V"; null when there
    /// is no curl binary.</summary>
    public static Task<CurlFeatures?> GetCurlFeaturesAsync()
    {
        lock (FeaturesGate) return _features ??= Task.Run(ProbeCurl);
    }

    private static async Task<CurlFeatures?> ProbeCurl()
    {
        string? path = ResolveCurlPath();
        if (path is null) return null;
        try
        {
            var psi = new ProcessStartInfo { FileName = path, UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            psi.ArgumentList.Add("-V");
            using var p = Process.Start(psi);
            if (p is null) return null;
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            string text = await p.StandardOutput.ReadToEndAsync(cts.Token).ConfigureAwait(false);
            try { await p.WaitForExitAsync(cts.Token).ConfigureAwait(false); } catch { try { p.Kill(true); } catch { } }
            string version = "curl";
            string features = string.Empty;
            foreach (var line in text.Split('\n'))
            {
                string l = line.Trim();
                if (l.StartsWith("curl ", StringComparison.Ordinal)) { var bits = l.Split(' '); if (bits.Length > 1) version = "curl " + bits[1]; }
                else if (l.StartsWith("Features:", StringComparison.Ordinal)) features = " " + l[9..] + " ";
            }
            return new CurlFeatures(path, version, features.Contains(" HTTP2 "), features.Contains(" HTTP3 "),
                                    features.Contains(" libz "), features.Contains(" brotli "));
        }
        catch { return null; }
    }

    // Absolute path of the curl binary, or null. Never a bare "curl": Windows' CreateProcess searches the app folder and
    // the CURRENT directory before System32 (a planted curl.exe in, say, Downloads would run on Send), and .NET on Unix
    // also probes the app folder + cwd. So: System32's curl.exe on Windows, else only absolute PATH entries.
    public static string? ResolveCurlPath()
    {
        if (OperatingSystem.IsWindows())
        {
            string sys = Path.Combine(Environment.SystemDirectory, "curl.exe");
            return File.Exists(sys) ? sys : FindOnPath("curl.exe");
        }
        return FindOnPath("curl");
    }

    private static string? FindOnPath(string exe)
    {
        foreach (var raw in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(Path.PathSeparator))
        {
            string dir = raw.Trim().Trim('"');
            if (dir.Length == 0 || !Path.IsPathFullyQualified(dir)) continue;   // skips "", "." and relative entries
            try
            {
                string full = Path.Combine(dir, exe);
                if (File.Exists(full)) return full;
            }
            catch { /* malformed PATH entry */ }
        }
        return null;
    }

    private const string WriteOut =
        "%{http_code} %{http_version} %{time_namelookup} %{time_connect} %{time_appconnect} %{time_pretransfer} " +
        "%{time_starttransfer} %{time_total} %{time_redirect} %{num_redirects} %{size_download} %{remote_ip} %{remote_port} %{url_effective}";

    private static async Task<CurlResult> RunCurlAsync(CurlRequest r, Uri uri, CurlRunOptions opt, CurlFeatures feats, CancellationToken ct)
    {
        var res = new CurlResult { Engine = feats.Version, FinalUrl = r.Url };
        var headers = r.EffectiveHeaders();
        var mode = r.EffectiveBodyMode;
        if (mode == CurlBodyMode.Multipart)   // the engine writes the boundary; a typed multipart Content-Type would break it
            headers.RemoveAll(h => h.Name.Equals("Content-Type", StringComparison.OrdinalIgnoreCase));

        string marker = "@@ECHOES-" + Guid.NewGuid().ToString("N")[..16] + "@@";
        string? configPath = null;
        Process? proc = null;
        Stream? fileBody = null;
        try
        {
            byte[]? bodyBytes = r.BodyBytes();
            if (mode == CurlBodyMode.File)
            {
                try { fileBody = OpenFile(opt, r.BodyFile.Trim()); }
                catch (Exception ex) { return Fail("Can't read the body file", $"{r.BodyFile.Trim()}: {Innermost(ex).Message}"); }
            }
            if (mode == CurlBodyMode.Multipart)
            {
                foreach (var p in r.Parts.Where(p => p.Enabled && p.IsFile && p.Name.Length > 0))
                    if (!File.Exists(p.Value.Trim()))
                        return Fail("Can't read a form file", $"{p.Name}: {p.Value.Trim()} doesn't exist.");
            }

            string config = BuildCurlConfig(r, headers);
            if (config.Length > 0) configPath = WriteCurlConfig(config);
            bool stdinBody = bodyBytes != null || fileBody != null;
            var args = BuildCurlArgs(r, uri, headers, opt.NicIp, configPath, marker, stdinBody);

            var psi = new ProcessStartInfo
            {
                FileName = feats.Path,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardInput = stdinBody,
                RedirectStandardOutput = true,   // raw bytes (BaseStream): only the trace says which charset the body is in
                RedirectStandardError = true,
            };
            foreach (var a in args) psi.ArgumentList.Add(a);

            proc = Process.Start(psi);
            if (proc is null) return Fail("curl didn't start", feats.Path);
            var started = proc;
            using var reg = ct.Register(() => { try { if (!started.HasExited) started.Kill(true); } catch { } });

            // Both drains start BEFORE the body is written: curl logs to stderr while it reads stdin, so a large body could
            // otherwise fill the stderr pipe and deadlock curl and us.
            var stdout = proc.StandardOutput.BaseStream;
            var outTask = Task.Run(() => DrainStdoutAsync(stdout, marker));
            var errTask = proc.StandardError.ReadToEndAsync();

            if (stdinBody)
            {
                var stdin = proc.StandardInput.BaseStream;
                try
                {
                    if (bodyBytes != null) await stdin.WriteAsync(bodyBytes, ct).ConfigureAwait(false);
                    else if (fileBody != null) await fileBody.CopyToAsync(stdin, 64 * 1024, ct).ConfigureAwait(false);
                    await stdin.FlushAsync(ct).ConfigureAwait(false);
                }
                catch (Exception) { /* curl may exit before reading it all (bad option, Stop) — its stderr says why */ }
                finally { try { proc.StandardInput.Close(); } catch { } }
            }

            await Task.WhenAll(outTask, errTask).ConfigureAwait(false);
            await proc.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
            if (ct.IsCancellationRequested) { res.Cancelled = true; return res; }

            var (buf, len, truncated, trailer) = outTask.Result;
            string trace = errTask.Result;
            ParseCurlTrace(trace, r, res);
            ParseTrailer(trailer, res);
            res.FullLog = FormatCurlLog(trace, res);

            if (proc.ExitCode != 0) MapCurlError(proc.ExitCode, trace, res, r);

            if (!r.Method.Equals("HEAD", StringComparison.OrdinalIgnoreCase) && res.Responded)
            {
                res.Body = buf;
                res.BodyLength = len;
                res.Truncated = truncated;
                DecodeIfCompressed(res, curlDecoded: CurlCompressed(r, headers));
            }
            return res;
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            return Fail("curl couldn't be started", ex.Message, "Switch the engine to .NET in Options.");
        }
        finally
        {
            fileBody?.Dispose();
            proc?.Dispose();
            if (configPath != null) try { File.Delete(configPath); } catch { }
        }
    }

    // --compressed lets curl pick the encodings its build can decode. An explicit Accept-Encoding header (every browser's
    // "Copy as cURL" has one, often naming br / zstd that Windows' curl can't decode — it would fail with error 61) goes
    // out as typed WITHOUT --compressed: curl then writes the body as it came and it's decoded here (gzip / deflate / br).
    private static bool CurlCompressed(CurlRequest r, List<(string Name, string Value)> headers)
        => r.Compressed && !headers.Any(h => h.Name.Equals("Accept-Encoding", StringComparison.OrdinalIgnoreCase));

    // argv for the curl binary, one token per element — launched via ProcessStartInfo.ArgumentList, so nothing is ever
    // re-split or re-quoted. With configPath, headers, credentials and form fields go into that owner-only file instead
    // of the command line (see WriteCurlConfig).
    private static List<string> BuildCurlArgs(CurlRequest r, Uri uri, List<(string Name, string Value)> headers, string? nicIp,
                                              string? configPath, string marker, bool stdinBody)
    {
        // -g: brackets/braces in the URL are literal (one request, like the .NET engine), not a glob. -S: say why it failed.
        var a = new List<string> { "-v", "-s", "-S", "-g", "-w", "\\n" + marker + " " + WriteOut + "\\n" };
        if (r.FollowRedirects) { a.Add("-L"); a.Add("--max-redirs"); a.Add(r.MaxRedirects.ToString(CultureInfo.InvariantCulture)); }
        if (r.TimeoutSec > 0) { a.Add("--max-time"); a.Add(r.TimeoutSec.ToString(CultureInfo.InvariantCulture)); }
        if (r.ConnectTimeoutSec > 0) { a.Add("--connect-timeout"); a.Add(r.ConnectTimeoutSec.ToString(CultureInfo.InvariantCulture)); }

        var mode = r.EffectiveBodyMode;
        bool hasBody = mode != CurlBodyMode.None;
        // HEAD must be -I (with -X HEAD curl waits for a body that never comes). A body makes curl POST by itself; an
        // explicit -X POST would keep POST across a 301/302/303 that a browser (and the .NET engine) turns into GET.
        switch (r.Method)
        {
            case "HEAD": a.Add("-I"); break;
            case "GET": if (hasBody) { a.Add("-X"); a.Add("GET"); } break;
            case "POST": if (!hasBody) { a.Add("-X"); a.Add("POST"); } break;
            default: a.Add("-X"); a.Add(r.Method); break;
        }
        if (r.Insecure) a.Add("-k");
        if (CurlCompressed(r, headers)) a.Add("--compressed");
        switch (r.HttpVersion)
        {
            case CurlHttpVersion.Http1: a.Add("--http1.1"); break;
            case CurlHttpVersion.Http2: a.Add("--http2"); break;
            case CurlHttpVersion.Http3: a.Add("--http3"); break;
        }

        if (configPath != null) { a.Add("-K"); a.Add(configPath); }
        else
        {
            foreach (var h in headers) { a.Add("-H"); a.Add(HeaderArg(h)); }
            if (HasProxyCreds(r)) { a.Add("-U"); a.Add($"{r.ProxyUser}:{r.ProxyPass}"); }
            if (mode == CurlBodyMode.Multipart)
                foreach (var (opt, value) in FormEntries(r)) { a.Add("--" + opt); a.Add(value); }
        }
        if (!string.IsNullOrEmpty(nicIp)) { a.Add("--interface"); a.Add(nicIp); }
        if (!string.IsNullOrWhiteSpace(r.Proxy) && (configPath == null || !ProxyInConfig(r))) { a.Add("-x"); a.Add(HttpHelper.CurlProxyArg(r.Proxy)); }

        if (OverrideFor(r, uri) is { } ov)
        {
            string host = uri.IdnHost;
            string h1 = host.Contains(':') ? $"[{host}]" : host;
            if (ov.Port is int p2)
            {
                string h2 = ov.Addr.Contains(':') ? $"[{ov.Addr}]" : ov.Addr;   // curl wants an IPv6 literal bracketed here
                a.Add("--connect-to"); a.Add($"{h1}:{ov.FromPort}:{h2}:{p2}");
            }
            else { a.Add("--resolve"); a.Add($"{h1}:{ov.FromPort}:{ov.Addr}"); }
        }

        if (stdinBody) { a.Add("--data-binary"); a.Add("@-"); }   // raw / form / file bodies are streamed via stdin
        if (configPath == null || !UrlInConfig(r)) { a.Add("--url"); a.Add(r.Url); }   // --url: a URL can't be read as an option
        return a;
    }

    private static bool HasProxyCreds(CurlRequest r)
        => !string.IsNullOrWhiteSpace(r.Proxy) && (!string.IsNullOrEmpty(r.ProxyUser) || !string.IsNullOrEmpty(r.ProxyPass));

    // "Name: value"; an empty value is "Name;" (curl reads "Name:" as "remove this header").
    private static string HeaderArg((string Name, string Value) h) => h.Value.Length == 0 ? h.Name + ";" : $"{h.Name}: {h.Value}";

    // -F / --form-string entries for a multipart body. Text values go as --form-string (a value starting with @ or <, or
    // holding ';type=', is never read as a file / parameter); files as name=@"path";type=…;filename=….
    private static IEnumerable<(string Option, string Value)> FormEntries(CurlRequest r)
    {
        foreach (var p in r.Parts.Where(p => p.Enabled && p.Name.Length > 0))
        {
            string type = CurlRequest.SafeMimeType(p.ContentType);   // never a raw ";…" that curl would read as another -F directive
            if (!p.IsFile)
            {
                if (type.Length == 0) yield return ("form-string", $"{p.Name}={p.Value}");
                else yield return ("form", $"{p.Name}={FormWord(p.Value)};type={type}");
                continue;
            }
            var sb = new StringBuilder();
            sb.Append(p.Name).Append("=@").Append(FormWord(p.Value.Trim()));
            sb.Append(";type=").Append(type.Length == 0 ? CurlRequest.GuessMime(p.Value, "application/octet-stream") : type);
            if (!string.IsNullOrEmpty(p.FileName)) sb.Append(";filename=").Append(FormWord(p.FileName));
            yield return ("form", sb.ToString());
        }
    }

    // A -F word: always quoted here (paths can hold ; and ,), with \ and " escaped — curl's own -F quoting.
    private static string FormWord(string s) => "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";

    // curl -K config: the secret half of the request (headers incl. Authorization / Cookie, proxy user:pass, form fields),
    // and the URL and proxy address, which can carry credentials too (user:pass@, ?token=, a bot token in the path) —
    // those two only when ASCII (a config file is read as bytes; a non-ASCII one stays an argv token, see UrlInConfig).
    // Values are double-quoted with curl's config escapes (\\ \" \t \n \r \v), so nothing in them can start a new option line.
    private static string BuildCurlConfig(CurlRequest r, List<(string Name, string Value)> headers)
    {
        var cfg = new StringBuilder();
        foreach (var h in headers) cfg.Append("header = ").Append(CfgQ(HeaderArg(h))).Append('\n');
        if (HasProxyCreds(r)) cfg.Append("proxy-user = ").Append(CfgQ($"{r.ProxyUser}:{r.ProxyPass}")).Append('\n');
        if (r.EffectiveBodyMode == CurlBodyMode.Multipart)
            foreach (var (opt, value) in FormEntries(r)) cfg.Append(opt).Append(" = ").Append(CfgQ(value)).Append('\n');
        if (ProxyInConfig(r)) cfg.Append("proxy = ").Append(CfgQ(HttpHelper.CurlProxyArg(r.Proxy!))).Append('\n');
        if (UrlInConfig(r)) cfg.Append("url = ").Append(CfgQ(r.Url)).Append('\n');
        return cfg.ToString();
    }

    private static bool UrlInConfig(CurlRequest r) => Ascii(r.Url);
    private static bool ProxyInConfig(CurlRequest r) => !string.IsNullOrWhiteSpace(r.Proxy) && Ascii(HttpHelper.CurlProxyArg(r.Proxy));
    private static bool Ascii(string s) => s.All(c => c is >= ' ' and <= '~');

    private static string CfgQ(string v)
    {
        var sb = new StringBuilder("\"");
        foreach (char c in v)
        {
            switch (c)
            {
                case '\\': sb.Append("\\\\"); break;
                case '"': sb.Append("\\\""); break;
                case '\t': sb.Append("\\t"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\v': sb.Append("\\v"); break;
                default: sb.Append(c); break;
            }
        }
        return sb.Append('"').ToString();
    }

    // Writes the curl config to a fresh owner-only temp file, so Bearer tokens / cookies / the proxy password aren't
    // readable by other local users from the command line (ps -ww, /proc/<pid>/cmdline). CreateNew never reuses or follows
    // an existing path, and on Unix the 0600 mode is applied at creation. Returns null on any failure — or when the temp
    // path isn't ASCII, which a non-Unicode Windows curl.exe couldn't open — and the caller then passes the values as
    // ordinary argv tokens (still injection-safe, just visible to `ps`).
    private static string? WriteCurlConfig(string content)
    {
        string? path = null;
        try
        {
            string dir = Path.GetTempPath();
            foreach (char c in dir) if (c > 0x7E) return null;
            path = Path.Combine(dir, "echoes-curl-" + Guid.NewGuid().ToString("N") + ".cfg");
            var opts = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
            if (!OperatingSystem.IsWindows()) opts.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using (var fs = new FileStream(path, opts))
                fs.Write(new UTF8Encoding(false).GetBytes(content));   // no BOM: curl would read it as part of the first option
            return path;
        }
        catch
        {
            if (path != null) try { File.Delete(path); } catch { }
            return null;
        }
    }

    // Reads curl's stdout: the body, then the -w trailer after "\n<marker>". Up to MaxResponseBytes of body is kept, but
    // the pipe is always drained to the end (a full pipe would block curl and deadlock the stderr read); the last 16 KB
    // are always kept too, so the trailer is found however big the body was.
    private static async Task<(byte[] Buffer, int Length, bool Truncated, string? Trailer)> DrainStdoutAsync(Stream s, string marker)
    {
        const int TailKeep = 16 * 1024;
        var ms = new MemoryStream();
        var tail = new byte[TailKeep];
        int tailLen = 0;
        long total = 0;
        var buf = new byte[64 * 1024];
        int read;
        while ((read = await s.ReadAsync(buf).ConfigureAwait(false)) > 0)
        {
            long room = (long)MaxResponseBytes + TailKeep - ms.Length;
            if (room > 0) ms.Write(buf, 0, (int)Math.Min(read, room));
            // rolling tail of the last TailKeep bytes
            if (read >= TailKeep) { Buffer.BlockCopy(buf, read - TailKeep, tail, 0, TailKeep); tailLen = TailKeep; }
            else
            {
                int drop = Math.Max(0, tailLen + read - TailKeep);
                if (drop > 0) { Buffer.BlockCopy(tail, drop, tail, 0, tailLen - drop); tailLen -= drop; }
                Buffer.BlockCopy(buf, 0, tail, tailLen, read);
                tailLen += read;
            }
            total += read;
        }

        byte[] m = Encoding.ASCII.GetBytes("\n" + marker + " ");
        int idx = LastIndexOf(tail, tailLen, m);
        string? trailer = null;
        long bodyLen = total;
        if (idx >= 0)
        {
            bodyLen = total - tailLen + idx;
            trailer = Encoding.UTF8.GetString(tail, idx + m.Length, tailLen - idx - m.Length).Trim();
        }
        bool truncated = bodyLen > MaxResponseBytes;
        int kept = (int)Math.Min(bodyLen, Math.Min(MaxResponseBytes, ms.Length));
        return (ms.GetBuffer(), kept, truncated, trailer);
    }

    private static int LastIndexOf(byte[] hay, int len, byte[] needle)
    {
        for (int i = len - needle.Length; i >= 0; i--)
        {
            int k = 0;
            while (k < needle.Length && hay[i + k] == needle[k]) k++;
            if (k == needle.Length) return i;
        }
        return -1;
    }

    // "200 1.1 0.001 0.002 0.000 0.002 0.010 0.012 0.000 0 1234 127.0.0.1 8080 http://…"
    private static void ParseTrailer(string? trailer, CurlResult res)
    {
        if (string.IsNullOrEmpty(trailer)) return;
        string line = trailer.Split('\n')[0].Trim('\r');
        var f = line.Split(' ');
        if (f.Length < 13) return;
        static double S(string v) => double.TryParse(v, NumberStyles.Float, CultureInfo.InvariantCulture, out double d) ? d * 1000.0 : 0;
        if (!res.Responded && int.TryParse(f[0], out int code) && code > 0) { res.Status = code; res.Responded = true; }
        if (res.HttpVersion.Length == 0 && f[1] is { Length: > 0 } hv && hv != "0") res.HttpVersion = "HTTP/" + hv;
        double dns = S(f[2]), conn = S(f[3]), app = S(f[4]), pre = S(f[5]), start = S(f[6]), total = S(f[7]);
        int redirects = int.TryParse(f[9], out int nr) ? nr : 0;
        var t = res.Timing;
        t.TotalMs = total;
        t.Requests = redirects + 1;
        t.DnsMs = dns;
        t.ConnectMs = conn > 0 ? Math.Max(0, conn - dns) : null;
        t.TlsMs = app > 0 ? Math.Max(0, app - conn) : null;
        if (start > 0)
        {
            t.WaitMs = Math.Max(0, start - pre);
            t.DownloadMs = Math.Max(0, total - start);
        }
        if (f[11].Length > 0) res.RemoteAddress = f[11].Contains(':') ? $"[{f[11]}]:{f[12]}" : $"{f[11]}:{f[12]}";
        string effective = string.Join(' ', f.Skip(13)).Trim();
        if (effective.Length > 0) res.FinalUrl = effective;
    }

    // The -v trace: "* info", "> request", "< response" (every hop with -L; a proxy CONNECT and 1xx interim replies too).
    private static void ParseCurlTrace(string trace, CurlRequest r, CurlResult res)
    {
        string currentUrl = r.Url;
        string? nextUrl = null;
        string reqMethod = r.Method;
        bool reqIsConnect = false;
        var reqHeaders = new List<(string, string)>();
        var lastReqHeaders = new List<(string, string)>();
        CurlHop? hop = null;
        List<(string, string)>? respHeaders = null;
        bool interim = false;
        bool first = true;
        var headersLog = new StringBuilder();

        foreach (var raw in trace.Split('\n'))
        {
            string line = raw.TrimEnd('\r');
            if (line.Length == 0) continue;
            if (line.StartsWith("> ", StringComparison.Ordinal) || line == ">")
            {
                string c = line.Length > 2 ? line[2..] : string.Empty;
                if (c.Length == 0) continue;
                if (IsRequestLine(c, out string method))
                {
                    reqIsConnect = method == "CONNECT";
                    if (reqIsConnect) continue;
                    if (!first) currentUrl = nextUrl ?? ResolveNext(currentUrl, hop?.Location) ?? currentUrl;
                    first = false;
                    nextUrl = null;
                    reqMethod = method;
                    reqHeaders = new List<(string, string)>();
                    headersLog.Append(headersLog.Length > 0 ? "\n" : "").Append("> ").Append(c).Append('\n');
                    continue;
                }
                if (reqIsConnect) continue;
                if (SplitHeader(c) is { } h) reqHeaders.Add(h);
                headersLog.Append("> ").Append(c).Append('\n');
                lastReqHeaders = reqHeaders;
            }
            else if (line.StartsWith("< ", StringComparison.Ordinal) || line == "<")
            {
                string c = line.Length > 2 ? line[2..] : string.Empty;
                if (c.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
                {
                    var (ver, status, reason) = ParseStatusLine(c);
                    interim = reqIsConnect || (status >= 100 && status < 200 && status != 101);
                    if (interim) { respHeaders = null; continue; }
                    hop = new CurlHop { Method = reqMethod, Url = currentUrl, Status = status, Reason = reason };
                    res.Hops.Add(hop);
                    respHeaders = new List<(string, string)>();
                    res.Status = status;
                    res.Reason = reason;
                    res.HttpVersion = ver;
                    res.Responded = true;
                    res.Headers = respHeaders;
                    res.RequestHeaders = reqHeaders;
                    headersLog.Append("\n< ").Append(c).Append('\n');
                    continue;
                }
                if (interim || respHeaders is null || c.Length == 0) continue;
                if (SplitHeader(c) is { } h)
                {
                    respHeaders.Add(h);
                    if (hop != null && h.Item1.Equals("Location", StringComparison.OrdinalIgnoreCase)) hop.Location = h.Item2;
                }
                headersLog.Append("< ").Append(c).Append('\n');
            }
            else if (line.StartsWith("* ", StringComparison.Ordinal))
            {
                // curl ≤ 8.x: "Issue another request to this URL: 'http://…'"
                const string issue = "Issue another request to this URL: '";
                int k = line.IndexOf(issue, StringComparison.Ordinal);
                if (k >= 0)
                {
                    string u = line[(k + issue.Length)..];
                    int end = u.LastIndexOf('\'');
                    nextUrl = end > 0 ? u[..end] : u;
                }
            }
        }
        if (res.RequestHeaders.Count == 0) res.RequestHeaders = lastReqHeaders;
        foreach (var h in res.Hops) if (h.Reason.Length == 0) h.Reason = ReasonPhrase(h.Status);
        if (res.Reason.Length == 0) res.Reason = ReasonPhrase(res.Status);
        res.HeadersLog = TextLimit.Cap(headersLog.ToString().Trim());
    }

    private static bool IsRequestLine(string c, out string method)
    {
        method = string.Empty;
        int sp = c.IndexOf(' ');
        if (sp <= 0 || !c.Contains(" HTTP/", StringComparison.Ordinal)) return false;
        string m = c[..sp];
        foreach (char ch in m) if (!(char.IsAsciiLetterUpper(ch) || ch == '-' || char.IsAsciiLetterLower(ch))) return false;
        method = m;
        return true;
    }

    private static (string Version, int Status, string Reason) ParseStatusLine(string c)
    {
        var parts = c.Split(' ', 3);
        string ver = parts[0].ToUpperInvariant();
        int status = parts.Length > 1 && int.TryParse(parts[1], out int s) ? s : 0;
        string reason = parts.Length > 2 ? parts[2].Trim() : string.Empty;
        return (ver, status, reason);
    }

    private static (string, string)? SplitHeader(string c)
    {
        int colon = c.IndexOf(':');
        if (colon <= 0) return null;
        return (c[..colon].Trim(), c[(colon + 1)..].Trim());
    }

    private static string? ResolveNext(string current, string? location)
    {
        if (string.IsNullOrWhiteSpace(location) || !Uri.TryCreate(current, UriKind.Absolute, out var cur)) return null;
        return ResolveLocation(cur, location.Trim())?.AbsoluteUri;
    }

    private static string FormatCurlLog(string trace, CurlResult res)
    {
        var sb = new StringBuilder();
        foreach (var raw in trace.Split('\n'))
        {
            string line = raw.TrimEnd('\r');
            if (line.Length == 0 || line.StartsWith("{ ", StringComparison.Ordinal) || line.StartsWith("} ", StringComparison.Ordinal)) continue;
            sb.Append(line).Append('\n');
        }
        AppendTimingLog(sb, res);
        return TextLimit.Cap(sb.ToString().TrimEnd());
    }

    private static void AppendTimingLog(StringBuilder sb, CurlResult res)
    {
        var t = res.Timing;
        if (t.TotalMs <= 0) return;
        sb.Append("\n══ TIMING ═══════════════════════════════\n");
        void Row(string label, double? ms) { if (ms is double v) sb.Append($"* {label,-14} {v,9:0.0} ms\n"); }
        Row("DNS lookup", t.DnsMs);
        Row("TCP connect", t.ConnectMs);
        Row("TLS handshake", t.TlsMs);
        Row("Waiting (TTFB)", t.WaitMs);
        Row("Download", t.DownloadMs);
        Row("Total", t.TotalMs);
        if (t.Requests > 1) sb.Append($"* ({t.Requests} requests — redirects included)\n");
    }

    private static void MapCurlError(int code, string trace, CurlResult res, CurlRequest r)
    {
        string detail = string.Empty;
        foreach (var raw in trace.Split('\n'))
        {
            string line = raw.TrimEnd('\r');
            if (line.StartsWith("curl: (", StringComparison.Ordinal))
            {
                int close = line.IndexOf(')');
                detail = close > 0 ? line[(close + 1)..].Trim() : line;
            }
        }
        string host = Uri.TryCreate(r.Url, UriKind.Absolute, out var u) ? u.Host : r.Url;
        (string title, string? hint) = code switch
        {
            3 => ("Invalid URL", (string?)null),
            5 => ("Couldn't resolve the proxy", "Check the proxy address in Options."),
            6 => ("Couldn't resolve host", $"\"{host}\" didn't resolve — check the name, or set an override IP in Options."),
            7 => ("Couldn't connect", null),
            16 or 92 => ("HTTP/2 error", "Try HTTP/1.1 in Options."),
            18 => ("Transfer ended early", "The server closed the connection before the whole body arrived."),
            26 => ("Can't read the request body", null),
            28 => ("Timed out", r.TimeoutSec > 0 ? $"No complete response within {r.TimeoutSec} s — raise the timeout in Options." : null),
            35 => ("TLS handshake failed", null),
            47 => ("Too many redirects", $"Stopped after {r.MaxRedirects} redirects."),
            52 => ("Empty reply from server", "The server closed the connection without answering."),
            55 => ("Couldn't send the request", null),
            56 => ("Connection dropped", null),
            58 or 59 or 77 or 83 => ("TLS setup problem", null),
            60 => ("Certificate not trusted", "Turn on Insecure in Options to skip the check — only for hosts you trust."),
            61 => ("Unknown content encoding", "Turn off Compressed in Options."),
            95 => ("HTTP/3 error", "Try HTTP/2 or Auto in Options."),
            97 => ("Proxy handshake failed", "Check the proxy's address, type and credentials."),
            _ => ($"curl error {code}", null),
        };
        res.ErrorTitle = title;
        res.ErrorDetail = detail.Length > 0 ? detail : $"curl exited with code {code}.";
        res.ErrorHint = hint;
    }

    // ================================================================== .NET HttpClient

    // Redirects followed per request, like a browser's limit — overridable with --max-redirs.
    private sealed class NetTimes
    {
        private readonly Stopwatch _clock = Stopwatch.StartNew();
        public double Now => _clock.Elapsed.TotalMilliseconds;
        public double DnsStart = -1, DnsEnd = -1, ConnectEnd = -1, TlsEnd = -1, FirstByte = -1;
        public volatile bool AwaitFirstByte;
        public string? Remote;
    }

    // Wraps the connection's plaintext stream: the first bytes read after a write are the response's first byte (TTFB).
    private sealed class TimingStream : Stream
    {
        private readonly Stream _inner;
        private readonly NetTimes _t;
        public TimingStream(Stream inner, NetTimes t) { _inner = inner; _t = t; }

        private void OnRead(int n) { if (n > 0 && _t.AwaitFirstByte) { _t.FirstByte = _t.Now; _t.AwaitFirstByte = false; } }
        private void OnWrite() => _t.AwaitFirstByte = true;

        public override bool CanRead => _inner.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => _inner.CanWrite;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => _inner.Flush();
        public override Task FlushAsync(CancellationToken ct) => _inner.FlushAsync(ct);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) { int n = _inner.Read(buffer, offset, count); OnRead(n); return n; }
        public override int Read(Span<byte> buffer) { int n = _inner.Read(buffer); OnRead(n); return n; }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        { int n = await _inner.ReadAsync(buffer, ct).ConfigureAwait(false); OnRead(n); return n; }
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
            => ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();
        public override void Write(byte[] buffer, int offset, int count) { OnWrite(); _inner.Write(buffer, offset, count); }
        public override void Write(ReadOnlySpan<byte> buffer) { OnWrite(); _inner.Write(buffer); }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default) { OnWrite(); return _inner.WriteAsync(buffer, ct); }
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) { OnWrite(); return _inner.WriteAsync(buffer, offset, count, ct); }
        protected override void Dispose(bool disposing) { if (disposing) _inner.Dispose(); base.Dispose(disposing); }
        public override ValueTask DisposeAsync() => _inner.DisposeAsync();
    }

    private static string AppVersion()
    {
        var v = typeof(CurlEngine).Assembly.GetName().Version;
        return v is null ? "1" : $"{v.Major}.{v.Minor}.{v.Build}";
    }

    private static async Task<CurlResult> RunDotNetAsync(CurlRequest r, Uri uri, CurlRunOptions opt, CancellationToken ct)
    {
        var res = await RunDotNetOnceAsync(r, uri, opt, ct, r.HttpVersion).ConfigureAwait(false);
        // curl --http3 tries HTTP/3 and falls back: do the same when QUIC isn't there or the server doesn't answer on it
        if (r.HttpVersion == CurlHttpVersion.Http3 && res.Failed && !res.Cancelled && !res.Responded && res.ErrorTitle != "Timed out")
        {
            string why = res.ErrorDetail ?? res.ErrorTitle ?? "no answer";
            var retry = await RunDotNetOnceAsync(r, uri, opt, ct, CurlHttpVersion.Auto).ConfigureAwait(false);
            retry.Notes.Add("HTTP/3 didn't work (" + Shorten(why, 90) + ") — fell back to HTTP/2 or 1.1");
            return retry;
        }
        return res;
    }

    private static async Task<CurlResult> RunDotNetOnceAsync(CurlRequest r, Uri uri, CurlRunOptions opt, CancellationToken ct, CurlHttpVersion version)
    {
        var res = new CurlResult { Engine = ".NET", FinalUrl = r.Url };
        var times = new NetTimes();
        IPAddress? bindIp = null;
        if (!string.IsNullOrEmpty(opt.NicIp)) IPAddress.TryParse(opt.NicIp, out bindIp);

        WebProxy? proxy = null;
        if (r.Proxy is { Length: > 0 })
        {
            HttpHelper.TryParseProxy(r.Proxy, out var proxyUri);   // validated in RunAsync
            // curl's socks5h (names resolved by the proxy) is what .NET's socks5 does anyway
            if (proxyUri!.Scheme.Equals("socks5h", StringComparison.OrdinalIgnoreCase))
                proxyUri = new UriBuilder(proxyUri) { Scheme = "socks5" }.Uri;
            proxy = new WebProxy(proxyUri);
            if (!string.IsNullOrEmpty(r.ProxyUser) || !string.IsNullOrEmpty(r.ProxyPass))
                proxy.Credentials = new NetworkCredential(r.ProxyUser ?? string.Empty, r.ProxyPass ?? string.Empty);
        }

        using var handler = new SocketsHttpHandler
        {
            // Redirects are followed by hand below: the handler's own following re-sends every header but Authorization —
            // Cookie, X-Api-Key, … — to whatever host the redirect names.
            AllowAutoRedirect = false,
            AutomaticDecompression = r.Compressed ? DecompressionMethods.All : DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(r.ConnectTimeoutSec > 0 ? r.ConnectTimeoutSec : 30),
            UseCookies = false,
        };
        if (r.Insecure) handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;
        if (proxy != null) { handler.Proxy = proxy; handler.UseProxy = true; }

        // curl --resolve / --connect-to: dial the override address (and port) but keep Host / SNI from the URL — only for the
        // origin port it was set for, like curl. --interface: bind the socket to the chosen NIC's address. Timed: DNS +
        // connect here, TLS when the plaintext stream appears, the first response byte in TimingStream.
        var ov = OverrideFor(r, uri);
        string originHost = uri.IdnHost;
        handler.ConnectCallback = async (ctx, token) =>
        {
            var ep = ctx.DnsEndPoint;
            string target = ep.Host.Trim('[', ']');
            int port = ep.Port;
            if (ov is { } o && target.Equals(originHost.Trim('[', ']'), StringComparison.OrdinalIgnoreCase) && (o.FromPort is null || o.FromPort == ep.Port))
            {
                target = o.Addr;
                port = o.Port ?? ep.Port;
            }
            times.DnsStart = times.Now;
            times.DnsEnd = times.ConnectEnd = times.TlsEnd = -1;
            IPAddress[] addrs;
            if (IPAddress.TryParse(target, out var literal)) addrs = new[] { literal };
            else addrs = await Dns.GetHostAddressesAsync(target, token).ConfigureAwait(false);
            times.DnsEnd = times.Now;
            if (bindIp != null)
            {
                addrs = addrs.Where(a => a.AddressFamily == bindIp.AddressFamily).ToArray();
                if (addrs.Length == 0)
                    throw new SocketException((int)SocketError.AddressFamilyNotSupported);
            }
            // No IPv6 at all on this machine (a Linux kernel booted with ipv6.disable=1): a dual-stack socket can't
            // even be created there, so use an IPv4 one and only the IPv4 addresses.
            var family = bindIp?.AddressFamily ?? (Socket.OSSupportsIPv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork);
            if (bindIp == null && family == AddressFamily.InterNetwork)
                addrs = addrs.Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToArray();
            if (addrs.Length == 0) throw new SocketException((int)SocketError.HostNotFound);

            var socket = new Socket(family, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                if (bindIp != null) socket.Bind(new IPEndPoint(bindIp, 0));
                else if (family == AddressFamily.InterNetworkV6) socket.DualMode = true;   // default dual-stack when not binding a NIC
                await socket.ConnectAsync(addrs, port, token).ConfigureAwait(false);
                times.ConnectEnd = times.Now;
                if (socket.RemoteEndPoint is IPEndPoint rep)
                {
                    var a = rep.Address.IsIPv4MappedToIPv6 ? rep.Address.MapToIPv4() : rep.Address;
                    times.Remote = a.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{a}]:{rep.Port}" : $"{a}:{rep.Port}";
                }
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch { socket.Dispose(); throw; }
        };
        handler.PlaintextStreamFilter = (ctx, token) =>
        {
            times.TlsEnd = times.Now;
            return ValueTask.FromResult<Stream>(new TimingStream(ctx.PlaintextStream, times));
        };

        // curl -m/--max-time bounds the whole operation; one deadline spans every redirect hop (and the body read).
        int overallSec = r.TimeoutSec > 0 ? r.TimeoutSec : 0;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        if (overallSec > 0) deadline.CancelAfter(TimeSpan.FromSeconds(overallSec));
        using var client = new HttpClient(handler, disposeHandler: false) { Timeout = Timeout.InfiniteTimeSpan };

        // The headers, split once: HttpRequestHeaders refuses exactly the content headers (Content-Type, …), which describe
        // the body and travel with it; every other one is a request header — the kind that carries credentials.
        var headers = r.EffectiveHeaders();
        var mode = r.EffectiveBodyMode;
        if (mode == CurlBodyMode.Multipart) headers.RemoveAll(h => h.Name.Equals("Content-Type", StringComparison.OrdinalIgnoreCase));
        var reqHeaders = new List<(string Name, string Value)>();
        var bodyHeaders = new List<(string Name, string Value)>();
        using (var probe = new HttpRequestMessage())
            foreach (var h in headers)
                (probe.Headers.TryAddWithoutValidation(h.Name, h.Value) ? reqHeaders : bodyHeaders).Add(h);
        var method = new HttpMethod(r.Method);
        bool sendBody = mode != CurlBodyMode.None;
        var current = uri;
        bool onOrigin = true;
        var exchanges = new StringBuilder();
        var trace = new List<string>();
        var timing = new CurlTiming { DnsMs = 0, ConnectMs = 0, TlsMs = 0, WaitMs = 0, DownloadMs = 0 };
        bool anyTls = false;
        HttpRequestMessage? req = null;
        HttpResponseMessage? resp = null;
        try
        {
            for (int hop = 0; ; hop++)
            {
                req = BuildDotNetRequest(r, opt, method, current, sendBody, bodyHeaders, reqHeaders, onOrigin, version);
                double hopStart = times.Now;
                try
                {
                    resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (deadline.IsCancellationRequested && !ct.IsCancellationRequested)
                {
                    throw new TimeoutException($"No complete response within {overallSec} s" + (hop > 0 ? $" ({hop} redirect(s) followed)." : "."));
                }
                double headersAt = times.Now;
                bool newConn = times.ConnectEnd >= hopStart;
                if (newConn)
                {
                    timing.DnsMs += Math.Max(0, times.DnsEnd - times.DnsStart);
                    timing.ConnectMs += Math.Max(0, times.ConnectEnd - times.DnsEnd);
                    if (current.Scheme == Uri.UriSchemeHttps && times.TlsEnd >= times.ConnectEnd)
                    {
                        timing.TlsMs += times.TlsEnd - times.ConnectEnd;
                        anyTls = true;
                    }
                }
                double sentAt = newConn ? Math.Max(times.ConnectEnd, times.TlsEnd) : hopStart;
                double firstByte = times.FirstByte >= sentAt ? Math.Min(times.FirstByte, headersAt) : headersAt;
                timing.WaitMs += Math.Max(0, firstByte - sentAt);

                var hopInfo = new CurlHop { Method = method.Method, Url = current.AbsoluteUri, Status = (int)resp.StatusCode, Reason = resp.ReasonPhrase ?? string.Empty };
                if (resp.Headers.NonValidated.TryGetValues("Location", out var locs)) foreach (var l in locs) { hopInfo.Location = l; break; }
                res.Hops.Add(hopInfo);
                AppendExchange(exchanges, req, resp);

                Uri? next = r.FollowRedirects ? RedirectTarget(resp, current, trace) : null;
                if (next == null)
                {
                    // the final response: read the body (capped) off the UI thread
                    var (buf, len, truncated) = await ReadCappedAsync(resp.Content, deadline.Token).ConfigureAwait(false);
                    double endAt = times.Now;
                    timing.DownloadMs += Math.Max(0, endAt - firstByte);
                    timing.TotalMs = endAt;
                    res.Body = buf;
                    res.BodyLength = len;
                    res.Truncated = truncated;
                    break;
                }
                timing.DownloadMs += Math.Max(0, times.Now - firstByte);
                if (hop >= r.MaxRedirects)
                {
                    trace.Add($"Maximum ({r.MaxRedirects}) redirects followed — stopping here");
                    var (buf, len, truncated) = await ReadCappedAsync(resp.Content, deadline.Token).ConfigureAwait(false);
                    res.Body = buf; res.BodyLength = len; res.Truncated = truncated;
                    timing.TotalMs = times.Now;
                    break;
                }

                var code = resp.StatusCode;
                trace.Add($"{(int)code} {resp.ReasonPhrase} — issue another request to this URL: '{next.AbsoluteUri}'");
                // SocketsHttpHandler's method rules: 303 → GET (HEAD stays HEAD); 300/301/302 turn only POST into GET;
                // 307/308 keep the method and the body. (Qualified: HttpMethod is also an enum in this file's scope.)
                bool toGet = code == HttpStatusCode.SeeOther
                    ? method != System.Net.Http.HttpMethod.Get && method != System.Net.Http.HttpMethod.Head
                    : (code is HttpStatusCode.MultipleChoices or HttpStatusCode.MovedPermanently or HttpStatusCode.Found)
                      && method == System.Net.Http.HttpMethod.Post;
                if (toGet)
                {
                    trace.Add($"Switch from {method} to GET" + (sendBody ? " (body dropped)" : ""));
                    method = System.Net.Http.HttpMethod.Get;
                    sendBody = false;
                }
                if (onOrigin && !SameOrigin(uri, next))
                {
                    // Once off the origin the user typed, no hop gets their headers again — not even one that comes back:
                    // the redirecting host would pick the path (and, with 307, the method).
                    onOrigin = false;
                    var names = reqHeaders.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                    if (names.Count > 0)
                        trace.Add($"Leaving {uri.Scheme}://{uri.Authority} — your header(s) not re-sent: {string.Join(", ", names)}");
                }
                resp.Dispose(); resp = null;   // the 3xx body isn't read; this just frees the connection
                req.Dispose(); req = null;
                current = next;
            }

            var final = resp!;
            res.Responded = true;
            res.Status = (int)final.StatusCode;
            res.Reason = final.ReasonPhrase ?? ReasonPhrase(res.Status);
            res.HttpVersion = final.Version.Major >= 2 ? $"HTTP/{final.Version.Major}" : $"HTTP/{final.Version.Major}.{final.Version.Minor}";
            foreach (var h in final.Headers.NonValidated) foreach (var v in h.Value) res.Headers.Add((h.Key, v));
            foreach (var h in final.Content.Headers.NonValidated) foreach (var v in h.Value) res.Headers.Add((h.Key, v));
            if (req != null)
            {
                foreach (var h in req.Headers) foreach (var v in h.Value) res.RequestHeaders.Add((h.Key, v));
                if (req.Content != null) foreach (var h in req.Content.Headers) foreach (var v in h.Value) res.RequestHeaders.Add((h.Key, v));
            }
            res.FinalUrl = current.AbsoluteUri;
            res.RemoteAddress = times.Remote;
            if (!anyTls) timing.TlsMs = uri.Scheme == Uri.UriSchemeHttps || current.Scheme == Uri.UriSchemeHttps ? timing.TlsMs : null;
            timing.Requests = res.Hops.Count;
            res.Timing = timing;
            // the handler strips Content-Encoding from what it decoded itself: only a body still encoded is decoded here
            DecodeIfCompressed(res, curlDecoded: false);
            if (version == CurlHttpVersion.Http3 && (ov != null || bindIp != null))
                res.Notes.Add("HTTP/3 (QUIC) doesn't use the override IP / interface in the .NET engine");
            res.HeadersLog = TextLimit.Cap(exchanges.ToString().TrimEnd());
            res.FullLog = BuildDotNetLog(r, ov, exchanges.ToString(), trace, res);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            res.Cancelled = true;
        }
        catch (Exception ex)
        {
            MapDotNetError(ex, res, r, current);
            res.Timing.TotalMs = times.Now;
            res.FullLog = BuildDotNetLog(r, ov, exchanges.ToString(), trace, res);
        }
        finally
        {
            resp?.Dispose();
            req?.Dispose();
        }
        return res;
    }

    // One hop's request. The user's request headers go only while the chain is still on the URL's own origin; content
    // headers stay with the body they describe. ByteArrayContent carries no default Content-Type (StringContent's
    // "text/plain; charset=utf-8" got the user's own Content-Type APPENDED to it, which JSON APIs reject with 415).
    private static HttpRequestMessage BuildDotNetRequest(CurlRequest r, CurlRunOptions opt, HttpMethod method, Uri target, bool withBody,
        List<(string Name, string Value)> bodyHeaders, List<(string Name, string Value)> reqHeaders, bool userHeaders,
        CurlHttpVersion version)
    {
        var req = new HttpRequestMessage(method, target);
        switch (version)
        {
            case CurlHttpVersion.Http1: req.Version = System.Net.HttpVersion.Version11; req.VersionPolicy = HttpVersionPolicy.RequestVersionExact; break;
            case CurlHttpVersion.Http3: req.Version = System.Net.HttpVersion.Version30; req.VersionPolicy = HttpVersionPolicy.RequestVersionExact; break;
            default: req.Version = System.Net.HttpVersion.Version20; req.VersionPolicy = HttpVersionPolicy.RequestVersionOrLower; break;
        }
        if (withBody)
        {
            HttpContent? content = r.EffectiveBodyMode switch
            {
                CurlBodyMode.Raw or CurlBodyMode.Form => new ByteArrayContent(r.BodyBytes() ?? Array.Empty<byte>()),
                CurlBodyMode.File => new StreamContent(OpenFile(opt, r.BodyFile.Trim()), 64 * 1024),
                CurlBodyMode.Multipart => BuildMultipart(r, opt),
                _ => null,
            };
            if (content != null)
            {
                foreach (var (name, value) in bodyHeaders)
                {
                    // Content-Type is single-valued — replace, never append
                    if (name.Equals("Content-Type", StringComparison.OrdinalIgnoreCase)) content.Headers.Remove("Content-Type");
                    content.Headers.TryAddWithoutValidation(name, value);
                }
                req.Content = content;
            }
        }
        if (userHeaders)
            foreach (var (name, value) in reqHeaders) req.Headers.TryAddWithoutValidation(name, value);
        // the defaults curl sends too (the user's own header of the same name wins)
        if (!req.Headers.Contains("Accept")) req.Headers.TryAddWithoutValidation("Accept", "*/*");
        if (!req.Headers.Contains("User-Agent")) req.Headers.TryAddWithoutValidation("User-Agent", "Echoes/" + AppVersion());
        return req;
    }

    // multipart/form-data the way curl writes it: text parts carry no Content-Type, file parts their type and file name;
    // name / filename quoted (MultipartFormDataContent's own Add writes them unquoted plus a filename*).
    private static MultipartFormDataContent BuildMultipart(CurlRequest r, CurlRunOptions opt)
    {
        var form = new MultipartFormDataContent("------------------------" + Guid.NewGuid().ToString("N")[..16]);
        foreach (var p in r.Parts.Where(p => p.Enabled && p.Name.Length > 0))
        {
            HttpContent part;
            if (p.IsFile)
            {
                string path = p.Value.Trim();
                part = new StreamContent(OpenFile(opt, path), 64 * 1024);
                part.Headers.ContentType = MediaTypeHeaderValue.TryParse(
                    string.IsNullOrEmpty(p.ContentType) ? CurlRequest.GuessMime(path, "application/octet-stream") : p.ContentType, out var mt)
                    ? mt : new MediaTypeHeaderValue("application/octet-stream");
                string fileName = !string.IsNullOrEmpty(p.FileName) ? p.FileName : Path.GetFileName(path);
                part.Headers.ContentDisposition = new ContentDispositionHeaderValue("form-data") { Name = Quote(p.Name), FileName = Quote(fileName) };
            }
            else
            {
                part = new ByteArrayContent(Encoding.UTF8.GetBytes(p.Value));
                if (!string.IsNullOrEmpty(p.ContentType) && MediaTypeHeaderValue.TryParse(p.ContentType, out var tt)) part.Headers.ContentType = tt;
                part.Headers.ContentDisposition = new ContentDispositionHeaderValue("form-data") { Name = Quote(p.Name) };
            }
            form.Add(part);
        }
        return form;
    }

    private static string Quote(string s) => "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";

    private static bool SameOrigin(Uri a, Uri b) =>
        string.Equals(a.Scheme, b.Scheme, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(a.IdnHost, b.IdnHost, StringComparison.OrdinalIgnoreCase) && a.Port == b.Port;

    // Where a 3xx sends the next request, or null to stop with this response as the result. A redirect that is not
    // followed gets a trace line saying why.
    private static Uri? RedirectTarget(HttpResponseMessage resp, Uri current, List<string> trace)
    {
        if (resp.StatusCode is not (HttpStatusCode.MultipleChoices or HttpStatusCode.MovedPermanently or HttpStatusCode.Found
            or HttpStatusCode.SeeOther or HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect)) return null;

        // The raw value: the typed Location getter parses with UriKind.RelativeOrAbsolute (see ResolveLocation).
        string? loc = null;
        if (resp.Headers.NonValidated.TryGetValues("Location", out var values))
            foreach (var v in values) { loc = v.Trim(); break; }
        if (string.IsNullOrEmpty(loc)) return null;   // a 3xx without Location is just a response

        var next = ResolveLocation(current, loc);
        if (next is null || (next.Scheme != Uri.UriSchemeHttp && next.Scheme != Uri.UriSchemeHttps))
        {
            trace.Add($"Not following the redirect to '{loc}' (not an http/https URL)");
            return null;
        }
        if (current.Scheme == Uri.UriSchemeHttps && next.Scheme == Uri.UriSchemeHttp)
        {
            // as the handler did: an https → http hop would put the request on the wire in clear text
            trace.Add($"Not following the https → http redirect to '{next.AbsoluteUri}'");
            return null;
        }
        return next;
    }

    // RFC 3986 reference resolution against the URL just requested. A value with a scheme is absolute; anything else
    // ("/p", "p", "?q", "//host/p") is a reference, parsed as UriKind.Relative on purpose — RelativeOrAbsolute can take
    // "/p" for a Unix file path or "\\host\p" for a UNC path.
    private static Uri? ResolveLocation(Uri current, string loc)
    {
        if (HasScheme(loc)) return Uri.TryCreate(loc, UriKind.Absolute, out var abs) ? abs : null;
        return Uri.TryCreate(loc, UriKind.Relative, out var rel) && Uri.TryCreate(current, rel, out var res) ? res : null;
    }

    private static bool HasScheme(string s)
    {
        int colon = s.IndexOf(':');
        if (colon < 1 || !char.IsAsciiLetter(s[0])) return false;
        for (int i = 1; i < colon; i++)
            if (!char.IsAsciiLetterOrDigit(s[i]) && s[i] is not ('+' or '-' or '.')) return false;
        return true;
    }

    // Read an HttpContent stream up to MaxResponseBytes (raw bytes; decoding happens later).
    private static async Task<(byte[] Buffer, int Length, bool Truncated)> ReadCappedAsync(HttpContent content, CancellationToken ct)
    {
        await using var stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var ms = new MemoryStream();
        var buf = new byte[64 * 1024];
        bool truncated = false;
        while (true)
        {
            long room = MaxResponseBytes - ms.Length;
            if (room <= 0) { truncated = await stream.ReadAsync(buf, ct).ConfigureAwait(false) > 0; break; }
            int read = await stream.ReadAsync(buf.AsMemory(0, (int)Math.Min(buf.Length, room)), ct).ConfigureAwait(false);
            if (read == 0) break;
            ms.Write(buf, 0, read);
        }
        return (ms.ToArray(), (int)ms.Length, truncated);
    }

    // A body still carrying its Content-Encoding (the engine didn't ask for compression, but the server — or the user's
    // own Accept-Encoding header — got it compressed) is decoded here, so it reads as text.
    private static void DecodeIfCompressed(CurlResult res, bool curlDecoded)
    {
        if (curlDecoded || res.BodyLength == 0 || res.Truncated) return;
        string? enc = res.Header("Content-Encoding")?.Trim().ToLowerInvariant();
        if (enc is not ("gzip" or "x-gzip" or "deflate" or "br")) return;
        try
        {
            using var input = new MemoryStream(res.Body, 0, res.BodyLength, writable: false);
            using Stream dec = enc switch
            {
                "br" => new BrotliStream(input, CompressionMode.Decompress),
                "deflate" => LooksZlib(res.Body) ? new ZLibStream(input, CompressionMode.Decompress) : new DeflateStream(input, CompressionMode.Decompress),
                _ => new GZipStream(input, CompressionMode.Decompress),
            };
            using var output = new MemoryStream();
            var buf = new byte[64 * 1024];
            int n;
            bool truncated = false;
            while ((n = dec.Read(buf, 0, buf.Length)) > 0)
            {
                long room = MaxResponseBytes - output.Length;
                if (room <= 0) { truncated = true; break; }
                output.Write(buf, 0, (int)Math.Min(n, room));
            }
            res.Body = output.ToArray();
            res.BodyLength = (int)output.Length;
            res.Truncated = truncated;
            res.ContentEncodingDecoded = enc;
        }
        catch { /* not really compressed: keep the bytes as they came */ }
    }

    private static bool LooksZlib(byte[] b) => b.Length >= 2 && (b[0] & 0x0F) == 8 && ((b[0] << 8) | b[1]) % 31 == 0;

    // One request/response exchange for the logs: the request as sent, the response headers as received.
    private static void AppendExchange(StringBuilder sb, HttpRequestMessage req, HttpResponseMessage resp)
    {
        if (sb.Length > 0) sb.AppendLine();
        sb.AppendLine($"> {req.Method} {req.RequestUri?.PathAndQuery} HTTP/{(resp.Version.Major >= 2 ? resp.Version.Major.ToString() : resp.Version.ToString())}");
        sb.AppendLine($"> Host: {req.RequestUri?.Authority}");
        foreach (var h in req.Headers) sb.AppendLine($"> {h.Key}: {string.Join(", ", h.Value)}");
        if (req.Content != null) foreach (var h in req.Content.Headers) sb.AppendLine($"> {h.Key}: {string.Join(", ", h.Value)}");
        sb.AppendLine($"< HTTP/{(resp.Version.Major >= 2 ? resp.Version.Major.ToString() : resp.Version.ToString())} {(int)resp.StatusCode} {resp.ReasonPhrase}");
        foreach (var h in resp.Headers.NonValidated) foreach (var v in h.Value) sb.AppendLine($"< {h.Key}: {v}");
        foreach (var h in resp.Content.Headers.NonValidated) foreach (var v in h.Value) sb.AppendLine($"< {h.Key}: {v}");
    }

    private static string BuildDotNetLog(CurlRequest r, HostOverride? ov, string exchanges, List<string> trace, CurlResult res)
    {
        var full = new StringBuilder();
        full.AppendLine("* Engine: .NET HttpClient");
        full.AppendLine($"* Resolved via: {(ov is { } o ? "override (" + o + ")" : "system DNS")}");
        if (res.RemoteAddress != null) full.AppendLine($"* Connected to {res.RemoteAddress}");
        if (r.Proxy is { Length: > 0 }) full.AppendLine($"* Proxy: {r.Proxy}");
        full.AppendLine($"* TLS verification: {(r.Insecure ? "DISABLED (-k)" : "enabled")}");
        foreach (var line in trace) full.AppendLine("* " + line);
        if (res.Responded) full.AppendLine($"* Status: {res.Status} {res.Reason}");
        if (res.ErrorTitle != null) full.AppendLine($"* Error: {res.ErrorTitle} — {res.ErrorDetail}");
        full.AppendLine();
        full.Append(exchanges);
        AppendTimingLog(full, res);
        return TextLimit.Cap(full.ToString().TrimEnd());
    }

    private static void MapDotNetError(Exception ex, CurlResult res, CurlRequest r, Uri at)
    {
        string inner = Innermost(ex).Message;
        string hostPort = $"{at.Host}:{(at.Port > 0 ? at.Port : (at.Scheme == "https" ? 443 : 80))}";
        res.ErrorDetail = inner;
        switch (ex)
        {
            case TimeoutException:
                res.ErrorTitle = "Timed out";
                res.ErrorDetail = ex.Message;
                res.ErrorHint = "Raise the timeout in Options, or check that the host answers.";
                return;
            case HttpRequestException hre:
                switch (hre.HttpRequestError)
                {
                    case HttpRequestError.NameResolutionError:
                        res.ErrorTitle = "Couldn't resolve host";
                        res.ErrorDetail = $"{at.Host}: {inner}";
                        res.ErrorHint = "Check the name, or set an override IP in Options.";
                        return;
                    case HttpRequestError.ConnectionError:
                        res.ErrorTitle = "Couldn't connect";
                        res.ErrorDetail = $"{hostPort}: {inner}";
                        return;
                    case HttpRequestError.SecureConnectionError:
                        bool cert = inner.Contains("certificate", StringComparison.OrdinalIgnoreCase) || ex.ToString().Contains("RemoteCertificate", StringComparison.Ordinal);
                        res.ErrorTitle = cert ? "Certificate not trusted" : "TLS handshake failed";
                        res.ErrorHint = cert ? "Turn on Insecure in Options to skip the check — only for hosts you trust." : null;
                        return;
                    case HttpRequestError.ProxyTunnelError:
                        res.ErrorTitle = "Proxy refused the connection";
                        res.ErrorHint = "Check the proxy's address, type and credentials.";
                        return;
                    case HttpRequestError.VersionNegotiationError:
                        res.ErrorTitle = "HTTP version not available";
                        res.ErrorHint = "The server doesn't speak the HTTP version chosen in Options — try Auto.";
                        return;
                    case HttpRequestError.ResponseEnded:
                        res.ErrorTitle = "Empty reply from server";
                        return;
                    case HttpRequestError.InvalidResponse:
                    case HttpRequestError.HttpProtocolError:
                        res.ErrorTitle = "Invalid response";
                        return;
                    case HttpRequestError.ConfigurationLimitExceeded:
                        res.ErrorTitle = "Response headers too large";
                        return;
                }
                if (Innermost(ex) is PlatformNotSupportedException)
                {
                    res.ErrorTitle = "Not supported here";
                    return;
                }
                res.ErrorTitle = "Request failed";
                return;
            case AuthenticationException:
                res.ErrorTitle = "TLS handshake failed";
                return;
            case SocketException se:
                res.ErrorTitle = se.SocketErrorCode == SocketError.HostNotFound ? "Couldn't resolve host" : "Couldn't connect";
                res.ErrorDetail = $"{hostPort}: {inner}";
                return;
            case FileNotFoundException or DirectoryNotFoundException or UnauthorizedAccessException:
                res.ErrorTitle = "Can't read a file the body names";
                return;
            case IOException:
                res.ErrorTitle = "Connection dropped";
                return;
            case NotSupportedException or PlatformNotSupportedException:
                res.ErrorTitle = "Not supported here";
                return;
        }
        res.ErrorTitle = "Request failed";
    }

    /// <summary>The standard reason phrase for a status (HTTP/2 and HTTP/3 send none).</summary>
    public static string ReasonPhrase(int status) => status switch
    {
        100 => "Continue", 101 => "Switching Protocols", 103 => "Early Hints",
        200 => "OK", 201 => "Created", 202 => "Accepted", 203 => "Non-Authoritative Information", 204 => "No Content",
        205 => "Reset Content", 206 => "Partial Content", 207 => "Multi-Status",
        300 => "Multiple Choices", 301 => "Moved Permanently", 302 => "Found", 303 => "See Other", 304 => "Not Modified",
        307 => "Temporary Redirect", 308 => "Permanent Redirect",
        400 => "Bad Request", 401 => "Unauthorized", 402 => "Payment Required", 403 => "Forbidden", 404 => "Not Found",
        405 => "Method Not Allowed", 406 => "Not Acceptable", 407 => "Proxy Authentication Required", 408 => "Request Timeout",
        409 => "Conflict", 410 => "Gone", 411 => "Length Required", 412 => "Precondition Failed", 413 => "Content Too Large",
        414 => "URI Too Long", 415 => "Unsupported Media Type", 416 => "Range Not Satisfiable", 417 => "Expectation Failed",
        418 => "I'm a teapot", 421 => "Misdirected Request", 422 => "Unprocessable Content", 425 => "Too Early",
        426 => "Upgrade Required", 428 => "Precondition Required", 429 => "Too Many Requests",
        431 => "Request Header Fields Too Large", 451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error", 501 => "Not Implemented", 502 => "Bad Gateway", 503 => "Service Unavailable",
        504 => "Gateway Timeout", 505 => "HTTP Version Not Supported", 507 => "Insufficient Storage",
        508 => "Loop Detected", 511 => "Network Authentication Required",
        _ => string.Empty,
    };
}
