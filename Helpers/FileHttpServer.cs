using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>One file offered for download. The server opens it lazily via <see cref="Open"/>, so
/// the source can be a desktop <c>FileStream</c> (seekable → Range works) or an Android content
/// stream — the server never touches the filesystem path, which is why path traversal is impossible.</summary>
public sealed class SharedItem
{
    public required string Id { get; init; }          // opaque, URL-safe; the ONLY way to address a file
    public required string Name { get; init; }
    public required long Size { get; init; }
    public required string ContentType { get; init; }
    public required Func<Task<Stream>> Open { get; init; }
    // Mtime of the version that was picked (desktop only; Android content streams have none). When set,
    // a seekable source gets Last-Modified + a strong ETag, so browsers can resume and If-Range works.
    public DateTime? LastModifiedUtc { get; init; }
}

/// <summary>Thrown by a <see cref="SharedItem.Open"/> whose file no longer matches what was picked
/// (size/mtime changed on disk). The server answers 410 instead of serving other bytes under the same
/// id — a blind resume (<c>curl -C -</c>, <c>wget -c</c>) would otherwise splice two versions.</summary>
public sealed class SharedItemChangedException : IOException
{
    public SharedItemChangedException() : base("The shared file changed since it was added.") { }
}

/// <summary>
/// A tiny, dependency-free HTTP/1.1 file server built on <see cref="TcpListener"/> (NOT HttpListener,
/// which needs http.sys URL-ACLs / admin on Windows and is flaky on Android). Pure managed BCL, works
/// on desktop and in the Android sandbox (listening socket, INTERNET permission, port &gt; 1024, no root).
/// Serves ONLY the explicitly shared items by opaque id — there is no URL→path mapping, so a client can
/// never request an arbitrary file. Supports HEAD and Range (resumable downloads) when the source seeks.
/// </summary>
public sealed class FileHttpServer : IDisposable
{
    private readonly Func<IReadOnlyList<SharedItem>> _items;
    private readonly string? _user;
    private readonly byte[]? _authExpected;  // UTF-8 "user:pass", compared in constant time
    private readonly string? _hostName;      // this machine's name, an allowed Host besides IP literals
    private readonly Action<string>? _log;
    private readonly Action? _onStats;
    private readonly Action<string, long>? _onDownload;
    private readonly SemaphoreSlim _slots;   // caps concurrent connections

    // Per-peer limits: the global slot cap alone let ONE LAN host hold every slot (idle sockets for
    // the header deadline, or trickle-reading big files) and lock everyone else out.
    private readonly int _perPeerCap;
    private const int MaxPendingPerPeer = 6; // sockets still sending headers (a browser opens ≤ 6 per host)
    private readonly ConcurrentDictionary<string, int> _perPeer = new();
    private readonly ConcurrentDictionary<string, int> _pendingPerPeer = new();

    // Basic-auth brute-force throttle: after AuthFreeTries wrong logins a peer is locked out for
    // 1 s, 2 s, 4 s … up to MaxLockoutSec. Locked-out requests get an instant 429 (never a delay,
    // which would itself hold a slot). A few typos — browsers may repeat a wrong credential on the
    // favicon request — never lock out a real user.
    private const int AuthFreeTries = 10;
    private const int MaxLockoutSec = 300;
    private const int MaxAuthEntries = 4096;   // bounds the table against address churn
    private readonly object _authGate = new();
    private readonly Dictionary<string, (int Fails, long UntilMs)> _authFail = new();   // under _authGate

    private TcpListener? _listener;
    private CancellationTokenSource? _cts;

    // Live stats (thread-safe; read via the public props below).
    private int _active;
    private long _totalConn;
    private long _totalDownloads;
    private long _bytesSent;
    private readonly ConcurrentDictionary<string, byte> _clients = new();

    /// <summary>Optional data: URI of the app icon, shown on the index page's hero. Set once by the app
    /// (keeps this server core BCL-only); when null the index falls back to a built-in vector mark.</summary>
    public static string? BrandLogoDataUri { get; set; }

    public bool IsRunning { get; private set; }
    public int ActiveConnections => Volatile.Read(ref _active);
    public long TotalConnections => Interlocked.Read(ref _totalConn);
    public long TotalDownloads => Interlocked.Read(ref _totalDownloads);
    public long BytesSent => Interlocked.Read(ref _bytesSent);
    public int ClientCount => _clients.Count;

    public FileHttpServer(Func<IReadOnlyList<SharedItem>> items, string? user, string? pass,
        Action<string>? log, Action? onStats = null, Action<string, long>? onDownload = null,
        int maxConnections = 24)
    {
        _items = items;
        _user = string.IsNullOrEmpty(user) ? null : user;
        _authExpected = _user is null ? null : Encoding.UTF8.GetBytes(_user + ":" + (pass ?? ""));
        try { _hostName = Dns.GetHostName(); } catch { }
        _log = log;
        _onStats = onStats;
        _onDownload = onDownload;
        int max = Math.Clamp(maxConnections, 1, 512);
        _slots = new SemaphoreSlim(max);
        // One peer may hold at most half the slots (others always get in), but never fewer than a
        // browser's own 6 per-host connections — so a normal single-user share is never throttled.
        _perPeerCap = Math.Max(Math.Min(6, max), max / 2);
    }

    /// <summary>Starts listening. Throws (e.g. SocketException "address in use") on failure.</summary>
    public void Start(IPAddress bind, int port)
    {
        Stop();
        _cts = new CancellationTokenSource();
        _listener = new TcpListener(bind, port);
        _listener.Start();
        IsRunning = true;
        // Run the loop on the pool: started from the UI thread, its awaits would otherwise capture the
        // Avalonia context and parse/serve every request on the UI thread (a LAN flood froze the app).
        // Locals, not fields — an immediate Stop() nulls/disposes those.
        var listener = _listener;
        var token = _cts.Token;
        _ = Task.Run(() => AcceptLoop(listener, token));
    }

    public void Stop()
    {
        IsRunning = false;
        try { _cts?.Cancel(); } catch { }
        try { _listener?.Stop(); } catch { }
        _listener = null;
        _cts?.Dispose();
        _cts = null;
    }

    private async Task AcceptLoop(TcpListener listener, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            // Take a slot BEFORE accepting, so we never pull more than the cap of sockets into
            // memory/FDs — accepted-but-idle connections can't grow unbounded (FD-exhaustion DoS).
            try { await _slots.WaitAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }

            TcpClient client;
            try { client = await listener.AcceptTcpClientAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { _slots.Release(); break; }
            catch (ObjectDisposedException) { _slots.Release(); break; }
            catch
            {
                _slots.Release();
                // Back off so a persistent accept failure (e.g. FD exhaustion) can't pin a CPU core.
                try { await Task.Delay(100, ct).ConfigureAwait(false); } catch { break; }
                continue;
            }

            // Handler on the pool too, so its synchronous part (e.g. File.OpenRead on a slow share)
            // never stalls the accept loop. Releases the slot in its finally.
            _ = Task.Run(() => HandleAsync(client, ct));
        }
    }

    private async Task HandleAsync(TcpClient client, CancellationToken ct)
    {
        string peer = "?";
        try { peer = (client.Client.RemoteEndPoint as IPEndPoint)?.Address.ToString() ?? "?"; } catch { }

        // Counted before any work so an over-cap socket is closed at once and frees its slot.
        int held = Bump(_perPeer, peer, 1);
        int pending = Bump(_pendingPerPeer, peer, 1);
        bool isPending = true;

        Interlocked.Increment(ref _active);   // paired with the Decrement in finally (can't throw here)
        try
        {
            if (held > _perPeerCap || pending > MaxPendingPerPeer) return;
            Interlocked.Increment(ref _totalConn);
            _clients.TryAdd(peer, 0);
            _onStats?.Invoke();
            client.NoDelay = true;
            using var stream = client.GetStream();
            var req = await ReadRequestAsync(stream, ct).ConfigureAwait(false);
            Bump(_pendingPerPeer, peer, -1);
            isPending = false;
            if (req is null) return;

            // DNS-rebinding guard: a hostile web page can point its own domain at 127.0.0.1 / this LAN
            // IP and then read the share same-origin (fetch ignores Content-Disposition), even in
            // "Localhost only" mode. Echoes only ever advertises IP-literal URLs, so a foreign name is
            // refused. A missing Host is allowed: browsers always send one, old CLI tools may not.
            string? host = req.Get("Host");
            if (host is not null && !IsAllowedHost(host))
            {
                await WriteTextAsync(stream, 421, "Unknown host - open the IP address shown in Echoes", head: req.IsHead, ct: ct).ConfigureAwait(false);
                _log?.Invoke($"{peer}  Host {Clean(host)}  → 421");
                return;
            }

            // Basic auth gate (with the per-peer brute-force lockout in front of it).
            if (_user is not null)
            {
                // Only a WRONG credential counts; the browser's first, credential-less request just gets the challenge.
                // A credential is judged by AuthVerdict, which re-checks the lockout in the same step.
                bool ok = false;
                if (!IsLockedOut(peer, out long retrySec) && req.Get("Authorization") is not null)
                    ok = AuthVerdict(peer, CheckAuth(req), out retrySec);
                if (!ok && retrySec > 0)
                {
                    await WriteTextAsync(stream, 429, "Too many failed logins - try again shortly",
                        extraHeaders: $"Retry-After: {retrySec}\r\n", head: req.IsHead, ct: ct).ConfigureAwait(false);
                    return;
                }
                if (!ok)
                {
                    await WriteTextAsync(stream, 401, "Unauthorized",
                        extraHeaders: "WWW-Authenticate: Basic realm=\"Echoes\"\r\n", head: req.IsHead, ct: ct).ConfigureAwait(false);
                    _log?.Invoke($"{peer}  {Clean(req.Method)} {Clean(req.Target)}  → 401");
                    return;
                }
            }

            if (req.Method is not ("GET" or "HEAD"))
            {
                await WriteTextAsync(stream, 405, "Method Not Allowed", head: req.IsHead, ct: ct).ConfigureAwait(false);
                _log?.Invoke($"{peer}  {Clean(req.Method)} {Clean(req.Target)}  → 405");
                return;
            }

            string path = req.Path;
            if (path is "/" or "/index.html")
            {
                int status = await WriteIndexAsync(stream, req.IsHead, ct).ConfigureAwait(false);
                _log?.Invoke($"{peer}  {req.Method} /  → {status}");
            }
            else if (path.StartsWith("/d/", StringComparison.Ordinal))
            {
                string id = Uri.UnescapeDataString(path[3..]);
                var item = Find(id);
                if (item is null)
                {
                    await WriteTextAsync(stream, 404, "Not Found", head: req.IsHead, ct: ct).ConfigureAwait(false);
                    _log?.Invoke($"{peer}  {req.Method} {Clean(path)}  → 404");
                }
                else
                {
                    int status = await ServeFileAsync(stream, item, req, ct).ConfigureAwait(false);
                    _log?.Invoke($"{peer}  {req.Method} {Clean(item.Name)}  → {status}");   // names can hold line breaks too
                }
            }
            else
            {
                await WriteTextAsync(stream, 404, "Not Found", head: req.IsHead, ct: ct).ConfigureAwait(false);
                _log?.Invoke($"{peer}  {req.Method} {Clean(path)}  → 404");
            }
        }
        catch { /* per-connection: never let one bad client take down the loop */ }
        finally
        {
            if (isPending) Bump(_pendingPerPeer, peer, -1);
            Bump(_perPeer, peer, -1);
            Interlocked.Decrement(ref _active);
            _onStats?.Invoke();
            try { client.Dispose(); } catch { }
            _slots.Release();
        }
    }

    private SharedItem? Find(string id)
    {
        foreach (var it in _items())
            if (string.Equals(it.Id, id, StringComparison.Ordinal)) return it;
        return null;
    }

    // Adjusts a per-peer counter and drops the entry at zero (only if still zero — a racing +1 wins),
    // so the maps never grow with every address ever seen.
    private static int Bump(ConcurrentDictionary<string, int> map, string peer, int delta)
    {
        int v = map.AddOrUpdate(peer, static (_, d) => d, static (_, old, d) => old + d, delta);
        if (v <= 0) map.TryRemove(new KeyValuePair<string, int>(peer, v));
        return v;
    }

    // Accepts IP literals ([v6]:port too), localhost and this machine's own name (+ ".local" for
    // mDNS). Never a name merely STARTING with ours — "mypc.evil.example" is the attacker's domain.
    private bool IsAllowedHost(string host)
    {
        host = host.Trim();
        if (host.StartsWith('['))
        {
            int rb = host.IndexOf(']');
            if (rb < 0) return false;
            host = host[1..rb];
        }
        else
        {
            int pc = host.LastIndexOf(':');
            if (pc >= 0) host = host[..pc];
        }
        if (host.Length == 0) return false;
        if (IPAddress.TryParse(host, out _)) return true;
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase)) return true;
        return !string.IsNullOrEmpty(_hostName)
            && (host.Equals(_hostName, StringComparison.OrdinalIgnoreCase)
                || host.Equals(_hostName + ".local", StringComparison.OrdinalIgnoreCase));
    }

    private bool IsLockedOut(string peer, out long retrySec)
    {
        lock (_authGate) return LockedOut(peer, out retrySec);
    }

    // Under _authGate.
    private bool LockedOut(string peer, out long retrySec)
    {
        retrySec = 0;
        if (!_authFail.TryGetValue(peer, out var f)) return false;
        long left = f.UntilMs - Environment.TickCount64;
        if (left <= 0) return false;
        retrySec = (left + 999) / 1000;
        return true;
    }

    // Judges a credential and checks/records the lockout in ONE step. Checked and counted separately, a burst of
    // parallel guesses all passed the check before the first failure was counted, so a burst got extra guesses per
    // lockout window. True = let in; false + retrySec > 0 = locked out (refused unchecked), else a counted failure.
    private bool AuthVerdict(string peer, bool ok, out long retrySec)
    {
        int fails;
        long secs = 0;
        lock (_authGate)
        {
            if (LockedOut(peer, out retrySec)) return false;
            if (ok) { _authFail.Remove(peer); return true; }
            _authFail.TryGetValue(peer, out var f);
            fails = f.Fails + 1;
            if (fails >= AuthFreeTries) secs = Math.Min(1L << Math.Min(fails - AuthFreeTries, 9), MaxLockoutSec);
            if (_authFail.Count >= MaxAuthEntries && !_authFail.ContainsKey(peer)) _authFail.Clear();
            _authFail[peer] = (fails, secs > 0 ? Environment.TickCount64 + secs * 1000 : 0L);
        }
        if (secs > 0) _log?.Invoke($"{peer}  {fails} failed logins  → locked out {secs}s");
        return false;
    }

    // ---- request parsing ----

    private sealed class Request
    {
        public string Method = "";
        public string Target = "";
        public string Path = "";
        public bool IsHead => Method == "HEAD";
        public readonly Dictionary<string, string> Headers = new(StringComparer.OrdinalIgnoreCase);
        public string? Get(string k) => Headers.TryGetValue(k, out var v) ? v : null;
    }

    private static async Task<Request?> ReadRequestAsync(NetworkStream stream, CancellationToken ct)
    {
        var buf = new byte[8192];
        int len = 0;
        // ONE wall-clock deadline for the ENTIRE header read. Creating the CTS per-iteration reset the
        // cap on every byte, letting a slow-drip client (slowloris) hold a connection slot forever
        // and — since a slot is taken before AcceptTcpClientAsync — stall the whole accept loop.
        // 5 s: a real client sends its headers in one packet; an idle socket holds a slot only briefly.
        using var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        readCts.CancelAfter(5000);
        // Read until the end-of-headers marker or the cap. Each read searches only the bytes it added (plus 3 of
        // overlap for a marker split across reads): rescanning from the start every time let a client that dribbles
        // its head one byte per segment cost ~30 ms of CPU per 8 KB head (O(n²)) for next to no traffic of its own.
        int scanned = 0;
        while (len < buf.Length)
        {
            int n = await stream.ReadAsync(buf.AsMemory(len, buf.Length - len), readCts.Token).ConfigureAwait(false);
            if (n <= 0) break;
            len += n;
            if (IndexOfCrlfCrlf(buf, scanned, len) >= 0) break;
            scanned = Math.Max(0, len - 3);
        }
        if (len == 0) return null;

        string text = Encoding.ASCII.GetString(buf, 0, len);
        int end = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (end >= 0) text = text[..end];
        var lines = text.Split("\r\n");
        if (lines.Length == 0) return null;

        // Strict request line: exactly "METHOD target HTTP/x", no control chars — a bare LF/TAB in
        // it would otherwise reach the REQUESTS log and forge extra entries.
        foreach (char ch in lines[0])
            if (ch < 0x20 || ch == 0x7f) return null;
        var first = lines[0].Split(' ');
        if (first.Length != 3) return null;

        var req = new Request { Method = first[0].ToUpperInvariant(), Target = first[1] };
        int q = req.Target.IndexOf('?');
        string rawPath = q >= 0 ? req.Target[..q] : req.Target;
        req.Path = rawPath.Length == 0 ? "/" : rawPath;

        for (int i = 1; i < lines.Length; i++)
        {
            int c = lines[i].IndexOf(':');
            if (c > 0) req.Headers[lines[i][..c].Trim()] = lines[i][(c + 1)..].Trim();
        }
        return req;
    }

    // Index of the first CRLFCRLF in b[from..len), or -1.
    private static int IndexOfCrlfCrlf(byte[] b, int from, int len)
    {
        int i = b.AsSpan(from, len - from).IndexOf("\r\n\r\n"u8);
        return i < 0 ? -1 : from + i;
    }

    private bool CheckAuth(Request req)
    {
        string? h = req.Get("Authorization");
        if (_authExpected is null || h is null || !h.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase)) return false;
        try
        {
            // Compare the raw "user:pass" bytes in constant time (no early exit at the first mismatch).
            byte[] got = Convert.FromBase64String(h[6..].Trim());
            return CryptographicOperations.FixedTimeEquals(got, _authExpected);
        }
        catch { return false; }
    }

    // ---- responses ----

    private async Task<int> WriteIndexAsync(NetworkStream stream, bool head, CancellationToken ct)
    {
        var list = _items();

        // Build the download cards (each whole card is a link to /d/{id}).
        var rows = new StringBuilder();
        if (list.Count == 0)
        {
            rows.Append("<div class=\"empty\">Nothing is being shared right now.</div>");
        }
        else
        {
            foreach (var it in list)
                rows.Append("<a class=\"f\" href=\"/d/").Append(Uri.EscapeDataString(it.Id)).Append("\">")
                    .Append("<span class=\"ic\">").Append(FileEmoji(it.Name)).Append("</span>")
                    .Append("<span class=\"meta\"><span class=\"nm\">").Append(HtmlEscape(it.Name)).Append("</span>")
                    .Append("<span class=\"sz\">").Append(HumanSize(it.Size)).Append("</span></span>")
                    .Append("<span class=\"dl\">GET&#8201;&#8595;</span></a>");
        }

        string count = list.Count switch { 0 => "Nothing shared yet", 1 => "1 file available", _ => $"{list.Count} files available" };

        // Prefer the real app icon (a small data: URI the app supplies); fall back to a built-in vector mark.
        string logoHtml = string.IsNullOrEmpty(BrandLogoDataUri)
            ? "<svg class=\"logo\" viewBox=\"0 0 100 100\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\">"
              + "<circle cx=\"50\" cy=\"50\" r=\"7.5\" fill=\"#42b883\"/>"
              + "<path d=\"M64 33a25 25 0 0 1 0 34\" stroke=\"#42b883\" stroke-width=\"5.5\" stroke-linecap=\"round\"/>"
              + "<path d=\"M74 22a40 40 0 0 1 0 56\" stroke=\"#42b883\" stroke-width=\"5.5\" stroke-linecap=\"round\" opacity=\".5\"/>"
              + "<path d=\"M36 67a25 25 0 0 1 0-34\" stroke=\"#42b883\" stroke-width=\"5.5\" stroke-linecap=\"round\"/>"
              + "<path d=\"M26 78a40 40 0 0 1 0-56\" stroke=\"#42b883\" stroke-width=\"5.5\" stroke-linecap=\"round\" opacity=\".5\"/></svg>"
            : $"<img class=\"logo\" src=\"{BrandLogoDataUri}\" alt=\"Echoes\">";

        // Raw interpolated literal ($$ → {{ }} are the holes, so single { } in CSS stay literal).
        string page = $$"""
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Echoes</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:radial-gradient(900px 520px at 50% -8%,#15271f 0%,#0f1012 54%);color:#e7e7ea;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;display:flex;flex-direction:column;align-items:center;padding:46px 18px 60px}
.hero{text-align:center;max-width:560px;width:100%}
.logo{width:96px;height:96px;margin:0 auto 16px;display:block;border-radius:50%;filter:drop-shadow(0 10px 28px rgba(60,180,200,.45))}
h1{font-size:34px;letter-spacing:4px;margin:0 0 8px;font-weight:800;background:linear-gradient(90deg,#8fd6b0,#42b883);-webkit-background-clip:text;background-clip:text;color:transparent}
.tag{color:#c7c8cf;font-size:14px;margin:0 0 4px}
.sub{color:#6b6c74;font-size:12.5px;margin:0}
.wrap{width:100%;max-width:560px;margin-top:30px;display:flex;flex-direction:column;gap:9px}
.sec{color:#9e9fa8;font-size:11px;font-weight:700;letter-spacing:1.6px;margin:2px 2px 4px}
.f{display:flex;align-items:center;gap:13px;padding:13px 15px;background:#191a1f;border:1px solid #2a2c33;border-radius:12px;text-decoration:none;color:inherit;transition:border-color .15s,transform .15s,background .15s}
.f:hover{border-color:#42b883;background:#1b241f;transform:translateY(-1px)}
.f:active{transform:translateY(0)}
.ic{width:40px;height:40px;flex:0 0 auto;border-radius:10px;background:#21261f;display:flex;align-items:center;justify-content:center;font-size:19px}
.meta{flex:1;min-width:0;display:flex;flex-direction:column}
.nm{font-size:14px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sz{color:#9e9fa8;font-size:12px;margin-top:3px;font-family:ui-monospace,Consolas,monospace}
.dl{color:#7fcba6;font-size:11.5px;font-weight:800;letter-spacing:.5px;white-space:nowrap;flex:0 0 auto}
.empty{text-align:center;color:#6b6c74;padding:34px 20px;background:#191a1f;border:1px dashed #2f3139;border-radius:12px;font-size:13.5px}
footer{margin-top:36px;color:#54555f;font-size:11px;text-align:center}
footer b{color:#42b883;font-weight:700}
</style></head><body>
<div class="hero">
{{logoHtml}}
<h1>ECHOES</h1>
<p class="tag">Shared files on your local network</p>
<p class="sub">{{count}}&#8195;·&#8195;direct transfer, no cloud</p>
</div>
<div class="wrap">
<div class="sec">DOWNLOADS</div>
{{rows}}
</div>
<footer>Served by <b>Echoes</b>&#8195;·&#8195;private peer-to-peer LAN sharing</footer>
</body></html>
""";

        byte[] body = Encoding.UTF8.GetBytes(page);
        var head2 = new StringBuilder()
            .Append("HTTP/1.1 200 OK\r\n")
            .Append("Content-Type: text/html; charset=utf-8\r\n")
            .Append("Content-Length: ").Append(body.Length).Append("\r\n")
            // Defense in depth for the only HTML page: file names are escaped above, but should one ever slip
            // through, no script may run, nothing loads from elsewhere and no other site can frame the page.
            .Append(IndexCsp)
            .Append("X-Content-Type-Options: nosniff\r\n")
            .Append("Connection: close\r\n\r\n");
        // Idle-timed like file writes: a client that asks for "/" and never reads can't pin its slot until STOP.
        await WriteWithTimeout(stream, Encoding.ASCII.GetBytes(head2.ToString()), ct).ConfigureAwait(false);
        if (!head) await WriteWithTimeout(stream, body, ct).ConfigureAwait(false);
        return 200;
    }

    // Inline <style> and the data: logo are all the index uses.
    private const string IndexCsp = "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
                                    + "base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n";

    private async Task<int> ServeFileAsync(NetworkStream stream, SharedItem item, Request req, CancellationToken ct)
    {
        Stream src;
        try { src = await item.Open().ConfigureAwait(false); }
        catch (SharedItemChangedException)
        {
            await WriteTextAsync(stream, 410, "File changed since it was shared - re-add it in Echoes", head: req.IsHead, ct: ct).ConfigureAwait(false);
            return 410;
        }
        catch { await WriteTextAsync(stream, 500, "Cannot open file", head: req.IsHead, ct: ct).ConfigureAwait(false); return 500; }

        await using (src)
        {
            // Only a SEEKABLE source has an authoritative length we can promise (Content-Length) and
            // seek within (Range). A non-seekable Android content stream is streamed to EOF with
            // Connection: close and NO Content-Length / NO Range — so a null/stale picked size can
            // never truncate the download or produce a 0-byte file.
            bool seekable = src.CanSeek;
            long total = seekable ? src.Length : -1;

            // Validators for the picked version (see SharedItem.LastModifiedUtc). If-Range that doesn't
            // match them (or arrives when we have none) means "send it whole" — never splice versions.
            string? etag = null, lastMod = null;
            if (seekable && item.LastModifiedUtc is DateTime lm)
            {
                etag = $"\"{lm.Ticks:x}-{item.Size:x}\"";
                lastMod = lm.ToString("R");
            }

            long start = 0, end = total - 1;
            bool partial = false;
            string? range = req.Get("Range");
            string? ifRange = req.Get("If-Range");
            if (ifRange is not null && ifRange != etag && ifRange != lastMod) range = null;
            if (range is not null && seekable && total > 0)
            {
                if (TryParseRange(range, total, out start, out end, out bool unsatisfiable)) partial = true;
                else if (unsatisfiable)
                {
                    // A range starting at or past the end — typically resuming a download that is already complete
                    // (curl -C -, wget -c). 416 tells them there is nothing left; sending the whole file again (200)
                    // made curl fail and wget refuse to overwrite the finished file.
                    await WriteTextAsync(stream, 416, "Range Not Satisfiable",
                        extraHeaders: $"Content-Range: bytes */{total}\r\n", head: req.IsHead, ct: ct).ConfigureAwait(false);
                    return 416;
                }
            }

            long count = partial ? end - start + 1 : total;
            var hb = new StringBuilder();
            hb.Append(partial ? "HTTP/1.1 206 Partial Content\r\n" : "HTTP/1.1 200 OK\r\n");
            hb.Append("Content-Type: ").Append(item.ContentType).Append("\r\n");
            if (seekable) hb.Append("Content-Length: ").Append(count).Append("\r\n");
            hb.Append("Accept-Ranges: ").Append(seekable ? "bytes" : "none").Append("\r\n");
            if (etag is not null) hb.Append("ETag: ").Append(etag).Append("\r\nLast-Modified: ").Append(lastMod).Append("\r\n");
            if (partial) hb.Append("Content-Range: bytes ").Append(start).Append('-').Append(end).Append('/').Append(total).Append("\r\n");
            hb.Append("Content-Disposition: attachment; filename=\"").Append(AsciiName(item.Name))
              .Append("\"; filename*=UTF-8''").Append(Uri.EscapeDataString(item.Name)).Append("\r\n");
            // Browsers download it (attachment); should a client render it anyway, a shared .html / .svg still can't
            // run script on this origin (where it could read the index and the other shares) or be sniffed into HTML.
            hb.Append("X-Content-Type-Options: nosniff\r\nContent-Security-Policy: sandbox\r\n");
            hb.Append("Connection: close\r\n\r\n");
            await WriteWithTimeout(stream, Encoding.ASCII.GetBytes(hb.ToString()), ct).ConfigureAwait(false);

            if (req.IsHead) return partial ? 206 : 200;

            if (partial) src.Seek(start, SeekOrigin.Begin);
            long sent = seekable
                ? await CopyExactAsync(src, stream, count, ct).ConfigureAwait(false)
                : await CopyToEndAsync(src, stream, ct).ConfigureAwait(false);

            // The copy loops already added the ACTUAL bytes to _bytesSent per chunk (so the live stat
            // moves during long downloads). Full GETs count as a download; range chunks add bytes only.
            if (!partial) Interlocked.Increment(ref _totalDownloads);
            _onDownload?.Invoke(item.Id, sent);
            _onStats?.Invoke();
            return partial ? 206 : 200;
        }
    }

    // A single write that stalls past WriteIdleMs (a slow-reading client) is aborted, freeing the
    // slot + source stream. Reads use ct (a slow SOURCE is not a client DoS); writes use the idle CTS.
    private const int WriteIdleMs = 30000;

    private static async Task WriteWithTimeout(Stream dst, byte[] data, CancellationToken ct)
    {
        using var idle = CancellationTokenSource.CreateLinkedTokenSource(ct);
        idle.CancelAfter(WriteIdleMs);
        await dst.WriteAsync(data, idle.Token).ConfigureAwait(false);
    }

    // Slow-read floor: the per-chunk idle timer alone let a client draining ~2 KB/s (one 64 KB chunk
    // per ~30 s) hold a slot for a whole big file. Over every SlowReadWindowSec spent BLOCKED IN WRITES
    // the client must average MinBytesPerSec (4 KB/s) — far below any real LAN client, fatal only to
    // deliberate tricklers. Source reads don't count: a slow share / content provider is not the
    // client's fault. It must be a RATE: a fixed byte count per window is met by any two 64 KB writes,
    // however long each blocked (up to WriteIdleMs), so it never fired.
    private const int SlowReadWindowSec = 30;
    private const int MinBytesPerSec = 4 * 1024;

    private sealed class SlowReadGuard
    {
        private long _blockedTicks, _bytes;

        public void Wrote(long startTimestamp, int n)
        {
            _blockedTicks += Stopwatch.GetTimestamp() - startTimestamp;
            _bytes += n;
            double blockedSec = (double)_blockedTicks / Stopwatch.Frequency;   // double: no overflow on huge files
            if (blockedSec < SlowReadWindowSec) return;
            if (_bytes < MinBytesPerSec * blockedSec) throw new TimeoutException("client reads too slowly");
            _blockedTicks = 0;
            _bytes = 0;
        }
    }

    private async Task<long> CopyExactAsync(Stream src, Stream dst, long count, CancellationToken ct)
    {
        using var idle = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var guard = new SlowReadGuard();
        var buf = new byte[64 * 1024];
        long remaining = count, sent = 0;
        while (remaining > 0)
        {
            int want = (int)Math.Min(buf.Length, remaining);
            int n = await src.ReadAsync(buf.AsMemory(0, want), ct).ConfigureAwait(false);
            if (n <= 0) break;
            idle.CancelAfter(WriteIdleMs);
            long t0 = Stopwatch.GetTimestamp();
            await dst.WriteAsync(buf.AsMemory(0, n), idle.Token).ConfigureAwait(false);
            idle.CancelAfter(Timeout.Infinite);   // disarm: the next source read must not eat the write's budget
            Interlocked.Add(ref _bytesSent, n);
            guard.Wrote(t0, n);
            sent += n;
            remaining -= n;
        }
        return sent;
    }

    private async Task<long> CopyToEndAsync(Stream src, Stream dst, CancellationToken ct)
    {
        using var idle = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var guard = new SlowReadGuard();
        var buf = new byte[64 * 1024];
        long sent = 0;
        int n;
        while ((n = await src.ReadAsync(buf, ct).ConfigureAwait(false)) > 0)
        {
            idle.CancelAfter(WriteIdleMs);
            long t0 = Stopwatch.GetTimestamp();
            await dst.WriteAsync(buf.AsMemory(0, n), idle.Token).ConfigureAwait(false);
            idle.CancelAfter(Timeout.Infinite);
            Interlocked.Add(ref _bytesSent, n);
            guard.Wrote(t0, n);
            sent += n;
        }
        return sent;
    }

    private static async Task WriteTextAsync(NetworkStream stream, int code, string msg, string? extraHeaders = null, bool head = false, CancellationToken ct = default)
    {
        byte[] body = Encoding.UTF8.GetBytes(msg);
        var hb = new StringBuilder()
            .Append("HTTP/1.1 ").Append(code).Append(' ').Append(msg).Append("\r\n")
            .Append("Content-Type: text/plain; charset=utf-8\r\n")
            .Append("X-Content-Type-Options: nosniff\r\n")
            .Append("Content-Length: ").Append(body.Length).Append("\r\n");
        if (extraHeaders is not null) hb.Append(extraHeaders);
        hb.Append("Connection: close\r\n\r\n");
        await WriteWithTimeout(stream, Encoding.ASCII.GetBytes(hb.ToString()), ct).ConfigureAwait(false);
        if (!head) await WriteWithTimeout(stream, body, ct).ConfigureAwait(false);
    }

    // ---- helpers ----

    // Request data is attacker-controlled: replace control chars (a bare LF would forge extra lines), line /
    // paragraph separators and bidi overrides / isolates (they'd reorder how the rest of the line reads), and cap
    // the length before it reaches the REQUESTS log.
    private static string Clean(string s)
    {
        var sb = new StringBuilder(Math.Min(s.Length, 201));
        foreach (char c in s)
        {
            if (sb.Length >= 200) { sb.Append('…'); break; }
            sb.Append(char.IsControl(c) || c is >= (char)0x2028 and <= (char)0x202E || c is >= (char)0x2066 and <= (char)0x2069 ? '?' : c);
        }
        return sb.ToString();
    }

    // False = serve the whole file (no / invalid / multi range) — or, with unsatisfiable set, answer 416: a well-formed
    // range that selects nothing ("bytes=N-" with N >= size, or "bytes=-0").
    private static bool TryParseRange(string header, long total, out long start, out long end, out bool unsatisfiable)
    {
        start = 0; end = total - 1; unsatisfiable = false;
        // Only the simple single-range "bytes=start-end" / "bytes=start-" / "bytes=-suffix".
        const string p = "bytes=";
        if (!header.StartsWith(p, StringComparison.OrdinalIgnoreCase)) return false;
        string spec = header[p.Length..].Trim();
        if (spec.Contains(',')) return false;                 // multi-range not supported
        int dash = spec.IndexOf('-');
        if (dash < 0) return false;
        string a = spec[..dash], b = spec[(dash + 1)..];
        if (a.Length == 0)
        {
            if (!long.TryParse(b, out long suffix) || suffix < 0) return false;
            if (suffix == 0) { unsatisfiable = true; return false; }
            start = Math.Max(0, total - suffix); end = total - 1;
        }
        else
        {
            if (!long.TryParse(a, out start) || start < 0) return false;
            if (b.Length == 0) end = total - 1;
            else if (!long.TryParse(b, out end) || end < start) return false;
            if (start >= total) { unsatisfiable = true; return false; }
            if (end >= total) end = total - 1;
        }
        return true;
    }

    private static string AsciiName(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (char c in name)
            sb.Append(c is '"' or '\\' or < ' ' or > (char)126 ? '_' : c);
        return sb.ToString();
    }

    private static string HtmlEscape(string s) => s
        .Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");

    // A little type icon for the index cards (emoji → renders on any browser, zero assets).
    private static string FileEmoji(string name) => Path.GetExtension(name).ToLowerInvariant() switch
    {
        ".png" or ".jpg" or ".jpeg" or ".gif" or ".webp" or ".svg" or ".bmp" => "🖼️",
        ".mp4" or ".webm" or ".mkv" or ".mov" or ".avi" => "🎬",
        ".mp3" or ".wav" or ".ogg" or ".flac" or ".m4a" or ".aac" => "🎵",
        ".zip" or ".rar" or ".7z" or ".tar" or ".gz" => "📦",
        ".apk" => "📱",
        ".pdf" => "📕",
        ".exe" or ".msi" or ".dmg" or ".appimage" => "⚙️",
        ".txt" or ".log" or ".md" or ".csv" or ".json" or ".xml" => "📃",
        _ => "📄",
    };

    public static string HumanSize(long bytes)
    {
        string[] u = { "B", "KB", "MB", "GB", "TB" };
        double v = bytes; int i = 0;
        while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
        return i == 0 ? $"{bytes} B" : $"{v:0.#} {u[i]}";
    }

    // Minimal MIME map — default is octet-stream (forces a download, which is what we want anyway).
    public static string GuessContentType(string name)
    {
        string ext = Path.GetExtension(name).ToLowerInvariant();
        return ext switch
        {
            ".txt" or ".log" or ".md" or ".csv" => "text/plain; charset=utf-8",
            ".html" or ".htm" => "text/html; charset=utf-8",
            ".json" => "application/json",
            ".xml" => "application/xml",
            ".pdf" => "application/pdf",
            ".zip" => "application/zip",
            ".png" => "image/png",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".gif" => "image/gif",
            ".webp" => "image/webp",
            ".svg" => "image/svg+xml",
            ".mp4" => "video/mp4",
            ".webm" => "video/webm",
            ".mp3" => "audio/mpeg",
            ".wav" => "audio/wav",
            ".apk" => "application/vnd.android.package-archive",
            _ => "application/octet-stream",
        };
    }

    public void Dispose() => Stop();
}
