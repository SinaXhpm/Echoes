using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>One line in the proxy's live connection log.</summary>
public sealed class ProxyLogEntry
{
    public string Time { get; init; } = "";
    public string Client { get; init; } = "";
    public string Proto { get; init; } = "";     // SOCKS5 / HTTP / HTTPS
    public string Target { get; init; } = "";
    public string User { get; init; } = "—";
    public string Status { get; init; } = "";
    public bool Ok { get; init; }
    /// <summary>Why it failed, in a sentence, where the short status doesn't say it all (the chosen interface).</summary>
    public string Detail { get; init; } = "";

    /// <summary>The row's tooltip: who connected, and the failure in full.</summary>
    public string Tip => Detail.Length > 0 ? $"client {Client}\n{Detail}" : $"client {Client}";
}

/// <summary>Which kind of address the proxy connects to.</summary>
public enum ProxyIpVersion
{
    /// <summary>Whatever the name resolves to, in the system's order.</summary>
    Auto,
    IPv4,
    IPv6,
}

/// <summary>How a <see cref="ProxyServer"/> runs. Read once, when the server is created. (A class, not a record: a
/// record prints its members, and one of them is the password.)</summary>
public sealed class ProxyServerOptions
{
    public const int DefaultConnectTimeoutMs = 15_000;
    public const int DefaultIdleTimeoutMs = 5 * 60_000;

    /// <summary>Null or empty: no login is asked.</summary>
    public string? User { get; init; }
    public string? Pass { get; init; }

    /// <summary>Connections at once, over all clients (1 to 512).</summary>
    public int MaxConnections { get; init; } = 64;

    /// <summary>Connections at once from one other device; 0 = half of <see cref="MaxConnections"/>, never fewer than 8.
    /// This device's own programs aren't counted.</summary>
    public int MaxPerClient { get; init; }

    public bool Socks5 { get; init; } = true;
    /// <summary>SOCKS5 clients may relay UDP (UDP ASSOCIATE): DNS, QUIC, games, calls. Off: refused as a command the proxy
    /// doesn't do. Through an upstream proxy only if it is SOCKS5 (its own UDP relay).</summary>
    public bool Udp { get; init; }
    /// <summary>SOCKS4 and SOCKS4a. They have no password login: with a login required they are refused.</summary>
    public bool Socks4 { get; init; } = true;
    public bool Http { get; init; } = true;

    /// <summary>The name of the interface every connection to a target leaves from (<see cref="NetIface.Name"/>);
    /// null = the system's routing table decides. While that interface is down nothing is connected: the proxy never
    /// falls back to another one.</summary>
    public string? OutInterface { get; init; }

    public ProxyIpVersion IpVersion { get; init; }

    /// <summary>How long a connection to a target may take (name lookup included).</summary>
    public int ConnectTimeoutMs { get; init; } = DefaultConnectTimeoutMs;

    /// <summary>A tunnel with no traffic in either direction for this long is closed.</summary>
    public int IdleTimeoutMs { get; init; } = DefaultIdleTimeoutMs;

    /// <summary>Bytes a second for all connections together, each way; 0 = no limit.</summary>
    public long SpeedLimit { get; init; }

    /// <summary>The proxy every connection is sent on to, instead of connecting to the targets from here; null = none.
    /// With one set nothing goes to a target directly: what the upstream can't carry is refused.</summary>
    public ProxyUpstream? Upstream { get; init; }

    public ProxyRules Rules { get; init; } = ProxyRules.None;
}

/// <summary>
/// A dependency-free SOCKS5 + SOCKS4/4a + HTTP forward proxy on a single <see cref="TcpListener"/>. The protocol
/// is auto-detected from the first byte (0x05 → SOCKS5, 0x04 → SOCKS4, anything else → HTTP), so one port serves all.
/// Pure managed BCL — works on desktop and in the Android sandbox (listening socket, INTERNET permission,
/// port &gt; 1024, no driver/root). Optional username/password auth (SOCKS5 RFC 1929 + HTTP Basic 407).
/// TCP tunnels are proxied, and SOCKS5 UDP when it is switched on (ProxyServer.Udp.cs); SOCKS BIND is declined. Clients from other
/// devices can't reach this device itself through it — its loopback, link-local or any of its own
/// interface addresses (see <see cref="Dial"/>). <see cref="ProxyServerOptions"/> adds the user's own choices: the
/// interface connections leave from, the IP version, which protocols answer, time-outs, limits and rules.
/// </summary>
public sealed partial class ProxyServer : IDisposable
{
    // One deadline for everything before the relay starts (first byte, SOCKS/HTTP negotiation, auth,
    // request head) — same 15 s as FileHttpServer's header read.
    private const int HandshakeMs = 15_000;
    // …but a socket that hasn't sent its first byte by this time is dropped sooner: every client speaks first.
    private const int FirstByteMs = 5_000;
    private const int MaxHeadBytes = 32 * 1024;
    // Brute-force brake: this many wrong credentials from one address lock it out for LockoutMs.
    private const int MaxAuthFails = 5;
    private const int LockoutMs = 60_000;

    private readonly string? _user;
    // The expected credentials as UTF-8, compared in constant time against the bytes a client sends (no timing hint,
    // and the client's password never becomes a string). The password sits in a pinned buffer (SecureMemory).
    private readonly byte[] _userBytes;
    private readonly byte[] _passBytes;
    private readonly bool _authRequired;
    private readonly Action<ProxyLogEntry>? _onConn;
    private readonly SemaphoreSlim _slots;
    // Per-host share of the slots: without it one LAN host (a runaway client, or plain idle sockets — each holds a
    // slot for the whole handshake deadline, before any auth) could take every slot and lock everyone else out.
    // This device's own clients are exempt: they're the owner's apps.
    private readonly int _perPeerCap;
    private readonly ConcurrentDictionary<IPAddress, int> _perPeer = new();
    private readonly object _authGate = new();
    private readonly Dictionary<IPAddress, (int fails, long until, long last)> _authFails = new();   // under _authGate; last = latest failure
    private const int MaxAuthEntries = 4096;
    private readonly OwnAddresses _own = new();

    // The user's choices (ProxyServerOptions), fixed for the server's life.
    private readonly bool _socks5, _socks4, _http, _udp;
    private readonly OutLink? _out;              // null: the routing table decides
    private readonly ProxyIpVersion _ipVersion;
    private readonly int _connectMs;
    // A tunnel with no traffic in EITHER direction for this long is torn down and frees its slot.
    private readonly int _idleMs;
    private readonly Throttle? _upLimit, _downLimit;   // null: no speed limit
    private readonly ProxyRules _rules;
    private readonly UpstreamLink? _upstream;    // null: connections go to the targets from here

    private TcpListener? _listener;
    private CancellationTokenSource? _cts;

    private int _active;
    private long _totalConn, _bytesUp, _bytesDown;

    public bool IsRunning { get; private set; }
    /// <summary>The port it listens on: the one asked for, or the one the system gave for 0.</summary>
    public int Port { get; private set; }
    public int ActiveConnections => Volatile.Read(ref _active);
    public long TotalConnections => Interlocked.Read(ref _totalConn);
    public long BytesUp => Interlocked.Read(ref _bytesUp);
    public long BytesDown => Interlocked.Read(ref _bytesDown);

    /// <summary>Tests only: looks a target's name up in place of the system's resolver (a name whose lookup takes its
    /// time).</summary>
    internal Func<string, CancellationToken, Task<IPAddress[]>>? LookUp { get; set; }

    /// <summary>Tests only: every client counts as one on another device (a test's clients are this computer itself,
    /// over loopback).</summary>
    internal bool ClientsAreOthers { get; set; }

    // No stats callback: the counters above are polled by the UI (one post per connection event let a
    // busy or hostile client flood the dispatcher, and never fired mid-transfer anyway).
    public ProxyServer(string? user, string? pass, Action<ProxyLogEntry>? onConn, int maxConnections)
        : this(new ProxyServerOptions { User = user, Pass = pass, MaxConnections = maxConnections }, onConn) { }

    public ProxyServer(ProxyServerOptions options, Action<ProxyLogEntry>? onConn)
    {
        _user = string.IsNullOrEmpty(options.User) ? null : options.User;
        _userBytes = Encoding.UTF8.GetBytes(_user ?? "");
        _passBytes = SecureMemory.Utf8(options.Pass ?? "");
        _authRequired = _user != null;
        _onConn = onConn;
        int max = Math.Clamp(options.MaxConnections, 1, 512);
        _slots = new SemaphoreSlim(max);
        // At most half of the slots per LAN host (never fewer than 8) unless the user set a number: one phone loading a
        // heavy page opens dozens of tunnels at once, so a tighter cap would break normal browsing. Silent sockets are
        // cut by FirstByteMs instead.
        _perPeerCap = options.MaxPerClient > 0 ? Math.Min(options.MaxPerClient, max) : Math.Max(8, max / 2);

        _socks5 = options.Socks5;
        _socks4 = options.Socks4;
        _http = options.Http;
        _udp = options.Udp;
        _out = string.IsNullOrEmpty(options.OutInterface) ? null : new OutLink(options.OutInterface);
        _ipVersion = options.IpVersion;
        _connectMs = Math.Clamp(options.ConnectTimeoutMs, 1000, 120_000);
        _idleMs = Math.Clamp(options.IdleTimeoutMs, 5000, 24 * 60 * 60_000);
        if (options.SpeedLimit > 0)
        {
            _upLimit = new Throttle(options.SpeedLimit);
            _downLimit = new Throttle(options.SpeedLimit);
        }
        _rules = options.Rules ?? ProxyRules.None;
        _upstream = options.Upstream is null ? null : new UpstreamLink(options.Upstream);
    }

    public void Start(IPAddress bind, int port)
    {
        Stop();
        _cts = new CancellationTokenSource();
        _listener = new TcpListener(bind, port);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        IsRunning = true;
        _own.Watch();
        _ = AcceptLoop(_listener, _cts.Token);
    }

    public void Stop()
    {
        IsRunning = false;
        _own.Unwatch();
        try { _cts?.Cancel(); } catch { }
        try { _listener?.Stop(); } catch { }
        _listener = null;
        try { _cts?.Dispose(); } catch { }
        _cts = null;
    }

    public void Dispose() => Stop();

    /// <summary>The listening socket stopped working while the proxy runs (raised once, on a pool thread): iOS closes
    /// the listeners of an app it suspended, and a bound address can vanish. The owner starts the proxy again.</summary>
    public event Action<string>? ListenerLost;
    private int _lost;

    private async Task AcceptLoop(TcpListener listener, CancellationToken ct)
    {
        int failures = 0;
        while (!ct.IsCancellationRequested)
        {
            // Take a slot before accepting so idle-but-accepted sockets can't grow past the cap.
            try { await _slots.WaitAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }

            TcpClient client;
            try { client = await listener.AcceptTcpClientAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { _slots.Release(); break; }
            catch (ObjectDisposedException) { _slots.Release(); break; }
            catch (Exception ex)
            {
                _slots.Release();
                // accept failing again and again: the listening socket itself is gone, not one client
                if (++failures >= SocketErrors.DeadListenerAfter)
                {
                    if (Interlocked.Exchange(ref _lost, 1) == 0)
                        try { ListenerLost?.Invoke(SocketErrors.Unwrap(ex).Message); } catch { }
                    break;
                }
                try { await Task.Delay(100, ct).ConfigureAwait(false); } catch { break; }
                continue;
            }

            failures = 0;
            BackgroundGuard.NoteActivity();
            _ = HandleAsync(client, ct);   // releases the slot in its finally
        }
    }

    // The connecting client. IsLocal = this device: loopback, or a source address equal to the local
    // address it connected to (only this host can complete a TCP handshake from its own address).
    // LocalAddress = that address of ours it reached — known to be this device's without any lookup.
    private readonly record struct Peer(string Name, IPAddress? Address, IPAddress? LocalAddress, bool IsLocal)
    {
        public static Peer Of(TcpClient c)
        {
            try
            {
                var ip = (c.Client.RemoteEndPoint as IPEndPoint)?.Address;
                if (ip is null) return new Peer("?", null, null, false);
                if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
                var local = (c.Client.LocalEndPoint as IPEndPoint)?.Address;
                if (local is { IsIPv4MappedToIPv6: true }) local = local.MapToIPv4();
                return new Peer(ip.ToString(), ip, local, IPAddress.IsLoopback(ip) || ip.Equals(local));
            }
            catch { return new Peer("?", null, null, false); }
        }
    }

    private async Task HandleAsync(TcpClient client, CancellationToken ct)
    {
        var peer = Peer.Of(client);
        if (ClientsAreOthers) peer = peer with { IsLocal = false };
        // Counted before any work, so a socket over its host's share is closed at once and frees its slot.
        IPAddress? counted = peer.IsLocal ? null : peer.Address;
        int held = counted is null ? 0 : BumpPeer(counted, 1);

        Interlocked.Increment(ref _active);
        try
        {
            using (client)
            {
                if (held > _perPeerCap) return;
                // The user's list of who may connect: anyone else is closed before a byte is read. This device's own
                // programs always may (the list is about other devices).
                if (!peer.IsLocal && !_rules.ClientAllowed(peer.Address))
                {
                    Log(peer.Name, "—", "—", "—", false, "client not allowed", "This address isn't in the proxy's Allowed clients list.");
                    return;
                }
                Interlocked.Increment(ref _totalConn);
                client.NoDelay = true;
                var stream = client.GetStream();
                // Handshake deadline: the slot is taken before accept, so without it a few dozen silent
                // or slow-drip sockets (pre-auth, so 'Require auth' doesn't help) would pin every slot and
                // stall the accept loop until STOP. The relay itself runs on the server token plus its
                // own idle timeout — never on this one, or every tunnel would die after 15 s.
                using var hs = CancellationTokenSource.CreateLinkedTokenSource(ct);
                hs.CancelAfter(FirstByteMs);
                var one = new byte[1];
                if (await stream.ReadAsync(one.AsMemory(0, 1), hs.Token).ConfigureAwait(false) == 0) return;
                hs.CancelAfter(HandshakeMs);   // it spoke: the full negotiation deadline from here

                // The first byte names the protocol: SOCKS5's and SOCKS4's version number, else an HTTP method's first
                // letter. One that is switched off is told so in its own words where it has any, and closed.
                if (one[0] == 0x05)
                {
                    if (_socks5) await HandleSocks5(stream, peer, hs.Token, ct).ConfigureAwait(false);
                    else
                    {
                        Log(peer.Name, "SOCKS5", "—", "—", false, "protocol off");
                        await ReplyAndClose(stream, new byte[] { 0x05, 0xFF }, hs.Token).ConfigureAwait(false);   // no acceptable method
                    }
                }
                else if (one[0] == 0x04)
                {
                    if (_socks4) await HandleSocks4(stream, peer, hs.Token, ct).ConfigureAwait(false);
                    else
                    {
                        Log(peer.Name, "SOCKS4", "—", "—", false, "protocol off");
                        await ReplyAndClose(stream, Socks4Rejected, hs.Token).ConfigureAwait(false);
                    }
                }
                else if (_http) await HandleHttp(stream, peer, one[0], hs.Token, ct).ConfigureAwait(false);
                else
                {
                    Log(peer.Name, "HTTP", "—", "—", false, "protocol off");
                    // only to what looks like an HTTP request (a method's capital letter): anything else is just closed
                    if (one[0] is >= (byte)'A' and <= (byte)'Z')
                        await ReplyAndClose(stream, HttpError("403 Forbidden", "Echoes proxy: HTTP is switched off on this port. Use it as a SOCKS proxy.\n"), hs.Token).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException) { }
        catch { /* per-connection errors are non-fatal to the server */ }
        finally
        {
            if (counted is not null) BumpPeer(counted, -1);
            Interlocked.Decrement(ref _active);
            _slots.Release();
        }
    }

    // Adjusts a host's connection count and drops the entry at zero (only if still zero — a racing +1 wins),
    // so the map never grows with every address ever seen.
    private int BumpPeer(IPAddress ip, int delta)
    {
        int v = _perPeer.AddOrUpdate(ip, static (_, d) => d, static (_, old, d) => old + d, delta);
        if (v <= 0) _perPeer.TryRemove(new KeyValuePair<IPAddress, int>(ip, v));
        return v;
    }

    // ------------------------------------------------------------------ SOCKS5

    // hs = handshake deadline (client negotiation); ct = server lifetime (dial, replies after it, relay).
    private async Task HandleSocks5(NetworkStream s, Peer peer, CancellationToken hs, CancellationToken ct)
    {
        var buf = new byte[512];
        // greeting: VER already consumed. NMETHODS + methods.
        await ReadExact(s, buf, 1, hs);
        int nm = buf[0];
        await ReadExact(s, buf, nm, hs);
        bool noAuth = false, userPass = false;
        for (int i = 0; i < nm; i++) { if (buf[i] == 0x00) noAuth = true; if (buf[i] == 0x02) userPass = true; }

        string user = "—";
        if (_authRequired)
        {
            if (!userPass) { await s.WriteAsync(new byte[] { 0x05, 0xFF }, hs); Log(peer.Name, "SOCKS5", "—", "—", false, "no user/pass method offered"); return; }
            await s.WriteAsync(new byte[] { 0x05, 0x02 }, hs);
            var (ok, u) = await Socks5Auth(s, buf, hs);
            user = u;
            ok = AuthVerdict(peer.Address, ok, out bool locked);
            await s.WriteAsync(new byte[] { 0x01, (byte)(ok ? 0x00 : 0x01) }, hs);
            if (!ok) { Log(peer.Name, "SOCKS5", "—", user, false, locked ? "locked out" : "bad credentials"); return; }
        }
        else if (noAuth)
        {
            await s.WriteAsync(new byte[] { 0x05, 0x00 }, hs);
        }
        else if (userPass)
        {
            // Auth is off but the client insists on user/pass — accept any credentials.
            await s.WriteAsync(new byte[] { 0x05, 0x02 }, hs);
            (_, user) = await Socks5Auth(s, buf, hs);
            await s.WriteAsync(new byte[] { 0x01, 0x00 }, hs);
        }
        else { await s.WriteAsync(new byte[] { 0x05, 0xFF }, hs); return; }

        // request: VER CMD RSV ATYP DST.ADDR DST.PORT
        await ReadExact(s, buf, 4, hs);
        byte cmd = buf[1], atyp = buf[3];
        string host;
        if (atyp == 0x01) { await ReadExact(s, buf, 4, hs); host = new IPAddress(new[] { buf[0], buf[1], buf[2], buf[3] }).ToString(); }
        else if (atyp == 0x03) { await ReadExact(s, buf, 1, hs); int l = buf[0]; await ReadExact(s, buf, l, hs); host = Encoding.ASCII.GetString(buf, 0, l); }
        else if (atyp == 0x04) { var a = new byte[16]; await ReadExact(s, a, 16, hs); host = new IPAddress(a).ToString(); }
        else { await Socks5Reply(s, 0x08, hs); return; }   // address type not supported
        await ReadExact(s, buf, 2, hs);
        int port = (buf[0] << 8) | buf[1];
        string target = FormatTarget(host, port);

        if (cmd == 0x03) { await UdpAssociateAsync(s, peer, user, port, ct).ConfigureAwait(false); return; }
        if (cmd != 0x01) { await Socks5Reply(s, 0x07, hs); Log(peer.Name, "SOCKS5", target, user, false, "command not supported"); return; }

        Remote remote;
        try { remote = await Dial(host, port, peer, ct); }
        catch (Exception ex) { LogDialFail(peer.Name, "SOCKS5", target, user, ex); await Socks5Reply(s, Socks5ErrFor(ex), ct); return; }

        using (remote)   // owned from here on, so a failing reply write can't leak the upstream socket
        {
            await Socks5Reply(s, 0x00, ct);
            Log(peer.Name, "SOCKS5", target, user, true, "connected");
            await Relay(s, remote, ct);
        }
    }

    private async Task<(bool ok, string user)> Socks5Auth(NetworkStream s, byte[] buf, CancellationToken ct)
    {
        // RFC 1929: VER(0x01) ULEN UNAME PLEN PASSWD
        await ReadExact(s, buf, 2, ct);
        int ulen = buf[1];
        await ReadExact(s, buf, ulen, ct);
        string uname = Encoding.UTF8.GetString(buf, 0, ulen);   // for the connection log
        bool userOk = CryptographicOperations.FixedTimeEquals(buf.AsSpan(0, ulen), _userBytes);
        await ReadExact(s, buf, 1, ct);
        int plen = buf[0];
        await ReadExact(s, buf, plen, ct);
        bool passOk = CryptographicOperations.FixedTimeEquals(buf.AsSpan(0, plen), _passBytes);
        CryptographicOperations.ZeroMemory(buf.AsSpan(0, plen));   // the client's password doesn't stay in the buffer
        return (userOk & passOk, uname);
    }

    private static Task Socks5Reply(NetworkStream s, byte rep, CancellationToken ct)
        => s.WriteAsync(new byte[] { 0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, ct).AsTask();

    private static byte Socks5ErrFor(Exception ex) => (byte)(ex switch
    {
        ProxyDeniedException => 0x02,   // connection not allowed by ruleset
        ProxyRouteException => 0x03,    // network unreachable: the chosen interface can't carry it
        ProxyUpstreamException u => u.SocksReply,
        SocketException se => se.SocketErrorCode switch
        {
            SocketError.ConnectionRefused => 0x05,
            SocketError.NetworkUnreachable => 0x03,
            SocketError.HostUnreachable => 0x04,
            SocketError.HostNotFound => 0x04,
            _ => 0x01,
        },
        _ => 0x01,
    });

    // ------------------------------------------------------------------ SOCKS4 / 4a

    // The longest request taken: CD + port + address, a user id and a host name of up to 255 bytes each with their NULs.
    private const int Socks4MaxRequest = 7 + 256 + 256;

    // VN (already consumed) CD DSTPORT DSTIP USERID NUL, and for SOCKS4a (DSTIP 0.0.0.x, x not 0) HOSTNAME NUL: the proxy
    // resolves the name. There is no password in SOCKS4 (the user id is only a name), so with a login required it is
    // refused. CONNECT only, as with SOCKS5.
    private async Task HandleSocks4(NetworkStream s, Peer peer, CancellationToken hs, CancellationToken ct)
    {
        var buf = new byte[Socks4MaxRequest];
        int n = 0, userEnd = -1, nameEnd = -1;
        bool named = false;
        while (true)
        {
            if (n >= 7)
            {
                named = buf[3] == 0 && buf[4] == 0 && buf[5] == 0 && buf[6] != 0;
                if (userEnd < 0) userEnd = Array.IndexOf(buf, (byte)0, 7, n - 7);
                if (userEnd >= 0)
                {
                    if (!named) break;
                    nameEnd = Array.IndexOf(buf, (byte)0, userEnd + 1, n - userEnd - 1);
                    if (nameEnd >= 0) break;
                }
            }
            if (n == buf.Length) { await ReplyAndClose(s, Socks4Rejected, hs); return; }   // no end in sight: not a request we take
            int r = await s.ReadAsync(buf.AsMemory(n), hs).ConfigureAwait(false);
            if (r == 0) return;
            n += r;
        }

        string proto = named ? "SOCKS4a" : "SOCKS4";
        int port = (buf[1] << 8) | buf[2];
        string user = userEnd > 7 ? Encoding.UTF8.GetString(buf, 7, userEnd - 7) : "—";
        string host = named
            ? Encoding.ASCII.GetString(buf, userEnd + 1, nameEnd - userEnd - 1)
            : new IPAddress(buf.AsSpan(3, 4)).ToString();
        string target = FormatTarget(host, port);
        int end = (named ? nameEnd : userEnd) + 1;   // what came after the request already belongs to the tunnel

        if (_authRequired)
        {
            await Socks4Reply(s, false, hs);
            Log(peer.Name, proto, target, user, false, "no password login", "SOCKS4 has no password login, and this proxy requires one. Use it as a SOCKS5 or HTTP proxy.");
            return;
        }
        if (buf[0] != 0x01) { await Socks4Reply(s, false, hs); Log(peer.Name, proto, target, user, false, "command not supported"); return; }

        Remote remote;
        try { remote = await Dial(host, port, peer, ct); }
        catch (Exception ex) { LogDialFail(peer.Name, proto, target, user, ex); await Socks4Reply(s, false, ct); return; }

        using (remote)   // owned from here on, so a failing reply write can't leak the upstream socket
        {
            await Socks4Reply(s, true, ct);
            Log(peer.Name, proto, target, user, true, "connected");
            if (n > end) { await remote.Stream.WriteAsync(buf.AsMemory(end, n - end), ct); Interlocked.Add(ref _bytesUp, n - end); }
            await Relay(s, remote, ct);
        }
    }

    // VN 0, CD 0x5A granted / 0x5B rejected or failed, then a port and address clients ignore for CONNECT.
    private static Task Socks4Reply(NetworkStream s, bool granted, CancellationToken ct)
        => s.WriteAsync(granted ? new byte[] { 0x00, 0x5A, 0, 0, 0, 0, 0, 0 } : Socks4Rejected, ct).AsTask();

    private static readonly byte[] Socks4Rejected = { 0x00, 0x5B, 0, 0, 0, 0, 0, 0 };

    // ------------------------------------------------------------------ auth lockout

    // After MaxAuthFails wrong credentials, every attempt from that address fails unchecked for
    // LockoutMs; a success clears its count. Keyed by IP — the listener is IPv4-only, so it stays small.
    private bool IsLockedOut(IPAddress? ip)
    {
        if (ip is null) return false;
        lock (_authGate) return _authFails.TryGetValue(ip, out var f) && f.until > Environment.TickCount64;
    }

    // Judges a credential against the lockout and records the outcome in ONE step. Checked and counted apart, a
    // burst of parallel guesses all passed the check before the first failure was counted (10 judged per burst of
    // 40 instead of 5). Returns whether to let the client in; locked = refused unchecked.
    private bool AuthVerdict(IPAddress? ip, bool ok, out bool locked)
    {
        locked = false;
        if (ip is null) return ok;
        lock (_authGate)
        {
            long now = Environment.TickCount64;
            _authFails.TryGetValue(ip, out var f);
            if (f.until > now) { locked = true; return false; }
            if (ok) { _authFails.Remove(ip); return true; }
            if (_authFails.Count > MaxAuthEntries) TrimAuthFails(now);
            int fails = f.until != 0 ? 1 : f.fails + 1;   // a lockout that ran out → count afresh
            _authFails[ip] = fails >= MaxAuthFails ? (0, now + LockoutMs, now) : (fails, 0L, now);
            return false;
        }
    }

    // Bounds the table against address churn without lifting lockouts early (a wholesale Clear() let 4097 throwaway
    // addresses unlock everyone): run-out lockouts and counts idle for LockoutMs go first, then the oldest counts, and a
    // live lockout only if the table is still full of them. Trims to 3/4 so it doesn't run on every failure.
    private void TrimAuthFails(long now)
    {
        var drop = new List<IPAddress>();
        foreach (var (ip, f) in _authFails)
            if (f.until != 0 ? f.until <= now : now - f.last >= LockoutMs) drop.Add(ip);
        foreach (var ip in drop) _authFails.Remove(ip);
        int excess = _authFails.Count - MaxAuthEntries * 3 / 4;
        if (excess <= 0) return;
        var rest = new List<KeyValuePair<IPAddress, (int fails, long until, long last)>>(_authFails);
        rest.Sort((x, y) => x.Value.until > now != y.Value.until > now ? (x.Value.until > now ? 1 : -1) : x.Value.last.CompareTo(y.Value.last));
        for (int i = 0; i < excess; i++) _authFails.Remove(rest[i].Key);
    }

    // ------------------------------------------------------------------ HTTP

    private async Task HandleHttp(NetworkStream s, Peer peer, byte first, CancellationToken hs, CancellationToken ct)
    {
        // Read the request head (starting with the already-consumed first byte) up to the blank line, in
        // 8 KB reads rather than one ReadAsync per byte. Bytes that arrived after the head (a request body,
        // a pipelined TLS ClientHello) stay in the reader and are forwarded, not dropped.
        var reader = new HttpReader(s, first);
        var (head, tooLarge) = await reader.ReadHeadAsync(MaxHeadBytes, hs).ConfigureAwait(false);
        if (tooLarge) { await ReplyAndClose(s, "HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n", hs); return; }
        if (head is null) return;   // closed before the head was complete
        string requestLine = head[..head.IndexOf("\r\n", StringComparison.Ordinal)];
        var parts = requestLine.Split(' ');
        if (parts.Length < 3) { await ReplyAndClose(s, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n", hs); return; }
        string method = parts[0], uri = parts[1], ver = parts[2];

        string user = "—";
        if (_authRequired)
        {
            var (ok, u) = CheckHttpAuth(head);
            user = u ?? "—";
            bool locked;
            if (u is not null) ok = AuthVerdict(peer.Address, ok, out locked);
            else locked = IsLockedOut(peer.Address);   // no credentials yet (the first 407) isn't a failure
            if (!ok)
            {
                Log(peer.Name, "HTTP", uri, user, false, locked ? "locked out" : u is null ? "auth required" : "bad credentials");
                await ReplyAndClose(s, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Echoes\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", hs);
                return;
            }
        }

        if (method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
        {
            var (h, p) = SplitHostPort(uri, 443);
            Remote remote;
            try { remote = await Dial(h, p, peer, ct); }
            catch (Exception ex) { LogDialFail(peer.Name, "HTTPS", FormatTarget(h, p), user, ex); await ReplyAndClose(s, HttpDialError(ex), ct); return; }
            using (remote)   // owned from here on, so a failing reply write can't leak the upstream socket
            {
                await WriteAscii(s, "HTTP/1.1 200 Connection Established\r\n\r\n", ct);
                Log(peer.Name, "HTTPS", FormatTarget(h, p), user, true, "tunnel");
                // Some clients pipeline the TLS ClientHello right behind the CONNECT head.
                var early = reader.TakeBuffered();
                if (!early.IsEmpty) { await remote.Stream.WriteAsync(early, ct); Interlocked.Add(ref _bytesUp, early.Length); }
                await Relay(s, remote, ct);
            }
        }
        else
        {
            if (!Uri.TryCreate(uri, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttp
                || !TryGetBodyFraming(head, out bool chunked, out long length))
            {
                await ReplyAndClose(s, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n", ct);
                return;
            }
            string host = u.Host;
            int port = u.IsDefaultPort ? 80 : u.Port;
            Remote? remote = null;
            bool parent = false;   // handed to an HTTP upstream as a proxy takes it (absolute form)
            try
            {
                if (_upstream?.Proxy.Kind == ProxyUpstreamKind.Http)
                    parent = (remote = await ParentForHttpAsync(host, port, peer, ct)) is not null;
                remote ??= await Dial(host, port, peer, ct);
            }
            catch (Exception ex) { LogDialFail(peer.Name, "HTTP", FormatTarget(host, port), user, ex); await ReplyAndClose(s, HttpDialError(ex), ct); return; }

            using (remote)   // owned from here on, so a failing write can't leak the upstream socket
            {
                // Latin-1 both ways: the head was read byte→char, so raw UTF-8 / obs-text in header values
                // (cookies, Referer, custom headers) reaches the origin byte-exact — ASCII turned it into '?'.
                byte[] rebuilt = Encoding.Latin1.GetBytes(parent ? RebuildForParent(head, method, u, ver, _upstream!.Proxy) : RebuildForOrigin(head, method, u, ver));
                await remote.Stream.WriteAsync(rebuilt, ct);
                Interlocked.Add(ref _bytesUp, rebuilt.Length);
                Log(peer.Name, "HTTP", $"{host}:{port}{u.AbsolutePath}", user, true, "forward");   // no query: it may carry tokens
                await ForwardAsync(reader, s, remote.Stream, chunked, length, parent, ct);
            }
        }
    }

    // One request per forwarded connection. The origin was asked to close after this one response, gets
    // exactly this request's body, and the response streams back until it closes. Nothing the client sends
    // after that body is ever read: a raw relay here used to hand later keep-alive requests (for any host,
    // with their Proxy-Authorization) straight to the FIRST origin, unchecked and unlogged, and pass its
    // answers off as theirs. The response says 'Connection: close', so the client sends its next request on
    // a fresh connection that is auth-checked and logged on its own. HTTPS (CONNECT) tunnels are unaffected.
    private async Task ForwardAsync(HttpReader client, NetworkStream cs, Stream rs, bool chunked, long length, bool fromParent, CancellationToken ct)
    {
        using var idle = CancellationTokenSource.CreateLinkedTokenSource(ct);
        idle.CancelAfter(_idleMs);
        var answered = new StrongBox<bool>();   // the final response head is on its way to the client
        // Upload alongside the response, so a '100 Continue' or an early error reply reaches the client
        // while it is still sending.
        _ = SendBodyAsync(client, rs, chunked, length, idle, answered);
        await RelayResponseAsync(rs, cs, idle, answered, fromParent).ConfigureAwait(false);
    }

    // Client → origin: exactly this request's body (Content-Length bytes, or chunks through the last-chunk
    // and trailers) and nothing after it. A broken upload cancels the whole exchange. Never throws.
    private async Task SendBodyAsync(HttpReader client, Stream rs, bool chunked, long length, CancellationTokenSource idle, StrongBox<bool> answered)
    {
        try
        {
            var tok = idle.Token;
            bool ok = chunked
                ? await CopyChunkedAsync(client, rs, idle, tok).ConfigureAwait(false)
                : await CopyBodyAsync(client, rs, length, idle, tok).ConfigureAwait(false);
            if (!ok) { idle.Cancel(); return; }
            // Body sent; keep watching the client. Its EOF once the answer has started means it left (a browser closing
            // after a Content-Length body): end the exchange instead of holding the slot for an origin that ignores
            // 'Connection: close'. An EOF before the answer is a half-close: keep waiting for it. What it sends meanwhile
            // is a pipelined request that is never served: read off and dropped, at most 64 KB.
            for (int extra = 0; extra < 64 * 1024;)
            {
                var more = await client.ReadSomeAsync(64 * 1024, tok).ConfigureAwait(false);
                if (more.IsEmpty) { if (Volatile.Read(ref answered.Value)) idle.Cancel(); return; }
                extra += more.Length;
            }
        }
        catch { try { idle.Cancel(); } catch { /* exchange already over */ } }
    }

    private async Task<bool> CopyBodyAsync(HttpReader client, Stream rs, long count, CancellationTokenSource idle, CancellationToken tok)
    {
        while (count > 0)
        {
            var chunk = await client.ReadSomeAsync((int)Math.Min(count, _upLimit?.Chunk ?? RelayBuffer), tok).ConfigureAwait(false);
            if (chunk.IsEmpty) return false;
            idle.CancelAfter(_idleMs);
            await PaceAsync(_upLimit, chunk.Length, idle).ConfigureAwait(false);
            await rs.WriteAsync(chunk, tok).ConfigureAwait(false);
            Interlocked.Add(ref _bytesUp, chunk.Length);
            count -= chunk.Length;
        }
        return true;
    }

    private async Task<bool> CopyChunkedAsync(HttpReader client, Stream rs, CancellationTokenSource idle, CancellationToken tok)
    {
        while (true)
        {
            string? line = await client.ReadLineAsync(MaxHeadBytes, tok).ConfigureAwait(false);
            if (line is null || !TryParseChunkSize(line, out long size)) return false;
            idle.CancelAfter(_idleMs);
            await WriteLine(rs, line, tok).ConfigureAwait(false);
            if (size == 0) break;
            if (!await CopyBodyAsync(client, rs, size + 2, idle, tok).ConfigureAwait(false)) return false;   // data + CRLF
        }
        // Trailer section: header lines up to the blank line that ends the body.
        while (true)
        {
            string? line = await client.ReadLineAsync(MaxHeadBytes, tok).ConfigureAwait(false);
            if (line is null) return false;
            await WriteLine(rs, line, tok).ConfigureAwait(false);
            if (line.Length == 0) return true;
        }
    }

    private async Task WriteLine(Stream s, string line, CancellationToken ct)
    {
        byte[] b = Encoding.Latin1.GetBytes(line + "\r\n");
        await s.WriteAsync(b, ct).ConfigureAwait(false);
        Interlocked.Add(ref _bytesUp, b.Length);
    }

    // Origin → client: the response head with 'Connection: close' (1xx interim heads pass as they are),
    // then the body until the origin closes. A head that isn't HTTP or won't parse is passed through raw.
    // fromParent: the answer comes through an HTTP upstream, whose own 407 (its login refused) is passed on as a 502: a 407
    // would have the client ask its user for THIS proxy's password, again and again.
    private async Task RelayResponseAsync(Stream rs, NetworkStream cs, CancellationTokenSource idle, StrongBox<bool> answered, bool fromParent)
    {
        var tok = idle.Token;
        var origin = new HttpReader(rs);
        while (true)
        {
            var (head, _) = await origin.ReadHeadAsync(MaxHeadBytes, tok).ConfigureAwait(false);
            if (head is null) break;   // EOF / oversized: whatever is buffered goes through as-is below
            idle.CancelAfter(_idleMs);
            bool http = head.StartsWith("HTTP/", StringComparison.Ordinal);
            bool interim = http && IsInterim(head);
            if (fromParent && http && StatusOf(head) == 407) head = "HTTP/1.1 502 Bad Gateway" + head[head.IndexOf("\r\n", StringComparison.Ordinal)..];
            byte[] b = Encoding.Latin1.GetBytes(http && !interim ? RewriteResponseHead(head) : head);
            await cs.WriteAsync(b, tok).ConfigureAwait(false);
            Interlocked.Add(ref _bytesDown, b.Length);
            if (!interim) break;
        }
        Volatile.Write(ref answered.Value, true);   // the final head is out (or a raw answer is about to be)
        var rest = origin.TakeBuffered();
        if (!rest.IsEmpty) { await cs.WriteAsync(rest, tok).ConfigureAwait(false); Interlocked.Add(ref _bytesDown, rest.Length); }
        await Pump(rs, cs, cs.Socket, false, idle).ConfigureAwait(false);
    }

    // Request body framing (RFC 9112 §6): chunked, a Content-Length, or none. False = malformed,
    // conflicting, or a transfer coding we can't delimit — the proxy must know where the body ends.
    private static bool TryGetBodyFraming(string head, out bool chunked, out long length)
    {
        chunked = false; length = 0;
        bool hasLength = false;
        foreach (var line in head.Split("\r\n"))
        {
            int c = line.IndexOf(':');
            if (c <= 0) continue;
            var name = line.AsSpan(0, c).Trim();
            var value = line.AsSpan(c + 1).Trim();
            if (name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase))
            {
                if (!value.Equals("chunked", StringComparison.OrdinalIgnoreCase)) return false;
                chunked = true;
            }
            else if (name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
            {
                if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out long n) || (hasLength && n != length)) return false;
                length = n; hasLength = true;
            }
        }
        return !(chunked && hasLength);
    }

    private static bool TryParseChunkSize(string line, out long size)
    {
        int semi = line.IndexOf(';');   // chunk extensions
        var hex = (semi >= 0 ? line.AsSpan(0, semi) : line.AsSpan()).Trim();
        return long.TryParse(hex, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out size)
               && size is >= 0 and <= long.MaxValue - 2;
    }

    // The status code of a response head ("HTTP/1.1 407 …" → 407); 0 when there is none.
    private static int StatusOf(string head)
    {
        int sp = head.IndexOf(' ');
        return sp > 0 && sp + 4 <= head.Length && int.TryParse(head.AsSpan(sp + 1, 3), NumberStyles.None, CultureInfo.InvariantCulture, out int code) ? code : 0;
    }

    // "HTTP/1.1 1xx" other than 101: informational (100 Continue, 103 Early Hints) — the final head follows.
    private static bool IsInterim(string head)
    {
        int sp = head.IndexOf(' ');
        return sp > 0 && sp + 3 < head.Length && head[sp + 1] == '1' && !(head[sp + 2] == '0' && head[sp + 3] == '1');
    }

    private static readonly string[] RequestHopHeaders = { "Connection", "Keep-Alive", "Proxy-Connection", "TE", "Upgrade" };
    private static readonly string[] ResponseHopHeaders = { "Connection", "Keep-Alive", "Proxy-Connection" };

    // Convert an absolute-form proxy request into an origin-form request the target server accepts:
    // rewrite the request line to the path, drop hop-by-hop headers, keep/synthesize Host, and ask the
    // origin to close after this response (one request per forwarded connection — see ForwardAsync).
    private static string RebuildForOrigin(string head, string method, Uri u, string ver)
    {
        var lines = head.Split("\r\n");
        var sb = new StringBuilder(head.Length + 32);
        sb.Append(method).Append(' ').Append(u.PathAndQuery).Append(' ').Append(ver).Append("\r\n");
        AppendEndToEndHeaders(sb, lines, RequestHopHeaders, out bool hasHost);
        if (!hasHost) sb.Append("Host: ").Append(u.Authority).Append("\r\n");
        sb.Append("Connection: close\r\n\r\n");
        return sb.ToString();
    }

    // For an HTTP upstream: the request as a proxy takes it (absolute form, with the upstream's own login), the client's
    // hop-by-hop and Proxy-* headers dropped as for an origin, Host kept or made, and the upstream asked to close after the
    // answer (one request per forwarded connection, as with an origin: see ForwardAsync).
    private static string RebuildForParent(string head, string method, Uri u, string ver, ProxyUpstream up)
    {
        var lines = head.Split("\r\n");
        var sb = new StringBuilder(head.Length + 96);
        sb.Append(method).Append(" http://").Append(u.Authority).Append(u.PathAndQuery).Append(' ').Append(ver).Append("\r\n");
        AppendEndToEndHeaders(sb, lines, RequestHopHeaders, out bool hasHost);
        if (!hasHost) sb.Append("Host: ").Append(u.Authority).Append("\r\n");
        sb.Append(up.AuthorizationLine());
        sb.Append("Connection: close\r\nProxy-Connection: close\r\n\r\n");
        return sb.ToString();
    }

    private static string RewriteResponseHead(string head)
    {
        var lines = head.Split("\r\n");
        var sb = new StringBuilder(head.Length + 48);
        sb.Append(lines[0]).Append("\r\n");
        AppendEndToEndHeaders(sb, lines, ResponseHopHeaders, out _);
        sb.Append("Connection: close\r\nProxy-Connection: close\r\n\r\n");
        return sb.ToString();
    }

    // Copy a head's header lines minus hop-by-hop ones: the given list, whatever the Connection header
    // names, and every Proxy-* header. Content-Length, Transfer-Encoding and Host are kept whatever
    // Connection names: the body is relayed byte for byte, so its framing must arrive intact.
    private static void AppendEndToEndHeaders(StringBuilder sb, string[] lines, string[] hop, out bool hasHost)
    {
        var drop = new HashSet<string>(hop, StringComparer.OrdinalIgnoreCase);
        for (int i = 1; i < lines.Length; i++)
            if (HeaderName(lines[i]).Equals("Connection", StringComparison.OrdinalIgnoreCase))
                foreach (var token in lines[i][(lines[i].IndexOf(':') + 1)..].Split(','))
                    drop.Add(token.Trim());
        drop.Remove("Content-Length");
        drop.Remove("Transfer-Encoding");
        drop.Remove("Host");

        hasHost = false;
        bool skip = false;
        for (int i = 1; i < lines.Length; i++)
        {
            string line = lines[i];
            if (line.Length == 0) break;
            if (line[0] is ' ' or '\t') { if (!skip) sb.Append(line).Append("\r\n"); continue; }   // obs-fold continues its header
            string name = HeaderName(line);
            skip = drop.Contains(name) || name.StartsWith("Proxy-", StringComparison.OrdinalIgnoreCase);
            if (skip) continue;
            if (name.Equals("Host", StringComparison.OrdinalIgnoreCase)) hasHost = true;
            sb.Append(line).Append("\r\n");
        }
    }

    private static string HeaderName(string line)
    {
        int c = line.IndexOf(':');
        return c > 0 ? line[..c].Trim() : "";
    }

    private (bool ok, string? user) CheckHttpAuth(string head)
    {
        foreach (var line in head.Split("\r\n"))
        {
            if (!line.StartsWith("Proxy-Authorization:", StringComparison.OrdinalIgnoreCase)) continue;
            string v = line["Proxy-Authorization:".Length..].Trim();
            if (!v.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase)) continue;
            byte[]? raw = null;
            try
            {
                // Compared as bytes in constant time; only the user name becomes a string (for the log).
                raw = Convert.FromBase64String(v[6..].Trim());
                int c = Array.IndexOf(raw, (byte)':');
                ReadOnlySpan<byte> un = c >= 0 ? raw.AsSpan(0, c) : raw.AsSpan();
                ReadOnlySpan<byte> pw = c >= 0 ? raw.AsSpan(c + 1) : ReadOnlySpan<byte>.Empty;
                bool ok = CryptographicOperations.FixedTimeEquals(un, _userBytes) & CryptographicOperations.FixedTimeEquals(pw, _passBytes);
                // Without a ':' the whole credential may be a password or token: never shown as the user name.
                return (ok, c >= 0 ? Encoding.UTF8.GetString(un) : "—");
            }
            catch { return (false, null); }
            finally { if (raw is not null) CryptographicOperations.ZeroMemory(raw); }
        }
        return (false, null);
    }

    private static (string host, int port) SplitHostPort(string s, int def)
    {
        if (s.StartsWith('['))   // [IPv6]:port
        {
            int e = s.IndexOf(']');
            if (e > 0)
            {
                string h = s[1..e];
                int c = s.IndexOf(':', e);
                return (h, c >= 0 && int.TryParse(s.AsSpan(c + 1), out int pp) ? pp : def);
            }
        }
        int i = s.LastIndexOf(':');
        return i > 0 && int.TryParse(s.AsSpan(i + 1), out int p) ? (s[..i], p) : (s, def);
    }

    // ------------------------------------------------------------------ shared

    // Thrown by Dial for a target the client may not reach (SOCKS 0x02 / HTTP 403): one a non-local client is never
    // given, or one the user's rules block. Status = log text; Body = what an HTTP client is told.
    private sealed class ProxyDeniedException : Exception
    {
        public ProxyDeniedException(string status, string? body = null)
        {
            Status = status;
            Body = body ?? DeniedBody;
        }

        public string Status { get; }
        public string Body { get; }
    }

    // Thrown by Dial when the connection can't leave this device the way the user chose: the outgoing interface is
    // down, has no address of the target's kind, or the system won't connect from it (SOCKS 0x03 / HTTP 502).
    // Status = log text; Detail = the sentence in the log row's tooltip.
    internal sealed class ProxyRouteException : Exception
    {
        public ProxyRouteException(string status, string detail, Exception? inner = null) : base(detail, inner)
        {
            Status = status;
            Detail = detail;
        }

        public string Status { get; }
        public string Detail { get; }
        /// <summary>The system wouldn't send from the interface (not: it has no address of the target's kind).</summary>
        public bool InterfaceFault { get; init; }
    }

    private const string DeniedBody = "Echoes proxy: for clients on other devices, this device's own addresses (loopback, link-local, LAN, VPN) are blocked, " +
                                      "and so are private networks other than the client's own and mail ports (25, 465, 587) while the proxy has no password.\n";
    private const string RuleBody = "Echoes proxy: this host or port is blocked by the proxy's rules.\n";

    // (the bodies are ASCII: a character is a byte)
    private static string HttpError(string status, string body)
        => $"HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n{body}";

    private static string HttpDialError(Exception ex) => ex switch
    {
        ProxyDeniedException d => HttpError("403 Forbidden", d.Body),
        OperationCanceledException or SocketException { SocketErrorCode: SocketError.TimedOut }
            => HttpError("504 Gateway Timeout", "Echoes proxy: the site didn't answer in time.\n"),
        _ => HttpError("502 Bad Gateway", $"Echoes proxy: couldn't connect to the site ({DialFailText(ex)}).\n"),
    };

    // The log's short status for a connection that wasn't made.
    private static string DialFailText(Exception ex) => ex switch
    {
        ProxyDeniedException d => d.Status,
        ProxyRouteException r => r.Status,
        ProxyUpstreamException u => u.Status,
        OperationCanceledException => "timed out",
        SocketException se => se.SocketErrorCode switch
        {
            SocketError.ConnectionRefused => "refused",
            SocketError.TimedOut => "timed out",
            SocketError.HostNotFound or SocketError.NoData or SocketError.TryAgain or SocketError.NoRecovery => "no such host",
            SocketError.NetworkUnreachable or SocketError.HostUnreachable or SocketError.NetworkDown or SocketError.HostDown => "unreachable",
            SocketError.ConnectionReset or SocketError.ConnectionAborted => "reset",
            _ => "connect failed",
        },
        _ => "connect failed",
    };

    private void LogDialFail(string client, string proto, string target, string user, Exception ex)
        => Log(client, proto, target, user, false, DialFailText(ex), ex switch { ProxyRouteException r => r.Detail, ProxyUpstreamException u => u.Detail, _ => "" });

    // Resolve, vet, connect. The proxy is open to the LAN by design, but it must not be a door from the LAN
    // into THIS device's loopback-only services (the Echoes file share on 'Localhost only', dev servers, DB
    // UIs, other apps' localhost ports on Android), nor to anything on its own LAN / VPN / Docker / WSL /
    // IPv6 addresses: that connection would start on this host itself, which host firewalls don't filter,
    // so CONNECT 192.168.1.10:445 to our own IP would reach a share the firewall blocks from the LAN. For a
    // client that isn't this device, a target that resolves to loopback, unspecified (0.0.0.0 / ::),
    // link-local or one of this device's addresses is refused. We then connect to exactly the vetted
    // addresses — letting ConnectAsync(host) resolve again would let DNS rebinding swap in 127.0.0.1.
    //
    // Then the user's own choices: blocked hosts and ports are refused, the IP version picks among the addresses, and
    // the connection is tied to the chosen outgoing interface (see ConnectOutAsync). A target on this device itself
    // (only its own programs get that far) never leaves it, so it is connected as always, whatever the interface.
    // With an upstream proxy set, the connection goes to it instead (DialUpstreamAsync).
    private async Task<Remote> Dial(string host, int port, Peer peer, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(_connectMs);
        host = CheckRequest(host, port, peer, out IPAddress? literal);
        if (_upstream is not null) return await DialUpstreamAsync(host, literal, port, peer, timeout.Token).ConfigureAwait(false);

        var targets = await TargetsAsync(host, literal, port, peer, timeout.Token).ConfigureAwait(false);
        Exception? last = null;
        foreach (var a in targets)
        {
            try { return new Remote(await ConnectOutAsync(a, port, ViaFor(a, peer), timeout.Token).ConfigureAwait(false)); }
            catch (Exception ex)
            {
                // a route problem with another address still to try (the interface has IPv4 only, the name both kinds)
                // doesn't hide what that other address says
                if (ex is not ProxyRouteException || last is null or ProxyRouteException) last = ex;
                if (ex is ProxyRouteException { InterfaceFault: true }) _out?.Suspect();
                if (timeout.IsCancellationRequested) break;
            }
        }
        throw last ?? new SocketException((int)SocketError.HostNotFound);
    }

    // What is refused before anything is looked up: an empty host, a port or a host name the user's rules block, and
    // mail ports for other devices while there is no password. Returns the host without the brackets of an IPv6
    // literal; literal = the address when the host is one.
    private string CheckRequest(string host, int port, Peer peer, out IPAddress? literal)
    {
        if (host.Length > 2 && host[0] == '[' && host[^1] == ']') host = host[1..^1];   // Uri.Host keeps IPv6 brackets
        if (host.Length == 0) throw new SocketException((int)SocketError.HostNotFound);   // "" would resolve to this host
        if (!_rules.PortAllowed(port)) throw new ProxyDeniedException("blocked (port)", RuleBody);
        if (!IPAddress.TryParse(host, out literal))
        {
            literal = null;
            if (_rules.HostBlocked(host)) throw new ProxyDeniedException("blocked (rule)", RuleBody);
        }
        // Without a password anyone who reaches the port could send mail under this device's address (spam relay).
        if (!peer.IsLocal && !_authRequired && port is 25 or 465 or 587) throw new ProxyDeniedException("blocked (mail port)");
        return host;
    }

    // The addresses a request may be connected to, in the resolver's order: the host's own (or the literal), vetted
    // for a client on another device as the comment above Dial says, then less what the user's rules block and what
    // the IP version leaves out. Throws when none is left.
    private async Task<List<IPAddress>> TargetsAsync(string host, IPAddress? literal, int port, Peer peer, CancellationToken ct)
    {
        IPAddress[] addrs = literal is not null
            ? new[] { literal }
            : await (LookUp?.Invoke(host, ct) ?? Dns.GetHostAddressesAsync(host, ct)).ConfigureAwait(false);
        if (addrs.Length == 0) throw new SocketException((int)SocketError.HostNotFound);
        if (!peer.IsLocal)
        {
            // The client's own subnet = the entry interface's subnet, and only if the client is on it too: one coming
            // through a port forward, a router or a VPN isn't, and gets no private target at all.
            bool clientOnLink = peer.Address is { } client && _own.SameSubnet(client, peer.LocalAddress);
            foreach (var raw in addrs)
            {
                var a = EmbeddedIPv4(raw);   // ::a.b.c.d, NAT64, 6to4 … judged as the IPv4 inside
                if (IsLocalTarget(a)) throw new ProxyDeniedException("blocked (local)");
                if (_own.Contains(raw, peer.LocalAddress) || _own.Contains(a, peer.LocalAddress)) throw new ProxyDeniedException("blocked (this host)");
                // Without a password the proxy serves anyone on the network it listens on: the internet and the client's
                // own subnet, yes; the networks only this device reaches (WSL / Docker / Hyper-V guests, a VPN's or another
                // interface's ranges, the LAN's global IPv6 prefix), no. With a password the user chose who connects: unchanged.
                if (!_authRequired && (IsPrivateTarget(a) || _own.OnOtherLink(a, peer.LocalAddress))
                    && !(clientOnLink && _own.SameSubnet(a, peer.LocalAddress)))
                    throw new ProxyDeniedException("blocked (private network)");
            }
        }

        // The user's rules and IP version: what is left is tried.
        var targets = new List<IPAddress>(addrs.Length);
        bool ruled = false;
        foreach (var raw in addrs)
        {
            var a = raw.IsIPv4MappedToIPv6 ? raw.MapToIPv4() : raw;   // ::ffff:a.b.c.d is connected to as the IPv4 address it is
            if (_rules.AddressBlocked(a) || _rules.AddressBlocked(EmbeddedIPv4(a))) { ruled = true; continue; }
            if (_ipVersion == ProxyIpVersion.IPv4 && a.AddressFamily != AddressFamily.InterNetwork) continue;
            if (_ipVersion == ProxyIpVersion.IPv6 && a.AddressFamily != AddressFamily.InterNetworkV6) continue;
            targets.Add(a);
        }
        if (targets.Count == 0)
        {
            if (ruled) throw new ProxyDeniedException("blocked (rule)", RuleBody);
            string kind = _ipVersion == ProxyIpVersion.IPv4 ? "IPv4" : "IPv6";
            throw new ProxyRouteException($"no {kind} address", $"{(literal is not null ? "It isn't an" : "The name has no")} {kind} address, and the proxy is set to {kind} only.");
        }
        return targets;
    }

    // The interface a connection to this address leaves from: none chosen, or an address on this device itself (which
    // never leaves it, so only its own programs get that far): null, the system's own way. Throws while the chosen
    // interface is down: nothing is sent some other way.
    private NetIface? ViaFor(IPAddress address, Peer peer)
    {
        if (_out is null || IsLocalTarget(address) || _own.Contains(address, peer.LocalAddress)) return null;
        return _out.Current(_own.Changes)
               ?? throw new ProxyRouteException("interface down", $"{_out.Name} isn't connected: nothing is sent while the proxy's outgoing interface is down.");
    }

    // ------------------------------------------------------------------ through the upstream proxy

    // With an upstream proxy set, the connection is made to IT (from the chosen interface, like any other), and it is
    // asked for a tunnel to the target. Nothing goes to a target directly.
    //
    // A name: an upstream that looks names up itself is handed the name, and nothing is looked up here (no query on
    // the local network that shows where the client is going; a resolver here that lies about a name doesn't matter).
    // But then this proxy can't know where the name leads, and an upstream on this device or on a network only this
    // device reaches would connect to this device's own services, or into those networks, for whoever asks: exactly
    // what the vetting above exists to stop. So a name passes as a name only for this device's own programs, or to an
    // upstream out on the internet. For a client on another device the name is looked up here, vetted, and a near
    // upstream is handed the address: also with a password or an allowed-clients list, which choose who may connect
    // and only ever refuse more, never let a client reach what the vetting refuses it without an upstream.
    private async Task<Remote> DialUpstreamAsync(string host, IPAddress? literal, int port, Peer peer, CancellationToken ct)
    {
        var up = _upstream!;
        var hops = await up.AddressesAsync(ct).ConfigureAwait(false);
        if (literal is null && MayPassName(up, hops, peer))
            return await TunnelAsync(up, hops, host, port, peer, ct).ConfigureAwait(false);

        var targets = await TargetsAsync(host, literal, port, peer, ct).ConfigureAwait(false);
        Exception? last = null;
        foreach (var a in targets)
        {
            try { return await TunnelAsync(up, hops, a.ToString(), port, peer, ct).ConfigureAwait(false); }
            catch (Exception ex)
            {
                last = ex;
                // the upstream itself is the trouble (or the interface): the target's other addresses fare no better
                if (ex is ProxyUpstreamException { Fatal: true } or ProxyRouteException || ct.IsCancellationRequested) break;
            }
        }
        throw last ?? new SocketException((int)SocketError.HostNotFound);
    }

    // Whether a name goes to the upstream as a name (see above): the upstream looks names up, nothing here needs the
    // addresses (an IP version or blocked addresses do), and the client is this device itself or the upstream is out on
    // the internet.
    private bool MayPassName(UpstreamLink up, IPAddress[] hops, Peer peer)
        => up.Proxy.ResolvesNames && _ipVersion == ProxyIpVersion.Auto && !_rules.BlocksAddresses
           && (peer.IsLocal || IsFar(hops));

    // A plain http:// request through an HTTP upstream: the connection to the upstream when the request may be handed to
    // it as a proxy takes it (absolute form: it connects, and looks the name up, itself), else null, and the request goes
    // through a tunnel to a vetted address like any other connection (Dial). Many HTTP proxies open tunnels to port 443
    // only, so the request as it is is what works through them.
    private async Task<Remote?> ParentForHttpAsync(string host, int port, Peer peer, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(_connectMs);
        host = CheckRequest(host, port, peer, out IPAddress? literal);
        var up = _upstream!;
        var hops = await up.AddressesAsync(timeout.Token).ConfigureAwait(false);
        if (literal is not null) await TargetsAsync(host, literal, port, peer, timeout.Token).ConfigureAwait(false);   // vetted: throws when refused
        else if (!MayPassName(up, hops, peer)) return null;
        return await OpenUpstreamAsync(up, hops, peer, timeout.Token).ConfigureAwait(false);
    }

    // The upstream's addresses are all out on the internet: not this device, not a private range, not a network of one
    // of this device's other interfaces.
    private bool IsFar(IPAddress[] hops)
    {
        foreach (var raw in hops)
        {
            var a = EmbeddedIPv4(raw);
            if (IsLocalTarget(a) || IsPrivateTarget(a) || _own.Contains(raw, null) || _own.Contains(a, null) || _own.OnOtherLink(a, null)) return false;
        }
        return hops.Length > 0;
    }

    // A connection to the upstream (its first address that takes one) with the tunnel to host:port open on it.
    private async Task<Remote> TunnelAsync(UpstreamLink up, IPAddress[] hops, string host, int port, Peer peer, CancellationToken ct)
    {
        var remote = await OpenUpstreamAsync(up, hops, peer, ct).ConfigureAwait(false);
        try
        {
            await up.Proxy.OpenTunnelAsync(remote.Stream, host, port, ct).ConfigureAwait(false);
            return remote;
        }
        catch
        {
            remote.Dispose();
            throw;
        }
    }

    // A connection to the upstream (ConnectUpstreamAsync), with TLS on it for an https:// one.
    private async Task<Remote> OpenUpstreamAsync(UpstreamLink up, IPAddress[] hops, Peer peer, CancellationToken ct)
    {
        var tcp = await ConnectUpstreamAsync(up, hops, peer, ct).ConfigureAwait(false);
        if (!up.Proxy.Tls) return new Remote(tcp);
        try { return new Remote(tcp, await up.Proxy.SecureAsync(tcp.GetStream(), ct).ConfigureAwait(false)); }
        catch
        {
            tcp.Dispose();
            throw;
        }
    }

    // A connection a tunnel or a forwarded request goes over: to the target, or to it through the upstream proxy. The
    // socket, and the stream on it (its own, or TLS to an https:// upstream). Disposing it closes both.
    private sealed class Remote(TcpClient tcp, Stream? stream = null) : IDisposable
    {
        public Socket Socket => tcp.Client;
        public Stream Stream { get; } = stream ?? tcp.GetStream();

        public void Dispose()
        {
            Stream.Dispose();
            tcp.Dispose();
        }
    }

    // A connection to the upstream: its first address that takes one, from the outgoing interface like any connection.
    private async Task<TcpClient> ConnectUpstreamAsync(UpstreamLink up, IPAddress[] hops, Peer peer, CancellationToken ct)
    {
        TcpClient? remote = null;
        Exception? down = null;
        foreach (var hop in hops)
        {
            try
            {
                remote = await ConnectOutAsync(hop, up.Proxy.Port, ViaFor(hop, peer), ct).ConfigureAwait(false);
                break;
            }
            catch (ProxyRouteException ex)
            {
                if (ex.InterfaceFault) _out?.Suspect();
                down ??= ex;
            }
            catch (Exception ex) when (ex is SocketException or IOException) { down = ex; }
        }
        if (remote is null)
        {
            if (down is ProxyRouteException) throw down;
            up.Forget();   // its address may have changed: look the name up again for the next connection
            throw new ProxyUpstreamException("upstream down", $"The upstream proxy {up.Proxy.Display} can't be reached ({(down is null ? "it has no address" : DialFailText(down))}).", inner: down) { Fatal = true };
        }
        return remote;
    }

    // The upstream proxy and where it is. An address is used as it is; a name is looked up by the system resolver and
    // looked up again every minute (and after a connection to it failed), so a proxy that moved is found again.
    private sealed class UpstreamLink(ProxyUpstream proxy)
    {
        private const long FreshMs = 60_000;
        private readonly IPAddress[]? _fixed = IPAddress.TryParse(proxy.Host, out var literal) ? new[] { literal } : null;
        private volatile Tuple<IPAddress[], long>? _found;

        public ProxyUpstream Proxy => proxy;

        public async Task<IPAddress[]> AddressesAsync(CancellationToken ct)
        {
            if (_fixed is not null) return _fixed;
            if (_found is { } known && Environment.TickCount64 - known.Item2 < FreshMs) return known.Item1;
            IPAddress[] addrs;
            try { addrs = await Dns.GetHostAddressesAsync(proxy.Host, ct).ConfigureAwait(false); }
            catch (SocketException ex)
            {
                throw new ProxyUpstreamException("upstream down", $"The upstream proxy's name {proxy.Host} doesn't resolve.", inner: ex) { Fatal = true };
            }
            if (addrs.Length == 0) throw new ProxyUpstreamException("upstream down", $"The upstream proxy's name {proxy.Host} has no address.") { Fatal = true };
            _found = Tuple.Create(addrs, Environment.TickCount64);
            return addrs;
        }

        public void Forget() => _found = null;
    }

    /// <summary>
    /// One connection to a target. <paramref name="via"/>: the interface it leaves from (null = the routing table's
    /// choice). A socket that can't be tied to the interface is never connected (it would take the default route):
    /// that, an interface without an address of the target's kind, and a connect the system refuses because of the
    /// interface are a <see cref="ProxyRouteException"/>; everything else is the target's own answer.
    /// </summary>
    internal static async Task<TcpClient> ConnectOutAsync(IPAddress address, int port, NetIface? via, CancellationToken ct)
    {
        if (via?.Missing(address) is { } missing)
            throw new ProxyRouteException(address.AddressFamily == AddressFamily.InterNetworkV6 ? "no IPv6 on interface" : "no IPv4 on interface", NetIfaceException.From(via, missing).Message);
        var remote = new TcpClient(address.AddressFamily) { NoDelay = true };
        try
        {
            if (via is not null)
            {
                address = via.Scoped(address);
                if (!via.TryBind(remote.Client, out string? why))
                    throw new ProxyRouteException("interface error", NetIfaceException.From(via, why ?? $"can't send through {via.Name}").Message) { InterfaceFault = true };
            }
            await remote.ConnectAsync(address, port, ct).ConfigureAwait(false);
            return remote;
        }
        catch (SocketException se) when (via?.ConnectProblem(se.SocketErrorCode, address.ToString()) is { } problem)
        {
            remote.Dispose();
            throw new ProxyRouteException("no route (interface)", NetIfaceException.From(via, problem).Message, se) { InterfaceFault = true };
        }
        catch
        {
            remote.Dispose();
            throw;
        }
    }

    // The chosen outgoing interface as it is right now. Its address changes (DHCP) and it comes and goes (Wi-Fi, a
    // VPN), so it is found by its name again after the system reports an address change, and every so often anyway
    // (where no change is reported: Android), sooner while it is down. Reading the interfaces takes milliseconds and
    // every connection asks, so the answer is kept in between.
    private sealed class OutLink(string name)
    {
        // (SuspectMs: after a connection couldn't leave from it. Not at once: a burst of failing connections would
        // otherwise read the interfaces once each, one behind the other.)
        private const long FoundMs = 30_000, MissingMs = 2_000, SuspectMs = 1_000;

        private readonly object _gate = new();
        private NetIface? _iface;
        private long _stamp;
        private int _changes;
        private bool _read, _suspect;

        public string Name => name;

        /// <summary>The interface, or null while it isn't up. <paramref name="changes"/>: the address-change count.</summary>
        public NetIface? Current(int changes)
        {
            lock (_gate)   // one lookup at a time; connections queued behind it take its result
            {
                long now = Environment.TickCount64, age = now - _stamp;
                if (!_read || changes != _changes || age >= (_iface is null ? MissingMs : FoundMs) || (_suspect && age >= SuspectMs))
                {
                    // (loopback too: it is never offered as a choice, but a test may name it)
                    _iface = NetIfaces.Find(name, withLoopback: true);
                    _stamp = now;
                    _changes = changes;
                    _read = true;
                    _suspect = false;
                }
                return _iface;
            }
        }

        /// <summary>A connection couldn't leave from it (its address may have changed): read it again soon.</summary>
        public void Suspect()
        {
            lock (_gate) _suspect = true;
        }
    }

    // Paces the bytes of all tunnels together to a rate (one of these for each direction). Each read "pays" for its
    // bytes on one shared time line: when the line is ahead of the clock, the read waits until its turn. Up to a quarter
    // second's worth passes at once after a quiet spell, so short exchanges (a handshake, a small page) aren't slowed.
    private sealed class Throttle(long bytesPerSecond)
    {
        private readonly object _gate = new();
        private long _paidUntil;   // Stopwatch ticks

        /// <summary>The most to read at once: about an eighth of a second's worth, so the pacing is smooth.</summary>
        public int Chunk { get; } = (int)Math.Clamp(bytesPerSecond / 8, 1024, RelayBuffer);

        /// <summary>Books <paramref name="bytes"/> and says how long to wait before sending them on.</summary>
        public TimeSpan Reserve(int bytes)
        {
            long now = System.Diagnostics.Stopwatch.GetTimestamp();
            long cost = (long)(bytes * (double)System.Diagnostics.Stopwatch.Frequency / bytesPerSecond);
            long due;
            lock (_gate)
            {
                long earliest = now - System.Diagnostics.Stopwatch.Frequency / 4;
                if (_paidUntil < earliest) _paidUntil = earliest;
                due = _paidUntil;
                _paidUntil += cost;
            }
            return due > now ? TimeSpan.FromSeconds((due - now) / (double)System.Diagnostics.Stopwatch.Frequency) : TimeSpan.Zero;
        }
    }

    // Waits out a speed limit for bytes just read (no limit: nothing). True when it had to wait: the tunnel isn't idle
    // while it waits its turn, so the idle deadline is kept past the wait. Kept, not set once: traffic the other way
    // (the other pump, a UDP answer) sets it back to the plain idle time meanwhile, and a wait longer than that (a low
    // limit shared by many downloads) would then be cut off as idle. So the wait is made in steps of half the idle
    // time, each moving the deadline past what is left of it.
    private async ValueTask<bool> PaceAsync(Throttle? limit, int bytes, CancellationTokenSource idle)
    {
        if (limit is null) return false;
        var wait = limit.Reserve(bytes);
        if (wait <= TimeSpan.Zero) return false;
        var idleTime = TimeSpan.FromMilliseconds(_idleMs);
        var step = idleTime / 2;
        long start = System.Diagnostics.Stopwatch.GetTimestamp();
        for (var left = wait; left >= TimeSpan.FromMilliseconds(1); left = wait - System.Diagnostics.Stopwatch.GetElapsedTime(start))
        {
            idle.CancelAfter(left + idleTime);
            await Task.Delay(left < step ? left : step, idle.Token).ConfigureAwait(false);
        }
        return true;
    }

    // Judged on the address bytes alone: IPAddress.Equals / IsLoopback also compare the IPv6 scope id, so
    // a literal like '::1%1' would otherwise slip past as "not loopback" and still connect to it.
    private static bool IsLocalTarget(IPAddress a)
    {
        if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
        var b = a.GetAddressBytes();
        if (a.AddressFamily == AddressFamily.InterNetwork)
            return b[0] is 0 or 127 || (b[0] == 169 && b[1] == 254);   // 0/8 'this host', 127/8 loopback, 169.254/16 link-local
        if (b.Length != 16) return false;
        bool zeroPrefix = b.AsSpan(0, 15).IndexOfAnyExcept((byte)0) < 0;
        return (zeroPrefix && b[15] <= 1)                              // :: unspecified, ::1 loopback
               || (b[0] == 0xFE && (b[1] & 0xC0) == 0x80);             // fe80::/10 link-local
    }

    // The IPv4 address an IPv6 one carries, else the address itself: IPv4-mapped (::ffff:a.b.c.d), IPv4-compatible
    // (::a.b.c.d), IPv4-translated (::ffff:0:a.b.c.d), NAT64 (64:ff9b::/96, 64:ff9b:1::/48 with the IPv4 in the last
    // 32 bits) and 6to4 (2002:AABB:CCDD::/48). Judged as that IPv4, so 64:ff9b::7f00:1 counts as 127.0.0.1.
    private static IPAddress EmbeddedIPv4(IPAddress a)
    {
        if (a.AddressFamily != AddressFamily.InterNetworkV6) return a;
        if (a.IsIPv4MappedToIPv6) return a.MapToIPv4();
        var b = a.GetAddressBytes();
        bool zero8 = b.AsSpan(0, 8).IndexOfAnyExcept((byte)0) < 0;
        if (zero8 && b[10] == 0 && b[11] == 0 && (b[8], b[9]) is (0, 0) or (0xFF, 0xFF))   // ::a.b.c.d, ::ffff:0:a.b.c.d
            return new IPAddress(b.AsSpan(12, 4));
        if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xFF && b[3] == 0x9B
            && (b.AsSpan(4, 8).IndexOfAnyExcept((byte)0) < 0 || (b[4] == 0 && b[5] == 1)))   // 64:ff9b::/96, 64:ff9b:1::/48
            return new IPAddress(b.AsSpan(12, 4));
        if (b[0] == 0x20 && b[1] == 0x02) return new IPAddress(b.AsSpan(2, 4));   // 2002::/16
        return a;
    }

    // Private ranges: 10/8, 172.16/12, 192.168/16, 100.64/10 (carrier-grade NAT, Tailscale), fc00::/7 (unique local),
    // fec0::/10 (old site-local). Not 198.18/15: TUN-mode VPN clients (v2rayN, Clash, sing-box) answer DNS with "fake"
    // addresses there, so every site would look private while one runs.
    private static bool IsPrivateTarget(IPAddress a)
    {
        if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
        var b = a.GetAddressBytes();
        if (a.AddressFamily == AddressFamily.InterNetwork)
            return b[0] == 10 || (b[0] == 172 && (b[1] & 0xF0) == 16) || (b[0] == 192 && b[1] == 168)
                   || (b[0] == 100 && (b[1] & 0xC0) == 64);
        return b.Length == 16 && ((b[0] & 0xFE) == 0xFC || (b[0] == 0xFE && (b[1] & 0xC0) == 0xC0));
    }

    // Every unicast address of every interface on this device (up or down — LAN, VPN, Docker, WSL, IPv6),
    // for Dial. Reading the interfaces takes milliseconds and Dial asks on every connection, so the set is
    // cached and rebuilt only after the OS reports an address change, or once it is StaleMs old (the only
    // refresh where change events aren't available). A failed rebuild keeps the last good set: a hiccup
    // reading interfaces must never break proxying — loopback / link-local are refused without it anyway.
    private sealed class OwnAddresses
    {
        private const long StaleMs = 30_000;

        // Changes = the _changes count the enumeration started under. Keys / Prefixes are never mutated once published.
        // Prefixes: each address's subnet prefix length, counted on the 128-bit key (an IPv4 /24 is 120).
        private sealed record Snapshot(HashSet<UInt128> Keys, Dictionary<UInt128, int> Prefixes, long Stamp, int Changes);

        private readonly object _gate = new();
        private volatile Snapshot? _snap;   // null until the first build
        // Bumped by every address-change event. A count, not a 'dirty' flag: a snapshot stays stale until one
        // built after the latest change is published, so lookups meanwhile queue behind that rebuild instead
        // of passing on the old set (clearing a flag at the start of the rebuild left exactly that window).
        private int _changes;
        private bool _watching;             // Start/Stop only

        /// <summary>How many address changes the system has reported (the outgoing interface is read again after one).</summary>
        public int Changes => Volatile.Read(ref _changes);

        public void Watch()
        {
            Interlocked.Increment(ref _changes);   // addresses may have changed while the server was stopped
            if (!_watching)
            {
                // Change events aren't available everywhere (Android 11+ apps may not bind the netlink socket
                // they need, so subscribing throws there) — the StaleMs re-read then keeps the set current alone.
                try { NetworkChange.NetworkAddressChanged += OnAddressChanged; _watching = true; }
                catch { }
            }
            _ = Task.Run(Current);   // build it now rather than inside the first client's dial
        }

        public void Unwatch()
        {
            if (!_watching) return;
            _watching = false;
            try { NetworkChange.NetworkAddressChanged -= OnAddressChanged; } catch { }
        }

        // Raised on a framework thread, often in bursts: only count it — the next lookup rebuilds once.
        private void OnAddressChanged(object? sender, EventArgs e) => Interlocked.Increment(ref _changes);

        // 'entry' = the address the client reached us on: ours by definition, so it is refused even before
        // the first build or in the window between an address change and the rebuild that picks it up.
        public bool Contains(IPAddress a, IPAddress? entry)
            => TryKey(a, out var k) && ((entry is not null && TryKey(entry, out var e) && e == k) || Current().Keys.Contains(k));

        // Is 'a' on the subnet of 'entry' (the address of ours the client reached us on, so the client's own network)?
        // An unknown prefix counts as a /24 (IPv4) or /64 (IPv6), the usual home / office subnet.
        public bool SameSubnet(IPAddress a, IPAddress? entry)
        {
            if (entry is null || !TryKey(a, out var k) || !TryKey(entry, out var e)) return false;
            bool v4 = (e >> 32) == 0xFFFF;   // IPv4-mapped: ::ffff:a.b.c.d
            int prefix = Current().Prefixes.TryGetValue(e, out int p) && p > 0 ? p : v4 ? 120 : 64;
            int shift = 128 - Math.Clamp(prefix, 1, 128);
            return (k >> shift) == (e >> shift);
        }

        // Is 'a' on the subnet of one of this device's interfaces OTHER than the entry one (another LAN, a corporate
        // network on a second adapter, the LAN's global IPv6 /64)? Those are reached only through this device, whatever
        // their address range. Not 198.18/15 (TUN-mode VPN fake-ip, see IsPrivateTarget), and prefixes shorter than
        // /8 (IPv4) or /32 (IPv6) aren't taken as a subnet: a VPN adapter reporting one would swallow the internet.
        public bool OnOtherLink(IPAddress a, IPAddress? entry)
        {
            if (!TryKey(a, out var k) || (k >> 17) == (new UInt128(0, 0xFFFF_C612_0000UL) >> 17)) return false;   // 198.18.0.0/15
            UInt128 e = default;
            bool hasEntry = entry is not null && TryKey(entry, out e);
            foreach (var (own, prefix) in Current().Prefixes)
            {
                bool v4 = (own >> 32) == 0xFFFF;
                if (prefix < (v4 ? 104 : 32) || prefix >= 128) continue;
                int shift = 128 - prefix;
                if ((k >> shift) != (own >> shift)) continue;
                if (hasEntry && (e >> shift) == (own >> shift)) continue;   // the entry interface's subnet: SameSubnet's call
                return true;
            }
            return false;
        }

        private bool IsStale([NotNullWhen(false)] Snapshot? s)
            => s is null || s.Changes != Volatile.Read(ref _changes) || Environment.TickCount64 - s.Stamp >= StaleMs;

        private Snapshot Current()
        {
            var snap = _snap;
            if (IsStale(snap))
            {
                lock (_gate)   // one rebuild at a time; callers queued behind it take its result
                {
                    snap = _snap;
                    if (IsStale(snap))
                    {
                        int changes = Volatile.Read(ref _changes);   // before enumerating: a change during it re-stales the result
                        var built = Enumerate();
                        snap = new Snapshot(built?.Keys ?? snap?.Keys ?? new HashSet<UInt128>(),
                                            built?.Prefixes ?? snap?.Prefixes ?? new Dictionary<UInt128, int>(),
                                            Environment.TickCount64, changes);
                        _snap = snap;
                    }
                }
            }
            return snap;
        }

        // null when the interfaces can't be read. An empty list counts as that too: even loopback is missing.
        private static (HashSet<UInt128> Keys, Dictionary<UInt128, int> Prefixes)? Enumerate()
        {
            try
            {
                var keys = new HashSet<UInt128>();
                var prefixes = new Dictionary<UInt128, int>();
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    try
                    {
                        foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                        {
                            if (!TryKey(ua.Address, out var k)) continue;
                            keys.Add(k);
                            try
                            {
                                int len = ua.PrefixLength;
                                if (len > 0) prefixes[k] = ua.Address.AddressFamily == AddressFamily.InterNetwork ? len + 96 : len;
                            }
                            catch { /* prefix not reported here: SameSubnet assumes the usual size */ }
                        }
                    }
                    catch { /* one unreadable interface mustn't hide the others */ }
                }
                return keys.Count > 0 ? (keys, prefixes) : null;
            }
            catch { return null; }
        }

        // An address as its raw 128 bits: IPv4 in IPv4-mapped form, so a.b.c.d and ::ffff:a.b.c.d are one
        // key, and no scope id (it isn't part of the address bytes), so fe80::1%3 and fe80::1%7 match.
        private static bool TryKey(IPAddress a, out UInt128 key)
        {
            Span<byte> b = stackalloc byte[16];
            key = default;
            if (!a.TryWriteBytes(b, out int n)) return false;
            if (n == 4) key = new UInt128(0, 0xFFFF_0000_0000UL | BinaryPrimitives.ReadUInt32BigEndian(b));
            else if (n == 16) key = new UInt128(BinaryPrimitives.ReadUInt64BigEndian(b), BinaryPrimitives.ReadUInt64BigEndian(b[8..]));
            else return false;
            return true;
        }
    }

    private async Task Relay(NetworkStream a, Remote b, CancellationToken ct)
    {
        // ONE idle timer for the whole tunnel, re-armed by traffic in either direction — a per-direction
        // timer would kill a long one-way transfer (a download while the client sends nothing).
        using var idle = CancellationTokenSource.CreateLinkedTokenSource(ct);
        idle.CancelAfter(_idleMs);
        var up = Pump(a, b.Stream, b.Socket, true, idle);
        var down = Pump(b.Stream, a, a.Socket, false, idle);
        var first = await Task.WhenAny(up, down).ConfigureAwait(false);
        // One side half-closed (a client after its request: nc -N, shutdown(SHUT_WR); a server after its banner or
        // answer while it still reads): Pump has passed the FIN on, so let the other direction finish too, until that
        // side closes or the tunnel idles out, instead of dropping what it still sends.
        if (await first.ConfigureAwait(false)) await (first == up ? down : up).ConfigureAwait(false);
        // The disposing 'using' on both endpoints unblocks whichever pump is still reading.
    }

    // Copies src → dst until EOF, then passes the half-close on (dstSocket: the socket under dst; over TLS the close is
    // said in TLS first, close_notify, so the other end reads an end and not a cut, except on Apple's systems, see
    // TlsCloseEndsReading). Traffic re-arms the shared idle timer
    // (at most once a second: a fast download is thousands of reads a second). True = clean EOF from src; false = reset /
    // idle timeout / stop. The copy buffer is pooled and given back while the tunnel waits for data (a zero-byte read,
    // which TLS passes down to the socket too), so the dozens of idle keep-alive tunnels a browser holds open cost no buffers.
    private async Task<bool> Pump(Stream src, Stream dst, Socket dstSocket, bool up, CancellationTokenSource idle)
    {
        var tok = idle.Token;
        var limit = up ? _upLimit : _downLimit;
        byte[]? buf = ArrayPool<byte>.Shared.Rent(RelayBuffer);
        long armed = Environment.TickCount64;
        bool clean = false;
        try
        {
            while (true)
            {
                var wait = src.ReadAsync(Memory<byte>.Empty, tok);
                if (wait.IsCompletedSuccessfully) _ = wait.Result;
                else
                {
                    var giveBack = buf;
                    buf = null;   // never returned twice when the wait throws
                    ArrayPool<byte>.Shared.Return(giveBack);
                    await wait.ConfigureAwait(false);
                    buf = ArrayPool<byte>.Shared.Rent(RelayBuffer);
                }
                int n = await src.ReadAsync(limit is null ? buf.AsMemory() : buf.AsMemory(0, limit.Chunk), tok).ConfigureAwait(false);
                if (n == 0) break;
                long now = Environment.TickCount64;
                if (now - armed >= 1000)
                {
                    armed = now;
                    idle.CancelAfter(_idleMs);
                }
                // (a wait moves the idle deadline: it is set again from the next read)
                if (limit is not null && await PaceAsync(limit, n, idle).ConfigureAwait(false)) armed = 0;
                await dst.WriteAsync(buf.AsMemory(0, n), tok).ConfigureAwait(false);
                if (up) Interlocked.Add(ref _bytesUp, n); else Interlocked.Add(ref _bytesDown, n);
            }
            clean = true;
        }
        catch { /* peer closed / reset / idle — normal end of a tunnel */ }
        finally
        {
            if (buf is not null) ArrayPool<byte>.Shared.Return(buf);
        }
        if (dst is SslStream tls && !TlsCloseEndsReading)
        {
            try { await tls.ShutdownAsync().WaitAsync(tok).ConfigureAwait(false); }
            catch { /* the tunnel is ending anyway */ }
        }
        try { dstSocket.Shutdown(SocketShutdown.Send); } catch { }
        return clean;
    }

    // Apple's TLS (SecureTransport, under SslStream on macOS / iOS) ends the whole session when it sends close_notify:
    // every read after it returns "end" at once, so the answer to a client's half-close through an https:// upstream was
    // lost there. On those systems the half-close goes on as the FIN alone. The upstream still reads it as the end of what
    // was sent (at a record boundary, which a Pump always stops on) and its answer still comes back.
    private static readonly bool TlsCloseEndsReading = OperatingSystem.IsMacOS() || OperatingSystem.IsIOS() || OperatingSystem.IsTvOS();

    private const int RelayBuffer = 64 * 1024;

    private static async Task ReadExact(NetworkStream s, byte[] buf, int n, CancellationToken ct)
    {
        int off = 0;
        while (off < n)
        {
            int r = await s.ReadAsync(buf.AsMemory(off, n - off), ct).ConfigureAwait(false);
            if (r == 0) throw new IOException("unexpected end of stream");
            off += r;
        }
    }

    private static Task WriteAscii(NetworkStream s, string text, CancellationToken ct)
        => s.WriteAsync(Encoding.ASCII.GetBytes(text), ct).AsTask();

    // An error reply, then close. A plain close with the client's request still unread (a POST body, the rest of an
    // oversized head) makes the stack send RST, and the client drops the reply with it. So half-close and read off
    // what is left first: at most 64 KB / 1 s, also on the caller's token, so it can't hold the slot for long.
    private static Task ReplyAndClose(NetworkStream s, string reply, CancellationToken ct)
        => ReplyAndClose(s, Encoding.ASCII.GetBytes(reply), ct);

    private static async Task ReplyAndClose(NetworkStream s, byte[] reply, CancellationToken ct)
    {
        await s.WriteAsync(reply, ct).ConfigureAwait(false);
        try
        {
            s.Socket.Shutdown(SocketShutdown.Send);
            using var drain = CancellationTokenSource.CreateLinkedTokenSource(ct);
            drain.CancelAfter(1000);
            var buf = new byte[8192];
            for (int total = 0, n; total < 64 * 1024 && (n = await s.ReadAsync(buf, drain.Token).ConfigureAwait(false)) > 0; total += n) { }
        }
        catch { /* drained, timed out, or the client is gone */ }
    }

    private static string FormatTarget(string host, int port)
        => host.Contains(':') ? $"[{host}]:{port}" : $"{host}:{port}";

    private void Log(string client, string proto, string target, string user, bool ok, string status, string detail = "")
        => _onConn?.Invoke(new ProxyLogEntry
        {
            Time = DateTime.Now.ToString("HH:mm:ss"),
            Client = client,
            Proto = proto,
            Target = Clean(UrlSecrets.Redact(WithoutUserInfo(target))),
            User = string.IsNullOrEmpty(user) ? "—" : Clean(user),
            Ok = ok,
            Status = status,
            Detail = detail,
        });

    // "http://user:pass@host/…" → "http://host/…": a URL's own credentials never reach the log (UrlSecrets.Redact
    // then empties secret-looking query values).
    private static string WithoutUserInfo(string s)
    {
        int start = s.IndexOf("://", StringComparison.Ordinal);
        start = start < 0 ? 0 : start + 3;
        int end = s.IndexOfAny(['/', '?', '#'], start);
        int at = s.AsSpan(start, (end < 0 ? s.Length : end) - start).LastIndexOf('@');
        return at < 0 ? s : string.Concat(s.AsSpan(0, start), s.AsSpan(start + at + 1));
    }

    // Target and user name come straight from the client: control characters and line / paragraph separators
    // (a fake second row inside one log row), bidi overrides / isolates (text that reads differently from what was
    // sent) become '?', and a 30 KB target is cut to a log-sized string.
    private static string Clean(string s)
    {
        const int Max = 200;
        var sb = new StringBuilder(Math.Min(s.Length, Max + 1));
        foreach (char c in s)
        {
            if (sb.Length >= Max) { sb.Append('…'); break; }
            sb.Append(char.IsControl(c) || c is >= (char)0x2028 and <= (char)0x202E || c is >= (char)0x2066 and <= (char)0x2069 ? '?' : c);
        }
        return sb.ToString();
    }

    // Buffered reader for the HTTP side (client request, origin response): heads, chunk-size lines and
    // body bytes, keeping whatever was read past the part asked for instead of losing it.
    private sealed class HttpReader
    {
        private readonly Stream _s;
        private byte[] _buf = new byte[8192];
        private int _pos, _len;   // unread bytes are _buf[_pos.._len)

        public HttpReader(Stream s) => _s = s;
        public HttpReader(Stream s, byte first) : this(s) => _buf[_len++] = first;

        // Through the blank line that ends a head (returned Latin-1, terminator included). null on EOF
        // first, or with tooLarge once 'max' bytes hold no end; either way the bytes stay buffered.
        public async Task<(string? head, bool tooLarge)> ReadHeadAsync(int max, CancellationToken ct)
        {
            int scanned = 0;   // bytes past _pos already searched
            while (true)
            {
                int i = _buf.AsSpan(_pos + scanned, _len - _pos - scanned).IndexOf("\r\n\r\n"u8);
                if (i >= 0)
                {
                    int end = _pos + scanned + i + 4;
                    string head = Encoding.Latin1.GetString(_buf, _pos, end - _pos);
                    _pos = end;
                    return (head, false);
                }
                if (_len - _pos >= max) return (null, true);
                scanned = Math.Max(0, _len - _pos - 3);
                if (await FillAsync(ct).ConfigureAwait(false) == 0) return (null, false);
            }
        }

        // One CRLF-terminated line, returned without it; null on EOF or past 'max'.
        public async Task<string?> ReadLineAsync(int max, CancellationToken ct)
        {
            int scanned = 0;
            while (true)
            {
                int i = _buf.AsSpan(_pos + scanned, _len - _pos - scanned).IndexOf("\r\n"u8);
                if (i >= 0)
                {
                    int end = _pos + scanned + i;
                    string line = Encoding.Latin1.GetString(_buf, _pos, end - _pos);
                    _pos = end + 2;
                    return line;
                }
                if (_len - _pos >= max) return null;
                scanned = Math.Max(0, _len - _pos - 1);
                if (await FillAsync(ct).ConfigureAwait(false) == 0) return null;
            }
        }

        // Up to 'max' bytes — buffered ones first, else one read. Empty = EOF. Valid until the next call.
        public async ValueTask<ReadOnlyMemory<byte>> ReadSomeAsync(int max, CancellationToken ct)
        {
            if (_pos == _len && await FillAsync(ct).ConfigureAwait(false) == 0) return ReadOnlyMemory<byte>.Empty;
            int n = Math.Min(max, _len - _pos);
            var m = new ReadOnlyMemory<byte>(_buf, _pos, n);
            _pos += n;
            return m;
        }

        // Everything buffered but not yet consumed.
        public ReadOnlyMemory<byte> TakeBuffered()
        {
            var m = new ReadOnlyMemory<byte>(_buf, _pos, _len - _pos);
            _pos = _len;
            return m;
        }

        private async ValueTask<int> FillAsync(CancellationToken ct)
        {
            if (_pos == _len) _pos = _len = 0;
            else if (_len == _buf.Length)
            {
                if (_pos > 0) { Buffer.BlockCopy(_buf, _pos, _buf, 0, _len - _pos); _len -= _pos; _pos = 0; }
                else Array.Resize(ref _buf, _buf.Length * 2);
            }
            int n = await _s.ReadAsync(_buf.AsMemory(_len), ct).ConfigureAwait(false);
            _len += n;
            return n;
        }
    }
}
