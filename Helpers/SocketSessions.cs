using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>
/// Where a socket session reports what happens. Called on socket threads; the Socket tool's view-model only queues
/// these and drains the queue on a UI timer, so a flood never posts one UI job per packet.
/// </summary>
public interface ISocketSink
{
    /// <summary>Bytes received. <paramref name="peer"/> is null for the client modes (one remote).</summary>
    void OnReceived(SocketPeer? peer, byte[] data);
    void OnInfo(string text);
    void OnError(string text);
    void OnPeerJoined(SocketPeer peer);
    /// <summary>A TCP client left / a UDP sender dropped off the list; <paramref name="reason"/> null = say nothing.</summary>
    void OnPeerLeft(SocketPeer peer, string? reason);
    /// <summary>The session is over on its own (remote closed, network error) — not when the user stopped it.</summary>
    void OnEnded(string reason, bool isError);
}

/// <summary>A failure already worded for the user (see <see cref="SocketErrors"/>).</summary>
public sealed class SocketFailure : Exception
{
    public SocketFailure(string message, Exception? inner = null) : base(message, inner) { }

    /// <summary>SHA-256 of the server certificate when the TLS certificate was the problem (for "connect anyway").</summary>
    public string? CertSha256 { get; init; }
    public IReadOnlyList<TlsProblem>? CertProblems { get; init; }
}

/// <summary>A TCP client of the server mode, or a UDP sender seen by the UDP server.</summary>
public sealed class SocketPeer
{
    private static int s_nextId;

    internal SocketPeer(IPEndPoint endPoint)
    {
        EndPoint = endPoint;
        Label = SocketNet.Label(endPoint);
        LastSeen = Since;
    }

    public int Id { get; } = Interlocked.Increment(ref s_nextId);
    public IPEndPoint EndPoint { get; }
    /// <summary>"10.0.0.5:51234" / "[fe80::1]:5000" (IPv4-mapped addresses shown as IPv4).</summary>
    public string Label { get; }
    public DateTime Since { get; } = DateTime.Now;
    public DateTime LastSeen { get; internal set; }

    internal long BytesInRaw, BytesOutRaw;
    public long BytesIn => Interlocked.Read(ref BytesInRaw);
    public long BytesOut => Interlocked.Read(ref BytesOutRaw);

    // TCP
    internal Socket? Socket;
    internal Stream? Stream;
    internal readonly SemaphoreSlim WriteLock = new(1, 1);
    internal readonly CancellationTokenSource Cts = new();
    internal volatile bool KickedByUser;
    internal int Closed;
    // UDP: the address exactly as received (may be IPv4-mapped on a dual-stack socket)
    internal IPEndPoint? SendEndPoint;

    public bool IsOpen => Volatile.Read(ref Closed) == 0;
}

public sealed class TcpConnectOptions
{
    public bool UseTls { get; init; }
    /// <summary>Accept exactly this certificate (SHA-256 hex) although it failed validation — the user chose "connect anyway".</summary>
    public string? AcceptCertSha256 { get; init; }
    public int TimeoutMs { get; init; } = 10_000;
}

/// <summary>Resolution, binding and labels shared by the sessions (and the TLS inspector).</summary>
public static class SocketNet
{
    /// <summary>"host:port", IPv6 literals bracketed.</summary>
    public static string Target(string host, int port)
        => host.Contains(':') && !host.StartsWith('[') ? $"[{host}]:{port}" : $"{host}:{port}";

    public static IPEndPoint Normalize(IPEndPoint ep)
        => ep.Address.IsIPv4MappedToIPv6 ? new IPEndPoint(ep.Address.MapToIPv4(), ep.Port) : ep;

    public static string Label(IPEndPoint ep)
    {
        var n = Normalize(ep);
        string port = n.Port.ToString(CultureInfo.InvariantCulture);
        return n.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{n.Address}]:{port}" : $"{n.Address}:{port}";
    }

    /// <summary>The ASCII (punycode) form of an internationalized host name; anything else unchanged.</summary>
    public static string AsciiHost(string host)
    {
        foreach (char c in host)
        {
            if (c > 0x7F)
            {
                try { return new IdnMapping().GetAscii(host); } catch { return host; }
            }
        }
        return host;
    }

    /// <summary>Addresses for a host or IP literal. Throws <see cref="SocketException"/> (HostNotFound) when none.</summary>
    public static async Task<IPAddress[]> ResolveAsync(string host, CancellationToken ct)
    {
        string h = host.Trim().Trim('[', ']');
        if (IPAddress.TryParse(h, out var ip)) return new[] { ip };
        var list = await Dns.GetHostAddressesAsync(AsciiHost(h), ct).ConfigureAwait(false);
        if (list.Length == 0) throw new SocketException((int)SocketError.HostNotFound);
        return list;
    }

    /// <summary>
    /// A socket bound to <paramref name="bind"/>:<paramref name="port"/>. <see cref="IPAddress.IPv6Any"/> means "all
    /// interfaces": one dual-stack socket for IPv6 + IPv4, or plain IPv4 where the system has no IPv6.
    /// </summary>
    public static Socket Bind(IPAddress bind, int port, SocketType type, ProtocolType proto)
    {
        if (bind.Equals(IPAddress.IPv6Any))
        {
            Socket? s6 = null;
            try
            {
                s6 = new Socket(AddressFamily.InterNetworkV6, type, proto) { DualMode = true };
                Prepare(s6, type);
                s6.Bind(new IPEndPoint(IPAddress.IPv6Any, port));
                return s6;
            }
            catch (SocketException e) when (e.SocketErrorCode is SocketError.AddressFamilyNotSupported
                                             or SocketError.ProtocolFamilyNotSupported or SocketError.AddressNotAvailable)
            {
                s6?.Dispose();
                bind = IPAddress.Any;
            }
            catch
            {
                s6?.Dispose();
                throw;
            }
        }
        var s = new Socket(bind.AddressFamily, type, proto);
        try
        {
            Prepare(s, type);
            s.Bind(new IPEndPoint(bind, port));
            return s;
        }
        catch
        {
            s.Dispose();
            throw;
        }
    }

    private static void Prepare(Socket s, SocketType type)
    {
        // Windows reports an ICMP "port unreachable" for an EARLIER datagram as a reset on the next receive of an
        // unconnected UDP socket, which would kill the server's receive loop for one gone client: switch that off.
        if (type == SocketType.Dgram && OperatingSystem.IsWindows())
        {
            try
            {
                const int SIO_UDP_CONNRESET = unchecked((int)0x9800000C);
                s.IOControl(SIO_UDP_CONNRESET, new byte[] { 0, 0, 0, 0 }, null);
            }
            catch { /* not supported: the receive loop tolerates resets anyway */ }
        }
    }

    /// <summary>
    /// TCP connect with a time budget over every address of the host, "happy eyeballs" style: the next address is
    /// tried 250 ms after the previous one started (or at once when it failed), and the first to connect wins. So an
    /// IPv6 address that hangs — or a refused one, which Windows retries for ~2 s — never delays a working IPv4 one.
    /// Throws <see cref="SocketFailure"/> worded for the user.
    /// </summary>
    public static async Task<Socket> ConnectTcpAsync(string host, int port, int timeoutMs, CancellationToken ct)
        => (await ConnectTcpTimedAsync(host, port, timeoutMs, ct).ConfigureAwait(false)).Socket;

    /// <summary>
    /// <see cref="ConnectTcpAsync"/>, plus how long the winning address's own TCP handshake took (not counting DNS or
    /// the wait for a slower address tried before it) — the TLS inspector's "connect" time.
    /// </summary>
    public static async Task<(Socket Socket, double ConnectMs)> ConnectTcpTimedAsync(string host, int port, int timeoutMs, CancellationToken ct)
    {
        string target = Target(host, port);
        IPAddress[] addrs;
        using (var rcts = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            rcts.CancelAfter(timeoutMs);
            try { addrs = await ResolveAsync(host, rcts.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            { throw new SocketFailure(SocketErrors.Describe(new TimeoutException(), SocketAction.Resolve, target, port)); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { throw new SocketFailure(SocketErrors.Describe(ex, SocketAction.Resolve, target, port), ex); }
        }

        using var all = CancellationTokenSource.CreateLinkedTokenSource(ct);
        all.CancelAfter(timeoutMs);
        var pending = new List<Task<(Socket Socket, double Ms)>>();
        int next = 0;
        Exception? best = null;
        try
        {
            while (true)
            {
                if (next < addrs.Length) pending.Add(AttemptAsync(addrs[next++], port, all.Token));
                var waitOn = new List<Task>(pending);
                Task? stagger = next < addrs.Length ? Task.Delay(250, all.Token) : null;
                if (stagger != null) waitOn.Add(stagger);
                if (waitOn.Count == 0) break;

                var done = await Task.WhenAny(waitOn).ConfigureAwait(false);
                if (done == stagger) continue;   // start the next address alongside
                var attempt = (Task<(Socket Socket, double Ms)>)done;
                pending.Remove(attempt);
                if (attempt.Status == TaskStatus.RanToCompletion) return attempt.Result;

                var ex = attempt.Exception?.InnerException;
                if (ex is OperationCanceledException)
                {
                    if (ct.IsCancellationRequested) throw new OperationCanceledException(ct);
                    best ??= new TimeoutException();
                }
                // keep the most telling error: a refusal beats an unreachable IPv6 address tried first
                else if (ex != null && best is not SocketException { SocketErrorCode: SocketError.ConnectionRefused }) best = ex;
                if (pending.Count == 0 && next >= addrs.Length) break;
            }
        }
        finally
        {
            all.Cancel();   // losers stop (each disposes its own socket)
            // one that connected in the same instant is closed; failures are observed (no unobserved-task noise)
            foreach (var p in pending)
                _ = p.ContinueWith(static t =>
                {
                    if (t.Status == TaskStatus.RanToCompletion) t.Result.Socket.Dispose();
                    else _ = t.Exception;
                }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }
        throw new SocketFailure(SocketErrors.Describe(best ?? new SocketException((int)SocketError.HostNotFound), SocketAction.Connect, target, port), best);
    }

    private static async Task<(Socket Socket, double Ms)> AttemptAsync(IPAddress addr, int port, CancellationToken token)
    {
        var s = new Socket(addr.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            var sw = Stopwatch.StartNew();
            await s.ConnectAsync(new IPEndPoint(addr, port), token).ConfigureAwait(false);
            double ms = sw.Elapsed.TotalMilliseconds;
            if (token.IsCancellationRequested) { s.Dispose(); token.ThrowIfCancellationRequested(); }
            return (s, ms);
        }
        catch
        {
            s.Dispose();
            throw;
        }
    }
}

/// <summary>TCP client: one connection, optionally wrapped in TLS (certificate problems are reported, never silently accepted).</summary>
public sealed class TcpClientSession : IDisposable
{
    private readonly Socket _socket;
    private readonly Stream _stream;
    private readonly ISocketSink _sink;
    private readonly CancellationTokenSource _cts = new();
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private int _closed;
    private long _in, _out;

    private TcpClientSession(Socket socket, Stream stream, ISocketSink sink, string target)
    {
        _socket = socket;
        _stream = stream;
        _sink = sink;
        Target = target;
        Remote = SocketNet.Normalize((IPEndPoint)socket.RemoteEndPoint!);
        Local = SocketNet.Normalize((IPEndPoint)socket.LocalEndPoint!);
    }

    public string Target { get; }
    public IPEndPoint Remote { get; }
    public IPEndPoint Local { get; }
    /// <summary>"TLS 1.3 · TLS_AES_256_GCM_SHA384" when TLS is on.</summary>
    public string? TlsDescription { get; private set; }
    /// <summary>The certificate failed validation and the user chose to continue.</summary>
    public bool CertificateOverridden { get; private set; }
    public long BytesIn => Interlocked.Read(ref _in);
    public long BytesOut => Interlocked.Read(ref _out);

    public static async Task<TcpClientSession> ConnectAsync(string host, int port, TcpConnectOptions opts, ISocketSink sink, CancellationToken ct)
    {
        string target = SocketNet.Target(host, port);
        var socket = await SocketNet.ConnectTcpAsync(host, port, opts.TimeoutMs, ct).ConfigureAwait(false);
        Stream stream = new NetworkStream(socket, ownsSocket: true);
        if (!opts.UseTls) return new TcpClientSession(socket, stream, sink, target);

        string tlsHost = SocketNet.AsciiHost(host.Trim('[', ']'));
        List<TlsProblem>? problems = null;
        string? sha = null;
        bool overridden = false;
        var ssl = new SslStream(stream, leaveInnerStreamOpen: false, (_, cert, chain, errors) =>
        {
            if (errors == SslPolicyErrors.None) return true;
            try
            {
                sha = cert != null ? TlsCertificates.Sha256Hex(cert) : null;
                if (sha != null && string.Equals(sha, opts.AcceptCertSha256, StringComparison.OrdinalIgnoreCase))
                {
                    overridden = true;   // exactly the certificate the user saw and accepted
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
            hs.CancelAfter(opts.TimeoutMs);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = tlsHost,
                EnabledSslProtocols = SslProtocols.None,   // what this system allows
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            }, hs.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            ssl.Dispose();
            if (problems != null)
                throw new SocketFailure("Certificate not trusted: " + TlsCertificates.Summary(problems), ex) { CertSha256 = sha, CertProblems = problems };
            if (ex is OperationCanceledException && ct.IsCancellationRequested) throw;
            throw new SocketFailure(SocketErrors.Describe(ex, SocketAction.Tls, target, port), ex);
        }

        var session = new TcpClientSession(socket, ssl, sink, target) { CertificateOverridden = overridden };
        string cipher = "";
        try { cipher = ssl.NegotiatedCipherSuite.ToString(); } catch { /* not reported on this platform */ }
        session.TlsDescription = TlsCertificates.ProtocolName(ssl.SslProtocol) + (cipher.Length > 0 ? " · " + cipher : "");
        return session;
    }

    /// <summary>Starts reading. Separate from connecting, so the caller can log "connected" before any data.</summary>
    public void Start() => _ = Task.Run(ReadLoopAsync);

    private async Task ReadLoopAsync()
    {
        var buf = new byte[32 * 1024];
        string reason;
        bool error = false;
        try
        {
            while (true)
            {
                int n = await _stream.ReadAsync(buf, _cts.Token).ConfigureAwait(false);
                if (n == 0) { reason = "The remote side closed the connection."; break; }
                Interlocked.Add(ref _in, n);
                _sink.OnReceived(null, buf.AsSpan(0, n).ToArray());
            }
        }
        catch (Exception ex)
        {
            if (Volatile.Read(ref _closed) != 0) return;   // closed by the user
            reason = "Connection lost: " + SocketErrors.Describe(ex, SocketAction.Receive, Target);
            error = true;
        }
        if (Interlocked.Exchange(ref _closed, 1) != 0) return;
        Teardown();
        _sink.OnEnded(reason, error);
    }

    public async Task SendAsync(byte[] data)
    {
        if (Volatile.Read(ref _closed) != 0) { _sink.OnError("Not connected."); return; }
        await _writeLock.WaitAsync().ConfigureAwait(false);
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
            cts.CancelAfter(30_000);
            await _stream.WriteAsync(data, cts.Token).ConfigureAwait(false);
            await _stream.FlushAsync(cts.Token).ConfigureAwait(false);
            Interlocked.Add(ref _out, data.Length);
        }
        catch (OperationCanceledException) when (!_cts.IsCancellationRequested)
        {
            _sink.OnError("Send timed out — the other side isn't reading (its receive buffer is full).");
        }
        catch (Exception ex) when (Volatile.Read(ref _closed) == 0)
        {
            _sink.OnError("Send failed: " + SocketErrors.Describe(ex, SocketAction.Send, Target));
        }
        catch { /* closed meanwhile */ }
        finally { _writeLock.Release(); }
    }

    /// <summary>Closes the connection (no <see cref="ISocketSink.OnEnded"/> — the user did it).</summary>
    public void Close()
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0) return;
        Teardown();
    }

    private void Teardown()
    {
        try { _cts.Cancel(); } catch { }
        try { _socket.Shutdown(SocketShutdown.Both); } catch { }
        try { _stream.Dispose(); } catch { }
        try { _socket.Dispose(); } catch { }
    }

    public void Dispose() => Close();
}

/// <summary>TCP server: listens, accepts up to <see cref="MaxClients"/> clients, sends to one or all, disconnects one.</summary>
public sealed class TcpServerSession : IDisposable
{
    public const int MaxClients = 64;

    private readonly Socket _listener;
    private readonly ISocketSink _sink;
    private readonly CancellationTokenSource _cts = new();
    private readonly ConcurrentDictionary<int, SocketPeer> _peers = new();
    private int _stopped;

    private TcpServerSession(Socket listener, ISocketSink sink)
    {
        _listener = listener;
        _sink = sink;
        LocalEndPoint = (IPEndPoint)listener.LocalEndPoint!;
    }

    public IPEndPoint LocalEndPoint { get; }
    public int ClientCount => _peers.Count;
    public IReadOnlyCollection<SocketPeer> Clients => _peers.Values.ToArray();

    /// <summary>Binds and listens (throws <see cref="SocketException"/>: in use, access denied …). Call <see cref="Start"/> to accept.</summary>
    public static TcpServerSession Listen(IPAddress bind, int port, ISocketSink sink)
    {
        var s = SocketNet.Bind(bind, port, SocketType.Stream, ProtocolType.Tcp);
        try { s.Listen(128); }
        catch { s.Dispose(); throw; }
        return new TcpServerSession(s, sink);
    }

    public void Start() => _ = Task.Run(AcceptLoopAsync);

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            Socket client;
            try
            {
                client = await _listener.AcceptAsync(_cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { return; }
            catch (ObjectDisposedException) { return; }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionAborted
                                             or SocketError.Interrupted)
            {
                continue;   // a client gave up before it was accepted
            }
            catch (Exception ex)
            {
                if (Interlocked.Exchange(ref _stopped, 1) != 0) return;
                TeardownAll();
                _sink.OnEnded("Stopped listening: " + SocketErrors.Describe(ex, SocketAction.Listen, SocketNet.Label(LocalEndPoint), LocalEndPoint.Port), true);
                return;
            }

            IPEndPoint ep;
            try { ep = SocketNet.Normalize((IPEndPoint)client.RemoteEndPoint!); }
            catch { try { client.Dispose(); } catch { } continue; }   // already gone

            if (_peers.Count >= MaxClients)
            {
                try { client.Dispose(); } catch { }
                NoteTurnedAway(ep);
                continue;
            }
            client.NoDelay = true;
            var peer = new SocketPeer(ep) { Socket = client, Stream = new NetworkStream(client, ownsSocket: true) };
            _peers[peer.Id] = peer;
            _sink.OnPeerJoined(peer);
            _ = Task.Run(() => PeerLoopAsync(peer));
        }
    }

    // A host hammering a full server must not queue one transcript line per refused attempt (thousands a second, each
    // one a UI event): the first refusal is reported at once, later ones are counted and summed up in one line every
    // TurnedAwayNoteMs for as long as they keep coming.
    private const int TurnedAwayNoteMs = 2000;
    private int _turnedAway;        // refused since the last line
    private int _turnedAwayArmed;   // 1 while the summary task runs

    private void NoteTurnedAway(IPEndPoint ep)
    {
        if (Interlocked.CompareExchange(ref _turnedAwayArmed, 1, 0) != 0)
        {
            Interlocked.Increment(ref _turnedAway);
            return;
        }
        _sink.OnInfo($"Turned away {SocketNet.Label(ep)} — {MaxClients} clients are already connected.");
        _ = Task.Run(async () =>
        {
            while (true)
            {
                try { await Task.Delay(TurnedAwayNoteMs, _cts.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }   // stopped: nothing more to report
                int n = Interlocked.Exchange(ref _turnedAway, 0);
                if (n == 0) { Volatile.Write(ref _turnedAwayArmed, 0); return; }
                _sink.OnInfo($"Turned away {n} more connection{(n == 1 ? "" : "s")} — {MaxClients} clients are already connected.");
            }
        });
    }

    private async Task PeerLoopAsync(SocketPeer peer)
    {
        var buf = new byte[32 * 1024];
        string reason;
        try
        {
            while (true)
            {
                int n = await peer.Stream!.ReadAsync(buf, peer.Cts.Token).ConfigureAwait(false);
                if (n == 0) { reason = peer.KickedByUser ? "was disconnected" : "closed the connection"; break; }
                Interlocked.Add(ref peer.BytesInRaw, n);
                peer.LastSeen = DateTime.Now;
                _sink.OnReceived(peer, buf.AsSpan(0, n).ToArray());
            }
        }
        catch (Exception ex)
        {
            if (_cts.IsCancellationRequested) { ClosePeer(peer); return; }   // the server is stopping: one summary line, not one per client
            reason = peer.KickedByUser ? "was disconnected" : "dropped — " + SocketErrors.Describe(ex, SocketAction.Receive, peer.Label);
        }
        ClosePeer(peer);
        if (!_cts.IsCancellationRequested) _sink.OnPeerLeft(peer, reason);
    }

    /// <summary>Sends to one client, or to every connected client when <paramref name="target"/> is null.</summary>
    public async Task SendAsync(SocketPeer? target, byte[] data)
    {
        var peers = target != null ? new[] { target } : _peers.Values.ToArray();
        if (peers.Length == 0) { _sink.OnError("No clients are connected."); return; }
        await Task.WhenAll(peers.Select(p => SendOneAsync(p, data))).ConfigureAwait(false);
    }

    private async Task SendOneAsync(SocketPeer p, byte[] data)
    {
        if (!p.IsOpen) { _sink.OnError($"{p.Label} isn't connected any more."); return; }
        await p.WriteLock.WaitAsync().ConfigureAwait(false);
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(p.Cts.Token);
            cts.CancelAfter(30_000);
            await p.Stream!.WriteAsync(data, cts.Token).ConfigureAwait(false);
            Interlocked.Add(ref p.BytesOutRaw, data.Length);
        }
        catch (OperationCanceledException) when (p.IsOpen && !p.Cts.IsCancellationRequested)
        {
            _sink.OnError($"Send to {p.Label} timed out — it isn't reading (its receive buffer is full).");
        }
        catch (Exception ex) when (p.IsOpen)
        {
            _sink.OnError($"Send to {p.Label} failed: " + SocketErrors.Describe(ex, SocketAction.Send, p.Label));
        }
        catch { /* closed meanwhile */ }
        finally { p.WriteLock.Release(); }
    }

    /// <summary>Disconnects one client (its loop then reports it as "was disconnected").</summary>
    public void Disconnect(SocketPeer peer)
    {
        peer.KickedByUser = true;
        try { peer.Socket?.Shutdown(SocketShutdown.Both); } catch { }
        try { peer.Cts.Cancel(); } catch { }
    }

    private void ClosePeer(SocketPeer p)
    {
        if (Interlocked.Exchange(ref p.Closed, 1) != 0) return;
        _peers.TryRemove(p.Id, out _);
        try { p.Cts.Cancel(); } catch { }
        try { p.Stream?.Dispose(); } catch { }
        try { p.Socket?.Dispose(); } catch { }
    }

    /// <summary>Stops listening and closes every client (no per-client events).</summary>
    public void Stop()
    {
        if (Interlocked.Exchange(ref _stopped, 1) != 0) return;
        TeardownAll();
    }

    private void TeardownAll()
    {
        try { _cts.Cancel(); } catch { }
        try { _listener.Dispose(); } catch { }
        foreach (var p in _peers.Values) ClosePeer(p);
    }

    public void Dispose() => Stop();
}

/// <summary>UDP client: a socket "connected" to host:port — datagrams go there and only its replies come back.</summary>
public sealed class UdpClientSession : IDisposable
{
    public const int MaxDatagram = 65_507;

    private readonly Socket _socket;
    private readonly ISocketSink _sink;
    private readonly CancellationTokenSource _cts = new();
    private int _closed;
    private long _in, _out;

    private UdpClientSession(Socket socket, ISocketSink sink, string target)
    {
        _socket = socket;
        _sink = sink;
        Target = target;
        Remote = SocketNet.Normalize((IPEndPoint)socket.RemoteEndPoint!);
        Local = SocketNet.Normalize((IPEndPoint)socket.LocalEndPoint!);
    }

    /// <summary>"udp host:port" — how errors name it.</summary>
    public string Target { get; }
    public IPEndPoint Remote { get; }
    public IPEndPoint Local { get; }
    public long BytesIn => Interlocked.Read(ref _in);
    public long BytesOut => Interlocked.Read(ref _out);

    public static async Task<UdpClientSession> OpenAsync(string host, int port, ISocketSink sink, CancellationToken ct)
    {
        string target = "udp " + SocketNet.Target(host, port);
        IPAddress[] addrs;
        using (var rcts = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            rcts.CancelAfter(10_000);
            try { addrs = await SocketNet.ResolveAsync(host, rcts.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            { throw new SocketFailure(SocketErrors.Describe(new TimeoutException(), SocketAction.Resolve, target, port)); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { throw new SocketFailure(SocketErrors.Describe(ex, SocketAction.Resolve, target, port), ex); }
        }
        // UDP can't fall back on a refusal the way TCP does, so prefer IPv4: most UDP services listen there
        // ("localhost" → 127.0.0.1, not ::1).
        var addr = addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addrs[0];
        var s = new Socket(addr.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            s.Connect(new IPEndPoint(addr, port));
        }
        catch (Exception ex)
        {
            s.Dispose();
            throw new SocketFailure(SocketErrors.Describe(ex, SocketAction.Connect, target, port), ex);
        }
        return new UdpClientSession(s, sink, target);
    }

    public void Start() => _ = Task.Run(ReceiveLoopAsync);

    private async Task ReceiveLoopAsync()
    {
        var buf = new byte[65_536];
        while (true)
        {
            try
            {
                int n = await _socket.ReceiveAsync(buf.AsMemory(), SocketFlags.None, _cts.Token).ConfigureAwait(false);
                Interlocked.Add(ref _in, n);
                _sink.OnReceived(null, buf.AsSpan(0, n).ToArray());
            }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionRefused
                                              && Volatile.Read(ref _closed) == 0)
            {
                // ICMP "port unreachable" for a datagram we sent: say so, keep the socket (the service may come up)
                _sink.OnError(SocketErrors.Describe(ex, SocketAction.Receive, Target));
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.MessageSize && Volatile.Read(ref _closed) == 0)
            {
                _sink.OnError("A datagram larger than 64 KB was cut off.");
            }
            catch (Exception ex)
            {
                if (Volatile.Read(ref _closed) != 0 || _cts.IsCancellationRequested) return;
                if (Interlocked.Exchange(ref _closed, 1) != 0) return;
                Teardown();
                _sink.OnEnded("Socket closed: " + SocketErrors.Describe(ex, SocketAction.Receive, Target), true);
                return;
            }
        }
    }

    public async Task SendAsync(byte[] data)
    {
        if (Volatile.Read(ref _closed) != 0) { _sink.OnError("Not connected."); return; }
        if (data.Length > MaxDatagram)
        {
            _sink.OnError($"Too large for one datagram — UDP carries at most {MaxDatagram:N0} bytes, this is {data.Length:N0}.");
            return;
        }
        try
        {
            int n = await _socket.SendAsync(data.AsMemory(), SocketFlags.None, _cts.Token).ConfigureAwait(false);
            Interlocked.Add(ref _out, n);
        }
        catch (Exception ex) when (Volatile.Read(ref _closed) == 0)
        {
            _sink.OnError("Send failed: " + SocketErrors.Describe(ex, SocketAction.Send, Target));
        }
        catch { }
    }

    public void Close()
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0) return;
        Teardown();
    }

    private void Teardown()
    {
        try { _cts.Cancel(); } catch { }
        try { _socket.Dispose(); } catch { }
    }

    public void Dispose() => Close();
}

/// <summary>UDP server: receives from anyone, remembers who sent (the "clients" list), replies to one sender.</summary>
public sealed class UdpServerSession : IDisposable
{
    public const int MaxPeers = 256;
    /// <summary>How long a sender must have been quiet before a full list drops it to make room for a new one.</summary>
    private static readonly TimeSpan EvictAfterIdle = TimeSpan.FromSeconds(30);
    private long _nextEvictCheck;      // Environment.TickCount64 (receive loop only)
    private SocketPeer? _unlisted;     // the latest sender that didn't fit the full list, reused while it keeps sending

    private readonly Socket _socket;
    private readonly ISocketSink _sink;
    private readonly CancellationTokenSource _cts = new();
    private readonly ConcurrentDictionary<string, SocketPeer> _peers = new(StringComparer.Ordinal);
    private int _stopped;
    private long _in, _out;

    private UdpServerSession(Socket socket, ISocketSink sink)
    {
        _socket = socket;
        _sink = sink;
        LocalEndPoint = (IPEndPoint)socket.LocalEndPoint!;
    }

    public IPEndPoint LocalEndPoint { get; }
    public long BytesIn => Interlocked.Read(ref _in);
    public long BytesOut => Interlocked.Read(ref _out);

    public static UdpServerSession Listen(IPAddress bind, int port, ISocketSink sink)
        => new(SocketNet.Bind(bind, port, SocketType.Dgram, ProtocolType.Udp), sink);

    public void Start() => _ = Task.Run(ReceiveLoopAsync);

    private async Task ReceiveLoopAsync()
    {
        var buf = new byte[65_536];
        EndPoint any = _socket.AddressFamily == AddressFamily.InterNetworkV6
            ? new IPEndPoint(IPAddress.IPv6Any, 0) : new IPEndPoint(IPAddress.Any, 0);
        while (!_cts.IsCancellationRequested)
        {
            SocketReceiveFromResult r;
            try
            {
                r = await _socket.ReceiveFromAsync(buf.AsMemory(), SocketFlags.None, any, _cts.Token).ConfigureAwait(false);
            }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionRefused
                                              or SocketError.MessageSize)
            {
                continue;   // an ICMP error for an earlier reply / an oversized datagram: keep serving
            }
            catch (Exception ex)
            {
                if (_cts.IsCancellationRequested || Interlocked.Exchange(ref _stopped, 1) != 0) return;
                Teardown();
                _sink.OnEnded("Stopped listening: " + SocketErrors.Describe(ex, SocketAction.Receive, SocketNet.Label(LocalEndPoint)), true);
                return;
            }

            var raw = (IPEndPoint)r.RemoteEndPoint;
            var ep = SocketNet.Normalize(raw);
            string key = SocketNet.Label(ep);
            if (!_peers.TryGetValue(key, out var peer))
            {
                // A full list takes a newcomer only in place of a sender that has gone quiet. Evicting the oldest for
                // every new sender let a flood from thousands of source ports add and drop one list row per datagram
                // (two UI events each). A sender that doesn't fit is still delivered and can be answered as the last
                // sender — it just isn't listed.
                bool reuse = _unlisted is { } u && u.Label == key;
                if (_peers.Count < MaxPeers || EvictIdle())
                {
                    peer = reuse ? _unlisted! : new SocketPeer(ep) { SendEndPoint = raw };
                    if (reuse) _unlisted = null;
                    _peers[key] = peer;
                    _sink.OnPeerJoined(peer);
                }
                else peer = reuse ? _unlisted! : (_unlisted = new SocketPeer(ep) { SendEndPoint = raw });
            }
            peer.LastSeen = DateTime.Now;
            Interlocked.Add(ref peer.BytesInRaw, r.ReceivedBytes);
            Interlocked.Add(ref _in, r.ReceivedBytes);
            _sink.OnReceived(peer, buf.AsSpan(0, r.ReceivedBytes).ToArray());
        }
    }

    // Receive loop only. Drops the longest-quiet sender once it has been quiet for EvictAfterIdle; false = every listed
    // sender is still active. A list full of active senders is re-checked at most once a second, not per datagram.
    private bool EvictIdle()
    {
        long now = Environment.TickCount64;
        if (now < _nextEvictCheck) return false;
        SocketPeer? oldest = null;
        foreach (var kv in _peers)   // one pass, no sort, no snapshot copy
            if (oldest is null || kv.Value.LastSeen < oldest.LastSeen) oldest = kv.Value;
        if (oldest is null || DateTime.Now - oldest.LastSeen < EvictAfterIdle)
        {
            _nextEvictCheck = now + 1000;
            return false;
        }
        if (_peers.TryRemove(oldest.Label, out _))
            _sink.OnPeerLeft(oldest, null);   // quietly: a sender list, not a connection
        return true;
    }

    public async Task SendToAsync(SocketPeer peer, byte[] data)
    {
        if (Volatile.Read(ref _stopped) != 0) { _sink.OnError("Not listening."); return; }
        if (data.Length > UdpClientSession.MaxDatagram)
        {
            _sink.OnError($"Too large for one datagram — UDP carries at most {UdpClientSession.MaxDatagram:N0} bytes, this is {data.Length:N0}.");
            return;
        }
        try
        {
            int n = await _socket.SendToAsync(data.AsMemory(), SocketFlags.None, peer.SendEndPoint ?? peer.EndPoint, _cts.Token).ConfigureAwait(false);
            Interlocked.Add(ref peer.BytesOutRaw, n);
            Interlocked.Add(ref _out, n);
        }
        catch (Exception ex) when (Volatile.Read(ref _stopped) == 0)
        {
            _sink.OnError($"Send to {peer.Label} failed: " + SocketErrors.Describe(ex, SocketAction.Send, "udp " + peer.Label));
        }
        catch { }
    }

    public void Stop()
    {
        if (Interlocked.Exchange(ref _stopped, 1) != 0) return;
        Teardown();
    }

    private void Teardown()
    {
        try { _cts.Cancel(); } catch { }
        try { _socket.Dispose(); } catch { }
    }

    public void Dispose() => Stop();
}
