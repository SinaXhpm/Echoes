using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>
/// SOCKS5 UDP ASSOCIATE (RFC 1928 §7), when it is switched on (<see cref="ProxyServerOptions.Udp"/>). The client asks on
/// its TCP connection for a relay, and is given a UDP port on the address it reached this proxy at. It sends each
/// datagram there with a short header naming where it goes (RSV RSV FRAG ATYP DST.ADDR DST.PORT, then the data); the
/// relay sends the data on, and each answer back with the same kind of header naming who answered. The association
/// lasts as long as that TCP connection, or until nothing has passed either way for the idle time.
/// <para>Every destination is judged as a TCP target is (<see cref="CheckRequest"/>, <see cref="TargetsAsync"/>): the
/// same protection of this device and of the networks behind it, the user's rules, the IP version and the outgoing
/// interface. Only the client's own address may use its relay port, and only hosts it has sent to may answer on it (a
/// port-restricted cone, as a home router's NAT), so the port is no way in from the internet. Fragments (FRAG not 0)
/// are dropped, as the RFC allows.</para>
/// <para>With an upstream proxy set, the datagrams go on through it as connections do, never straight to a destination:
/// a SOCKS5 upstream is asked for a UDP relay of its own, and each datagram goes there behind a header naming its
/// destination (the name itself where a connection's would go as one, see <see cref="MayPassName"/>; else the address
/// judged here). SOCKS4a and HTTP(S) carry no UDP: with such an upstream, UDP is refused.</para>
/// </summary>
public sealed partial class ProxyServer
{
    private const int MaxUdpAnswerers = 4096;  // hosts remembered per association as allowed to answer
    private const int MaxUdpLogRows = 32;      // destinations logged per association (the first time each is used)
    private const int MaxUdpVerdicts = 256;    // destinations' verdicts remembered per association
    private const int MaxUdpLookups = 16;      // names looked up at once per association
    private const int MaxUdpHeld = 256 * 1024; // bytes of datagrams waiting for those lookups, per association
    private const int MaxUdpPayload = 65_507;  // the most a datagram over IPv4 carries
    private const int UdpReplyRoom = 22;       // the longest answer header: RSV RSV FRAG ATYP, 16 address bytes, the port
    private const int UdpHeaderRoom = 262;     // the longest header of all: RSV RSV FRAG ATYP, a 255-byte name with its length, the port

    private async Task UdpAssociateAsync(NetworkStream control, Peer peer, string user, int clientPort, CancellationToken ct)
    {
        if (!_udp)
        {
            await Socks5Reply(control, 0x07, ct).ConfigureAwait(false);   // command not supported
            Log(peer.Name, "SOCKS5", "UDP relay", user, false, "UDP off", "UDP relaying is switched off (Advanced, Protocols).");
            return;
        }
        if (_upstream is { Proxy.Kind: not ProxyUpstreamKind.Socks5 } other)
        {
            await Socks5Reply(control, 0x07, ct).ConfigureAwait(false);
            Log(peer.Name, "SOCKS5", "UDP relay", user, false, "UDP off (upstream)",
                $"The upstream proxy {other.Proxy.Display} is {(other.Proxy.Kind == ProxyUpstreamKind.Socks4a ? "a" : "an")} {other.Proxy.KindName} proxy, which carries no UDP, and nothing goes to a site directly while an upstream proxy is set.");
            return;
        }
        if (peer.Address is not { } client || peer.LocalAddress is not { } entry)
        {
            await Socks5Reply(control, 0x01, ct).ConfigureAwait(false);
            return;
        }

        using var association = new UdpAssociation(this, peer, user, client, clientPort, ct);
        if (_upstream is { } upstream)
        {
            // the upstream's relay first: when it can't be had, the client hears why instead of getting a relay that
            // sends nowhere
            try { await association.ThroughAsync(upstream, ct).ConfigureAwait(false); }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                if (ex is ProxyRouteException { InterfaceFault: true }) _out?.Suspect();
                LogDialFail(peer.Name, "SOCKS5", "UDP relay", user, ex);
                await Socks5Reply(control, Socks5ErrFor(ex), ct).ConfigureAwait(false);
                return;
            }
        }
        IPEndPoint relay;
        try { relay = association.Open(entry); }
        catch (SocketException ex)
        {
            await Socks5Reply(control, 0x01, ct).ConfigureAwait(false);
            Log(peer.Name, "SOCKS5", "UDP relay", user, false, "UDP failed", $"No UDP port could be opened for the relay: {ex.Message}");
            return;
        }

        // The reply names the relay: the address the client reached this proxy at, and the port opened there.
        bool v4 = relay.AddressFamily == AddressFamily.InterNetwork;
        var reply = new byte[v4 ? 10 : 22];
        reply[0] = 5;
        reply[3] = (byte)(v4 ? 1 : 4);
        relay.Address.TryWriteBytes(reply.AsSpan(4), out int written);
        BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(4 + written), (ushort)relay.Port);
        await control.WriteAsync(reply, ct).ConfigureAwait(false);
        Log(peer.Name, "SOCKS5", "UDP relay", user, true, "UDP associate",
            $"Its datagrams go to {FormatTarget(relay.Address.ToString(), relay.Port)} while this connection stays open"
            + (association.UpstreamRelay is { } through ? $", and on through the upstream proxy {_upstream!.Proxy.Display} (its relay at {through})." : "."));

        await association.RunAsync(control).ConfigureAwait(false);
    }

    // Where an upstream's UDP relay is: what it named, when that is an address as near as the upstream itself (this device,
    // the link, a private network, the internet). Otherwise the upstream's own address, with the port it named: for none
    // (0.0.0.0 or ::, "where you reached me", or a name), and for one that can't be right from here. A relay bound to
    // loopback or behind a NAT names its own side (127.0.0.1, 10.0.0.5) to a client out on the internet; a proxy program
    // on this device or the LAN names its public address. And an upstream elsewhere never points this proxy at this
    // device's own services.
    private IPAddress UpstreamRelayAddress(IPAddress hop, IPAddress? named) => ChooseUdpRelay(hop, named, a => _own.Contains(a, null));

    internal static IPAddress ChooseUdpRelay(IPAddress hop, IPAddress? named, Func<IPAddress, bool> isOwn)
    {
        if (hop.IsIPv4MappedToIPv6) hop = hop.MapToIPv4();
        if (named is null) return hop;
        if (named.IsIPv4MappedToIPv6) named = named.MapToIPv4();
        if (named.GetAddressBytes().AsSpan().IndexOfAnyExcept((byte)0) < 0 || Distance(named, isOwn) != Distance(hop, isOwn)) return hop;
        // a link-local address means nothing without the link: the upstream's
        return named.IsIPv6LinkLocal && named.ScopeId == 0 && hop.AddressFamily == AddressFamily.InterNetworkV6
            ? new IPAddress(named.GetAddressBytes(), hop.ScopeId)
            : named;
    }

    // How far an address is from this device: 0 this device itself (loopback, 0.0.0.0/8, its own addresses), 1 the link
    // (link-local), 2 a private network, 3 the internet.
    private static int Distance(IPAddress a, Func<IPAddress, bool> isOwn)
    {
        var v4 = EmbeddedIPv4(a);
        if (isOwn(a) || isOwn(v4)) return 0;
        var b = v4.GetAddressBytes();
        if (v4.AddressFamily == AddressFamily.InterNetwork)
        {
            if (b[0] is 0 or 127) return 0;
            if (b[0] == 169 && b[1] == 254) return 1;
        }
        else
        {
            if (b.AsSpan(0, 15).IndexOfAnyExcept((byte)0) < 0 && b[15] <= 1) return 0;   // ::, ::1
            if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return 1;                          // fe80::/10
        }
        return IsPrivateTarget(v4) ? 2 : 3;
    }

    // RSV RSV FRAG ATYP DST.ADDR DST.PORT: for an address, or (ATYP 3) a name.
    private static byte[] UdpHeader(IPAddress to, int port)
    {
        if (to.IsIPv4MappedToIPv6) to = to.MapToIPv4();
        bool v4 = to.AddressFamily == AddressFamily.InterNetwork;
        var h = new byte[v4 ? 10 : 22];
        h[3] = (byte)(v4 ? 1 : 4);
        to.TryWriteBytes(h.AsSpan(4), out int n);
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(4 + n), (ushort)port);
        return h;
    }

    // (the name in its ASCII form: a name in another script as its xn-- form, see ProxyUpstream.AsciiHost)
    internal static byte[] UdpHeader(string name, int port)
    {
        byte[] bytes = ProxyUpstream.AsciiHost(name) is { } ascii ? Encoding.ASCII.GetBytes(ascii) : Array.Empty<byte>();
        if (bytes.Length is 0 or > 255) throw new SocketException((int)SocketError.HostNotFound);
        var h = new byte[5 + bytes.Length + 2];
        h[3] = 3;
        h[4] = (byte)bytes.Length;
        bytes.CopyTo(h, 5);
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(5 + bytes.Length), (ushort)port);
        return h;
    }

    // Windows reports an ICMP "port unreachable" for an earlier datagram as an error on the NEXT receive (WSAECONNRESET),
    // which would end a relay loop over one host that doesn't listen: switched off (SIO_UDP_CONNRESET).
    private static void IgnoreUdpResets(Socket socket)
    {
        if (!OperatingSystem.IsWindows()) return;
        try { socket.IOControl(unchecked((int)0x9800000C), new byte[4], null); }
        catch (Exception e) when (e is SocketException or NotSupportedException or PlatformNotSupportedException) { }
    }

    // A receive error about one datagram (an ICMP answer to an earlier one, a datagram too big), not about the socket.
    private static bool IsTransient(SocketException e) => e.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionRefused
        or SocketError.NetworkReset or SocketError.MessageSize or SocketError.HostUnreachable or SocketError.NetworkUnreachable;

    // RSV RSV FRAG ATYP DST.ADDR DST.PORT DATA. False for a fragment (FRAG not 0: not put together again) or for what
    // isn't a datagram of the relay.
    internal static bool TryParseUdpHeader(ReadOnlySpan<byte> d, out string host, out int port, out int dataAt)
    {
        host = string.Empty;
        port = 0;
        dataAt = 0;
        if (d.Length < 4 || d[2] != 0) return false;
        int at = 4;
        switch (d[3])
        {
            case 1:
                if (d.Length < at + 4 + 2) return false;
                host = new IPAddress(d.Slice(at, 4)).ToString();
                at += 4;
                break;
            case 4:
                if (d.Length < at + 16 + 2) return false;
                host = new IPAddress(d.Slice(at, 16)).ToString();
                at += 16;
                break;
            case 3:
                if (d.Length < at + 1) return false;
                int length = d[at];
                if (length == 0 || d.Length < at + 1 + length + 2) return false;
                host = Encoding.ASCII.GetString(d.Slice(at + 1, length));
                at += 1 + length;
                break;
            default:
                return false;
        }
        port = BinaryPrimitives.ReadUInt16BigEndian(d.Slice(at, 2));
        dataAt = at + 2;
        return port != 0;
    }

    /// <summary>One client's UDP relay: the port it sends to, the sockets toward the destinations (made at first use,
    /// one per kind of address) or toward the upstream proxy's relay, and who may answer.</summary>
    private sealed class UdpAssociation : IDisposable
    {
        private readonly ProxyServer _server;
        private readonly Peer _peer;
        private readonly string _user;
        private readonly UInt128 _clientKey;
        private readonly int _clientPort;            // the port the client named; 0: its first datagram's is taken
        private readonly CancellationTokenSource _life;
        private Socket? _front;                       // the relay port the client sends to
        private volatile IPEndPoint? _client;         // where its datagrams come from, and the answers go
        private long _armed;

        // Shared by the client loop and the lookups running beside it (LookUpAsync), under _gate: the sockets toward the
        // destinations, by kind of address and whether tied to the outgoing interface (null: it couldn't be made; the
        // answer loops each read their own); each destination's way on (null: refused); the datagrams waiting for a
        // name's lookup, and their bytes; the destinations logged; and whether the association has been disposed.
        private readonly object _gate = new();
        private readonly Dictionary<(AddressFamily Family, bool Tied), Socket?> _out = new();
        private readonly Dictionary<string, Way?> _ways = new(StringComparer.Ordinal);
        private readonly Dictionary<string, Queue<byte[]>> _pending = new(StringComparer.Ordinal);
        private int _held;
        private readonly HashSet<string> _logged = new(StringComparer.Ordinal);
        private bool _closed;
        private readonly ConcurrentDictionary<(UInt128 Address, int Port), byte> _answerers = new();

        // Through an upstream proxy (ThroughAsync): its TCP connection, which its relay lasts as long as; where that relay
        // takes the datagrams and the one socket they go there from, and the ports of the destinations handed on as
        // names, whose addresses only the upstream knows.
        private UpstreamLink? _up;
        private IPAddress[] _hops = Array.Empty<IPAddress>();
        private TcpClient? _upControl;
        private Socket? _upSocket;
        private IPEndPoint? _upRelay;
        private UInt128 _upRelayKey;
        private byte[] _upBuffer = Array.Empty<byte>();                                                   // client loop only
        private readonly ConcurrentDictionary<int, byte> _namedPorts = new();

        // Where a destination's datagrams go: straight to the first of its addresses a socket can be had for, or to the
        // upstream's relay behind this header.
        private sealed record Way(List<IPAddress>? Targets, byte[]? Header);

        /// <summary>The upstream proxy's relay ("127.0.0.1:61000"), or null when the datagrams go straight to the destinations.</summary>
        public string? UpstreamRelay => _upRelay is { } r ? FormatTarget(r.Address.ToString(), r.Port) : null;

        public UdpAssociation(ProxyServer server, Peer peer, string user, IPAddress client, int clientPort, CancellationToken ct)
        {
            _server = server;
            _peer = peer;
            _user = user;
            ProxyRules.TryKey(client, out _clientKey);
            _clientPort = clientPort;
            _life = CancellationTokenSource.CreateLinkedTokenSource(ct);
            _life.CancelAfter(server._idleMs);
        }

        /// <summary>Opens the relay port on <paramref name="entry"/> (the address the client reached the proxy at).</summary>
        public IPEndPoint Open(IPAddress entry)
        {
            var front = new Socket(entry.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                IgnoreUdpResets(front);
                front.Bind(new IPEndPoint(entry, 0));
            }
            catch
            {
                front.Dispose();
                throw;
            }
            _front = front;
            return (IPEndPoint)front.LocalEndPoint!;
        }

        /// <summary>
        /// Asks the upstream proxy for its UDP relay (on a connection of its own, made as any connection to it is), and
        /// opens the socket the datagrams go there from: tied to the outgoing interface like that connection, else from
        /// the address that connection came from (the one the upstream lets use its relay). Throws what a connection
        /// through the upstream would when the relay can't be had: down, the login, no UDP, the interface.
        /// </summary>
        public async Task ThroughAsync(UpstreamLink up, CancellationToken ct)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(_server._connectMs);
            _up = up;
            _hops = await up.AddressesAsync(timeout.Token).ConfigureAwait(false);
            _upControl = await _server.ConnectUpstreamAsync(up, _hops, _peer, timeout.Token).ConfigureAwait(false);
            var (host, port) = await up.Proxy.OpenUdpAsync(_upControl.GetStream(), timeout.Token).ConfigureAwait(false);
            if (port == 0)
                throw new ProxyUpstreamException("upstream failed", $"The upstream proxy {up.Proxy.Display} named no port for its UDP relay.") { Fatal = true };

            var hop = ((IPEndPoint)_upControl.Client.RemoteEndPoint!).Address;
            var from = ((IPEndPoint)_upControl.Client.LocalEndPoint!).Address;
            var relay = _server.UpstreamRelayAddress(hop, IPAddress.TryParse(host, out var named) ? named : null);
            var via = _server.ViaFor(relay, _peer);   // throws while the interface is down
            if (via?.Missing(relay) is { } missing)
                throw new ProxyRouteException(relay.AddressFamily == AddressFamily.InterNetworkV6 ? "no IPv6 on interface" : "no IPv4 on interface", NetIfaceException.From(via, missing).Message);
            var socket = new Socket(relay.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                IgnoreUdpResets(socket);
                if (via is not null)
                {
                    if (!via.TryBind(socket, out string? why))
                        throw new ProxyRouteException("interface error", NetIfaceException.From(via, why ?? $"can't send through {via.Name}").Message) { InterfaceFault = true };
                    relay = via.Scoped(relay);
                }
                else
                {
                    if (from.IsIPv4MappedToIPv6) from = from.MapToIPv4();
                    socket.Bind(new IPEndPoint(from.AddressFamily == relay.AddressFamily ? from
                        : relay.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0));
                }
            }
            catch
            {
                socket.Dispose();
                throw;
            }
            _upSocket = socket;
            _upRelay = new IPEndPoint(relay, port);
            ProxyRules.TryKey(relay, out _upRelayKey);
            _upBuffer = new byte[UdpHeaderRoom + 65_536];
        }

        /// <summary>Relays until the client closes its TCP connection, the server stops, or nothing passes for the idle
        /// time; through an upstream, also until it closes its own.</summary>
        public async Task RunAsync(System.IO.Stream control)
        {
            var token = _life.Token;
            if (_upSocket is { } upstream) _ = UpstreamAnswersAsync(upstream, token);
            var ends = new List<Task>(3) { ClientLoopAsync(token), WatchControlAsync(control, token) };
            if (_upControl is { } upControl) ends.Add(WatchControlAsync(upControl.GetStream(), token));
            await Task.WhenAny(ends).ConfigureAwait(false);
            try { _life.Cancel(); } catch (ObjectDisposedException) { }
            // the client loop never throws; after it, only a lookup still running may add a socket, and none once the
            // association is disposed (SocketFor)
            await ends[0].ConfigureAwait(false);
        }

        // Nothing more is said on a control connection (the client's, the one to the upstream): its closing is the end of
        // the association.
        private static async Task WatchControlAsync(System.IO.Stream control, CancellationToken token)
        {
            var buf = new byte[256];
            try { while (await control.ReadAsync(buf, token).ConfigureAwait(false) > 0) { } }
            catch { /* reset, or the association ended first */ }
        }

        // Traffic either way keeps the association alive (the idle deadline moved at most once a second).
        private void Touch()
        {
            long now = Environment.TickCount64;
            if (now - Interlocked.Read(ref _armed) < 1000) return;
            Interlocked.Exchange(ref _armed, now);
            try { _life.CancelAfter(_server._idleMs); } catch (ObjectDisposedException) { }
        }

        // ------------------------------------------------------------------ client → destinations

        private async Task ClientLoopAsync(CancellationToken token)
        {
            try
            {
                var front = _front!;
                var buf = new byte[65_536];
                EndPoint any = new IPEndPoint(front.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
                int errors = 0;
                while (!token.IsCancellationRequested)
                {
                    SocketReceiveFromResult got;
                    try { got = await front.ReceiveFromAsync(buf, SocketFlags.None, any, token).ConfigureAwait(false); }
                    catch (SocketException e) when (IsTransient(e) && ++errors < 1000) { continue; }
                    errors = 0;
                    if (!FromClient((IPEndPoint)got.RemoteEndPoint)) continue;
                    Touch();
                    if (!TryParseUdpHeader(buf.AsSpan(0, got.ReceivedBytes), out string host, out int port, out int dataAt)) continue;
                    var data = buf.AsMemory(dataAt, got.ReceivedBytes - dataAt);
                    if (await WayAsync(host, port, data, token).ConfigureAwait(false) is { } way)
                        await SendOnAsync(way, host, port, data, _upBuffer, token).ConfigureAwait(false);
                }
            }
            catch { /* the association ended, or its socket broke */ }
        }

        // Only the client of this association may use its relay port: from its address, and from one port (the one it
        // named, or else the one its first datagram came from).
        private bool FromClient(IPEndPoint from)
        {
            if (!ProxyRules.TryKey(from.Address, out var key) || key != _clientKey) return false;
            if (_clientPort != 0 && from.Port != _clientPort) return false;
            if (_client is { } known) return known.Port == from.Port;
            _client = new IPEndPoint(from.Address.IsIPv4MappedToIPv6 ? from.Address.MapToIPv4() : from.Address, from.Port);
            return true;
        }

        // The way on to host:port, when it is known or can be had at once (an address; a name the upstream is given as
        // it is). A name that has to be looked up is looked up on a task of its own (LookUpAsync), and the datagrams to
        // it wait there in the order they came (null here): the lookup may take the connect time-out, and this loop is
        // the only one reading the client's datagrams, to every destination.
        private async ValueTask<Way?> WayAsync(string host, int port, ReadOnlyMemory<byte> data, CancellationToken token)
        {
            string key = host + " " + port.ToString(CultureInfo.InvariantCulture);
            bool lookUp = NeedsLookup(host);
            lock (_gate)
            {
                if (_ways.TryGetValue(key, out var known)) return known;
                if (_pending.TryGetValue(key, out var waiting))
                {
                    Hold(waiting, data);
                    return null;
                }
                if (lookUp)
                {
                    // (at most MaxUdpLookups at once: past that the datagram is lost, as one may be)
                    if (_pending.Count >= MaxUdpLookups) return null;
                    waiting = new Queue<byte[]>();
                    Hold(waiting, data);
                    _pending[key] = waiting;
                }
            }
            if (lookUp)
            {
                _ = LookUpAsync(key, host, port, token);
                return null;
            }
            var (way, keep) = await FindAsync(host, port, token).ConfigureAwait(false);   // done at once: nothing to look up
            if (keep) lock (_gate) Remember(key, way);
            return way;
        }

        // Whether the way to host can only be had by looking its name up: not an address, and not a name the upstream
        // is given as it is.
        private bool NeedsLookup(string host)
            => !IPAddress.TryParse(host, out _) && !(_upRelay is not null && _server.MayPassName(_up!, _hops, _peer));

        // A datagram waits for its destination's lookup: a copy (the loop reads the next one into the same buffer), within
        // MaxUdpHeld bytes for the association; past that it is lost, as a datagram may be. Under _gate.
        private void Hold(Queue<byte[]> waiting, ReadOnlyMemory<byte> data)
        {
            if (_held + data.Length > MaxUdpHeld) return;
            waiting.Enqueue(data.ToArray());
            _held += data.Length;
        }

        // Under _gate.
        private void Remember(string key, Way? way)
        {
            if (_ways.Count >= MaxUdpVerdicts) _ways.Clear();
            _ways[key] = way;
        }

        // A name's lookup, beside the client loop. Then the datagrams that waited for it go on in the order they came, and
        // only when none is left waiting is the way remembered for the loop to send by at once (in the same step), so a
        // datagram that came meanwhile can't pass those before it. Refused, or the association ended: they are dropped.
        private async Task LookUpAsync(string key, string host, int port, CancellationToken token)
        {
            try
            {
                var (way, keep) = await FindAsync(host, port, token).ConfigureAwait(false);
                while (true)
                {
                    byte[] next;
                    lock (_gate)
                    {
                        var waiting = _pending[key];
                        if (way is null || waiting.Count == 0)
                        {
                            Release(key);
                            if (keep) Remember(key, way);
                            return;
                        }
                        next = waiting.Dequeue();
                        _held -= next.Length;
                    }
                    await SendOnAsync(way, host, port, next, null, token).ConfigureAwait(false);
                }
            }
            catch
            {
                // the association ended
                lock (_gate) Release(key);
            }

            // Under _gate: the lookup is over, and what still waits for it is dropped.
            void Release(string done)
            {
                if (!_pending.Remove(done, out var dropped)) return;
                foreach (var d in dropped) _held -= d.Length;
            }
        }

        // Where datagrams for host:port may go, judged as a TCP target is: straight to its addresses, or through the
        // upstream behind the header naming it, as a connection's target is handed to it (the name itself where that may
        // go as one, MayPassName; else the address judged here, the first the rules and the IP version leave, which may
        // answer from then on). Null when they may not go there (logged once). Keep: false for a lookup that timed out,
        // which isn't remembered.
        private async Task<(Way? Way, bool Keep)> FindAsync(string host, int port, CancellationToken token)
        {
            try
            {
                using var lookup = CancellationTokenSource.CreateLinkedTokenSource(token);
                lookup.CancelAfter(_server._connectMs);
                string h = _server.CheckRequest(host, port, _peer, out IPAddress? literal);
                if (_upRelay is null)
                    return (new Way(await _server.TargetsAsync(h, literal, port, _peer, lookup.Token).ConfigureAwait(false), null), true);
                if (literal is null && _server.MayPassName(_up!, _hops, _peer))
                {
                    var named = UdpHeader(h, port);
                    _namedPorts.TryAdd(port, 0);
                    return (new Way(null, named), true);
                }
                var to = (await _server.TargetsAsync(h, literal, port, _peer, lookup.Token).ConfigureAwait(false))[0];
                if (ProxyRules.TryKey(to, out var answerer) && _answerers.Count < MaxUdpAnswerers) _answerers.TryAdd((answerer, port), 0);
                return (new Way(null, UdpHeader(to, port)), true);
            }
            catch (OperationCanceledException) when (!token.IsCancellationRequested)
            {
                LogOnce(host, port, new OperationCanceledException());
                return (null, false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                LogOnce(host, port, ex);
                return (null, true);
            }
        }

        // One datagram on: to the upstream's relay behind the destination's header (put together in buffer, or in one
        // made for it), or straight to the first of the destination's addresses a socket can be had for.
        private async Task SendOnAsync(Way way, string host, int port, ReadOnlyMemory<byte> data, byte[]? buffer, CancellationToken token)
        {
            if (way.Header is { } header)
            {
                buffer ??= new byte[header.Length + data.Length];
                header.CopyTo(buffer, 0);
                data.CopyTo(buffer.AsMemory(header.Length));
                LogOnce(host, port, null);
                await _server.PaceAsync(_server._upLimit, data.Length, _life).ConfigureAwait(false);
                try
                {
                    await _upSocket!.SendToAsync(buffer.AsMemory(0, header.Length + data.Length), SocketFlags.None, _upRelay!, token).ConfigureAwait(false);
                    Interlocked.Add(ref _server._bytesUp, data.Length);
                }
                catch (SocketException) { /* lost, as a datagram may be */ }
                return;
            }
            foreach (var address in way.Targets!)
            {
                if (SocketFor(address, host, port, out var to) is not { } socket) continue;
                // the host may answer from then on (unless the list is full: the ones already on it still may)
                if (ProxyRules.TryKey(to, out var key) && (_answerers.Count < MaxUdpAnswerers || _answerers.ContainsKey((key, port))))
                    _answerers.TryAdd((key, port), 0);
                LogOnce(host, port, null);
                await _server.PaceAsync(_server._upLimit, data.Length, _life).ConfigureAwait(false);
                try
                {
                    await socket.SendToAsync(data, SocketFlags.None, new IPEndPoint(to, port), token).ConfigureAwait(false);
                    Interlocked.Add(ref _server._bytesUp, data.Length);
                }
                catch (SocketException) { /* lost, as a datagram may be */ }
                return;
            }
        }

        // The socket datagrams to this address leave from: one per kind of address, tied to the outgoing interface (or
        // not, for this device's own addresses), made at first use with its own loop for the answers. Null when it can't
        // be made (logged once), or the association is over. to = the address to send to (a link-local one with the
        // interface's zone).
        private Socket? SocketFor(IPAddress address, string host, int port, out IPAddress to)
        {
            to = address;
            NetIface? via;
            try { via = _server.ViaFor(address, _peer); }
            catch (ProxyRouteException ex)
            {
                LogOnce(host, port, ex);   // the interface is down
                return null;
            }
            if (via is not null) to = via.Scoped(address);
            var key = (address.AddressFamily, via is not null);

            Socket? socket = null;
            Exception? failed = null;
            lock (_gate)
            {
                if (_out.TryGetValue(key, out var made)) return made;
                if (_closed) return null;
                try
                {
                    socket = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                    IgnoreUdpResets(socket);
                    string? why = via?.Missing(address);
                    if (why is null && via is not null && !via.TryBind(socket, out why)) why ??= $"can't send through {via.Name}";
                    if (why is not null)
                    {
                        socket.Dispose();
                        socket = null;
                        failed = new ProxyRouteException("interface error", NetIfaceException.From(via!, why).Message);
                    }
                    else if (!socket.IsBound)
                        socket.Bind(new IPEndPoint(address.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0));
                }
                catch (SocketException ex)
                {
                    socket?.Dispose();
                    socket = null;
                    failed = ex;
                }
                _out[key] = socket;
                if (socket is not null) _ = AnswerLoopAsync(socket, _life.Token);
            }
            if (failed is not null) LogOnce(host, port, failed);
            return socket;
        }

        // The first datagram to each destination is logged (relayed, or why not), up to MaxUdpLogRows an association.
        private void LogOnce(string host, int port, Exception? refused)
        {
            string target = FormatTarget(host, port);
            lock (_gate)
                if (_logged.Count >= MaxUdpLogRows || !_logged.Add(target)) return;
            if (refused is null) _server.Log(_peer.Name, "UDP", target, _user, true, "relayed");
            else _server.LogDialFail(_peer.Name, "UDP", target, _user, refused);
        }

        // ------------------------------------------------------------------ destinations → client

        // Answers go to the client from the hosts it has sent to only, each behind the header that names who answered.
        private async Task AnswerLoopAsync(Socket socket, CancellationToken token)
        {
            try
            {
                var buf = new byte[UdpReplyRoom + 65_536];
                EndPoint any = new IPEndPoint(socket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
                int errors = 0;
                while (!token.IsCancellationRequested)
                {
                    SocketReceiveFromResult got;
                    try { got = await socket.ReceiveFromAsync(buf.AsMemory(UdpReplyRoom), SocketFlags.None, any, token).ConfigureAwait(false); }
                    catch (SocketException e) when (IsTransient(e) && ++errors < 1000) { continue; }
                    errors = 0;
                    var from = (IPEndPoint)got.RemoteEndPoint;
                    var address = from.Address.IsIPv4MappedToIPv6 ? from.Address.MapToIPv4() : from.Address;
                    if (!ProxyRules.TryKey(address, out var key) || !_answerers.ContainsKey((key, from.Port))) continue;
                    if (_client is not { } client) continue;
                    bool v4 = address.AddressFamily == AddressFamily.InterNetwork;
                    int headLength = v4 ? 10 : 22, start = UdpReplyRoom - headLength;
                    if (headLength + got.ReceivedBytes > MaxUdpPayload) continue;   // it wouldn't fit in a datagram to the client
                    Touch();
                    buf[start] = 0;
                    buf[start + 1] = 0;
                    buf[start + 2] = 0;
                    buf[start + 3] = (byte)(v4 ? 1 : 4);
                    address.TryWriteBytes(buf.AsSpan(start + 4), out int n);
                    BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(start + 4 + n), (ushort)from.Port);
                    await _server.PaceAsync(_server._downLimit, got.ReceivedBytes, _life).ConfigureAwait(false);
                    try
                    {
                        await _front!.SendToAsync(buf.AsMemory(start, headLength + got.ReceivedBytes), SocketFlags.None, client, token).ConfigureAwait(false);
                        Interlocked.Add(ref _server._bytesDown, got.ReceivedBytes);
                    }
                    catch (SocketException) { /* lost, as a datagram may be */ }
                }
            }
            catch { /* the association ended, or the socket broke */ }
        }

        // Answers from the upstream's relay (nothing else that reaches its socket), each behind the header that names who
        // answered, as the client takes them: passed on as they are, from the hosts it has sent to only. Those are an
        // address it sent to, or for a destination handed on as a name (whose address only the upstream knows) any host
        // on that port.
        private async Task UpstreamAnswersAsync(Socket socket, CancellationToken token)
        {
            try
            {
                var buf = new byte[65_536];
                var relay = _upRelay!;
                EndPoint any = new IPEndPoint(socket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
                int errors = 0;
                while (!token.IsCancellationRequested)
                {
                    SocketReceiveFromResult got;
                    try { got = await socket.ReceiveFromAsync(buf, SocketFlags.None, any, token).ConfigureAwait(false); }
                    catch (SocketException e) when (IsTransient(e) && ++errors < 1000) { continue; }
                    errors = 0;
                    var from = (IPEndPoint)got.RemoteEndPoint;
                    if (from.Port != relay.Port || !ProxyRules.TryKey(from.Address, out var key) || key != _upRelayKey) continue;
                    var datagram = buf.AsMemory(0, got.ReceivedBytes);
                    if (!TryParseUdpHeader(datagram.Span, out string host, out int port, out int dataAt) || !MayAnswer(host, port)) continue;
                    if (_client is not { } client) continue;
                    Touch();
                    int length = got.ReceivedBytes - dataAt;
                    await _server.PaceAsync(_server._downLimit, length, _life).ConfigureAwait(false);
                    try
                    {
                        await _front!.SendToAsync(datagram, SocketFlags.None, client, token).ConfigureAwait(false);
                        Interlocked.Add(ref _server._bytesDown, length);
                    }
                    catch (SocketException) { /* lost, as a datagram may be */ }
                }
            }
            catch { /* the association ended, or the socket broke */ }
        }

        private bool MayAnswer(string host, int port)
            => (IPAddress.TryParse(host, out var a) && ProxyRules.TryKey(a, out var key) && _answerers.ContainsKey((key, port)))
               || _namedPorts.ContainsKey(port);

        public void Dispose()
        {
            try { _life.Cancel(); } catch (ObjectDisposedException) { }
            _front?.Dispose();
            List<Socket?> outs;
            lock (_gate)
            {
                _closed = true;   // a lookup still running makes no socket from now on
                outs = new List<Socket?>(_out.Values);
            }
            foreach (var socket in outs) socket?.Dispose();
            _upSocket?.Dispose();
            _upControl?.Dispose();
            _life.Dispose();
        }
    }
}
