using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>How a probe goes out. <see cref="Auto"/> (what the app uses everywhere): ICMP echo, and where ICMP isn't
/// permitted at all, a UDP datagram probe. <see cref="Icmp"/> / <see cref="Udp"/> force one method (tests).</summary>
public enum PingMethod { Auto, Icmp, Udp }

/// <summary>The packet one probe is asked to go out as (the Ping tab's options): <paramref name="PayloadSize"/> data
/// bytes (0-<see cref="IcmpPinger.MaxPayloadSize"/>), <paramref name="Ttl"/> (0 = the system's default) and the Don't
/// fragment flag. Only the <see cref="IcmpPinger.SendAsync(IPAddress, int, IcmpProbeOptions, CancellationToken, PingMethod, int)"/>
/// overload takes it; the classic overload keeps sending exactly what it always did.</summary>
public readonly record struct IcmpProbeOptions(int PayloadSize = IcmpPinger.PayloadSize, int Ttl = 0, bool DontFragment = false);

/// <summary>Which of the requested <see cref="IcmpProbeOptions"/> the path that sent a probe really applied (the
/// system ping utility can't send a custom size, IPv6 has no DF flag, …). <see cref="IcmpPinger.PingResult.Note"/> says why.</summary>
[Flags]
public enum IcmpApplied { None = 0, Size = 1, Ttl = 2, DontFragment = 4 }

/// <summary>
/// Cross-platform ICMP echo ("ping") that works without root.
///
/// On Windows it uses the managed <see cref="Ping"/> class (reliable, no
/// privileges needed). Everywhere else it opens an unprivileged ICMP *datagram*
/// socket (SOCK_DGRAM, IPPROTO_ICMP / IPPROTO_ICMPV6) and builds the echo packet by hand — Android
/// keeps net.ipv4.ping_group_range open for all apps, so this works in the sandbox
/// with only the INTERNET permission, on desktop Linux it avoids needing sudo
/// wherever ping_group_range allows the caller's gid, and macOS / iOS allow it to any app (their
/// sockets see every ICMP message, so the replies are matched to the probe by identifier and sequence).
///
/// Where no form of ICMP is allowed (ping sockets off, no raw-socket rights, no usable ping utility: containers,
/// locked-down or sandboxed systems), <see cref="PingMethod.Udp"/> needs no permission anywhere: a datagram to a port
/// nothing listens on makes the target itself answer with ICMP "port unreachable", which the kernel hands to the
/// sending socket — so the round trip is real (see <see cref="SendUdpAsync"/>).
/// </summary>
public static class IcmpPinger
{
    public readonly record struct PingResult(
        bool Success,
        long RoundtripMs,
        IPAddress? Address,
        int Ttl,            // -1 when unknown (datagram sockets don't expose the reply TTL)
        string? Error,
        bool PermissionDenied,  // no probe can work here: ICMP isn't permitted and (Auto) the UDP fallback failed too — Error says why
        PingMethod Method = PingMethod.Icmp,    // what actually went out: Icmp, or Udp (Auto's fallback)
        IcmpApplied Applied = IcmpApplied.None, // which requested options the path applied (the IcmpProbeOptions overload)
        int Mtu = 0,                            // Error == PacketTooBig: the MTU the error reported (0 = not known)
        string? Note = null);                   // why a requested option couldn't be applied here (the options overload)

    /// <summary>The error text of a probe bigger than the path allows with Don't fragment set (ICMP "fragmentation
    /// needed" / ICMPv6 "packet too big", or this computer's own link MTU). Windows reports it as the IPStatus name
    /// "PacketTooBig".</summary>
    public const string PacketTooBig = "Packet too big";

    /// <summary>Largest payload every path accepts (managed Ping's ceiling; Windows' ping -l allows the same).</summary>
    public const int MaxPayloadSize = 65500;

    /// <summary>The UDP probe's destination port: traceroute's base port, which nothing listens on, so the target replies
    /// with ICMP "port unreachable" — the answer the probe times.</summary>
    public const int DefaultUdpPort = 33434;

    // Auto: ICMP was refused once in this process, so later Auto probes go straight to UDP instead of failing first.
    // Per family: on Linux IPv4 can have the ping socket while IPv6 has only an unusable ping utility (see SendIcmpAsync).
    private static volatile bool _icmpDenied4, _icmpDenied6;

    /// <summary>A UDP probe can trace (TTL &gt; 0) only where an unprivileged socket gets the routers' ICMP errors: Linux /
    /// Android through IP_RECVERR (as tracepath does). Elsewhere ICMP traceroute needs no privileges anyway.</summary>
    public static bool UdpCanTrace => OperatingSystem.IsLinux() || OperatingSystem.IsAndroid();

    // 32-byte payload, like classic ping ('a'..).
    private static readonly byte[] DefaultPayload =
        Enumerable.Range(0, 32).Select(i => (byte)('a' + (i % 23))).ToArray();

    public const int PayloadSize = 32;

    // What the classic overload sends (custom: false ignores the size; the managed fallback's loopback checks use it).
    private static readonly IcmpProbeOptions Classic = new(PayloadSize, 0, false);

    // The same 'a'..'w' pattern at any size (Windows ping's own); the last one is kept, a run sends one size.
    private static byte[] _lastPayload = DefaultPayload;
    private static byte[] Payload(int size)
    {
        if (size == PayloadSize) return DefaultPayload;
        var last = _lastPayload;
        if (last.Length == size) return last;
        var p = new byte[size];
        for (int i = 0; i < p.Length; i++) p[i] = (byte)('a' + (i % 23));
        _lastPayload = p;
        return p;
    }

    // Managed Ping refused a custom payload once (it runs the system ping utility here): later probes don't try again.
    private static volatile bool _customSizeRefused;

    private const string SizeNote = "This system's ping can't send a custom size without raw-socket rights (it uses the ping program), so 32 bytes were sent.";
    private const string Df6Note = "Don't fragment is an IPv4 flag: over IPv6 routers never split packets (they answer \"packet too big\"), but this system may split one bigger than its own link MTU.";
    private const string DfSocketNote = "Don't fragment couldn't be set on this system's socket, so packets may be split.";

    private static int _seq;

    public static async Task<IPAddress> ResolveAsync(string host, CancellationToken token)
    {
        if (IPAddress.TryParse(host, out var ip)) return ip;
        var addrs = await Dns.GetHostAddressesAsync(AsciiHost(host), token);
        // Prefer IPv4, as ping does.
        return addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
               ?? addrs.FirstOrDefault()
               ?? throw new SocketException((int)SocketError.HostNotFound);
    }

    /// <summary>Punycode form of an internationalized (non-ASCII) host name; anything else comes back unchanged.
    /// Windows' resolver converts IDNs itself, but getaddrinfo on Linux/Android/macOS gets the raw UTF-8 and fails
    /// ("Name or service not known" for bücher.com).</summary>
    public static string AsciiHost(string host)
    {
        foreach (char c in host)
        {
            if (c <= 0x7F) continue;
            try { return new System.Globalization.IdnMapping().GetAscii(host); }
            catch (ArgumentException) { return host; }   // not a valid IDN: let the resolver report it
        }
        return host;
    }

    /// <summary>The classic probe (Monitor, Scanner, Doctor, traceroute, MTR): 32 bytes, the system TTL or
    /// <paramref name="ttl"/> (then with Don't fragment on the managed path, as tracert does).</summary>
    public static Task<PingResult> SendAsync(IPAddress addr, int timeoutMs, CancellationToken token, int ttl = 0,
                                             PingMethod method = PingMethod.Auto, int udpPort = DefaultUdpPort)
        => SendCoreAsync(addr, timeoutMs, new IcmpProbeOptions(PayloadSize, ttl, ttl > 0), custom: false, token, method, udpPort);

    /// <summary>
    /// A probe with the Ping tab's packet settings: payload size, TTL and Don't fragment (clamped to what every path
    /// accepts). Same fallbacks as the classic overload. Where the path that sends it can't apply a setting (the system
    /// ping utility sends only its own 32 bytes; IPv6 has no DF flag) the probe still goes out, without it:
    /// <see cref="PingResult.Applied"/> lacks it and <see cref="PingResult.Note"/> says why. A packet too big for the
    /// path with DF set fails with <see cref="PacketTooBig"/> ("PacketTooBig" on Windows) and, where known, the MTU.
    /// </summary>
    public static Task<PingResult> SendAsync(IPAddress addr, int timeoutMs, IcmpProbeOptions options, CancellationToken token,
                                             PingMethod method = PingMethod.Auto, int udpPort = DefaultUdpPort)
        => SendCoreAsync(addr, timeoutMs,
                         options with { PayloadSize = Math.Clamp(options.PayloadSize, 0, MaxPayloadSize), Ttl = Math.Clamp(options.Ttl, 0, 255) },
                         custom: true, token, method, udpPort);

    /// <summary>True once this process has seen that managed Ping can't send a custom payload size here (it runs the
    /// system ping utility: no raw-socket rights); such probes go out with the default 32 bytes.</summary>
    public static bool CustomSizeUnavailable => _customSizeRefused;

    // custom: the options overload. False keeps every path exactly as the classic probe always was.
    private static async Task<PingResult> SendCoreAsync(IPAddress addr, int timeoutMs, IcmpProbeOptions o, bool custom,
                                                        CancellationToken token, PingMethod method, int udpPort)
    {
        if (method == PingMethod.Udp) return await SendUdpAsync(addr, udpPort, timeoutMs, o, custom, token);

        // A TTL-limited UDP probe can only be timed where routers' "time exceeded" reaches the socket (a trace); the
        // Ping tab's TTL is a plain setting, its UDP probe still gets the target's answer.
        bool udpUsable = custom || o.Ttl == 0 || UdpCanTrace;
        bool v6 = addr.AddressFamily == AddressFamily.InterNetworkV6;
        if (method == PingMethod.Auto && (v6 ? _icmpDenied6 : _icmpDenied4) && udpUsable)
            return Fallback(await SendUdpAsync(addr, udpPort, timeoutMs, o, custom, token));

        var r = await SendIcmpAsync(addr, timeoutMs, o, custom, token);
        if (method == PingMethod.Auto && r.PermissionDenied && udpUsable)
        {
            if (v6) _icmpDenied6 = true; else _icmpDenied4 = true;
            return Fallback(await SendUdpAsync(addr, udpPort, timeoutMs, o, custom, token));
        }
        return r;

        // The fallback can't work either (UDP refused, no such address family, a bug): the run ends with both reasons,
        // not a bare socket message that doesn't say ICMP was the first thing that failed.
        static PingResult Fallback(PingResult u)
            => u.PermissionDenied ? u with { Error = $"ICMP isn't permitted here, and the UDP fallback failed: {u.Error}" } : u;
    }

    private static async Task<PingResult> SendIcmpAsync(IPAddress addr, int timeoutMs, IcmpProbeOptions o, bool custom, CancellationToken token)
    {
        // Windows: managed Ping is privilege-free (IcmpSendEcho) and gives us the reply TTL. macOS goes the datagram way
        // below, like iOS and Linux: there managed Ping runs /sbin/ping, a process per probe (an MTR started ~20 a second, a
        // sweep hundreds), and the Mac App Store sandbox would have to allow the child process. Managed Ping stays the
        // fallback where the socket is refused.
        if (OperatingSystem.IsWindows())
            return await SendManagedAsync(addr, timeoutMs, o, custom, token);

        if (addr.AddressFamily != AddressFamily.InterNetwork)
        {
            // Linux/Android IPv6: the ICMPv6 datagram ping socket first — net.ipv4.ping_group_range governs it just as
            // it does IPv4's, and Android opens both to every app. Managed Ping's own fallback runs the system ping
            // utility, a process per probe: ~4-9 ms of CPU each against ~0.5 ms on the socket (round-5 measurement,
            // as nobody in a network namespace), and MTR to an IPv6 host sends up to ~30 probes a second.
            if (Datagram6Usable())
            {
                var r6 = await SendDatagramAsync(addr, timeoutMs, o, custom, token);
                if (!r6.PermissionDenied) return r6;
            }
            // No ICMPv6 ping socket here: managed Ping — a raw socket when privileged, else the system ping utility.
            // Where neither works it reports every probe as TimedOut, so settle once, with a loopback ping, whether it
            // can; if not, that's a permission result (the hint, Auto's UDP fallback).
            if (_managedFallback6 == 0)
                _managedFallback6 = (await SendManagedAsync(IPAddress.IPv6Loopback, 1000, Classic, false, token)).Success ? 1 : -1;
            return _managedFallback6 > 0 ? await SendManagedAsync(addr, timeoutMs, o, custom, token)
                : new PingResult(false, 0, null, -1, "ICMPv6 isn't permitted for this user", true);
        }

        var r = await SendDatagramAsync(addr, timeoutMs, o, custom, token);
        if (!r.PermissionDenied) return r;

        // The ping socket needs the caller's gid in net.ipv4.ping_group_range. Where that's off (the kernel default
        // "1 0": non-systemd distros, minimal containers) it's refused even for root, so the "launch with sudo" hint
        // could never work. Managed Ping still can: a raw socket when privileged (sudo / CAP_NET_RAW), else the
        // system ping utility (setuid / file capability). Whether it can is settled once with a loopback ping —
        // an unprivileged utility fails instantly and Ping reports that as TimedOut, which must not replace the
        // permission result + hint with an endless "Request timeout".
        if (_managedFallback == 0)
            _managedFallback = (await SendManagedAsync(IPAddress.Loopback, 1000, Classic, false, token)).Success ? 1 : -1;
        return _managedFallback > 0 ? await SendManagedAsync(addr, timeoutMs, o, custom, token) : r;
    }

    private static int _managedFallback;   // Linux with the ping socket refused: 0 = untested, 1 = managed Ping works, -1 = not
    private static int _managedFallback6;  // the same for IPv6 on Linux/Android, when its ping socket is refused
    private static int _datagram6;         // Linux/Android: 0 = untested, 1 = an ICMPv6 ping socket opens, -1 = it doesn't

    // Settled once, like the managed fallback: the ping-group check happens when the socket is created (EACCES), and a
    // kernel without ICMPv6 ping sockets refuses it with another error — either way managed Ping is the way then.
    private static bool Datagram6Usable()
    {
        if (_datagram6 == 0)
        {
            try
            {
                using var probe = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.IcmpV6);
                _datagram6 = 1;
            }
            catch (Exception) { _datagram6 = -1; }
        }
        return _datagram6 > 0;
    }

    private static async Task<PingResult> SendManagedAsync(IPAddress addr, int timeoutMs, IcmpProbeOptions o, bool custom, CancellationToken token)
    {
        bool v6 = addr.AddressFamily == AddressFamily.InterNetworkV6;
        PingOptions? options;
        IcmpApplied applied = IcmpApplied.Size;
        string? note = null;
        if (!custom) options = o.Ttl > 0 ? new PingOptions(o.Ttl, true) : null;   // the classic probe, as it always was
        else
        {
            // PingOptions' own TTL (128) when only DF is asked for: what Windows sends by default anyway.
            options = o.Ttl > 0 || o.DontFragment ? new PingOptions(o.Ttl > 0 ? o.Ttl : 128, o.DontFragment) : null;
            if (o.Ttl > 0) applied |= IcmpApplied.Ttl;
            if (o.DontFragment)
            {
                if (v6) note = Df6Note;   // an IPv4 header flag: Ping applies it to IPv4 only
                else applied |= IcmpApplied.DontFragment;
            }
        }
        // buffer: null = Ping's own default 32-byte payload (the same bytes as DefaultPayload), and it must be that very
        // array: without raw-socket rights (macOS, Linux/Android IPv6 as a normal user) Ping runs the system ping
        // utility, which rejects any other buffer ("Unable to send custom ping payload"). An empty array passes too.
        byte[]? buffer = !custom || o.PayloadSize == PayloadSize ? null
                       : o.PayloadSize == 0 ? Array.Empty<byte>()
                       : _customSizeRefused ? null
                       : Payload(o.PayloadSize);
        if (custom && o.PayloadSize != PayloadSize && o.PayloadSize != 0 && buffer is null)
        {
            applied &= ~IcmpApplied.Size;
            note = SizeNote;
        }

        Ping ping = new();
        try
        {
            var sw = Stopwatch.StartNew();
            PingReply reply;
            try
            {
                reply = await ping.SendPingAsync(addr, TimeSpan.FromMilliseconds(timeoutMs), buffer, options).WaitAsync(token);
            }
            catch (Exception ex) when (buffer is { Length: > 0 } && (ex is PlatformNotSupportedException || ex.InnerException is PlatformNotSupportedException))
            {
                // The ping utility path: it sends only its own payload. Settled for the process; this probe goes out
                // again with the default 32 bytes, the note says so.
                _customSizeRefused = true;
                applied &= ~IcmpApplied.Size;
                note = SizeNote;
                ping.Dispose();
                ping = new Ping();
                sw.Restart();
                reply = await ping.SendPingAsync(addr, TimeSpan.FromMilliseconds(timeoutMs), null, options).WaitAsync(token);
            }

            bool ok = reply.Status == IPStatus.Success;
            // Windows fills RoundtripTime only on Success (0 for TtlExpired etc.), so time the other
            // replies ourselves — otherwise every intermediate traceroute hop reads "0 ms".
            long rtt = ok ? reply.RoundtripTime : sw.ElapsedMilliseconds;
            return new PingResult(ok, rtt, reply.Address ?? addr,
                reply.Options?.Ttl ?? -1, ok ? null : reply.Status.ToString(), false, PingMethod.Icmp, applied, 0, note);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            var e = ex is PingException pe && pe.InnerException != null ? pe.InnerException : ex;
            bool perm = IsPermissionError(e);
            return new PingResult(false, 0, null, -1, e.Message, perm, PingMethod.Icmp, applied, 0, note);
        }
        finally
        {
            ping.Dispose();
        }
    }

    private static async Task<PingResult> SendDatagramAsync(IPAddress addr, int timeoutMs, IcmpProbeOptions o, bool custom, CancellationToken token)
    {
        Socket? sock = null;
        IcmpApplied applied = IcmpApplied.Size;   // the packet is built here: any size goes out as asked
        string? note = null;
        try
        {
            bool v6 = addr.AddressFamily == AddressFamily.InterNetworkV6;
            sock = new Socket(addr.AddressFamily, SocketType.Dgram, v6 ? ProtocolType.IcmpV6 : ProtocolType.Icmp);
            bool df = custom && o.DontFragment;
            if (o.Ttl > 0)
            {
                sock.Ttl = (short)o.Ttl;   // IPv6: the hop limit
                applied |= IcmpApplied.Ttl;
            }
            if (df)
            {
                if (TrySetDontFragment(sock)) applied |= IcmpApplied.DontFragment;
                else note = DfSocketNote;
            }
            bool recvErr = false;
            // Traceroute: the kernel drops ICMP "time exceeded" for a ping socket unless IP_RECVERR (IPv6:
            // IPV6_RECVERR) is set — every hop would just time out. With it, the pending receive fails and the
            // router's reply waits on the socket's error queue (see ReadQueuedError). With DF, a router's
            // "fragmentation needed" (ICMPv6 "packet too big") and its MTU arrive the same way.
            if ((o.Ttl > 0 || df) && (OperatingSystem.IsLinux() || OperatingSystem.IsAndroid()))
            {
                try { sock.SetRawSocketOption(v6 ? SOL_IPV6 : SOL_IP, v6 ? IPV6_RECVERR : IP_RECVERR, BitConverter.GetBytes(1)); recvErr = true; }
                catch (SocketException) { }
            }

            var ep = new IPEndPoint(addr, 0);
            // Linux / Android: the kernel replaces the identifier with the socket's own and delivers only that socket's
            // replies. iOS / macOS send it as it is and deliver every ICMP message to every ICMP socket: the replies are
            // matched here (identifier, sequence, source).
            bool matchIds = !OperatingSystem.IsLinux() && !OperatingSystem.IsAndroid();
            ushort id = (ushort)(Environment.ProcessId & 0xFFFF);
            ushort seq = (ushort)(Interlocked.Increment(ref _seq) & 0xFFFF);
            byte[] payload = custom ? Payload(o.PayloadSize) : DefaultPayload;
            // Echo request: ICMP type 8, ICMPv6 type 128 (whose checksum covers a pseudo-header: the kernel fills it in).
            byte[] packet = BuildEchoRequest(v6 ? (byte)128 : (byte)8, id, seq, payload);

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeoutCts.CancelAfter(timeoutMs);

            var sw = Stopwatch.StartNew();
            try
            {
                await sock.SendToAsync(packet, SocketFlags.None, ep, timeoutCts.Token);
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.MessageSize)
            {
                // DF set and bigger than this computer's own link MTU: refused before it left (EMSGSIZE); the error
                // queue holds that MTU.
                return Result(false, sw.ElapsedMilliseconds, null, PacketTooBig, recvErr ? ReadQueuedError(sock).Info : 0);
            }

            var buffer = new byte[Math.Max(1024, payload.Length + 8 + 128)];   // the reply echoes the payload back
            while (true)
            {
                SocketReceiveFromResult r;
                try
                {
                    r = await sock.ReceiveFromAsync(buffer, SocketFlags.None, ep, timeoutCts.Token);
                }
                catch (SocketException ex) when (recvErr)
                {
                    // An ICMP error for our probe (IP_RECVERR) fails the pending receive with its errno
                    // (EHOSTUNREACH for "time exceeded", ENETUNREACH/ECONNREFUSED/… for the unreachable codes,
                    // EMSGSIZE for "fragmentation needed").
                    long errElapsed = sw.ElapsedMilliseconds;
                    var q = ReadQueuedError(sock);
                    if (q.TooBig) return Result(false, errElapsed, q.From, PacketTooBig, q.Info);
                    if (q.Type < 0) throw;                      // not an ICMP error: a real socket failure
                    if (q.Type is 4 or 5) continue;             // source quench / redirect: the probe goes on
                    return Result(false, errElapsed, q.From,
                        q.Type == 11 ? "TTL expired" : q.Type == 3 ? "Destination unreachable" : ex.Message);
                }
                long elapsed = sw.ElapsedMilliseconds;
                int len = r.ReceivedBytes;
                if (len < 1) continue;

                // Linux / Android: the payload starts at the ICMP header. iOS and macOS hand an IPv4 ping socket the whole
                // packet, IP header first: skip it, or every reply reads as type 0x45 and the probe times out.
                int at = 0;
                if (!v6 && (buffer[0] >> 4) == 4 && len > (buffer[0] & 0xF) * 4) at = (buffer[0] & 0xF) * 4;
                byte type = buffer[at];
                var from = (r.RemoteEndPoint as IPEndPoint)?.Address ?? addr;

                if (type == (v6 ? 129 : 0))   // echo reply
                {
                    // iOS / macOS: the socket gets EVERY echo reply that reaches this device, not only its own probe's
                    // (Linux and Android match replies to the socket by identifier). Taking the first one ended a probe on
                    // another probe's reply: a powered-off host read as up while a monitored neighbour answered, MTR cut
                    // the path at a silent hop. Darwin keeps the identifier as sent: identifier, sequence and source.
                    if (matchIds && !(QuotesProbe(buffer, at + 4, len, id, seq) && SameAddress(from, addr))) continue;
                    return Result(true, elapsed, from, null, ttl: at > 0 ? buffer[8] : -1);   // Darwin: the TTL is in the IPv4 header
                }
                // An ICMP error quotes the start of the probe it is about: the probe's IP header (IPv6: 40 bytes), then its
                // echo header with the identifier and sequence. On iOS / macOS it arrives as an ordinary datagram, and
                // other probes' errors too.
                int inner = at + 8 + (v6 ? 40 : len > at + 8 ? (buffer[at + 8] & 0xF) * 4 : 0);
                if (matchIds && !QuotesProbe(buffer, inner + 4, len, id, seq)) continue;
                if (v6 ? type == 3 : type == 11) return Result(false, elapsed, from, "TTL expired");   // time exceeded
                if (v6 ? type == 2 : type == 3 && len > at + 1 && buffer[at + 1] == 4)                 // packet too big / fragmentation needed
                    return Result(false, elapsed, from, PacketTooBig, v6 ? ReadMtu(buffer, at + 4, len, 4) : ReadMtu(buffer, at + 6, len, 2));
                if (v6 ? type == 1 : type == 3) return Result(false, elapsed, from, "Destination unreachable");
                // anything else: ignore and keep waiting until the deadline fires the token
            }
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        {
            return Result(false, timeoutMs, null, "Request timed out");
        }
        catch (OperationCanceledException) { throw; }
        catch (SocketException ex) when (IsPermissionError(ex))
        {
            return new PingResult(false, 0, null, -1, ex.Message, true, PingMethod.Icmp, applied, 0, note);
        }
        catch (Exception ex)
        {
            return Result(false, 0, null, ex.Message);
        }
        finally
        {
            sock?.Dispose();
        }

        PingResult Result(bool ok, long ms, IPAddress? from, string? error, int mtu = 0, int ttl = -1)
            => new(ok, ms, from, ttl, error, false, PingMethod.Icmp, applied, mtu, note);
    }

    // True when the 4 bytes at off are this probe's identifier and sequence (big-endian, as BuildEchoRequest writes them).
    private static bool QuotesProbe(byte[] b, int off, int length, ushort id, ushort seq)
        => off >= 0 && off + 4 <= length
           && b[off] == (byte)(id >> 8) && b[off + 1] == (byte)id
           && b[off + 2] == (byte)(seq >> 8) && b[off + 3] == (byte)seq;

    // The MTU an ICMP "fragmentation needed" (16 bits at off) or ICMPv6 "packet too big" (32 bits) reports; 0 if cut off.
    private static int ReadMtu(byte[] b, int off, int length, int size)
    {
        if (off < 0 || off + size > length) return 0;
        long v = 0;
        for (int i = 0; i < size; i++) v = (v << 8) | b[off + i];
        return v is > 0 and <= int.MaxValue ? (int)v : 0;
    }

    // ---------- UDP datagram probe: no permission needed on any OS ----------
    // A datagram to a port nothing listens on (DefaultUdpPort) makes the target answer with ICMP "port unreachable".
    // On a CONNECTED UDP socket the kernel reports that to the sender — ECONNREFUSED on Linux / macOS / Android,
    // WSAECONNRESET on Windows — so its arrival time is a real round trip. A reply from a service on that port counts
    // as "up" just the same. Silence means down, or UDP filtered on the way (the honest limit of this method). With a
    // TTL on Linux / Android, IP_RECVERR also hands over the routers' "time exceeded": a traceroute, like tracepath.
    // The options overload's size, TTL and DF apply here too (the datagram is the same size as the echo it replaces).
    private static async Task<PingResult> SendUdpAsync(IPAddress addr, int port, int timeoutMs, IcmpProbeOptions o, bool custom, CancellationToken token)
    {
        Socket? sock = null;
        IcmpApplied applied = IcmpApplied.Size;
        string? note = null;
        try
        {
            sock = new Socket(addr.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            if (o.Ttl > 0)
            {
                sock.Ttl = (short)o.Ttl;   // IPv6: the hop limit
                applied |= IcmpApplied.Ttl;
            }
            if (custom && o.DontFragment)
            {
                if (TrySetDontFragment(sock)) applied |= IcmpApplied.DontFragment;
                else note = DfSocketNote;
            }
            // Linux / Android: with IP_RECVERR every ICMP error for the probe reaches the socket, with the sender's
            // address — the routers' "time exceeded" for a trace, and a router's "host unreachable" (reported fast,
            // where a plain connected socket only learns of "port unreachable" and would wait out the timeout).
            bool recvErr = false;
            if (UdpCanTrace)
            {
                bool v6 = addr.AddressFamily == AddressFamily.InterNetworkV6;
                try { sock.SetRawSocketOption(v6 ? SOL_IPV6 : SOL_IP, v6 ? IPV6_RECVERR : IP_RECVERR, BitConverter.GetBytes(1)); recvErr = true; }
                catch (SocketException) { }
            }

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeoutCts.CancelAfter(timeoutMs);

            // Connecting a UDP socket sends nothing; it binds the flow, so ICMP errors for it reach this socket.
            await sock.ConnectAsync(new IPEndPoint(addr, Math.Clamp(port, 1, 65535)), timeoutCts.Token);
            byte[] payload = custom ? Payload(o.PayloadSize) : DefaultPayload;
            var sw = Stopwatch.StartNew();
            try
            {
                await sock.SendAsync(payload, SocketFlags.None, timeoutCts.Token);
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.MessageSize)
            {
                // DF set and bigger than this computer's own link MTU (Linux queues that MTU)
                return Result(false, sw.ElapsedMilliseconds, null, PacketTooBig, recvErr ? ReadQueuedError(sock).Info : 0);
            }

            var buffer = new byte[2048];
            while (true)
            {
                try
                {
                    await sock.ReceiveAsync(buffer, SocketFlags.None, timeoutCts.Token);
                    return Result(true, sw.ElapsedMilliseconds, addr, null);   // a service answered
                }
                catch (SocketException ex)
                {
                    long elapsed = sw.ElapsedMilliseconds;
                    if (recvErr)
                    {
                        var q = ReadQueuedError(sock);
                        if (q.TooBig) return Result(false, elapsed, q.From, PacketTooBig, q.Info);
                        if (q.Type == 11) return Result(false, elapsed, q.From, "TTL expired");
                        if (q.Type is 4 or 5) continue;   // source quench / redirect: the probe goes on
                        // "port unreachable" proves the target is up only when the target sent it; from anyone else
                        // it's a firewall on the way rejecting the probe (iptables REJECT answers from its own address)
                        if (q.Type == 3 && q.Code == 3)
                            return q.From is null || SameAddress(q.From, addr)
                                ? Result(true, elapsed, addr, null)
                                : Result(false, elapsed, q.From, "Destination port unreachable");
                        if (q.Type == 3) return Result(false, elapsed, q.From, "Destination unreachable");
                        // nothing queued: classify by the error itself
                    }
                    return ex.SocketErrorCode switch
                    {
                        // the target's "port unreachable": it is up, and this is its round trip
                        SocketError.ConnectionRefused or SocketError.ConnectionReset => Result(true, elapsed, addr, null),
                        SocketError.HostUnreachable or SocketError.NetworkUnreachable => Result(false, elapsed, null, "Destination unreachable"),
                        _ => Result(false, elapsed, null, ex.Message),
                    };
                }
            }
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        {
            return Result(false, timeoutMs, null, "Request timed out");
        }
        catch (OperationCanceledException) { throw; }
        catch (SocketException ex) when (!IsUdpHardError(ex.SocketErrorCode))
        {
            // a network condition for this probe (no route right now, interface down, out of buffers): the next may get through
            return Result(false, 0, null, ex.Message);
        }
        catch (Exception ex)
        {
            // UDP can't work here at all (the socket or the send refused, no such address family, a target that can't be
            // sent to) or something broke: PermissionDenied ends the run with this error instead of repeating it per probe.
            return new PingResult(false, 0, null, -1, ex is SocketException ? ex.Message : $"{ex.GetType().Name}: {ex.Message}",
                                  true, PingMethod.Udp, applied, 0, note);
        }
        finally
        {
            sock?.Dispose();
        }

        PingResult Result(bool ok, long ms, IPAddress? from, string? error, int mtu = 0)
            => new(ok, ms, from, -1, error, false, PingMethod.Udp, applied, mtu, note);
    }

    // Don't fragment on a datagram socket: IPv4's DF bit (IP_MTU_DISCOVER = DO on Linux / Android); for IPv6, which has
    // no such bit, IPV6_DONTFRAG (+ IPV6_MTU_DISCOVER = DO on Linux) stops this computer splitting the packet itself.
    private static bool TrySetDontFragment(Socket s)
    {
        try
        {
            if (s.AddressFamily != AddressFamily.InterNetworkV6)
            {
                s.DontFragment = true;
                return true;
            }
            if (OperatingSystem.IsWindows())
            {
                s.SetSocketOption(SocketOptionLevel.IPv6, (SocketOptionName)14, 1);   // IPV6_DONTFRAG
                return true;
            }
            if (OperatingSystem.IsLinux() || OperatingSystem.IsAndroid())
            {
                s.SetRawSocketOption(SOL_IPV6, IPV6_MTU_DISCOVER, BitConverter.GetBytes(IP_PMTUDISC_DO));
                s.SetRawSocketOption(SOL_IPV6, IPV6_DONTFRAG, BitConverter.GetBytes(1));
                return true;
            }
            if (OperatingSystem.IsMacOS() || OperatingSystem.IsIOS())
            {
                s.SetRawSocketOption(IPPROTO_IPV6_BSD, IPV6_DONTFRAG, BitConverter.GetBytes(1));
                return true;
            }
        }
        catch (Exception) { }
        return false;
    }

    // Socket errors that no later probe can get past: the environment (or this target) rules UDP out.
    private static bool IsUdpHardError(SocketError e) => e is SocketError.AccessDenied
        or SocketError.AddressFamilyNotSupported or SocketError.ProtocolFamilyNotSupported or SocketError.ProtocolNotSupported
        or SocketError.ProtocolType or SocketError.ProtocolOption or SocketError.SocketNotSupported
        or SocketError.OperationNotSupported or SocketError.AddressNotAvailable or SocketError.InvalidArgument or SocketError.Fault;

    // Same host, ignoring an IPv6 scope id (the error queue's offender address carries none).
    private static bool SameAddress(IPAddress a, IPAddress b)
        => a.AddressFamily == b.AddressFamily && a.GetAddressBytes().AsSpan().SequenceEqual(b.GetAddressBytes());

    // ---------- Linux/Android: ICMP errors on the unprivileged ping socket (traceroute hops) ----------
    // The error queue is only readable with recvmsg(MSG_ERRQUEUE), a flag managed SocketFlags can't express,
    // hence the P/Invoke. Blittable structs + DllImport only (trim/AOT-safe); nint/nuint keep the layout
    // right on both 64-bit and 32-bit (android-arm) ABIs.
    private const int SOL_IP = 0, IP_RECVERR = 11, SOL_IPV6 = 41, IPV6_RECVERR = 25, MSG_DONTWAIT = 0x40, MSG_ERRQUEUE = 0x2000;
    private const int IPV6_MTU_DISCOVER = 23, IPV6_DONTFRAG = 62, IP_PMTUDISC_DO = 2;   // Linux (IPV6_DONTFRAG is 62 on macOS too)
    private const int IPPROTO_IPV6_BSD = 41;
    private const int EMSGSIZE = 90;   // Linux
    private const byte SO_EE_ORIGIN_LOCAL = 1, SO_EE_ORIGIN_ICMP = 2, SO_EE_ORIGIN_ICMP6 = 3;
    private const ushort AF_INET = 2, AF_INET6 = 10;   // Linux values (AddressFamily.InterNetworkV6 is Windows' 23)

    [StructLayout(LayoutKind.Sequential)]
    private struct IoVec { public nint Base; public nuint Len; }

    [StructLayout(LayoutKind.Sequential)]
    private struct MsgHdr
    {
        public nint Name; public uint NameLen;
        public nint Iov; public nuint IovLen;
        public nint Control; public nuint ControlLen;
        public int Flags;
    }

    [DllImport("libc", EntryPoint = "recvmsg")]
    private static extern nint RecvMsg(int sockfd, ref MsgHdr msg, int flags);

    /// <summary>One entry of a socket's error queue. ICMP errors: the sender, type and code in ICMPv4 numbers (ICMPv6
    /// is mapped, see ParseRecvErr) and ee_info (the MTU of a "fragmentation needed" / "packet too big"). This
    /// computer's own errors (origin LOCAL, Type -1): errno and, for EMSGSIZE, the link MTU in Info.</summary>
    private readonly record struct QueuedError(IPAddress? From, int Type, int Code, int Info, int Origin, int Errno)
    {
        public bool TooBig => (Type == 3 && Code == 4) || (Origin == SO_EE_ORIGIN_LOCAL && Errno == EMSGSIZE);
    }

    private static readonly QueuedError NoQueuedError = new(null, -1, -1, 0, 0, 0);

    // The error queued for this socket (consumes it), or NoQueuedError (Type -1) if there is none / it can't be read.
    private static QueuedError ReadQueuedError(Socket sock)
    {
        var data = new byte[256];      // the offending (original) packet — unused, but recvmsg needs room for it
        var control = new byte[256];   // cmsg: sock_extended_err + SO_EE_OFFENDER sockaddr_in
        var iov = new IoVec[1];
        var hData = GCHandle.Alloc(data, GCHandleType.Pinned);
        var hCtl = GCHandle.Alloc(control, GCHandleType.Pinned);
        var hIov = GCHandle.Alloc(iov, GCHandleType.Pinned);
        try
        {
            iov[0] = new IoVec { Base = hData.AddrOfPinnedObject(), Len = (nuint)data.Length };
            var msg = new MsgHdr
            {
                Iov = hIov.AddrOfPinnedObject(), IovLen = 1,
                Control = hCtl.AddrOfPinnedObject(), ControlLen = (nuint)control.Length,
            };
            if (RecvMsg((int)sock.Handle, ref msg, MSG_ERRQUEUE | MSG_DONTWAIT) < 0) return NoQueuedError;
            return ParseRecvErr(control, (int)Math.Min((ulong)msg.ControlLen, (ulong)control.Length));
        }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException or ObjectDisposedException)
        {
            return NoQueuedError;
        }
        finally
        {
            hData.Free(); hCtl.Free(); hIov.Free();
        }
    }

    private static QueuedError ParseRecvErr(byte[] c, int len)
    {
        int word = IntPtr.Size;   // cmsg_len is a size_t and cmsg data is size_t-aligned
        int hdr = word + 8;       // sizeof(struct cmsghdr): size_t len + int level + int type
        for (int off = 0; off + hdr <= len;)
        {
            long cmsgLen = word == 8 ? BitConverter.ToInt64(c, off) : BitConverter.ToInt32(c, off);
            // (len - off, not off + cmsgLen: a length near long.MaxValue wrapped that sum negative and passed)
            if (cmsgLen < hdr || cmsgLen > len - off) break;
            int level = BitConverter.ToInt32(c, off + word);
            int type = BitConverter.ToInt32(c, off + word + 4);
            // struct sock_extended_err { u32 errno; u8 origin, type, code, pad; u32 info, data; } is followed
            // by SO_EE_OFFENDER: the sockaddr_in (sockaddr_in6) of the router that sent the ICMP error.
            bool v4 = level == SOL_IP && type == IP_RECVERR, v6 = level == SOL_IPV6 && type == IPV6_RECVERR;
            if ((v4 || v6) && cmsgLen >= hdr + 16)
            {
                int d = off + hdr;
                int errno = BitConverter.ToInt32(c, d);
                byte origin = c[d + 4];
                int info = BitConverter.ToInt32(c, d + 8);
                // this computer's own error (a DF packet over the link MTU): no sender, errno + MTU only
                if (origin == SO_EE_ORIGIN_LOCAL) return new QueuedError(null, -1, -1, info, origin, errno);
                if (cmsgLen < hdr + 16 + 8) break;
                if (v4)
                {
                    if (origin != SO_EE_ORIGIN_ICMP) break;
                    IPAddress? from = BitConverter.ToUInt16(c, d + 16) == AF_INET
                        ? new IPAddress(c.AsSpan(d + 20, 4)) : null;
                    return new QueuedError(from, c[d + 5], c[d + 6], info, origin, errno);   // ee_type, ee_code
                }
                if (origin != SO_EE_ORIGIN_ICMP6) break;
                // sockaddr_in6: family, port, flowinfo, then the 16-byte address
                IPAddress? from6 = cmsgLen >= hdr + 16 + 24 && BitConverter.ToUInt16(c, d + 16) == AF_INET6
                    ? new IPAddress(c.AsSpan(d + 24, 16)) : null;
                byte t6 = c[d + 5], code6 = c[d + 6];
                // ICMPv6 time exceeded (3) → 11; destination unreachable (1) → 3, its port unreachable (4) → code 3;
                // packet too big (2) → 3/4, ICMPv4's "fragmentation needed"
                var (t, cd) = t6 switch
                {
                    3 => (11, (int)code6),
                    1 => (3, code6 == 4 ? 3 : 1),
                    2 => (3, 4),
                    _ => (256 + t6, (int)code6),   // parameter problem etc.: no ICMPv4 twin, matches nothing
                };
                return new QueuedError(from6, t, cd, info, origin, errno);
            }
            off += (int)((cmsgLen + word - 1) & ~(long)(word - 1));   // CMSG_NXTHDR alignment
        }
        return NoQueuedError;
    }

    private static byte[] BuildEchoRequest(byte type, ushort id, ushort seq, byte[] payload)
    {
        int len = 8 + payload.Length;
        var p = new byte[len];
        p[0] = type;         // echo request: 8 (ICMP), 128 (ICMPv6)
        p[1] = 0;            // code
        p[2] = 0; p[3] = 0;  // checksum (filled below; kernel recomputes for datagram sockets too)
        p[4] = (byte)(id >> 8);  p[5] = (byte)(id & 0xFF);
        p[6] = (byte)(seq >> 8); p[7] = (byte)(seq & 0xFF);
        Array.Copy(payload, 0, p, 8, payload.Length);

        ushort cs = Checksum(p);
        p[2] = (byte)(cs >> 8);
        p[3] = (byte)(cs & 0xFF);
        return p;
    }

    private static ushort Checksum(byte[] data)
    {
        uint sum = 0;
        int i = 0;
        for (; i + 1 < data.Length; i += 2)
            sum += (uint)((data[i] << 8) | data[i + 1]);
        if (i < data.Length)
            sum += (uint)(data[i] << 8);
        while ((sum >> 16) != 0)
            sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }

    private static bool IsPermissionError(Exception e)
    {
        if (e is SocketException s && s.SocketErrorCode == SocketError.AccessDenied)
            return true;

        var msg = e.Message;
        return msg.Contains("Operation not permitted", StringComparison.OrdinalIgnoreCase)
            || msg.Contains("Permission denied", StringComparison.OrdinalIgnoreCase)
            || msg.Contains("Access denied", StringComparison.OrdinalIgnoreCase)
            || msg.Contains("not allowed", StringComparison.OrdinalIgnoreCase);
    }
}
