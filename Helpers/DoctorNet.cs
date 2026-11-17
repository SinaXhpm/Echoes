using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>This device's side: is there a network, through which interface and gateway, a VPN, a system proxy.</summary>
public sealed class DoctorLocal
{
    /// <summary>false: no interface is up with an address; null: this system doesn't let us look (Android).</summary>
    public bool? HasNetwork { get; init; }
    public string? Interface { get; init; }
    public string? Gateway { get; init; }
    /// <summary>An active VPN / tunnel interface ("wg0", "Ethernet 2 (TAP-Windows Adapter V9)").</summary>
    public string? Vpn { get; init; }
    /// <summary>The system proxy browsers use ("127.0.0.1:10809"); the Doctor's checks go direct.</summary>
    public string? SystemProxy { get; set; }
}

/// <summary>One TCP connect attempt. <paramref name="InterfaceFault"/>: it failed for a reason that is the chosen
/// interface's own (no address of that kind, no route from it, a VPN program's redirect a socket tied to it can't follow),
/// which says nothing about the target.</summary>
public sealed record DoctorConnectAttempt(IPAddress Address, int Port, bool Ok, double Ms, string? Error, SocketError? Code,
                                          bool InterfaceFault = false);

/// <summary>The connection check: which address and port took the connection, and what every attempt got.</summary>
public sealed class DoctorConnect
{
    public bool Ok => Address != null;
    public IPAddress? Address { get; set; }
    public int Port { get; set; }
    public double Ms { get; set; }
    public List<DoctorConnectAttempt> Attempts { get; } = new();

    /// <summary>The fastest address that took a connection on <paramref name="port"/>, or null.</summary>
    public DoctorConnectAttempt? Best(int? port)
        => port is int p ? Attempts.Where(a => a.Port == p && a.Ok).OrderBy(a => a.Ms).FirstOrDefault() : null;

    public bool OkOn(int? port) => Best(port) != null;

    /// <summary>The first failed attempt on <paramref name="port"/> (what to say when none worked).</summary>
    public DoctorConnectAttempt? FailureOn(int? port) => port is int p ? Attempts.FirstOrDefault(a => a.Port == p && !a.Ok) : null;
}

/// <summary>The captive-portal check: intercepted (true), the internet answers (false) or no check could be fetched (null);
/// what intercepted it, which check answered as the internet does, and why the ones before it didn't.</summary>
public sealed record DoctorCaptive(bool? Intercepted, string? Detail, string? Answered, IReadOnlyList<string> Errors);

/// <summary>The ping check; <paramref name="Replies"/> holds each probe's round trip in order (null: no reply).</summary>
public sealed record DoctorPing(int Sent, int Received, double? Avg, double? Min, double? Max, bool Denied, bool ViaUdp, string? Error,
                                IReadOnlyList<double?>? Replies = null);

/// <summary>Local network facts, quick TCP connects and ping for the Doctor.</summary>
public static class DoctorNet
{
    // ------------------------------------------------------------------ the interface a run leaves from

    // The tab's Interface choice for the run in progress (DoctorOptions.Interface), set once at its start
    // (DoctorEngine.RunAsync): everything the run awaits sees it, so every probe's socket is tied to that interface and
    // the checks say what its path does. Null: the system's routing table decides, as it always did. An HTTP handler's
    // connection callback may run outside the run's flow, so the handlers capture it when they are made.
    private static readonly AsyncLocal<NetIface?> s_from = new();

    /// <summary>The interface the run in progress sends from; null = wherever the routing table points.</summary>
    public static NetIface? From => s_from.Value;

    /// <summary>Sets <see cref="From"/> for the rest of the calling run (an async method's setting ends with it).</summary>
    internal static void SendFrom(NetIface? via) => s_from.Value = via;

    /// <summary>A socket for one of the run's probes, tied to <paramref name="via"/> (<see cref="From"/> when null). It
    /// throws a <see cref="NetIfaceException"/> saying why when it can't be tied: a probe never goes out another way.</summary>
    public static Socket NewSocket(AddressFamily family, SocketType type, ProtocolType protocol, NetIface? via = null)
    {
        via ??= From;
        var s = new Socket(family, type, protocol);
        if (via is null || via.TryBind(s, out string? note)) return s;
        s.Dispose();
        throw NetIfaceException.From(via, note ?? $"can't send through {via.Name}");
    }

    /// <summary><see cref="Routes"/> for a chosen interface: the kinds of address it has (a link-local IPv6 address
    /// reaches its own link only).</summary>
    public static (bool V4, bool V6) RoutesOf(NetIface via) => (via.V4 is not null, via.V6 is not null);

    /// <summary>An HTTP handler's connections made from <paramref name="via"/>: a name is looked up with the interface's
    /// own DNS servers (<see cref="DoctorDns.ResolveFromAsync"/>), and its addresses are tried in turn.</summary>
    public static Func<SocketsHttpConnectionContext, CancellationToken, ValueTask<Stream>> ConnectFrom(NetIface via)
        => async (ctx, token) =>
        {
            string host = ctx.DnsEndPoint.Host.Trim('[', ']');
            var addrs = IPAddress.TryParse(host, out var literal) ? new[] { literal }
                : await DoctorDns.ResolveFromAsync(via, host, token).ConfigureAwait(false);
            Exception? last = null;
            foreach (var a in DoctorIp.Ordered(addrs))
            {
                if (via.Missing(a) is { } missing)
                {
                    last ??= NetIfaceException.From(via, missing);
                    continue;
                }
                var s = NewSocket(a.AddressFamily, SocketType.Stream, ProtocolType.Tcp, via);
                try
                {
                    s.NoDelay = true;
                    await s.ConnectAsync(new IPEndPoint(a, ctx.DnsEndPoint.Port), token).ConfigureAwait(false);
                    return new NetworkStream(s, ownsSocket: true);
                }
                catch (SocketException e)
                {
                    s.Dispose();
                    last = via.ConnectProblem(e.SocketErrorCode, host) is { } why ? NetIfaceException.From(via, why, e) : e;
                }
                catch
                {
                    s.Dispose();
                    throw;
                }
            }
            throw last ?? new SocketException((int)SocketError.HostNotFound);
        };

    /// <summary><see cref="Local"/> for a chosen interface: its own name, gateway and kind, not the system's first.</summary>
    public static DoctorLocal LocalOf(NetIface via) => new()
    {
        HasNetwork = via.V4 is not null || via.V6 is not null,
        Interface = via.Name,
        Gateway = via.Gateway4?.ToString(),
        Vpn = IsVpn(via.Name, via.Description, NetworkInterfaceType.Unknown) ? via.Name : null,
    };

    // ------------------------------------------------------------------ this device

    /// <summary>Whether the system has a route to the internet over IPv4 and over IPv6. A UDP socket "connected" to a
    /// public address sends nothing: the system only picks the route and the source address, and refuses at once when it
    /// has none (an IPv6-only network has no IPv4 route; a CLAT, where there is one, gives it one).</summary>
    public static (bool V4, bool V6) Routes()
    {
        return (Has(IPAddress.Parse("1.1.1.1")), Has(IPAddress.Parse("2606:4700:4700::1111")));

        static bool Has(IPAddress to)
        {
            try
            {
                using var s = new Socket(to.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                s.Connect(new IPEndPoint(to, 53));
                return s.LocalEndPoint is IPEndPoint { Address: var from } && !from.Equals(IPAddress.Any) && !from.Equals(IPAddress.IPv6Any);
            }
            catch (SocketException) { return false; }
            catch (NotSupportedException) { return false; }   // no IPv6 stack at all
        }
    }

    /// <summary>RFC 7050: the NAT64 /96 prefix of an IPv6-only network, read from its DNS64 answer for ipv4only.arpa. Null
    /// when the system resolver gives no such address (no DNS64, or a prefix that isn't a /96).</summary>
    public static async Task<IPAddress?> Nat64PrefixAsync(Func<string, CancellationToken, Task<IPAddress[]>> resolve, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(2500);
        try
        {
            foreach (var a in await resolve("ipv4only.arpa", cts.Token).ConfigureAwait(false))
                if (DoctorIp.Nat64PrefixOf(a) is { } prefix) return prefix;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
        catch (SocketException) { }
        return null;
    }

    public static DoctorLocal Local()
    {
        NetworkInterface[] all;
        try { all = NetworkInterface.GetAllNetworkInterfaces(); }
        catch { return new DoctorLocal { HasNetwork = null }; }

        string? iface = null, gateway = null, vpn = null;
        bool anyAddress = false;
        foreach (var n in all)
        {
            try
            {
                if (n.OperationalStatus != OperationalStatus.Up || n.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                var props = n.GetIPProperties();
                bool hasAddr = props.UnicastAddresses.Any(u => !IPAddress.IsLoopback(u.Address)
                    && !(u.Address.AddressFamily == AddressFamily.InterNetwork && u.Address.GetAddressBytes() is [169, 254, ..])
                    && !u.Address.IsIPv6LinkLocal);
                if (!hasAddr) continue;
                anyAddress = true;
                // Android has no gateway info (PlatformNotSupportedException): an empty list, so the VPN check below still runs
                List<IPAddress> gws;
                try
                {
                    gws = OperatingSystem.IsAndroid() ? new List<IPAddress>() : props.GatewayAddresses.Select(g => g.Address)
                        .Where(a => !a.Equals(IPAddress.Any) && !a.Equals(IPAddress.IPv6Any)).ToList();
                }
                catch (PlatformNotSupportedException) { gws = new List<IPAddress>(); }
                if (IsVpn(n))
                {
                    vpn ??= n.Name.Equals(n.Description, StringComparison.OrdinalIgnoreCase) || n.Description.Length == 0
                        ? n.Name : $"{n.Name} ({n.Description})";
                    continue;
                }
                if (gws.Count > 0 && gateway == null)
                {
                    iface = n.Name;
                    gateway = (gws.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? gws[0]).ToString();
                }
            }
            catch { /* an interface that vanished meanwhile */ }
        }
        // Android 10+ hides the routing table, and an iPhone's may be hidden too (not tried on one yet): an address
        // without a visible gateway is "can't tell" there, not "none"
        bool? has = !anyAddress ? false
                  : gateway != null || vpn != null ? true
                  : OperatingSystem.IsAndroid() || OperatingSystem.IsIOS() ? null : false;
        return new DoctorLocal { HasNetwork = has, Interface = iface, Gateway = gateway, Vpn = vpn };
    }

    private static readonly string[] VpnWords =
        { "tap-windows", "wintun", "wireguard", "openvpn", "tailscale", "zerotier", "vpn", "warp", "tun", "v2ray", "clash", "sing-box", "hiddify" };

    private static bool IsVpn(NetworkInterface n) => IsVpn(n.Name, n.Description, n.NetworkInterfaceType);

    private static bool IsVpn(string interfaceName, string description, NetworkInterfaceType type)
    {
        string name = interfaceName.ToLowerInvariant(), desc = description.ToLowerInvariant();
        if (desc.Contains("teredo") || desc.Contains("isatap") || desc.Contains("6to4") || name.Contains("teredo")) return false;
        if (type is NetworkInterfaceType.Ppp) return true;
        if (name.StartsWith("tun") || name.StartsWith("wg") || name.StartsWith("utun") || name.StartsWith("ppp")
            || name.StartsWith("tap") || name.StartsWith("ipsec")) return true;
        foreach (var w in VpnWords)
            if (desc.Contains(w) || (w.Length > 3 && name.Contains(w))) return true;
        return type == NetworkInterfaceType.Tunnel;
    }

    /// <summary>The system proxy for web traffic, or null. Reading it can mean a WPAD lookup, so it gets a short budget.</summary>
    public static async Task<string?> SystemProxyAsync(int budgetMs)
    {
        var task = Task.Run(() =>
        {
            try
            {
                var probe = new Uri("https://example.com/");
                var p = HttpClient.DefaultProxy;
                if (p.IsBypassed(probe)) return null;
                var u = p.GetProxy(probe);
                return u == null || u == probe || u.Host.Length == 0 ? null : $"{u.Host}:{u.Port}";
            }
            catch { return null; }
        });
        var done = await Task.WhenAny(task, Task.Delay(budgetMs)).ConfigureAwait(false);
        return done == task ? await task.ConfigureAwait(false) : null;
    }

    // ------------------------------------------------------------------ TCP

    public static async Task<DoctorConnectAttempt> ConnectAsync(IPAddress addr, int port, int timeoutMs, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        var sw = Stopwatch.StartNew();
        try
        {
            using var s = NewSocket(addr.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            s.NoDelay = true;
            await s.ConnectAsync(new IPEndPoint(addr, port), cts.Token).ConfigureAwait(false);
            return new DoctorConnectAttempt(addr, port, true, sw.Elapsed.TotalMilliseconds, null, null);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new DoctorConnectAttempt(addr, port, false, sw.Elapsed.TotalMilliseconds, "timed out", SocketError.TimedOut);
        }
        catch (OperationCanceledException) { throw; }
        catch (SocketException e)
        {
            // from a chosen interface, an error that is the interface's (no route from it, a VPN driver's redirect) says so
            string? fault = From?.ConnectProblem(e.SocketErrorCode, addr.ToString());
            return new DoctorConnectAttempt(addr, port, false, sw.Elapsed.TotalMilliseconds, fault ?? DoctorDns.Short(e), e.SocketErrorCode,
                                            InterfaceFault: fault != null);
        }
        catch (NetIfaceException e)
        {
            return new DoctorConnectAttempt(addr, port, false, sw.Elapsed.TotalMilliseconds, DoctorDns.Short(e), null, InterfaceFault: true);
        }
        catch (Exception e)
        {
            return new DoctorConnectAttempt(addr, port, false, sw.Elapsed.TotalMilliseconds, DoctorDns.Short(e), null);
        }
    }

    /// <summary>
    /// Connects to up to three addresses on every candidate port at once; the first port in <paramref name="ports"/>
    /// that any address accepts wins (443 before 80), and on it the fastest address. IPv4 addresses when there are any
    /// (an IPv6 address failing on a network without IPv6 says nothing about the site), else IPv6.
    /// </summary>
    public static async Task<DoctorConnect> ConnectAllAsync(IReadOnlyList<IPAddress> addrs, IReadOnlyList<int> ports, int timeoutMs,
                                                            CancellationToken ct)
    {
        var v4 = addrs.Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToList();
        var picked = (v4.Count > 0 ? v4 : addrs.ToList()).Take(3).ToList();
        var tasks = new List<Task<DoctorConnectAttempt>>();
        foreach (int port in ports)
            foreach (var a in picked)
                tasks.Add(ConnectAsync(a, port, timeoutMs, ct));
        var results = await Task.WhenAll(tasks).ConfigureAwait(false);
        var c = new DoctorConnect();
        c.Attempts.AddRange(results);
        foreach (int port in ports)
        {
            var best = results.Where(r => r.Port == port && r.Ok).OrderBy(r => r.Ms).FirstOrDefault();
            if (best == null) continue;
            c.Address = best.Address;
            c.Port = port;
            c.Ms = best.Ms;
            break;
        }
        if (!c.Ok) c.Port = ports[0];
        return c;
    }

    // ------------------------------------------------------------------ ping

    public static async Task<DoctorPing> PingAsync(IPAddress addr, int count, CancellationToken ct)
    {
        var rtts = new List<double>();
        var replies = new List<double?>();
        int sent = 0;
        bool udp = false;
        string? error = null;
        for (int i = 0; i < count; i++)
        {
            if (i > 0) await Task.Delay(200, ct).ConfigureAwait(false);
            var r = await IcmpPinger.SendAsync(addr, 1200, ct, via: From).ConfigureAwait(false);
            if (r.PermissionDenied) return new DoctorPing(sent, 0, null, null, null, true, false, r.Error, replies);
            // the chosen interface can't send it (no address of that kind, gone): no probe left, and it says why
            if (r.NotSent) return new DoctorPing(sent, 0, null, null, null, false, false, r.Error, replies);
            sent++;
            udp |= r.Method == PingMethod.Udp;
            if (r.Success) rtts.Add(Math.Max(r.RoundtripMs, 0));
            else error ??= r.Error;
            replies.Add(r.Success ? Math.Max(r.RoundtripMs, 0) : null);
        }
        return rtts.Count == 0
            ? new DoctorPing(sent, 0, null, null, null, false, udp, error, replies)
            : new DoctorPing(sent, rtts.Count, rtts.Average(), rtts.Min(), rtts.Max(), false, udp, error, replies);
    }

    // ------------------------------------------------------------------ captive portal

    /// <summary>
    /// Fetches the connectivity checks over plain HTTP, without a proxy and without following redirects, one after another
    /// (<see cref="Fallback"/>: the next after a head start, or at once when one fails or is intercepted) until one answers
    /// as the internet does: a 204, an empty 200 (a transparent proxy that drops the 204) or the check's own text. A
    /// redirect (to a sign-in page), an HTTP 511 or another page is a captive portal or a transparent proxy speaking for
    /// the internet. An error status is that check's own failure, as Android reads it: a site down, or refusing this
    /// country (a 403), says nothing about a portal. Intercepted is null when no check could be fetched at all.
    /// </summary>
    public static async Task<DoctorCaptive> CaptiveAsync(IReadOnlyList<DoctorCaptiveCheck> checks, int timeoutMs, CancellationToken ct)
    {
        if (checks.Count == 0) return new DoctorCaptive(null, null, null, Array.Empty<string>());
        using var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromMilliseconds(timeoutMs),
        };
        if (From is { } via) handler.ConnectCallback = ConnectFrom(via);
        using var http = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };   // each check has its own deadline
        var caught = new ConcurrentQueue<string>();
        var sources = checks.Select(c => new Fallback.Source<string>(c.Url.Host, async token =>
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, c.Url);
            using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
            int code = (int)resp.StatusCode;
            if (code == 204) return c.Url.Host;
            if (code >= 400 && code != 511) throw new HttpRequestException(null, null, resp.StatusCode);
            if (code == 200)
            {
                string body = (await ReadTextAsync(resp.Content, 4096, token).ConfigureAwait(false)).Trim();
                if (body.Length == 0 || (c.Expect != null && body.Equals(c.Expect, StringComparison.OrdinalIgnoreCase))) return c.Url.Host;
            }
            string? loc = resp.Headers.Location?.ToString();
            caught.Enqueue($"{c.Url.Host} answered HTTP {code}" + (loc != null ? $" → {Trim(loc, 60)}" : ""));
            return null;   // the next check: one that answers as itself means the internet does
        })).ToList();

        // a dead network gets twice the time the checks once had all at once, then what came in decides
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(2 * timeoutMs);
        IReadOnlyList<string> errors = Array.Empty<string>();
        try
        {
            var r = await Fallback.FirstAsync("doctor.captive", sources, budget.Token, TimeSpan.FromSeconds(1),
                                              TimeSpan.FromMilliseconds(timeoutMs)).ConfigureAwait(false);
            if (r.Value != null) return new DoctorCaptive(false, null, r.Value, r.Errors);
            errors = r.Errors;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { errors = new[] { "no answer in time" }; }
        return caught.TryPeek(out var first)
            ? new DoctorCaptive(true, first, null, errors)
            : new DoctorCaptive(null, null, null, errors);
    }

    // The start of a small answer as text (a check's page is a few bytes; a portal's page is cut here).
    private static async Task<string> ReadTextAsync(HttpContent content, int cap, CancellationToken ct)
    {
        await using var stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var buf = new byte[cap];
        int total = 0, n;
        while (total < cap && (n = await stream.ReadAsync(buf.AsMemory(total), ct).ConfigureAwait(false)) > 0) total += n;
        return Encoding.UTF8.GetString(buf, 0, total);
    }

    internal static string Trim(string s, int max) => s.Length > max ? s[..max] + "…" : s;
}
