using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
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

/// <summary>One TCP connect attempt.</summary>
public sealed record DoctorConnectAttempt(IPAddress Address, int Port, bool Ok, double Ms, string? Error, SocketError? Code);

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

public sealed record DoctorPing(int Sent, int Received, double? Avg, double? Min, double? Max, bool Denied, bool ViaUdp, string? Error);

/// <summary>Local network facts, quick TCP connects and ping for the Doctor.</summary>
public static class DoctorNet
{
    // ------------------------------------------------------------------ this device

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
        // Android 10+ hides the routing table: an address without a visible gateway is "can't tell" there, not "none"
        bool? has = !anyAddress ? false
                  : gateway != null || vpn != null ? true
                  : OperatingSystem.IsAndroid() ? null : false;
        return new DoctorLocal { HasNetwork = has, Interface = iface, Gateway = gateway, Vpn = vpn };
    }

    private static readonly string[] VpnWords =
        { "tap-windows", "wintun", "wireguard", "openvpn", "tailscale", "zerotier", "vpn", "warp", "tun", "v2ray", "clash", "sing-box", "hiddify" };

    private static bool IsVpn(NetworkInterface n)
    {
        string name = n.Name.ToLowerInvariant(), desc = n.Description.ToLowerInvariant();
        if (desc.Contains("teredo") || desc.Contains("isatap") || desc.Contains("6to4") || name.Contains("teredo")) return false;
        if (n.NetworkInterfaceType is NetworkInterfaceType.Ppp) return true;
        if (name.StartsWith("tun") || name.StartsWith("wg") || name.StartsWith("utun") || name.StartsWith("ppp")
            || name.StartsWith("tap") || name.StartsWith("ipsec")) return true;
        foreach (var w in VpnWords)
            if (desc.Contains(w) || (w.Length > 3 && name.Contains(w))) return true;
        return n.NetworkInterfaceType == NetworkInterfaceType.Tunnel;
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
        using var s = new Socket(addr.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
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
            return new DoctorConnectAttempt(addr, port, false, sw.Elapsed.TotalMilliseconds, DoctorDns.Short(e), e.SocketErrorCode);
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
        int sent = 0;
        bool udp = false;
        string? error = null;
        for (int i = 0; i < count; i++)
        {
            if (i > 0) await Task.Delay(200, ct).ConfigureAwait(false);
            var r = await IcmpPinger.SendAsync(addr, 1200, ct).ConfigureAwait(false);
            if (r.PermissionDenied) return new DoctorPing(sent, 0, null, null, null, true, false, r.Error);
            sent++;
            udp |= r.Method == PingMethod.Udp;
            if (r.Success) rtts.Add(Math.Max(r.RoundtripMs, 0));
            else error ??= r.Error;
        }
        return rtts.Count == 0
            ? new DoctorPing(sent, 0, null, null, null, false, udp, error)
            : new DoctorPing(sent, rtts.Count, rtts.Average(), rtts.Min(), rtts.Max(), false, udp, error);
    }

    // ------------------------------------------------------------------ captive portal

    /// <summary>
    /// Fetches the "generate_204" URLs over plain HTTP, without a proxy and without following redirects. A 204 means
    /// nothing intercepts; any other answer (a redirect to a sign-in page, a 200 with HTML) is a captive portal or a
    /// transparent proxy speaking for the internet. Null when none could be fetched at all.
    /// </summary>
    public static async Task<(bool? Intercepted, string? Detail)> CaptiveAsync(IReadOnlyList<Uri> urls, int timeoutMs, CancellationToken ct)
    {
        if (urls.Count == 0) return (null, null);
        using var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromMilliseconds(timeoutMs),
        };
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(timeoutMs), MaxResponseContentBufferSize = 64 * 1024 };
        async Task<(bool Ok, string? Detail)> Probe(Uri u)
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, u);
                using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                int code = (int)resp.StatusCode;
                if (code == 204) return (true, null);
                string? loc = resp.Headers.Location?.ToString();
                return (false, $"{u.Host} answered HTTP {code}" + (loc != null ? $" → {Trim(loc, 60)}" : ""));
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch { return (false, null); }
        }
        var results = await Task.WhenAll(urls.Select(Probe)).ConfigureAwait(false);
        if (results.Any(r => r.Ok)) return (false, null);
        var intercepted = results.FirstOrDefault(r => r.Detail != null);
        return intercepted.Detail != null ? (true, intercepted.Detail) : (null, null);
    }

    internal static string Trim(string s, int max) => s.Length > max ? s[..max] + "…" : s;
}
