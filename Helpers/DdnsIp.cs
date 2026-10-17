using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>The address family a dynamic-DNS record follows: an A record gets the public IPv4, an AAAA the IPv6.</summary>
public enum DdnsFamily { V4, V6 }

/// <summary>One public-IP lookup: the address the sources agreed on, or why there is none.</summary>
public sealed class DdnsIpResult
{
    /// <summary>The agreed public address (canonical text), or null.</summary>
    public string? Address { get; init; }
    /// <summary>Why there is no address (empty when there is one). Never names anything secret.</summary>
    public string Error { get; init; } = string.Empty;
    /// <summary>What each asked source said ("Cloudflare 203.0.113.9 · ipify timed out").</summary>
    public string Detail { get; init; } = string.Empty;
    public bool Ok => Address != null;
}

/// <summary>
/// This device's public IP for dynamic DNS. Asked DIRECTLY — never through the Cloudflare account's proxy or the system
/// proxy, which would report their own address — and pinned to the family (an IPv4 lookup only connects over IPv4, an
/// IPv6 one only over IPv6, whatever the host name resolves to). Two independent services are asked first; an address
/// counts only when at least two of them report it (and more than report anything else), so one wrong or hijacked
/// answer can't move a record. A private / reserved address is never accepted.
/// </summary>
public static class DdnsIpDetector
{
    private sealed record Source(string Name, string Url, bool Trace);

    // The first two are asked together; the others only when those two don't agree (or don't answer). Every source is
    // a host NAME: a TLS hello without a server name (https://1.1.1.1/…) is reset by some networks' filters.
    // Cloudflare's trace is reached by name and pinned to the family by the connection itself.
    private static readonly Source[] V4Sources =
    {
        new("Cloudflare", "https://www.cloudflare.com/cdn-cgi/trace", true),
        new("ipify", "https://api.ipify.org/", false),
        new("ident.me", "https://v4.ident.me/", false),
        new("icanhazip", "https://ipv4.icanhazip.com/", false),
    };

    private static readonly Source[] V6Sources =
    {
        new("Cloudflare", "https://www.cloudflare.com/cdn-cgi/trace", true),
        new("ipify", "https://api6.ipify.org/", false),
        new("ident.me", "https://v6.ident.me/", false),
        new("icanhazip", "https://ipv6.icanhazip.com/", false),
    };

    private const int MaxAnswerBytes = 4096;
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(8);

    private static Source[]? _testV4, _testV6;
    private static bool _testPinned;

    /// <summary>
    /// Test hook: stand-in sources (a local mock), loopback http(s) URLs only — nothing else is accepted, so this can't
    /// point the lookup anywhere real. A body is either a bare address or Cloudflare's trace format ("ip=…" lines).
    /// Null restores the real services. <paramref name="pinFamily"/> keeps the real family pinning (an IPv6 lookup then
    /// can't reach a 127.0.0.1 source). Not bound to any UI or setting.
    /// </summary>
    internal static void SetTestSources(IReadOnlyList<string>? v4, IReadOnlyList<string>? v6, bool pinFamily = false)
    {
        _testV4 = v4 is null ? null : ToTestSources(v4);
        _testV6 = v6 is null ? null : ToTestSources(v6);
        _testPinned = pinFamily;
    }

    private static Source[] ToTestSources(IReadOnlyList<string> urls)
    {
        var list = new List<Source>();
        foreach (string url in urls)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || !u.IsLoopback
                || (u.Scheme != Uri.UriSchemeHttp && u.Scheme != Uri.UriSchemeHttps) || u.UserInfo.Length > 0)
                throw new ArgumentException("Test IP sources must be loopback http(s) URLs.");
            list.Add(new Source("test" + (list.Count + 1), url, url.Contains("trace", StringComparison.Ordinal)));
        }
        return list.ToArray();
    }

    /// <summary>The public address of <paramref name="family"/>, cross-checked. Never throws except for <paramref name="ct"/>.</summary>
    public static async Task<DdnsIpResult> DetectAsync(DdnsFamily family, CancellationToken ct)
    {
        Source[]? test = family == DdnsFamily.V4 ? _testV4 : _testV6;
        Source[] sources = test ?? (family == DdnsFamily.V4 ? V4Sources : V6Sources);
        using var http = CreateClient(family, direct: test is null || _testPinned);

        var answers = new List<(Source Src, string? Ip, string Error)>();
        var first = await Task.WhenAll(sources.Take(2).Select(s => AskAsync(http, s, family, ct))).ConfigureAwait(false);
        answers.AddRange(first);
        bool agreeAtOnce = first.Length == 2 && first[0].Ip != null && first[0].Ip == first[1].Ip;
        if (!agreeAtOnce && sources.Length > 2)
            answers.AddRange(await Task.WhenAll(sources.Skip(2).Select(s => AskAsync(http, s, family, ct))).ConfigureAwait(false));
        ct.ThrowIfCancellationRequested();

        string detail = string.Join(" · ", answers.Select(a => a.Src.Name + " " + (a.Ip ?? a.Error)));
        string fam = family == DdnsFamily.V4 ? "IPv4" : "IPv6";
        var votes = answers.Where(a => a.Ip != null).GroupBy(a => a.Ip!).Select(g => (Ip: g.Key, Count: g.Count()))
                           .OrderByDescending(v => v.Count).ToList();

        if (votes.Count == 0)
        {
            string why = string.Join("; ", answers.Select(a => a.Src.Name + ": " + a.Error));
            return new DdnsIpResult
            {
                Detail = detail,
                Error = family == DdnsFamily.V6
                    ? $"Couldn't find a public IPv6 address: no IPv6 service answered (this network may have no IPv6). {why}."
                    : $"Couldn't find your public IPv4 address: no service answered. {why}.",
            };
        }
        if (votes[0].Count >= 2 && (votes.Count == 1 || votes[0].Count > votes[1].Count))
            return new DdnsIpResult { Address = votes[0].Ip, Detail = detail };

        if (votes.Count == 1)
            return new DdnsIpResult
            {
                Detail = detail,
                Error = $"Only one service reported your public {fam} ({votes[0].Ip}); a second one must confirm it before a record changes.",
            };
        return new DdnsIpResult
        {
            Detail = detail,
            Error = $"The IP services disagree about your public {fam} ({string.Join(", ", answers.Where(a => a.Ip != null).Select(a => a.Src.Name + " " + a.Ip))}): nothing was changed.",
        };
    }

    /// <summary>Diagnostics / tests: ask only the first real source (Cloudflare's trace), pinned to the family. One light
    /// request; returns its address or why there is none.</summary>
    internal static async Task<(string? Ip, string Error)> AskCloudflareAsync(DdnsFamily family, CancellationToken ct)
    {
        using var http = CreateClient(family, direct: true);
        var (_, ip, error) = await AskAsync(http, (family == DdnsFamily.V4 ? V4Sources : V6Sources)[0], family, ct).ConfigureAwait(false);
        return (ip, error);
    }

    // A client of its own per lookup: no proxy at all (UseProxy = false also skips the system proxy), no redirects, no
    // cookies, a small answer cap. "direct" pins the connection to the family; the loopback test sources skip that.
    private static HttpClient CreateClient(DdnsFamily family, bool direct)
    {
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(6),
            PooledConnectionLifetime = TimeSpan.FromSeconds(30),
        };
        if (direct) handler.ConnectCallback = (ctx, ct) => ConnectAsync(ctx.DnsEndPoint, family, ct);
        var http = new HttpClient(handler) { Timeout = RequestTimeout, MaxResponseContentBufferSize = MaxAnswerBytes };
        var ver = typeof(DdnsIpDetector).Assembly.GetName().Version;
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"Echoes/{ver?.Major ?? 0}.{ver?.Minor ?? 0}.{ver?.Build ?? 0}");
        return http;
    }

    // Only addresses of the wanted family are tried: an IPv4 lookup that connected over IPv6 (or the reverse) would
    // report the other address.
    private static async ValueTask<Stream> ConnectAsync(DnsEndPoint ep, DdnsFamily family, CancellationToken ct)
    {
        var af = family == DdnsFamily.V4 ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;
        string host = ep.Host.Length > 2 && ep.Host[0] == '[' && ep.Host[^1] == ']' ? ep.Host[1..^1] : ep.Host;
        IPAddress[] addrs = IPAddress.TryParse(host, out var literal)
            ? new[] { literal }
            : await Dns.GetHostAddressesAsync(host, af, ct).ConfigureAwait(false);
        Exception? last = null;
        foreach (var a in addrs)
        {
            if (a.AddressFamily != af) continue;
            var socket = new Socket(af, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await socket.ConnectAsync(new IPEndPoint(a, ep.Port), ct).ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (Exception ex)
            {
                socket.Dispose();
                last = ex;
                if (ct.IsCancellationRequested) throw;
            }
        }
        throw last ?? new SocketException((int)SocketError.HostNotFound);
    }

    private static async Task<(Source Src, string? Ip, string Error)> AskAsync(HttpClient http, Source s, DdnsFamily family, CancellationToken ct)
    {
        try
        {
            using var resp = await http.GetAsync(s.Url, HttpCompletionOption.ResponseContentRead, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return (s, null, $"HTTP {(int)resp.StatusCode}");
            string body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            string text = (s.Trace ? TraceValue(body, "ip") : body).Trim();
            if (text.Length is 0 or > 64 || !IPAddress.TryParse(text, out var ip)) return (s, null, "no address in its answer");
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            var want = family == DdnsFamily.V4 ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;
            if (ip.AddressFamily != want) return (s, null, family == DdnsFamily.V4 ? "answered an IPv6 address" : "answered an IPv4 address");
            if (!IsPublic(ip)) return (s, null, $"answered a private address ({ip})");
            return (s, ip.ToString(), string.Empty);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return (s, null, "timed out"); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { return (s, null, Reason(ex)); }
    }

    private static string Reason(Exception ex)
    {
        for (var e = ex; e != null; e = e.InnerException)
            if (e is SocketException se)
                return se.SocketErrorCode switch
                {
                    SocketError.HostNotFound or SocketError.NoData => "no address for its name",
                    SocketError.NetworkUnreachable or SocketError.HostUnreachable => "unreachable",
                    SocketError.ConnectionRefused => "refused",
                    SocketError.TimedOut => "timed out",
                    _ => "connection failed",
                };
        string msg = ex.InnerException?.Message ?? ex.Message;
        return msg.Length > 80 ? msg[..80] + "…" : msg;
    }

    /// <summary>A "key=value" line of Cloudflare's /cdn-cgi/trace answer ("" when absent).</summary>
    public static string TraceValue(string body, string key)
    {
        foreach (var raw in body.Split('\n'))
        {
            string line = raw.Trim();
            if (line.Length > key.Length && line.StartsWith(key, StringComparison.Ordinal) && line[key.Length] == '=')
                return line[(key.Length + 1)..].Trim();
        }
        return string.Empty;
    }

    /// <summary>The canonical text of an address (lower-case, compressed IPv6), or null when it isn't one.</summary>
    public static string? Canonical(string? text)
    {
        if (string.IsNullOrWhiteSpace(text) || !IPAddress.TryParse(text.Trim(), out var ip)) return null;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        return ip.ToString();
    }

    /// <summary>
    /// A globally routable unicast address. IPv4: not 0/8, 10/8, 100.64/10 (carrier-grade NAT), 127/8, 169.254/16,
    /// 172.16/12, 192.0.0/24, 192.0.2/24, 192.88.99/24, 192.168/16, 198.18/15, 198.51.100/24, 203.0.113/24, 224/4 or
    /// 240/4. IPv6: inside 2000::/3, but not 2001::/23 (Teredo and other protocol ranges), 2001:db8::/32, 2002::/16 (6to4)
    /// or 3fff::/20 (documentation).
    /// </summary>
    public static bool IsPublic(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        byte[] b = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetwork && b.Length == 4)
        {
            return !(b[0] is 0 or 10 or 127 || b[0] >= 224
                     || (b[0] == 100 && (b[1] & 0xC0) == 64)
                     || (b[0] == 169 && b[1] == 254)
                     || (b[0] == 172 && (b[1] & 0xF0) == 16)
                     || (b[0] == 192 && b[1] == 0 && b[2] is 0 or 2)
                     || (b[0] == 192 && b[1] == 88 && b[2] == 99)
                     || (b[0] == 192 && b[1] == 168)
                     || (b[0] == 198 && (b[1] & 0xFE) == 18)
                     || (b[0] == 198 && b[1] == 51 && b[2] == 100)
                     || (b[0] == 203 && b[1] == 0 && b[2] == 113));
        }
        if (ip.AddressFamily == AddressFamily.InterNetworkV6 && b.Length == 16)
        {
            if ((b[0] & 0xE0) != 0x20) return false;                                  // global unicast is 2000::/3
            if (b[0] == 0x20 && b[1] == 0x01 && b[2] < 0x02) return false;            // 2001::/23 (Teredo 2001::/32 …)
            if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8) return false;   // 2001:db8::/32
            if (b[0] == 0x20 && b[1] == 0x02) return false;                           // 2002::/16 (6to4)
            if (b[0] == 0x3F && b[1] == 0xFF && (b[2] & 0xF0) == 0) return false;     // 3fff::/20
            return true;
        }
        return false;
    }
}
