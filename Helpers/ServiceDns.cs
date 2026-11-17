using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using DnsClient;

namespace Echoes.Helpers;

/// <summary>
/// Name resolution for the web services the tools are built on (WHOIS and RDAP, IP Info, the update check …), never for
/// the hosts a user tests, whose answers the tools must show as the system gets them. On a filtered network the system's
/// resolver answers a blocked name with nothing, or with the filter's own address (10.10.34.x), and every request to the
/// service then fails although the service itself can be reached. So the system is asked first, and when it hasn't
/// answered after a head start, or answered with a filter's or a private address, public DNS-over-HTTPS resolvers at fixed
/// addresses are asked too (<see cref="Fallback"/>); the connection goes to the first usable answer. TLS still checks the
/// service's certificate against its name, so a wrong answer can't stand in for it. On a healthy network the system
/// answers within milliseconds and nothing else is asked.
/// </summary>
public static class ServiceDns
{
    // Long-standing resolvers at fixed addresses (no name to resolve first), several operators.
    private static readonly string[] Resolvers =
    {
        "https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query", "https://94.140.14.14/dns-query",
        "https://208.67.222.222/dns-query", "https://185.222.222.222/dns-query", "https://9.9.9.9/dns-query",
    };

    private static readonly TimeSpan HeadStart = TimeSpan.FromSeconds(1.5);
    private static readonly TimeSpan PerSource = TimeSpan.FromSeconds(6);
    private static readonly TimeSpan PerAddress = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan MaxCacheFor = TimeSpan.FromMinutes(5);

    // DoH answers, for at most their TTL (5 minutes): every request of a service would otherwise ask again. The system's
    // own answers are cached by the system.
    private static readonly ConcurrentDictionary<string, (IPAddress[] Addresses, DateTime Until)> s_cache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>A <see cref="SocketsHttpHandler.ConnectCallback"/> that resolves as described above. A connection to the
    /// system's proxy (another host than the request's) resolves as the system does: a local or private proxy address is
    /// what it should be.</summary>
    public static ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken ct)
        => ConnectAsync(context, null, true, ct);

    /// <summary>The same callback with every connection made from <paramref name="via"/> (the Speed Test over a chosen
    /// interface): an interface that can't reach the server fails with a <see cref="NetIfaceException"/> that says why,
    /// instead of the connection taking the default route. <paramref name="serviceDns"/> false: the name resolves as the
    /// system does (a user's own server, which may be a name only the local network knows).</summary>
    public static Func<SocketsHttpConnectionContext, CancellationToken, ValueTask<Stream>> ConnectFrom(NetIface via, bool serviceDns)
        => (context, ct) => ConnectAsync(context, via, serviceDns, ct);

    /// <summary>The callback for connections that are measured (the Speed Test's): the name resolves as for the others
    /// (as the system does when <paramref name="serviceDns"/> is false), every connection is made from
    /// <paramref name="via"/> when one is given, and the addresses are tried in the answer's order rather than IPv4 first.
    /// When the system answered, that is its own order, so the test takes the path the device's traffic takes: IPv6 on
    /// most dual-stack networks, where IPv4 may go through a carrier's NAT or a tunnel. One callback serves one test, its
    /// clients sharing it (<see cref="MeasuredOrder"/>).</summary>
    public static Func<SocketsHttpConnectionContext, CancellationToken, ValueTask<Stream>> ConnectMeasured(NetIface? via, bool serviceDns)
    {
        var order = new MeasuredOrder();
        return (context, ct) => ConnectAsync(context, via, serviceDns, ct, order);
    }

    private static async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, NetIface? via, bool serviceDns, CancellationToken ct,
                                                        MeasuredOrder? measured = null)
    {
        var endpoint = context.DnsEndPoint;
        bool toProxy = !string.Equals(endpoint.Host, context.InitialRequestMessage.RequestUri?.IdnHost, StringComparison.OrdinalIgnoreCase);
        IPAddress[] addresses = IPAddress.TryParse(endpoint.Host, out var literal) ? new[] { literal }
            : toProxy || !serviceDns ? await Dns.GetHostAddressesAsync(endpoint.Host, ct).ConfigureAwait(false)
            : await ResolveAsync(endpoint.Host, ct).ConfigureAwait(false);
        return await ConnectAsync(addresses, endpoint.Port, ct, via, endpoint.Host, measured).ConfigureAwait(false);
    }

    /// <summary>The addresses to use for <paramref name="host"/>, of <paramref name="family"/> only when given (a lookup
    /// that must go out over IPv4 or IPv6); throws an <see cref="IOException"/> (host not found, with every source's
    /// reason) when no source has a usable one.</summary>
    public static async Task<IPAddress[]> ResolveAsync(string host, CancellationToken ct, AddressFamily? family = null)
    {
        string key = family is { } f ? host + "|" + f : host;
        if (s_cache.TryGetValue(key, out var cached) && cached.Until > DateTime.UtcNow) return cached.Addresses;
        var sources = new List<Fallback.Source<IPAddress[]>>
        {
            new("system", async t =>
            {
                var answer = (await Dns.GetHostAddressesAsync(host, family ?? AddressFamily.Unspecified, t).ConfigureAwait(false))
                    .Where(Usable).ToArray();
                return answer.Length > 0 ? answer : null;   // nothing, or only a filter's / private address
            }),
        };
        foreach (string resolver in Resolvers)
            sources.Add(new(new Uri(resolver).Host, t => ViaDohAsync(resolver, host, family, key, t)));
        // Per name: a blocked one moves to DoH for the session, the others stay with the system.
        var result = await Fallback.FirstAsync("dns:" + key, sources, ct, HeadStart, PerSource).ConfigureAwait(false);
        if (result.Value is { } addresses) return addresses;
        throw new IOException($"{host}: no usable address ({string.Join("; ", result.Errors)})", new SocketException((int)SocketError.HostNotFound));
    }

    private static async Task<IPAddress[]?> ViaDohAsync(string resolver, string host, AddressFamily? family, string key, CancellationToken ct)
    {
        if (!ResolverSpec.TryParse(resolver, out var spec, out _)) return null;
        int ttl = int.MaxValue;
        var found = new List<IPAddress>();
        var types = family switch
        {
            AddressFamily.InterNetwork => new[] { QueryType.A },
            AddressFamily.InterNetworkV6 => new[] { QueryType.AAAA },
            _ => new[] { QueryType.A, QueryType.AAAA },
        };
        foreach (var type in types)
        {
            var result = await SecureDns.QueryAsync(spec, host, type, ct, PerSource).ConfigureAwait(false);
            if (!result.Answered) throw new IOException(result.ShortError ?? result.Error ?? "no answer");
            foreach (var answer in result.OfType(type == QueryType.A ? "A" : "AAAA"))
                if (IPAddress.TryParse(answer.Value, out var ip) && Usable(ip))
                {
                    found.Add(ip);
                    ttl = Math.Min(ttl, answer.Ttl);
                }
            if (found.Count > 0) break;   // IPv4 is enough; AAAA only for a name without it
        }
        if (found.Count == 0) return null;
        var addresses = found.ToArray();
        var keepFor = TimeSpan.FromSeconds(Math.Clamp(ttl, 30, (int)MaxCacheFor.TotalSeconds));
        s_cache[key] = (addresses, DateTime.UtcNow + keepFor);
        return addresses;
    }

    // A service is on the internet: an empty, filter, private or loopback answer is a blocking resolver's. A NAT64 address
    // (64:ff9b::/96) is what an IPv6-only network's DNS64 answers for a name that has IPv4 addresses only (Apple's App
    // Review network is one): the network's translator reaches the IPv4 address in its last 32 bits, so it is as usable as
    // that address (a filter's 10.10.34.x stays one). A network's own NAT64 prefix (64:ff9b:1::/48 among them) isn't
    // special-purpose anyway. A shared address (100.64.0.0/10) is never a service's: only a carrier's or a VPN's inside.
    internal static bool Usable(IPAddress ip)
    {
        if (ip.AddressFamily == AddressFamily.InterNetworkV6
            && ip.GetAddressBytes() is [0, 0x64, 0xFF, 0x9B, 0, 0, 0, 0, 0, 0, 0, 0, var a, var b, var c, var d])
            ip = new IPAddress(new[] { a, b, c, d });
        return Rdap.SpecialPurpose(ip) == null;
    }

    // IPv4 first (some networks' IPv6 drops traffic), each address with its own deadline so one that drops packets doesn't
    // use up the handler's whole connect timeout. A measured connection goes in the order MeasuredOrder gives instead.
    // (via: the interface every attempt leaves from. Only the addresses of a kind it has are tried, and an attempt that
    // can't leave from it ends the connect with the reason: the next address would go the same way.)
    private static async ValueTask<Stream> ConnectAsync(IPAddress[] addresses, int port, CancellationToken ct,
                                                        NetIface? via = null, string? host = null, MeasuredOrder? measured = null)
    {
        if (via is not null && addresses.Length > 0)
        {
            var reachable = addresses.Where(a => via.SourceFor(a) is not null).ToArray();
            if (reachable.Length == 0)
                throw NetIfaceException.From(via, $"{via.Missing(addresses[0])}, so {host ?? addresses[0].ToString()} can't be reached from it");
            addresses = reachable;
        }
        Exception? last = null;
        foreach (var address in measured?.Of(addresses) ?? addresses.OrderBy(a => a.AddressFamily == AddressFamily.InterNetworkV6))
        {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                if (via is not null && !via.TryBind(socket, out string? unbound))
                    throw NetIfaceException.From(via, unbound ?? $"can't connect from {via.Name}");
                using var attempt = CancellationTokenSource.CreateLinkedTokenSource(ct);
                attempt.CancelAfter(PerAddress);
                await socket.ConnectAsync(new IPEndPoint(via?.Scoped(address) ?? address, port), attempt.Token).ConfigureAwait(false);
                measured?.GotThrough(address);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (NetIfaceException)
            {
                socket.Dispose();
                throw;
            }
            catch (SocketException se) when (via?.ConnectProblem(se.SocketErrorCode, host ?? address.ToString()) is { } problem)
            {
                socket.Dispose();
                throw NetIfaceException.From(via!, problem, se);
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                socket.Dispose();
                last = ex;
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }
        throw last ?? new SocketException((int)SocketError.HostNotFound);
    }

    /// <summary>
    /// The order a measured connection tries the addresses in: the answer's, with the two families taking turns (as RFC
    /// 8305 has it), so a family that drops traffic costs one attempt's deadline, never the whole connect timeout. The
    /// family the last connection got through on goes first: on a network whose IPv6 drops traffic only a test's first
    /// connection waits for it, not every stream. Its connections may run at once: the family is a single word.
    /// </summary>
    internal sealed class MeasuredOrder
    {
        private volatile int _family;   // the AddressFamily of the last connection that got through; 0 (Unspecified) before

        public IEnumerable<IPAddress> Of(IReadOnlyList<IPAddress> addresses)
        {
            if (addresses.Count == 0) return addresses;
            var first = (AddressFamily)_family;
            if (!addresses.Any(a => a.AddressFamily == first)) first = addresses[0].AddressFamily;
            var lead = addresses.Where(a => a.AddressFamily == first).ToList();
            var other = addresses.Where(a => a.AddressFamily != first).ToList();
            var order = new List<IPAddress>(addresses.Count);
            for (int i = 0; i < Math.Max(lead.Count, other.Count); i++)
            {
                if (i < lead.Count) order.Add(lead[i]);
                if (i < other.Count) order.Add(other[i]);
            }
            return order;
        }

        public void GotThrough(IPAddress address) => _family = (int)address.AddressFamily;
    }
}
