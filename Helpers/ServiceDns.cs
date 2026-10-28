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

    /// <summary>A <see cref="SocketsHttpHandler.ConnectCallback"/> that resolves as described above.</summary>
    public static async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken ct)
    {
        var endpoint = context.DnsEndPoint;
        IPAddress[] addresses = IPAddress.TryParse(endpoint.Host, out var literal) ? new[] { literal }
            : await ResolveAsync(endpoint.Host, ct).ConfigureAwait(false);
        return await ConnectAsync(addresses, endpoint.Port, ct).ConfigureAwait(false);
    }

    /// <summary>The addresses to use for <paramref name="host"/>; throws a host-not-found <see cref="SocketException"/>
    /// (with every source's reason) when no source has a usable one.</summary>
    public static async Task<IPAddress[]> ResolveAsync(string host, CancellationToken ct)
    {
        if (s_cache.TryGetValue(host, out var cached) && cached.Until > DateTime.UtcNow) return cached.Addresses;
        var sources = new List<Fallback.Source<IPAddress[]>>
        {
            new("system", async t =>
            {
                var answer = (await Dns.GetHostAddressesAsync(host, t).ConfigureAwait(false)).Where(Usable).ToArray();
                return answer.Length > 0 ? answer : null;   // nothing, or only a filter's / private address
            }),
        };
        foreach (string resolver in Resolvers)
            sources.Add(new(new Uri(resolver).Host, t => ViaDohAsync(resolver, host, t)));
        // Per name: a blocked one moves to DoH for the session, the others stay with the system.
        var result = await Fallback.FirstAsync("dns:" + host, sources, ct, HeadStart, PerSource).ConfigureAwait(false);
        if (result.Value is { } addresses) return addresses;
        throw new IOException($"{host}: no usable address ({string.Join("; ", result.Errors)})", new SocketException((int)SocketError.HostNotFound));
    }

    private static async Task<IPAddress[]?> ViaDohAsync(string resolver, string host, CancellationToken ct)
    {
        if (!ResolverSpec.TryParse(resolver, out var spec, out _)) return null;
        int ttl = int.MaxValue;
        var found = new List<IPAddress>();
        foreach (var type in new[] { QueryType.A, QueryType.AAAA })
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
        s_cache[host] = (addresses, DateTime.UtcNow + keepFor);
        return addresses;
    }

    // A service is on the internet: an empty, filter, private or loopback answer is a blocking resolver's.
    private static bool Usable(IPAddress ip) => Rdap.SpecialPurpose(ip) == null;

    // IPv4 first (some networks' IPv6 drops traffic), each address with its own deadline so one that drops packets doesn't
    // use up the handler's whole connect timeout.
    private static async ValueTask<Stream> ConnectAsync(IPAddress[] addresses, int port, CancellationToken ct)
    {
        Exception? last = null;
        foreach (var address in addresses.OrderBy(a => a.AddressFamily == AddressFamily.InterNetworkV6))
        {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                using var attempt = CancellationTokenSource.CreateLinkedTokenSource(ct);
                attempt.CancelAfter(PerAddress);
                await socket.ConnectAsync(new IPEndPoint(address, port), attempt.Token).ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
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
}
