using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>One resolver's answer for the target (A + AAAA together).</summary>
public sealed class DoctorDnsAnswer
{
    /// <summary>"System", "1.1.1.1", …</summary>
    public string Source { get; init; } = "";
    /// <summary>A DNS reply came back (any response code).</summary>
    public bool Answered { get; set; }
    /// <summary>0 = NOERROR, 2 = SERVFAIL, 3 = NXDOMAIN, 5 = REFUSED; -1 = no reply.</summary>
    public int Rcode { get; set; } = -1;
    public List<IPAddress> Addresses { get; } = new();
    /// <summary>Why there is no reply ("timed out", "connection reset", …).</summary>
    public string? Error { get; set; }
    public double Ms { get; set; }
    /// <summary>Plain UDP only: two different replies came back to one query — the first one was forged on the way.</summary>
    public bool Injected { get; set; }
    /// <summary>The addresses of the later reply when <see cref="Injected"/>.</summary>
    public List<IPAddress> Later { get; } = new();

    public bool NoSuchName => Answered && Rcode == 3;
    public bool Good => Answered && Rcode is 0 or 3;
}

/// <summary>How a resolver's answer compares with the encrypted (trusted) one.</summary>
public enum DoctorDnsMatch
{
    /// <summary>No reply, or nothing to compare with.</summary>
    Unknown,
    /// <summary>At least one address in common.</summary>
    Same,
    /// <summary>Different addresses, but in the same networks.</summary>
    Similar,
    /// <summary>Different public addresses (a CDN edge, or a server that isn't the site's: checked later).</summary>
    Differs,
    /// <summary>A private / reserved / filter address for a public name.</summary>
    Bogus,
    /// <summary>"No such name" (or no addresses), while the encrypted resolvers know it.</summary>
    Missing,
}

/// <summary>
/// The Doctor's own small resolver: a DNS message builder / reader, plain UDP queries (which also notice a forged reply
/// racing the real one) and DNS-over-HTTPS (RFC 8484) to resolvers addressed by IP, so asking them needs no DNS at all.
/// Independent of the app's other DNS code on purpose: it is a probe, and it wants to see exactly what comes back.
/// </summary>
public static class DoctorDns
{
    public const ushort TypeA = 1, TypeAaaa = 28;
    private const int MaxMessage = 64 * 1024;

    // ------------------------------------------------------------------ messages

    /// <summary>A recursive query for one name and type.</summary>
    public static byte[] BuildQuery(string name, ushort type, ushort id)
    {
        var b = new List<byte>(64)
        {
            (byte)(id >> 8), (byte)id,
            0x01, 0x00,   // RD
            0, 1,         // one question
            0, 0, 0, 0, 0, 0,
        };
        foreach (var label in name.TrimEnd('.').Split('.'))
        {
            byte[] bytes = Encoding.ASCII.GetBytes(label);
            if (bytes.Length is 0 or > 63) throw new ArgumentException($"\"{name}\" isn't a valid DNS name.");
            b.Add((byte)bytes.Length);
            b.AddRange(bytes);
        }
        b.Add(0);
        b.Add((byte)(type >> 8));
        b.Add((byte)type);
        b.Add(0);
        b.Add(1);   // class IN
        return b.ToArray();
    }

    /// <summary>Reads a reply to query <paramref name="id"/>: its response code and the addresses of type
    /// <paramref name="type"/> (CNAMEs are followed by the resolver; only the final records count).</summary>
    public static bool TryParse(ReadOnlySpan<byte> m, ushort id, ushort type, out int rcode, List<IPAddress> addrs)
    {
        rcode = -1;
        if (m.Length < 12) return false;
        if (((m[0] << 8) | m[1]) != id || (m[2] & 0x80) == 0) return false;   // not our reply
        rcode = m[3] & 0x0F;
        int qd = (m[4] << 8) | m[5], an = (m[6] << 8) | m[7];
        int p = 12;
        for (int i = 0; i < qd; i++)
        {
            if (!SkipName(m, ref p) || p + 4 > m.Length) return false;
            p += 4;
        }
        for (int i = 0; i < an && i < 256; i++)
        {
            if (!SkipName(m, ref p) || p + 10 > m.Length) return false;
            int rtype = (m[p] << 8) | m[p + 1];
            int rclass = (m[p + 2] << 8) | m[p + 3];
            int len = (m[p + 8] << 8) | m[p + 9];
            p += 10;
            if (p + len > m.Length) return false;
            if (rclass == 1 && rtype == type)
            {
                if (type == TypeA && len == 4) addrs.Add(new IPAddress(m.Slice(p, 4)));
                else if (type == TypeAaaa && len == 16) addrs.Add(new IPAddress(m.Slice(p, 16)));
            }
            p += len;
        }
        return true;
    }

    private static bool SkipName(ReadOnlySpan<byte> m, ref int p)
    {
        for (int guard = 0; guard < 128; guard++)
        {
            if (p >= m.Length) return false;
            byte len = m[p];
            if (len == 0) { p++; return true; }
            if ((len & 0xC0) == 0xC0) { p += 2; return p <= m.Length; }   // a pointer ends the name
            if ((len & 0xC0) != 0) return false;
            p += 1 + len;
        }
        return false;
    }

    // ------------------------------------------------------------------ the system resolver

    public static async Task<DoctorDnsAnswer> SystemAsync(Func<string, CancellationToken, Task<IPAddress[]>> resolve, string host,
                                                          int timeoutMs, CancellationToken ct)
    {
        var ans = new DoctorDnsAnswer { Source = "System" };
        var sw = Stopwatch.StartNew();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        try
        {
            var list = await resolve(host, cts.Token).WaitAsync(cts.Token).ConfigureAwait(false);
            ans.Answered = true;
            ans.Rcode = 0;
            ans.Addresses.AddRange(DoctorIp.Ordered(list));
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { ans.Error = "timed out"; }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.HostNotFound)
        {
            ans.Answered = true;
            ans.Rcode = 3;
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.NoData)
        {
            ans.Answered = true;
            ans.Rcode = 0;
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.TryAgain) { ans.Error = "the resolver didn't answer"; }
        catch (OperationCanceledException) { throw; }
        catch (Exception e) { ans.Error = Short(e); }
        ans.Ms = sw.Elapsed.TotalMilliseconds;
        return ans;
    }

    // ------------------------------------------------------------------ plain UDP

    /// <summary>A and AAAA from <paramref name="server"/> over UDP. A lost datagram is sent again once; after the first
    /// reply the socket listens a little longer, because an on-path forger races the real server: two different replies
    /// to one query prove it (<see cref="DoctorDnsAnswer.Injected"/>).</summary>
    public static async Task<DoctorDnsAnswer> UdpAsync(IPEndPoint server, string name, int timeoutMs, CancellationToken ct)
    {
        var ans = new DoctorDnsAnswer { Source = server.Port == 53 ? server.Address.ToString() : server.ToString() };
        var a = UdpQueryAsync(server, name, TypeA, timeoutMs, ct);
        var aaaa = UdpQueryAsync(server, name, TypeAaaa, timeoutMs, ct);
        var r4 = await a.ConfigureAwait(false);
        var r6 = await aaaa.ConfigureAwait(false);
        Merge(ans, r4, r6);
        return ans;
    }

    private sealed class Reply
    {
        public bool Answered;
        public int Rcode = -1;
        public readonly List<IPAddress> Addrs = new();
        public readonly List<IPAddress> Later = new();
        public bool Injected;
        public string? Error;
        public double Ms;
    }

    private static void Merge(DoctorDnsAnswer ans, Reply a, Reply b)
    {
        ans.Answered = a.Answered || b.Answered;
        ans.Rcode = a.Answered ? a.Rcode : b.Rcode;
        if (a.Answered && b.Answered && a.Rcode == 3) ans.Rcode = 3;
        ans.Addresses.AddRange(DoctorIp.Ordered(a.Addrs.Concat(b.Addrs)));
        ans.Injected = a.Injected || b.Injected;
        ans.Later.AddRange(DoctorIp.Ordered(a.Later.Concat(b.Later)));
        ans.Error = ans.Answered ? null : a.Error ?? b.Error;
        ans.Ms = a.Answered ? a.Ms : b.Answered ? b.Ms : Math.Max(a.Ms, b.Ms);
    }

    private static async Task<Reply> UdpQueryAsync(IPEndPoint server, string name, ushort type, int timeoutMs, CancellationToken ct)
    {
        var r = new Reply();
        ushort id = (ushort)RandomNumberGenerator.GetInt32(1, 65535);
        byte[] query = BuildQuery(name, type, id);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        var sw = Stopwatch.StartNew();
        using var s = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        var buf = new byte[4096];
        try
        {
            await s.ConnectAsync(server, cts.Token).ConfigureAwait(false);
            await s.SendAsync(query, SocketFlags.None, cts.Token).ConfigureAwait(false);
            var recv = s.ReceiveAsync(buf, SocketFlags.None, cts.Token).AsTask();
            bool resent = false;
            while (true)
            {
                if (!resent)
                {
                    var first = await Task.WhenAny(recv, Task.Delay(Math.Min(1000, timeoutMs / 2), cts.Token)).ConfigureAwait(false);
                    if (first != recv)
                    {
                        resent = true;   // a lost datagram: ask once more, on the same socket (same id)
                        await s.SendAsync(query, SocketFlags.None, cts.Token).ConfigureAwait(false);
                        continue;
                    }
                }
                int n = await recv.ConfigureAwait(false);
                var addrs = new List<IPAddress>();
                if (TryParse(buf.AsSpan(0, n), id, type, out int rcode, addrs))
                {
                    r.Answered = true;
                    r.Rcode = rcode;
                    r.Addrs.AddRange(addrs);
                    r.Ms = sw.Elapsed.TotalMilliseconds;
                    break;
                }
                recv = s.ReceiveAsync(buf, SocketFlags.None, cts.Token).AsTask();   // something else: keep waiting
            }

            // a second, different reply to the same query = the first was injected on the way
            using var late = CancellationTokenSource.CreateLinkedTokenSource(ct);
            late.CancelAfter(350);
            try
            {
                while (true)
                {
                    int n = await s.ReceiveAsync(buf, SocketFlags.None, late.Token).ConfigureAwait(false);
                    var addrs = new List<IPAddress>();
                    if (!TryParse(buf.AsSpan(0, n), id, type, out int rc2, addrs)) continue;
                    bool differs = rc2 != r.Rcode || !addrs.OrderBy(x => x.ToString()).SequenceEqual(r.Addrs.OrderBy(x => x.ToString()));
                    // After the resend two genuine replies are expected, and they can differ (another frontend of the
                    // resolver, another CDN answer): that alone said "forged" on a slow path. Then only an answer that
                    // points somewhere no real one would (a filter page, a private or reserved address) counts.
                    bool forgedLooking = !resent || addrs.Concat(r.Addrs).Any(a => DoctorIp.IsKnownFilter(a) || !DoctorIp.IsPublic(a));
                    if (differs && forgedLooking)
                    {
                        r.Injected = true;
                        r.Later.AddRange(addrs);
                    }
                    break;
                }
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
            catch (SocketException) { }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { r.Error ??= "timed out"; }
        catch (OperationCanceledException) { throw; }
        catch (SocketException e) when (e.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionRefused)
        {
            r.Error = "port 53 refused";   // ICMP port unreachable: something on the way rejects DNS
        }
        catch (Exception e) { r.Error = Short(e); }
        if (!r.Answered) r.Ms = sw.Elapsed.TotalMilliseconds;
        return r;
    }

    // ------------------------------------------------------------------ DNS over HTTPS

    /// <summary>The client for the DoH queries: direct (no proxy: this is about the network itself), no redirects,
    /// HTTP/2 where offered. The endpoints are IP literals whose certificates name those IPs.</summary>
    public static HttpClient CreateDohClient(DoctorProxy? proxy = null)
    {
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(4),
            PooledConnectionLifetime = TimeSpan.FromSeconds(30),
            MaxResponseHeadersLength = 64,
        };
        // through a proxy: the Doctor's own tunnel to the resolver's IP (no DNS needed on either side)
        if (proxy != null)
            handler.ConnectCallback = async (ctx, token) =>
                (await proxy.OpenAsync(ctx.DnsEndPoint.Host.Trim('[', ']'), ctx.DnsEndPoint.Port, 6000, token).ConfigureAwait(false)).Stream;
        return new HttpClient(handler)
        {
            Timeout = Timeout.InfiniteTimeSpan,   // each query has its own deadline
            DefaultRequestVersion = HttpVersion.Version20,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
            MaxResponseContentBufferSize = MaxMessage,
        };
    }

    public static async Task<DoctorDnsAnswer> DohAsync(HttpClient http, DoctorDohEndpoint ep, string name, int timeoutMs, CancellationToken ct)
    {
        var ans = new DoctorDnsAnswer { Source = ep.Name };
        // only https — except a loopback test endpoint
        if (ep.Uri.Scheme != Uri.UriSchemeHttps && !(ep.Uri.Scheme == Uri.UriSchemeHttp && ep.Uri.IsLoopback))
        {
            ans.Error = "not an https endpoint";
            return ans;
        }
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        var sw = Stopwatch.StartNew();
        var a = DohQueryAsync(http, ep.Uri, name, TypeA, sw, cts.Token);
        var aaaa = DohQueryAsync(http, ep.Uri, name, TypeAaaa, sw, cts.Token);
        Reply r4, r6;
        try
        {
            r4 = await a.ConfigureAwait(false);
            r6 = await aaaa.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        Merge(ans, r4, r6);
        return ans;
    }

    private static async Task<Reply> DohQueryAsync(HttpClient http, Uri endpoint, string name, ushort type, Stopwatch sw, CancellationToken ct)
    {
        var r = new Reply();
        try
        {
            byte[] query = BuildQuery(name, type, 0);   // RFC 8484: id 0, so the GET is cacheable
            string url = endpoint.GetLeftPart(UriPartial.Path) + "?dns=" + Base64Url(query);
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Accept.ParseAdd("application/dns-message");
            using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
            {
                r.Error = $"HTTP {(int)resp.StatusCode}";
                return r;
            }
            byte[] body = await ReadCappedAsync(resp.Content, MaxMessage, ct).ConfigureAwait(false);
            var addrs = new List<IPAddress>();
            if (!TryParse(body, 0, type, out int rcode, addrs))
            {
                r.Error = "an unreadable reply";
                return r;
            }
            r.Answered = true;
            r.Rcode = rcode;
            r.Addrs.AddRange(addrs);
            r.Ms = sw.Elapsed.TotalMilliseconds;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { r.Error = "timed out"; }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { r.Error = "timed out"; }
        catch (Exception e) { r.Error = Short(e); }
        if (!r.Answered) r.Ms = sw.Elapsed.TotalMilliseconds;
        return r;
    }

    /// <summary>
    /// Asks every DoH endpoint at once. Once one has answered, the others get a short grace period (so their answers
    /// can join the trusted set) and are then left behind — a filtered endpoint never holds the run up.
    /// </summary>
    public static async Task<List<DoctorDnsAnswer>> DohAllAsync(HttpClient http, IReadOnlyList<DoctorDohEndpoint> endpoints, string name,
                                                                int timeoutMs, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var tasks = endpoints.Select(ep => DohAsync(http, ep, name, timeoutMs, cts.Token)).ToList();
        var pending = new List<Task<DoctorDnsAnswer>>(tasks);
        var answers = new DoctorDnsAnswer?[tasks.Count];
        DateTime? graceEnd = null;
        while (pending.Count > 0)
        {
            Task delay = graceEnd is { } g ? Task.Delay(Max(TimeSpan.Zero, g - DateTime.UtcNow), ct) : Task.Delay(Timeout.Infinite, ct);
            var done = await Task.WhenAny(pending.Cast<Task>().Append(delay)).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            if (done == delay) break;
            var t = (Task<DoctorDnsAnswer>)done;
            pending.Remove(t);
            var a = await t.ConfigureAwait(false);
            answers[tasks.IndexOf(t)] = a;
            if (a.Good && graceEnd == null) graceEnd = DateTime.UtcNow.AddMilliseconds(700);
        }
        cts.Cancel();   // the stragglers: no longer needed
        var list = new List<DoctorDnsAnswer>();
        for (int i = 0; i < tasks.Count; i++)
            list.Add(answers[i] ?? new DoctorDnsAnswer { Source = endpoints[i].Name, Error = "too slow" });
        return list;
    }

    private static TimeSpan Max(TimeSpan a, TimeSpan b) => a > b ? a : b;

    // ------------------------------------------------------------------ comparing

    /// <summary>
    /// How <paramref name="a"/> compares with the encrypted answers: <paramref name="trusted"/> holds their addresses,
    /// <paramref name="trustedKnown"/> says whether any encrypted resolver answered at all, <paramref name="trustedNx"/>
    /// that they all said "no such name".
    /// </summary>
    public static DoctorDnsMatch Compare(DoctorDnsAnswer a, IReadOnlyCollection<IPAddress> trusted, bool trustedKnown, bool trustedNx)
    {
        if (!a.Answered) return DoctorDnsMatch.Unknown;
        var bogus = a.Addresses.Where(x => !DoctorIp.IsPublic(x)).ToList();
        if (bogus.Count > 0)
        {
            if (bogus.Any(DoctorIp.IsKnownFilter)) return DoctorDnsMatch.Bogus;
            if (trustedKnown && (trustedNx || trusted.Any(DoctorIp.IsPublic))) return DoctorDnsMatch.Bogus;
            return DoctorDnsMatch.Unknown;   // a private answer we can't check: a company / home network's own name
        }
        if (!trustedKnown) return DoctorDnsMatch.Unknown;
        if (trustedNx) return a.NoSuchName || a.Addresses.Count == 0 ? DoctorDnsMatch.Same : DoctorDnsMatch.Differs;
        if (a.NoSuchName || a.Addresses.Count == 0) return trusted.Count > 0 ? DoctorDnsMatch.Missing : DoctorDnsMatch.Same;
        if (a.Addresses.Any(x => trusted.Contains(x))) return DoctorDnsMatch.Same;
        if (a.Addresses.Any(x => trusted.Any(t => DoctorIp.SameNetwork(x, t)))) return DoctorDnsMatch.Similar;
        return DoctorDnsMatch.Differs;
    }

    // ------------------------------------------------------------------ bits

    private static async Task<byte[]> ReadCappedAsync(HttpContent content, int cap, CancellationToken ct)
    {
        if (content.Headers.ContentLength is long n && n > cap) throw new InvalidDataException("reply too large");
        await using var stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var ms = new MemoryStream();
        var chunk = new byte[8192];
        while (true)
        {
            int got = await stream.ReadAsync(chunk, ct).ConfigureAwait(false);
            if (got == 0) break;
            if (ms.Length + got > cap) throw new InvalidDataException("reply too large");
            ms.Write(chunk, 0, got);
        }
        return ms.ToArray();
    }

    private static string Base64Url(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>A failure in two or three words ("timed out", "connection reset", "certificate rejected").</summary>
    public static string Short(Exception ex)
    {
        if (DoctorProxy.Find(ex) is { } proxyFailure) return proxyFailure.Message;   // the proxy said why, in its own words
        for (var e = ex; e != null; e = e.InnerException)
        {
            if (e is AuthenticationException) return "TLS failed";
            if (e is SocketException s)
            {
                return s.SocketErrorCode switch
                {
                    SocketError.ConnectionReset or SocketError.ConnectionAborted => "connection reset",
                    SocketError.ConnectionRefused => "refused",
                    SocketError.TimedOut => "timed out",
                    SocketError.HostUnreachable or SocketError.NetworkUnreachable or SocketError.NetworkDown => "unreachable",
                    SocketError.HostNotFound => "no such name",
                    SocketError.AccessDenied => "blocked by the system",
                    _ => s.SocketErrorCode.ToString(),
                };
            }
            if (e is TimeoutException) return "timed out";
            if (e is IOException io && io.InnerException == null)
                return io.Message.Contains("EOF", StringComparison.OrdinalIgnoreCase) || io.Message.Contains("0 bytes", StringComparison.Ordinal)
                    ? "connection closed" : "connection reset";
        }
        if (ex is HttpRequestException h && h.HttpRequestError == HttpRequestError.SecureConnectionError) return "TLS failed";
        string m = ex.Message.Trim();
        return m.Length > 60 ? m[..60] + "…" : m;
    }
}
