using DnsClient;
using DnsClient.Protocol;
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
/// counts only when services of at least two different operators report it, one of them over HTTPS, and more operators
/// report it than anything else, so one wrong or hijacked answer can't move a record. When the first two don't agree (or
/// don't answer), more services are asked until the answers decide: as many at once as could still decide, a failed one
/// replaced at once, one more for each head start that passes without an answer, three at most at a time. After a
/// disagreement four answers are gathered first, as when four services were asked at once. A private / reserved address
/// is never accepted.
/// </summary>
public static class DdnsIpDetector
{
    /// <param name="Operator">Who runs it: the answers of one operator's services are one vote, so a second one is asked
    /// only when the operator's first failed.</param>
    /// <param name="Dns">A DNS question instead of a web page: the record holds the address the server saw.</param>
    private sealed record Source(string Name, string Operator, string Url, bool Trace = false, DnsAsk? Dns = null);

    /// <param name="Authoritative">The server is the name's own: an answer without the AA flag came from a resolver in
    /// between, and holds that resolver's address.</param>
    private sealed record DnsAsk(IPAddress Server, string Name, QueryType Type, QueryClass Class, bool Authoritative = false);

    private sealed record Answer(Source Src, string? Ip, string Error);

    private const string Cloudflare = "Cloudflare";

    // The first two are asked together; the others when those two don't agree (or don't answer). The web services are
    // reached by host NAME first: a TLS hello without a server name (https://1.1.1.1/…) is reset by some networks'
    // filters, so the trace at Cloudflare's IP comes late, for a network whose resolver or filter blocks the names
    // (one.one.one.one resolves to a filter's address on some). icanhazip has been Cloudflare's since 2021. The DNS
    // answers come from fixed server addresses and work where web services are blocked; they are unauthenticated, so they
    // can confirm an HTTPS answer but never decide alone.
    private static readonly Source[] V4Sources =
    {
        new(Cloudflare, Cloudflare, "https://www.cloudflare.com/cdn-cgi/trace", Trace: true),
        new("ipify", "ipify", "https://api.ipify.org/"),
        new("ident.me", "ident.me", "https://v4.ident.me/"),
        new("Amazon", "Amazon", "https://checkip.amazonaws.com/"),
        new("ipinfo", "ipinfo", "https://ipinfo.io/ip"),
        new("ifconfig.me", "ifconfig.me", "https://ifconfig.me/ip"),
        new("OpenDNS", "OpenDNS", "", Dns: new(IPAddress.Parse("208.67.222.222"), "myip.opendns.com", QueryType.A, QueryClass.IN)),
        new("ifconfig.co", "ifconfig.co", "https://ifconfig.co/ip"),
        new("Google", "Google", "", Dns: new(IPAddress.Parse("216.239.32.10"), "o-o.myaddr.l.google.com", QueryType.TXT, QueryClass.IN, Authoritative: true)),
        new("ip.sb", "ip.sb", "https://api-ipv4.ip.sb/ip"),
        new("ipecho", "ipecho", "https://ipecho.net/plain"),
        new("wtfismyip", "wtfismyip", "https://ipv4.wtfismyip.com/text"),
        new("myexternalip", "myexternalip", "https://ipv4.myexternalip.com/raw"),
        new("Mullvad", "Mullvad", "https://am.i.mullvad.net/ip"),
        new("icanhazip", Cloudflare, "https://ipv4.icanhazip.com/"),
        new("one.one.one.one", Cloudflare, "https://one.one.one.one/cdn-cgi/trace", Trace: true),
        new("Cloudflare DNS", Cloudflare, "", Dns: new(IPAddress.Parse("1.1.1.1"), "whoami.cloudflare", QueryType.TXT, QueryClass.CH)),
        new("Cloudflare by IP", Cloudflare, "https://1.1.1.1/cdn-cgi/trace", Trace: true),
        new("ipify (api64)", "ipify", "https://api64.ipify.org/"),
    };

    private static readonly Source[] V6Sources =
    {
        new(Cloudflare, Cloudflare, "https://www.cloudflare.com/cdn-cgi/trace", Trace: true),
        new("ipify", "ipify", "https://api6.ipify.org/"),
        new("ident.me", "ident.me", "https://v6.ident.me/"),
        new("ipinfo", "ipinfo", "https://v6.ipinfo.io/ip"),
        new("ifconfig.me", "ifconfig.me", "https://ifconfig.me/ip"),
        new("OpenDNS", "OpenDNS", "", Dns: new(IPAddress.Parse("2620:119:35::35"), "myip.opendns.com", QueryType.AAAA, QueryClass.IN)),
        new("ifconfig.co", "ifconfig.co", "https://ifconfig.co/ip"),
        new("Google", "Google", "", Dns: new(IPAddress.Parse("2001:4860:4802:32::a"), "o-o.myaddr.l.google.com", QueryType.TXT, QueryClass.IN, Authoritative: true)),
        new("ip.sb", "ip.sb", "https://api-ipv6.ip.sb/ip"),
        new("ipecho", "ipecho", "https://ipecho.net/plain"),
        new("wtfismyip", "wtfismyip", "https://ipv6.wtfismyip.com/text"),
        new("myexternalip", "myexternalip", "https://ipv6.myexternalip.com/raw"),
        new("Mullvad", "Mullvad", "https://ipv6.am.i.mullvad.net/ip"),
        new("icanhazip", Cloudflare, "https://ipv6.icanhazip.com/"),
        new("one.one.one.one", Cloudflare, "https://one.one.one.one/cdn-cgi/trace", Trace: true),
        new("Cloudflare DNS", Cloudflare, "", Dns: new(IPAddress.Parse("2606:4700:4700::1111"), "whoami.cloudflare", QueryType.TXT, QueryClass.CH)),
        new("Cloudflare by IP", Cloudflare, "https://[2606:4700:4700::1111]/cdn-cgi/trace", Trace: true),
        new("ipify (api64)", "ipify", "https://api64.ipify.org/"),
    };

    private const int MaxAnswerBytes = 4096;
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(8);
    // A DNS question goes over UDP, then over TCP: some networks drop one of them to foreign servers.
    private static readonly TimeSpan DnsUdpTimeout = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan DnsTcpTimeout = TimeSpan.FromSeconds(4);
    private static readonly TimeSpan HeadStart = TimeSpan.FromSeconds(2);
    private const int MaxAsking = 3;
    private const int AnswersAfterDisagreement = 4;
    // The whole lookup: services not asked by then aren't asked (it runs every few minutes in the background).
    private static readonly TimeSpan LookupBudget = TimeSpan.FromSeconds(30);

    // The services whose answers agreed last time, per family, go first next time: on a network that blocks some of the
    // first ones, a background round then costs two requests again, not a failed one each time.
    private static readonly ConcurrentDictionary<DdnsFamily, string[]> s_agreed = new();

    private static Source[]? _testV4, _testV6;
    private static bool _testPinned;

    /// <summary>
    /// Test hook: stand-in sources (a local mock), loopback http(s) URLs only — nothing else is accepted, so this can't
    /// point the lookup anywhere real. A body is either a bare address or Cloudflare's trace format ("ip=…" lines). An
    /// entry may name its operator first ("op|url"): entries of one operator are one vote; otherwise each is its own.
    /// Null restores the real services. <paramref name="pinFamily"/> keeps the real family pinning (an IPv6 lookup then
    /// can't reach a 127.0.0.1 source). Not bound to any UI or setting.
    /// </summary>
    internal static void SetTestSources(IReadOnlyList<string>? v4, IReadOnlyList<string>? v6, bool pinFamily = false)
    {
        _testV4 = v4 is null ? null : ToTestSources(v4);
        _testV6 = v6 is null ? null : ToTestSources(v6);
        _testPinned = pinFamily;
        s_agreed.Clear();
    }

    private static Source[] ToTestSources(IReadOnlyList<string> entries)
    {
        var list = new List<Source>();
        foreach (string entry in entries)
        {
            int bar = entry.IndexOf('|');
            string url = bar >= 0 ? entry[(bar + 1)..] : entry;
            if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || !u.IsLoopback
                || (u.Scheme != Uri.UriSchemeHttp && u.Scheme != Uri.UriSchemeHttps) || u.UserInfo.Length > 0)
                throw new ArgumentException("Test IP sources must be loopback http(s) URLs.");
            string name = "test" + (list.Count + 1);
            list.Add(new Source(name, bar > 0 ? entry[..bar] : name, url, url.Contains("trace", StringComparison.Ordinal)));
        }
        return list.ToArray();
    }

    /// <summary>The public address of <paramref name="family"/>, cross-checked. Never throws except for <paramref name="ct"/>.</summary>
    public static async Task<DdnsIpResult> DetectAsync(DdnsFamily family, CancellationToken ct)
    {
        Source[]? test = family == DdnsFamily.V4 ? _testV4 : _testV6;
        var order = InOrder(test ?? (family == DdnsFamily.V4 ? V4Sources : V6Sources), family);
        using var http = CreateClient(family, direct: test is null || _testPinned, serviceDns: test is null);
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(LookupBudget);

        var answers = new List<Answer>();
        var asking = new List<(Task<Answer> Task, Source Src)>();
        var asked = new HashSet<Source>();
        DdnsIpResult? verdict = null;

        // the next service of an operator that is neither being asked nor has answered
        Source? Next() => budget.IsCancellationRequested ? null : order.FirstOrDefault(s => !asked.Contains(s)
            && !asking.Any(a => a.Src.Operator == s.Operator) && !answers.Any(a => a.Ip != null && a.Src.Operator == s.Operator));

        void Start(Source s)
        {
            asked.Add(s);
            var task = AskAsync(http, s, family, budget.Token);
            // one still running when the answers decide is cancelled; nobody awaits it
            _ = task.ContinueWith(static t => _ = t.Exception, CancellationToken.None,
                                  TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            asking.Add((task, s));
        }

        // as many at once as could still decide (three at most): the first two together, then each failure replaced
        void Fill()
        {
            while (asking.Count < Math.Min(Needed(answers), MaxAsking) && Next() is { } s) Start(s);
        }

        try
        {
            Fill();
            while (asking.Count > 0)
            {
                var waits = asking.Select(a => (Task)a.Task).ToList();
                Task? turn = asking.Count < MaxAsking && Next() != null ? Task.Delay(HeadStart, budget.Token) : null;
                if (turn != null) waits.Add(turn);
                Task done = await Task.WhenAny(waits).ConfigureAwait(false);
                ct.ThrowIfCancellationRequested();
                if (done == turn)
                {
                    if (Next() is { } more) Start(more);
                    continue;
                }

                var entry = asking.First(a => a.Task == done);
                asking.Remove(entry);
                Answer answer;
                try { answer = await entry.Task.ConfigureAwait(false); }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested) { answer = new(entry.Src, null, "timed out"); }
                answers.Add(answer);
                if ((verdict = Decide(answers, family, final: false)) != null) break;
                Fill();
            }
        }
        finally { budget.Cancel(); }
        ct.ThrowIfCancellationRequested();

        verdict ??= Decide(answers, family, final: true)!;
        if (verdict.Address is { } agreed)
            s_agreed[family] = answers.Where(a => a.Ip == agreed).Select(a => a.Src.Name).ToArray();
        return verdict;
    }

    // How many more answers could decide, while undecided: a second one for the single address reported (an HTTPS one
    // after DNS answers), or as many as make four after a disagreement. A head start passing without an answer adds one
    // more besides (DetectAsync), so a service that hangs doesn't hold the lookup up for its whole timeout.
    private static int Needed(List<Answer> answers)
    {
        var got = answers.Where(a => a.Ip != null).ToList();
        bool disagree = got.Select(a => a.Ip).Distinct().Count() > 1;
        return Math.Max(1, (disagree ? AnswersAfterDisagreement : 2) - got.Count);
    }

    // The sources that agreed last time first (in that order), then the rest as listed.
    private static List<Source> InOrder(Source[] sources, DdnsFamily family)
    {
        var order = sources.ToList();
        if (s_agreed.TryGetValue(family, out var names))
            for (int i = names.Length - 1; i >= 0; i--)
                if (order.FindIndex(s => s.Name == names[i]) is >= 0 and var at)
                {
                    var s = order[at];
                    order.RemoveAt(at);
                    order.Insert(0, s);
                }
        return order;
    }

    /// <summary>The verdict on the answers so far, or null while more answers could change it. <paramref name="final"/>:
    /// no more will come. Each operator answers once at most (a second service of it isn't asked), so the answers for an
    /// address are a count of operators.</summary>
    private static DdnsIpResult? Decide(List<Answer> answers, DdnsFamily family, bool final)
    {
        var votes = answers.Where(a => a.Ip != null).GroupBy(a => a.Ip!)
                           .Select(g => (Ip: g.Key, Count: g.Count(), Web: g.Any(a => a.Src.Dns is null)))
                           .OrderByDescending(v => v.Count).ThenByDescending(v => v.Web).ToList();
        bool agreed = votes.Count > 0 && votes[0].Count >= 2 && votes[0].Web && (votes.Count == 1 || votes[0].Count > votes[1].Count);
        bool decided = votes.Count == 1 ? agreed : votes.Count > 1 && votes.Sum(v => v.Count) >= AnswersAfterDisagreement;
        if (!decided && !final) return null;

        string detail = string.Join(" · ", answers.Select(a => a.Src.Name + " " + (a.Ip ?? a.Error)));
        string fam = family == DdnsFamily.V4 ? "IPv4" : "IPv6";
        if (agreed) return new DdnsIpResult { Address = votes[0].Ip, Detail = detail };
        if (votes.Count == 0)
        {
            // one reason, then the services that gave it: a short line even when many were asked
            string why = string.Join("; ", answers.GroupBy(a => a.Error).Select(g => g.Key + ": " + string.Join(", ", g.Select(a => a.Src.Name))));
            return new DdnsIpResult
            {
                Detail = detail,
                Error = family == DdnsFamily.V6
                    ? $"Couldn't find a public IPv6 address: no IPv6 service answered (this network may have no IPv6). {why}."
                    : $"Couldn't find your public IPv4 address: no service answered. {why}.",
            };
        }
        if (votes.Count == 1)
            return new DdnsIpResult
            {
                Detail = detail,
                Error = votes[0].Count < 2
                    ? $"Only one service reported your public {fam} ({votes[0].Ip}); a second one must confirm it before a record changes."
                    : $"Only DNS answers reported your public {fam} ({votes[0].Ip}); an HTTPS service must confirm it before a record changes.",
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
        using var http = CreateClient(family, direct: true, serviceDns: true);
        var answer = await AskAsync(http, (family == DdnsFamily.V4 ? V4Sources : V6Sources)[0], family, ct).ConfigureAwait(false);
        return (answer.Ip, answer.Error);
    }

    // A client of its own per lookup: no proxy at all (UseProxy = false also skips the system proxy), no redirects, no
    // cookies, a small answer cap. "direct" pins the connection to the family; the loopback test sources skip that.
    // "serviceDns": the services' names resolve around a resolver that blocks them (the test sources' as the system has them).
    private static HttpClient CreateClient(DdnsFamily family, bool direct, bool serviceDns)
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
        if (direct) handler.ConnectCallback = (ctx, ct) => ConnectAsync(ctx.DnsEndPoint, family, serviceDns, ct);
        var http = new HttpClient(handler) { Timeout = RequestTimeout, MaxResponseContentBufferSize = MaxAnswerBytes };
        var ver = typeof(DdnsIpDetector).Assembly.GetName().Version;
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"Echoes/{ver?.Major ?? 0}.{ver?.Minor ?? 0}.{ver?.Build ?? 0}");
        return http;
    }

    // Only addresses of the wanted family are tried: an IPv4 lookup that connected over IPv6 (or the reverse) would
    // report the other address.
    private static async ValueTask<Stream> ConnectAsync(DnsEndPoint ep, DdnsFamily family, bool serviceDns, CancellationToken ct)
    {
        var af = family == DdnsFamily.V4 ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;
        string host = ep.Host.Length > 2 && ep.Host[0] == '[' && ep.Host[^1] == ']' ? ep.Host[1..^1] : ep.Host;
        IPAddress[] addrs = IPAddress.TryParse(host, out var literal) ? new[] { literal }
            : serviceDns ? await ServiceDns.ResolveAsync(host, ct).ConfigureAwait(false)
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

    private static async Task<Answer> AskAsync(HttpClient http, Source s, DdnsFamily family, CancellationToken ct)
    {
        try
        {
            string text;
            if (s.Dns is { } question) text = await AskDnsAsync(question, ct).ConfigureAwait(false);
            else
            {
                using var resp = await http.GetAsync(s.Url, HttpCompletionOption.ResponseContentRead, ct).ConfigureAwait(false);
                if (!resp.IsSuccessStatusCode) return new(s, null, $"HTTP {(int)resp.StatusCode}");
                string body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                text = (s.Trace ? TraceValue(body, "ip") : body).Trim();
            }
            if (text.Length is 0 or > 64 || !IPAddress.TryParse(text, out var ip)) return new(s, null, "no address in its answer");
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            var want = family == DdnsFamily.V4 ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;
            if (ip.AddressFamily != want) return new(s, null, family == DdnsFamily.V4 ? "answered an IPv6 address" : "answered an IPv4 address");
            if (!IsPublic(ip)) return new(s, null, $"answered a private address ({ip})");
            return new(s, ip.ToString(), string.Empty);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return new(s, null, "timed out"); }
        catch (OperationCanceledException) { throw; }
        catch (InvalidDataException ex) { return new(s, null, ex.Message); }
        catch (Exception ex) { return new(s, null, Reason(ex)); }
    }

    // The address in a DNS answer, as text; throws InvalidDataException with a reason for an answer that isn't usable.
    private static async Task<string> AskDnsAsync(DnsAsk q, CancellationToken ct)
    {
        IDnsQueryResponse? resp = null;
        Exception? failed = null;
        foreach (bool tcp in new[] { false, true })
        {
            var client = new LookupClient(new LookupClientOptions(new NameServer(q.Server))
            {
                UseTcpOnly = tcp, Timeout = tcp ? DnsTcpTimeout : DnsUdpTimeout, Retries = 0, UseCache = false,
                ThrowDnsErrors = false, ContinueOnDnsError = false, ContinueOnEmptyResponse = false,
            });
            try
            {
                resp = await client.QueryAsync(q.Name, q.Type, q.Class, ct).ConfigureAwait(false);
                break;
            }
            catch (Exception ex) when ((ex is DnsResponseException or SocketException) && !ct.IsCancellationRequested) { failed = ex; }
        }
        if (resp is null) throw failed!;
        if (resp.Header.ResponseCode != DnsHeaderResponseCode.NoError) throw new InvalidDataException("DNS answered " + resp.Header.ResponseCode);
        if (q.Authoritative && !resp.Header.HasAuthorityAnswer) throw new InvalidDataException("answered by another resolver");
        var values = new List<string>();
        foreach (var record in resp.Answers)
        {
            if (record is ARecord a && q.Type == QueryType.A) values.Add(a.Address.ToString());
            else if (record is AaaaRecord aaaa && q.Type == QueryType.AAAA) values.Add(aaaa.Address.ToString());
            else if (record is TxtRecord txt && q.Type == QueryType.TXT)
                foreach (string v in txt.Text)
                {
                    // Google adds the subnet a resolver in between passed on: then the address is that resolver's
                    if (v.StartsWith("edns0-client-subnet", StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("answered by another resolver");
                    values.Add(v.Trim());
                }
        }
        var distinct = values.Distinct().ToList();
        if (distinct.Count > 1) throw new InvalidDataException("more than one address in its answer");
        return distinct.Count == 1 ? distinct[0] : string.Empty;
    }

    private static string Reason(Exception ex)
    {
        for (var e = ex; e != null; e = e.InnerException)
        {
            if (e is SocketException se)
                return se.SocketErrorCode switch
                {
                    SocketError.HostNotFound or SocketError.NoData => "no address for its name",
                    SocketError.NetworkUnreachable or SocketError.HostUnreachable => "unreachable",
                    SocketError.ConnectionRefused => "refused",
                    SocketError.TimedOut => "timed out",
                    _ => "connection failed",
                };
            if (e is DnsResponseException dns) return dns.Code == DnsResponseCode.ConnectionTimeout ? "timed out" : "no DNS answer";
        }
        // TLS refused or answered by something that isn't TLS (a filter's page), and the rest: as every fallback says it
        return Fallback.Reason(ex);
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
