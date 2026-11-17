using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>
/// The DNS tool's WHOIS, from many sources (<see cref="Fallback"/>): on a filtered network any of them can be blocked, and
/// a different one from hour to hour.
/// <para>A domain:
/// <list type="bullet">
/// <item>classic WHOIS from IANA on to the registry and the registrar (<see cref="Whois43"/>);</item>
/// <item>classic WHOIS straight from the registry's server, for when IANA's is out of reach;</item>
/// <item>RDAP through rdap.org, through ARIN's bootstrap server, and straight from the registry's RDAP server (IANA's
/// bootstrap list);</item>
/// <item>then two WHOIS web services (who-dat.as93.net, networkcalc.com).</item>
/// </list></para>
/// <para>An address or AS number:
/// <list type="bullet">
/// <item>RDAP through rdap.org, through ARIN's (it hands other registries' space on to them), through ARIN's bootstrap,
/// and straight from the registry's server;</item>
/// <item>RIPEstat;</item>
/// <item>classic WHOIS through IANA, and straight from ARIN;</item>
/// <item>then ip.guide's summary of the network and its AS.</item>
/// </list></para>
/// </summary>
public static class WhoisLookup
{
    /// <summary>What to show: where it came from ("% WHOIS whois.iana.org → whois.nic.ir", "% RDAP rdap.org →
    /// rdap.verisign.com") and the record as text, cleaned.</summary>
    public sealed record Answer(string Heading, string Body);

    // A WHOIS chain takes a second or two: the next source gets a fair head start's wait before it starts too.
    private static readonly TimeSpan HeadStart = TimeSpan.FromSeconds(2.5);
    private static readonly TimeSpan PerSource = TimeSpan.FromSeconds(15);
    // A classic WHOIS chain's own deadline, a second inside its source's share: a chain can need three or four hops of up
    // to 8 s each, and a server still to answer when this runs out leaves the answers before it, with a note. The source's
    // own cancellation would end the chain and take those answers with it.
    private static readonly TimeSpan ChainTimeout = PerSource - TimeSpan.FromSeconds(1);

    /// <summary>The first source's answer for <paramref name="query"/> (a domain, an address, or an AS number written
    /// "13335" or "AS13335"), with the reasons of the sources that failed before it; or none, and every source's reason.
    /// Throws <see cref="OperationCanceledException"/> only when <paramref name="ct"/> is cancelled.</summary>
    public static async Task<(Answer? Answer, IReadOnlyList<string> Errors)> LookUpAsync(string query, Whois43.Kind kind, CancellationToken ct)
    {
        string key = kind == Whois43.Kind.Asn ? query.TrimStart('A', 'S', 'a', 's') : query;
        Whois43.Answer? ianaOnly = null;
        var sources = new List<Fallback.Source<Answer>>();

        // Classic WHOIS through IANA. When only IANA answered (the server it named didn't), its record names the registry,
        // not the holder: another source goes on, and it is shown only when none answers.
        sources.Add(new("WHOIS", async t =>
        {
            var a = await Whois43.LookUpAsync(kind == Whois43.Kind.Asn ? "AS" + key : query, kind, t, ChainTimeout).ConfigureAwait(false);
            if (a.Servers.Count == 1 && a.Note != null)
            {
                ianaOnly = a;
                throw new InvalidDataException(a.Note);
            }
            return Classic(a);
        }));

        if (kind == Whois43.Kind.Domain)
        {
            if (Whois43.RegistryServer(query) is { } registry)
                sources.Add(new("WHOIS " + registry, async t => Classic(await Whois43.LookUpAsync(query, kind, t, ChainTimeout, firstServer: registry).ConfigureAwait(false))));
            sources.Add(RdapSource("rdap.org", $"https://rdap.org/domain/{key}"));
            sources.Add(RdapSource("ARIN's RDAP bootstrap", $"https://rdap-bootstrap.arin.net/bootstrap/domain/{key}"));
            sources.Add(new("registry RDAP", t => DirectRdap("dns", key, "domain", t)));
            sources.Add(WebSource("who-dat.as93.net", $"https://who-dat.as93.net/{Uri.EscapeDataString(key)}", root =>
                root.TryGetProperty("domain", out _) && !(root.TryGetProperty("error", out var e) && e.ValueKind != JsonValueKind.Null)));
            sources.Add(WebSource("networkcalc.com", $"https://networkcalc.com/api/dns/whois/{Uri.EscapeDataString(key)}", root =>
                root.TryGetProperty("status", out var s) && s.ValueKind == JsonValueKind.String && s.GetString() == "OK"
                && root.TryGetProperty("whois", out var w) && w.ValueKind == JsonValueKind.Object));
        }
        else
        {
            string path = kind == Whois43.Kind.Asn ? "autnum/" + key : "ip/" + key;
            sources.Insert(0, RdapSource("rdap.org", "https://rdap.org/" + path));
            sources.Insert(1, RdapSource("ARIN's RDAP", "https://rdap.arin.net/registry/" + path));
            sources.Insert(2, RdapSource("ARIN's RDAP bootstrap", "https://rdap-bootstrap.arin.net/bootstrap/" + path));
            sources.Insert(3, new("registry RDAP", t => kind == Whois43.Kind.Asn ? DirectRdap("asn", key, "autnum", t)
                                                         : DirectRdap(key.Contains(':') ? "ipv6" : "ipv4", key, "ip", t)));
            sources.Insert(4, new("RIPEstat", async t =>
            {
                var (body, status) = await Rdap.FetchAsync(Rdap.RipeStatWhoisUrl(kind == Whois43.Kind.Asn ? "AS" + key : key), t).ConfigureAwait(false);
                if (status is < 200 or >= 300) throw new HttpRequestException(null, null, (HttpStatusCode)status);
                string? text = await Task.Run(() => Rdap.RipeStatText(body), t).ConfigureAwait(false);
                return text == null ? null : new Answer("% via RIPEstat (the registry's WHOIS)", Clean(text));
            }));
            // ARIN's server answers for any address or AS, pointing at the registry that holds it
            sources.Add(new("WHOIS " + Whois43.Arin, async t => Classic(await Whois43.LookUpAsync(key, kind, t, ChainTimeout, firstServer: Whois43.Arin).ConfigureAwait(false))));
            sources.Add(WebSource("ip.guide", "https://ip.guide/" + (kind == Whois43.Kind.Asn ? "AS" + key : Uri.EscapeDataString(key)), root =>
                root.TryGetProperty(kind == Whois43.Kind.Asn ? "asn" : "network", out var n) && n.ValueKind != JsonValueKind.Null,
                "the network and its AS only"));
        }

        var result = await Fallback.FirstAsync("whois." + kind, sources, ct, HeadStart, PerSource).ConfigureAwait(false);
        if (result.Value is { } answer) return (answer, result.Errors);
        if (ianaOnly != null) return (Classic(ianaOnly), result.Errors.Where(e => !e.StartsWith("WHOIS:", StringComparison.Ordinal)).ToList());
        return (null, result.Errors);
    }

    private static Answer Classic(Whois43.Answer a)
        => new("% WHOIS " + string.Join(" → ", a.Servers) + (a.Note != null ? "; " + a.Note : ""), a.Text);

    // An RDAP server's answer, flattened to "key: value" lines; "via" names the server it ended at after redirects.
    // No record there (404) is no answer: another source may have one (a TLD without RDAP has its WHOIS on port 43).
    private static Fallback.Source<Answer> RdapSource(string name, string url) => new(name, async t =>
    {
        var (body, status, final) = await Rdap.FetchFinalAsync(url, t).ConfigureAwait(false);
        if (status == 404) return null;
        if (status is < 200 or >= 300 || !body.TrimStart().StartsWith('{')) throw new HttpRequestException(null, null, (HttpStatusCode)status);
        string text = await Task.Run(() => Flatten(body), t).ConfigureAwait(false);
        string start = new Uri(url).Host;
        string via = final != null && !final.Host.Equals(start, StringComparison.OrdinalIgnoreCase) ? $"{start} → {final.Host}" : start;
        return new Answer("% RDAP " + via, text);
    });

    // A WHOIS web service's JSON, flattened; "isRecord" tells an answer from the service's "nothing found".
    private static Fallback.Source<Answer> WebSource(string name, string url, Func<JsonElement, bool> isRecord, string? scope = null) => new(name, async t =>
    {
        var (body, status, _) = await Rdap.FetchFinalAsync(url, t).ConfigureAwait(false);
        if (status == 404) return null;
        if (status is < 200 or >= 300 || !body.TrimStart().StartsWith('{')) throw new HttpRequestException(null, null, (HttpStatusCode)status);
        string? text = await Task.Run(() =>
        {
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.ValueKind == JsonValueKind.Object && isRecord(doc.RootElement) ? Flatten(body) : null;
        }, t).ConfigureAwait(false);
        return text == null ? null : new Answer($"% via {name}" + (scope != null ? $" ({scope})" : " (a WHOIS web service)"), text);
    });

    // ---------------------------------------------------------------- the registry's own RDAP server

    // IANA's bootstrap lists (dns, ipv4, ipv6, asn: which RDAP server serves what), read once per session. A failed read
    // isn't kept: the next lookup tries again.
    private static readonly Dictionary<string, List<(string[] Keys, string Url)>> s_bootstrap = new();
    private static readonly SemaphoreSlim s_bootstrapGate = new(1, 1);

    // A few registries' RDAP servers for when IANA's list can't be read.
    private static readonly Dictionary<string, string> KnownDomainRdap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["com"] = "https://rdap.verisign.com/com/v1/", ["net"] = "https://rdap.verisign.com/net/v1/",
        ["org"] = "https://rdap.publicinterestregistry.org/rdap/",
    };

    private static async Task<Answer?> DirectRdap(string list, string key, string path, CancellationToken ct)
    {
        string? baseUrl = null;
        if (await BootstrapAsync(list, ct).ConfigureAwait(false) is { } services)
            baseUrl = list switch
            {
                "dns" => services.FirstOrDefault(s => s.Keys.Contains(Tld(key), StringComparer.OrdinalIgnoreCase)).Url,
                "asn" => long.TryParse(key, out long n) ? services.FirstOrDefault(s => s.Keys.Any(k => InRange(k, n))).Url : null,
                _ => IPAddress.TryParse(key, out var ip)
                    ? services.Where(s => s.Keys.Any(k => Contains(k, ip))).OrderByDescending(s => s.Keys.Where(k => Contains(k, ip)).Max(PrefixLength)).FirstOrDefault().Url
                    : null,
            };
        if (baseUrl == null && list == "dns") KnownDomainRdap.TryGetValue(Tld(key), out baseUrl);
        if (baseUrl == null) return null;
        return await RdapSource(new Uri(baseUrl).Host, baseUrl.TrimEnd('/') + "/" + path + "/" + key).Fetch(ct).ConfigureAwait(false);
    }

    private static async Task<List<(string[] Keys, string Url)>?> BootstrapAsync(string list, CancellationToken ct)
    {
        await s_bootstrapGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (s_bootstrap.TryGetValue(list, out var known)) return known;
            var (body, status) = await Rdap.FetchAsync($"https://data.iana.org/rdap/{list}.json", ct).ConfigureAwait(false);
            if (status != 200) return null;
            var services = new List<(string[], string)>();
            using var doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("services", out var all) || all.ValueKind != JsonValueKind.Array) return null;
            foreach (var service in all.EnumerateArray())
            {
                if (service.ValueKind != JsonValueKind.Array || service.GetArrayLength() < 2) continue;
                var keys = service[0].ValueKind == JsonValueKind.Array
                    ? service[0].EnumerateArray().Where(k => k.ValueKind == JsonValueKind.String).Select(k => k.GetString()!).ToArray() : Array.Empty<string>();
                string? url = service[1].ValueKind == JsonValueKind.Array
                    ? service[1].EnumerateArray().Where(u => u.ValueKind == JsonValueKind.String).Select(u => u.GetString()!)
                        .FirstOrDefault(u => Uri.TryCreate(u, UriKind.Absolute, out var x) && x.Scheme == Uri.UriSchemeHttps)
                    : null;
                if (keys.Length > 0 && url != null) services.Add((keys, url));
            }
            s_bootstrap[list] = services;
            return services;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception) { return null; }
        finally { s_bootstrapGate.Release(); }
    }

    private static string Tld(string domain) => domain[(domain.LastIndexOf('.') + 1)..];

    // "1877-1901" or "1877"
    private static bool InRange(string range, long n)
    {
        int dash = range.IndexOf('-');
        return dash < 0 ? long.TryParse(range, out long one) && one == n
            : long.TryParse(range[..dash], out long lo) && long.TryParse(range[(dash + 1)..], out long hi) && n >= lo && n <= hi;
    }

    private static bool Contains(string cidr, IPAddress ip) => IPNetwork.TryParse(cidr, out var net) && net.Contains(ip);

    private static int PrefixLength(string cidr) => IPNetwork.TryParse(cidr, out var net) ? net.PrefixLength : -1;

    // ---------------------------------------------------------------- text

    /// <summary>JSON as "key: value" lines (nested objects and lists in order), cleaned like any remote text.</summary>
    public static string Flatten(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var sb = new StringBuilder();
        Walk(doc.RootElement, sb);
        return Clean(sb.ToString());

        static void Walk(JsonElement element, StringBuilder sb)
        {
            if (element.ValueKind == JsonValueKind.Object)
            {
                foreach (var property in element.EnumerateObject())
                {
                    if (property.Value.ValueKind is JsonValueKind.Object or JsonValueKind.Array) Walk(property.Value, sb);
                    else if (property.Value.ValueKind != JsonValueKind.Null) sb.Append(property.Name).Append(": ").Append(property.Value.ToString()).Append('\n');
                }
            }
            else if (element.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in element.EnumerateArray()) Walk(item, sb);
            }
        }
    }

    private static string Clean(string text) => TextLimit.Cap(RemoteText.Clean(text.ReplaceLineEndings("\n").Trim(), keepNewlines: true).ReplaceLineEndings());
}
