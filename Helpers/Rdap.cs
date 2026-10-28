using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>Who holds an IP address, in a few fields: the inline WHOIS of an address in the DNS results. A field is
/// empty when the address's registry doesn't publish it.</summary>
public sealed record IpWhois
{
    /// <summary>The holder ("Cloudflare, Inc.").</summary>
    public string Org { get; init; } = "";
    /// <summary>The network's name in its registry ("CLOUDFLARENET").</summary>
    public string Network { get; init; } = "";
    public string Country { get; init; } = "";
    /// <summary>The registered block: its CIDR ("104.16.0.0/12"), or first – last address.</summary>
    public string Range { get; init; } = "";
    /// <summary>The AS that announces it ("AS13335").</summary>
    public string Asn { get; init; } = "";
    public string Abuse { get; init; } = "";
    /// <summary>What the address is rather than whose (a private range, loopback …), or that no registry has it.</summary>
    public string Note { get; init; } = "";
    /// <summary>Why nothing came back, each source with its reason. Never cached: opening it again asks again.</summary>
    public string? Error { get; init; }
}

/// <summary>
/// RDAP, the registries' WHOIS in JSON: the DNS tool's WHOIS (domains, addresses, AS numbers) and the inline WHOIS of the
/// addresses in its results. rdap.org sends each query on to the registry that holds it. For addresses and AS numbers,
/// RIPEstat (RIPE NCC's public API, which reads every registry's WHOIS) answers when that registry's RDAP can't be
/// reached: ARIN's can't from some countries, and it holds most of the addresses of the big US networks.
/// </summary>
public static class Rdap
{
    // RDAP answers are a few KB. rdap.org redirects to whichever registry serves the name, so the body is a third
    // party's: it was buffered whole (100 MB in 1.4 s on loopback took ~350 MB of memory) and then parsed on the UI thread.
    public const int MaxBytes = 2 * 1024 * 1024;
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    // The inline WHOIS waits less than the WHOIS pane: someone is looking at the row, and a source that hasn't answered
    // by then is passed over for the other one.
    private static readonly TimeSpan InlineTimeout = TimeSpan.FromSeconds(6);

    // One client for every RDAP / RIPEstat request: an address panel asks for several at once, and they share
    // connections (a TLS handshake per server, not per address). Its Timeout is the longest wait; a call that waits less
    // cancels at its own deadline.
    private static readonly Lazy<HttpClient> s_client = new(() =>
    {
        var client = HttpHelper.Create(timeout: Timeout);
        client.DefaultRequestHeaders.Accept.ParseAdd("application/rdap+json");
        client.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        return client;
    });

    /// <summary>GETs <paramref name="url"/> (RDAP or RIPEstat): the body as text and the HTTP status. Throws for a network
    /// failure; a timeout surfaces as an <see cref="OperationCanceledException"/> while <paramref name="token"/> isn't
    /// cancelled.</summary>
    public static async Task<(string body, int status)> FetchAsync(string url, CancellationToken token, TimeSpan? timeout = null)
    {
        var (body, status, _) = await FetchFinalAsync(url, token, timeout).ConfigureAwait(false);
        return (body, status);
    }

    /// <summary><see cref="FetchAsync"/>, and the address that answered after redirects (rdap.org's to the registry).</summary>
    public static async Task<(string body, int status, Uri? final)> FetchFinalAsync(string url, CancellationToken token, TimeSpan? timeout = null)
    {
        // Headers first, then the body read with a ceiling (decompressed bytes, so a gzip bomb stops there too). The
        // client's Timeout ends with the headers, so the body gets the same deadline; it surfaces as "timed out".
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(timeout ?? Timeout);
        using var response = await s_client.Value.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
        Uri? final = response.RequestMessage?.RequestUri;
        await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
        using var ms = new MemoryStream();
        byte[] buf = new byte[16 * 1024];
        int n;
        while ((n = await stream.ReadAsync(buf, deadline.Token).ConfigureAwait(false)) > 0)
        {
            if (ms.Length + n > MaxBytes) throw new InvalidDataException($"the answer is larger than {MaxBytes / (1024 * 1024)} MB");
            ms.Write(buf, 0, n);
        }
        // RDAP is JSON, so UTF-8 (RFC 8259); a BOM is skipped as ReadAsStringAsync did.
        int skip = ms.Length >= 3 && ms.GetBuffer()[0] == 0xEF && ms.GetBuffer()[1] == 0xBB && ms.GetBuffer()[2] == 0xBF ? 3 : 0;
        return (Encoding.UTF8.GetString(ms.GetBuffer(), skip, (int)ms.Length - skip), (int)response.StatusCode, final);
    }

    // ---------------------------------------------------------------- RIPEstat

    /// <summary>RIPEstat's copy of the WHOIS of whichever registry holds <paramref name="resource"/> (an address, a
    /// range, or an AS number written "AS13335").</summary>
    public static string RipeStatWhoisUrl(string resource) => RipeStat("whois", resource);

    public static bool IsRipeStat(string url) => url.StartsWith("https://stat.ripe.net/", StringComparison.Ordinal);

    private static string RipeStat(string call, string resource)
        => $"https://stat.ripe.net/data/{call}/data.json?resource={Uri.EscapeDataString(resource)}&sourceapp=echoes";

    /// <summary>A RIPEstat whois answer as WHOIS text ("key: value" lines, a blank line between objects), or null when it
    /// holds no record.</summary>
    public static string? RipeStatText(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var groups = RipeStatGroups(doc.RootElement);
        if (groups.Count == 0) return null;
        var sb = new StringBuilder();
        foreach (var group in groups)
        {
            if (sb.Length > 0) sb.AppendLine();
            foreach (var (key, value) in group) sb.Append(key).Append(": ").AppendLine(value);
        }
        return sb.ToString();
    }

    // data.records (the registry's own objects), then data.irr_records (route objects: their origin is the AS that
    // announces the block); each object a list of { key, value }. A "No match found" object is no record.
    private static List<List<(string key, string value)>> RipeStatGroups(JsonElement root)
    {
        var groups = new List<List<(string, string)>>();
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Object)
            return groups;
        foreach (string name in new[] { "records", "irr_records" })
        {
            if (!data.TryGetProperty(name, out var list) || list.ValueKind != JsonValueKind.Array) continue;
            foreach (var obj in list.EnumerateArray())
            {
                if (obj.ValueKind != JsonValueKind.Array) continue;
                var group = new List<(string, string)>();
                foreach (var kv in obj.EnumerateArray())
                {
                    string key = Str(kv, "key"), value = Str(kv, "value");
                    if (key.StartsWith("No match found", StringComparison.OrdinalIgnoreCase)) { group.Clear(); break; }
                    if (key.Length > 0) group.Add((key, value));
                }
                if (group.Count > 0) groups.Add(group);
            }
        }
        return groups;
    }

    // ---------------------------------------------------------------- an address, in a few fields

    // Every address looked up this session, so one seen in many rows (or opened again) is asked once. A few hundred at most.
    private const int MaxCached = 512;
    private static readonly ConcurrentDictionary<string, IpWhois> s_cache = new();
    // rdap.org and RIPEstat limit how fast one client may ask: a panel of eight addresses goes two at a time.
    private static readonly SemaphoreSlim s_gate = new(2, 2);

    /// <summary>What is known about <paramref name="ip"/> without asking: a special-purpose address, or one looked up
    /// already this session. Null when it has to be asked.</summary>
    public static IpWhois? Known(IPAddress ip)
    {
        if (SpecialPurpose(ip) is { } note) return new IpWhois { Note = note };
        return s_cache.TryGetValue(ip.ToString(), out var known) ? known : null;
    }

    /// <summary>
    /// Who holds <paramref name="ip"/>, from many sources (<see cref="Fallback"/>):
    /// <list type="bullet">
    /// <item>RDAP through rdap.org, through ARIN's (it hands other registries' space on to them), and through ARIN's
    /// bootstrap;</item>
    /// <item>RIPEstat's copy of the registry's WHOIS;</item>
    /// <item>classic WHOIS through IANA, and straight from ARIN (<see cref="Whois43"/>);</item>
    /// <item>ip.guide's summary.</item>
    /// </list>
    /// The AS it is announced from is asked alongside (RIPEstat, else ip.guide): RDAP rarely has it. Never throws for a
    /// network failure: that is <see cref="IpWhois.Error"/>, naming each source's reason. Throws
    /// <see cref="OperationCanceledException"/> only when <paramref name="ct"/> is cancelled.
    /// </summary>
    public static async Task<IpWhois> LookUpIpAsync(IPAddress ip, CancellationToken ct)
    {
        if (Known(ip) is { } known) return known;
        string key = ip.ToString();
        await s_gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (s_cache.TryGetValue(key, out var cached)) return cached;   // another row asked for it meanwhile
            var announced = AnnouncedByAsync(key, ct);
            var sources = new List<Fallback.Source<IpWhois>>
            {
                RdapNetwork("rdap.org", "https://rdap.org/ip/" + key),
                RdapNetwork("ARIN's RDAP", "https://rdap.arin.net/registry/ip/" + key),
                RdapNetwork("ARIN's RDAP bootstrap", "https://rdap-bootstrap.arin.net/bootstrap/ip/" + key),
                new("RIPEstat", async t =>
                {
                    using var doc = await JsonAsync(RipeStat("whois", key), t).ConfigureAwait(false);
                    return FromRipeStat(doc.RootElement);
                }),
                Classic("WHOIS", key, null),
                Classic("WHOIS " + Whois43.Arin, key, Whois43.Arin),
                new("ip.guide", async t =>
                {
                    using var doc = await JsonAsync("https://ip.guide/" + key, t).ConfigureAwait(false);
                    return FromIpGuide(doc.RootElement);
                }),
            };
            var result = await Fallback.FirstAsync("whois.inline", sources, ct, TimeSpan.FromSeconds(2), InlineTimeout).ConfigureAwait(false);
            string asn = await announced.ConfigureAwait(false);
            if (result.Value is not { } found) return new IpWhois { Asn = asn, Error = "No WHOIS: " + string.Join("; ", result.Errors) };
            if (found.Asn.Length == 0 && asn.Length > 0) found = found with { Asn = asn };
            if (s_cache.Count >= MaxCached) s_cache.Clear();
            s_cache[key] = found;
            return found;
        }
        finally { s_gate.Release(); }
    }

    // An RDAP network object. rdap.org and ARIN know every registry's blocks: no record there means nobody has it.
    private static Fallback.Source<IpWhois> RdapNetwork(string name, string url) => new(name, async t =>
    {
        var (body, status) = await FetchAsync(url, t, InlineTimeout).ConfigureAwait(false);
        if (status == 404) return new IpWhois { Note = "No registry has a record of it (unallocated?)" };
        if (status is < 200 or >= 300 || !body.TrimStart().StartsWith('{')) throw new HttpRequestException(null, null, (HttpStatusCode)status);
        using var doc = JsonDocument.Parse(body);
        return FromRdap(doc.RootElement);
    });

    // Classic WHOIS through IANA, or starting at another server. IANA's record alone is the registry's whole block, not
    // the holder's.
    private static Fallback.Source<IpWhois> Classic(string name, string ip, string? first) => new(name, async t =>
    {
        var answer = await Whois43.LookUpAsync(ip, Whois43.Kind.Ip, t, firstServer: first).ConfigureAwait(false);
        if (first == null && answer.Servers.Count == 1) throw new InvalidDataException(answer.Note ?? "only IANA's block");
        return FromGroups(Whois43.Objects(answer.Text));
    });

    // A JSON answer, or an exception naming why not (the status, or not JSON).
    private static async Task<JsonDocument> JsonAsync(string url, CancellationToken ct)
    {
        var (body, status) = await FetchAsync(url, ct, InlineTimeout).ConfigureAwait(false);
        if (status is < 200 or >= 300 || !body.TrimStart().StartsWith('{')) throw new HttpRequestException(null, null, (HttpStatusCode)status);
        return JsonDocument.Parse(body);
    }

    // The AS(es) the address is announced from: RIPEstat's routing view, else ip.guide's. "" when unknown, and never throws
    // (only for the caller's cancellation): the summary is whole without it.
    private static async Task<string> AnnouncedByAsync(string ip, CancellationToken ct)
    {
        try
        {
            var result = await Fallback.FirstAsync("announced", new Fallback.Source<string>[]
            {
                new("RIPEstat", async t =>
                {
                    using var doc = await JsonAsync(RipeStat("network-info", ip), t).ConfigureAwait(false);
                    if (!doc.RootElement.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Object
                        || !data.TryGetProperty("asns", out var asns) || asns.ValueKind != JsonValueKind.Array)
                        return null;
                    var list = asns.EnumerateArray()
                        .Select(a => a.ValueKind == JsonValueKind.String ? a.GetString() ?? "" : a.ValueKind == JsonValueKind.Number ? a.GetRawText() : "")
                        .Where(a => a.Length is > 0 and <= 10 && a.All(char.IsAsciiDigit)).ToList();
                    return list.Count == 0 ? null : string.Join(", ", list.Take(2).Select(a => "AS" + a)) + (list.Count > 2 ? $" +{list.Count - 2}" : "");
                }),
                new("ip.guide", async t =>
                {
                    using var doc = await JsonAsync("https://ip.guide/" + ip, t).ConfigureAwait(false);
                    return FromIpGuide(doc.RootElement)?.Asn is { Length: > 0 } asn ? asn : null;
                }),
            }, ct, TimeSpan.FromSeconds(2), InlineTimeout).ConfigureAwait(false);
            return result.Value ?? "";
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return ""; }
    }

    // ip.guide: the announced network (CIDR) and its AS (number, holder, country); no registry contacts.
    private static IpWhois? FromIpGuide(JsonElement r)
    {
        if (r.ValueKind != JsonValueKind.Object || !r.TryGetProperty("network", out var net) || net.ValueKind != JsonValueKind.Object) return null;
        string cidr = Str(net, "cidr");
        string org = "", country = "", asn = "";
        if (net.TryGetProperty("autonomous_system", out var a) && a.ValueKind == JsonValueKind.Object)
        {
            org = Str(a, "organization");
            if (org.Length == 0) org = Str(a, "name");
            country = Str(a, "country");
            if (a.TryGetProperty("asn", out var n) && n.ValueKind == JsonValueKind.Number && n.TryGetInt64(out long number)) asn = "AS" + number;
        }
        var w = new IpWhois { Org = Clean(org), Country = Clean(country), Range = Clean(cidr), Asn = Clean(asn) };
        return w.Org.Length + w.Range.Length == 0 ? null : w;
    }

    // The RDAP network object. The holder is the registrant that is an organisation (RIPE nests it under the abuse
    // contact, its top-level registrant being a maintainer), else the first registrant that isn't a maintainer, else the
    // network's description (APNIC's first remark). ARIN gives no country of its own: the holder's address ends with it.
    private static IpWhois? FromRdap(JsonElement r)
    {
        if (r.ValueKind != JsonValueKind.Object) return null;
        var contacts = new List<Contact>();
        Contacts(r, contacts, 0);
        string org = contacts.FirstOrDefault(c => c.Registrant && c.Kind == "org" && c.Name.Length > 0)?.Name
                     ?? contacts.FirstOrDefault(c => c.Registrant && c.Name.Length > 0 && !c.Name.EndsWith("-MNT", StringComparison.OrdinalIgnoreCase))?.Name
                     ?? Description(r);
        string country = Str(r, "country");
        if (country.Length == 0) country = contacts.FirstOrDefault(c => c.Registrant && c.Country.Length > 0)?.Country ?? "";
        string range = Cidrs(r);
        if (range.Length == 0 && Str(r, "startAddress") is { Length: > 0 } first) range = $"{first} – {Str(r, "endAddress")}";
        var w = new IpWhois
        {
            Org = Clean(org), Network = Clean(Str(r, "name")), Country = Clean(country), Range = Clean(range), Asn = OriginAs(r),
            Abuse = Clean(contacts.FirstOrDefault(c => c.Abuse && c.Email.Length > 0)?.Email ?? ""),
        };
        return w.Org.Length + w.Network.Length + w.Range.Length == 0 ? null : w;
    }

    private sealed record Contact(bool Registrant, bool Abuse, string Kind, string Name, string Email, string Country);

    // the entities, and those inside them (ARIN files the abuse contact under the organisation): a few levels at most
    private static void Contacts(JsonElement obj, List<Contact> into, int depth)
    {
        if (depth > 3 || !obj.TryGetProperty("entities", out var list) || list.ValueKind != JsonValueKind.Array) return;
        foreach (var e in list.EnumerateArray())
        {
            if (e.ValueKind != JsonValueKind.Object || into.Count >= 64) continue;
            var roles = e.TryGetProperty("roles", out var rs) && rs.ValueKind == JsonValueKind.Array
                ? rs.EnumerateArray().Select(Text).ToList()
                : new List<string>();
            var (kind, name, email, country) = VCard(e);
            into.Add(new Contact(roles.Contains("registrant"), roles.Contains("abuse"), kind, name, email, country));
            Contacts(e, into, depth + 1);
        }
    }

    // jCard (RFC 7095): ["vcard", [[name, params, type, value], …]]. The country is the last part of the address, or the
    // last line of its label when that is a whole postal address (ARIN fills in only the label).
    private static (string kind, string name, string email, string country) VCard(JsonElement entity)
    {
        string kind = "", name = "", email = "", country = "";
        if (!entity.TryGetProperty("vcardArray", out var v) || v.ValueKind != JsonValueKind.Array || v.GetArrayLength() < 2
            || v[1].ValueKind != JsonValueKind.Array)
            return (kind, name, email, country);
        foreach (var p in v[1].EnumerateArray())
        {
            if (p.ValueKind != JsonValueKind.Array || p.GetArrayLength() < 4) continue;
            switch (Text(p[0]))
            {
                case "kind": kind = Text(p[3]); break;
                case "fn": name = Text(p[3]); break;
                case "email" when email.Length == 0: email = Text(p[3]); break;
                case "adr" when country.Length == 0:
                    if (p[3].ValueKind == JsonValueKind.Array && p[3].GetArrayLength() >= 7) country = Text(p[3][6]);
                    if (country.Length == 0 && Str(p[1], "label").Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        is { Length: >= 3 } lines)
                        country = lines[^1];
                    break;
            }
        }
        return (kind, name, email, country);
    }

    private static string Description(JsonElement r)
    {
        if (!r.TryGetProperty("remarks", out var remarks) || remarks.ValueKind != JsonValueKind.Array) return "";
        foreach (var x in remarks.EnumerateArray())
            if (Str(x, "title").Equals("description", StringComparison.OrdinalIgnoreCase)
                && x.TryGetProperty("description", out var d) && d.ValueKind == JsonValueKind.Array && d.GetArrayLength() > 0)
                return Text(d[0]);
        return "";
    }

    // cidr0, the CIDR extension every registry serves: "104.16.0.0/12" (a block registered as several, joined)
    private static string Cidrs(JsonElement r)
    {
        if (!r.TryGetProperty("cidr0_cidrs", out var list) || list.ValueKind != JsonValueKind.Array) return "";
        var parts = new List<string>();
        foreach (var c in list.EnumerateArray())
        {
            string prefix = Str(c, "v4prefix") is { Length: > 0 } v4 ? v4 : Str(c, "v6prefix");
            if (prefix.Length > 0 && c.TryGetProperty("length", out var len) && len.ValueKind == JsonValueKind.Number)
                parts.Add($"{prefix}/{len.GetRawText()}");
            if (parts.Count == 3) break;
        }
        return string.Join(", ", parts);
    }

    // ARIN's originas0 extension: the AS numbers the network is announced from
    private static string OriginAs(JsonElement r)
        => r.TryGetProperty("arin_originas0_originautnums", out var a) && a.ValueKind == JsonValueKind.Array && a.GetArrayLength() > 0
           && a[0].ValueKind == JsonValueKind.Number
            ? "AS" + a[0].GetRawText()
            : "";

    private static IpWhois? FromRipeStat(JsonElement root) => FromGroups(RipeStatGroups(root));

    // A registry's whois objects in its own words (RIPEstat's copy, or port 43's text): ARIN's NetName / OrgName /
    // OrgAbuseEmail, the others' netname / descr / country; route objects add the block and the AS that announces it. An
    // answer that is only IANA's catch-all block (an unallocated or special address) is no answer.
    private static IpWhois? FromGroups(List<List<(string key, string value)>> groups)
    {
        if (groups.Count == 0) return null;
        string Find(params string[] keys)
        {
            foreach (string k in keys)
                foreach (var group in groups)
                    foreach (var (key, value) in group)
                        if (key.Equals(k, StringComparison.OrdinalIgnoreCase) && value.Trim().Length > 0) return value.Trim();
            return "";
        }
        string range = Find("CIDR", "inetnum", "inet6num", "NetRange", "route", "route6");
        if (range is "0.0.0.0/0" or "::/0" || range.StartsWith("0.0.0.0 - 255.255.255.255", StringComparison.Ordinal)) return null;
        string org = Find("OrgName", "org-name", "Organization", "owner", "descr");
        // ARIN writes the organisation with its handle: "Cloudflare, Inc. (CLOUD14)"
        if (org.EndsWith(')') && org.LastIndexOf(" (", StringComparison.Ordinal) is > 0 and var cut) org = org[..cut];
        string asn = Find("OriginAS", "origin");
        if (asn.Length > 0 && !asn.StartsWith("AS", StringComparison.OrdinalIgnoreCase)) asn = "AS" + asn;
        var w = new IpWhois
        {
            Org = Clean(org), Network = Clean(Find("NetName", "netname")), Country = Clean(Find("Country")), Range = Clean(range),
            Asn = Clean(asn), Abuse = Clean(Find("OrgAbuseEmail", "RAbuseEmail", "abuse-mailbox")),
        };
        return w.Org.Length + w.Network.Length + w.Range.Length == 0 ? null : w;
    }

    /// <summary>What a special-purpose address is (no registry lists it as anyone's), or null for an ordinary one.</summary>
    public static string? SpecialPurpose(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        byte[] b = ip.GetAddressBytes();
        if (b.Length == 4)
        {
            if (DnsCompare.IsCensorAddress(ip.ToString())) return "A filter's redirect (10.10.34.0/24): the name is blocked on this network, this isn't its address";
            return b switch
            {
                [0, ..] => "Unspecified (0.0.0.0/8): what a resolver answers for a name it blocks",
                [10, ..] or [172, >= 16 and <= 31, ..] or [192, 168, ..] => "Private address (RFC 1918): used inside a network, not on the internet",
                [100, >= 64 and <= 127, ..] => "Shared address (RFC 6598): inside a carrier's NAT, not on the internet",
                [127, ..] => "Loopback: this device itself",
                [169, 254, ..] => "Link-local: only on the local network segment",
                [192, 0, 2, _] or [198, 51, 100, _] or [203, 0, 113, _] => "Documentation range (RFC 5737): for examples, never in real use",
                [198, 18 or 19, ..] => "Benchmarking range (RFC 2544): not on the internet",
                [>= 224 and <= 239, ..] => "Multicast address: a group, not one host",
                [>= 240, ..] => "Reserved range (240.0.0.0/4): not in use on the internet",
                _ => null,
            };
        }
        if (ip.Equals(IPAddress.IPv6Any)) return "Unspecified (::): what a resolver answers for a name it blocks";
        if (ip.Equals(IPAddress.IPv6Loopback)) return "Loopback: this device itself";
        return b switch
        {
            [0xFC or 0xFD, ..] => "Unique local address (fc00::/7): private, not on the internet",
            [0xFE, >= 0x80 and <= 0xBF, ..] => "Link-local: only on the local network segment",
            [0xFF, ..] => "Multicast address: a group, not one host",
            [0x20, 0x01, 0x0D, 0xB8, ..] => "Documentation range (2001:db8::/32): for examples, never in real use",
            [0, 0x64, 0xFF, 0x9B, 0, 0, 0, 0, 0, 0, 0, 0, _, _, _, _] => $"NAT64 (64:ff9b::/96) for {b[12]}.{b[13]}.{b[14]}.{b[15]}: that IPv4 address is the real one",
            _ => null,
        };
    }

    // a few words: the error line names every source's reason
    private static string Reason(Exception ex)
    {
        var e = SocketErrors.Unwrap(ex);
        if (e is HttpRequestException { InnerException: { } inner }) e = SocketErrors.Unwrap(inner);
        if (e is IOException { InnerException: AuthenticationException tls }) e = tls;
        return e switch
        {
            OperationCanceledException or TimeoutException => "timed out",
            AuthenticationException => "TLS failed",
            SocketException { SocketErrorCode: SocketError.ConnectionRefused } => "refused",
            SocketException { SocketErrorCode: SocketError.ConnectionReset } => "connection reset",
            SocketException { SocketErrorCode: SocketError.HostNotFound or SocketError.NoData or SocketError.TryAgain } => "host unknown",
            SocketException { SocketErrorCode: SocketError.NetworkUnreachable or SocketError.HostUnreachable or SocketError.NetworkDown } => "unreachable",
            JsonException => "unreadable answer",
            InvalidDataException => e.Message,   // over the size cap
            IOException => "connection reset",
            _ => RemoteText.Clean(e.Message.ReplaceLineEndings(" ").Trim(), 120),
        };
    }

    // registry text is someone else's: no control / bidi characters, and a sane length
    private static string Clean(string s) => RemoteText.Clean(s.Trim(), 200);

    private static string Str(JsonElement e, string name)
        => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static string Text(JsonElement e) => e.ValueKind == JsonValueKind.String ? e.GetString() ?? "" : "";
}
