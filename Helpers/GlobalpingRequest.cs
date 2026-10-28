using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;

namespace Echoes.Helpers;

/// <summary>One of Globalping's location filters: {"continent": "EU"}, {"region": "Western Asia"}, {"country": "DE",
/// "city": "Frankfurt", "limit": 2}.</summary>
public sealed record GlobalpingLocation(string Field, string Value, string? City = null, int? Limit = null);

/// <summary>
/// A Check Host check as a Globalping measurement. The checks map to the closest measurement:
/// <list type="bullet">
/// <item>Ping: an ICMP ping of 4 packets, like check-host.net's 4 pings.</item>
/// <item>HTTP: a HEAD request to the URL (a host alone is http://, as check-host.net reads it); redirects aren't followed.</item>
/// <item>TCP: a TCP ping (three connects) to the port.</item>
/// <item>DNS: an A query through each probe's own resolver (check-host.net also returns AAAA).</item>
/// <item>UDP: none — Globalping has no UDP check, so UDP stays with check-host.net.</item>
/// </list>
/// The nodes: Automatic is Globalping's own world-wide spread, as many as max nodes (at most 50); regions map to its
/// continents (the Middle East to Western Asia and Iran); nodes picked one by one map to probes in the same city when
/// Globalping has one there, else in the same country.
/// </summary>
public sealed class GlobalpingRequest
{
    /// <summary>An address without an account may use up to 50 probes in one measurement.</summary>
    public const int MaxProbes = 50;
    public const int PingPackets = 4;
    public const int TcpPackets = 3;

    private GlobalpingRequest(CheckHostKind kind, string target)
    {
        Kind = kind;
        Target = target;
    }

    public CheckHostKind Kind { get; }
    /// <summary>The host or IP address the probes check.</summary>
    public string Target { get; }
    /// <summary>TCP and HTTP: the port; null for HTTP's default.</summary>
    public int? Port { get; private init; }
    /// <summary>HTTP: "HTTP" or "HTTPS".</summary>
    public string Protocol { get; private init; } = "";
    public string Path { get; private init; } = "/";
    public string Query { get; private init; } = "";
    public IReadOnlyList<GlobalpingLocation> Locations { get; private init; } = Array.Empty<GlobalpingLocation>();
    /// <summary>The measurement's limit when the locations carry none of their own.</summary>
    public int? Limit { get; private init; }
    /// <summary>What this run does differently from check-host.net, for the status line ("A records only"); "" when nothing.</summary>
    public string Note { get; private init; } = "";

    /// <summary>The probes asked for.</summary>
    public int Probes => Limit ?? Locations.Sum(l => l.Limit ?? 1);

    public static bool Supports(CheckHostKind kind) => kind != CheckHostKind.Udp;

    /// <summary>The measurement for <paramref name="kind"/> on <paramref name="target"/> (as <see cref="CheckHostTarget"/>
    /// made it), run from the places <paramref name="choice"/> names. <paramref name="catalog"/>: check-host.net's node
    /// list (live or saved), to know where picked nodes are; <paramref name="probes"/>: where Globalping has probes, when
    /// known. Throws <see cref="CheckHostException"/> when Globalping can't run it.</summary>
    public static GlobalpingRequest Build(CheckHostKind kind, string target, CheckHostNodeChoice choice, int maxNodes,
                                          IReadOnlyList<CheckHostNode>? catalog, GlobalpingProbeIndex? probes)
    {
        if (!Supports(kind)) throw new CheckHostException("Globalping has no UDP check.");
        int max = Math.Clamp(maxNodes, 1, MaxProbes);
        var request = kind switch
        {
            CheckHostKind.Http => ForHttp(target),
            CheckHostKind.Tcp => ForTcp(target),
            _ => new GlobalpingRequest(kind, Host(target, allowUnderscore: kind == CheckHostKind.Dns)),
        };
        var notes = new List<string>(2);
        if (kind == CheckHostKind.Dns) notes.Add("A records only");
        IReadOnlyList<GlobalpingLocation> locations = Array.Empty<GlobalpingLocation>();
        int? limit = max;
        switch (choice.Mode)
        {
            case CheckHostNodeChoice.ChoiceMode.Regions:
                locations = ForRegions(choice.Regions);
                break;
            case CheckHostNodeChoice.ChoiceMode.Nodes:
                locations = ForNodes(choice, catalog, max, probes, out var missing);
                limit = null;
                if (missing.Count > 0) notes.Add("no Globalping probes in " + string.Join(", ", missing));
                break;
        }
        return new GlobalpingRequest(kind, request.Target)
        {
            Port = request.Port,
            Protocol = request.Protocol,
            Path = request.Path,
            Query = request.Query,
            Locations = locations,
            Limit = limit,
            Note = string.Join(" · ", notes),
        };
    }

    // ---------------- targets ----------------

    /// <summary>A host name (in its ASCII form) or an IP address, as Globalping takes a target.</summary>
    private static string Host(string raw, bool allowUnderscore = false)
    {
        string h = raw.Trim().TrimEnd('.');
        if (h.StartsWith('[') && h.EndsWith(']')) h = h[1..^1];
        if (IPAddress.TryParse(h, out var ip)) return ip.ToString();
        if (h.Any(c => c > 127))
        {
            try { h = new IdnMapping().GetAscii(h); }
            catch (ArgumentException) { throw NotAHost(raw); }
        }
        h = h.ToLowerInvariant();
        if (!HostExtractor.IsHostName(h, requireDot: true) || (!allowUnderscore && h.Contains('_'))) throw NotAHost(raw);
        return h;
    }

    private static CheckHostException NotAHost(string raw) =>
        new($"Globalping checks a public host name or IP address, and \"{RemoteText.Clean(raw, 80)}\" isn't one.");

    // http://host/path?query, https://host:8443/…, or a host (and port) alone: http://, as check-host.net reads it
    private static GlobalpingRequest ForHttp(string target)
    {
        string t = target.Trim();
        if (t.Contains("://", StringComparison.Ordinal))
        {
            if (!Uri.TryCreate(t, UriKind.Absolute, out var uri) || uri.Host.Length == 0)
                throw new CheckHostException("Globalping needs a whole URL here, such as https://example.com/.");
            if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
                throw new CheckHostException("Globalping checks http:// and https:// URLs only.");
            // (any user:password@ in the URL is left out: it would go to a third party)
            return new GlobalpingRequest(CheckHostKind.Http, Host(uri.Host))
            {
                Protocol = uri.Scheme == Uri.UriSchemeHttps ? "HTTPS" : "HTTP",
                Port = uri.IsDefaultPort ? null : uri.Port,
                Path = uri.AbsolutePath.Length > 0 ? uri.AbsolutePath : "/",
                Query = uri.Query.TrimStart('?'),
            };
        }
        var found = HostExtractor.Best(t) ?? throw NotAHost(t);
        return new GlobalpingRequest(CheckHostKind.Http, Host(found.Host))
        {
            Protocol = found.Port == 443 ? "HTTPS" : "HTTP",
            Port = found.Port is 80 or 443 ? null : found.Port,
        };
    }

    // host:port, or a URL whose scheme names the port (smtp://, https://)
    private static GlobalpingRequest ForTcp(string target)
    {
        var found = HostExtractor.Best(target.Trim()) ?? throw NotAHost(target);
        int? port = found.Port;
        if (port is null && found.Url is { } url && Uri.TryCreate(url, UriKind.Absolute, out var uri))
            port = uri.Port > 0 ? uri.Port : SchemePort(uri.Scheme);
        if (port is not (> 0 and <= 65535)) throw new CheckHostException("Globalping needs the port for a TCP check — e.g. example.com:443.");
        return new GlobalpingRequest(CheckHostKind.Tcp, Host(found.Host)) { Port = port };
    }

    private static int? SchemePort(string scheme) => scheme.ToLowerInvariant() switch
    {
        "http" or "ws" => 80,
        "https" or "wss" => 443,
        "ftp" => 21,
        "ssh" or "sftp" => 22,
        "telnet" => 23,
        "smtp" => 25,
        "pop3" => 110,
        "imap" => 143,
        "ldap" => 389,
        "smtps" => 465,
        "submission" => 587,
        "ldaps" => 636,
        "imaps" => 993,
        "pop3s" => 995,
        "mysql" => 3306,
        "rdp" => 3389,
        "postgres" or "postgresql" => 5432,
        "redis" => 6379,
        "mongodb" => 27017,
        _ => null,
    };

    // ---------------- places ----------------

    // check-host.net's regions in Globalping's terms: its continents, and for the Middle East the UN M49 region Western
    // Asia plus Iran (which M49 puts in Southern Asia; most of check-host.net's Middle East nodes are there).
    private static readonly Dictionary<string, GlobalpingLocation[]> RegionPlaces = new(StringComparer.OrdinalIgnoreCase)
    {
        [CheckHostRegions.Europe] = new[] { new GlobalpingLocation("continent", "EU") },
        [CheckHostRegions.MiddleEast] = new[] { new GlobalpingLocation("region", "Western Asia"), new GlobalpingLocation("country", "IR") },
        [CheckHostRegions.Asia] = new[] { new GlobalpingLocation("continent", "AS") },
        [CheckHostRegions.Americas] = new[] { new GlobalpingLocation("continent", "NA"), new GlobalpingLocation("continent", "SA") },
        [CheckHostRegions.Africa] = new[] { new GlobalpingLocation("continent", "AF") },
        [CheckHostRegions.Oceania] = new[] { new GlobalpingLocation("continent", "OC") },
    };

    /// <summary>
    /// The chosen regions' places, for one measurement limit: Globalping gives each place an equal share, passes the
    /// share of a place without enough probes on to the others, and spreads a place's share over its cities and networks.
    /// (Repeating a place to weigh it more would undo that spread: each copy's first pick is the same big city.)
    /// </summary>
    internal static IReadOnlyList<GlobalpingLocation> ForRegions(IReadOnlyList<string> regions)
    {
        var list = new List<GlobalpingLocation>();
        foreach (string region in regions)
            if (RegionPlaces.TryGetValue(region, out var places))
                foreach (var place in places)
                    if (!list.Contains(place)) list.Add(place);
        return list;   // empty for only "Other": the whole world
    }

    /// <summary>The picked nodes (spread over their countries as a check-host.net run would, at most
    /// <paramref name="max"/>) as places with a probe count each: the node's city when Globalping has a probe there, else
    /// its country. <paramref name="missing"/>: the countries Globalping has no probe in.</summary>
    internal static IReadOnlyList<GlobalpingLocation> ForNodes(CheckHostNodeChoice choice, IReadOnlyList<CheckHostNode>? catalog, int max,
                                                               GlobalpingProbeIndex? probes, out List<string> missing)
    {
        var known = new List<CheckHostNode>();
        foreach (string id in choice.Nodes)
            if (CheckHostSnapshot.Find(id, catalog) is { } node) known.Add(node);
        var picked = CheckHostNodeChoice.Spread(known, max);

        var counts = new Dictionary<(string Country, string? City), int>();
        var order = new List<(string, string?)>();
        missing = new List<string>();
        foreach (var n in picked)
        {
            // (one country code Globalping doesn't know would make it refuse the whole request)
            if (n.CountryCode.Length != 2 || !CloudflareCountries.IsCode(n.CountryCode) || n.CountryCode is "xx" or "t1") continue;
            string cc = n.CountryCode.ToUpperInvariant();
            string? city = null;
            if (probes is not null)
            {
                if (!probes.HasCountry(cc))
                {
                    if (!missing.Contains(n.Country)) missing.Add(n.Country);
                    continue;
                }
                city = probes.City(cc, n.City);
            }
            var key = (cc, city);
            if (!counts.ContainsKey(key)) order.Add(key);
            counts[key] = counts.GetValueOrDefault(key) + 1;
        }
        if (order.Count == 0)
            throw new CheckHostException(missing.Count > 0
                ? $"Globalping has no probes in {string.Join(", ", missing)} right now, so it can't stand in for the chosen nodes."
                : "Globalping can't tell where the chosen nodes are — choose them again, or use Automatic.");
        return order.Select(k => new GlobalpingLocation("country", k.Item1, k.Item2, counts[k])).ToList();
    }

    // ---------------- the request body ----------------

    /// <summary>The JSON to POST, for at most <paramref name="cap"/> probes (fewer than asked for when the hourly limit
    /// has fewer tests left).</summary>
    public string Json(int? cap = null)
    {
        int want = Probes;
        int allowed = cap is int c ? Math.Clamp(c, 1, want) : want;
        var locations = Limit is null && allowed < want ? Shrink(Locations, allowed) : Locations;
        using var ms = new MemoryStream();
        using (var j = new Utf8JsonWriter(ms))
        {
            j.WriteStartObject();
            j.WriteString("type", Kind switch { CheckHostKind.Http => "http", CheckHostKind.Dns => "dns", _ => "ping" });
            j.WriteString("target", Target);
            // each probe's result as it finishes (true would also stream the first five probes' raw output)
            j.WriteBoolean("inProgressUpdates", false);
            if (locations.Count > 0)
            {
                j.WriteStartArray("locations");
                foreach (var l in locations)
                {
                    j.WriteStartObject();
                    j.WriteString(l.Field, l.Value);
                    if (l.City is { } city) j.WriteString("city", city);
                    if (Limit is null) j.WriteNumber("limit", l.Limit ?? 1);
                    j.WriteEndObject();
                }
                j.WriteEndArray();
            }
            if (Limit is int limit) j.WriteNumber("limit", Math.Min(limit, allowed));
            j.WriteStartObject("measurementOptions");
            switch (Kind)
            {
                case CheckHostKind.Ping:
                    j.WriteNumber("packets", PingPackets);
                    break;
                case CheckHostKind.Tcp:
                    j.WriteString("protocol", "TCP");
                    j.WriteNumber("port", Port ?? 80);
                    j.WriteNumber("packets", TcpPackets);
                    break;
                case CheckHostKind.Dns:
                    j.WriteStartObject("query");
                    j.WriteString("type", "A");
                    j.WriteEndObject();
                    break;
                case CheckHostKind.Http:
                    j.WriteString("protocol", Protocol);
                    if (Port is int port) j.WriteNumber("port", port);
                    j.WriteStartObject("request");
                    j.WriteString("method", "HEAD");
                    j.WriteString("path", Path);
                    if (Query.Length > 0) j.WriteString("query", Query);
                    j.WriteEndObject();
                    break;
            }
            j.WriteEndObject();
            j.WriteEndObject();
        }
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    // fewer probes over the same places: the largest counts give first, a place left with none goes
    private static IReadOnlyList<GlobalpingLocation> Shrink(IReadOnlyList<GlobalpingLocation> locations, int total)
    {
        var counts = locations.Select(l => l.Limit ?? 1).ToArray();
        while (counts.Sum() > total)
        {
            int at = Array.IndexOf(counts, counts.Max());
            counts[at]--;
        }
        return locations.Select((l, i) => l with { Limit = counts[i] }).Where(l => l.Limit > 0).ToList();
    }
}
