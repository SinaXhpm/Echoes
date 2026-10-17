using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace Echoes.Helpers;

/// <summary>What a destination runs, which decides how it is measured (<see cref="SpeedTestProviders"/>).</summary>
public enum SpeedTestKind
{
    /// <summary>speed.cloudflare.com or a server with the same API: GET __down?bytes=N, POST __up.</summary>
    Cloudflare,
    /// <summary>A big file on a web server: downloads (Range requests), latency (a 1-byte range); upload only with an
    /// upload URL beside it.</summary>
    File,
    /// <summary>An Ookla Speedtest server (OoklaServer daemon): /latency.txt, /download?size=N, POST /upload.</summary>
    Speedtest,
    /// <summary>A LibreSpeed backend: garbage.php?ckSize=N, empty.php (latency, and POST for upload).</summary>
    LibreSpeed,
    /// <summary>A bare server address typed by the user: what it runs is found out when the test starts.</summary>
    Auto,
}

/// <summary>
/// One place a speed test can run against: a curated public host, or one the user added (a file, or a LibreSpeed,
/// Speedtest or Cloudflare-style server). Immutable; the picker, the engine and the saved list all share it.
/// </summary>
public sealed class SpeedTestDestination
{
    public required string Id { get; init; }
    public required SpeedTestKind Kind { get; init; }
    /// <summary>Who runs it ("Leaseweb", "DataPacket"), or the name the user gave it.</summary>
    public required string Provider { get; init; }
    /// <summary>The city ("Falkenstein"), empty when unknown.</summary>
    public string Place { get; init; } = "";
    /// <summary>The country's English name ("Germany"), empty when unknown.</summary>
    public string Country { get; init; } = "";
    /// <summary>ISO 3166 alpha-2, upper case ("DE"), empty when unknown.</summary>
    public string CountryCode { get; init; } = "";
    /// <summary>The picker group: "Europe", "Asia", "Americas" (curated), or set by the list it comes from.</summary>
    public string Region { get; init; } = "";
    /// <summary>The file (File) or the server's base address (the others).</summary>
    public required Uri Url { get; init; }
    /// <summary>The same host over plain HTTP, tried automatically when HTTPS can't connect (blocked or not served).</summary>
    public Uri? HttpFallback { get; init; }
    /// <summary>File destinations: where uploads go (POST), when the host takes them.</summary>
    public Uri? UploadUrl { get; init; }
    /// <summary>Speedtest servers: the distance speedtest.net gives (km); NaN otherwise.</summary>
    public double DistanceKm { get; init; } = double.NaN;
    /// <summary>Added by the user: shown under "Saved", removable.</summary>
    public bool Saved { get; init; }
    /// <summary>The most connections the host takes from one address at a time, the latency probe's included; 0 when
    /// there is no known limit. The engine runs fewer streams than the user's setting to stay under it.</summary>
    public int MaxConnections { get; init; }

    /// <summary>"Leaseweb · Amsterdam", "Cloudflare", "My server".</summary>
    public string Name => Place.Length > 0 ? $"{Provider} · {Place}" : Provider;

    /// <summary>Upload support as far as is known before connecting (null: found out when the test starts).</summary>
    public bool? HasUpload => Kind switch
    {
        SpeedTestKind.Cloudflare or SpeedTestKind.Speedtest or SpeedTestKind.LibreSpeed => true,
        SpeedTestKind.File => UploadUrl is not null,
        _ => UploadUrl is not null ? true : null,
    };

    public bool Secure => Url.Scheme == Uri.UriSchemeHttps;

    /// <summary>What it measures, for the picker: "download and upload" / "download only".</summary>
    public string Measures => HasUpload switch
    {
        true => "download and upload",
        false => "download only",
        _ => "checked when the test starts",
    };

    /// <summary>The same destination kept in the saved list.</summary>
    public SpeedTestDestination AsSaved() => new()
    {
        Id = Id, Kind = Kind, Provider = Provider, Place = Place, Country = Country, CountryCode = CountryCode,
        Region = SpeedTestDestinations.SavedRegion, Url = Url, HttpFallback = HttpFallback, UploadUrl = UploadUrl,
        DistanceKm = DistanceKm, Saved = true,
    };

    public override string ToString() => Name;
}

/// <summary>
/// The curated destinations (each checked to serve its file to a ranged GET), custom destinations typed by the user,
/// and the saved list in the profile (written with Utf8JsonWriter / read with JsonDocument: AOT-safe).
/// </summary>
public static class SpeedTestDestinations
{
    public const string AutomaticRegion = "Automatic";
    public const string SavedRegion = "Saved";
    public const string SavedKey = "speed.saved";
    public const string SelectedKey = "speed.dest";
    public const int MaxSavedCustom = 20;
    public const int MaxUrlLength = 2000;
    public const int MaxNameLength = 60;

    public static readonly SpeedTestDestination Cloudflare = new()
    {
        Id = "cf", Kind = SpeedTestKind.Cloudflare, Provider = "Cloudflare", Place = "",
        Region = AutomaticRegion, Url = new Uri("https://speed.cloudflare.com/"),
    };

    /// <summary>
    /// The public test-file hosts, by region, then country and city (the picker shows them in this order). Each one
    /// answered a 1-byte and a 64 KB ranged GET (206) and kept six parallel streams going when it was added: Linode,
    /// Leaseweb, Scaleway, Tele2 (2026-10), DataPacket and Selectel (2026-10-16). HTTPS is tried first where it is
    /// served, plain HTTP is the fallback (Leaseweb's HTTPS, and Linode's in London / Fremont, were reset on the test
    /// network; their HTTP worked); Scaleway and Tele2 are HTTP only (their pages link HTTP). Tele2 also takes uploads
    /// (POST upload.php); the others measure download and latency. DataPacket's Istanbul takes five connections from one
    /// address and answers 503 to the sixth, so a test there runs at most four streams (plus the latency probe's).
    /// Left out: Hetzner's speed hosts and OVH's
    /// proof.ovh.ca (HTTP 429 once a handful of requests arrive from one address: a six-connection test lost four of its
    /// streams), Vultr's looking-glass files (HTTP 503 with a few parallel requests), OVH Roubaix and librespeed.org
    /// (blocked on the test network), DigitalOcean's speedtest hosts (retired). The speedtest.net servers aren't listed:
    /// near a connection they are its own country's ISPs, which measure the domestic network rather than the internet.
    /// </summary>
    public static readonly IReadOnlyList<SpeedTestDestination> Curated = new[]
    {
        Cloudflare,
        // ---- Europe
        DataPacket("vie", "Vienna", "Austria", "AT"),
        DataPacket("sof", "Sofia", "Bulgaria", "BG"),
        DataPacket("prg", "Prague", "Czechia", "CZ"),
        DataPacket("par", "Paris", "France", "FR"),
        File("sw-par", "Scaleway", "Paris", "France", "FR", "Europe", "http://ping.online.net/10000Mo.dat"),
        DataPacket("fra", "Frankfurt", "Germany", "DE"),
        File("lw-fra", "Leaseweb", "Frankfurt", "Germany", "DE", "Europe", "https://speedtest.fra1.de.leaseweb.net/10000mb.bin", fallback: true),
        File("li-fra", "Linode", "Frankfurt", "Germany", "DE", "Europe", "https://speedtest.frankfurt.linode.com/100MB-frankfurt.bin", fallback: true),
        DataPacket("ath", "Athens", "Greece", "GR"),
        DataPacket("mil", "Milan", "Italy", "IT"),
        DataPacket("ams", "Amsterdam", "Netherlands", "NL"),
        File("lw-ams", "Leaseweb", "Amsterdam", "Netherlands", "NL", "Europe", "https://speedtest.ams1.nl.leaseweb.net/10000mb.bin", fallback: true),
        File("sl-ru", "Selectel", "", "Russia", "RU", "Europe", "https://speedtest.selectel.ru/1GB", fallback: true),
        DataPacket("mad", "Madrid", "Spain", "ES"),
        DataPacket("sto", "Stockholm", "Sweden", "SE"),
        File("t2-sto", "Tele2", "Stockholm", "Sweden", "SE", "Europe", "http://speedtest.tele2.net/10GB.zip",
             upload: "http://speedtest.tele2.net/upload.php"),
        DataPacket("ist", "Istanbul", "Turkey", "TR", maxConnections: 5),
        DataPacket("lon", "London", "United Kingdom", "GB"),
        File("li-lon", "Linode", "London", "United Kingdom", "GB", "Europe", "https://speedtest.london.linode.com/100MB-london.bin", fallback: true),
        // ---- Asia
        File("lw-hkg", "Leaseweb", "Hong Kong", "Hong Kong", "HK", "Asia", "https://speedtest.hkg12.hk.leaseweb.net/10000mb.bin", fallback: true),
        File("li-bom", "Linode", "Mumbai", "India", "IN", "Asia", "https://speedtest.mumbai1.linode.com/100MB-mumbai1.bin", fallback: true),
        DataPacket("tyo", "Tokyo", "Japan", "JP", "Asia"),
        File("li-tyo", "Linode", "Tokyo", "Japan", "JP", "Asia", "https://speedtest.tokyo2.linode.com/100MB-tokyo2.bin", fallback: true),
        DataPacket("sin", "Singapore", "Singapore", "SG", "Asia"),
        File("lw-sin", "Leaseweb", "Singapore", "Singapore", "SG", "Asia", "https://speedtest.sin1.sg.leaseweb.net/10000mb.bin", fallback: true),
        // ---- Americas
        DataPacket("nyc", "New York", "United States", "US", "Americas"),
        File("li-ewr", "Linode", "Newark", "United States", "US", "Americas", "https://speedtest.newark.linode.com/100MB-newark.bin", fallback: true),
        File("lw-wdc", "Leaseweb", "Washington", "United States", "US", "Americas", "https://speedtest.wdc2.us.leaseweb.net/10000mb.bin", fallback: true),
        File("lw-sfo", "Leaseweb", "San Francisco", "United States", "US", "Americas", "https://speedtest.sfo12.us.leaseweb.net/10000mb.bin", fallback: true),
        File("li-fmt", "Linode", "Fremont", "United States", "US", "Americas", "https://speedtest.fremont.linode.com/100MB-fremont.bin", fallback: true),
    };

    // DataPacket's test file in one of its locations (a 10 GB file, HTTPS with an HTTP fallback).
    private static SpeedTestDestination DataPacket(string code, string place, string country, string cc, string region = "Europe",
                                                   int maxConnections = 0)
    {
        var d = File("dp-" + code, "DataPacket", place, country, cc, region, $"https://{code}.download.datapacket.com/10000mb.bin", fallback: true);
        return maxConnections > 0
            ? new SpeedTestDestination
            {
                Id = d.Id, Kind = d.Kind, Provider = d.Provider, Place = d.Place, Country = d.Country, CountryCode = d.CountryCode,
                Region = d.Region, Url = d.Url, HttpFallback = d.HttpFallback, MaxConnections = maxConnections,
            }
            : d;
    }

    private static SpeedTestDestination File(string id, string provider, string place, string country, string cc, string region,
                                             string url, bool fallback = false, string? upload = null)
    {
        var u = new Uri(url);
        return new SpeedTestDestination
        {
            Id = id, Kind = SpeedTestKind.File, Provider = provider, Place = place, Country = country, CountryCode = cc,
            Region = region, Url = u, UploadUrl = upload is null ? null : new Uri(upload),
            HttpFallback = fallback && u.Scheme == Uri.UriSchemeHttps ? new UriBuilder(u) { Scheme = Uri.UriSchemeHttp, Port = -1 }.Uri : null,
        };
    }

    public static SpeedTestDestination? FindCurated(string? id)
        => id is null ? null : Curated.FirstOrDefault(d => d.Id == id);

    // ---------------- custom destinations ----------------

    /// <summary>
    /// Checks what the user typed and builds the destination. <paramref name="address"/>: the URL of a big file, or of a
    /// server (LibreSpeed, Speedtest, Cloudflare-style); "https://" is assumed when no scheme is given. The kind is told
    /// from the address (see <see cref="Detect"/>). Returns false with one sentence in <paramref name="error"/>.
    /// </summary>
    public static bool TryCreateCustom(string? name, string? address, string? uploadAddress,
                                       out SpeedTestDestination? destination, out string error)
    {
        destination = null;
        if (!TryParseUrl(address, out var url, out error)) return false;
        Uri? upload = null;
        if (!string.IsNullOrWhiteSpace(uploadAddress))
        {
            if (!TryParseUrl(uploadAddress, out upload, out string upError))
            {
                error = "Upload URL: " + char.ToLowerInvariant(upError[0]) + upError[1..];
                return false;
            }
        }
        var (kind, baseUrl) = Detect(url!);
        string label = SpeedTestMath.CleanLabel(name) is { } n ? Cut(n, MaxNameLength) : url!.Host;
        destination = new SpeedTestDestination
        {
            Id = "c:" + Guid.NewGuid().ToString("N")[..12], Kind = kind, Provider = label, Url = baseUrl,
            UploadUrl = kind is SpeedTestKind.File or SpeedTestKind.Auto ? upload : null,
            Region = SavedRegion, Saved = true,
        };
        error = "";
        return true;
    }

    /// <summary>One sentence on what an address is taken for (the editor shows it while typing); null when it isn't a
    /// usable address yet.</summary>
    public static string? DescribeAddress(string? address, string? uploadAddress)
    {
        if (!TryParseUrl(address, out var url, out _)) return null;
        bool upload = !string.IsNullOrWhiteSpace(uploadAddress);
        return Detect(url!).Kind switch
        {
            SpeedTestKind.Cloudflare => "Cloudflare-style: download, upload, latency.",
            SpeedTestKind.LibreSpeed => "LibreSpeed: download, upload, latency.",
            SpeedTestKind.Speedtest => "Speedtest server: download, upload, latency.",
            SpeedTestKind.Auto => "A server: checked when the test starts.",
            _ => upload ? "A file: download, latency and upload." : "A file: download and latency.",
        };
    }

    /// <summary>
    /// What an address points at, from its shape alone: a Cloudflare-style API (…/__down, speed.cloudflare.com), a
    /// LibreSpeed backend (garbage.php, empty.php, getIP.php), a Speedtest server (…/speedtest/upload.php, /latency.txt,
    /// /hello, /download, /upload), a bare server address (a path ending in "/": probed when the test starts), else a
    /// file. Returns the base the kind's requests are built on.
    /// </summary>
    public static (SpeedTestKind Kind, Uri Base) Detect(Uri url)
    {
        string path = url.AbsolutePath;
        string last = path[(path.LastIndexOf('/') + 1)..].ToLowerInvariant();
        string dir = path[..(path.LastIndexOf('/') + 1)];
        Uri At(string p) => new UriBuilder(url) { Path = p, Query = "", Fragment = "" }.Uri;

        if (url.Host.Equals("speed.cloudflare.com", StringComparison.OrdinalIgnoreCase)) return (SpeedTestKind.Cloudflare, At("/"));
        if (last is "__down" or "__up") return (SpeedTestKind.Cloudflare, At(dir));
        if (last is "garbage.php" or "empty.php" or "getip.php") return (SpeedTestKind.LibreSpeed, At(dir));
        if (dir.EndsWith("/speedtest/", StringComparison.OrdinalIgnoreCase) && last is "upload.php" or "latency.txt" or "upload.asp" or "upload.aspx")
            return (SpeedTestKind.Speedtest, At("/"));
        if (dir == "/" && last is "latency.txt" or "hello" or "download" or "upload") return (SpeedTestKind.Speedtest, At("/"));
        if (last.Length == 0) return (SpeedTestKind.Auto, At(dir));
        return (SpeedTestKind.File, new UriBuilder(url) { Fragment = "" }.Uri);
    }

    /// <summary>An absolute http(s) URL with a host, no user name / password in it, at most
    /// <see cref="MaxUrlLength"/> characters. A missing scheme means https.</summary>
    public static bool TryParseUrl(string? text, out Uri? url, out string error)
    {
        url = null;
        string s = (text ?? "").Trim();
        if (s.Length == 0)
        {
            error = "Type the address of a big file or of a speed test server.";
            return false;
        }
        if (s.Length > MaxUrlLength)
        {
            error = $"That address is too long (over {MaxUrlLength} characters).";
            return false;
        }
        if (!s.Contains("://", StringComparison.Ordinal)) s = "https://" + s;
        if (!Uri.TryCreate(s, UriKind.Absolute, out var u) || (u.Scheme != Uri.UriSchemeHttp && u.Scheme != Uri.UriSchemeHttps)
            || string.IsNullOrEmpty(u.Host))
        {
            error = "That isn't a web address: use one like https://example.com/100MB.bin.";
            return false;
        }
        if (u.UserInfo.Length > 0)
        {
            error = "Leave the user name and password out of the address: speed test servers don't need them.";
            return false;
        }
        url = u;
        error = "";
        return true;
    }

    private static string Cut(string s, int max) => s.Length <= max ? s : s[..max].TrimEnd();

    // ---------------- the saved list (profile) ----------------

    public static List<SpeedTestDestination> LoadSaved() => ParseSaved(ProfileService.Instance.GetSetting(SavedKey));

    public static void SaveSaved(IReadOnlyList<SpeedTestDestination> saved)
        => ProfileService.Instance.SetSetting(SavedKey, SerializeSaved(saved));

    public static string SerializeSaved(IReadOnlyList<SpeedTestDestination> saved)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartArray();
            foreach (var d in saved)
            {
                w.WriteStartObject();
                w.WriteString("id", d.Id);
                w.WriteString("k", d.Kind.ToString());
                w.WriteString("p", d.Provider);
                if (d.Place.Length > 0) w.WriteString("pl", d.Place);
                if (d.Country.Length > 0) w.WriteString("co", d.Country);
                if (d.CountryCode.Length > 0) w.WriteString("cc", d.CountryCode);
                w.WriteString("u", d.Url.AbsoluteUri);
                if (d.HttpFallback is { } f) w.WriteString("f", f.AbsoluteUri);
                if (d.UploadUrl is { } up) w.WriteString("up", up.AbsoluteUri);
                if (!double.IsNaN(d.DistanceKm)) w.WriteNumber("km", Math.Round(d.DistanceKm, 1));
                w.WriteEndObject();
            }
            w.WriteEndArray();
        }
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    /// <summary>Tolerant: a damaged entry is skipped, a damaged value reads as an empty list — never an exception.
    /// Every URL is checked again (http/https, no credentials) and every label cleaned.</summary>
    public static List<SpeedTestDestination> ParseSaved(string? json)
    {
        var list = new List<SpeedTestDestination>();
        if (string.IsNullOrWhiteSpace(json)) return list;
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return list;
            int custom = 0;
            foreach (var e in doc.RootElement.EnumerateArray())
            {
                if (e.ValueKind != JsonValueKind.Object) continue;
                string? id = Str(e, "id");
                if (id is null || id.Length > 40 || list.Any(x => x.Id == id)) continue;
                if (!Enum.TryParse<SpeedTestKind>(Str(e, "k"), out var kind) || !Enum.IsDefined(kind)) continue;
                if (!TryParseUrl(Str(e, "u"), out var url, out _)) continue;
                Uri? fallback = TryParseUrl(Str(e, "f"), out var f, out _) && f!.Scheme == Uri.UriSchemeHttp && f.Host == url!.Host ? f : null;
                Uri? upload = Str(e, "up") is { } ups && TryParseUrl(ups, out var up, out _) ? up : null;
                // Only the user's own ("c:"). Older versions also kept the speedtest.net servers picked from the list
                // ("st:", the country's ISPs near the connection); that list is gone, so they are dropped here.
                if (!id.StartsWith("c:", StringComparison.Ordinal)) continue;
                if (++custom > MaxSavedCustom) continue;
                string cc = Str(e, "cc") is { Length: 2 } c && c.All(char.IsAsciiLetter) ? c.ToUpperInvariant() : "";
                list.Add(new SpeedTestDestination
                {
                    Id = id, Kind = kind, Provider = Cut(SpeedTestMath.CleanLabel(Str(e, "p")) ?? url!.Host, MaxNameLength),
                    Place = SpeedTestMath.CleanLabel(Str(e, "pl")) ?? "", Country = SpeedTestMath.CleanLabel(Str(e, "co")) ?? "",
                    CountryCode = cc, Region = SavedRegion, Url = url!, HttpFallback = fallback,
                    UploadUrl = kind is SpeedTestKind.File or SpeedTestKind.Auto ? upload : null,
                    DistanceKm = e.TryGetProperty("km", out var km) && km.ValueKind == JsonValueKind.Number && km.TryGetDouble(out double k) && k >= 0 ? k : double.NaN,
                    Saved = true,
                });
            }
        }
        catch (JsonException) { }
        return list;

        static string? Str(JsonElement e, string name)
            => e.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;
    }

    /// <summary>"Falkenstein, Germany" / "Helsinki, Finland · 3 km" / the host of a custom one.</summary>
    public static string Where(SpeedTestDestination d)
    {
        var parts = new List<string>(3);
        string loc = string.Join(", ", new[] { d.Place, d.Country.Length > 0 ? d.Country : d.CountryCode }.Where(s => s.Length > 0));
        if (loc.Length > 0) parts.Add(loc);
        else if (d.Kind != SpeedTestKind.Cloudflare) parts.Add(d.Url.Host);
        if (!double.IsNaN(d.DistanceKm)) parts.Add(d.DistanceKm.ToString(d.DistanceKm < 10 ? "0.#" : "0", CultureInfo.InvariantCulture) + " km");
        return string.Join(" · ", parts);
    }
}
