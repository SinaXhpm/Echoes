using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;

namespace Echoes.Helpers;

/// <summary>
/// The zone traffic summary from the GraphQL Analytics API (POST /graphql, Zone → Analytics : Read).
///
/// <para>Last 24 hours = <c>httpRequests1hGroups</c>, last 7 days = <c>httpRequests1dGroups</c> (both on every plan).
/// One request asks for the totals (no dimensions: one aggregated group, so unique visitors are counted over the whole
/// range) and the per-hour / per-day series for the bars. The values that go into the query are generated here (a
/// validated zone id, formatted dates), so nothing user-typed is ever spliced into it.</para>
/// </summary>
public static class CloudflareAnalytics
{
    public sealed class Bucket
    {
        public DateTime Start { get; init; }
        public long Requests { get; init; }
        public long Cached { get; init; }
    }

    public sealed class Country
    {
        public string Code { get; init; } = string.Empty;
        public long Requests { get; init; }
        public long Threats { get; init; }
    }

    public sealed class Summary
    {
        public bool Week { get; init; }
        public long Requests { get; init; }
        public long CachedRequests { get; init; }
        public long Bytes { get; init; }
        public long CachedBytes { get; init; }
        public long Threats { get; init; }
        public long PageViews { get; init; }
        public long Uniques { get; init; }
        public List<Bucket> Series { get; } = new();
        /// <summary>Countries by requests, most first.</summary>
        public List<Country> Countries { get; } = new();
    }

    private const string Sums = "requests cachedRequests bytes cachedBytes threats pageViews countryMap { clientCountryName requests threats }";

    /// <summary>The query for the last 24 hours (24 hourly buckets up to now) or the last 7 days (7 days up to today).</summary>
    public static string BuildQuery(string zoneId, bool week, DateTime nowUtc)
    {
        if (!CloudflareApi.IsId(zoneId)) throw new ArgumentException("Invalid zone id.");
        string zone = zoneId.ToLowerInvariant();
        var sb = new StringBuilder();
        sb.Append("{ viewer { zones(filter: {zoneTag: \"").Append(zone).Append("\"}) { ");
        if (week)
        {
            DateTime today = nowUtc.Date;
            string from = today.AddDays(-6).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            string to = today.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            string filter = $"filter: {{date_geq: \"{from}\", date_leq: \"{to}\"}}";
            sb.Append("totals: httpRequests1dGroups(limit: 1, ").Append(filter).Append(") { sum { ").Append(Sums).Append(" } uniq { uniques } } ");
            sb.Append("series: httpRequests1dGroups(limit: 10, ").Append(filter).Append(", orderBy: [date_ASC]) { dimensions { date } sum { requests cachedRequests } } ");
        }
        else
        {
            DateTime hour = new(nowUtc.Year, nowUtc.Month, nowUtc.Day, nowUtc.Hour, 0, 0, DateTimeKind.Utc);
            string from = hour.AddHours(-23).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
            string to = hour.AddHours(1).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
            string filter = $"filter: {{datetime_geq: \"{from}\", datetime_lt: \"{to}\"}}";
            sb.Append("totals: httpRequests1hGroups(limit: 1, ").Append(filter).Append(") { sum { ").Append(Sums).Append(" } uniq { uniques } } ");
            sb.Append("series: httpRequests1hGroups(limit: 30, ").Append(filter).Append(", orderBy: [datetime_ASC]) { dimensions { datetime } sum { requests cachedRequests } } ");
        }
        sb.Append("} } }");
        return sb.ToString();
    }

    /// <summary>Read the "data" of the query above. A zone without traffic yet has no groups: all zeros.</summary>
    public static Summary Parse(JsonNode? data, bool week)
    {
        var zone = (data?["viewer"]?["zones"] as JsonArray) is { Count: > 0 } zones ? zones[0] : null;
        var total = (zone?["totals"] as JsonArray) is { Count: > 0 } t ? t[0] : null;
        var sum = total?["sum"];
        var s = new Summary
        {
            Week = week,
            Requests = CfJson.Long(sum?["requests"]) ?? 0,
            CachedRequests = CfJson.Long(sum?["cachedRequests"]) ?? 0,
            Bytes = CfJson.Long(sum?["bytes"]) ?? 0,
            CachedBytes = CfJson.Long(sum?["cachedBytes"]) ?? 0,
            Threats = CfJson.Long(sum?["threats"]) ?? 0,
            PageViews = CfJson.Long(sum?["pageViews"]) ?? 0,
            Uniques = CfJson.Long(total?["uniq"]?["uniques"]) ?? 0,
        };

        if (sum?["countryMap"] is JsonArray countries)
        {
            var merged = new Dictionary<string, (long Req, long Thr)>(StringComparer.Ordinal);
            foreach (var c in countries)
            {
                string code = CfJson.Str(c?["clientCountryName"]).Trim().ToUpperInvariant();
                if (code.Length is 0 or > 3) code = "XX";
                merged.TryGetValue(code, out var cur);
                merged[code] = (cur.Req + (CfJson.Long(c?["requests"]) ?? 0), cur.Thr + (CfJson.Long(c?["threats"]) ?? 0));
            }
            foreach (var (code, v) in merged) s.Countries.Add(new Country { Code = code, Requests = v.Req, Threats = v.Thr });
            s.Countries.Sort((a, b) => b.Requests.CompareTo(a.Requests));
        }

        if (zone?["series"] is JsonArray series)
            foreach (var g in series)
            {
                string key = week ? CfJson.Str(g?["dimensions"]?["date"]) : CfJson.Str(g?["dimensions"]?["datetime"]);
                if (!DateTime.TryParse(key, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var start))
                    continue;
                s.Series.Add(new Bucket
                {
                    Start = start,
                    Requests = CfJson.Long(g?["sum"]?["requests"]) ?? 0,
                    Cached = CfJson.Long(g?["sum"]?["cachedRequests"]) ?? 0,
                });
            }
        s.Series.Sort((a, b) => a.Start.CompareTo(b.Start));
        return s;
    }

    // ---------------------------------------------------------------- formatting

    /// <summary>1234 → "1,234"; 15300 → "15.3K"; 2400000 → "2.4M".</summary>
    public static string Count(long n)
    {
        if (n < 10_000) return n.ToString("N0", CultureInfo.InvariantCulture);
        if (n < 1_000_000) return (n / 1000d).ToString(n < 100_000 ? "0.#" : "0", CultureInfo.InvariantCulture) + "K";
        if (n < 1_000_000_000) return (n / 1_000_000d).ToString(n < 100_000_000 ? "0.#" : "0", CultureInfo.InvariantCulture) + "M";
        return (n / 1_000_000_000d).ToString("0.#", CultureInfo.InvariantCulture) + "B";
    }

    /// <summary>Bytes in binary units: "512 B", "3.4 MB", "1.2 GB".</summary>
    public static string Bytes(long b)
    {
        string[] units = { "B", "KB", "MB", "GB", "TB", "PB" };
        double v = b;
        int u = 0;
        while (v >= 1024 && u < units.Length - 1) { v /= 1024; u++; }
        return u == 0 ? $"{b} B" : v.ToString(v < 100 ? "0.#" : "0", CultureInfo.InvariantCulture) + " " + units[u];
    }

    /// <summary>part of whole as "42%" ("0%" for no traffic; "<1%" for a sliver).</summary>
    public static string Percent(long part, long whole)
    {
        if (whole <= 0 || part <= 0) return "0%";
        double p = 100d * part / whole;
        return p < 1 ? "<1%" : Math.Round(p).ToString(CultureInfo.InvariantCulture) + "%";
    }
}

/// <summary>ISO 3166-1 alpha-2 country names (plus Cloudflare's T1 = Tor and XX = unknown), for the analytics countries
/// and the country rules of IP access. Built once, on first use.</summary>
public static class CloudflareCountries
{
    private const string Table =
        "AD:Andorra|AE:United Arab Emirates|AF:Afghanistan|AG:Antigua and Barbuda|AI:Anguilla|AL:Albania|AM:Armenia|AO:Angola|" +
        "AQ:Antarctica|AR:Argentina|AS:American Samoa|AT:Austria|AU:Australia|AW:Aruba|AX:Åland Islands|AZ:Azerbaijan|" +
        "BA:Bosnia and Herzegovina|BB:Barbados|BD:Bangladesh|BE:Belgium|BF:Burkina Faso|BG:Bulgaria|BH:Bahrain|BI:Burundi|" +
        "BJ:Benin|BL:Saint Barthélemy|BM:Bermuda|BN:Brunei|BO:Bolivia|BQ:Caribbean Netherlands|BR:Brazil|BS:Bahamas|BT:Bhutan|" +
        "BV:Bouvet Island|BW:Botswana|BY:Belarus|BZ:Belize|CA:Canada|CC:Cocos (Keeling) Islands|CD:DR Congo|" +
        "CF:Central African Republic|CG:Congo|CH:Switzerland|CI:Côte d'Ivoire|CK:Cook Islands|CL:Chile|CM:Cameroon|CN:China|" +
        "CO:Colombia|CR:Costa Rica|CU:Cuba|CV:Cape Verde|CW:Curaçao|CX:Christmas Island|CY:Cyprus|CZ:Czechia|DE:Germany|" +
        "DJ:Djibouti|DK:Denmark|DM:Dominica|DO:Dominican Republic|DZ:Algeria|EC:Ecuador|EE:Estonia|EG:Egypt|EH:Western Sahara|" +
        "ER:Eritrea|ES:Spain|ET:Ethiopia|FI:Finland|FJ:Fiji|FK:Falkland Islands|FM:Micronesia|FO:Faroe Islands|FR:France|" +
        "GA:Gabon|GB:United Kingdom|GD:Grenada|GE:Georgia|GF:French Guiana|GG:Guernsey|GH:Ghana|GI:Gibraltar|GL:Greenland|" +
        "GM:Gambia|GN:Guinea|GP:Guadeloupe|GQ:Equatorial Guinea|GR:Greece|GS:South Georgia|GT:Guatemala|GU:Guam|" +
        "GW:Guinea-Bissau|GY:Guyana|HK:Hong Kong|HM:Heard and McDonald Islands|HN:Honduras|HR:Croatia|HT:Haiti|HU:Hungary|" +
        "ID:Indonesia|IE:Ireland|IL:Israel|IM:Isle of Man|IN:India|IO:British Indian Ocean Territory|IQ:Iraq|IR:Iran|" +
        "IS:Iceland|IT:Italy|JE:Jersey|JM:Jamaica|JO:Jordan|JP:Japan|KE:Kenya|KG:Kyrgyzstan|KH:Cambodia|KI:Kiribati|KM:Comoros|" +
        "KN:Saint Kitts and Nevis|KP:North Korea|KR:South Korea|KW:Kuwait|KY:Cayman Islands|KZ:Kazakhstan|LA:Laos|LB:Lebanon|" +
        "LC:Saint Lucia|LI:Liechtenstein|LK:Sri Lanka|LR:Liberia|LS:Lesotho|LT:Lithuania|LU:Luxembourg|LV:Latvia|LY:Libya|" +
        "MA:Morocco|MC:Monaco|MD:Moldova|ME:Montenegro|MF:Saint Martin|MG:Madagascar|MH:Marshall Islands|MK:North Macedonia|" +
        "ML:Mali|MM:Myanmar|MN:Mongolia|MO:Macao|MP:Northern Mariana Islands|MQ:Martinique|MR:Mauritania|MS:Montserrat|" +
        "MT:Malta|MU:Mauritius|MV:Maldives|MW:Malawi|MX:Mexico|MY:Malaysia|MZ:Mozambique|NA:Namibia|NC:New Caledonia|NE:Niger|" +
        "NF:Norfolk Island|NG:Nigeria|NI:Nicaragua|NL:Netherlands|NO:Norway|NP:Nepal|NR:Nauru|NU:Niue|NZ:New Zealand|OM:Oman|" +
        "PA:Panama|PE:Peru|PF:French Polynesia|PG:Papua New Guinea|PH:Philippines|PK:Pakistan|PL:Poland|" +
        "PM:Saint Pierre and Miquelon|PN:Pitcairn Islands|PR:Puerto Rico|PS:Palestine|PT:Portugal|PW:Palau|PY:Paraguay|" +
        "QA:Qatar|RE:Réunion|RO:Romania|RS:Serbia|RU:Russia|RW:Rwanda|SA:Saudi Arabia|SB:Solomon Islands|SC:Seychelles|" +
        "SD:Sudan|SE:Sweden|SG:Singapore|SH:Saint Helena|SI:Slovenia|SJ:Svalbard and Jan Mayen|SK:Slovakia|SL:Sierra Leone|" +
        "SM:San Marino|SN:Senegal|SO:Somalia|SR:Suriname|SS:South Sudan|ST:São Tomé and Príncipe|SV:El Salvador|" +
        "SX:Sint Maarten|SY:Syria|SZ:Eswatini|TC:Turks and Caicos Islands|TD:Chad|TF:French Southern Territories|TG:Togo|" +
        "TH:Thailand|TJ:Tajikistan|TK:Tokelau|TL:Timor-Leste|TM:Turkmenistan|TN:Tunisia|TO:Tonga|TR:Türkiye|" +
        "TT:Trinidad and Tobago|TV:Tuvalu|TW:Taiwan|TZ:Tanzania|UA:Ukraine|UG:Uganda|UM:U.S. Outlying Islands|US:United States|" +
        "UY:Uruguay|UZ:Uzbekistan|VA:Vatican City|VC:Saint Vincent and the Grenadines|VE:Venezuela|VG:British Virgin Islands|" +
        "VI:U.S. Virgin Islands|VN:Vietnam|VU:Vanuatu|WF:Wallis and Futuna|WS:Samoa|XK:Kosovo|YE:Yemen|YT:Mayotte|" +
        "ZA:South Africa|ZM:Zambia|ZW:Zimbabwe|T1:Tor network|XX:Unknown";

    // Other common spellings typed into the IP access box.
    private static readonly (string Alias, string Code)[] Aliases =
    {
        ("usa", "US"), ("united states of america", "US"), ("america", "US"), ("uk", "GB"), ("great britain", "GB"),
        ("britain", "GB"), ("england", "GB"), ("turkey", "TR"), ("czech republic", "CZ"), ("russian federation", "RU"),
        ("korea", "KR"), ("holland", "NL"), ("tor", "T1"), ("ivory coast", "CI"), ("burma", "MM"), ("swaziland", "SZ"),
    };

    private static Dictionary<string, string>? _byCode;
    private static Dictionary<string, string>? _byName;

    private static void Build()
    {
        if (_byCode != null) return;
        var byCode = new Dictionary<string, string>(StringComparer.Ordinal);
        var byName = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string entry in Table.Split('|'))
        {
            string code = entry[..2], name = entry[3..];
            byCode[code] = name;
            byName[name] = code;
        }
        foreach (var (alias, code) in Aliases) byName.TryAdd(alias, code);
        _byName = byName;
        _byCode = byCode;
    }

    /// <summary>"DE" → "Germany"; an unknown code comes back as itself.</summary>
    public static string Name(string code)
    {
        Build();
        string c = (code ?? string.Empty).Trim().ToUpperInvariant();
        return _byCode!.TryGetValue(c, out var n) ? n : c;
    }

    public static bool IsCode(string code)
    {
        Build();
        return _byCode!.ContainsKey((code ?? string.Empty).Trim().ToUpperInvariant());
    }

    /// <summary>A country code from a code ("de") or an English name ("Germany", "usa"); null when neither.</summary>
    public static string? Find(string text)
    {
        Build();
        string t = (text ?? string.Empty).Trim();
        if (t.Length == 2 && _byCode!.ContainsKey(t.ToUpperInvariant())) return t.ToUpperInvariant();
        return _byName!.TryGetValue(t, out var code) ? code : null;
    }
}
