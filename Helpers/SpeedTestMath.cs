using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;

namespace Echoes.Helpers;

/// <summary>The arithmetic of a speed test (pure functions, so they can be checked on their own).</summary>
public static class SpeedTestMath
{
    public static double Median(IReadOnlyList<double> values)
    {
        if (values.Count == 0) return double.NaN;
        var sorted = values.OrderBy(v => v).ToArray();
        int mid = sorted.Length / 2;
        return sorted.Length % 2 == 1 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
    }

    /// <summary>The mean absolute difference of consecutive samples (as Cloudflare's own page computes jitter).</summary>
    public static double Jitter(IReadOnlyList<double> values)
    {
        if (values.Count < 2) return double.NaN;
        double sum = 0;
        for (int i = 1; i < values.Count; i++) sum += Math.Abs(values[i] - values[i - 1]);
        return sum / (values.Count - 1);
    }

    /// <summary>Server processing time (ms) from Server-Timing: cfRequestDuration (cfReqDur…) when present, else the sum
    /// of the cfSpeed* entries (cfSpeedEdge, cfSpeedWorker); 0 when there is none.</summary>
    public static double ServerTimeMs(IEnumerable<string>? headerValues)
    {
        if (headerValues is null) return 0;
        double request = 0, speed = 0;
        foreach (string value in headerValues)
        {
            foreach (string entry in SplitOutsideQuotes(value, ','))
            {
                var parts = SplitOutsideQuotes(entry, ';');
                if (parts.Count == 0) continue;
                string name = parts[0].Trim();
                double dur = double.NaN;
                for (int i = 1; i < parts.Count; i++)
                {
                    string p = parts[i].Trim();
                    if (p.StartsWith("dur=", StringComparison.OrdinalIgnoreCase)
                        && double.TryParse(p.AsSpan(4).Trim('"'), NumberStyles.Float, CultureInfo.InvariantCulture, out double d))
                        dur = d;
                }
                if (double.IsNaN(dur) || dur < 0) continue;
                if (IsRequestDuration(name)) request = dur;
                else if (name.StartsWith("cfSpeed", StringComparison.OrdinalIgnoreCase)) speed += dur;
            }
        }
        return request > 0.01 ? request : speed > 0.01 ? speed : 0;

        // cfReqDur, cfRequestDur, cfReqDuration, cfRequestDuration
        static bool IsRequestDuration(string n)
            => n.Equals("cfReqDur", StringComparison.OrdinalIgnoreCase) || n.Equals("cfRequestDur", StringComparison.OrdinalIgnoreCase)
            || n.Equals("cfReqDuration", StringComparison.OrdinalIgnoreCase) || n.Equals("cfRequestDuration", StringComparison.OrdinalIgnoreCase);
    }

    private static List<string> SplitOutsideQuotes(string s, char separator)
    {
        var parts = new List<string>();
        bool quoted = false;
        int start = 0;
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] == '"') quoted = !quoted;
            else if (s[i] == separator && !quoted)
            {
                parts.Add(s[start..i]);
                start = i + 1;
            }
        }
        parts.Add(s[start..]);
        return parts;
    }

    /// <summary>Throughput (Mbps) over the last <paramref name="window"/> seconds of the samples, not reaching back before
    /// <paramref name="notBefore"/> seconds; NaN until there is a stretch of at least 0.3 s to measure.</summary>
    public static double RecentMbps(IReadOnlyList<(double T, long Bytes)> samples, double window, double notBefore = 0)
    {
        if (samples.Count < 2) return double.NaN;
        var last = samples[^1];
        double from = Math.Max(last.T - window, notBefore);
        int j = 0;
        while (j < samples.Count - 1 && samples[j].T < from) j++;
        double dt = last.T - samples[j].T;
        return dt >= 0.3 ? (last.Bytes - samples[j].Bytes) * 8 / dt / 1e6 : double.NaN;
    }

    /// <summary>
    /// Steady-state throughput (Mbps) of a transfer phase from its byte counter's samples (seconds, bytes). The plateau is
    /// the median 1-second rate over the later part of the phase; the steady stretch starts at the first sample past
    /// <paramref name="rampSeconds"/> whose 1-second rate reaches 80 % of it (so the TCP slow-start ramp — and an
    /// upload's buffer-filling burst — stay out) and ends at <paramref name="endSeconds"/>. Falls back to the plateau
    /// when that stretch is under a second, and to the plain average when there are too few samples for either.
    /// </summary>
    public static double SteadyMbps(IReadOnlyList<(double T, long Bytes)> samples, double rampSeconds, double endSeconds)
    {
        int e = samples.Count - 1;
        while (e > 0 && samples[e].T > endSeconds + 1e-9) e--;
        if (e <= 0) return double.NaN;
        double total = samples[e].T - samples[0].T;
        double average = total > 0 ? (samples[e].Bytes - samples[0].Bytes) * 8 / total / 1e6 : double.NaN;

        var rates = new double[e + 1];
        for (int i = 0; i <= e; i++)
        {
            rates[i] = double.NaN;
            int j = i;
            while (j > 0 && samples[i].T - samples[j - 1].T <= 1.0 + 1e-9) j--;
            double dt = samples[i].T - samples[j].T;
            if (dt >= 0.9) rates[i] = (samples[i].Bytes - samples[j].Bytes) * 8 / dt / 1e6;
        }

        double tailFrom = Math.Max(rampSeconds + 1.0, samples[e].T * 0.4);
        var tail = new List<double>();
        for (int i = 0; i <= e; i++)
            if (samples[i].T >= tailFrom && !double.IsNaN(rates[i])) tail.Add(rates[i]);
        // A phase too short for a plateau (a fast link spent its byte cap within a couple of seconds): its last full
        // second, which lies past the ramp, else the plain average.
        if (tail.Count == 0)
            return samples[e].T >= rampSeconds && !double.IsNaN(rates[e]) ? rates[e] : average;
        double plateau = Median(tail);

        int s = -1;
        for (int i = 0; i <= e; i++)
            if (samples[i].T >= rampSeconds && !double.IsNaN(rates[i]) && rates[i] >= 0.8 * plateau) { s = i; break; }
        if (s < 0 || samples[e].T - samples[s].T < 1.0) return plateau;
        return (samples[e].Bytes - samples[s].Bytes) * 8 / (samples[e].T - samples[s].T) / 1e6;
    }

    /// <summary>The next request's size: what this stream would move in <paramref name="targetSeconds"/> at the rate just
    /// seen, at most 4× (and at least half) the last size, within [min, max].</summary>
    public static long NextChunk(long size, long moved, double seconds, double targetSeconds, long min, long max)
    {
        if (moved <= 0 || seconds <= 0) return Math.Clamp(size, min, max);
        double ideal = moved / seconds * targetSeconds;
        double next = Math.Clamp(ideal, size / 2.0, size * 4.0);
        return Math.Clamp((long)next, min, max);
    }

    /// <summary>speed.cloudflare.com/meta: {"clientIp","asn","asOrganization","country","city","colo":{"iata","city","cca2"}}.</summary>
    public static SpeedTestServer? ParseMeta(ReadOnlySpan<byte> json)
    {
        try
        {
            var reader = new Utf8JsonReader(json);
            using var doc = JsonDocument.ParseValue(ref reader);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return null;
            string? colo = null, coloCity = null, coloCountry = null;
            if (root.TryGetProperty("colo", out var c))
            {
                if (c.ValueKind == JsonValueKind.Object)
                {
                    colo = Str(c, "iata");
                    coloCity = Str(c, "city");
                    coloCountry = Str(c, "cca2");
                }
                else if (c.ValueKind == JsonValueKind.String) colo = c.GetString();
            }
            int asn = root.TryGetProperty("asn", out var a) && a.ValueKind == JsonValueKind.Number && a.TryGetInt32(out int n) ? n : 0;
            var server = new SpeedTestServer
            {
                Colo = colo, ColoCity = coloCity, ColoCountry = coloCountry,
                ClientIp = Str(root, "clientIp"), Isp = Str(root, "asOrganization"), Asn = asn,
                ClientCity = Str(root, "city"), ClientCountry = Str(root, "country"),
            };
            return server.Colo is null && server.ClientIp is null ? null : server;
        }
        catch (JsonException) { return null; }

        static string? Str(JsonElement e, string name)
            => e.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String ? CleanLabel(p.GetString()) : null;
    }

    /// <summary>The longest label kept from the service (a data center, an ISP's name, a city).</summary>
    public const int MaxLabel = 100;

    /// <summary>
    /// A name from the service as the card, the copied result and the saved history may show it: its JSON escapes can
    /// carry any character, so control characters become spaces, invisible format characters (bidi overrides,
    /// zero-width) go, runs of spaces collapse, and it is cut at <see cref="MaxLabel"/>. Null for nothing left.
    /// </summary>
    public static string? CleanLabel(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        var sb = new System.Text.StringBuilder(Math.Min(s.Length, MaxLabel));
        for (int i = 0; i < s.Length && sb.Length < MaxLabel; i++)
        {
            char c = s[i];
            if (char.IsSurrogate(c))
            {
                // a pair is kept unless it encodes a format character (the U+E0000 tags); a lone half is dropped
                if (char.IsHighSurrogate(c) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]))
                {
                    var pairCategory = CharUnicodeInfo.GetUnicodeCategory(char.ConvertToUtf32(c, s[i + 1]));
                    if (pairCategory is not (UnicodeCategory.Format or UnicodeCategory.PrivateUse) && sb.Length + 2 <= MaxLabel)
                        sb.Append(c).Append(s[i + 1]);
                    i++;
                }
                continue;
            }
            if (CharUnicodeInfo.GetUnicodeCategory(c) is UnicodeCategory.Format or UnicodeCategory.PrivateUse) continue;
            bool space = char.IsControl(c) || char.IsWhiteSpace(c);
            if (space && (sb.Length == 0 || sb[^1] == ' ')) continue;
            sb.Append(space ? ' ' : c);
        }
        string r = sb.ToString().TrimEnd();
        return r.Length == 0 ? null : r;
    }
}
