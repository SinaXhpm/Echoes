using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;

namespace Echoes.Helpers;

/// <summary>One finished speed test, as the history keeps it (NaN = that part didn't run or finish).
/// <paramref name="Server"/> names the destination ("Leaseweb · Amsterdam, NL", "Cloudflare · Frankfurt-am-Main (FRA)");
/// <paramref name="Connections"/> is the download's parallel connections (0 in entries from before the setting);
/// <paramref name="NoUpload"/>: the server takes no uploads.</summary>
public sealed record SpeedTestRecord(
    DateTimeOffset Time,
    double DownloadMbps,
    double UploadMbps,
    double LatencyMs,
    double JitterMs,
    double LoadedDownMs,
    double LoadedUpMs,
    string? Server,
    string? Isp,
    int Connections = 0,
    bool NoUpload = false);

/// <summary>
/// The last <see cref="Capacity"/> speed test results, newest first, kept in the profile as one compact JSON array
/// (written with Utf8JsonWriter / read with JsonDocument: no reflection, trim- and AOT-safe). The client's IP address is
/// deliberately not kept. Entries of older versions (local network tests among them) still read.
/// </summary>
public static class SpeedTestHistory
{
    public const string Key = "speed.history";
    public const int Capacity = 20;

    public static List<SpeedTestRecord> Load() => Parse(ProfileService.Instance.GetSetting(Key));

    public static void Save(IReadOnlyList<SpeedTestRecord> records)
        => ProfileService.Instance.SetSetting(Key, Serialize(records));

    public static string Serialize(IReadOnlyList<SpeedTestRecord> records)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartArray();
            for (int i = 0; i < records.Count && i < Capacity; i++)
            {
                var r = records[i];
                w.WriteStartObject();
                w.WriteString("t", r.Time.ToString("o", CultureInfo.InvariantCulture));
                Number(w, "d", r.DownloadMbps, 2);
                Number(w, "u", r.UploadMbps, 2);
                Number(w, "p", r.LatencyMs, 1);
                Number(w, "j", r.JitterMs, 1);
                Number(w, "ld", r.LoadedDownMs, 1);
                Number(w, "lu", r.LoadedUpMs, 1);
                if (!string.IsNullOrEmpty(r.Server)) w.WriteString("s", r.Server);
                if (!string.IsNullOrEmpty(r.Isp)) w.WriteString("i", r.Isp);
                if (r.Connections > 0) w.WriteNumber("c", r.Connections);
                if (r.NoUpload) w.WriteBoolean("nu", true);
                w.WriteEndObject();
            }
            w.WriteEndArray();
        }
        return Encoding.UTF8.GetString(ms.ToArray());

        static void Number(Utf8JsonWriter w, string name, double v, int digits)
        {
            if (double.IsNaN(v) || double.IsInfinity(v)) w.WriteNull(name);
            else w.WriteNumber(name, Math.Round(v, digits));
        }
    }

    /// <summary>Tolerant: a damaged or foreign value yields what can be read (or nothing), never an exception.</summary>
    public static List<SpeedTestRecord> Parse(string? json)
    {
        var list = new List<SpeedTestRecord>();
        if (string.IsNullOrWhiteSpace(json)) return list;
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return list;
            foreach (var e in doc.RootElement.EnumerateArray())
            {
                if (e.ValueKind != JsonValueKind.Object) continue;
                if (!e.TryGetProperty("t", out var t) || t.ValueKind != JsonValueKind.String
                    || !DateTimeOffset.TryParse(t.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var time))
                    continue;
                int connections = e.TryGetProperty("c", out var c) && c.ValueKind == JsonValueKind.Number && c.TryGetInt32(out int n)
                                  && n is >= SpeedTestOptions.MinConnections and <= SpeedTestOptions.MaxConnections ? n : 0;
                bool noUpload = e.TryGetProperty("nu", out var nu) && nu.ValueKind == JsonValueKind.True;
                list.Add(new SpeedTestRecord(time, Num(e, "d"), Num(e, "u"), Num(e, "p"), Num(e, "j"), Num(e, "ld"), Num(e, "lu"),
                                             Str(e, "s"), Str(e, "i"), connections, noUpload));
                if (list.Count >= Capacity) break;
            }
        }
        catch (JsonException) { }
        return list;

        static double Num(JsonElement e, string name)
            => e.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.Number && p.TryGetDouble(out double d) ? d : double.NaN;

        static string? Str(JsonElement e, string name)
            => e.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String ? SpeedTestMath.CleanLabel(p.GetString()) : null;
    }
}
