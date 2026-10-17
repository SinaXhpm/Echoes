using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace Echoes.Helpers;

/// <summary>What a run was: the check, target, request and timing (the header of every export).</summary>
public sealed class CheckHostRunInfo
{
    public CheckHostKind Kind { get; init; }
    public string Target { get; init; } = "";
    public string RequestId { get; init; } = "";
    public string Permalink { get; init; } = "";
    public DateTimeOffset Started { get; init; }
    /// <summary>How long the run took; null while it is still running.</summary>
    public TimeSpan? Duration { get; init; }
    /// <summary>"Automatic", "Europe", "5 nodes" — how the nodes were chosen.</summary>
    public string NodeChoice { get; init; } = "Automatic";
    public bool Stopped { get; init; }
}

/// <summary>Numbers and per-node texts, shared by the result rows and the exports so they always agree.</summary>
public static class CheckHostFormat
{
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    /// <summary>"12.3 ms", "157.0 ms", "3.00 s".</summary>
    public static string Ms(double? ms) => ms is not double v ? "" : v < 1000 ? v.ToString("0.0", Inv) + " ms" : (v / 1000).ToString("0.00", Inv) + " s";

    /// <summary>A bare millisecond figure for a "min · avg · max" triple.</summary>
    public static string Num(double? ms) => ms is not double v ? "–" : v < 1000 ? v.ToString("0.0", Inv) : v.ToString("0", Inv);

    public static string Pct(double? p) => p is not double v ? "" : (v == Math.Round(v) ? v.ToString("0", Inv) : v.ToString("0.#", Inv)) + "%";

    public static string Plural(int n, string one, string many) => n == 1 ? $"1 {one}" : $"{n.ToString(Inv)} {many}";

    /// <summary>"131.4 · 183.9 · 239.8 ms"</summary>
    public static string Triple(double? min, double? avg, double? max) =>
        min is null ? "–" : $"{Num(min)} · {Num(avg)} · {Num(max)} ms";

    /// <summary>A whole-millisecond figure for a summary tile (one decimal below 10 ms): "131", "9.2".</summary>
    public static string Whole(double? ms) => ms is not double v ? "–" : v < 10 ? v.ToString("0.0", Inv) : v.ToString("0", Inv);

    /// <summary>"131 · 184 · 240 ms" — the tile's short form of <see cref="Triple"/>.</summary>
    public static string TripleShort(double? min, double? avg, double? max) =>
        min is null ? "–" : $"{Whole(min)} · {Whole(avg)} · {Whole(max)} ms";

    /// <summary>"131 ms", "9.2 ms", "1.24 s" — a tile's single time.</summary>
    public static string MsShort(double? ms) => ms is not double v ? "–" : v < 1000 ? Whole(v) + " ms" : (v / 1000).ToString("0.00", Inv) + " s";

    /// <summary>The verdict shown in a node's result pill.</summary>
    public static string Status(CheckHostEntry e) => e.State switch
    {
        CheckHostState.Pending => "Waiting",
        CheckHostState.Stopped => "Stopped",
        _ => e.Result?.Status ?? "",
    };

    /// <summary>The latency column: the time the node is ranked by, or the TTL for DNS ("600 s", under a "TTL" head).</summary>
    public static string Latency(CheckHostEntry e)
    {
        if (e.Result is not { } r) return "";
        if (r.Kind == CheckHostKind.Dns) return r.Ttl is long t && r.RecordCount > 0 ? $"{t.ToString(Inv)} s" : "";
        return Ms(r.LatencyMs);
    }

    /// <summary>DNS: the node resolved the name, but to something other than what most nodes got.</summary>
    public static bool AnswerDiffers(CheckHostEntry e, string? majorityAnswer) =>
        majorityAnswer is not null && e.Result is { Kind: CheckHostKind.Dns, State: CheckHostState.Ok } r
        && r.AnswerKey.Length > 0 && r.AnswerKey != majorityAnswer;

    /// <summary>The rest of a node's result on one line: ping spread and loss, the address it reached, the records (marked
    /// when they differ from most nodes'), or the node's error.</summary>
    public static string Details(CheckHostEntry e, string? majorityAnswer = null)
    {
        if (e.Result is not { } r) return e.State == CheckHostState.Stopped ? "Stopped before the node reported" : "";
        var parts = new List<string>(4);
        switch (r.Kind)
        {
            case CheckHostKind.Ping:
                if (r.MinMs is not null) parts.Add($"min {Num(r.MinMs)} · max {Num(r.MaxMs)} ms");
                // loss only when there is some: a lossy node stands out instead of every line saying "0% loss"
                if (r.LossPercent is > 0 && r.Received > 0) parts.Add($"{Pct(r.LossPercent)} loss");
                if (r.Received == 0 && r.Error.Length > 0) parts.Add(r.Error.TrimEnd('.'));
                if (r.Address.Length > 0) parts.Add(r.Address);
                break;
            case CheckHostKind.Dns:
                if (AnswerDiffers(e, majorityAnswer)) parts.Add("Different answer");
                foreach (var rec in r.Records)
                    if (rec.Value.Length > 0) parts.Add(rec.Key + " " + string.Join(", ", rec.Value));
                if (parts.Count == 0 && r.Error.Length > 0) parts.Add(r.Error.TrimEnd('.'));
                break;
            default:
                if (r.State == CheckHostState.Failed && r.Error.Length > 0) parts.Add(r.Error.TrimEnd('.'));
                else if (r.NoReply) parts.Add("open or filtered");
                if (r.Address.Length > 0) parts.Add(r.Address);
                break;
        }
        return string.Join(" · ", parts);
    }

    /// <summary>One node on one line (the row copy): "Frankfurt, Germany · de4 AS34549 · 4/4 · 12.3 ms · min … · 45.33.32.156".</summary>
    public static string Line(CheckHostEntry e, string? majorityAnswer = null)
    {
        var parts = new List<string>(5) { e.Node.Location, (e.Node.ShortId + " " + e.Node.Asn).Trim(), Status(e) };
        string lat = Latency(e), det = Details(e, majorityAnswer);
        if (e.Kind == CheckHostKind.Dns && lat.Length > 0) lat = "TTL " + lat;   // no column head to say what it is
        if (lat.Length > 0) parts.Add(lat);
        if (det.Length > 0) parts.Add(det);
        return string.Join(" · ", parts.Where(p => p.Length > 0));
    }

    /// <summary>Lowercase state name for CSV / JSON.</summary>
    public static string StateKey(CheckHostState s) => s switch
    {
        CheckHostState.Ok => "ok",
        CheckHostState.Warning => "warning",
        CheckHostState.Failed => "failed",
        CheckHostState.Stopped => "stopped",
        _ => "pending",
    };

    /// <summary>"Reachable" (ping), "Responded" (HTTP), "Connected" (TCP), "Replied" (UDP), "Resolved" (DNS).</summary>
    public static string ReachedCaption(CheckHostKind kind) => kind switch
    {
        CheckHostKind.Http => "Responded",
        CheckHostKind.Tcp => "Connected",
        CheckHostKind.Udp => "Replied",
        CheckHostKind.Dns => "Resolved",
        _ => "Reachable",
    };

    /// <summary>"7 ok · 1 warning · 2 failed · 3 waiting"</summary>
    public static string Counts(CheckHostSummary s)
    {
        var parts = new List<string>(5);
        if (s.Ok > 0) parts.Add($"{s.Ok} ok");
        if (s.Warning > 0) parts.Add(Plural(s.Warning, "warning", "warnings"));
        if (s.Failed > 0) parts.Add($"{s.Failed} failed");
        if (s.Pending > 0) parts.Add($"{s.Pending} waiting");
        if (s.Stopped > 0) parts.Add($"{s.Stopped} stopped");
        return string.Join(" · ", parts);
    }

    /// <summary>"A 1 · AAAA 1"</summary>
    public static string RecordTypes(CheckHostSummary s) =>
        s.RecordTypes.Count == 0 ? "–" : string.Join(" · ", s.RecordTypes.Select(t => $"{t.Key} {t.Value.ToString(Inv)}"));

    /// <summary>"492 – 3600 s", "300 s"</summary>
    public static string TtlRange(CheckHostSummary s) =>
        s.TtlMin is null ? "–" : s.TtlMin == s.TtlMax ? $"{s.TtlMin.Value.ToString(Inv)} s" : $"{s.TtlMin.Value.ToString(Inv)} – {s.TtlMax!.Value.ToString(Inv)} s";

    /// <summary>"All agree", "2 different", "–"</summary>
    public static string Answers(CheckHostSummary s) => s.AnswerSets switch
    {
        0 => "–",
        1 => "All agree",
        _ => $"{s.AnswerSets} different",
    };

    public static string Duration(TimeSpan d) =>
        d.TotalSeconds < 60 ? d.TotalSeconds.ToString("0.0", Inv) + " s" : $"{(int)d.TotalMinutes}m {d.Seconds:00}s";
}

/// <summary>A run as a text report, CSV or JSON. Rows come in the order given (the list's current order); the filter
/// doesn't apply — exports always hold every node.</summary>
public static class CheckHostReport
{
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    // ---------------- text ----------------

    public static string Text(CheckHostRunInfo info, IReadOnlyList<CheckHostEntry> entries, CheckHostSummary s, bool groupByRegion)
    {
        var sb = new StringBuilder();
        string Pad(string k) => k.PadRight(11);
        sb.Append("Check Host — ").Append(info.Kind.Label()).Append(' ').Append(info.Target).Append('\n');
        string when = info.Started.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", Inv);
        sb.Append(Pad("Date")).Append(when);
        if (info.Duration is { } d) sb.Append(info.Stopped ? " · stopped after " : " · took ").Append(CheckHostFormat.Duration(d));
        else sb.Append(" · still running");
        sb.Append('\n');
        sb.Append(Pad("Nodes")).Append(s.Total.ToString(Inv)).Append(" · ").Append(info.NodeChoice).Append('\n');
        if (info.Permalink.Length > 0) sb.Append(Pad("Report")).Append(info.Permalink).Append('\n');
        sb.Append('\n');

        sb.Append(Pad(CheckHostFormat.ReachedCaption(info.Kind))).Append($"{s.Reached} of {s.Total}");
        string counts = CheckHostFormat.Counts(s);
        if (counts.Length > 0) sb.Append(" · ").Append(counts);
        sb.Append('\n');
        if (info.Kind == CheckHostKind.Dns)
        {
            sb.Append(Pad("Answers")).Append(CheckHostFormat.Answers(s)).Append('\n');
            sb.Append(Pad("Records")).Append(CheckHostFormat.RecordTypes(s)).Append('\n');
            sb.Append(Pad("TTL")).Append(CheckHostFormat.TtlRange(s)).Append('\n');
        }
        else if (s.MinMs is not null)
        {
            sb.Append(Pad("Latency")).Append($"min {CheckHostFormat.Num(s.MinMs)} · avg {CheckHostFormat.Num(s.AvgMs)} · max {CheckHostFormat.Num(s.MaxMs)} ms")
              .Append($" (median {CheckHostFormat.Num(s.MedianMs)})").Append('\n');
            if (info.Kind == CheckHostKind.Ping && s.LossPercent is not null)
                sb.Append(Pad("Loss")).Append(CheckHostFormat.Pct(s.LossPercent)).Append(" of all pings").Append('\n');
            if (s.Fastest is { } f) sb.Append(Pad("Fastest")).Append($"{f.Node.Location} ({f.Node.ShortId}) {CheckHostFormat.Ms(f.LatencyMs)}").Append('\n');
            if (s.Slowest is { } w) sb.Append(Pad("Slowest")).Append($"{w.Node.Location} ({w.Node.ShortId}) {CheckHostFormat.Ms(w.LatencyMs)}").Append('\n');
        }
        sb.Append(Pad("Countries")).Append(s.Countries.ToString(Inv));
        if (s.Regions.Count > 0) sb.Append(" · ").Append(string.Join(", ", s.Regions));
        sb.Append('\n');

        // the table: Location | Node | Result | Latency | Details, padded to the longest value of each column
        var rows = entries.Select(e => new[]
        {
            e.Node.Location, e.Node.ShortId, CheckHostFormat.Status(e), CheckHostFormat.Latency(e), CheckHostFormat.Details(e, s.MajorityAnswer),
        }).ToList();
        var head = new[] { "Location", "Node", "Result", info.Kind == CheckHostKind.Dns ? "TTL" : "Latency", "Details" };
        int[] w4 = new int[4];
        for (int c = 0; c < 4; c++)
            w4[c] = Math.Min(c == 0 ? 32 : 24, Math.Max(head[c].Length, rows.Count == 0 ? 0 : rows.Max(r => r[c].Length)));
        string Row(string[] r)
        {
            var line = new StringBuilder();
            for (int c = 0; c < 4; c++)
            {
                string v = r[c].Length > w4[c] ? r[c][..(w4[c] - 1)] + "…" : r[c];
                // the latency column is right-aligned, like numbers
                line.Append(c == 3 ? v.PadLeft(w4[c]) : v.PadRight(w4[c])).Append("  ");
            }
            line.Append(r[4]);
            return line.ToString().TrimEnd();
        }
        sb.Append('\n').Append(Row(head)).Append('\n');
        sb.Append(Row(head.Select((h, i) => new string('-', i < 4 ? w4[i] : Math.Max(7, h.Length))).ToArray())).Append('\n');
        string? region = null;
        for (int i = 0; i < entries.Count; i++)
        {
            if (groupByRegion && entries[i].Node.Region != region)
            {
                region = entries[i].Node.Region;
                int n = entries.Count(e => e.Node.Region == region);
                if (i > 0) sb.Append('\n');
                sb.Append(region).Append(" · ").Append(CheckHostFormat.Plural(n, "node", "nodes")).Append('\n');
            }
            sb.Append(Row(rows[i])).Append('\n');
        }
        return sb.ToString();
    }

    // ---------------- CSV ----------------

    public static string Csv(CheckHostRunInfo info, IReadOnlyList<CheckHostEntry> entries, string? majorityAnswer = null)
    {
        var w = new StringWriter(Inv) { NewLine = "\r\n" };
        var head = new List<string>
        {
            "node", "location", "city", "country", "country_code", "region", "asn", "node_ip",
            "state", "result", "latency_ms", "address", "error",
        };
        head.AddRange(info.Kind switch
        {
            CheckHostKind.Ping => new[] { "sent", "received", "loss_pct", "min_ms", "avg_ms", "max_ms", "jitter_ms", "replies" },
            CheckHostKind.Http => new[] { "http_code", "http_reason" },
            CheckHostKind.Udp => new[] { "reply" },
            CheckHostKind.Dns => new[] { "ttl", "a", "aaaa", "other_records", "answer_differs" },
            _ => Array.Empty<string>(),
        });
        w.WriteLine(string.Join(",", head));
        foreach (var e in entries)
        {
            var r = e.Result;
            var cells = new List<string>
            {
                Field(e.Node.Id), Field(e.Node.Location), Field(e.Node.City), Field(e.Node.Country), Field(e.Node.CountryCode.ToUpperInvariant()),
                Field(e.Node.Region), Field(e.Node.Asn), Field(e.Node.Ip),
                Field(CheckHostFormat.StateKey(e.State)), Field(CheckHostFormat.Status(e)), Number(r?.LatencyMs),
                Field(r?.Address), Field(r?.Error),
            };
            switch (info.Kind)
            {
                case CheckHostKind.Ping:
                    cells.Add(r is null ? "" : r.Sent.ToString(Inv));
                    cells.Add(r is null ? "" : r.Received.ToString(Inv));
                    cells.Add(Number(r?.LossPercent));
                    cells.Add(Number(r?.MinMs));
                    cells.Add(Number(r?.AvgMs));
                    cells.Add(Number(r?.MaxMs));
                    cells.Add(Number(r?.JitterMs));
                    cells.Add(Field(r is null ? "" : string.Join("; ", r.Replies.Select(p => p.Ms is double ms && p.IsOk ? $"{p.Status} {ms.ToString("0.###", Inv)}" : p.Status))));
                    break;
                case CheckHostKind.Http:
                    cells.Add(r?.HttpCode is int code ? code.ToString(Inv) : "");
                    cells.Add(Field(r?.HttpReason));
                    break;
                case CheckHostKind.Udp:
                    cells.Add(Field(r is null ? "" : r.State == CheckHostState.Ok ? "replied" : r.NoReply ? "no reply" : ""));
                    break;
                case CheckHostKind.Dns:
                    cells.Add(r?.Ttl is long t ? t.ToString(Inv) : "");
                    cells.Add(Field(Values(r, "A")));
                    cells.Add(Field(Values(r, "AAAA")));
                    cells.Add(Field(r is null ? "" : string.Join("; ", r.Records.Where(x => x.Key is not ("A" or "AAAA") && x.Value.Length > 0)
                                                                         .Select(x => x.Key + "=" + string.Join(" ", x.Value)))));
                    cells.Add(CheckHostFormat.AnswerDiffers(e, majorityAnswer) ? "yes" : "");
                    break;
            }
            w.WriteLine(string.Join(",", cells));
        }
        return w.ToString();
    }

    private static string Values(CheckHostResult? r, string type) =>
        r is null ? "" : string.Join(" ", r.Records.Where(x => x.Key == type).SelectMany(x => x.Value));

    /// <summary>RFC 4180 field; a leading = + - @ (a spreadsheet formula) is defused with a quote, as the scanner's CSV does —
    /// node and server texts come from the network.</summary>
    private static string Field(string? v)
    {
        v ??= "";
        if (v.Length > 0 && v[0] is '=' or '+' or '-' or '@' or '\t' or '\r') v = "'" + v;
        return "\"" + v.Replace("\"", "\"\"") + "\"";
    }

    private static string Number(double? v) => v is double d ? d.ToString("0.###", Inv) : "";

    // ---------------- JSON ----------------

    public static string Json(CheckHostRunInfo info, IReadOnlyList<CheckHostEntry> entries, CheckHostSummary s)
    {
        using var ms = new MemoryStream();
        using (var j = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
        {
            j.WriteStartObject();
            j.WriteString("check", info.Kind.Api());
            j.WriteString("target", info.Target);
            j.WriteString("requestId", info.RequestId);
            j.WriteString("permalink", info.Permalink);
            j.WriteString("started", info.Started.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ", Inv));
            if (info.Duration is { } d) j.WriteNumber("durationSeconds", Math.Round(d.TotalSeconds, 3));
            else j.WriteNull("durationSeconds");
            j.WriteBoolean("stopped", info.Stopped);
            j.WriteString("nodeChoice", info.NodeChoice);

            j.WriteStartObject("summary");
            j.WriteNumber("nodes", s.Total);
            j.WriteNumber("reached", s.Reached);
            j.WriteNumber("ok", s.Ok);
            j.WriteNumber("warning", s.Warning);
            j.WriteNumber("failed", s.Failed);
            j.WriteNumber("pending", s.Pending);
            j.WriteNumber("stopped", s.Stopped);
            if (s.MinMs is not null)
            {
                j.WriteStartObject("latencyMs");
                Num(j, "min", s.MinMs); Num(j, "avg", s.AvgMs); Num(j, "median", s.MedianMs); Num(j, "max", s.MaxMs);
                j.WriteEndObject();
            }
            if (s.Fastest is { } f) NodeRef(j, "fastest", f);
            if (s.Slowest is { } sl) NodeRef(j, "slowest", sl);
            if (info.Kind == CheckHostKind.Ping) Num(j, "lossPercent", s.LossPercent);
            if (info.Kind == CheckHostKind.Dns)
            {
                j.WriteNumber("answerSets", s.AnswerSets);
                if (s.MajorityAnswer is { } majority) j.WriteString("majorityAnswer", majority);
                if (s.TtlMin is long tmin) j.WriteNumber("ttlMin", tmin);
                if (s.TtlMax is long tmax) j.WriteNumber("ttlMax", tmax);
            }
            j.WriteNumber("countries", s.Countries);
            j.WriteStartArray("regions");
            foreach (var r in s.Regions) j.WriteStringValue(r);
            j.WriteEndArray();
            j.WriteEndObject();

            j.WriteStartArray("nodes");
            foreach (var e in entries) WriteEntry(j, e, s.MajorityAnswer);
            j.WriteEndArray();
            j.WriteEndObject();
        }
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    private static void Num(Utf8JsonWriter j, string name, double? v)
    {
        if (v is double d) j.WriteNumber(name, Math.Round(d, 3));
        else j.WriteNull(name);
    }

    private static void NodeRef(Utf8JsonWriter j, string name, CheckHostEntry e)
    {
        j.WriteStartObject(name);
        j.WriteString("node", e.Node.Id);
        j.WriteString("location", e.Node.Location);
        Num(j, "latencyMs", e.LatencyMs);
        j.WriteEndObject();
    }

    private static void WriteEntry(Utf8JsonWriter j, CheckHostEntry e, string? majorityAnswer)
    {
        var n = e.Node;
        var r = e.Result;
        j.WriteStartObject();
        j.WriteString("node", n.Id);
        j.WriteString("location", n.Location);
        j.WriteString("city", n.City);
        j.WriteString("country", n.Country);
        j.WriteString("countryCode", n.CountryCode);
        j.WriteString("region", n.Region);
        j.WriteString("asn", n.Asn);
        j.WriteString("nodeIp", n.Ip);
        j.WriteString("state", CheckHostFormat.StateKey(e.State));
        j.WriteString("result", CheckHostFormat.Status(e));
        j.WriteBoolean("reached", r?.Reached ?? false);
        Num(j, "latencyMs", r?.LatencyMs);
        j.WriteString("address", r?.Address ?? "");
        j.WriteString("error", r?.Error ?? "");
        if (r is not null)
        {
            switch (r.Kind)
            {
                case CheckHostKind.Ping:
                    j.WriteNumber("sent", r.Sent);
                    j.WriteNumber("received", r.Received);
                    Num(j, "lossPercent", r.LossPercent);
                    Num(j, "minMs", r.MinMs);
                    Num(j, "avgMs", r.AvgMs);
                    Num(j, "maxMs", r.MaxMs);
                    Num(j, "jitterMs", r.JitterMs);
                    j.WriteStartArray("replies");
                    foreach (var p in r.Replies)
                    {
                        j.WriteStartObject();
                        j.WriteString("status", p.Status);
                        Num(j, "ms", p.Ms);
                        j.WriteEndObject();
                    }
                    j.WriteEndArray();
                    break;
                case CheckHostKind.Http:
                    if (r.HttpCode is int code) j.WriteNumber("httpCode", code);
                    else j.WriteNull("httpCode");
                    j.WriteString("httpReason", r.HttpReason);
                    break;
                case CheckHostKind.Udp:
                    j.WriteBoolean("noReply", r.NoReply);
                    break;
                case CheckHostKind.Dns:
                    if (r.Ttl is long t) j.WriteNumber("ttl", t);
                    else j.WriteNull("ttl");
                    j.WriteBoolean("answerDiffers", CheckHostFormat.AnswerDiffers(e, majorityAnswer));
                    j.WriteStartObject("records");
                    foreach (var rec in r.Records)
                    {
                        j.WriteStartArray(rec.Key);
                        foreach (var v in rec.Value) j.WriteStringValue(v);
                        j.WriteEndArray();
                    }
                    j.WriteEndObject();
                    break;
            }
            // the node's entry exactly as check-host.net sent it
            if (r.Raw.Length > 0)
            {
                j.WritePropertyName("raw");
                try
                {
                    using var raw = JsonDocument.Parse(r.Raw);
                    raw.RootElement.WriteTo(j);
                }
                catch (JsonException) { j.WriteStringValue(r.Raw); }
            }
        }
        j.WriteEndObject();
    }
}
