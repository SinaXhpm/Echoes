using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>
/// Globalping's results in Check Host's model: each probe as a node ("gp3": its city, country, ASN and network; Globalping
/// doesn't name its probes), each test as a node's result. Everything is read defensively and every text is cleaned.
/// </summary>
public static class GlobalpingResults
{
    /// <summary>More results than any measurement has (50 probes without an account) are not read.</summary>
    public const int MaxResults = 100;

    public static string NodeId(int index) => "gp" + (index + 1).ToString(CultureInfo.InvariantCulture);

    /// <summary>The probe of result <paramref name="index"/>: {"country": "DE", "city": "Falkenstein", "asn": 24940,
    /// "network": "Hetzner Online", …}.</summary>
    public static CheckHostNode Node(int index, JsonElement probe)
    {
        string cc = Str(probe, "country");
        if (cc.Length != 2 || !cc.All(char.IsAsciiLetter)) cc = "";
        long asn = Long(probe, "asn") is long a and > 0 and < 4294967296 ? a : 0;
        return new CheckHostNode(NodeId(index), cc, cc.Length == 2 ? CloudflareCountries.Name(cc) : "", Str(probe, "city"), "",
                                 asn > 0 ? "AS" + asn.ToString(CultureInfo.InvariantCulture) : "")
        {
            Network = Str(probe, "network"),
        };
    }

    /// <summary>A probe's test (its "result"), or null while it runs. <paramref name="port"/>: the TCP check's port.</summary>
    public static CheckHostResult? Parse(CheckHostKind kind, JsonElement result, int? port = null)
    {
        if (result.ValueKind != JsonValueKind.Object) return Unreadable(kind, "", "");
        string status = Str(result, "status");
        if (status == "in-progress") return null;
        string raw = Raw(result);
        string output = result.TryGetProperty("rawOutput", out var o) && o.ValueKind == JsonValueKind.String
            ? RemoteText.Clean((o.GetString() ?? "").Trim('\n', '\r'), 3000, keepNewlines: true) : "";
        try
        {
            return status switch
            {
                "finished" => kind switch
                {
                    CheckHostKind.Ping => Ping(result, raw, output),
                    CheckHostKind.Tcp => Tcp(result, raw, output, port),
                    CheckHostKind.Http => Http(result, raw, output),
                    CheckHostKind.Dns => Dns(result, raw, output),
                    _ => null,
                } ?? Unreadable(kind, raw, output),
                "failed" => Failed(kind, raw, output),
                "offline" => new CheckHostResult
                {
                    Kind = kind, State = CheckHostState.Failed, Status = "Offline", Raw = raw, Output = output,
                    Error = "The probe went offline before it ran the check.",
                },
                _ => Unreadable(kind, raw, output),
            };
        }
        catch (Exception ex) when (ex is InvalidOperationException or FormatException or JsonException or IndexOutOfRangeException)
        {
            return Unreadable(kind, raw, output);
        }
    }

    private static CheckHostResult Unreadable(CheckHostKind kind, string raw, string output) => new()
    {
        Kind = kind,
        State = CheckHostState.Failed,
        Status = "Bad data",
        Error = "Globalping sent a result this version can't read (see the raw value).",
        Raw = raw,
        Output = output,
    };

    // The test without its text output (kept in Output) and the HTTP headers / certificate: the figures it reported.
    private static string Raw(JsonElement result)
    {
        using var ms = new MemoryStream();
        using (var j = new Utf8JsonWriter(ms))
        {
            j.WriteStartObject();
            foreach (var p in result.EnumerateObject())
            {
                if (p.Name is "rawOutput" or "rawHeaders" or "rawBody" or "headers" or "tls") continue;
                p.WriteTo(j);
            }
            j.WriteEndObject();
        }
        return ms.Length > 8000 ? "" : Encoding.UTF8.GetString(ms.ToArray());
    }

    private static CheckHostResult Failed(CheckHostKind kind, string raw, string output)
    {
        // the probe's own words: the last line of its output ("queryA ENODATA example.invalid", "Request timed out …")
        string said = output.Split('\n').Select(l => l.Trim()).LastOrDefault(l => l.Length > 0) ?? "";
        if (said.Length > 200) said = said[..200] + "…";
        string verdict = CheckHostResult.ShortError(said);
        return new CheckHostResult
        {
            Kind = kind, State = CheckHostState.Failed, Status = verdict, Raw = raw, Output = output,
            Error = said.Length == 0 ? "The probe couldn't run the check."
                : verdict == "Unresolved" ? $"The probe couldn't resolve the name ({said.TrimEnd('.')})."
                : said,
        };
    }

    private static (int Sent, int Received, List<double> Rtts, JsonElement Stats)? Packets(JsonElement r)
    {
        var stats = r.TryGetProperty("stats", out var s) && s.ValueKind == JsonValueKind.Object ? s : default;
        if (stats.ValueKind != JsonValueKind.Object || Long(stats, "total") is not long total || total is <= 0 or > 64) return null;
        var rtts = new List<double>();
        if (r.TryGetProperty("timings", out var t) && t.ValueKind == JsonValueKind.Array)
            foreach (var timing in t.EnumerateArray().Take(64))
                if (Num(timing, "rtt") is double rtt) rtts.Add(rtt);
        int received = (int)Math.Clamp(Long(stats, "rcv") ?? rtts.Count, 0, total);
        return ((int)total, received, rtts, stats);
    }

    private static CheckHostResult? Ping(JsonElement r, string raw, string output)
    {
        if (Packets(r) is not { } packets) return null;
        var (sent, received, rtts, stats) = packets;
        var ok = rtts.Take(received).ToList();
        var replies = new List<CheckHostReply>(sent);
        for (int i = 0; i < received; i++) replies.Add(new CheckHostReply("OK", i < ok.Count ? ok[i] : null));
        // Globalping lists the replies only, not which ones were lost: the lost ones come last
        for (int i = received; i < sent; i++) replies.Add(new CheckHostReply("TIMEOUT", null));
        double? jitter = null;
        if (ok.Count >= 2)
        {
            double sum = 0;
            for (int i = 1; i < ok.Count; i++) sum += Math.Abs(ok[i] - ok[i - 1]);
            jitter = sum / (ok.Count - 1);
        }
        double? min = Num(stats, "min") ?? (ok.Count > 0 ? ok.Min() : null);
        double? avg = Num(stats, "avg") ?? (ok.Count > 0 ? ok.Average() : null);
        double? max = Num(stats, "max") ?? (ok.Count > 0 ? ok.Max() : null);
        return new CheckHostResult
        {
            Kind = CheckHostKind.Ping,
            State = received == sent ? CheckHostState.Ok : received > 0 ? CheckHostState.Warning : CheckHostState.Failed,
            Reached = received > 0,
            LatencyMs = received > 0 ? avg : null,
            Address = Ip(r, "resolvedAddress"),
            Status = received > 0 ? $"{received}/{sent}" : "Timeout",
            Error = received == 0 ? "No reply to any ping." : "",
            Raw = raw,
            Output = output,
            Replies = replies,
            Sent = sent,
            Received = received,
            LossPercent = 100.0 * (sent - received) / sent,
            MinMs = received > 0 ? min : null,
            AvgMs = received > 0 ? avg : null,
            MaxMs = received > 0 ? max : null,
            JitterMs = jitter,
        };
    }

    private static CheckHostResult? Tcp(JsonElement r, string raw, string output, int? port)
    {
        if (Packets(r) is not { } packets) return null;
        var (sent, received, rtts, stats) = packets;
        string address = Ip(r, "resolvedAddress");
        string on = port is int p ? $" on port {p.ToString(CultureInfo.InvariantCulture)}" : "";
        if (received > 0)
            return new CheckHostResult
            {
                Kind = CheckHostKind.Tcp, State = CheckHostState.Ok, Reached = true, Address = address, Raw = raw, Output = output,
                LatencyMs = Num(stats, "avg") ?? (rtts.Count > 0 ? rtts.Take(received).Average() : null),
                Status = "Connected",
            };
        bool refused = output.Contains("refused", StringComparison.OrdinalIgnoreCase);
        return new CheckHostResult
        {
            Kind = CheckHostKind.Tcp, State = CheckHostState.Failed, Address = address, Raw = raw, Output = output,
            Status = refused ? "Refused" : "Timeout",
            Error = refused ? $"The connection{on} was refused." : $"No answer{on} ({CheckHostFormat.Plural(sent, "try", "tries")}).",
        };
    }

    private static CheckHostResult? Http(JsonElement r, string raw, string output)
    {
        if (Long(r, "statusCode") is not long c || c is < 100 or > 999) return null;
        int code = (int)c;
        string name = RemoteText.Clean(Str(r, "statusCodeName"), 60);
        // the time to the answer without the body's download (a GET's total includes it), as a HEAD's total was
        double? ms = null;
        if (r.TryGetProperty("timings", out var t) && t.ValueKind == JsonValueKind.Object && Num(t, "total") is double total)
            ms = Num(t, "download") is double dl && dl >= 0 && dl <= total ? total - dl : total;
        string head = name.Length > 0 ? $"{code} {name}" : code.ToString(CultureInfo.InvariantCulture);
        bool success = code is >= 200 and < 400;   // check-host.net counts a redirect as success too, and follows none
        return new CheckHostResult
        {
            Kind = CheckHostKind.Http,
            State = success ? CheckHostState.Ok : code >= 500 ? CheckHostState.Failed : CheckHostState.Warning,
            Reached = true,
            LatencyMs = ms,
            Address = Ip(r, "resolvedAddress"),
            Raw = raw,
            // the status line and the headers: the body has its own viewer
            Output = HeadOf(output),
            Status = head,
            HttpCode = code,
            HttpReason = name,
            Error = success ? "" : $"The server answered {head}.",
            Response = Answer(r, code, name, output),
        };
    }

    /// <summary>What a probe sends back of a body (Globalping's limit).</summary>
    public const int ProbeBodyBytes = 10_000;

    // The probe's answer for the response viewer: its status line (the version as the probe's output gives it), its
    // headers (rawHeaders, one per line) and the first 10 KB of its body (already decompressed by the probe).
    private static HttpResponseSnapshot Answer(JsonElement r, int code, string name, string output)
    {
        string first = output.Split('\n', 2)[0].Trim();
        string version = first.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase) ? first.Split(' ')[0] : "HTTP";
        var headers = new List<(string, string)>();
        string rawHeaders = r.TryGetProperty("rawHeaders", out var rh) && rh.ValueKind == JsonValueKind.String ? rh.GetString() ?? "" : "";
        foreach (var line in rawHeaders.Split('\n'))
        {
            int colon = line.IndexOf(':');
            // the remote's text: control and bidi characters out, each header on a line of its own
            if (colon > 0) headers.Add((RemoteText.Clean(line[..colon].Trim(), 200), RemoteText.Clean(line[(colon + 1)..].Trim(), 8000)));
        }
        string body = r.TryGetProperty("rawBody", out var b) && b.ValueKind == JsonValueKind.String ? b.GetString() ?? "" : "";
        bool cut = r.TryGetProperty("truncated", out var tr) && tr.ValueKind == JsonValueKind.True;
        byte[] bytes = Encoding.UTF8.GetBytes(body);
        return new HttpResponseSnapshot($"{version} {code} {name}", headers, bytes, bytes.Length, cut, ProbeBodyBytes)
        {
            About = cut ? "A probe sends back the first 10 KB of a body." : null,
        };
    }

    // "HTTP/1.1 200\nServer: …\n\n<body>" → the part before the blank line
    private static string HeadOf(string output)
    {
        int blank = output.IndexOf("\n\n", StringComparison.Ordinal);
        return blank < 0 ? output : output[..blank];
    }

    private static CheckHostResult? Dns(JsonElement r, string raw, string output)
    {
        if (!r.TryGetProperty("answers", out var answers) || answers.ValueKind != JsonValueKind.Array) return null;
        var a = new List<string>();
        var aaaa = new List<string>();
        long? ttl = null;
        foreach (var answer in answers.EnumerateArray().Take(64))
        {
            string type = Str(answer, "type").ToUpperInvariant();
            if (type is not ("A" or "AAAA")) continue;   // a CNAME on the way is in the output
            string value = Ip(answer, "value");
            if (value.Length == 0) continue;
            var list = type == "A" ? a : aaaa;
            if (!list.Contains(value, StringComparer.OrdinalIgnoreCase)) list.Add(value);
            if (Long(answer, "ttl") is long t and >= 0) ttl = ttl is null ? t : Math.Min(ttl.Value, t);
        }
        var records = new List<KeyValuePair<string, string[]>> { new("A", a.ToArray()) };
        if (aaaa.Count > 0) records.Add(new("AAAA", aaaa.ToArray()));
        int count = a.Count + aaaa.Count;
        if (count == 0)
        {
            string code = RemoteText.Clean(Str(r, "statusCodeName"), 20);
            return new CheckHostResult
            {
                Kind = CheckHostKind.Dns, State = CheckHostState.Failed, Raw = raw, Output = output, Records = records,
                Status = "Unresolved",
                Error = code.Length == 0 || code == "NOERROR" ? "The probe's resolver returned no A record for this name."
                    : $"The probe's resolver answered {code}.",
            };
        }
        return new CheckHostResult
        {
            Kind = CheckHostKind.Dns, State = CheckHostState.Ok, Reached = true, Raw = raw, Output = output, Records = records, Ttl = ttl,
            Address = a.Count > 0 ? a[0] : aaaa[0], Status = count == 1 ? "1 record" : $"{count} records",
        };
    }

    // ---------------- defensive readers ----------------

    private static string Str(JsonElement o, string name) =>
        o.ValueKind == JsonValueKind.Object && o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? RemoteText.Clean((v.GetString() ?? "").Trim(), 300) : "";

    private static long? Long(JsonElement o, string name) =>
        o.ValueKind == JsonValueKind.Object && o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out long n)
            ? n : null;

    private static double? Num(JsonElement o, string name) =>
        o.ValueKind == JsonValueKind.Object && o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number
        && v.TryGetDouble(out double d) && double.IsFinite(d) && d >= 0 ? d : null;

    /// <summary>An address the probe resolved: only ever an IP address ("" otherwise).</summary>
    private static string Ip(JsonElement o, string name) =>
        Str(o, name) is { Length: > 0 and <= 64 } s && IPAddress.TryParse(s, out var ip) ? ip.ToString() : "";
}

/// <summary>
/// One check on Globalping, from the request to the last result: creates the measurement, then reads it until every probe
/// has reported or the deadline passes — the first look 500 ms in and each next one 500 ms after the last answer (1 s
/// once the run is long), with the ETag, so an unchanged measurement is an empty 304. Reports through the same
/// <see cref="ICheckHostSink"/> as a check-host.net run. Failures that end it are <see cref="CheckHostException"/>s.
/// </summary>
public static class GlobalpingRun
{
    private sealed class State(string id, string link, CheckHostKind kind, int? port)
    {
        public readonly string Id = id, Link = link;
        public readonly CheckHostKind Kind = kind;
        public readonly int? Port = port;
        public readonly HashSet<int> Waiting = new();
        public bool Started;
    }

    public static async Task<CheckHostEnd> RunAsync(GlobalpingClient client, GlobalpingRequest request, ICheckHostSink sink,
                                                    CheckHostPolling polling, CancellationToken ct)
    {
        var clock = Stopwatch.StartNew();
        GlobalpingCreated created;
        try { created = await client.CreateAsync(request.Json(), ct).ConfigureAwait(false); }
        catch (CheckHostException ex) when (ex.RateLimited && ex.Remaining is int left && left > 0 && left < request.Probes)
        {
            // fewer tests left this hour than the run asks for: run on that many (the docs' advice)
            created = await client.CreateAsync(request.Json(left), ct).ConfigureAwait(false);
        }
        var st = new State(created.Id, GlobalpingClient.ReportUrl(created.Id), request.Kind, request.Port);

        EntityTagHeaderValue? etag = null;
        int failures = 0;
        await Task.Delay(polling.GlobalpingInterval, ct).ConfigureAwait(false);
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            TimeSpan wait;
            try
            {
                using var poll = await client.GetAsync(st.Id, etag, ct).ConfigureAwait(false);
                failures = 0;
                sink.PollProblem(null);
                bool final = false;
                if (poll.Document is { } doc)
                {
                    etag = poll.ETag;
                    final = Read(doc.RootElement, sink, st);
                }
                if (st.Started && st.Waiting.Count == 0) return CheckHostEnd.Complete;
                if (final)
                {
                    if (!st.Started) throw new CheckHostException("Globalping found no probes to run this check.");
                    return CheckHostEnd.Deadline;   // finished with tests still open: they report no result
                }
                wait = clock.Elapsed < polling.SlowAfter ? polling.GlobalpingInterval : polling.GlobalpingSlowInterval;
            }
            catch (CheckHostException ex)
            {
                // a blip: keep the results so far and look again; enough of them in a row end the run
                if (++failures >= polling.MaxFailures)
                    throw new CheckHostException("Lost contact with Globalping while collecting results — " + Lower(ex.Message), ex, ex.RateLimited);
                sink.PollProblem(ex.Message);
                wait = ex.RetryAfter is { } asked ? TimeSpan.FromSeconds(Math.Clamp(asked.TotalSeconds, 0.5, 10)) : polling.Interval;
            }
            if (clock.Elapsed + wait > polling.Deadline)
            {
                // one last look at the deadline itself, so a probe that reports in the final second still counts
                var remaining = polling.Deadline - clock.Elapsed;
                if (remaining > TimeSpan.Zero) await Task.Delay(remaining, ct).ConfigureAwait(false);
                try
                {
                    using var poll = await client.GetAsync(st.Id, etag, ct).ConfigureAwait(false);
                    if (poll.Document is { } doc) Read(doc.RootElement, sink, st);
                }
                catch (CheckHostException) { }
                if (!st.Started) throw new CheckHostException("Globalping didn't start the check's probes in time. Run again in a moment.");
                return st.Waiting.Count == 0 ? CheckHostEnd.Complete : CheckHostEnd.Deadline;
            }
            await Task.Delay(wait, ct).ConfigureAwait(false);
        }
    }

    /// <summary>Hands on what's new in a look at the measurement: the probes the first time they're listed, then each
    /// test that has finished. True when the measurement is final.</summary>
    private static bool Read(JsonElement root, ICheckHostSink sink, State st)
    {
        if (root.ValueKind != JsonValueKind.Object) throw new CheckHostException("Globalping sent an answer this version can't read.");
        if (root.TryGetProperty("results", out var results) && results.ValueKind == JsonValueKind.Array)
        {
            if (!st.Started && results.GetArrayLength() > 0)
            {
                var nodes = new List<CheckHostNode>();
                int i = 0;
                foreach (var item in results.EnumerateArray().Take(GlobalpingResults.MaxResults))
                {
                    nodes.Add(GlobalpingResults.Node(i, item.ValueKind == JsonValueKind.Object && item.TryGetProperty("probe", out var p) ? p : default));
                    st.Waiting.Add(i++);
                }
                st.Started = true;
                sink.Started(new CheckHostStart(st.Id, st.Link, nodes, CheckHostService.Globalping));
            }
            if (st.Started)
            {
                var batch = new List<KeyValuePair<string, CheckHostResult>>();
                int i = 0;
                foreach (var item in results.EnumerateArray().Take(GlobalpingResults.MaxResults))
                {
                    if (st.Waiting.Contains(i) && item.ValueKind == JsonValueKind.Object && item.TryGetProperty("result", out var res)
                        && GlobalpingResults.Parse(st.Kind, res, st.Port) is { } parsed)
                    {
                        st.Waiting.Remove(i);
                        batch.Add(new KeyValuePair<string, CheckHostResult>(GlobalpingResults.NodeId(i), parsed));
                    }
                    i++;
                }
                if (batch.Count > 0) sink.Results(batch);
            }
        }
        string status = root.TryGetProperty("status", out var s) && s.ValueKind == JsonValueKind.String ? s.GetString() ?? "" : "";
        return status.Length > 0 && status != "in-progress";
    }

    // (a sentence that starts with the service's name keeps its capital)
    private static string Lower(string s) =>
        s.Length > 1 && char.IsUpper(s[0]) && !char.IsUpper(s[1]) && !s.StartsWith("Globalping", StringComparison.Ordinal) ? char.ToLowerInvariant(s[0]) + s[1..] : s;
}
