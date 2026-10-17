using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;

namespace Echoes.Helpers;

/// <summary>What one pass of a repeating scan changed against the pass before it.</summary>
public sealed class ScanDiff
{
    public List<PortFinding> NewOpen { get; } = new();
    /// <summary>Open last pass, not now: a row carrying today's state (closed / filtered / …, or Unknown when the host
    /// didn't answer at all this time), marked <see cref="ScanChange.Gone"/>.</summary>
    public List<PortFinding> Gone { get; } = new();
    public List<ScanHost> HostsUp { get; } = new();
    public List<ScanHost> HostsDown { get; } = new();

    public bool Any => NewOpen.Count + Gone.Count + HostsUp.Count + HostsDown.Count > 0;

    /// <summary>"+2 open · −1 closed · 1 host down" — "" when nothing changed.</summary>
    public string Summary
    {
        get
        {
            var parts = new List<string>();
            if (NewOpen.Count > 0) parts.Add($"+{NewOpen.Count:N0} open");
            if (Gone.Count > 0) parts.Add($"−{Gone.Count:N0} no longer open");
            if (HostsUp.Count > 0) parts.Add($"{HostsUp.Count:N0} host(s) came up");
            if (HostsDown.Count > 0) parts.Add($"{HostsDown.Count:N0} host(s) went down");
            return string.Join(" · ", parts);
        }
    }
}

/// <summary>The facts of a finished pass that the next one is compared with (open ports and live hosts).</summary>
public sealed class ScanSnapshot
{
    private readonly Dictionary<string, HashSet<long>> _open = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _up = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<long, PortFinding> _sample = new();   // a finding per key, for the service name

    public static ScanSnapshot Of(ScanPass pass)
    {
        var s = new ScanSnapshot();
        foreach (var h in pass.Targets) if (h.Status == HostStatus.Up) s._up.Add(h.Ip);
        foreach (var f in pass.Findings)
        {
            if (f.State != PortState.Open || f.Host.AcceptsAll) continue;
            if (!s._open.TryGetValue(f.Host.Ip, out var set)) s._open[f.Host.Ip] = set = new HashSet<long>();
            set.Add(f.Key);
            s._sample.TryAdd(f.Key, f);
        }
        return s;
    }

    /// <summary>Changes from this snapshot to <paramref name="now"/>; marks the new open findings (<see cref="ScanChange.New"/>).</summary>
    public ScanDiff Compare(ScanPass now)
    {
        var d = new ScanDiff();
        var current = new Dictionary<(string, long), PortFinding>();
        foreach (var f in now.Findings) current[(f.Host.Ip, f.Key)] = f;

        foreach (var h in now.Targets)
        {
            bool wasUp = _up.Contains(h.Ip), isUp = h.Status == HostStatus.Up;
            if (isUp && !wasUp) d.HostsUp.Add(h);
            if (wasUp && !isUp) d.HostsDown.Add(h);
        }
        foreach (var f in now.Findings)
        {
            if (f.State != PortState.Open || f.Host.AcceptsAll) continue;
            if (_open.TryGetValue(f.Host.Ip, out var set) && set.Contains(f.Key)) continue;
            f.Change = ScanChange.New;
            d.NewOpen.Add(f);
        }
        var byIp = now.Targets.ToDictionary(h => h.Ip, StringComparer.OrdinalIgnoreCase);
        foreach (var (ip, keys) in _open)
        {
            if (!byIp.TryGetValue(ip, out var host) || host.AcceptsAll) continue;
            foreach (long key in keys)
            {
                if (current.TryGetValue((ip, key), out var f) && f.State == PortState.Open) continue;
                var was = _sample[key];
                var gone = new PortFinding(host, was.Port, was.Proto)
                {
                    State = f?.State ?? PortState.Unknown,
                    Reason = f?.Reason ?? (host.Status == HostStatus.Up ? "not-scanned" : "host-down"),
                    Change = ScanChange.Gone,
                };
                if (f is null) gone.Service = was.Service;
                d.Gone.Add(gone);
            }
        }
        d.Gone.Sort(FindingOrder.Instance);
        return d;
    }
}

/// <summary>
/// The scan's outputs: the nmap-style text report, CSV (every retained probe) and JSON (hosts → ports, with names,
/// MACs, the "not shown" tallies and the repeat diff). Pure functions of a finished pass — safe on a worker thread.
/// </summary>
public static class ScanReport
{
    /// <summary>nmap lists every port of a state only while there are this few; more are summarized ("Not shown").</summary>
    public const int ListThreshold = 25;

    // The report is a read-only TextBox that lays out every character; past this it is capped (exports have it all).
    public const int MaxChars = 200_000;

    public static string Flags(ScanOptions o)
    {
        if (o.PingOnly) return "-sn";
        return string.Join(" ", new[]
        {
            o.Tcp ? "-sT" : "", o.Udp ? "-sU" : "", o.ServiceDetection ? "-sV" : "", o.SkipDiscovery ? "-Pn" : "",
        }.Where(s => s.Length > 0));
    }

    /// <summary>True when a port row belongs in the listing: open, a change, or a state with few enough ports on its host.</summary>
    public static bool Listed(PortFinding f) =>
        f.State == PortState.Open || f.Change != ScanChange.None || f.Host.Count(f.State) <= ListThreshold;

    // ---------------------------------------------------------------- text

    public static string BuildText(ScanPass pass, string portsText, ScanDiff? diff)
    {
        var o = pass.Options;
        var sb = new StringBuilder();
        string when = pass.StartedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
        sb.AppendLine($"# Echoes {AppVersion()} scan — {when} — {pass.Targets.Count:N0} target(s)"
                      + (o.PingOnly ? "" : $", {portsText}") + $", {o.Timing.Label}");
        sb.AppendLine($"# {Flags(o)}   timeout {o.TimeoutMs} ms, retries {o.Timing.MaxRetries} (up to {o.Timing.RetryCap} on a lossy host)");
        sb.AppendLine();

        var byHost = pass.Findings.GroupBy(f => f.Host).ToDictionary(g => g.Key, g => g.ToList());
        var gone = (diff?.Gone ?? new List<PortFinding>()).GroupBy(f => f.Host).ToDictionary(g => g.Key, g => g.ToList());
        // A set, not List.Contains per target: a -Pn /16 (or a sweep where a transparent proxy makes every address "up")
        // scans 65,536 hosts, and the per-target list search made this report O(n²) — ~50 s of CPU before the pass
        // could finish.
        var scannedSet = new HashSet<ScanHost>(pass.Scanned);
        int omitted = 0, down = 0, unknown = 0;
        var tail = new StringBuilder();

        foreach (var h in pass.Targets)   // numeric order
        {
            bool scanned = scannedSet.Contains(h);
            if (h.Status != HostStatus.Up && !(scanned && pass.Targets.Count == 1) && !gone.ContainsKey(h))
            {
                if (h.Status == HostStatus.Unknown) unknown++; else down++;
                continue;
            }
            if (sb.Length >= MaxChars) { omitted++; continue; }
            byHost.TryGetValue(h, out var rows);
            gone.TryGetValue(h, out var goneRows);
            AppendHost(sb, pass, h, rows ?? new List<PortFinding>(), goneRows, o);
        }

        if (o.PingOnly || pass.Targets.Count > 1)
        {
            if (down > 0) tail.AppendLine($"{down:N0} host(s) down or not answering — not listed"
                                          + (o.PingOnly || o.SkipDiscovery ? "" : " — tick Skip ping (-Pn) to scan them anyway"));
            if (unknown > 0) tail.AppendLine($"{unknown:N0} host(s) undetermined: the OS ran out of sockets — try a slower timing");
        }
        if (diff is { Any: true }) tail.AppendLine($"Changes since the previous pass: {diff.Summary}");

        double secs = pass.Elapsed.TotalSeconds;
        tail.AppendLine($"Scan done: {pass.Targets.Count:N0} IP address(es) ({pass.HostsUp:N0} host(s) up) scanned in "
                        + $"{secs:0.00} s — {pass.ProbesSent:N0} probes sent" + (secs > 0.5 ? $" ({pass.ProbesSent / secs:N0}/s)" : ""));
        if (pass.Stopped) tail.AppendLine("(stopped before completion — partial results)");
        foreach (int port in pass.UbiquitousPorts)
            tail.AppendLine($"(port {port}/tcp is open on nearly every host scanned — a transparent proxy or ISP interception on the path is likelier than a real service on each)");
        if (pass.UnknownProbes > 0)
            tail.AppendLine($"({pass.UnknownProbes:N0} probe(s) couldn't be sent — the OS ran out of sockets; those ports are unknown, not filtered)");
        if (pass.RecheckSkipped > 0)
            tail.AppendLine($"({pass.RecheckSkipped:N0} silent UDP port(s) left open|filtered: the host rate-limits its ICMP errors and re-checking more would take too long)");
        if (pass.DroppedRows > 0)
            tail.AppendLine($"({pass.DroppedRows:N0} closed/filtered row(s) not kept for the export — the counts above are exact)");

        string body = sb.ToString().TrimEnd();
        if (body.Length > MaxChars || omitted > 0)
            body = TextLimit.Cap(body, MaxChars)
                   + (omitted > 0 ? $"\n… {omitted:N0} more host(s) not shown here" : "")
                   + "\n… export JSON or CSV for everything (this view is capped so it stays responsive).";
        return body + Environment.NewLine + Environment.NewLine + tail.ToString().TrimEnd();
    }

    private static void AppendHost(StringBuilder sb, ScanPass pass, ScanHost h, List<PortFinding> rows,
                                   List<PortFinding>? gone, ScanOptions o)
    {
        sb.AppendLine($"Scan report for {h.Display}");
        if (h.Status == HostStatus.Up)
            sb.AppendLine("Host is up" + (h.LatencyMs > 0 ? $" ({ScanText.Latency(h.LatencyMs)} latency)" : "")
                          + (h.Reason.Length > 0 ? $", {h.Reason}." : "."));
        else
            sb.AppendLine("Host seems down: nothing answered" + (h.Reason == "socket-limit" ? " (the OS ran out of sockets)." : "."));
        if (!string.IsNullOrEmpty(h.ReverseName) && !string.Equals(h.ReverseName, h.Name, StringComparison.OrdinalIgnoreCase))
            sb.AppendLine($"rDNS record for {h.Ip}: {h.ReverseName}");
        if (h.OtherAddresses is { Count: > 0 } others)
            sb.AppendLine($"Other addresses for {h.Name} (not scanned): " + string.Join(" ", others.Take(12).Select(a => a.ToString()))
                          + (others.Count > 12 ? $" (+{others.Count - 12} more)" : ""));
        if (!string.IsNullOrEmpty(h.Mac))
            sb.AppendLine($"MAC address: {h.Mac}" + (string.IsNullOrEmpty(h.Vendor) ? "" : $" ({h.Vendor})"));
        if (o.PingOnly) { sb.AppendLine(); return; }

        if (h.AcceptsAll)
        {
            int open = h.Count(ScanProto.Tcp, PortState.Open);
            sb.AppendLine("Warning: this host completed the handshake on ports that should be closed — it answers every TCP");
            sb.AppendLine("connection (a SYN proxy, tarpit or transparent proxy), so its open TCP ports mean nothing and aren't listed"
                          + $" ({open:N0} answered" + (h.SkippedTcp > 0 ? $", {h.SkippedTcp:N0} not probed" : "") + ").");
        }
        if (h.LocalAnswerPorts.Length > 0)
            sb.AppendLine($"Warning: {h.LocalAnswerPorts} answered faster than this host's own round trip — a local proxy, VPN or antivirus"
                          + " completed those connections, so they may not really be open on the host.");

        // nmap's collapse: a state with more than 25 ports on this host is summarized, the rest listed.
        var notShown = h.Reasons
            .Select(kv => (Parts: kv.Key.Split('|'), Count: kv.Value))
            .Select(x => (State: (PortState)int.Parse(x.Parts[0]), Proto: (ScanProto)int.Parse(x.Parts[1]), Reason: x.Parts[2], x.Count))
            .Where(x => h.Count(x.State) > ListThreshold)
            .OrderBy(x => x.State).ThenBy(x => x.Proto).ThenByDescending(x => x.Count)
            .Select(x => $"{x.Count:N0} {ScanText.State(x.State)} {ScanText.Proto(x.Proto)} port{(x.Count == 1 ? "" : "s")} ({x.Reason})")
            .ToList();
        if (notShown.Count > 0) sb.AppendLine("Not shown: " + string.Join(", ", notShown));

        var listed = rows.Where(f => Listed(f) && !(h.AcceptsAll && f.Proto == ScanProto.Tcp && f.State == PortState.Open)).ToList();
        if (gone is not null) listed.AddRange(gone);
        listed.Sort(FindingOrder.Instance);
        if (listed.Count == 0)
        {
            int scanned = h.Tally.Sum();
            if (scanned > 0 && h.Count(PortState.Open) == 0) sb.AppendLine($"All {scanned:N0} scanned ports are closed, filtered or silent.");
            sb.AppendLine();
            return;
        }

        int wPort = Math.Max(4, listed.Max(f => f.PortLabel.Length)) + 1;
        int wState = Math.Max(5, listed.Max(f => ScanText.State(f.State).Length)) + 1;
        int wSvc = Math.Max(7, listed.Max(f => f.Service.Length)) + 1;
        int wReason = Math.Max(6, listed.Max(f => f.Reason.Length)) + 1;
        sb.AppendLine("PORT".PadRight(wPort) + " " + "STATE".PadRight(wState) + " " + "SERVICE".PadRight(wSvc) + " "
                      + "REASON".PadRight(wReason) + " VERSION");
        foreach (var f in listed)
        {
            string line = f.PortLabel.PadRight(wPort) + " " + ScanText.State(f.State).PadRight(wState) + " "
                          + f.Service.PadRight(wSvc) + " " + f.Reason.PadRight(wReason) + " " + f.Version;
            if (f.Change == ScanChange.New) line += "   [new]";
            else if (f.Change == ScanChange.Gone) line += "   [was open]";
            if (f.AnsweredFast) line += "   [answered locally]";
            if (f.Interceptor.Length > 0 && !f.Version.StartsWith("intercepted", StringComparison.Ordinal)) line += $"   [via {f.Interceptor}]";
            sb.AppendLine(line.TrimEnd());
            if (f.Detail.Length > 0) sb.AppendLine("|_ " + f.Detail);
        }
        sb.AppendLine();
    }

    // ---------------------------------------------------------------- CSV

    public static void WriteCsv(Stream stream, ScanPass pass, ScanDiff? diff)
    {
        // 64 KB buffer; fields are written straight into it. leaveOpen: the caller owns the stream.
        using var w = new StreamWriter(stream, new UTF8Encoding(false), 1 << 16, leaveOpen: true);
        w.WriteLine("Address,Hostname,ReverseDns,Mac,Vendor,Port,Protocol,State,Service,Version,Detail,Reason,LatencyMs,Change");
        if (pass.Options.PingOnly)
        {
            foreach (var h in pass.Targets)
            {
                HostFields(w, h);
                w.Write(",,"); CsvField(w, ScanText.Status(h.Status)); w.Write(",,,,");
                CsvField(w, h.Reason); w.Write(','); CsvNumber(w, h.LatencyMs); w.Write(',');
                w.WriteLine();
            }
        }
        var rows = pass.Findings.AsEnumerable();
        if (diff is { Gone.Count: > 0 }) rows = rows.Concat(diff.Gone);
        foreach (var f in rows)
        {
            HostFields(w, f.Host);
            w.Write(f.Port.ToString(CultureInfo.InvariantCulture)); w.Write(',');
            CsvField(w, ScanText.Proto(f.Proto)); w.Write(',');
            CsvField(w, ScanText.State(f.State)); w.Write(',');
            CsvField(w, f.Service); w.Write(',');
            CsvField(w, f.Version); w.Write(',');
            CsvField(w, f.Detail); w.Write(',');
            CsvField(w, f.Reason); w.Write(',');
            CsvNumber(w, f.LatencyMs); w.Write(',');
            CsvField(w, f.Change switch { ScanChange.New => "new", ScanChange.Gone => "no longer open", _ => "" });
            w.WriteLine();
        }
        if (pass.DroppedRows > 0)
        {
            CsvField(w, $"# {pass.DroppedRows:N0} closed/filtered row(s) not kept (cap {ScanEngine.MaxRetainOther:N0}); the report's per-host counts are exact");
            w.WriteLine();
        }
        w.Flush();
    }

    private static void HostFields(TextWriter w, ScanHost h)
    {
        CsvField(w, h.Ip); w.Write(',');
        CsvField(w, h.Name); w.Write(',');
        CsvField(w, h.ReverseName); w.Write(',');
        CsvField(w, h.Mac); w.Write(',');
        CsvField(w, h.Vendor); w.Write(',');
    }

    // RFC 4180: every text field quoted (embedded quotes doubled), so a remote banner can't shift columns. Plus a
    // formula-injection guard: service text is remote input, and quoting alone doesn't stop a spreadsheet from
    // evaluating "=cmd|…" — a leading = + - @ (or tab / CR) gets an apostrophe.
    private static void CsvField(TextWriter w, string? v)
    {
        v ??= "";
        w.Write('"');
        if (v.Length > 0 && v[0] is '=' or '+' or '-' or '@' or '\t' or '\r') w.Write('\'');
        int start = 0;
        for (int q; (q = v.IndexOf('"', start)) >= 0; start = q + 1)
        {
            w.Write(v.AsSpan(start, q - start + 1));
            w.Write('"');
        }
        w.Write(v.AsSpan(start));
        w.Write('"');
    }

    private static void CsvNumber(TextWriter w, double v)
    {
        if (v <= 0) return;
        Span<char> buf = stackalloc char[24];
        v.TryFormat(buf, out int n, "0.###", CultureInfo.InvariantCulture);
        w.Write((ReadOnlySpan<char>)buf[..n]);
    }

    // ---------------------------------------------------------------- JSON

    public static void WriteJson(Stream stream, ScanPass pass, string portsText, ScanDiff? diff)
    {
        using var j = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });
        var o = pass.Options;
        j.WriteStartObject();
        j.WriteString("scanner", "Echoes " + AppVersion());
        j.WriteString("started", pass.StartedUtc.ToString("o", CultureInfo.InvariantCulture));
        j.WriteString("finished", pass.FinishedUtc.ToString("o", CultureInfo.InvariantCulture));
        j.WriteNumber("elapsedSeconds", Math.Round(pass.Elapsed.TotalSeconds, 3));
        j.WriteBoolean("stopped", pass.Stopped);

        j.WriteStartObject("options");
        j.WriteString("flags", Flags(o));
        j.WriteString("ports", portsText);
        j.WriteString("timing", o.Timing.Label);
        j.WriteNumber("timeoutMs", o.TimeoutMs);
        j.WriteNumber("maxRetries", o.Timing.MaxRetries);
        j.WriteNumber("parallelism", o.Concurrency);
        j.WriteEndObject();

        j.WriteStartObject("summary");
        j.WriteNumber("targets", pass.Targets.Count);
        j.WriteNumber("hostsUp", pass.HostsUp);
        j.WriteNumber("probesSent", pass.ProbesSent);
        foreach (PortState s in new[] { PortState.Open, PortState.OpenFiltered, PortState.Filtered, PortState.Closed, PortState.Unknown })
            j.WriteNumber(ScanText.State(s).Replace("|", "_"), pass.Targets.Sum(h => h.Count(s)));
        if (pass.UbiquitousPorts.Count > 0)
        {
            j.WriteStartArray("likelyInterceptedPorts");
            foreach (int p in pass.UbiquitousPorts) j.WriteNumberValue(p);
            j.WriteEndArray();
        }
        if (pass.DroppedRows > 0) j.WriteNumber("rowsNotKept", pass.DroppedRows);
        j.WriteEndObject();

        if (diff is not null)
        {
            j.WriteStartObject("changes");
            WritePortList(j, "newOpen", diff.NewOpen);
            WritePortList(j, "noLongerOpen", diff.Gone);
            j.WriteStartArray("hostsUp");
            foreach (var h in diff.HostsUp) j.WriteStringValue(h.Ip);
            j.WriteEndArray();
            j.WriteStartArray("hostsDown");
            foreach (var h in diff.HostsDown) j.WriteStringValue(h.Ip);
            j.WriteEndArray();
            j.WriteEndObject();
        }

        var byHost = pass.Findings.GroupBy(f => f.Host).ToDictionary(g => g.Key, g => g.ToList());
        j.WriteStartArray("hosts");
        foreach (var h in pass.Targets)
        {
            byHost.TryGetValue(h, out var rows);
            if (h.Status != HostStatus.Up && rows is null && !o.PingOnly) continue;
            j.WriteStartObject();
            j.WriteString("address", h.Ip);
            if (h.Name is { Length: > 0 }) j.WriteString("hostname", h.Name);
            if (h.ReverseName is { Length: > 0 }) j.WriteString("reverseDns", h.ReverseName);
            if (h.Mac is { Length: > 0 }) j.WriteString("mac", h.Mac);
            if (h.Vendor is { Length: > 0 }) j.WriteString("vendor", h.Vendor);
            j.WriteString("status", ScanText.Status(h.Status));
            if (h.Reason.Length > 0) j.WriteString("reason", h.Reason);
            if (h.LatencyMs > 0) j.WriteNumber("latencyMs", Math.Round(h.LatencyMs, 2));
            if (h.AcceptsAll) j.WriteBoolean("answersEveryPort", true);
            if (h.LocalAnswerPorts.Length > 0) j.WriteString("answeredLocally", h.LocalAnswerPorts);
            if (h.OtherAddresses is { Count: > 0 } others)
            {
                j.WriteStartArray("otherAddresses");
                foreach (var a in others) j.WriteStringValue(a.ToString());
                j.WriteEndArray();
            }
            if (!o.PingOnly)
            {
                j.WriteStartArray("ports");
                foreach (var f in rows ?? new List<PortFinding>()) WritePort(j, f);
                j.WriteEndArray();
                j.WriteStartObject("counts");
                foreach (PortState s in new[] { PortState.Open, PortState.OpenFiltered, PortState.Filtered, PortState.Closed, PortState.Unknown })
                    if (h.Count(s) > 0) j.WriteNumber(ScanText.State(s).Replace("|", "_"), h.Count(s));
                j.WriteEndObject();
            }
            j.WriteEndObject();
        }
        j.WriteEndArray();
        j.WriteEndObject();
        j.Flush();
    }

    private static void WritePortList(Utf8JsonWriter j, string name, List<PortFinding> list)
    {
        j.WriteStartArray(name);
        foreach (var f in list)
        {
            j.WriteStartObject();
            j.WriteString("address", f.Host.Ip);
            j.WriteNumber("port", f.Port);
            j.WriteString("protocol", ScanText.Proto(f.Proto));
            j.WriteString("state", ScanText.State(f.State));
            j.WriteEndObject();
        }
        j.WriteEndArray();
    }

    private static void WritePort(Utf8JsonWriter j, PortFinding f)
    {
        j.WriteStartObject();
        j.WriteNumber("port", f.Port);
        j.WriteString("protocol", ScanText.Proto(f.Proto));
        j.WriteString("state", ScanText.State(f.State));
        if (f.Reason.Length > 0) j.WriteString("reason", f.Reason);
        j.WriteString("service", f.Service);
        if (f.Version.Length > 0) j.WriteString("version", f.Version);
        if (f.Detail.Length > 0) j.WriteString("detail", f.Detail);
        if (f.LatencyMs > 0) j.WriteNumber("latencyMs", Math.Round(f.LatencyMs, 2));
        if (f.Change == ScanChange.New) j.WriteBoolean("new", true);
        if (f.AnsweredFast) j.WriteBoolean("answeredLocally", true);
        if (f.Interceptor.Length > 0) j.WriteString("interceptedBy", f.Interceptor);
        j.WriteEndObject();
    }

    private static string AppVersion()
    {
        var v = typeof(ScanReport).Assembly.GetName().Version;
        return v is null ? "" : $"{v.Major}.{v.Minor}.{v.Build}";
    }
}
