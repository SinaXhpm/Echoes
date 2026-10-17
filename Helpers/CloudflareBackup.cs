using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Echoes.Helpers;

/// <summary>
/// The DNS backup file ("echoes-cloudflare-dns", version 1) and the restore plan built from it.
///
/// <code>{"format":"echoes-cloudflare-dns","version":1,"zone":"example.com","exportedAt":"2026-10-12T08:00:00Z",
///  "records":[{"type":"A","name":"www.example.com","content":"192.0.2.1","ttl":1,"proxied":true,"comment":"…"}]}</code>
///
/// <para>Only the whitelisted record fields (<see cref="Fields"/>) are ever written or sent: never ids, zone ids,
/// timestamps or credentials. A file to restore is treated as hostile: size-capped, parsed strictly (no comments, no
/// trailing commas, shallow), the format must match, and every record is validated field by field (type from a fixed
/// set, string lengths, ttl, priority, a small flat <c>data</c> object, tags). Invalid entries are reported and left
/// out; unknown fields are ignored.</para>
/// </summary>
public static class CloudflareBackup
{
    public const string Format = "echoes-cloudflare-dns";
    public const int Version = 1;
    public const int MaxFileBytes = 5 * 1024 * 1024;
    public const int MaxRecords = 20_000;

    /// <summary>The only record fields a backup holds and a restore sends.</summary>
    public static readonly string[] Fields = { "type", "name", "content", "ttl", "proxied", "priority", "data", "comment", "tags" };

    /// <summary>Record types Cloudflare serves (a backup entry of any other type is rejected).</summary>
    public static readonly HashSet<string> AllowedTypes = new(StringComparer.Ordinal)
    {
        "A", "AAAA", "CAA", "CERT", "CNAME", "DNSKEY", "DS", "HTTPS", "LOC", "MX", "NAPTR", "NS",
        "OPENPGPKEY", "PTR", "SMIMEA", "SRV", "SSHFP", "SVCB", "TLSA", "TXT", "URI",
    };

    private const int MaxNameLength = 253;
    private const int MaxContentLength = 4096;
    private const int MaxCommentLength = 500;
    private const int MaxTags = 20;
    private const int MaxTagLength = 140;
    private const int MaxDataProperties = 16;
    private const int MaxDataValueLength = 4096;

    /// <summary>One DNS record as kept in a backup (whitelisted fields only).</summary>
    public sealed class Entry
    {
        public string Type { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Content { get; set; } = string.Empty;
        public int Ttl { get; set; } = 1;
        public bool? Proxied { get; set; }
        public int? Priority { get; set; }
        /// <summary>Structured value (CAA, SRV, HTTPS, …): a flat object of strings / numbers / booleans.</summary>
        public JsonObject? Data { get; set; }
        public string? Comment { get; set; }
        public List<string>? Tags { get; set; }
    }

    public sealed class Parsed
    {
        public string Zone { get; init; } = string.Empty;
        public DateTimeOffset? ExportedAt { get; init; }
        public List<Entry> Entries { get; } = new();
        /// <summary>Entries that failed validation: "#12 (www.example.com): reason" (the first 200).</summary>
        public List<string> Invalid { get; } = new();
        public int InvalidCount { get; set; }
        public int Total { get; init; }
    }

    public static bool Proxiable(string type) => type is "A" or "AAAA" or "CNAME";

    /// <summary>Types with a top-level <c>priority</c> field (SRV / HTTPS / SVCB keep theirs inside <c>data</c>).</summary>
    public static bool UsesPriority(string type) => type is "MX" or "URI";

    // ================================================================ writing

    /// <summary>The backup file for <paramref name="zone"/> (indented UTF-8 JSON, no BOM).</summary>
    public static byte[] Write(string zone, IEnumerable<Entry> entries, DateTimeOffset exportedAt)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true }))
        {
            w.WriteStartObject();
            w.WriteString("format", Format);
            w.WriteNumber("version", Version);
            w.WriteString("zone", zone);
            w.WriteString("exportedAt", exportedAt.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture));
            w.WriteStartArray("records");
            foreach (var e in entries)
            {
                w.WriteStartObject();
                w.WriteString("type", e.Type);
                w.WriteString("name", e.Name);
                w.WriteString("content", e.Content);
                w.WriteNumber("ttl", e.Ttl);
                if (e.Proxied is bool p) w.WriteBoolean("proxied", p);
                if (e.Priority is int pr) w.WriteNumber("priority", pr);
                if (e.Data is { Count: > 0 } d)
                {
                    w.WritePropertyName("data");
                    d.WriteTo(w);
                }
                if (!string.IsNullOrEmpty(e.Comment)) w.WriteString("comment", e.Comment);
                if (e.Tags is { Count: > 0 } tags)
                {
                    w.WriteStartArray("tags");
                    foreach (var t in tags) w.WriteStringValue(t);
                    w.WriteEndArray();
                }
                w.WriteEndObject();
            }
            w.WriteEndArray();
            w.WriteEndObject();
        }
        return ms.ToArray();
    }

    /// <summary>A copy of a record's <c>data</c> keeping only flat primitive values (what the API returns for every type).</summary>
    public static JsonObject? CleanData(JsonObject? data)
    {
        if (data is null || data.Count == 0) return null;
        var o = new JsonObject();
        foreach (var (k, v) in data)
        {
            if (o.Count >= MaxDataProperties || k.Length is 0 or > 64) continue;
            switch (v?.GetValueKind())
            {
                case JsonValueKind.String:
                    string s = v.GetValue<string>();
                    if (s.Length <= MaxDataValueLength) o[k] = s;
                    break;
                case JsonValueKind.Number:
                    o[k] = v.DeepClone();
                    break;
                case JsonValueKind.True:
                case JsonValueKind.False:
                    o[k] = v.GetValueKind() == JsonValueKind.True;
                    break;
            }
        }
        return o.Count > 0 ? o : null;
    }

    // ================================================================ reading (hostile input)

    /// <summary>
    /// Parse and validate a backup file. Throws <see cref="FormatException"/> (with a readable message) when the file
    /// as a whole is unusable; individual bad records land in <see cref="Parsed.Invalid"/>.
    /// </summary>
    public static Parsed Parse(byte[] bytes)
    {
        if (bytes.Length > MaxFileBytes) throw new FormatException("The file is larger than 5 MB, so it isn't a DNS backup.");
        ReadOnlyMemory<byte> utf8 = bytes;
        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) utf8 = utf8[3..];

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(utf8, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 8,
            });
        }
        catch (JsonException) { throw new FormatException("The file isn't valid JSON."); }

        using (doc)
        {
            var root = doc.RootElement;
            // A property name with a broken \u escape throws InvalidOperationException (JsonProperty.Name): that escaped
            // as a non-FormatException instead of this file's readable refusal.
            Dictionary<string, JsonElement>? top;
            try { top = root.ValueKind == JsonValueKind.Object ? Props(root) : null; }
            catch (InvalidOperationException) { top = null; }
            if (top is null)
                throw new FormatException("This isn't an Echoes DNS backup.");
            if (!top.TryGetValue("format", out var f) || f.ValueKind != JsonValueKind.String || TryGetString(f) != Format)
                throw new FormatException("This isn't an Echoes DNS backup (its \"format\" field doesn't match).");
            if (!top.TryGetValue("version", out var v) || v.ValueKind != JsonValueKind.Number || !v.TryGetInt32(out int ver) || ver < 1)
                throw new FormatException("The backup has no valid version.");
            if (ver > Version)
                throw new FormatException($"The backup was made by a newer Echoes (format version {ver}). Update Echoes to restore it.");
            if (!top.TryGetValue("zone", out var z) || z.ValueKind != JsonValueKind.String || TryGetString(z) is not { } zoneText
                || NormName(zoneText) is not { } zone || !IsDnsName(zone, wildcard: false))
                throw new FormatException("The backup's zone name is missing or invalid.");
            if (!top.TryGetValue("records", out var recs) || recs.ValueKind != JsonValueKind.Array)
                throw new FormatException("The backup has no record list.");
            int total = recs.GetArrayLength();
            if (total > MaxRecords) throw new FormatException($"The backup lists {total} records; the limit is {MaxRecords}.");

            DateTimeOffset? exported = null;
            if (top.TryGetValue("exportedAt", out var ex) && ex.ValueKind == JsonValueKind.String
                && DateTimeOffset.TryParse(TryGetString(ex), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var when))
                exported = when;

            var parsed = new Parsed { Zone = zone, ExportedAt = exported, Total = total };
            int i = 0;
            foreach (var el in recs.EnumerateArray())
            {
                i++;
                Entry? entry;
                string? error;
                // A broken \u escape in one record's text makes that record invalid, not the whole file unrestorable.
                try { entry = ParseEntry(el, out error); }
                catch (InvalidOperationException) { entry = null; error = "a text field has a broken \\u escape"; }
                if (entry != null) { parsed.Entries.Add(entry); continue; }
                parsed.InvalidCount++;
                if (parsed.Invalid.Count < 200)
                    parsed.Invalid.Add($"#{i}{(Peek(el) is { } n ? $" ({n})" : "")}: {error ?? "invalid"}");
            }
            return parsed;
        }
    }

    private static string? Peek(JsonElement el)
    {
        try
        {
            if (el.ValueKind != JsonValueKind.Object || !el.TryGetProperty("name", out var n) || n.ValueKind != JsonValueKind.String) return null;
            if (TryGetString(n) is not { } s) return null;
            s = Sanitize(s);
            return s.Length > 60 ? s[..60] + "…" : s;
        }
        // The lookup decodes property names: one with a broken \u escape threw here, outside the per-record catch, and
        // failed the whole file instead of reporting that one entry.
        catch (InvalidOperationException) { return null; }
    }

    // JsonElement.GetString() throws InvalidOperationException on an unpaired surrogate escape ("\ud800") — not the
    // FormatException callers expect from a bad file. Such a field reads as missing.
    private static string? TryGetString(JsonElement e)
    {
        try { return e.GetString(); }
        catch (InvalidOperationException) { return null; }
    }

    private static string Sanitize(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s) sb.Append(char.IsControl(c) ? '?' : c);
        return sb.ToString();
    }

    // The properties of an object, or null when a name repeats (an ambiguous record is refused, not guessed at).
    private static Dictionary<string, JsonElement>? Props(JsonElement obj)
    {
        var d = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var p in obj.EnumerateObject())
            if (!d.TryAdd(p.Name, p.Value)) return null;
        return d;
    }

    private static Entry? ParseEntry(JsonElement el, out string? error)
    {
        error = null;
        if (el.ValueKind != JsonValueKind.Object) { error = "not a record object"; return null; }
        if (Props(el) is not { } p) { error = "a field appears twice"; return null; }

        if (!p.TryGetValue("type", out var t) || t.ValueKind != JsonValueKind.String) { error = "missing type"; return null; }
        string type = (t.GetString() ?? string.Empty).Trim().ToUpperInvariant();
        if (!AllowedTypes.Contains(type)) { error = $"unsupported type \"{Clip(type, 12)}\""; return null; }

        if (!p.TryGetValue("name", out var n) || n.ValueKind != JsonValueKind.String) { error = "missing name"; return null; }
        string name = NormName(n.GetString() ?? string.Empty);
        if (!IsDnsName(name, wildcard: true)) { error = "invalid name"; return null; }

        JsonObject? data = null;
        if (p.TryGetValue("data", out var d) && d.ValueKind != JsonValueKind.Null)
        {
            data = ReadData(d, out error);
            if (error != null) return null;
        }

        string content = string.Empty;
        if (p.TryGetValue("content", out var c) && c.ValueKind != JsonValueKind.Null)
        {
            if (c.ValueKind != JsonValueKind.String) { error = "content isn't text"; return null; }
            content = c.GetString() ?? string.Empty;
            if (content.Length > MaxContentLength) { error = "content is too long"; return null; }
            if (HasControlChars(content)) { error = "content has control characters"; return null; }
        }
        if (content.Length == 0 && data is null) { error = "no content"; return null; }

        int ttl = 1;
        if (p.TryGetValue("ttl", out var tt) && tt.ValueKind != JsonValueKind.Null)
        {
            if (tt.ValueKind != JsonValueKind.Number || !tt.TryGetInt32(out ttl) || !(ttl == 1 || ttl is >= 30 and <= 86400))
            { error = "ttl must be 1 (auto) or 30–86400"; return null; }
        }

        bool? proxied = null;
        if (p.TryGetValue("proxied", out var px) && px.ValueKind != JsonValueKind.Null)
        {
            if (px.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) { error = "proxied isn't true/false"; return null; }
            proxied = px.ValueKind == JsonValueKind.True;
        }

        int? priority = null;
        if (p.TryGetValue("priority", out var pr) && pr.ValueKind != JsonValueKind.Null)
        {
            if (pr.ValueKind != JsonValueKind.Number || !pr.TryGetInt32(out int prio) || prio is < 0 or > 65535)
            { error = "priority must be 0–65535"; return null; }
            priority = prio;
        }

        string? comment = null;
        if (p.TryGetValue("comment", out var cm) && cm.ValueKind != JsonValueKind.Null)
        {
            if (cm.ValueKind != JsonValueKind.String) { error = "comment isn't text"; return null; }
            comment = cm.GetString();
            if (comment is { Length: > MaxCommentLength }) { error = "comment is too long"; return null; }
            if (comment != null && HasControlChars(comment)) { error = "comment has control characters"; return null; }
        }

        List<string>? tags = null;
        if (p.TryGetValue("tags", out var tg) && tg.ValueKind != JsonValueKind.Null)
        {
            if (tg.ValueKind != JsonValueKind.Array || tg.GetArrayLength() > MaxTags) { error = $"tags must be a list of up to {MaxTags}"; return null; }
            tags = new List<string>();
            foreach (var tag in tg.EnumerateArray())
            {
                if (tag.ValueKind != JsonValueKind.String) { error = "a tag isn't text"; return null; }
                string s = tag.GetString() ?? string.Empty;
                if (s.Length is 0 or > MaxTagLength || HasControlChars(s)) { error = "invalid tag"; return null; }
                tags.Add(s);
            }
        }

        // ids, zone ids, timestamps, meta and anything else in the object are deliberately ignored.
        return new Entry
        {
            Type = type, Name = name, Content = content, Ttl = ttl, Proxied = proxied, Priority = priority,
            Data = data, Comment = string.IsNullOrEmpty(comment) ? null : comment, Tags = tags,
        };
    }

    // data: a small flat object of strings / numbers / booleans (that's what every record type's data is).
    private static JsonObject? ReadData(JsonElement d, out string? error)
    {
        error = null;
        if (d.ValueKind != JsonValueKind.Object) { error = "data isn't an object"; return null; }
        if (Props(d) is not { } props) { error = "a data field appears twice"; return null; }
        if (props.Count > MaxDataProperties) { error = "data has too many fields"; return null; }
        var o = new JsonObject();
        foreach (var (k, v) in props)
        {
            if (k.Length is 0 or > 64 || HasControlChars(k)) { error = "invalid data field name"; return null; }
            switch (v.ValueKind)
            {
                case JsonValueKind.String:
                    string s = v.GetString() ?? string.Empty;
                    if (s.Length > MaxDataValueLength || HasControlChars(s)) { error = "a data value is too long or invalid"; return null; }
                    o[k] = s;
                    break;
                case JsonValueKind.Number:
                    if (v.TryGetInt64(out long l)) o[k] = l;
                    else if (v.TryGetDouble(out double dbl) && double.IsFinite(dbl)) o[k] = dbl;
                    else { error = "a data number is invalid"; return null; }
                    break;
                case JsonValueKind.True:
                case JsonValueKind.False:
                    o[k] = v.ValueKind == JsonValueKind.True;
                    break;
                case JsonValueKind.Null:
                    break;
                default:
                    error = "data values must be plain text, numbers or true/false";
                    return null;
            }
        }
        return o.Count > 0 ? o : null;
    }

    private static bool HasControlChars(string s)
    {
        foreach (char c in s)
            if (char.IsControl(c)) return true;
        return false;
    }

    private static string Clip(string s, int max) => Sanitize(s.Length > max ? s[..max] + "…" : s);

    // ================================================================ names + matching

    public static string NormName(string name) => name.Trim().TrimEnd('.').ToLowerInvariant();

    /// <summary>A DNS name in ASCII form: letters, digits, '-', '_', '.', and (when allowed) '*' labels.</summary>
    public static bool IsDnsName(string name, bool wildcard)
    {
        if (name.Length is 0 or > MaxNameLength) return false;
        foreach (string label in name.Split('.'))
        {
            if (label.Length is 0 or > 63) return false;
            if (label == "*") { if (!wildcard) return false; continue; }
            foreach (char c in label)
                if (!(char.IsAsciiLetterOrDigit(c) || c is '-' or '_')) return false;
        }
        return true;
    }

    /// <summary>True when <paramref name="name"/> is <paramref name="zone"/> or one of its subdomains.</summary>
    public static bool InZone(string name, string zone)
    {
        string n = NormName(name), z = NormName(zone);
        return n == z || n.EndsWith("." + z, StringComparison.Ordinal);
    }

    /// <summary>Move a name from one zone to another (old.com → new.com, www.old.com → www.new.com); others unchanged.</summary>
    public static string Rename(string name, string fromZone, string toZone)
    {
        string n = NormName(name), from = NormName(fromZone), to = NormName(toZone);
        if (from.Length == 0 || to.Length == 0) return n;
        if (n == from) return to;
        if (n.EndsWith("." + from, StringComparison.Ordinal)) return n[..^from.Length] + to;
        return n;
    }

    /// <summary>Content in comparable form: IPs canonicalised, host names lower-cased without the trailing dot.</summary>
    public static string NormContent(string type, string content)
    {
        string c = content.Trim();
        switch (type)
        {
            case "A":
            case "AAAA":
                return IPAddress.TryParse(c, out var ip) ? ip.ToString() : c;
            case "CNAME":
            case "NS":
            case "PTR":
            case "MX":
                return c.TrimEnd('.').ToLowerInvariant();
            case "TXT":
                return UnquoteTxt(c);
            default:
                return c;
        }
    }

    // TXT content may come quoted ("v=spf1 …" or "part 1" "part 2") or bare, depending on how and when it was
    // written: compare the text itself, so a backup still matches after the quoting style changed.
    private static string UnquoteTxt(string c)
    {
        if (c.Length < 2 || c[0] != '"') return c;
        var sb = new StringBuilder(c.Length);
        int i = 0;
        while (i < c.Length)
        {
            while (i < c.Length && c[i] == ' ') i++;
            if (i >= c.Length) break;
            if (c[i] != '"') return c;          // not a pure sequence of quoted strings: compare as written
            i++;
            bool closed = false;
            while (i < c.Length)
            {
                char ch = c[i++];
                if (ch == '\\' && i < c.Length) { sb.Append(c[i++]); continue; }
                if (ch == '"') { closed = true; break; }
                sb.Append(ch);
            }
            if (!closed) return c;
        }
        return sb.ToString();
    }

    /// <summary>Identity of a record for matching: same type + name + content means the same record.</summary>
    public static string Key(string type, string name, string content)
        => type.ToUpperInvariant() + "\n" + NormName(name) + "\n" + NormContent(type.ToUpperInvariant(), content);

    // ================================================================ restore plan

    /// <summary>A record already in the zone (what matching and updating need).</summary>
    public sealed class Existing
    {
        public string Id { get; init; } = string.Empty;
        public string Type { get; init; } = string.Empty;
        public string Name { get; init; } = string.Empty;
        public string Content { get; init; } = string.Empty;
        public int Ttl { get; init; } = 1;
        public bool Proxied { get; init; }
        public int? Priority { get; init; }
        public string? Comment { get; init; }
    }

    public enum Action { Add, Update, Present, Skip }

    public sealed class PlanItem
    {
        public Action Action { get; init; }
        public Entry Entry { get; init; } = new();
        /// <summary>The name the record gets in the target zone (after an optional zone rename).</summary>
        public string Name { get; init; } = string.Empty;
        public string? ExistingId { get; init; }
        /// <summary>The request body: the whole record for an add, only the differing fields for an update.</summary>
        public JsonObject? Body { get; init; }
        /// <summary>What changes ("TTL 1 h → auto · proxied") or why the entry is skipped.</summary>
        public string Detail { get; init; } = string.Empty;
    }

    public sealed class Plan
    {
        public List<PlanItem> Items { get; } = new();
        public int Adds { get; set; }
        public int Updates { get; set; }
        public int Present { get; set; }
        public int Skipped { get; set; }
        public bool TagsLeftOut { get; set; }
    }

    /// <summary>
    /// Compare a backup with the target zone. Same type + name + content = the same record: when its ttl / proxied /
    /// priority / comment differ it is UPDATED (only those fields), otherwise it is already present. Everything else
    /// is ADDED. Records in the zone that the backup doesn't list are never touched (a restore never deletes).
    /// </summary>
    public static Plan BuildPlan(IReadOnlyList<Entry> entries, string backupZone, string targetZone, bool renameZone,
                                 IReadOnlyList<Existing> existing, bool leaveOutTags)
    {
        var plan = new Plan();
        var index = new Dictionary<string, Existing>(StringComparer.Ordinal);
        foreach (var r in existing) index.TryAdd(Key(r.Type, r.Name, r.Content), r);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        string target = NormName(targetZone);

        foreach (var e in entries)
        {
            string name = renameZone ? Rename(e.Name, backupZone, target) : NormName(e.Name);
            if (!InZone(name, target))
            {
                plan.Items.Add(new PlanItem { Action = Action.Skip, Entry = e, Name = name, Detail = $"not part of {target}" });
                plan.Skipped++;
                continue;
            }
            string key = Key(e.Type, name, e.Content);
            if (!seen.Add(key))
            {
                plan.Items.Add(new PlanItem { Action = Action.Skip, Entry = e, Name = name, Detail = "listed twice in the backup" });
                plan.Skipped++;
                continue;
            }
            if (e.Content.Length == 0 && e.Data is null)
            {
                plan.Items.Add(new PlanItem { Action = Action.Skip, Entry = e, Name = name, Detail = "no content" });
                plan.Skipped++;
                continue;
            }

            if (index.TryGetValue(key, out var cur))
            {
                var (patch, detail) = Differences(e, cur);
                if (patch is null)
                {
                    plan.Items.Add(new PlanItem { Action = Action.Present, Entry = e, Name = name, ExistingId = cur.Id });
                    plan.Present++;
                }
                else
                {
                    plan.Items.Add(new PlanItem { Action = Action.Update, Entry = e, Name = name, ExistingId = cur.Id, Body = patch, Detail = detail });
                    plan.Updates++;
                }
            }
            else
            {
                bool dropTags = leaveOutTags && e.Tags is { Count: > 0 };
                plan.TagsLeftOut |= dropTags;
                plan.Items.Add(new PlanItem { Action = Action.Add, Entry = e, Name = name, Body = CreateBody(e, name, leaveOutTags) });
                plan.Adds++;
            }
        }
        return plan;
    }

    // ttl / proxied / priority / comment that differ → the PATCH body (null when nothing differs) + a readable summary.
    private static (JsonObject? Patch, string Detail) Differences(Entry e, Existing cur)
    {
        var patch = new JsonObject();
        var parts = new List<string>();
        bool proxiable = Proxiable(e.Type);
        bool wantProxied = e.Proxied ?? false;

        if (proxiable && e.Proxied is bool && wantProxied != cur.Proxied)
        {
            patch["proxied"] = wantProxied;
            parts.Add(wantProxied ? "proxied" : "DNS only");
        }
        // A proxied record's TTL is always automatic; comparing it would only produce a no-op update.
        bool proxiedAfter = proxiable && (e.Proxied ?? cur.Proxied);
        if (!proxiedAfter && e.Ttl != cur.Ttl)
        {
            patch["ttl"] = e.Ttl;
            parts.Add($"TTL {TtlText(cur.Ttl)} → {TtlText(e.Ttl)}");
        }
        if (UsesPriority(e.Type) && e.Priority is int p && p != cur.Priority)
        {
            patch["priority"] = p;
            parts.Add($"priority {cur.Priority?.ToString(CultureInfo.InvariantCulture) ?? "none"} → {p}");
        }
        string want = e.Comment ?? string.Empty, have = cur.Comment ?? string.Empty;
        if (want != have)
        {
            patch["comment"] = want;
            parts.Add(want.Length == 0 ? "comment removed" : have.Length == 0 ? "comment added" : "comment changed");
        }
        return patch.Count == 0 ? (null, string.Empty) : (patch, string.Join(" · ", parts));
    }

    /// <summary>POST body for a new record from a backup entry: whitelisted fields only.</summary>
    public static JsonObject CreateBody(Entry e, string name, bool leaveOutTags)
    {
        var o = new JsonObject
        {
            ["type"] = e.Type,
            ["name"] = name,
        };
        // Structured types (CAA, SRV, HTTPS, …) are created from data; their content is only its formatted form.
        if (e.Data is { Count: > 0 } d) o["data"] = d.DeepClone();
        else o["content"] = e.Content;
        bool proxied = Proxiable(e.Type) && e.Proxied == true;
        o["ttl"] = proxied ? 1 : e.Ttl;   // a proxied record's TTL is always automatic
        if (Proxiable(e.Type) && e.Proxied is bool p) o["proxied"] = p;
        if (UsesPriority(e.Type) && e.Priority is int pr) o["priority"] = pr;
        if (!string.IsNullOrEmpty(e.Comment)) o["comment"] = e.Comment;
        if (!leaveOutTags && e.Tags is { Count: > 0 } tags)
        {
            var arr = new JsonArray();
            foreach (var t in tags) arr.Add((JsonNode?)JsonValue.Create(t));
            o["tags"] = arr;
        }
        return o;
    }

    /// <summary>"auto", "5 min", "1 hr", "1 day" (the labels the TTL picker uses).</summary>
    public static string TtlText(int ttl)
    {
        if (ttl <= 1) return "auto";
        if (ttl % 86400 == 0) return ttl == 86400 ? "1 day" : $"{ttl / 86400} days";
        if (ttl % 3600 == 0) return $"{ttl / 3600} hr";
        if (ttl % 60 == 0) return $"{ttl / 60} min";
        return $"{ttl} s";
    }

    /// <summary>"example.com-dns-2026-10-12.json" (anything odd in the zone name becomes '-').</summary>
    public static string SuggestedFileName(string zone, DateTime date, string suffix)
    {
        var sb = new StringBuilder();
        foreach (char c in NormName(zone)) sb.Append(char.IsAsciiLetterOrDigit(c) || c is '.' or '-' ? c : '-');
        if (sb.Length == 0) sb.Append("zone");
        return $"{sb}-{suffix}-{date.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}";
    }

    /// <summary>Reads a picked file with a size cap (the stream's length may be unknown, e.g. Android content URIs).</summary>
    public static async System.Threading.Tasks.Task<byte[]> ReadCappedAsync(Stream s, int maxBytes = MaxFileBytes)
    {
        using var ms = new MemoryStream();
        byte[] buf = new byte[64 * 1024];
        int n;
        while ((n = await s.ReadAsync(buf)) > 0)
        {
            if (ms.Length + n > maxBytes) throw new FormatException($"The file is larger than {maxBytes / (1024 * 1024)} MB, so it isn't a DNS backup.");
            ms.Write(buf, 0, n);
        }
        return ms.ToArray();
    }

    /// <summary>True for a valid IPv4 address in dotted-quad form (IPAddress.TryParse alone also takes "1" or "1.2").</summary>
    public static bool IsIPv4(string s)
    {
        string[] parts = s.Split('.');
        if (parts.Length != 4) return false;
        foreach (var p in parts)
            if (p.Length is 0 or > 3 || !int.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out int v) || v > 255) return false;
        return true;
    }

    public static bool IsIPv6(string s)
        => s.Contains(':') && IPAddress.TryParse(s, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6;
}
