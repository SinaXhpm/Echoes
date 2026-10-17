using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Echoes.Helpers;

/// <summary>
/// A BIND zone file read for the import preview (POST /zones/{id}/dns_records/import, multipart "file").
///
/// <para>The file is untrusted text: it is size-capped by the caller (Cloudflare takes 256 KiB), parsed without ever
/// following $INCLUDE, and what is uploaded is NOT the file itself but a clean file generated from the records the
/// preview shows as new — one record per line, owner names absolute, the host names in CNAME / MX / NS / PTR / SRV made
/// fully qualified (Cloudflare requires that), SOA, the old provider's apex NS records, records already in the zone and
/// duplicates left out. So what the preview lists is exactly what is sent. $GENERATE lines (which Cloudflare expands
/// itself) are passed through whole with the $ORIGIN they were written under, and listed in the preview too. Control
/// characters (other than tab) anywhere outside comments mean the file isn't a zone file.</para>
/// </summary>
public static class CloudflareZoneFile
{
    public const int MaxBytes = 256 * 1024;
    private const int MaxGenerateLength = 300;

    public sealed class Entry
    {
        public int Line { get; init; }
        public string Type { get; init; } = string.Empty;
        /// <summary>Owner name, absolute, lower-case, no trailing dot.</summary>
        public string Name { get; init; } = string.Empty;
        /// <summary>Content as Cloudflare lists it (for matching against the zone): MX / SRV without the priority.</summary>
        public string Content { get; init; } = string.Empty;
        /// <summary>Content for the preview (MX / SRV with their priority).</summary>
        public string Display { get; init; } = string.Empty;
        public int? Ttl { get; init; }
        /// <summary>The cf_tags comment of the line ("cf-proxied:true,team:web"), kept as written.</summary>
        public string? Tags { get; init; }
        /// <summary>The record's data in the form the generated file uses (names fully qualified).</summary>
        public string Rdata { get; init; } = string.Empty;
    }

    public sealed class Problem
    {
        public int Line { get; init; }
        public string Text { get; init; } = string.Empty;
        public string Reason { get; init; } = string.Empty;
    }

    public sealed class Parsed
    {
        public List<Entry> Entries { get; } = new();
        /// <summary>Lines that couldn't be read as a record (shown, not sent).</summary>
        public List<Problem> Unreadable { get; } = new();
        /// <summary>$GENERATE lines, each with the origin in force where it was written.</summary>
        public List<(string Origin, string Text)> Generates { get; } = new();
    }

    private sealed class Logical
    {
        public int Line;
        public bool ImplicitOwner;
        public readonly List<string> Tokens = new();
        public string Comment = string.Empty;
        public string Raw = string.Empty;
    }

    /// <summary>Parse the file for <paramref name="zone"/>. Throws <see cref="FormatException"/> (readable) when the file
    /// as a whole can't be imported ($INCLUDE, binary data).</summary>
    public static Parsed Parse(string text, string zone)
    {
        string origin = CloudflareBackup.NormName(zone);
        var result = new Parsed();
        int? defaultTtl = null, lastTtl = null;
        string? lastOwner = null;

        foreach (var rec in Split((text ?? string.Empty).TrimStart('﻿')))
        {
            if (rec.Tokens.Count == 0) continue;
            string first = rec.Tokens[0];

            if (!rec.ImplicitOwner && first.StartsWith('$'))
            {
                switch (first.ToUpperInvariant())
                {
                    case "$ORIGIN":
                        if (rec.Tokens.Count < 2) { Bad(result, rec, "$ORIGIN needs a domain name"); continue; }
                        origin = Resolve(rec.Tokens[1], origin);
                        continue;
                    case "$TTL":
                        if (rec.Tokens.Count < 2 || ParseTtl(rec.Tokens[1]) is not int t) { Bad(result, rec, "$TTL needs a time"); continue; }
                        defaultTtl = t;
                        continue;
                    case "$INCLUDE":
                        throw new FormatException($"Line {rec.Line}: Cloudflare's import doesn't support $INCLUDE. Paste the included records into this file instead.");
                    case "$GENERATE":
                        // Uploaded as written, so never shortened: Clip's "…" in the middle of a long line sent Cloudflare
                        // a broken one. And its $ORIGIN line is written too, so that must be a real domain.
                        if (rec.Raw.Length > MaxGenerateLength) { Bad(result, rec, "the $GENERATE line is too long"); continue; }
                        if (!CloudflareBackup.IsDnsName(origin, wildcard: false)) { Bad(result, rec, "the $ORIGIN above isn't a valid domain"); continue; }
                        result.Generates.Add((origin, Clip(rec.Raw, MaxGenerateLength)));
                        continue;
                    default:
                        Bad(result, rec, $"unknown directive {Clip(first, 20)}");
                        continue;
                }
            }

            int i = 0;
            string owner;
            if (rec.ImplicitOwner)
            {
                if (lastOwner is null) { Bad(result, rec, "no owner name (the line starts with a space)"); continue; }
                owner = lastOwner;
            }
            else
            {
                owner = Resolve(first, origin);
                i = 1;
            }

            int? ttl = null;
            for (int k = 0; k < 2 && i < rec.Tokens.Count; k++)
            {
                string tok = rec.Tokens[i];
                if (ttl is null && ParseTtl(tok) is int tv) { ttl = tv; i++; continue; }
                if (tok.ToUpperInvariant() is "IN" or "CH" or "HS" or "CS") { i++; continue; }
                break;
            }
            if (i >= rec.Tokens.Count) { Bad(result, rec, "no record type"); continue; }
            string type = rec.Tokens[i].ToUpperInvariant();
            if (type.Length is 0 or > 12 || !IsWord(type)) { Bad(result, rec, $"\"{Clip(rec.Tokens[i], 20)}\" isn't a record type"); continue; }
            var rdata = rec.Tokens.GetRange(i + 1, rec.Tokens.Count - i - 1);
            if (rdata.Count == 0) { Bad(result, rec, $"the {type} record has no data"); continue; }
            if (!CloudflareBackup.IsDnsName(owner, wildcard: true) && type != "SOA") { Bad(result, rec, "invalid owner name"); continue; }

            lastOwner = owner;
            if (ttl is int explicitTtl) lastTtl = explicitTtl;
            int? effectiveTtl = ttl ?? defaultTtl ?? lastTtl;

            if (!TryContent(type, rdata, origin, out string content, out string display, out string canonical, out string? why))
            {
                Bad(result, rec, why ?? $"unreadable {type} data");
                continue;
            }

            result.Entries.Add(new Entry
            {
                Line = rec.Line,
                Type = type,
                Name = owner,
                Content = content,
                Display = display,
                Ttl = effectiveTtl,
                Tags = CfTags(rec.Comment),
                Rdata = canonical,
            });
        }
        return result;
    }

    private static void Bad(Parsed p, Logical rec, string reason)
    {
        if (p.Unreadable.Count < 200)
            p.Unreadable.Add(new Problem { Line = rec.Line, Text = Clip(rec.Raw, 120), Reason = reason });
    }

    // Content per type. Host-name targets are made absolute (with a trailing dot in the generated file).
    private static bool TryContent(string type, List<string> rd, string origin, out string content, out string display,
                                   out string canonical, out string? why)
    {
        why = null;
        content = display = canonical = string.Empty;
        string Abs(string name) => name == "." ? "." : Resolve(name, origin);
        string Fq(string name) => name == "." ? "." : Abs(name) + ".";
        switch (type)
        {
            case "A":
                if (rd.Count != 1 || !CloudflareBackup.IsIPv4(rd[0])) { why = "the A record needs one IPv4 address"; return false; }
                content = display = canonical = rd[0];
                return true;
            case "AAAA":
                if (rd.Count != 1 || !CloudflareBackup.IsIPv6(rd[0])) { why = "the AAAA record needs one IPv6 address"; return false; }
                content = display = canonical = rd[0];
                return true;
            case "CNAME":
            case "NS":
            case "PTR":
            case "DNAME":
                if (rd.Count != 1) { why = $"the {type} record needs one host name"; return false; }
                content = display = Abs(rd[0]);
                canonical = Fq(rd[0]);
                return true;
            case "MX":
                if (rd.Count != 2 || !ushort.TryParse(rd[0], NumberStyles.None, CultureInfo.InvariantCulture, out ushort pref))
                { why = "the MX record needs a priority and a mail server"; return false; }
                content = Abs(rd[1]);
                display = pref.ToString(CultureInfo.InvariantCulture) + "  " + content;
                canonical = pref.ToString(CultureInfo.InvariantCulture) + " " + Fq(rd[1]);
                return true;
            case "SRV":
                if (rd.Count != 4 || !ushort.TryParse(rd[0], NumberStyles.None, CultureInfo.InvariantCulture, out ushort prio)
                    || !ushort.TryParse(rd[1], NumberStyles.None, CultureInfo.InvariantCulture, out ushort weight)
                    || !ushort.TryParse(rd[2], NumberStyles.None, CultureInfo.InvariantCulture, out ushort port))
                { why = "the SRV record needs priority, weight, port and target"; return false; }
                string target = Abs(rd[3]);
                content = $"{weight} {port} {target}";
                display = $"{prio} {weight} {port} {target}";
                canonical = $"{prio} {weight} {port} {Fq(rd[3])}";
                return true;
            case "SOA":
                content = display = canonical = string.Join(' ', rd);
                return true;
            default:
                content = display = canonical = string.Join(' ', rd);
                if (content.Length > 4096) { why = "the record data is too long"; return false; }
                return true;
        }
    }

    /// <summary>The file Cloudflare receives: the kept records, one per line, plus the $GENERATE lines.</summary>
    public static string BuildUpload(IEnumerable<Entry> keep, IEnumerable<(string Origin, string Text)> generates)
    {
        var sb = new StringBuilder();
        sb.Append(";; Prepared by Echoes for the Cloudflare import\n");
        foreach (var e in keep)
        {
            sb.Append(e.Name).Append(".\t");
            if (e.Ttl is int ttl) sb.Append(Math.Clamp(ttl, 30, 86400).ToString(CultureInfo.InvariantCulture)).Append('\t');
            sb.Append("IN\t").Append(e.Type).Append('\t').Append(e.Rdata);
            if (!string.IsNullOrEmpty(e.Tags)) sb.Append(" ; cf_tags=").Append(e.Tags);
            sb.Append('\n');
        }
        foreach (var (origin, text) in generates)
            sb.Append("$ORIGIN ").Append(origin).Append(".\n").Append(text).Append('\n');
        return sb.ToString();
    }

    // ---------------------------------------------------------------- lexing

    // Logical records: physical lines joined inside ( … ), comments split off, quoted strings kept whole (quotes
    // included). A line that starts with blank space has no owner name of its own.
    private static IEnumerable<Logical> Split(string text)
    {
        var cur = new Logical { Line = 1 };
        var tok = new StringBuilder();
        var raw = new StringBuilder();
        int depth = 0, line = 1;
        bool inQuote = false, inComment = false, atLineStart = true;
        var comment = new StringBuilder();

        void EndToken()
        {
            if (tok.Length > 0) { cur.Tokens.Add(tok.ToString()); tok.Clear(); }
        }

        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (c == '\r') continue;
            if (c == '\n')
            {
                line++;
                inQuote = false;   // a string can't span lines: an unterminated one ends here
                inComment = false;
                atLineStart = true;
                if (depth > 0) { EndToken(); raw.Append(' '); continue; }
                EndToken();
                cur.Comment = comment.ToString();
                cur.Raw = raw.ToString().Trim();
                yield return cur;
                cur = new Logical { Line = line };
                comment.Clear();
                raw.Clear();
                continue;
            }
            if (inComment) { comment.Append(c); continue; }
            if (atLineStart)
            {
                atLineStart = false;
                // only the first line of a record decides; a continuation line inside ( … ) is indented anyway
                if (depth == 0 && c is ' ' or '\t') cur.ImplicitOwner = true;
            }
            raw.Append(c);
            if (inQuote)
            {
                // A zone file's text has no raw control characters (they're written \DDD). One inside quotes — or a CR
                // taken in by a backslash — went into the uploaded file as is, where Cloudflare's parser may read it
                // differently from the preview (a raw CR can end a line there). Refused like control characters
                // anywhere else; a backslash never takes a line break.
                if (IsBinary(c)) throw Binary(line);
                tok.Append(c);
                if (c == '\\' && i + 1 < text.Length && text[i + 1] is not ('\n' or '\r'))
                {
                    if (IsBinary(text[i + 1])) throw Binary(line);
                    tok.Append(text[++i]);
                    raw.Append(text[i]);
                }
                else if (c == '"') inQuote = false;
                continue;
            }
            switch (c)
            {
                case '"':
                    inQuote = true;
                    tok.Append(c);
                    break;
                case ';':
                    EndToken();
                    inComment = true;
                    raw.Length--;
                    break;
                case '(':
                    EndToken();
                    depth++;
                    break;
                case ')':
                    EndToken();
                    if (depth > 0) depth--;
                    break;
                case ' ':
                case '\t':
                    EndToken();
                    break;
                case '\\':
                    tok.Append(c);
                    if (i + 1 < text.Length && text[i + 1] is not ('\n' or '\r'))
                    {
                        if (IsBinary(text[i + 1])) throw Binary(line);
                        tok.Append(text[++i]);
                        raw.Append(text[i]);
                    }
                    break;
                default:
                    if (char.IsControl(c)) throw Binary(line);
                    tok.Append(c);
                    break;
            }
        }
        EndToken();
        cur.Comment = comment.ToString();
        cur.Raw = raw.ToString().Trim();
        yield return cur;
    }

    // Tab is blank space in a zone file; any other control character means it isn't one.
    private static bool IsBinary(char c) => char.IsControl(c) && c != '\t';

    private static FormatException Binary(int line) => new($"Line {line} contains binary data: this isn't a zone file.");

    private static string Resolve(string name, string origin)
    {
        string n = name.Trim();
        if (n == "@") return origin;
        if (n.EndsWith('.')) return CloudflareBackup.NormName(n);
        return CloudflareBackup.NormName(n + "." + origin);
    }

    /// <summary>"3600", or BIND units: "1h", "30m", "1d", "1w", "1h30m".</summary>
    public static int? ParseTtl(string s)
    {
        if (s.Length is 0 or > 20) return null;
        if (int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out int plain)) return plain;
        long total = 0, num = 0;
        bool any = false;
        foreach (char c in s.ToLowerInvariant())
        {
            if (char.IsAsciiDigit(c)) { num = num * 10 + (c - '0'); any = true; if (num > int.MaxValue) return null; continue; }
            if (!any) return null;
            long mult = c switch { 's' => 1, 'm' => 60, 'h' => 3600, 'd' => 86400, 'w' => 604800, _ => 0 };
            if (mult == 0) return null;
            total += num * mult;
            num = 0;
            any = false;
            if (total > int.MaxValue) return null;
        }
        return any ? null : (int)total;
    }

    // "cf_tags=cf-proxied:true,team:web" from the comment of a record line (Cloudflare's export writes it there).
    private static string? CfTags(string comment)
    {
        int at = comment.IndexOf("cf_tags=", StringComparison.OrdinalIgnoreCase);
        if (at < 0) return null;
        string rest = comment[(at + 8)..].Trim();
        int end = rest.IndexOfAny(new[] { ' ', '\t' });
        if (end >= 0) rest = rest[..end];
        if (rest.Length is 0 or > 400) return null;
        foreach (char ch in rest)
            if (char.IsControl(ch) || ch == ';') return null;
        return rest;
    }

    /// <summary>The cf-proxied tag of a line: true / false, or null when the line doesn't say.</summary>
    public static bool? ProxiedTag(string? tags)
    {
        if (string.IsNullOrEmpty(tags)) return null;
        foreach (string t in tags.Split(','))
        {
            string tag = t.Trim();
            if (tag.Equals("cf-proxied:true", StringComparison.OrdinalIgnoreCase)) return true;
            if (tag.Equals("cf-proxied:false", StringComparison.OrdinalIgnoreCase)) return false;
        }
        return null;
    }

    private static bool IsWord(string s)
    {
        foreach (char c in s)
            if (!char.IsAsciiLetterOrDigit(c)) return false;
        return true;
    }

    private static string Clip(string s, int max)
    {
        var sb = new StringBuilder(Math.Min(s.Length, max + 1));
        foreach (char c in s)
        {
            if (sb.Length >= max) { sb.Append('…'); break; }
            sb.Append(char.IsControl(c) ? ' ' : c);
        }
        return sb.ToString();
    }
}
