using DnsClient;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

public enum MailStatus { Ok, Info, Warning, Fail }

/// <summary>One finding of the email check: the area (MX, SPF …), how good it is, one line saying what, optional
/// detail lines (records, hosts) and a one-line fix.</summary>
public sealed record MailCheckItem(string Area, MailStatus Status, string Summary, string? Detail = null, string? Fix = null);

/// <summary>How the email check asks DNS (the DNS view passes its resolvers, with automatic fallback).</summary>
public delegate Task<DnsResult> MailDnsQuery(string name, QueryType type, CancellationToken ct);

/// <summary>
/// The email-domain check: MX (each host resolved), SPF (parsed, DNS lookups counted recursively), DMARC, DKIM under
/// common selectors, MTA-STS (TXT + the HTTPS policy), TLS-RPT and the MX addresses on three DNS blocklists.
/// Every area reports ok / info / warning / fail findings with a one-line fix. Read-only: DNS queries and one HTTPS GET.
/// </summary>
public static class MailCheck
{
    public static readonly string[] Areas = { "MX", "SPF", "DMARC", "DKIM", "MTA-STS", "TLS-RPT", "DNSBL" };

    /// <summary>Selectors the big senders and hosted-mail services publish under.</summary>
    public static readonly string[] DkimSelectors =
    {
        "default", "google", "selector1", "selector2", "k1", "k2", "k3", "mail", "dkim", "dkim1", "s1", "s2", "smtp", "mx",
        "everlytickey1", "everlytickey2", "mandrill", "zoho", "zmail", "protonmail", "protonmail2", "protonmail3",
        "fm1", "fm2", "fm3", "sig1", "mailjet", "key1", "key2", "cm",
    };

    public static readonly (string Zone, string Name, string Delist)[] Blocklists =
    {
        ("zen.spamhaus.org", "Spamhaus ZEN", "https://check.spamhaus.org"),
        ("b.barracudacentral.org", "Barracuda", "https://www.barracudacentral.org/rbl/removal-request"),
        ("bl.spamcop.net", "SpamCop", "https://www.spamcop.net/bl.shtml"),
    };

    private const int MaxMxHosts = 10;
    private const int MaxBlocklistIps = 8;
    private const int MaxSpfLookups = 10;
    private const int MaxPolicyBytes = 64 * 1024;
    private static readonly TimeSpan PolicyTimeout = TimeSpan.FromSeconds(8);

    /// <summary>Test hook (the harness): serves the MTA-STS policy fetch. Internal on purpose.</summary>
    internal static Func<Uri, CancellationToken, Task<(int status, string? contentType, string body)>>? FetchHook { get; set; }

    /// <summary>
    /// Runs every check for <paramref name="domain"/> (ASCII). MX goes first (a domain that doesn't exist ends the check
    /// there; the blocklist and MTA-STS checks need its hosts); the rest run at once. <paramref name="onArea"/> gets each
    /// area's findings as soon as they are in, with the area's index in <see cref="Areas"/>.
    /// </summary>
    public static async Task RunAsync(string domain, MailDnsQuery query, Action<int, IReadOnlyList<MailCheckItem>> onArea, CancellationToken ct)
    {
        var mx = await Guard("MX", () => CheckMxAsync(domain, query, ct), ct).ConfigureAwait(false);
        onArea(0, Safe(mx.Items));
        if (mx.Stop) return;

        async Task Area(int index, Func<Task<List<MailCheckItem>>> run)
        {
            var items = await Guard(Areas[index], async () => new MxResult(await run().ConfigureAwait(false)), ct).ConfigureAwait(false);
            onArea(index, Safe(items.Items));
        }
        await Task.WhenAll(
            Area(1, () => CheckSpfAsync(domain, query, ct)),
            Area(2, () => CheckDmarcAsync(domain, query, ct)),
            Area(3, () => CheckDkimAsync(domain, query, ct)),
            Area(4, () => CheckMtaStsAsync(domain, mx.Hosts, query, ct)),
            Area(5, () => CheckTlsRptAsync(domain, query, ct)),
            Area(6, () => CheckBlocklistsAsync(mx.IPv4, query, ct))).ConfigureAwait(false);
    }

    // Findings quote the domain's own records and policy file (a hostile domain writes those): control / bidi characters
    // are replaced and every field is capped before anything is shown or copied — a 60,000-character "mode:" line froze
    // the results list.
    private static List<MailCheckItem> Safe(List<MailCheckItem> items)
        => items.ConvertAll(i => i with
        {
            Summary = RemoteText.Clean(i.Summary, 400),
            Detail = i.Detail is null ? null : RemoteText.Clean(i.Detail, 2000, keepNewlines: true),
            Fix = i.Fix is null ? null : RemoteText.Clean(i.Fix, 700),   // fixes quote the domain (up to 253 characters) twice
        });

    private sealed record MxHost(int Pref, string Host, List<string> V4, List<string> V6, bool Alias, bool IpLiteral, string? Error);

    private sealed record MxResult(List<MailCheckItem> Items, bool Stop = false)
    {
        public List<string> Hosts { get; init; } = new();
        public List<string> IPv4 { get; init; } = new();
    }

    // a check that throws (a bug, an unexpected answer) becomes one finding instead of ending the whole run
    private static async Task<MxResult> Guard(string area, Func<Task<MxResult>> run, CancellationToken ct)
    {
        try { return await run().ConfigureAwait(false); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            return new MxResult(new List<MailCheckItem> { new(area, MailStatus.Warning, "Couldn't check: " + OneLine(ex.Message)) });
        }
    }

    private static MailCheckItem LookupFailed(string area, string name, DnsResult r)
        => new(area, MailStatus.Warning, $"Couldn't look up {name}: {r.StatusText}",
               Fix: "Try again, or put another resolver first in the list.");

    private static async Task<(List<string> texts, DnsResult r)> TxtAsync(string name, MailDnsQuery query, CancellationToken ct)
    {
        var r = await query(name, QueryType.TXT, ct).ConfigureAwait(false);
        var list = r.Ok ? r.OfType("TXT").Select(a => a.Joined).ToList() : new List<string>();
        return (list, r);
    }

    // a TXT lookup "failed" only when no response came / the server errored; NXDOMAIN and "no records" are answers
    private static bool Failed(DnsResult r) => !r.Answered || r.Rcode is not (0 or 3);

    // ================================================================ MX

    private static async Task<MxResult> CheckMxAsync(string domain, MailDnsQuery query, CancellationToken ct)
    {
        const string A = "MX";
        var r = await query(domain, QueryType.MX, ct).ConfigureAwait(false);
        if (!r.Answered)
            return new MxResult(new() { new(A, MailStatus.Fail, "Couldn't look up the MX records: " + r.StatusText,
                Fix: "Check the connection, or put another resolver first in the list.") }, Stop: true);
        if (r.IsNxDomain)
            return new MxResult(new() { new(A, MailStatus.Fail, $"{domain} doesn't exist (NXDOMAIN)", Fix: "Check the spelling of the domain.") }, Stop: true);
        if (r.Rcode != 0)
            return new MxResult(new() { new(A, MailStatus.Fail, "The MX lookup failed: " + r.RcodeText,
                Fix: "The domain's name servers are failing — SERVFAIL often means broken DNSSEC.") });

        var mxs = new List<(int pref, string host)>();
        foreach (var a in r.OfType("MX"))
        {
            string[] parts = a.Value.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length == 2 && int.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out int pref))
                mxs.Add((pref, parts[1]));
        }

        var items = new List<MailCheckItem>();
        if (mxs.Count == 0)
        {
            var addr = await query(domain, QueryType.A, ct).ConfigureAwait(false);
            if (addr.OfType("A").Any())
                items.Add(new(A, MailStatus.Warning, "No MX record — senders fall back to the domain's own address (A record)",
                    Fix: "Add MX records naming the servers that receive your mail (or a null MX \"0 .\" if it receives none)."));
            else
                items.Add(new(A, MailStatus.Fail, "No MX record — the domain can't receive mail",
                    Fix: "Add MX records for your mail servers, or publish a null MX (\"0 .\") if it never receives mail."));
            return new MxResult(items);
        }
        if (mxs.Count == 1 && mxs[0].host is "." or "")
        {
            items.Add(new(A, MailStatus.Info, "Null MX — the domain says it accepts no mail (RFC 7505)"));
            return new MxResult(items);
        }

        mxs = mxs.OrderBy(m => m.pref).ThenBy(m => m.host, StringComparer.OrdinalIgnoreCase).ToList();
        var shown = mxs.Take(MaxMxHosts).ToList();
        var resolved = await Task.WhenAll(shown.Select(async m =>
        {
            string host = m.host.TrimEnd('.');
            if (IPAddress.TryParse(host, out _)) return new MxHost(m.pref, host, new(), new(), false, true, null);
            var a4 = query(host, QueryType.A, ct);
            var a6 = query(host, QueryType.AAAA, ct);
            var r4 = await a4.ConfigureAwait(false);
            var r6 = await a6.ConfigureAwait(false);
            var v4 = r4.OfType("A").Select(x => x.Value).Take(8).ToList();
            var v6 = r6.OfType("AAAA").Select(x => x.Value).Take(8).ToList();
            bool alias = r4.OfType("CNAME").Any() || r6.OfType("CNAME").Any();
            string? err = v4.Count + v6.Count == 0 && Failed(r4) && Failed(r6) ? r4.StatusText : null;
            return new MxHost(m.pref, host, v4, v6, alias, false, err);
        })).ConfigureAwait(false);

        var detail = new StringBuilder();
        var hosts = new List<string>();
        var ipv4 = new List<string>();
        int bad = 0;
        foreach (var x in resolved)
        {
            if (!x.IpLiteral) hosts.Add(x.Host);
            foreach (string ip in x.V4) if (!ipv4.Contains(ip)) ipv4.Add(ip);
            int n = x.V4.Count + x.V6.Count;
            string addrs = n == 0 ? "(no address)" : string.Join(", ", x.V4.Concat(x.V6).Take(4)) + (n > 4 ? " …" : "");
            if (detail.Length > 0) detail.Append('\n');
            detail.Append(CultureInfo.InvariantCulture, $"{x.Pref,3}  {x.Host}  →  {addrs}");

            if (x.IpLiteral)
            {
                bad++;
                items.Add(new(A, MailStatus.Fail, $"MX {x.Host} is an IP address, not a host name",
                    Fix: "An MX must name a host: point it at a name that has an A record."));
            }
            else if (x.Error != null)
            {
                items.Add(new(A, MailStatus.Warning, $"Couldn't resolve MX host {x.Host}: {x.Error}"));
            }
            else if (n == 0)
            {
                bad++;
                items.Add(new(A, MailStatus.Fail, $"MX host {x.Host} doesn't resolve to an address",
                    Fix: $"Add an A / AAAA record for {x.Host}, or remove that MX."));
            }
            else if (x.Alias)
            {
                items.Add(new(A, MailStatus.Warning, $"MX host {x.Host} is an alias (CNAME)",
                    Fix: "Point the MX straight at the canonical host name (RFC 2181 §10.3)."));
            }
        }
        if (mxs.Count > shown.Count) detail.Append(CultureInfo.InvariantCulture, $"\n… {mxs.Count - shown.Count} more not checked");
        string head = mxs.Count == 1 ? "1 mail server" : $"{mxs.Count} mail servers";
        items.Insert(0, new(A, items.Count == 0 ? MailStatus.Ok : MailStatus.Info,
            bad == 0 ? head + (resolved.All(x => x.Error == null) ? ", all resolve" : "") : $"{head}, {bad} broken",
            detail.ToString()));
        return new MxResult(items) { Hosts = hosts, IPv4 = ipv4 };
    }

    // ================================================================ SPF

    private sealed class SpfCount
    {
        public int Lookups;
        public int Fetches;
        public bool Capped;
        public readonly HashSet<string> Visited = new(StringComparer.OrdinalIgnoreCase);
        public readonly List<MailCheckItem> Problems = new();
        // a record with dozens of broken includes would otherwise list every one
        public void Problem(MailCheckItem item) { if (Problems.Count < 6) Problems.Add(item); }
    }

    private static async Task<List<MailCheckItem>> CheckSpfAsync(string domain, MailDnsQuery query, CancellationToken ct)
    {
        const string A = "SPF";
        var (texts, r) = await TxtAsync(domain, query, ct).ConfigureAwait(false);
        if (Failed(r)) return new() { LookupFailed(A, "the TXT records", r) };
        var spf = texts.Where(SpfRecord.IsSpf).ToList();
        if (spf.Count == 0)
            return new() { new(A, MailStatus.Fail, "No SPF record — anyone can send mail as this domain",
                Fix: $"Add a TXT record at {domain}: \"v=spf1 mx -all\" (plus include: for each service that sends your mail).") };

        var items = new List<MailCheckItem>();
        if (spf.Count > 1)
            items.Add(new(A, MailStatus.Fail, $"{spf.Count} SPF records — receivers treat that as an error (permerror)",
                string.Join("\n", spf.Select(s => Clip(s, 300))), "Merge them into one TXT record."));

        var count = new SpfCount();
        count.Visited.Add(domain);
        var rec = SpfRecord.Parse(spf[0]);
        await CountAsync(rec, domain, 0, count, query, ct).ConfigureAwait(false);
        items.AddRange(Assess(rec, count, domain));

        string allText = rec.All is { } all ? all.Qualifier switch { '-' => "-all (fail)", '~' => "~all (softfail)", '?' => "?all (neutral)", _ => "+all (pass)" }
                       : rec.Redirect != null ? "redirect=" + rec.Redirect : "no all";
        string lookups = count.Capped ? $"over {count.Lookups} DNS lookups (counting stopped)" : $"{count.Lookups} of {MaxSpfLookups} DNS lookups";
        items.Insert(0, new(A, items.Count == 0 ? MailStatus.Ok : MailStatus.Info,
            $"{allText} · {lookups}", Clip(spf[0], 600)));
        return items;
    }

    /// <summary>The findings for a parsed record + its counted lookups (shared with the harness checks).</summary>
    internal static List<MailCheckItem> Assess(SpfRecord rec, SpfCountResult count, string domain)
        => Assess(rec, new SpfCount { Lookups = count.Lookups, Capped = count.Capped }, domain, count.Problems);

    private static List<MailCheckItem> Assess(SpfRecord rec, SpfCount count, string domain, IEnumerable<MailCheckItem>? extra = null)
    {
        const string A = "SPF";
        var items = new List<MailCheckItem>();
        foreach (string e in rec.Errors.Take(4))
            items.Add(new(A, MailStatus.Fail, "Invalid: " + e + " (permerror)", Fix: "Fix or remove that term — one bad term voids the whole record."));
        if (rec.All is { } all)
        {
            if (all.Qualifier == '+')
                items.Add(new(A, MailStatus.Fail, "+all lets any server on the internet send as " + domain,
                    Fix: "End the record with -all (or ~all while testing)."));
            else if (all.Qualifier == '?')
                items.Add(new(A, MailStatus.Warning, "?all (neutral) gives no protection against spoofing",
                    Fix: "Use ~all or, better, -all."));
        }
        else if (rec.Redirect == null)
            items.Add(new(A, MailStatus.Warning, "No all at the end — servers not listed get a neutral result",
                Fix: "End the record with ~all or -all."));
        if (rec.Terms.Any(t => t.Name == "ptr" && !t.IsModifier))
            items.Add(new(A, MailStatus.Warning, "Uses ptr, which is slow and deprecated (RFC 7208 §5.5)",
                Fix: "Replace ptr with ip4: / ip6: ranges or an a: mechanism."));
        if (count.Lookups > MaxSpfLookups)
            items.Add(new(A, MailStatus.Fail, $"{(count.Capped ? "Over " : "")}{count.Lookups} DNS lookups — over the limit of {MaxSpfLookups} (permerror)",
                Fix: "Remove includes you don't use, or replace some with their ip4: / ip6: ranges."));
        else if (count.Lookups >= MaxSpfLookups - 1)
            items.Add(new(A, MailStatus.Warning, $"{count.Lookups} DNS lookups — close to the limit of {MaxSpfLookups}",
                Fix: "One more include will break SPF; flatten something before adding a service."));
        items.AddRange(count.Problems);
        if (extra != null) items.AddRange(extra);
        return items;
    }

    /// <summary>The recursive count, as a plain result (the harness checks it on canned records).</summary>
    internal sealed record SpfCountResult(int Lookups, bool Capped, List<MailCheckItem> Problems);

    internal static async Task<SpfCountResult> CountLookupsAsync(string domain, string record, MailDnsQuery query, CancellationToken ct)
    {
        var c = new SpfCount();
        c.Visited.Add(domain);
        await CountAsync(SpfRecord.Parse(record), domain, 0, c, query, ct).ConfigureAwait(false);
        return new SpfCountResult(c.Lookups, c.Capped, c.Problems);
    }

    // RFC 7208 §4.6.4: include, a, mx, ptr, exists and redirect each cost one lookup, counted through every included
    // record. Capped: depth 10, 30 records fetched, 40 lookups — far past the limit anyway, and a loop ends there.
    private static async Task CountAsync(SpfRecord rec, string domain, int depth, SpfCount c, MailDnsQuery query, CancellationToken ct)
    {
        const string A = "SPF";
        foreach (var t in rec.Terms)
        {
            if (c.Lookups > 40 || c.Fetches > 30) { c.Capped = true; return; }
            string? target = null;
            if (!t.IsModifier)
            {
                switch (t.Name)
                {
                    case "include": c.Lookups++; target = t.Value; break;
                    case "a": case "mx": case "ptr": case "exists": c.Lookups++; break;
                }
            }
            else if (t.Name == "redirect" && rec.All == null) { c.Lookups++; target = t.Value; }
            if (target == null) continue;
            if (SpfRecord.HasMacro(target)) continue;   // depends on the message (%{i} …): can't be followed here
            if (depth >= 10) { c.Capped = true; return; }
            if (!c.Visited.Add(target.TrimEnd('.')))
            {
                c.Problem(new(A, MailStatus.Fail, $"{t.Name} {Clip(target, 80)} is included twice or loops back",
                    Fix: "Remove the repeated include."));
                continue;
            }
            c.Fetches++;
            var (texts, r) = await TxtAsync(target, query, ct).ConfigureAwait(false);
            if (Failed(r))
            {
                c.Problem(new(A, MailStatus.Warning, $"Couldn't fetch {t.Name}:{Clip(target, 80)} ({r.StatusText}) — its lookups aren't counted"));
                continue;
            }
            var sub = texts.Where(SpfRecord.IsSpf).ToList();
            if (sub.Count != 1)
            {
                c.Problem(new(A, MailStatus.Fail,
                    sub.Count == 0 ? $"{t.Name}:{Clip(target, 80)} has no SPF record (permerror)" : $"{t.Name}:{Clip(target, 80)} has {sub.Count} SPF records (permerror)",
                    Fix: $"Fix the {t.Name} — check the service's documented SPF include."));
                continue;
            }
            await CountAsync(SpfRecord.Parse(sub[0]), target, depth + 1, c, query, ct).ConfigureAwait(false);
        }
    }

    // ================================================================ DMARC

    private static async Task<List<MailCheckItem>> CheckDmarcAsync(string domain, MailDnsQuery query, CancellationToken ct)
    {
        const string A = "DMARC";
        var (texts, r) = await TxtAsync("_dmarc." + domain, query, ct).ConfigureAwait(false);
        if (Failed(r)) return new() { LookupFailed(A, "_dmarc." + domain, r) };
        var recs = texts.Where(DmarcRecord.IsDmarc).ToList();
        string? inheritedFrom = null;

        // none of its own: a subdomain falls under its organizational domain's record (approximated by the last two labels)
        if (recs.Count == 0)
        {
            string[] labels = domain.Split('.');
            if (labels.Length > 2)
            {
                string org = string.Join('.', labels[^2..]);
                var (orgTexts, orgR) = await TxtAsync("_dmarc." + org, query, ct).ConfigureAwait(false);
                var orgRecs = orgTexts.Where(DmarcRecord.IsDmarc).ToList();
                if (!Failed(orgR) && orgRecs.Count == 1) { recs = orgRecs; inheritedFrom = org; }
            }
        }
        if (recs.Count == 0)
            return new() { new(A, MailStatus.Fail, "No DMARC record — receivers get no policy for mail that fails SPF / DKIM",
                Fix: $"Add a TXT record at _dmarc.{domain}: \"v=DMARC1; p=none; rua=mailto:dmarc@{domain}\", then tighten p= once reports look clean.") };
        if (recs.Count > 1)
            return new() { new(A, MailStatus.Fail, $"{recs.Count} DMARC records — receivers ignore all of them",
                string.Join("\n", recs.Select(x => Clip(x, 300))), "Keep exactly one TXT record at _dmarc." + domain + ".") };

        var d = DmarcRecord.Parse(recs[0]);
        var items = new List<MailCheckItem>();
        string? effective = inheritedFrom != null ? d.SubdomainPolicy ?? d.Policy : d.Policy;
        if (!d.VersionFirst)
            items.Add(new(A, MailStatus.Fail, "v=DMARC1 must be the first tag", Fix: "Start the record with v=DMARC1;"));
        if (d.Policy == null)
            items.Add(new(A, MailStatus.Fail, "No valid p= policy — the record is ignored",
                Fix: "Add p=none, p=quarantine or p=reject."));
        else if (effective == "none")
            items.Add(new(A, MailStatus.Warning, "p=none — monitoring only, spoofed mail is still delivered",
                Fix: "Move to p=quarantine, then p=reject, once the reports show only your own mail."));
        if (inheritedFrom == null && d.Policy is "quarantine" or "reject" && d.SubdomainPolicy == "none")
            items.Add(new(A, MailStatus.Warning, "sp=none leaves subdomains unprotected", Fix: "Remove sp= (subdomains then follow p=) or set it to quarantine / reject."));
        if (!d.PctValid)
            items.Add(new(A, MailStatus.Warning, "pct= isn't a number from 0 to 100", Fix: "Remove pct= or set it to 100."));
        else if (d.Pct < 100 && d.Policy is "quarantine" or "reject")
            items.Add(new(A, MailStatus.Warning, $"pct={d.Pct} — the policy applies to only {d.Pct}% of failing mail", Fix: "Raise pct to 100 (or remove it)."));
        if (d.Rua.Count == 0)
            items.Add(new(A, MailStatus.Warning, "No rua= — you get no aggregate reports", Fix: $"Add rua=mailto:dmarc-reports@{domain} to see who sends as you."));

        var facts = new List<string> { "p=" + (d.Policy ?? "?") };
        if (d.SubdomainPolicy != null) facts.Add("sp=" + d.SubdomainPolicy);
        if (d.Tags.ContainsKey("pct")) facts.Add("pct=" + d.Pct);
        if (d.Rua.Count > 0) facts.Add("reports to " + ReportTarget(d.Rua));
        if (d.Ruf.Count > 0) facts.Add("failure reports to " + ReportTarget(d.Ruf));
        string summary = string.Join(" · ", facts) + (inheritedFrom != null ? $" (inherited from {inheritedFrom})" : "");
        // the facts row is neutral when a finding below carries the problem (each problem is counted once)
        var status = items.Count == 0 ? MailStatus.Ok : MailStatus.Info;
        items.Insert(0, new(A, status, summary, Clip(recs[0], 600)));
        return items;
    }

    // "dmarc-reports.cloudflare.net +1": where the reports go, short (the full record is in the detail line)
    private static string ReportTarget(List<string> uris)
    {
        string first = uris[0];
        int at = first.LastIndexOf('@');
        string host = at >= 0 ? first[(at + 1)..] : first.Replace("mailto:", "", StringComparison.OrdinalIgnoreCase);
        int bang = host.IndexOf('!');   // a size limit: mailto:d@x.com!10m
        if (bang > 0) host = host[..bang];
        return Clip(host, 60) + (uris.Count > 1 ? $" +{uris.Count - 1}" : "");
    }

    // ================================================================ DKIM

    private static async Task<List<MailCheckItem>> CheckDkimAsync(string domain, MailDnsQuery query, CancellationToken ct)
    {
        const string A = "DKIM";
        using var gate = new SemaphoreSlim(8);
        var found = new List<(string selector, DkimKey key, string text)>();
        int errors = 0;
        await Task.WhenAll(DkimSelectors.Select(async sel =>
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                var (texts, r) = await TxtAsync($"{sel}._domainkey.{domain}", query, ct).ConfigureAwait(false);
                if (Failed(r)) { Interlocked.Increment(ref errors); return; }
                string? txt = texts.FirstOrDefault(DkimKey.IsDkim);
                if (txt == null) return;
                var key = DkimKey.Parse(txt);
                lock (found) found.Add((sel, key, txt));
            }
            finally { gate.Release(); }
        })).ConfigureAwait(false);

        var items = new List<MailCheckItem>();
        if (found.Count == 0)
        {
            items.Add(new(A, MailStatus.Warning, $"No key under {DkimSelectors.Length} common selectors" + (errors > 0 ? $" ({errors} lookups failed)" : ""),
                Fix: $"It may use its own selector: find s= in a sent message's DKIM-Signature header and look up <s>._domainkey.{domain}."));
            return items;
        }
        foreach (var (sel, key, txt) in found.OrderBy(f => Array.IndexOf(DkimSelectors, f.selector)))
        {
            string what = $"{sel}: {key.Describe()}" + (key.Testing ? " · testing (t=y)" : "");
            string detail = Clip(txt, 160);
            if (key.Revoked)
                items.Add(new(A, MailStatus.Info, what, detail));
            else if (key.KeyType == "rsa" && key.Bits is > 0 and < 1024)
                items.Add(new(A, MailStatus.Fail, what + " — breakable", detail, "Rotate to a 2048-bit key."));
            else if (key.KeyType == "rsa" && key.Bits is >= 1024 and < 2048)
                items.Add(new(A, MailStatus.Warning, what + " — weak", detail, "Rotate to a 2048-bit key."));
            else
                items.Add(new(A, MailStatus.Ok, what, detail));
        }
        return items;
    }

    // ================================================================ MTA-STS

    private static async Task<List<MailCheckItem>> CheckMtaStsAsync(string domain, List<string> mxHosts, MailDnsQuery query, CancellationToken ct)
    {
        const string A = "MTA-STS";
        var (texts, r) = await TxtAsync("_mta-sts." + domain, query, ct).ConfigureAwait(false);
        if (Failed(r)) return new() { LookupFailed(A, "_mta-sts." + domain, r) };
        var recs = texts.Where(t => t.TrimStart().StartsWith("v=STSv1", StringComparison.OrdinalIgnoreCase)).ToList();
        if (recs.Count == 0)
            return new() { new(A, MailStatus.Info, "Not set up (optional) — senders may deliver to you without TLS",
                Fix: $"Publish _mta-sts.{domain} TXT \"v=STSv1; id=1\" and a policy at https://mta-sts.{domain}/.well-known/mta-sts.txt.") };
        if (recs.Count > 1)
            return new() { new(A, MailStatus.Fail, $"{recs.Count} _mta-sts records — senders ignore the policy", Fix: "Keep exactly one.") };

        var items = new List<MailCheckItem>();
        var tags = TagList.Parse(recs[0]);
        if (!tags.TryGetValue("id", out string? id) || id.Length is 0 or > 32 || !id.All(char.IsAsciiLetterOrDigit))
            items.Add(new(A, MailStatus.Fail, "The TXT record has no valid id= (1–32 letters / digits)", Fix: "Add id=<something you change with each policy update>."));

        var url = new Uri($"https://mta-sts.{domain}/.well-known/mta-sts.txt");
        (int status, string? type, string body) got;
        try { got = await FetchPolicyAsync(url, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            items.Insert(0, new(A, MailStatus.Fail, "Policy file unreachable: " + Reason(ex), url.AbsoluteUri,
                $"Serve it over HTTPS with a valid certificate for mta-sts.{domain}."));
            return items;
        }
        if (got.status is >= 300 and < 400)
        {
            items.Insert(0, new(A, MailStatus.Fail, $"Policy file redirects (HTTP {got.status}) — not allowed (RFC 8461 §3.3)", url.AbsoluteUri,
                "Serve the file directly at that URL."));
            return items;
        }
        if (got.status != 200)
        {
            items.Insert(0, new(A, MailStatus.Fail, $"Policy file: HTTP {got.status}", url.AbsoluteUri, "Serve the policy at that URL with status 200."));
            return items;
        }
        if (got.type != null && !got.type.Equals("text/plain", StringComparison.OrdinalIgnoreCase))
            items.Add(new(A, MailStatus.Warning, $"The policy is served as {got.type}, not text/plain", Fix: "Serve it with Content-Type: text/plain."));

        var p = MtaStsPolicy.Parse(got.body);
        if (p.Version != "STSv1")
            items.Add(new(A, MailStatus.Fail, "The policy has no \"version: STSv1\" line", Fix: "Start the file with version: STSv1."));
        if (p.Mode is not ("enforce" or "testing" or "none"))
            items.Add(new(A, MailStatus.Fail, "The policy has no valid mode (enforce / testing / none)", Fix: "Add mode: testing, then mode: enforce."));
        else if (p.Mode == "testing")
            items.Add(new(A, MailStatus.Info, "mode: testing — TLS failures are only reported, not enforced", Fix: "Switch to mode: enforce once TLS-RPT reports are clean."));
        else if (p.Mode == "none")
            items.Add(new(A, MailStatus.Warning, "mode: none — the policy is switched off", Fix: "Set mode: testing, then mode: enforce (or remove the _mta-sts record)."));
        if (p.MaxAge < 0)
            items.Add(new(A, MailStatus.Fail, "The policy has no max_age", Fix: "Add max_age: 604800 (a week) or more."));
        else if (p.MaxAge < 86400)
            items.Add(new(A, MailStatus.Warning, $"max_age {p.MaxAge}s is short — senders re-fetch constantly", Fix: "Use at least 86400 (a day); weeks are common."));
        if (p.Mode is "enforce" or "testing")
        {
            if (p.Mx.Count == 0)
                items.Add(new(A, MailStatus.Fail, "The policy lists no mx: hosts", Fix: "Add an mx: line for each MX host (wildcards like *.example.com work)."));
            foreach (string h in mxHosts.Where(h => !p.Covers(h)).Take(4))
                items.Add(new(A, MailStatus.Fail, $"MX {h} isn't covered by the policy — mail to it would fail in enforce mode",
                    Fix: $"Add \"mx: {h}\" to the policy."));
        }

        string facts = $"mode {(p.Mode is { } m ? Clip(m, 20) : "?")} · max_age {Age(p.MaxAge)} · mx: {(p.Mx.Count == 0 ? "none" : string.Join(", ", p.Mx.Take(3).Select(x => Clip(x, 60))) + (p.Mx.Count > 3 ? " …" : ""))}";
        var status = items.Count == 0 && p.Mode == "enforce" ? MailStatus.Ok : MailStatus.Info;
        items.Insert(0, new(A, status, facts, Clip(recs[0], 200) + "\n" + url.AbsoluteUri));
        return items;
    }

    private static string Age(long s) => s < 0 ? "?" : s >= 2 * 86400 ? $"{s / 86400} days" : s >= 86400 ? "1 day" : $"{s}s";

    private static readonly Lazy<HttpClient> PolicyClient = new(() =>
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,             // RFC 8461 §3.3: a policy fetch must not follow redirects
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromSeconds(6),
            MaxResponseHeadersLength = 32,
        };
        var c = new HttpClient(handler) { Timeout = PolicyTimeout, MaxResponseContentBufferSize = MaxPolicyBytes };
        c.DefaultRequestHeaders.UserAgent.ParseAdd("Echoes");
        return c;
    });

    private static async Task<(int status, string? contentType, string body)> FetchPolicyAsync(Uri url, CancellationToken ct)
    {
        if (FetchHook is { } hook) return await hook(url, ct).ConfigureAwait(false);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(PolicyTimeout);
        var client = PolicyClient.Value;
        // the system proxy lookup runs inside SendAsync on the calling thread: start on the pool
        using var resp = await Task.Run(() => client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, deadline.Token), deadline.Token).ConfigureAwait(false);
        int status = (int)resp.StatusCode;
        string? type = resp.Content.Headers.ContentType?.MediaType;
        if (status != 200) return (status, type, "");
        await using var s = await resp.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
        using var ms = new MemoryStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = await s.ReadAsync(buf, deadline.Token).ConfigureAwait(false)) > 0)
        {
            if (ms.Length + n > MaxPolicyBytes) throw new InvalidDataException("the policy file is larger than 64 KB");
            ms.Write(buf, 0, n);
        }
        return (status, type, Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length));
    }

    private static string Reason(Exception ex)
    {
        var e = SocketErrors.Unwrap(ex);
        if (e is HttpRequestException { InnerException: { } inner }) e = SocketErrors.Unwrap(inner);
        return e switch
        {
            OperationCanceledException or TimeoutException => "timed out",
            System.Security.Authentication.AuthenticationException => "its HTTPS certificate isn't valid",
            IOException { InnerException: System.Security.Authentication.AuthenticationException } => "its HTTPS certificate isn't valid",
            SocketException { SocketErrorCode: SocketError.HostNotFound or SocketError.NoData } => "mta-sts host doesn't resolve",
            SocketException se => SocketErrors.Describe(se, SocketAction.Connect, "the policy host"),
            _ => OneLine(e.Message),
        };
    }

    // ================================================================ TLS-RPT

    private static async Task<List<MailCheckItem>> CheckTlsRptAsync(string domain, MailDnsQuery query, CancellationToken ct)
    {
        const string A = "TLS-RPT";
        var (texts, r) = await TxtAsync("_smtp._tls." + domain, query, ct).ConfigureAwait(false);
        if (Failed(r)) return new() { LookupFailed(A, "_smtp._tls." + domain, r) };
        var recs = texts.Where(t => t.TrimStart().StartsWith("v=TLSRPTv1", StringComparison.OrdinalIgnoreCase)).ToList();
        if (recs.Count == 0)
            return new() { new(A, MailStatus.Info, "Not set up (optional) — you get no reports of TLS failures delivering to you",
                Fix: $"Add a TXT record at _smtp._tls.{domain}: \"v=TLSRPTv1; rua=mailto:tls-reports@{domain}\".") };
        if (recs.Count > 1)
            return new() { new(A, MailStatus.Warning, $"{recs.Count} TLS-RPT records — senders ignore them", Fix: "Keep exactly one.") };
        var tags = TagList.Parse(recs[0]);
        if (!tags.TryGetValue("rua", out string? rua) || rua.Length == 0)
            return new() { new(A, MailStatus.Fail, "No rua= — reports have nowhere to go", Clip(recs[0], 300), $"Add rua=mailto:tls-reports@{domain}.") };
        return new() { new(A, MailStatus.Ok, "Reports go to " + Clip(rua, 120), Clip(recs[0], 300)) };
    }

    // ================================================================ blocklists

    private enum ListState { NotListed, Listed, Refused, Unknown }

    private static async Task<List<MailCheckItem>> CheckBlocklistsAsync(List<string> ipv4, MailDnsQuery query, CancellationToken ct)
    {
        const string A = "DNSBL";
        var ips = ipv4.Take(MaxBlocklistIps).ToList();
        if (ips.Count == 0)
            return new() { new(A, MailStatus.Info, "No IPv4 mail server address to check") };

        using var gate = new SemaphoreSlim(6);
        var results = new List<(string zone, string ip, ListState state, string code)>();
        await Task.WhenAll(Blocklists.SelectMany(bl => ips.Select(async ip =>
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                string name = string.Join('.', Enumerable.Reverse(ip.Split('.'))) + "." + bl.Zone;
                var r = await query(name, QueryType.A, ct).ConfigureAwait(false);
                var (state, code) = Classify(bl.Zone, r);
                lock (results) results.Add((bl.Zone, ip, state, code));
            }
            finally { gate.Release(); }
        }))).ConfigureAwait(false);

        var items = new List<MailCheckItem>();
        foreach (var bl in Blocklists)
        {
            var mine = results.Where(x => x.zone == bl.Zone).OrderBy(x => ips.IndexOf(x.ip)).ToList();
            var listed = mine.Where(x => x.state == ListState.Listed).ToList();
            int clean = mine.Count(x => x.state == ListState.NotListed);
            int refused = mine.Count(x => x.state == ListState.Refused);
            int unknown = mine.Count(x => x.state == ListState.Unknown);
            string detail = string.Join("\n", mine.Select(x => $"{x.ip}  {StateText(x.state)}{(x.code.Length > 0 ? " (" + x.code + ")" : "")}"));
            if (listed.Count > 0)
            {
                bool policyOnly = listed.All(x => x.code.StartsWith("PBL", StringComparison.Ordinal));
                items.Add(new(A, policyOnly ? MailStatus.Warning : MailStatus.Fail,
                    $"{bl.Name}: listed — {string.Join(", ", listed.Take(3).Select(x => x.ip + (x.code.Length > 0 ? " (" + x.code + ")" : "")))}",
                    detail,
                    policyOnly ? "The PBL lists end-user ranges; a server that sends mail directly should be delisted at " + bl.Delist + "."
                               : $"Find the cause (an open relay, a hacked account), then request removal at {bl.Delist}."));
            }
            else if (clean == mine.Count)
                items.Add(new(A, MailStatus.Ok, $"{bl.Name}: not listed ({Plural(clean, "address", "addresses")})", detail));
            else if (refused > 0 && clean == 0)
                items.Add(new(A, MailStatus.Info, $"{bl.Name}: unknown (query refused)", detail,
                    bl.Zone.EndsWith("spamhaus.org", StringComparison.Ordinal)
                        ? "Spamhaus refuses queries arriving through big public resolvers (1.1.1.1, 8.8.8.8 …): put system (your ISP's resolver) first and check again."
                        : "The list refused this resolver's queries: try another resolver (system) first."));
            else if (clean == 0)
                items.Add(new(A, MailStatus.Info, $"{bl.Name}: unknown (no answer)", detail, "Try again, or put another resolver first."));
            else
                items.Add(new(A, MailStatus.Info, $"{bl.Name}: not listed ({clean}), unknown ({refused + unknown})", detail));
        }
        return items;
    }

    private static (ListState state, string code) Classify(string zone, DnsResult r)
    {
        if (!r.Answered) return (ListState.Unknown, r.ShortError ?? "no answer");
        if (r.IsNxDomain) return (ListState.NotListed, "");
        if (r.Rcode == 5) return (ListState.Refused, "REFUSED");
        if (r.Rcode != 0) return (ListState.Unknown, r.Rcode == 2 ? "SERVFAIL" : "RCODE " + r.Rcode);
        var a = r.OfType("A").Select(x => x.Value).FirstOrDefault();
        if (a == null) return (ListState.NotListed, "");
        // Spamhaus's error answers (not listings): 127.255.255.252 = DQS key typo, .254 = query via a public / open
        // resolver, .255 = excessive queries
        if (a.StartsWith("127.255.255.", StringComparison.Ordinal))
            return (ListState.Refused, a switch { "127.255.255.254" => "public resolver", "127.255.255.255" => "rate limited", _ => "refused " + a });
        if (!a.StartsWith("127.", StringComparison.Ordinal)) return (ListState.Unknown, "unexpected answer " + a);
        if (zone == "zen.spamhaus.org")
        {
            string code = a switch
            {
                "127.0.0.2" => "SBL",
                "127.0.0.3" => "SBL CSS",
                "127.0.0.9" => "SBL DROP",
                "127.0.0.4" or "127.0.0.5" or "127.0.0.6" or "127.0.0.7" => "XBL exploits",
                "127.0.0.10" or "127.0.0.11" => "PBL end-user range",
                _ => a,
            };
            return (ListState.Listed, code);
        }
        return (ListState.Listed, a);
    }

    private static string StateText(ListState s) => s switch
    {
        ListState.NotListed => "not listed",
        ListState.Listed => "LISTED",
        ListState.Refused => "unknown (query refused)",
        _ => "unknown",
    };

    // ================================================================ report

    public static string StatusWord(MailStatus s) => s switch
    {
        MailStatus.Ok => "OK",
        MailStatus.Info => "INFO",
        MailStatus.Warning => "WARN",
        _ => "FAIL",
    };

    /// <summary>The whole check as text (Copy report).</summary>
    public static string Report(string domain, string via, IEnumerable<MailCheckItem> items)
    {
        var list = items.ToList();
        var sb = new StringBuilder();
        sb.AppendLine($"Email check: {domain} — {DateTime.Now.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)}" + (via.Length > 0 ? $", via {via}" : ""));
        sb.AppendLine(Counts(list));
        foreach (var it in list)
        {
            sb.AppendLine();
            sb.AppendLine($"[{StatusWord(it.Status)}] {it.Area,-8} {it.Summary}");
            if (!string.IsNullOrEmpty(it.Detail))
                foreach (string line in it.Detail.Split('\n')) sb.AppendLine("                " + line);
            if (!string.IsNullOrEmpty(it.Fix)) sb.AppendLine("       Fix:     " + it.Fix);
        }
        return sb.ToString();
    }

    public static string Counts(IReadOnlyCollection<MailCheckItem> items)
    {
        int ok = items.Count(i => i.Status == MailStatus.Ok), warn = items.Count(i => i.Status == MailStatus.Warning),
            fail = items.Count(i => i.Status == MailStatus.Fail), info = items.Count(i => i.Status == MailStatus.Info);
        var parts = new List<string> { $"{ok} ok" };
        if (warn > 0) parts.Add(Plural(warn, "warning", "warnings"));
        if (fail > 0) parts.Add(Plural(fail, "problem", "problems"));
        if (info > 0) parts.Add($"{info} info");
        return string.Join(" · ", parts);
    }

    private static string Plural(int n, string one, string many) => n == 1 ? $"1 {one}" : $"{n} {many}";

    private static string Clip(string s, int max) => s.Length > max ? s[..max] + "…" : s;

    private static string OneLine(string m)
    {
        string s = m.ReplaceLineEndings(" ").Trim();
        return s.Length > 160 ? s[..160] + "…" : s;
    }
}
