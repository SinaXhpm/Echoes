using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Sockets;
using System.Text;

namespace Echoes.Helpers;

/// <summary>
/// Turns what the checks found into ONE sentence and one "what to do" line. The rules go from the device outwards:
/// no network, a captive portal, no internet, a name that doesn't exist, DNS tampering, SNI filtering, a blocked
/// address, a filter page, the server's own failures, certificate problems — and the outside view decides between
/// "your network" and "down for everyone".
/// </summary>
public static class DoctorVerdicts
{
    private const string UseVpn = "Use a VPN or a proxy for this site; changing DNS alone won't help.";

    public static DoctorVerdict Decide(DoctorFacts f)
    {
        var direct = DecideDirect(f);
        return f.Proxy != null && f.Via != null ? WithProxy(f, direct) : direct;
    }

    // When the name's handshake is cut by SNI filtering but a fragmented ClientHello gets through, say exactly that:
    // the user can turn on 'fragment' instead of needing a full VPN.
    private static string SniAdvice(DoctorFacts f)
        => f.Dpi is { AnyWorked: true } d
            ? $"It works when the ClientHello is {DoctorDpiResult.Name(d.Working!.Value)}: turn on 'fragment' in your client (v2rayNG / Hiddify / Xray). A VPN or proxy also works."
            : UseVpn;

    // A short clause for the sentence ("It works with a fragmented ClientHello.") when a trick got through.
    private static string FragClause(DoctorFacts f)
        => f.Dpi is { AnyWorked: true } ? " It works when the ClientHello is split (fragment)." : "";

    // UDP/443 blocked note, appended to advice where it matters (HTTP/3 and QUIC-based tools won't work).
    private static string QuicNote(DoctorFacts f)
        => f.Quic is { Ran: true, Open: false } ? " QUIC (UDP 443) is blocked here too, so HTTP/3 and Hysteria2 / TUIC won't work." : "";

    /// <summary>A request that worked: an answer, no block / captive page, no error, status below 400.</summary>
    public static bool Works(DoctorHttpResult? r)
        => r is { Answered: true, Error: null, FilterPage: null, CaptivePage: null } && r.Status < 400;

    // what went wrong with a request, as a verb phrase ("gets no answer", "gets the filter's block page")
    private static string Fails(DoctorHttpResult r)
        => r.FilterPage != null ? "gets the filter's block page"
         : r.CaptivePage != null ? "is caught by a captive portal"
         : r.ProxyLogin ? $"stops at the proxy's login ({r.Error})"
         : r.FailedHost != null ? $"redirects to {r.FailedHost}, which fails ({r.Error})"
         : r.TimedOut ? "gets no answer"
         : r.Error != null ? $"fails ({r.Error})"
         : $"answers HTTP {r.Status} {r.Reason}".TrimEnd();

    private static DoctorVerdict DecideDirect(DoctorFacts f)
    {
        var t = f.Target;
        string h = t.Host;
        string hp = t.Display(f.Port);
        var plan = f.Plan;
        var c = f.Connect;
        var o = f.Outside;
        bool outsideWorks = o?.WorksOutside == true;
        bool outsideDown = o?.DownEverywhere == true;
        bool outsideErrors = o?.ErrorsEverywhere == true;
        string outsidePlaces = o?.Ran == true ? DoctorOutside.Places(o.Nodes.Where(n => n.Good)) : "";

        // ---- this device and its network
        if (f.Local?.HasNetwork == false && f.InternetTcp != true)
            return Problem("This device isn't connected to any network.",
                           "Connect to Wi-Fi or plug in the cable, then run the diagnosis again.");
        if (f.Captive == true)
            return Problem("A captive portal is intercepting your connection: the network wants you to sign in first.",
                           "Open any website in a browser and sign in (hotel, café or office Wi-Fi), then run again.");
        if (f.InternetTcp == false && f.InternetDns == false)
            return Problem("Your connection has no internet access: nothing outside your network answers, and DNS fails.",
                           "Restart the router or modem, reconnect your VPN if you use one, or call your provider.");

        // ---- the name
        if (f.NameMissing)
            return Problem($"{h} doesn't exist: no DNS server knows the name.", "Check the spelling of the address.");

        // ---- which scheme decides: the one asked for; with both (no scheme given), HTTPS unless only HTTP connected.
        // The other one's result is a clause ("…, and plain HTTP gets the filter's block page").
        bool connected = c?.Ok == true;
        bool rawPort = plan.Raw != null;
        bool httpsMain = plan.Https != null && (plan.Both ? c?.OkOn(plan.Https) == true || c?.OkOn(plan.Http) != true : plan.HttpsPrimary);
        int? mainPort = rawPort ? plan.Raw : httpsMain ? plan.Https : plan.Http;
        bool mainConnected = c?.OkOn(mainPort) == true;
        var tls = httpsMain || rawPort ? f.Tls : null;
        var http = httpsMain ? f.Https : rawPort ? null : f.PlainHttp;
        var other = rawPort ? null : httpsMain ? f.PlainHttp : f.Https;
        string mainName = httpsMain ? "HTTPS" : "plain HTTP";
        string otherName = httpsMain ? "plain HTTP" : "HTTPS";
        bool tlsBlocked = tls?.Outcome is DoctorTlsOutcome.SniFiltered or DoctorTlsOutcome.AllCut or DoctorTlsOutcome.HandshakeCut;
        bool pathWorks = connected && (Works(http) || Works(other)
                         || (rawPort && !tlsBlocked && tls?.Outcome is not DoctorTlsOutcome.ServerRefused));
        string? filterPage = http?.FilterPage ?? other?.FilterPage;

        string OtherClause()
        {
            if (other == null) return "";
            if (other.FilterPage != null) return $", and {otherName} gets the filter's block page";
            if (Works(other))
                return !httpsMain || !other.RedirectsToHttps ? $"; {otherName} still answers" : $"; {otherName} only redirects to HTTPS";
            return "";
        }

        // ---- DNS tampered with, or the name's lookups dropped
        if (f.SysTampered || f.DnsDropped)
        {
            string forged = f.SysTampered && f.ForgedAddress is { } fa ? $" (they point to {fa}{(DoctorIp.IsKnownFilter(fa) ? ", the filter's address" : "")})" : "";
            string what = f.SysTampered
                ? $"DNS answers for {h} are tampered with on your network{forged}"
                : $"DNS lookups for {h} go unanswered on your network, while other names resolve";
            string clause = f.SysTampered ? "its DNS answers are tampered with" : "its DNS lookups go unanswered";
            // a real address to test the path with: from encrypted DNS, or (that blocked too) from check-host.net's nodes
            bool realAddress = f.Trusted.Count > 0 && f.TrustedFrom is "encrypted DNS" or "check-host.net";
            // name a resolver that actually answered from this network (1.1.1.1 / 8.8.8.8 are often the blocked ones)
            string dohHint = f.WorkingDoh.FirstOrDefault() is { } w
                ? $"{(w.Provider.Length > 0 ? w.Provider : w.Name)}, which answered here: {w.Uri}"
                : "1.1.1.1 or 8.8.8.8 over HTTPS";
            string dnsFix = f.DohAnswered
                ? $"Turn on encrypted DNS (DoH) in your browser or system — e.g. {dohHint} — or use a VPN."
                : "Encrypted DNS is blocked here too: use a VPN or a proxy, or a DNS-over-HTTPS resolver that isn't blocked.";
            if (!realAddress)
                return f.DohAnswered
                    ? Problem(what + ".", dnsFix)
                    : Problem(what + ", and encrypted DNS is blocked too, so its real address can't be checked" +
                              (outsideWorks ? $" (it works from {outsidePlaces})." : "."), "Use a VPN or a proxy for this site.");
            if (tls?.Outcome == DoctorTlsOutcome.SniFiltered)
                return Problem($"{h} is filtered on your network: {clause}, and connections that name the site are cut (SNI filtering){OtherClause()}.{FragClause(f)}", SniAdvice(f));
            if (!connected)
                return Problem($"{h} is blocked on your network: {clause}{forged}, and its real addresses don't answer from here either.", UseVpn);
            if (tlsBlocked)
                return Problem($"{h} is blocked on your network: {clause}, and TLS connections to its real address are cut{OtherClause()}.", UseVpn);
            if (filterPage != null && !Works(http))
                return Problem($"{h} is blocked on your network: {clause}, and its pages are replaced by the filter's block page.", UseVpn);
            if (pathWorks)
                return Problem(what + (f.TrustedFrom == "encrypted DNS"
                                   ? "; it works over encrypted DNS."
                                   : "; its real address works from here, but encrypted DNS is blocked too."), dnsFix);
            return Problem(what + ".", dnsFix);
        }

        // ---- no address at all
        if (f.Trusted.Count == 0)
        {
            if (f.InternetDns == false)
                return Problem("DNS doesn't work on your network: the system resolver answers nothing.",
                               "Check the DNS settings (or set 1.1.1.1 / 8.8.8.8), or restart the router.");
            return Unknown($"{h} can't be resolved: this system's resolver doesn't answer for it and encrypted DNS is unreachable.",
                           "Run again in a minute; if it persists, try a VPN.");
        }

        // ---- the connection
        if (tls?.Outcome == DoctorTlsOutcome.SniFiltered)
            return Problem($"Blocked at TLS: the connection is reset right after the ClientHello names {h} (SNI filtering){OtherClause()}.{FragClause(f)}", SniAdvice(f));

        if (!mainConnected)
        {
            var codes = c?.Attempts.Where(a => a.Port == mainPort).Select(a => a.Code).ToList() ?? new List<SocketError?>();
            bool refused = codes.Count > 0 && codes.All(x => x == SocketError.ConnectionRefused);
            string ports = mainPort?.ToString(CultureInfo.InvariantCulture) ?? string.Join(" and ", plan.All);
            if (t.IsLocal)
                return Problem(refused
                        ? $"{hp} refuses connections: the service isn't running on that port, or a firewall rejects it."
                        : $"{hp} doesn't answer on your local network: the device may be off, or the port closed.",
                    "Check that the device is on and the service runs on that port.");
            if (outsideDown)
                return Down($"{h} is down from everywhere, not just you: nothing answers on port {ports}.",
                            "Wait and try again later, or tell the site's owner.");
            if (outsideWorks)
                return Problem(refused
                        ? $"{h} works from outside ({outsidePlaces}), but connections from your network are refused: a firewall on the way rejects them."
                        : $"{h} works from outside ({outsidePlaces}), but your network can't reach its address: the IP is blocked or unroutable from here.",
                    UseVpn);
            if (refused)
                return Problem($"{h} refuses connections on port {ports}: the service isn't running, or a firewall rejects it.",
                               "Check the port number; try again later.");
            return Unknown($"{h} doesn't answer on port {ports} from here, and the outside check couldn't tell whether it's down for everyone.",
                           "Try again later, or check the site through a VPN.");
        }

        if (tls?.Outcome == DoctorTlsOutcome.AllCut)
            return outsideDown || outsideErrors
                ? Down($"{h} is broken for everyone: TLS connections to it fail everywhere.", "Wait, or tell the site's owner.")
                : Problem($"TLS connections to {h} are cut whatever the name: its address is blocked for HTTPS on your network{OtherClause()}" +
                          (outsideWorks ? $" (it works from {outsidePlaces})." : "."), UseVpn + QuicNote(f));
        if (tls?.Outcome == DoctorTlsOutcome.HandshakeCut)
            return Problem($"The secure connection to {h} is cut on your network, though simple probes get through: a filter likely recognizes it{OtherClause()}.{FragClause(f)}", SniAdvice(f));

        // ---- filter / captive pages
        if (http?.FilterPage != null)
            return Works(other)
                ? Problem($"{mainName} to {h} gets the filter's block page ({http.FilterPage}), but {otherName} works.",
                          httpsMain ? UseVpn : $"Use https://{h} — or a VPN for the http:// pages.")
                : Problem($"{h} is blocked by a filter page on your network: {http.FilterPage}.", UseVpn);
        if (http?.CaptivePage != null || other?.CaptivePage != null)
            return Problem($"A captive portal is intercepting the connection to {h}: {http?.CaptivePage ?? other!.CaptivePage}.",
                           "Sign in to the network in a browser, then run again.");

        // ---- both schemes asked for, and only HTTP's port answers
        bool httpsClosed = false;
        if (plan.Both && c != null && !c.OkOn(plan.Https) && c.OkOn(plan.Http))
        {
            var fail = c.FailureOn(plan.Https);
            httpsClosed = fail?.Code == SocketError.ConnectionRefused;
            if (!httpsClosed && Works(http))
                return Problem($"Plain HTTP to {h} answers, but HTTPS (port {plan.Https}) doesn't: {fail?.Error ?? "no answer"}.",
                               "If https:// fails only on your network, use a VPN or a proxy.");
        }

        // ---- the server's own failures
        if (tls?.Outcome == DoctorTlsOutcome.ServerRefused)
            return outsideDown || outsideErrors
                ? Down($"{h} refuses secure connections from everywhere: {Lower(tls.Error)}", "It's the site's problem; only its owner can fix it.")
                : Problem($"{h} refuses the secure connection: {Lower(tls.Error)}",
                          "Try another browser or device; if it fails everywhere, the site is misconfigured.");
        if (tls?.Outcome == DoctorTlsOutcome.NotTls && f.UsesTls == true)
            return Problem($"{hp} doesn't speak TLS: {Lower(tls.Error)}", "Use http:// instead, or check the port.");

        // the main scheme fails while the other one works: say which
        if (http != null && !Works(http) && Works(other) && http.Status is not (403 or 451))
            return Problem($"{h} works over {otherName}, but {mainName} {Fails(http)}.",
                           httpsMain ? "If HTTPS fails only on your network, use a VPN or a proxy." : $"Use https://{h}.");

        if (http != null && (!http.Answered || http.Error != null))
        {
            string what = http.TimedOut ? "never answers the request" : $"fails the request ({http.Error})";
            // a redirect's target failing is about that host, not the one typed
            string who = http.FailedHost != null ? $"{h} redirects to {http.FailedHost}, which" : $"{h} accepts the connection but";
            if (http.FailedHost != null && !http.TimedOut) what = $"fails ({http.Error})";
            if (f.Mtu?.Mtu is int mtu && mtu < DoctorMtu.Small)
                return Problem($"{who} {what}. Large packets may be getting lost: the path only carries {mtu} bytes.",
                               $"Lower the MTU of your VPN or connection to {mtu - 40} or less, then try again.");
            if (outsideDown || outsideErrors)
                return Down($"{who} {what}, from everywhere: the site itself is broken right now.", "Wait, or tell the site's owner.");
            if (outsideWorks)
                return Problem($"{who} {what} from here, while {h} works from outside: the traffic may be throttled or filtered.", UseVpn);
            return Unknown($"{who} {what}.", "Try again later, or through a VPN.");
        }

        if (http != null && http.Status >= 500)
            return outsideWorks
                ? Problem($"{h} answers your network with an error (HTTP {http.Status}), but works from outside ({outsidePlaces}).",
                          "Try later or through a VPN; the site treats your network differently.")
                : Down($"{h} answers with an error (HTTP {http.Status} {http.Reason}) — the site itself is broken right now" +
                       (o?.Ran == true ? ", from everywhere." : "."), "Wait, or tell the site's owner.");

        if (http != null && http.Status is 403 or 451 && outsideWorks)
            return Problem(http.Status == 451
                    ? $"{h} refuses your network for legal reasons (HTTP 451), but works from elsewhere: it blocks your country."
                    : $"{h} refuses visitors from your network (HTTP 403), but works from elsewhere ({outsidePlaces}): it blocks your country or network.",
                "Use a VPN or a proxy in another country.");

        // ---- the certificate
        if (tls?.Outcome == DoctorTlsOutcome.CertProblem)
        {
            string problem = tls.Problems.First(p => p.Severity == TlsSeverity.Error).Text.TrimEnd('.');
            bool untrusted = problem.StartsWith("Untrusted root", StringComparison.Ordinal);
            return Problem($"{h} answers, but its certificate has a problem: {Lower(problem)}. Browsers will refuse it.",
                           untrusted ? "If other sites show the same, something on your network or an antivirus is intercepting HTTPS; otherwise only the site's owner can fix it."
                                     : "Only the site's owner can fix it; don't bypass the warning on a site that takes passwords.");
        }

        // ---- it works
        var fine = new List<string> { "DNS", "the connection" };
        if (f.Tls?.Outcome == DoctorTlsOutcome.Ok) fine.Add("TLS");
        if (Works(f.Https)) fine.Add("HTTPS");
        if (Works(f.PlainHttp)) fine.Add("HTTP");
        string what2 = http != null || f.Tls != null
            ? string.Join(", ", fine.Take(fine.Count - 1)) + " and " + fine[^1] + (fine.Count > 2 ? " are all fine" : " are fine")
            : $"it accepts connections on port {f.Port}";
        // the other scheme, in a few words
        string note = "";
        if (other != null && !Works(other) && (other.Answered || other.Error != null))
            note = other.FilterPage != null ? $"; {otherName} gets the filter's block page, though"
                 : other.CaptivePage != null ? "" : $"; {otherName} {Fails(other)}";
        else if (Works(f.PlainHttp) && f.PlainHttp!.RedirectsToHttps && Works(f.Https))
            note = "; HTTP redirects to HTTPS";
        if (httpsClosed) note = " (it has no HTTPS: port 443 is closed)";
        string advice = "Nothing to fix on the network. If an app still fails, its own settings (proxy, cache) are the next suspect.";
        if (f.Mtu?.Mtu is int m && m < DoctorMtu.Small)
            advice = $"The path carries only {m}-byte packets (a VPN or tunnel). If pages stall while loading, lower the MTU to {m}.";
        else if (f.Ping is { Received: > 0 } p && p.Received < p.Sent)
            advice = $"Ping lost {100 * (p.Sent - p.Received) / p.Sent}% of its packets: the connection may be unstable.";
        if (f.PlainTampered)
            advice = "Your system's DNS is fine, but plain DNS to outside resolvers is tampered with on the way: keep the current DNS, or use encrypted DNS.";
        if (f.Quic is { Ran: true, Open: false })
            advice += " (QUIC / UDP 443 is blocked here, so HTTP/3 and Hysteria2 / TUIC won't work — TCP-based tools still do.)";
        if (http != null && http.Status >= 400)
            return Problem($"{h} is reachable, but answers HTTP {http.Status} {http.Reason}.".Replace("  ", " "),
                           o?.Ran == true && !outsideWorks ? "It answers the same way from outside: the page may not exist or needs a login." : "Check the address (path) of the page.");
        return new DoctorVerdict(DoctorVerdictKind.Works, $"{h} works from here: {what2}{note}.", advice);
    }

    // ------------------------------------------------------------------ the proxy, compared with the direct path

    private static DoctorVerdict WithProxy(DoctorFacts f, DoctorVerdict direct)
    {
        var via = f.Via!;
        var proxy = f.Proxy!;
        var plan = f.Plan;
        string h = f.Target.Host;
        string pd = proxy.Display;

        // the proxy itself doesn't work: that, next to whatever the direct path showed
        if (via.Failure is { } e)
        {
            (string sentence, string advice) = e.Stage switch
            {
                DoctorProxyStage.Login => (proxy.HasLogin ? $"The proxy {pd} refused the login." : $"The proxy {pd} wants a login.",
                                           proxy.HasLogin ? "Check the proxy's user name and password." : "Enter the proxy's user name and password."),
                DoctorProxyStage.Reach => (Sentence(e.Message) + ".",
                                           "Check that the proxy (or its app) is running, and its address and port."),
                DoctorProxyStage.Tls => ($"The TLS connection to the proxy {pd} fails.", "Check that it really is an HTTPS proxy; otherwise use http://."),
                _ => ($"{pd} doesn't work as a proxy: {e.Message}.", "Check the proxy type (http://, socks5://) and the port."),
            };
            return direct.Kind == DoctorVerdictKind.Works
                ? Problem($"{h} works directly, but {LowerFirst(sentence)}", advice)
                : new DoctorVerdict(direct.Kind, $"{direct.Sentence} {sentence}", $"{direct.Advice} {advice}");
        }

        bool viaWorks = via.HttpsWorks || via.HttpWorks
                        || (!plan.IsWeb && via.TunnelOk(plan.Raw) && via.Tls is null or { Outcome: DoctorTlsOutcome.Ok or DoctorTlsOutcome.CertProblem });
        if (viaWorks)
            return direct.Kind == DoctorVerdictKind.Works
                ? new DoctorVerdict(DoctorVerdictKind.Works, $"{h} works directly and through the proxy.", direct.Advice)
                : Problem($"{direct.Sentence} It works through the proxy.", "Keep using the proxy (or a VPN) for this site.");

        string why = ViaWhy(f, via);
        return direct.Kind == DoctorVerdictKind.Works
            ? Problem($"{h} works directly, but fails through the proxy: {why}.",
                      "The proxy (or the server behind it) can't reach the site: check its own connection and rules.")
            : new DoctorVerdict(direct.Kind, $"{direct.Sentence} It fails through the proxy as well ({why}).",
                                direct.Advice == UseVpn ? "This proxy doesn't get through either: try another proxy, or a VPN." : direct.Advice);
    }

    // the first thing that failed through the proxy, in a few words
    private static string ViaWhy(DoctorFacts f, DoctorViaProxy via)
    {
        var plan = f.Plan;
        if (!plan.All.Any(p => via.TunnelOk(p)))
            return via.Tunnels.Values.Select(x => x.Error?.Message).FirstOrDefault(m => m != null) ?? "no tunnel";
        if (via.Tls is { Outcome: not (DoctorTlsOutcome.Ok or DoctorTlsOutcome.CertProblem) } tls)
            return "TLS: " + (tls.Error ?? "the handshake failed");
        if (via.Https is { } https && !Works(https)) return "HTTPS " + Fails(https);
        if (via.Http is { } http && !Works(http)) return "HTTP " + Fails(http);
        return "no working answer";
    }

    private static string LowerFirst(string s) => s.Length > 1 && char.IsUpper(s[0]) && !char.IsUpper(s[1]) ? char.ToLowerInvariant(s[0]) + s[1..] : s;
    private static string Sentence(string s) => s.Length > 0 && char.IsLower(s[0]) ? char.ToUpperInvariant(s[0]) + s[1..] : s;

    private static DoctorVerdict Problem(string s, string a) => new(DoctorVerdictKind.Problem, s, a);
    private static DoctorVerdict Down(string s, string a) => new(DoctorVerdictKind.Down, s, a);
    private static DoctorVerdict Unknown(string s, string a) => new(DoctorVerdictKind.Unknown, s, a);

    private static string Lower(string? s)
    {
        if (string.IsNullOrEmpty(s)) return "no reason given.";
        s = s.Trim();
        if (!s.EndsWith('.')) s += ".";
        return s.Length > 1 && char.IsUpper(s[0]) && !char.IsUpper(s[1]) ? char.ToLowerInvariant(s[0]) + s[1..] : s;
    }

    // ------------------------------------------------------------------ the plain-text report

    public readonly record struct Line(string Title, DoctorState State, string Detail, string Time);

    /// <summary>One check and its granular sub-steps, for the copied report's full trace.</summary>
    public readonly record struct Block(Line Head, IReadOnlyList<Line> Steps);

    public static string Report(string target, DoctorVerdict? verdict, IEnumerable<Line> lines, DateTime when)
        => Report(target, verdict, lines.Select(l => new Block(l, Array.Empty<Line>())), when);

    /// <summary>The full plain-text report: the verdict, then every check with its sub-steps indented beneath it.</summary>
    public static string Report(string target, DoctorVerdict? verdict, IEnumerable<Block> blocks, DateTime when)
    {
        var sb = new StringBuilder();
        sb.Append("Echoes Doctor: ").Append(target).Append('\n');
        sb.Append(when.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)).Append("\n\n");
        if (verdict != null)
        {
            sb.Append(verdict.Title).Append(": ").Append(verdict.Sentence).Append('\n');
            sb.Append("What to do: ").Append(verdict.Advice).Append("\n\n");
        }
        static string Tag(DoctorState s) => s switch
        {
            DoctorState.Ok => "OK",
            DoctorState.Warning => "WARN",
            DoctorState.Fail => "FAIL",
            DoctorState.Skipped => "SKIP",
            DoctorState.Running => "...",
            _ => "-",
        };
        foreach (var b in blocks)
        {
            var l = b.Head;
            sb.Append(Tag(l.State).PadRight(5)).Append(l.Title.PadRight(14)).Append(l.Detail);
            if (l.Time.Length > 0) sb.Append("  (").Append(l.Time).Append(')');
            sb.Append('\n');
            foreach (var s in b.Steps)
            {
                sb.Append("       ").Append(Tag(s.State).PadRight(5)).Append(s.Title).Append(": ").Append(s.Detail);
                if (s.Time.Length > 0) sb.Append("  (").Append(s.Time).Append(')');
                sb.Append('\n');
            }
        }
        return sb.ToString().TrimEnd() + "\n";
    }
}
