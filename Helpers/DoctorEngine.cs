using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>Everything one diagnosis found — what the verdict is decided from.</summary>
public sealed class DoctorFacts
{
    public DoctorFacts(DoctorTarget target) => Target = target;

    public DoctorTarget Target { get; }
    public DoctorLocal? Local { get; set; }
    /// <summary>A probe (1.1.1.1:443, 8.8.8.8:443) connected; null = not checked.</summary>
    public bool? InternetTcp { get; set; }
    /// <summary>The system resolver answered for a well-known name.</summary>
    public bool? InternetDns { get; set; }
    public bool? Captive { get; set; }
    public string? CaptiveDetail { get; set; }

    public DoctorDnsAnswer? Sys { get; set; }
    public List<DoctorDnsAnswer> Plain { get; set; } = new();
    public List<DoctorDnsAnswer> Doh { get; set; } = new();
    public DoctorDnsMatch SysMatch { get; set; }
    public List<DoctorDnsMatch> PlainMatch { get; set; } = new();
    /// <summary>An encrypted resolver answered (the reference exists).</summary>
    public bool DohAnswered { get; set; }
    /// <summary>The encrypted resolvers that answered from this network (what to recommend).</summary>
    public List<DoctorDohEndpoint> WorkingDoh { get; set; } = new();
    /// <summary>The name exists nowhere (encrypted DNS and the system agree: no such name).</summary>
    public bool NameMissing { get; set; }
    /// <summary>The first plain resolver answered a well-known name (port 53 works; a silence for the target is about the name).</summary>
    public bool PlainControlOk { get; set; }
    /// <summary>Lookups of this name go unanswered (system and plain resolvers), while other names resolve: dropped at DNS.</summary>
    public bool DnsDropped => Sys is { Answered: false } && Plain.All(p => !p.Answered) && (PlainControlOk || InternetDns == true);
    /// <summary>The system's (differing) address doesn't serve the site, while the trusted one does: DNS points elsewhere.</summary>
    public bool SysPointsElsewhere { get; set; }
    /// <summary>The addresses the next checks use, and where they came from.</summary>
    public List<IPAddress> Trusted { get; set; } = new();
    public string TrustedFrom { get; set; } = "";

    /// <summary>Which ports the web checks use (HTTPS and HTTP together unless the input pins one).</summary>
    public DoctorPorts Plan { get; set; } = new(443, 80, null, true, true);
    public DoctorConnect? Connect { get; set; }
    /// <summary>The TLS check ran (on the HTTPS port, or a non-web port that speaks TLS).</summary>
    public bool? UsesTls { get; set; }
    public DoctorPing? Ping { get; set; }
    public DoctorTlsResult? Tls { get; set; }
    /// <summary>The request over HTTPS, and the one over plain HTTP (each null when not run).</summary>
    public DoctorHttpResult? Https { get; set; }
    public DoctorHttpResult? PlainHttp { get; set; }
    public DoctorMtuResult? Mtu { get; set; }
    public DoctorOutsideResult? Outside { get; set; }
    /// <summary>The anti-DPI retries, run only when the handshake with the name is cut but the address answers otherwise.</summary>
    public DoctorDpiResult? Dpi { get; set; }
    /// <summary>Whether UDP/443 (QUIC / HTTP-3) is open, for a web target on the default port.</summary>
    public DoctorQuicResult? Quic { get; set; }

    /// <summary>The proxy the user asked to test through (null: none), and what came out of it.</summary>
    public DoctorProxy? Proxy { get; set; }
    public DoctorViaProxy? Via { get; set; }

    public bool SysTampered => SysMatch is DoctorDnsMatch.Bogus or DoctorDnsMatch.Missing || SysPointsElsewhere;
    public bool PlainTampered => PlainMatch.Any(m => m is DoctorDnsMatch.Bogus) || Plain.Any(p => p.Injected);
    /// <summary>The first forged address seen ("10.10.34.36").</summary>
    public IPAddress? ForgedAddress =>
        (Sys?.Addresses ?? new List<IPAddress>()).Concat(Plain.SelectMany(p => p.Addresses)).FirstOrDefault(a => !DoctorIp.IsPublic(a))
        ?? (SysPointsElsewhere ? Sys?.Addresses.FirstOrDefault() : null);
    public int Port => Connect?.Ok == true ? Connect.Port : Plan.All[0];
}

/// <summary>The same checks through the proxy.</summary>
public sealed class DoctorViaProxy
{
    /// <summary>The proxy itself failed (unreachable, its TLS, not that protocol, the login): nothing else ran.</summary>
    public DoctorProxyException? Failure { get; set; }
    public double ReachMs { get; set; }
    public bool LoginUsed { get; set; }
    /// <summary>A tunnel per port: open (and how long it took), or why not.</summary>
    public Dictionary<int, (double Ms, DoctorProxyException? Error)> Tunnels { get; } = new();
    public DoctorTlsResult? Tls { get; set; }
    public DoctorHttpResult? Https { get; set; }
    public DoctorHttpResult? Http { get; set; }
    public List<DoctorDnsAnswer> Doh { get; set; } = new();

    public bool TunnelOk(int? port) => port is int p && Tunnels.TryGetValue(p, out var t) && t.Error == null;
    public bool HttpsWorks => DoctorVerdicts.Works(Https);
    public bool HttpWorks => DoctorVerdicts.Works(Http);
}

/// <summary>
/// The Doctor: runs every check (independent ones in parallel, each with its own deadline) and reports each row as it
/// goes. Order: the local network and DNS at once; then, with the address encrypted DNS gave (never the system resolver's,
/// which may be the filter's), the connection, ping and path MTU; then TLS and HTTP over the connection that worked, and
/// the outside view from check-host.net. No options: what to check follows from the target.
/// </summary>
public static class DoctorEngine
{
    public static string Title(DoctorCheck c) => c switch
    {
        DoctorCheck.Network => "Network",
        DoctorCheck.Internet => "Internet",
        DoctorCheck.DnsSystem => "DNS (system)",
        DoctorCheck.DnsPlain => "Plain DNS",
        DoctorCheck.DnsEncrypted or DoctorCheck.ProxyDns => "Encrypted DNS",
        DoctorCheck.Connect or DoctorCheck.ProxyConnect => "Connection",
        DoctorCheck.Ping => "Ping",
        DoctorCheck.Tls or DoctorCheck.ProxyTls => "TLS",
        DoctorCheck.Https or DoctorCheck.ProxyHttps => "HTTPS",
        DoctorCheck.Http or DoctorCheck.ProxyHttp => "HTTP",
        DoctorCheck.Mtu => "Path MTU",
        DoctorCheck.ProxyServer => "Proxy",
        _ => "Outside view",
    };

    /// <summary>The row's name in the copied report (the proxy's rows say so).</summary>
    public static string ReportTitle(DoctorCheck c) => IsProxy(c) && c != DoctorCheck.ProxyServer ? "Proxy " + Title(c) : Title(c);

    public static bool IsProxy(DoctorCheck c) => c >= DoctorCheck.ProxyServer;

    /// <summary>What each check looks at (shown before the first run): a few words.</summary>
    public static string About(DoctorCheck c) => c switch
    {
        DoctorCheck.Network => "Your connection, gateway, VPN, proxy",
        DoctorCheck.Internet => "Does the internet answer",
        DoctorCheck.DnsSystem => "What your resolver answers",
        DoctorCheck.DnsPlain => "What 1.1.1.1 and 8.8.8.8 answer",
        DoctorCheck.DnsEncrypted => "The trusted answer (DoH)",
        DoctorCheck.Connect => "TCP to the real address",
        DoctorCheck.Ping => "Round trips and loss",
        DoctorCheck.Tls => "Handshake, with and without the name",
        DoctorCheck.Https => "A request over HTTPS",
        DoctorCheck.Http => "A request over plain HTTP",
        DoctorCheck.Mtu => "Largest packet that passes",
        DoctorCheck.Outside => "The site from other countries",
        DoctorCheck.ProxyServer => "Reach, protocol, login",
        DoctorCheck.ProxyDns => "DoH through the proxy",
        DoctorCheck.ProxyConnect => "TCP through the proxy",
        DoctorCheck.ProxyTls => "Handshake through the proxy",
        DoctorCheck.ProxyHttps => "HTTPS through the proxy",
        _ => "HTTP through the proxy",
    };

    /// <summary>What can't be tested through a proxy (shown with the proxy's rows, and in the report).</summary>
    public const string ProxyNote = "Plain DNS, ping and path MTU can't go through a proxy: those rows show the direct path.";

    internal static async Task<DoctorFacts> RunAsync(DoctorTarget t, DoctorEnvironment env, DoctorProxy? proxy, IDoctorSink sink, CancellationToken ct)
    {
        var f = new DoctorFacts(t) { Plan = t.Plan(env.DefaultHttpsPort, env.DefaultHttpPort), Proxy = proxy };
        using var doh = DoctorDns.CreateDohClient();

        var local = Step(sink, new[] { DoctorCheck.Network, DoctorCheck.Internet }, () => LocalAsync(f, env, sink, ct));
        var proxyRows = new[] { DoctorCheck.ProxyServer, DoctorCheck.ProxyDns, DoctorCheck.ProxyConnect, DoctorCheck.ProxyTls, DoctorCheck.ProxyHttps, DoctorCheck.ProxyHttp };
        var via = proxy != null ? Step(sink, proxyRows, () => ViaProxyAsync(f, env, proxy, sink, ct)) : Task.CompletedTask;
        await Step(sink, new[] { DoctorCheck.DnsSystem, DoctorCheck.DnsPlain, DoctorCheck.DnsEncrypted },
                   () => DnsAsync(f, env, doh, sink, ct)).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();

        var pathRows = new[] { DoctorCheck.Connect, DoctorCheck.Ping, DoctorCheck.Tls, DoctorCheck.Https, DoctorCheck.Http, DoctorCheck.Mtu };
        if (f.NameMissing)
        {
            foreach (var c in pathRows) sink.Report(c, DoctorState.Skipped, $"Skipped: {t.Host} doesn't exist");
            sink.Report(DoctorCheck.Outside, DoctorState.Skipped, $"Skipped: {t.Host} doesn't exist");
        }
        else if (f.Trusted.Count == 0)
        {
            // No answer this network's DNS gives can be trusted, and encrypted DNS is out of reach: check-host.net's nodes
            // resolve the name abroad — their addresses are the second-best source for testing the path from here.
            foreach (var c in pathRows) sink.Report(c, DoctorState.Running, "Waiting for the real address from the outside view…");
            await Step(sink, new[] { DoctorCheck.Outside }, () => OutsideAsync(f, env, sink, ct)).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            var abroad = DoctorIp.Ordered((f.Outside?.Nodes ?? new List<DoctorNodeView>())
                .Select(n => IPAddress.TryParse(n.Address, out var a) ? a : null)
                .Where(a => a != null && DoctorIp.IsPublic(a)).Select(a => a!));
            if (abroad.Count > 0)
            {
                f.Trusted = abroad;
                f.TrustedFrom = "check-host.net";
                await PathAsync(f, env, doh, sink, runOutside: false, ct).ConfigureAwait(false);
            }
            else
            {
                string why = t.IsIp ? "no address" : $"no trustworthy address for {t.Host}";
                foreach (var c in pathRows) sink.Report(c, DoctorState.Skipped, $"Skipped: {why}");
            }
        }
        else await PathAsync(f, env, doh, sink, runOutside: true, ct).ConfigureAwait(false);
        await local.ConfigureAwait(false);
        await via.ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        return f;
    }

    // The path to the trusted address: connection, ping, path MTU, TLS, HTTP (and the outside view once the port is known).
    private static async Task PathAsync(DoctorFacts f, DoctorEnvironment env, HttpClient doh, IDoctorSink sink, bool runOutside, CancellationToken ct)
    {
        var target0 = f.Trusted[0];
        var ping = Step(sink, new[] { DoctorCheck.Ping }, () => PingAsync(f, target0, sink, ct));
        var mtu = Step(sink, new[] { DoctorCheck.Mtu }, () => MtuAsync(f, target0, sink, ct));
        // UDP/443 (QUIC / HTTP-3): a Version Negotiation back means it's open — only when HTTPS is (one of) the scheme(s) asked for
        var quic = f.Plan.Https is int qp && (f.Plan.HttpsPrimary || f.Plan.Both)
            ? Step(sink, new[] { DoctorCheck.Connect }, () => QuicAsync(f, target0, qp, sink, ct)) : Task.CompletedTask;
        await Step(sink, new[] { DoctorCheck.Connect }, () => ConnectAsync(f, sink, ct)).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        var outside = runOutside ? Step(sink, new[] { DoctorCheck.Outside }, () => OutsideAsync(f, env, sink, ct)) : Task.CompletedTask;
        var verify = f.SysMatch == DoctorDnsMatch.Differs ? VerifySystemAsync(f, sink, ct) : Task.CompletedTask;

        if (f.Connect?.Ok == true)
        {
            // plain HTTP needs no TLS: it runs alongside the handshake; HTTPS waits for the TLS verdict
            var plain = Step(sink, new[] { DoctorCheck.Http }, () => WebAsync(f, env, doh, tls: false, sink, ct));
            await Step(sink, new[] { DoctorCheck.Tls }, () => TlsAsync(f, env, sink, ct)).ConfigureAwait(false);
            await Step(sink, new[] { DoctorCheck.Https }, () => WebAsync(f, env, doh, tls: true, sink, ct)).ConfigureAwait(false);
            await plain.ConfigureAwait(false);
        }
        else
        {
            sink.Report(DoctorCheck.Tls, DoctorState.Skipped, "Skipped: no connection");
            sink.Report(DoctorCheck.Https, DoctorState.Skipped, "Skipped: no connection");
            sink.Report(DoctorCheck.Http, DoctorState.Skipped, "Skipped: no connection");
        }
        await verify.ConfigureAwait(false);
        await ping.ConfigureAwait(false);
        await mtu.ConfigureAwait(false);
        await quic.ConfigureAwait(false);
        await outside.ConfigureAwait(false);
    }

    // UDP/443: one greased QUIC Initial; a Version Negotiation back = open (HTTP-3 / Hysteria2 / TUIC can work here).
    private static async Task QuicAsync(DoctorFacts f, IPAddress addr, int port, IDoctorSink sink, CancellationToken ct)
    {
        var q = await DoctorDpi.QuicProbeAsync(addr, port, 2500, ct).ConfigureAwait(false);
        f.Quic = q;
        Tr(sink, DoctorCheck.Connect, q.Open ? DoctorState.Ok : DoctorState.Warning, $"UDP {port} (QUIC)",
           q.Open ? $"answered ({q.Note}) — HTTP/3 and QUIC VPNs can work" : $"no answer ({q.Note}) — QUIC blocked: Hysteria2 / TUIC / HTTP-3 won't work here",
           q.Ms > 0 ? q.Ms : null);
    }

    // A check that throws (a bug, an odd platform) fails its own rows instead of the whole diagnosis.
    private static async Task Step(IDoctorSink sink, DoctorCheck[] rows, Func<Task> body)
    {
        try { await body().ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (Exception e)
        {
            CrashLog.Write("Doctor." + rows[0], e);
            foreach (var r in rows) sink.Report(r, DoctorState.Fail, "This check failed: " + DoctorDns.Short(e));
        }
    }

    // ------------------------------------------------------------------ network + internet

    private static async Task LocalAsync(DoctorFacts f, DoctorEnvironment env, IDoctorSink sink, CancellationToken ct)
    {
        sink.Report(DoctorCheck.Network, DoctorState.Running, "Looking at this device's network…");
        sink.Report(DoctorCheck.Internet, DoctorState.Running, "Reaching " + string.Join(" and ", env.InternetProbes.Select(p => p.Address)) + "…");
        var sw = Stopwatch.StartNew();
        var probes = env.InternetProbes.Select(ep => DoctorNet.ConnectAsync(ep.Address, ep.Port, 3000, ct)).ToList();
        var names = env.WellKnownNames.Select(n => DoctorDns.SystemAsync(env.SystemResolve, n, 4000, ct)).ToList();
        var captive = DoctorNet.CaptiveAsync(env.CaptiveChecks, 3500, ct);
        var proxy = DoctorNet.SystemProxyAsync(1500);

        var local = await Task.Run(DoctorNet.Local, ct).ConfigureAwait(false);
        local.SystemProxy = await proxy.ConfigureAwait(false);
        f.Local = local;
        double localMs = sw.Elapsed.TotalMilliseconds;
        var parts = new List<string>();
        if (local.Interface != null) parts.Add(local.Interface);
        if (local.Gateway != null) parts.Add("gateway " + local.Gateway);
        if (local.Vpn != null) parts.Add("VPN " + local.Vpn);
        if (local.SystemProxy != null) parts.Add($"system proxy {local.SystemProxy} (these checks go direct)");
        if (local.HasNetwork == false)
            sink.Report(DoctorCheck.Network, DoctorState.Fail, "Not connected: no network interface has a gateway", localMs);
        else
            sink.Report(DoctorCheck.Network, DoctorState.Ok,
                        parts.Count > 0 ? Cap(string.Join(" · ", parts)) : "Connected (this system doesn't show the gateway)", localMs);

        var probeRes = await Task.WhenAll(probes).ConfigureAwait(false);
        var nameRes = await Task.WhenAll(names).ConfigureAwait(false);
        var (intercepted, captiveDetail) = await captive.ConfigureAwait(false);
        f.InternetTcp = probeRes.Any(p => p.Ok);
        f.InternetDns = nameRes.Any(n => n.Addresses.Count > 0);
        f.Captive = intercepted;
        f.CaptiveDetail = captiveDetail;

        var okProbes = probeRes.Where(p => p.Ok).ToList();
        double? ms = okProbes.Count > 0 ? okProbes.Min(p => p.Ms) : null;
        string tcp = okProbes.Count > 0
            ? string.Join(" · ", okProbes.Select(p => $"{p.Address} in {Ms(p.Ms)}"))
            : string.Join(", ", probeRes.Select(p => p.Address.ToString())) + " don't answer (" + (probeRes.FirstOrDefault()?.Error ?? "no reply") + ")";
        if (intercepted == true)
            sink.Report(DoctorCheck.Internet, DoctorState.Fail, Cap($"A captive portal answers instead of the internet: {captiveDetail}"), ms);
        else if (f.InternetTcp == true && f.InternetDns == true)
            sink.Report(DoctorCheck.Internet, DoctorState.Ok, $"{tcp} · DNS answers", ms);
        else if (f.InternetTcp == true)
            sink.Report(DoctorCheck.Internet, DoctorState.Warning,
                        $"{tcp}, but this system's resolver doesn't answer ({nameRes.FirstOrDefault()?.Error ?? "no address"})", ms);
        else if (f.InternetDns == true)
            sink.Report(DoctorCheck.Internet, DoctorState.Warning, $"{tcp}, but DNS works — a restricted network?", nameRes.Select(n => n.Ms).DefaultIfEmpty(0).Min());
        else
            sink.Report(DoctorCheck.Internet, DoctorState.Fail, $"No internet: {tcp}, and DNS doesn't answer", sw.Elapsed.TotalMilliseconds);
    }

    // ------------------------------------------------------------------ DNS

    private static string Ans(DoctorDnsAnswer a)
        => !a.Answered ? $"no answer ({a.Error ?? "no reply"})"
         : a.NoSuchName ? "no such name"
         : a.Rcode is not (0 or 3) ? $"error {RcodeName(a.Rcode)}"
         : a.Addresses.Count == 0 ? "no addresses"
         : DoctorIp.List(a.Addresses);

    private static string RcodeName(int rcode) => rcode switch { 2 => "SERVFAIL", 5 => "REFUSED", 1 => "FORMERR", _ => rcode.ToString(CultureInfo.InvariantCulture) };

    private static async Task DnsAsync(DoctorFacts f, DoctorEnvironment env, HttpClient doh, IDoctorSink sink, CancellationToken ct)
    {
        var t = f.Target;
        if (t.Ip != null)
        {
            foreach (var c in new[] { DoctorCheck.DnsSystem, DoctorCheck.DnsPlain, DoctorCheck.DnsEncrypted })
                sink.Report(c, DoctorState.Skipped, "An IP address: nothing to look up");
            f.Trusted = new List<IPAddress> { t.Ip };
            f.TrustedFrom = "the address you gave";
            return;
        }

        sink.Report(DoctorCheck.DnsSystem, DoctorState.Running, "Asking this system's resolver…");
        if (t.IsLocal)
        {
            sink.Report(DoctorCheck.DnsPlain, DoctorState.Skipped, "A local name: public resolvers don't know it");
            sink.Report(DoctorCheck.DnsEncrypted, DoctorState.Skipped, "A local name: public resolvers don't know it");
            var local = await DoctorDns.SystemAsync(env.SystemResolve, t.AsciiHost, 5000, ct).ConfigureAwait(false);
            f.Sys = local;
            f.SysMatch = DoctorDnsMatch.Unknown;
            f.Trusted = DoctorIp.Ordered(local.Addresses);
            f.TrustedFrom = "this system's resolver";
            sink.Report(DoctorCheck.DnsSystem, local.Addresses.Count > 0 ? DoctorState.Ok : DoctorState.Fail,
                        local.Addresses.Count > 0 ? Ans(local) : $"{t.Host}: {Ans(local)}", local.Ms);
            if (local.NoSuchName) f.NameMissing = true;
            return;
        }

        sink.Report(DoctorCheck.DnsPlain, DoctorState.Running, "Asking " + string.Join(" and ", env.PlainDns.Select(s => s.Address)) + " over UDP…");
        sink.Report(DoctorCheck.DnsEncrypted, DoctorState.Running, "Asking " + string.Join(", ", env.Doh.Take(3).Select(d => d.Name)) + " over HTTPS…");

        async Task<DoctorDnsAnswer> SystemTask()
        {
            var a = await DoctorDns.SystemAsync(env.SystemResolve, t.AsciiHost, 5000, ct).ConfigureAwait(false);
            sink.Report(DoctorCheck.DnsSystem, DoctorState.Running, Ans(a) + " — comparing with encrypted DNS…", a.Ms);
            return a;
        }
        async Task<List<DoctorDnsAnswer>> PlainTask()
        {
            var list = (await Task.WhenAll(env.PlainDns.Select(s => DoctorDns.UdpAsync(s, t.AsciiHost, 3000, ct))).ConfigureAwait(false)).ToList();
            sink.Report(DoctorCheck.DnsPlain, DoctorState.Running, "Comparing with encrypted DNS…", list.Where(a => a.Answered).Select(a => a.Ms).DefaultIfEmpty(0).Min());
            return list;
        }
        var sysT = SystemTask();
        var plainT = PlainTask();
        // a control: does the same plain resolver answer a name nobody blocks? (tells "this name is dropped" from "port 53 is")
        var controlT = env.PlainDns.Count > 0 && env.WellKnownNames.Count > 0
            ? DoctorDns.UdpAsync(env.PlainDns[0], env.WellKnownNames[0], 3000, ct) : Task.FromResult(new DoctorDnsAnswer());
        var dohList = await DoctorDns.DohAllAsync(doh, env.Doh, t.AsciiHost, 4500, ct).ConfigureAwait(false);
        var sys = await sysT.ConfigureAwait(false);
        var plain = await plainT.ConfigureAwait(false);
        f.PlainControlOk = (await controlT.ConfigureAwait(false)).Addresses.Count > 0;
        f.Sys = sys;
        f.Plain = plain;
        f.Doh = dohList;

        // ---- the reference: what encrypted DNS says
        var dohGood = dohList.Where(a => a.Good).ToList();
        bool known = dohGood.Count > 0;
        var trustedSet = DoctorIp.Ordered(dohGood.SelectMany(a => a.Addresses));
        bool nx = known && dohGood.Any(a => a.NoSuchName) && dohGood.All(a => a.NoSuchName || a.Addresses.Count == 0);
        f.DohAnswered = known;
        f.WorkingDoh = env.Doh.Where(d => dohGood.Any(a => a.Source == d.Name)).ToList();
        f.SysMatch = DoctorDns.Compare(sys, trustedSet, known, nx);
        f.PlainMatch = plain.Select(p => DoctorDns.Compare(p, trustedSet, known, nx)).ToList();
        f.NameMissing = nx ? (sys.NoSuchName || sys.Addresses.Count == 0 || !sys.Answered)
                           : !known && sys.NoSuchName && plain.Any(p => p.NoSuchName) && plain.All(p => p.NoSuchName || !p.Answered);
        TraceDns(sink, f);

        // ---- the addresses the next checks use
        var publicTrusted = trustedSet.Where(DoctorIp.IsPublic).ToList();
        if (publicTrusted.Count > 0)
        {
            f.Trusted = publicTrusted;
            f.TrustedFrom = "encrypted DNS";
        }
        else if (!nx)
        {
            int i = -1;
            for (int k = 0; k < plain.Count && i < 0; k++)
                if (plain[k].Addresses.Any(DoctorIp.IsPublic) && !plain[k].Injected
                    && f.PlainMatch[k] is not (DoctorDnsMatch.Bogus or DoctorDnsMatch.Missing)) i = k;
            if (i >= 0)
            {
                f.Trusted = DoctorIp.Ordered(plain[i].Addresses.Where(DoctorIp.IsPublic));
                f.TrustedFrom = plain[i].Source;
            }
            else if (sys.Addresses.Any(DoctorIp.IsPublic) && f.SysMatch != DoctorDnsMatch.Bogus)
            {
                f.Trusted = DoctorIp.Ordered(sys.Addresses.Where(DoctorIp.IsPublic));
                f.TrustedFrom = "this system's resolver";
            }
            else if (sys.Addresses.Count > 0 && f.SysMatch == DoctorDnsMatch.Unknown && sys.Addresses.All(a => !DoctorIp.IsKnownFilter(a)))
            {
                // a private answer nobody could cross-check: a company's own name, most likely — use it
                f.Trusted = DoctorIp.Ordered(sys.Addresses);
                f.TrustedFrom = "this system's resolver";
            }
        }
        string trustedText = DoctorIp.List(trustedSet);

        // ---- encrypted DNS row
        if (!known)
        {
            var errs = dohList.Where(a => a.Error != null).Take(2).Select(a => $"{a.Source}: {a.Error}");
            sink.Report(DoctorCheck.DnsEncrypted, DoctorState.Warning,
                        Cap("No encrypted resolver answered (" + string.Join(", ", errs) + ") — DoH may be blocked here"),
                        dohList.Select(a => a.Ms).DefaultIfEmpty(0).Max());
        }
        else if (nx)
            sink.Report(DoctorCheck.DnsEncrypted, DoctorState.Warning, $"{t.Host} doesn't exist (no such name)", dohGood.Min(a => a.Ms));
        else
            sink.Report(DoctorCheck.DnsEncrypted, DoctorState.Ok,
                        Cap(string.Join(", ", dohGood.Take(3).Select(a => a.Source)) + ": " + trustedText), dohGood.Min(a => a.Ms));

        // ---- system row
        ReportSystem(f, sink, sys, trustedText, known);

        // ---- plain row
        var states = new List<(DoctorState State, string Text)>();
        for (int i = 0; i < plain.Count; i++)
        {
            var p = plain[i];
            var m = f.PlainMatch[i];
            if (p.Injected)
                states.Add((DoctorState.Fail, $"{p.Source} gave two answers ({DoctorIp.List(p.Addresses)} first, then {DoctorIp.List(p.Later)}): the first was forged on the way"));
            else if (m == DoctorDnsMatch.Bogus)
                states.Add((DoctorState.Fail, $"{p.Source} → {Ans(p)}: {Why(p.Addresses)} — forged on the way"));
            else if (m == DoctorDnsMatch.Missing)
                states.Add((DoctorState.Fail, $"{p.Source} → {Ans(p)}, though encrypted DNS knows it"));
            else if (m == DoctorDnsMatch.Differs)
                states.Add((DoctorState.Warning, $"{p.Source} → {Ans(p)}: differs from encrypted DNS (may be a CDN)"));
            else if (!p.Answered)
                states.Add((DoctorState.Warning, $"{p.Source}: {p.Error ?? "no reply"}"));
            else
                states.Add((DoctorState.Ok, $"{p.Source} → {Ans(p)}"));
        }
        double plainMs = plain.Where(p => p.Answered).Select(p => p.Ms).DefaultIfEmpty(plain.Select(p => p.Ms).DefaultIfEmpty(0).Max()).Min();
        if (states.Count == 0)
            sink.Report(DoctorCheck.DnsPlain, DoctorState.Skipped, "No plain resolvers to ask");
        else if (states.All(s => s.State == DoctorState.Ok) && plain.Select(p => Ans(p)).Distinct().Count() == 1)
            sink.Report(DoctorCheck.DnsPlain, DoctorState.Ok,
                        Cap(string.Join(" and ", plain.Select(p => p.Source)) + (plain.Count > 1 ? " agree: " : ": ") + Ans(plain[0]) +
                            (known ? "" : " (not cross-checked)")), plainMs);
        else if (plain.All(p => !p.Answered) && f.PlainControlOk)
            sink.Report(DoctorCheck.DnsPlain, DoctorState.Fail,
                        Cap($"No answer from {string.Join(" or ", plain.Select(p => p.Source))}, though they answer other names: this name is dropped"),
                        plainMs);
        else if (plain.All(p => !p.Answered))
            sink.Report(DoctorCheck.DnsPlain, DoctorState.Warning,
                        Cap("No answer over plain DNS (" + string.Join(", ", states.Select(s => s.Text)) + ") — port 53 to outside resolvers may be blocked"), plainMs);
        else
        {
            var worst = states.Max(s => s.State == DoctorState.Fail ? 2 : s.State == DoctorState.Warning ? 1 : 0);
            var state = worst == 2 ? DoctorState.Fail : worst == 1 ? DoctorState.Warning : DoctorState.Ok;
            sink.Report(DoctorCheck.DnsPlain, state, Cap(string.Join(" · ", states.OrderByDescending(s => s.State).Select(s => s.Text))), plainMs);
        }
    }

    private static void ReportSystem(DoctorFacts f, IDoctorSink sink, DoctorDnsAnswer sys, string trustedText, bool known)
    {
        string host = f.Target.Host;
        switch (f.SysMatch)
        {
            case DoctorDnsMatch.Same:
                sink.Report(DoctorCheck.DnsSystem, DoctorState.Ok, Cap($"{Ans(sys)} — matches encrypted DNS"), sys.Ms);
                break;
            case DoctorDnsMatch.Similar:
                sink.Report(DoctorCheck.DnsSystem, DoctorState.Ok, Cap($"{Ans(sys)} — the same networks as encrypted DNS"), sys.Ms);
                break;
            case DoctorDnsMatch.Bogus:
                sink.Report(DoctorCheck.DnsSystem, DoctorState.Fail,
                            Cap($"{Ans(sys)}: {Why(sys.Addresses)}, not {host}'s" + (known ? $" (encrypted DNS: {trustedText})" : "")), sys.Ms);
                break;
            case DoctorDnsMatch.Missing:
                sink.Report(DoctorCheck.DnsSystem, DoctorState.Fail, Cap($"Says {Ans(sys)}, though encrypted DNS knows it ({trustedText})"), sys.Ms);
                break;
            case DoctorDnsMatch.Differs:
                sink.Report(DoctorCheck.DnsSystem, DoctorState.Running, Cap($"{Ans(sys)} — differs from encrypted DNS ({trustedText}); checking which is right…"), sys.Ms);
                break;
            default:
                if (!sys.Answered)
                    sink.Report(DoctorCheck.DnsSystem, DoctorState.Fail, Cap($"No answer for {host} ({sys.Error ?? "no reply"})"), sys.Ms);
                else if (sys.NoSuchName)
                    sink.Report(DoctorCheck.DnsSystem, f.NameMissing ? DoctorState.Fail : DoctorState.Warning, $"Says {host} doesn't exist", sys.Ms);
                else if (sys.Addresses.Count == 0)
                    sink.Report(DoctorCheck.DnsSystem, DoctorState.Warning, Cap($"{Ans(sys)} for {host}"), sys.Ms);
                else if (sys.Addresses.Any(a => !DoctorIp.IsPublic(a)))
                    sink.Report(DoctorCheck.DnsSystem, DoctorState.Warning,
                                Cap($"{Ans(sys)}: {Why(sys.Addresses)} — couldn't be checked against encrypted DNS"), sys.Ms);
                else
                    sink.Report(DoctorCheck.DnsSystem, DoctorState.Ok, Cap(Ans(sys) + (known ? "" : " (not cross-checked)")), sys.Ms);
                break;
        }
    }

    // "the filter's address" / "a private address"
    private static string Why(IEnumerable<IPAddress> addrs)
    {
        var bad = addrs.FirstOrDefault(a => !DoctorIp.IsPublic(a));
        if (bad == null) return "not the site's address";
        string kind = DoctorIp.Kind(bad) ?? "reserved";
        return kind.StartsWith("the ", StringComparison.Ordinal) ? kind : $"a {kind} address";
    }

    // The system's answer differs from encrypted DNS: a CDN edge (serves the site too), or a server that isn't the site's.
    private static async Task VerifySystemAsync(DoctorFacts f, IDoctorSink sink, CancellationToken ct)
    {
        try
        {
            var sys = f.Sys!;
            var other = sys.Addresses.FirstOrDefault(DoctorIp.IsPublic);
            string host = f.Target.AsciiHost;
            string trustedText = DoctorIp.List(f.Trusted);
            if (other == null) return;
            // the site's own HTTPS port (a certificate names the site)
            int port = f.Plan.Https ?? 443;
            var theirs = DoctorTls.ServesAsync(other, port, host, 5000, ct);
            var ours = DoctorTls.ServesAsync(f.Trusted[0], port, host, 5000, ct);
            bool? sysServes = await theirs.ConfigureAwait(false);
            bool? realServes = await ours.ConfigureAwait(false);
            if (sysServes == true)
                sink.Report(DoctorCheck.DnsSystem, DoctorState.Ok,
                            Cap($"{Ans(sys)} — differs from encrypted DNS ({trustedText}), but serves {f.Target.Host} too (another edge of the same site)"), sys.Ms);
            else if (realServes == true)
            {
                f.SysPointsElsewhere = true;
                sink.Report(DoctorCheck.DnsSystem, DoctorState.Fail,
                            Cap($"{Ans(sys)} — a server that isn't {f.Target.Host}'s (encrypted DNS: {trustedText})"), sys.Ms);
            }
            else
                sink.Report(DoctorCheck.DnsSystem, DoctorState.Warning,
                            Cap($"{Ans(sys)} — differs from encrypted DNS ({trustedText}); couldn't tell which is right"), sys.Ms);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception e) { sink.Report(DoctorCheck.DnsSystem, DoctorState.Warning, "Differs from encrypted DNS; the check failed: " + DoctorDns.Short(e)); }
    }

    // ------------------------------------------------------------------ connection, ping, MTU

    private static async Task ConnectAsync(DoctorFacts f, IDoctorSink sink, CancellationToken ct)
    {
        var plan = f.Plan;
        var ports = plan.All;
        sink.Report(DoctorCheck.Connect, DoctorState.Running,
                    $"Connecting to {DoctorIp.List(f.Trusted.Take(3).ToList(), 3)} on port {string.Join(" and ", ports)}…");
        var c = await DoctorNet.ConnectAllAsync(f.Trusted, ports, 4000, ct).ConfigureAwait(false);
        f.Connect = c;
        // a sub-step per address × port: SYN → SYN/ACK time, or refused (RST) vs dropped (timeout)
        foreach (var a in c.Attempts.OrderBy(a => a.Port).ThenBy(a => a.Address.AddressFamily))
        {
            if (a.Ok) Tr(sink, DoctorCheck.Connect, DoctorState.Ok, $"TCP {a.Port}", $"{a.Address} → SYN/ACK in {Ms(a.Ms)}", a.Ms);
            else Tr(sink, DoctorCheck.Connect, a.Code == SocketError.ConnectionRefused ? DoctorState.Warning : DoctorState.Fail,
                    $"TCP {a.Port}", $"{a.Address} → {SaysLong(a)}", a.Ms);
        }
        string from = f.TrustedFrom switch
        {
            "encrypted DNS" => " (encrypted DNS's address)",
            "check-host.net" => " (check-host.net's address)",
            _ => "",
        };
        // one part per port: "443 in 120 ms", "80: refused"; the asked-for ports decide the state, an extra one only notes
        var parts = new List<string>();
        bool primaryFailed = false;
        foreach (int p in ports)
        {
            bool primary = p == plan.Raw || (p == plan.Https && plan.HttpsPrimary) || (p == plan.Http && plan.HttpPrimary);
            if (c.Best(p) is { } ok) parts.Add($"{p} in {Ms(ok.Ms)}");
            else
            {
                parts.Add($"{p}: {Says(c.FailureOn(p))}");
                primaryFailed |= primary;
            }
        }
        if (c.Ok)
        {
            var onPort = c.Attempts.Where(a => a.Port == c.Port).ToList();
            int failedAddrs = onPort.Count(a => !a.Ok);
            string text = $"{c.Address}{from} · port " + string.Join(" · ", parts);
            if (failedAddrs > 0) text += $" · {failedAddrs} of {onPort.Count} addresses failed";
            sink.Report(DoctorCheck.Connect, primaryFailed || failedAddrs > 0 ? DoctorState.Warning : DoctorState.Ok, Cap(text), c.Ms);
        }
        else
        {
            var first = c.FailureOn(ports[0]) ?? c.Attempts.FirstOrDefault();
            int n = c.Attempts.Select(a => a.Address).Distinct().Count();
            string where = n > 1 ? $"{n} addresses" : (first?.Address ?? f.Trusted[0]).ToString();
            sink.Report(DoctorCheck.Connect, DoctorState.Fail, Cap($"Can't connect to {where}: port " + string.Join(" · ", parts)), first?.Ms);
        }
    }

    // a failed connect in a few words
    private static string Says(DoctorConnectAttempt? a) => a?.Code switch
    {
        SocketError.ConnectionRefused => "refused",
        SocketError.TimedOut => "timed out",
        SocketError.ConnectionReset => "reset",
        SocketError.HostUnreachable or SocketError.NetworkUnreachable => "unreachable",
        _ => a?.Error ?? "no answer",
    };

    private static async Task PingAsync(DoctorFacts f, IPAddress addr, IDoctorSink sink, CancellationToken ct)
    {
        sink.Report(DoctorCheck.Ping, DoctorState.Running, $"Pinging {addr}…");
        var p = await DoctorNet.PingAsync(addr, 4, ct).ConfigureAwait(false);
        f.Ping = p;
        if (p.Denied) Tr(sink, DoctorCheck.Ping, DoctorState.Skipped, "ICMP", $"not permitted for this app here{(p.Error is { } de ? $" ({de})" : "")}");
        else if (p.Received == 0) Tr(sink, DoctorCheck.Ping, DoctorState.Warning, p.ViaUdp ? "UDP probe" : "ICMP echo", $"{addr} → no reply (0/{p.Sent}) — many hosts ignore ping");
        else Tr(sink, DoctorCheck.Ping, p.Received < p.Sent ? DoctorState.Warning : DoctorState.Ok, p.ViaUdp ? "UDP probe" : "ICMP echo",
                $"{addr} → {p.Received}/{p.Sent} replies, avg {Ms(p.Avg!.Value)}", p.Avg);
        string via = p.ViaUdp ? " (UDP probes: ICMP isn't permitted here)" : "";
        if (p.Denied)
            sink.Report(DoctorCheck.Ping, DoctorState.Skipped, Cap("Ping isn't permitted here" + (p.Error is { } e ? $" ({e})" : "")));
        else if (p.Received == 0)
            sink.Report(DoctorCheck.Ping, DoctorState.Warning, $"No replies (0/{p.Sent}): many servers ignore ping{via}");
        else
        {
            int loss = (int)Math.Round(100.0 * (p.Sent - p.Received) / p.Sent);
            string text = $"{p.Received}/{p.Sent} replies · avg {Ms(p.Avg!.Value)} (min {Ms(p.Min!.Value)}, max {Ms(p.Max!.Value)})"
                          + (loss > 0 ? $" · {loss}% loss" : "") + via;
            sink.Report(DoctorCheck.Ping, loss > 0 ? DoctorState.Warning : DoctorState.Ok, text, p.Avg);
        }
    }

    private static async Task MtuAsync(DoctorFacts f, IPAddress addr, IDoctorSink sink, CancellationToken ct)
    {
        sink.Report(DoctorCheck.Mtu, DoctorState.Running, "Finding the largest packet that gets through…");
        var sw = Stopwatch.StartNew();
        var m = await DoctorMtu.MeasureAsync(addr, 7000, ct).ConfigureAwait(false);
        f.Mtu = m;
        double ms = sw.Elapsed.TotalMilliseconds;
        if (m.Mtu is int mv)
            Tr(sink, DoctorCheck.Mtu, mv >= DoctorMtu.Small ? DoctorState.Ok : DoctorState.Warning, "Largest packet",
               (m.Exact ? $"{mv} bytes pass" : $"at least {mv} bytes pass") + (mv >= DoctorMtu.Full ? " (full size)" : mv >= DoctorMtu.Small ? " (DSL / PPPoE)" : " — a PMTU black hole: bigger packets vanish"), ms);
        if (m.Mtu is not int mtu)
            sink.Report(DoctorCheck.Mtu, DoctorState.Skipped, "Not measured: " + m.Skipped);
        else if (mtu >= DoctorMtu.Full)
            sink.Report(DoctorCheck.Mtu, DoctorState.Ok, "1500 bytes: full size", ms);
        else if (mtu >= DoctorMtu.Small)
            sink.Report(DoctorCheck.Mtu, DoctorState.Ok, $"{mtu} bytes: normal for DSL (PPPoE)", ms);
        else
            sink.Report(DoctorCheck.Mtu, DoctorState.Warning,
                        (m.Exact ? $"{mtu} bytes" : $"at least {mtu} bytes") + ": a VPN or tunnel on the way"
                        + (f.Local?.Vpn != null ? " (yours)" : "") + "; if pages stall, lower its MTU", ms);
    }

    // ------------------------------------------------------------------ TLS + HTTP

    private static async Task TlsAsync(DoctorFacts f, DoctorEnvironment env, IDoctorSink sink, CancellationToken ct)
    {
        var t = f.Target;
        var c = f.Connect!;
        var plan = f.Plan;
        string? sni = t.IsIp ? null : t.AsciiHost;
        int port;
        bool? tls;
        if (plan.Https is int hs) { port = hs; tls = true; }
        else if (plan.Raw is int raw) { port = raw; tls = t.SpeaksTls(raw); }
        else
        {
            f.UsesTls = false;
            sink.Report(DoctorCheck.Tls, DoctorState.Skipped, "No HTTPS to test");
            return;
        }
        if (c.Best(port) is not { } conn)
        {
            f.UsesTls = false;
            sink.Report(DoctorCheck.Tls, DoctorState.Skipped, $"Skipped: port {port} doesn't answer");
            return;
        }
        var addr = conn.Address;
        sink.Report(DoctorCheck.Tls, DoctorState.Running, $"TLS handshake with {DoctorIp.EndPoint(addr, port)}…");
        if (tls == null)
        {
            var probe = await DoctorTls.HelloAsync(addr, port, sni, 3000, ct).ConfigureAwait(false);
            if (probe.State != DoctorHello.Answered)
            {
                f.UsesTls = false;
                sink.Report(DoctorCheck.Tls, DoctorState.Skipped, probe.State == DoctorHello.NotTls
                    ? Cap($"Not TLS on port {port}: it says \"{probe.Text}\"")
                    : $"No TLS answer on port {port} (the service may not speak TLS)");
                return;
            }
        }
        f.UsesTls = true;
        var r = await DoctorTls.CheckAsync(addr, port, sni, env.HarmlessSni, env.TrustRoots, ct).ConfigureAwait(false);
        f.Tls = r;
        await TraceTlsAsync(f, r, addr, port, sni, sink, ct).ConfigureAwait(false);
        switch (r.Outcome)
        {
            case DoctorTlsOutcome.Ok:
            case DoctorTlsOutcome.CertProblem:
                ReportTlsOk(sink, DoctorCheck.Tls, r);
                break;
            case DoctorTlsOutcome.SniFiltered:
                sink.Report(DoctorCheck.Tls, DoctorState.Fail,
                            "Cut when the name is sent, answered without it: SNI filtering");
                break;
            case DoctorTlsOutcome.NotTls when tls == true:
                sink.Report(DoctorCheck.Tls, DoctorState.Fail, Cap(r.Error ?? "Not TLS"));
                break;
            case DoctorTlsOutcome.NotTls:
                f.UsesTls = false;
                sink.Report(DoctorCheck.Tls, DoctorState.Skipped, Cap(r.Error ?? "Not TLS"));
                break;
            case DoctorTlsOutcome.HandshakeCut:
                sink.Report(DoctorCheck.Tls, DoctorState.Warning, Cap(r.Error ?? "The handshake was cut"));
                break;
            default:
                sink.Report(DoctorCheck.Tls, DoctorState.Fail, Cap(r.Error ?? "The handshake failed"));
                break;
        }
    }

    // The TLS handshake, stage by stage (ClientHello → ServerHello → Certificate → done), so the exact stuck point shows;
    // and, when the name's handshake is cut but the address answers otherwise, the anti-DPI retries that may get past it.
    private static async Task TraceTlsAsync(DoctorFacts f, DoctorTlsResult r, IPAddress addr, int port, string? sni, IDoctorSink sink, CancellationToken ct)
    {
        string name = sni ?? addr.ToString();
        Tr(sink, DoctorCheck.Tls, DoctorState.Ok, "ClientHello", $"sent to {DoctorIp.EndPoint(addr, port)}, SNI {(sni != null ? sni : "(none)")}");
        switch (r.Outcome)
        {
            case DoctorTlsOutcome.Ok:
            case DoctorTlsOutcome.CertProblem:
                Tr(sink, DoctorCheck.Tls, DoctorState.Ok, "ServerHello", $"received ({r.Protocol})", r.HandshakeMs);
                if (r.CertSubject != null)
                {
                    bool certBad = r.Outcome == DoctorTlsOutcome.CertProblem;
                    Tr(sink, DoctorCheck.Tls, certBad ? DoctorState.Fail : r.CoversName == false ? DoctorState.Warning : DoctorState.Ok, "Certificate",
                       $"{r.CertSubject}, issuer {r.CertIssuer}" + (r.CoversName == true ? $" — names {name}" : r.CoversName == false ? $" — does NOT name {name}" : "")
                       + (certBad ? " — a browser would refuse it" : ""));
                }
                Tr(sink, DoctorCheck.Tls, r.Outcome == DoctorTlsOutcome.CertProblem ? DoctorState.Warning : DoctorState.Ok, "Handshake", $"done in {Ms(r.HandshakeMs)}", r.HandshakeMs);
                break;
            case DoctorTlsOutcome.SniFiltered:
                Tr(sink, DoctorCheck.Tls, DoctorState.Fail, "ServerHello", r.CutHow == "silent"
                    ? $"no answer after the ClientHello named {name} (SNI filtering)" : $"reset right after the ClientHello named {name} (SNI filtering)");
                Tr(sink, DoctorCheck.Tls, DoctorState.Ok, "Without the name", "a hello with no name / a harmless name gets a ServerHello — the address speaks TLS");
                break;
            case DoctorTlsOutcome.HandshakeCut:
                Tr(sink, DoctorCheck.Tls, DoctorState.Fail, "ServerHello", "this system's full handshake was cut, though a simple hello gets through — a filter matches its fingerprint");
                break;
            case DoctorTlsOutcome.AllCut:
                Tr(sink, DoctorCheck.Tls, DoctorState.Fail, "ServerHello", r.CutHow == "silent"
                    ? "no answer after the ClientHello (blackhole)" : "reset after the ClientHello");
                if (r.BaselineAnswered == false) Tr(sink, DoctorCheck.Tls, DoctorState.Fail, "Without the name", "also cut — the address is blocked for TLS");
                break;
            case DoctorTlsOutcome.ServerRefused:
                Tr(sink, DoctorCheck.Tls, DoctorState.Fail, "ServerHello", "a TLS alert — the server refused: " + (r.Error ?? "no common version / cipher"));
                break;
            case DoctorTlsOutcome.NotTls:
                Tr(sink, DoctorCheck.Tls, DoctorState.Skipped, "ServerHello", "not a TLS answer" + (r.NotTlsText is { } nt ? $" — it said \"{nt}\"" : ""));
                break;
        }

        // the address answers TLS, only this name is cut: try the anti-DPI tricks a censorship-bypass client would use
        if (sni != null && r.Outcome is DoctorTlsOutcome.SniFiltered or DoctorTlsOutcome.HandshakeCut)
        {
            var dpi = await DoctorDpi.TryBypassAsync(addr, port, sni, ct).ConfigureAwait(false);
            f.Dpi = dpi;
            foreach (var at in dpi.Attempts)
                Tr(sink, DoctorCheck.Tls, at.Answered ? DoctorState.Ok : DoctorState.Fail, "Anti-DPI: " + DoctorDpiResult.Short(at.Trick),
                   at.Answered ? "ServerHello OK — this gets through" : $"still cut ({at.Note ?? "no answer"})", at.Ms);
            if (dpi.Working is { } w)
                Tr(sink, DoctorCheck.Tls, DoctorState.Ok, "Workaround", $"the ClientHello {DoctorDpiResult.Name(w)} gets through → turn on 'fragment' in your client");
        }
    }

    // A good handshake, or one with a certificate browsers would refuse (direct or through the proxy).
    private static void ReportTlsOk(IDoctorSink sink, DoctorCheck row, DoctorTlsResult r)
    {
        if (r.Outcome == DoctorTlsOutcome.CertProblem)
        {
            sink.Report(row, DoctorState.Fail,
                        Cap($"Handshake OK ({r.Protocol}), but the certificate is bad: " + r.Problems.First(p => p.Severity == TlsSeverity.Error).Text.TrimEnd('.')),
                        r.HandshakeMs);
            return;
        }
        var warn = r.Problems.FirstOrDefault(p => p.Severity == TlsSeverity.Warning);
        sink.Report(row, warn != null ? DoctorState.Warning : DoctorState.Ok,
                    Cap($"{r.Protocol} in {Ms(r.HandshakeMs)} · " + (warn?.Text.TrimEnd('.') ?? $"certificate valid, {r.CertText}")), r.HandshakeMs);
    }

    // The HTTPS row (tls) or the plain HTTP row, on the port the plan gives each, pinned to the trusted address.
    private static async Task WebAsync(DoctorFacts f, DoctorEnvironment env, HttpClient doh, bool tls, IDoctorSink sink, CancellationToken ct)
    {
        var t = f.Target;
        var c = f.Connect!;
        var plan = f.Plan;
        var row = tls ? DoctorCheck.Https : DoctorCheck.Http;
        int? port = tls ? plan.Https : plan.Http;
        if (port is not int p)
        {
            sink.Report(row, DoctorState.Skipped, plan.Raw is int raw ? $"Port {raw} isn't a web port" : "Not tested");
            return;
        }
        if (c.Best(p) is not { } conn)
        {
            sink.Report(row, DoctorState.Skipped, $"Skipped: port {p} doesn't answer");
            return;
        }
        if (tls && f.Tls is { Outcome: DoctorTlsOutcome.SniFiltered or DoctorTlsOutcome.AllCut or DoctorTlsOutcome.HandshakeCut or DoctorTlsOutcome.ServerRefused or DoctorTlsOutcome.NotTls })
        {
            sink.Report(row, DoctorState.Skipped, "Skipped: the TLS handshake fails");
            return;
        }
        var url = new Uri(t.Url(p, tls, withPath: tls ? plan.HttpsPrimary : plan.HttpPrimary));
        sink.Report(row, DoctorState.Running, Cap($"GET {url}…"));

        // a redirect's host: through the encrypted resolvers that answered in this run (blocked ones would only burn
        // time), else this system's resolver
        var working = env.Doh.Where(d => f.Doh.Any(a => a.Good && a.Source == d.Name)).Take(2).ToList();
        async Task<IPAddress?> ResolveOther(string host, CancellationToken token)
        {
            if (working.Count > 0)
            {
                var answers = await DoctorDns.DohAllAsync(doh, working, host, 3000, token).ConfigureAwait(false);
                var a = DoctorIp.Ordered(answers.Where(x => x.Good).SelectMany(x => x.Addresses).Where(DoctorIp.IsPublic)).FirstOrDefault();
                if (a != null) return a;
            }
            var s = await DoctorDns.SystemAsync(env.SystemResolve, host, 4000, token).ConfigureAwait(false);
            return s.Addresses.FirstOrDefault(DoctorIp.IsPublic) ?? s.Addresses.FirstOrDefault();
        }

        var r = await DoctorHttp.GetAsync(url, conn.Address, ResolveOther, ct).ConfigureAwait(false);
        if (tls) f.Https = r; else f.PlainHttp = r;
        ReportHttp(sink, row, r);
    }

    // One request's row: blocked / captive / failed, or the status, server, first byte and the redirect chain.
    private static void ReportHttp(IDoctorSink sink, DoctorCheck row, DoctorHttpResult r)
    {
        TraceHttp(sink, row, r);
        string chain = r.Chain.Count > 0 ? " · " + string.Join(" · ", r.Chain) : "";
        double? ms = r.Answered ? r.FirstByteMs : null;
        if (r.FilterPage != null)
            sink.Report(row, DoctorState.Fail, Cap($"Blocked: {r.FilterPage}"), ms);
        else if (r.CaptivePage != null)
            sink.Report(row, DoctorState.Fail, Cap($"Captive portal: {r.CaptivePage}"), ms);
        else if (!r.Answered || r.Error != null)
            sink.Report(row, DoctorState.Fail,
                        Cap((r.Answered ? $"{r.Status} {r.Reason}{chain}, then " : "")
                            + (r.FailedHost != null || r.ProxyLogin ? r.Error : r.TimedOut ? "no answer within 8 s" : "failed: " + r.Error)), ms);
        else
        {
            // the redirects first, then where they ended: "301 → https://example.com/ · 200 OK · nginx · first byte 90 ms"
            string head = (r.Chain.Count > 0 ? string.Join(" · ", r.Chain) + " · " : "")
                          + $"{r.Status} {r.Reason}".Trim() + (r.Server is { Length: > 0 } sv ? $" · {DoctorNet.Trim(sv, 30)}" : "")
                          + $" · first byte {Ms(r.FirstByteMs)}";
            var state = r.Status >= 500 ? DoctorState.Fail : r.Status >= 400 ? DoctorState.Warning : DoctorState.Ok;
            sink.Report(row, state, Cap(head), r.FirstByteMs);
        }
    }

    // HTTP, stage by stage: request sent → redirects → status line → server → first byte, or a block / captive page.
    private static void TraceHttp(IDoctorSink sink, DoctorCheck row, DoctorHttpResult r)
    {
        Tr(sink, row, DoctorState.Ok, "Request", "GET sent");
        foreach (var hop in r.Chain) Tr(sink, row, DoctorState.Warning, "Redirect", hop);
        if (r.FilterPage != null) { Tr(sink, row, DoctorState.Fail, "Block page", r.FilterPage); return; }
        if (r.CaptivePage != null) { Tr(sink, row, DoctorState.Fail, "Captive", r.CaptivePage); return; }
        if (r.Answered && r.Error == null)
        {
            Tr(sink, row, r.Status >= 500 ? DoctorState.Fail : r.Status >= 400 ? DoctorState.Warning : DoctorState.Ok, "Status", $"{r.Status} {r.Reason}".Trim(), r.FirstByteMs);
            if (r.Server is { Length: > 0 } sv) Tr(sink, row, DoctorState.Ok, "Server", DoctorNet.Trim(sv, 40));
            Tr(sink, row, DoctorState.Ok, "First byte", Ms(r.FirstByteMs), r.FirstByteMs);
        }
        else
        {
            if (r.Answered) Tr(sink, row, DoctorState.Warning, "Status", $"{r.Status} {r.Reason}".Trim(), r.FirstByteMs);
            Tr(sink, row, DoctorState.Fail, r.TimedOut ? "No answer" : r.ProxyLogin ? "Proxy login" : "Failed",
               r.TimedOut ? "no answer within 8 s" : (r.FailedHost != null ? r.FailedHost + ": " : "") + (r.Error ?? "failed"));
        }
    }

    // ------------------------------------------------------------------ through the proxy

    // The proxy itself first (one tunnel: reach, TLS to an https proxy, protocol, login), then — in parallel — a tunnel
    // per port, encrypted DNS, TLS with the site's name, HTTP and HTTPS, all through it. The proxy resolves the name.
    private static async Task ViaProxyAsync(DoctorFacts f, DoctorEnvironment env, DoctorProxy proxy, IDoctorSink sink, CancellationToken ct)
    {
        var t = f.Target;
        var plan = f.Plan;
        var via = f.Via = new DoctorViaProxy();
        string host = t.AsciiHost;
        var rest = new[] { DoctorCheck.ProxyDns, DoctorCheck.ProxyConnect, DoctorCheck.ProxyTls, DoctorCheck.ProxyHttps, DoctorCheck.ProxyHttp };
        sink.Report(DoctorCheck.ProxyServer, DoctorState.Running, $"Reaching {proxy.Display}…");
        foreach (var r in rest) sink.Report(r, DoctorState.Running, "Waiting for the proxy…");

        int first = plan.All[0];
        try
        {
            using var probe = await proxy.OpenAsync(host, first, 8000, ct).ConfigureAwait(false);
            via.ReachMs = probe.ReachMs;
            via.LoginUsed = probe.LoginUsed;
            via.Tunnels[first] = (probe.TotalMs, null);
        }
        catch (DoctorProxyException e) when (e.Stage == DoctorProxyStage.Tunnel)
        {
            via.Tunnels[first] = (0, e);   // the proxy works; it just can't reach this target
            via.LoginUsed = proxy.HasLogin;   // the login comes before the tunnel: it got past it
        }
        catch (DoctorProxyException e)
        {
            via.Failure = e;
            sink.Report(DoctorCheck.ProxyServer, DoctorState.Fail, Cap($"{proxy.Display}: {e.Message}"));
            string why = e.Stage switch
            {
                DoctorProxyStage.Login => "the proxy refused the login",
                DoctorProxyStage.Reach => "the proxy doesn't answer",
                _ => "the proxy doesn't work",
            };
            foreach (var r in rest) sink.Report(r, DoctorState.Skipped, $"Skipped: {why}");
            return;
        }
        string where = proxy.Host.Contains(':') ? $"[{proxy.Host}]:{proxy.Port}" : $"{proxy.Host}:{proxy.Port}";
        string login = via.LoginUsed ? "login accepted" : proxy.HasLogin ? "no login asked" : "no login";
        sink.Report(DoctorCheck.ProxyServer, DoctorState.Ok, $"{where} · {proxy.KindName}{(proxy.Guessed ? " (detected)" : "")} · {login}",
                    via.ReachMs > 0 ? via.ReachMs : null);
        Tr(sink, DoctorCheck.ProxyServer, DoctorState.Ok, "Reach", $"{where} answered in {Ms(via.ReachMs)} · {proxy.KindName}", via.ReachMs > 0 ? via.ReachMs : null);
        Tr(sink, DoctorCheck.ProxyServer, DoctorState.Ok, "Login", login);

        // ---- a tunnel to every port
        async Task Tunnel(int port)
        {
            (double, DoctorProxyException?) result;
            try
            {
                using var tn = await proxy.OpenAsync(host, port, 8000, ct).ConfigureAwait(false);
                result = (tn.TotalMs, null);
            }
            catch (DoctorProxyException e) { result = (0, e); }
            lock (via.Tunnels) via.Tunnels[port] = result;
        }
        async Task Tunnels()
        {
            await Task.WhenAll(plan.All.Where(p => !via.Tunnels.ContainsKey(p)).Select(Tunnel)).ConfigureAwait(false);
            foreach (int p in plan.All)
                Tr(sink, DoctorCheck.ProxyConnect, via.TunnelOk(p) ? DoctorState.Ok : DoctorState.Fail, $"Tunnel {p}",
                   via.Tunnels[p] is { Error: null } ok2 ? $"{t.Display()} open in {Ms(ok2.Ms)}" : via.Tunnels[p].Error!.Message, via.Tunnels[p].Ms > 0 ? via.Tunnels[p].Ms : null);
            var parts = plan.All.Select(p => via.Tunnels[p] is { Error: null } ok ? $"{p} in {Ms(ok.Ms)}" : $"{p}: {via.Tunnels[p].Error!.Message}").ToList();
            var okPorts = plan.All.Where(p => via.TunnelOk(p)).ToList();
            double? fastest = okPorts.Count > 0 ? okPorts.Min(p => via.Tunnels[p].Ms) : null;
            sink.Report(DoctorCheck.ProxyConnect, okPorts.Count == plan.All.Count ? DoctorState.Ok : okPorts.Count > 0 ? DoctorState.Warning : DoctorState.Fail,
                        Cap((okPorts.Count > 0 ? $"{t.Display()} through the proxy · port " : "Can't reach it through the proxy: port ") + string.Join(" · ", parts)),
                        fastest);
        }

        // ---- encrypted DNS through the proxy
        async Task Dns()
        {
            if (t.IsIp || t.IsLocal)
            {
                sink.Report(DoctorCheck.ProxyDns, DoctorState.Skipped, t.IsIp ? "An IP address: nothing to look up" : "A local name: public resolvers don't know it");
                return;
            }
            using var http = DoctorDns.CreateDohClient(proxy);
            var list = await DoctorDns.DohAllAsync(http, env.Doh.Take(3).ToList(), host, 6000, ct).ConfigureAwait(false);
            via.Doh = list;
            var good = list.Where(a => a.Good).ToList();
            if (good.Count == 0)
                sink.Report(DoctorCheck.ProxyDns, DoctorState.Warning,
                            Cap("No encrypted resolver answered through the proxy (" + string.Join(", ", list.Where(a => a.Error != null).Take(2).Select(a => $"{a.Source}: {a.Error}")) + ")"));
            else if (good.All(a => a.NoSuchName))
                sink.Report(DoctorCheck.ProxyDns, DoctorState.Warning, $"{t.Host} doesn't exist (no such name)", good.Min(a => a.Ms));
            else
                sink.Report(DoctorCheck.ProxyDns, DoctorState.Ok,
                            Cap(string.Join(", ", good.Select(a => a.Source)) + ": " + DoctorIp.List(DoctorIp.Ordered(good.SelectMany(a => a.Addresses)))),
                            good.Min(a => a.Ms));
        }

        // ---- TLS with the site's name, then HTTPS
        async Task TlsThenHttps()
        {
            int? tlsPort = plan.Https ?? (plan.Raw is int raw && t.SpeaksTls(raw) == true ? raw : null);
            if (tlsPort is not int p)
            {
                sink.Report(DoctorCheck.ProxyTls, DoctorState.Skipped, "No HTTPS to test");
                sink.Report(DoctorCheck.ProxyHttps, DoctorState.Skipped, plan.Raw is int r2 ? $"Port {r2} isn't a web port" : "Not tested");
                return;
            }
            try
            {
                using var tn = await proxy.OpenAsync(host, p, 8000, ct).ConfigureAwait(false);
                var r = await DoctorTls.OverStreamAsync(tn.Stream, t.IsIp ? null : host, host, env.TrustRoots, 6000, ct).ConfigureAwait(false);
                via.Tls = r;
                bool tlsOk = r.Outcome is DoctorTlsOutcome.Ok or DoctorTlsOutcome.CertProblem;
                Tr(sink, DoctorCheck.ProxyTls, tlsOk ? DoctorState.Ok : DoctorState.Fail, "Handshake",
                   tlsOk ? $"ServerHello {r.Protocol}, {(r.CoversName == true ? "certificate names the site" : r.CertSubject ?? "certificate received")}" : (r.Error ?? "the handshake failed"), r.HandshakeMs);
                if (tlsOk) ReportTlsOk(sink, DoctorCheck.ProxyTls, r);
                else sink.Report(DoctorCheck.ProxyTls, DoctorState.Fail, Cap(Sentence(r.Error ?? "the handshake failed") + " (through the proxy)"));
            }
            catch (DoctorProxyException e)
            {
                via.Tls = new DoctorTlsResult { Outcome = DoctorTlsOutcome.AllCut, Error = e.Message };
                sink.Report(DoctorCheck.ProxyTls, DoctorState.Skipped, Cap("Skipped: " + e.Message));
            }
            if (plan.Https is not int hs)
            {
                sink.Report(DoctorCheck.ProxyHttps, DoctorState.Skipped, $"Port {p} isn't a web port");
                return;
            }
            if (via.Tls is not { Outcome: DoctorTlsOutcome.Ok or DoctorTlsOutcome.CertProblem })
            {
                sink.Report(DoctorCheck.ProxyHttps, DoctorState.Skipped, "Skipped: the TLS handshake fails");
                return;
            }
            var url = new Uri(t.Url(hs, true, withPath: plan.HttpsPrimary));
            sink.Report(DoctorCheck.ProxyHttps, DoctorState.Running, Cap($"GET {url} through the proxy…"));
            via.Https = await DoctorHttp.GetViaProxyAsync(url, proxy, ct).ConfigureAwait(false);
            ReportHttp(sink, DoctorCheck.ProxyHttps, via.Https);
        }

        // ---- plain HTTP
        async Task Plain()
        {
            if (plan.Http is not int hp)
            {
                sink.Report(DoctorCheck.ProxyHttp, DoctorState.Skipped, plan.Raw is int r2 ? $"Port {r2} isn't a web port" : "Not tested");
                return;
            }
            var url = new Uri(t.Url(hp, false, withPath: plan.HttpPrimary));
            sink.Report(DoctorCheck.ProxyHttp, DoctorState.Running, Cap($"GET {url} through the proxy…"));
            via.Http = await DoctorHttp.GetViaProxyAsync(url, proxy, ct).ConfigureAwait(false);
            ReportHttp(sink, DoctorCheck.ProxyHttp, via.Http);
        }

        await Task.WhenAll(
            Step(sink, new[] { DoctorCheck.ProxyConnect }, Tunnels),
            Step(sink, new[] { DoctorCheck.ProxyDns }, Dns),
            Step(sink, new[] { DoctorCheck.ProxyTls, DoctorCheck.ProxyHttps }, TlsThenHttps),
            Step(sink, new[] { DoctorCheck.ProxyHttp }, Plain)).ConfigureAwait(false);
    }

    private static string Sentence(string s) => s.Length > 0 && char.IsLower(s[0]) ? char.ToUpperInvariant(s[0]) + s[1..] : s;

    // ------------------------------------------------------------------ outside view

    private static async Task OutsideAsync(DoctorFacts f, DoctorEnvironment env, IDoctorSink sink, CancellationToken ct)
    {
        var t = f.Target;
        if (t.IsLocal && !DoctorIp.LoopbackIsPublic)
        {
            sink.Report(DoctorCheck.Outside, DoctorState.Skipped, "A local address: check-host.net can't reach it");
            return;
        }
        // an HTTP check of the scheme that connected here (HTTPS first), else a TCP check of the asked-for port;
        // never with the query string (it may carry a token)
        var plan = f.Plan;
        var c = f.Connect;
        int? webPort = c?.OkOn(plan.Https) == true ? plan.Https : c?.OkOn(plan.Http) == true ? plan.Http : null;
        bool web = webPort != null;
        int port = webPort ?? plan.All[0];
        CheckHostKind kind = web ? CheckHostKind.Http : CheckHostKind.Tcp;
        string target = web ? NoQuery(t.Url(port, port == plan.Https, withPath: port == plan.Https ? plan.HttpsPrimary : plan.HttpPrimary)) : t.Display(port);
        sink.Report(DoctorCheck.Outside, DoctorState.Running, $"Asking check-host.net ({kind.Label()} check of {DoctorNet.Trim(target, 50)})…");
        var sw = Stopwatch.StartNew();
        var o = await DoctorOutside.RunAsync(env.CheckHostBase, kind, target, ct).ConfigureAwait(false);
        f.Outside = o;
        double ms = sw.Elapsed.TotalMilliseconds;
        if (!o.Ran)
        {
            sink.Report(DoctorCheck.Outside, DoctorState.Warning, Cap("Couldn't check from outside: " + (o.Error ?? "no result").TrimEnd('.')), ms);
            return;
        }
        int total = o.Nodes.Count;
        var bad = o.Nodes.Where(n => !n.Good).ToList();
        var good = o.Nodes.Where(n => n.Good).ToList();
        string failNote = "";
        if (bad.Count > 0 && good.Count > 0)
        {
            failNote = $" · fails from {DoctorOutside.Places(bad, 2)}";
        }
        if (o.WorksOutside)
            sink.Report(DoctorCheck.Outside, bad.Count == 0 ? DoctorState.Ok : DoctorState.Warning,
                        Cap($"Works from {good.Count} of {total} places ({DoctorOutside.Places(good)}){failNote}"), ms);
        else if (o.DownEverywhere)
            sink.Report(DoctorCheck.Outside, DoctorState.Fail,
                        Cap($"Down from all {total} places ({DoctorOutside.Places(o.Nodes)}): {CommonError(o.Nodes)}"), ms);
        else if (o.ErrorsEverywhere)
            sink.Report(DoctorCheck.Outside, DoctorState.Fail,
                        Cap($"Answers with errors from all {total} places ({CommonError(o.Nodes)})"), ms);
        else
            sink.Report(DoctorCheck.Outside, DoctorState.Warning,
                        Cap($"Works from only {good.Count} of {total} places ({(good.Count > 0 ? DoctorOutside.Places(good) : "none")}){failNote}"), ms);
    }

    private static string CommonError(IEnumerable<DoctorNodeView> nodes)
    {
        var top = nodes.Select(n => n.HttpCode is int code ? $"HTTP {code}" : CheckHostResult.ShortError(n.Why))
                       .GroupBy(s => s).OrderByDescending(g => g.Count()).FirstOrDefault();
        return top?.Key ?? "no answer";
    }

    // ------------------------------------------------------------------ bits

    private static string NoQuery(string url) => url.IndexOf('?') is int q and >= 0 ? url[..q] : url;

    internal static string Ms(double ms) => ms < 10 ? $"{ms.ToString("0.#", CultureInfo.InvariantCulture)} ms" : $"{Math.Round(ms).ToString(CultureInfo.InvariantCulture)} ms";

    // details quote what servers said (a status line, a Server header, a certificate's issuer, check-host.net's
    // answers): control / bidi characters replaced, and capped
    private static string Cap(string s) => RemoteText.Clean(s, 240);

    // ------------------------------------------------------------------ the granular trace (sub-steps under each check)

    // One sub-step under a check: a short step label and a one-line finding, so the user sees exactly where it stuck.
    private static void Tr(IDoctorSink sink, DoctorCheck c, DoctorState st, string step, string detail, double? ms = null)
        => sink.Trace(c, st, step, Cap(detail), ms);

    // DNS: every resolver's records, named and classed (a filter / private answer, a forged reply, NXDOMAIN, a timeout).
    private static void TraceDns(IDoctorSink sink, DoctorFacts f)
    {
        foreach (var a in f.Doh)
        {
            if (a.Good && a.Addresses.Count > 0) Tr(sink, DoctorCheck.DnsEncrypted, DoctorState.Ok, a.Source, DoctorIp.List(a.Addresses, 4), a.Ms);
            else if (a.NoSuchName) Tr(sink, DoctorCheck.DnsEncrypted, DoctorState.Warning, a.Source, "no such name", a.Ms);
            else Tr(sink, DoctorCheck.DnsEncrypted, DoctorState.Warning, a.Source, a.Error ?? "no answer", a.Ms);
        }
        if (f.Sys is { } sys)
        {
            if (!sys.Answered) Tr(sink, DoctorCheck.DnsSystem, DoctorState.Fail, "query", sys.Error ?? "no answer", sys.Ms);
            else if (sys.NoSuchName) Tr(sink, DoctorCheck.DnsSystem, f.NameMissing ? DoctorState.Fail : DoctorState.Warning, "answer", "no such name (NXDOMAIN)", sys.Ms);
            else if (sys.Addresses.Count == 0) Tr(sink, DoctorCheck.DnsSystem, DoctorState.Warning, "answer", "no addresses", sys.Ms);
            else foreach (var a in sys.Addresses)
            {
                string? kind = DoctorIp.Kind(a);
                bool filter = DoctorIp.IsKnownFilter(a);
                Tr(sink, DoctorCheck.DnsSystem, filter || (kind != null && f.SysTampered) ? DoctorState.Fail : kind != null ? DoctorState.Warning : DoctorState.Ok,
                   a.AddressFamily == AddressFamily.InterNetworkV6 ? "AAAA" : "A",
                   a + (filter ? " — the filter's block-page address" : kind != null ? $" — {kind}, not a public site" : ""));
            }
        }
        foreach (var p in f.Plain)
        {
            if (p.Injected) Tr(sink, DoctorCheck.DnsPlain, DoctorState.Fail, p.Source, $"forged {DoctorIp.List(p.Addresses)} first, then the real {DoctorIp.List(p.Later)} — injected on the way", p.Ms);
            else if (!p.Answered) Tr(sink, DoctorCheck.DnsPlain, DoctorState.Warning, p.Source, p.Error ?? "no reply", p.Ms);
            else if (p.NoSuchName) Tr(sink, DoctorCheck.DnsPlain, DoctorState.Warning, p.Source, "no such name", p.Ms);
            else
            {
                bool bad = p.Addresses.Any(a => !DoctorIp.IsPublic(a));
                Tr(sink, DoctorCheck.DnsPlain, bad ? DoctorState.Fail : DoctorState.Ok, p.Source, DoctorIp.List(p.Addresses, 4) + (bad ? " — forged" : ""), p.Ms);
            }
        }
    }

    // "refused (RST)" / "timed out (dropped)" / "unreachable" — the granular form of a failed TCP attempt.
    private static string SaysLong(DoctorConnectAttempt a) => a.Code switch
    {
        SocketError.ConnectionRefused => "refused (RST — nothing listening or a firewall rejects it)",
        SocketError.TimedOut => "timed out (dropped — no SYN/ACK, silently blocked)",
        SocketError.ConnectionReset => "reset (RST)",
        SocketError.HostUnreachable or SocketError.NetworkUnreachable => "unreachable (no route)",
        _ => a.Error ?? "no answer",
    };
}
