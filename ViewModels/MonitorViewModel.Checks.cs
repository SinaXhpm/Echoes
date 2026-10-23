using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

/// <summary>One warning of a monitor. <see cref="Signature"/> tells a new warning from one already alerted.</summary>
public sealed record MonitorWarning(string Kind, string Text, string Signature);

/// <summary>The certificate state of one host:port, shared by every https monitor on it (UI thread).</summary>
internal sealed class MonitorCertEntry
{
    public MonitorCertResult? Result;   // the last verdict (a check without one keeps the previous)
    public DateTime NextDueUtc;
    public bool InFlight;
    public string? LastNetError;        // the last check couldn't connect (no verdict)
}

/// <summary>The registration state of one domain, shared by every monitor under it (UI thread).</summary>
internal sealed class MonitorDomainEntry
{
    public DateTime? CheckedUtc;
    public DateTime? ExpiresUtc;        // kept across failed lookups
    public MonitorRdapOutcome? Outcome; // of the last lookup; null = never looked up
    public DateTime NextDueUtc;
    public bool InFlight;
}

// ============================================================================ the monitor's extras

public sealed partial class MonitorTarget
{
    // ---- its own rules (opt-in; persisted in monitor.targetOptions) ----
    internal string? Keyword;                  // null = no keyword rule
    internal bool KeywordMustContain = true;
    internal MonitorDnsKind DnsWatch;
    internal string[]? DnsBaseline;            // the accepted answers
    internal string[]? DnsCurrent;             // the latest lookup
    internal DateTime? DnsCheckedAt;
    internal long DnsNextDue;                  // Environment.TickCount64
    internal bool DnsInFlight;

    // ---- automatic ----
    internal MonitorCertEntry? Cert;           // https monitors
    internal MonitorDomainEntry? DomainInfo;   // monitors with a registrable domain
    internal string? Domain;
    /// <summary>Current warnings, in a fixed order (certificate, domain, DNS).</summary>
    internal List<MonitorWarning> Warnings = new();
    /// <summary>Signatures of the warnings already alerted (persisted: a restart doesn't alert them again).</summary>
    internal readonly HashSet<string> Alerted = new(StringComparer.Ordinal);
    /// <summary>The UTC day the warnings were last worked out. What they depend on changes only when a slow check
    /// finishes (which works them out again) or the day turns ("expires in 3 days"), so a round re-checks them only on a
    /// new day, not every few seconds for every monitor. default = not yet.</summary>
    internal DateTime WarningsDay;

    internal string? CertKey => Endpoint.IsHttps ? Endpoint.Host.ToLowerInvariant() + ":" + Endpoint.Port : null;
    internal bool HasKeyword => !string.IsNullOrEmpty(Keyword) && Endpoint.HasHttp;
    internal bool CanWatchDns => !IPAddress.TryParse(Endpoint.Host, out _);

    /// <summary>The checks as they apply to this monitor: a keyword rule needs the HTTP check, on even when it is off for all.</summary>
    internal MonitorCheckOptions Eff(MonitorCheckOptions o) => HasKeyword && !o.Http ? o with { Http = true } : o;

    /// <summary>Up, with at least one warning (amber; not downtime).</summary>
    [ObservableProperty] private bool _isWarning;
    /// <summary>Up, no warning: the green pill.</summary>
    [ObservableProperty] private bool _isGreen;
    /// <summary>Failing below the threshold, or up with a warning: the amber pill / dot.</summary>
    [ObservableProperty] private bool _isAmber;
    [ObservableProperty] private bool _summaryWarn;

    // Row chips for the slow checks: "Cert 23 d", "Domain 12 d", "DNS changed".
    [ObservableProperty] private bool _showCert;
    [ObservableProperty] private string _certText = string.Empty;
    [ObservableProperty] private string _certTip = string.Empty;
    [ObservableProperty] private bool _certWarn;
    [ObservableProperty] private bool _certFailed;
    [ObservableProperty] private bool _showDomainChip;
    [ObservableProperty] private string _domainChipText = string.Empty;
    [ObservableProperty] private bool _showDnsChip;
    [ObservableProperty] private string _dnsChipTip = string.Empty;

    /// <summary>Refreshes the slow checks' chips from the shared certificate / domain state and the DNS watch.</summary>
    internal void RefreshExtraChips(DateTime nowUtc)
    {
        if (Cert?.Result is { Reached: true } c)
        {
            ShowCert = true;
            if (c.Problem is not null)
            {
                CertText = c.NotAfterUtc is { } na && na < nowUtc ? "Cert expired" : "Cert invalid";
                CertFailed = true;
                CertWarn = false;
                CertTip = c.Problem;
            }
            else if (c.NotAfterUtc is { } na)
            {
                int days = MonitorChecks.DaysLeft(na, nowUtc);
                CertText = $"Cert {Math.Max(0, days)} d";
                CertFailed = false;
                CertWarn = days <= MonitorChecks.CertWarnDays;
                CertTip = $"TLS certificate expires {MonitorChecks.InDays(days)} ({MonitorChecks.ShortDate(na)})";
            }
        }
        else ShowCert = false;

        var domainWarning = Warnings.FirstOrDefault(w => w.Kind == "domain");
        ShowDomainChip = domainWarning is not null && DomainInfo?.ExpiresUtc is not null;
        if (ShowDomainChip && DomainInfo?.ExpiresUtc is { } exp)
        {
            int days = MonitorChecks.DaysLeft(exp, nowUtc);
            DomainChipText = days < 0 ? "Domain expired" : $"Domain {days} d";
        }
        var dns = Warnings.FirstOrDefault(w => w.Kind == "dns");
        ShowDnsChip = dns is not null;
        DnsChipTip = dns is null ? string.Empty : dns.Text + " — accept the new answers in the details";
    }
}

// ============================================================================ the detail panel's extras

public sealed partial class MonitorDetail
{
    [ObservableProperty] private bool _showCertLine;
    [ObservableProperty] private string _certLine = string.Empty;
    [ObservableProperty] private bool _certLineWarn;
    [ObservableProperty] private bool _certLineFailed;
    [ObservableProperty] private bool _showDomainLine;
    [ObservableProperty] private string _domainLine = string.Empty;
    [ObservableProperty] private bool _domainLineWarn;
    [ObservableProperty] private string _dnsLine = string.Empty;
    [ObservableProperty] private bool _dnsLineWarn;
    [ObservableProperty] private string _keywordLine = string.Empty;
    [ObservableProperty] private bool _hasWarnings;
    [ObservableProperty] private string _warningText = string.Empty;
    [ObservableProperty] private bool _canAcceptDns;

    internal void UpdateExtras(MonitorTarget t)
    {
        var now = DateTime.UtcNow;
        HasWarnings = t.Warnings.Count > 0;
        WarningText = string.Join("\n", t.Warnings.Select(w => w.Text));
        CanAcceptDns = t.Warnings.Any(w => w.Kind == "dns");

        // TLS certificate (https monitors)
        ShowCertLine = t.Cert is not null;
        CertLineWarn = CertLineFailed = false;
        if (t.Cert is { } ce)
        {
            if (ce.Result is { Reached: true } c)
            {
                if (c.Problem is not null) { CertLine = c.Problem; CertLineFailed = true; }
                else if (c.NotAfterUtc is { } na)
                {
                    int days = MonitorChecks.DaysLeft(na, now);
                    CertLine = $"Expires {MonitorChecks.ShortDate(na)} · {MonitorChecks.InDays(days)}"
                               + (c.Issuer is { Length: > 0 } iss ? " · " + iss : "");
                    CertLineWarn = days <= MonitorChecks.CertWarnDays;
                }
                else CertLine = "No expiry date";
            }
            else CertLine = ce.InFlight ? "Checking…"
                : ce.LastNetError is { } err ? $"Couldn't check ({err}) — trying again shortly"
                : "Checked while monitoring runs";
        }

        // Domain registration (RDAP)
        ShowDomainLine = t.Domain is not null;
        DomainLineWarn = false;
        if (t.Domain is { } d && t.DomainInfo is { } de)
        {
            if (de.ExpiresUtc is { } exp)
            {
                int days = MonitorChecks.DaysLeft(exp, now);
                DomainLine = days < 0 ? $"{d} · expired {-days} days ago" : $"{d} · expires {MonitorChecks.ShortDate(exp)} · {MonitorChecks.InDays(days)}";
                DomainLineWarn = days <= MonitorChecks.DomainWarnDays;
            }
            else DomainLine = de.InFlight ? $"{d} · looking it up…"
                : de.Outcome switch
                {
                    MonitorRdapOutcome.Found => $"{d} · no expiry date listed",
                    MonitorRdapOutcome.NoData => $"{d} · no RDAP record",
                    MonitorRdapOutcome.Failed => $"{d} · couldn't look it up (tries again tomorrow)",
                    _ => $"{d} · looked up once a day while monitoring runs",
                };
        }

        // DNS watch
        DnsLineWarn = CanAcceptDns;
        DnsLine = t.DnsWatch == MonitorDnsKind.Off ? (t.CanWatchDns ? "Not watched" : "Not for an IP address")
            : CanAcceptDns ? "Changed — " + t.Warnings.First(w => w.Kind == "dns").Text["DNS changed: ".Length..]
            : t.DnsBaseline is { } b ? $"{KindName(t.DnsWatch)} · {b.Length} answer{(b.Length == 1 ? "" : "s")} accepted"
              + (b.Length is > 0 and <= 2 ? ": " + string.Join(", ", b) : "")
            : $"{KindName(t.DnsWatch)} · waiting for the first lookup";

        KeywordLine = !t.Endpoint.HasHttp ? "Only for web monitors"
            : !t.HasKeyword ? "None"
            : (t.KeywordMustContain ? "Must contain “" : "Must not contain “") + t.Keyword + "”";
    }

    internal static string KindName(MonitorDnsKind k) => k switch
    {
        MonitorDnsKind.Address => "A/AAAA",
        MonitorDnsKind.Cname => "CNAME",
        MonitorDnsKind.Ns => "NS",
        _ => "Off",
    };
}

// ============================================================================ the view-model's part

public sealed partial class MonitorViewModel
{
    private const string KeyTargetOptions = "monitor.targetOptions", KeyExtraCache = "monitor.extraCache";
    private const int MaxConcurrentExtras = 4;

    private readonly Dictionary<string, MonitorCertEntry> _certs = new(StringComparer.Ordinal);
    private readonly Dictionary<string, MonitorDomainEntry> _domains = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _extraGate = new(MaxConcurrentExtras);

    // Diagnostics / tests: how many slow checks finished.
    internal int CertChecksRun { get; private set; }
    internal int DomainChecksRun { get; private set; }
    internal int DnsChecksRun { get; private set; }

    // ---- per-monitor edit (the detail panel) ----
    [ObservableProperty] private bool _isEditingChecks;
    [ObservableProperty] private string _editKeyword = string.Empty;
    [ObservableProperty] private int _editKeywordModeIndex;   // 0 must contain, 1 must not contain
    [ObservableProperty] private int _editDnsIndex;           // MonitorDnsKind
    [ObservableProperty] private bool _canEditKeyword;
    [ObservableProperty] private bool _canEditDns;
    [ObservableProperty] private string _editChecksNote = string.Empty;

    public bool HasEditChecksNote => EditChecksNote.Length > 0;
    partial void OnEditChecksNoteChanged(string value) => OnPropertyChanged(nameof(HasEditChecksNote));

    /// <summary>Points a monitor at the shared certificate / domain state (created on first use).</summary>
    private void LinkExtras(MonitorTarget t)
    {
        if (t.CertKey is { } ck)
        {
            if (!_certs.TryGetValue(ck, out var ce)) _certs[ck] = ce = new MonitorCertEntry();
            t.Cert = ce;
        }
        t.Domain = MonitorChecks.RegistrableDomain(t.Endpoint.Host);
        if (t.Domain is { } d)
        {
            if (!_domains.TryGetValue(d, out var de)) _domains[d] = de = new MonitorDomainEntry();
            t.DomainInfo = de;
        }
        t.WarningsDay = default;   // worked out again on its next round
        t.RefreshExtraChips(DateTime.UtcNow);
    }

    /// <summary>A new run: certificates that failed, or couldn't be checked, are looked at again right away.</summary>
    private void BeginExtrasRun()
    {
        var now = DateTime.UtcNow;
        foreach (var ce in _certs.Values)
            if (ce.Result is null || ce.Result.Problem is not null) ce.NextDueUtc = now;
        foreach (var t in Targets) t.DnsNextDue = 0;
    }

    private MonitorProbeSpec SpecFor(MonitorTarget t) => new(t.Endpoint)
    {
        ForceHttp = t.HasKeyword,
        Keyword = t.HasKeyword ? t.Keyword : null,
        KeywordMustContain = t.KeywordMustContain,
        CertProblem = t.Cert?.Result?.Problem,
    };

    // The round's HTTPS request vouched for a certificate the last check had failed: look again now.
    private void RecheckCertSoon(MonitorTarget t)
    {
        if (t.Cert is { InFlight: false } ce) ce.NextDueUtc = DateTime.UtcNow;
        Wake();
    }

    // UI thread, at the top of every loop pass: start whatever slow check is due (each runs on its own, gated). Returns
    // the checks of certificates never looked at before: the caller lets those finish (bounded) before the round, so an
    // expired certificate's first "down" already names it instead of the HTTPS request's "TLS error".
    private List<Task>? ScheduleExtraChecks(CancellationToken token)
    {
        var nowUtc = DateTime.UtcNow;
        long tick = Environment.TickCount64;
        int timeout = Math.Clamp(TimeoutMs, MonitorProbe.MinTimeoutMs, MonitorProbe.MaxTimeoutMs);
        List<Task>? first = null;
        foreach (var t in Targets)
        {
            if (t.IsPaused || t.Removed) continue;
            if (t.Cert is { InFlight: false } ce && nowUtc >= ce.NextDueUtc)
            {
                ce.InFlight = true;
                bool never = ce.Result is null && ce.LastNetError is null;
                var task = RunCertCheckAsync(ce, t.Endpoint.Host, t.Endpoint.Port, timeout, token);
                if (never) (first ??= new List<Task>()).Add(task);
            }
            if (t.Domain is { } d && t.DomainInfo is { InFlight: false } de && nowUtc >= de.NextDueUtc)
            {
                de.InFlight = true;
                _ = RunDomainCheckAsync(d, de, token);
            }
            if (t.DnsWatch != MonitorDnsKind.Off && t.CanWatchDns && !t.DnsInFlight && tick >= t.DnsNextDue)
            {
                t.DnsInFlight = true;
                _ = RunDnsCheckAsync(t, t.DnsWatch, token);
            }
        }
        return first;
    }

    private async Task RunCertCheckAsync(MonitorCertEntry ce, string host, int port, int timeoutMs, CancellationToken token)
    {
        MonitorCertResult? r = null;
        try
        {
            await _extraGate.WaitAsync(token);
            try { r = await Task.Run(() => MonitorChecks.CheckCertAsync(host, port, Math.Max(timeoutMs * 2, 5000), token), token); }
            finally { _extraGate.Release(); }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { CrashLog.Write("Monitor.Cert", ex); }
        finally { ce.InFlight = false; }
        if (r is null || token.IsCancellationRequested) return;   // stopped: the next run looks again

        CertChecksRun++;
        var now = DateTime.UtcNow;
        if (!r.Reached)
        {
            ce.LastNetError = r.NetError;
            ce.NextDueUtc = now + MonitorChecks.CertRetryEvery;   // keep the previous verdict
        }
        else
        {
            ce.LastNetError = null;
            ce.Result = r;
            ce.NextDueUtc = now + (r.Problem is null ? MonitorChecks.CertEvery : MonitorChecks.CertFailingEvery);
            PersistExtraCache();
        }
        ExtrasChanged(t => ReferenceEquals(t.Cert, ce));
    }

    private async Task RunDomainCheckAsync(string domain, MonitorDomainEntry de, CancellationToken token)
    {
        MonitorRdapResult? r = null;
        try
        {
            await _extraGate.WaitAsync(token);
            try { r = await Task.Run(() => MonitorChecks.FetchDomainExpiryAsync(domain, token), token); }
            finally { _extraGate.Release(); }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { CrashLog.Write("Monitor.Rdap", ex); }
        finally { de.InFlight = false; }
        if (r is not { } res || token.IsCancellationRequested) return;

        DomainChecksRun++;
        var now = DateTime.UtcNow;
        // Once a day, whatever the outcome; a failed lookup keeps what was known (and never alarms).
        de.CheckedUtc = now;
        de.NextDueUtc = now + MonitorChecks.DomainEvery;
        de.Outcome = res.Outcome;
        if (res.Outcome != MonitorRdapOutcome.Failed) de.ExpiresUtc = res.ExpiresUtc;
        PersistExtraCache();
        ExtrasChanged(t => ReferenceEquals(t.DomainInfo, de));
    }

    private async Task RunDnsCheckAsync(MonitorTarget t, MonitorDnsKind kind, CancellationToken token)
    {
        string[]? answers = null;
        try
        {
            await _extraGate.WaitAsync(token);
            try { answers = await Task.Run(() => MonitorChecks.ResolveAsync(t.Endpoint.Host, kind, token), token); }
            finally { _extraGate.Release(); }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { CrashLog.Write("Monitor.DnsWatch", ex); }
        finally
        {
            t.DnsInFlight = false;
            t.DnsNextDue = Environment.TickCount64 + (long)Math.Max(MonitorChecks.DnsEvery.TotalMilliseconds, IntervalSeconds * 1000L);
        }
        if (token.IsCancellationRequested || t.Removed || t.DnsWatch != kind) return;   // stopped / changed meanwhile
        DnsChecksRun++;
        if (answers is null) return;   // the lookup failed: silent (the regular checks report a name that doesn't resolve)

        t.DnsCurrent = answers;
        t.DnsCheckedAt = DateTime.Now;
        if (t.DnsBaseline is null)
        {
            t.DnsBaseline = answers;   // the first answers are the accepted ones
            PersistTargets();
        }
        ExtrasChanged(x => ReferenceEquals(x, t));
    }

    // A slow check finished: warnings (with their events / alerts), chips, summary and detail of the monitors it covers.
    private void ExtrasChanged(Func<MonitorTarget, bool> affected)
    {
        var o = Options;
        bool anyWarning = false;
        foreach (var t in Targets)
        {
            if (!affected(t) || t.IsPaused) continue;
            if (RefreshWarnings(t, raiseEvents: true)) anyWarning = true;
            t.RefreshState(o);
        }
        // A new warning found by a slow check (certificate, domain, DNS): the soft double tap.
        if (anyWarning) PlayAlert(false, false, true);
        UpdateSummary();
        RefreshDetail();
    }

    /// <summary>
    /// Recomputes a monitor's warnings. A warning not alerted before raises a Warning event (+ Telegram); one that went
    /// away — with the data to tell — a Resolved event. Kinds without data yet (no certificate verdict, no RDAP answer,
    /// no DNS answer this session) keep what was alerted, so a restart neither re-alerts nor falsely clears them.
    /// True when a new warning was raised (an event + alert: the caller plays the warning sound).
    /// </summary>
    internal bool RefreshWarnings(MonitorTarget t, bool raiseEvents, string? dnsResolvedText = null)
    {
        bool raised = false;
        var now = DateTime.UtcNow;
        var fresh = new List<MonitorWarning>(3);
        var known = new HashSet<string>(StringComparer.Ordinal);

        if (t.Cert?.Result is { Reached: true } c)
        {
            known.Add("cert");
            if (c.Problem is null && c.NotAfterUtc is { } na && MonitorChecks.DaysLeft(na, now) is var days && days <= MonitorChecks.CertWarnDays)
                fresh.Add(new MonitorWarning("cert", $"TLS certificate expires {MonitorChecks.InDays(days)} ({MonitorChecks.ShortDate(na)})", "cert"));
        }
        if (t.Domain is { } d && t.DomainInfo is { Outcome: MonitorRdapOutcome.Found or MonitorRdapOutcome.NoData } de)
        {
            known.Add("domain");
            if (de.ExpiresUtc is { } exp && MonitorChecks.DaysLeft(exp, now) is var dd && dd <= MonitorChecks.DomainWarnDays)
                fresh.Add(new MonitorWarning("domain",
                    dd < 0 ? $"Domain {d} expired {-dd} days ago" : $"Domain {d} expires {MonitorChecks.InDays(dd)} ({MonitorChecks.ShortDate(exp)})",
                    "domain"));
        }
        if (t.DnsWatch == MonitorDnsKind.Off || t.DnsCurrent is not null) known.Add("dns");
        if (t.DnsWatch != MonitorDnsKind.Off && t.DnsBaseline is { } b && t.DnsCurrent is { } cur && !MonitorChecks.SameAnswers(b, cur))
            fresh.Add(new MonitorWarning("dns", "DNS changed: " + MonitorChecks.DescribeChange(b, cur), "dns:" + string.Join(",", cur)));

        // Kinds without data keep their previous warning (display) as they were.
        foreach (var old in t.Warnings)
            if (!known.Contains(old.Kind) && !fresh.Any(w => w.Kind == old.Kind)) fresh.Add(old);
        fresh.Sort((x, y) => Order(x.Kind).CompareTo(Order(y.Kind)));

        bool persist = false;
        foreach (var w in fresh)
        {
            if (t.Alerted.Contains(w.Signature)) continue;
            // A DNS change that moves on to other answers replaces the alerted one.
            t.Alerted.RemoveWhere(s => Kind(s) == w.Kind);
            t.Alerted.Add(w.Signature);
            persist = true;
            if (raiseEvents)
            {
                AddEvent(t, MonitorEventKind.Warning, w.Text);
                Alert(MonitorAlertKind.Warning, t, w.Text, DateTime.Now);
                raised = true;
            }
        }
        foreach (var sig in t.Alerted.ToList())
        {
            string kind = Kind(sig);
            if (!known.Contains(kind) || fresh.Any(w => w.Kind == kind)) continue;
            t.Alerted.Remove(sig);
            persist = true;
            if (raiseEvents) AddEvent(t, MonitorEventKind.Resolved, ResolvedText(t, kind, dnsResolvedText));
        }
        t.Warnings = fresh;
        t.WarningsDay = now.Date;
        t.RefreshExtraChips(now);
        if (persist) PersistTargets();
        return raised;

        static int Order(string kind) => kind switch { "cert" => 0, "domain" => 1, _ => 2 };
        static string Kind(string sig) { int i = sig.IndexOf(':'); return i < 0 ? sig : sig[..i]; }
    }

    private static string ResolvedText(MonitorTarget t, string kind, string? dnsText)
    {
        var now = DateTime.UtcNow;
        switch (kind)
        {
            case "cert" when t.Cert?.Result is { Problem: null, NotAfterUtc: { } na }:
                return $"TLS certificate renewed · expires {MonitorChecks.InDays(MonitorChecks.DaysLeft(na, now))}";
            case "cert":
                return "Certificate warning cleared";
            case "domain" when t.DomainInfo?.ExpiresUtc is { } exp:
                return $"Domain renewed · expires {MonitorChecks.ShortDate(exp)}";
            case "domain":
                return "Domain warning cleared";
            default:
                return dnsText ?? "DNS answers are back to the accepted ones";
        }
    }

    // ================================================================ per-monitor edit (the detail panel)

    [RelayCommand]
    private void EditChecks()
    {
        if (SelectedTarget is not { } t) return;
        CanEditKeyword = t.Endpoint.HasHttp;
        CanEditDns = t.CanWatchDns;
        EditKeyword = t.Keyword ?? string.Empty;
        EditKeywordModeIndex = t.KeywordMustContain ? 0 : 1;
        EditDnsIndex = (int)t.DnsWatch;
        EditChecksNote = string.Empty;
        IsEditingChecks = true;
    }

    [RelayCommand]
    private void CancelEditChecks()
    {
        IsEditingChecks = false;
        EditChecksNote = string.Empty;
    }

    [RelayCommand]
    private void SaveChecks()
    {
        if (SelectedTarget is not { } t || t.Removed) { IsEditingChecks = false; return; }
        string kw = (EditKeyword ?? string.Empty).Trim();
        if (kw.Length > MonitorProbe.MaxKeywordLength)
        {
            EditChecksNote = $"The keyword can be at most {MonitorProbe.MaxKeywordLength} characters.";
            return;
        }
        bool mustContain = EditKeywordModeIndex != 1;
        var dns = t.CanWatchDns ? (MonitorDnsKind)Math.Clamp(EditDnsIndex, 0, 3) : MonitorDnsKind.Off;

        string? newKeyword = kw.Length == 0 || !t.Endpoint.HasHttp ? null : kw;
        bool keywordChanged = newKeyword != t.Keyword || (newKeyword is not null && mustContain != t.KeywordMustContain);
        t.Keyword = newKeyword;
        t.KeywordMustContain = mustContain;
        if (dns != t.DnsWatch)
        {
            // Another kind of answers: a new baseline from the next lookup; the old warning goes without an event.
            t.DnsWatch = dns;
            t.DnsBaseline = null;
            t.DnsCurrent = null;
            t.DnsNextDue = 0;
            t.Alerted.RemoveWhere(s => s.StartsWith("dns", StringComparison.Ordinal));
            t.Warnings = t.Warnings.Where(w => w.Kind != "dns").ToList();
        }
        IsEditingChecks = false;
        EditChecksNote = string.Empty;

        RefreshWarnings(t, raiseEvents: true);
        t.ApplyChecks(Options);
        PersistTargets();
        UpdateSummary();
        RefreshDetail();
        if (IsMonitoring)
        {
            if (keywordChanged) t.NeedsCheck = !t.IsPaused;
            Wake();
        }
    }

    /// <summary>"Accept new answers": the current DNS answers become the accepted ones; the warning clears.</summary>
    [RelayCommand]
    private void AcceptDnsAnswers(MonitorTarget? target)
    {
        var t = target ?? SelectedTarget;
        if (t is null || t.DnsCurrent is not { } current) return;
        t.DnsBaseline = current;
        RefreshWarnings(t, raiseEvents: true, dnsResolvedText: "New DNS answers accepted");
        t.RefreshState(Options);
        PersistTargets();
        UpdateSummary();
        RefreshDetail();
    }

    // ================================================================ persistence

    private static readonly JsonWriterOptions JsonOut = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    internal sealed record TargetOptions(string? Keyword, bool MustContain, MonitorDnsKind Dns, string[]? Baseline, string[] Alerted);

    /// <summary>monitor.targetOptions: { address: { kw, kwNot, dns, base[], warned[] } } — only monitors with something set.</summary>
    private string SerializeTargetOptions()
    {
        var buffer = new ArrayBufferWriter<byte>(256);
        int written = 0;
        using (var w = new Utf8JsonWriter(buffer, JsonOut))
        {
            w.WriteStartObject();
            foreach (var t in Targets)
            {
                if (!t.HasKeyword && t.DnsWatch == MonitorDnsKind.Off && t.Alerted.Count == 0) continue;
                w.WriteStartObject(t.Address);
                if (t.HasKeyword)
                {
                    w.WriteString("kw", t.Keyword);
                    if (!t.KeywordMustContain) w.WriteBoolean("kwNot", true);
                }
                if (t.DnsWatch != MonitorDnsKind.Off)
                {
                    w.WriteString("dns", t.DnsWatch switch { MonitorDnsKind.Cname => "cname", MonitorDnsKind.Ns => "ns", _ => "a" });
                    if (t.DnsBaseline is { } b)
                    {
                        w.WriteStartArray("base");
                        foreach (var s in b) w.WriteStringValue(s);
                        w.WriteEndArray();
                    }
                }
                if (t.Alerted.Count > 0)
                {
                    w.WriteStartArray("warned");
                    foreach (var s in t.Alerted.Take(8)) w.WriteStringValue(s.Length > 600 ? s[..600] : s);
                    w.WriteEndArray();
                }
                w.WriteEndObject();
                written++;
            }
            w.WriteEndObject();
        }
        return written == 0 ? string.Empty : Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    /// <summary>Reads monitor.targetOptions; a missing / damaged value is simply no options (never throws).</summary>
    internal static Dictionary<string, TargetOptions> ReadTargetOptions(string? json)
    {
        var map = new Dictionary<string, TargetOptions>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(json)) return map;
        try
        {
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 16 });
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return map;
            foreach (var p in doc.RootElement.EnumerateObject())
            {
                if (p.Value.ValueKind != JsonValueKind.Object) continue;
                var v = p.Value;
                string? kw = v.TryGetProperty("kw", out var k) && k.ValueKind == JsonValueKind.String ? k.GetString() : null;
                if (kw is { Length: > MonitorProbe.MaxKeywordLength }) kw = kw[..MonitorProbe.MaxKeywordLength];
                bool not = v.TryGetProperty("kwNot", out var kn) && kn.ValueKind == JsonValueKind.True;
                var dns = v.TryGetProperty("dns", out var dk) && dk.ValueKind == JsonValueKind.String
                    ? dk.GetString() switch { "a" => MonitorDnsKind.Address, "cname" => MonitorDnsKind.Cname, "ns" => MonitorDnsKind.Ns, _ => MonitorDnsKind.Off }
                    : MonitorDnsKind.Off;
                map[p.Name] = new TargetOptions(string.IsNullOrWhiteSpace(kw) ? null : kw, !not, dns,
                    dns == MonitorDnsKind.Off ? null : MonitorChecks.Normalize(Strings(v, "base")), Strings(v, "warned") ?? Array.Empty<string>());
            }
        }
        catch (JsonException) { }
        return map;

        static string[]? Strings(JsonElement o, string name)
        {
            if (!o.TryGetProperty(name, out var a) || a.ValueKind != JsonValueKind.Array) return null;
            var list = new List<string>();
            foreach (var e in a.EnumerateArray())
                if (e.ValueKind == JsonValueKind.String && e.GetString() is { Length: > 0 } s && list.Count < MonitorChecks.MaxDnsAnswers) list.Add(s);
            return list.ToArray();
        }
    }

    private static void ApplyTargetOptions(MonitorTarget t, TargetOptions o)
    {
        t.Keyword = o.Keyword;
        t.KeywordMustContain = o.MustContain;
        t.DnsWatch = t.CanWatchDns ? o.Dns : MonitorDnsKind.Off;
        t.DnsBaseline = t.DnsWatch == MonitorDnsKind.Off ? null : o.Baseline;
        foreach (var s in o.Alerted) t.Alerted.Add(s);
        t.WarningsDay = default;
    }

    /// <summary>
    /// monitor.extraCache: the last certificate verdicts and RDAP answers, so a restart doesn't repeat them before they are
    /// due (certificate every 6 h, RDAP once a day). Nothing secret in it.
    /// </summary>
    private void PersistExtraCache()
    {
        if (!_loaded) return;
        var usedCerts = new HashSet<string>(Targets.Select(t => t.CertKey).OfType<string>(), StringComparer.Ordinal);
        var usedDomains = new HashSet<string>(Targets.Select(t => t.Domain).OfType<string>(), StringComparer.Ordinal);
        var buffer = new ArrayBufferWriter<byte>(256);
        using (var w = new Utf8JsonWriter(buffer, JsonOut))
        {
            w.WriteStartObject();
            w.WriteStartObject("cert");
            foreach (var (key, e) in _certs)
            {
                if (!usedCerts.Contains(key) || e.Result is not { Reached: true } r) continue;
                w.WriteStartObject(key);
                w.WriteNumber("at", Unix(r.CheckedUtc));
                if (r.NotAfterUtc is { } na) w.WriteNumber("na", Unix(na));
                if (r.NotBeforeUtc is { } nb) w.WriteNumber("nb", Unix(nb));
                if (r.Issuer is { } iss) w.WriteString("iss", iss);
                if (r.Problem is { } p) w.WriteString("p", p);
                w.WriteEndObject();
            }
            w.WriteEndObject();
            w.WriteStartObject("rdap");
            foreach (var (key, e) in _domains)
            {
                if (!usedDomains.Contains(key) || e.CheckedUtc is not { } at || e.Outcome is not { } outcome) continue;
                w.WriteStartObject(key);
                w.WriteNumber("at", Unix(at));
                if (e.ExpiresUtc is { } exp) w.WriteNumber("exp", Unix(exp));
                w.WriteNumber("o", (int)outcome);
                w.WriteEndObject();
            }
            w.WriteEndObject();
            w.WriteEndObject();
        }
        ProfileService.Instance.SetSetting(KeyExtraCache, Encoding.UTF8.GetString(buffer.WrittenSpan));
    }

    private void LoadExtraCache(ProfileService ps)
    {
        string? json = ps.GetSetting(KeyExtraCache);
        if (string.IsNullOrWhiteSpace(json)) return;
        var now = DateTime.UtcNow;
        try
        {
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 16 });
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return;
            if (root.TryGetProperty("cert", out var certs) && certs.ValueKind == JsonValueKind.Object)
            {
                foreach (var p in certs.EnumerateObject())
                {
                    var v = p.Value;
                    if (v.ValueKind != JsonValueKind.Object || Time(v, "at") is not { } at || at > now) continue;
                    string? problem = Text(v, "p");
                    _certs[p.Name] = new MonitorCertEntry
                    {
                        Result = new MonitorCertResult
                        {
                            CheckedUtc = at, Reached = true, NotAfterUtc = Time(v, "na"), NotBeforeUtc = Time(v, "nb"),
                            Issuer = Text(v, "iss"), Problem = problem,
                        },
                        NextDueUtc = at + (problem is null ? MonitorChecks.CertEvery : MonitorChecks.CertFailingEvery),
                    };
                }
            }
            if (root.TryGetProperty("rdap", out var rdap) && rdap.ValueKind == JsonValueKind.Object)
            {
                foreach (var p in rdap.EnumerateObject())
                {
                    var v = p.Value;
                    if (v.ValueKind != JsonValueKind.Object || Time(v, "at") is not { } at || at > now) continue;
                    int o = v.TryGetProperty("o", out var oe) && oe.TryGetInt32(out int oi) ? oi : (int)MonitorRdapOutcome.Failed;
                    _domains[p.Name] = new MonitorDomainEntry
                    {
                        CheckedUtc = at, ExpiresUtc = Time(v, "exp"),
                        Outcome = (MonitorRdapOutcome)Math.Clamp(o, 0, 2),
                        NextDueUtc = at + MonitorChecks.DomainEvery,
                    };
                }
            }
        }
        catch (JsonException) { }

        static DateTime? Time(JsonElement o, string name)
            => o.TryGetProperty(name, out var e) && e.ValueKind == JsonValueKind.Number && e.TryGetInt64(out long s)
               && s is > 0 and < 253_402_300_799 ? DateTimeOffset.FromUnixTimeSeconds(s).UtcDateTime : null;
        static string? Text(JsonElement o, string name)
            => o.TryGetProperty(name, out var e) && e.ValueKind == JsonValueKind.String && e.GetString() is { Length: > 0 and <= 300 } s ? s : null;
    }

    private static long Unix(DateTime utc) => new DateTimeOffset(DateTime.SpecifyKind(utc, DateTimeKind.Utc)).ToUnixTimeSeconds();
}
