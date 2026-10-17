using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

/// <summary>A label / value line of the result (with how good or bad the value is).</summary>
public sealed class TlsFact
{
    public TlsFact(string label, string value, TlsSeverity severity = TlsSeverity.Info, string? tip = null)
    {
        Label = label;
        Value = value;
        Severity = severity;
        Tip = tip ?? value;
    }

    public string Label { get; }
    public string Value { get; }
    public TlsSeverity Severity { get; }
    public string Tip { get; }
    public bool IsOk => Severity == TlsSeverity.Ok;
    public bool IsWarn => Severity == TlsSeverity.Warning;
    public bool IsBad => Severity == TlsSeverity.Error;
}

/// <summary>One TLS version's test, as a chip.</summary>
public sealed class TlsVersionChip
{
    public TlsVersionChip(TlsVersionResult r)
    {
        Name = r.Name;
        Supported = r.Supported;
        Detail = $"{r.Name}: {r.Detail}";
        bool old = r.Version <= TlsHello.Tls11;
        IsGood = r.Supported == true && !old;
        IsOld = r.Supported == true && old;
        IsOff = r.Supported == false;
        IsUnknown = r.Supported == null;
    }

    public string Name { get; }
    public bool? Supported { get; }
    public bool IsSupported => Supported == true;
    public string Detail { get; }
    public bool IsGood { get; }
    public bool IsOld { get; }
    public bool IsOff { get; }
    public bool IsUnknown { get; }
}

/// <summary>A certificate of the chain, ready to show (and to copy as PEM).</summary>
public sealed partial class TlsCertView : ObservableObject
{
    public TlsCertView(TlsChainCert cc, int index, int count, DateTime utcNow)
    {
        var c = cc.Cert;
        Cert = c;
        bool self = TlsCertificates.IsSelfIssued(c);
        Role = index == 0 ? (count == 1 && self ? "Self-signed" : "Leaf")
             : index == count - 1 && self ? "Root" : "Intermediate";
        Name = TlsCertificates.ShortName(c);
        Organization = TlsCertificates.DnPart(c.SubjectName, "O");
        Issuer = TlsCertificates.IssuerText(c);
        Subject = c.Subject;
        ValidFrom = TlsCertificates.DateTimeUtc(c.NotBefore);
        ValidTo = TlsCertificates.DateTimeUtc(c.NotAfter);
        ExpiryText = TlsCertificates.ExpiryPhrase(c, utcNow);
        ExpirySeverity = TlsCertificates.ExpirySeverity(c, utcNow);
        var sans = TlsCertificates.Sans(c);
        Sans = sans.Count == 0 ? "—" : string.Join(", ", sans);
        HasSans = sans.Count > 0;
        SanCount = sans.Count;
        Key = TlsCertificates.KeyText(c);
        Signature = TlsCertificates.SignatureText(c);
        Serial = TlsCertificates.Serial(c);
        Sha256 = TlsCertificates.Sha256(c);
        Sha1 = TlsCertificates.Sha1(c);
        Source = index == 0 ? "Sent by the server" : cc.FromServer ? "Sent by the server" : "From this system's trust store";
        IsCa = TlsCertificates.IsCa(c);
        IsExpanded = index == 0;   // the leaf opens; the CA certificates show their one-line summary
    }

    internal X509Certificate2 Cert { get; }
    public string Role { get; }
    public string Name { get; }
    public string Organization { get; }
    public bool HasOrganization => Organization.Length > 0 && Organization != Name;
    /// <summary>The card's second line: "Example Inc · issued by DigiCert …".</summary>
    public string HeaderSub => (HasOrganization ? Organization + " · " : string.Empty) + "issued by " + Issuer;
    public string Issuer { get; }
    public string Subject { get; }
    public string ValidFrom { get; }
    public string ValidTo { get; }
    public string Validity => $"{ValidFrom} → {ValidTo}";
    public string ExpiryText { get; }
    public TlsSeverity ExpirySeverity { get; }
    public bool ExpiryOk => ExpirySeverity == TlsSeverity.Ok;
    public bool ExpiryWarn => ExpirySeverity == TlsSeverity.Warning;
    public bool ExpiryBad => ExpirySeverity == TlsSeverity.Error;
    public string Sans { get; }
    public bool HasSans { get; }
    public int SanCount { get; }
    public string SansLabel => SanCount > 1 ? $"Names ({SanCount})" : "Names";
    public string Key { get; }
    public string Signature { get; }
    public string KeyAndSignature => $"{Key} · signed with {Signature}";
    public string Serial { get; }
    public string Sha256 { get; }
    public string Sha1 { get; }
    public string Source { get; }
    public bool IsCa { get; }
    public bool IsLeaf => Role is "Leaf" or "Self-signed";

    [ObservableProperty] private bool _isExpanded;

    [RelayCommand]
    private void ToggleExpanded() => IsExpanded = !IsExpanded;

    [RelayCommand]
    private Task CopyPem() => ClipboardHelper.SetTextAsync(TlsCertificates.Pem(Cert));

    [RelayCommand]
    private Task CopyFingerprint() => ClipboardHelper.SetTextAsync(Sha256);
}

/// <summary>A row of the bulk check.</summary>
public sealed partial class TlsBulkRow : ObservableObject
{
    public TlsBulkRow(string target, string host, int port, string? parseError)
    {
        Target = target;
        Host = host;
        Port = port;
        if (parseError != null)
        {
            IsValid = false;
            StatusText = parseError;
            Severity = TlsSeverity.Error;
            Detail = parseError;
        }
    }

    private string? _expiryPhrase;

    /// <summary>The phone layout's second line: "2026-01-15 · 94 days left · issuer".</summary>
    public string SubLine => _expiryPhrase != null
        ? $"{ExpiresText} · {_expiryPhrase} · {Issuer}"
        : Protocol.Length > 0 ? Protocol : "—";

    /// <summary>The days cell tinted: amber inside the warning window, red once expired.</summary>
    public bool DaysWarn => DaysLeft is int d && d >= 0 && d < TlsCertificates.ExpiryWarningDays;
    public bool DaysBad => DaysLeft is int d && (d < 0 || _expiryPhrase?.StartsWith("expired", StringComparison.Ordinal) == true);

    public string Target { get; }
    public string Host { get; }
    public int Port { get; }
    public bool IsValid { get; } = true;
    public string Endpoint => Port == TlsInspector.DefaultPort ? Host : SocketNet.Target(Host, Port);

    [ObservableProperty] private string _statusText = "Waiting";
    [ObservableProperty] private string _detail = string.Empty;
    [ObservableProperty] private string _expiresText = "—";
    [ObservableProperty] private string _daysText = "—";
    [ObservableProperty] private string _issuer = "—";
    [ObservableProperty] private string _protocol = string.Empty;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsOk), nameof(IsWarn), nameof(IsBad), nameof(IsPending))]
    private TlsSeverity _severity = TlsSeverity.Info;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsPending))]
    private bool _done;

    public DateTime? Expires { get; private set; }
    public int? DaysLeft { get; private set; }

    public bool IsOk => Done && Severity == TlsSeverity.Ok;
    public bool IsWarn => Done && Severity == TlsSeverity.Warning;
    public bool IsBad => (Done || !IsValid) && Severity == TlsSeverity.Error;
    public bool IsPending => !Done && IsValid;

    internal void Checking() => StatusText = "Checking…";

    internal void Apply(TlsReport r)
    {
        var now = DateTime.UtcNow;
        if (r.Leaf is { } leaf)
        {
            Expires = leaf.NotAfter.ToUniversalTime();
            DaysLeft = TlsCertificates.DaysLeft(leaf, now);
            _expiryPhrase = TlsCertificates.ExpiryPhrase(leaf, now);
            ExpiresText = TlsCertificates.Date(leaf.NotAfter);
            DaysText = DaysLeft.Value.ToString(CultureInfo.InvariantCulture);
            Issuer = TlsCertificates.IssuerText(leaf);
            OnPropertyChanged(nameof(DaysWarn));
            OnPropertyChanged(nameof(DaysBad));
        }
        Protocol = r.Protocol ?? string.Empty;
        var worst = r.Problems.FirstOrDefault();
        if (r.Error != null)
        {
            StatusText = Short(r.Error);
            Detail = r.Error;
            Severity = TlsSeverity.Error;
        }
        else if (worst != null)
        {
            StatusText = Short(worst.Text);
            Detail = string.Join("\n", r.Problems.Select(p => p.Text));
            Severity = r.Verdict;
        }
        else
        {
            StatusText = "Valid";
            Detail = $"Trusted · {r.Protocol}" + (DaysLeft is int d ? $" · {TlsCertificates.Plural(d, "day")} left" : "");
            Severity = TlsSeverity.Ok;
        }
        Done = true;
        OnPropertyChanged(nameof(SubLine));
    }

    internal void Fail(string message)
    {
        StatusText = Short(message);
        Detail = message;
        Severity = TlsSeverity.Error;
        Done = true;
        OnPropertyChanged(nameof(SubLine));
    }

    // the first clause of a sentence: "Name mismatch — the certificate is for …" → "Name mismatch"
    private static string Short(string s)
    {
        int cut = s.IndexOf(" — ", StringComparison.Ordinal);
        string head = cut > 0 ? s[..cut] : s;
        if (head.StartsWith("The certificate expired", StringComparison.Ordinal)) return "Expired";
        if (head.StartsWith("The certificate isn't valid yet", StringComparison.Ordinal)) return "Not valid yet";
        if (head.StartsWith("Expires soon", StringComparison.Ordinal)) return "Expires soon";
        return head.Length > 48 ? head[..47].TrimEnd() + "…" : head.TrimEnd('.');
    }
}

/// <summary>
/// The TLS inspector: one endpoint in depth (handshake, chain, verdict, versions, staple, revocation, HSTS) or many
/// endpoints in bulk (expiry, issuer, status — a bounded number at a time).
/// </summary>
public partial class TlsViewModel : ObservableObject
{
    private const string HTarget = "tls.target";
    private const string KBulk = "tls.bulk", KTab = "tls.tab", KSni = "tls.sni", KStartTls = "tls.starttls";
    private const int BulkConcurrency = 8;
    private const int BulkMax = 500;

    private readonly bool _restoring;
    private CancellationTokenSource? _cts;
    private CancellationTokenSource? _bulkCts;
    private TlsReport? _report;

    // ---------------- inspect ----------------
    [ObservableProperty] private int _tabIndex;
    [ObservableProperty] private string _target = string.Empty;
    [ObservableProperty] private string _sni = string.Empty;
    [ObservableProperty] private int _startTlsIndex;
    public string[] StartTlsOptions { get; } = { "Automatic", "None", "SMTP", "IMAP", "POP3", "FTP" };
    public ObservableCollection<string> TargetHistory => HistoryService.Instance.Get(HTarget);

    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string _progress = string.Empty;
    [ObservableProperty] private bool _hasResult;
    [ObservableProperty] private string? _error;
    [ObservableProperty] private string? _errorDetail;

    // result
    [ObservableProperty] private string _verdictText = string.Empty;
    [ObservableProperty] private TlsSeverity _verdict;
    [ObservableProperty] private string _endpointText = string.Empty;
    [ObservableProperty] private string _addressText = string.Empty;
    [ObservableProperty] private string _summaryText = string.Empty;
    public ObservableCollection<TlsProblem> Problems { get; } = new();
    public ObservableCollection<TlsFact> Facts { get; } = new();
    public ObservableCollection<TlsVersionChip> Versions { get; } = new();
    public ObservableCollection<TlsCertView> Chain { get; } = new();
    [ObservableProperty] private string _chainNote = string.Empty;

    // ---------------- bulk ----------------
    [ObservableProperty] private string _bulkInput = string.Empty;
    public ObservableCollection<TlsBulkRow> BulkRows { get; } = new();
    [ObservableProperty] private bool _isBulkBusy;
    [ObservableProperty] private string _bulkStatus = string.Empty;
    [ObservableProperty] private string? _bulkError;
    private string _sortColumn = string.Empty;
    private bool _sortDesc;

    public TlsViewModel()
    {
        _restoring = true;
        var p = ProfileService.Instance;
        TabIndex = Math.Clamp(p.GetInt(KTab, 0), 0, 1);
        BulkInput = p.GetSetting(KBulk) ?? string.Empty;
        if (HistoryService.Instance.Last(HTarget) is { } last) Target = last;
        Sni = p.GetSetting(KSni) ?? string.Empty;
        StartTlsIndex = Math.Clamp(p.GetInt(KStartTls, 0), 0, StartTlsOptions.Length - 1);
        _restoring = false;
    }

    // The SNI override (a host name: at most 253 characters are worth keeping) and the STARTTLS choice are remembered.
    partial void OnSniChanged(string value)
    {
        if (!_restoring) ProfileService.Instance.SetSetting(KSni, (value ?? string.Empty).Length <= 253 ? value : string.Empty);
    }

    partial void OnStartTlsIndexChanged(int value)
    {
        if (!_restoring && value >= 0) ProfileService.Instance.SetSetting(KStartTls, value.ToString(CultureInfo.InvariantCulture));
    }

    public bool IsIdle => !IsBusy;
    public bool IsBulkIdle => !IsBulkBusy;
    public string InspectText => IsBusy ? "Stop" : "Inspect";
    public string BulkText => IsBulkBusy ? "Stop" : "Check all";
    public bool HasProblems => Problems.Count > 0;
    public bool HasVersions => Versions.Count > 0;
    public bool HasChain => Chain.Count > 0;
    public bool HasError => !string.IsNullOrEmpty(Error);
    public bool ShowEmpty => !HasResult && !IsBusy && !HasError;
    public bool VerdictOk => Verdict == TlsSeverity.Ok;
    public bool VerdictWarn => Verdict == TlsSeverity.Warning;
    public bool VerdictBad => Verdict == TlsSeverity.Error;
    public bool HasBulkRows => BulkRows.Count > 0;
    public bool HasBulkInput => !string.IsNullOrWhiteSpace(BulkInput);

    partial void OnIsBusyChanged(bool value)
    {
        OnPropertyChanged(nameof(IsIdle));
        OnPropertyChanged(nameof(InspectText));
        OnPropertyChanged(nameof(ShowEmpty));
    }

    partial void OnIsBulkBusyChanged(bool value)
    {
        OnPropertyChanged(nameof(IsBulkIdle));
        OnPropertyChanged(nameof(BulkText));
    }

    partial void OnHasResultChanged(bool value) => OnPropertyChanged(nameof(ShowEmpty));

    partial void OnErrorChanged(string? value)
    {
        OnPropertyChanged(nameof(HasError));
        OnPropertyChanged(nameof(ShowEmpty));
    }

    partial void OnVerdictChanged(TlsSeverity value)
    {
        OnPropertyChanged(nameof(VerdictOk));
        OnPropertyChanged(nameof(VerdictWarn));
        OnPropertyChanged(nameof(VerdictBad));
    }

    partial void OnTabIndexChanged(int value)
    {
        if (!_restoring) ProfileService.Instance.SetSetting(KTab, value.ToString(CultureInfo.InvariantCulture));
    }

    partial void OnBulkInputChanged(string value)
    {
        OnPropertyChanged(nameof(HasBulkInput));
        if (BulkError != null) BulkError = null;
    }

    // ================================================================ inspect

    [RelayCommand(AllowConcurrentExecutions = true)]   // the same button cancels / stops while it runs
    private async Task Inspect()
    {
        if (IsBusy) { _cts?.Cancel(); return; }
        if (!TlsInspector.TryParseTarget(Target, out var host, out var port, out var parseError))
        {
            ShowError(parseError!, null);
            return;
        }
        string normalized = port == TlsInspector.DefaultPort ? host : SocketNet.Target(host, port);
        HistoryService.Instance.Add(HTarget, normalized);

        StartTlsKind? starttls = StartTlsIndex switch
        {
            1 => StartTlsKind.None,
            2 => StartTlsKind.Smtp,
            3 => StartTlsKind.Imap,
            4 => StartTlsKind.Pop3,
            5 => StartTlsKind.Ftp,
            _ => null,
        };
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        IsBusy = true;
        Error = null;
        ErrorDetail = null;
        HasResult = false;   // the last host's result mustn't come back under the new target if this one is stopped
        Progress = "Connecting…";
        try
        {
            var progress = new Progress<string>(s => { if (!ct.IsCancellationRequested) Progress = s; });
            var report = await Task.Run(() => TlsInspector.InspectAsync(host, port, new TlsInspectOptions
            {
                Sni = string.IsNullOrWhiteSpace(Sni) ? null : Sni.Trim(),
                StartTls = starttls,
                Progress = progress,
            }, ct), ct);
            Show(report);
        }
        catch (OperationCanceledException)
        {
            Progress = string.Empty;
        }
        catch (Exception ex)
        {
            ShowError("The inspection failed: " + ex.Message, null);
        }
        finally
        {
            IsBusy = false;
            Progress = string.Empty;
            _cts?.Dispose();
            _cts = null;
        }
    }

    private void ShowError(string message, string? detail)
    {
        Error = message;
        ErrorDetail = detail;
        HasResult = false;
    }

    internal void Show(TlsReport r)
    {
        _report = r;
        var now = DateTime.UtcNow;
        Error = r.Error;
        ErrorDetail = r.ErrorDetail is { } d && r.Error != null && !r.Error.Contains(d, StringComparison.Ordinal) ? "System message: " + d : null;
        EndpointText = SocketNet.Target(r.Host, r.Port);
        AddressText = r.Address is { } a && a != r.Host ? a : string.Empty;

        // verdict
        if (r.Error != null && r.Chain.Count == 0) { Verdict = TlsSeverity.Error; VerdictText = "No TLS session"; }
        else if (r.Error != null) { Verdict = TlsSeverity.Error; VerdictText = "Handshake failed"; }
        else
        {
            Verdict = r.Verdict;
            VerdictText = r.Verdict switch
            {
                TlsSeverity.Ok => "Trusted",
                TlsSeverity.Warning => "Trusted, with warnings",
                _ => "Not trusted",
            };
        }
        var bits = new List<string>();
        if (r.Protocol != null) bits.Add(r.Protocol);
        if (r.CipherSuite != null) bits.Add(r.CipherSuite);
        if (r.Handshaken) bits.Add(r.Alpn != null ? "ALPN " + r.Alpn : r.StartTls == StartTlsKind.None ? "no ALPN" : "STARTTLS " + TlsStartTls.Name(r.StartTls));
        if (r.Handshaken) bits.Add($"handshake {Ms(r.HandshakeMs)} (connect {Ms(r.ConnectMs)})");
        SummaryText = string.Join("  ·  ", bits);

        Problems.Clear();
        foreach (var p in r.Problems) Problems.Add(p);

        Facts.Clear();
        if (r.Leaf is { } leaf)
        {
            Facts.Add(new TlsFact("Expires", $"{TlsCertificates.Date(leaf.NotAfter)} · {TlsCertificates.ExpiryPhrase(leaf, now)}",
                                  TlsCertificates.ExpirySeverity(leaf, now),
                                  $"Valid {TlsCertificates.DateTimeUtc(leaf.NotBefore)} → {TlsCertificates.DateTimeUtc(leaf.NotAfter)}"));
            Facts.Add(new TlsFact("Issued by", TlsCertificates.IssuerText(leaf)));
        }
        Facts.Add(new TlsFact("Server name", r.Sni is { } sni ? $"{sni} (sent as SNI)" : "none sent — connected to an IP address"));
        if (r.StartTls != StartTlsKind.None) Facts.Add(new TlsFact("STARTTLS", TlsStartTls.Name(r.StartTls) + " — upgraded from plain text"));
        if (r.Hsts != null) Facts.Add(new TlsFact("HSTS", r.Hsts, r.HstsSeverity));
        if (r.Stapling != null) Facts.Add(new TlsFact("OCSP stapling", r.Stapling, r.StaplingSeverity));
        if (r.Revocation != null) Facts.Add(new TlsFact("Revocation", r.Revocation, r.RevocationSeverity));

        Versions.Clear();
        if (r.Versions.Any(v => v.Supported != null))   // nothing but failed tests (not TLS at all) says nothing
            foreach (var v in r.Versions) Versions.Add(new TlsVersionChip(v));

        Chain.Clear();
        for (int i = 0; i < r.Chain.Count; i++) Chain.Add(new TlsCertView(r.Chain[i], i, r.Chain.Count, now));
        ChainNote = r.ChainFromProbe ? "from the plain-text handshake" : string.Empty;

        HasResult = true;
        OnPropertyChanged(nameof(HasProblems));
        OnPropertyChanged(nameof(HasVersions));
        OnPropertyChanged(nameof(HasChain));
    }

    private static string Ms(double ms) => ms < 10 ? $"{ms:0.0} ms" : $"{ms:0} ms";

    [RelayCommand]
    private Task CopyReport() => _report == null ? Task.CompletedTask : ClipboardHelper.SetTextAsync(BuildReport(_report));

    [RelayCommand]
    private Task CopyChainPem()
        => Chain.Count == 0 ? Task.CompletedTask : ClipboardHelper.SetTextAsync(string.Concat(Chain.Select(c => TlsCertificates.Pem(c.Cert))));

    [RelayCommand]
    private Task CopyError() => string.IsNullOrEmpty(Error) ? Task.CompletedTask : ClipboardHelper.SetTextAsync(Error + (ErrorDetail != null ? "\n" + ErrorDetail : ""));

    internal string BuildReport(TlsReport r)
    {
        var now = DateTime.UtcNow;
        var sb = new StringBuilder();
        sb.Append($"TLS inspection — {SocketNet.Target(r.Host, r.Port)}");
        if (r.Address != null) sb.Append($" ({r.Address})");
        sb.Append($" — {r.CheckedAt:yyyy-MM-dd HH:mm}\n");
        sb.Append($"Verdict: {VerdictText}\n");
        if (r.Error != null) sb.Append($"Error: {r.Error}\n");
        if (r.Handshaken) sb.Append($"Connection: {SummaryText}\n");
        foreach (var f in Facts) sb.Append($"{f.Label}: {f.Value}\n");
        if (r.Versions.Count > 0)
            sb.Append("Versions: ").Append(string.Join(", ", r.Versions.Select(v => $"{v.Name} {(v.Supported switch { true => "yes", false => "no", _ => "?" })}"))).Append('\n');
        if (r.Problems.Count > 0)
        {
            sb.Append("Problems:\n");
            foreach (var p in r.Problems) sb.Append($"  - [{p.Severity}] {p.Text}\n");
        }
        for (int i = 0; i < r.Chain.Count; i++)
        {
            var v = new TlsCertView(r.Chain[i], i, r.Chain.Count, now);
            sb.Append($"\n[{i}] {v.Role}: {v.Name}\n");
            sb.Append($"    Subject:   {v.Subject}\n");
            sb.Append($"    Issuer:    {v.Issuer}\n");
            sb.Append($"    Valid:     {v.Validity} ({v.ExpiryText})\n");
            if (v.HasSans) sb.Append($"    Names:     {v.Sans}\n");
            sb.Append($"    Key:       {v.KeyAndSignature}\n");
            sb.Append($"    Serial:    {v.Serial}\n");
            sb.Append($"    SHA-256:   {v.Sha256}\n");
            sb.Append($"    SHA-1:     {v.Sha1}\n");
            sb.Append($"    Source:    {v.Source}\n");
        }
        return sb.ToString();
    }

    // ================================================================ bulk

    [RelayCommand(AllowConcurrentExecutions = true)]   // the same button cancels / stops while it runs
    private async Task RunBulk()
    {
        if (IsBulkBusy) { _bulkCts?.Cancel(); return; }
        BulkError = null;
        var lines = (BulkInput ?? string.Empty).Split('\n', '\r')
            .Select(l => l.Trim())
            .Where(l => l.Length > 0 && !l.StartsWith('#'))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (lines.Count == 0) { BulkError = "Paste host names, host:port or URLs — one per line."; return; }
        if (lines.Count > BulkMax) { BulkError = $"That's {lines.Count} hosts — the bulk check takes up to {BulkMax} at a time."; return; }
        if ((BulkInput ?? "").Length <= 64 * 1024) ProfileService.Instance.SetSetting(KBulk, BulkInput);

        BulkRows.Clear();
        _sortColumn = string.Empty;
        foreach (var line in lines)
        {
            bool ok = TlsInspector.TryParseTarget(line, out var h, out var p, out var err);
            BulkRows.Add(new TlsBulkRow(line, ok ? h : line, p, ok ? null : (err ?? "Not a host")));
        }
        OnPropertyChanged(nameof(HasBulkRows));

        _bulkCts = new CancellationTokenSource();
        var ct = _bulkCts.Token;
        IsBulkBusy = true;
        UpdateBulkStatus();
        using var gate = new SemaphoreSlim(BulkConcurrency);
        try
        {
            await Task.WhenAll(BulkRows.ToList().Where(r => r.IsValid).Select(async row =>
            {
                try
                {
                    await gate.WaitAsync(ct);
                }
                catch (OperationCanceledException) { return; }
                try
                {
                    row.Checking();
                    var rep = await Task.Run(() => TlsInspector.QuickAsync(row.Host, row.Port, 10_000, ct), ct);
                    row.Apply(rep);
                }
                catch (OperationCanceledException) { }
                catch (Exception ex) { row.Fail(ex.Message); }
                finally
                {
                    gate.Release();
                    UpdateBulkStatus();
                }
            }));
        }
        finally
        {
            foreach (var r in BulkRows.Where(r => r.IsPending)) r.StatusText = "Stopped";
            IsBulkBusy = false;
            _bulkCts?.Dispose();
            _bulkCts = null;
            UpdateBulkStatus();
        }
    }

    private void UpdateBulkStatus()
    {
        int total = BulkRows.Count, done = BulkRows.Count(r => r.Done || !r.IsValid);
        int ok = BulkRows.Count(r => r.IsOk), warn = BulkRows.Count(r => r.IsWarn), bad = BulkRows.Count(r => r.IsBad);
        string counts = $"{ok} valid · {warn} warning{(warn == 1 ? "" : "s")} · {bad} failed";
        BulkStatus = IsBulkBusy ? $"Checking {done} of {total}…  {counts}" : total == 0 ? string.Empty : $"{total} checked · {counts}";
    }

    [RelayCommand]
    private void SortBy(string? column)
    {
        if (string.IsNullOrEmpty(column) || BulkRows.Count == 0) return;
        ApplySort(column, _sortColumn == column && !_sortDesc);   // a second click reverses
    }

    private void ApplySort(string column, bool desc)
    {
        _sortColumn = column;
        _sortDesc = desc;
        IEnumerable<TlsBulkRow> sorted = column switch
        {
            "host" => BulkRows.OrderBy(r => r.Endpoint, StringComparer.OrdinalIgnoreCase),
            "issuer" => BulkRows.OrderBy(r => r.Issuer == "—" ? "￿" : r.Issuer, StringComparer.OrdinalIgnoreCase),
            "status" => BulkRows.OrderByDescending(r => r.IsBad ? 3 : r.IsWarn ? 2 : r.IsOk ? 1 : 0).ThenBy(r => r.StatusText, StringComparer.OrdinalIgnoreCase),
            _ => BulkRows.OrderBy(r => r.DaysLeft ?? int.MaxValue),   // "days" / "expires": soonest first, failures last
        };
        var list = sorted.ToList();
        if (desc) list.Reverse();
        for (int i = 0; i < list.Count; i++)
        {
            int at = BulkRows.IndexOf(list[i]);
            if (at != i) BulkRows.Move(at, i);
        }
    }

    [RelayCommand]
    private void ClearBulk()
    {
        if (IsBulkBusy) return;
        BulkRows.Clear();
        BulkStatus = string.Empty;
        OnPropertyChanged(nameof(HasBulkRows));
    }

    [RelayCommand]
    private Task CopyBulk() => BulkRows.Count == 0 ? Task.CompletedTask : ClipboardHelper.SetTextAsync(BuildCsv());

    public string SuggestedCsvName => $"tls-check-{DateTime.Now:yyyyMMdd-HHmm}.csv";

    public async Task ExportCsvAsync(Stream stream)
    {
        string csv = BuildCsv();
        await using var w = new StreamWriter(stream, new UTF8Encoding(false), 1 << 16, leaveOpen: true);
        await w.WriteAsync(csv);
        await w.FlushAsync();
    }

    public void ReportExport(string? name, string? error)
        => BulkStatus = error == null ? $"Saved {name}." : "Couldn't save the file: " + error;

    internal string BuildCsv()
    {
        var sb = new StringBuilder("Host,Port,Status,Expires,Days left,Issuer,Protocol,Details\n");
        foreach (var r in BulkRows)
        {
            Field(sb, r.Host); sb.Append(',');
            sb.Append(r.Port.ToString(CultureInfo.InvariantCulture)).Append(',');
            Field(sb, r.StatusText); sb.Append(',');
            Field(sb, r.ExpiresText == "—" ? "" : r.ExpiresText); sb.Append(',');
            sb.Append(r.DaysLeft?.ToString(CultureInfo.InvariantCulture) ?? "").Append(',');
            Field(sb, r.Issuer == "—" ? "" : r.Issuer); sb.Append(',');
            Field(sb, r.Protocol); sb.Append(',');
            Field(sb, r.Detail.Replace('\n', ';'));
            sb.Append('\n');
        }
        return sb.ToString();
    }

    // RFC 4180 quoting, plus a spreadsheet formula-injection guard (text from a remote certificate)
    private static void Field(StringBuilder sb, string? v)
    {
        v ??= string.Empty;
        if (v.Length > 0 && v[0] is '=' or '+' or '-' or '@' or '\t' or '\r') v = "'" + v;
        sb.Append('"').Append(v.Replace("\"", "\"\"")).Append('"');
    }
}
