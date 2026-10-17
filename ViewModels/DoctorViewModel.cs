using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

/// <summary>What the verdict card shows.</summary>
public enum DoctorCard { Idle, Running, Works, Problem, Down, Unknown, Stopped, InputError }

/// <summary>
/// The Doctor ("why doesn't this site work for me"): one input, one button, a verdict card with one sentence and what to
/// do, and the checks behind it, live. The only choice is an optional proxy to test through as well; everything else
/// follows from the target (see <see cref="DoctorEngine"/>).
/// </summary>
public partial class DoctorViewModel : ObservableObject
{
    private const string HistoryKey = "doctor";
    private const string ProxyHistoryKey = "ip.proxy";   // shared with IP Info / Check Host (addresses without credentials)

    [ObservableProperty] private string _target = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanCopy))]
    private bool _isRunning;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CardNeutral), nameof(CardWorks), nameof(CardProblem), nameof(CardDown), nameof(CardUnknown),
                              nameof(CardRunning), nameof(CardIdle), nameof(CardStopped), nameof(HasAdvice), nameof(CanCopy))]
    private DoctorCard _card = DoctorCard.Idle;

    [ObservableProperty] private string _cardTitle = "Find out why a site doesn't work";
    [ObservableProperty] private string _cardText = "Enter a site and press Diagnose: every step is checked, and the cause is named.";
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasAdvice))] private string _cardAdvice = "";

    // ---- the optional proxy (the address is a plaintext setting: never with user info; the password is encrypted)
    [ObservableProperty] private bool _useProxy;
    [ObservableProperty] private string _proxyAddress = string.Empty;
    [ObservableProperty] private string _proxyUser = string.Empty;
    [ObservableProperty] private string _proxyPass = string.Empty;

    /// <summary>Expand every check's sub-steps (off: only the ones with a problem open automatically). Persisted.</summary>
    [ObservableProperty] private bool _showDetails;

    public ObservableCollection<string> TargetHistory => HistoryService.Instance.Get(HistoryKey);
    public ObservableCollection<string> ProxyHistory => HistoryService.Instance.Get(ProxyHistoryKey);

    /// <summary>Every check's row (the proxy's ones are shown only with a proxy).</summary>
    public IReadOnlyList<DoctorStepRow> Steps { get; } = Enum.GetValues<DoctorCheck>().Select(c => new DoctorStepRow(c)).ToList();
    /// <summary>What the list shows: the direct rows, then (with a proxy) a header and the proxy's rows.</summary>
    public ObservableCollection<object> Items { get; } = new();
    private readonly DoctorStepGroup _proxyGroup = new("Through the proxy", DoctorEngine.ProxyNote);

    public DoctorStepRow Row(DoctorCheck c) => Steps[(int)c];
    private IEnumerable<DoctorStepRow> Visible => Steps.Where(s => _withProxy || !DoctorEngine.IsProxy(s.Check));

    public bool CardIdle => Card == DoctorCard.Idle;
    public bool CardRunning => Card == DoctorCard.Running;
    public bool CardStopped => Card == DoctorCard.Stopped;
    public bool CardNeutral => Card is DoctorCard.Idle or DoctorCard.Running or DoctorCard.Stopped;
    public bool CardWorks => Card == DoctorCard.Works;
    public bool CardProblem => Card is DoctorCard.Problem or DoctorCard.InputError;
    public bool CardDown => Card == DoctorCard.Down;
    public bool CardUnknown => Card == DoctorCard.Unknown;
    public bool HasAdvice => CardAdvice.Length > 0 && Card is DoctorCard.Works or DoctorCard.Problem or DoctorCard.Down or DoctorCard.Unknown;
    public bool CanCopy => _reportTarget != null && !IsRunning;

    /// <summary>Where the checks go — the test harness swaps in loopback servers. Not a user setting.</summary>
    internal DoctorEnvironment Env { get; set; } = DoctorEnvironment.Default;
    /// <summary>Trust exactly these roots for an https:// proxy (tests).</summary>
    internal System.Security.Cryptography.X509Certificates.X509Certificate2Collection? ProxyTrustRoots { get; set; }

    /// <summary>The run in flight (the harness awaits it).</summary>
    internal Task? RunTask { get; private set; }

    private CancellationTokenSource? _cts;
    private int _run;
    private string? _reportTarget;
    private string? _reportProxy;
    private DoctorVerdict? _verdict;
    private DateTime _ranAt;
    private bool _withProxy;   // the rows on show include the proxy's
    private bool _loaded;
    // the saved password when it can't be decrypted here: written back as stored until the user types one of their own
    private string? _unreadablePass;

    public DoctorViewModel()
    {
        if (HistoryService.Instance.Last(HistoryKey) is { } last) Target = last;
        var ps = ProfileService.Instance;
        UseProxy = ps.GetBool("doctor.useProxy");
        ProxyAddress = ps.GetSetting("doctor.proxyAddr") ?? string.Empty;
        ProxyUser = ps.GetSetting("doctor.proxyUser") ?? string.Empty;
        string rawPass = ps.GetSetting("doctor.proxyPass") ?? string.Empty;
        ProxyPass = SecretProtector.Unprotect(rawPass);
        if (rawPass.Length > 0 && ProxyPass.Length == 0) _unreadablePass = rawPass;
        ShowDetails = ps.GetBool("doctor.showDetails");
        _withProxy = UseProxy;
        RebuildItems();
        _loaded = true;
        MoveProxyCredentials(whileTyping: false);
    }

    partial void OnUseProxyChanged(bool value)
    {
        if (IsRunning) return;   // the rows of the run in flight stay; the next run shows the new choice
        _withProxy = value;
        RebuildItems();
    }

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (!_loaded) return;
        if (e.PropertyName == nameof(ProxyPass)) _unreadablePass = null;
        if (e.PropertyName is nameof(UseProxy) or nameof(ProxyAddress) or nameof(ProxyUser) or nameof(ProxyPass) or nameof(ShowDetails)) SchedulePersist();
    }

    partial void OnShowDetailsChanged(bool value)
    {
        foreach (var row in Steps) ApplyExpansion(row);
    }

    // A check's sub-steps open when Details is on, or (otherwise) when the check ended in a warning / problem.
    private void ApplyExpansion(DoctorStepRow row)
        => row.IsExpanded = ShowDetails ? row.HasTrace : row.HasTrace && row.State is DoctorState.Warning or DoctorState.Fail;

    private void RebuildItems()
    {
        Items.Clear();
        foreach (var s in Steps.Where(s => !DoctorEngine.IsProxy(s.Check))) Items.Add(s);
        if (!_withProxy) return;
        Items.Add(_proxyGroup);
        foreach (var s in Steps.Where(s => DoctorEngine.IsProxy(s.Check))) Items.Add(s);
    }

    [RelayCommand]
    private void ToggleRun()
    {
        if (IsRunning) Stop();
        else Start();
    }

    private void Start()
    {
        if (!DoctorTarget.TryParse(Target, out var t, out string error))
        {
            ShowInputError("Nothing to diagnose", error);
            return;
        }
        DoctorProxy? proxy = null;
        if (UseProxy)
        {
            MoveProxyCredentials(whileTyping: false);
            if (!DoctorProxy.TryParse(ProxyAddress, ProxyUser, ProxyPass, out proxy, out string perr))
            {
                ShowInputError("Check the proxy", perr);
                return;
            }
            if (ProxyTrustRoots != null) proxy!.TrustRoots = ProxyTrustRoots;
            HistoryService.Instance.Add(ProxyHistoryKey, CheckHostProxy.Clean(ProxyAddress));
        }
        FlushPendingSave();

        // the box and the history keep the clean target: no user info, no query string (it may carry a token)
        string clean = HistoryValue(t);
        Target = clean;
        HistoryService.Instance.Add(HistoryKey, clean);

        _cts?.Cancel();
        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        int run = ++_run;
        _withProxy = proxy != null;
        RebuildItems();
        foreach (var row in Steps)
        {
            row.State = DoctorState.Pending;
            row.Detail = "Waiting…";
            row.Time = "";
            row.ClearTrace();
        }
        _verdict = null;
        _reportTarget = t.Display();
        _reportProxy = proxy?.Display;
        _ranAt = DateTime.Now;
        IsRunning = true;
        Card = DoctorCard.Running;
        CardTitle = $"Diagnosing {t.Display()}…";
        CardAdvice = "";
        UpdateProgress();

        var token = _cts.Token;
        var env = Env;
        RunTask = Task.Run(() => RunAsync(t, env, proxy, run, token));
    }

    private void ShowInputError(string title, string text)
    {
        Card = DoctorCard.InputError;
        CardTitle = title;
        CardText = text;
        CardAdvice = "";
    }

    private void Stop()
    {
        _cts?.Cancel();
        _run++;   // late reports of the stopped run are dropped
        IsRunning = false;
        foreach (var row in Visible)
            if (!row.IsDone)
            {
                row.State = DoctorState.Skipped;
                row.Detail = "Stopped";
                row.Time = "";
            }
        Card = DoctorCard.Stopped;
        CardTitle = "Stopped";
        CardText = "Stopped early: the checks below show what was found.";
        CardAdvice = "";
    }

    private async Task RunAsync(DoctorTarget t, DoctorEnvironment env, DoctorProxy? proxy, int run, CancellationToken ct)
    {
        try
        {
            var facts = await DoctorEngine.RunAsync(t, env, proxy, new Sink(this, run), ct).ConfigureAwait(false);
            var verdict = DoctorVerdicts.Decide(facts);
            Dispatcher.UIThread.Post(() => { if (_run == run) Finish(verdict); });
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            CrashLog.Write("Doctor.Run", ex);
            Dispatcher.UIThread.Post(() =>
            {
                if (_run != run) return;
                Finish(new DoctorVerdict(DoctorVerdictKind.Unknown, "The diagnosis itself failed: " + DoctorDns.Short(ex) + ".",
                                         "Run it again; if it keeps failing, the checks below show how far it got."));
            });
        }
    }

    private void Finish(DoctorVerdict v)
    {
        // a check left behind (it shouldn't happen) must not keep spinning
        foreach (var row in Visible)
            if (!row.IsDone)
            {
                row.State = DoctorState.Skipped;
                row.Detail = "Not run";
            }
        _verdict = v;
        IsRunning = false;
        Card = v.Kind switch
        {
            DoctorVerdictKind.Works => DoctorCard.Works,
            DoctorVerdictKind.Problem => DoctorCard.Problem,
            DoctorVerdictKind.Down => DoctorCard.Down,
            _ => DoctorCard.Unknown,
        };
        CardTitle = v.Title;
        CardText = v.Sentence;
        CardAdvice = v.Advice;
        if (UseProxy != _withProxy)
        {
            _withProxy = UseProxy;   // the box changed during the run: show what the next run will do
            RebuildItems();
        }
    }

    private void Apply(DoctorCheck check, DoctorState state, string detail, double? ms)
    {
        var row = Row(check);
        row.State = state;
        row.Detail = detail;
        string time = DoctorStepRow.FormatTime(ms);
        if (time.Length > 0 || state != DoctorState.Running) row.Time = time;
        if (state != DoctorState.Running) ApplyExpansion(row);
        UpdateProgress();
    }

    private void ApplyTrace(DoctorCheck check, DoctorState state, string step, string detail, double? ms)
    {
        var row = Row(check);
        row.AddTrace(new DoctorTraceRow(state, step, detail, DoctorStepRow.FormatTime(ms)));
        if (row.State is DoctorState.Warning or DoctorState.Fail || ShowDetails) ApplyExpansion(row);
    }

    private void UpdateProgress()
    {
        if (Card != DoctorCard.Running) return;
        var rows = Visible.ToList();
        CardText = $"{rows.Count(s => s.IsDone)} of {rows.Count} checks done — usually 10–15 s.";
    }

    [RelayCommand]
    private async Task CopyReport()
    {
        if (_reportTarget == null) return;
        await ClipboardHelper.SetTextAsync(BuildReport());
    }

    /// <summary>The plain-text report of the last run (what Copy report puts on the clipboard). With a proxy: its address
    /// (never the login), its rows, and what can't go through it.</summary>
    public string BuildReport()
    {
        string target = _reportTarget ?? "";
        if (_reportProxy != null) target += $" (also through {_reportProxy})";
        string text = DoctorVerdicts.Report(target, _verdict,
            Visible.Select(s => new DoctorVerdicts.Block(
                new DoctorVerdicts.Line(DoctorEngine.ReportTitle(s.Check), s.State, s.Detail, s.Time),
                s.Trace.Select(tr => new DoctorVerdicts.Line(tr.Step, tr.State, tr.Detail, tr.Time)).ToList())), _ranAt);
        if (_reportProxy != null) text += "Note: " + DoctorEngine.ProxyNote + "\n";
        if (_verdict != null || Card != DoctorCard.Stopped) return text;
        int body = text.IndexOf("\n\n", StringComparison.Ordinal);   // after the target + time lines
        return body < 0 ? text : text[..(body + 2)] + "Stopped before the diagnosis finished.\n\n" + text[(body + 2)..];
    }

    // "https://example.com/path" / "example.com:8443" — the target without user info, query or fragment.
    private static string HistoryValue(DoctorTarget t)
    {
        string path = t.Path;
        int q = path.IndexOf('?');
        if (q >= 0) path = path[..q];
        if (t.Scheme is null) return t.Display();
        return $"{t.Scheme}://{t.Display()}{(path == "/" ? "" : path)}";
    }

    // ---- the proxy's settings

    /// <summary>Pasted "user:pass@host:port" credentials move out of the address into the user / password fields.</summary>
    private void MoveProxyCredentials(bool whileTyping)
    {
        if (CheckHostProxy.Parse(ProxyAddress) is not { HasHost: true } info || (whileTyping && !info.HasPort)) return;
        ProxyAddress = info.Clean;
        if (info.User.Length > 0) ProxyUser = info.User;
        if (info.Pass.Length > 0) ProxyPass = info.Pass;
    }

    // debounced: the boxes change on every keystroke, and a save rewrites the profile; Diagnose flushes a pending one
    private CancellationTokenSource? _persistCts;
    private bool _persistPending;

    private void SchedulePersist()
    {
        _persistPending = true;
        _persistCts?.Cancel();
        _persistCts?.Dispose();
        var cts = _persistCts = new CancellationTokenSource();
        _ = Task.Delay(500, cts.Token).ContinueWith(t =>
        {
            if (!t.IsCanceled) Dispatcher.UIThread.Post(FlushPendingSave);
        }, TaskScheduler.Default);
    }

    /// <summary>Persist a pending settings change now (no-op when none). UI thread only.</summary>
    public void FlushPendingSave()
    {
        _persistCts?.Cancel();
        if (!_persistPending) return;
        MoveProxyCredentials(whileTyping: true);
        _persistCts?.Cancel();
        _persistPending = false;
        ProfileService.Instance.SetMany(
            ("doctor.useProxy", UseProxy ? "true" : "false"),
            ("doctor.proxyAddr", CheckHostProxy.Clean(ProxyAddress)),
            ("doctor.proxyUser", ProxyUser),
            ("doctor.proxyPass", _unreadablePass ?? SecretProtector.Protect(ProxyPass)),
            ("doctor.showDetails", ShowDetails ? "true" : "false"));
    }

    private sealed class Sink : IDoctorSink
    {
        private readonly DoctorViewModel _vm;
        private readonly int _run;

        public Sink(DoctorViewModel vm, int run)
        {
            _vm = vm;
            _run = run;
        }

        public void Report(DoctorCheck check, DoctorState state, string detail, double? ms = null)
            => Dispatcher.UIThread.Post(() => { if (_vm._run == _run) _vm.Apply(check, state, detail, ms); });

        public void Trace(DoctorCheck check, DoctorState state, string step, string detail, double? ms = null)
            => Dispatcher.UIThread.Post(() => { if (_vm._run == _run) _vm.ApplyTrace(check, state, step, detail, ms); });
    }
}

/// <summary>A header in the checks list ("Through the proxy") with a one-line note.</summary>
public sealed record DoctorStepGroup(string Title, string Note);
