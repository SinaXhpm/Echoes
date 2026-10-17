using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>
/// Distributed checks from check-host.net's nodes around the world: ping, HTTP, TCP, UDP and DNS. A run starts the check,
/// then polls its results (off the UI thread) until every node has reported; rows fill in as they arrive. Nodes are chosen
/// automatically, by region or one by one. The calls go through the app's <see cref="HttpHelper"/>, so an optional proxy can
/// tunnel them (useful where check-host.net itself is filtered).
/// </summary>
public partial class CheckHostViewModel : ObservableObject
{
    /// <summary>The API's address and polling schedule; a test harness points them at a stand-in server.</summary>
    internal static Uri ApiBase { get; set; } = CheckHostClient.DefaultBase;
    internal static CheckHostPolling Polling { get; set; } = CheckHostPolling.Default;
    internal static TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(15);

    [ObservableProperty] private string _host = string.Empty;
    [ObservableProperty] private int _selectedTypeIndex;          // CheckHostKinds.All: ping · http · tcp · udp · dns
    [ObservableProperty] private int _maxNodes = 20;
    [ObservableProperty] private bool _isWorking;
    /// <summary>Where the run is ("12 of 20 nodes reported", "Done in 4.2 s"); empty before the first run.</summary>
    [ObservableProperty] private string _statusMessage = string.Empty;
    /// <summary>The one clear error of the last run ("" when there is none).</summary>
    [ObservableProperty] private string _errorText = string.Empty;

    [ObservableProperty] private bool _useProxy;
    [ObservableProperty] private string _proxyAddress = string.Empty;
    [ObservableProperty] private string _proxyUser = string.Empty;
    [ObservableProperty] private string _proxyPass = string.Empty;

    public ObservableCollection<string> CheckTypes { get; } = new(CheckHostKinds.All.Select(k => k.Label()));

    public ObservableCollection<string> HostHistory => HistoryService.Instance.Get("checkhost.host");
    public ObservableCollection<string> ProxyHistory => HistoryService.Instance.Get("ip.proxy");

    public CheckHostKind Kind => CheckHostKinds.All[Math.Clamp(SelectedTypeIndex, 0, CheckHostKinds.All.Length - 1)];
    public bool HasError => ErrorText.Length > 0;
    public bool HasStatus => StatusMessage.Length > 0;

    /// <summary>What the target box expects for the chosen check (a phone's narrower box gets the short form).</summary>
    public string TargetPlaceholder => (Kind, AppPlatform.IsMobile) switch
    {
        (CheckHostKind.Http, false) => "e.g. https://example.com",
        (CheckHostKind.Http, true) => "URL or host",
        (CheckHostKind.Tcp, _) => "e.g. example.com:443",
        (CheckHostKind.Udp, _) => "e.g. 8.8.8.8:53",
        (_, false) => "e.g. example.com",
        _ => "Host or IP",
    };

    partial void OnErrorTextChanged(string value) => OnPropertyChanged(nameof(HasError));
    partial void OnStatusMessageChanged(string value) => OnPropertyChanged(nameof(HasStatus));
    partial void OnSelectedTypeIndexChanged(int value)
    {
        OnPropertyChanged(nameof(Kind));
        OnPropertyChanged(nameof(TargetPlaceholder));
    }
    partial void OnIsWorkingChanged(bool value) => OnEmptyStateChanged();

    private CancellationTokenSource? _cts;
    private int _runId;
    private bool _loaded;
    private static readonly HashSet<string> PersistProps = new()
    { "UseProxy", "ProxyAddress", "ProxyUser", "ProxyPass", "SelectedTypeIndex", "MaxNodes", "SortIndex" };

    // The saved proxy password when it can't be decrypted here (no key file, a profile from another machine): Unprotect
    // gives "" for it, which looks like "no password", and the next save of ANY setting would write "" over the stored
    // secret. It's written back exactly as stored until the user types a password of their own.
    private string? _unreadablePass;

    public CheckHostViewModel()
    {
        var ps = ProfileService.Instance;
        if (HistoryService.Instance.Last("checkhost.host") is { } lastHost) Host = lastHost;   // the target checked last
        UseProxy = ps.GetBool("checkhost.useProxy");
        ProxyAddress = ps.GetSetting("checkhost.proxyAddr") ?? (HistoryService.Instance.Last("ip.proxy") ?? string.Empty);
        ProxyUser = ps.GetSetting("checkhost.proxyUser") ?? string.Empty;
        // Stored encrypted via SecretProtector (per-user key); legacy plaintext and old-format values still
        // load and are re-saved in the current format right away.
        string rawPass = ps.GetSetting("checkhost.proxyPass") ?? string.Empty;
        ProxyPass = SecretProtector.Unprotect(rawPass);
        if (rawPass.Length > 0 && ProxyPass.Length == 0) _unreadablePass = rawPass;
        // The check by name; older versions saved an index into [ping, http, tcp, dns] (before UDP was added).
        if (CheckHostKinds.TryParse(ps.GetSetting("checkhost.check"), out var kind))
            SelectedTypeIndex = Array.IndexOf(CheckHostKinds.All, kind);
        else if (int.TryParse(ps.GetSetting("checkhost.type"), out int ti) && ti is >= 0 and <= 3)
            SelectedTypeIndex = Array.IndexOf(CheckHostKinds.All, new[] { CheckHostKind.Ping, CheckHostKind.Http, CheckHostKind.Tcp, CheckHostKind.Dns }[ti]);
        if (int.TryParse(ps.GetSetting("checkhost.maxNodes"), out int mn) && mn is > 0 and <= 100) MaxNodes = mn;
        _nodeChoice = CheckHostNodeChoice.Parse(ps.GetSetting("checkhost.nodes"));
        if (CheckHostOrder.TryParse(ps.GetSetting("checkhost.sort"), out var sort)) _sortIndex = Array.IndexOf(CheckHostOrder.All, sort);
        _loaded = true;
        // Re-save under the current key: legacy plaintext, or an old "enc1:" value that still decrypts (one that
        // doesn't is left untouched rather than overwritten with an empty password).
        if (rawPass.Length > 0 && (ProxyPass == rawPass || (SecretProtector.IsLegacy(rawPass) && ProxyPass.Length > 0))) SchedulePersist();
        // An address saved with credentials in it (by an older version): into the fields, and the profile is rewritten
        // without them.
        MoveProxyCredentials(whileTyping: false);
    }

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (_loaded && e.PropertyName == nameof(ProxyPass)) _unreadablePass = null;   // the user's own password now
        if (_loaded && e.PropertyName is { } n && PersistProps.Contains(n)) SchedulePersist();
    }

    /// <summary>
    /// Pasted "user:pass@host:port" credentials move out of the proxy address into the user / password fields (the
    /// password is stored encrypted; the address is a plaintext setting, and .NET authenticates only with the fields).
    /// </summary>
    /// <param name="whileTyping">From the debounced save: only an address that already ends in its port is split, so a
    /// pause mid-typing doesn't cut "user:p@ss…" at the wrong '@'. (The save itself never writes the user info.)</param>
    private void MoveProxyCredentials(bool whileTyping)
    {
        if (CheckHostProxy.Parse(ProxyAddress) is not { HasHost: true } info || (whileTyping && !info.HasPort)) return;
        ProxyAddress = info.Clean;
        if (info.User.Length > 0) ProxyUser = info.User;
        if (info.Pass.Length > 0) ProxyPass = info.Pass;
    }

    // Debounced: the proxy boxes update on every keystroke, and each save re-serializes + rewrites the whole
    // profile file on the UI thread. Write once typing pauses; RUN and app exit/background flush a pending one.
    private CancellationTokenSource? _persistCts;
    private bool _persistPending;   // UI thread only

    private void SchedulePersist()
    {
        _persistPending = true;
        _persistCts?.Cancel();
        _persistCts?.Dispose();
        var cts = _persistCts = new CancellationTokenSource();
        _ = Task.Delay(500, cts.Token).ContinueWith(t =>
        {
            // Values are read back on the UI thread at write time, so the latest edit always wins.
            if (!t.IsCanceled) Avalonia.Threading.Dispatcher.UIThread.Post(FlushPendingSave);
        }, TaskScheduler.Default);
    }

    /// <summary>Persist a pending (debounced) settings change now. No-op when nothing is pending. UI thread only.</summary>
    public void FlushPendingSave()
    {
        _persistCts?.Cancel();
        if (!_persistPending) return;
        MoveProxyCredentials(whileTyping: true);   // its property changes re-arm the debounce: cancelled again here
        _persistCts?.Cancel();
        _persistPending = false;
        ProfileService.Instance.SetMany(
            // the address goes into the plaintext profile: never with user info in it, even half-typed
            ("checkhost.useProxy", UseProxy ? "true" : "false"), ("checkhost.proxyAddr", CheckHostProxy.Clean(ProxyAddress)),
            ("checkhost.proxyUser", ProxyUser), ("checkhost.proxyPass", _unreadablePass ?? SecretProtector.Protect(ProxyPass)),
            ("checkhost.check", Kind.Api()), ("checkhost.maxNodes", MaxNodes.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            ("checkhost.nodes", NodeChoice.Serialize()), ("checkhost.sort", Sort.Key()));
    }

    /// <summary>The proxy to use (never with user info in it: credentials travel in the user / password fields).</summary>
    private string? ProxyOrNull => UseProxy && CheckHostProxy.Clean(ProxyAddress) is { Length: > 0 } address ? address : null;

    // Synchronous command → it stays enabled while a run is in flight, so STOP is always clickable.
    // (An async [RelayCommand] disables itself for the duration of the task, which blocked STOP.)
    [RelayCommand]
    private void ToggleRun()
    {
        if (IsWorking) { _cts?.Cancel(); return; }
        _ = RunCheck();
    }

    private async Task RunCheck()
    {
        var kind = Kind;
        string target, note;
        try { target = CheckHostTarget.Normalize(kind, Host, out note); }
        catch (CheckHostException ex)
        {
            ErrorText = ex.Message;
            return;
        }
        MoveProxyCredentials(whileTyping: false);   // typing is done: credentials in the address go to the fields this run uses
        FlushPendingSave();   // the settings this run uses are saved even if the app closes mid-run
        HistoryService.Instance.Add("checkhost.host", Host.Trim());
        string? proxy = ProxyOrNull;
        if (proxy != null) HistoryService.Instance.Add("ip.proxy", proxy);

        _cts?.Cancel();
        _cts?.Dispose();
        var cts = _cts = new CancellationTokenSource();
        var token = cts.Token;
        int runId = ++_runId;
        var clock = Stopwatch.StartNew();
        var choice = NodeChoice;
        BeginRun(kind, target, choice);
        IsWorking = true;
        ErrorText = "";

        try
        {
            using var http = HttpHelper.Create(proxy, ProxyUser, ProxyPass, timeout: RequestTimeout);
            var client = new CheckHostClient(http, ApiBase, viaProxy: proxy != null);

            IReadOnlyList<string> nodes = Array.Empty<string>();
            if (!choice.IsAutomatic)
            {
                StatusMessage = "Loading the node list…";
                var (catalog, catalogError) = await LoadCatalogAsync(token);
                if (runId != _runId) return;
                var resolved = choice.Resolve(catalog, MaxNodes);
                if (resolved is null)
                    throw new CheckHostException($"Couldn't load check-host.net's node list to pick the {choice.Label(null)} nodes — {Lower(catalogError)}");
                if (resolved.Count == 0)
                    throw new CheckHostException("None of the chosen nodes is on check-host.net's list any more — choose the nodes again, or use Automatic.");
                nodes = resolved;
            }

            StatusMessage = "Starting the check…";
            var end = await CheckHostRun.RunAsync(client, kind, target, MaxNodes, nodes, new Sink(this, runId), Polling, token);
            if (runId != _runId) return;
            DrainQueue();
            int silent = 0;
            if (end == CheckHostEnd.Deadline)
                foreach (var row in _all)
                    if (row.Result is null) { row.SetResult(CheckHostResult.NoResult(kind, Polling.Deadline)); silent++; }
            FinishRun(clock.Elapsed, stopped: false);
            StatusMessage = $"Done in {CheckHostFormat.Duration(clock.Elapsed)}"
                            + (silent > 0 ? $" · {CheckHostFormat.Plural(silent, "node", "nodes")} didn't report" : "")
                            + (note.Length > 0 ? $" · {kind.Label()} {note} (no port given)" : "");
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            if (runId != _runId) return;
            DrainQueue();
            int reported = _all.Count(r => r.Entry.IsFinal);
            foreach (var row in _all) row.MarkStopped();
            FinishRun(clock.Elapsed, stopped: true);
            StatusMessage = _all.Count == 0 ? "Stopped." : $"Stopped after {CheckHostFormat.Duration(clock.Elapsed)} · {reported} of {_all.Count} nodes reported";
        }
        catch (Exception ex) when (ex is CheckHostException or ArgumentException)
        {
            if (runId != _runId) return;
            DrainQueue();
            foreach (var row in _all) row.MarkStopped();
            FinishRun(clock.Elapsed, stopped: true);
            ErrorText = ex.Message;   // an invalid proxy address (ArgumentException) already reads as one sentence
            StatusMessage = _all.Count > 0 ? $"Stopped after {CheckHostFormat.Duration(clock.Elapsed)}" : "";
        }
        catch (Exception ex)
        {
            if (runId != _runId) return;
            DrainQueue();
            foreach (var row in _all) row.MarkStopped();
            FinishRun(clock.Elapsed, stopped: true);
            ErrorText = "The check failed: " + ex.Message;
            StatusMessage = "";
        }
        finally
        {
            if (runId == _runId) IsWorking = false;
        }
    }

    private static string Lower(string s) => s.Length > 1 && char.IsUpper(s[0]) && !char.IsUpper(s[1]) ? char.ToLowerInvariant(s[0]) + s[1..] : s;

    // ---- engine → UI hand-off ----
    // The engine reports on the thread pool. Everything it says goes through one queue, drained on the UI thread in
    // order; the run's own continuation drains it first, so a last batch can't land after the run is marked done.

    private readonly ConcurrentQueue<(int Run, Action Apply)> _queue = new();
    private int _drainPosted;

    private void Enqueue(int runId, Action apply)
    {
        _queue.Enqueue((runId, apply));
        if (Interlocked.Exchange(ref _drainPosted, 1) == 0)
            Avalonia.Threading.Dispatcher.UIThread.Post(DrainQueue);
    }

    private void DrainQueue()
    {
        Interlocked.Exchange(ref _drainPosted, 0);
        while (_queue.TryDequeue(out var item))
            if (item.Run == _runId) item.Apply();
    }

    private sealed class Sink(CheckHostViewModel vm, int runId) : ICheckHostSink
    {
        public void Started(CheckHostStart start) => vm.Enqueue(runId, () => vm.OnStarted(start));
        public void Results(IReadOnlyList<KeyValuePair<string, CheckHostResult>> batch) => vm.Enqueue(runId, () => vm.OnResults(batch));
        public void PollProblem(string? problem) => vm.Enqueue(runId, () => vm.OnPollProblem(problem));
    }
}
