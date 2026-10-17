using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>
/// The Ping tab's MTR mode: an <see cref="MtrSession"/> shown as a live table. The session works on pool threads; this
/// copies its snapshot into <see cref="Hops"/> at most four times a second (each row only touches what changed), and
/// fills in reverse-DNS names as they arrive. Every UI post carries the run it belongs to, so nothing from a stopped run
/// lands in the next one's table.
/// </summary>
public sealed partial class MtrViewModel : ObservableObject
{
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;
    private const int FlushIntervalMs = 250;

    public ObservableCollection<MtrHopRow> Hops { get; } = new();

    /// <summary>One line under the table: progress, the UDP note, or the error that stopped the run.</summary>
    [ObservableProperty] private string _status = string.Empty;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(ShowHint))] private bool _statusIsError;

    /// <summary>The empty table's how-to line: not beside an error.</summary>
    public bool ShowHint => Hops.Count == 0 && !StatusIsError;

    public MtrViewModel() => Hops.CollectionChanged += (_, _) => OnPropertyChanged(nameof(ShowHint));

    /// <summary>Tests / screenshots: session tuning (e.g. a simulated network via <see cref="MtrOptions.Probe"/>).</summary>
    public MtrOptions? Options { get; set; }

    /// <summary>Tests / screenshots: replaces the reverse-DNS lookup.</summary>
    public Func<IPAddress, Task<string?>>? NameLookup { get; set; }

    // UI-thread state of the current run.
    private int _runId;
    private bool _active;
    private string _label = string.Empty;
    private DateTimeOffset _startedAt;
    private MtrSnapshot? _last;
    private readonly Dictionary<IPAddress, string?> _names = new();

    // Flush throttle (touched from pool threads).
    private int _flushQueued;
    private long _lastFlush;

    /// <summary>UI thread, before a run: empties the table and returns the new run's id (pass it to <see cref="RunAsync"/>).</summary>
    public int Reset()
    {
        _runId++;
        _active = false;
        _last = null;
        // Addresses whose name never came: ask again in this run (MtrReverseDns keeps a definite "no such name", and
        // forgets a timed-out lookup after a minute — this table held on to the miss for the whole session).
        foreach (var unnamed in _names.Where(kv => kv.Value is null).Select(kv => kv.Key).ToList()) _names.Remove(unnamed);
        Hops.Clear();
        Status = string.Empty;
        StatusIsError = false;
        return _runId;
    }

    /// <summary>Resolves <paramref name="host"/> and runs MTR to it until <paramref name="token"/> is cancelled or no probe can
    /// work here. Off the UI thread; never throws. Returns false when the run ended by itself (an error).</summary>
    public async Task<bool> RunAsync(string host, int runId, CancellationToken token)
    {
        IPAddress target;
        try
        {
            if (!IPAddress.TryParse(host, out _)) Post(runId, () => Status = $"Resolving {host}…");
            target = await IcmpPinger.ResolveAsync(host, token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { return true; }
        catch (Exception)
        {
            Post(runId, () => SetError($"Host not found: {host}"));
            return false;
        }

        var session = new MtrSession(target, Options);
        string label = IPAddress.TryParse(host, out _) ? target.ToString() : $"{host} ({target})";
        Post(runId, () =>
        {
            _active = true;
            _label = label;
            _startedAt = DateTimeOffset.Now;
            Status = $"Discovering the hops to {label}…";
            StatusIsError = false;
        });
        session.Changed += () => QueueFlush(runId, session);

        try
        {
            await session.RunAsync(token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Post(runId, () => SetError($"MTR error: {ex.Message}"));
            return false;
        }

        var final = session.Snapshot();
        Post(runId, () =>
        {
            _active = false;
            Apply(runId, final);
        });
        return final.Fatal is null;
    }

    private void SetError(string message)
    {
        _active = false;
        Status = message;
        StatusIsError = true;
    }

    private void Post(int runId, Action action)
        => Dispatcher.UIThread.Post(() => { if (runId == _runId) action(); });

    // Coalesce the session's change events: one pending flush at a time, at most every FlushIntervalMs.
    private void QueueFlush(int runId, MtrSession session)
    {
        if (Interlocked.Exchange(ref _flushQueued, 1) == 1) return;
        long wait = FlushIntervalMs - (Environment.TickCount64 - Interlocked.Read(ref _lastFlush));
        if (wait <= 0) Dispatcher.UIThread.Post(() => Flush(runId, session), DispatcherPriority.Background);
        else
            _ = Task.Delay((int)wait).ContinueWith(_ => Dispatcher.UIThread.Post(() => Flush(runId, session), DispatcherPriority.Background),
                                                    TaskScheduler.Default);
    }

    private void Flush(int runId, MtrSession session)
    {
        Interlocked.Exchange(ref _lastFlush, Environment.TickCount64);
        Interlocked.Exchange(ref _flushQueued, 0);   // before the snapshot: a change after it queues the next flush
        if (runId != _runId) return;
        Apply(runId, session.Snapshot());
    }

    // UI thread.
    private void Apply(int runId, MtrSnapshot snap)
    {
        // No probe could even go out (no permission at all): the error alone, not an empty "???" row.
        if (snap.Fatal is not null && snap.Hops.All(h => h.Sent == 0 && h.Address is null))
            snap = new MtrSnapshot { Target = snap.Target, Rounds = snap.Rounds, UsesUdp = snap.UsesUdp, Fatal = snap.Fatal };
        _last = snap;
        var hops = snap.Hops;
        while (Hops.Count > hops.Count) Hops.RemoveAt(Hops.Count - 1);
        for (int i = 0; i < hops.Count; i++)
        {
            var hop = hops[i];
            MtrHopRow row;
            if (i < Hops.Count) row = Hops[i];
            else
            {
                row = new MtrHopRow(hop.Ttl, Options?.HistoryLength ?? 40);
                Hops.Add(row);
            }
            if (hop.Address is { } a) RequestName(runId, a);
            row.Update(hop, NameOf(hop.Address), NamesOf(hop.Others));
        }

        if (snap.Fatal is { } fatal)
        {
            Status = IcmpPinger.UdpCanTrace
                ? $"MTR can't run: {fatal}. {PermissionHint}"
                : "MTR needs ICMP permission, which isn't available on this platform.";
            StatusIsError = true;
            return;
        }
        Status = StatusText(snap);
        StatusIsError = false;
    }

    private string StatusText(MtrSnapshot snap)
    {
        var sb = new StringBuilder();
        if (snap.UsesUdp)
            sb.Append("ICMP isn't permitted here: probing with UDP datagrams to port ").Append(IcmpPinger.DefaultUdpPort).Append(" instead. ");

        int count = snap.Hops.Count;
        var lastHop = count > 0 ? snap.Hops[count - 1] : null;
        string rounds = snap.Rounds == 1 ? "1 round" : $"{snap.Rounds} rounds";
        if (lastHop?.Error is { } dead && !snap.DestinationReached)
            sb.Append("The path ends at hop ").Append(lastHop.Ttl).Append(": ").Append(dead.ToLowerInvariant());
        else if (snap.DestinationReached)
            sb.Append(count == 1 ? "1 hop to " : $"{count} hops to ").Append(_label);
        else
        {
            int answered = 0;
            foreach (var h in snap.Hops) if (h.Address is not null) answered++;
            sb.Append(_label).Append(" hasn't answered").Append(_active ? " yet" : string.Empty)
              .Append(answered == 1 ? " · 1 hop answered" : answered > 1 ? $" · {answered} hops answered" : string.Empty);
        }
        sb.Append(_active ? $" · round {snap.Rounds}" : $" · stopped after {rounds}");
        return sb.ToString();
    }

    private static readonly string PermissionHint =
        OperatingSystem.IsLinux()
            ? "To allow ICMP: sudo sysctl -w net.ipv4.ping_group_range=\"0 2147483647\" (or launch Echoes with sudo)."
            : "Raw ICMP sockets need elevated privileges on this platform.";

    // ---------- reverse DNS ----------

    private string? NameOf(IPAddress? a) => a is not null && _names.TryGetValue(a, out var n) ? n : null;

    private List<(IPAddress, string?)> NamesOf(IReadOnlyList<IPAddress> others)
    {
        var list = new List<(IPAddress, string?)>(others.Count);
        foreach (var o in others)
        {
            list.Add((o, NameOf(o)));
            RequestName(_runId, o);
        }
        return list;
    }

    private void RequestName(int runId, IPAddress a)
    {
        if (_names.ContainsKey(a)) return;
        _names[a] = null;   // asked: shown without a name until the answer comes
        var lookup = NameLookup ?? MtrReverseDns.LookupAsync;
        Task<string?> task;
        try { task = lookup(a); }
        catch (Exception) { return; }
        // (Clean again whatever the lookup was: a PTR name is remote text — no control / bidi characters in the table,
        // its tooltips or the copied report.)
        if (task.IsCompletedSuccessfully) { _names[a] = MtrReverseDns.Clean(task.Result); return; }
        task.ContinueWith(t =>
        {
            string? name = t.IsCompletedSuccessfully ? MtrReverseDns.Clean(t.Result) : null;
            if (name is null) return;
            Dispatcher.UIThread.Post(() =>
            {
                _names[a] = name;
                if (runId != _runId || _last is null) return;
                // only the rows that show this address: the rest of the table stays as it is
                for (int i = 0; i < Hops.Count && i < _last.Hops.Count; i++)
                {
                    var hop = _last.Hops[i];
                    if (Equals(hop.Address, a) || hop.Others.Contains(a))
                        Hops[i].Update(hop, NameOf(hop.Address), NamesOf(hop.Others), force: true);
                }
            }, DispatcherPriority.Background);
        }, TaskScheduler.Default);
    }

    // ---------- report ----------

    /// <summary>The table as text, in mtr's --report layout (plus the run's target and how the probes went out).</summary>
    public string BuildReport()
    {
        var snap = _last;
        if (snap is null || snap.Hops.Count == 0) return Status;

        var hosts = new List<string>(snap.Hops.Count);
        int width = 28;
        foreach (var h in snap.Hops)
        {
            string host = HostLabel(h.Address);
            hosts.Add(host);
            width = Math.Max(width, host.Length);
            foreach (var o in h.Others) width = Math.Max(width, HostLabel(o).Length + 6);
        }

        var sb = new StringBuilder();
        sb.Append("MTR to ").Append(_label).Append(snap.UsesUdp ? " (UDP probes to port " + IcmpPinger.DefaultUdpPort + ")" : " (ICMP)").AppendLine();
        sb.Append("Start: ").Append(_startedAt.ToString("yyyy-MM-dd'T'HH:mm:ssK", Inv)).AppendLine();
        sb.Append("HOST: ").Append(Environment.MachineName.PadRight(width + 2))
          .Append(" Loss%   Snt   Last    Avg   Best   Wrst  StDev").AppendLine();
        for (int i = 0; i < snap.Hops.Count; i++)
        {
            var h = snap.Hops[i];
            sb.Append(' ').Append(h.Ttl.ToString(Inv).PadLeft(2)).Append(".|-- ").Append(hosts[i].PadRight(width))
              .Append(' ').Append(Fixed(h.LossPercent, "0.0", 5)).Append('%')
              .Append(' ').Append(h.Sent.ToString(Inv).PadLeft(5))
              .Append(' ').Append(Fixed(h.LastMs, "0.0", 6))
              .Append(' ').Append(Fixed(h.AvgMs, "0.0", 6))
              .Append(' ').Append(Fixed(h.BestMs, "0.0", 6))
              .Append(' ').Append(Fixed(h.WorstMs, "0.0", 6))
              .Append(' ').Append(Fixed(h.StDevMs, "0.0", 6));
            if (h.Error is { } e) sb.Append("  ").Append(e);
            sb.AppendLine();
            foreach (var o in h.Others) sb.Append("    |  `|-- ").Append(HostLabel(o)).AppendLine();
        }
        if (!snap.DestinationReached)
            sb.Append("(").Append(_label).Append(" didn't answer)").AppendLine();
        return sb.ToString().TrimEnd();

        string HostLabel(IPAddress? a) => a is null ? "???" : NameOf(a) is { } n ? $"{n} ({a})" : a.ToString();
    }

    private static string Fixed(double v, string format, int width)
        => (double.IsNaN(v) ? "0.0" : v.ToString(format, Inv)).PadLeft(width);
}

/// <summary>One row of the MTR table, preformatted for binding and updated in place (UI thread).</summary>
public sealed partial class MtrHopRow : ObservableObject
{
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    public MtrHopRow(int ttl, int history)
    {
        Ttl = ttl;
        TtlText = ttl.ToString(Inv);
        Series = new LatencySeries(Math.Max(1, history));
    }

    public int Ttl { get; }
    public string TtlText { get; }

    /// <summary>The hop's recent results (NaN = no answer) for the row's graph; redrawn when <see cref="SeriesVersion"/> changes.</summary>
    public LatencySeries Series { get; }
    [ObservableProperty] private int _seriesVersion;

    [ObservableProperty] private string _host = "???";
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasName))] private string? _name;
    [ObservableProperty] private bool _isSilent = true;
    [ObservableProperty] private bool _isDestination;

    /// <summary>"+1", "+2": other addresses answer at this TTL too (equal-cost multipath).</summary>
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasMultipath))] private string? _multipath;
    [ObservableProperty] private string? _multipathTip;

    /// <summary>Why the path ends here ("unreachable"), for a badge; the full text is in <see cref="HostTip"/>.</summary>
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasNote))] private string? _note;
    [ObservableProperty] private string? _hostTip;

    [ObservableProperty] private string _lossText = "—";
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(SomeLoss), nameof(AllLost))] private int _lossLevel;
    [ObservableProperty] private string _sentText = "0";
    [ObservableProperty] private string _lastText = "—";
    [ObservableProperty] private string _avgText = "—";
    [ObservableProperty] private string _bestText = "—";
    [ObservableProperty] private string _worstText = "—";
    [ObservableProperty] private string _stDevText = "—";

    /// <summary>The numbers on one line, for the two-line (phone) layout.</summary>
    [ObservableProperty] private string _summary = string.Empty;

    public bool HasName => !string.IsNullOrEmpty(Name);
    public bool HasMultipath => !string.IsNullOrEmpty(Multipath);
    public bool HasNote => !string.IsNullOrEmpty(Note);
    public bool SomeLoss => LossLevel == 1;
    public bool AllLost => LossLevel == 2;

    private int _version = -1;
    private string? _nameShown;
    private string? _othersKey;

    internal void Update(MtrHopSnapshot hop, string? name, List<(IPAddress Address, string? Name)> others, bool force = false)
    {
        string othersKey = string.Join(",", others.ConvertAll(o => o.Address + "=" + o.Name));
        if (!force && hop.Version == _version && name == _nameShown && othersKey == _othersKey) return;
        _version = hop.Version;
        _nameShown = name;
        _othersKey = othersKey;

        bool silent = hop.Address is null;
        IsSilent = silent;
        Host = silent ? "???" : hop.Address!.ToString();
        Name = silent ? null : name;
        IsDestination = hop.IsDestination;

        if (others.Count > 0)
        {
            Multipath = "+" + others.Count.ToString(Inv);
            MultipathTip = "Also answering at this hop: " + string.Join(", ", others.ConvertAll(o => o.Name is null ? o.Address.ToString() : $"{o.Name} ({o.Address})"));
        }
        else
        {
            Multipath = null;
            MultipathTip = null;
        }
        Note = hop.Error is null ? null : "unreachable";

        var tip = new StringBuilder();
        if (silent) tip.Append("No answer from this hop yet (it may not send ICMP time-exceeded at all)");
        else
        {
            tip.Append(hop.Address);
            if (name is not null) tip.Append(Environment.NewLine).Append(name);
            if (hop.IsDestination) tip.Append(Environment.NewLine).Append("The destination");
        }
        if (hop.Error is { } err) tip.Append(Environment.NewLine).Append(err).Append(": the path ends here");
        if (MultipathTip is { } mp) tip.Append(Environment.NewLine).Append(mp);
        HostTip = tip.ToString();

        int completed = hop.Received + hop.Lost;
        LossText = completed == 0 ? "—" : hop.LossPercent.ToString("0.0", Inv) + "%";
        LossLevel = completed == 0 || hop.Lost == 0 ? 0 : hop.Received == 0 ? 2 : 1;
        SentText = hop.Sent.ToString(Inv);
        LastText = Ms(hop.LastMs);
        AvgText = Ms(hop.AvgMs);
        BestText = Ms(hop.BestMs);
        WorstText = Ms(hop.WorstMs);
        StDevText = Ms(hop.StDevMs);
        Summary = hop.Received > 0
            ? $"avg {AvgText} · {BestText}–{WorstText} ms"
            : completed > 0 ? $"no answer · {hop.Sent} sent" : "waiting for the first answer";

        Series.Set(hop.Recent);
        SeriesVersion++;
    }

    private static string Ms(double v) => double.IsNaN(v) ? "—" : v >= 1000 ? v.ToString("0", Inv) : v.ToString("0.0", Inv);
}
