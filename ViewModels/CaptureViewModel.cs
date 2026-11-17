using Avalonia.Platform.Storage;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>An observable list that takes many items in one change (one event for a few thousand packets, where
/// adding them one by one would raise as many).</summary>
public sealed class RangeCollection<T> : ObservableCollection<T>
{
    public void AddRange(IReadOnlyList<T> items)
    {
        if (items.Count == 0) return;
        int start = Count;
        ((List<T>)Items).AddRange(items);
        Raise(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Add, items as IList ?? items.ToList(), start));
    }

    /// <summary>Replaces everything (one reset).</summary>
    public void ResetTo(IEnumerable<T> items)
    {
        var list = (List<T>)Items;
        list.Clear();
        list.AddRange(items);
        Raise(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
    }

    private void Raise(NotifyCollectionChangedEventArgs e)
    {
        OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
        OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
        OnCollectionChanged(e);
    }
}

/// <summary>
/// The Capture tool: the packets on one network interface as they pass (<see cref="PacketCapture"/>), in a table with
/// one line per packet, a filter over them (<see cref="PacketFilter"/>), the selected packet's layers and bytes
/// (<see cref="PacketDecoder"/>), and files: a capture saved as pcap (which Wireshark and tcpdump open), CSV or text,
/// and pcap / pcapng files opened to look at.
/// <para>Packets arrive on the capture's thread, where they are decoded and queued; the UI takes the queue over a few
/// times a second, so a download's thousands of packets a second cost a handful of list changes. The capture keeps the
/// newest <see cref="MaxPackets"/> packets and <see cref="MaxBytes"/> of data: beyond that the oldest go, and the
/// status line says how many.</para>
/// </summary>
public sealed partial class CaptureViewModel : ObservableObject, IToolSession
{
    /// <summary>The most packets kept (the oldest tenth goes when one more arrives).</summary>
    public const int MaxPackets = 100_000;
    /// <summary>The most packet data kept.</summary>
    public const long MaxBytes = 128L * 1024 * 1024;
    private const int FlushMs = 150;
    private const int MaxPending = 50_000;   // packets waiting for the UI: past this a burst is counted, not kept

    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;
    private const string IfaceKey = "capture.iface", PromiscuousKey = "capture.promiscuous", FilterKey = "capture.filter";

    private readonly ToolStore Store = ToolStore.Current;

    /// <summary>The interface to listen on (loopback included). Locked while a capture runs.</summary>
    public IfacePicker Iface { get; }

    public ObservableCollection<string> FilterHistory => Store.History.Get(FilterKey);

    /// <summary>The packets shown: all of them, or the ones the filter lets through.</summary>
    public RangeCollection<PacketRecord> Rows { get; } = new();

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(CanChoose))] private bool _isCapturing;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(CanChoose))] private bool _isLoading;
    [ObservableProperty] private bool _promiscuous;
    [ObservableProperty] private string _filterText = string.Empty;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasFilterError))] private string? _filterError;
    [ObservableProperty] private string _status = string.Empty;
    [ObservableProperty] private bool _statusIsError;
    [ObservableProperty] private string _countText = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelection))]
    private PacketRecord? _selected;

    /// <summary>The selected packet's layers and its bytes, for the detail pane.</summary>
    [ObservableProperty] private IReadOnlyList<PacketLayer> _layers = Array.Empty<PacketLayer>();
    [ObservableProperty] private byte[]? _selectedBytes;

    public bool HasSelection => Selected is not null;
    public bool HasFilterError => FilterError is not null;
    public bool HasPackets => _all.Count > 0;
    public bool ShowHint => _all.Count == 0 && !IsLoading;

    /// <summary>The interface and the options can be changed (nothing runs).</summary>
    public bool CanChoose => !IsCapturing && !IsLoading;

    /// <summary>Live capture is possible on this system at all (a phone can only open files).</summary>
    public bool CanCapture => PacketCapture.Supported;

    /// <summary>The empty table's line: what to do, and what capturing needs here.</summary>
    public string Hint => (CanCapture ? "Choose an interface and press Start, or open a capture file.\n" : string.Empty) + _requirement;

    // What capturing needs here (PacketCapture.Requirement). On Windows, finding out loads Npcap's wpcap.dll: worked out on
    // the thread pool (ReadRequirement), not by this binding on the UI thread while the page is first built.
    private string _requirement = string.Empty;

    private void ReadRequirement()
        => _ = Task.Run(() => PacketCapture.Requirement).ContinueWith(t => Dispatcher.UIThread.Post(() =>
        {
            _requirement = t.Result;
            OnPropertyChanged(nameof(Hint));
        }), CancellationToken.None, TaskContinuationOptions.OnlyOnRanToCompletion, TaskScheduler.Default);

    /// <summary>Raised when packets were added at the end (the view follows them while it shows the last row).</summary>
    public event Action? Appended;

    // ---- the capture's state. _all, _bytes, _filter: UI thread. The pending list: under _gate. ----
    private readonly List<PacketRecord> _all = new();
    private long _bytes;
    private long _trimmed;            // packets dropped from the start to stay under the caps
    private PacketFilter? _filter;
    private string _source = string.Empty;   // "on Ethernet with Npcap" / "captured.pcap"

    private readonly object _gate = new();
    private List<PacketRecord> _pending = new();
    private long _overflow;           // packets not kept because the UI was behind (under _gate)
    private long _nextNumber;         // the last packet's number (under _gate)
    private DateTime _firstTime;      // the first frame's time (capture thread)

    private PacketCapture? _capture;
    private int _run;                 // which capture's packets and end are still wanted
    private CancellationTokenSource? _filterDelay;

    // Flush throttle (touched from the capture thread): one pending flush at a time, at most every FlushMs.
    private int _flushQueued;
    private long _lastFlush;

    public CaptureViewModel()
    {
        Iface = new IfacePicker(Store.Profile, IfaceKey, autoLabel: null, withLoopback: true);
        Promiscuous = Store.Profile.GetBool(PromiscuousKey);
        Status = string.Empty;
        UpdateCounts();
        ReadRequirement();
    }

    partial void OnPromiscuousChanged(bool value)
    {
        if (Store.Profile.GetBool(PromiscuousKey) != value) Store.Profile.SetBool(PromiscuousKey, value);
    }

    partial void OnIsLoadingChanged(bool value) => OnPropertyChanged(nameof(ShowHint));

    // ------------------------------------------------------------------ capture

    [RelayCommand]
    private void ToggleCapture()
    {
        if (IsCapturing) StopCapture();
        else StartCapture();
    }

    private void StartCapture()
    {
        if (IsLoading) return;
        if (Iface.Name is not { } name)
        {
            SetStatus("No network interface is up.", error: true);
            return;
        }
        var iface = Iface.Resolve();
        if (iface is null)
        {
            SetStatus($"{name} isn't connected: choose another interface.", error: true);
            return;
        }

        ClearPackets();
        int run = ++_run;
        var decoder = new PacketDecoder();   // the capture thread's own
        _nextNumber = 0;
        _firstTime = default;
        PacketCapture capture;
        try
        {
            capture = PacketCapture.Start(iface, Promiscuous, frame => OnFrame(run, decoder, frame),
                                          error => Dispatcher.UIThread.Post(() => OnEnded(run, error)));
        }
        catch (CaptureException ex)
        {
            SetStatus(ex.Message, error: true);
            return;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            SetStatus("The capture library couldn't be used: " + ex.Message, error: true);
            return;
        }
        _capture = capture;
        _source = $"on {iface.Name} with {capture.Engine}";
        IsCapturing = true;
        SetStatus($"Capturing {_source}…", error: false);
    }

    private void StopCapture()
    {
        _capture?.Stop();   // its end comes back through OnEnded
    }

    // Capture thread: decode, queue. The run id keeps a stopped capture's last frames out of the next one.
    private void OnFrame(int run, PacketDecoder decoder, in CapturedFrame frame)
    {
        if (run != Volatile.Read(ref _run)) return;
        if (_firstTime == default) _firstTime = frame.TimeUtc;
        var p = new PacketRecord
        {
            TimeUtc = frame.TimeUtc,
            Seconds = Math.Max(0, (frame.TimeUtc - _firstTime).TotalSeconds),
            Data = frame.Data,
            WireLength = frame.WireLength,
            Link = frame.Link,
        };
        decoder.Summarize(p);
        lock (_gate)
        {
            if (_pending.Count >= MaxPending) { _overflow++; return; }
            p.Number = ++_nextNumber;   // the packets kept are numbered without gaps
            _pending.Add(p);
        }
        QueueFlush(run);
    }

    // Coalesces the packets' arrivals: one pending flush at a time, at most every FlushMs (as the MTR table does).
    private void QueueFlush(int run)
    {
        if (Interlocked.Exchange(ref _flushQueued, 1) == 1) return;
        long wait = FlushMs - (Environment.TickCount64 - Interlocked.Read(ref _lastFlush));
        if (wait <= 0) Dispatcher.UIThread.Post(() => Flush(run), DispatcherPriority.Background);
        else
            _ = Task.Delay((int)wait).ContinueWith(_ => Dispatcher.UIThread.Post(() => Flush(run), DispatcherPriority.Background),
                                                    TaskScheduler.Default);
    }

    // UI thread, a few times a second while packets arrive: the queued ones join the table.
    private void Flush(int run)
    {
        Interlocked.Exchange(ref _lastFlush, Environment.TickCount64);
        Interlocked.Exchange(ref _flushQueued, 0);   // before the queue is taken: a packet after it queues the next flush
        if (run != _run) return;
        List<PacketRecord> batch;
        lock (_gate)
        {
            if (_pending.Count == 0) return;
            batch = _pending;
            _pending = new List<PacketRecord>(Math.Min(batch.Count * 2, 8192));
        }
        Append(batch);
    }

    private void Append(List<PacketRecord> batch)
    {
        bool wasEmpty = _all.Count == 0;
        _all.AddRange(batch);
        foreach (var p in batch) _bytes += p.Data.Length;

        if (_all.Count > MaxPackets || _bytes > MaxBytes)
        {
            // The oldest go, down to nine tenths of each limit (so this isn't done for every packet); the table is
            // rebuilt once.
            int drop = 0;
            long freed = 0;
            while (drop < _all.Count - 1 && (_all.Count - drop > MaxPackets - MaxPackets / 10 || _bytes - freed > MaxBytes - MaxBytes / 10))
                freed += _all[drop++].Data.Length;
            _all.RemoveRange(0, drop);
            _bytes -= freed;
            _trimmed += drop;
            RebuildRows(keepSelection: true);
        }
        else
        {
            var filter = _filter;
            if (filter is null) Rows.AddRange(batch);
            else
            {
                var shown = new List<PacketRecord>();
                foreach (var p in batch) if (filter.Matches(p)) shown.Add(p);
                Rows.AddRange(shown);
            }
        }
        if (wasEmpty) { OnPropertyChanged(nameof(HasPackets)); OnPropertyChanged(nameof(ShowHint)); }
        UpdateCounts();
        Appended?.Invoke();
    }

    private void OnEnded(int run, string? error)
    {
        if (run != _run) return;
        Flush(run);
        _capture = null;
        IsCapturing = false;
        if (error is not null) SetStatus($"The capture {_source} ended: {error}", error: true);
        else SetStatus($"Captured {_source}.", error: false);
        UpdateCounts();
    }

    [RelayCommand]
    private void Clear()
    {
        ClearPackets();
        if (!IsCapturing) SetStatus(string.Empty, error: false);
    }

    private void ClearPackets()
    {
        lock (_gate)
        {
            _pending.Clear();
            _overflow = 0;
        }
        _all.Clear();
        _bytes = 0;
        _trimmed = 0;
        Selected = null;
        Rows.ResetTo(Array.Empty<PacketRecord>());
        OnPropertyChanged(nameof(HasPackets));
        OnPropertyChanged(nameof(ShowHint));
        UpdateCounts();
    }

    // ------------------------------------------------------------------ filter

    partial void OnFilterTextChanged(string value)
    {
        // typed: applied once the typing pauses (a filter half written is neither an error nor a filter yet)
        _filterDelay?.Cancel();
        var delay = _filterDelay = new CancellationTokenSource();
        _ = Task.Delay(350, delay.Token).ContinueWith(t =>
        {
            if (!t.IsCanceled) Dispatcher.UIThread.Post(() => { if (!delay.IsCancellationRequested) ApplyFilterNow(remember: false); });
        }, TaskScheduler.Default);
    }

    /// <summary>Enter in the filter box: applied at once, and kept in the box's history.</summary>
    [RelayCommand]
    private void ApplyFilter() => ApplyFilterNow(remember: true);

    private void ApplyFilterNow(bool remember)
    {
        _filterDelay?.Cancel();
        if (!PacketFilter.TryParse(FilterText, out var filter, out string? error))
        {
            FilterError = "Filter: " + error;   // the table keeps the last filter that made sense
            return;
        }
        FilterError = null;
        if (remember && filter is not null) Store.History.Add(FilterKey, filter.Text);
        if (filter?.Text == _filter?.Text) return;
        _filter = filter;
        RebuildRows(keepSelection: true);
        UpdateCounts();
    }

    private void RebuildRows(bool keepSelection)
    {
        var keep = keepSelection ? Selected : null;
        var filter = _filter;
        Rows.ResetTo(filter is null ? _all : _all.Where(filter.Matches));
        // (the reset emptied the list's selection: the packet stays selected when the filter still shows it)
        Selected = keep is not null && (filter is null || filter.Matches(keep)) && _all.Count > 0 && keep.Number >= _all[0].Number ? keep : null;
    }

    // ------------------------------------------------------------------ selection

    partial void OnSelectedChanged(PacketRecord? value)
    {
        Layers = value is null ? Array.Empty<PacketLayer>() : PacketDecoder.Describe(value);
        SelectedBytes = value?.Data;
    }

    /// <summary>The selected packet as text: its line, its layers and a hex dump.</summary>
    [RelayCommand]
    private async Task CopyPacket()
    {
        if (Selected is not { } p) return;
        var sb = new StringBuilder(1024);
        sb.Append(p.NumberText).Append("  ").Append(p.TimeText).Append("  ").Append(p.Source).Append(" → ").Append(p.Destination)
          .Append("  ").Append(p.Protocol).Append("  ").Append(p.LengthText).Append("  ").AppendLine(p.Info).AppendLine();
        foreach (var layer in Layers)
        {
            sb.AppendLine(layer.Title);
            foreach (var f in layer.Fields) sb.Append("    ").Append(f.Name).Append(": ").AppendLine(f.Value);
        }
        sb.AppendLine().Append(HexDump(p.Data));
        await ClipboardHelper.SetTextAsync(sb.ToString());
    }

    private static string HexDump(byte[] data)
    {
        var sb = new StringBuilder(data.Length * 4 + 64);
        for (int at = 0; at < data.Length; at += 16)
        {
            sb.Append(at.ToString("x4", Inv)).Append("  ");
            for (int i = 0; i < 16; i++)
            {
                if (at + i < data.Length) sb.Append(data[at + i].ToString("x2", Inv)).Append(' ');
                else sb.Append("   ");
                if (i == 7) sb.Append(' ');
            }
            sb.Append(' ');
            for (int i = 0; i < 16 && at + i < data.Length; i++)
            {
                byte b = data[at + i];
                sb.Append(b is >= 0x20 and < 0x7F ? (char)b : '.');
            }
            sb.AppendLine();
        }
        return sb.ToString();
    }

    // ------------------------------------------------------------------ files

    /// <summary>Opens a pcap / pcapng file in place of what is shown (a running capture stops first).</summary>
    public async Task OpenAsync(IStorageProvider storage)
    {
        var files = await storage.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Open a capture file",
            AllowMultiple = false,
            FileTypeFilter = new[]
            {
                new FilePickerFileType("Capture files") { Patterns = new[] { "*.pcap", "*.pcapng", "*.cap", "*.dmp" } },
                FilePickerFileTypes.All,
            },
        });
        if (files.Count == 0) return;
        var file = files[0];
        if (IsCapturing)
        {
            _run++;   // its remaining frames and its end are no longer wanted
            _capture?.Stop();
            _capture = null;
            IsCapturing = false;
        }
        ClearPackets();
        IsLoading = true;
        SetStatus($"Reading {file.Name}…", error: false);
        try
        {
            await using var stream = await file.OpenReadAsync();
            var (packets, truncated) = await Task.Run(() =>
            {
                var entries = PcapFile.Read(stream, MaxPackets, MaxBytes, out bool cut);
                var decoder = new PacketDecoder();
                var list = new List<PacketRecord>(entries.Count);
                DateTime first = entries.Count > 0 ? entries[0].TimeUtc : default;
                foreach (var e in entries)
                {
                    var p = new PacketRecord
                    {
                        Number = list.Count + 1,
                        TimeUtc = e.TimeUtc,
                        Seconds = Math.Max(0, (e.TimeUtc - first).TotalSeconds),
                        Data = e.Data,
                        WireLength = e.WireLength,
                        Link = e.Link,
                    };
                    decoder.Summarize(p);
                    list.Add(p);
                }
                return (list, cut);
            });
            _source = file.Name;
            IsLoading = false;
            if (packets.Count > 0) Append(packets);
            SetStatus(packets.Count == 0 ? $"{file.Name} holds no packets."
                : truncated ? $"{file.Name}: the first {packets.Count:N0} packets (the file has more than Echoes keeps at once)."
                : file.Name, error: false);
        }
        catch (Exception ex) when (ex is PcapFormatException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            SetStatus(ex is PcapFormatException ? ex.Message : $"Couldn't read {file.Name}: {ex.Message}", error: true);
        }
        finally
        {
            IsLoading = false;
            UpdateCounts();
        }
    }

    /// <summary>Saves the packets shown (the filter applies) as "pcap", "csv" or "txt".</summary>
    public async Task ExportAsync(IStorageProvider storage, string format)
    {
        var packets = Rows.ToList();
        if (packets.Count == 0)
        {
            SetStatus(_all.Count == 0 ? "Nothing to save yet: capture something first." : "The filter shows no packets, so there is nothing to save.", error: true);
            return;
        }
        var (ext, label, pattern) = format switch
        {
            "csv" => (".csv", "CSV", "*.csv"),
            "txt" => (".txt", "Text", "*.txt"),
            _ => (".pcap", "Capture file (Wireshark, tcpdump)", "*.pcap"),
        };
        string stamp = packets[0].TimeUtc.ToLocalTime().ToString("yyyyMMdd-HHmmss", Inv);
        var file = await storage.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Save the packets shown",
            SuggestedFileName = $"echoes-capture-{stamp}{ext}",
            DefaultExtension = ext,
            FileTypeChoices = new[] { new FilePickerFileType(label) { Patterns = new[] { pattern } } },
        });
        if (file is null) return;

        await using var stream = await file.OpenWriteAsync();
        if (stream.CanSeek) stream.SetLength(0);   // overwriting a longer file must not leave its tail behind
        await Task.Run(() =>
        {
            switch (format)
            {
                case "csv": WriteCsv(stream, packets); break;
                case "txt": WriteText(stream, packets); break;
                default: PcapFile.Write(stream, packets); break;
            }
        });
        SetStatus($"Saved {packets.Count:N0} packet{(packets.Count == 1 ? string.Empty : "s")} to {file.Name}.", error: false);
    }

    private static void WriteCsv(Stream stream, List<PacketRecord> packets)
    {
        using var w = new StreamWriter(stream, new UTF8Encoding(true), 1 << 16, leaveOpen: true) { NewLine = "\r\n" };
        w.WriteLine("no,time,time_s,source,destination,protocol,length,info");
        foreach (var p in packets)
        {
            w.Write(p.NumberText); w.Write(',');
            w.Write(p.TimeUtc.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", Inv)); w.Write(',');
            w.Write(p.TimeText); w.Write(',');
            w.Write(Field(p.Source)); w.Write(',');
            w.Write(Field(p.Destination)); w.Write(',');
            w.Write(Field(p.Protocol)); w.Write(',');
            w.Write(p.LengthText); w.Write(',');
            w.WriteLine(Field(p.Info));
        }
    }

    // RFC 4180 field; a leading = + - @ (a spreadsheet formula) is defused with a quote, as the scanner's CSV does:
    // names and request lines in the info column come from the network.
    private static string Field(string? v)
    {
        v ??= string.Empty;
        if (v.Length > 0 && v[0] is '=' or '+' or '-' or '@' or '\t' or '\r') v = "'" + v;
        return "\"" + v.Replace("\"", "\"\"") + "\"";
    }

    private static void WriteText(Stream stream, List<PacketRecord> packets)
    {
        using var w = new StreamWriter(stream, new UTF8Encoding(false), 1 << 16, leaveOpen: true);
        int source = Math.Clamp(packets.Max(p => p.Source.Length), 6, 39), destination = Math.Clamp(packets.Max(p => p.Destination.Length), 11, 39);
        w.WriteLine($"{"No.",7}  {"Time",-12} {"Source".PadRight(source)}  {"Destination".PadRight(destination)}  {"Protocol",-9} {"Length",6}  Info");
        foreach (var p in packets)
            w.WriteLine($"{p.NumberText,7}  {p.TimeText,-12} {p.Source.PadRight(source)}  {p.Destination.PadRight(destination)}  {p.Protocol,-9} {p.LengthText,6}  {p.Info}");
    }

    // ------------------------------------------------------------------ status

    private void SetStatus(string text, bool error)
    {
        Status = text;
        StatusIsError = error;
    }

    /// <summary>An error from the view (a file dialog that failed), on the status line.</summary>
    public void Report(string error) => SetStatus(error, error: true);

    private void UpdateCounts()
    {
        long overflow;
        lock (_gate) overflow = _overflow;
        long engineDrops = Math.Max(0, _capture?.Dropped ?? 0);
        if (_all.Count == 0 && overflow == 0) { CountText = string.Empty; return; }
        var sb = new StringBuilder(64);
        sb.Append(_all.Count.ToString("N0", Inv)).Append(_all.Count == 1 ? " packet" : " packets");
        if (_filter is not null) sb.Append(" · ").Append(Rows.Count.ToString("N0", Inv)).Append(" shown");
        sb.Append(" · ").Append(Size(_bytes));
        if (_trimmed > 0) sb.Append(" · ").Append(_trimmed.ToString("N0", Inv)).Append(" older dropped");
        if (overflow + engineDrops > 0) sb.Append(" · ").Append((overflow + engineDrops).ToString("N0", Inv)).Append(" missed");
        CountText = sb.ToString();
    }

    private static string Size(long bytes)
        => bytes >= 1024 * 1024 ? (bytes / (1024.0 * 1024)).ToString("0.0", Inv) + " MB"
         : bytes >= 1024 ? (bytes / 1024.0).ToString("0.0", Inv) + " KB"
         : bytes.ToString(Inv) + " B";

    // ------------------------------------------------------------------ the shell

    bool IToolSession.IsBusy => IsCapturing;

    void IToolSession.EndSession()
    {
        if (IsCapturing) StopCapture();
    }
}
