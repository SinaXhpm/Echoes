using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>A line of the node list: a region heading or a node.</summary>
public abstract class CheckHostRow : ObservableObject
{
    /// <summary>Re-read everything the row shows.</summary>
    internal void Refresh() => OnPropertyChanged(string.Empty);

    /// <summary>The row as one line of text (the copy shortcut, a screen reader).</summary>
    public abstract string Describe();
}

/// <summary>A region heading above its nodes (the list is grouped when sorted by region).</summary>
public sealed partial class CheckHostGroupRow : CheckHostRow
{
    public CheckHostGroupRow(string region) => Region = region;

    public string Region { get; }

    /// <summary>"8 nodes · 7 ok · 1 failed · avg 183.9 ms" over the nodes listed under it.</summary>
    public string Summary { get; private set; } = "";

    internal void Update(IReadOnlyList<CheckHostEntry> entries)
    {
        var s = CheckHostSummary.Compute(entries);
        var parts = new List<string>(4) { CheckHostFormat.Plural(s.Total, "node", "nodes") };
        string counts = CheckHostFormat.Counts(s);
        if (counts.Length > 0) parts.Add(counts);
        if (s.AvgMs is not null) parts.Add("avg " + CheckHostFormat.Ms(s.AvgMs));
        string text = string.Join(" · ", parts);
        if (text == Summary) return;
        Summary = text;
        Refresh();
    }

    public override string Describe() => $"{Region} · {Summary}";

    [RelayCommand] private Task Copy() => ClipboardHelper.SetTextAsync(Describe());
}

/// <summary>One key / value line of a node's expanded details.</summary>
public sealed class CheckHostDetail
{
    public CheckHostDetail(string key, string value, bool mono = false, string tone = "")
    {
        Key = key;
        Value = value;
        Mono = mono;
        Tone = tone;
    }

    public string Key { get; }
    public string Value { get; }
    public bool Mono { get; }
    /// <summary>"ok", "warn", "bad" or "" (plain).</summary>
    public string Tone { get; }
    public bool IsOk => Tone == "ok";
    public bool IsWarn => Tone == "warn";
    public bool IsBad => Tone == "bad";
}

/// <summary>A node of the current run and what it reported. Drawn by ChNodeLine; click it for the details.</summary>
public sealed partial class CheckHostNodeRow : CheckHostRow
{
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    public CheckHostNodeRow(CheckHostEntry entry) => Entry = entry;

    public CheckHostEntry Entry { get; }
    public CheckHostNode Node => Entry.Node;
    public CheckHostKind Kind => Entry.Kind;
    public CheckHostResult? Result => Entry.Result;
    public CheckHostState State => Entry.State;

    /// <summary>DNS: the answer most nodes got (null when they agree, or no answer clearly leads) — set by the view-model.</summary>
    internal string? Majority { get; private set; }

    internal void SetMajority(string? majority)
    {
        if (majority == Majority) return;
        bool before = AnswerDiffers;
        Majority = majority;
        if (AnswerDiffers != before) Refresh();
    }

    // ---- what the line shows ----
    public string Location => Node.Location;
    public string NodeText => Node.ShortId;
    public string NodeMeta => Node.Asn;
    public string StatusText => CheckHostFormat.Status(Entry);
    public string LatencyText => CheckHostFormat.Latency(Entry);
    public string DetailText => CheckHostFormat.Details(Entry, Majority);
    /// <summary>The details line is the node's error (drawn in the danger color).</summary>
    public bool DetailIsError => State == CheckHostState.Failed && Kind != CheckHostKind.Dns;
    /// <summary>DNS: this node's resolver answered differently from most (drawn in the warning color).</summary>
    public bool AnswerDiffers => CheckHostFormat.AnswerDiffers(Entry, Majority);
    public IReadOnlyList<CheckHostReply> Replies => Result?.Replies ?? Array.Empty<CheckHostReply>();
    public bool HasAddress => Result?.Address.Length > 0;

    [ObservableProperty] private bool _isExpanded;

    [RelayCommand] private void ToggleExpand() => IsExpanded = !IsExpanded;

    internal void SetResult(CheckHostResult result)
    {
        Entry.SetResult(result);
        Refresh();
    }

    internal void MarkStopped()
    {
        if (Entry.IsFinal) return;
        Entry.MarkStopped();
        Refresh();
    }

    public override string Describe() => CheckHostFormat.Line(Entry, Majority);

    [RelayCommand] private Task CopyRow() => ClipboardHelper.SetTextAsync(Describe());
    [RelayCommand] private Task CopyAddress() => ClipboardHelper.SetTextAsync(Result?.Address);
    [RelayCommand] private Task CopyNode() => ClipboardHelper.SetTextAsync(Node.Id);

    /// <summary>Case-insensitive match against everything the row shows (and the node's own address / ASN).</summary>
    internal bool Matches(string f)
    {
        static bool Has(string? s, string f) => s is { Length: > 0 } && s.Contains(f, StringComparison.OrdinalIgnoreCase);
        var n = Node;
        if (f.Length == 2 && string.Equals(n.CountryCode, f, StringComparison.OrdinalIgnoreCase)) return true;
        return Has(n.Location, f) || Has(n.Id, f) || Has(n.Region, f) || Has(n.Asn, f) || Has(n.Ip, f)
               || Has(StatusText, f) || Has(DetailText, f) || Has(Result?.Error, f);
    }

    /// <summary>The expanded panel's lines: everything check-host.net reported for this node.</summary>
    public IReadOnlyList<CheckHostDetail> Details
    {
        get
        {
            var n = Node;
            var list = new List<CheckHostDetail>(8)
            {
                new("Node", string.Join("  ·  ", new[] { n.Id, n.Ip, n.Asn }.Where(s => s.Length > 0)), mono: true),
                new("Location", $"{n.Location} · {n.Region}"),
            };
            var r = Result;
            if (r is null)
            {
                list.Add(new("Status", State == CheckHostState.Stopped ? "Stopped before the node reported" : "Waiting for the node to report…"));
                return list;
            }
            string tone = r.State switch { CheckHostState.Ok => "ok", CheckHostState.Warning => "warn", _ => "bad" };
            switch (r.Kind)
            {
                case CheckHostKind.Ping:
                    if (r.Replies.Count > 0 && r.Sent > 0)
                    {
                        var sb = new StringBuilder();
                        for (int i = 0; i < r.Replies.Count; i++)
                        {
                            var p = r.Replies[i];
                            if (i > 0) sb.Append('\n');
                            sb.Append((i + 1).ToString(Inv)).Append("  ").Append(p.Status.PadRight(9))
                              .Append(p.IsOk || p.Status == "MALFORMED" ? CheckHostFormat.Ms(p.Ms) : p.Ms is double w ? "after " + CheckHostFormat.Ms(w) : "");
                        }
                        list.Add(new("Replies", sb.ToString().TrimEnd(), mono: true));
                        list.Add(new("Received", $"{r.Received} of {r.Sent} · {CheckHostFormat.Pct(r.LossPercent)} loss", tone: tone));
                        if (r.MinMs is not null)
                            list.Add(new("Round trip", $"min {CheckHostFormat.Num(r.MinMs)} · avg {CheckHostFormat.Num(r.AvgMs)} · max {CheckHostFormat.Num(r.MaxMs)} ms"
                                                       + (r.JitterMs is double j ? $" · jitter {CheckHostFormat.Num(j)} ms" : "")));
                    }
                    else list.Add(new("Status", r.Error.Length > 0 ? r.Error : r.Status, tone: tone));
                    break;
                case CheckHostKind.Http:
                    list.Add(new("Status", r.HttpCode is not null ? r.Status : r.Error.Length > 0 ? r.Error : r.Status, tone: tone));
                    if (r.LatencyMs is not null) list.Add(new("Time", CheckHostFormat.Ms(r.LatencyMs)));
                    break;
                case CheckHostKind.Tcp:
                    list.Add(new("Result", r.State == CheckHostState.Ok ? $"Connected in {CheckHostFormat.Ms(r.LatencyMs)}" : r.Error, tone: tone));
                    break;
                case CheckHostKind.Udp:
                    list.Add(new("Result", r.State == CheckHostState.Ok ? $"Replied in {CheckHostFormat.Ms(r.LatencyMs)}" : r.Error, tone: tone));
                    break;
                case CheckHostKind.Dns:
                    if (r.RecordCount == 0) list.Add(new("Result", r.Error, tone: tone));
                    if (AnswerDiffers) list.Add(new("Answer", "Different from what most nodes got", tone: "warn"));
                    foreach (var rec in r.Records)
                        if (rec.Value.Length > 0) list.Add(new(rec.Key, string.Join("\n", rec.Value), mono: true));
                    if (r.Ttl is long ttl) list.Add(new("TTL", $"{ttl.ToString(Inv)} s"));
                    break;
            }
            if (r.Kind != CheckHostKind.Dns && r.Address.Length > 0) list.Add(new("Address", r.Address, mono: true));
            if (r.Raw.Length > 0) list.Add(new("Raw", r.Raw, mono: true));
            return list;
        }
    }
}
