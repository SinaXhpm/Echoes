using CommunityToolkit.Mvvm.ComponentModel;
using Echoes.Helpers;
using System.Collections.Generic;
using System.Linq;

namespace Echoes.ViewModels;

/// <summary>One DNS answer (or a status line) shown as a row in the Lookup results.</summary>
public sealed class DnsRecordRow
{
    /// <summary>The most of a value a row shows (a 4096-bit DKIM key is ~750 characters). The results list isn't
    /// virtualized, and a resolver or zone can answer 64 KB of TXT: 20 rows of 60,000 characters took over a minute to
    /// lay out.</summary>
    public const int MaxShown = 1024;

    private string _value = "", _shown = "";

    public string Type { get; init; } = "";
    /// <summary>What the row shows: the value with control / bidi characters replaced, cut at <see cref="MaxShown"/>
    /// (or less, <see cref="ShowAtMost"/>).</summary>
    public string Value
    {
        get => _shown;
        init
        {
            _value = RemoteText.Clean(value);
            _shown = RemoteText.Shorten(_value, MaxShown);
        }
    }
    /// <summary>The whole value (control / bidi characters replaced): what Copy puts on the clipboard.</summary>
    public string CopyValue => _value;
    /// <summary>Shows less of a long value (the lookup's overall budget ran out). Call before the row is posted.</summary>
    internal void ShowAtMost(int max) => _shown = RemoteText.Shorten(_value, Math.Min(max, MaxShown));
    /// <summary>The resolver, short ("1.1.1.1", "cloudflare-dns.com", "system").</summary>
    public string Server { get; init; } = "";
    /// <summary>What carried the answer and how long it took: "DoH h2 · 23 ms".</summary>
    public string Meta { get; init; } = "";
    /// <summary>The resolver line in full (tooltip).</summary>
    public string ServerTip { get; init; } = "";
    public bool IsStatus { get; init; }            // "no records" / "timeout" — not a real, copyable record
    public bool IsRecord => !IsStatus;
    public string ServerLine => Meta.Length == 0 ? Server : Server.Length == 0 ? Meta : $"{Server} · {Meta}";
}

/// <summary>One resolver in the presets menu (a toggle: on when its line is in the list).</summary>
public sealed partial class PresetChip : ObservableObject
{
    public PresetChip(string label, string line, string tip, System.Action<PresetChip> toggle)
    {
        Toggle = new CommunityToolkit.Mvvm.Input.RelayCommand(() => toggle(this));
        Label = label;
        Line = line;
        Tip = tip;
        Canonical = ResolverSpec.TryParse(line, out var s, out _) ? s.Text : line;
    }
    public string Label { get; }
    public string Line { get; }
    public string Tip { get; }
    public string Canonical { get; }
    /// <summary>Adds the line to the resolver list, or takes it out.</summary>
    public CommunityToolkit.Mvvm.Input.IRelayCommand Toggle { get; }
    [ObservableProperty] private bool _isOn;
}

/// <summary>A provider row in the presets menu: its name, a note ("Iran", "blocks ads") and its forms.</summary>
public sealed class PresetGroup
{
    public PresetGroup(string name, string note, IReadOnlyList<PresetChip> chips) { Name = name; Note = note; Chips = chips; }
    public string Name { get; }
    public string Note { get; }
    public bool HasNote => Note.Length > 0;
    public IReadOnlyList<PresetChip> Chips { get; }
}

/// <summary>One resolver's line in the Compare table (updated live while the rounds run).</summary>
public sealed partial class CompareRow : ObservableObject
{
    public CompareRow(ResolverSpec spec)
    {
        Spec = spec;
        Label = spec.Label == spec.Short ? spec.Short : spec.Label;
        SpecText = spec.Label == spec.Short || spec.Transport == DnsTransport.System ? "" : spec.Short;
        Transport = spec.TransportLabel;
    }

    public ResolverSpec Spec { get; }
    public string Label { get; }
    public string SpecText { get; }
    public bool HasSpecText => SpecText.Length > 0;
    public string Transport { get; }
    public bool IsEncrypted => Spec.IsEncrypted;
    public string Tip => Spec.Text;

    [ObservableProperty] private string _medianText = "…";
    [ObservableProperty] private string _rateText = "";
    [ObservableProperty] private string _answersText = "";
    [ObservableProperty] private string _answersTip = "";
    [ObservableProperty] private string _verdictText = "…";
    [ObservableProperty] private string _note = "";
    [ObservableProperty] private bool _isBest;
    [ObservableProperty] private bool _isGood;
    [ObservableProperty] private bool _isWarn;
    [ObservableProperty] private bool _isBad;
    /// <summary>The phone layout's second line: transport · median · rounds · answers.</summary>
    [ObservableProperty] private string _summaryLine = "";

    /// <summary>The run was stopped before this row's verdict: no "…" is left as if it were still running.</summary>
    public void MarkStopped()
    {
        if (MedianText == "…") MedianText = "—";
        if (VerdictText == "…") VerdictText = "stopped";
        SummaryLine = string.Join(" · ", new[] { Transport, MedianText, RateText, AnswersText }.Where(x => x.Length > 0));
    }

    /// <summary>Copies what <paramref name="s"/> has so far (call on the UI thread; reads under the stats' lock).</summary>
    public void Update(CompareStats s, bool final)
    {
        lock (s)
        {
            MedianText = s.Median is { } m ? DnsCompare.Ms(m) : s.Attempts > 0 && s.Successes == 0 ? "—" : "…";
            RateText = s.Attempts == 0 ? "" : $"{s.Successes}/{s.Attempts}";
            if (s.Values.Count > 0)
            {
                // values are the resolver's (a TXT can be 8,000 characters): cleaned and cut for the cell and the tooltip
                AnswersText = string.Join(", ", s.Values.Take(3).Select(v => RemoteText.Clean(v, 80))) + (s.Values.Count > 3 ? $" +{s.Values.Count - 3}" : "");
                AnswersTip = string.Join("\n", s.Values.Take(20).Select(v => RemoteText.Clean(v, 300))) + (s.Values.Count > 20 ? "\n…" : "");
            }
            else if (s.SawNxDomain) { AnswersText = "NXDOMAIN"; AnswersTip = "the resolver says the name doesn't exist"; }
            else if (s.SawEmpty) { AnswersText = "no records"; AnswersTip = "the name exists but has no records of this type"; }
            else if (s.Attempts > 0 && s.Successes == 0) { AnswersText = s.LastShortError ?? "no answer"; AnswersTip = RemoteText.Clean(s.LastError, 400); }
            else { AnswersText = ""; AnswersTip = ""; }
            SummaryLine = string.Join(" · ", new[] { Transport, MedianText, RateText, AnswersText }.Where(x => x.Length > 0));

            if (!final) return;
            VerdictText = s.IsBest ? "best" : DnsCompare.VerdictText(s.Verdict);
            Note = RemoteText.Clean(s.Note, 400);
            IsBest = s.IsBest;
            IsGood = s.Verdict == CompareVerdict.Ok;
            IsWarn = s.Verdict is CompareVerdict.Unstable or CompareVerdict.Differs;
            IsBad = s.Verdict is CompareVerdict.Filtered or CompareVerdict.Tampered or CompareVerdict.Failed;
        }
    }
}

/// <summary>One finding in the Email check results.</summary>
public sealed class MailRow
{
    public MailRow(MailCheckItem item) => Item = item;
    public MailCheckItem Item { get; }
    public string Area => Item.Area;
    public string Summary => Item.Summary;
    public string Detail => Item.Detail ?? "";
    public string FixText => Item.Fix is { Length: > 0 } f ? f : "";
    public bool HasDetail => Detail.Length > 0;
    public bool HasFix => FixText.Length > 0;
    public string StatusText => MailCheck.StatusWord(Item.Status);
    public bool IsOk => Item.Status == MailStatus.Ok;
    public bool IsInfo => Item.Status == MailStatus.Info;
    public bool IsWarn => Item.Status == MailStatus.Warning;
    public bool IsFail => Item.Status == MailStatus.Fail;
    /// <summary>The first finding of its area (a rule above it separates the areas).</summary>
    public bool IsAreaStart { get; init; }
}
