using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using Echoes.Helpers;

namespace Echoes.ViewModels;

/// <summary>
/// What String Lab remembers between visits and launches: the tool that was open (category + tool), each tool's options,
/// and the few short boxes that work like settings — the regex pattern / replacement, the Text lab's find / replace /
/// prefix / suffix / separator, the base conversion's number and bases, the cron expression, and the subnet, IP and
/// epoch boxes. Saved once typing pauses; app exit / backgrounding flush a pending save (MainViewModel.FlushPersistence).
/// <para>Not kept, on purpose: the payload boxes (Base64, URL, hex, escape, hash, JWT, regex input, Text lab, case, diff,
/// JSON, XML, convert inputs and every output) — they can be megabytes, and they are where tokens get pasted — and the
/// secrets (the HMAC key, the JWT key and signing secret).</para>
/// </summary>
public partial class StringLabViewModel
{
    // The open tool: the category strip, then each category's own tool strip.
    [ObservableProperty] private int _categoryIndex;
    [ObservableProperty] private int _encodeToolIndex;
    [ObservableProperty] private int _textToolIndex;
    [ObservableProperty] private int _dataToolIndex;
    [ObservableProperty] private int _devToolIndex;

    private const int MaxPrefChars = 256;     // a short box longer than this isn't a setting: not kept
    private const int MaxPatternChars = 2048; // regex pattern / replacement

    private bool _prefsLoaded;
    private bool _prefsPending;   // UI thread only
    private CancellationTokenSource? _prefsCts;

    private static readonly HashSet<string> PrefProps = new()
    {
        nameof(CategoryIndex), nameof(EncodeToolIndex), nameof(TextToolIndex), nameof(DataToolIndex), nameof(DevToolIndex),
        nameof(HexUpper), nameof(HexSeparator), nameof(HashFormat),
        nameof(RegexPattern), nameof(RegexReplacement), nameof(RegexIgnoreCase), nameof(RegexMultiline),
        nameof(RegexSingleline), nameof(RegexExplicitCapture),
        nameof(EditFind), nameof(EditReplace), nameof(EditIgnoreCase), nameof(EditPrefix), nameof(EditSuffix), nameof(EditSeparator),
        nameof(DiffIgnoreCase), nameof(DiffIgnoreWhitespace), nameof(DiffIgnoreBlankLines),
        nameof(BaseInput), nameof(BaseFrom), nameof(BaseTo), nameof(CronExpression),
        nameof(SubnetInput), nameof(IpConvInput), nameof(EpochInput),
        nameof(GenerateLength), nameof(GenerateCount), nameof(GenSymbols), nameof(GenExcludeAmbiguous),
    };

    /// <summary>Called by the constructor, before anything is shown.</summary>
    private void RestorePrefs()
    {
        var ps = ProfileService.Instance;
        string? S(string key, int max) => ps.GetSetting(key) is { } v && v.Length <= max ? v : null;

        CategoryIndex = Math.Clamp(ps.GetInt("lab.cat", 0), 0, 3);
        EncodeToolIndex = Math.Clamp(ps.GetInt("lab.encodeTool", 0), 0, 7);
        TextToolIndex = Math.Clamp(ps.GetInt("lab.textTool", 0), 0, 3);
        DataToolIndex = Math.Clamp(ps.GetInt("lab.dataTool", 0), 0, 2);
        DevToolIndex = Math.Clamp(ps.GetInt("lab.devTool", 0), 0, 5);

        HexUpper = ps.GetBool("lab.hexUpper");
        if (S("lab.hexSep", MaxPrefChars) is { } sep && Array.IndexOf(HexSeparators, sep) >= 0) HexSeparator = sep;
        if (S("lab.hashFormat", MaxPrefChars) is { } hf && Array.IndexOf(HashFormats, hf) >= 0) HashFormat = hf;

        RegexPattern = S("lab.regex", MaxPatternChars) ?? RegexPattern;
        RegexReplacement = S("lab.regexReplace", MaxPatternChars) ?? RegexReplacement;
        RegexIgnoreCase = ps.GetBool("lab.regexI");
        RegexMultiline = ps.GetBool("lab.regexM");
        RegexSingleline = ps.GetBool("lab.regexS");
        RegexExplicitCapture = ps.GetBool("lab.regexN");

        EditFind = S("lab.editFind", MaxPrefChars) ?? EditFind;
        EditReplace = S("lab.editReplace", MaxPrefChars) ?? EditReplace;
        EditIgnoreCase = ps.GetBool("lab.editI");
        EditPrefix = S("lab.editPrefix", MaxPrefChars) ?? EditPrefix;
        EditSuffix = S("lab.editSuffix", MaxPrefChars) ?? EditSuffix;
        EditSeparator = S("lab.editSep", MaxPrefChars) ?? EditSeparator;

        DiffIgnoreCase = ps.GetBool("lab.diffI");
        DiffIgnoreWhitespace = ps.GetBool("lab.diffW");
        DiffIgnoreBlankLines = ps.GetBool("lab.diffB");

        BaseInput = S("lab.baseIn", MaxPrefChars) ?? BaseInput;
        BaseFrom = S("lab.baseFrom", MaxPrefChars) ?? BaseFrom;
        BaseTo = S("lab.baseTo", MaxPrefChars) ?? BaseTo;
        if (S("lab.cron", MaxPrefChars) is { Length: > 0 } cron) CronExpression = cron;   // fans out to the five fields
        if (S("lab.subnet", MaxPrefChars) is { Length: > 0 } subnet) SubnetInput = subnet;
        IpConvInput = S("lab.ipconv", MaxPrefChars) ?? IpConvInput;
        EpochInput = S("lab.epoch", MaxPrefChars) ?? EpochInput;

        GenerateLength = Math.Clamp(ps.GetInt("lab.genLength", GenerateLength), 1, 4096);
        GenerateCount = Math.Clamp(ps.GetInt("lab.genCount", GenerateCount), 1, 1000);
        GenSymbols = ps.GetBool("lab.genSymbols", GenSymbols);
        GenExcludeAmbiguous = ps.GetBool("lab.genNoAmbiguous", GenExcludeAmbiguous);

        _prefsLoaded = true;
    }

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (_prefsLoaded && e.PropertyName is { } n && PrefProps.Contains(n)) SchedulePrefsSave();
    }

    // Debounced: the boxes change on every keystroke, and a save is one more profile write.
    private void SchedulePrefsSave()
    {
        _prefsPending = true;
        _prefsCts?.Cancel();
        _prefsCts?.Dispose();
        var cts = _prefsCts = new CancellationTokenSource();
        _ = Task.Delay(600, cts.Token).ContinueWith(t =>
        {
            // Values are read back on the UI thread at write time, so the latest edit always wins.
            if (!t.IsCanceled) Avalonia.Threading.Dispatcher.UIThread.Post(FlushPendingSave);
        }, TaskScheduler.Default);
    }

    /// <summary>Persist a pending (debounced) change now. No-op when nothing is pending. UI thread only.</summary>
    public void FlushPendingSave()
    {
        _prefsCts?.Cancel();
        if (!_prefsPending) return;
        _prefsPending = false;
        var inv = CultureInfo.InvariantCulture;
        static string B(bool b) => b ? "true" : "false";
        static string T(string? s, int max) => s is { } v && v.Length <= max ? v : string.Empty;
        ProfileService.Instance.SetMany(
            ("lab.cat", Math.Max(CategoryIndex, 0).ToString(inv)), ("lab.encodeTool", Math.Max(EncodeToolIndex, 0).ToString(inv)),
            ("lab.textTool", Math.Max(TextToolIndex, 0).ToString(inv)), ("lab.dataTool", Math.Max(DataToolIndex, 0).ToString(inv)),
            ("lab.devTool", Math.Max(DevToolIndex, 0).ToString(inv)),
            ("lab.hexUpper", B(HexUpper)), ("lab.hexSep", T(HexSeparator, MaxPrefChars)), ("lab.hashFormat", T(HashFormat, MaxPrefChars)),
            ("lab.regex", T(RegexPattern, MaxPatternChars)), ("lab.regexReplace", T(RegexReplacement, MaxPatternChars)),
            ("lab.regexI", B(RegexIgnoreCase)), ("lab.regexM", B(RegexMultiline)), ("lab.regexS", B(RegexSingleline)),
            ("lab.regexN", B(RegexExplicitCapture)),
            ("lab.editFind", T(EditFind, MaxPrefChars)), ("lab.editReplace", T(EditReplace, MaxPrefChars)), ("lab.editI", B(EditIgnoreCase)),
            ("lab.editPrefix", T(EditPrefix, MaxPrefChars)), ("lab.editSuffix", T(EditSuffix, MaxPrefChars)),
            ("lab.editSep", T(EditSeparator, MaxPrefChars)),
            ("lab.diffI", B(DiffIgnoreCase)), ("lab.diffW", B(DiffIgnoreWhitespace)), ("lab.diffB", B(DiffIgnoreBlankLines)),
            ("lab.baseIn", T(BaseInput, MaxPrefChars)), ("lab.baseFrom", T(BaseFrom, MaxPrefChars)), ("lab.baseTo", T(BaseTo, MaxPrefChars)),
            ("lab.cron", T(CronExpression, MaxPrefChars)), ("lab.subnet", T(SubnetInput, MaxPrefChars)),
            ("lab.ipconv", T(IpConvInput, MaxPrefChars)), ("lab.epoch", T(EpochInput, MaxPrefChars)),
            ("lab.genLength", Math.Clamp(GenerateLength, 1, 4096).ToString(inv)), ("lab.genCount", Math.Clamp(GenerateCount, 1, 1000).ToString(inv)),
            ("lab.genSymbols", B(GenSymbols)), ("lab.genNoAmbiguous", B(GenExcludeAmbiguous)));
    }
}
