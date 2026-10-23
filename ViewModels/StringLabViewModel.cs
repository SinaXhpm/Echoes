using System;
using System.Buffers;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

public partial class StringLabViewModel : ObservableObject
{
    [ObservableProperty] private string _errorMessage = string.Empty;

    // Drives the thin progress bar under the tabs. Only raised for work that is actually slow (see
    // RunOffUi) so quick actions don't flash it.
    [ObservableProperty] private bool _isBusy;

    private void ResetError() => ErrorMessage = string.Empty;

    // Hard ceiling for outputs that expand their input (hex ×3, binary ×9, escapes…): refuse up front
    // rather than build a string that OOMs a phone. The boxes only ever show the first 100 K chars
    // (DisplayCapConverter); this bounds what is kept in memory for COPY.
    private const long MaxOutputChars = 10_000_000;

    // One regex budget for every user-driven pattern in String Lab (and a short one for our own
    // fixed patterns) — a pathological pattern/input pair must never hang a worker thread forever.
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan InternalRegexTimeout = TimeSpan.FromSeconds(2);

    // Tools that currently have work in flight on the thread pool, keyed by tool name. A second
    // click on the same tool while it runs is ignored instead of racing two results into one box.
    private readonly HashSet<string> _runningTools = new();

    /// <summary>
    /// Runs <paramref name="work"/> on the thread pool (big pastes into hash/diff/regex/JSON/XML
    /// would otherwise freeze the UI), then hands the result to <paramref name="apply"/> back on the
    /// UI thread — the await resumes on Avalonia's synchronization context. Inputs must be captured
    /// by the caller on the UI thread; <paramref name="work"/> must not touch bound properties.
    /// </summary>
    private async Task RunOffUi<T>(string tool, Func<T> work, Action<T> apply, string errorPrefix = "")
    {
        if (!_runningTools.Add(tool)) return;
        ResetError();
        try
        {
            var task = Task.Run(work);
            if (await Task.WhenAny(task, Task.Delay(250)) != task) IsBusy = true;
            apply(await task);
        }
        // User patterns get 5 s, our own helper patterns 2 s — report whichever actually fired.
        catch (RegexMatchTimeoutException ex) { ErrorMessage = errorPrefix + $"pattern matching timed out after {ex.MatchTimeout.TotalSeconds:0.#} s (possible catastrophic backtracking)."; }
        catch (OutOfMemoryException) { ErrorMessage = errorPrefix + "Input is too large for this operation."; }
        catch (Exception ex) { ErrorMessage = errorPrefix + ex.Message; }
        finally
        {
            _runningTools.Remove(tool);
            if (_runningTools.Count == 0 && !IsHashingFile) IsBusy = false;
        }
    }

    private static void EnsureOutputSize(long chars, string what)
    {
        if (chars > MaxOutputChars)
            throw new InvalidOperationException($"{what} would be {Math.Ceiling(chars / 100_000.0) / 10:0.#} M characters — refusing (limit {MaxOutputChars / 1_000_000} M). Use a smaller input.");
    }

    private static InvalidOperationException OutputTooLarge(string what)
        => new($"{what} would be over {MaxOutputChars / 1_000_000} M characters — refusing. Use a smaller input.");

    // Pretty-printers multiply their input by more than a fixed factor: the writers (Helpers/CappedWriters.cs) stop at the
    // output ceiling.

    /// <summary>JSON written into a buffer that refuses to grow past the output ceiling (UTF-8 bytes, so the text that
    /// comes back is within the char ceiling too).</summary>
    private static string WriteJsonCapped(JsonWriterOptions options, Action<Utf8JsonWriter> write, string what)
    {
        var buffer = new CappedBufferWriter(MaxOutputChars, () => OutputTooLarge(what));
        using (var w = new Utf8JsonWriter(buffer, options)) write(w);
        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    /// <summary>The StringWriter an XmlWriter formats into, refusing to grow past the output ceiling.</summary>
    private static CappedStringWriter CappedText(StringBuilder sb, string what) => new(sb, MaxOutputChars, () => OutputTooLarge(what));

    /// <summary>For writers that build a StringBuilder line by line (YAML, the YAML subset's JSON): call per line.</summary>
    private static void CheckOutput(StringBuilder sb, string what)
    {
        if (sb.Length > MaxOutputChars) throw OutputTooLarge(what);
    }

    // Shared by every COPY button; the output text arrives as the CommandParameter. Concurrent so one
    // slow clipboard write never greys out the other tabs' COPY buttons.
    [RelayCommand(AllowConcurrentExecutions = true)]
    private async Task CopyText(string? text)
    {
        try { await ClipboardHelper.SetTextAsync(text); }
        catch (Exception ex) { ErrorMessage = "Copy failed: " + ex.Message; }
    }

    [RelayCommand]
    private void Clear(string tab)
    {
        ResetError();
        switch (tab)
        {
            case "b64": B64Input = B64Output = string.Empty; break;
            case "url": UrlInput = UrlOutput = string.Empty; break;
            case "hash":
                _hashFileCts?.Cancel();   // a running file hash would otherwise refill the box
                HashInput = HashOutput = HashKey = HashExpected = HashFileStatus = string.Empty;
                _lastDigests.Clear();
                UpdateHashCompare();
                break;
            case "hex": HexInput = HexOutput = string.Empty; break;
            case "esc": EscInput = EscOutput = string.Empty; break;
            case "regex": RegexInput = RegexOutput = RegexPattern = RegexReplacement = string.Empty; SelectedRegex = null; break;
            case "edit":
                if (EditInput.Length > 0) _editUndo = EditInput;   // CLEAR is undoable too
                EditInput = EditFind = EditReplace = EditPrefix = EditSuffix = string.Empty;
                EditStatus = _editUndo is null ? string.Empty : "Cleared — UNDO brings the text back.";
                break;
            case "json": JsonInput = JsonOutput = string.Empty; break;
            case "xml": XmlInput = XmlOutput = string.Empty; break;
            case "subnet": SubnetInput = SubnetOutput = string.Empty; break;
            case "epoch": EpochInput = EpochOutput = string.Empty; break;
            case "gen": GenerateOutput = GenerateInfo = string.Empty; SetCrackTime(null); break;
            case "baseconv": BaseInput = BaseOutput = BaseFrom = BaseTo = string.Empty; break;
            case "ipconv": IpConvInput = IpConvOutput = string.Empty; break;
            case "hashid": HashIdInput = HashIdOutput = string.Empty; break;
            case "jwt": JwtInput = JwtKey = JwtOutput = JwtVerify = string.Empty; break;
            case "jwtsign":
                JwtSignHeader = DefaultJwtHeader;
                JwtSignPayload = JwtSignSecret = JwtSignOutput = string.Empty;
                break;
            case "diff": DiffLeft = DiffRight = DiffOutput = string.Empty; break;
            case "case": CaseInput = CaseOutput = string.Empty; break;
            case "convert": ConvertInput = ConvertOutput = string.Empty; break;
            case "cron": CronExpression = "* * * * *"; break;
        }
    }
}
