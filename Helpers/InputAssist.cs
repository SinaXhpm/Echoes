using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Data;
using Avalonia.Input;
using Avalonia.Input.Platform;
using Avalonia.Input.TextInput;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Threading;
using Avalonia.VisualTree;

namespace Echoes.Helpers;

/// <summary>How a field cleans what is pasted into it (<see cref="InputAssist.PasteModeProperty"/>).</summary>
public enum PasteMode
{
    /// <summary>Plain paste, nothing intercepted.</summary>
    None,
    /// <summary>Plain text — only the paste button is added (String Lab inputs).</summary>
    Text,
    /// <summary>One host or IP (Ping, SSH).</summary>
    Host,
    /// <summary>One host, preferring a domain name over an IP (DNS).</summary>
    Domain,
    /// <summary>One host, preferring an IP over a domain name (IP Info).</summary>
    Ip,
    /// <summary>Whatever endpoint the text names — URL, host:port or host (Check-Host).</summary>
    Endpoint,
    /// <summary>A URL; a pasted curl command yields its URL (cURL).</summary>
    Url,
    /// <summary>IPs / hosts / CIDR / ranges, one per line (port scanner).</summary>
    Targets,
    /// <summary>Entries one per line — trimmed, bullets and duplicates removed (monitor).</summary>
    Lines,
    /// <summary>A Telegram bot token.</summary>
    Token,
}

/// <summary>
/// Attached input behaviours for the app's entry fields. Works on a plain <see cref="TextBox"/> or an
/// <see cref="AutoCompleteBox"/> (it drives the inner TextBox).
///
/// <c>SelectAllOnFocus</c> — the click/tap that brings focus INTO the field selects the whole value, so a
/// paste or typing replaces it in one go. Only that first click; later clicks place the caret normally,
/// and a drag-select on the first click is respected. (Tab-focus already selects all in TextBox.)
///
/// <c>PasteMode</c> — a paste (Ctrl+V, context menu, Android paste, the paste button) is cleaned for the
/// field: the host out of a URL / log line / e-mail / defanged IOC, a URL out of a curl command, targets
/// out of a blob, … (see <see cref="HostExtractor"/>). The result goes in through the TextBox's own input
/// path, so Ctrl+Z undoes it; Ctrl+Shift+V pastes the raw text instead; when the clipboard holds nothing
/// usable the text is pasted as-is rather than replaced by junk. A short hint says what was cleaned.
///
/// <c>PasteButton</c> — a small paste icon inside the field (right edge) doing the same thing.
///
/// <c>UserTarget</c> / <c>PortTarget</c> — names of sibling fields that receive the user / port found in a
/// pasted "user@host:port" or "ssh -p 2222 user@host" (SSH), instead of those parts being dropped.
///
/// Phone keyboards (<see cref="Install"/>): a host / URL / list field gets no autocorrect or word suggestions, a URL
/// keyboard for one address and English where Android has it; a masked box is kept out of the keyboard's memory; and
/// digits typed in the phone's language (Persian, Arabic, Hindi ...) become ASCII in the fields that hold numbers and addresses.
/// </summary>
public static class InputAssist
{
    public static readonly AttachedProperty<bool> SelectAllOnFocusProperty =
        AvaloniaProperty.RegisterAttached<Control, bool>("SelectAllOnFocus", typeof(InputAssist));

    public static readonly AttachedProperty<PasteMode> PasteModeProperty =
        AvaloniaProperty.RegisterAttached<Control, PasteMode>("PasteMode", typeof(InputAssist));

    public static readonly AttachedProperty<bool> PasteButtonProperty =
        AvaloniaProperty.RegisterAttached<Control, bool>("PasteButton", typeof(InputAssist));

    public static readonly AttachedProperty<string?> UserTargetProperty =
        AvaloniaProperty.RegisterAttached<Control, string?>("UserTarget", typeof(InputAssist));

    public static readonly AttachedProperty<string?> PortTargetProperty =
        AvaloniaProperty.RegisterAttached<Control, string?>("PortTarget", typeof(InputAssist));

    // Set by the pointer press that moves focus into the field; consumed by the matching release.
    private static readonly AttachedProperty<bool> PendingSelectAllProperty =
        AvaloniaProperty.RegisterAttached<Control, bool>("PendingSelectAll", typeof(InputAssist));

    // Paste-hint bookkeeping (the field's own tooltip is restored afterwards).
    private static readonly AttachedProperty<DispatcherTimer?> HintTimerProperty =
        AvaloniaProperty.RegisterAttached<Control, DispatcherTimer?>("HintTimer", typeof(InputAssist));
    private static readonly AttachedProperty<bool> HintActiveProperty =
        AvaloniaProperty.RegisterAttached<Control, bool>("HintActive", typeof(InputAssist));
    private static readonly AttachedProperty<object?> SavedTipProperty =
        AvaloniaProperty.RegisterAttached<Control, object?>("SavedTip", typeof(InputAssist));
    private static readonly AttachedProperty<PlacementMode> SavedPlacementProperty =
        AvaloniaProperty.RegisterAttached<Control, PlacementMode>("SavedPlacement", typeof(InputAssist));

    public static void SetSelectAllOnFocus(Control c, bool v) => c.SetValue(SelectAllOnFocusProperty, v);
    public static bool GetSelectAllOnFocus(Control c) => c.GetValue(SelectAllOnFocusProperty);
    public static void SetPasteMode(Control c, PasteMode v) => c.SetValue(PasteModeProperty, v);
    public static PasteMode GetPasteMode(Control c) => c.GetValue(PasteModeProperty);
    public static void SetPasteButton(Control c, bool v) => c.SetValue(PasteButtonProperty, v);
    public static bool GetPasteButton(Control c) => c.GetValue(PasteButtonProperty);
    public static void SetUserTarget(Control c, string? v) => c.SetValue(UserTargetProperty, v);
    public static string? GetUserTarget(Control c) => c.GetValue(UserTargetProperty);
    public static void SetPortTarget(Control c, string? v) => c.SetValue(PortTargetProperty, v);
    public static string? GetPortTarget(Control c) => c.GetValue(PortTargetProperty);

    // Above this the clipboard is pasted untouched: cleaning runs on the UI thread.
    private const int MaxCleanLength = 2_000_000;

    // Ctrl+Shift+V re-runs the TextBox's own Paste(); this lets that one call through untouched.
    private static bool _rawPasteInProgress;

    static InputAssist()
    {
        SelectAllOnFocusProperty.Changed.AddClassHandler<Control>((c, e) =>
        {
            // handledEventsToo: TextBox marks its pointer events handled (caret placement / capture).
            c.RemoveHandler(InputElement.PointerPressedEvent, OnPointerPressed);
            c.RemoveHandler(InputElement.PointerReleasedEvent, OnPointerReleased);
            c.RemoveHandler(InputElement.LostFocusEvent, OnLostFocus);
            if (e.NewValue is true)
            {
                c.AddHandler(InputElement.PointerPressedEvent, OnPointerPressed, RoutingStrategies.Tunnel, handledEventsToo: true);
                c.AddHandler(InputElement.PointerReleasedEvent, OnPointerReleased, RoutingStrategies.Bubble, handledEventsToo: true);
                c.AddHandler(InputElement.LostFocusEvent, OnLostFocus, RoutingStrategies.Bubble, handledEventsToo: true);
            }
        });

        PasteModeProperty.Changed.AddClassHandler<Control>((c, e) =>
        {
            // PastingFromClipboard bubbles out of an AutoCompleteBox's inner TextBox too.
            c.RemoveHandler(TextBox.PastingFromClipboardEvent, OnPasting);
            c.RemoveHandler(InputElement.KeyDownEvent, OnKeyDown);
            if (e.NewValue is PasteMode m && IsSmart(m))
            {
                c.AddHandler(TextBox.PastingFromClipboardEvent, OnPasting, RoutingStrategies.Bubble);
                c.AddHandler(InputElement.KeyDownEvent, OnKeyDown, RoutingStrategies.Tunnel);
                TechnicalKeyboard(c, m);
            }
        });

        PasteButtonProperty.Changed.AddClassHandler<Control>((c, e) =>
        {
            if (e.NewValue is true) AttachPasteButton(c);
            else DetachPasteButton(c);
        });

        // Tunnel: runs before the TextBox inserts the text, which can still be rewritten.
        InputElement.TextInputEvent.AddClassHandler<TextBox>(OnTextInput, RoutingStrategies.Tunnel);

        // A masked box (password, passphrase, API token): the keyboard neither suggests nor learns what is typed (Gboard
        // otherwise keeps typed passwords in its dictionary), iOS treats it as secure entry.
        TextBox.PasswordCharProperty.Changed.AddClassHandler<TextBox>((tb, _) =>
        {
            if (tb.PasswordChar != default) tb.SetValue(TextInputOptions.IsSensitiveProperty, true, BindingPriority.Style);
        });
    }

    /// <summary>Registers the app-wide handlers (typed digits, masked boxes) before the first view exists; the attached
    /// properties register theirs as they are set.</summary>
    public static void Install()   // the static constructor does the rest
    {
        // Phone: a flyout opens without moving focus into its first field (the standard mode does, for keyboard users),
        // which put the keyboard up over the options before anything was tapped. A tap on a field focuses it as usual.
        if (!AppPlatform.IsMobile || _flyoutsHooked) return;
        _flyoutsHooked = true;
        Button.FlyoutProperty.Changed.AddClassHandler<Button>((_, e) => NoFocusOnOpen(e.NewValue));
        FlyoutBase.AttachedFlyoutProperty.Changed.AddClassHandler<Control>((_, e) => NoFocusOnOpen(e.NewValue));
    }

    private static bool _flyoutsHooked;

    private static void NoFocusOnOpen(object? flyout)
    {
        if (flyout is PopupFlyoutBase { ShowMode: FlyoutShowMode.Standard } f) f.ShowMode = FlyoutShowMode.Transient;
    }

    private static bool IsSmart(PasteMode m) => m is not (PasteMode.None or PasteMode.Text);

    // ---------------------------------------------------------------- phone keyboards

    private static readonly IReadOnlyList<string> EnglishHint = ["en-US"];

    // Hosts, URLs and lists of them: autocorrect "fixed" github.com to GitHub.com and a word still being composed was
    // left out of the value when a button was tapped; one address gets the URL keyboard (".", "/" at hand); Android
    // switches to English where the user has it (iOS has no such hint); a bot token stays out of the keyboard's memory.
    // Style priority: what a view sets on the field itself wins.
    private static void TechnicalKeyboard(Control c, PasteMode m)
    {
        c.SetValue(TextInputOptions.ShowSuggestionsProperty, false, BindingPriority.Style);
        c.SetValue(TextInputOptions.LocaleHintsProperty, EnglishHint, BindingPriority.Style);
        if (m is PasteMode.Host or PasteMode.Domain or PasteMode.Ip or PasteMode.Endpoint or PasteMode.Url)
            c.SetValue(TextInputOptions.ContentTypeProperty, TextInputContentType.Url, BindingPriority.Style);
        else if (m is PasteMode.Token)
            c.SetValue(TextInputOptions.IsSensitiveProperty, true, BindingPriority.Style);
    }

    // Digits typed in the phone's language become ASCII where the value is a number, a port, an address or a URL: a
    // NumericUpDown or a number keyboard always, a host / URL field unless it already holds non-ASCII letters (someone
    // typing an internationalised domain, whose digits are part of the name). Elsewhere (messages, String Lab) the text
    // is the user's and stays as typed.
    private static void OnTextInput(object? sender, TextInputEventArgs e)
    {
        if (sender is not TextBox tb || e.Text is not { Length: > 0 } text) return;
        var host = tb.TemplatedParent as Control ?? tb;   // the NumericUpDown / AutoCompleteBox around an inner box
        var type = TextInputOptions.GetContentType(tb);
        bool number = host is NumericUpDown || type is TextInputContentType.Digits or TextInputContentType.Number or TextInputContentType.Pin;
        if (!number && !((IsSmart(GetPasteMode(host)) || type is TextInputContentType.Url or TextInputContentType.Email)
                         && !LocalDigits.HasNonAsciiLetter(tb.Text)))
            return;

        string folded = LocalDigits.Fold(text);
        // a box that takes fractions (Ping's interval) reads only "."; there "0,5" is a decimal comma, never thousands
        if (host is NumericUpDown nud && (nud.FormatString.Contains('.') || nud.Increment % 1 != 0))
            folded = folded.Replace(',', '.');
        if (folded != text) e.Text = folded;
    }

    // ---------------------------------------------------------------- select-all on the first focusing click

    private static void OnPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        // Tunnel phase runs before the TextBox takes focus, so "not focused yet" == this click is the
        // one entering the field. A click inside an already-focused field — or on the paste button,
        // which manages focus itself — is left alone.
        if (sender is Control host && !host.IsKeyboardFocusWithin && !IsInPasteButton(e.Source as Visual, host))
            host.SetValue(PendingSelectAllProperty, true);
    }

    private static void OnPointerReleased(object? sender, PointerReleasedEventArgs e)
    {
        if (sender is not Control host || !host.GetValue(PendingSelectAllProperty)) return;
        host.SetValue(PendingSelectAllProperty, false);

        var tb = InnerTextBox(host);
        if (tb is null) return;
        // Post so it runs after the TextBox finishes its own press/release caret handling.
        Dispatcher.UIThread.Post(() =>
        {
            // Respect a drag-selection made with this same click; only select when it's a plain click.
            if (tb.IsKeyboardFocusWithin && tb.SelectionStart == tb.SelectionEnd && !string.IsNullOrEmpty(tb.Text))
                tb.SelectAll();
        }, DispatcherPriority.Input);
    }

    private static void OnLostFocus(object? sender, FocusChangedEventArgs e)
    {
        // A press whose release never reached the field (e.g. captured elsewhere) must not leave a
        // stale flag that would select-all on some later, unrelated click.
        if (sender is Control host && !host.IsKeyboardFocusWithin)
            host.SetValue(PendingSelectAllProperty, false);
    }

    // ---------------------------------------------------------------- paste interception

    private static async void OnPasting(object? sender, RoutedEventArgs e)
    {
        if (_rawPasteInProgress || sender is not Control host) return;
        var mode = GetPasteMode(host);
        if (!IsSmart(mode)) return;
        var tb = e.Source as TextBox ?? InnerTextBox(host);
        if (tb is null || tb.IsReadOnly) return;

        e.Handled = true;   // suppress the raw paste; the cleaned value is written below
        try
        {
            string? raw = await ReadClipboardAsync(tb);
            if (string.IsNullOrEmpty(raw)) return;
            Apply(host, tb, raw, mode, fromButton: false, focusedBefore: true);
        }
        catch (Exception ex) { CrashLog.Write("InputAssist.Paste", ex); }   // never escape an async void handler
    }

    // Ctrl+Shift+V (Cmd+Shift+V on macOS): paste exactly what's on the clipboard, no cleaning.
    private static void OnKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key != Key.V || !e.KeyModifiers.HasFlag(KeyModifiers.Shift)) return;
        if (!e.KeyModifiers.HasFlag(KeyModifiers.Control) && !e.KeyModifiers.HasFlag(KeyModifiers.Meta)) return;
        if (sender is not Control host || InnerTextBox(host) is not { IsReadOnly: false } tb) return;

        e.Handled = true;
        _rawPasteInProgress = true;
        try { tb.Paste(); }   // raises PastingFromClipboard synchronously — let that one through
        finally { _rawPasteInProgress = false; }
    }

    // ---------------------------------------------------------------- the paste button

    private static Geometry? _pasteIcon;

    // A clipboard outline in the 24x24 grid the app's other glyphs use.
    private static Geometry PasteIcon => _pasteIcon ??= StreamGeometry.Parse(
        "M9 2.5h6v3.5H9z M8 4.25H6.5A1.5 1.5 0 0 0 5 5.75v14.5a1.5 1.5 0 0 0 1.5 1.5h11a1.5 1.5 0 0 0 1.5-1.5V5.75a1.5 1.5 0 0 0-1.5-1.5H16 M9 11.5h6 M9 15.5h4");

    private static void AttachPasteButton(Control host)
    {
        if (host is not (TextBox or AutoCompleteBox)) return;

        var btn = new Button
        {
            Focusable = false,       // keep focus (and the caret) where the user left it
            Content = new Avalonia.Controls.Shapes.Path { Data = PasteIcon, Stretch = Stretch.Uniform, Width = 14, Height = 14 },
        };
        btn.Classes.Add("pasteBtn");
        ToolTip.SetTip(btn, IsSmart(GetPasteMode(host))
            ? (AppPlatform.IsMobile ? "Paste (cleaned)" : "Paste (cleaned) — Ctrl+Shift+V pastes as-is")
            : "Paste");

        // Was the field already being edited before this click? Captured on the press (tunnel) because
        // the press itself may move focus into the field.
        bool focusedBefore = false;
        btn.AddHandler(InputElement.PointerPressedEvent,
            (_, _) => focusedBefore = InnerTextBox(host)?.IsKeyboardFocusWithin == true,
            RoutingStrategies.Tunnel, handledEventsToo: true);
        btn.Click += async (_, _) =>
        {
            try { await PasteFromButtonAsync(host, focusedBefore); }
            catch (Exception ex) { CrashLog.Write("InputAssist.PasteButton", ex); }
        };

        // A long press on the icon is about the icon (a phone shows its tooltip), not the field's text selection and menu.
        btn.AddHandler(InputElement.HoldingEvent, (_, e) => e.Handled = true);
        btn.AddHandler(InputElement.ContextRequestedEvent, (_, e) => e.Handled = true);

        // A tall multi-line box gets the icon in its top-right corner instead of the vertical middle.
        btn.AttachedToVisualTree += (_, _) => btn.Classes.Set("top", InnerTextBox(host)?.AcceptsReturn == true);

        if (host is TextBox tb) tb.InnerRightContent = btn;
        else if (host is AutoCompleteBox acb) acb.InnerRightContent = btn;
    }

    private static void DetachPasteButton(Control host)
    {
        if (host is TextBox tb && tb.InnerRightContent is Button { Classes: var c1 } && c1.Contains("pasteBtn"))
            tb.InnerRightContent = null;
        else if (host is AutoCompleteBox acb && acb.InnerRightContent is Button { Classes: var c2 } && c2.Contains("pasteBtn"))
            acb.InnerRightContent = null;
    }

    private static bool IsInPasteButton(Visual? v, Control host)
    {
        for (; v is not null && !ReferenceEquals(v, host); v = v.GetVisualParent())
            if (v is Button b && b.Classes.Contains("pasteBtn")) return true;
        return false;
    }

    private static async Task PasteFromButtonAsync(Control host, bool focusedBefore)
    {
        var tb = InnerTextBox(host);
        if (tb is null || tb.IsReadOnly || !tb.IsEffectivelyEnabled) return;

        string? raw = await ReadClipboardAsync(tb);
        if (string.IsNullOrEmpty(raw)) { ShowHint(host, "The clipboard has no text"); return; }

        tb.Focus();   // so Enter runs the tool right after pasting
        Apply(host, tb, raw, GetPasteMode(host), fromButton: true, focusedBefore);
    }

    // ---------------------------------------------------------------- cleaning + insertion

    private sealed record Outcome(string Text, IReadOnlyList<string>? Lines, bool Changed, string? Note,
                                  string? User = null, int? Port = null);

    private static void Apply(Control host, TextBox tb, string raw, PasteMode mode, bool fromButton, bool focusedBefore)
    {
        var o = Clean(raw, mode, host);
        if (o is null) return;

        string current = tb.Text ?? string.Empty;
        int s = Math.Clamp(Math.Min(tb.SelectionStart, tb.SelectionEnd), 0, current.Length);
        int e = Math.Clamp(Math.Max(tb.SelectionStart, tb.SelectionEnd), 0, current.Length);
        string insert = o.Text;
        string? note = o.Note;

        if (mode is PasteMode.Targets or PasteMode.Lines && o.Lines is { } lines)
        {
            // Lists: the button adds to what's there (unless the user was editing at a spot); entries
            // already in the box are skipped, and every entry keeps a line of its own.
            if (fromButton && !focusedBefore) s = e = current.Length;
            var existing = new HashSet<string>(
                (current[..s] + "\n" + current[e..]).Split('\n', '\r').Select(l => l.Trim()).Where(l => l.Length > 0),
                StringComparer.OrdinalIgnoreCase);
            var fresh = lines.Where(l => !existing.Contains(l)).ToList();
            if (fresh.Count == 0) { ShowHint(host, "Already in the list"); return; }
            if (fresh.Count < lines.Count) note = Join(note, $"{lines.Count - fresh.Count} already listed");
            string nl = string.IsNullOrEmpty(tb.NewLine) ? "\n" : tb.NewLine;
            insert = string.Join(nl, fresh);
            if (s > 0 && current[s - 1] is not ('\n' or '\r')) insert = nl + insert;
            if (e < current.Length && current[e] is not ('\n' or '\r')) insert += nl;
        }
        else if (mode is PasteMode.Text or PasteMode.None)
        {
            if (fromButton && !focusedBefore) { s = 0; e = current.Length; }   // the button fills the box
        }
        else
        {
            // One-value fields: the button, an empty / fully selected box, or text that had to be cleaned
            // replaces the whole value (it holds exactly one host / URL); a clean fragment pasted into a
            // partial selection behaves like a normal paste ("www." + "example.com").
            bool whole = current.Length == 0 || (s == 0 && e == current.Length);
            if (fromButton || whole || o.Changed) { s = 0; e = current.Length; }
        }

        // Through the TextBox's input path: an undoable edit (Ctrl+Z), MaxLength / AcceptsReturn honoured,
        // and the caret lands right after the inserted text.
        tb.SelectionStart = s;
        tb.SelectionEnd = e;
        tb.SelectedText = insert;

        SetCompanion(host, GetUserTarget(host), o.User);
        SetCompanion(host, GetPortTarget(host), o.Port?.ToString());

        // An AutoCompleteBox treats the edit as typing and may pop its history list over the result.
        if (host is AutoCompleteBox acb)
            Dispatcher.UIThread.Post(() => acb.IsDropDownOpen = false, DispatcherPriority.Input);

        // Secret fields turn undo off (no earlier values kept in the undo history), so don't promise it there.
        if (note is not null)
            ShowHint(host, o.Changed && !AppPlatform.IsMobile && tb.IsUndoEnabled ? note + "  ·  Ctrl+Z undoes" : note);
    }

    private static Outcome? Clean(string raw, PasteMode mode, Control host)
    {
        if (!IsSmart(mode)) return new Outcome(raw, null, false, null);   // plain-text field: paste as-is
        if (raw.Length > MaxCleanLength)
            return new Outcome(raw, null, false, "Clipboard too large to clean — pasted as-is");

        // An address and port from a chat, typed on a Persian keyboard, read in ASCII digits. A URL or list keeps its
        // digits when it holds other letters too (a path or domain in that script, where they are part of the name).
        if (mode is not (PasteMode.Url or PasteMode.Lines) || !LocalDigits.HasNonAsciiLetter(raw)) raw = LocalDigits.Fold(raw);

        string trimmed = raw.Trim();
        string? defangNote = HostExtractor.WasDefanged(raw) ? "defanged text restored" : null;

        switch (mode)
        {
            case PasteMode.Host or PasteMode.Domain or PasteMode.Ip:
            {
                var prefer = mode switch
                {
                    PasteMode.Domain => HostExtractor.Prefer.Domain,
                    PasteMode.Ip => HostExtractor.Prefer.Ip,
                    _ => HostExtractor.Prefer.Any,
                };
                var all = HostExtractor.FindAll(raw);
                if (HostExtractor.Best(raw, prefer) is not { } best)
                    return AsIs(raw, mode == PasteMode.Domain ? "No domain or IP found — pasted as-is" : "No host or IP found — pasted as-is");

                bool userField = !string.IsNullOrEmpty(GetUserTarget(host));
                bool portField = !string.IsNullOrEmpty(GetPortTarget(host));
                string? note = Origin(best);
                if (best.Port is int p) note = Join(note, portField ? $"port {p} → Port" : $"port {p} dropped");
                if (best.User is { } u && userField) note = Join(note, $"user {u} → User");
                int hosts = all.Select(f => f.Host).Distinct(StringComparer.OrdinalIgnoreCase).Count();
                if (hosts > 1) note = Join(note, $"first of {hosts} hosts");
                note = Join(note, defangNote);
                return new Outcome(best.Host, null, best.Host != trimmed, Capitalize(note),
                                   userField ? best.User : null, portField ? best.Port : null);
            }

            case PasteMode.Endpoint:
            {
                if (HostExtractor.Best(raw) is not { } best) return AsIs(raw, "No host, URL or IP found — pasted as-is");
                string value = best.Via == "url" && best.Url is { } url ? url : best.HostPort;
                string? note = best.Via == "url" ? (value != trimmed ? "URL extracted" : null) : Origin(best);
                return new Outcome(value, null, value != trimmed, Capitalize(Join(note, defangNote)));
            }

            case PasteMode.Url:
            {
                var url = HostExtractor.ExtractUrl(raw, out bool fromCurl);
                if (url is null) return AsIs(raw, "No URL found — pasted as-is");
                string? note = fromCurl ? "URL taken from the curl command" : url != trimmed ? "URL extracted" : null;
                return new Outcome(url, null, url != trimmed, Capitalize(Join(note, defangNote)));
            }

            case PasteMode.Targets:
            {
                var targets = HostExtractor.ExtractTargets(raw);
                if (targets.Count == 0) return AsIs(raw, "No IP, host, range or CIDR found — pasted as-is", keepLines: true);
                bool changed = !SameLines(targets, raw);
                string? note = changed ? $"{targets.Count} target{(targets.Count == 1 ? "" : "s")} extracted" : null;
                return new Outcome(string.Join("\n", targets), targets, changed, Capitalize(Join(note, defangNote)));
            }

            case PasteMode.Lines:
            {
                var lines = HostExtractor.CleanLines(raw);
                if (lines.Count == 0) return null;
                bool changed = !SameLines(lines, raw);
                return new Outcome(string.Join("\n", lines), lines, changed, changed ? "List cleaned (bullets, blanks, duplicates)" : null);
            }

            case PasteMode.Token:
            {
                if (HostExtractor.ExtractBotToken(raw) is not { } token) return AsIs(raw, "No bot token found — pasted as-is");
                return new Outcome(token, null, token != trimmed, token != trimmed ? "Bot token extracted" : null);
            }

            default:
                return new Outcome(raw, null, false, null);   // unreachable: handled by IsSmart above
        }
    }

    // Nothing recognisable: paste the text itself (first line for one-value fields) so the user sees what
    // was on the clipboard, instead of a junk token or silently doing nothing.
    private static Outcome AsIs(string raw, string note, bool keepLines = false)
    {
        string text = keepLines ? raw.Trim() : FirstLine(raw);
        return new Outcome(text, keepLines ? text.Split('\n', '\r').Select(l => l.Trim()).Where(l => l.Length > 0).ToList() : null,
                           false, note);
    }

    private static string FirstLine(string raw)
    {
        foreach (var line in raw.Split('\n', '\r'))
            if (line.Trim() is { Length: > 0 } l) return l;
        return raw.Trim();
    }

    private static bool SameLines(IReadOnlyList<string> cleaned, string raw)
    {
        var rawLines = raw.Split('\n', '\r').Select(l => l.Trim()).Where(l => l.Length > 0).ToList();
        return rawLines.Count == cleaned.Count && rawLines.SequenceEqual(cleaned, StringComparer.Ordinal);
    }

    private static string? Origin(HostExtractor.Found f) => f.Via switch
    {
        "url" => "host taken from the URL",
        "user@host" => "host taken from user@host / e-mail",
        "unc" => "host taken from the network path",
        "proxy" => "host taken from the proxy line",
        _ => null,
    };

    private static string? Join(string? a, string? b)
        => string.IsNullOrEmpty(a) ? b : string.IsNullOrEmpty(b) ? a : a + " · " + b;

    private static string? Capitalize(string? s)
        => string.IsNullOrEmpty(s) ? s : char.ToUpperInvariant(s[0]) + s[1..];

    // Push a parsed part (user / port) into a named sibling field; its binding carries it to the VM.
    private static void SetCompanion(Control host, string? name, string? value)
    {
        if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(value)) return;
        // FindControl walks up to the nearest name scope (the view), where the sibling field is registered.
        switch (host.FindControl<Control>(name))
        {
            case TextBox t: t.Text = value; break;
            case AutoCompleteBox a: a.Text = value; break;
        }
    }

    // ---------------------------------------------------------------- hint

    // A short tooltip under the field saying what the paste did. The field's own tooltip and placement
    // are restored when it closes.
    private static void ShowHint(Control host, string text)
    {
        if (!host.GetValue(HintActiveProperty))
        {
            host.SetValue(SavedTipProperty, ToolTip.GetTip(host));
            host.SetValue(SavedPlacementProperty, ToolTip.GetPlacement(host));
            host.SetValue(HintActiveProperty, true);
        }
        ToolTip.SetTip(host, text);
        ToolTip.SetPlacement(host, PlacementMode.Bottom);
        ToolTip.SetIsOpen(host, true);

        var timer = host.GetValue(HintTimerProperty);
        if (timer is null)
        {
            var t = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3.2) };
            t.Tick += (_, _) => { t.Stop(); EndHint(host); };
            host.SetValue(HintTimerProperty, t);
            timer = t;
        }
        timer.Stop();
        timer.Start();
    }

    private static void EndHint(Control host)
    {
        if (!host.GetValue(HintActiveProperty)) return;
        ToolTip.SetIsOpen(host, false);
        ToolTip.SetTip(host, host.GetValue(SavedTipProperty));
        ToolTip.SetPlacement(host, host.GetValue(SavedPlacementProperty));
        host.SetValue(HintActiveProperty, false);
    }

    // ---------------------------------------------------------------- helpers

    private static async Task<string?> ReadClipboardAsync(Control c)
    {
        var clipboard = TopLevel.GetTopLevel(c)?.Clipboard;
        if (clipboard is null) return null;
        try { return await clipboard.TryGetTextAsync(); }
        catch { return null; }   // clipboard held by another process
    }

    private static TextBox? InnerTextBox(Control host)
        => host as TextBox ?? host.GetVisualDescendants().OfType<TextBox>().FirstOrDefault();
}
