using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Renci.SshNet;
using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>The Terminal sub-tab: the shell's output (coalesced, capped) and the command line with its history.</summary>
public partial class SshViewModel
{
    [ObservableProperty] private string _commandInput = string.Empty;
    [ObservableProperty] private string _terminalOutput = string.Empty;

    private readonly List<string> _history = new();
    private const int MaxCommandHistory = 500;
    private int _historyIndex = -1;

    // Terminal output is coalesced: the reader only appends to _pending (bounded) and a 100 ms DispatcherTimer moves
    // it into the bound text. Every TerminalOutput change re-shapes and re-wraps the whole text block, so a fast
    // `cat`/`journalctl -f` may cost at most ~10 re-layouts/s of at most 16K chars — not one per chunk or frame.
    private const int MaxTerminalChars = 16 * 1024;
    private static readonly TimeSpan FlushInterval = TimeSpan.FromMilliseconds(100);
    private readonly StringBuilder _pending = new();
    private bool _pendingOverflowed;        // older pending output was dropped: replace the text, don't append
    private bool _flushArmed;               // a StartFlushing is queued or the timer runs; guarded by _pending
    private DispatcherTimer? _flushTimer;   // UI thread only

    // ShellStream.Read blocks until data arrives and returns 0 once the stream is disposed — by Disconnect, by the
    // channel closing (remote `exit`) or by the session dropping — so there is no DataAvailable/Delay polling.
    private void ReadFromStream(ShellStream shell, SshSession session)
    {
        var buffer = new byte[16 * 1024];
        var chars = new char[Encoding.UTF8.GetMaxCharCount(buffer.Length + 4)];
        // Stateful decoder: a multi-byte UTF-8 char split across two reads is held until the rest
        // arrives, instead of both halves turning into U+FFFD.
        var decoder = Encoding.UTF8.GetDecoder();
        string carry = string.Empty;   // an escape sequence (or "\r" of "\r\n") cut off at the end of a read
        try
        {
            int n;
            while ((n = shell.Read(buffer, 0, buffer.Length)) > 0)
            {
                int cc = decoder.GetChars(buffer, 0, n, chars, 0, flush: false);
                string text = carry + new string(chars, 0, cc);
                int cut = IncompleteTailStart(text);
                carry = cut >= 0 ? text[cut..] : string.Empty;
                if (cut >= 0) text = text[..cut];
                if (text.Length > 0) AppendToTerminal(SanitizeAnsi(text));
            }
        }
        catch (Exception) { /* stream torn down mid-read — handled as end of session below */ }

        // Reader ended without Disconnect (remote `exit`, dropped session): tear down so the UI doesn't keep
        // showing Disconnect / live forwards while commands go nowhere. No-op if Disconnect already did.
        StopSession(session);
    }

    private const int MaxCarry = 256;   // bounds the held tail so malformed input can't grow it

    // Start index of a trailing ESC sequence that isn't terminated yet (it continues in the next read),
    // or of a trailing "\r" that may be the first half of "\r\n"; -1 when the text ends cleanly.
    private static int IncompleteTailStart(string s)
    {
        int from = Math.Max(0, s.Length - MaxCarry);
        // OSC (ESC ] … BEL | ESC \), e.g. a window-title update
        int osc = s.LastIndexOf("\x1B]", StringComparison.Ordinal);
        if (osc >= from && s.IndexOf('\x07', osc) < 0 && s.IndexOf("\x1B\\", osc, StringComparison.Ordinal) < 0)
            return osc;
        int esc = s.LastIndexOf('\x1B');
        if (esc >= from)
        {
            if (esc == s.Length - 1) return esc;
            char k = s[esc + 1];
            if (k is >= ' ' and <= '/') { if (esc + 2 >= s.Length) return esc; }   // ESC ( B: needs one more byte
            else if (k == '[')                                                       // CSI: ends at a final byte @-~
            {
                bool done = false;
                for (int i = esc + 2; i < s.Length && !done; i++) done = s[i] is >= '@' and <= '~';
                if (!done) return esc;
            }
        }
        return s.Length > 0 && s[^1] == '\r' ? s.Length - 1 : -1;
    }

    // Any thread.
    private void AppendToTerminal(string text)
    {
        if (text.Length == 0) return;
        lock (_pending)
        {
            _pending.Append(text);
            if (_pending.Length > MaxTerminalChars)
            {
                // The UI fell a whole screenful behind: anything older can never be shown, so don't keep it.
                string all = _pending.ToString();
                int cut = TrimStart(all);
                _pending.Clear().Append(all, cut, all.Length - cut);
                _pendingOverflowed = true;
            }
            if (_flushArmed) return;   // the running timer (or a queued StartFlushing) picks this up
            _flushArmed = true;
        }
        Dispatcher.UIThread.Post(StartFlushing, DispatcherPriority.Background);
    }

    // UI thread. Output after a quiet spell shows at once (a command's echo stays snappy); the rest of a burst
    // waits for the timer ticks.
    private void StartFlushing()
    {
        if (_flushTimer is { IsEnabled: true } || !FlushTerminal()) return;
        if (_flushTimer is null)
        {
            _flushTimer = new DispatcherTimer(DispatcherPriority.Background, Dispatcher.UIThread) { Interval = FlushInterval };
            _flushTimer.Tick += (_, _) => FlushTerminal();
        }
        _flushTimer.Start();
    }

    // UI thread. Moves pending output into the bound text. Once a pass finds nothing new (or the session is over:
    // final) it disarms and stops the timer, so an idle shell costs no wakeups; the next append re-arms it.
    private bool FlushTerminal(bool final = false)
    {
        string chunk;
        bool replace, disarm;
        lock (_pending)
        {
            chunk = _pending.ToString();
            _pending.Clear();
            replace = _pendingOverflowed;
            _pendingOverflowed = false;
            disarm = final || chunk.Length == 0;
            if (disarm) _flushArmed = false;   // under the lock: a racing append either lands in this chunk or
        }                                      // sees false and queues a StartFlushing of its own
        if (disarm) _flushTimer?.Stop();
        if (chunk.Length > 0)
        {
            string s = replace ? chunk : TerminalOutput + chunk;
            TerminalOutput = s.Length > MaxTerminalChars ? s[TrimStart(s)..] : s;
        }
        return !disarm;
    }

    // Where to cut s so at most MaxTerminalChars remain, starting on a line boundary. A line longer than half the
    // cap (minified JSON, base64) is cut mid-line rather than dropped whole, but never inside a surrogate pair.
    private static int TrimStart(string s)
    {
        int from = s.Length - MaxTerminalChars;
        if (from <= 0) return 0;
        int nl = s.IndexOf('\n', from - 1);
        if (nl >= 0 && s.Length - (nl + 1) >= MaxTerminalChars / 2) return nl + 1;
        return char.IsLowSurrogate(s[from]) ? from + 1 : from;
    }

    private string SanitizeAnsi(string input)
    {
        if (string.IsNullOrEmpty(input)) return input;
        // OSC (ESC ] … BEL|ST, e.g. a window title) must come first: the 2-char "ESC ]" alternative would
        // otherwise match and leak the title text ("0;user@host: ~") into the terminal.
        // Two-char escapes are every ESC + 0x30-0x7E except '[' (CSI), not only 0x40-0x5F: zsh's stock zshrc
        // (Debian/Ubuntu/Kali, oh-my-zsh) sends keypad mode ESC = / ESC > around every prompt for vt100, which
        // showed as "=" / ">" garbage; ESC 7/8 and ESC c too. ESC + intermediates + final = charset (ESC ( 0).
        string pattern = @"\x1B\][^\x07\x1B]*(?:\x07|\x1B\\)|\x1B(?:[0-Z\\-~]|\[[0-?]*[ -/]*[@-~]|[ -/]+[0-~])|\x07";
        string result = Regex.Replace(input, pattern, string.Empty);
        return result.Replace("\r\n", "\n").Replace("\r", "\n");
    }

    [RelayCommand]
    private void SendCommand()
    {
        var session = _session;
        var shell = session?.Shell;
        if (shell is null || string.IsNullOrEmpty(CommandInput)) return;
        try
        {
            shell.Write(CommandInput + "\r");
            shell.Flush();
        }
        catch (Exception ex)
        {
            // The channel/session died (remote `exit`, dropped link) before the reader tore it down. This runs
            // on the UI thread, so an escaping ObjectDisposed/SshException would kill the app — report instead.
            AppendToTerminal($"\n# {ex.Message}\n");
            if (session != null) _ = Task.Run(() => StopSession(session));
            return;
        }

        _history.Add(CommandInput);
        // Memory only (never saved), but a long session mustn't grow it without end: Up / Down reach the last ones.
        if (_history.Count > MaxCommandHistory) _history.RemoveRange(0, _history.Count - MaxCommandHistory);
        _historyIndex = _history.Count;
        CommandInput = string.Empty;
    }

    [RelayCommand]
    private void HistoryUp()
    {
        if (_history.Count > 0 && _historyIndex > 0)
        {
            _historyIndex--;
            CommandInput = _history[_historyIndex];
        }
    }

    [RelayCommand]
    private void HistoryDown()
    {
        if (_historyIndex < _history.Count - 1)
        {
            _historyIndex++;
            CommandInput = _history[_historyIndex];
        }
        else
        {
            _historyIndex = _history.Count;
            CommandInput = string.Empty;
        }
    }
}
