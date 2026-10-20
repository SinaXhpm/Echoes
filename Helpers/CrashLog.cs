using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace Echoes.Helpers;

/// <summary>
/// Best-effort crash logger. A diagnostic tool that dies with no trace is the worst failure mode,
/// so unhandled/unobserved exceptions are appended here (next to the binary, or the per-user data
/// dir when that isn't writable). Writing must never throw.
/// </summary>
public static class CrashLog
{
    // Bounded: a failure that repeats (an unobserved task every few seconds, a crash loop) must not grow the log until
    // the disk is full. Past MaxBytes the log moves to echoes-crash.old.log (replacing the previous one) and a new one
    // starts, so at most two generations exist. One entry is capped too (an exception can quote a whole response).
    private const long MaxBytes = 1024 * 1024;
    private const int MaxEntryChars = 64 * 1024;
    private const string FileName = "echoes-crash.log", OldFileName = "echoes-crash.old.log";
    private static readonly object Gate = new();   // the background and UI threads can both crash at once

    // Secrets that exception texts can quote: a URL's user:password@ (up to the last '@' of the authority), a scheme-less
    // user:password@host proxy ("Invalid proxy address 'user:pass@1.2.3.4:8080'"), and Telegram bot tokens (digits, ':',
    // the secret part). Replaced by "•••" — the log is the file people attach to bug reports.
    private static readonly Regex Secrets = new(
        @"(?<=://)[^/?#\s'""<>]*(?=@)" +
        @"|(?<=^|[\s'""(=,;])(?!mailto:)[^\s/?#@:'""<>]+:[^\s/?#'""<>]*(?=@)" +
        @"|[0-9]{3,20}:[A-Za-z0-9_-]{20,128}",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    /// <summary>The end of the crash log: at most <paramref name="maxChars"/> characters, starting at a line. Empty when nothing was
    /// logged. The About box's "Copy log" hands it to phones, where the file itself can't be opened.</summary>
    public static string ReadTail(int maxChars = 12_000)
    {
        try
        {
            string path = AppStorage.UserPath(FileName);
            lock (Gate)
            {
                if (!File.Exists(path)) return string.Empty;
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                long take = Math.Min(fs.Length, maxChars * 4L);   // UTF-8: up to 4 bytes a character
                var bytes = new byte[take];
                fs.Seek(fs.Length - take, SeekOrigin.Begin);
                fs.ReadExactly(bytes);
                string text = Encoding.UTF8.GetString(bytes);
                if (take < fs.Length || text.Length > maxChars)
                {
                    if (text.Length > maxChars) text = text[^maxChars..];
                    int line = text.IndexOf('\n');                // the first line is cut: drop it
                    if (line >= 0) text = text[(line + 1)..];
                }
                return text.Trim();
            }
        }
        catch { return string.Empty; }
    }

    public static void Write(string source, Exception? ex)
    {
        try
        {
            string text = $"{source}: {ex}";
            if (text.Length > MaxEntryChars) text = text[..MaxEntryChars] + " … [truncated]";
            try { text = Secrets.Replace(text, "•••"); }
            catch (RegexMatchTimeoutException) { }
            string entry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {text}{Environment.NewLine}{Environment.NewLine}";
            byte[] bytes = Encoding.UTF8.GetBytes(entry);

            // The per-user data folder (the one About → Data opens), never next to the executable: on macOS that is
            // inside the signed Echoes.app bundle, and a read-only install folder would lose the log anyway.
            string path = AppStorage.UserPath(FileName);
            lock (Gate)
            {
                try
                {
                    var info = new FileInfo(path);
                    if (info.Exists && info.Length + bytes.Length > MaxBytes)
                        File.Move(path, Path.Combine(Path.GetDirectoryName(path) ?? string.Empty, OldFileName), overwrite: true);
                }
                catch { /* can't rotate (locked): keep appending — losing the entry would be worse */ }

                // Created owner-only on Linux/macOS: exception text can carry hosts, URLs and paths.
                using var fs = new FileStream(path, AppStorage.PrivateFileOptions(FileMode.Append, FileAccess.Write, FileShare.Read));
                fs.Write(bytes);
            }
        }
        catch { /* logging must never throw */ }
    }
}
