using System;
using System.IO;

namespace Echoes.Helpers;

/// <summary>
/// Best-effort crash logger. A diagnostic tool that dies with no trace is the worst failure mode,
/// so unhandled/unobserved exceptions are appended here (next to the binary, or the per-user data
/// dir when that isn't writable). Writing must never throw.
/// </summary>
public static class CrashLog
{
    public static void Write(string source, Exception? ex)
    {
        try
        {
            string path = AppStorage.ResolvePath("echoes-crash.log");
            string entry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {source}: {ex}{Environment.NewLine}{Environment.NewLine}";
            File.AppendAllText(path, entry);
        }
        catch { /* logging must never throw */ }
    }
}
