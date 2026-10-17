using System;
using System.IO;

namespace Echoes.Helpers;

/// <summary>
/// Resolves a command name ("paplay", "xdg-open", …) to an absolute executable path using only
/// absolute PATH entries plus the standard system directories. A bare name handed to Process.Start
/// is also looked up in the app's own directory and the current directory first on Unix, so an
/// executable planted next to an extracted tarball / in a cloned repo would run instead of the real tool.
/// </summary>
public static class ExecutablePath
{
    private static readonly string[] UnixSystemDirs = { "/usr/bin", "/bin", "/usr/local/bin", "/opt/homebrew/bin" };

    /// <summary>Absolute path of <paramref name="name"/>, or null when it isn't installed.</summary>
    public static string? Find(string name)
    {
        try
        {
            if (Path.IsPathFullyQualified(name)) return File.Exists(name) ? name : null;

            foreach (var raw in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(Path.PathSeparator))
            {
                string dir = raw.Trim().Trim('"');
                if (dir.Length == 0 || !Path.IsPathFullyQualified(dir)) continue;   // skips "", "." and relative entries
                string full = Path.Combine(dir, name);
                if (File.Exists(full)) return full;
            }
            if (!OperatingSystem.IsWindows())
                foreach (var dir in UnixSystemDirs)
                {
                    string full = Path.Combine(dir, name);
                    if (File.Exists(full)) return full;
                }
        }
        catch { /* malformed PATH entry / inaccessible directory */ }
        return null;
    }
}
