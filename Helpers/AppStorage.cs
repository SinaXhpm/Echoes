using System;
using System.IO;

namespace Echoes.Helpers;

public static class AppStorage
{
    private static bool? _baseDirWritable;

    public static string ResolvePath(string fileName)
    {
        string baseDir = AppContext.BaseDirectory;

        if (IsBaseDirWritable(baseDir))
            return Path.Combine(baseDir, fileName);

        string userDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Echoes");

        try { Directory.CreateDirectory(userDir); } catch { }

        string fallback = Path.Combine(userDir, fileName);
        string primary = Path.Combine(baseDir, fileName);

        if (File.Exists(primary) && !File.Exists(fallback))
        {
            try { File.Copy(primary, fallback); } catch { }
        }

        return fallback;
    }

    /// <summary>
    /// Always resolves to the per-user data directory (%APPDATA%/Echoes, ~/.config/Echoes,
    /// ~/Library/Application Support/Echoes), regardless of whether the app dir is writable.
    /// Use this for per-user / sensitive data (e.g. notes) that should live in the user profile.
    /// Migrates a legacy copy that previously lived next to the binary.
    /// </summary>
    public static string UserPath(string fileName)
    {
        string userDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Echoes");

        try { Directory.CreateDirectory(userDir); } catch { }

        string target = Path.Combine(userDir, fileName);
        string legacy = Path.Combine(AppContext.BaseDirectory, fileName);

        if (File.Exists(legacy) && !File.Exists(target))
        {
            try { File.Copy(legacy, target); } catch { }
        }

        return target;
    }

    private static bool IsBaseDirWritable(string dir)
    {
        if (_baseDirWritable.HasValue) return _baseDirWritable.Value;

        try
        {
            string probe = Path.Combine(dir, ".echoes_write_probe");
            File.WriteAllText(probe, "ok");
            File.Delete(probe);
            _baseDirWritable = true;
        }
        catch
        {
            _baseDirWritable = false;
        }

        return _baseDirWritable.Value;
    }
}
