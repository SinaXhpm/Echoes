using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Versioning;
using System.Threading.Tasks;

namespace Echoes.Helpers;

public static class AppStorage
{
    private static bool? _baseDirWritable;

    // Owner-only modes for the per-user data on desktop Linux/macOS. Earlier builds created the dir 0755 and the files
    // 0644, so any local user could read the input history, the SSH host pins and the proxy passwords. (Windows:
    // %APPDATA% is per-user by ACL already. Android: app storage is private already — left alone.)
    private const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode OwnerFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private static readonly object PermsGate = new();
    private static bool _permsTightened;

    public static string ResolvePath(string fileName)
    {
        string baseDir = AppContext.BaseDirectory;

        // Next to the executable only on Windows (portable copies of old builds kept their files there). Elsewhere the
        // install folder is Echoes.app/Contents/MacOS (the signed bundle), /usr/bin or a read-only AppImage mount: even
        // probing it for write access would drop a file inside.
        if (OperatingSystem.IsWindows() && IsBaseDirWritable(baseDir))
            return Path.Combine(baseDir, fileName);

        string userDir = UserDir();

        string fallback = Path.Combine(userDir, fileName);
        string primary = Path.Combine(baseDir, fileName);

        if (File.Exists(primary) && !File.Exists(fallback))
        {
            try { File.Copy(primary, fallback); MakePrivate(fallback); } catch { }   // a copy keeps the source's mode
        }

        return fallback;
    }

    /// <summary>
    /// The per-user data directory (%APPDATA%/Echoes, ~/.config/Echoes, ~/Library/Application Support/Echoes),
    /// created if missing. On desktop Linux/macOS it is created owner-only (0700), and the first call of a run also
    /// tightens an existing directory (0700) and the files already in it (0600). Never throws.
    /// </summary>
    public static string UserDir()
    {
        string dir = Path.Combine(AppDataRoot(), "Echoes");
        try
        {
            if (OperatingSystem.IsWindows() || OperatingSystem.IsAndroid())
            {
                Directory.CreateDirectory(dir);
            }
            else
            {
                Directory.CreateDirectory(dir, OwnerOnly);   // the mode applies only if it is created now
                TightenOnce(dir);
            }
        }
        catch { }
        return dir;
    }

    // On Linux / macOS, GetFolderPath returns "" when the folder doesn't exist yet (a fresh account without ~/.config or
    // $XDG_CONFIG_HOME) — and Path.Combine("", "Echoes") is a RELATIVE path: the data (profile, notes, the secret key, the
    // instance lock) silently went into whatever directory Echoes was started from. Create the folder instead, and never
    // hand out a relative path: fall back to ~/.config, then (no home at all) the temp dir.
    private static string AppDataRoot()
    {
        string root = string.Empty;
        try { root = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData, Environment.SpecialFolderOption.Create); }
        catch { }
        if (!string.IsNullOrEmpty(root) && Path.IsPathRooted(root)) return root;

        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return !string.IsNullOrEmpty(home) && Path.IsPathRooted(home) ? Path.Combine(home, ".config") : Path.GetTempPath();
    }

    /// <summary>
    /// Always resolves to the per-user data directory (see <see cref="UserDir"/>), regardless of whether the app dir
    /// is writable. Use this for per-user / sensitive data (e.g. notes) that should live in the user profile.
    /// Migrates a legacy copy that previously lived next to the binary.
    /// </summary>
    public static string UserPath(string fileName)
    {
        string userDir = UserDir();

        string target = Path.Combine(userDir, fileName);
        string legacy = Path.Combine(AppContext.BaseDirectory, fileName);

        // App run straight from the data dir: "legacy" IS the live file — never move or delete it.
        // (Case-insensitive on purpose: a false match only skips the migration, the safe direction.)
        if (SamePath(legacy, target)) return target;

        // MOVE, not copy: a copy left beside the binary gets zipped / synced / shared with a portable app
        // folder, and it resurrects deleted data (delete the user-dir file to reset → the next launch copies
        // the old one back). Copy only as a fallback when the app folder can't be modified.
        if (File.Exists(legacy) && !File.Exists(target))
        {
            try { File.Move(legacy, target); }
            catch { try { File.Copy(legacy, target); } catch { } }
            MakePrivate(target);   // both keep the old file's (world-readable) mode
        }
        // Pre-0.2.6 notes.dat (AES-CBC, fixed global salt, 5000 iterations) that an older build already
        // migrated by copy: it's a cheap, precomputable oracle for the master password (which also guards
        // the current notes + Cloudflare vaults), so remove it. Harmless no-op in a read-only app folder.
        // Only when it isn't NEWER than the migrated copy: a newer one means an old build was run again from
        // the app folder and wrote notes there that the user-dir vault doesn't have.
        else if (fileName == "notes.dat" && File.Exists(legacy) && File.Exists(target))
        {
            try
            {
                if (File.GetLastWriteTimeUtc(legacy) <= File.GetLastWriteTimeUtc(target)) File.Delete(legacy);
            }
            catch { }
        }

        return target;
    }

    private static bool SamePath(string a, string b)
    {
        try { return string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), StringComparison.OrdinalIgnoreCase); }
        catch { return true; }   // can't tell → treat as the same file and leave it alone
    }

    /// <summary>Options for creating a data file: owner-only (0600) on desktop Linux/macOS. A rename keeps the mode,
    /// so a file written via temp + rename stays private too.</summary>
    public static FileStreamOptions PrivateFileOptions(FileMode mode, FileAccess access = FileAccess.Write,
                                                      FileShare share = FileShare.None)
    {
        var o = new FileStreamOptions { Mode = mode, Access = access, Share = share };
        if (!OperatingSystem.IsWindows() && !OperatingSystem.IsAndroid()) o.UnixCreateMode = OwnerFile;
        return o;
    }

    /// <summary>Owner-only (0600) for a file copied / moved into the data dir (both keep the source's mode).
    /// No-op on Windows and Android; never throws.</summary>
    public static void MakePrivate(string path)
    {
        if (OperatingSystem.IsWindows() || OperatingSystem.IsAndroid()) return;
        StripGroupOther(path, isDir: false);
    }

    [UnsupportedOSPlatform("windows")]
    private static void TightenOnce(string dir)
    {
        lock (PermsGate)
        {
            if (_permsTightened) return;
            _permsTightened = true;
            StripGroupOther(dir, isDir: true);
            try { foreach (string f in Directory.EnumerateFiles(dir)) StripGroupOther(f, isDir: false); } catch { }
        }
    }

    // Drop the group/other bits, keep the owner's. A symlinked file points outside the data dir: left alone.
    [UnsupportedOSPlatform("windows")]
    private static void StripGroupOther(string path, bool isDir)
    {
        try
        {
            if (!isDir && new FileInfo(path).LinkTarget is not null) return;
            UnixFileMode mode = File.GetUnixFileMode(path);
            UnixFileMode want = isDir ? OwnerOnly : mode & OwnerOnly;
            if (want != mode) File.SetUnixFileMode(path, want);
        }
        catch { }
    }

    /// <summary>
    /// Crash-safe replace of <paramref name="path"/>: write a temp file in the same directory, flush it to
    /// disk, then rename it over the target (an atomic rename on Unix/Android, MoveFileEx on Windows). A
    /// failure mid-way (disk full, process kill, power loss) leaves the previous file intact instead of a
    /// truncated one — the vaults have no other copy. Callers serialize writes to one path (the temp name is fixed).
    /// </summary>
    public static void WriteAllBytesAtomic(string path, byte[] data)
    {
        string tmp = path + ".tmp";
        try
        {
            using (var fs = new FileStream(tmp, PrivateFileOptions(FileMode.Create)))
            {
                fs.Write(data);
                fs.Flush(flushToDisk: true);
            }
            File.Move(tmp, path, overwrite: true);
        }
        catch
        {
            try { File.Delete(tmp); } catch { }
            throw;
        }
    }

    /// <summary>Create <paramref name="path"/> holding <paramref name="data"/> only if it doesn't exist yet, never
    /// leaving a partial file (unique temp + flush + no-overwrite rename). Throws an IOException if it exists.</summary>
    public static void CreateNewFileAtomic(string path, byte[] data)
    {
        string tmp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";   // unique: racing creators never share one
        try
        {
            using (var fs = new FileStream(tmp, PrivateFileOptions(FileMode.CreateNew)))
            {
                fs.Write(data);
                fs.Flush(flushToDisk: true);
            }
            File.Move(tmp, path, overwrite: false);
        }
        finally
        {
            try { File.Delete(tmp); } catch { }   // already gone after a successful move (a no-op then)
        }
    }

    // ---------- Background writes ----------
    private static readonly Dictionary<string, AtomicFileWriter> Writers = new(StringComparer.Ordinal);

    /// <summary>The one shared background writer for <paramref name="path"/>: every writer of that file (the notes
    /// autosave, a backup restore) goes through the same queue and lock, so an older write can never land last.</summary>
    public static AtomicFileWriter WriterFor(string path)
    {
        string key;
        try { key = Path.GetFullPath(path); } catch { key = path; }
        lock (Writers)
        {
            // Desktop: anything still queued when the process exits is written first (Android: FlushPersistence).
            if (Writers.Count == 0) AppDomain.CurrentDomain.ProcessExit += (_, _) => FlushAllWriters();
            if (!Writers.TryGetValue(key, out var w)) Writers[key] = w = new AtomicFileWriter(path);
            return w;
        }
    }

    private static void FlushAllWriters()
    {
        AtomicFileWriter[] all;
        lock (Writers) { all = new AtomicFileWriter[Writers.Count]; Writers.Values.CopyTo(all, 0); }
        foreach (var w in all) w.Flush();
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

/// <summary>
/// Coalescing, serialized background writer for one file. <see cref="Enqueue"/> hands over the newest bytes and returns
/// at once; the thread pool writes them with <see cref="AppStorage.WriteAllBytesAtomic"/>, so a slow disk / fsync never
/// stalls the UI thread. Only the latest pending bytes are kept (each enqueue is a complete file). <see cref="Flush"/>
/// blocks until everything enqueued before it is on disk — app exit, backgrounding, and before the file is read.
/// Get the instance via <see cref="AppStorage.WriterFor"/>.
/// </summary>
public sealed class AtomicFileWriter
{
    private readonly string _path;
    private readonly object _io = new();     // held across "take pending + write": Flush can't return before a write that took newer bytes
    private readonly object _gate = new();   // guards _pending / _draining
    private byte[]? _pending;
    private bool _draining;

    /// <summary>A background or flush write failed (disk full, permissions). The bytes stay pending and are retried by
    /// the next <see cref="Enqueue"/> / <see cref="Flush"/>. Raised on the writing thread.</summary>
    public event Action<Exception>? WriteFailed;

    internal AtomicFileWriter(string path) => _path = path;

    public void Enqueue(byte[] data)
    {
        lock (_gate)
        {
            _pending = data;
            if (_draining) return;
            _draining = true;
        }
        _ = Task.Run(Drain);
    }

    /// <summary>Write whatever is pending now, waiting for a write in flight. Safe from any thread; never throws.</summary>
    public void Flush()
    {
        lock (_io)
        {
            byte[]? data;
            lock (_gate) { data = _pending; _pending = null; }
            if (data is null || TryWrite(data)) return;
            lock (_gate) _pending ??= data;   // still failing: keep it for a later retry
        }
    }

    /// <summary>Replace the file with <paramref name="data"/> synchronously, dropping any pending (older) bytes — a
    /// backup restore, which must not be overwritten afterwards by an autosave queued before it. Throws on failure.</summary>
    public void WriteNow(byte[] data)
    {
        lock (_io)
        {
            lock (_gate) _pending = null;
            AppStorage.WriteAllBytesAtomic(_path, data);
        }
    }

    private void Drain()
    {
        while (true)
        {
            lock (_io)
            {
                byte[]? data;
                lock (_gate)
                {
                    data = _pending;
                    _pending = null;
                    if (data is null) { _draining = false; return; }
                }
                if (TryWrite(data)) continue;
                lock (_gate)
                {
                    if (_pending is not null) continue;   // newer bytes arrived meanwhile: try those
                    _pending = data;                      // keep the failed bytes for the next Enqueue / Flush
                    _draining = false;
                    return;
                }
            }
        }
    }

    private bool TryWrite(byte[] data)
    {
        try
        {
            AppStorage.WriteAllBytesAtomic(_path, data);
            return true;
        }
        catch (Exception ex)
        {
            try { WriteFailed?.Invoke(ex); } catch { }
            return false;
        }
    }
}
