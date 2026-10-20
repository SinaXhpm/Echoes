using System;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Echoes.Helpers;

/// <summary>
/// Where files sent from a browser land, and how they're named. A received name is only a hint from the other device:
/// it is cut to its last path segment, stripped of control / bidi / invisible characters, made valid on Windows
/// (no &lt;&gt;:"/\|?*, no CON/NUL/COM1…, no trailing dots or spaces) and kept short; an existing file is never
/// replaced (" (2)" is added instead). On Windows each file gets the Mark of the Web (Zone.Identifier, ZoneId=3), so
/// SmartScreen and Office treat it like a download from the internet.
/// </summary>
public static class ShareInbox
{
    private const int MaxNameChars = 160;      // leaves room for " (9999)" and the folder path
    private const int MaxNameUtf8 = 200;       // Linux / Android file systems allow 255 bytes per name

    /// <summary>A safe file name for <paramref name="raw"/> (never empty, never a path).</summary>
    public static string SanitizeName(string? raw)
    {
        string s = raw ?? string.Empty;
        int cut = Math.Max(s.LastIndexOf('/'), s.LastIndexOf('\\'));
        if (cut >= 0) s = s[(cut + 1)..];

        var sb = new StringBuilder(s.Length);
        foreach (var rune in s.EnumerateRunes())
        {
            int v = rune.Value;
            if (v < 0x20 || v is >= 0x7F and <= 0x9F) continue;                 // C0 / DEL / C1 controls
            if (v is 0x200B or 0x200C or 0x200D or 0x200E or 0x200F or 0x2060 or 0xFEFF or 0x061C or 0x180E) continue;   // invisible / bidi marks
            if (v is >= 0x202A and <= 0x202E || v is >= 0x2066 and <= 0x2069) continue;                                  // bidi embeddings / overrides / isolates
            if (v is 0x2028 or 0x2029) continue;                                  // line / paragraph separators
            if (v is >= 0xFFF0 and <= 0xFFFF || v is >= 0xE000 and <= 0xF8FF) continue;   // specials, private use
            if (v is 0x00AD || v is >= 0xE0000 and <= 0xE007F) continue;           // soft hyphen, tag characters (invisible)
            // a run of blanks (spaces, or fillers that only look blank) becomes one space: padding can't push the real
            // extension out of sight ("photo.jpg        .exe")
            if (Rune.IsWhiteSpace(rune) || v is 0x3164 or 0x115F or 0x1160 or 0xFFA0 or 0x2800)
            {
                if (sb.Length > 0 && sb[^1] != ' ') sb.Append(' ');
                continue;
            }
            if (v is '<' or '>' or ':' or '"' or '/' or '\\' or '|' or '?' or '*') { sb.Append('_'); continue; }
            sb.Append(rune.ToString());
        }
        // Cut to length first: the checks below must see the name as it will be saved (cutting a long name can expose
        // "CON" or an inner ".lnk", or leave nothing).
        return Guard(Shorten(sb.ToString().Trim()));
    }

    private static string Guard(string s)
    {
        // Windows drops trailing dots and spaces itself ("a.txt." opens "a.txt") — and "..": nothing left
        s = s.TrimEnd('.', ' ');
        if (s.Length == 0 || s.Trim('.').Length == 0) s = "file";

        // Reserved device names, with or without an extension ("con.txt" is the console too)
        string stem = s.Split('.')[0].TrimEnd(' ');
        if (IsReservedDevice(stem)) s = "_" + s;

        // Files that act when a folder is merely shown (an icon fetched from a remote share leaks the user's NTLM hash) or
        // that run when "opened": the extension is broken so a deliberate rename is needed.
        string ext = Path.GetExtension(s).ToLowerInvariant();
        if (ext is ".lnk" or ".url" or ".scf" or ".library-ms" or ".searchconnector-ms" or ".desktop" or ".appref-ms" or ".settingcontent-ms")
            s += "_";
        return s;
    }

    private static bool IsReservedDevice(string stem)
    {
        string u = stem.ToUpperInvariant();
        if (u is "CON" or "PRN" or "AUX" or "NUL" or "CONIN$" or "CONOUT$") return true;
        // COM1-9 / LPT1-9, and the superscript digits Windows also treats as devices
        return u.Length == 4 && (u.StartsWith("COM", StringComparison.Ordinal) || u.StartsWith("LPT", StringComparison.Ordinal))
               && (u[3] is >= '1' and <= '9' or '¹' or '²' or '³');
    }

    // Keep the extension; cut the stem (never between a surrogate pair) until both limits hold.
    private static string Shorten(string s)
    {
        if (s.Length <= MaxNameChars && Encoding.UTF8.GetByteCount(s) <= MaxNameUtf8) return s;
        string ext = Path.GetExtension(s);
        if (ext.Length > 16) ext = string.Empty;
        string stem = s[..^ext.Length];
        while (stem.Length > 1 && (stem.Length + ext.Length > MaxNameChars || Encoding.UTF8.GetByteCount(stem) + Encoding.UTF8.GetByteCount(ext) > MaxNameUtf8))
        {
            int cut = stem.Length - 1;
            if (cut > 0 && char.IsLowSurrogate(stem[cut]) && char.IsHighSurrogate(stem[cut - 1])) cut--;
            stem = stem[..cut];
        }
        return stem.TrimEnd('.', ' ') + ext;
    }

    /// <summary>"name (2).ext" for n = 2 (a leading-dot name like ".bashrc" has no extension).</summary>
    public static string WithCounter(string name, int n) => WithTag(name, n.ToString(CultureInfo.InvariantCulture));

    private static string WithTag(string name, string tag)
    {
        string ext = Path.GetExtension(name);
        if (ext.Length == name.Length || ext.Length > 16) ext = string.Empty;
        string stem = name[..^ext.Length];
        return $"{stem} ({tag}){ext}";
    }

    private const int MaxNumbered = 50;

    /// <summary>Moves a finished upload into <paramref name="folder"/> under <paramref name="name"/> (sanitized
    /// already), or "name (2)" … when that exists — never over an existing file. Past " (50)" a random tag is used
    /// ("name (3fa9c1)"): probing every number up to thousands made each upload of a common name slower than the last.
    /// Returns the final path.</summary>
    public static string FinalizeInto(string partPath, string folder, string name)
    {
        Directory.CreateDirectory(folder);
        for (int n = 1; n <= MaxNumbered + 20; n++)
        {
            string candidate = n == 1 ? name
                : n <= MaxNumbered ? WithCounter(name, n)
                : WithTag(name, Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(3)).ToLowerInvariant());
            string target = Path.Combine(folder, candidate);
            if (File.Exists(target) || Directory.Exists(target)) continue;
            try
            {
                File.Move(partPath, target, overwrite: false);
                return target;
            }
            catch (IOException) when (File.Exists(target) || Directory.Exists(target))
            {
                // another upload took the name a moment ago: try the next one
            }
        }
        throw new IOException("There are too many files with that name in the folder.");
    }

    /// <summary>Windows: marks a received file as coming from another computer (ZoneId=3, the internet zone). A file
    /// system without alternate streams (FAT32 / exFAT sticks) just doesn't keep it.</summary>
    public static bool MarkOfTheWeb(string path)
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            File.WriteAllText(path + ":Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\n", Encoding.ASCII);
            return true;
        }
        catch { return false; }
    }

    /// <summary>Executables and scripts: the app offers "Show in folder" for them, not "Open".</summary>
    public static bool IsRiskyToOpen(string name)
    {
        string ext = Path.GetExtension(name).ToLowerInvariant().TrimEnd('_');
        return ext is ".exe" or ".msi" or ".msix" or ".appx" or ".bat" or ".cmd" or ".com" or ".scr" or ".pif" or ".cpl" or ".ps1"
            or ".psm1" or ".vbs" or ".vbe" or ".js" or ".jse" or ".wsf" or ".wsh" or ".hta" or ".lnk" or ".url" or ".scf" or ".reg"
            or ".jar" or ".sh" or ".command" or ".app" or ".appimage" or ".desktop" or ".run" or ".py" or ".pl" or ".apk"
            or ".library-ms" or ".searchconnector-ms" or ".appref-ms" or ".settingcontent-ms" or ".msc" or ".gadget" or ".inf"
            or ".dll" or ".sys" or ".chm" or ".iso" or ".img" or ".vhd" or ".vhdx";
    }

    /// <summary>Free bytes on the volume holding <paramref name="folder"/> (or its nearest existing parent); -1 unknown.</summary>
    public static long FreeSpace(string folder)
    {
        try
        {
            string? dir = folder;
            while (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) dir = Path.GetDirectoryName(dir);
            if (string.IsNullOrEmpty(dir)) return -1;
            // Windows: the drive root; elsewhere DriveInfo takes any path on the mount (statvfs)
            var drive = new DriveInfo(OperatingSystem.IsWindows() ? Path.GetPathRoot(Path.GetFullPath(dir))! : dir);
            return drive.AvailableFreeSpace;
        }
        catch { return -1; }
    }

    /// <summary>Desktop: Downloads\Echoes. Android: a folder in the app's own storage (files are then saved out of it, or
    /// copied into the folder the user picked). iOS: Documents/Received, which the Files app shows.</summary>
    public static string DefaultFolder()
        => OperatingSystem.IsAndroid() ? Path.Combine(AppStorage.UserDir(), "Inbox")
            : OperatingSystem.IsIOS() ? IosReceivedFolder()
            : Path.Combine(DownloadsFolder(), "Echoes");

    /// <summary>iOS: Documents/Received. The Info.plist keys UIFileSharingEnabled and LSSupportsOpeningDocumentsInPlace make
    /// the Documents folder show up in the Files app (On My iPhone › Echoes), so received files are reachable there.</summary>
    public static string IosReceivedFolder()
    {
        string docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        if (string.IsNullOrEmpty(docs) || !Path.IsPathRooted(docs)) docs = AppStorage.UserDir();
        return Path.Combine(docs, "Received");
    }

    /// <summary>iOS: an app update or a reinstall gives the app a new container folder, so a path saved by an earlier run
    /// points into the old one. What follows "/Documents/" is put under this container's Documents. Null when the result is
    /// not inside the received folder: Clean up may only ever reach files in it.</summary>
    public static string? RebaseIos(string path)
    {
        const string marker = "/Documents/";
        int at = path.IndexOf(marker, StringComparison.Ordinal);
        if (at < 0) return null;
        string docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        if (string.IsNullOrEmpty(docs) || !Path.IsPathRooted(docs)) return null;
        try
        {
            string full = Path.GetFullPath(docs.TrimEnd('/') + path[(at + marker.Length - 1)..]);   // ".." can't climb out
            return full.StartsWith(Path.GetFullPath(IosReceivedFolder()).TrimEnd('/') + "/", StringComparison.Ordinal) ? full : null;
        }
        catch { return null; }
    }

    /// <summary>Where uploads are written while they arrive on Android (app storage).</summary>
    public static string AppInboxFolder() => Path.Combine(AppStorage.UserDir(), "Inbox");

    /// <summary>The user's Downloads folder: the shell's known folder on Windows (it may have been moved), XDG on Linux,
    /// ~/Downloads elsewhere.</summary>
    public static string DownloadsFolder()
    {
        if (OperatingSystem.IsWindows())
        {
            try
            {
                var id = new Guid("374DE290-123F-4565-9164-39C4925E467B");   // FOLDERID_Downloads
                if (SHGetKnownFolderPath(in id, 0, IntPtr.Zero, out IntPtr p) == 0 && p != IntPtr.Zero)
                {
                    try
                    {
                        string? s = Marshal.PtrToStringUni(p);
                        if (!string.IsNullOrEmpty(s) && Path.IsPathRooted(s)) return s;
                    }
                    finally { Marshal.FreeCoTaskMem(p); }
                }
            }
            catch { /* fall through to the profile folder */ }
        }
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (OperatingSystem.IsLinux() && XdgDownloads(home) is { } xdg) return xdg;
        return Path.Combine(string.IsNullOrEmpty(home) ? Path.GetTempPath() : home, "Downloads");
    }

    // XDG_DOWNLOAD_DIR="$HOME/Downloads" in ~/.config/user-dirs.dirs (localized desktops rename it)
    private static string? XdgDownloads(string home)
    {
        try
        {
            string cfg = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME") is { Length: > 0 } c ? c : Path.Combine(home, ".config");
            string file = Path.Combine(cfg, "user-dirs.dirs");
            if (!File.Exists(file)) return null;
            foreach (var line in File.ReadLines(file))
            {
                var l = line.Trim();
                if (!l.StartsWith("XDG_DOWNLOAD_DIR=", StringComparison.Ordinal)) continue;
                string v = l["XDG_DOWNLOAD_DIR=".Length..].Trim().Trim('"').Replace("$HOME", home, StringComparison.Ordinal);
                return Path.IsPathRooted(v) ? v : null;
            }
        }
        catch { }
        return null;
    }

    [DllImport("shell32.dll", ExactSpelling = true)]
    private static extern int SHGetKnownFolderPath(in Guid rfid, uint dwFlags, IntPtr hToken, out IntPtr ppszPath);
}
