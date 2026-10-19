using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Security;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Win32;

namespace Echoes.Helpers;

/// <summary>Which kind of login entry a <see cref="AutoStartTarget"/> manages.</summary>
public enum AutoStartKind
{
    /// <summary>A value under HKCU\…\CurrentVersion\Run (plus its Task Manager on/off flag under StartupApproved).</summary>
    Windows,
    /// <summary>An XDG autostart .desktop file (~/.config/autostart).</summary>
    Linux,
    /// <summary>A LaunchAgent plist with RunAtLoad (~/Library/LaunchAgents).</summary>
    MacOS,
}

/// <summary>
/// Where the login entry lives and what it starts. <see cref="AutoStart.ForThisProcess"/> builds the real one for the
/// running desktop app; tests build their own pointing at a throwaway registry key / folders.
/// </summary>
public sealed class AutoStartTarget
{
    public AutoStartTarget(AutoStartKind kind, string executablePath)
    {
        Kind = kind;
        ExecutablePath = executablePath;
    }

    public AutoStartKind Kind { get; }
    /// <summary>The program the entry starts: this copy of Echoes (Linux AppImage: the .AppImage file itself).</summary>
    public string ExecutablePath { get; }
    /// <summary>Why this copy can't be registered (it runs from a temporary location), or null.</summary>
    public string? Problem { get; init; }

    /// <summary>HKCU-relative key holding the Run value.</summary>
    public string WindowsRunKey { get; init; } = @"Software\Microsoft\Windows\CurrentVersion\Run";
    /// <summary>HKCU-relative key where Task Manager's "Startup apps" keeps its enabled / disabled flag.</summary>
    public string WindowsApprovedKey { get; init; } = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    public string WindowsValueName { get; init; } = "Echoes";

    /// <summary>Linux: the XDG autostart folder ($XDG_CONFIG_HOME/autostart).</summary>
    public string? LinuxAutostartDir { get; init; }
    public string LinuxFileName { get; init; } = "echoes.desktop";

    /// <summary>macOS: the user's LaunchAgents folder.</summary>
    public string? MacLaunchAgentsDir { get; init; }
    public string MacLabel { get; init; } = "com.echoes.app.autostart";
    // The app bundle's CFBundleIdentifier (packaging/macos/Info.plist): macOS lists the login entry under this app's name.
    // The Label stays as it was so an entry made by an earlier build is still the same entry.
    public string MacBundleId { get; init; } = "com.sinaxhpm.echoes";

    internal string LinuxFile => Path.Combine(LinuxAutostartDir ?? string.Empty, LinuxFileName);
    internal string MacFile => Path.Combine(MacLaunchAgentsDir ?? string.Empty, MacLabel + ".plist");
}

public enum AutoStartState
{
    /// <summary>No entry, or one the system has switched off (Task Manager, GNOME's startup apps, Disabled key).</summary>
    Off,
    /// <summary>An entry that starts this copy.</summary>
    On,
    /// <summary>An entry that starts another copy of Echoes that still exists.</summary>
    OtherCopy,
    /// <summary>An entry whose program is gone (Echoes was moved or deleted).</summary>
    Moved,
}

public readonly record struct AutoStartStatus(AutoStartState State, string? RegisteredPath);

/// <summary>
/// "Open Echoes when I sign in" (Monitor settings): a per-user login entry that starts Echoes with
/// <see cref="BackgroundFlag"/> — hidden in the tray, monitoring on. Windows: an HKCU Run value; Linux: an XDG autostart
/// .desktop file; macOS: a LaunchAgent plist with RunAtLoad. The entry itself is the state: nothing is kept in the
/// profile, so the setting always shows what is really registered.
///
/// <para>Nothing touches the system until the desktop head arms it (<see cref="Configure"/> in Program.Main): the
/// Android head, the designer and test harnesses never do, so for them the option doesn't exist
/// (<see cref="IsSupported"/>) — tests configure a <see cref="AutoStartTarget"/> of their own instead.</para>
/// </summary>
public static class AutoStart
{
    /// <summary>The command-line switch of a login launch.</summary>
    public const string BackgroundFlag = "--background";

    private static readonly object Gate = new();
    private static AutoStartTarget? _target;

    public static AutoStartTarget? Target
    {
        get { lock (Gate) return _target; }
    }

    public static bool IsSupported => Target is not null;

    public static void Configure(AutoStartTarget? target)
    {
        lock (Gate) _target = target;
    }

    /// <summary>True when the process was started by the login entry (<see cref="BackgroundFlag"/>).</summary>
    public static bool IsBackgroundLaunch(string[] args)
        => Array.Exists(args, a => string.Equals(a, BackgroundFlag, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// The real entry for this desktop process, or null where there is none to make (another OS, no executable path,
    /// running under the dotnet host).
    /// </summary>
    public static AutoStartTarget? ForThisProcess()
    {
        string? exe = Environment.ProcessPath;
        // An AppImage runs from a fresh temporary mount each time; the file to start is the .AppImage itself.
        if (OperatingSystem.IsLinux()
            && AppImageFile(exe, Environment.GetEnvironmentVariable("APPIMAGE"), Environment.GetEnvironmentVariable("APPDIR")) is { } appImage)
            exe = appImage;
        if (string.IsNullOrEmpty(exe) || !Path.IsPathFullyQualified(exe)) return null;
        // "dotnet Echoes.dll" (development): the host isn't Echoes; an entry for it would start dotnet.
        if (Path.GetFileNameWithoutExtension(exe).Equals("dotnet", StringComparison.OrdinalIgnoreCase)) return null;

        string? problem = TemporaryLocationProblem(exe);
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (OperatingSystem.IsWindows())
            return new AutoStartTarget(AutoStartKind.Windows, exe) { Problem = problem };
        if (OperatingSystem.IsMacOS())
        {
            if (string.IsNullOrEmpty(home)) return null;
            return new AutoStartTarget(AutoStartKind.MacOS, exe)
            {
                Problem = problem,
                MacLaunchAgentsDir = Path.Combine(home, "Library", "LaunchAgents"),
            };
        }
        if (OperatingSystem.IsLinux())
        {
            string? config = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME");
            if (string.IsNullOrEmpty(config) || !Path.IsPathFullyQualified(config))
            {
                if (string.IsNullOrEmpty(home)) return null;
                config = Path.Combine(home, ".config");
            }
            return new AutoStartTarget(AutoStartKind.Linux, exe)
            {
                Problem = problem,
                LinuxAutostartDir = Path.Combine(config, "autostart"),
            };
        }
        return null;
    }

    /// <summary>
    /// The .AppImage this process was started from, or null. The AppImage runtime sets $APPIMAGE (the file) and $APPDIR
    /// (where it mounted or extracted it, which this binary runs from) — and both are inherited by everything started from
    /// inside an AppImage: the deb / rpm Echoes launched from a terminal that an AppImage'd app opened would otherwise
    /// register THAT app as "Echoes" at sign-in (and the startup repair would point an existing entry at it). So $APPIMAGE
    /// counts only while this process really runs from an AppImage: from inside $APPDIR, or from a runtime mount
    /// ("/.mount_…": the runtime sets both variables afresh for what it starts, and a $TMPDIR behind a symlink can make
    /// the resolved process path differ from $APPDIR).
    /// </summary>
    internal static string? AppImageFile(string? processPath, string? appImage, string? appDir)
    {
        if (string.IsNullOrEmpty(appImage) || !Path.IsPathFullyQualified(appImage) || !File.Exists(appImage)) return null;
        if (string.IsNullOrEmpty(processPath)) return null;
        if (processPath.Contains("/.mount_", StringComparison.Ordinal)) return appImage;
        if (string.IsNullOrEmpty(appDir) || !Path.IsPathFullyQualified(appDir)) return null;
        string root = appDir.TrimEnd('/') + "/";
        return root.Length > 1 && processPath.StartsWith(root, StringComparison.Ordinal) ? appImage : null;
    }

    // A copy that won't be there at the next sign-in: macOS App Translocation (a quarantined app opened where it was
    // downloaded runs from a random read-only mount), or the temp folder (Windows: opened straight from the zip).
    private static string? TemporaryLocationProblem(string exe)
    {
        if (OperatingSystem.IsMacOS() && exe.Contains("/AppTranslocation/", StringComparison.Ordinal))
            return "macOS is running Echoes from a temporary copy. Move Echoes to Applications, open it from there and try again.";
        try
        {
            string temp = Path.GetFullPath(Path.GetTempPath());
            var cmp = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            if (Path.GetFullPath(exe).StartsWith(temp, cmp))
                return OperatingSystem.IsWindows()
                    ? "Echoes is running from a temporary folder (straight from the zip?). Extract it to a folder of its own, open it from there and try again."
                    : "Echoes is running from a temporary folder. Move it to a permanent place, open it from there and try again.";
        }
        catch { }
        return null;
    }

    // ------------------------------------------------------------------ state

    /// <summary>What is registered right now. Never throws (an unreadable entry reads as off).</summary>
    public static AutoStartStatus Read()
    {
        var t = Target;
        if (t is null) return new(AutoStartState.Off, null);
        lock (Gate)
        {
            try
            {
                string? registered = t.Kind switch
                {
                    AutoStartKind.Windows => OperatingSystem.IsWindows() ? ReadWindows(t) : null,
                    AutoStartKind.Linux => ReadLinux(t),
                    _ => ReadMac(t),
                };
                if (registered is null) return new(AutoStartState.Off, null);
                if (SamePath(registered, t.ExecutablePath, t.Kind)) return new(AutoStartState.On, registered);
                return registered.Length > 0 && File.Exists(registered)
                    ? new(AutoStartState.OtherCopy, registered)
                    : new(AutoStartState.Moved, registered);
            }
            catch (Exception ex)
            {
                CrashLog.Write("AutoStart.Read", ex);
                return new(AutoStartState.Off, null);
            }
        }
    }

    /// <summary>Registers this copy (replacing any other entry). Null when done, else the one reason it failed.</summary>
    public static string? Enable()
    {
        var t = Target;
        if (t is null) return "Opening at sign-in isn't available here.";
        if (t.Problem is { } problem) return problem;
        lock (Gate)
        {
            try
            {
                switch (t.Kind)
                {
                    case AutoStartKind.Windows:
                        if (!OperatingSystem.IsWindows()) return "Opening at sign-in isn't available here.";
                        WriteWindows(t);
                        break;
                    case AutoStartKind.Linux:
                        WriteFileAtomic(t.LinuxFile, DesktopEntry(t.ExecutablePath));
                        break;
                    default:
                        WriteFileAtomic(t.MacFile, LaunchAgentPlist(t));
                        break;
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or SecurityException)
            {
                return "Couldn't set Echoes to open at sign-in: " + DeniedWhere(t) + ".";
            }
            catch (Exception ex) when (ex is IOException or ArgumentException or NotSupportedException)
            {
                return "Couldn't set Echoes to open at sign-in: " + ex.Message;
            }
        }
        return Read().State == AutoStartState.On ? null : "Couldn't set Echoes to open at sign-in: the entry didn't stick.";
    }

    /// <summary>Removes the entry, whichever copy it starts. Null when done, else the one reason it failed.</summary>
    public static string? Disable()
    {
        var t = Target;
        if (t is null) return null;
        lock (Gate)
        {
            try
            {
                switch (t.Kind)
                {
                    case AutoStartKind.Windows:
                        if (OperatingSystem.IsWindows()) DeleteWindows(t);
                        break;
                    case AutoStartKind.Linux:
                        if (File.Exists(t.LinuxFile)) File.Delete(t.LinuxFile);
                        break;
                    default:
                        if (File.Exists(t.MacFile)) File.Delete(t.MacFile);
                        break;
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or SecurityException)
            {
                return "Couldn't stop Echoes opening at sign-in: " + DeniedWhere(t) + ".";
            }
            catch (Exception ex) when (ex is IOException or ArgumentException or NotSupportedException)
            {
                return "Couldn't stop Echoes opening at sign-in: " + ex.Message;
            }
        }
        return Read().State == AutoStartState.Off ? null : "Couldn't stop Echoes opening at sign-in: the entry is still there.";
    }

    /// <summary>
    /// Program start: an entry whose program is gone (this copy was moved, or an old one deleted) is pointed at this
    /// copy, so sign-in keeps working without a visit to the settings. Leaves an entry for another existing copy alone.
    /// True when it rewrote the entry.
    /// </summary>
    public static bool RepairIfMoved()
    {
        var t = Target;
        if (t is null || t.Problem is not null) return false;
        return Read().State == AutoStartState.Moved && Enable() is null;
    }

    private static string DeniedWhere(AutoStartTarget t) => t.Kind switch
    {
        AutoStartKind.Windows => "Windows denied access to the startup list (a policy may block startup apps)",
        AutoStartKind.Linux => "no permission to write " + t.LinuxFile,
        _ => "no permission to write " + t.MacFile,
    };

    internal static bool SamePath(string a, string b, AutoStartKind kind)
    {
        if (kind != AutoStartKind.Windows) return string.Equals(a, b, StringComparison.Ordinal);
        try
        {
            if (OperatingSystem.IsWindows()) { a = Path.GetFullPath(a); b = Path.GetFullPath(b); }
        }
        catch { }
        return string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
    }

    // Temp file + rename in the same folder: a half-written entry never runs at the next sign-in.
    private static void WriteFileAtomic(string path, string content)
    {
        string dir = Path.GetDirectoryName(path) ?? throw new IOException("No folder for " + path);
        Directory.CreateDirectory(dir);
        string tmp = path + ".tmp";
        File.WriteAllText(tmp, content, new UTF8Encoding(false));
        File.Move(tmp, path, overwrite: true);
    }

    // ------------------------------------------------------------------ Windows

    // "C:\…\Echoes.exe" --background. Task Manager's switch lives apart from the Run value (StartupApproved: an odd
    // first byte = disabled); a value it has disabled reads as off, and turning the option on clears that flag.
    [SupportedOSPlatform("windows")]
    private static string? ReadWindows(AutoStartTarget t)
    {
        using var run = Registry.CurrentUser.OpenSubKey(t.WindowsRunKey);
        if (run?.GetValue(t.WindowsValueName) is not string command) return null;
        using (var approved = Registry.CurrentUser.OpenSubKey(t.WindowsApprovedKey))
        {
            if (approved?.GetValue(t.WindowsValueName) is byte[] { Length: > 0 } flags && (flags[0] & 1) == 1) return null;
        }
        return CommandLineProgram(command);
    }

    [SupportedOSPlatform("windows")]
    private static void WriteWindows(AutoStartTarget t)
    {
        using (var run = Registry.CurrentUser.CreateSubKey(t.WindowsRunKey, writable: true))
            run.SetValue(t.WindowsValueName, WindowsCommand(t.ExecutablePath), RegistryValueKind.String);
        using var approved = Registry.CurrentUser.OpenSubKey(t.WindowsApprovedKey, writable: true);
        approved?.DeleteValue(t.WindowsValueName, throwOnMissingValue: false);
    }

    [SupportedOSPlatform("windows")]
    private static void DeleteWindows(AutoStartTarget t)
    {
        using (var run = Registry.CurrentUser.OpenSubKey(t.WindowsRunKey, writable: true))
            run?.DeleteValue(t.WindowsValueName, throwOnMissingValue: false);
        using var approved = Registry.CurrentUser.OpenSubKey(t.WindowsApprovedKey, writable: true);
        approved?.DeleteValue(t.WindowsValueName, throwOnMissingValue: false);
    }

    internal static string WindowsCommand(string exe) => "\"" + exe + "\" " + BackgroundFlag;

    /// <summary>The program of a Run command line: the quoted first token, or everything up to the first space.</summary>
    internal static string CommandLineProgram(string command)
    {
        string s = command.Trim();
        if (s.StartsWith('"'))
        {
            int end = s.IndexOf('"', 1);
            return end < 0 ? s[1..] : s[1..end];
        }
        int space = s.IndexOf(' ');
        return space < 0 ? s : s[..space];
    }

    // ------------------------------------------------------------------ Linux (.desktop)

    internal static string DesktopEntry(string exe)
    {
        var sb = new StringBuilder();
        sb.Append("[Desktop Entry]\n");
        sb.Append("Type=Application\n");
        sb.Append("Name=Echoes\n");
        sb.Append("Comment=Starts Echoes in the tray, with monitoring on\n");
        sb.Append("Exec=").Append(DesktopExecQuote(exe)).Append(' ').Append(BackgroundFlag).Append('\n');
        // Echoes deleted: the session skips the entry instead of failing to start it at every sign-in.
        sb.Append("TryExec=").Append(DesktopEscape(exe)).Append('\n');
        sb.Append("Terminal=false\n");
        sb.Append("X-GNOME-Autostart-enabled=true\n");
        return sb.ToString();
    }

    // Desktop Entry spec, Exec key: the program is a double-quoted argument (inside it ", `, $ and \ take a backslash),
    // % is written %%, and then the general string escaping applies on top (every backslash doubled again).
    internal static string DesktopExecQuote(string path)
    {
        var q = new StringBuilder("\"");
        foreach (char c in path)
        {
            if (c is '"' or '`' or '$' or '\\') q.Append('\\');
            q.Append(c);
        }
        q.Append('"');
        return DesktopEscape(q.ToString().Replace("%", "%%"));
    }

    private static string DesktopEscape(string value)
        => value.Replace("\\", "\\\\").Replace("\n", "\\n").Replace("\t", "\\t").Replace("\r", "\\r");

    private static string DesktopUnescape(string value)
    {
        var sb = new StringBuilder(value.Length);
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (c == '\\' && i + 1 < value.Length)
            {
                char n = value[++i];
                sb.Append(n switch { 's' => ' ', 'n' => '\n', 't' => '\t', 'r' => '\r', _ => n });
            }
            else sb.Append(c);
        }
        return sb.ToString();
    }

    /// <summary>The program of an Exec value (the inverse of <see cref="DesktopExecQuote"/>).</summary>
    internal static string DesktopExecProgram(string execValue)
    {
        string s = DesktopUnescape(execValue).Replace("%%", "%").TrimStart();
        var sb = new StringBuilder();
        if (s.StartsWith('"'))
        {
            for (int i = 1; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '\\' && i + 1 < s.Length) { sb.Append(s[++i]); continue; }
                if (c == '"') break;
                sb.Append(c);
            }
            return sb.ToString();
        }
        foreach (char c in s)
        {
            if (char.IsWhiteSpace(c)) break;
            sb.Append(c);
        }
        return sb.ToString();
    }

    // The program of our entry; null when there is none, or the desktop has switched it off (Hidden=true means
    // "deleted"; GNOME's startup-apps switch writes X-GNOME-Autostart-enabled=false).
    private static string? ReadLinux(AutoStartTarget t)
    {
        if (!File.Exists(t.LinuxFile)) return null;
        string? exec = null;
        bool inEntry = false, off = false;
        foreach (var raw in File.ReadAllLines(t.LinuxFile))
        {
            string line = raw.Trim();
            if (line.Length == 0 || line[0] == '#') continue;
            if (line[0] == '[') { inEntry = line == "[Desktop Entry]"; continue; }
            if (!inEntry) continue;
            int eq = line.IndexOf('=');
            if (eq <= 0) continue;
            string key = line[..eq].Trim(), value = line[(eq + 1)..].Trim();
            if (key == "Exec") exec = value;
            else if (key == "Hidden" && value.Equals("true", StringComparison.OrdinalIgnoreCase)) off = true;
            else if (key == "X-GNOME-Autostart-enabled" && value.Equals("false", StringComparison.OrdinalIgnoreCase)) off = true;
        }
        if (off) return null;
        return exec is null ? string.Empty : DesktopExecProgram(exec);
    }

    // ------------------------------------------------------------------ macOS (LaunchAgent)

    // RunAtLoad starts it when launchd loads the user's agents, i.e. at sign-in (the file isn't loaded now: that would
    // start a second Echoes at once). Aqua = GUI sessions only; no KeepAlive, so quitting Echoes keeps it quit.
    // AssociatedBundleIdentifiers lets System Settings › Login Items show it as Echoes (macOS 13+).
    internal static string LaunchAgentPlist(AutoStartTarget t)
    {
        static string X(string s) => SecurityElement.Escape(s) ?? string.Empty;
        var sb = new StringBuilder();
        sb.Append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        sb.Append("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
        sb.Append("<plist version=\"1.0\">\n<dict>\n");
        sb.Append("\t<key>Label</key>\n\t<string>").Append(X(t.MacLabel)).Append("</string>\n");
        sb.Append("\t<key>ProgramArguments</key>\n\t<array>\n");
        sb.Append("\t\t<string>").Append(X(t.ExecutablePath)).Append("</string>\n");
        sb.Append("\t\t<string>").Append(BackgroundFlag).Append("</string>\n");
        sb.Append("\t</array>\n");
        sb.Append("\t<key>RunAtLoad</key>\n\t<true/>\n");
        sb.Append("\t<key>LimitLoadToSessionType</key>\n\t<string>Aqua</string>\n");
        sb.Append("\t<key>ProcessType</key>\n\t<string>Interactive</string>\n");
        sb.Append("\t<key>AssociatedBundleIdentifiers</key>\n\t<array>\n\t\t<string>").Append(X(t.MacBundleId)).Append("</string>\n\t</array>\n");
        sb.Append("</dict>\n</plist>\n");
        return sb.ToString();
    }

    // The first ProgramArguments string (else Program); null when there's no file or it says Disabled.
    private static string? ReadMac(AutoStartTarget t)
    {
        if (!File.Exists(t.MacFile)) return null;
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Ignore, XmlResolver = null, MaxCharactersFromEntities = 1024, IgnoreComments = true,
        };
        XDocument doc;
        using (var reader = XmlReader.Create(t.MacFile, settings)) doc = XDocument.Load(reader);
        string? program = null, fallback = null;
        bool disabled = false;
        // A plist <dict> is <key> followed by its value, in order.
        var items = doc.Root?.Element("dict")?.Elements().ToList() ?? new List<XElement>();
        for (int i = 0; i + 1 < items.Count; i++)
        {
            if (items[i].Name != "key") continue;
            var value = items[i + 1];
            switch (items[i].Value.Trim())
            {
                case "ProgramArguments" when value.Name == "array":
                    program ??= value.Elements("string").FirstOrDefault()?.Value;
                    break;
                case "Program" when value.Name == "string":
                    fallback ??= value.Value;
                    break;
                case "Disabled":
                    disabled = value.Name == "true";
                    break;
            }
        }
        if (disabled) return null;
        return program ?? fallback ?? string.Empty;
    }
}
