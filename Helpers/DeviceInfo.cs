using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Echoes.Helpers;

/// <summary>One line of the Device page: a label and its value.</summary>
public record DeviceRow(string Label, string Value);

/// <summary>A line that starts a group within a card (a memory module, a disk, a display).</summary>
public sealed record DeviceHeading(string Text) : DeviceRow(string.Empty, Text);

/// <summary>One card of the Device page.</summary>
public sealed class DeviceSection
{
    public DeviceSection(string key, string title)
    {
        Key = key;
        Title = title;
    }

    public string Key { get; }
    public string Title { get; }
    public List<DeviceRow> Rows { get; } = new();

    /// <summary>The card as plain text, for Copy.</summary>
    public string Text
    {
        get
        {
            var sb = new StringBuilder();
            sb.Append("== ").Append(Title).Append(" ==\n");
            foreach (var row in Rows)
            {
                if (row is DeviceHeading h) sb.Append("-- ").Append(h.Text).Append('\n');
                else sb.Append(row.Label).Append(": ").Append(row.Value).Append('\n');
            }
            return sb.ToString();
        }
    }
}

/// <summary>
/// What the collectors fill in: rows go to a section by its key, and the sections come out in one fixed order whatever
/// order they were filled in. Within a group (since the last heading) the first value for a label wins, so the most
/// specific source runs first and a generic fallback after it only fills the gaps.
/// </summary>
public sealed class DeviceReport
{
    private static readonly (string Key, string Title)[] Order =
    {
        ("device", "Device"),
        ("board", "Motherboard & firmware"),
        ("os", "Operating system"),
        ("cpu", "Processor"),
        ("memory", "Memory"),
        ("gpu", "Graphics"),
        ("display", "Displays"),
        ("storage", "Storage"),
        ("battery", "Battery & power"),
        ("thermal", "Temperatures"),
        ("camera", "Cameras"),
        ("sensor", "Sensors"),
        ("feature", "Features"),
        ("app", "Echoes"),
    };

    private readonly Dictionary<string, DeviceSection> _sections = new();

    public void Row(string section, string label, string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        var rows = Get(section).Rows;
        for (int i = rows.Count - 1; i >= 0 && rows[i] is not DeviceHeading; i--)
            if (rows[i].Label == label) return;
        rows.Add(new DeviceRow(label, value.Trim()));
    }

    public void Heading(string section, string text) => Get(section).Rows.Add(new DeviceHeading(text.Trim()));

    /// <summary>The first value given for a label in a section (outside any group), or null.</summary>
    public string? Value(string section, string label)
        => _sections.TryGetValue(section, out var s) ? s.Rows.FirstOrDefault(r => r is not DeviceHeading && r.Label == label)?.Value : null;

    public bool HasRows(string section) => _sections.TryGetValue(section, out var s) && s.Rows.Count > 0;

    public IReadOnlyList<DeviceSection> Sections
        => Order.Select(o => _sections.GetValueOrDefault(o.Key)).Where(s => s is { Rows.Count: > 0 }).Select(s => s!).ToList();

    private DeviceSection Get(string key)
    {
        if (_sections.TryGetValue(key, out var s)) return s;
        string title = Order.FirstOrDefault(o => o.Key == key).Title ?? key;
        return _sections[key] = new DeviceSection(key, title);
    }
}

/// <summary>
/// The Device page's data: this machine's hardware and system, read on the device itself when the page is opened or
/// refreshed (nothing polls, nothing is sent anywhere). Each OS has its own sources: Windows' SMBIOS table, registry and
/// device IOCTLs (Helpers/DeviceInfoWindows), Linux's /proc and /sys (DeviceInfoLinux), sysctl on macOS and iOS
/// (DeviceInfoApple), and the Android and iOS heads add what only their SDKs know (<see cref="PlatformCollector"/>).
/// Every part is read on its own: one that fails or is withheld leaves the rest.
/// </summary>
public static class DeviceInfo
{
    /// <summary>Set by the Android and iOS heads: their SDK's sources (Build, sensors, cameras, UIDevice, Metal …), run
    /// first so they win over the generic ones. Called off the UI thread.</summary>
    public static Action<DeviceReport>? PlatformCollector { get; set; }

    /// <summary>A screen as the UI framework sees it, for the platforms without a richer source.</summary>
    public sealed record ScreenInfo(string Name, int Width, int Height, double Scaling, bool Primary);

    /// <summary>Reads everything (off the UI thread: some sources block for a moment).</summary>
    public static DeviceReport Collect(IReadOnlyList<ScreenInfo> screens, string appVersion)
    {
        var r = new DeviceReport();
        Try(() => PlatformCollector?.Invoke(r));
        if (OperatingSystem.IsWindows()) DeviceInfoWindows.Collect(r);
        else if (OperatingSystem.IsMacOS() || OperatingSystem.IsIOS()) DeviceInfoApple.Collect(r);
        else if (OperatingSystem.IsLinux() || OperatingSystem.IsAndroid()) DeviceInfoLinux.Collect(r);
        Try(() => CpuId.Collect(r));
        Try(() => Generic(r));
        if (!r.HasRows("display")) Try(() => Screens(r, screens));
        Try(() => App(r, appVersion));
        return r;
    }

    /// <summary>"Lenovo Legion 5 15ACH6 · Windows 11 Pro 24H2": the page's heading.</summary>
    public static string Headline(DeviceReport r)
    {
        string? maker = r.Value("device", "Manufacturer");
        string? model = r.Value("device", "Model");
        string device = model is null ? maker ?? Environment.MachineName
                      : maker is null || model.StartsWith(maker, StringComparison.OrdinalIgnoreCase) ? model : $"{maker} {model}";
        string? os = r.Value("os", "Name");
        return os is null ? device : $"{device} · {os}";
    }

    // What .NET knows everywhere: a fallback for whatever the OS sources left out.
    private static void Generic(DeviceReport r)
    {
        r.Row("device", "Name", AppInfo.DeviceName ?? Environment.MachineName);
        r.Row("os", "Name", RuntimeInformation.OSDescription);
        r.Row("os", "Architecture", Arch(RuntimeInformation.OSArchitecture));
        r.Row("os", "Uptime", Duration(TimeSpan.FromMilliseconds(Environment.TickCount64)));
        // the desktop build runs culture-invariant (no ICU data): there the OS readers name the language and formats
        if (CultureInfo.CurrentUICulture.Name.Length > 0) r.Row("os", "Language", CultureInfo.CurrentUICulture.DisplayName);
        if (CultureInfo.CurrentCulture.Name.Length > 0)
            r.Row("os", "Formats", $"{CultureInfo.CurrentCulture.DisplayName} ({CultureInfo.CurrentCulture.Name})");
        if ((Environment.GetEnvironmentVariable("LC_ALL") ?? Environment.GetEnvironmentVariable("LANG")) is { Length: > 0 } lang)
            r.Row("os", "Language", lang);
        var tz = TimeZoneInfo.Local;
        var offset = tz.GetUtcOffset(DateTime.Now);
        r.Row("os", "Time zone", $"{tz.Id} (UTC{(offset < TimeSpan.Zero ? "-" : "+")}{offset:hh\\:mm})");
        r.Row("cpu", "Logical processors", Environment.ProcessorCount.ToString(CultureInfo.InvariantCulture));
        long total = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
        if (total > 0 && !r.HasRows("memory")) r.Row("memory", "Total", Bytes(total));
    }

    // Mounted volumes, where the OS source has no list of its own.
    internal static void Volumes(DeviceReport r, Func<DriveInfo, bool>? keep = null)
    {
        var drives = DriveInfo.GetDrives()
            .Where(d => d.DriveType is DriveType.Fixed or DriveType.Removable)
            .Where(d => Try(() => d.IsReady, false) && Try(() => d.TotalSize, 0L) > 0)
            .Where(d => keep?.Invoke(d) ?? true)
            .ToList();
        if (drives.Count == 0) return;
        r.Heading("storage", drives.Count == 1 ? "Volume" : $"Volumes ({drives.Count})");
        foreach (var d in drives)
        {
            long size = d.TotalSize, free = d.TotalFreeSpace;
            string label = Try(() => d.VolumeLabel, string.Empty);
            string name = d.Name.TrimEnd('\\');
            string format = Try(() => d.DriveFormat, string.Empty);
            r.Row("storage", label.Length > 0 && label != name ? $"{name} ({label})" : name,
                  $"{Bytes(size)}, {Bytes(free)} free ({Percent(size - free, size)} used){(format.Length > 0 ? " · " + format : "")}"
                  + (d.DriveType == DriveType.Removable ? " · removable" : ""));
        }
    }

    private static void Screens(DeviceReport r, IReadOnlyList<ScreenInfo> screens)
    {
        int n = 0;
        foreach (var s in screens.OrderByDescending(s => s.Primary))
        {
            n++;
            r.Heading("display", $"Display {n}{(s.Name.Length > 0 ? " — " + s.Name : "")}{(s.Primary && screens.Count > 1 ? " (main)" : "")}");
            r.Row("display", "Resolution", $"{s.Width} × {s.Height}");
            if (s.Scaling > 0) r.Row("display", "Scaling", $"{s.Scaling * 100:0} %");
        }
    }

    private static void App(DeviceReport r, string appVersion)
    {
        r.Row("app", "Version", appVersion);
        r.Row("app", "Runtime", AppInfo.Runtime);
        r.Row("app", "UI", AppInfo.Ui);
        r.Row("app", "Process", $"{Arch(RuntimeInformation.ProcessArchitecture)}, {(Environment.Is64BitProcess ? "64" : "32")}-bit");
        r.Row("app", "Memory in use", Bytes(Environment.WorkingSet));
    }

    // ---------------------------------------------------------------- formatting

    /// <summary>Binary units as file managers show them: "15.8 GB".</summary>
    public static string Bytes(long bytes)
    {
        if (bytes < 0) return "—";
        string[] units = { "bytes", "KB", "MB", "GB", "TB", "PB" };
        double v = bytes;
        int u = 0;
        while (v >= 1024 && u < units.Length - 1) { v /= 1024; u++; }
        return u == 0 ? $"{bytes} bytes" : v >= 100 ? $"{v:0} {units[u]}" : $"{v:0.#} {units[u]}";
    }

    /// <summary>A disk's size the way its maker states it (decimal), beside the binary size: "931.5 GB (1 TB)".</summary>
    public static string DiskBytes(long bytes)
    {
        double tb = bytes / 1e12, gb = bytes / 1e9;
        string maker = tb >= 1 ? $"{tb:0.##} TB" : $"{gb:0} GB";
        return $"{Bytes(bytes)} ({maker})";
    }

    public static string Mhz(double mhz) => mhz >= 1000 ? $"{mhz / 1000:0.00} GHz" : $"{mhz:0} MHz";

    public static string Percent(long part, long whole) => whole <= 0 ? "—" : $"{100.0 * part / whole:0}%";

    public static string Duration(TimeSpan t)
        => t.TotalDays >= 1 ? $"{(int)t.TotalDays} d {t.Hours} h {t.Minutes} min"
         : t.TotalHours >= 1 ? $"{t.Hours} h {t.Minutes} min" : $"{t.Minutes} min";

    public static string Arch(Architecture a) => a switch
    {
        Architecture.X64 => "x64",
        Architecture.X86 => "x86",
        Architecture.Arm64 => "ARM64",
        Architecture.Arm => "ARM",
        _ => a.ToString(),
    };

    /// <summary>A firmware string, or null for the placeholders boards ship with ("To be filled by O.E.M.").</summary>
    public static string? Clean(string? s)
    {
        if (s is null) return null;
        s = s.Trim().Trim('\0').Trim();
        if (s.Length == 0) return null;
        if (s.All(c => c == s[0]) && s[0] is '0' or 'F' or 'f' or ' ' or '.' or 'X' or 'x') return null;
        string l = s.ToLowerInvariant();
        string[] junk =
        {
            "to be filled by o.e.m.", "to be filled by oem", "default string", "system product name", "system manufacturer",
            "system version", "system serial number", "base board serial number", "not specified", "not applicable",
            "none", "n/a", "na", "oem", "o.e.m.", "unknown", "123456789", "0123456789", "chassis serial number",
            "type1productconfigid", "invalid", "empty", "undefined", "not available", "sku", "family",
        };
        return junk.Contains(l) ? null : s;
    }

    /// <summary>The chassis type number of SMBIOS and of Linux's /sys/class/dmi/id/chassis_type.</summary>
    public static string? ChassisType(int t) => t switch
    {
        3 => "Desktop", 4 => "Low-profile desktop", 5 => "Pizza box", 6 => "Mini tower", 7 => "Tower", 8 => "Portable",
        9 => "Laptop", 10 => "Notebook", 11 => "Handheld", 12 => "Docking station", 13 => "All-in-one",
        14 => "Sub-notebook", 15 => "Space-saving", 16 => "Lunch box", 17 => "Server", 23 => "Rack server",
        24 => "Sealed-case PC", 30 => "Tablet", 31 => "Convertible", 32 => "Detachable", 33 => "IoT gateway",
        34 => "Embedded PC", 35 => "Mini PC", 36 => "Stick PC",
        _ => null,
    };

    internal static void Try(Action a)
    {
        try { a(); }
        catch { /* that part isn't readable here: the others still are */ }
    }

    internal static T Try<T>(Func<T> f, T fallback)
    {
        try { return f(); }
        catch { return fallback; }
    }
}
