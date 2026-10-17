using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Echoes.Helpers;

/// <summary>Two readings of the "cpu" line of /proc/stat give the busy share between them.</summary>
public readonly record struct SshCpuTimes(ulong Idle, ulong Total);

public sealed record SshDiskInfo(string Filesystem, string Mount, long SizeKb, long UsedKb, double Percent);

public sealed record SshProcInfo(string Pid, string User, double Cpu, double Mem, string Command);

/// <summary>One answer of the health command, parsed. Missing parts stay empty / null (non-Linux servers).</summary>
public sealed class SshHealthSnapshot
{
    public string Hostname { get; set; } = string.Empty;
    public string Os { get; set; } = string.Empty;
    public string Kernel { get; set; } = string.Empty;
    public double? UptimeSeconds { get; set; }
    /// <summary>The "up …" part of `uptime` when /proc/uptime isn't there.</summary>
    public string UptimeText { get; set; } = string.Empty;
    public double[]? Load { get; set; }
    public SshCpuTimes? Cpu1 { get; set; }
    public SshCpuTimes? Cpu2 { get; set; }
    public int Cpus { get; set; }
    public long MemTotalKb { get; set; } = -1;
    public long MemAvailableKb { get; set; } = -1;
    public long SwapTotalKb { get; set; } = -1;
    public long SwapFreeKb { get; set; } = -1;
    public List<SshDiskInfo> Disks { get; } = new();
    public List<SshProcInfo> Processes { get; } = new();
    public bool HasProcStat => Cpu1 is not null;
    /// <summary>The shell answered the batch at all (a Windows server's cmd.exe doesn't).</summary>
    public bool Recognized { get; set; }
}

/// <summary>
/// Server health without an agent: ONE exec command batch per refresh (Linux /proc, df -P, ps, uptime — with
/// fallbacks for BSD / macOS where /proc is missing) and a tolerant parser for its sectioned output.
/// </summary>
public static partial class SshHealth
{
    /// <summary>Upper bound for the command's output that is read at all (the batch itself caps its lists).</summary>
    public const int MaxOutputChars = 256 * 1024;
    public const int MaxDisks = 16;
    public const int MaxProcesses = 8;

    /// <summary>The batch, run through sh whatever the login shell is. <paramref name="twoCpuSamples"/>: also a second
    /// /proc/stat reading half a second later (the first refresh has no earlier reading to compare with).</summary>
    public static string Command(bool twoCpuSamples)
    {
        // No single quotes inside: the whole script is one sh -c '…' argument.
        var sb = new StringBuilder();
        sb.Append("export LC_ALL=C; ");
        sb.Append("echo @@host; hostname 2>/dev/null || uname -n 2>/dev/null; ");
        sb.Append("echo @@uname; uname -srm 2>/dev/null; ");
        sb.Append("echo @@os; if [ -r /etc/os-release ]; then . /etc/os-release; echo \"$PRETTY_NAME\"; ");
        sb.Append("elif command -v sw_vers >/dev/null 2>&1; then echo \"$(sw_vers -productName) $(sw_vers -productVersion)\"; fi; ");
        sb.Append("echo @@uptime; cat /proc/uptime 2>/dev/null; ");
        sb.Append("echo @@uptimecmd; uptime 2>/dev/null; ");
        sb.Append("echo @@loadavg; cat /proc/loadavg 2>/dev/null; ");
        sb.Append("echo @@stat; grep \"^cpu \" /proc/stat 2>/dev/null; ");
        if (twoCpuSamples) sb.Append("sleep 0.5; echo @@stat2; grep \"^cpu \" /proc/stat 2>/dev/null; ");
        sb.Append("echo @@nproc; nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null; ");
        sb.Append("echo @@mem; grep -E \"^(MemTotal|MemAvailable|MemFree|Buffers|Cached|SwapTotal|SwapFree):\" /proc/meminfo 2>/dev/null; ");
        sb.Append("echo @@df; df -P -k 2>/dev/null | head -n 200; ");
        sb.Append("echo @@ps; { ps -eo pid=,user=,pcpu=,pmem=,comm= --sort=-pcpu 2>/dev/null || ps -Ao pid=,user=,pcpu=,pmem=,comm= -r 2>/dev/null; } | head -n 12; ");
        sb.Append("echo @@end");
        return "sh -c '" + sb + "'";
    }

    public static SshHealthSnapshot Parse(string output)
    {
        var snap = new SshHealthSnapshot();
        if (output.Length > MaxOutputChars) output = output[..MaxOutputChars];
        var sections = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        List<string>? current = null;
        foreach (var raw in output.Split('\n'))
        {
            string line = raw.TrimEnd('\r');
            if (line.StartsWith("@@", StringComparison.Ordinal) && line.Length < 16 && line.Skip(2).All(char.IsAsciiLetterOrDigit))
            {
                current = new List<string>();
                sections[line[2..]] = current;
                continue;
            }
            current?.Add(line);   // anything before the first marker (a login banner) is ignored
        }
        snap.Recognized = sections.ContainsKey("host") && sections.ContainsKey("end");
        if (!snap.Recognized) return snap;

        snap.Hostname = First(sections, "host");
        snap.Kernel = First(sections, "uname");
        snap.Os = First(sections, "os");

        if (First(sections, "uptime") is { Length: > 0 } up && Num(up.Split(' ')[0]) is double secs)
            snap.UptimeSeconds = secs;
        string upCmd = First(sections, "uptimecmd");
        if (snap.UptimeSeconds is null && UpRx().Match(upCmd) is { Success: true } um)
            snap.UptimeText = um.Groups[1].Value.Trim().TrimEnd(',');

        string la = First(sections, "loadavg");
        var laParts = la.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (laParts.Length >= 3 && Num(laParts[0]) is double l1 && Num(laParts[1]) is double l5 && Num(laParts[2]) is double l15)
            snap.Load = new[] { l1, l5, l15 };
        else if (LoadRx().Match(upCmd) is { Success: true } lm && Num(lm.Groups[1].Value) is double a && Num(lm.Groups[2].Value) is double b && Num(lm.Groups[3].Value) is double c)
            snap.Load = new[] { a, b, c };

        snap.Cpu1 = Cpu(First(sections, "stat"));
        snap.Cpu2 = Cpu(First(sections, "stat2"));
        if (int.TryParse(First(sections, "nproc"), NumberStyles.None, CultureInfo.InvariantCulture, out int n) && n is > 0 and < 100000)
            snap.Cpus = n;

        if (sections.TryGetValue("mem", out var mem))
        {
            var kv = new Dictionary<string, long>(StringComparer.Ordinal);
            foreach (var m in mem)
            {
                int colon = m.IndexOf(':');
                if (colon <= 0) continue;
                var v = m[(colon + 1)..].Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (v.Length > 0 && long.TryParse(v[0], NumberStyles.None, CultureInfo.InvariantCulture, out long kb)) kv[m[..colon]] = kb;
            }
            if (kv.TryGetValue("MemTotal", out long total))
            {
                snap.MemTotalKb = total;
                snap.MemAvailableKb = kv.TryGetValue("MemAvailable", out long av) ? av
                    : (kv.GetValueOrDefault("MemFree") + kv.GetValueOrDefault("Buffers") + kv.GetValueOrDefault("Cached"));
            }
            if (kv.TryGetValue("SwapTotal", out long st)) snap.SwapTotalKb = st;
            if (kv.TryGetValue("SwapFree", out long sf)) snap.SwapFreeKb = sf;
        }

        if (sections.TryGetValue("df", out var df)) ParseDf(df, snap.Disks);
        if (sections.TryGetValue("ps", out var ps)) ParsePs(ps, snap.Processes);
        return snap;
    }

    private static string First(Dictionary<string, List<string>> s, string key)
        => s.TryGetValue(key, out var l) ? l.FirstOrDefault(x => x.Trim().Length > 0)?.Trim() ?? string.Empty : string.Empty;

    private static double? Num(string s)
        => double.TryParse(s.Trim().TrimEnd(','), NumberStyles.Float, CultureInfo.InvariantCulture, out double d) && double.IsFinite(d) ? d : null;

    private static SshCpuTimes? Cpu(string line)
    {
        // cpu  user nice system idle iowait irq softirq steal guest guest_nice — guest time is already inside user.
        var p = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (p.Length < 5 || p[0] != "cpu") return null;
        ulong total = 0, idle = 0;
        for (int i = 1; i < p.Length && i <= 8; i++)
        {
            if (!ulong.TryParse(p[i], NumberStyles.None, CultureInfo.InvariantCulture, out ulong v)) return null;
            total += v;
            if (i is 4 or 5) idle += v;   // idle + iowait
        }
        return new SshCpuTimes(idle, total);
    }

    /// <summary>Busy share (0-100) between two readings; null when they don't make sense (counter reset, same reading).</summary>
    public static double? CpuPercent(SshCpuTimes? before, SshCpuTimes? after)
    {
        if (before is not { } a || after is not { } b || b.Total <= a.Total || b.Idle < a.Idle) return null;
        double dt = b.Total - a.Total, di = b.Idle - a.Idle;
        return Math.Clamp(100.0 * (1 - di / dt), 0, 100);
    }

    // Pseudo / virtual filesystems a disk-usage view shouldn't list.
    private static readonly HashSet<string> VirtualFs = new(StringComparer.Ordinal)
    { "tmpfs", "devtmpfs", "overlay", "squashfs", "udev", "none", "shm", "cgroup", "cgroup2", "proc", "sysfs", "devfs",
      "efivarfs", "ramfs", "run", "snapfuse", "fdesc", "nullfs", "procfs", "linprocfs", "tracefs", "securityfs" };

    private static void ParseDf(List<string> lines, List<SshDiskInfo> disks)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var all = new List<SshDiskInfo>();
        foreach (var line in lines)
        {
            var t = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            // Filesystem 1024-blocks Used Available Capacity Mounted-on — the filesystem and the mount point may hold
            // spaces, so anchor on the "NN%" capacity column.
            int cap = -1;
            for (int i = 4; i < t.Length; i++)
                if (t[i].EndsWith('%') && t[i].Length > 1 && t[i][..^1].All(char.IsAsciiDigit)) { cap = i; break; }
            if (cap < 4 || cap == t.Length - 1) continue;
            if (!long.TryParse(t[cap - 3], NumberStyles.None, CultureInfo.InvariantCulture, out long size) ||
                !long.TryParse(t[cap - 2], NumberStyles.None, CultureInfo.InvariantCulture, out long used) ||
                !long.TryParse(t[cap - 1], NumberStyles.None, CultureInfo.InvariantCulture, out long avail)) continue;
            string fs = string.Join(' ', t[..(cap - 3)]);
            string mount = string.Join(' ', t[(cap + 1)..]);
            if (size <= 0 || VirtualFs.Contains(fs) || fs.StartsWith("map ", StringComparison.Ordinal)) continue;
            if (mount.StartsWith("/proc", StringComparison.Ordinal) || mount.StartsWith("/sys", StringComparison.Ordinal)
                || mount.StartsWith("/dev", StringComparison.Ordinal) || mount.StartsWith("/run", StringComparison.Ordinal)
                || mount.StartsWith("/snap/", StringComparison.Ordinal) || mount.StartsWith("/System/Volumes/", StringComparison.Ordinal)) continue;
            if (!seen.Add(mount)) continue;
            // df's own capacity rounds up and counts reserved blocks: used / (used + available), like df.
            double pct = used + avail > 0 ? 100.0 * used / (used + avail) : 0;
            all.Add(new SshDiskInfo(fs, mount, size, used, Math.Clamp(pct, 0, 100)));
        }
        disks.AddRange(all.OrderBy(d => d.Mount == "/" ? 0 : 1).ThenByDescending(d => d.SizeKb).Take(MaxDisks));
    }

    private static void ParsePs(List<string> lines, List<SshProcInfo> procs)
    {
        foreach (var line in lines)
        {
            if (procs.Count >= MaxProcesses) break;
            var t = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (t.Length < 5 || !t[0].All(char.IsAsciiDigit)) continue;   // a header row (BSD ps without '=')
            if (Num(t[2]) is not double cpu || Num(t[3]) is not double memPct) continue;
            string cmd = string.Join(' ', t[4..]);
            if (cmd is "ps" or "sh" or "head") continue;   // the batch itself
            procs.Add(new SshProcInfo(t[0], t[1], cpu, memPct, cmd));
        }
    }

    [GeneratedRegex(@"\bup\s+(.+?),\s+\d+\s+users?", RegexOptions.CultureInvariant)]
    private static partial Regex UpRx();

    [GeneratedRegex(@"load averages?:\s*([\d.]+),?\s+([\d.]+),?\s+([\d.]+)", RegexOptions.CultureInvariant)]
    private static partial Regex LoadRx();

    // ---------------------------------------------------------------- formatting

    public static string Kb(long kb) => kb < 0 ? "—" : SshText.Bytes(kb * 1024);

    public static string Uptime(double seconds)
    {
        var t = TimeSpan.FromSeconds(Math.Max(0, seconds));
        if (t.TotalDays >= 1) return $"{(int)t.TotalDays} d {t.Hours} h";
        if (t.TotalHours >= 1) return $"{t.Hours} h {t.Minutes} m";
        return $"{Math.Max(1, t.Minutes)} m";
    }
}
