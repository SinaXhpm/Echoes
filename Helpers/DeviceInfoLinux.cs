using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace Echoes.Helpers;

/// <summary>
/// The Device page on Linux and the base of Android's: /proc (CPU, memory, kernel, uptime) and /sys (DMI model and
/// firmware, per-core clocks and caches, disks, GPUs, batteries, temperature sensors). Only world-readable files: the
/// serial numbers DMI keeps for root are left out. Android keeps most of /sys from apps; what its SDK knows comes from
/// the Android head (DeviceInfo.PlatformCollector), so here it adds the kernel, the CPU clusters, memory and sensors.
/// </summary>
internal static class DeviceInfoLinux
{
    public static void Collect(DeviceReport r)
    {
        bool android = OperatingSystem.IsAndroid();
        if (!android)
        {
            DeviceInfo.Try(() => Dmi(r));
            DeviceInfo.Try(() => OsRelease(r));
        }
        DeviceInfo.Try(() => Kernel(r));
        DeviceInfo.Try(() => Cpu(r));
        DeviceInfo.Try(() => Memory(r));
        if (!android)
        {
            DeviceInfo.Try(() => Gpu(r));
            DeviceInfo.Try(() => Disks(r));
            DeviceInfo.Try(() => DeviceInfo.Volumes(r, KeepVolume));
            DeviceInfo.Try(() => Power(r));
        }
        DeviceInfo.Try(() => Thermal(r));
    }

    private static void Dmi(DeviceReport r)
    {
        string? D(string name) => DeviceInfo.Clean(Read($"/sys/class/dmi/id/{name}"));
        r.Row("device", "Manufacturer", D("sys_vendor"));
        r.Row("device", "Model", D("product_name"));
        r.Row("device", "Family", D("product_family"));
        r.Row("device", "Version", D("product_version"));
        r.Row("device", "SKU", D("product_sku"));
        if (int.TryParse(Read("/sys/class/dmi/id/chassis_type"), out int chassis)) r.Row("device", "Type", DeviceInfo.ChassisType(chassis));
        r.Row("device", "Serial number", D("product_serial"));   // root only on most systems
        r.Row("board", "Motherboard", string.Join(" ", new[] { D("board_vendor"), D("board_name") }.Where(s => s is not null)));
        r.Row("board", "Board version", D("board_version"));
        r.Row("board", "BIOS vendor", D("bios_vendor"));
        r.Row("board", "BIOS version", D("bios_version"));
        r.Row("board", "BIOS date", D("bios_date"));
        r.Row("board", "Firmware", Directory.Exists("/sys/firmware/efi") ? "UEFI" : "Legacy BIOS");
    }

    private static void OsRelease(DeviceReport r)
    {
        var os = KeyValues("/etc/os-release", '=');
        string? V(string k) => os.TryGetValue(k, out var v) ? v.Trim('"') : null;
        r.Row("os", "Name", V("PRETTY_NAME") ?? V("NAME"));
        r.Row("os", "Version", V("VERSION"));
        r.Row("os", "Desktop", Environment.GetEnvironmentVariable("XDG_CURRENT_DESKTOP"));
        r.Row("os", "Session", Environment.GetEnvironmentVariable("XDG_SESSION_TYPE"));
    }

    private static void Kernel(DeviceReport r)
    {
        r.Row("os", "Kernel", Read("/proc/sys/kernel/osrelease"));
        if (Read("/proc/uptime") is { } up && double.TryParse(up.Split(' ')[0], NumberStyles.Float, CultureInfo.InvariantCulture, out double secs))
        {
            var t = TimeSpan.FromSeconds(secs);
            r.Row("os", "Uptime", DeviceInfo.Duration(t));
            r.Row("os", "Last start", (DateTime.Now - t).ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture));
        }
        r.Row("os", "Kernel build", Read("/proc/version"));
    }

    // ---------------------------------------------------------------- processor

    private static void Cpu(DeviceReport r)
    {
        string? info = Read("/proc/cpuinfo");
        if (info is null) return;
        var blocks = info.Split("\n\n", StringSplitOptions.RemoveEmptyEntries).Select(b => KeyValuesOf(b, ':')).ToList();
        var procs = blocks.Where(b => b.ContainsKey("processor")).ToList();
        var first = procs.FirstOrDefault() ?? new Dictionary<string, string>();
        string? V(Dictionary<string, string> b, string k) => b.TryGetValue(k, out var v) && v.Length > 0 ? v : null;
        string? global(string k) => blocks.Select(b => V(b, k)).FirstOrDefault(v => v is not null);

        r.Row("cpu", "Name", V(first, "model name") ?? global("Hardware") ?? global("Model"));
        r.Row("cpu", "Hardware", global("Hardware"));
        // x86: physical / core ids give the real core count
        var cores = procs.Select(p => (V(p, "physical id") ?? "0") + ":" + (V(p, "core id") ?? V(p, "processor"))).Distinct().Count();
        var sockets = procs.Select(p => V(p, "physical id")).Where(s => s is not null).Distinct().Count();
        if (sockets > 1) r.Row("cpu", "Sockets", sockets.ToString(CultureInfo.InvariantCulture));
        if (procs.Any(p => p.ContainsKey("core id"))) r.Row("cpu", "Cores", cores.ToString(CultureInfo.InvariantCulture));

        // per-core type (ARM part number) and clocks: big.LITTLE clusters
        var cpus = new List<(int Id, string Part, long MaxKhz, long MinKhz)>();
        foreach (var p in procs)
        {
            if (!int.TryParse(V(p, "processor"), out int id)) continue;
            string part = ArmCore(V(p, "CPU implementer"), V(p, "CPU part")) ?? string.Empty;
            long max = Long(Read($"/sys/devices/system/cpu/cpu{id}/cpufreq/cpuinfo_max_freq"));
            long min = Long(Read($"/sys/devices/system/cpu/cpu{id}/cpufreq/cpuinfo_min_freq"));
            cpus.Add((id, part, max, min));
        }
        if (cpus.Count > 0 && cpus.Any(c => c.MaxKhz > 0 || c.Part.Length > 0))
        {
            var clusters = cpus.GroupBy(c => (c.Part, c.MaxKhz)).OrderBy(g => g.Key.MaxKhz).ToList();
            string text = string.Join(" + ", clusters.Select(g =>
                $"{g.Count()} × {(g.Key.Part.Length > 0 ? g.Key.Part : "core")}{(g.Key.MaxKhz > 0 ? " @ " + DeviceInfo.Mhz(g.Key.MaxKhz / 1000.0) : "")}"));
            r.Row("cpu", clusters.Count > 1 ? "Clusters" : "Cores", text);
            long top = cpus.Max(c => c.MaxKhz), low = cpus.Where(c => c.MinKhz > 0).Select(c => c.MinKhz).DefaultIfEmpty(0).Min();
            if (top > 0) r.Row("cpu", "Max clock", DeviceInfo.Mhz(top / 1000.0));
            if (low > 0) r.Row("cpu", "Min clock", DeviceInfo.Mhz(low / 1000.0));
        }
        r.Row("cpu", "Governor", Read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"));
        // caches as cpu0 sees them
        var caches = new List<string>();
        for (int i = 0; i < 8; i++)
        {
            string dir = $"/sys/devices/system/cpu/cpu0/cache/index{i}";
            if (!Directory.Exists(dir)) break;
            string? level = Read($"{dir}/level"), type = Read($"{dir}/type"), size = Read($"{dir}/size");
            if (level is null || size is null) continue;
            caches.Add($"L{level}{type switch { "Data" => "d", "Instruction" => "i", _ => "" }} {size.Replace("K", " KB").Replace("M", " MB")}");
        }
        if (caches.Count > 0) r.Row("cpu", "Caches (per core)", string.Join(", ", caches));
        // ARM lists its extensions here (x86's "flags" run to hundreds: CPUID names the ones that matter)
        if (V(first, "Features") is { } features)
            r.Row("cpu", "Instruction sets", string.Join(", ", features.Split(' ', StringSplitOptions.RemoveEmptyEntries)));
        r.Row("cpu", "Bogomips", V(first, "bogomips") ?? V(first, "BogoMIPS"));
    }

    // ARM's own and a few licensees' core designs, by implementer and part number.
    private static string? ArmCore(string? implementer, string? part)
    {
        if (implementer is null || part is null) return null;
        int imp = Hex(implementer), p = Hex(part);
        if (imp == 0x41) return p switch
        {
            0xd03 => "Cortex-A53", 0xd04 => "Cortex-A35", 0xd05 => "Cortex-A55", 0xd07 => "Cortex-A57", 0xd08 => "Cortex-A72",
            0xd09 => "Cortex-A73", 0xd0a => "Cortex-A75", 0xd0b => "Cortex-A76", 0xd0c => "Neoverse N1", 0xd0d => "Cortex-A77",
            0xd0e => "Cortex-A76AE", 0xd40 => "Neoverse V1", 0xd41 => "Cortex-A78", 0xd44 => "Cortex-X1", 0xd46 => "Cortex-A510",
            0xd47 => "Cortex-A710", 0xd48 => "Cortex-X2", 0xd49 => "Neoverse N2", 0xd4b => "Cortex-A78C", 0xd4d => "Cortex-A715",
            0xd4e => "Cortex-X3", 0xd4f => "Neoverse V2", 0xd80 => "Cortex-A520", 0xd81 => "Cortex-A720", 0xd82 => "Cortex-X4",
            0xd85 => "Cortex-X925", 0xd87 => "Cortex-A725", 0xd88 => "Cortex-A520AE",
            _ => $"ARM 0x{p:x3}",
        };
        if (imp == 0x51) return p switch
        {
            0x800 or 0x801 => "Kryo 2xx", 0x802 or 0x803 => "Kryo 3xx", 0x804 or 0x805 => "Kryo 4xx", 0x001 => "Oryon",
            _ => $"Qualcomm 0x{p:x3}",
        };
        if (imp == 0x53) return $"Samsung 0x{p:x3}";
        if (imp == 0x48) return $"HiSilicon 0x{p:x3}";
        if (imp == 0x61) return $"Apple 0x{p:x3}";
        return null;
    }

    // ---------------------------------------------------------------- memory

    private static void Memory(DeviceReport r)
    {
        var m = KeyValues("/proc/meminfo", ':');
        long Kb(string k) => m.TryGetValue(k, out var v) ? Long(v.Replace("kB", string.Empty).Trim()) * 1024 : 0;
        long total = Kb("MemTotal"), avail = Kb("MemAvailable"), swap = Kb("SwapTotal"), swapFree = Kb("SwapFree");
        if (total > 0) r.Row("memory", "Usable", DeviceInfo.Bytes(total));
        if (total > 0 && avail > 0)
            r.Row("memory", "In use", $"{DeviceInfo.Bytes(total - avail)} ({DeviceInfo.Percent(total - avail, total)}), {DeviceInfo.Bytes(avail)} free");
        if (swap > 0) r.Row("memory", OperatingSystem.IsAndroid() ? "Swap (zram)" : "Swap", $"{DeviceInfo.Bytes(swap)}, {DeviceInfo.Bytes(swap - swapFree)} used");
    }

    // ---------------------------------------------------------------- GPU, disks, power (desktop Linux)

    private static void Gpu(DeviceReport r)
    {
        var ids = PciIds();
        foreach (string card in Directory.GetDirectories("/sys/class/drm", "card*").Where(d => !Path.GetFileName(d).Contains('-')).OrderBy(d => d))
        {
            string dev = Path.Combine(card, "device");
            int vendor = Hex(Read($"{dev}/vendor")), device = Hex(Read($"{dev}/device"));
            if (vendor == 0) continue;
            string? driver = DeviceInfo.Try(() => new DirectoryInfo($"{dev}/driver").LinkTarget is { } t ? Path.GetFileName(t) : null, null);
            string? name = ids?.Device(vendor, device);
            string maker = ids?.Vendor(vendor) ?? $"0x{vendor:x4}";
            r.Heading("gpu", name is null ? maker : $"{maker} {name}");
            r.Row("gpu", "Device ID", $"{vendor:x4}:{device:x4}");
            r.Row("gpu", "Driver", driver);
            long vram = Long(Read($"{dev}/mem_info_vram_total"));
            if (vram > 0) r.Row("gpu", "Video memory", DeviceInfo.Bytes(vram));
        }
    }

    private static void Disks(DeviceReport r)
    {
        foreach (string dir in Directory.GetDirectories("/sys/block").OrderBy(d => d))
        {
            string name = Path.GetFileName(dir);
            if (name.StartsWith("loop", StringComparison.Ordinal) || name.StartsWith("ram", StringComparison.Ordinal)
                || name.StartsWith("zram", StringComparison.Ordinal) || name.StartsWith("dm-", StringComparison.Ordinal)
                || name.StartsWith("md", StringComparison.Ordinal) || name.StartsWith("sr", StringComparison.Ordinal)) continue;
            long sectors = Long(Read($"{dir}/size"));
            if (sectors <= 0) continue;
            string model = string.Join(" ", new[] { DeviceInfo.Clean(Read($"{dir}/device/vendor")), DeviceInfo.Clean(Read($"{dir}/device/model")) }.Where(s => s is not null));
            bool rotational = Read($"{dir}/queue/rotational") == "1", removable = Read($"{dir}/removable") == "1";
            r.Heading("storage", $"{name}{(model.Length > 0 ? " — " + model : "")}");
            r.Row("storage", "Type", (name.StartsWith("nvme", StringComparison.Ordinal) ? "NVMe " : name.StartsWith("mmc", StringComparison.Ordinal) ? "eMMC / SD " : "")
                  + (rotational ? "Hard disk" : "SSD") + (removable ? " · removable" : ""));
            r.Row("storage", "Capacity", DeviceInfo.DiskBytes(sectors * 512));
            r.Row("storage", "Firmware", DeviceInfo.Clean(Read($"{dir}/device/firmware_rev") ?? Read($"{dir}/device/rev")));
            r.Row("storage", "Serial number", DeviceInfo.Clean(Read($"{dir}/device/serial")));
        }
    }

    private static bool KeepVolume(DriveInfo d)
    {
        string f = DeviceInfo.Try(() => d.DriveFormat, string.Empty);
        string[] pseudo = { "tmpfs", "devtmpfs", "proc", "sysfs", "overlay", "squashfs", "cgroup", "cgroup2", "devpts", "efivarfs",
                            "securityfs", "pstore", "bpf", "tracefs", "debugfs", "fusectl", "configfs", "mqueue", "hugetlbfs", "ramfs",
                            "autofs", "binfmt_misc", "nsfs", "fuse.portal", "fuse.gvfsd-fuse" };
        return !pseudo.Contains(f) && !d.Name.StartsWith("/snap/", StringComparison.Ordinal) && !d.Name.StartsWith("/boot/efi", StringComparison.Ordinal);
    }

    private static void Power(DeviceReport r)
    {
        if (!Directory.Exists("/sys/class/power_supply")) return;
        bool any = false;
        foreach (string dir in Directory.GetDirectories("/sys/class/power_supply").OrderBy(d => d))
        {
            string? type = Read($"{dir}/type");
            if (type == "Mains" && Read($"{dir}/online") is { } online) r.Row("battery", "Power", online == "1" ? "Plugged in" : "On battery");
            if (type != "Battery" || Read($"{dir}/scope") == "Device") continue;   // a mouse's or a pen's battery: not the system's
            any = true;
            string name = Path.GetFileName(dir);
            r.Heading("battery", $"Battery {name}{(DeviceInfo.Clean(Read($"{dir}/model_name")) is { } model ? " — " + model : "")}");
            r.Row("battery", "Maker", DeviceInfo.Clean(Read($"{dir}/manufacturer")));
            r.Row("battery", "Charge", Read($"{dir}/capacity") is { } c ? c + "%" : null);
            r.Row("battery", "Status", Read($"{dir}/status"));
            r.Row("battery", "Chemistry", Read($"{dir}/technology"));
            // energy in µWh, or charge in µAh on some
            long full = Long(Read($"{dir}/energy_full")), design = Long(Read($"{dir}/energy_full_design"));
            string unit = "Wh";
            if (full == 0) { full = Long(Read($"{dir}/charge_full")); design = Long(Read($"{dir}/charge_full_design")); unit = "Ah"; }
            if (design > 0) r.Row("battery", "Design capacity", $"{design / 1e6:0.##} {unit}");
            if (full > 0) r.Row("battery", "Full charge capacity", $"{full / 1e6:0.##} {unit}");
            if (design > 0 && full > 0) r.Row("battery", "Health", $"{Math.Min(100.0, 100.0 * full / design):0}% of its design capacity");
            long cycles = Long(Read($"{dir}/cycle_count"));
            if (cycles > 0) r.Row("battery", "Charge cycles", cycles.ToString(CultureInfo.InvariantCulture));
            long uv = Long(Read($"{dir}/voltage_now"));
            if (uv > 0) r.Row("battery", "Voltage", $"{uv / 1e6:0.00} V");
            long uw = Long(Read($"{dir}/power_now"));
            if (uw > 0) r.Row("battery", "Power draw", $"{uw / 1e6:0.0} W");
        }
        if (!any) r.Row("battery", "Battery", "None (mains power)");
    }

    // ---------------------------------------------------------------- temperatures

    private static void Thermal(DeviceReport r)
    {
        int shown = 0;
        // hwmon (desktop Linux): CPU package, NVMe, GPU sensors with their own labels
        if (Directory.Exists("/sys/class/hwmon"))
            foreach (string dir in Directory.GetDirectories("/sys/class/hwmon").OrderBy(d => d))
            {
                string chip = Read($"{dir}/name") ?? Path.GetFileName(dir);
                foreach (string input in Directory.GetFiles(dir, "temp*_input").OrderBy(f => f))
                {
                    long milli = Long(Read(input));
                    if (milli is <= -40000 or >= 150000 || milli == 0) continue;
                    string label = Read(input.Replace("_input", "_label")) ?? Path.GetFileName(input).Replace("_input", string.Empty);
                    r.Row("thermal", $"{chip} · {label}", $"{milli / 1000.0:0.#} °C");
                    if (++shown >= 24) return;
                }
            }
        // thermal zones (Android, ARM boards, laptops)
        if (!Directory.Exists("/sys/class/thermal")) return;
        foreach (string dir in Directory.GetDirectories("/sys/class/thermal", "thermal_zone*").OrderBy(d => Long(Path.GetFileName(d)[12..])))
        {
            long milli = Long(Read($"{dir}/temp"));
            if (milli is <= -40000 or >= 150000 || milli == 0) continue;
            string type = Read($"{dir}/type") ?? Path.GetFileName(dir);
            r.Row("thermal", type, $"{(Math.Abs(milli) > 1000 ? milli / 1000.0 : milli):0.#} °C");
            if (++shown >= 24) return;
        }
    }

    // ---------------------------------------------------------------- helpers

    private static string? Read(string path)
    {
        try { return File.Exists(path) ? File.ReadAllText(path).Trim() : null; }
        catch { return null; }
    }

    private static Dictionary<string, string> KeyValues(string path, char sep) => KeyValuesOf(Read(path) ?? string.Empty, sep);

    private static Dictionary<string, string> KeyValuesOf(string text, char sep)
    {
        var d = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string line in text.Split('\n'))
        {
            int at = line.IndexOf(sep);
            if (at <= 0) continue;
            string k = line[..at].Trim(), v = line[(at + 1)..].Trim();
            d.TryAdd(k, v);
        }
        return d;
    }

    private static long Long(string? s) => long.TryParse(s?.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out long v) ? v : 0;

    private static int Hex(string? s)
    {
        if (s is null) return 0;
        s = s.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s[2..];
        return int.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int v) ? v : 0;
    }

    /// <summary>The pci.ids database most distributions ship (hwdata), for GPU names.</summary>
    private sealed class PciIdsDb
    {
        private readonly string[] _lines;
        public PciIdsDb(string[] lines) => _lines = lines;

        public string? Vendor(int vendor) => Find(vendor, -1);
        public string? Device(int vendor, int device) => Find(vendor, device);

        private string? Find(int vendor, int device)
        {
            string v = vendor.ToString("x4", CultureInfo.InvariantCulture);
            for (int i = 0; i < _lines.Length; i++)
            {
                string line = _lines[i];
                if (line.Length < 6 || line[0] == '\t' || line[0] == '#' || !line.StartsWith(v, StringComparison.Ordinal)) continue;
                if (device < 0) return Short(line[4..].Trim());
                string d = "\t" + device.ToString("x4", CultureInfo.InvariantCulture);
                for (int j = i + 1; j < _lines.Length && _lines[j].StartsWith('\t'); j++)
                    if (_lines[j].StartsWith(d, StringComparison.Ordinal) && !_lines[j].StartsWith("\t\t", StringComparison.Ordinal))
                        return _lines[j][6..].Trim();
                return null;
            }
            return null;
        }

        // "NVIDIA Corporation" → "NVIDIA", "Advanced Micro Devices, Inc. [AMD/ATI]" → "AMD"
        private static string Short(string vendor)
        {
            int b = vendor.IndexOf('[');
            if (b >= 0 && vendor.IndexOf(']', b) is var e and > 0) return vendor[(b + 1)..e].Split('/')[0];
            foreach (string suffix in new[] { " Corporation", " Corp.", ", Inc.", " Inc.", " Co., Ltd.", " Ltd." })
                if (vendor.EndsWith(suffix, StringComparison.Ordinal)) return vendor[..^suffix.Length];
            return vendor;
        }
    }

    private static PciIdsDb? PciIds()
    {
        foreach (string p in new[] { "/usr/share/hwdata/pci.ids", "/usr/share/misc/pci.ids", "/usr/share/pci.ids" })
            if (File.Exists(p)) return DeviceInfo.Try(() => new PciIdsDb(File.ReadAllLines(p)), null);
        return null;
    }
}
