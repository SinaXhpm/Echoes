using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;

namespace Echoes.Helpers;

/// <summary>
/// The Device page on Windows, all as a standard user: the SMBIOS table (model, serials, board, BIOS, memory modules),
/// the registry (Windows edition and build, processor name, GPU drivers, monitor EDIDs), GetLogicalProcessorInformationEx
/// (cores, hybrid core types, caches), the storage and battery IOCTLs (disk model, bus, SSD or not, temperature;
/// battery design and full capacity, wear, cycles) and the display APIs (mode, refresh rate, scaling). Blittable
/// DllImports with manual offsets, as the other Windows readers here.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class DeviceInfoWindows
{
    public static void Collect(DeviceReport r)
    {
        var smbios = DeviceInfo.Try(Smbios.Read, null);
        DeviceInfo.Try(() => Device(r, smbios));
        DeviceInfo.Try(() => Board(r, smbios));
        DeviceInfo.Try(() => Os(r));
        DeviceInfo.Try(() => Cpu(r, smbios));
        DeviceInfo.Try(() => Memory(r, smbios));
        var adapters = DeviceInfo.Try(DisplayAdapters, new List<Adapter>());
        DeviceInfo.Try(() => Gpu(r, adapters));
        DeviceInfo.Try(() => Displays(r, adapters));
        DeviceInfo.Try(() => Storage(r));
        DeviceInfo.Try(() => Battery(r));
    }

    // ---------------------------------------------------------------- device, board, firmware

    private static void Device(DeviceReport r, Smbios? s)
    {
        var sys = s?.First(1);
        var bios = Reg(@"HARDWARE\DESCRIPTION\System\BIOS");
        r.Row("device", "Manufacturer", sys?.Str(0x04) ?? DeviceInfo.Clean(bios?.GetValue("SystemManufacturer") as string));
        r.Row("device", "Model", sys?.Str(0x05) ?? DeviceInfo.Clean(bios?.GetValue("SystemProductName") as string));
        r.Row("device", "Family", sys is { Length: > 0x1A } ? sys.Str(0x1A) : DeviceInfo.Clean(bios?.GetValue("SystemFamily") as string));
        r.Row("device", "Version", sys?.Str(0x06) ?? DeviceInfo.Clean(bios?.GetValue("SystemVersion") as string));
        r.Row("device", "SKU", sys is { Length: > 0x19 } ? sys.Str(0x19) : DeviceInfo.Clean(bios?.GetValue("SystemSKU") as string));
        if (s?.First(3) is { } chassis)
        {
            r.Row("device", "Type", DeviceInfo.ChassisType(chassis.Byte(0x05) & 0x7F));
            r.Row("device", "Chassis maker", chassis.Str(0x04));
        }
        r.Row("device", "Serial number", sys?.Str(0x07));
        r.Row("device", "UUID", sys is { Length: >= 0x18 } ? sys.Uuid(0x08) : null);
        r.Row("device", "Name", Environment.MachineName);
        r.Row("device", "User", Environment.UserName);
    }

    private static void Board(DeviceReport r, Smbios? s)
    {
        var bios = Reg(@"HARDWARE\DESCRIPTION\System\BIOS");
        var board = s?.First(2);
        r.Row("board", "Motherboard", Join(board?.Str(0x04) ?? DeviceInfo.Clean(bios?.GetValue("BaseBoardManufacturer") as string),
                                            board?.Str(0x05) ?? DeviceInfo.Clean(bios?.GetValue("BaseBoardProduct") as string)));
        r.Row("board", "Board version", board?.Str(0x06) ?? DeviceInfo.Clean(bios?.GetValue("BaseBoardVersion") as string));
        r.Row("board", "Board serial", board?.Str(0x07));
        var b0 = s?.First(0);
        r.Row("board", "BIOS vendor", b0?.Str(0x04) ?? DeviceInfo.Clean(bios?.GetValue("BIOSVendor") as string));
        r.Row("board", "BIOS version", b0?.Str(0x05) ?? DeviceInfo.Clean(bios?.GetValue("BIOSVersion") as string));
        r.Row("board", "BIOS date", b0?.Str(0x08) ?? DeviceInfo.Clean(bios?.GetValue("BIOSReleaseDate") as string));
        if (b0 is { Length: > 0x15 } && b0.Byte(0x14) != 0xFF) r.Row("board", "BIOS release", $"{b0.Byte(0x14)}.{b0.Byte(0x15)}");
        if (GetFirmwareType(out int fw)) r.Row("board", "Firmware", fw switch { 1 => "Legacy BIOS", 2 => "UEFI", _ => null });
        if (Reg(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State")?.GetValue("UEFISecureBootEnabled") is int sb)
            r.Row("board", "Secure Boot", sb == 1 ? "On" : "Off");
        var tpm = new byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(tpm, 1);
        if (DeviceInfo.Try(() => Tbsi_GetDeviceInfo(16, tpm), uint.MaxValue) == 0)
            r.Row("board", "TPM", BinaryPrimitives.ReadUInt32LittleEndian(tpm.AsSpan(4)) switch { 1 => "1.2", 2 => "2.0", var v => v.ToString(CultureInfo.InvariantCulture) });
        else r.Row("board", "TPM", "None found");
        if (s is not null) r.Row("board", "SMBIOS", $"{s.Major}.{s.Minor}");
    }

    // ---------------------------------------------------------------- Windows itself

    private static void Os(DeviceReport r)
    {
        var cv = Reg(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
        int build = Environment.OSVersion.Version.Build;
        string? product = cv?.GetValue("ProductName") as string;
        // Windows 11 still names itself "Windows 10" here
        if (product is not null && build >= 22000) product = product.Replace("Windows 10", "Windows 11");
        string? display = cv?.GetValue("DisplayVersion") as string ?? cv?.GetValue("ReleaseId") as string;
        r.Row("os", "Name", product is null ? null : display is null ? product : $"{product} {display}");
        r.Row("os", "Edition", cv?.GetValue("EditionID") as string);
        string ubr = cv?.GetValue("UBR") is int u ? "." + u.ToString(CultureInfo.InvariantCulture) : string.Empty;
        r.Row("os", "Build", $"{cv?.GetValue("CurrentBuild") as string ?? build.ToString(CultureInfo.InvariantCulture)}{ubr}");
        r.Row("os", "Kernel", Environment.OSVersion.Version.ToString());
        if (cv?.GetValue("InstallDate") is int installed && installed > 0)
            r.Row("os", "Installed", DateTimeOffset.FromUnixTimeSeconds((uint)installed).ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture));
        var up = TimeSpan.FromMilliseconds(Environment.TickCount64);
        r.Row("os", "Last start", (DateTime.Now - up).ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture));
        r.Row("os", "Architecture", DeviceInfo.Arch(RuntimeInformation.OSArchitecture));
        var name = new char[85];   // LOCALE_NAME_MAX_LENGTH
        if (LCIDToLocaleName(GetUserDefaultUILanguage(), name, name.Length, 0) > 1) r.Row("os", "Language", new string(name).TrimEnd('\0'));
        Array.Clear(name);
        if (GetUserDefaultLocaleName(name, name.Length) > 1) r.Row("os", "Formats", new string(name).TrimEnd('\0'));
    }

    // ---------------------------------------------------------------- processor

    private static void Cpu(DeviceReport r, Smbios? s)
    {
        var cpu0 = Reg(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
        r.Row("cpu", "Name", (cpu0?.GetValue("ProcessorNameString") as string)?.Trim());
        r.Row("cpu", "Identifier", cpu0?.GetValue("Identifier") as string);
        Topology(r);
        if (cpu0?.GetValue("~MHz") is int mhz && mhz > 0) r.Row("cpu", "Base clock", DeviceInfo.Mhz(mhz));
        if (s?.First(4) is { } p)
        {
            ushort max = p.Word(0x14), bus = p.Word(0x12);
            if (max is > 0 and < 20000) r.Row("cpu", "Max clock (firmware)", DeviceInfo.Mhz(max));
            if (bus is > 0 and < 2000) r.Row("cpu", "Bus clock", DeviceInfo.Mhz(bus));
            r.Row("cpu", "Socket", p.Str(0x04));
        }
        if (RuntimeInformation.OSArchitecture == Architecture.Arm64)
        {
            var f = new List<string>();
            if (IsProcessorFeaturePresent(30)) f.Add("AES / SHA (crypto)");
            if (IsProcessorFeaturePresent(31)) f.Add("CRC32");
            if (IsProcessorFeaturePresent(34)) f.Add("LSE atomics");
            if (IsProcessorFeaturePresent(43)) f.Add("Dot product");
            if (IsProcessorFeaturePresent(44)) f.Add("JSCVT");
            if (IsProcessorFeaturePresent(45)) f.Add("LRCPC");
            if (IsProcessorFeaturePresent(46)) f.Add("SVE");
            if (f.Count > 0) r.Row("cpu", "Instruction sets", "NEON, " + string.Join(", ", f));
        }
    }

    // Sockets, cores (by efficiency class on hybrid chips), logical processors and caches.
    private static void Topology(DeviceReport r)
    {
        uint len = 0;
        GetLogicalProcessorInformationEx(0xFFFF, null, ref len);
        if (len == 0 || len > 1 << 22) return;
        var buf = new byte[len];
        if (!GetLogicalProcessorInformationEx(0xFFFF, buf, ref len)) return;
        int maskSize = IntPtr.Size == 8 ? 16 : 12;   // GROUP_AFFINITY: KAFFINITY mask, group, 3 reserved words
        int packages = 0, logical = 0;
        var coresByClass = new SortedDictionary<int, (int Cores, int Threads)>();
        var caches = new Dictionary<(int Level, int Type), (long Size, int Count)>();
        for (int off = 0; off + 8 <= len;)
        {
            int rel = BinaryPrimitives.ReadInt32LittleEndian(buf.AsSpan(off));
            int size = BinaryPrimitives.ReadInt32LittleEndian(buf.AsSpan(off + 4));
            if (size <= 0) break;
            var e = buf.AsSpan(off + 8, Math.Min(size - 8, (int)len - off - 8));
            switch (rel)
            {
                case 0:   // RelationProcessorCore
                {
                    int cls = e[1];
                    int groups = BinaryPrimitives.ReadUInt16LittleEndian(e.Slice(22));
                    int threads = 0;
                    for (int g = 0; g < groups; g++)
                    {
                        var m = e.Slice(24 + g * maskSize);
                        ulong mask = IntPtr.Size == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(m) : BinaryPrimitives.ReadUInt32LittleEndian(m);
                        threads += BitOperations.PopCount(mask);
                    }
                    var c = coresByClass.GetValueOrDefault(cls);
                    coresByClass[cls] = (c.Cores + 1, c.Threads + threads);
                    logical += threads;
                    break;
                }
                case 2:   // RelationCache
                {
                    int level = e[0], type = BinaryPrimitives.ReadInt32LittleEndian(e.Slice(8));
                    long cacheSize = BinaryPrimitives.ReadUInt32LittleEndian(e.Slice(4));
                    var c = caches.GetValueOrDefault((level, type));
                    caches[(level, type)] = (cacheSize, c.Count + 1);
                    break;
                }
                case 3: packages++; break;   // RelationProcessorPackage
            }
            off += size;
        }
        int cores = coresByClass.Values.Sum(v => v.Cores);
        if (cores == 0) return;
        if (packages > 1) r.Row("cpu", "Sockets", packages.ToString(CultureInfo.InvariantCulture));
        string coreText = cores.ToString(CultureInfo.InvariantCulture);
        if (coresByClass.Count > 1)   // hybrid (Intel 12th gen+, Snapdragon X): the higher class is the faster core
        {
            var classes = coresByClass.Reverse().ToList();
            var parts = classes.Select((c, i) => $"{c.Value.Cores} {(i == 0 ? "performance" : i == classes.Count - 1 ? "efficient" : "mid")}");
            coreText += $" ({string.Join(" + ", parts)})";
        }
        r.Row("cpu", "Cores", coreText);
        r.Row("cpu", "Logical processors", logical.ToString(CultureInfo.InvariantCulture));
        string CacheText(int level, int type)
            => caches.TryGetValue((level, type), out var c) ? (c.Count > 1 ? $"{c.Count} × {DeviceInfo.Bytes(c.Size)}" : DeviceInfo.Bytes(c.Size)) : string.Empty;
        string l1d = CacheText(1, 2), l1i = CacheText(1, 1);
        if (l1d.Length > 0) r.Row("cpu", "L1 cache", l1i.Length > 0 ? $"{l1d} data + {l1i} instruction" : l1d);
        foreach (int level in new[] { 2, 3, 4 })
        {
            var parts = caches.Where(c => c.Key.Level == level).ToList();
            if (parts.Count == 0) continue;
            long total = parts.Sum(c => c.Value.Size * c.Value.Count);
            string each = string.Join(" + ", parts.Select(c => CacheText(level, c.Key.Type)));
            r.Row("cpu", $"L{level} cache", parts.Sum(c => c.Value.Count) > 1 ? $"{each} ({DeviceInfo.Bytes(total)})" : each);
        }
    }

    // ---------------------------------------------------------------- memory

    private static void Memory(DeviceReport r, Smbios? s)
    {
        if (GetPhysicallyInstalledSystemMemory(out ulong kb) && kb > 0) r.Row("memory", "Installed", DeviceInfo.Bytes((long)kb * 1024));
        var st = new byte[64];
        BinaryPrimitives.WriteUInt32LittleEndian(st, 64);
        if (GlobalMemoryStatusEx(st))
        {
            long total = (long)BinaryPrimitives.ReadUInt64LittleEndian(st.AsSpan(8));
            long avail = (long)BinaryPrimitives.ReadUInt64LittleEndian(st.AsSpan(16));
            long commit = (long)BinaryPrimitives.ReadUInt64LittleEndian(st.AsSpan(24));
            long commitFree = (long)BinaryPrimitives.ReadUInt64LittleEndian(st.AsSpan(32));
            r.Row("memory", "Usable", DeviceInfo.Bytes(total));
            r.Row("memory", "In use", $"{DeviceInfo.Bytes(total - avail)} ({DeviceInfo.Percent(total - avail, total)}), {DeviceInfo.Bytes(avail)} free");
            r.Row("memory", "Commit limit", $"{DeviceInfo.Bytes(commit)} ({DeviceInfo.Bytes(commit - commitFree)} committed)");
        }
        if (s is null) return;
        if (s.OfType(16).FirstOrDefault(a => a.Byte(0x05) == 3) is { } array)   // the system memory array
        {
            uint maxKb = array.Dword(0x07);
            long max = maxKb == 0x80000000 && array.Length >= 0x17 ? (long)array.Qword(0x0F) : (long)maxKb * 1024;
            if (max > 0) r.Row("memory", "Maximum supported", DeviceInfo.Bytes(max));
            r.Row("memory", "Error correction", Smbios.ErrorCorrection(array.Byte(0x06)));
        }
        var slots = s.OfType(17).ToList();
        var used = slots.Where(m => ModuleSize(m) > 0).ToList();
        if (slots.Count > 0) r.Row("memory", "Slots", $"{used.Count} of {slots.Count} used");
        if (used.Count > 0 && Smbios.MemoryType(used[0].Byte(0x12)) is { } type)
        {
            uint speed = Speed(used[0], 0x15, 0x54);
            r.Row("memory", "Type", speed > 0 ? $"{type}-{speed}" : type);
        }
        foreach (var m in used)
        {
            long size = ModuleSize(m);
            string where = Join(m.Str(0x11), m.Str(0x10), " / ") ?? "Module";
            uint rated = Speed(m, 0x15, 0x54), running = m.Length > 0x21 ? Speed(m, 0x20, 0x58) : 0;
            string? mtype = Smbios.MemoryType(m.Byte(0x12));
            r.Heading("memory", $"{where} — {DeviceInfo.Bytes(size)}{(mtype is null ? "" : " " + mtype)}");
            r.Row("memory", "Speed", rated == 0 ? null : running > 0 && running != rated ? $"{rated} MT/s (running at {running} MT/s)" : $"{rated} MT/s");
            r.Row("memory", "Form factor", Smbios.FormFactor(m.Byte(0x0E)));
            r.Row("memory", "Maker", Smbios.MemoryMaker(m.Str(0x17)));
            r.Row("memory", "Part number", m.Str(0x1A));
            r.Row("memory", "Serial number", m.Str(0x18));
            if (m.Length > 0x1B && (m.Byte(0x1B) & 0x0F) is var rank and > 0) r.Row("memory", "Ranks", rank.ToString(CultureInfo.InvariantCulture));
            if (m.Length > 0x27 && m.Word(0x26) is var mv and > 0) r.Row("memory", "Voltage", $"{mv / 1000.0:0.###} V");
            if (m.Length > 0x0B && m.Word(0x0A) is var width and > 0 and < 0xFFFF) r.Row("memory", "Data width", $"{width} bit");
        }
    }

    private static long ModuleSize(Smbios.Entry m)
    {
        ushort size = m.Word(0x0C);
        if (size == 0 || size == 0xFFFF) return 0;
        if (size == 0x7FFF && m.Length > 0x1F) return (long)(m.Dword(0x1C) & 0x7FFFFFFF) * 1024 * 1024;
        return (size & 0x8000) != 0 ? (long)(size & 0x7FFF) * 1024 : (long)size * 1024 * 1024;
    }

    private static uint Speed(Smbios.Entry m, int offset, int extended)
    {
        ushort v = m.Word(offset);
        if (v == 0xFFFF && m.Length >= extended + 4) return m.Dword(extended);
        return v;
    }

    // ---------------------------------------------------------------- graphics and displays

    private sealed record Adapter(string DeviceName, string Name, string Id, bool Attached, bool Primary);

    // Every output of every adapter, as EnumDisplayDevices lists them (an adapter appears once per output).
    private static List<Adapter> DisplayAdapters()
    {
        var list = new List<Adapter>();
        var dd = new byte[840];
        for (uint i = 0; i < 64; i++)
        {
            Array.Clear(dd);
            BinaryPrimitives.WriteUInt32LittleEndian(dd, 840);
            if (!EnumDisplayDevicesW(null, i, dd, 0)) break;
            uint flags = BinaryPrimitives.ReadUInt32LittleEndian(dd.AsSpan(324));
            list.Add(new Adapter(WStr(dd, 4, 32), WStr(dd, 68, 128), WStr(dd, 328, 128), (flags & 1) != 0, (flags & 4) != 0));
        }
        return list;
    }

    private sealed record GpuDevice(string Name, string HardwareId, string DriverKey);

    // The display adapters Windows has right now (SetupAPI, present only): also a laptop's render-only GPU, which drives
    // no output and so isn't in EnumDisplayDevices.
    private static List<GpuDevice> PresentGpus()
    {
        var list = new List<GpuDevice>();
        var displayClass = new Guid("4d36e968-e325-11ce-bfc1-08002be10318");
        var set = SetupDiGetClassDevsW(ref displayClass, IntPtr.Zero, IntPtr.Zero, 0x2);
        if (set == new IntPtr(-1)) return list;
        try
        {
            int dataSize = IntPtr.Size == 8 ? 32 : 28;
            var buf = new byte[2048];
            string Prop(byte[] dev, uint property)
                => SetupDiGetDeviceRegistryPropertyW(set, dev, property, out _, buf, (uint)buf.Length, out uint need) && need >= 2
                    ? Encoding.Unicode.GetString(buf, 0, (int)Math.Min(need, (uint)buf.Length)).Split('\0')[0].Trim() : string.Empty;
            for (uint i = 0; i < 16; i++)
            {
                var dev = new byte[dataSize];
                BinaryPrimitives.WriteInt32LittleEndian(dev, dataSize);
                if (!SetupDiEnumDeviceInfo(set, i, dev)) break;
                string name = Prop(dev, 12);   // SPDRP_FRIENDLYNAME
                if (name.Length == 0) name = Prop(dev, 0);   // SPDRP_DEVICEDESC
                list.Add(new GpuDevice(name, Prop(dev, 1), Prop(dev, 9)));   // SPDRP_HARDWAREID (first), SPDRP_DRIVER
            }
        }
        finally { SetupDiDestroyDeviceInfoList(set); }
        // physical GPUs (PCI, or ACPI on ARM laptops) first; remote / indirect-display / basic adapters only when that's all
        var real = list.Where(g => g.HardwareId.StartsWith("PCI\\", StringComparison.OrdinalIgnoreCase)
                                || g.HardwareId.StartsWith("ACPI\\", StringComparison.OrdinalIgnoreCase)).ToList();
        return real.Count > 0 ? real : list;
    }

    private static void Gpu(DeviceReport r, List<Adapter> outputs)
    {
        var gpus = PresentGpus();
        if (gpus.Count == 0)
            gpus = outputs.GroupBy(a => a.Id, StringComparer.OrdinalIgnoreCase).Select(g => new GpuDevice(g.First().Name, g.Key, string.Empty)).ToList();
        int n = 0;
        foreach (var gpu in gpus)
        {
            n++;
            using var key = gpu.DriverKey.Length > 0 ? Reg($@"SYSTEM\CurrentControlSet\Control\Class\{gpu.DriverKey}") : null;
            r.Heading("gpu", gpus.Count > 1 ? $"GPU {n} — {gpu.Name}" : gpu.Name);
            r.Row("gpu", "Maker", Vendor(gpu.HardwareId) ?? key?.GetValue("ProviderName") as string);
            r.Row("gpu", "Chip", DeviceInfo.Clean(RegText(key?.GetValue("HardwareInformation.ChipType"))));
            long vram = key?.GetValue("HardwareInformation.qwMemorySize") switch
            {
                long q => q,
                byte[] { Length: >= 8 } b => (long)BinaryPrimitives.ReadUInt64LittleEndian(b),
                _ => key?.GetValue("HardwareInformation.MemorySize") switch
                {
                    int dw => (uint)dw,
                    long q => q,
                    byte[] { Length: >= 4 } b => BinaryPrimitives.ReadUInt32LittleEndian(b),
                    _ => 0,
                },
            };
            if (vram > 0) r.Row("gpu", "Video memory", DeviceInfo.Bytes(vram));
            r.Row("gpu", "Driver", Join(key?.GetValue("DriverVersion") as string, key?.GetValue("DriverDate") as string is { } d ? $"({d})" : null));
            r.Row("gpu", "Driver by", key?.GetValue("ProviderName") as string);
            r.Row("gpu", "BIOS", DeviceInfo.Clean(RegText(key?.GetValue("HardwareInformation.BiosString"))));
            r.Row("gpu", "Device ID", PciId(gpu.HardwareId));
            int screens = outputs.Count(o => o.Attached && o.Id.Length > 0 && gpu.HardwareId.StartsWith(o.Id, StringComparison.OrdinalIgnoreCase));
            r.Row("gpu", "Displays", screens > 0 ? screens.ToString(CultureInfo.InvariantCulture) : "None connected");
        }
    }

    private static void Displays(DeviceReport r, List<Adapter> outputs)
    {
        var attached = outputs.Where(o => o.Attached).OrderByDescending(o => o.Primary).ToList();
        int n = 0;
        var mode = new byte[220];
        var mon = new byte[840];
        foreach (var output in attached)
        {
            n++;
            Array.Clear(mode);
            BinaryPrimitives.WriteUInt16LittleEndian(mode.AsSpan(68), 220);
            if (!EnumDisplaySettingsW(output.DeviceName, -1, mode)) continue;
            int x = BinaryPrimitives.ReadInt32LittleEndian(mode.AsSpan(76)), y = BinaryPrimitives.ReadInt32LittleEndian(mode.AsSpan(80));
            uint bits = BinaryPrimitives.ReadUInt32LittleEndian(mode.AsSpan(168));
            uint w = BinaryPrimitives.ReadUInt32LittleEndian(mode.AsSpan(172)), h = BinaryPrimitives.ReadUInt32LittleEndian(mode.AsSpan(176));
            uint hz = BinaryPrimitives.ReadUInt32LittleEndian(mode.AsSpan(184));
            // the monitor on this output, by its interface path: that leads to its EDID
            Array.Clear(mon);
            BinaryPrimitives.WriteUInt32LittleEndian(mon, 840);
            Edid? edid = null;
            string monitorName = string.Empty;
            if (EnumDisplayDevicesW(output.DeviceName, 0, mon, 1))
            {
                monitorName = WStr(mon, 68, 128);
                edid = DeviceInfo.Try(() => Edid.FromInterface(WStr(mon, 328, 128)), null);
            }
            string name = edid?.Name ?? (monitorName.Length > 0 && !monitorName.StartsWith("Generic", StringComparison.OrdinalIgnoreCase) ? monitorName : string.Empty);
            r.Heading("display", $"Display {n}{(name.Length > 0 ? " — " + name : "")}{(output.Primary && attached.Count > 1 ? " (main)" : "")}");
            r.Row("display", "Resolution", $"{w} × {h}");
            if (edid is { NativeWidth: > 0 } && (edid.NativeWidth != w || edid.NativeHeight != h))
                r.Row("display", "Native resolution", $"{edid.NativeWidth} × {edid.NativeHeight}");
            if (hz > 1) r.Row("display", "Refresh rate", $"{hz} Hz");
            var hmon = MonitorFromPoint(new Point { X = x + 1, Y = y + 1 }, 2);
            if (hmon != IntPtr.Zero && DeviceInfo.Try(() => GetDpiForMonitor(hmon, 0, out uint dpi, out _) == 0 ? dpi : 0u, 0u) is var dpiX and > 0)
                r.Row("display", "Scaling", $"{dpiX * 100 / 96} % ({dpiX} dpi)");
            if (bits > 0) r.Row("display", "Color depth", $"{bits}-bit");
            if (edid is { WidthCm: > 0, HeightCm: > 0 })
            {
                double inches = Math.Sqrt(edid.WidthCm * edid.WidthCm + edid.HeightCm * edid.HeightCm) / 2.54;
                r.Row("display", "Size", $"{inches:0.0}″ ({edid.WidthCm} × {edid.HeightCm} cm)");
            }
            if (edid is not null)
            {
                r.Row("display", "Maker", edid.Maker);
                r.Row("display", "Product code", $"{edid.MakerId}{edid.Product:X4}");
                if (edid.Year > 1990) r.Row("display", "Made", edid.Week is > 0 and <= 53 ? $"{edid.Year}, week {edid.Week}" : edid.Year.ToString(CultureInfo.InvariantCulture));
                r.Row("display", "Serial number", edid.Serial);
            }
            r.Row("display", "Connected to", output.Name);
            r.Row("display", "Position", $"{x}, {y}");
        }
    }

    /// <summary>The parts of a monitor's EDID block worth showing.</summary>
    private sealed class Edid
    {
        public string MakerId = string.Empty;
        public string? Maker, Name, Serial;
        public int Product, Week, Year, WidthCm, HeightCm;
        public uint NativeWidth, NativeHeight;

        // "\\?\DISPLAY#GSM5B7F#5&2a8c0b1&0&UID4352#{e6f07b5f-…}" → Enum\DISPLAY\GSM5B7F\5&2a8c0b1&0&UID4352\Device Parameters
        public static Edid? FromInterface(string path)
        {
            var parts = path.Split('#');
            if (parts.Length < 3) return null;
            using var key = Reg($@"SYSTEM\CurrentControlSet\Enum\DISPLAY\{parts[1]}\{parts[2]}\Device Parameters");
            return key?.GetValue("EDID") is byte[] { Length: >= 128 } b ? Parse(b) : null;
        }

        private static Edid? Parse(byte[] b)
        {
            if (b[0] != 0 || b[1] != 0xFF || b[7] != 0) return null;
            int m = (b[8] << 8) | b[9];
            var e = new Edid
            {
                MakerId = new string(new[] { (char)('A' - 1 + ((m >> 10) & 0x1F)), (char)('A' - 1 + ((m >> 5) & 0x1F)), (char)('A' - 1 + (m & 0x1F)) }),
                Product = b[10] | (b[11] << 8),
                Week = b[16],
                Year = b[17] + 1990,
                WidthCm = b[21],
                HeightCm = b[22],
            };
            e.Maker = PnpMaker(e.MakerId);
            for (int d = 54; d <= 108; d += 18)
            {
                if (b[d] == 0 && b[d + 1] == 0)
                {
                    string text = Encoding.ASCII.GetString(b, d + 5, 13).Split('\n')[0].Trim();
                    if (b[d + 3] == 0xFC && text.Length > 0) e.Name = text;
                    else if (b[d + 3] == 0xFF && text.Length > 0) e.Serial = DeviceInfo.Clean(text);
                }
                else if (d == 54)   // the first detailed timing is the preferred (native) mode
                {
                    e.NativeWidth = (uint)(b[d + 2] | ((b[d + 4] & 0xF0) << 4));
                    e.NativeHeight = (uint)(b[d + 5] | ((b[d + 7] & 0xF0) << 4));
                }
            }
            return e;
        }

        private static string? PnpMaker(string id) => id switch
        {
            "GSM" => "LG", "LGD" => "LG Display", "SAM" or "SEC" => "Samsung", "SDC" => "Samsung Display", "DEL" => "Dell",
            "AUS" => "ASUS", "ACR" => "Acer", "BNQ" => "BenQ", "HWP" or "HPN" => "HP", "LEN" => "Lenovo", "AOC" => "AOC",
            "PHL" => "Philips", "VSC" => "ViewSonic", "MSI" => "MSI", "GBT" => "Gigabyte", "BOE" => "BOE",
            "AUO" => "AU Optronics", "CMN" => "Innolux", "SHP" => "Sharp", "APP" => "Apple", "IVM" => "iiyama",
            "NEC" => "NEC", "SNY" => "Sony", "MEI" => "Panasonic", "CSO" => "CSOT", "HKC" => "HKC", "XMI" => "Xiaomi",
            "EIZ" or "ENC" => "EIZO", "HSD" => "HannStar", "IVO" => "InfoVision", "TCL" => "TCL", "VIZ" => "Vizio",
            "MZI" => "Mi", "HUA" or "HWV" => "Huawei", "KOA" => "Konka", "PNP" => null,
            _ => null,
        };
    }

    // ---------------------------------------------------------------- storage

    private static void Storage(DeviceReport r)
    {
        // which volume lives on which disk
        var volumesOnDisk = new Dictionary<int, List<string>>();
        foreach (var d in DriveInfo.GetDrives())
        {
            if (d.DriveType is not (DriveType.Fixed or DriveType.Removable)) continue;
            string letter = d.Name.TrimEnd('\\');
            var h = CreateFileW($@"\\.\{letter}", 0, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
            if (h == new IntPtr(-1)) continue;
            try
            {
                var ext = new byte[256];
                if (DeviceIoControl(h, 0x00560000, null, 0, ext, (uint)ext.Length, out _, IntPtr.Zero))
                {
                    uint count = BinaryPrimitives.ReadUInt32LittleEndian(ext);
                    for (int i = 0; i < count && 8 + i * 24 + 4 <= ext.Length; i++)
                    {
                        int disk = BinaryPrimitives.ReadInt32LittleEndian(ext.AsSpan(8 + i * 24));
                        if (!volumesOnDisk.TryGetValue(disk, out var list)) volumesOnDisk[disk] = list = new List<string>();
                        if (!list.Contains(letter)) list.Add(letter);
                    }
                }
            }
            finally { CloseHandle(h); }
        }

        int misses = 0;
        for (int i = 0; i < 32 && misses < 8; i++)
        {
            var h = CreateFileW($@"\\.\PhysicalDrive{i}", 0, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
            if (h == new IntPtr(-1)) { misses++; continue; }
            misses = 0;
            try { Disk(r, h, i, volumesOnDisk.GetValueOrDefault(i)); }
            finally { CloseHandle(h); }
        }
        DeviceInfo.Volumes(r);
    }

    private static void Disk(DeviceReport r, IntPtr h, int number, List<string>? volumes)
    {
        var desc = Property(h, 0, 1024);
        if (desc is null) return;
        string Field(int offsetAt)
        {
            int at = (int)BinaryPrimitives.ReadUInt32LittleEndian(desc.AsSpan(offsetAt));
            if (at <= 0 || at >= desc.Length) return string.Empty;
            int end = Array.IndexOf(desc, (byte)0, at);
            return Encoding.ASCII.GetString(desc, at, (end < 0 ? desc.Length : end) - at).Trim();
        }
        string vendor = Field(12), product = Field(16), revision = Field(20), serial = Field(24);
        bool removable = desc[10] != 0;
        int bus = (int)BinaryPrimitives.ReadUInt32LittleEndian(desc.AsSpan(28));
        string model = vendor.Length > 0 && !product.StartsWith(vendor, StringComparison.OrdinalIgnoreCase) ? $"{vendor} {product}" : product;
        bool? ssd = Property(h, 7, 16) is { } seek ? seek[8] == 0 : null;
        string busName = bus switch
        {
            1 => "SCSI", 2 => "ATAPI", 3 => "ATA", 4 => "FireWire", 6 => "Fibre Channel", 7 => "USB", 8 => "RAID", 9 => "iSCSI",
            10 => "SAS", 11 => "SATA", 12 => "SD card", 13 => "MMC", 14 => "Virtual", 15 => "Virtual (file)", 16 => "Storage Spaces",
            17 => "NVMe", 18 => "SCM", 19 => "UFS", _ => string.Empty,
        };
        string kind = ssd switch { true => "SSD", false => "Hard disk", null => string.Empty };
        r.Heading("storage", $"Disk {number}{(model.Length > 0 ? " — " + model : "")}");
        r.Row("storage", "Type", Join(busName.Length > 0 ? busName : null, kind.Length > 0 ? kind : null) + (removable ? " · removable" : ""));
        var geo = new byte[256];
        if (DeviceIoControl(h, 0x000700A0, null, 0, geo, (uint)geo.Length, out uint got, IntPtr.Zero) && got >= 32)
        {
            long size = BinaryPrimitives.ReadInt64LittleEndian(geo.AsSpan(24));
            uint sector = BinaryPrimitives.ReadUInt32LittleEndian(geo.AsSpan(20));
            if (size > 0) r.Row("storage", "Capacity", DeviceInfo.DiskBytes(size));
            if (sector > 0) r.Row("storage", "Sector size", $"{sector} bytes");
        }
        r.Row("storage", "Firmware", revision);
        r.Row("storage", "Serial number", DeviceInfo.Clean(serial.Trim('.', ' ')));
        if (Property(h, 52, 64) is { } temp && BinaryPrimitives.ReadUInt16LittleEndian(temp.AsSpan(12)) > 0)
        {
            short c = BinaryPrimitives.ReadInt16LittleEndian(temp.AsSpan(26));
            if (c is > -40 and < 150) r.Row("storage", "Temperature", $"{c} °C");
        }
        if (volumes is { Count: > 0 }) r.Row("storage", "Volumes", string.Join(", ", volumes));
    }

    // IOCTL_STORAGE_QUERY_PROPERTY, standard query: the descriptor, or null when the disk doesn't answer it.
    private static byte[]? Property(IntPtr h, int id, int size)
    {
        var query = new byte[12];
        BinaryPrimitives.WriteInt32LittleEndian(query, id);
        var outBuf = new byte[size];
        return DeviceIoControl(h, 0x002D1400, query, 12, outBuf, (uint)size, out uint got, IntPtr.Zero) && got >= 8 ? outBuf : null;
    }

    // ---------------------------------------------------------------- battery

    private static void Battery(DeviceReport r)
    {
        var ps = new byte[12];
        if (!GetSystemPowerStatus(ps)) return;
        byte ac = ps[0], flag = ps[1], percent = ps[2], saver = ps[3];
        int left = BinaryPrimitives.ReadInt32LittleEndian(ps.AsSpan(4));
        if (flag == 128)
        {
            r.Row("battery", "Battery", "None (mains power)");
            return;
        }
        r.Row("battery", "Power", ac switch { 0 => "On battery", 1 => (flag & 8) != 0 ? "Plugged in, charging" : "Plugged in", _ => null });
        if (percent <= 100) r.Row("battery", "Charge", $"{percent}%");
        if (left > 0 && ac == 0) r.Row("battery", "Time left", DeviceInfo.Duration(TimeSpan.FromSeconds(left)));
        r.Row("battery", "Battery saver", saver == 1 ? "On" : "Off");
        DeviceInfo.Try(() => BatteryDetails(r));
    }

    // Design and full-charge capacity (wear), cycles, chemistry, maker: the battery device's IOCTLs.
    private static void BatteryDetails(DeviceReport r)
    {
        var batteryClass = new Guid("72631e54-78a4-11d0-bcf7-00aa00b7b32a");
        var set = SetupDiGetClassDevsW(ref batteryClass, IntPtr.Zero, IntPtr.Zero, 0x2 | 0x10);
        if (set == new IntPtr(-1)) return;
        try
        {
            int n = 0;
            int dataSize = IntPtr.Size == 8 ? 32 : 28;
            for (uint i = 0; i < 8; i++)
            {
                var did = new byte[dataSize];
                BinaryPrimitives.WriteInt32LittleEndian(did, dataSize);
                if (!SetupDiEnumDeviceInterfaces(set, IntPtr.Zero, ref batteryClass, i, did)) break;
                SetupDiGetDeviceInterfaceDetailW(set, did, null, 0, out uint need, IntPtr.Zero);
                if (need == 0 || need > 4096) continue;
                var detail = new byte[need];
                BinaryPrimitives.WriteInt32LittleEndian(detail, IntPtr.Size == 8 ? 8 : 6);
                if (!SetupDiGetDeviceInterfaceDetailW(set, did, detail, need, out _, IntPtr.Zero)) continue;
                string path = Encoding.Unicode.GetString(detail, 4, (int)need - 4).TrimEnd('\0');
                var h = CreateFileW(path, 0xC0000000, 3, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
                if (h == new IntPtr(-1)) continue;
                try { OneBattery(r, h, ++n); }
                finally { CloseHandle(h); }
            }
        }
        finally { SetupDiDestroyDeviceInfoList(set); }
    }

    private static void OneBattery(DeviceReport r, IntPtr h, int n)
    {
        var wait = new byte[4];
        var tagBuf = new byte[4];
        if (!DeviceIoControl(h, 0x00294040, wait, 4, tagBuf, 4, out _, IntPtr.Zero)) return;
        uint tag = BinaryPrimitives.ReadUInt32LittleEndian(tagBuf);
        if (tag == 0) return;
        byte[]? Query(int level, int size)
        {
            var q = new byte[12];
            BinaryPrimitives.WriteUInt32LittleEndian(q, tag);
            BinaryPrimitives.WriteInt32LittleEndian(q.AsSpan(4), level);
            var o = new byte[size];
            return DeviceIoControl(h, 0x00294044, q, 12, o, (uint)size, out uint got, IntPtr.Zero) && got > 0 ? o : null;
        }
        string? Text(int level) => Query(level, 512) is { } b ? DeviceInfo.Clean(Encoding.Unicode.GetString(b).Split('\0')[0]) : null;

        string? name = Text(4), maker = Text(6);
        if (n > 1 || name is not null) r.Heading("battery", $"Battery {n}{(name is null ? "" : " — " + name)}");
        r.Row("battery", "Maker", maker);
        if (Query(0, 40) is { } info)
        {
            string chem = Encoding.ASCII.GetString(info, 8, 4).Trim('\0', ' ');
            uint design = BinaryPrimitives.ReadUInt32LittleEndian(info.AsSpan(12));
            uint full = BinaryPrimitives.ReadUInt32LittleEndian(info.AsSpan(16));
            uint cycles = BinaryPrimitives.ReadUInt32LittleEndian(info.AsSpan(32));
            bool relative = (BinaryPrimitives.ReadUInt32LittleEndian(info) & 0x40000000) != 0;   // capacities in percent, not mWh
            r.Row("battery", "Chemistry", chem switch
            {
                "LION" or "Li-I" or "LIon" => "Lithium-ion", "LiP" or "LIPO" or "LiPo" => "Lithium polymer", "NiMH" => "Nickel metal hydride",
                "PbAc" => "Lead acid", "NiCd" => "Nickel cadmium", "" => null, _ => chem,
            });
            if (!relative && design > 0 && design != uint.MaxValue)
            {
                r.Row("battery", "Design capacity", $"{design / 1000.0:0.#} Wh");
                if (full > 0 && full != uint.MaxValue)
                {
                    r.Row("battery", "Full charge capacity", $"{full / 1000.0:0.#} Wh");
                    r.Row("battery", "Health", $"{Math.Min(100.0, 100.0 * full / design):0}% of its design capacity");
                }
            }
            if (cycles > 0) r.Row("battery", "Charge cycles", cycles.ToString(CultureInfo.InvariantCulture));
        }
        var ws = new byte[20];
        BinaryPrimitives.WriteUInt32LittleEndian(ws, tag);
        var status = new byte[16];
        if (DeviceIoControl(h, 0x0029404C, ws, 20, status, 16, out _, IntPtr.Zero))
        {
            uint voltage = BinaryPrimitives.ReadUInt32LittleEndian(status.AsSpan(8));
            int rate = BinaryPrimitives.ReadInt32LittleEndian(status.AsSpan(12));
            if (voltage is > 0 and < 100000) r.Row("battery", "Voltage", $"{voltage / 1000.0:0.00} V");
            if (rate != 0 && rate != int.MinValue && Math.Abs(rate) < 500000)
                r.Row("battery", rate < 0 ? "Discharge rate" : "Charge rate", $"{Math.Abs(rate) / 1000.0:0.0} W");
        }
        if (Query(2, 4) is { } t && BinaryPrimitives.ReadUInt32LittleEndian(t) is var dk and > 2000 and < 4000)
            r.Row("battery", "Temperature", $"{dk / 10.0 - 273.15:0.#} °C");
    }

    // ---------------------------------------------------------------- helpers

    private static RegistryKey? Reg(string path)
    {
        try { return Registry.LocalMachine.OpenSubKey(path); }
        catch { return null; }
    }

    private static string? RegText(object? v) => v switch
    {
        string s => s,
        byte[] b => Encoding.Unicode.GetString(b).TrimEnd('\0'),
        _ => null,
    };

    private static string? Join(string? a, string? b, string sep = " ")
        => a is null ? b : b is null ? a : b.StartsWith(a, StringComparison.OrdinalIgnoreCase) ? b : a + sep + b;

    private static string WStr(byte[] b, int offset, int chars)
    {
        string s = Encoding.Unicode.GetString(b, offset, chars * 2);
        int nul = s.IndexOf('\0');
        return (nul >= 0 ? s[..nul] : s).Trim();
    }

    private static string? Vendor(string id)
    {
        int at = id.IndexOf("VEN_", StringComparison.OrdinalIgnoreCase);
        if (at < 0 || at + 8 > id.Length) return null;
        return id.Substring(at + 4, 4).ToUpperInvariant() switch
        {
            "10DE" => "NVIDIA", "1002" or "1022" => "AMD", "8086" => "Intel", "5143" or "QCOM" => "Qualcomm", "1414" => "Microsoft",
            "15AD" => "VMware", "80EE" => "VirtualBox", "1AB8" => "Parallels", "1234" => "QEMU", _ => null,
        };
    }

    private static string? PciId(string id)
    {
        int v = id.IndexOf("VEN_", StringComparison.OrdinalIgnoreCase), d = id.IndexOf("DEV_", StringComparison.OrdinalIgnoreCase);
        return v >= 0 && d >= 0 && v + 8 <= id.Length && d + 8 <= id.Length ? $"{id.Substring(v + 4, 4)}:{id.Substring(d + 4, 4)}".ToLowerInvariant() : null;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Point
    {
        public int X, Y;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetLogicalProcessorInformationEx(int relationship, byte[]? buffer, ref uint length);

    [DllImport("kernel32.dll")]
    private static extern bool GetPhysicallyInstalledSystemMemory(out ulong totalKb);

    [DllImport("kernel32.dll")]
    private static extern bool GlobalMemoryStatusEx(byte[] status);

    [DllImport("kernel32.dll")]
    private static extern bool GetFirmwareType(out int type);

    [DllImport("kernel32.dll")]
    private static extern ushort GetUserDefaultUILanguage();

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern int LCIDToLocaleName(uint lcid, char[] name, int size, uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetUserDefaultLocaleName(char[] name, int size);

    [DllImport("kernel32.dll")]
    private static extern bool IsProcessorFeaturePresent(int feature);

    [DllImport("kernel32.dll")]
    private static extern bool GetSystemPowerStatus(byte[] status);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(IntPtr device, uint code, byte[]? inBuf, uint inSize, byte[]? outBuf, uint outSize, out uint returned, IntPtr overlapped);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("tbs.dll")]
    private static extern uint Tbsi_GetDeviceInfo(uint size, byte[] info);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern bool EnumDisplayDevicesW(string? device, uint index, byte[] displayDevice, uint flags);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern bool EnumDisplaySettingsW(string device, int mode, byte[] devMode);

    [DllImport("user32.dll")]
    private static extern IntPtr MonitorFromPoint(Point point, uint flags);

    [DllImport("shcore.dll")]
    private static extern int GetDpiForMonitor(IntPtr monitor, int type, out uint dpiX, out uint dpiY);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr SetupDiGetClassDevsW(ref Guid classGuid, IntPtr enumerator, IntPtr parent, uint flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiEnumDeviceInterfaces(IntPtr set, IntPtr deviceInfo, ref Guid interfaceClass, uint index, byte[] interfaceData);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetupDiGetDeviceInterfaceDetailW(IntPtr set, byte[] interfaceData, byte[]? detail, uint detailSize, out uint required, IntPtr deviceInfo);

    [DllImport("setupapi.dll")]
    private static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiEnumDeviceInfo(IntPtr set, uint index, byte[] deviceInfo);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetupDiGetDeviceRegistryPropertyW(IntPtr set, byte[] deviceInfo, uint property, out uint regType, byte[] buffer, uint size, out uint required);
}
