using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace Echoes.Helpers;

/// <summary>
/// The Device page on macOS and the base of iOS's: sysctl (model identifier, chip, core types and caches, memory,
/// OS build, boot time, the ARM extensions the chip has). Allowed in the App Sandbox. What only UIKit / Metal know
/// (the iPhone's name, screen, battery, GPU) comes from the iOS head (DeviceInfo.PlatformCollector).
/// </summary>
internal static class DeviceInfoApple
{
    public static void Collect(DeviceReport r)
    {
        bool mac = OperatingSystem.IsMacOS();
        DeviceInfo.Try(() =>
        {
            if (mac)
            {
                r.Row("device", "Manufacturer", "Apple");
                r.Row("device", "Model identifier", Str("hw.model"));
            }
            r.Row("os", "Name", mac ? $"macOS {Str("kern.osproductversion")}" : null);
            r.Row("os", "Build", Str("kern.osversion"));
            r.Row("os", "Kernel", Str("kern.osrelease") is { } rel ? $"Darwin {rel}" : null);
            if (Bytes("kern.boottime") is { Length: >= 8 } bt)
            {
                var boot = DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadInt64LittleEndian(bt)).ToLocalTime();
                r.Row("os", "Last start", boot.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture));
                r.Row("os", "Uptime", DeviceInfo.Duration(DateTimeOffset.Now - boot));
            }
        });
        DeviceInfo.Try(() => Cpu(r));
        DeviceInfo.Try(() =>
        {
            long mem = Long("hw.memsize");
            if (mem > 0) r.Row("memory", mac ? "Installed" : "Total", DeviceInfo.Bytes(mem));
            if (mac) r.Row("memory", "Page size", Long("hw.pagesize") is var p and > 0 ? DeviceInfo.Bytes(p) : null);
        });
        if (mac) DeviceInfo.Try(() => DeviceInfo.Volumes(r, d => d.Name == "/" || d.Name.StartsWith("/Volumes/", StringComparison.Ordinal)));
    }

    private static void Cpu(DeviceReport r)
    {
        r.Row("cpu", "Name", Str("machdep.cpu.brand_string"));
        long physical = Long("hw.physicalcpu"), logical = Long("hw.logicalcpu");
        int levels = (int)Long("hw.nperflevels");
        if (levels > 1)
        {
            var parts = new List<string>();
            for (int i = 0; i < levels; i++)
            {
                long n = Long($"hw.perflevel{i}.physicalcpu");
                string name = (Str($"hw.perflevel{i}.name") ?? (i == 0 ? "Performance" : "Efficiency")).ToLowerInvariant();
                if (n > 0) parts.Add($"{n} {name}");
            }
            r.Row("cpu", "Cores", $"{physical} ({string.Join(" + ", parts)})");
        }
        else if (physical > 0) r.Row("cpu", "Cores", physical.ToString(CultureInfo.InvariantCulture));
        if (logical > 0) r.Row("cpu", "Logical processors", logical.ToString(CultureInfo.InvariantCulture));
        long freq = Long("hw.cpufrequency_max") is var fm and > 0 ? fm : Long("hw.cpufrequency");
        if (freq > 0) r.Row("cpu", "Max clock", DeviceInfo.Mhz(freq / 1e6));
        long l1d = Long("hw.l1dcachesize"), l1i = Long("hw.l1icachesize"), l2 = Long("hw.l2cachesize"), l3 = Long("hw.l3cachesize");
        if (levels > 1)
        {
            // Apple silicon: each core type has its own L1 / shared L2
            for (int i = 0; i < levels; i++)
            {
                long d = Long($"hw.perflevel{i}.l1dcachesize"), ii = Long($"hw.perflevel{i}.l1icachesize"), s2 = Long($"hw.perflevel{i}.l2cachesize");
                string name = (Str($"hw.perflevel{i}.name") ?? (i == 0 ? "Performance" : "Efficiency"));
                if (d > 0) r.Row("cpu", $"{name} cores' caches", $"L1 {DeviceInfo.Bytes(d)} data + {DeviceInfo.Bytes(ii)} instruction, L2 {DeviceInfo.Bytes(s2)}");
            }
        }
        else
        {
            if (l1d > 0) r.Row("cpu", "L1 cache", l1i > 0 ? $"{DeviceInfo.Bytes(l1d)} data + {DeviceInfo.Bytes(l1i)} instruction" : DeviceInfo.Bytes(l1d));
            if (l2 > 0) r.Row("cpu", "L2 cache", DeviceInfo.Bytes(l2));
        }
        if (l3 > 0) r.Row("cpu", "L3 cache", DeviceInfo.Bytes(l3));
        r.Row("cpu", "Cache line", Long("hw.cachelinesize") is var line and > 0 ? $"{line} bytes" : null);
        if (Long("hw.optional.arm64") == 1)
        {
            var feats = new List<string>();
            foreach (var (key, name) in new[]
            {
                ("FEAT_AES", "AES"), ("FEAT_SHA256", "SHA-256"), ("FEAT_SHA512", "SHA-512"), ("FEAT_SHA3", "SHA-3"),
                ("FEAT_CRC32", "CRC32"), ("FEAT_LSE", "LSE atomics"), ("FEAT_DotProd", "Dot product"), ("FEAT_FP16", "FP16"),
                ("FEAT_BF16", "BF16"), ("FEAT_I8MM", "Int8 matrix"), ("FEAT_SME", "SME"), ("FEAT_SME2", "SME2"),
                ("FEAT_PAuth", "Pointer authentication"), ("FEAT_BTI", "BTI"), ("FEAT_MTE", "MTE"),
            })
                if (Long("hw.optional.arm." + key) == 1) feats.Add(name);
            if (feats.Count > 0) r.Row("cpu", "Instruction sets", "NEON, " + string.Join(", ", feats));
            if (OperatingSystem.IsMacOS() && Long("sysctl.proc_translated") == 1) r.Row("cpu", "Note", "Echoes runs under Rosetta 2 here");
        }
    }

    // ---------------------------------------------------------------- sysctl

    private const string LibSystem = "/usr/lib/libSystem.dylib";

    [DllImport(LibSystem, EntryPoint = "sysctlbyname")]
    private static extern int SysctlByName(byte[] name, byte[]? oldp, ref nuint oldlenp, IntPtr newp, nuint newlen);

    internal static byte[]? Bytes(string name)
    {
        try
        {
            byte[] key = Encoding.ASCII.GetBytes(name + "\0");
            nuint len = 0;
            if (SysctlByName(key, null, ref len, IntPtr.Zero, 0) != 0 || len == 0 || len > 1 << 16) return null;
            var buf = new byte[(int)len];
            if (SysctlByName(key, buf, ref len, IntPtr.Zero, 0) != 0) return null;
            return buf.AsSpan(0, (int)len).ToArray();
        }
        catch { return null; }
    }

    internal static string? Str(string name)
        => Bytes(name) is { } b ? DeviceInfo.Clean(Encoding.UTF8.GetString(b).TrimEnd('\0')) : null;

    internal static long Long(string name) => Bytes(name) switch
    {
        { Length: 8 } b => BinaryPrimitives.ReadInt64LittleEndian(b),
        { Length: 4 } b => BinaryPrimitives.ReadInt32LittleEndian(b),
        _ => 0,
    };
}
