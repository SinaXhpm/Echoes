using System.Collections.Generic;
using System.Runtime.Intrinsics.X86;
using System.Text;

namespace Echoes.Helpers;

/// <summary>
/// The processor's own description through the CPUID instruction (x86 / x64, any OS): vendor, brand string, family /
/// model / stepping, the instruction-set extensions it has and the hypervisor it runs under, if any. The OS sources
/// (registry, /proc/cpuinfo, sysctl) come first; this fills what they don't say. ARM has no such instruction.
/// </summary>
internal static class CpuId
{
    public static void Collect(DeviceReport r)
    {
        if (!X86Base.IsSupported) return;
        var (maxLeaf, b0, c0, d0) = X86Base.CpuId(0, 0);
        string vendor = Ascii(b0, d0, c0);
        r.Row("cpu", "Name", Brand());
        r.Row("cpu", "Vendor", vendor switch
        {
            "GenuineIntel" => "Intel",
            "AuthenticAMD" => "AMD",
            "HygonGenuine" => "Hygon",
            "CentaurHauls" or "  Shanghai  " => "Zhaoxin",
            _ => vendor,
        });
        if (maxLeaf < 1) return;
        var (a1, _, c1, d1) = X86Base.CpuId(1, 0);
        int stepping = a1 & 0xF, model = (a1 >> 4) & 0xF, family = (a1 >> 8) & 0xF;
        int fullFamily = family == 0xF ? family + ((a1 >> 20) & 0xFF) : family;
        int fullModel = family is 0x6 or 0xF ? (((a1 >> 16) & 0xF) << 4) + model : model;
        if (r.Value("cpu", "Identifier") is null)   // Windows names these in its own identifier line
            r.Row("cpu", "Family / model / stepping", $"{fullFamily} / {fullModel} (0x{fullModel:X2}) / {stepping}");

        int b7 = 0, c7 = 0, a71 = 0;
        if (maxLeaf >= 7)
        {
            (_, b7, c7, _) = X86Base.CpuId(7, 0);
            (a71, _, _, _) = X86Base.CpuId(7, 1);
        }
        uint maxExt = (uint)X86Base.CpuId(unchecked((int)0x80000000), 0).Eax;
        int cExt = maxExt >= 0x80000001 ? X86Base.CpuId(unchecked((int)0x80000001), 0).Ecx : 0;

        var f = new List<string>();
        void Add(bool has, string name) { if (has) f.Add(name); }
        Add(Bit(d1, 26), "SSE2");
        Add(Bit(c1, 0), "SSE3");
        Add(Bit(c1, 9), "SSSE3");
        Add(Bit(c1, 19), "SSE4.1");
        Add(Bit(c1, 20), "SSE4.2");
        Add(Bit(c1, 28), "AVX");
        Add(Bit(b7, 5), "AVX2");
        Add(Bit(c1, 12), "FMA3");
        Add(Bit(b7, 16), "AVX-512F");
        Add(Bit(b7, 30), "AVX-512BW");
        Add(Bit(c7, 11), "AVX-512 VNNI");
        Add(Bit(a71, 4), "AVX-VNNI");
        Add(Bit(c1, 25), "AES-NI");
        Add(Bit(b7, 29), "SHA");
        Add(Bit(c1, 1), "PCLMULQDQ");
        Add(Bit(b7, 3), "BMI1");
        Add(Bit(b7, 8), "BMI2");
        Add(Bit(c1, 23), "POPCNT");
        Add(Bit(cExt, 5), "LZCNT");
        Add(Bit(c1, 29), "F16C");
        Add(Bit(c1, 30), "RDRAND");
        Add(Bit(b7, 18), "RDSEED");
        Add(Bit(c1, 5), "VT-x");
        Add(Bit(cExt, 2), "AMD-V");
        if (f.Count > 0) r.Row("cpu", "Instruction sets", string.Join(", ", f));

        // Set under any hypervisor — also on a physical PC whose Windows runs on Hyper-V (VBS, WSL 2, Sandbox)
        if (Bit(c1, 31))
        {
            var (_, hb, hc, hd) = X86Base.CpuId(0x40000000, 0);
            string hv = Ascii(hb, hc, hd).Trim('\0', ' ');
            r.Row("cpu", "Hypervisor", hv switch
            {
                "Microsoft Hv" => "Hyper-V (also used by Windows security features and WSL 2)",
                "VMwareVMware" => "VMware",
                "KVMKVMKVM" => "KVM",
                "VBoxVBoxVBox" => "VirtualBox",
                "XenVMMXenVMM" => "Xen",
                "TCGTCGTCGTCG" => "QEMU",
                "prl hyperv" or " lrpepyh  vr" => "Parallels",
                "ACRNACRNACRN" => "ACRN",
                "Apple VZ" or "" => "present",
                _ => hv,
            });
        }
    }

    private static string? Brand()
    {
        if ((uint)X86Base.CpuId(unchecked((int)0x80000000), 0).Eax < 0x80000004) return null;
        var sb = new StringBuilder(48);
        for (uint leaf = 0x80000002; leaf <= 0x80000004; leaf++)
        {
            var (a, b, c, d) = X86Base.CpuId(unchecked((int)leaf), 0);
            sb.Append(Ascii(a, b, c, d));
        }
        string s = sb.ToString().Trim('\0', ' ');
        while (s.Contains("  ")) s = s.Replace("  ", " ");
        return s.Length > 0 ? s : null;
    }

    private static bool Bit(int value, int bit) => ((value >> bit) & 1) != 0;

    private static string Ascii(params int[] regs)
    {
        var sb = new StringBuilder(regs.Length * 4);
        foreach (int reg in regs)
            for (int i = 0; i < 4; i++)
            {
                char c = (char)((reg >> (8 * i)) & 0xFF);
                if (c != '\0') sb.Append(c);
            }
        return sb.ToString();
    }
}
