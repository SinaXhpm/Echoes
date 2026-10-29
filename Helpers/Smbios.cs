using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Echoes.Helpers;

/// <summary>
/// The firmware's SMBIOS (DMI) table: what the board says about the system, the board itself, the BIOS, the chassis,
/// the processor socket and every memory slot. Windows hands it to any user (GetSystemFirmwareTable 'RSMB'); Linux
/// only to root (/sys/firmware/dmi/tables/DMI), so there the world-readable /sys/class/dmi/id files are used instead.
/// </summary>
internal sealed class Smbios
{
    /// <summary>One structure: its type, formatted area and strings.</summary>
    public sealed class Entry
    {
        public Entry(byte type, byte[] data, List<string> strings)
        {
            Type = type;
            Data = data;
            Strings = strings;
        }

        public byte Type { get; }
        public byte[] Data { get; }
        public List<string> Strings { get; }

        public int Length => Data.Length;
        public byte Byte(int offset) => offset < Data.Length ? Data[offset] : (byte)0;
        public ushort Word(int offset) => offset + 2 <= Data.Length ? BinaryPrimitives.ReadUInt16LittleEndian(Data.AsSpan(offset)) : (ushort)0;
        public uint Dword(int offset) => offset + 4 <= Data.Length ? BinaryPrimitives.ReadUInt32LittleEndian(Data.AsSpan(offset)) : 0;
        public ulong Qword(int offset) => offset + 8 <= Data.Length ? BinaryPrimitives.ReadUInt64LittleEndian(Data.AsSpan(offset)) : 0;

        /// <summary>The string a byte at <paramref name="offset"/> points to (1-based), placeholders dropped.</summary>
        public string? Str(int offset)
        {
            int i = Byte(offset);
            return i >= 1 && i <= Strings.Count ? DeviceInfo.Clean(Strings[i - 1]) : null;
        }

        /// <summary>The 16-byte UUID at <paramref name="offset"/>, in its usual text form (the first three fields are little-endian).</summary>
        public string? Uuid(int offset)
        {
            if (offset + 16 > Data.Length) return null;
            var b = Data.AsSpan(offset, 16);
            bool allSame = true;
            for (int i = 1; i < 16; i++) if (b[i] != b[0]) { allSame = false; break; }
            if (allSame) return null;   // all 00 / FF: not set
            return new Guid(b).ToString().ToUpperInvariant();
        }
    }

    private Smbios(byte major, byte minor, List<Entry> entries)
    {
        Major = major;
        Minor = minor;
        Entries = entries;
    }

    public byte Major { get; }
    public byte Minor { get; }
    public List<Entry> Entries { get; }

    public IEnumerable<Entry> OfType(byte type)
    {
        foreach (var e in Entries) if (e.Type == type) yield return e;
    }

    public Entry? First(byte type)
    {
        foreach (var e in Entries) if (e.Type == type) return e;
        return null;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetSystemFirmwareTable(uint provider, uint tableId, byte[]? buffer, uint size);

    public static Smbios? Read()
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                const uint Rsmb = 0x52534D42;   // 'RSMB'
                uint size = GetSystemFirmwareTable(Rsmb, 0, null, 0);
                if (size == 0 || size > 1 << 20) return null;
                var buf = new byte[size];
                if (GetSystemFirmwareTable(Rsmb, 0, buf, size) != size) return null;
                // RawSMBIOSData: calling method, major, minor, DMI revision, table length, table
                int length = (int)BinaryPrimitives.ReadUInt32LittleEndian(buf.AsSpan(4));
                return Parse(buf[1], buf[2], buf.AsSpan(8, Math.Min(length, buf.Length - 8)));
            }
            if (OperatingSystem.IsLinux() && File.Exists("/sys/firmware/dmi/tables/DMI"))
            {
                byte[] table = File.ReadAllBytes("/sys/firmware/dmi/tables/DMI");
                byte major = 0, minor = 0;
                if (File.Exists("/sys/firmware/dmi/tables/smbios_entry_point"))
                {
                    byte[] ep = File.ReadAllBytes("/sys/firmware/dmi/tables/smbios_entry_point");
                    if (ep.Length > 8 && ep[0] == '_' && ep[1] == 'S' && ep[2] == 'M' && ep[3] == '3') { major = ep[7]; minor = ep[8]; }
                    else if (ep.Length > 7 && ep[0] == '_' && ep[1] == 'S' && ep[2] == 'M') { major = ep[6]; minor = ep[7]; }
                }
                return Parse(major, minor, table);
            }
        }
        catch { /* not readable here (Linux: root only) */ }
        return null;
    }

    private static Smbios Parse(byte major, byte minor, ReadOnlySpan<byte> t)
    {
        var entries = new List<Entry>();
        int pos = 0;
        while (pos + 4 <= t.Length)
        {
            byte type = t[pos], len = t[pos + 1];
            if (len < 4 || pos + len > t.Length) break;
            var data = t.Slice(pos, len).ToArray();
            // the string set: NUL-terminated strings, ended by an extra NUL
            int s = pos + len;
            var strings = new List<string>();
            while (s < t.Length)
            {
                int end = t.Slice(s).IndexOf((byte)0);
                if (end < 0) { s = t.Length; break; }
                if (end == 0) { s++; break; }
                strings.Add(Encoding.ASCII.GetString(t.Slice(s, end)));
                s += end + 1;
            }
            if (strings.Count == 0 && s < t.Length && t[s] == 0) s++;   // an empty set is two NULs
            entries.Add(new Entry(type, data, strings));
            if (type == 127) break;   // end of table
            pos = s;
        }
        return new Smbios(major, minor, entries);
    }

    // ---------------------------------------------------------------- decoded fields

    public static string? MemoryType(byte t) => t switch
    {
        0x0F => "SDRAM", 0x12 => "DDR", 0x13 => "DDR2", 0x14 => "DDR2 FB-DIMM", 0x18 => "DDR3", 0x1A => "DDR4",
        0x1B => "LPDDR", 0x1C => "LPDDR2", 0x1D => "LPDDR3", 0x1E => "LPDDR4", 0x1F => "Non-volatile", 0x20 => "HBM",
        0x21 => "HBM2", 0x22 => "DDR5", 0x23 => "LPDDR5", 0x24 => "HBM3",
        _ => null,
    };

    public static string? FormFactor(byte f) => f switch
    {
        0x03 => "SIMM", 0x05 => "Chip (soldered)", 0x06 => "DIP", 0x08 => "Proprietary card", 0x09 => "DIMM", 0x0B => "Row of chips",
        0x0C => "RIMM", 0x0D => "SO-DIMM", 0x0F => "FB-DIMM", 0x10 => "Die", 0x11 => "CAMM",
        _ => null,
    };

    public static string? ErrorCorrection(byte e) => e switch
    {
        0x03 => "None", 0x04 => "Parity", 0x05 => "Single-bit ECC", 0x06 => "Multi-bit ECC", 0x07 => "CRC",
        _ => null,
    };

    /// <summary>A memory module maker: SMBIOS often gives its JEDEC code ("80CE") instead of a name.</summary>
    public static string? MemoryMaker(string? s)
    {
        if (s is null) return null;
        string k = s.Replace(" ", string.Empty).ToUpperInvariant();
        if (k.StartsWith("0X", StringComparison.Ordinal)) k = k[2..];
        if (k.Length > 4 && k.TrimEnd('0').Length <= 4) k = k[..4];   // "80CE000080CE" and the like
        string? name = k switch
        {
            "80CE" or "CE00" or "00CE" or "CE80" => "Samsung",
            "80AD" or "AD00" or "00AD" or "AD80" => "SK hynix",
            "802C" or "2C00" or "002C" or "2C80" => "Micron",
            "859B" or "9B85" => "Crucial",
            "9801" or "0198" or "0117" => "Kingston",
            "04CD" or "CD04" => "G.Skill",
            "029E" or "9E02" => "Corsair",
            "04CB" or "CB04" => "ADATA",
            "0B4E" or "4E0B" => "Kingmax",
            "8551" or "5185" => "Qimonda",
            "857F" or "7F85" => "Hynix",
            "8A76" => "CXMT",
            _ => null,
        };
        return name is null ? s : name == s ? s : $"{name} ({s})";
    }
}
