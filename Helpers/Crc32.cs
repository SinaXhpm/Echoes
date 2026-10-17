using System;

namespace Echoes.Helpers;

/// <summary>
/// CRC-32 / IEEE 802.3 (reflected polynomial 0xEDB88320, init and final XOR 0xFFFFFFFF) — the value
/// zlib, PNG, gzip, Ethernet and the <c>crc32</c> CLI all print ("123456789" → CBF43926).
/// Hand-rolled because System.IO.Hashing is a separate NuGet package; a 256-entry table is plenty
/// fast for the string/file sizes String Lab deals with.
/// </summary>
public sealed class Crc32
{
    private static readonly uint[] Table = BuildTable();

    private uint _state = 0xFFFFFFFFu;

    public void Append(ReadOnlySpan<byte> data)
    {
        uint crc = _state;
        foreach (byte b in data)
            crc = Table[(crc ^ b) & 0xFF] ^ (crc >> 8);
        _state = crc;
    }

    public uint Value => ~_state;

    // Big-endian, so the hex of the bytes reads the same as the conventional "%08x" of the value.
    public byte[] GetHashBytes()
    {
        uint v = Value;
        return new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v };
    }

    public static byte[] Hash(ReadOnlySpan<byte> data)
    {
        var crc = new Crc32();
        crc.Append(data);
        return crc.GetHashBytes();
    }

    private static uint[] BuildTable()
    {
        var table = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i;
            for (int k = 0; k < 8; k++)
                c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        return table;
    }
}
