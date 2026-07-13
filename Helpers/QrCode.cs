using System;
using System.Collections.Generic;
using System.Text;

namespace Echoes.Helpers;

/// <summary>
/// Minimal, dependency-free QR Code encoder — byte mode (UTF-8), error-correction level M,
/// versions 1..10 (auto-picks the smallest that fits). Produces a boolean module matrix
/// (<c>true</c> = dark). Pure managed BCL, so it runs on desktop and Android with no external
/// library or native code. The algorithm follows the public-domain reference by Project Nayuki
/// (https://www.nayuki.io/page/qr-code-generator-library); mask penalty uses rules 1, 3 and 4
/// (mask choice only affects readability, never correctness — the applied mask always matches
/// the mask written into the format bits).
/// </summary>
public static class QrCode
{
    private const int MaxVersion = 10;

    // Error-correction level M tables, indexed by version (index 0 unused).
    private static readonly int[] EccPerBlock  = { -1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26 };
    private static readonly int[] NumEccBlocks = { -1,  1,  1,  1,  2,  2,  4,  4,  2,  3,  4 };

    /// <summary>Encodes <paramref name="text"/> (UTF-8) into a square dark/light matrix indexed
    /// [row, col]. Returns null if it is too long for versions 1..10 at EC level M.</summary>
    public static bool[,]? Encode(string text)
    {
        byte[] data = Encoding.UTF8.GetBytes(text ?? string.Empty);
        for (int ver = 1; ver <= MaxVersion; ver++)
        {
            int ccBits = ver <= 9 ? 8 : 16;                       // byte-mode char-count bits
            int needBits = 4 + ccBits + data.Length * 8;
            if (needBits <= NumDataCodewords(ver) * 8)
                return Build(data, ver);
        }
        return null;
    }

    // ---- codeword generation ----

    private static bool[,] Build(byte[] data, int ver)
    {
        // 1) data bit stream: mode (byte=0b0100) + char count + bytes + terminator + pad.
        var bits = new List<bool>();
        AppendBits(bits, 0b0100, 4);
        AppendBits(bits, data.Length, ver <= 9 ? 8 : 16);
        foreach (byte b in data) AppendBits(bits, b, 8);

        int capacityBits = NumDataCodewords(ver) * 8;
        AppendBits(bits, 0, Math.Min(4, capacityBits - bits.Count));       // terminator
        AppendBits(bits, 0, (8 - bits.Count % 8) % 8);                     // byte-align
        for (int pad = 0xEC; bits.Count < capacityBits; pad ^= 0xEC ^ 0x11) // alternate pad bytes
            AppendBits(bits, pad, 8);

        var dataCw = new byte[bits.Count / 8];
        for (int i = 0; i < bits.Count; i++)
            if (bits[i]) dataCw[i >> 3] |= (byte)(1 << (7 - (i & 7)));

        // 2) error correction + interleave.
        byte[] all = AddEccAndInterleave(dataCw, ver);

        // 3) place onto the matrix and pick the best mask.
        return DrawMatrix(all, ver);
    }

    private static void AppendBits(List<bool> bits, int value, int len)
    {
        for (int i = len - 1; i >= 0; i--)
            bits.Add(((value >> i) & 1) != 0);
    }

    private static int NumRawDataModules(int ver)
    {
        int result = (16 * ver + 128) * ver + 64;
        if (ver >= 2)
        {
            int numAlign = ver / 7 + 2;
            result -= (25 * numAlign - 10) * numAlign - 55;
            if (ver >= 7) result -= 36;   // version information modules
        }
        return result;
    }

    private static int NumDataCodewords(int ver) =>
        NumRawDataModules(ver) / 8 - EccPerBlock[ver] * NumEccBlocks[ver];

    private static byte[] AddEccAndInterleave(byte[] data, int ver)
    {
        int numBlocks = NumEccBlocks[ver];
        int blockEccLen = EccPerBlock[ver];
        int rawCodewords = NumRawDataModules(ver) / 8;
        int numShort = numBlocks - rawCodewords % numBlocks;
        int shortLen = rawCodewords / numBlocks;

        var blocks = new byte[numBlocks][];
        byte[] rsDiv = RsDivisor(blockEccLen);
        for (int i = 0, k = 0; i < numBlocks; i++)
        {
            int datLen = shortLen - blockEccLen + (i < numShort ? 0 : 1);
            var dat = new byte[datLen];
            Array.Copy(data, k, dat, 0, datLen);
            k += datLen;
            var block = new byte[shortLen + 1];
            Array.Copy(dat, 0, block, 0, dat.Length);
            byte[] ecc = RsRemainder(dat, rsDiv);
            Array.Copy(ecc, 0, block, block.Length - blockEccLen, blockEccLen);
            blocks[i] = block;
        }

        var result = new byte[rawCodewords];
        for (int i = 0, idx = 0; i < blocks[0].Length; i++)
            for (int j = 0; j < blocks.Length; j++)
                if (i != shortLen - blockEccLen || j >= numShort)   // skip unused cell in short blocks
                    result[idx++] = blocks[j][i];
        return result;
    }

    // ---- Reed-Solomon over GF(256), primitive polynomial 0x11D ----

    private static byte[] RsDivisor(int degree)
    {
        var result = new byte[degree];
        result[degree - 1] = 1;
        int root = 1;
        for (int i = 0; i < degree; i++)
        {
            for (int j = 0; j < degree; j++)
            {
                result[j] = (byte)RsMul(result[j] & 0xFF, root);
                if (j + 1 < degree) result[j] ^= result[j + 1];
            }
            root = RsMul(root, 0x02);
        }
        return result;
    }

    private static byte[] RsRemainder(byte[] data, byte[] divisor)
    {
        var result = new byte[divisor.Length];
        foreach (byte b in data)
        {
            int factor = (b ^ result[0]) & 0xFF;
            Array.Copy(result, 1, result, 0, result.Length - 1);
            result[^1] = 0;
            for (int i = 0; i < result.Length; i++)
                result[i] ^= (byte)RsMul(divisor[i] & 0xFF, factor);
        }
        return result;
    }

    private static int RsMul(int x, int y)
    {
        int z = 0;
        for (int i = 7; i >= 0; i--)
        {
            z = (z << 1) ^ ((z >> 7) * 0x11D);
            z ^= ((y >> i) & 1) * x;
        }
        return z & 0xFF;
    }

    // ---- matrix drawing ----

    private static bool[,] DrawMatrix(byte[] codewords, int ver)
    {
        int size = ver * 4 + 17;
        var mod = new bool[size, size];
        var fn = new bool[size, size];

        void Set(int x, int y, bool dark) { mod[y, x] = dark; fn[y, x] = true; }

        // timing patterns
        for (int i = 0; i < size; i++) { Set(6, i, i % 2 == 0); Set(i, 6, i % 2 == 0); }

        // finder patterns (+ separators) centred at the three corners
        void Finder(int cx, int cy)
        {
            for (int dy = -4; dy <= 4; dy++)
                for (int dx = -4; dx <= 4; dx++)
                {
                    int x = cx + dx, y = cy + dy;
                    if (x < 0 || x >= size || y < 0 || y >= size) continue;
                    int d = Math.Max(Math.Abs(dx), Math.Abs(dy));
                    Set(x, y, d != 2 && d != 4);
                }
        }
        Finder(3, 3); Finder(size - 4, 3); Finder(3, size - 4);

        // alignment patterns (skip the three that collide with finders)
        int[] pos = AlignPositions(ver);
        int n = pos.Length;
        for (int i = 0; i < n; i++)
            for (int j = 0; j < n; j++)
            {
                if ((i == 0 && j == 0) || (i == 0 && j == n - 1) || (i == n - 1 && j == 0)) continue;
                int cx = pos[i], cy = pos[j];
                for (int dy = -2; dy <= 2; dy++)
                    for (int dx = -2; dx <= 2; dx++)
                        Set(cx + dx, cy + dy, Math.Max(Math.Abs(dx), Math.Abs(dy)) != 1);
            }

        // reserve format + version areas
        DrawFormat(mod, fn, size, 0);
        DrawVersion(Set, size, ver);

        // place codeword bits in the zig-zag pattern, skipping function modules
        int bit = 0;
        for (int right = size - 1; right >= 1; right -= 2)
        {
            if (right == 6) right = 5;
            for (int v = 0; v < size; v++)
                for (int c = 0; c < 2; c++)
                {
                    int x = right - c;
                    bool upward = ((right + 1) & 2) == 0;
                    int y = upward ? size - 1 - v : v;
                    if (!fn[y, x] && bit < codewords.Length * 8)
                    {
                        mod[y, x] = ((codewords[bit >> 3] >> (7 - (bit & 7))) & 1) != 0;
                        bit++;
                    }
                }
        }

        // choose the mask with the lowest penalty, then bake it + its format bits in
        int bestMask = 0, minPenalty = int.MaxValue;
        for (int m = 0; m < 8; m++)
        {
            ApplyMask(mod, fn, size, m);
            DrawFormat(mod, fn, size, m);
            int p = Penalty(mod, size);
            if (p < minPenalty) { minPenalty = p; bestMask = m; }
            ApplyMask(mod, fn, size, m);   // XOR again to undo
        }
        ApplyMask(mod, fn, size, bestMask);
        DrawFormat(mod, fn, size, bestMask);
        return mod;
    }

    private static int[] AlignPositions(int ver)
    {
        if (ver == 1) return Array.Empty<int>();
        int numAlign = ver / 7 + 2;
        int step = (ver * 4 + numAlign * 2 + 1) / (numAlign * 2 - 2) * 2;
        int size = ver * 4 + 17;
        var result = new int[numAlign];
        result[0] = 6;
        for (int i = numAlign - 1, p = size - 7; i >= 1; i--, p -= step) result[i] = p;
        return result;
    }

    private static void DrawFormat(bool[,] mod, bool[,] fn, int size, int mask)
    {
        int data = mask;                         // EC level M format bits = 0b00, so data = mask
        int rem = data;
        for (int i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >> 9) * 0x537);
        int bits = ((data << 10) | rem) ^ 0x5412;

        bool B(int i) => ((bits >> i) & 1) != 0;
        void Set(int x, int y, bool d) { mod[y, x] = d; fn[y, x] = true; }

        for (int i = 0; i <= 5; i++) Set(8, i, B(i));
        Set(8, 7, B(6)); Set(8, 8, B(7)); Set(7, 8, B(8));
        for (int i = 9; i < 15; i++) Set(14 - i, 8, B(i));

        for (int i = 0; i < 8; i++) Set(size - 1 - i, 8, B(i));
        for (int i = 8; i < 15; i++) Set(8, size - 15 + i, B(i));
        Set(8, size - 8, true);                  // module that is always dark
    }

    private static void DrawVersion(Action<int, int, bool> set, int size, int ver)
    {
        if (ver < 7) return;
        int rem = ver;
        for (int i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
        int bits = (ver << 12) | rem;            // 18 bits
        for (int i = 0; i < 18; i++)
        {
            bool b = ((bits >> i) & 1) != 0;
            int a = size - 11 + i % 3, c = i / 3;
            set(a, c, b);
            set(c, a, b);
        }
    }

    private static void ApplyMask(bool[,] mod, bool[,] fn, int size, int mask)
    {
        for (int y = 0; y < size; y++)
            for (int x = 0; x < size; x++)
            {
                if (fn[y, x]) continue;
                bool invert = mask switch
                {
                    0 => (x + y) % 2 == 0,
                    1 => y % 2 == 0,
                    2 => x % 3 == 0,
                    3 => (x + y) % 3 == 0,
                    4 => (x / 3 + y / 2) % 2 == 0,
                    5 => x * y % 2 + x * y % 3 == 0,
                    6 => (x * y % 2 + x * y % 3) % 2 == 0,
                    _ => ((x + y) % 2 + x * y % 3) % 2 == 0,
                };
                if (invert) mod[y, x] ^= true;
            }
    }

    // Penalty using rules 1 (runs of 5+), 3 (2x2 blocks) and 4 (dark proportion).
    private static int Penalty(bool[,] mod, int size)
    {
        int result = 0;

        // rule 1 — runs of five or more same-colour modules, per row and per column
        for (int y = 0; y < size; y++)
        {
            int run = 1;
            for (int x = 1; x < size; x++)
            {
                if (mod[y, x] == mod[y, x - 1]) { run++; if (run == 5) result += 3; else if (run > 5) result++; }
                else run = 1;
            }
        }
        for (int x = 0; x < size; x++)
        {
            int run = 1;
            for (int y = 1; y < size; y++)
            {
                if (mod[y, x] == mod[y - 1, x]) { run++; if (run == 5) result += 3; else if (run > 5) result++; }
                else run = 1;
            }
        }

        // rule 3 — 2x2 blocks of the same colour
        for (int y = 0; y < size - 1; y++)
            for (int x = 0; x < size - 1; x++)
            {
                bool c = mod[y, x];
                if (c == mod[y, x + 1] && c == mod[y + 1, x] && c == mod[y + 1, x + 1]) result += 3;
            }

        // rule 4 — deviation of dark-module proportion from 50%
        int dark = 0;
        for (int y = 0; y < size; y++)
            for (int x = 0; x < size; x++)
                if (mod[y, x]) dark++;
        int total = size * size;
        int k = (Math.Abs(dark * 20 - total * 10) + total - 1) / total - 1;
        result += k * 10;

        return result;
    }
}
