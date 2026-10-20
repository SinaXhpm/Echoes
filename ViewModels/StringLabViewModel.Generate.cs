using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _generateOutput = string.Empty;
    [ObservableProperty] private int _generateLength = 24;
    [ObservableProperty] private int _generateCount = 5;
    [ObservableProperty] private bool _genSymbols = true;           // PASSWORD: include !@#$…
    [ObservableProperty] private bool _genExcludeAmbiguous = true;  // drop 0/O, 1/l/I (read-aloud / handwriting safe)
    [ObservableProperty] private string _generateInfo = string.Empty;


    // The card under the generated values: empty (hidden) for identifiers (UUID, ULID), which aren't secrets.
    [ObservableProperty] private IReadOnlyList<CrackRow> _crackRows = Array.Empty<CrackRow>();
    [ObservableProperty] private string _crackBitsText = string.Empty;
    public bool HasCrackTime => CrackRows.Count > 0;
    partial void OnCrackRowsChanged(IReadOnlyList<CrackRow> value) => OnPropertyChanged(nameof(HasCrackTime));

    private const string PwSymbol = "!@#$%^&*-_=+?";
    private const string NanoIdAlphabet = "useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict";
    private const string Crockford32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    [RelayCommand]
    private Task Generate(string type)
    {
        int count = Math.Clamp(GenerateCount, 1, 1000);
        int len = Math.Clamp(GenerateLength, 1, 4096);
        bool symbols = GenSymbols, noAmbiguous = GenExcludeAmbiguous;
        double? bits = SecretBits(type, len, symbols, noAmbiguous);

        return RunOffUi("gen", () =>
        {
            var sb = new StringBuilder();
            for (int i = 0; i < count; i++)
                sb.AppendLine(GenerateOne(type, len, symbols, noAmbiguous));
            return (Text: sb.ToString().TrimEnd(), Info: DescribeEntropy(type, len, symbols, noAmbiguous));
        }, r =>
        {
            GenerateOutput = r.Text;
            string clamped = count != GenerateCount || len != GenerateLength ? $"   (clamped to count {count}, length {len})" : "";
            GenerateInfo = r.Info + clamped;
            SetCrackTime(bits);
        }, "Generate: ");
    }

    // The entropy of what is generated, for the types that are secrets (null for identifiers such as UUID and ULID).
    private static double? SecretBits(string type, int len, bool symbols, bool noAmbiguous)
    {
        var (upper, lower, digit) = PwSets(noAmbiguous);
        return type switch
        {
            "password" => CrackTime.PasswordBits(symbols ? new[] { upper.Length, lower.Length, digit.Length, PwSymbol.Length }
                                                         : new[] { upper.Length, lower.Length, digit.Length }, len),
            "alnum" => CrackTime.Bits(upper.Length + lower.Length + digit.Length, len),
            "pin" => CrackTime.Bits(10, len),
            "nanoid" => CrackTime.Bits(NanoIdAlphabet.Length, 21),
            "hex" or "base64" or "b64url" => len * 8.0,
            _ => null,
        };
    }

    private void SetCrackTime(double? bits)
    {
        if (bits is not { } b)
        {
            CrackRows = Array.Empty<CrackRow>();
            CrackBitsText = string.Empty;
            return;
        }
        var rows = new List<CrackRow>();
        foreach (var s in CrackTime.Scenarios)
        {
            var level = CrackTime.Judge(b, s.Rate);
            rows.Add(new CrackRow(s.Name, s.Detail, CrackTime.Describe(b, s.Rate),
                level == CrackTime.Level.Weak, level == CrackTime.Level.Fair, level == CrackTime.Level.Strong));
        }
        CrackRows = rows;
        CrackBitsText = $"{Math.Floor(b):N0} bits";
    }

    private static (string Upper, string Lower, string Digit) PwSets(bool noAmbiguous) => noAmbiguous
        ? ("ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789")
        : ("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", "0123456789");

    private static string GenerateOne(string type, int len, bool symbols, bool noAmbiguous)
    {
        var (upper, lower, digit) = PwSets(noAmbiguous);
        return type switch
        {
            "uuid" => Guid.NewGuid().ToString(),
            "guidn" => Guid.NewGuid().ToString("N"),
            "uuidv7" => NewUuidV7(),
            "ulid" => NewUlid(),
            "nanoid" => RandomNumberGenerator.GetString(NanoIdAlphabet, 21),
            "password" => Password(len, symbols ? new[] { upper, lower, digit, PwSymbol } : new[] { upper, lower, digit }),
            "alnum" => RandomNumberGenerator.GetString(upper + lower + digit, len),
            "hex" => Convert.ToHexString(RandomNumberGenerator.GetBytes(len)).ToLowerInvariant(),
            "base64" => Convert.ToBase64String(RandomNumberGenerator.GetBytes(len)),
            "b64url" => ToBase64Url(RandomNumberGenerator.GetBytes(len)),
            "pin" => RandomNumberGenerator.GetString("0123456789", len),
            _ => Guid.NewGuid().ToString()
        };
    }

    // Uniform over the union alphabet, re-drawn until every class appears (when the length allows).
    // Rejection keeps the result uniform over all valid passwords, unlike "force one of each" splicing.
    private static string Password(int len, string[] classes)
    {
        string all = string.Concat(classes);
        string pw = RandomNumberGenerator.GetString(all, len);
        if (len < classes.Length) return pw;
        for (int attempt = 0; attempt < 100 && !Array.TrueForAll(classes, c => pw.AsSpan().IndexOfAny(c) >= 0); attempt++)
            pw = RandomNumberGenerator.GetString(all, len);
        return pw;
    }

    private static string DescribeEntropy(string type, int len, bool symbols, bool noAmbiguous)
    {
        var (upper, lower, digit) = PwSets(noAmbiguous);
        static string Bits(double b) => $"≈ {Math.Floor(b):N0} bits of entropy per value";
        return type switch
        {
            "uuid" or "guidn" => "UUID v4 — 122 random bits.",
            "uuidv7" => "UUID v7 — 48-bit Unix-ms timestamp + 12-bit sequence + 62 random bits (sorts by creation time).",
            "ulid" => "ULID — 48-bit Unix-ms timestamp + 80 random bits, Crockford Base32 (sorts by creation time).",
            "nanoid" => "NanoID — 21 URL-safe chars, 126 random bits.",
            "password" => $"{Bits(len * Math.Log2(upper.Length + lower.Length + digit.Length + (symbols ? PwSymbol.Length : 0)))} ({len} chars from {upper.Length + lower.Length + digit.Length + (symbols ? PwSymbol.Length : 0)} symbols).",
            "alnum" => $"{Bits(len * Math.Log2(upper.Length + lower.Length + digit.Length))} ({len} chars from {upper.Length + lower.Length + digit.Length} symbols).",
            "pin" => $"{Bits(len * Math.Log2(10))} ({len} digits).",
            "hex" or "base64" or "b64url" => $"{Bits(len * 8.0)} ({len} random bytes).",
            _ => string.Empty,
        };
    }

    // ---- UUID v7 (RFC 9562 §5.7) — Guid.CreateVersion7 only exists from .NET 9 ----

    private static readonly object TimeIdLock = new();
    private static long _v7LastMs;
    private static int _v7Seq;

    private static string NewUuidV7()
    {
        Span<byte> b = stackalloc byte[16];
        RandomNumberGenerator.Fill(b);

        long ms;
        int seq;
        lock (TimeIdLock)
        {
            // §6.2 method 1: rand_a is a 12-bit counter seeded randomly each millisecond (top bit
            // clear leaves room to count), so a batch generated within one ms still sorts in order.
            ms = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (ms <= _v7LastMs)
            {
                ms = _v7LastMs;
                if (++_v7Seq > 0xFFF) { ms++; _v7Seq = RandomNumberGenerator.GetInt32(0x800); }
            }
            else _v7Seq = RandomNumberGenerator.GetInt32(0x800);
            _v7LastMs = ms;
            seq = _v7Seq;
        }

        b[0] = (byte)(ms >> 40); b[1] = (byte)(ms >> 32); b[2] = (byte)(ms >> 24);
        b[3] = (byte)(ms >> 16); b[4] = (byte)(ms >> 8); b[5] = (byte)ms;
        b[6] = (byte)(0x70 | (seq >> 8));            // version 7 + high 4 bits of the sequence
        b[7] = (byte)seq;
        b[8] = (byte)((b[8] & 0x3F) | 0x80);         // variant 10xx (RFC 4122/9562)

        string hex = Convert.ToHexString(b).ToLowerInvariant();
        return $"{hex[..8]}-{hex[8..12]}-{hex[12..16]}-{hex[16..20]}-{hex[20..]}";
    }

    // ---- ULID: 48-bit ms time + 80-bit randomness, Crockford Base32, 26 chars ----

    private static long _ulidLastMs;
    private static UInt128 _ulidLastRandom;

    private static string NewUlid()
    {
        Span<byte> r = stackalloc byte[10];
        RandomNumberGenerator.Fill(r);
        UInt128 random = ((UInt128)(uint)(r[0] << 8 | r[1]) << 64) | System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(r[2..]);
        UInt128 max80 = (UInt128.One << 80) - 1;

        long ms;
        lock (TimeIdLock)
        {
            // Spec's monotonic mode: same millisecond → previous randomness + 1, so IDs stay ordered.
            ms = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (ms <= _ulidLastMs)
            {
                ms = _ulidLastMs;
                if (_ulidLastRandom >= max80) { ms++; }
                else random = _ulidLastRandom + 1;
            }
            _ulidLastMs = ms;
            _ulidLastRandom = random;
        }

        Span<char> c = stackalloc char[26];
        long t = ms;
        for (int i = 9; i >= 0; i--) { c[i] = Crockford32[(int)(t & 31)]; t >>= 5; }
        for (int i = 25; i >= 10; i--) { c[i] = Crockford32[(int)(random & 31)]; random >>= 5; }
        return new string(c);
    }
}

/// <summary>One line of the String Lab "Time to crack" card: an attacker's situation, and how long this secret lasts against it.</summary>
public sealed record CrackRow(string Name, string Detail, string Time, bool IsWeak, bool IsFair, bool IsStrong);
