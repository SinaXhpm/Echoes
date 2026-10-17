using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _hashInput = string.Empty;
    [ObservableProperty] private string _hashOutput = string.Empty;
    [ObservableProperty] private string _hashKey = string.Empty;        // optional: turns digests into HMACs
    [ObservableProperty] private string _hashExpected = string.Empty;   // optional: "compare with"
    [ObservableProperty] private string _hashCompare = string.Empty;    // MATCH / MISMATCH verdict line
    [ObservableProperty] private bool _hashCompareOk;
    [ObservableProperty] private string _hashFormat = "hex";
    [ObservableProperty] private string _hashFileStatus = string.Empty;
    [ObservableProperty] private bool _isHashingFile;

    public string[] HashFormats { get; } = { "hex", "HEX", "Base64" };

    private sealed record HashRow(string Label, byte[]? Digest, string? Note);

    // The last result, kept as raw bytes so flipping hex/HEX/Base64 or typing an expected value
    // re-renders / re-compares instantly — without re-reading a multi-GB file.
    private readonly List<HashRow> _lastDigests = new();
    private string _lastHashHeader = string.Empty;

    private CancellationTokenSource? _hashFileCts;

    private static readonly string[] AllHashAlgs = { "md5", "sha1", "sha256", "sha384", "sha512", "sha3-256", "sha3-512", "crc32" };

    partial void OnHashFormatChanged(string value) => RenderHashOutput();
    partial void OnHashExpectedChanged(string value) => UpdateHashCompare();

    [RelayCommand]
    private Task HashAction(string type)
    {
        string input = HashInput;
        string key = HashKey;
        if (string.IsNullOrEmpty(input)) { ResetError(); return Task.CompletedTask; }

        return RunOffUi("hash", () =>
        {
            byte[] data = Encoding.UTF8.GetBytes(input);
            byte[]? hmacKey = key.Length > 0 ? Encoding.UTF8.GetBytes(key) : null;
            var rows = new List<HashRow>();
            foreach (var alg in type == "all" ? AllHashAlgs : new[] { type })
                rows.Add(ComputeDigest(alg, data, hmacKey));
            return rows;
        }, rows =>
        {
            // A single unsupported algorithm is an error, not an output.
            if (rows.Count == 1 && rows[0].Digest is null)
            {
                ErrorMessage = rows[0].Note ?? "Not supported.";
                return;
            }
            _lastDigests.Clear();
            _lastDigests.AddRange(rows);
            _lastHashHeader = string.Empty;
            RenderHashOutput();
        }, "Hash: ");
    }

    private static HashRow ComputeDigest(string alg, byte[] data, byte[]? key)
    {
        bool hmac = key != null;
        switch (alg)
        {
            case "md5": return hmac ? new("HMAC-MD5", HMACMD5.HashData(key!, data), null) : new("MD5", MD5.HashData(data), null);
            case "sha1": return hmac ? new("HMAC-SHA1", HMACSHA1.HashData(key!, data), null) : new("SHA-1", SHA1.HashData(data), null);
            case "sha256": return hmac ? new("HMAC-SHA256", HMACSHA256.HashData(key!, data), null) : new("SHA-256", SHA256.HashData(data), null);
            case "sha384": return hmac ? new("HMAC-SHA384", HMACSHA384.HashData(key!, data), null) : new("SHA-384", SHA384.HashData(data), null);
            case "sha512": return hmac ? new("HMAC-SHA512", HMACSHA512.HashData(key!, data), null) : new("SHA-512", SHA512.HashData(data), null);
            // SHA-3 depends on the OS crypto library (Windows 11 24H2+/OpenSSL 1.1.1+; not Android).
            case "sha3-256":
                if (hmac)
                    return HMACSHA3_256.IsSupported
                        ? new("HMAC-SHA3-256", HMACSHA3_256.HashData(key!, data), null)
                        : new("HMAC-SHA3-256", null, "HMAC-SHA3-256 is not supported on this OS.");
                return SHA3_256.IsSupported
                    ? new("SHA3-256", SHA3_256.HashData(data), null)
                    : new("SHA3-256", null, "SHA3-256 is not supported on this OS.");
            case "sha3-512":
                if (hmac)
                    return HMACSHA3_512.IsSupported
                        ? new("HMAC-SHA3-512", HMACSHA3_512.HashData(key!, data), null)
                        : new("HMAC-SHA3-512", null, "HMAC-SHA3-512 is not supported on this OS.");
                return SHA3_512.IsSupported
                    ? new("SHA3-512", SHA3_512.HashData(data), null)
                    : new("SHA3-512", null, "SHA3-512 is not supported on this OS.");
            case "crc32":
                return new("CRC-32", Crc32.Hash(data), hmac ? "CRC-32 has no keyed form — HMAC key ignored." : null);
            default:
                return new(alg, null, $"Unknown algorithm '{alg}'.");
        }
    }

    private string FormatDigest(byte[] d) => HashFormat switch
    {
        "HEX" => Convert.ToHexString(d),
        "Base64" => Convert.ToBase64String(d),
        _ => Convert.ToHexString(d).ToLowerInvariant(),
    };

    private void RenderHashOutput()
    {
        if (_lastDigests.Count == 0) { UpdateHashCompare(); return; }

        // One plain digest → just the digest, so COPY yields exactly the value.
        if (_lastHashHeader.Length == 0 && _lastDigests.Count == 1 && _lastDigests[0].Digest is { } only && _lastDigests[0].Note is null)
        {
            HashOutput = FormatDigest(only);
            UpdateHashCompare();
            return;
        }

        var sb = new StringBuilder(_lastHashHeader);
        foreach (var row in _lastDigests)
        {
            if (row.Digest is { } d) Row2(sb, row.Label, FormatDigest(d));
            else Row2(sb, row.Label, "(" + (row.Note ?? "n/a") + ")");
        }
        foreach (var row in _lastDigests)
            if (row.Digest is not null && row.Note is not null) sb.AppendLine("# " + row.Note);
        HashOutput = sb.ToString().TrimEnd();
        UpdateHashCompare();
    }

    // Compare against every digest in the last result: hex case-insensitively, Base64 exactly.
    // Whitespace and ':' are ignored ("AB:CD…" fingerprints); a "hash  filename" line from
    // sha256sum also works (its first token is tried on its own).
    private void UpdateHashCompare()
    {
        string raw = HashExpected.Trim();
        int withDigest = 0;
        foreach (var r in _lastDigests) if (r.Digest is not null) withDigest++;
        if (raw.Length == 0 || withDigest == 0) { HashCompare = string.Empty; return; }

        var candidates = new List<string> { StripDigestNoise(raw) };
        int ws = raw.IndexOfAny(new[] { ' ', '\t' });
        if (ws > 0) candidates.Add(StripDigestNoise(raw[..ws]));

        foreach (var row in _lastDigests)
        {
            if (row.Digest is not { } d) continue;
            string hex = Convert.ToHexString(d);
            string b64 = Convert.ToBase64String(d).TrimEnd('=');
            foreach (var c in candidates)
            {
                string cc = c.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? c[2..] : c;
                if (string.Equals(cc, hex, StringComparison.OrdinalIgnoreCase) || string.Equals(c.TrimEnd('='), b64, StringComparison.Ordinal))
                {
                    HashCompareOk = true;
                    HashCompare = withDigest == 1 ? "✓ MATCH" : $"✓ MATCH — {row.Label}";
                    return;
                }
            }
        }
        HashCompareOk = false;
        HashCompare = withDigest == 1 ? "✗ MISMATCH" : "✗ MISMATCH — none of the digests above equals the expected value";
    }

    private static string StripDigestNoise(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s)
            if (!char.IsWhiteSpace(c) && c != ':') sb.Append(c);
        return sb.ToString();
    }

    // ---------- file hashing ----------

    /// <summary>
    /// Stream a file through MD5/SHA-1/SHA-256/SHA-512 (HMAC when a key is set) in one pass, 1 MB at
    /// a time, so a multi-GB ISO never lands in memory. Called by the view's FILE… button — the
    /// picker needs the TopLevel's StorageProvider, so it lives in code-behind like other views.
    /// </summary>
    public async Task HashFileAsync(string name, long size, Func<Task<Stream>> open)
    {
        if (IsHashingFile) return;
        ResetError();
        var cts = new CancellationTokenSource();
        _hashFileCts = cts;
        IsHashingFile = true;
        IsBusy = true;
        string key = HashKey;
        bool finished = false;
        HashFileStatus = $"Hashing {name} …";

        // Progress<T> posts back to the UI thread; drop reports that arrive after the final status.
        var progress = new Progress<long>(done =>
        {
            if (finished) return;
            HashFileStatus = size > 0
                ? $"Hashing {name} — {Math.Min(100, done * 100 / size)}%  ({HumanBytes(done)} of {HumanBytes(size)})"
                : $"Hashing {name} — {HumanBytes(done)}";
        });

        try
        {
            var sw = Stopwatch.StartNew();
            Stream stream = await open();
            List<HashRow> rows;
            long total;
            try
            {
                (rows, total) = await Task.Run(() => HashStreamAsync(stream, key, progress, cts.Token), cts.Token);
            }
            finally { await stream.DisposeAsync(); }

            finished = true;
            var header = new StringBuilder();
            Row2(header, "File", name);
            Row2(header, "Size", $"{HumanBytes(total)}  ({total:N0} bytes)");
            if (key.Length > 0) Row2(header, "Mode", "HMAC (key from the HMAC field)");
            _lastDigests.Clear();
            _lastDigests.AddRange(rows);
            _lastHashHeader = header.ToString();
            RenderHashOutput();
            HashFileStatus = $"✓ {name} — {HumanBytes(total)} in {sw.Elapsed.TotalSeconds:F1} s";
        }
        catch (OperationCanceledException) { finished = true; HashFileStatus = "File hash cancelled."; }
        catch (Exception ex) { finished = true; HashFileStatus = string.Empty; ErrorMessage = "File hash: " + ex.Message; }
        finally
        {
            _hashFileCts = null;
            cts.Dispose();
            IsHashingFile = false;
            if (_runningTools.Count == 0) IsBusy = false;
        }
    }

    private static async Task<(List<HashRow> Rows, long Total)> HashStreamAsync(Stream stream, string key, IProgress<long> progress, CancellationToken ct)
    {
        byte[]? k = key.Length > 0 ? Encoding.UTF8.GetBytes(key) : null;
        var algs = new[] { HashAlgorithmName.MD5, HashAlgorithmName.SHA1, HashAlgorithmName.SHA256, HashAlgorithmName.SHA512 };
        string[] labels = k != null
            ? new[] { "HMAC-MD5", "HMAC-SHA1", "HMAC-SHA256", "HMAC-SHA512" }
            : new[] { "MD5", "SHA-1", "SHA-256", "SHA-512" };
        var hashes = new IncrementalHash[algs.Length];
        for (int i = 0; i < algs.Length; i++)
            hashes[i] = k != null ? IncrementalHash.CreateHMAC(algs[i], k) : IncrementalHash.CreateHash(algs[i]);

        byte[] buffer = ArrayPool<byte>.Shared.Rent(1 << 20);
        try
        {
            long total = 0, lastReport = Environment.TickCount64;
            int n;
            while ((n = await stream.ReadAsync(buffer.AsMemory(0, 1 << 20), ct).ConfigureAwait(false)) > 0)
            {
                // The four digests are independent — feeding them in parallel roughly triples
                // throughput on a multi-core machine versus running them back to back.
                int len = n;
                Parallel.For(0, hashes.Length, i => hashes[i].AppendData(buffer, 0, len));
                total += n;
                if (Environment.TickCount64 - lastReport >= 150)
                {
                    lastReport = Environment.TickCount64;
                    progress.Report(total);
                }
            }
            var rows = new List<HashRow>(hashes.Length);
            for (int i = 0; i < hashes.Length; i++)
                rows.Add(new HashRow(labels[i], hashes[i].GetHashAndReset(), null));
            return (rows, total);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
            foreach (var h in hashes) h.Dispose();
        }
    }

    [RelayCommand]
    private void CancelHashFile() => _hashFileCts?.Cancel();

    private static string HumanBytes(long bytes)
    {
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        double v = bytes;
        int u = 0;
        while (v >= 1024 && u < units.Length - 1) { v /= 1024; u++; }
        return u == 0 ? $"{bytes} B" : $"{v:0.##} {units[u]}";
    }
}
