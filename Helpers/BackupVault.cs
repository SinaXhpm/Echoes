using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>
/// Password-based encryption for the app's single-file backup. Fully self-contained (no external
/// crypto deps): PBKDF2-SHA256 (600k iterations) derives the key, AES-256-GCM protects the payload.
///
/// <para>File layout: [magic "ECHOBAK1" (8)][salt (16)][nonce (12)][tag (16)][ciphertext].
/// A wrong password fails the GCM auth tag, so <see cref="Decrypt"/> throws a clear error instead
/// of returning garbage.</para>
/// </summary>
public static class BackupVault
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("ECHOBAK1"); // 8 bytes
    private const int Iterations = 600_000;
    private const int SaltLen = 16, NonceLen = 12, TagLen = 16;

    // A real backup is the profile + the notes vault: kilobytes to a few MB. The cap only stops a huge file
    // that happens to start with the magic from exhausting memory (an OOM kill on Android).
    private const int MaxFileBytes = 128 * 1024 * 1024;

    /// <summary>
    /// Read a user-picked backup file. The 8-byte magic is checked FIRST, so picking the wrong (possibly
    /// multi-GB) file fails at once instead of being copied into memory; the rest is read up to a sane cap.
    /// </summary>
    public static async Task<byte[]> ReadFileAsync(Stream stream)
    {
        byte[] head = new byte[Magic.Length];
        int got = await stream.ReadAtLeastAsync(head, head.Length, throwOnEndOfStream: false).ConfigureAwait(false);
        if (got < head.Length || !head.AsSpan().SequenceEqual(Magic))
            throw new InvalidOperationException("This isn't an Echoes backup file.");

        long known = -1;
        try { if (stream.CanSeek) known = stream.Length; } catch { }
        if (known > MaxFileBytes) throw TooLarge();

        using var ms = new MemoryStream(known > 0 ? (int)known : 64 * 1024);
        ms.Write(head);
        byte[] buf = new byte[81920];
        int n;
        while ((n = await stream.ReadAsync(buf).ConfigureAwait(false)) > 0)
        {
            if (ms.Length + n > MaxFileBytes) throw TooLarge();
            ms.Write(buf, 0, n);
        }
        return ms.ToArray();

        static InvalidOperationException TooLarge()
            => new($"File is too large for an Echoes backup (over {MaxFileBytes / (1024 * 1024)} MB).");
    }

    // Key and plaintext live in pinned buffers that are zeroed when done (SecureMemory); the ciphertext is written
    // straight into the output instead of an intermediate array.
    public static byte[] Encrypt(string plaintext, ReadOnlySpan<char> password)
    {
        int head = Magic.Length + SaltLen + NonceLen + TagLen;
        byte[] pt = SecureMemory.Utf8(plaintext);
        byte[]? key = null;
        try
        {
            byte[] blob = new byte[head + pt.Length];
            Magic.CopyTo(blob, 0);
            Span<byte> salt = blob.AsSpan(Magic.Length, SaltLen);
            Span<byte> nonce = blob.AsSpan(Magic.Length + SaltLen, NonceLen);
            RandomNumberGenerator.Fill(salt);
            RandomNumberGenerator.Fill(nonce);
            key = SecureMemory.Pbkdf2(password, salt, Iterations, 32);
            using var gcm = new AesGcm(key, TagLen);
            gcm.Encrypt(nonce, pt, blob.AsSpan(head), blob.AsSpan(Magic.Length + SaltLen + NonceLen, TagLen));
            return blob;
        }
        finally
        {
            SecureMemory.Zero(key);
            SecureMemory.Zero(pt);
        }
    }

    /// <summary>Decrypt a backup into a pinned UTF-8 buffer the caller parses and then zeroes.</summary>
    public static byte[] Decrypt(byte[] blob, ReadOnlySpan<char> password)
    {
        int head = Magic.Length + SaltLen + NonceLen + TagLen;
        if (blob.Length < head || !blob.AsSpan(0, Magic.Length).SequenceEqual(Magic))
            throw new InvalidOperationException("This isn't an Echoes backup file.");

        ReadOnlySpan<byte> salt = blob.AsSpan(Magic.Length, SaltLen);
        ReadOnlySpan<byte> nonce = blob.AsSpan(Magic.Length + SaltLen, NonceLen);
        ReadOnlySpan<byte> tag = blob.AsSpan(Magic.Length + SaltLen + NonceLen, TagLen);

        byte[] key = SecureMemory.Pbkdf2(password, salt, Iterations, 32);
        byte[] pt = SecureMemory.Alloc(blob.Length - head);
        try
        {
            using var gcm = new AesGcm(key, TagLen);
            gcm.Decrypt(nonce, blob.AsSpan(head), tag, pt);   // throws on wrong password / tampering
            return pt;
        }
        catch (CryptographicException)
        {
            SecureMemory.Zero(pt);
            throw new InvalidOperationException("Wrong password, or the file is corrupt.");
        }
        finally { SecureMemory.Zero(key); }
    }
}
