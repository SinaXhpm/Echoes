using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

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

    public static byte[] Encrypt(string plaintext, string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltLen);
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceLen);
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, 32);

        byte[] pt = Encoding.UTF8.GetBytes(plaintext);
        byte[] ct = new byte[pt.Length];
        byte[] tag = new byte[TagLen];
        try
        {
            using var gcm = new AesGcm(key, TagLen);
            gcm.Encrypt(nonce, pt, ct, tag);
        }
        finally { CryptographicOperations.ZeroMemory(key); }

        using var ms = new MemoryStream(Magic.Length + SaltLen + NonceLen + TagLen + ct.Length);
        ms.Write(Magic);
        ms.Write(salt);
        ms.Write(nonce);
        ms.Write(tag);
        ms.Write(ct);
        return ms.ToArray();
    }

    public static string Decrypt(byte[] blob, string password)
    {
        int min = Magic.Length + SaltLen + NonceLen + TagLen;
        if (blob.Length < min || !blob.Take(Magic.Length).SequenceEqual(Magic))
            throw new InvalidOperationException("This isn't an Echoes backup file.");

        int o = Magic.Length;
        byte[] salt = blob.AsSpan(o, SaltLen).ToArray(); o += SaltLen;
        byte[] nonce = blob.AsSpan(o, NonceLen).ToArray(); o += NonceLen;
        byte[] tag = blob.AsSpan(o, TagLen).ToArray(); o += TagLen;
        byte[] ct = blob.AsSpan(o).ToArray();

        byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, 32);
        byte[] pt = new byte[ct.Length];
        try
        {
            using var gcm = new AesGcm(key, TagLen);
            gcm.Decrypt(nonce, ct, tag, pt);   // throws on wrong password / tampering
        }
        catch (CryptographicException)
        {
            throw new InvalidOperationException("Wrong password, or the file is corrupt.");
        }
        finally { CryptographicOperations.ZeroMemory(key); }

        return Encoding.UTF8.GetString(pt);
    }
}
