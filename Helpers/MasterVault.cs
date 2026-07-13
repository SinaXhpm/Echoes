using System;
using System.Security.Cryptography;
using System.Text;

namespace Echoes.Helpers;

/// <summary>
/// Password-based vault for a single string payload (AES-GCM + PBKDF2-SHA256).
/// Used to protect Cloudflare credentials behind a user-chosen master password.
///
/// New blob layout (Base64): [magic "ECV1"(4)][salt(16)][nonce(12)][tag(16)][ciphertext],
/// derived with 600k PBKDF2 iterations (OWASP). Legacy blobs (no magic header, 200k
/// iterations) still decrypt via a fallback and are upgraded to the new format the next
/// time the vault is saved. A wrong password fails the GCM auth tag, so
/// <see cref="TryDecrypt"/> returns false instead of garbage.
/// </summary>
public static class MasterVault
{
    private const int Iterations = 600_000;         // OWASP PBKDF2-SHA256 guidance
    private const int LegacyIterations = 200_000;   // pre-"ECV1" blobs

    private static readonly byte[] Magic = { 0x45, 0x43, 0x56, 0x31 }; // "ECV1"

    public static string Encrypt(string plain, string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, 32);

        byte[] pt = Encoding.UTF8.GetBytes(plain);
        byte[] ct = new byte[pt.Length];
        byte[] tag = new byte[16];
        try
        {
            using var gcm = new AesGcm(key, 16);
            gcm.Encrypt(nonce, pt, ct, tag);
        }
        finally { Array.Clear(key); }

        byte[] blob = new byte[Magic.Length + 16 + 12 + 16 + ct.Length];
        Buffer.BlockCopy(Magic, 0, blob, 0, Magic.Length);
        Buffer.BlockCopy(salt, 0, blob, Magic.Length, 16);
        Buffer.BlockCopy(nonce, 0, blob, Magic.Length + 16, 12);
        Buffer.BlockCopy(tag, 0, blob, Magic.Length + 28, 16);
        Buffer.BlockCopy(ct, 0, blob, Magic.Length + 44, ct.Length);
        return Convert.ToBase64String(blob);
    }

    public static bool TryDecrypt(string blobB64, string password, out string plain)
    {
        plain = string.Empty;
        try
        {
            byte[] blob = Convert.FromBase64String(blobB64);

            // New format: strip the magic header and derive with the current (600k) work factor.
            if (blob.Length >= Magic.Length + 44 && HasMagic(blob)
                && TryDecryptBody(blob, Magic.Length, password, Iterations, out plain))
                return true;

            // Legacy format: no header, 200k iterations. Also the fallback if a legacy blob's
            // random leading bytes ever collided with the magic prefix.
            if (blob.Length >= 44 && TryDecryptBody(blob, 0, password, LegacyIterations, out plain))
                return true;

            return false;
        }
        catch
        {
            return false;
        }
    }

    private static bool HasMagic(byte[] blob)
    {
        for (int i = 0; i < Magic.Length; i++)
            if (blob[i] != Magic[i]) return false;
        return true;
    }

    // Decrypt a [salt(16)][nonce(12)][tag(16)][ct] body starting at <paramref name="offset"/>.
    private static bool TryDecryptBody(byte[] blob, int offset, string password, int iterations, out string plain)
    {
        plain = string.Empty;
        if (blob.Length - offset < 44) return false;

        byte[] salt = blob[offset..(offset + 16)];
        byte[] nonce = blob[(offset + 16)..(offset + 28)];
        byte[] tag = blob[(offset + 28)..(offset + 44)];
        byte[] ct = blob[(offset + 44)..];

        byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, 32);
        byte[] pt = new byte[ct.Length];
        try
        {
            using var gcm = new AesGcm(key, 16);
            gcm.Decrypt(nonce, ct, tag, pt);   // throws on wrong password / tampering
        }
        catch { return false; }
        finally { Array.Clear(key); }

        plain = Encoding.UTF8.GetString(pt);
        return true;
    }
}
