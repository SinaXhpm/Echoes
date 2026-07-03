using System;
using System.Security.Cryptography;
using System.Text;

namespace Echoes.Helpers;

/// <summary>
/// Password-based vault for a single string payload (AES-GCM + PBKDF2-SHA256).
/// Used to protect Cloudflare credentials behind a user-chosen master password.
/// Blob layout (Base64): [salt(16)][nonce(12)][tag(16)][ciphertext]. A wrong password
/// fails the GCM auth tag, so <see cref="TryDecrypt"/> returns false instead of garbage.
/// </summary>
public static class MasterVault
{
    private const int Iterations = 200_000;

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

        byte[] blob = new byte[16 + 12 + 16 + ct.Length];
        Buffer.BlockCopy(salt, 0, blob, 0, 16);
        Buffer.BlockCopy(nonce, 0, blob, 16, 12);
        Buffer.BlockCopy(tag, 0, blob, 28, 16);
        Buffer.BlockCopy(ct, 0, blob, 44, ct.Length);
        return Convert.ToBase64String(blob);
    }

    public static bool TryDecrypt(string blobB64, string password, out string plain)
    {
        plain = string.Empty;
        try
        {
            byte[] blob = Convert.FromBase64String(blobB64);
            if (blob.Length < 44) return false;

            byte[] salt = blob[..16];
            byte[] nonce = blob[16..28];
            byte[] tag = blob[28..44];
            byte[] ct = blob[44..];

            byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, 32);
            byte[] pt = new byte[ct.Length];
            try
            {
                using var gcm = new AesGcm(key, 16);
                gcm.Decrypt(nonce, ct, tag, pt);   // throws on wrong password / tampering
            }
            finally { Array.Clear(key); }

            plain = Encoding.UTF8.GetString(pt);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
