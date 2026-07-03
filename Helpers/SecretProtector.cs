using System;
using System.Security.Cryptography;
using System.Text;

namespace Echoes.Helpers;

/// <summary>
/// Lightweight, cross-platform at-rest protection for stored secrets (API tokens, keys).
///
/// The AES-GCM key is derived from this machine + user identity (PBKDF2) — it is NOT stored
/// anywhere and is NOT in the (open-source) binary. Consequences:
///   • Secrets are no longer readable as plaintext in the profile file.
///   • A profile file copied to another machine/user simply won't decrypt (its fields drop to
///     empty and the user re-enters them) — this is the intended protection, not a bug.
///
/// This is defense-in-depth against casual leaks (cat-ing the file, accidental sharing, roaming
/// sync), NOT protection against malware running as the same user. For that, use a scoped token.
/// </summary>
public static class SecretProtector
{
    private const string Prefix = "enc1:";   // tag so Unprotect can tell encrypted vs legacy plaintext
    private static readonly Lazy<byte[]> Key = new(DeriveKey);

    private static byte[] DeriveKey()
    {
        // Stable per machine+user, reproducible across launches, different per install.
        string identity = $"{Environment.MachineName}|{Environment.UserName}|{Environment.OSVersion.Platform}"
            .ToLowerInvariant();
        byte[] salt = Encoding.UTF8.GetBytes("Echoes.SecretProtector.v1");
        return Rfc2898DeriveBytes.Pbkdf2(identity, salt, 100_000, HashAlgorithmName.SHA256, 32);
    }

    /// <summary>Encrypt a secret for storage. Empty/null → empty string.</summary>
    public static string Protect(string? plain)
    {
        if (string.IsNullOrEmpty(plain)) return string.Empty;

        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] pt = Encoding.UTF8.GetBytes(plain);
        byte[] ct = new byte[pt.Length];
        byte[] tag = new byte[16];

        using (var gcm = new AesGcm(Key.Value, 16))
            gcm.Encrypt(nonce, pt, ct, tag);

        byte[] blob = new byte[12 + 16 + ct.Length];
        Buffer.BlockCopy(nonce, 0, blob, 0, 12);
        Buffer.BlockCopy(tag, 0, blob, 12, 16);
        Buffer.BlockCopy(ct, 0, blob, 28, ct.Length);
        return Prefix + Convert.ToBase64String(blob);
    }

    /// <summary>
    /// Decrypt a stored value. Values without the tag are returned as-is (legacy plaintext,
    /// auto-migrated on next save). A value that fails to decrypt (wrong machine / tampered)
    /// yields empty so the user re-enters it instead of crashing.
    /// </summary>
    public static string Unprotect(string? stored)
    {
        if (string.IsNullOrEmpty(stored)) return string.Empty;
        if (!stored.StartsWith(Prefix, StringComparison.Ordinal)) return stored;

        try
        {
            byte[] blob = Convert.FromBase64String(stored[Prefix.Length..]);
            if (blob.Length < 28) return string.Empty;

            byte[] nonce = blob[..12];
            byte[] tag = blob[12..28];
            byte[] ct = blob[28..];
            byte[] pt = new byte[ct.Length];

            using var gcm = new AesGcm(Key.Value, 16);
            gcm.Decrypt(nonce, ct, tag, pt);
            return Encoding.UTF8.GetString(pt);
        }
        catch
        {
            return string.Empty;
        }
    }
}
