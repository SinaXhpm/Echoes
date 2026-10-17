using System;
using System.Security.Cryptography;

namespace Echoes.Helpers;

/// <summary>
/// Password-based vault for a single payload (AES-GCM + PBKDF2-SHA256).
/// Used to protect Cloudflare credentials behind a user-chosen master password.
///
/// New blob layout (Base64): [magic "ECV1"(4)][salt(16)][nonce(12)][tag(16)][ciphertext],
/// derived with 600k PBKDF2 iterations (OWASP). Legacy blobs (no magic header, 200k
/// iterations) still decrypt via a fallback and are upgraded to the new format the next
/// time the vault is saved. A wrong password fails the GCM auth tag, so the TryDecrypt
/// methods return false instead of garbage.
///
/// Memory: keys and plaintext live in pinned buffers (<see cref="SecureMemory"/>) that are zeroed after use; the
/// decrypted payload is handed out as UTF-8 bytes so the caller can parse it and zero it, with no string copy of the
/// whole vault left on the heap.
/// </summary>
public static class MasterVault
{
    private const int Iterations = 600_000;         // OWASP PBKDF2-SHA256 guidance
    private const int LegacyIterations = 200_000;   // pre-"ECV1" blobs

    private static readonly byte[] Magic = { 0x45, 0x43, 0x56, 0x31 }; // "ECV1"

    /// <summary>Derive the 32-byte vault key (600k PBKDF2-SHA256) into a pinned buffer the caller zeroes. Callers that save
    /// repeatedly derive it ONCE per unlocked session and pass it to <see cref="Encrypt(ReadOnlySpan{byte}, byte[], byte[])"/>.</summary>
    public static byte[] DeriveKey(ReadOnlySpan<char> password, ReadOnlySpan<byte> salt)
        => SecureMemory.Pbkdf2(password, salt, Iterations, 32);

    /// <summary>Encrypt UTF-8 plaintext with an already-derived session key (same "ECV1" layout). A fresh random nonce per
    /// call keeps AES-GCM safe while the key + salt stay fixed for the session. The caller still owns (and zeroes) the
    /// plaintext.</summary>
    public static string Encrypt(ReadOnlySpan<byte> plainUtf8, byte[] key, byte[] salt)
    {
        // A wiped session key (the process-exit wipe ran while a debounced save was still due) is all zeros: sealing
        // with it would replace the vault with one the password no longer opens — and anyone can. Refuse; the vault on
        // disk stays as it was.
        if (SecureMemory.IsWiped(key)) throw new InvalidOperationException("The vault is locked.");
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] blob = new byte[Magic.Length + 16 + 12 + 16 + plainUtf8.Length];
        Magic.CopyTo(blob, 0);
        salt.AsSpan(0, 16).CopyTo(blob.AsSpan(Magic.Length));
        nonce.CopyTo(blob, Magic.Length + 16);
        // Encrypt straight into the blob: no separate ciphertext array to copy around.
        using (var gcm = new AesGcm(key, 16))
            gcm.Encrypt(nonce, plainUtf8, blob.AsSpan(Magic.Length + 44), blob.AsSpan(Magic.Length + 28, 16));
        return Convert.ToBase64String(blob);
    }

    /// <summary>Like <see cref="Encrypt(ReadOnlySpan{byte}, byte[], byte[])"/> for a string payload: its UTF-8 bytes go
    /// through a pinned buffer that is zeroed right after.</summary>
    public static string Encrypt(string plain, byte[] key, byte[] salt)
    {
        byte[] pt = SecureMemory.Utf8(plain);
        try { return Encrypt(pt, key, salt); }
        finally { SecureMemory.Zero(pt); }
    }

    /// <summary>
    /// Decrypt a vault. On the current ("ECV1", 600k) path it also hands back the derived key + the vault's salt so the
    /// caller can cache them for the session and re-encrypt without another PBKDF2. For a legacy (200k, headerless) vault
    /// both are null: that key must NOT be reused under the ECV1 header (the next decrypt would derive with 600k and fail),
    /// so the caller derives a fresh one. The caller owns <paramref name="plainUtf8"/> and <paramref name="key"/> (pinned)
    /// and zeroes them when done.
    /// </summary>
    public static bool TryDecrypt(string blobB64, ReadOnlySpan<char> password,
                                  out byte[]? plainUtf8, out byte[]? key, out byte[]? salt)
    {
        plainUtf8 = null;
        key = null;
        salt = null;
        try
        {
            byte[] blob = Convert.FromBase64String(blobB64);

            // New format: strip the magic header and derive with the current (600k) work factor.
            if (blob.Length >= Magic.Length + 44 && blob.AsSpan(0, Magic.Length).SequenceEqual(Magic))
            {
                if (TryDecryptBody(blob, Magic.Length, password, Iterations, out plainUtf8, out key))
                {
                    salt = blob[Magic.Length..(Magic.Length + 16)];
                    return true;
                }
                // A wrong password against an ECV1 vault: skip the 200k legacy attempt (it only
                // doubled the UI stall). A headerless legacy blob starts with a random salt, so it
                // collides with the 4-byte magic only 1 time in 2^32.
                return false;
            }

            // Legacy format: no header, 200k iterations.
            if (blob.Length >= 44 && TryDecryptBody(blob, 0, password, LegacyIterations, out plainUtf8, out byte[]? legacyKey))
            {
                SecureMemory.Zero(legacyKey);
                return true;
            }

            return false;
        }
        catch
        {
            SecureMemory.Zero(plainUtf8);
            SecureMemory.Zero(key);
            plainUtf8 = key = salt = null;
            return false;
        }
    }

    // Decrypt a [salt(16)][nonce(12)][tag(16)][ct] body starting at <paramref name="offset"/>.
    // On success the plaintext and the derived key are handed to the caller (who zeroes them); on failure both are
    // zeroed here.
    private static bool TryDecryptBody(byte[] blob, int offset, ReadOnlySpan<char> password, int iterations,
                                       out byte[]? plainUtf8, out byte[]? key)
    {
        plainUtf8 = null;
        key = null;
        if (blob.Length - offset < 44) return false;

        ReadOnlySpan<byte> body = blob.AsSpan(offset);
        byte[] derived = SecureMemory.Pbkdf2(password, body[..16], iterations, 32);
        byte[] pt = SecureMemory.Alloc(body.Length - 44);
        try
        {
            using var gcm = new AesGcm(derived, 16);
            gcm.Decrypt(body.Slice(16, 12), body[44..], body.Slice(28, 16), pt);   // throws on wrong password / tampering
        }
        catch
        {
            SecureMemory.Zero(derived);
            SecureMemory.Zero(pt);
            return false;
        }

        plainUtf8 = pt;
        key = derived;
        return true;
    }
}
