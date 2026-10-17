using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Echoes.Helpers;

/// <summary>
/// Lightweight, cross-platform at-rest protection for stored secrets (proxy passwords, credentialed URLs).
///
/// Current format "enc2:": AES-GCM under a random 32-byte key generated once per install and kept in the data dir
/// (<c>.secret.key</c>: owner-only 0600 on Linux/macOS; %APPDATA% is per-user on Windows, app storage on Android).
/// The key is NOT in the profile, so:
///   • Secrets are no longer readable as plaintext in the profile file (or in a backup of it).
///   • A profile copied to another machine/user (or restored onto a fresh install) simply won't decrypt — its fields
///     drop to empty and the user re-enters them. That is the intended protection, not a bug.
///
/// Legacy "enc1:" values were sealed with PBKDF2(machine|user|platform, constant salt): any local user could derive that
/// key, and on macOS the machine name follows the network (DHCP / reverse DNS), which silently emptied saved
/// passwords. They still decrypt with that derived key (migration only) and should be re-saved — <see cref="IsLegacy"/>;
/// ProfileService also upgrades them in the background at startup. Untagged values are legacy plaintext.
///
/// This is defense-in-depth against casual leaks (cat-ing the file, accidental sharing, roaming
/// sync), NOT protection against malware running as the same user. For that, use a scoped token.
/// </summary>
public static class SecretProtector
{
    private const string Prefix = "enc2:";         // tag so Unprotect can tell encrypted vs legacy plaintext
    private const string LegacyPrefix = "enc1:";   // machine+user-derived key: read for migration, written only as a fallback
    private const string KeyFileName = ".secret.key";
    private const int KeyLength = 32;

    // Loaded (or created) once, thread-safe, on first use — ProfileService warms it on a background thread at startup,
    // so the VM constructors that call Unprotect on the UI thread don't do the file I/O. Never throws: null means no
    // usable key file, and then Protect falls back to the legacy key (today's behaviour) and "enc2:" values read empty.
    private static readonly Lazy<byte[]?> Key = new(LoadOrCreateKey, LazyThreadSafetyMode.ExecutionAndPublication);
    private static readonly Lazy<byte[]> LegacyKey = new(DeriveLegacyKey, LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>Load / create the key now (call off the UI thread). <paramref name="legacyToo"/> also derives the legacy
    /// key (100k PBKDF2), needed only to read "enc1:" values.</summary>
    public static void WarmUp(bool legacyToo = false)
    {
        _ = Key.Value;
        if (legacyToo) _ = LegacyKey.Value;
    }

    /// <summary>
    /// False when this run has no usable key file (it couldn't be read or created — the miss is cached for the run). An
    /// "enc2:" value then reads as empty although it is intact on disk, and a later run may well open it: a caller must
    /// not write such a value back as empty, or over it. (True with the key loaded: a value that still doesn't open is
    /// from another machine / user, or damaged — the documented "re-enter it" case.) Loads the key on first use: call it
    /// off the UI thread where that may be the first use.
    /// </summary>
    public static bool IsKeyAvailable => Key.Value is not null;

    /// <summary>True for a value sealed with the legacy machine-derived key ("enc1:"). It still decrypts, but callers
    /// should re-save it (<see cref="Protect"/> writes "enc2:") right after reading it.</summary>
    public static bool IsLegacy(string? stored) => stored is not null && stored.StartsWith(LegacyPrefix, StringComparison.Ordinal);

    /// <summary>True for any sealed value ("enc2:" or legacy "enc1:"), as opposed to plaintext.</summary>
    public static bool IsProtected(string? stored)
        => stored is not null && (stored.StartsWith(Prefix, StringComparison.Ordinal) || stored.StartsWith(LegacyPrefix, StringComparison.Ordinal));

    /// <summary>Encrypt a secret for storage. Empty/null → empty string.</summary>
    public static string Protect(string? plain)
    {
        if (string.IsNullOrEmpty(plain)) return string.Empty;
        return Key.Value is { } key ? Seal(plain, key, Prefix) : Seal(plain, LegacyKey.Value, LegacyPrefix);
    }

    /// <summary>
    /// Decrypt a stored value. Values without a tag are returned as-is (legacy plaintext, auto-migrated on next save).
    /// A value that fails to decrypt (wrong machine / tampered / no key file) yields empty so the user re-enters it
    /// instead of crashing.
    /// </summary>
    public static string Unprotect(string? stored)
    {
        if (string.IsNullOrEmpty(stored)) return string.Empty;
        try
        {
            if (stored.StartsWith(Prefix, StringComparison.Ordinal))
                return Key.Value is { } key ? Open(stored, Prefix.Length, key) : string.Empty;
            if (stored.StartsWith(LegacyPrefix, StringComparison.Ordinal))
                return Open(stored, LegacyPrefix.Length, LegacyKey.Value);
        }
        catch
        {
            return string.Empty;
        }
        return stored;
    }

    // Blob layout (both tags): base64([nonce 12][tag 16][ciphertext]). The plaintext bytes sit in a pinned buffer that is
    // zeroed right after (SecureMemory); the ciphertext is written straight into the blob.
    private static string Seal(string plain, byte[] key, string prefix)
    {
        byte[] pt = SecureMemory.Utf8(plain);
        try
        {
            byte[] blob = new byte[12 + 16 + pt.Length];
            RandomNumberGenerator.Fill(blob.AsSpan(0, 12));
            using (var gcm = new AesGcm(key, 16))
                gcm.Encrypt(blob.AsSpan(0, 12), pt, blob.AsSpan(28), blob.AsSpan(12, 16));
            return prefix + Convert.ToBase64String(blob);
        }
        finally { SecureMemory.Zero(pt); }
    }

    private static string Open(string stored, int start, byte[] key)
    {
        byte[] blob = Convert.FromBase64String(stored[start..]);
        if (blob.Length < 28) return string.Empty;

        byte[] pt = SecureMemory.Alloc(blob.Length - 28);
        try
        {
            using var gcm = new AesGcm(key, 16);
            gcm.Decrypt(blob.AsSpan(0, 12), blob.AsSpan(28), blob.AsSpan(12, 16), pt);   // throws on wrong key / tampering
            return System.Text.Encoding.UTF8.GetString(pt);
        }
        finally { SecureMemory.Zero(pt); }
    }

    private static byte[]? LoadOrCreateKey()
    {
        try
        {
            string path = Path.Combine(AppStorage.UserDir(), KeyFileName);
            for (int attempt = 0; ; attempt++)
            {
                try
                {
                    if (File.Exists(path))
                    {
                        byte[] read = File.ReadAllBytes(path);
                        try
                        {
                            // Kept for the whole run in a pinned buffer (no stale copies after a GC compaction); the
                            // GC-movable array File.ReadAllBytes returned is zeroed. Not wiped at exit: it's on disk
                            // anyway, and a late background save must never seal a value with a zeroed key.
                            if (read.Length == KeyLength) return SecureMemory.Copy(read);
                        }
                        finally { SecureMemory.Zero(read); }
                        // It is only ever created atomically, so a wrong size is outside damage, not a torn write: set it
                        // aside (never delete a key) and start a new one — values sealed with it can't open anyway.
                        File.Move(path, path + ".bad", overwrite: true);
                    }
                    byte[] fresh = SecureMemory.Alloc(KeyLength);
                    RandomNumberGenerator.Fill(fresh);
                    try { AppStorage.CreateNewFileAtomic(path, fresh); }   // IOException if another process created it first
                    catch { SecureMemory.Zero(fresh); throw; }
                    return fresh;
                }
                catch (Exception e) when (attempt < 5 && e is IOException or UnauthorizedAccessException)
                {
                    // Lost a creation race, or the file is held for a moment (an AV scan, a backup / sync tool): read it
                    // again. A miss is cached for the whole run — "enc2:" values then read as empty, and the next save of
                    // such a setting (a proxy password, the cURL library) replaces the stored one — so keep trying for
                    // ~1.5 s (50…800 ms). This runs on WarmUp's background thread at startup.
                    Thread.Sleep(50 << attempt);
                }
            }
        }
        catch
        {
            return null;
        }
    }

    // The pre-"enc2" key, kept only to read "enc1:" values (and as the fallback when there's no key file). Byte-for-byte
    // the old derivation — same identity string, salt and work factor — or existing values stop decrypting.
    private static byte[] DeriveLegacyKey()
    {
        try
        {
            string identity = $"{Environment.MachineName}|{Environment.UserName}|{Environment.OSVersion.Platform}"
                .ToLowerInvariant();
            byte[] salt = Encoding.UTF8.GetBytes("Echoes.SecretProtector.v1");
            return SecureMemory.Pbkdf2(identity, salt, 100_000, 32);
        }
        catch
        {
            // No machine / user identity at all (odd sandbox): "enc1:" values then read as empty, like any decrypt
            // failure, and the fallback Protect still works for this run.
            byte[] key = SecureMemory.Alloc(32);
            RandomNumberGenerator.Fill(key);
            return key;
        }
    }
}
