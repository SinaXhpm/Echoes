using Renci.SshNet;
using Renci.SshNet.Common;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Echoes.Helpers;

/// <summary>What a private key file turned out to be (the key itself, or why it can't be used).</summary>
public sealed class SshKeyLoad
{
    public PrivateKeyFile? Key { get; init; }
    /// <summary>One short sentence, ready to show ("Wrong passphrase for the key."). Null when the key loaded.</summary>
    public string? Error { get; init; }
    /// <summary>"ed25519", "rsa", "ecdsa-sha2-nistp256"… — for the connected summary.</summary>
    public string Kind { get; init; } = string.Empty;
}

/// <summary>
/// Loads an SSH private key for SSH.NET (OpenSSH, OpenSSL PEM / PKCS#8 and PuTTY .ppk v2/v3: RSA, ECDSA, Ed25519) and
/// turns its failures into the three answers a person can act on: the key needs its passphrase, the passphrase is wrong,
/// or the format isn't supported (including "that's the .pub file"). SSH.NET reports a wrong passphrase in a different
/// way per format (a check-bytes mismatch, a PuTTY MAC failure, bad padding, a BouncyCastle cipher error), so the file
/// is looked at first: whether it is encrypted decides what a parse failure means.
/// </summary>
public static class SshKeys
{
    /// <summary>A 16384-bit RSA key in PEM is ~13 KB; anything far larger isn't a private key.</summary>
    public const int MaxKeyBytes = 64 * 1024;

    public const string NeedsPassphrase = "The key is encrypted: enter its passphrase.";
    public const string WrongPassphrase = "Wrong passphrase for the key.";
    public const string NotSupported = "Key format not supported.";

    internal enum KeyFormat { Unknown, OpenSsh, Pem, Pkcs8, Putty, SshCom, PublicKey }

    internal readonly record struct KeyInfo(KeyFormat Format, bool Encrypted);

    /// <summary>Reads and parses the key at <paramref name="path"/> (or through <paramref name="opener"/>, e.g. an
    /// Android content URI picked earlier). Call off the UI thread. Never throws.</summary>
    public static SshKeyLoad Load(string path, string? passphrase, Func<Stream>? opener = null)
    {
        // A key picked on Android is a content URI that only opens through the picker's grant of this run.
        if (opener is null && path.StartsWith("content:", StringComparison.OrdinalIgnoreCase))
            return Fail("Pick the key file again: this device only lets Echoes read it right after it is picked.");
        byte[] data;
        try
        {
            using var s = opener?.Invoke() ?? new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            data = ReadCapped(s, MaxKeyBytes);
        }
        catch (FileNotFoundException) { return Fail("Key file not found: " + Path.GetFileName(path)); }
        catch (DirectoryNotFoundException) { return Fail("Key file not found: " + Path.GetFileName(path)); }
        catch (UnauthorizedAccessException) { return Fail("Can't read the key file: access denied."); }
        catch (InvalidDataException) { return Fail("This file is too large to be a private key."); }
        catch (Exception ex) { return Fail("Can't read the key file: " + ex.Message); }
        try { return Parse(data, passphrase); }
        finally { CryptographicOperations.ZeroMemory(data); }   // private key material: don't leave it for the GC
    }

    /// <summary>Parses key file bytes. Never throws.</summary>
    public static SshKeyLoad Parse(byte[] data, string? passphrase)
    {
        string text;
        try { text = Encoding.UTF8.GetString(data); }
        catch (Exception) { return Fail(NotSupported); }
        var info = Inspect(text);
        if (info.Format == KeyFormat.PublicKey)
            return Fail("This is a public key: pick the private key file (the one without .pub).");
        if (info.Format == KeyFormat.Unknown)
            return Fail(NotSupported + " Pick an OpenSSH, PEM or PuTTY (.ppk) private key.");
        if (info.Encrypted && string.IsNullOrEmpty(passphrase))
            return Fail(NeedsPassphrase);

        try
        {
            var key = new PrivateKeyFile(new MemoryStream(data, writable: false), string.IsNullOrEmpty(passphrase) ? null : passphrase);
            string kind = string.Empty;
            try
            {
                foreach (var a in key.HostKeyAlgorithms) { kind = ShortKind(a.Name); break; }
            }
            catch (Exception) { /* cosmetic only */ }
            return new SshKeyLoad { Key = key, Kind = kind };
        }
        catch (SshPassPhraseNullOrEmptyException) { return Fail(NeedsPassphrase); }
        catch (NotSupportedException ex) { return Fail(NotSupported + Detail(ex.Message)); }
        catch (Exception ex)
        {
            // An encrypted key that fails to open means the passphrase — unless the cipher itself is what's missing.
            if (info.Encrypted && !ex.Message.Contains("not supported", StringComparison.OrdinalIgnoreCase)) return Fail(WrongPassphrase);
            return Fail(NotSupported + Detail(ex.Message));
        }
    }

    private static string Detail(string message)
    {
        // "Key 'DSA PRIVATE KEY' is not supported." → " (DSA keys aren't supported)"
        if (message.Contains("DSA", StringComparison.Ordinal) && !message.Contains("ECDSA", StringComparison.Ordinal))
            return " DSA keys aren't supported: use an Ed25519, ECDSA or RSA key.";
        message = message.Trim();
        if (message.Length == 0 || message.Equals("Invalid private key file.", StringComparison.Ordinal))
            return " The file isn't a private key this app can read.";
        return " (" + TextLimit(message, 120) + ")";
    }

    private static string TextLimit(string s, int max) => s.Length <= max ? s : s[..max] + "…";

    private static string ShortKind(string algorithm) => algorithm switch
    {
        "ssh-ed25519" => "ed25519",
        "ssh-rsa" or "rsa-sha2-256" or "rsa-sha2-512" => "rsa",
        _ when algorithm.StartsWith("ecdsa-sha2-", StringComparison.Ordinal) => "ecdsa",
        _ => algorithm,
    };

    private static SshKeyLoad Fail(string error) => new() { Error = error };

    private static byte[] ReadCapped(Stream s, int max)
    {
        using var ms = new MemoryStream();
        var buf = new byte[8192];
        int n;
        while ((n = s.Read(buf, 0, buf.Length)) > 0)
        {
            if (ms.Length + n > max) { CryptographicOperations.ZeroMemory(ms.GetBuffer()); throw new InvalidDataException(); }
            ms.Write(buf, 0, n);
        }
        var data = ms.ToArray();
        CryptographicOperations.ZeroMemory(ms.GetBuffer());
        CryptographicOperations.ZeroMemory(buf);
        return data;
    }

    /// <summary>Which kind of key file this is, and whether it is passphrase-protected.</summary>
    internal static KeyInfo Inspect(string text)
    {
        string t = text.TrimStart('﻿', ' ', '\t', '\r', '\n');
        if (t.StartsWith("PuTTY-User-Key-File-", StringComparison.Ordinal))
        {
            int at = t.IndexOf("\nEncryption:", StringComparison.Ordinal);
            bool enc = at >= 0 && !LineValue(t, at + 12).Equals("none", StringComparison.OrdinalIgnoreCase);
            return new(KeyFormat.Putty, enc);
        }
        if (t.Contains("-----BEGIN OPENSSH PRIVATE KEY-----", StringComparison.Ordinal))
            return new(KeyFormat.OpenSsh, OpenSshEncrypted(t));
        if (t.Contains("-----BEGIN ENCRYPTED PRIVATE KEY-----", StringComparison.Ordinal))
            return new(KeyFormat.Pkcs8, true);
        if (t.Contains("-----BEGIN PRIVATE KEY-----", StringComparison.Ordinal))
            return new(KeyFormat.Pkcs8, false);
        if (t.Contains(" PRIVATE KEY-----", StringComparison.Ordinal) && t.Contains("-----BEGIN ", StringComparison.Ordinal))
            return new(KeyFormat.Pem, t.Contains("Proc-Type: 4,ENCRYPTED", StringComparison.Ordinal));
        if (t.Contains("---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----", StringComparison.Ordinal))
            return new(KeyFormat.SshCom, false);   // the header says ENCRYPTED even for "none": let the parser decide
        if (t.Contains("---- BEGIN SSH2 PUBLIC KEY ----", StringComparison.Ordinal) || LooksLikePublicKeyLine(t))
            return new(KeyFormat.PublicKey, false);
        return new(KeyFormat.Unknown, false);
    }

    private static string LineValue(string t, int from)
    {
        int end = t.IndexOf('\n', from);
        return (end < 0 ? t[from..] : t[from..end]).Trim();
    }

    // "ssh-ed25519 AAAAC3Nza… comment" (authorized_keys / .pub)
    private static bool LooksLikePublicKeyLine(string t)
    {
        int sp = t.IndexOf(' ');
        if (sp <= 0 || sp > 64) return false;
        string algo = t[..sp];
        bool known = algo.StartsWith("ssh-", StringComparison.Ordinal) || algo.StartsWith("ecdsa-", StringComparison.Ordinal)
                     || algo.StartsWith("sk-", StringComparison.Ordinal);
        return known && t.AsSpan(sp + 1).StartsWith("AAAA", StringComparison.Ordinal);
    }

    // openssh-key-v1: "openssh-key-v1\0" + string ciphername + … ; "none" = not encrypted.
    private static bool OpenSshEncrypted(string t)
    {
        const string begin = "-----BEGIN OPENSSH PRIVATE KEY-----", end = "-----END OPENSSH PRIVATE KEY-----";
        int a = t.IndexOf(begin, StringComparison.Ordinal) + begin.Length;
        int b = t.IndexOf(end, a, StringComparison.Ordinal);
        if (b < 0) return false;
        // Only the first few hundred base64 chars are needed for the magic + cipher name.
        var sb = new StringBuilder(128);
        for (int i = a; i < b && sb.Length < 96; i++)
        {
            char c = t[i];
            if (c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '+' or '/') sb.Append(c);
        }
        try
        {
            var bytes = Convert.FromBase64String(sb.ToString(0, sb.Length - sb.Length % 4));
            const string magic = "openssh-key-v1\0";
            if (bytes.Length < magic.Length + 4 || Encoding.ASCII.GetString(bytes, 0, magic.Length) != magic) return false;
            int len = (bytes[magic.Length] << 24) | (bytes[magic.Length + 1] << 16) | (bytes[magic.Length + 2] << 8) | bytes[magic.Length + 3];
            if (len <= 0 || len > 64 || magic.Length + 4 + len > bytes.Length) return false;
            return Encoding.ASCII.GetString(bytes, magic.Length + 4, len) != "none";
        }
        catch (FormatException) { return false; }
    }
}
