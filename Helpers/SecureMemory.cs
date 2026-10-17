using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Echoes.Helpers;

/// <summary>
/// Memory hygiene for secrets (master password, derived vault keys, decrypted payloads).
///
/// <para>Secret bytes and chars live in PINNED arrays (the pinned object heap): the GC never moves them, so a compaction
/// can't leave stale copies of a key behind in freed heap memory. Each buffer is zeroed as soon as it's no longer needed;
/// the long-lived ones (the shared master password, the Notes / Cloudflare session keys, the at-rest key) are also
/// <see cref="Track">tracked</see>, so a normal process exit wipes whatever is still alive.</para>
///
/// <para>Limits, by design of .NET: strings are immutable and may be copied or interned by the runtime, so they can't be
/// wiped. Secrets that must exist as strings (text typed into a TextBox, API tokens sent in HTTP headers, JSON string
/// fields) are instead kept as short-lived as possible — bound fields are cleared after use, and decryption parses the
/// plaintext bytes directly instead of building a string of the whole payload.</para>
/// </summary>
public static class SecureMemory
{
    private static readonly object Gate = new();
    private static readonly HashSet<object> Tracked = new(ReferenceEqualityComparer.Instance);

    static SecureMemory()
    {
        // Normal exit (desktop window closed / Quit, Main returning). Android usually kills the process instead —
        // nothing runs then, and the OS reclaims the pages.
        AppDomain.CurrentDomain.ProcessExit += (_, _) => WipeAll();
    }

    /// <summary>A pinned, zero-initialised byte buffer for key material or plaintext.</summary>
    public static byte[] Alloc(int length)
        => length <= 0 ? Array.Empty<byte>() : GC.AllocateArray<byte>(length, pinned: true);

    /// <summary>A pinned, zero-initialised char buffer (passwords).</summary>
    public static char[] AllocChars(int length)
        => length <= 0 ? Array.Empty<char>() : GC.AllocateArray<char>(length, pinned: true);

    /// <summary>Pinned copy of <paramref name="source"/>; the caller zeroes it.</summary>
    public static byte[] Copy(ReadOnlySpan<byte> source)
    {
        byte[] b = Alloc(source.Length);
        source.CopyTo(b);
        return b;
    }

    /// <summary>Pinned copy of <paramref name="source"/> (e.g. a password typed into a TextBox); the caller zeroes it.</summary>
    public static char[] CopyChars(ReadOnlySpan<char> source)
    {
        char[] c = AllocChars(source.Length);
        source.CopyTo(c);
        return c;
    }

    /// <summary>UTF-8 encode into a pinned buffer the caller zeroes (instead of a GC-movable Encoding.GetBytes array).</summary>
    public static byte[] Utf8(ReadOnlySpan<char> text)
    {
        byte[] b = Alloc(Encoding.UTF8.GetByteCount(text));
        Encoding.UTF8.GetBytes(text, b);
        return b;
    }

    /// <summary>Decode UTF-8 to a string, then zero the source buffer. For payloads that have to become a string anyway.</summary>
    public static string ToStringAndZero(byte[] utf8)
    {
        try { return Encoding.UTF8.GetString(utf8); }
        finally { Zero(utf8); }
    }

    /// <summary>PBKDF2-SHA256 straight into a pinned key buffer (the span overload: no intermediate password byte array).</summary>
    public static byte[] Pbkdf2(ReadOnlySpan<char> password, ReadOnlySpan<byte> salt, int iterations, int length)
    {
        byte[] key = Alloc(length);
        Rfc2898DeriveBytes.Pbkdf2(password, salt, key, iterations, HashAlgorithmName.SHA256);
        return key;
    }

    public static void Zero(byte[]? buffer)
    {
        if (buffer is { Length: > 0 }) CryptographicOperations.ZeroMemory(buffer);
    }

    public static void Zero(char[]? buffer)
    {
        if (buffer is { Length: > 0 }) CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(buffer.AsSpan()));
    }

    /// <summary>
    /// True when <paramref name="key"/> is empty or all zeros, i.e. it has been wiped (<see cref="Release(byte[])"/>,
    /// <see cref="WipeAll"/>). A real derived key is never all zeros. The vault writers check this before sealing:
    /// <see cref="WipeAll"/> zeroes the live session keys IN PLACE at process exit, and on a SIGTERM (Linux / macOS) the
    /// UI thread keeps running meanwhile, so a debounced save landing then would replace the vault with one sealed by
    /// the all-zero key: the password no longer opens it, and anyone can.
    /// </summary>
    public static bool IsWiped(ReadOnlySpan<byte> key) => key.IndexOfAnyExcept((byte)0) < 0;

    /// <summary>Remember a long-lived secret so <see cref="WipeAll"/> (process exit) zeroes it if it's still alive.</summary>
    public static void Track(byte[]? secret) { if (secret is { Length: > 0 }) lock (Gate) Tracked.Add(secret); }

    /// <inheritdoc cref="Track(byte[])"/>
    public static void Track(char[]? secret) { if (secret is { Length: > 0 }) lock (Gate) Tracked.Add(secret); }

    /// <summary>Zero a secret and forget it (the owner is done with it: lock, logout, key replaced).</summary>
    public static void Release(byte[]? secret)
    {
        if (secret is null) return;
        Zero(secret);
        lock (Gate) Tracked.Remove(secret);
    }

    /// <inheritdoc cref="Release(byte[])"/>
    public static void Release(char[]? secret)
    {
        if (secret is null) return;
        Zero(secret);
        lock (Gate) Tracked.Remove(secret);
    }

    /// <summary>Zero every tracked secret. Runs at process exit; nothing may use a tracked buffer afterwards.</summary>
    public static void WipeAll()
    {
        lock (Gate)
        {
            foreach (object o in Tracked)
            {
                if (o is byte[] b) Zero(b);
                else if (o is char[] c) Zero(c);
            }
            Tracked.Clear();
        }
    }
}

/// <summary>
/// An <see cref="System.Buffers.IBufferWriter{T}"/> over ONE caller-owned (pinned) buffer that never grows: a
/// <see cref="System.Text.Json.Utf8JsonWriter"/> on top of it serializes secrets with no internal or re-allocated copies,
/// so zeroing the buffer afterwards really removes the plaintext. Throws <see cref="NotSupportedException"/> when full.
/// </summary>
public sealed class PinnedBufferWriter : System.Buffers.IBufferWriter<byte>
{
    private readonly byte[] _buffer;

    public PinnedBufferWriter(byte[] buffer) => _buffer = buffer;

    public int Written { get; private set; }

    public ReadOnlySpan<byte> WrittenSpan => _buffer.AsSpan(0, Written);

    public void Advance(int count)
    {
        if (count < 0 || Written + count > _buffer.Length) throw new ArgumentOutOfRangeException(nameof(count));
        Written += count;
    }

    public Memory<byte> GetMemory(int sizeHint = 0) => _buffer.AsMemory(Written, Room(sizeHint));

    public Span<byte> GetSpan(int sizeHint = 0) => _buffer.AsSpan(Written, Room(sizeHint));

    private int Room(int sizeHint)
    {
        int free = _buffer.Length - Written;
        if (free < Math.Max(sizeHint, 1)) throw new NotSupportedException("The secure buffer is full.");
        return free;
    }
}
