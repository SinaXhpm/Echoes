using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Echoes.Helpers;

/// <summary>
/// Windows protection for a portable copy, whose data folder travels with it (a USB stick, a synced folder): the key that
/// opens the saved secrets is sealed to the Windows account (DPAPI), so a copy of the folder opens nothing on another PC
/// or for another user, and the folder itself is made readable by that account (and SYSTEM) only.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class WindowsSecret
{
    // "EDPAPI1" + a newline, then the DPAPI blob: a raw key is exactly 32 bytes, so the two can't be confused.
    private static readonly byte[] Magic = "EDPAPI1\n"u8.ToArray();
    private static readonly byte[] Entropy = "Echoes.secret.key"u8.ToArray();

    public static bool IsSealed(ReadOnlySpan<byte> data) => data.Length > Magic.Length && data[..Magic.Length].SequenceEqual(Magic);

    /// <summary><paramref name="secret"/> sealed to this Windows user on this PC.</summary>
    public static byte[] Seal(byte[] secret)
    {
        byte[] blob = Run(secret, protect: true) ?? throw new IOException("Windows could not seal the key");
        var sealedData = new byte[Magic.Length + blob.Length];
        Magic.CopyTo(sealedData, 0);
        blob.CopyTo(sealedData, Magic.Length);
        return sealedData;
    }

    /// <summary>The secret inside <paramref name="data"/>, or null when it was sealed for another user or PC.</summary>
    public static byte[]? Unseal(byte[] data) => IsSealed(data) ? Run(data[Magic.Length..], protect: false) : null;

    /// <summary>Only the current user and SYSTEM may open <paramref name="dir"/> and what it holds (inheritance from the
    /// parent cut). Best effort: a FAT / exFAT stick has no permissions at all, and then the sealed key is what protects.</summary>
    public static void OwnerOnly(string dir)
    {
        try
        {
            var me = WindowsIdentity.GetCurrent().User;
            if (me is null) return;
            const InheritanceFlags Both = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.AddAccessRule(new FileSystemAccessRule(me, FileSystemRights.FullControl, Both, PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                                                            FileSystemRights.FullControl, Both, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(dir).SetAccessControl(security);
        }
        catch { }
    }

    private static byte[]? Run(byte[] input, bool protect)
    {
        var inHandle = GCHandle.Alloc(input, GCHandleType.Pinned);
        var entHandle = GCHandle.Alloc(Entropy, GCHandleType.Pinned);
        try
        {
            var inBlob = new DataBlob { Size = input.Length, Data = inHandle.AddrOfPinnedObject() };
            var entBlob = new DataBlob { Size = Entropy.Length, Data = entHandle.AddrOfPinnedObject() };
            bool ok = protect
                ? CryptProtectData(ref inBlob, null, ref entBlob, IntPtr.Zero, IntPtr.Zero, UiForbidden, out var outBlob)
                : CryptUnprotectData(ref inBlob, IntPtr.Zero, ref entBlob, IntPtr.Zero, IntPtr.Zero, UiForbidden, out outBlob);
            if (!ok) return null;
            try
            {
                var result = new byte[outBlob.Size];
                Marshal.Copy(outBlob.Data, result, 0, outBlob.Size);
                return result;
            }
            finally
            {
                if (!protect) ZeroNative(outBlob);   // the plain key: not left in freed memory
                LocalFree(outBlob.Data);
            }
        }
        finally
        {
            inHandle.Free();
            entHandle.Free();
        }
    }

    private static void ZeroNative(DataBlob blob)
    {
        for (int i = 0; i < blob.Size; i++) Marshal.WriteByte(blob.Data, i, 0);
    }

    // Blittable struct + DllImport only (trim / AOT-safe), like the other P/Invokes here.
    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int Size;
        public IntPtr Data;
    }

    private const int UiForbidden = 0x1;   // CRYPTPROTECT_UI_FORBIDDEN: never a prompt

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptProtectData(ref DataBlob dataIn, string? description, ref DataBlob entropy, IntPtr reserved,
                                                IntPtr prompt, int flags, out DataBlob dataOut);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CryptUnprotectData(ref DataBlob dataIn, IntPtr description, ref DataBlob entropy, IntPtr reserved,
                                                  IntPtr prompt, int flags, out DataBlob dataOut);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr handle);
}
