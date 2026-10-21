using System;
using System.Runtime.InteropServices;

namespace Echoes.Helpers;

/// <summary>
/// The Mac App Store build runs in the App Sandbox (docs/apple/README.md, "Mac App Store"). Two things differ there: $HOME is
/// the app's own container, and what the user didn't pick or the entitlements don't name can't be read. The native calls are
/// compiled only into that build (the STORE constant); everywhere else this class has nothing to do.
/// </summary>
internal static class MacSandbox
{
#if STORE
    [DllImport("libc", EntryPoint = "getuid")]
    private static extern uint GetUid();

    [DllImport("libc", EntryPoint = "getpwuid")]
    private static extern IntPtr GetPwUid(uint uid);
#endif

    /// <summary>
    /// The real home folder (/Users/name) from the user database. In the sandbox $HOME, and so
    /// <see cref="Environment.SpecialFolder.UserProfile"/>, is ~/Library/Containers/…/Data, where "Downloads" is not the
    /// user's Downloads folder. Null when it can't be told, or when it is itself a container folder.
    /// </summary>
    public static string? RealHome()
    {
#if STORE
        if (!OperatingSystem.IsMacOS()) return null;
        try
        {
            IntPtr pw = GetPwUid(GetUid());
            if (pw == IntPtr.Zero) return null;
            // struct passwd (64-bit macOS): pw_name 0, pw_passwd 8, pw_uid 16, pw_gid 20, pw_change 24, pw_class 32,
            // pw_gecos 40, pw_dir 48
            IntPtr dir = Marshal.ReadIntPtr(pw, 48);
            string? home = dir == IntPtr.Zero ? null : Marshal.PtrToStringUTF8(dir);
            if (string.IsNullOrEmpty(home) || !home.StartsWith('/') || home.Contains("/Library/Containers/", StringComparison.Ordinal)) return null;
            return home;
        }
        catch { return null; }
#else
        return null;
#endif
    }
}
