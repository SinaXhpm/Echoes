using System;
using System.Runtime.InteropServices;
using UIKit;

namespace Echoes.iOS;

public static class Program
{
    // The process entry point of an iOS app: hand control to UIKit with our app delegate.
    private static void Main(string[] args)
    {
        RaiseFileDescriptorLimit();
        Echoes.Helpers.AppStorage.ExcludeFromBackup = IosBackupExclusion.Exclude;   // before anything makes the key file
        UIApplication.Main(args, null, typeof(AppDelegate));
    }

    // iOS starts an app with a soft limit of 256 open descriptors, like macOS (where the desktop Program.Main raises it the
    // same way). The scanner's discovery runs ~100 host checks of up to 6 sockets each and the monitor's checks hold sockets
    // too: at 256 a default sweep ran out ("socket limit") and web monitors read as down. Soft = the hard limit, capped at
    // OPEN_MAX (setrlimit refuses more). Best effort: it must never keep the app from starting.
    private static void RaiseFileDescriptorLimit()
    {
        try
        {
            const int RLIMIT_NOFILE = 8;   // Darwin
            if (GetRLimit(RLIMIT_NOFILE, out RLimit lim) != 0) return;
            ulong want = Math.Min(lim.Max, 10240UL /* OPEN_MAX */);
            if (lim.Cur >= want) return;
            lim.Cur = want;
            _ = SetRLimit(RLIMIT_NOFILE, ref lim);
        }
        catch { }
    }

    // struct rlimit { rlim_t rlim_cur, rlim_max; } with a 64-bit rlim_t
    [StructLayout(LayoutKind.Sequential)]
    private struct RLimit { public ulong Cur, Max; }

    [DllImport(ObjCRuntime.Constants.libSystemLibrary, EntryPoint = "getrlimit")]
    private static extern int GetRLimit(int resource, out RLimit rlim);

    [DllImport(ObjCRuntime.Constants.libSystemLibrary, EntryPoint = "setrlimit")]
    private static extern int SetRLimit(int resource, ref RLimit rlim);
}
