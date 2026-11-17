using Avalonia;
using System;
using System.IO;
using System.Runtime.InteropServices;
namespace Echoes;

class Program
{
    // Held for the whole process lifetime (a static root, so the GC can't finalize it and release the lock).
    private static FileStream? _instanceLock;

    [STAThread]
    public static void Main(string[] args)
    {
        RaiseFileDescriptorLimit();

#if STORE
        // The Mac App Store build under the App Sandbox: the checks of .github/workflows/macos-appstore.yml (see
        // Desktop/StoreSelfTest.cs). Nothing happens unless ECHOES_STORE_SELFTEST=1.
        bool storeSelfTest = Desktop.StoreSelfTest.Requested;
        if (storeSelfTest) Desktop.StoreSelfTest.RunHeadless();
#endif

        // Started by the "Open Echoes when I sign in" entry (Monitor settings, Helpers/AutoStart): hidden in the tray,
        // monitoring on.
        bool background = Helpers.AutoStart.IsBackgroundLaunch(args);

        // One instance per user. Every instance loads the profile (incl. the Cloudflare vault) and notes once and
        // later writes its WHOLE in-memory copy back, so a second instance would silently roll back the first
        // one's saved tokens / notes / settings (last writer wins). A second launch therefore just exits — the
        // simplest behaviour that can never lose data; a read-only second window wouldn't be much use anyway.
        // An exclusive lock file in the user's own data dir, not a named Mutex: under NativeAOT on Linux/macOS a named
        // mutex is process-local (both instances "created" it), and on Windows a Global\ name can be squatted by any
        // other local user to keep Echoes from starting. FileShare.None is flock() on Unix and a share-mode lock on
        // Windows; the OS drops either when the process dies. If the lock can't be taken for any other reason
        // (read-only home, odd sandbox), start anyway rather than refuse to run.
        // Before exiting, a second launch asks the running instance to show its window (Desktop/SingleInstance): with
        // close-to-tray that instance may have nothing on screen, and a launch that silently did nothing would look
        // broken. An older build has no listener — then it's the plain "already running" exit, at once.
        try
        {
            _instanceLock = new FileStream(Path.Combine(Helpers.AppStorage.UserDir(), ".instance.lock"),
                Helpers.AppStorage.PrivateFileOptions(FileMode.OpenOrCreate, FileAccess.ReadWrite));
        }
        catch (IOException ex) when (IsHeldByAnotherInstance(ex))
        {
            // A login launch while Echoes already runs has nothing to do: it leaves quietly, without bringing the
            // running instance's window up.
            if (background) return;
            Console.Error.WriteLine(Desktop.SingleInstance.TrySignalExisting()
                ? "Echoes is already running; showing its window."
                : "Echoes is already running.");
            return;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _instanceLock = null;
        }

        // Only the lock holder answers those requests. It listens before Avalonia starts, so a quick double launch
        // already finds the pipe (a request that arrives before the window exists is dropped: startup shows it anyway).
        if (_instanceLock is not null) Desktop.SingleInstance.StartListening();

        // The profile (read, parsed, its history cleaned) loads while Avalonia and Skia start, instead of on the UI thread
        // at the theme's first look at it. No UI types in it; the type initializer makes the two callers wait for one load.
        if (_instanceLock is not null) _ = System.Threading.Tasks.Task.Run(() => Helpers.ProfileService.Instance);

        // "Open Echoes when I sign in" edits the real login entry only from here, the desktop head: tests, the designer
        // and the Android head never arm it. An entry left pointing at a moved / deleted copy is pointed at this one
        // (off the UI thread: a registry value or a small file).
        try { Helpers.AutoStart.Configure(Helpers.AutoStart.ForThisProcess()); }
        catch (Exception ex) { Helpers.CrashLog.Write("AutoStart.Configure", ex); }   // an extra: never blocks startup
        if (_instanceLock is not null) _ = System.Threading.Tasks.Task.Run(Helpers.AutoStart.RepairIfMoved);
        App.StartedInBackground = background;

        // Tray icon, close-to-tray, bringing the window back: desktop-only code that App (shared with the Android head)
        // can't reference, so it reaches App through this hook and runs once the main window exists. A login launch
        // starts with the window hidden in the tray.
        App.DesktopStarted = (desktop, window, vm) =>
        {
            Desktop.TrayService.Attach(desktop, window, startHidden: background);
#if STORE
            if (storeSelfTest) Desktop.StoreSelfTest.Finish();
            // the Mac App Store screenshots of the same workflow (Desktop/StoreShots.cs), only with ECHOES_STORE_SHOTS=1
            else if (Desktop.StoreShots.Requested) Desktop.StoreShots.Start(window, vm);
#endif
        };

        try
        {
            BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }
        catch (Exception ex)
        {
            // Last-resort: record a startup/teardown crash before the process exits.
            Helpers.CrashLog.Write("Startup", ex);
            throw;
        }
        finally
        {
            Desktop.SingleInstance.StopListening();
        }
    }

    public static AppBuilder BuildAvaloniaApp()
    {
        return AppBuilder.Configure<App>()
            .UsePlatformDetect()
            // Inter on every OS (the Android head already registers it): Fluent prefers it when present, so the
            // UI renders with the same metrics everywhere instead of Segoe / SF / whatever the distro ships.
            .WithInterFont()
            // Windows: Avalonia's software renderer (Skia on the CPU) unless ECHOES_RENDER=gpu. Echoes' solid, mostly still UI
            // rarely redraws much, while the GPU path's costs came up front and stayed: measured with the Native AOT build on
            // one laptop (2026-11-17), the process's first Direct3D device alone took 0.46-0.75 s on the UI thread before
            // anything was drawn; drawing on the CPU, the app was ready ~0.15 s sooner on a third of the start-up CPU, and
            // held 73 MB less memory and 27 fewer threads for the whole session (in the tray for days). The price: a
            // whole-window redraw costs ~3x the CPU (~18 ms against ~6 ms at full screen), so a window being resized redraws
            // at 40-50 fps.
            // With the GPU: DirectComposition rather than Avalonia's first choice, WinUI composition, whose extras (blur,
            // Mica) Echoes' solid colors never use: the window's first frame showed about 120 ms sooner (Native AOT
            // build, 6 starts each), with the same memory.
            .With(GpuRendering
                ? new Win32PlatformOptions
                {
                    CompositionMode = new[] { Win32CompositionMode.DirectComposition, Win32CompositionMode.RedirectionSurface }
                }
                : new Win32PlatformOptions { RenderingMode = new[] { Win32RenderingMode.Software } })
            .LogToTrace();
    }

    // ECHOES_RENDER=gpu (Windows): Direct3D through ANGLE, as Echoes drew up to 1.1.0, for a machine where drawing on the
    // CPU proves too slow (a very large window on a 4K screen, redrawn often). See BuildAvaloniaApp.
    private static bool GpuRendering
        => string.Equals(Environment.GetEnvironmentVariable("ECHOES_RENDER"), "gpu", StringComparison.OrdinalIgnoreCase);

    // A lock conflict is a plain IOException: a sharing / lock violation on Windows, flock's EWOULDBLOCK on Unix. The
    // errors that clearly aren't one (missing path, I/O error, disk full, read-only file system) start the app instead.
    private static bool IsHeldByAnotherInstance(IOException ex)
    {
        if (ex is FileNotFoundException or DirectoryNotFoundException or PathTooLongException) return false;
        int code = ex.HResult;
        if (OperatingSystem.IsWindows()) return (code & 0xFFFF) is 32 or 33;   // ERROR_SHARING_VIOLATION / ERROR_LOCK_VIOLATION
        return code is not (5 or 28 or 30);                                     // EIO, ENOSPC, EROFS (same on Linux and macOS)
    }

    // NativeAOT, unlike CoreCLR, doesn't raise the soft RLIMIT_NOFILE at startup, so a macOS GUI app stays at 256
    // descriptors (Linux often 1024) and the port scanner ran out of sockets. Do what CoreCLR does: soft = hard limit,
    // capped at OPEN_MAX on macOS (setrlimit rejects more). Best effort — it must never block startup.
    private static void RaiseFileDescriptorLimit()
    {
        if (!OperatingSystem.IsMacOS() && !OperatingSystem.IsLinux()) return;
        try
        {
            int resource = OperatingSystem.IsMacOS() ? 8 : 7;   // RLIMIT_NOFILE
            if (GetRLimit(resource, out RLimit lim) != 0) return;
            ulong want = OperatingSystem.IsMacOS() ? Math.Min(lim.Max, 10240UL /* OPEN_MAX */) : lim.Max;
            if (lim.Cur >= want) return;
            lim.Cur = want;
            _ = SetRLimit(resource, ref lim);
        }
        catch { }
    }

    // struct rlimit { rlim_t rlim_cur, rlim_max; } — rlim_t is 64-bit on every shipped desktop target (x64 / arm64).
    [StructLayout(LayoutKind.Sequential)]
    private struct RLimit { public ulong Cur, Max; }

    [DllImport("libc", EntryPoint = "getrlimit")]
    private static extern int GetRLimit(int resource, out RLimit rlim);

    [DllImport("libc", EntryPoint = "setrlimit")]
    private static extern int SetRLimit(int resource, ref RLimit rlim);
}
