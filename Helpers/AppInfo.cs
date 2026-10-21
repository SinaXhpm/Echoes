using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Echoes.Helpers;

/// <summary>
/// What the About box shows and its "Copy info" copies for a bug report: the OS, the .NET runtime and the UI framework.
/// Each is worked out once, on first use.
/// </summary>
public static class AppInfo
{
    /// <summary>
    /// The OS line, when the platform head knows it better than .NET does: the Android head sets the release and API
    /// level from Build.VERSION in its Application.OnCreate, before the App (and the About box's bindings) exist, since
    /// <see cref="Platform"/> is worked out once. The CPU architecture is still appended here.
    /// </summary>
    public static string? PlatformOverride { get; set; }

    /// <summary>
    /// What this device is called where others see it (the Web Server hub's page and chat): set by the Android head from
    /// the phone's own name ("realme 12 Pro+"), since .NET only reports "localhost" there. Null elsewhere: the machine
    /// name is used.
    /// </summary>
    public static string? DeviceName { get; set; }

    /// <summary>
    /// True in a build that an app store distributes: the iOS head, and a Mac App Store build compiled with the STORE
    /// constant. The store updates the app itself and its rules don't allow an app to look for or point to a copy
    /// downloaded elsewhere, so the update check and the "Releases" link are left out there.
    /// </summary>
    public static bool IsStoreBuild =>
#if STORE
        true;
#else
        OperatingSystem.IsIOS();
#endif

    /// <summary>
    /// True in the Mac App Store build, which the store runs in the App Sandbox: no login item of its own, a data folder
    /// inside the app's container, and file access only where the entitlements or the user's own pick allow it.
    /// </summary>
    public static bool IsMacSandbox =>
#if STORE
        OperatingSystem.IsMacOS();
#else
        false;
#endif

    private static string? _platform, _runtime, _ui;

    public static string Platform => _platform ??= $"{PlatformOverride ?? DescribeOs()} · {DescribeArch()}";

    public static string Runtime => _runtime ??= RuntimeInformation.FrameworkDescription
        + (RuntimeFeature.IsDynamicCodeSupported ? string.Empty : " · Native AOT");

    public static string Ui => _ui ??= "Avalonia " + VersionOf(typeof(Avalonia.AvaloniaObject).Assembly);

    /// <summary>The block "Copy info" puts on the clipboard.</summary>
    public static string Summary(string appVersion)
        => $"Echoes v{appVersion}\nPlatform: {Platform}\nRuntime: {Runtime}\nUI: {Ui}";

    private static string DescribeOs()
    {
        var v = Environment.OSVersion.Version;
        if (OperatingSystem.IsWindows()) return $"{(v.Build >= 22000 ? "Windows 11" : "Windows 10")} (build {v.Build})";
        if (OperatingSystem.IsMacOS()) return $"macOS {v.Major}.{v.Minor}";
        if (OperatingSystem.IsAndroid()) return "Android";
        if (OperatingSystem.IsIOS()) return $"iOS {v.Major}.{v.Minor}";
        if (OperatingSystem.IsLinux()) return "Linux";
        return RuntimeInformation.OSDescription;
    }

    private static string DescribeArch() => RuntimeInformation.OSArchitecture switch
    {
        Architecture.X64 => "x64",
        Architecture.X86 => "x86",
        Architecture.Arm64 => "ARM64",
        Architecture.Arm => "ARM",
        var other => other.ToString(),
    };

    // "12.1.4" from the informational version ("12.1.4+commit"), else the assembly version.
    private static string VersionOf(Assembly asm)
    {
        string? info = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(info))
        {
            int plus = info.IndexOf('+');
            return plus > 0 ? info[..plus] : info;
        }
        var v = asm.GetName().Version;
        return v is null ? "?" : $"{v.Major}.{v.Minor}.{v.Build}";
    }
}
