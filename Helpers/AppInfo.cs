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
