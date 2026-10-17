using System;

namespace Echoes.Helpers;

/// <summary>
/// The phone side of "start by itself": the Android head implements it (Echoes.Android/BootReceiver.cs) by switching its
/// boot receiver component on or off, so a phone that never asked for it doesn't even start Echoes at boot.
/// </summary>
public interface IBootStartHost
{
    /// <summary>Whether the boot receiver is switched on in the system right now.</summary>
    bool IsEnabled { get; }

    /// <summary>Switches the boot receiver on or off. Null when done, else the one reason it failed.</summary>
    string? SetEnabled(bool on);

    /// <summary>Opens Echoes' page in the phone's app settings (auto launch, battery, notifications).</summary>
    void OpenAppSettings();
}

/// <summary>
/// "Start when the phone starts" (Monitor settings, Android only): after a reboot — and after an update of Echoes — the
/// boot receiver starts the background service and monitoring, without opening Echoes. The wish is a profile setting
/// (<see cref="ProfileKey"/>, read by the receiver); the receiver component is kept in step with it. Desktop heads and
/// test harnesses never register a host, so the option doesn't exist there (<see cref="IsSupported"/>).
/// </summary>
public static class BootStart
{
    public const string ProfileKey = "monitor.bootStart";

    private static IBootStartHost? _host;

    /// <summary>Called once at startup by the Android head (a test harness may register a stand-in).</summary>
    public static void Register(IBootStartHost? host) => _host = host;

    public static bool IsSupported => _host is not null;

    /// <summary>The user's choice (profile). Cheap: the profile is already in memory when the receiver runs.</summary>
    public static bool IsWanted => ProfileService.Instance.GetBool(ProfileKey, false);

    /// <summary>Puts the receiver in step with <paramref name="on"/>. Null when done (or nothing to do), else the reason.</summary>
    public static string? Apply(bool on)
    {
        if (_host is not { } host) return null;
        try
        {
            if (host.IsEnabled == on) return null;
            return host.SetEnabled(on);
        }
        catch (Exception ex)
        {
            CrashLog.Write("BootStart.Apply", ex);
            return "Couldn't change starting with the phone: " + ex.Message;
        }
    }

    public static void OpenAppSettings()
    {
        try { _host?.OpenAppSettings(); }
        catch (Exception ex) { CrashLog.Write("BootStart.OpenAppSettings", ex); }
    }
}
