using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace Echoes.Helpers;

public static class SoundHelper
{
    private static readonly (string File, string Args)[] LinuxPlayers =
    {
        ("paplay", "/usr/share/sounds/freedesktop/stereo/message-new-instant.oga"),
        ("pw-play", "/usr/share/sounds/freedesktop/stereo/message-new-instant.oga"),
        ("canberra-gtk-play", "-i message-new-instant"),
        ("aplay", "-q /usr/share/sounds/alsa/Front_Center.wav")
    };

    public static void PlayNotify(bool isSuccess)
    {
        Task.Run(() =>
        {
            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    Console.Beep(isSuccess ? 900 : 400, 250);
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    TryStart("afplay", "/System/Library/Sounds/Tink.aiff");
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    foreach (var (file, args) in LinuxPlayers)
                    {
                        if (TryStart(file, args)) return;
                    }
                    Console.Write("\a");
                }
            }
            catch
            {
                Console.Write("\a");
            }
        });
    }

    private static bool TryStart(string file, string args)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = file,
                Arguments = args,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var process = Process.Start(psi);
            return process != null;
        }
        catch
        {
            return false;
        }
    }
}
