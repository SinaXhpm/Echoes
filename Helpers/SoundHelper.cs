using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace Echoes.Helpers;

public static class SoundHelper
{
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
                    Process.Start("afplay", "/System/Library/Sounds/Tink.aiff");
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    Process.Start("paplay", "/usr/share/sounds/freedesktop/stereo/message-new-instant.oga");
                }
            }
            catch
            {
                Console.Write("\a");
            }
        });
    }
}