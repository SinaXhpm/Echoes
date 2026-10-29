#if DEBUG
using System;
using System.Threading.Tasks;
using Android.Content;
using Android.Util;
using Echoes.Helpers;

namespace Echoes.Android;

/// <summary>
/// Debug builds only: the Device page's report, written to logcat on a broadcast, so it can be checked on a phone over
/// adb without its screen (a locked phone stays locked):
/// <c>adb shell am broadcast -n com.sinaxhpm.echoes.dev/com.sinaxhpm.echoes.debug.DeviceReport</c>, then
/// <c>adb logcat -s EchoesDevice</c>.
/// </summary>
[BroadcastReceiver(Name = "com.sinaxhpm.echoes.debug.DeviceReport", Exported = true)]
internal sealed class DebugDeviceReport : BroadcastReceiver
{
    public override void OnReceive(Context? context, Intent? intent)
    {
        var pending = GoAsync();
        Task.Run(() =>
        {
            try
            {
                var report = DeviceInfo.Collect(Array.Empty<DeviceInfo.ScreenInfo>(), "debug");
                Log.Info("EchoesDevice", DeviceInfo.Headline(report));
                foreach (var section in report.Sections)
                    foreach (string line in section.Text.Split('\n'))
                        if (line.Length > 0) Log.Info("EchoesDevice", line);
                Log.Info("EchoesDevice", "== end ==");
            }
            catch (Exception ex) { Log.Error("EchoesDevice", ex.ToString()); }
            finally { pending?.Finish(); }
        });
    }
}
#endif
