using Avalonia;
using Avalonia.iOS;
using Foundation;

namespace Echoes.iOS;

// The Avalonia iOS entry: AvaloniaAppDelegate<TApp> starts Avalonia with the shared App, which (single-view lifetime)
// shows the same touch shell (drawer + one tool at a time) as the Android head. CustomizeAppBuilder is where builder
// tweaks (fonts, etc.) go.
[Register("AppDelegate")]
public class AppDelegate : AvaloniaAppDelegate<global::Echoes.App>
{
    protected override AppBuilder CustomizeAppBuilder(AppBuilder builder)
    {
        // What the Web Server's chat and page call this device. iOS 16+ reports a generic "iPhone" / "iPad" unless Apple
        // grants the user-assigned-device-name entitlement, which is still better than the host name ("localhost").
        string name = UIKit.UIDevice.CurrentDevice.Name;
        if (!string.IsNullOrWhiteSpace(name)) Echoes.Helpers.AppInfo.DeviceName = name.Trim();
        // Alert sounds (ambient: the ringer switch silences them) and "keep the screen on while something is running"
        // (iOS suspends the app, and its sockets, soon after it leaves the screen or the phone locks).
        Echoes.Helpers.SoundHelper.RegisterPlayer(new IosSoundPlayer());
        Echoes.Helpers.BackgroundGuard.Register(new IosBackgroundGuard());
        // CI starts the app with ECHOES_SELFTEST=1 on a simulator to check what the shared tools need (see SelfTest.cs).
        if (SelfTest.Requested) _ = Task.Run(async () => { await Task.Delay(6000).ConfigureAwait(false); await SelfTest.RunAsync().ConfigureAwait(false); });
        return base.CustomizeAppBuilder(builder).WithInterFont();
    }
}
