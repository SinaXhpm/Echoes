using Android.Content;
using Echoes.Helpers;

namespace Echoes.Android;

/// <summary>
/// Android implementation of <see cref="IBackgroundGuard"/>: acquiring starts the
/// <see cref="KeepAliveService"/> foreground service, releasing stops it. The shared
/// <see cref="BackgroundGuard"/> ref-counts calls, so this only ever sees the first
/// acquire and the last release.
/// </summary>
public sealed class AndroidBackgroundGuard : IBackgroundGuard
{
    private readonly Context _context;

    public AndroidBackgroundGuard(Context context) => _context = context;

    public void Acquire(string reason)
    {
        KeepAliveService.StopWanted = false;   // a release still pending from before is overtaken by this start
        var intent = new Intent(_context, typeof(KeepAliveService));
        intent.PutExtra(KeepAliveService.ExtraReason, reason);

        // From the foreground (a user tapping Start) this is allowed on every API level;
        // API 26+ requires StartForegroundService so the service can call StartForeground.
        if (OperatingSystem.IsAndroidVersionAtLeast(26))
            _context.StartForegroundService(intent);
        else
            _context.StartService(intent);
    }

    // Not stopped before it has gone foreground: Android would kill the app (see KeepAliveService.IsForeground). A release
    // that early is recorded instead, and the service stops itself right after StartForeground.
    public void Release()
    {
        if (!KeepAliveService.IsForeground)
        {
            KeepAliveService.StopWanted = true;
            return;
        }
        _context.StopService(new Intent(_context, typeof(KeepAliveService)));
    }
}
