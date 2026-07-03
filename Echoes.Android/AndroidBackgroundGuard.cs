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
        var intent = new Intent(_context, typeof(KeepAliveService));
        intent.PutExtra(KeepAliveService.ExtraReason, reason);

        // From the foreground (a user tapping Start) this is allowed on every API level;
        // API 26+ requires StartForegroundService so the service can call StartForeground.
        if (OperatingSystem.IsAndroidVersionAtLeast(26))
            _context.StartForegroundService(intent);
        else
            _context.StartService(intent);
    }

    public void Release()
    {
        _context.StopService(new Intent(_context, typeof(KeepAliveService)));
    }
}
