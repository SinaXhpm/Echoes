using System;
using Avalonia.Threading;

namespace Echoes.Helpers;

/// <summary>
/// A UI-thread timer for showing what background threads queue (a server's log, a socket's transcript): it ticks at the
/// fast interval while there is something to show and slows down after about a second with nothing. A server left running
/// for hours (on a phone in the background, where the keep-alive service keeps the process up for it) otherwise woke the
/// UI thread several times a second with nothing to do. The tick returns whether it found anything; <see cref="Wake"/>
/// goes back to the fast pace at once (after the user sends something, for instance).
/// </summary>
internal sealed class PacedTimer
{
    private readonly DispatcherTimer _timer;
    private readonly Func<bool> _tick;
    private readonly TimeSpan _fast, _slow;
    private readonly int _quietTicks;
    private int _idle;

    public PacedTimer(int fastMs, int slowMs, Func<bool> tick)
    {
        _fast = TimeSpan.FromMilliseconds(fastMs);
        _slow = TimeSpan.FromMilliseconds(slowMs);
        _quietTicks = Math.Max(1, (int)Math.Ceiling(1000.0 / fastMs));   // about a second of quiet
        _tick = tick;
        _timer = new DispatcherTimer { Interval = _fast };
        _timer.Tick += (_, _) =>
        {
            if (_tick()) Wake();
            else if (++_idle == _quietTicks) _timer.Interval = _slow;
        };
    }

    public void Start()
    {
        Wake();
        _timer.Start();
    }

    public void Stop() => _timer.Stop();

    public void Wake()
    {
        _idle = 0;
        if (_timer.Interval != _fast) _timer.Interval = _fast;
    }
}
