using System;
using System.Threading;
using Avalonia.Threading;

namespace Echoes.Helpers;

/// <summary>
/// A UI-thread timer for showing what background threads queue (a server's log, a socket's transcript): it ticks at the
/// fast interval while there is something to show and slows down after about a second with nothing. A server left running
/// for hours (on a phone in the background, where the keep-alive service keeps the process up for it) otherwise woke the
/// UI thread several times a second with nothing to do. The tick returns whether it found anything; <see cref="Wake"/>
/// goes back to the fast pace at once (after the user sends something, for instance), and <see cref="Poke"/> does the same
/// from the thread that queued something, so the first message after a quiet spell isn't a slow interval late.
/// </summary>
internal sealed class PacedTimer
{
    private readonly DispatcherTimer _timer;
    private readonly Func<bool> _tick;
    private readonly TimeSpan _fast, _slow;
    private readonly int _quietTicks;
    private int _idle;
    private volatile bool _slowNow;
    private int _poked;

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
            else if (++_idle == _quietTicks)
            {
                _timer.Interval = _slow;
                _slowNow = true;
            }
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
        _slowNow = false;
        if (_timer.Interval != _fast) _timer.Interval = _fast;
    }

    /// <summary>Any thread: something was queued. While the pace is slow, the UI thread shows it now and goes back to the
    /// fast pace (one post however many arrive); while fast, nothing to do.</summary>
    public void Poke()
    {
        if (!_slowNow || Interlocked.Exchange(ref _poked, 1) == 1) return;
        Dispatcher.UIThread.Post(() =>
        {
            Interlocked.Exchange(ref _poked, 0);
            if (!_timer.IsEnabled || !_slowNow) return;
            Wake();
            _tick();
        });
    }
}
