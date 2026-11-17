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
/// <para>While nobody sees the app (the window minimized or in the tray, a phone app in the background:
/// <see cref="AppPlatform.IsInForeground"/>) it ticks only every <see cref="HiddenInterval"/>, however much arrives, to
/// drain what queued up; on screen again it shows everything at once and goes back to the fast pace. A server busy in
/// the tray otherwise drained and refreshed its hidden page up to ten times a second. (The queues it drains have caps
/// of their own, so a slower drain can't let them grow without end.)</para>
/// </summary>
internal sealed class PacedTimer
{
    private static readonly TimeSpan HiddenInterval = TimeSpan.FromSeconds(5);

    private readonly DispatcherTimer _timer;
    private readonly Func<bool> _tick;
    private readonly TimeSpan _fast, _slow;
    private readonly int _quietTicks;
    private int _idle;
    private volatile bool _slowNow;
    private int _poked;
    private bool _hooked;

    public PacedTimer(int fastMs, int slowMs, Func<bool> tick)
    {
        _fast = TimeSpan.FromMilliseconds(fastMs);
        _slow = TimeSpan.FromMilliseconds(slowMs);
        _quietTicks = Math.Max(1, (int)Math.Ceiling(1000.0 / fastMs));   // about a second of quiet
        _tick = tick;
        _timer = new DispatcherTimer { Interval = _fast };
        _timer.Tick += (_, _) =>
        {
            bool found = _tick();
            if (!AppPlatform.IsInForeground) Hide();
            else if (found) Wake();
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
        // (an instance event on a static: hooked only while running, so a stopped timer doesn't keep its page alive)
        if (!_hooked)
        {
            AppPlatform.ForegroundChanged += OnForegroundChanged;
            _hooked = true;
        }
    }

    public void Stop()
    {
        _timer.Stop();
        if (_hooked)
        {
            AppPlatform.ForegroundChanged -= OnForegroundChanged;
            _hooked = false;
        }
    }

    public void Wake()
    {
        _idle = 0;
        if (!AppPlatform.IsInForeground)
        {
            Hide();
            return;
        }
        _slowNow = false;
        if (_timer.Interval != _fast) _timer.Interval = _fast;
    }

    private void Hide()
    {
        _slowNow = true;   // (Poke then waits for the hidden tick)
        if (_timer.Interval != HiddenInterval) _timer.Interval = HiddenInterval;
    }

    // UI thread (AppPlatform.SetForeground). Back on screen: what queued up meanwhile shows now.
    private void OnForegroundChanged()
    {
        if (!_timer.IsEnabled) return;
        if (!AppPlatform.IsInForeground)
        {
            Hide();
            return;
        }
        Wake();
        _tick();
    }

    /// <summary>Any thread: something was queued. While the pace is slow, the UI thread shows it now and goes back to the
    /// fast pace (one post however many arrive); while fast, nothing to do.</summary>
    public void Poke()
    {
        // (hidden: nobody would see it; the hidden tick drains it)
        if (!_slowNow || !AppPlatform.IsInForeground || Interlocked.Exchange(ref _poked, 1) == 1) return;
        Dispatcher.UIThread.Post(() =>
        {
            Interlocked.Exchange(ref _poked, 0);
            if (!_timer.IsEnabled || !_slowNow) return;
            Wake();
            _tick();
        });
    }
}
