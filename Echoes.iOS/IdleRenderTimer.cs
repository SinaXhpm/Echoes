using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Runtime.CompilerServices;
using Avalonia;
using Avalonia.Platform;
using Avalonia.Rendering;
using Avalonia.Rendering.Composition;
using CoreAnimation;
using Foundation;
using UIKit;

namespace Echoes.iOS;

/// <summary>
/// The render timer, in place of Avalonia 12.1.4's: its CADisplayLink fires 60 times a second for as long as Echoes is
/// on screen, drawing or not (the render loop sets <see cref="Tick"/> to null when it is idle, and that timer ignores it),
/// so a page that sat still kept waking the CPU. This one pauses the link while there is nothing to draw and while the app
/// is in the background, as Avalonia's own timer does after 12.1.4 (src/iOS/Avalonia.iOS/DisplayLinkTimer.cs, MIT).
/// Avalonia's reference assemblies hide IRenderTimer's members from apps; Echoes.iOS.csproj compiles against the
/// implementation assembly, where they are public. Installed by <see cref="Use"/> from <see cref="AppDelegate"/>.
/// </summary>
internal sealed class IdleRenderTimer : IRenderTimer
{
    private readonly CADisplayLink _link;
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    // Guards _tick, _inBackground and _paused: the render loop, the main thread and the link's thread all touch them.
    private readonly object _lock = new();
    private Action<TimeSpan>? _tick;
    private bool _inBackground;
    private bool _paused = true;
    private long _callbacks;

    private IdleRenderTimer()
    {
        _link = CADisplayLink.Create(OnLinkTick);
        _link.Paused = true;
        TimerThread = new Thread(() =>
        {
            _link.AddToRunLoop(NSRunLoop.Current, NSRunLoopMode.Common);
            NSRunLoop.Current.Run();
        }) { Name = "Echoes render timer", IsBackground = true };
        TimerThread.Start();
        UIApplication.Notifications.ObserveDidEnterBackground((_, _) => SetInBackground(true));
        UIApplication.Notifications.ObserveWillEnterForeground((_, _) => SetInBackground(false));
    }

    /// <summary>The timer in use, or null; <see cref="State"/> says which and why (the self-test reports it).</summary>
    internal static IdleRenderTimer? Current { get; private set; }

    internal static string State { get; private set; } = "not installed";

    /// <summary>Display-link callbacks so far, drawing or not: what the self-test counts while nothing moves.</summary>
    internal long Callbacks => Interlocked.Read(ref _callbacks);

    public Thread TimerThread { get; }

    public bool RunsInBackground => true;

    public Action<TimeSpan>? Tick
    {
        get
        {
            lock (_lock)
                return _tick;
        }
        set
        {
            lock (_lock)
            {
                _tick = value;
                UpdateLink();
            }
        }
    }

    private void SetInBackground(bool inBackground)
    {
        lock (_lock)
        {
            _inBackground = inBackground;
            UpdateLink();
        }
    }

    // With _lock held. CADisplayLink.Paused may be set from any thread.
    private void UpdateLink()
    {
        bool paused = _inBackground || _tick is null;
        if (_paused == paused) return;
        _paused = paused;
        _link.Paused = paused;
    }

    private void OnLinkTick()
    {
        Interlocked.Increment(ref _callbacks);
        Action<TimeSpan>? tick;
        // a callback already on its way when the link was paused still arrives
        lock (_lock)
            tick = _paused ? null : _tick;
        tick?.Invoke(_clock.Elapsed);
    }

    /// <summary>
    /// Puts this timer under Avalonia's renderer. Avalonia.iOS keeps its timer in Platform.Timer (a public field of an
    /// internal class), makes one only while that is null, and builds on it the render loop and the compositor the views
    /// draw with (Platform.Compositor). So before the platform starts, Platform.Timer gets a stand-in that never runs: an
    /// instance of Avalonia's timer whose constructor never ran (no display link, no thread). Once the platform is up, the
    /// views' compositor is replaced by one on a render loop driven by this timer. Avalonia's own timer stays when it
    /// already pauses itself (a release with the fix) or when its internals aren't the ones this was written against.
    /// </summary>
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicFields | DynamicallyAccessedMemberTypes.NonPublicProperties,
        "Avalonia.iOS.Platform", "Avalonia.iOS")]
    [DynamicDependency(DynamicallyAccessedMemberTypes.NonPublicFields, "Avalonia.iOS.DisplayLinkTimer", "Avalonia.iOS")]
    internal static AppBuilder Use(AppBuilder builder)
    {
        try
        {
            const BindingFlags instance = BindingFlags.Instance | BindingFlags.NonPublic;
            var platform = Type.GetType("Avalonia.iOS.Platform, Avalonia.iOS");
            var stock = Type.GetType("Avalonia.iOS.DisplayLinkTimer, Avalonia.iOS");
            if (stock?.GetField("_paused", instance) is not null)
            {
                State = "not needed: Avalonia's timer pauses itself";
                return builder;
            }
            var timerField = platform?.GetField("Timer", BindingFlags.Static | BindingFlags.Public);
            var compositor = platform?.GetProperty("Compositor", BindingFlags.Static | BindingFlags.NonPublic);
            var threadField = stock?.GetField("<TimerThread>k__BackingField", instance);
            var tickField = stock?.GetField("_tick", instance);
            if (stock is null || timerField is null || timerField.FieldType != stock || timerField.GetValue(null) is not null
                || compositor?.SetMethod is null || threadField is null || tickField?.FieldType != typeof(Action<TimeSpan>))
            {
                State = "not installed: Avalonia.iOS isn't laid out as in 12.1.4";
                return builder;
            }

            var timer = new IdleRenderTimer();
            object standIn = RuntimeHelpers.GetUninitializedObject(stock);
            threadField.SetValue(standIn, timer.TimerThread);   // the OpenGL ES fallback checks that it draws on this thread
            builder = builder.AfterPlatformServicesSetup(_ =>
            {
                var original = AvaloniaLocator.Current.GetService<IRenderLoop>();
                try
                {
                    AvaloniaLocator.CurrentMutable.Bind<IRenderLoop>().ToConstant(RenderLoop.FromTimer(timer));
                    var replacement = new Compositor(AvaloniaLocator.Current.GetService<IPlatformGraphics>());
                    compositor.SetValue(null, replacement);
                    AvaloniaLocator.CurrentMutable.Bind<Compositor>().ToConstant(replacement);
                    Current = timer;
                    State = "installed";
                }
                catch (Exception ex)
                {
                    // The views still draw through the stand-in's render loop: a link of its own drives it without ever
                    // pausing, which is what Avalonia's timer would have done.
                    if (original is not null) AvaloniaLocator.CurrentMutable.Bind<IRenderLoop>().ToConstant(original);
                    var fallback = new IdleRenderTimer();
                    threadField.SetValue(standIn, fallback.TimerThread);
                    fallback.Tick = time => (tickField.GetValue(standIn) as Action<TimeSpan>)?.Invoke(time);
                    State = "not installed (Avalonia's behaviour kept): " + ex.Message;
                    Helpers.CrashLog.Write("IdleRenderTimer", ex);
                }
            });
            timerField.SetValue(null, standIn);   // last: from here on, the callback above is what the views draw with
            return builder;
        }
        catch (Exception ex)
        {
            State = "not installed: " + ex.Message;
            Helpers.CrashLog.Write("IdleRenderTimer", ex);
            return builder;
        }
    }
}
