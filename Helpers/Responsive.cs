using Avalonia;
using Avalonia.Controls;
using Avalonia.Reactive;

namespace Echoes.Helpers;

/// <summary>
/// Width-driven responsive helper. Set <c>Responsive.BreakWidth</c> on any control and
/// it keeps the mutually-exclusive style classes <c>narrow</c>/<c>wide</c> in sync with
/// the control's own rendered width: width &lt; break → <c>narrow</c>, otherwise <c>wide</c>.
///
/// XAML can then express two layouts via <c>Selector="X.narrow ..."</c> / <c>"X.wide ..."</c>
/// style setters — no media queries. Because it reacts to the control's actual width, the
/// same rule fires on a resized desktop window and on a phone screen, so a single markup
/// path serves both the desktop tab shell and the mobile carousel.
/// </summary>
public static class Responsive
{
    public static readonly AttachedProperty<double> BreakWidthProperty =
        AvaloniaProperty.RegisterAttached<Control, double>("BreakWidth", typeof(Responsive));

    public static void SetBreakWidth(Control control, double value) => control.SetValue(BreakWidthProperty, value);
    public static double GetBreakWidth(Control control) => control.GetValue(BreakWidthProperty);

    static Responsive()
    {
        BreakWidthProperty.Changed.AddClassHandler<Control>((control, _) =>
        {
            // Re-evaluate whenever the control is (re)laid out. Subscribing here (rather than
            // in a constructor we don't own) keeps this a zero-touch attached behaviour.
            control.GetObservable(Visual.BoundsProperty)
                   .Subscribe(new AnonymousObserver<Rect>(_ => Apply(control)));
            Apply(control);
        });
    }

    private static void Apply(Control control)
    {
        double breakWidth = GetBreakWidth(control);
        if (breakWidth <= 0) return;

        double width = control.Bounds.Width;
        // Width 0 == not laid out yet: default to "wide" so the desktop layout is correct on
        // the very first frame (the mobile shell narrows on its first real measure pass).
        bool narrow = width > 0 && width < breakWidth;

        SetClass(control, "narrow", narrow);
        SetClass(control, "wide", !narrow);
    }

    private static void SetClass(Control control, string name, bool on)
    {
        bool has = control.Classes.Contains(name);
        if (on && !has) control.Classes.Add(name);
        else if (!on && has) control.Classes.Remove(name);
    }
}
