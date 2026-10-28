using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Presenters;
using Avalonia.Reactive;
using Avalonia.VisualTree;

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
            // Entering the tree, before its first layout: guessed from where it sits (see AncestorWidth).
            control.AttachedToVisualTree += (_, _) => Apply(control);
            Apply(control);
        });
    }

    private static void Apply(Control control)
    {
        double breakWidth = GetBreakWidth(control);
        if (breakWidth <= 0) return;

        double width = control.Bounds.Width;
        // Width 0 == not laid out yet. A control is never wider than the nearest ancestor already laid out, so below the
        // break there it starts narrow: on a phone every page used to be laid out wide first and then again narrow, part by
        // part. Otherwise "wide", so the desktop layout is right on the very first frame; the real width corrects either.
        if (width <= 0) width = AncestorWidth(control);
        bool narrow = width > 0 && width < breakWidth;

        SetClass(control, "narrow", narrow);
        SetClass(control, "wide", !narrow);
    }

    // The width of the nearest laid-out ancestor; 0 (unknown) inside a sideways scroller, whose content may be wider.
    private static double AncestorWidth(Control control)
    {
        for (var v = control.GetVisualParent(); v is not null; v = v.GetVisualParent())
        {
            if (v is ScrollContentPresenter { CanHorizontallyScroll: true }) return 0;
            if (v.Bounds.Width > 0) return v.Bounds.Width;
        }
        return 0;
    }

    private static void SetClass(Control control, string name, bool on)
    {
        bool has = control.Classes.Contains(name);
        if (on && !has) control.Classes.Add(name);
        else if (!on && has) control.Classes.Remove(name);
    }
}
