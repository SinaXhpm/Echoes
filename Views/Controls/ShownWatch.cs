using System;
using System.Collections.Generic;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Reactive;
using Avalonia.VisualTree;

namespace Echoes.Views.Controls;

/// <summary>
/// Whether a page can be seen: in the visual tree, and visible along with every ancestor. The desktop tabs take the page
/// they leave out of the tree, but the phone shell's carousel only hides it (IsVisible on its host), so attach / detach
/// alone said "shown" for every page visited once: a page's "is the user looking at me" logic (the chat's unread count,
/// SSH's server polling) went on behind other pages. <see cref="Changed"/> fires on the UI thread when the answer changes.
/// Made before the control is attached (a view's constructor) or while it is (the header's tab strip watching its
/// target); disposed when no longer wanted.
/// </summary>
internal sealed class ShownWatch : IDisposable
{
    private readonly Control _control;
    private readonly List<IDisposable> _ancestors = new();
    private bool _attached;

    public ShownWatch(Control control)
    {
        _control = control;
        control.AttachedToVisualTree += OnAttached;
        control.DetachedFromVisualTree += OnDetached;
        if (TopLevel.GetTopLevel(control) is not null)
        {
            _attached = true;
            Hook();
        }
    }

    public bool IsShown { get; private set; }

    public event Action<bool>? Changed;

    public void Dispose()
    {
        _control.AttachedToVisualTree -= OnAttached;
        _control.DetachedFromVisualTree -= OnDetached;
        Unhook();
    }

    private void OnAttached(object? sender, VisualTreeAttachmentEventArgs e)
    {
        _attached = true;
        Hook();
    }

    private void OnDetached(object? sender, VisualTreeAttachmentEventArgs e)
    {
        _attached = false;
        Unhook();
        Update();
    }

    private void Hook()
    {
        Unhook();
        for (Visual? v = _control; v is not null; v = v.GetVisualParent())
            _ancestors.Add(v.GetPropertyChangedObservable(Visual.IsVisibleProperty)
                            .Subscribe(new AnonymousObserver<AvaloniaPropertyChangedEventArgs>(_ => Update())));
        Update();
    }

    private void Unhook()
    {
        foreach (var watch in _ancestors) watch.Dispose();
        _ancestors.Clear();
    }

    // IsEffectivelyVisible is up to date by the time a change notification comes (OnPropertyChanged sets it first), but
    // detaching sets it back to true and the window is let go of only after DetachedFromVisualTree: hence _attached.
    private void Update()
    {
        bool shown = _attached && _control.IsEffectivelyVisible;
        if (shown == IsShown) return;
        IsShown = shown;
        Changed?.Invoke(shown);
    }
}
