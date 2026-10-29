using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.LogicalTree;

namespace Echoes.Views.Controls;

/// <summary>
/// Marks a tool's main tab strip: <c>ctl:PageTabs.Primary="True"</c> on its TabControl (or its segmented ListBox).
/// The shell shows those tabs in the page header (<see cref="PageTabStrip"/>, beside the title on a desktop, a chip
/// row under the app bar on a phone) and the control draws no strip of its own (the <c>pageTabs</c> class, see
/// AppStyles); its content, selection binding and lazily built tabs stay as they are.
/// </summary>
public sealed class PageTabs
{
    public static readonly AttachedProperty<bool> PrimaryProperty =
        AvaloniaProperty.RegisterAttached<PageTabs, Control, bool>("Primary");

    /// <summary>A marked strip came on screen: a part built when first shown (Cloudflare's tabs, once the vault is
    /// unlocked) wasn't there when its page opened, so the shell looks again.</summary>
    public static event Action<Control>? Appeared;

    static PageTabs()
    {
        PrimaryProperty.Changed.AddClassHandler<Control>((c, e) =>
        {
            bool on = e.NewValue is true;
            c.Classes.Set("pageTabs", on);
            c.AttachedToVisualTree -= OnAttached;
            if (on) c.AttachedToVisualTree += OnAttached;
        });
    }

    private static void OnAttached(object? sender, VisualTreeAttachmentEventArgs e)
    {
        if (sender is Control c) Appeared?.Invoke(c);
    }

    public static bool GetPrimary(Control control) => control.GetValue(PrimaryProperty);

    public static void SetPrimary(Control control, bool value) => control.SetValue(PrimaryProperty, value);

    /// <summary>The strip marked <see cref="PrimaryProperty"/> under <paramref name="root"/> (a page host), or null for
    /// a page without tabs. Of several (a page with one per mode, each bound to the mode), the first one not hidden.</summary>
    public static SelectingItemsControl? FindIn(ILogical? root)
    {
        if (root is null) return null;
        SelectingItemsControl? first = null;
        foreach (var node in root.GetSelfAndLogicalDescendants())
        {
            if (node is not SelectingItemsControl s || !GetPrimary(s)) continue;
            first ??= s;
            if (ShownWithin(s, root)) return s;
        }
        return first;
    }

    private static bool ShownWithin(Control c, ILogical root)
    {
        for (ILogical? n = c; n is not null && !ReferenceEquals(n, root); n = n.LogicalParent)
            if (n is Visual { IsVisible: false }) return false;
        return true;
    }
}
