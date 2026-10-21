using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Threading;

namespace Echoes.Views;

public partial class DnsView : UserControl
{
    // Paste-to-host and select-all-on-focus for the domain box are declared in XAML via
    // helpers:InputAssist (HostPaste / SelectAllOnFocus).
    public DnsView()
    {
        InitializeComponent();

        // The resolver box's MaxHeight follows the action row's bottom edge (see DnsResolvers in the XAML), which it takes
        // from the layout before. Coming back from the stacked layout it started from the stacked value (~250 px), the
        // auto rows beside it stretched to that, and the card stayed ~120 px too tall. Freed once when the form turns wide,
        // it settles from below, as on the first load.
        bool wide = DnsForm.Classes.Contains("wide");
        DnsForm.Classes.CollectionChanged += (_, _) =>
        {
            bool now = DnsForm.Classes.Contains("wide");
            if (now && !wide)
            {
                DnsResolvers.SetCurrentValue(Layoutable.MaxHeightProperty, 0d);
                // once laid out without it, the action row's edge is the natural one: take it (the binding may not fire
                // again when that edge didn't move, and the box would stay at 0)
                Dispatcher.UIThread.Post(() => DnsResolvers.SetCurrentValue(Layoutable.MaxHeightProperty, DnsActions.Bounds.Bottom),
                                         DispatcherPriority.Background);
            }
            wide = now;
        };
    }
}
