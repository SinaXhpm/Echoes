using System;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Threading;
using Echoes.Helpers;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class DnsView : UserControl
{
    // Paste-to-host and select-all-on-focus for the domain box are declared in XAML via
    // helpers:InputAssist (HostPaste / SelectAllOnFocus).
    // interfaces come and go (Wi-Fi, a VPN): the picker lists the current ones whenever it opens
    private void IfaceBox_DropDownOpened(object? sender, EventArgs e)
    {
        if (DataContext is DnsViewModel { IsWorking: false } vm) vm.Iface.Refresh();
    }

    public DnsView()
    {
        InitializeComponent();
        if (AppPlatform.IsMobile) DnsRoot.Classes.Add("touch");   // finger-size resolver rows (styles in the XAML)

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

    private DnsViewModel? _vm;

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);
        if (_vm is not null) _vm.ResolverAdded -= ShowAddedResolver;
        _vm = DataContext as DnsViewModel;
        if (_vm is not null) _vm.ResolverAdded += ShowAddedResolver;
    }

    // An added resolver goes to the end of the list, below the rows the box shows: scrolled to once its row is laid out.
    private void ShowAddedResolver()
        => Dispatcher.UIThread.Post(() => ResolverScroll.ScrollToEnd(), DispatcherPriority.Background);
}
