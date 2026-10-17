using Avalonia;
using Avalonia.Controls;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class NetworkInfoView : UserControl
{
    public NetworkInfoView()
    {
        InitializeComponent();

        // The Wi-Fi tab reads (and scans) only while it is on screen: the tab control keeps just the selected tab's
        // content in the visual tree, and a hidden tool page is detached or invisible, so attach / detach start and
        // stop the polling, and every tick checks it is still effectively visible.
        WifiRoot.AttachedToVisualTree += (_, _) =>
        {
            if (DataContext is NetworkInfoViewModel vm)
                vm.WifiShown(() => WifiRoot.IsEffectivelyVisible && TopLevel.GetTopLevel(WifiRoot) is not null);
        };
        WifiRoot.DetachedFromVisualTree += (_, _) =>
        {
            if (DataContext is NetworkInfoViewModel vm) vm.WifiHidden();
        };
    }
}
