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
            // a minimized window counts as hidden too (its controls stay "visible", and a laptop scanned on regardless)
            if (DataContext is NetworkInfoViewModel vm)
                vm.WifiShown(() => Helpers.AppPlatform.OnScreen(WifiRoot));
        };
        WifiRoot.DetachedFromVisualTree += (_, _) =>
        {
            if (DataContext is NetworkInfoViewModel vm) vm.WifiHidden();
        };
    }
}
