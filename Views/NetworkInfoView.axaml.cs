using Avalonia;
using Avalonia.Controls;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class NetworkInfoView : UserControl
{
    public NetworkInfoView()
    {
        InitializeComponent();
    }

    // The Wi-Fi tab reads (and scans) only while it is on screen: the tab control keeps just the selected tab's content in
    // the visual tree, and a hidden tool page is detached or invisible, so attach / detach start and stop the polling, and
    // every tick checks it is still effectively visible. (The tab is built the first time it is shown, Views/Controls/
    // Deferred: its root reports itself through these XAML events.)
    private void WifiRoot_Attached(object? sender, VisualTreeAttachmentEventArgs e)
    {
        // a minimized window counts as hidden too (its controls stay "visible", and a laptop scanned on regardless)
        if (DataContext is NetworkInfoViewModel vm && sender is Control root)
            vm.WifiShown(() => Helpers.AppPlatform.OnScreen(root));
    }

    private void WifiRoot_Detached(object? sender, VisualTreeAttachmentEventArgs e)
    {
        if (DataContext is NetworkInfoViewModel vm) vm.WifiHidden();
    }
}
