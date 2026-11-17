using Avalonia.Controls;
using Avalonia.Input;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class DoctorView : UserControl
{
    public DoctorView()
    {
        InitializeComponent();

        // Smart paste (a URL, host:port or a log line reduced to the endpoint) and select-all-on-focus are declared in
        // XAML via helpers:InputAssist. A phone's narrower box cut the example off mid-word.
        if (Helpers.AppPlatform.IsMobile)
        {
            TargetBox.PlaceholderText = "A site or URL";
            ProxyBox.PlaceholderText = "socks5://host:port";
        }
    }

    // The interface list is read when it opens (Wi-Fi, a VPN come and go), as on the other tools' pickers.
    private void IfaceBox_DropDownOpened(object? sender, System.EventArgs e)
    {
        if (DataContext is DoctorViewModel { IsRunning: false } vm) vm.Iface.Refresh();
    }

    // Tapping a check with sub-steps opens or closes its granular trace.
    private void OnStepTapped(object? sender, TappedEventArgs e)
    {
        if (sender is Control { DataContext: DoctorStepRow row } && row.HasTrace)
            row.ToggleCommand.Execute(null);
    }
}
