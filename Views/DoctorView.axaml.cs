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
            TargetBox.PlaceholderText = "Site, URL or host:port";
            ProxyBox.PlaceholderText = "socks5://host:port";
        }
    }

    // Tapping a check with sub-steps opens or closes its granular trace.
    private void OnStepTapped(object? sender, TappedEventArgs e)
    {
        if (sender is Control { DataContext: DoctorStepRow row } && row.HasTrace)
            row.ToggleCommand.Execute(null);
    }
}
