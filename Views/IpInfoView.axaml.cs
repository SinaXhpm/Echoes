using Avalonia.Controls;

namespace Echoes.Views;

public partial class IpInfoView : UserControl
{
    public IpInfoView()
    {
        InitializeComponent();
        // The full sentence doesn't fit a phone's box in the mono font ("…for your own public").
        if (Helpers.AppPlatform.IsMobile) IpBox.PlaceholderText = "Empty for your own public IP";
    }
}