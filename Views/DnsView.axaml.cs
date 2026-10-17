using Avalonia.Controls;

namespace Echoes.Views;

public partial class DnsView : UserControl
{
    // Paste-to-host and select-all-on-focus for the domain box are declared in XAML via
    // helpers:InputAssist (HostPaste / SelectAllOnFocus).
    public DnsView()
    {
        InitializeComponent();
    }
}
