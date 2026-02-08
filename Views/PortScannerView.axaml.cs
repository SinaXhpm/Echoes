using Avalonia.Controls;
using Avalonia.Interactivity;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class PortScannerView : UserControl
{
    public PortScannerView()
    {
        InitializeComponent();
    }
    private async void Export_Click(object? sender, RoutedEventArgs e)
    {
        if (DataContext is PortScannerViewModel vm)
        {
            var topLevel = TopLevel.GetTopLevel(this);
            if (topLevel != null)
            {
                await vm.ExportResults(topLevel.StorageProvider);
            }
        }
    }
}