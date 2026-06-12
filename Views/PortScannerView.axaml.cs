using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class PortScannerView : UserControl
{
    public PortScannerView()
    {
        InitializeComponent();
    }

    // Enter starts/stops the scan; Shift+Enter inserts a newline (multi-target input).
    private void Input_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && e.KeyModifiers == KeyModifiers.None && DataContext is PortScannerViewModel vm)
        {
            vm.ToggleScanCommand.Execute(null);
            e.Handled = true;
        }
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