using Avalonia.Controls;
using Avalonia.Input;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class MonitorView : UserControl
{
    public MonitorView()
    {
        InitializeComponent();
    }

    // Enter starts/stops monitoring; Shift+Enter inserts a newline (multi-target input).
    private void Input_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && e.KeyModifiers == KeyModifiers.None && DataContext is MonitorViewModel vm)
        {
            vm.ToggleMonitorCommand.Execute(null);
            e.Handled = true;
        }
    }
}