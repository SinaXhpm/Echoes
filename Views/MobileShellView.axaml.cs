using Avalonia.Controls;
using Avalonia.Interactivity;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class MobileShellView : UserControl
{
    public MobileShellView()
    {
        InitializeComponent();
        Loaded += async (s, e) =>
        {
            if (DataContext is MainViewModel vm)
                await vm.CheckForUpdatesAsync();
        };
    }

    private void TogglePane(object? sender, RoutedEventArgs e)
        => Split.IsPaneOpen = !Split.IsPaneOpen;

    private void Nav_SelectionChanged(object? sender, SelectionChangedEventArgs e)
        => Split.IsPaneOpen = false; // close the drawer after picking a tool
}
