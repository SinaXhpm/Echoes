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
    {
        // SelectionChanged also fires while the XAML tree is still being populated
        // (when SelectedIndex="0" is applied), before sibling named controls like
        // Split are assigned — guard against the null to avoid a startup crash.
        if (Split is not null)
            Split.IsPaneOpen = false; // close the drawer after picking a tool
    }
}
