using Avalonia.Controls;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class MainView : UserControl
{
    public MainView()
    {
        InitializeComponent();
        Loaded += async (s, e) =>
        {
            if (DataContext is MainViewModel vm)
            {
                await vm.CheckForUpdatesAsync();
            }
        };
    }
}
