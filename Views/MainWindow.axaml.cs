using Avalonia.Controls;

namespace Echoes.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        // The UI lives in MainView (shared with the Android single-view head);
        // it triggers the update check on Loaded.
    }
}