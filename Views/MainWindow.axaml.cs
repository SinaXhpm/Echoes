using Avalonia.Controls;
using Echoes.ViewModels;
using System;

namespace Echoes.Views;

public partial class MainWindow : Window
{
    public MainWindow()
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