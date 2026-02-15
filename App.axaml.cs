using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Echoes.ViewModels;
using Echoes.Views;
using System;

namespace Echoes;

public partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var mainWindow = new MainWindow();
            var viewModel = new MainViewModel();

            desktop.MainWindow = mainWindow;
            mainWindow.DataContext = viewModel;
        }

        base.OnFrameworkInitializationCompleted();
    }
}