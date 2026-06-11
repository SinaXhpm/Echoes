using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Echoes.ViewModels;
using Echoes.Views;
using System;

namespace Echoes;

public partial class App : Avalonia.Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        var viewModel = new MainViewModel();

        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.MainWindow = new MainWindow { DataContext = viewModel };
        }
        else if (ApplicationLifetime is ISingleViewApplicationLifetime singleView)
        {
            // Mobile / single-view heads (e.g. Android) get the touch-friendly shell
            // (drawer nav + single tool at a time) over the same shared ViewModels.
            Helpers.AppPlatform.IsMobile = true;
            singleView.MainView = new MobileShellView { DataContext = viewModel };
        }

        base.OnFrameworkInitializationCompleted();
    }
}