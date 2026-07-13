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
        // Detect the platform BEFORE constructing the ViewModels, so any VM that reads
        // AppPlatform.IsMobile during construction observes the correct value.
        Helpers.AppPlatform.IsMobile = ApplicationLifetime is ISingleViewApplicationLifetime;

        // Persist unhandled/unobserved exceptions instead of dying silently — this is a
        // diagnostic tool, so a crash the user can't see is the worst outcome.
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            Helpers.CrashLog.Write("AppDomain.UnhandledException", e.ExceptionObject as Exception);
        System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            Helpers.CrashLog.Write("UnobservedTaskException", e.Exception);
            e.SetObserved();
        };

        var viewModel = new MainViewModel();

        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.MainWindow = new MainWindow { DataContext = viewModel };
            desktop.ShutdownRequested += (_, _) => viewModel.FlushOnExit();
        }
        else if (ApplicationLifetime is ISingleViewApplicationLifetime singleView)
        {
            // Mobile / single-view heads (e.g. Android) get the touch-friendly shell
            // (drawer nav + single tool at a time) over the same shared ViewModels.
            singleView.MainView = new MobileShellView { DataContext = viewModel };
        }

        base.OnFrameworkInitializationCompleted();
    }
}