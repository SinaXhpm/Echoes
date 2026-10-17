using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using Echoes.ViewModels;
using Echoes.Views;
using System;

namespace Echoes;

public partial class App : Avalonia.Application
{
    /// <summary>
    /// Desktop-only integration — tray icon, close-to-tray, bringing the window back on request — set by the desktop
    /// head's Program.Main and run once the main window exists. This file is shared with the Android head, which doesn't
    /// compile that code (Desktop/), hence a hook. Null on Android and in the designer.
    /// </summary>
    public static Action<IClassicDesktopStyleApplicationLifetime, MainWindow, MainViewModel>? DesktopStarted { get; set; }

    /// <summary>
    /// Set by the desktop head's Program.Main for a login launch (--background, see Helpers/AutoStart): the window stays
    /// hidden in the tray (Desktop/TrayService) and monitoring starts. Never set on Android.
    /// </summary>
    public static bool StartedInBackground { get; set; }

    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        // Detect the platform BEFORE constructing the ViewModels, so any VM that reads
        // AppPlatform.IsMobile during construction observes the correct value.
        Helpers.AppPlatform.IsMobile = ApplicationLifetime is ISingleViewApplicationLifetime;

        // The saved light / dark choice, before any window or view exists (nothing opens dark and then flips).
        Helpers.ThemeService.ApplySaved();

        // Legacy code pages (windows-1252/1251/1256, shift_jis, gbk, …) aren't built into .NET; without the
        // provider Encoding.GetEncoding throws and pages declaring those charsets were decoded as UTF-8.
        System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);

        // Persist unhandled/unobserved exceptions instead of dying silently — this is a
        // diagnostic tool, so a crash the user can't see is the worst outcome.
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            Helpers.CrashLog.Write("AppDomain.UnhandledException", e.ExceptionObject as Exception);
        System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            Helpers.CrashLog.Write("UnobservedTaskException", e.Exception);
            e.SetObserved();
        };
        // Last line of defence for the UI thread: an exception escaping an event handler or an
        // async void continuation lands here. Log it and keep the app alive — one tool's failure
        // shouldn't take down a running scan, monitor or file share in another tab.
        Avalonia.Threading.Dispatcher.UIThread.UnhandledException += (_, e) =>
        {
            Helpers.CrashLog.Write("Dispatcher.UnhandledException", e.Exception);
            if (e.Exception is not OutOfMemoryException) e.Handled = true;
        };

        var viewModel = new MainViewModel();

        // Dynamic DNS (Cloudflare): keeps chosen A / AAAA records on this device's public IP, with or without the vault
        // unlocked. Returns at once; with no records to keep updated it makes no network calls.
        Helpers.DdnsService.Start();

        // Monitor: "Start monitoring when Echoes opens", and every login launch. Only then is its view-model created at
        // launch (otherwise it stays lazy until the tab is opened). Posted: it runs once the main loop is up, after the
        // window has been shown.
        if (StartedInBackground || MonitorViewModel.StartsWithApp)
        {
            Dispatcher.UIThread.Post(() =>
            {
                try { viewModel.MonitorVM.StartAtLaunch(); }
                catch (Exception ex) { Helpers.CrashLog.Write("Monitor.StartAtLaunch", ex); }
            }, DispatcherPriority.Background);
        }

        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var mainWindow = new MainWindow { DataContext = viewModel };
            desktop.MainWindow = mainWindow;
            if (OperatingSystem.IsMacOS())
            {
                // The macOS app menu: without an app-level menu Avalonia shows its own "About Avalonia" item there.
                var about = new NativeMenuItem("About Echoes");
                about.Click += (_, _) =>
                {
                    mainWindow.Show();
                    mainWindow.Activate();
                    viewModel.OpenAboutCommand.Execute(null);
                };
                NativeMenu.SetMenu(this, new NativeMenu { Items = { about } });
            }
            desktop.ShutdownRequested += (_, _) => viewModel.FlushOnExit();
            // Also on Exit: a direct Shutdown() skips ShutdownRequested. A second flush is a no-op.
            desktop.Exit += (_, _) => viewModel.FlushPersistence();
            // Optional extras: a failure there must not keep Echoes from starting.
            try { DesktopStarted?.Invoke(desktop, mainWindow, viewModel); }
            catch (Exception ex) { Helpers.CrashLog.Write("DesktopStarted", ex); }
        }
        else if (ApplicationLifetime is ISingleViewApplicationLifetime singleView)
        {
            // Mobile / single-view heads (e.g. Android) get the touch-friendly shell
            // (drawer nav + single tool at a time) over the same shared ViewModels.
            singleView.MainView = new MobileShellView { DataContext = viewModel };
        }

        // Android has no shutdown event: a backgrounded app can be killed without notice, so write pending
        // debounced edits (note text, Cloudflare profiles, ...) the moment it goes to the background.
        // (Also fires where desktop platforms support it, e.g. hiding the app on macOS — harmless.)
        if (this.TryGetFeature<IActivatableLifetime>() is { } activatable)
        {
            activatable.Deactivated += (_, e) =>
            {
                if (e.Kind != ActivationKind.Background) return;
                if (Dispatcher.UIThread.CheckAccess()) viewModel.FlushPersistence();
                else Dispatcher.UIThread.Invoke(viewModel.FlushPersistence);
            };
        }

        base.OnFrameworkInitializationCompleted();
    }
}