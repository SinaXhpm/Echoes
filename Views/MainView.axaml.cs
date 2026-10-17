using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Echoes.Helpers;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class MainView : UserControl
{
    // Page header text (bound from the shell template), taken from the selected nav entry.
    public static readonly StyledProperty<string?> PageTitleProperty =
        AvaloniaProperty.Register<MainView, string?>(nameof(PageTitle));
    public static readonly StyledProperty<string?> PageSubtitleProperty =
        AvaloniaProperty.Register<MainView, string?>(nameof(PageSubtitle));

    public string? PageTitle { get => GetValue(PageTitleProperty); set => SetValue(PageTitleProperty, value); }
    public string? PageSubtitle { get => GetValue(PageSubtitleProperty); set => SetValue(PageSubtitleProperty, value); }

    public MainView()
    {
        InitializeComponent();
        UpdatePageHeader();
        Loaded += async (s, e) =>
        {
            if (DataContext is MainViewModel vm)
            {
                await vm.CheckForUpdatesAsync();
            }
        };
    }

    private void UpdatePageHeader()
    {
        if (MainTabs?.SelectedItem is Controls.INavInfo nav)
        {
            PageTitle = nav.Title;
            PageSubtitle = nav.Subtitle;
        }
    }

    // The MainViewModel arrives after InitializeComponent (App sets it on the window), so the tab
    // auto-selected during load had no view-model to build its tool from yet — build it now.
    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);
        if (DataContext is MainViewModel vm) EnsureSelectedToolView(vm);
    }

    // Build the tool on first visit, then refresh per-tab live data when the user switches in.
    private void OnTabSelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        // SelectionChanged is routed — ignore events bubbling up from inner ComboBox/TabControl.
        if (!ReferenceEquals(e.Source, MainTabs)) return;
        UpdatePageHeader();
        if (DataContext is not MainViewModel vm) return;

        EnsureSelectedToolView(vm);
        if (MainTabs.SelectedItem is TabItem { Tag: string tool }) ToolViews.RefreshAfterRender(vm, tool, "MainView.TabRefresh");
    }

    private void EnsureSelectedToolView(MainViewModel vm)
    {
        // MainTabs is still null while InitializeComponent auto-selects the first tab.
        if (MainTabs?.SelectedItem is not TabItem { Tag: string tool } tab) return;
        if (tool == "DATA")
        {
            ToolViews.Fill(HistoryHost, "HISTORY", vm);
            ToolViews.Fill(BackupHost, "BACKUP", vm);
        }
        else if (tab.Content is Decorator host)
        {
            ToolViews.Fill(host, tool, vm);
        }
    }
}

/// <summary>
/// Builds each tool's view + view-model on first visit, for both shells (desktop tab rail and mobile
/// drawer). Declaring the views inline made XAML build all 17 tool view trees at startup (String Lab,
/// the scanner, cURL's WebView host…) plus the inline Telegram VM, just to show the first tool, and it
/// left the MainViewModel <c>??=</c> getters one binding away from running every VM constructor (the
/// Network tab's four table scans, three synchronous NIC enumerations…). Now a tool costs nothing until
/// it is opened, and its VM is created by the lazy getter at that moment.
///
/// <para>Each shell hosts a tool in an empty <see cref="Decorator"/> that stays that tab's / page's
/// content for the whole session. Once filled, the host keeps the same view instance (and the view
/// keeps its view-model), exactly as the inline views did, so switching away never resets a running
/// ping, scan, monitor or server, or any half-typed input. Deliberately not a DataTemplate: a templated
/// presenter re-creates the view on every switch (losing view state and cURL's native WebView).</para>
/// </summary>
internal static class ToolViews
{
    /// <summary>
    /// The per-visit refresh of live data, for both shells. History (cheap, skipped when nothing changed) is reloaded
    /// before the page shows. The others enumerate the network interfaces on the UI thread — tens of ms each with many
    /// (virtual) adapters, and Web Server does it two or three times — so they run once the switched-to page has been
    /// laid out and drawn (Background is below layout / render): the page appears at once, its address lists follow.
    /// </summary>
    public static void RefreshAfterRender(MainViewModel vm, string tool, string where)
    {
        if (tool == "DATA")   // merged HISTORY + BACKUP tab
        {
            Run(vm, tool, where);
            return;
        }
        if (tool is "CURL" or "WEB SERVER" or "PROXY")
            Avalonia.Threading.Dispatcher.UIThread.Post(() => Run(vm, tool, where), Avalonia.Threading.DispatcherPriority.Background);

        static void Run(MainViewModel vm, string tool, string where)
        {
            // Guarded like Fill: a VM getter that failed to construct there throws again here.
            try
            {
                switch (tool)
                {
                    case "CURL": vm.CurlVM.RefreshInterfaces(); break;
                    case "DATA": vm.HistoryVM.Reload(); break;
                    case "WEB SERVER": vm.WebServerVM.RefreshAddressesCommand.Execute(null); break;
                    case "PROXY": vm.ProxyVM.RefreshAddressesCommand.Execute(null); break;
                }
            }
            catch (Exception ex) { CrashLog.Write(where, ex); }
        }
    }

    public static void Fill(Decorator host, string tool, MainViewModel vm)
    {
        if (host.Child is not null) return;
        try
        {
            host.Child = Create(tool, vm);
        }
        catch (Exception ex)
        {
            // A throwing view-model constructor used to surface as a binding error on a blank page;
            // keep it contained to that tool instead of letting it escape a SelectionChanged handler.
            CrashLog.Write($"ToolViews.Create({tool})", ex);
            var error = new TextBlock
            {
                Text = $"{tool} failed to load: {ex.Message}",
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(16),
            };
            // the design token (Styles/Tokens.axaml), following light / dark switches
            error.Bind(TextBlock.ForegroundProperty, error.GetResourceObservable("Danger"));
            host.Child = error;
        }
    }

    // Keyed by the nav Tag shared by both shells. The VMs come from MainViewModel's lazy getters (the one
    // source of VMs); TELEGRAM BOT, SPEED TEST, TLS and SOCKET have no slot there and own their VM (the view,
    // kept by its host for the session, keeps it alive): they save each change at once (Telegram's debounced save is
    // flushed through TgViewModel.FlushAll), so MainViewModel.FlushPersistence has nothing of theirs to write.
    private static Control? Create(string tool, MainViewModel vm) => tool switch
    {
        "PING" => new PingView { DataContext = vm.PingVM },
        "DOCTOR" => new DoctorView { DataContext = vm.DoctorVM },
        "DNS" => new DnsView { DataContext = vm.DnsVM },
        "CURL" => new CurlView { DataContext = vm.CurlVM },
        "IP INFO" => new IpInfoView { DataContext = vm.IpInfoVM },
        "CHECK-HOST" => new CheckHostView { DataContext = vm.CheckHostVM },
        "CLOUDFLARE" => new CloudflareView { DataContext = vm.CloudflareVM },
        "SCANNER" => new PortScannerView { DataContext = vm.PortScannerVM },
        "WEB SERVER" => new WebServerView { DataContext = vm.WebServerVM },
        "PROXY" => new ProxyView { DataContext = vm.ProxyVM },
        "NETWORK" => new NetworkInfoView { DataContext = vm.NetworkVM },
        "MONITOR" => new MonitorView { DataContext = vm.MonitorVM },
        "SSH" => new SshView { DataContext = vm.SshVM },
        "TELEGRAM BOT" => new TgView { DataContext = new TgViewModel() },
        "SPEED TEST" => new SpeedTestView { DataContext = new SpeedTestViewModel() },
        "TLS" => new TlsView { DataContext = new TlsViewModel() },
        "SOCKET" => new SocketView { DataContext = new SocketViewModel() },
        "STRING LAB" => new StringLabView { DataContext = vm.StringTool },
        "NOTES" => new NoteView { DataContext = vm.NoteVM },
        "HISTORY" => new HistoryView { DataContext = vm.HistoryVM },
        "BACKUP" => new BackupView { DataContext = vm.BackupVM },
        _ => null,
    };
}
