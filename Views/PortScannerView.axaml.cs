using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class PortScannerView : UserControl
{
    private PortScannerViewModel? _vm;

    public PortScannerView()
    {
        InitializeComponent();

        // Tunnel, so Enter is seen before the multi-line TextBox turns it into a newline. Desktop only: a phone
        // keyboard has no Shift+Enter, so there Enter stays a newline (one target per line).
        if (!Helpers.AppPlatform.IsMobile)
            ScanTargets.AddHandler(KeyDownEvent, Targets_KeyDown, RoutingStrategies.Tunnel);
        else
            ScanTargets.PlaceholderText = "IP, host, range or CIDR — one per line";

        ResultsList.KeyDown += Results_KeyDown;
        ResultsList.ContextRequested += Results_ContextRequested;
    }

    protected override void OnDataContextChanged(System.EventArgs e)
    {
        base.OnDataContextChanged(e);
        if (_vm is not null) _vm.ScanStarted -= ShowResults;
        _vm = DataContext as PortScannerViewModel;
        if (_vm is not null) _vm.ScanStarted += ShowResults;
    }

    // A scan just started: its progress and results are on the Results tab.
    private void ShowResults() => Tabs.SelectedIndex = 1;

    // Enter starts / stops the scan; Shift+Enter inserts a newline.
    private void Targets_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && e.KeyModifiers == KeyModifiers.None && _vm is not null)
        {
            _vm.ToggleScanCommand.Execute(null);
            e.Handled = true;
        }
    }

    // The selected row: Enter / Space opens a port's details, the copy shortcut copies the row (a host's address).
    private void Results_KeyDown(object? sender, KeyEventArgs e)
    {
        var item = ResultsList.SelectedItem;
        if (item is null) return;
        if (e.Key is Key.Enter or Key.Space && e.KeyModifiers == KeyModifiers.None && item is ScanPortRow port)
        {
            port.IsExpanded = !port.IsExpanded;
            e.Handled = true;
        }
        else if (e.Key == Key.C && e.KeyModifiers is KeyModifiers.Control or KeyModifiers.Meta)   // Ctrl+C, Cmd+C on a Mac
        {
            if (item is ScanPortRow p) p.CopyRowCommand.Execute(null);
            else if (item is ScanHostRow h) h.CopyAddressCommand.Execute(null);
            e.Handled = true;
        }
    }

    // The menu key (no pointer): the selected row's copy menu. Right-click / long-press reach the row itself.
    private void Results_ContextRequested(object? sender, ContextRequestedEventArgs e)
    {
        if (e.Handled || e.TryGetPosition(ResultsList, out _) || ResultsList.SelectedItem is not { } item) return;
        if (ResultsList.ContainerFromItem(item) is ListBoxItem { Presenter.Child: Controls.ScanRowLine line })
            e.Handled = line.OpenMenu();
    }

    private void ExportJson_Click(object? sender, RoutedEventArgs e) => Export("json");
    private void ExportCsv_Click(object? sender, RoutedEventArgs e) => Export("csv");
    private void ExportText_Click(object? sender, RoutedEventArgs e) => Export("txt");

    private async void Export(string format)
    {
        if (_vm is null || TopLevel.GetTopLevel(this) is not { } top) return;
        // async void: an I/O failure (disk full, read-only target, locked file) must not escape and crash the app.
        try
        {
            await _vm.ExportAsync(top.StorageProvider, format);
        }
        catch (System.Exception ex)
        {
            _vm.StatusMessage = "Export failed: " + ex.Message;
            _vm.StatusIsError = true;
        }
    }
}
