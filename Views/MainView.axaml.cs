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

    // Refresh per-tab live data when the user switches in.
    private void OnTabSelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        // SelectionChanged is routed — ignore events bubbling up from inner ComboBox/TabControl.
        if (!ReferenceEquals(e.Source, MainTabs)) return;
        if (DataContext is not MainViewModel vm) return;

        switch (MainTabs.SelectedItem)
        {
            case TabItem { Header: "CURL" }:
                vm.CurlVM.RefreshInterfaces();
                break;
            case TabItem { Header: "HISTORY" }:
                vm.HistoryVM.Reload();
                break;
            case TabItem { Header: "WEB SERVER" }:
                vm.WebServerVM.RefreshAddressesCommand.Execute(null);
                break;
            case TabItem { Header: "PROXY" }:
                vm.ProxyVM.RefreshAddressesCommand.Execute(null);
                break;
        }
    }
}
