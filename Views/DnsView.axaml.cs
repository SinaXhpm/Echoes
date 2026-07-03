using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Echoes.Helpers;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class DnsView : UserControl
{
    public DnsView()
    {
        InitializeComponent();

        // Intercept Ctrl+V on the domain box (tunnel: before the inner TextBox pastes) and drop in
        // the bare domain/IP extracted from whatever was on the clipboard.
        var domainBox = this.FindControl<AutoCompleteBox>("DomainBox");
        domainBox?.AddHandler(KeyDownEvent, OnDomainPaste, RoutingStrategies.Tunnel);
    }

    private async void OnDomainPaste(object? sender, KeyEventArgs e)
    {
        if (e.Key != Key.V || !e.KeyModifiers.HasFlag(KeyModifiers.Control)) return;
        e.Handled = true;  // suppress the raw paste; we set the cleaned value ourselves
        string? text = await ClipboardHelper.GetTextAsync();
        if (string.IsNullOrWhiteSpace(text)) return;
        if (DataContext is DnsViewModel vm) vm.DomainName = HostExtractor.Extract(text);
    }
}
