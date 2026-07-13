using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Echoes.Helpers;
using Echoes.ViewModels;
using System.Collections.Specialized;

namespace Echoes.Views;

public partial class PingView : UserControl
{
    public PingView()
    {
        InitializeComponent();

        var listBox = this.FindControl<ListBox>("LogList");
        if (listBox?.Items is INotifyCollectionChanged collection)
        {
            collection.CollectionChanged += (s, e) =>
            {
                if (e.Action == NotifyCollectionChangedAction.Add)
                {
                    listBox.ScrollIntoView(listBox.Items.Count - 1);
                }
            };
        }

        // Intercept Ctrl+V on the host box (tunnel: before the inner TextBox pastes) and drop in
        // the bare host extracted from whatever was on the clipboard.
        var hostBox = this.FindControl<AutoCompleteBox>("HostBox");
        hostBox?.AddHandler(KeyDownEvent, OnHostPaste, RoutingStrategies.Tunnel);
    }

    private async void OnHostPaste(object? sender, KeyEventArgs e)
    {
        if (e.Key != Key.V || !e.KeyModifiers.HasFlag(KeyModifiers.Control)) return;
        e.Handled = true;  // suppress the raw paste; we set the cleaned value ourselves
        try
        {
            string? text = await ClipboardHelper.GetTextAsync();
            if (string.IsNullOrWhiteSpace(text)) return;
            if (DataContext is PingViewModel vm) vm.TargetHost = HostExtractor.Extract(text);
        }
        catch { /* clipboard held by another process — don't crash the async void handler */ }
    }
}
