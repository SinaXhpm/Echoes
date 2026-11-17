using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Echoes.ViewModels;

namespace Echoes.Views.Controls;

/// <summary>The shared response viewer (see ResponseView.axaml). It lays its response's body out when it is shown, and
/// saves the body through the platform's file picker (the desktop's dialog, Android's storage provider).</summary>
public partial class ResponseView : UserControl
{
    public ResponseView()
    {
        InitializeComponent();
    }

    private bool _shown;

    // the body is laid out once a viewer shows it, not when its response is caught
    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);
        if (_shown && DataContext is HttpResponseViewModel vm) _ = vm.LoadAsync();
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        _shown = true;
        if (DataContext is HttpResponseViewModel vm) _ = vm.LoadAsync();
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnDetachedFromVisualTree(e);
        _shown = false;
    }

    private async void OnSave(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not HttpResponseViewModel vm) return;
        try
        {
            var top = TopLevel.GetTopLevel(this);
            if (top is null) return;
            var file = await top.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = "Save the response body",
                SuggestedFileName = vm.SuggestedFileName,
                ShowOverwritePrompt = true,
            });
            if (file is null) return;
            string? error;
            await using (var stream = await file.OpenWriteAsync())
                error = await vm.SaveAsync(stream);
            vm.ReportSaved(file.Name, error);
        }
        catch (Exception ex) { vm.ReportSaved(null, ex.Message); }
    }

    /// <summary>
    /// Shows a response in a flyout over the window (opened from a row's button in Monitor, Check Host, the proxy
    /// checker or the Socket transcript): centred, as big as the window allows up to 720 × 560, with a heading. A click
    /// outside it or Esc closes it.
    /// </summary>
    public static void ShowFlyout(Control anchor, HttpResponseViewModel vm, string heading)
    {
        var top = TopLevel.GetTopLevel(anchor);
        double width = Math.Clamp((top?.Bounds.Width ?? 760) - 40, 260, 720);
        double height = Math.Clamp((top?.Bounds.Height ?? 640) - 80, 220, 560);
        var title = new TextBlock
        {
            Text = heading,
            FontWeight = FontWeight.SemiBold,
            TextTrimming = TextTrimming.CharacterEllipsis,
            Margin = new Thickness(0, 0, 0, 8),
        };
        var view = new ResponseView { DataContext = vm };
        DockPanel.SetDock(title, Dock.Top);
        var flyout = new WideFlyout
        {
            Placement = PlacementMode.Center,
            Content = new DockPanel { Width = width, Height = height, Children = { title, view } },
        };
        // over the middle of the window's page (the window itself can't be a flyout's target): a row near its bottom
        // would leave a flyout below it no room
        flyout.ShowAt(top?.Content as Control ?? anchor);
    }

    // Fluent's flyout presenter stops at 456 px wide: this one takes the size its content asks for.
    private sealed class WideFlyout : Flyout
    {
        protected override Control CreatePresenter()
        {
            var presenter = base.CreatePresenter();
            presenter.MaxWidth = double.PositiveInfinity;
            presenter.MaxHeight = double.PositiveInfinity;
            return presenter;
        }
    }
}
