using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Threading;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class AboutView : UserControl
{
    private TopLevel? _topLevel;

    public AboutView()
    {
        InitializeComponent();
    }

    private MainViewModel? Vm => DataContext as MainViewModel;

    // A press on the backdrop (outside the card) closes the box; presses inside the card are the card's.
    protected override void OnPointerPressed(PointerPressedEventArgs e)
    {
        base.OnPointerPressed(e);
        if (ReferenceEquals(e.Source, this) && Vm is { IsAboutOpen: true } vm)
        {
            vm.IsAboutOpen = false;
            e.Handled = true;
        }
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        _topLevel = TopLevel.GetTopLevel(this);
        if (_topLevel is null) return;
        // Tunnel: Esc reaches the box before a tool's own Esc handling (cURL's search, Monitor's edit…) behind it.
        _topLevel.AddHandler(KeyDownEvent, OnTopLevelKeyDown, RoutingStrategies.Tunnel);
        _topLevel.BackRequested += OnBackRequested;
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        if (_topLevel is not null)
        {
            _topLevel.RemoveHandler(KeyDownEvent, OnTopLevelKeyDown);
            _topLevel.BackRequested -= OnBackRequested;
            _topLevel = null;
        }
        base.OnDetachedFromVisualTree(e);
    }

    // Opening moves the keyboard focus into the box (Tab then cycles inside it), so typing can't land in the tool behind.
    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == IsVisibleProperty && change.GetNewValue<bool>())
            Dispatcher.UIThread.Post(() => CloseButton.Focus(), DispatcherPriority.Background);
    }

    private void OnTopLevelKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape && Vm is { IsAboutOpen: true } vm)
        {
            vm.IsAboutOpen = false;
            e.Handled = true;
        }
    }

    // Android back closes the box instead of leaving the app.
    private void OnBackRequested(object? sender, RoutedEventArgs e)
    {
        if (Vm is { IsAboutOpen: true } vm)
        {
            vm.IsAboutOpen = false;
            e.Handled = true;
        }
    }
}
