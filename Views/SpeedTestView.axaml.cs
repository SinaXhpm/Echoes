using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Threading;
using Echoes.Helpers;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class SpeedTestView : UserControl
{
    // Below this the history card would show its header and no row: it steps aside instead (a short phone screen).
    private const double MinHistoryHeight = 72;
    private const double PickerWidth = 360;

    private SpeedTestViewModel? _vm;

    public SpeedTestView()
    {
        InitializeComponent();

        // The history takes what the rows above leave. Their heights don't depend on it, so the check can't feed back.
        StRoot.SizeChanged += (_, _) => FitHistory();
        SetupRow.SizeChanged += (_, _) => FitHistory();
        TestCard.SizeChanged += (_, _) => FitHistory();

        // A flyout hands the focus to its first focusable control as it opens: on a phone that is the search box, and
        // its keyboard would cover half the list. There it takes the focus only when tapped.
        if (AppPlatform.IsMobile)
        {
            PickSearch.Focusable = false;
            PickSearch.AddHandler(PointerPressedEvent, (_, _) =>
            {
                if (PickSearch.Focusable) return;
                PickSearch.Focusable = true;
                PickSearch.Focus();
            }, RoutingStrategies.Tunnel);
        }
    }

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);
        if (_vm is not null) _vm.PickDone -= ClosePicker;
        _vm = DataContext as SpeedTestViewModel;
        if (_vm is not null) _vm.PickDone += ClosePicker;
    }

    private void ClosePicker() => DestBtn.Flyout?.Hide();

    // The picker fits a phone (the flyout keeps a margin on both sides), and reads the nearby servers when needed.
    private void DestFlyout_Opened(object? sender, EventArgs e)
    {
        double screen = TopLevel.GetTopLevel(this)?.ClientSize.Width ?? PickerWidth + 48;
        PickPanel.Width = Math.Max(240, Math.Min(PickerWidth, screen - 48));
        PickScroll.Height = Math.Clamp((TopLevel.GetTopLevel(this)?.ClientSize.Height ?? 600) - 260, 160, 300);
        _vm?.PickerOpened();
        PickScroll.Offset = default;
        if (AppPlatform.IsDesktop) Dispatcher.UIThread.Post(() => PickSearch.Focus());
    }

    // A phone's search box goes back to waiting for a tap.
    private void DestFlyout_Closed(object? sender, EventArgs e)
    {
        if (AppPlatform.IsMobile) PickSearch.Focusable = false;
    }

    private void FitHistory()
    {
        double used = SetupRow.Bounds.Height + TestCard.Bounds.Height + StRoot.RowSpacing * 2;
        bool fits = StRoot.Bounds.Height <= 0 || StRoot.Bounds.Height - used >= MinHistoryHeight;
        if (HistCard.IsVisible != fits) HistCard.IsVisible = fits;
    }
}
