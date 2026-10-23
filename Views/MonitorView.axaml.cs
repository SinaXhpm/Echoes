using System;
using System.ComponentModel;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Threading;
using Echoes.Helpers;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class MonitorView : UserControl
{
    // Widths (of the view) where the layout changes. Below Phone: compact cards and a 4 x 2 summary; from Dock up the
    // detail panel sits beside the list (below it, it replaces the list); the summary fits one line from SummaryOneLine,
    // with the Settings label from SummaryLabel; the settings are a two-column form from SettingsForm (below it one
    // column, which takes the list's place while open) — the width the form's widest rows need, more with touch inputs.
    private const double Phone = 600, Dock = 860, SummaryOneLine = 840, SummaryLabel = 1000, DetailWidth = 332;
    private const double SettingsForm = 752, SettingsFormTouch = 820;
    // Width of the LIST where its rows switch: one line (lw) / name over chips (lm, + sparkline from RowsSpark) /
    // compact cards (lc).
    private const double RowsOneLine = 980, RowsSpark = 840, RowsTwoLines = 520;

    // Ticks only while the view is on screen: the "8s ago" ages and the detail panel's durations.
    private readonly DispatcherTimer _clock = new() { Interval = TimeSpan.FromSeconds(1) };
    private MonitorViewModel? _vm;

    public MonitorView()
    {
        InitializeComponent();
        _clock.Tick += (_, _) => { if (OnScreen()) _vm?.Tick(); };

        // Tunnel so we see Enter before the AcceptsReturn boxes turn it into a newline. Desktop only: a phone keyboard
        // has no Shift+Enter, so there Enter must stay a newline (one target per line) and the buttons add / save.
        if (!AppPlatform.IsMobile)
        {
            AddBox.AddHandler(KeyDownEvent, AddBox_KeyDown, RoutingStrategies.Tunnel);
            EditBox.AddHandler(KeyDownEvent, EditBox_KeyDown, RoutingStrategies.Tunnel);
        }
        else
        {
            AddBox.PlaceholderText = "Host or URL";   // beside Add / Edit a phone's box shows ~15 mono characters
            EditHint.IsVisible = false;
            MonRoot.Classes.Add("touch");   // row icon buttons at the touch height (Control.Height)
        }

        // One-line boxes: Enter saves the token / the monitor's checks (desktop and phone alike): their handlers are set in
        // the XAML (the settings panel and the detail card are built when first shown).

        MonRoot.SizeChanged += (_, _) => UpdateLayoutClasses();
        AddHandler(KeyDownEvent, View_KeyDown, RoutingStrategies.Bubble);
    }

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);
        if (_vm is not null) _vm.PropertyChanged -= Vm_PropertyChanged;
        _vm = DataContext as MonitorViewModel;
        if (_vm is not null) _vm.PropertyChanged += Vm_PropertyChanged;
        UpdateLayoutClasses();
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        AppPlatform.ForegroundChanged += OnForegroundChanged;
        OnForegroundChanged();
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        AppPlatform.ForegroundChanged -= OnForegroundChanged;
        _clock.Stop();
        base.OnDetachedFromVisualTree(e);
    }

    // The window hidden in the tray (monitoring goes on there) or minimized, or the phone app in the background (its
    // views stay "visible" there), keeps this view attached: the per-second refresh of every row's age stops then, and
    // coming back brings the ages up to date at once.
    private void OnForegroundChanged()
    {
        if (!AppPlatform.IsInForeground) { _clock.Stop(); return; }
        _vm?.Tick();
        _clock.Start();
    }

    private bool OnScreen() => AppPlatform.OnScreen(this);

    private void Vm_PropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MonitorViewModel.HasSelection)) UpdateLayoutClasses();
    }

    private void TgTokenBox_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && _vm is { } vm) { vm.SaveTgTokenCommand.Execute(null); e.Handled = true; }
    }

    private void KeywordBox_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && _vm is { } vm) { vm.SaveChecksCommand.Execute(null); e.Handled = true; }
    }

    // Enter adds what's typed and starts monitoring if it's stopped (an empty box just starts); Shift+Enter is a newline.
    private void AddBox_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && e.KeyModifiers == KeyModifiers.None && _vm is { } vm)
        {
            vm.SubmitAddBox();
            e.Handled = true;
        }
    }

    // Enter saves the list (and starts monitoring if it's stopped); Shift+Enter is a newline.
    private void EditBox_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && e.KeyModifiers == KeyModifiers.None && _vm is { } vm)
        {
            vm.SubmitEditList();
            e.Handled = true;
        }
    }

    // Esc leaves the list editor or the monitor's checks editor, else closes the detail panel.
    private void View_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key != Key.Escape || _vm is not { } vm) return;
        if (vm.IsEditingList) { vm.CancelEditListCommand.Execute(null); e.Handled = true; }
        else if (vm.IsEditingChecks) { vm.CancelEditChecksCommand.Execute(null); e.Handled = true; }
        else if (vm.HasSelection) { vm.CloseDetailCommand.Execute(null); e.Handled = true; }
    }

    private void UpdateLayoutClasses()
    {
        double width = MonRoot.Bounds.Width;
        if (width <= 0) return;   // not laid out yet: the XAML defaults (wide desktop) stand

        bool phone = width < Phone;
        bool selection = _vm?.HasSelection == true;
        bool docked = selection && !phone && width >= Dock;
        double listWidth = docked ? width - DetailWidth : width;

        bool oneLine = !phone && width >= SummaryOneLine;
        var c = MonRoot.Classes;
        c.Set("phone", phone);
        c.Set("sw", oneLine);
        c.Set("slabel", !phone && (!oneLine || width >= SummaryLabel));
        c.Set("docked", docked);
        c.Set("drill", selection && !docked);
        c.Set("lw", !phone && listWidth >= RowsOneLine);
        c.Set("lm", !phone && listWidth >= RowsTwoLines && listWidth < RowsOneLine);
        c.Set("ls", listWidth >= RowsSpark);
        c.Set("lc", phone || listWidth < RowsTwoLines);
        c.Set("sform", !phone && width >= (AppPlatform.IsMobile ? SettingsFormTouch : SettingsForm));
    }
}
