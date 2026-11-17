using System;
using System.Collections.Specialized;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class CaptureView : UserControl
{
    private CaptureViewModel? _vm;
    private ScrollViewer? _scroll;
    // The table follows new packets while it shows the last one: scrolling up to read, or picking a packet, stops that;
    // back at the end it follows again.
    private bool _follow = true;

    public CaptureView()
    {
        InitializeComponent();
        PacketList.TemplateApplied += (_, e) =>
        {
            if (_scroll is not null) _scroll.ScrollChanged -= OnScrolled;
            _scroll = e.NameScope.Find<ScrollViewer>("PART_ScrollViewer");
            if (_scroll is not null) _scroll.ScrollChanged += OnScrolled;
        };
        PacketList.SelectionChanged += (_, _) => { if (PacketList.SelectedItem is not null) _follow = false; };
    }

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);
        if (_vm is not null)
        {
            _vm.Appended -= OnAppended;
            _vm.Rows.CollectionChanged -= OnRowsChanged;
        }
        _vm = DataContext as CaptureViewModel;
        if (_vm is not null)
        {
            _vm.Appended += OnAppended;
            _vm.Rows.CollectionChanged += OnRowsChanged;
        }
    }

    private void OnRowsChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        // an emptied table (a new capture, Clear) starts at its end again
        if (e.Action == NotifyCollectionChangedAction.Reset && _vm is { Rows.Count: 0 }) _follow = true;
    }

    private void OnAppended()
    {
        if (_follow && _vm is { Rows.Count: > 0 } vm) PacketList.ScrollIntoView(vm.Rows.Count - 1);
    }

    // Only a move of the view itself decides (new rows change the extent, not the offset).
    private void OnScrolled(object? sender, ScrollChangedEventArgs e)
    {
        if (_scroll is { } sv && Math.Abs(e.OffsetDelta.Y) > 0.01)
            _follow = sv.Offset.Y >= sv.Extent.Height - sv.Viewport.Height - 24;
    }

    // interfaces come and go (Wi-Fi, a VPN): the picker lists the current ones whenever it opens
    private void IfaceBox_DropDownOpened(object? sender, EventArgs e)
    {
        if (_vm is { CanChoose: true } vm) vm.Iface.Refresh();
    }

    private void CloseDetail_Click(object? sender, RoutedEventArgs e)
    {
        if (_vm is not null) _vm.Selected = null;
    }

    private async void Open_Click(object? sender, RoutedEventArgs e)
    {
        if (_vm is null || TopLevel.GetTopLevel(this) is not { } top) return;
        // async void: a failure opening the file must not escape and crash the app
        try { await _vm.OpenAsync(top.StorageProvider); }
        catch (Exception ex) { _vm.Report("Couldn't open the file: " + ex.Message); }
    }

    private void SavePcap_Click(object? sender, RoutedEventArgs e) => Save("pcap");
    private void SaveCsv_Click(object? sender, RoutedEventArgs e) => Save("csv");
    private void SaveText_Click(object? sender, RoutedEventArgs e) => Save("txt");

    private async void Save(string format)
    {
        if (_vm is null || TopLevel.GetTopLevel(this) is not { } top) return;
        // async void: an I/O failure (disk full, read-only target, locked file) must not escape and crash the app
        try { await _vm.ExportAsync(top.StorageProvider, format); }
        catch (Exception ex) { _vm.Report("Couldn't save: " + ex.Message); }
    }
}
