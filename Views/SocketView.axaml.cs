using System;
using System.Collections.Specialized;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Echoes.Helpers;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class SocketView : UserControl
{
    private SocketViewModel? _vm;
    private ScrollViewer? _scroll;
    private bool _stick = true;       // follow new entries while the user is at the bottom
    private bool _scrollQueued;

    public SocketView()
    {
        InitializeComponent();

        // Tunnel: see Enter before the multi-line box turns it into a newline. Desktop: Enter sends, Shift+Enter is a
        // new line. Phone keyboards have no Shift+Enter, so there Enter stays a newline and the Send button sends.
        InputBox.AddHandler(KeyDownEvent, OnInputKeyDown, RoutingStrategies.Tunnel);

        // a history pick ("host:port") fills both boxes
        HostBox.DropDownClosed += (_, _) =>
        {
            if (HostBox.SelectedItem is string s && s == HostBox.Text)
                Dispatcher.UIThread.Post(() => _vm?.ApplyTarget(s), DispatcherPriority.Background);
        };
        // interfaces come and go (VPN, Wi-Fi): list the current ones whenever the picker opens
        BindBox.DropDownOpened += (_, _) => { if (_vm is { IsIdle: true }) _vm.RebuildBindOptions(); };

        TxList.TemplateApplied += (_, e) =>
        {
            if (_scroll != null) _scroll.ScrollChanged -= OnScrollChanged;
            _scroll = e.NameScope.Find<ScrollViewer>("PART_Scroll");
            if (_scroll != null) _scroll.ScrollChanged += OnScrollChanged;
            // a transcript that already has entries opens on the newest one
            if (_vm is { Entries.Count: > 0 })
                Dispatcher.UIThread.Post(() => ScrollToBottom(3), DispatcherPriority.Background);
        };
        TxList.AddHandler(ContextRequestedEvent, OnEntryContext, RoutingStrategies.Bubble);
        // back on screen after another tool: what arrived meanwhile scrolled nothing, so catch up to the end
        TxList.AttachedToVisualTree += (_, _) =>
        {
            if (_stick && _vm is { Entries.Count: > 0 }) QueueScroll();
        };

        if (AppPlatform.IsMobile)
        {
            HostBox.PlaceholderText = "Host name or IP";
            WsUrlBox.PlaceholderText = "wss://host/path";
            SkRoot.Classes.Add("touch");
        }
    }

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);
        if (_vm != null) _vm.Entries.CollectionChanged -= OnEntriesChanged;
        _vm = DataContext as SocketViewModel;
        if (_vm != null) _vm.Entries.CollectionChanged += OnEntriesChanged;
    }

    // ---------------- follow the newest entry ----------------

    private void OnScrollChanged(object? sender, ScrollChangedEventArgs e)
    {
        if (_scroll is null) return;
        // only a scroll by the user (offset moved) decides whether to keep following; growth alone doesn't
        if (Math.Abs(e.OffsetDelta.Y) > 0.01) _stick = AtBottom(_scroll);
        // growth that wasn't followed (entries that came while the list was hidden behind another sub-tab or page) is
        // caught up as soon as the list is laid out again
        else if (_stick && Math.Abs(e.ExtentDelta.Y) > 0.01 && !AtBottom(_scroll)) QueueScroll();
    }

    private static bool AtBottom(ScrollViewer sv) => sv.Offset.Y >= sv.Extent.Height - sv.Viewport.Height - 24;

    private void OnEntriesChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (e.Action == NotifyCollectionChangedAction.Reset) _stick = true;
        if (_stick) QueueScroll();
    }

    private void QueueScroll()
    {
        if (_scrollQueued) return;
        _scrollQueued = true;
        Dispatcher.UIThread.Post(() => { _scrollQueued = false; ScrollToBottom(3); }, DispatcherPriority.Background);
    }

    // the virtualizing panel estimates the extent: a second pass lands exactly on the end
    private void ScrollToBottom(int attempts)
    {
        if (_scroll is null) return;
        _scroll.ScrollToEnd();
        _stick = true;
        if (attempts > 1)
            Dispatcher.UIThread.Post(() =>
            {
                if (_scroll != null && _stick && !AtBottom(_scroll)) ScrollToBottom(attempts - 1);
            }, DispatcherPriority.Background);
    }

    // ---------------- send box keys ----------------

    private void OnInputKeyDown(object? sender, KeyEventArgs e)
    {
        if (_vm is null) return;
        if (e.Key == Key.Enter)
        {
            bool send = e.KeyModifiers == KeyModifiers.Control || (!AppPlatform.IsMobile && e.KeyModifiers == KeyModifiers.None);
            if (send)
            {
                e.Handled = true;
                if (_vm.SendCommand.CanExecute(null)) _vm.SendCommand.Execute(null);
            }
            return;
        }
        // Up / Down recall earlier messages, like a shell — unless the message has several lines (then they move the caret)
        if (e.KeyModifiers == KeyModifiers.None && e.Key is Key.Up or Key.Down)
        {
            if ((InputBox.Text ?? string.Empty).Contains('\n')) return;
            bool changed = e.Key == Key.Up ? _vm.HistoryUp() : _vm.HistoryDown();
            if (changed)
            {
                e.Handled = true;
                InputBox.CaretIndex = (InputBox.Text ?? string.Empty).Length;
            }
        }
    }

    // ---------------- save ----------------

    private async void OnSaveClick(object? sender, RoutedEventArgs e)
    {
        if (_vm is null || _vm.Entries.Count == 0) return;
        var top = TopLevel.GetTopLevel(this);
        if (top is null) return;
        try
        {
            var file = await top.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = "Save the transcript",
                SuggestedFileName = _vm.SuggestedFileName,
                DefaultExtension = "txt",
                ShowOverwritePrompt = true,
                FileTypeChoices = new[] { new FilePickerFileType("Text") { Patterns = new[] { "*.txt", "*.log" }, MimeTypes = new[] { "text/plain" } } },
            });
            if (file is null) return;
            await using (var stream = await file.OpenWriteAsync())
                await _vm.SaveTranscriptAsync(stream);
            _vm.ReportSaved(file.Name, null);
        }
        catch (Exception ex)
        {
            _vm.ReportSaved(null, ex.Message);
        }
    }

    // ---------------- one context menu for every entry ----------------

    private void OnEntryContext(object? sender, ContextRequestedEventArgs e)
    {
        if (_vm is null || (e.Source as StyledElement)?.DataContext is not SocketEntry entry) return;
        e.Handled = true;
        var vm = _vm;
        var menu = new ContextMenu();

        void Add(string header, Action action)
        {
            var item = new MenuItem { Header = header };
            item.Click += (_, _) => action();
            menu.Items.Add(item);
        }

        string? selection = (e.Source as SelectableTextBlock)?.SelectedText;
        if (!string.IsNullOrEmpty(selection)) Add("Copy selection", () => _ = ClipboardHelper.SetTextAsync(selection));
        if (entry.Data != null)
        {
            Add("Copy as text", () => _ = vm.CopyEntry(entry, "text"));
            Add("Copy hex dump", () => _ = vm.CopyEntry(entry, "hex"));
            Add("Copy as hex bytes", () => _ = vm.CopyEntry(entry, "hexstring"));
            Add("Copy as escaped string", () => _ = vm.CopyEntry(entry, "escaped"));
            if (entry.IsSent && vm.CanSend && entry.Tag is null or "text" or "bin") Add("Send again", () => _ = vm.Resend(entry));
        }
        else Add("Copy message", () => _ = vm.CopyEntry(entry, "text"));
        menu.Items.Add(new Separator());
        Add("Copy the whole transcript", () => vm.CopyTranscriptCommand.Execute(null));

        menu.Open(e.Source as Control ?? TxList);
    }
}
