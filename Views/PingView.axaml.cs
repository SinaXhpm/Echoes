using System;
using Avalonia.Controls;
using System.Collections.Specialized;

namespace Echoes.Views;

public partial class PingView : UserControl
{
    private ScrollViewer? _logScroll;
    private bool _follow = true;   // follow new lines while the user is at the bottom: scrolling up to read stops it

    public PingView()
    {
        InitializeComponent();

        var listBox = this.FindControl<ListBox>("LogList");
        if (listBox is not null)
        {
            listBox.TemplateApplied += (_, e) =>
            {
                if (_logScroll is not null) _logScroll.ScrollChanged -= OnLogScrolled;
                _logScroll = e.NameScope.Find<ScrollViewer>("PART_ScrollViewer");
                if (_logScroll is not null) _logScroll.ScrollChanged += OnLogScrolled;
            };
        }
        if (listBox?.Items is INotifyCollectionChanged collection)
        {
            collection.CollectionChanged += (s, e) =>
            {
                if (e.Action == NotifyCollectionChangedAction.Reset) _follow = true;   // a new run starts at its end again
                if (e.Action == NotifyCollectionChangedAction.Add && _follow)
                {
                    listBox.ScrollIntoView(listBox.Items.Count - 1);
                }
            };
        }

        // Paste-to-host and select-all-on-focus for the host box are declared in XAML via
        // helpers:InputAssist (HostPaste / SelectAllOnFocus; in TCP mode PortTarget sends a pasted port to the Port box).
        // The placeholder comes from the view-model (PingViewModel.HostPlaceholder): shorter on a phone, where the
        // narrower box (Start beside it) cut the example off mid-address ("e.g. 8").
    }

    // Only a move of the view itself decides (new lines change the extent, not the offset): back at the end, it follows again.
    private void OnLogScrolled(object? sender, ScrollChangedEventArgs e)
    {
        if (_logScroll is { } sv && Math.Abs(e.OffsetDelta.Y) > 0.01)
            _follow = sv.Offset.Y >= sv.Extent.Height - sv.Viewport.Height - 24;
    }
}
