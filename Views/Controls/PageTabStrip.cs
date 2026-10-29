using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.LogicalTree;
using Avalonia.Media;
using Avalonia.Reactive;
using CommunityToolkit.Mvvm.ComponentModel;

namespace Echoes.Views.Controls;

/// <summary>One tab of the page header's strip, mirrored from the tool's own tab item.</summary>
public sealed partial class PageTab : ObservableObject
{
    public PageTab(int index) => Index = index;

    /// <summary>The tab's position in the tool's own strip.</summary>
    public int Index { get; }

    [ObservableProperty] private string _header = string.Empty;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasIcon))] private Geometry? _icon;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasBadge))] private string _badge = string.Empty;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasBadge))] private bool _badgeShown;
    [ObservableProperty] private string? _tip;

    public bool HasIcon => Icon is not null;
    public bool HasBadge => BadgeShown && Badge.Length > 0;
}

/// <summary>
/// The page header's tab strip: the tabs of the tool's main strip (<see cref="PageTabs.Primary"/>) as icon capsules.
/// It follows the tool's strip both ways: the selected tab, tabs a platform hides (IsVisible), a disabled strip
/// (a run in progress) and the count badges in rich headers ("Monitors [3]"). With fewer than two tabs shown it hides.
/// </summary>
public sealed class PageTabStrip : ListBox
{
    public static readonly StyledProperty<SelectingItemsControl?> TargetProperty =
        AvaloniaProperty.Register<PageTabStrip, SelectingItemsControl?>(nameof(Target));

    // a tab title → its glyph (Assets/ToolIcons.axaml); the same title reads the same everywhere
    private static readonly Dictionary<string, string> Icons = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Ping"] = "IcoPing", ["Traceroute"] = "TabRoute", ["MTR"] = "TabTable", ["TCP"] = "TabPort",
        ["Lookup"] = "IcoScanner", ["Compare"] = "TabBars", ["Email check"] = "TabMail",
        ["Checks"] = "TabCheck", ["Log"] = "TabList",
        ["Setup"] = "TabSliders", ["Results"] = "TabTable", ["Report"] = "TabDoc",
        ["Monitors"] = "IcoMonitor", ["Events"] = "TabBell",
        ["Interfaces"] = "IcoNetwork", ["Wi-Fi"] = "TabWifi", ["Neighbors"] = "TabPeople", ["Ports"] = "TabPort", ["Routing"] = "TabRoute",
        ["Request"] = "TabSend", ["Response"] = "TabReceive", ["Code"] = "TabCode", ["Saved"] = "TabBookmark",
        ["Inspect"] = "IcoTls", ["Bulk check"] = "TabList",
        ["Subnet / CIDR"] = "TabGrid",
        ["Overview"] = "TabGrid", ["SSL/TLS"] = "IcoTls", ["Security"] = "TabShield", ["Settings"] = "TabSliders",
        ["DNS"] = "IcoDns", ["Analytics"] = "TabBars", ["Rules"] = "TabList", ["Cache"] = "TabBolt",
        ["Terminal"] = "IcoSsh", ["Files"] = "TabFolder", ["Forwarding"] = "IcoProxy", ["Server"] = "IcoWebServer",
        ["TCP client"] = "TabSend", ["TCP server"] = "IcoWebServer", ["UDP client"] = "IcoTelegram", ["UDP server"] = "TabInbox",
        ["WebSocket"] = "IcoSocket",
        ["Share & chat"] = "TabChat", ["Catch requests"] = "TabFunnel",
        ["Check proxies"] = "TabCheck",
        ["Encode"] = "TabKey", ["Text"] = "TabText", ["Data"] = "TabDatabase", ["Dev"] = "TabCode",
        ["History"] = "IcoHistory", ["Backup"] = "IcoBackup",
    };

    private readonly ObservableCollection<PageTab> _shown = new();
    private readonly List<(Control Item, PageTab Tab)> _all = new();
    private readonly List<IDisposable> _watches = new();
    private ShownWatch? _targetShown;   // the strip hides while its target can't be seen (a locked vault's tabs)
    private bool _syncing;

    public PageTabStrip()
    {
        Classes.Add("pageTabStrip");   // styled as a ListBox (StyleKeyOverride), so AppStyles finds it by this class
        ItemsSource = _shown;
        IsVisible = false;
        SelectionChanged += (_, _) =>
        {
            if (_syncing || SelectedItem is not PageTab tab || Target is not { } target) return;
            if (target.SelectedIndex != tab.Index) target.SelectedIndex = tab.Index;
        };
    }

    protected override Type StyleKeyOverride => typeof(ListBox);

    public SelectingItemsControl? Target
    {
        get => GetValue(TargetProperty);
        set => SetValue(TargetProperty, value);
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == TargetProperty) Attach(change.GetNewValue<SelectingItemsControl?>());
    }

    private void Attach(SelectingItemsControl? target)
    {
        _targetShown?.Dispose();
        _targetShown = null;
        foreach (var w in _watches) w.Dispose();
        _watches.Clear();
        _all.Clear();
        if (target is not null)
        {
            // watched from its container: a ListBox target is itself hidden (the pageTabs class), only its place counts
            _targetShown = new ShownWatch(target.Parent as Control ?? target);
            _targetShown.Changed += _ => Rebuild();
            int index = 0;
            foreach (object? item in target.Items)
            {
                if (item is Control c)
                {
                    var tab = new PageTab(index);
                    Describe(c, tab);
                    _all.Add((c, tab));
                    _watches.Add(Watch(c, IsVisibleProperty, Rebuild));
                }
                index++;
            }
            _watches.Add(Watch(target, SelectingItemsControl.SelectedIndexProperty, SyncSelection));
            _watches.Add(Watch(target, IsEnabledProperty, () => IsEnabled = target.IsEnabled));
            IsEnabled = target.IsEnabled;
        }
        Rebuild();
    }

    // The header text, tooltip and badge of a tab item: plain text, or the first text and the badge of a rich header.
    private void Describe(Control item, PageTab tab)
    {
        tab.Tip = ToolTip.GetTip(item) as string;
        void Read()
        {
            object? header = item is HeaderedContentControl h ? h.Header : (item as ContentControl)?.Content;
            if (header is string s)
            {
                tab.Header = s;
                return;
            }
            if (header is not Control rich) return;
            TextBlock? title = null, badge = null;
            Border? badgeBox = null;
            foreach (var node in rich.GetSelfAndLogicalDescendants())
            {
                if (node is Border b && b.Classes.Contains("badge")) badgeBox ??= b;
                else if (node is TextBlock t)
                {
                    if (badgeBox is not null && t.GetLogicalAncestors().Contains(badgeBox)) badge ??= t;
                    else title ??= t;
                }
            }
            if (title is not null)
            {
                tab.Header = title.Text ?? string.Empty;
                _watches.Add(Watch(title, TextBlock.TextProperty, () => tab.Header = title.Text ?? string.Empty));
            }
            if (badge is not null && badgeBox is not null)
            {
                void Badge()
                {
                    tab.Badge = badge.Text ?? string.Empty;
                    tab.BadgeShown = badgeBox.IsVisible;
                }
                Badge();
                _watches.Add(Watch(badge, TextBlock.TextProperty, Badge));
                _watches.Add(Watch(badgeBox, IsVisibleProperty, Badge));
            }
        }
        Read();
        tab.Icon = IconFor(tab.Header);
        var headerProperty = item is HeaderedContentControl ? HeaderedContentControl.HeaderProperty : ContentControl.ContentProperty;
        _watches.Add(Watch(item, headerProperty, () =>
        {
            Read();
            tab.Icon = IconFor(tab.Header);
        }));
    }

    private static Geometry? IconFor(string header)
        => Icons.TryGetValue(header, out string? key) && Application.Current?.TryGetResource(key, null, out object? value) == true
            ? value as Geometry : null;

    private void Rebuild()
    {
        var shown = _all.Where(a => a.Item.IsVisible).Select(a => a.Tab).ToList();
        if (!shown.SequenceEqual(_shown))
        {
            _syncing = true;
            _shown.Clear();
            foreach (var tab in shown) _shown.Add(tab);
            _syncing = false;
        }
        IsVisible = shown.Count >= 2 && _targetShown?.IsShown == true;
        SyncSelection();
    }

    private void SyncSelection()
    {
        _syncing = true;
        SelectedItem = Target is { } target ? _shown.FirstOrDefault(t => t.Index == target.SelectedIndex) : null;
        _syncing = false;
    }

    private static IDisposable Watch(AvaloniaObject o, AvaloniaProperty property, Action changed)
        => o.GetPropertyChangedObservable(property).Subscribe(new AnonymousObserver<AvaloniaPropertyChangedEventArgs>(_ => changed()));
}
