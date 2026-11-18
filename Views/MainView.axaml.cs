using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading;
using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Chrome;
using Avalonia.Controls.Primitives;
using Avalonia.Controls.Shapes;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Echoes.Helpers;
using Echoes.ViewModels;
using Echoes.Views.Controls;

namespace Echoes.Views;

/// <summary>
/// The desktop shell: a top bar of tabs, as in a browser, over the chosen tab's page. A tab is one tool, or a new tab,
/// which shows the launcher: every tool as a card with what it does, and a (!) for the details. A tool that makes sense
/// twice (Ping, DNS, cURL, SSH …, <see cref="ToolInfo.AllowsMany"/>) opens in as many tabs as you like, each with its own
/// inputs (<see cref="ToolStore"/>); the others have one tab, and opening them again goes there. Closing a tab ends what
/// runs in it (asking first while something runs). The open tabs come back at the next start, each with its inputs,
/// nothing running.
/// </summary>
public partial class MainView : UserControl
{
    public static readonly StyledProperty<bool> IsLauncherOpenProperty =
        AvaloniaProperty.Register<MainView, bool>(nameof(IsLauncherOpen));

    /// <summary>The launcher is showing: the chosen tab is a new tab.</summary>
    public bool IsLauncherOpen { get => GetValue(IsLauncherOpenProperty); set => SetValue(IsLauncherOpenProperty, value); }

    public static readonly StyledProperty<double> CaptionSpaceProperty =
        AvaloniaProperty.Register<MainView, double>(nameof(CaptionSpace), 144);

    /// <summary>The width kept free at the end of the top bar for the caption buttons Avalonia draws there (Windows,
    /// Linux); measured once the window shows (<see cref="FitCaptionSpace"/>), 144 until then (three 46 wide, 2
    /// apart, and 2 before them).</summary>
    public double CaptionSpace { get => GetValue(CaptionSpaceProperty); set => SetValue(CaptionSpaceProperty, value); }

    // profile keys: the tabs in bar order ('|'-separated: tags hold spaces; see NavTabItem.SaveKey), and the chosen one's index
    private const string TabsKey = "shell.tabs", TabKey = "shell.tab";

    // Cmd on macOS, Ctrl elsewhere: new tab, close tab
    private static readonly KeyModifiers Command = OperatingSystem.IsMacOS() ? KeyModifiers.Meta : KeyModifiers.Control;

    private long _useCounter;
    private int _nextInstance = 1;
    private bool _restored;
    private TabStripPanel? _strip;
    private MainViewModel? _vm;

    // A tool's first tab keeps its view-model (MainViewModel holds it) when it is closed; its page is kept too, and comes
    // back as it was when the tool is opened again (cURL's web view included).
    private readonly Dictionary<string, Decorator> _mainHosts = new();

    public MainView()
    {
        InitializeComponent();
        MainTabs.AddHandler(NavTabItem.CloseRequestedEvent, (_, e) => { if (e.Source is NavTabItem tab) RequestClose(tab); });
        MainTabs.TemplateApplied += (_, e) =>
        {
            if (e.NameScope.Find<Button>("PART_NewTab") is { } plus)
            {
                plus.Click += (_, _) => NewTab();
                ToolTip.SetTip(plus, "New tab (" + (Command == KeyModifiers.Meta ? "⌘T" : "Ctrl+T") + ")");
            }
            if (e.NameScope.Find<Button>("PART_TabList") is { } list)
            {
                _tabList = list;
                list.Click += (_, _) => ShowTabList(list);
            }
            if (e.NameScope.Find<Button>("PART_ScrollBack") is { } back)
            {
                _scrollBack = back;
                back.Click += (_, _) => _strip?.ScrollPage(-1);
            }
            if (e.NameScope.Find<Button>("PART_ScrollForward") is { } forward)
            {
                _scrollForward = forward;
                forward.Click += (_, _) => _strip?.ScrollPage(1);
            }
            FitTabList();
        };
        // (the shell's own keys are watched on the window: OnAttachedToVisualTree)
        // The search box: Enter, Escape and Down are its own before they are the text box's (Tunnel). The cards' arrow keys
        // and typing are watched on their panel, inside the scroller (which takes the arrows for itself otherwise).
        LauncherSearch.AddHandler(KeyDownEvent, OnSearchKeyDown, RoutingStrategies.Tunnel);
        LauncherSearch.PropertyChanged += (_, e) => { if (e.Property == TextBox.TextProperty) FilterLauncher(); };
        LauncherStack.AddHandler(KeyDownEvent, OnCardKeyDown);
        LauncherStack.AddHandler(TextInputEvent, OnCardTextInput);
        RestoreTabs();
        LauncherScroll.SizeChanged += (_, _) => LayoutLauncher();
        Loaded += async (s, e) =>
        {
            if (_strip is null && MainTabs.ItemsPanelRoot is TabStripPanel strip)
            {
                _strip = strip;
                strip.ScrollChanged += (_, _) => FitTabList();
                strip.Reordered += (dragged, at) => { if (dragged is NavTabItem tab) MoveTab(tab, at); };
                FitTabList();
            }
            RevealSelected();
            FitCaptionSpace();
            FocusSearch();
            if (DataContext is MainViewModel vm)
            {
                await vm.CheckForUpdatesIfStale();
            }
        };
    }

    // The caption buttons are drawn by Avalonia over the end of the bar, each marked with its role (as tall as the bar,
    // in one row with About and the theme switch: MainWindow, the CaptionButton* keys). With no maximize (MainWindow),
    // the full-screen one is only a greyed-out button, so it goes; the bar then keeps exactly the width the others take,
    // whatever the theme or scale, and 2 more, the gap the caption buttons have between them, so the row runs on evenly
    // from the theme switch. None found (macOS's native traffic lights, a headless run): the defaults stay.
    private void FitCaptionSpace()
    {
        if (TopLevel.GetTopLevel(this) is not Window window) return;
        Visual root = window;
        while (root.GetVisualParent() is { } up) root = up;
        double left = double.PositiveInfinity;
        bool hid = false;
        foreach (var v in root.GetVisualDescendants())
        {
            var role = WindowDecorationProperties.GetElementRole(v);
            if (role == WindowDecorationsElementRole.FullScreenButton && !window.CanMaximize && v is Control fullScreen)
            {
                hid |= fullScreen.IsVisible;
                fullScreen.IsVisible = false;   // its stack is right-aligned: the others keep their places
                continue;
            }
            if (role is WindowDecorationsElementRole.CloseButton or WindowDecorationsElementRole.MinimizeButton
                    or WindowDecorationsElementRole.MaximizeButton or WindowDecorationsElementRole.FullScreenButton
                && v.IsEffectivelyVisible && v.TranslatePoint(default, window) is { } at)
                left = Math.Min(left, at.X);
        }
        if (!double.IsInfinity(left) && left > 0 && left < window.Bounds.Width)
            CaptionSpace = window.Bounds.Width - left + 2;
        // ... to the device pixel, though: their stack, a button shorter, is laid out again, and may round a pixel the
        // other way. Measured again once it has been.
        if (hid) Dispatcher.UIThread.Post(FitCaptionSpace, DispatcherPriority.Background);
    }

    private IEnumerable<NavTabItem> Tabs => MainTabs.Items.OfType<NavTabItem>();

    private NavTabItem? Current => MainTabs.SelectedItem as NavTabItem;

    private static Geometry? Glyph(string key)
        => Application.Current is { } app && app.TryGetResource(key, null, out var value) ? value as Geometry : null;

    // ---- tabs ----

    private NavTabItem MakeTab(ToolInfo? tool, int instanceId)
    {
        var store = tool is null ? null : ToolStore.ForTab(instanceId);
        var tab = new NavTabItem(tool, instanceId, store) { Glyph = Glyph(tool?.IconKey ?? "IcoTools") };
        if (tool is not null && instanceId == 0 && _mainHosts.Remove(tool.Tag, out var host)) tab.Content = host;
        if (tool?.SubjectKey is { } key && store is not null)
        {
            // what the tab works on follows its last input ("Ping · 1.1.1.1"); the store may raise it off the UI thread
            tab.SubjectWatch = changed => { if (changed == key) Dispatcher.UIThread.Post(() => Label(tab)); };
            store.LastChanged += tab.SubjectWatch;
        }
        tab.ContextRequested += OnTabContextRequested;
        tab.StateChanged += OnTabStateChanged;
        Label(tab);
        return tab;
    }

    // what runs in a tab changed: the launcher's dot for its tool follows
    private void OnTabStateChanged(object? sender, EventArgs e) => MarkLauncher();

    // "Ping", or "Ping · 1.1.1.1" once it has worked on something; the tooltip says it in full.
    private static void Label(NavTabItem tab)
    {
        if (tab.Tool is not { } tool)
        {
            tab.Header = "New tab";
            tab.Tip = "Pick a tool";
            AutomationProperties.SetName(tab, "New tab");
            return;
        }
        string? subject = tool.SubjectKey is { } key ? tab.Store?.PeekLast(key) : null;
        string? shown = Short(subject);
        string header = shown is null ? tool.Header : tool.Header + " · " + shown;
        tab.Header = header;
        tab.Tip = subject is { Length: > 0 } ? tool.Title + ": " + subject.Trim() : tool.Title + ": " + tool.Summary;
        AutomationProperties.SetName(tab, header);
    }

    // A URL shows its host, a pasted list its first line, anything long its start.
    private static string? Short(string? subject)
    {
        if (string.IsNullOrWhiteSpace(subject)) return null;
        string s = subject.Trim();
        int line = s.IndexOfAny(new[] { '\r', '\n' });
        if (line >= 0) s = s[..line].TrimEnd() + " …";
        else if (s.Contains("://", StringComparison.Ordinal) && Uri.TryCreate(s, UriKind.Absolute, out var uri) && uri.Host.Length > 0)
            s = uri.Host;
        return s.Length > 26 ? s[..25] + "…" : s;
    }

    private void RestoreTabs()
    {
        var profile = ProfileService.Instance;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in (profile.GetSetting(TabsKey) ?? "").Split('|', StringSplitOptions.RemoveEmptyEntries))
        {
            if (entry == NavTabItem.NewTabKey) { MainTabs.Items.Add(MakeTab(null, 0)); continue; }
            if (!seen.Add(entry)) continue;
            int hash = entry.IndexOf('#');
            if (ToolCatalog.Find(hash < 0 ? entry : entry[..hash]) is not { } tool) continue;
            int id = 0;
            if (hash >= 0 && (!tool.AllowsMany
                              || !int.TryParse(entry.AsSpan(hash + 1), NumberStyles.None, CultureInfo.InvariantCulture, out id)
                              || id <= 0))
                continue;
            MainTabs.Items.Add(MakeTab(tool, id));
            _nextInstance = Math.Max(_nextInstance, id + 1);
        }
        // the copies of tabs that aren't open any more (a crash between closing one and saving the list)
        ToolStore.RemoveOrphans(Tabs.Where(t => t.InstanceId > 0).Select(t => t.InstanceId).ToList());
        if (MainTabs.ItemCount == 0) MainTabs.Items.Add(MakeTab(null, 0));

        var tabs = Tabs.ToList();
        string? chosen = profile.GetSetting(TabKey);
        var pick = int.TryParse(chosen, NumberStyles.None, CultureInfo.InvariantCulture, out int at) && at < tabs.Count
            ? tabs[at]
            : tabs.FirstOrDefault(t => t.SaveKey == chosen) ?? tabs[0];   // an earlier build saved the tool's tag
        pick.LastUsed = ++_useCounter;
        MainTabs.SelectedItem = pick;   // its page is built once the view-model is here (OnDataContextChanged)
        IsLauncherOpen = pick.IsNewTab;
        _restored = true;
    }

    private void SaveTabs()
    {
        if (!_restored) return;
        var tabs = Tabs.ToList();
        string list = string.Join('|', tabs.Select(t => t.SaveKey));
        string chosen = Math.Max(0, Current is { } cur ? tabs.IndexOf(cur) : 0).ToString(CultureInfo.InvariantCulture);
        var profile = ProfileService.Instance;
        // the profile writes on any set: only when something really changed
        if (profile.GetSetting(TabsKey) != list || profile.GetSetting(TabKey) != chosen)
            profile.SetMany((TabsKey, list), (TabKey, chosen));
    }

    private void NewTab()
    {
        var tab = MakeTab(null, 0);
        MainTabs.Items.Add(tab);
        MainTabs.SelectedItem = tab;
    }

    /// <summary>Opens a tool as a hand-off or a script does: its most recently used tab, or a new one.</summary>
    public void OpenTool(string tag)
    {
        if (ToolCatalog.Find(tag) is { } tool) ShowTool(tool, null);
    }

    // A card in the launcher: the tool opens in the new tab it was picked in, ready to type in.
    private void OpenFromLauncher(ToolInfo tool)
    {
        var tab = TabFor(tool, reuseOpen: false);
        Place(tab, Current is { IsNewTab: true } blank ? blank : null);
        FocusPage(tab);
    }

    // A tool picked in the launcher is about to be used: its first field takes the keys (Ping's host, DNS's domain, the
    // scanner's targets), so search, Enter, an address, Enter runs it without the mouse. Focused as Tab would, which
    // selects what the field still holds from last time: typing replaces it, Enter runs it again. Posted: the page is
    // built and laid out first. A number spinner is a setting, not what the tool works on, so it doesn't count, and a
    // tool with no field to type in (Network, Device, Speed Test) is left as it is.
    private void FocusPage(NavTabItem tab)
    {
        Dispatcher.UIThread.Post(() =>
        {
            if (!ReferenceEquals(Current, tab) || IsAboutOpen() || tab.Content is not Decorator host) return;
            var field = ToolViews.ViewIn(host)?.GetVisualDescendants().OfType<TextBox>()
                .FirstOrDefault(box => box.IsEffectivelyVisible && box.IsEffectivelyEnabled && box.Focusable && !box.IsReadOnly
                                       && box.FindAncestorOfType<NumericUpDown>() is null);
            field?.Focus(NavigationMethod.Tab);
        }, DispatcherPriority.Background);
    }

    private void ShowTool(ToolInfo tool, Action<object>? apply)
    {
        var tab = TabFor(tool, reuseOpen: true);
        Place(tab, Current is { IsNewTab: true } blank ? blank : null);
        if (apply is null || _vm is null) return;
        BuildPage(tab, _vm);
        if (tab.ViewModel is { } model) apply(model);
    }

    // The tab a tool opens in: its first tab when that isn't open; else the open one (a hand-off, or a tool with one tab);
    // else a further tab, starting with its main input empty.
    private NavTabItem TabFor(ToolInfo tool, bool reuseOpen)
    {
        var open = Tabs.Where(t => t.Tool?.Tag == tool.Tag).ToList();
        if (open.Count > 0 && (reuseOpen || !tool.AllowsMany)) return open.MaxBy(t => t.LastUsed)!;
        if (!open.Any(t => t.InstanceId == 0)) return MakeTab(tool, 0);
        var tab = MakeTab(tool, _nextInstance++);
        if (tool.SubjectKey is { } key) tab.Store!.StartFresh(key);
        Label(tab);
        return tab;
    }

    // Shows a tab: one in the bar already is chosen; a new one takes the place of the new tab it was picked from, or goes
    // after the chosen tab (at the end when not chosen). The new tab it was picked from goes either way.
    private void Place(NavTabItem tab, NavTabItem? replacing, bool select = true)
    {
        var items = MainTabs.Items;
        if (!items.Contains(tab))
        {
            int at = replacing is not null ? items.IndexOf(replacing)
                   : select && Current is { } cur ? items.IndexOf(cur) + 1
                   : items.Count;
            items.Insert(Math.Clamp(at, 0, items.Count), tab);
        }
        if (select) MainTabs.SelectedItem = tab;
        if (replacing is not null && !ReferenceEquals(replacing, tab)) items.Remove(replacing);
        SaveTabs();
        MarkLauncher();
    }

    // A tool started by itself (the Monitor at launch) gets a tab if it has none: closing that tab is how it stops. The tab
    // goes at the end, not chosen (its dot says it runs): the app still opens on the page it would have, the tools to
    // pick from when no tabs were saved.
    private void ShowStarted(ToolInfo tool)
    {
        if (Tabs.Any(t => t.Tool?.Tag == tool.Tag)) return;
        var tab = MakeTab(tool, 0);
        tab.ViewModel = _vm?.MainTool(tool.Tag);   // it runs already: closing the tab asks first
        Place(tab, null, select: false);
    }

    private void Duplicate(NavTabItem source)
    {
        if (source.Tool is not { AllowsMany: true } tool || source.Store is null) return;
        // what the source has typed but not yet written goes into the copy too
        try { (source.ViewModel as IPendingSave)?.FlushPendingSave(); }
        catch (Exception ex) { CrashLog.Write("MainView.Duplicate", ex); }
        var tab = MakeTab(tool, _nextInstance++);
        tab.Store!.CopyFrom(source.Store, tool.SubjectKey);
        Label(tab);
        MainTabs.Items.Insert(MainTabs.Items.IndexOf(source) + 1, tab);
        MainTabs.SelectedItem = tab;
    }

    // A tab goes to another place in the bar (dragged there, or Ctrl+Shift+PageUp / PageDown). The chosen tab itself
    // stays where the tab control has it and the tabs it passes are moved around it, one by one: taking the chosen tab
    // out of the bar would take its page off the screen for a moment, and the keyboard focus out of its fields.
    private void MoveTab(NavTabItem tab, int to)
    {
        var items = MainTabs.Items;
        int from = items.IndexOf(tab);
        to = Math.Clamp(to, 0, items.Count - 1);
        if (from < 0 || from == to) return;
        if (!ReferenceEquals(Current, tab))
        {
            items.RemoveAt(from);
            items.Insert(to, tab);
        }
        else
        {
            for (int at = from; at != to;)
            {
                int beside = to > at ? at + 1 : at - 1;
                var passed = items[beside];
                items.RemoveAt(beside);
                items.Insert(at, passed);   // on the other side of the tab now
                at = beside;
            }
        }
        SaveTabs();
        RevealSelected();
    }

    private void RequestClose(NavTabItem tab) => RequestClose(new[] { tab }, tab);

    // Closing ends what the tabs run: while something runs, a confirmation on the tab comes first.
    private void RequestClose(IReadOnlyList<NavTabItem> tabs, NavTabItem anchor)
    {
        if (tabs.Count == 0) return;
        var busy = tabs.Where(t => t.ViewModel is IToolSession { IsBusy: true }).ToList();
        if (busy.Count == 0)
        {
            CloseTabs(tabs);
            return;
        }
        string text = busy.Count == 1
            ? busy[0].Tool!.Title + " is running. Stop it and close" + (tabs.Count > 1 ? " the tabs?" : "?")
            : busy.Count + " tabs are running. Stop them and close?";
        var at = busy.Count == 1 && tabs.Count == 1 ? busy[0] : anchor;
        if (!ReferenceEquals(Current, at) && at.IsEffectivelyVisible) _strip?.Reveal(at);
        Confirm(at, text, "Stop and close", () => CloseTabs(tabs));
    }

    private void CloseTabs(IReadOnlyList<NavTabItem> closing)
    {
        var items = MainTabs.Items;
        var all = Tabs.ToList();
        if (Current is { } cur && closing.Contains(cur))
        {
            // the chosen tab goes: the next one that stays, else the nearest on its left, else a new tab
            int at = all.IndexOf(cur);
            var next = all.Skip(at + 1).FirstOrDefault(t => !closing.Contains(t))
                       ?? all.Take(at).LastOrDefault(t => !closing.Contains(t));
            if (next is null)
            {
                next = MakeTab(null, 0);
                items.Add(next);
            }
            MainTabs.SelectedItem = next;
        }
        foreach (var tab in closing)
        {
            if (!items.Contains(tab)) continue;
            End(tab);
            items.Remove(tab);
        }
        SaveTabs();
        MarkLauncher();
    }

    // A tab goes: what it runs stops. A further tab's view-model and settings go with it; a first tab's stay (the tool's
    // inputs for next time), and its page is kept for when the tool is opened again.
    private void End(NavTabItem tab)
    {
        if (tab.SubjectWatch is { } watch && tab.Store is { } store) store.LastChanged -= watch;
        tab.ContextRequested -= OnTabContextRequested;
        tab.StateChanged -= OnTabStateChanged;
        var model = tab.ViewModel;
        try { (model as IToolSession)?.EndSession(); }
        catch (Exception ex) { CrashLog.Write("MainView.CloseTab", ex); }
        // the tab stops watching its view-model (a first tab's lives on in MainViewModel, and would keep the tab alive)
        tab.ViewModel = null;
        if (tab.Tool is not { } tool) return;
        if (tab.InstanceId == 0)
        {
            if (tab.Content is Decorator host)
            {
                tab.Content = null;
                _mainHosts[tool.Tag] = host;
            }
            return;
        }
        if (model is not null)
        {
            _vm?.UntrackTool(model);
            (model as CurlViewModel)?.DetachLibrary();
        }
        tab.Content = null;
        tab.Store?.Clear();
    }

    private void Confirm(Control anchor, string text, string action, Action run)
    {
        var flyout = new Flyout { Placement = PlacementMode.BottomEdgeAlignedLeft };
        var yes = new Button { Content = action };
        yes.Classes.Add("primary");
        var no = new Button { Content = "Cancel" };
        no.Classes.Add("secondary");
        yes.Click += (_, _) => { flyout.Hide(); run(); };
        no.Click += (_, _) => flyout.Hide();
        var message = new TextBlock { Text = text };
        message.Classes.Add("infoPoint");
        flyout.Content = new StackPanel
        {
            Spacing = 10,
            MaxWidth = 260,
            Children =
            {
                message,
                new StackPanel
                {
                    Orientation = Orientation.Horizontal, Spacing = 8, HorizontalAlignment = HorizontalAlignment.Right,
                    Children = { no, yes },
                },
            },
        };
        flyout.ShowAt(anchor);
        Dispatcher.UIThread.Post(() => yes.Focus(), DispatcherPriority.Input);
    }

    private void OnTabContextRequested(object? sender, ContextRequestedEventArgs e)
    {
        if (sender is not NavTabItem tab) return;
        e.Handled = true;
        var others = Tabs.Where(t => !ReferenceEquals(t, tab)).ToList();
        var menu = new ContextMenu();
        menu.Items.Add(MenuEntry("New tab", new KeyGesture(Key.T, Command), NewTab));
        if (tab.Tool is { AllowsMany: true }) menu.Items.Add(MenuEntry("Duplicate", null, () => Duplicate(tab)));
        menu.Items.Add(new Separator());
        menu.Items.Add(MenuEntry("Close", new KeyGesture(Key.W, Command), () => RequestClose(tab)));
        var closeOthers = MenuEntry("Close other tabs", null, () => RequestClose(others, tab));
        closeOthers.IsEnabled = others.Count > 0;
        menu.Items.Add(closeOthers);
        var all = Tabs.ToList();
        var after = all.Skip(all.IndexOf(tab) + 1).ToList();
        var closeAfter = MenuEntry("Close tabs to the right", null, () => RequestClose(after, tab));
        closeAfter.IsEnabled = after.Count > 0;
        menu.Items.Add(closeAfter);
        menu.Open(tab);
    }

    private static MenuItem MenuEntry(string header, KeyGesture? gesture, Action run)
    {
        var item = new MenuItem { Header = header, InputGesture = gesture };
        item.Click += (_, _) => run();
        return item;
    }

    // ---- the list of all tabs ----

    private Button? _tabList, _scrollBack, _scrollForward;

    // While the row scrolls (some tabs are out of the bar, the others a few letters wide): the < and > at its ends, each
    // greyed once the row has reached that end, and the button after + that lists every tab. Both arrows stay while it
    // scrolls, so the row doesn't change width, and a click doesn't land somewhere else, as it reaches an end.
    private void FitTabList()
    {
        bool scrolls = _strip?.IsOverflowing == true;
        if (_tabList is not null) _tabList.IsVisible = scrolls;
        if (_scrollBack is not null)
        {
            _scrollBack.IsVisible = scrolls;
            _scrollBack.IsEnabled = _strip?.CanScrollBack == true;
        }
        if (_scrollForward is not null)
        {
            _scrollForward.IsVisible = scrolls;
            _scrollForward.IsEnabled = _strip?.CanScrollForward == true;
        }
    }

    // Every tab in bar order, by its glyph and whole label; the chosen one in the accent. Picking one goes there (the bar
    // scrolls to it). The first eight carry their Ctrl+1 … Ctrl+8, the last one Ctrl+9.
    private void ShowTabList(Control anchor)
    {
        var tabs = Tabs.ToList();
        var menu = new ContextMenu { Placement = PlacementMode.BottomEdgeAlignedLeft };
        for (int i = 0; i < tabs.Count; i++)
        {
            var tab = tabs[i];
            var glyph = new Avalonia.Controls.Shapes.Path { Data = tab.Glyph, StrokeThickness = 2.3 };
            glyph.Classes.Add("ico");
            KeyGesture? gesture = i < 8 ? new KeyGesture(Key.D1 + i, Command)
                : i == tabs.Count - 1 ? new KeyGesture(Key.D9, Command) : null;
            var item = MenuEntry(tab.Header as string ?? string.Empty, gesture, () => MainTabs.SelectedItem = tab);
            item.Icon = glyph;
            if (ReferenceEquals(tab, Current))
            {
                glyph.Bind(Shape.StrokeProperty, glyph.GetResourceObservable("Accent.Text"));
                item.Bind(TemplatedControl.ForegroundProperty, item.GetResourceObservable("Accent.Text"));
            }
            menu.Items.Add(item);
        }
        menu.Open(anchor);
    }

    private void RevealSelected()
    {
        if (_strip is not null && Current is { } tab) _strip.Reveal(tab);
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property != IsLauncherOpenProperty || !change.GetNewValue<bool>()) return;
        BuildLauncher();
        MarkLauncher();
        LauncherSearch.Text = string.Empty;   // a new tab starts with every tool showing
        FocusSearch();
    }

    // The shell's keys are watched on the window, not on this view: while nothing has the keyboard focus (a tool just
    // opened from the launcher, whose card went with it; a restored tab at start, before a click) a key is raised on the
    // window itself and never passes through the view, and Ctrl+T, Ctrl+W and the rest did nothing.
    private TopLevel? _keysFrom;

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        _keysFrom = TopLevel.GetTopLevel(this);
        _keysFrom?.AddHandler(KeyDownEvent, OnShellKeyDown);
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        _keysFrom?.RemoveHandler(KeyDownEvent, OnShellKeyDown);
        _keysFrom = null;
        base.OnDetachedFromVisualTree(e);
    }

    // Ctrl+T (⌘T) a new tab, Ctrl+W (⌘W) closes the chosen one, Ctrl+Tab / Ctrl+Shift+Tab walk the tabs in bar order,
    // Ctrl+1 … Ctrl+8 (⌘1 …) go to that tab and Ctrl+9 to the last one, Ctrl+Shift+PageUp / PageDown move the chosen tab
    // one place left / right, as in a browser; Escape on a new tab goes back to the tab before it. Not inside the SSH
    // terminal, where a shell uses those keys (the terminal pane only: from the SSH tool's host, user and other fields
    // they work as anywhere).
    private void OnShellKeyDown(object? sender, KeyEventArgs e)
    {
        if (IsAboutOpen()) return;
        bool inTerminal = e.Source is Visual source
                          && source.FindAncestorOfType<SshView>(includeSelf: true) is { } ssh && ssh.IsTerminal(source);
        if (e.Key == Key.Escape && Current is { IsNewTab: true } blank && MainTabs.ItemCount > 1)
        {
            var back = Tabs.Where(t => !ReferenceEquals(t, blank)).MaxBy(t => t.LastUsed);
            MainTabs.SelectedItem = back;
            MainTabs.Items.Remove(blank);
            SaveTabs();
            e.Handled = true;
        }
        else if (e.KeyModifiers == Command && e.Key == Key.T && !inTerminal)
        {
            NewTab();
            e.Handled = true;
        }
        else if (e.KeyModifiers == Command && e.Key == Key.W && !inTerminal)
        {
            if (Current is { } tab) RequestClose(tab);
            e.Handled = true;
        }
        else if (e.KeyModifiers == Command && e.Key is >= Key.D1 and <= Key.D9 && !inTerminal)
        {
            var tabs = Tabs.ToList();
            int at = e.Key == Key.D9 ? tabs.Count - 1 : e.Key - Key.D1;
            if (at < tabs.Count) MainTabs.SelectedItem = tabs[at];
            e.Handled = true;
        }
        else if (e.KeyModifiers == (Command | KeyModifiers.Shift) && e.Key is (Key.PageUp or Key.PageDown) && !inTerminal)
        {
            if (Current is { } tab) MoveTab(tab, MainTabs.Items.IndexOf(tab) + (e.Key == Key.PageUp ? -1 : 1));
            e.Handled = true;
        }
        else if (e.Key == Key.Tab && e.KeyModifiers.HasFlag(KeyModifiers.Control))
        {
            var tabs = Tabs.ToList();
            if (tabs.Count < 2) return;
            int at = Current is { } cur ? tabs.IndexOf(cur) : -1;
            int step = e.KeyModifiers.HasFlag(KeyModifiers.Shift) ? -1 : 1;
            MainTabs.SelectedItem = tabs[((at < 0 ? 0 : at + step) % tabs.Count + tabs.Count) % tabs.Count];
            e.Handled = true;
        }
    }

    private bool IsAboutOpen() => DataContext is MainViewModel { IsAboutOpen: true };

    // ---- launcher ----

    private readonly List<(ToolInfo Tool, Panel Tile)> _tiles = new();
    private readonly List<(TextBlock Heading, List<Panel> Tiles)> _groups = new();
    private ToolInfo? _bestMatch;

    // A heading and its cards per group, in catalog order, built the first time a new tab shows; LauncherPanel lays them
    // out.
    private void BuildLauncher()
    {
        if (_tiles.Count > 0) return;
        List<Panel>? tiles = null;
        string? group = null;
        foreach (var tool in ToolCatalog.All)
        {
            if (tiles is null || tool.Group != group)
            {
                group = tool.Group;
                var heading = new TextBlock { Text = group };
                heading.Classes.Add("launchGroup");
                LauncherStack.Children.Add(heading);
                _groups.Add((heading, tiles = new List<Panel>()));
            }
            var tile = MakeTile(tool);
            LauncherStack.Children.Add(tile);
            tiles.Add(tile);
            _tiles.Add((tool, tile));
        }
        LayoutLauncher();
    }

    // The cards fill the height the launcher has below its search box, when they fit in it with room to spare.
    private void LayoutLauncher()
    {
        double height = LauncherScroll.Bounds.Height;
        LauncherStack.FitHeight = height > 0 ? Math.Max(0, height - 10) : double.PositiveInfinity;
    }

    private Panel MakeTile(ToolInfo tool)
    {
        var glyph = new Avalonia.Controls.Shapes.Path { Data = Glyph(tool.IconKey) };
        glyph.Classes.Add("ico");
        var badge = new Border { Child = glyph, VerticalAlignment = VerticalAlignment.Center };
        badge.Classes.Add("launchBadge");
        badge.Classes.Add(HueOf(tool));
        var name = new TextBlock { Text = tool.Title };
        name.Classes.Add("launchTitle");
        var line = new TextBlock { Text = tool.Summary };
        line.Classes.Add("launchSummary");
        var text = new StackPanel { VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(10, 0, 0, 0), Children = { name, line } };
        Grid.SetColumn(text, 1);
        var row = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*"), Children = { badge, text } };

        var card = new Button { Content = row };
        card.Classes.Add("launchCard");
        AutomationProperties.SetName(card, tool.Title);
        AutomationProperties.SetHelpText(card, tool.Summary);
        card.Click += (_, _) => OpenFromLauncher(tool);

        var info = new Button { Content = "!" };
        info.Classes.Add("launchInfo");
        ToolTip.SetTip(info, "About " + tool.Title);
        AutomationProperties.SetName(info, "About " + tool.Title);
        info.Click += (_, _) => ShowDetails(tool, info);

        var dot = new Ellipse();
        dot.Classes.Add("launchDot");

        var tile = new Panel { Children = { card, info, dot } };
        tile.Classes.Add("launchTile");
        return tile;
    }

    // The (!) popover: what the tool does, its main features, what it is like, how its tabs work, and Open.
    private void ShowDetails(ToolInfo tool, Control anchor)
    {
        var glyph = new Avalonia.Controls.Shapes.Path { Data = Glyph(tool.IconKey) };
        glyph.Classes.Add("ico");
        var badge = new Border { Child = glyph, VerticalAlignment = VerticalAlignment.Center };
        badge.Classes.Add("launchBadge");
        badge.Classes.Add(HueOf(tool));
        var title = new TextBlock { Text = tool.Title };
        title.Classes.Add("infoTitle");
        var summary = new TextBlock { Text = tool.Summary };
        summary.Classes.Add("infoMuted");
        var names = new StackPanel { Margin = new Thickness(10, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center, Children = { title, summary } };
        Grid.SetColumn(names, 1);
        var head = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*"), Children = { badge, names } };

        var points = new StackPanel { Spacing = 5 };
        foreach (var detail in tool.Details)
        {
            var mark = new TextBlock { Text = "•" };
            mark.Classes.Add("infoPoint");
            var said = new TextBlock { Text = detail };
            said.Classes.Add("infoPoint");
            Grid.SetColumn(said, 1);
            points.Children.Add(new Grid { ColumnDefinitions = new ColumnDefinitions("14,*"), Children = { mark, said } });
        }

        var panel = new StackPanel { Spacing = 10, Width = 300, Children = { head, points } };
        if (tool.SimilarTo is { } similar) panel.Children.Add(Muted("Similar to " + similar));
        panel.Children.Add(Muted(tool.AllowsMany
            ? "Opens in as many tabs as you like, each with its own inputs."
            : "Has one tab: opening it again goes there."));
        var open = new Button { Content = "Open", HorizontalAlignment = HorizontalAlignment.Right };
        open.Classes.Add("primary");
        panel.Children.Add(open);

        var flyout = new Flyout { Content = panel, Placement = PlacementMode.BottomEdgeAlignedRight };
        open.Click += (_, _) =>
        {
            flyout.Hide();
            OpenFromLauncher(tool);
        };
        flyout.ShowAt(anchor);

        static TextBlock Muted(string text)
        {
            var block = new TextBlock { Text = text };
            block.Classes.Add("infoMuted");
            return block;
        }
    }

    // Tools with a tab carry a dot, in the color of what runs in their tabs (the most pressing one: down, then waiting,
    // then running) as the tabs show it.
    private void MarkLauncher()
    {
        if (_tiles.Count == 0) return;
        var open = new Dictionary<string, ToolState>(StringComparer.Ordinal);
        foreach (var tab in Tabs)
        {
            if (tab.Tool is not { } tool) continue;
            open[tool.Tag] = open.TryGetValue(tool.Tag, out var other) && other > tab.State ? other : tab.State;
        }
        foreach (var (tool, tile) in _tiles)
        {
            bool has = open.TryGetValue(tool.Tag, out var state);
            tile.Classes.Set("open", has);
            tile.Classes.Set("running", has && state == ToolState.Running);
            tile.Classes.Set("waiting", has && state == ToolState.Waiting);
            tile.Classes.Set("down", has && state == ToolState.Down);
        }
    }

    // Each launcher group has a color for its cards' glyph badges, in launcher order: blue, violet, green, amber
    // (Border.launchBadge.hue0 … hue3 in the XAML).
    private static readonly List<string> GroupOrder = ToolCatalog.All.Select(t => t.Group).Distinct().ToList();

    private static string HueOf(ToolInfo tool) => "hue" + Math.Max(0, GroupOrder.IndexOf(tool.Group)) % 4;

    // ---- launcher: search and keys ----

    // A new tab is for picking a tool: the search box takes the keys, so typing finds one at once. Posted, like the About
    // box's focus: after the launcher is laid out, and after a click on + has put the focus on that button.
    private void FocusSearch()
    {
        if (!IsLauncherOpen) return;
        Dispatcher.UIThread.Post(() =>
        {
            if (IsLauncherOpen && !IsAboutOpen()) LauncherSearch.Focus();
        }, DispatcherPriority.Background);
    }

    // The cards that answer the search stay (ToolCatalog.Match), a group with none left goes with its heading, and the
    // best match is marked: Enter opens it. With nothing typed every card shows and none is marked.
    private void FilterLauncher()
    {
        if (_tiles.Count == 0) return;
        string query = (LauncherSearch.Text ?? string.Empty).Trim();
        var words = query.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        ToolInfo? best = null;
        int bestScore = 0;
        foreach (var (tool, tile) in _tiles)
        {
            int score = words.Length == 0 ? 1 : ToolCatalog.Match(tool, words);
            tile.IsVisible = score > 0;
            if (words.Length > 0 && score > bestScore)   // a tie goes to the first in launcher order
            {
                best = tool;
                bestScore = score;
            }
        }
        _bestMatch = best;
        foreach (var (tool, tile) in _tiles) tile.Classes.Set("best", ReferenceEquals(tool, best));
        foreach (var (heading, tiles) in _groups) heading.IsVisible = tiles.Any(tile => tile.IsVisible);
        LauncherHint.IsVisible = best is not null;
        LauncherHint.Text = best is null ? null : "Enter opens " + best.Title;
        LauncherEmpty.IsVisible = words.Length > 0 && best is null;
        LauncherEmpty.Text = LauncherEmpty.IsVisible ? "No tool matches “" + query + "”." : null;
    }

    private IEnumerable<Button> ShownCards()
        => _tiles.Where(t => t.Tile.IsVisible).Select(t => t.Tile.Children[0]).OfType<Button>();

    // In the search box: Enter opens the best match, Escape empties the box (with it empty the shell's Escape applies:
    // back to the tab before), Down goes to the first card.
    private void OnSearchKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.KeyModifiers != KeyModifiers.None) return;
        if (e.Key == Key.Enter && _bestMatch is { } tool)
        {
            e.Handled = true;
            OpenFromLauncher(tool);
        }
        else if (e.Key == Key.Escape && !string.IsNullOrEmpty(LauncherSearch.Text))
        {
            e.Handled = true;
            LauncherSearch.Text = string.Empty;
        }
        else if (e.Key == Key.Down && ShownCards().FirstOrDefault() is { } first)
        {
            e.Handled = true;
            first.Focus(NavigationMethod.Directional);
        }
    }

    // On a card: the arrows walk the cards as they lie on the page (groups sit side by side, so the next card in the
    // catalog isn't always the one to the right); up from the top row is the search box.
    private void OnCardKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.KeyModifiers != KeyModifiers.None || e.Key is not (Key.Left or Key.Right or Key.Up or Key.Down)) return;
        if (e.Source is not Button from || !from.Classes.Contains("launchCard")) return;
        var cards = ShownCards().ToList();
        if (!cards.Contains(from)) return;
        e.Handled = true;
        InputElement? to = CardToward(cards, from, e.Key);
        if (to is null && e.Key == Key.Up) to = LauncherSearch;
        to?.Focus(NavigationMethod.Directional);
    }

    // The card next to this one that way: in the nearest row (column) that way, the one most in line with it.
    private Button? CardToward(IReadOnlyList<Button> cards, Button from, Key way)
    {
        Point origin = Middle(from);
        Button? best = null;
        double bestAhead = double.MaxValue, bestAcross = double.MaxValue;
        foreach (var card in cards)
        {
            if (ReferenceEquals(card, from)) continue;
            Point at = Middle(card);
            double ahead = way switch
            {
                Key.Left => origin.X - at.X,
                Key.Right => at.X - origin.X,
                Key.Up => origin.Y - at.Y,
                _ => at.Y - origin.Y,
            };
            if (ahead < 1) continue;   // the same column (row), or the other way
            double across = way is Key.Left or Key.Right ? Math.Abs(at.Y - origin.Y) : Math.Abs(at.X - origin.X);
            if (ahead < bestAhead - 1 || (ahead <= bestAhead + 1 && across < bestAcross))
            {
                best = card;
                bestAhead = Math.Min(bestAhead, ahead);
                bestAcross = across;
            }
        }
        return best;

        Point Middle(Control c)
            => c.TranslatePoint(new Point(c.Bounds.Width / 2, c.Bounds.Height / 2), LauncherStack) ?? default;
    }

    // Typing with a card focused (after walking them with the arrows) goes on in the search box.
    private void OnCardTextInput(object? sender, TextInputEventArgs e)
    {
        if (e.Source is TextBox || string.IsNullOrWhiteSpace(e.Text) || e.Text.Any(char.IsControl)) return;
        e.Handled = true;
        LauncherSearch.Text = (LauncherSearch.Text ?? string.Empty) + e.Text;
        LauncherSearch.Focus();
        LauncherSearch.CaretIndex = LauncherSearch.Text.Length;
    }

    // ---- pages ----

    // The MainViewModel arrives after InitializeComponent (App sets it on the window), so the restored tab had no
    // view-model to build its tool from yet: build it now.
    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);
        if (_vm is not null) _vm.ToolRequested -= OnToolRequested;
        _vm = DataContext as MainViewModel;
        if (_vm is null) return;
        _vm.ToolRequested += OnToolRequested;
        if (Current is { } tab) BuildPage(tab, _vm);
    }

    // A tool handed another one something (an address to look up), or one started by itself.
    private void OnToolRequested(ToolRequest request)
    {
        if (ToolCatalog.Find(request.Tag) is not { } tool) return;
        if (request.Background) ShowStarted(tool);
        else ShowTool(tool, request.Apply);
    }

    // The chosen tab's page (built on its first visit, with per-tab live data refreshed on the way in), or the launcher.
    private void OnTabSelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        // SelectionChanged is routed: ignore events bubbling up from a page's own ComboBox / TabControl.
        if (!ReferenceEquals(e.Source, MainTabs)) return;
        if (!_restored) return;   // RestoreTabs sets the first selection itself

        var tab = Current;
        if (tab is not null) tab.LastUsed = ++_useCounter;
        IsLauncherOpen = tab is null || tab.IsNewTab;
        FocusSearch();   // also from one new tab to the next (+ pressed on a new tab), where IsLauncherOpen stays as it is
        SaveTabs();
        RevealSelected();
        if (tab?.Tool is not { } tool || _vm is null) return;
        BuildPage(tab, _vm);
        ToolViews.RefreshAfterRender(_vm, tool.Tag, "MainView.TabRefresh", tab.ViewModel, tab.SaveKey);
        (tab.ViewModel as CurlViewModel)?.MarkCurrentSaved();
    }

    private void BuildPage(NavTabItem tab, MainViewModel vm)
    {
        if (tab.Tool is not { } tool || tab.Content is not Decorator host) return;
        if (host.Child is null)
        {
            if (tool.Tag == "DATA")
            {
                host.Child = DataPage(vm);
            }
            else
            {
                ToolViews.Fill(host, tool.Tag, vm, tab.InstanceId == 0 ? null : tab.Store);
                if (tab.InstanceId > 0 && ToolViews.ViewIn(host)?.DataContext is { } model) vm.TrackTool(model);
            }
        }
        if (tool.Tag != "DATA") tab.ViewModel ??= ToolViews.ViewIn(host)?.DataContext;
    }

    // History & Backup: two pages under one tab. History is built with the tab, Backup the first time it is shown (only
    // then is its host in the visual tree).
    private static Control DataPage(MainViewModel vm)
    {
        var history = new Decorator();
        var backup = new Decorator();
        backup.AttachedToVisualTree += (_, _) => ToolViews.Fill(backup, "BACKUP", vm);
        var pages = new TabControl { Padding = new Thickness(0) };
        pages.Items.Add(new TabItem { Header = "History", Content = history });
        pages.Items.Add(new TabItem { Header = "Backup", Content = backup });
        ToolViews.Fill(history, "HISTORY", vm);
        return pages;
    }
}

/// <summary>
/// Builds each tool's view + view-model on first visit, for both shells (desktop tabs and mobile
/// drawer). Declaring the views inline made XAML build all 17 tool view trees at startup (String Lab,
/// the scanner, cURL's WebView host…) plus the inline Telegram VM, just to show the first tool, and it
/// left the MainViewModel <c>??=</c> getters one binding away from running every VM constructor (the
/// Network tab's four table scans, three synchronous NIC enumerations…). Now a tool costs nothing until
/// it is opened, and its VM is created by the lazy getter at that moment.
///
/// <para>Each shell hosts a tool in an empty <see cref="Decorator"/> that stays that tab's / page's
/// content. Once filled, the host keeps the same view instance (and the view keeps its view-model), so
/// switching away never resets a running ping, scan, monitor or server, or any half-typed input.
/// Deliberately not a DataTemplate: a templated presenter re-creates the view on every switch (losing
/// view state and cURL's native WebView).</para>
///
/// <para>A tool's further desktop tabs (a second Ping …) get a view-model of their own, made with the tab's
/// <see cref="ToolStore"/> so that it keeps its own settings.</para>
/// </summary>
internal static class ToolViews
{
    /// <summary>
    /// The per-visit refresh of live data, for both shells. History (cheap, skipped when nothing changed) is reloaded
    /// before the page shows. The others enumerate the network interfaces on the UI thread — tens of ms each with many
    /// (virtual) adapters, and Web Server does it two or three times — so they run once the switched-to page has been
    /// laid out and drawn (Background is below layout / render): the page appears at once, its address lists follow.
    /// <paramref name="toolVM"/>: the tab's own view-model (a further cURL tab); <paramref name="key"/>: the tab, for
    /// the address lists' age (each tab lists its own).
    /// </summary>
    public static void RefreshAfterRender(MainViewModel vm, string tool, string where, object? toolVM = null, string? key = null)
    {
        if (tool == "DATA")   // merged HISTORY + BACKUP tab
        {
            Run(vm, tool, where, toolVM);
            return;
        }
        if (tool is "CURL" or "WEB SERVER" or "PROXY" && AddressesMayHaveChanged(key ?? tool))
            Avalonia.Threading.Dispatcher.UIThread.Post(() => Run(vm, tool, where, toolVM), Avalonia.Threading.DispatcherPriority.Background);

        static void Run(MainViewModel vm, string tool, string where, object? toolVM)
        {
            // Guarded like Fill: a VM getter that failed to construct there throws again here.
            try
            {
                switch (tool)
                {
                    case "CURL": (toolVM as CurlViewModel ?? vm.CurlVM).RefreshInterfaces(); break;
                    case "DATA": vm.HistoryVM.Reload(); break;
                    case "WEB SERVER": vm.WebServerVM.RefreshAddressesCommand.Execute(null); break;
                    case "PROXY": vm.ProxyVM.RefreshAddressesCommand.Execute(null); break;
                }
            }
            catch (Exception ex) { CrashLog.Write(where, ex); }
        }
    }

    // Switching back and forth between tools listed the adapters again on every visit (a hitch right after the page drew).
    // A tool's addresses are listed again when the network changed since its last listing (the system's address-changed
    // event), and in any case after AddressesMaxAge: where that event doesn't come, a list is never older than that.
    private static readonly TimeSpan AddressesMaxAge = TimeSpan.FromSeconds(30);
    private static int s_netEpoch;
    private static bool s_netHooked;
    private static readonly Dictionary<string, (int Epoch, long At)> s_listed = new();

    private static bool AddressesMayHaveChanged(string key)
    {
        if (!s_netHooked)
        {
            s_netHooked = true;
            try { System.Net.NetworkInformation.NetworkChange.NetworkAddressChanged += (_, _) => Interlocked.Increment(ref s_netEpoch); }
            catch { /* not on this platform: the age rule alone */ }
        }
        int epoch = Volatile.Read(ref s_netEpoch);
        long now = Environment.TickCount64;
        if (s_listed.TryGetValue(key, out var last) && last.Epoch == epoch && now - last.At < (long)AddressesMaxAge.TotalMilliseconds)
            return false;
        s_listed[key] = (epoch, now);
        return true;
    }

    /// <summary>Builds the tool's view in an empty host: with the tool's main view-model, or, for a further desktop tab
    /// (<paramref name="store"/>), a view-model of its own.</summary>
    public static void Fill(Decorator host, string tool, MainViewModel vm, ToolStore? store = null)
    {
        if (host.Child is not null) return;
        try
        {
            var view = store is null || store.IsMain ? Create(tool, vm) : CreateFor(tool, vm, store);
            host.Child = view is not null && AppPlatform.IsMobile ? PhonePage(view) : view;
        }
        catch (Exception ex)
        {
            // A throwing view-model constructor used to surface as a binding error on a blank page;
            // keep it contained to that tool instead of letting it escape a SelectionChanged handler.
            CrashLog.Write($"ToolViews.Create({tool})", ex);
            var error = new TextBlock
            {
                Text = $"{tool} failed to load: {ex.Message}",
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(16),
            };
            // the design token (Styles/Tokens.axaml), following light / dark switches
            error.Bind(TextBlock.ForegroundProperty, error.GetResourceObservable("Danger"));
            host.Child = error;
        }
    }

    // A phone page is laid out at the screen's height, but never below this: in landscape, or with the keyboard over half
    // the screen, a page squeezed into what was left clipped its lower fields and buttons out of reach. Below it the page
    // scrolls as a whole (the shell brings the focused box above the keyboard); from it up the page is exactly the screen,
    // laid out as before. A tool that already scrolls as a whole is left as it is.
    private const double PhoneMinHeight = 600;

    private static Control PhonePage(Control view)
    {
        // a page that scrolls as a whole already, and cURL, whose web preview is a native view (a scroller can't clip one)
        if (view is UserControl { Content: ScrollViewer } or CurlView) return view;
        var frame = new Decorator { Child = view, Height = PhoneMinHeight };
        var page = new ScrollViewer
        {
            Content = frame,
            HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled,
            VerticalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Auto,
        };
        page.Classes.Add(PhonePageClass);
        page.PropertyChanged += (_, e) =>
        {
            if (e.Property == ScrollViewer.ViewportProperty)
                frame.Height = Math.Max(PhoneMinHeight, page.Viewport.Height);
        };
        return page;
    }

    private const string PhonePageClass = "phonePage";

    /// <summary>The tool view a page host holds (on a phone it sits inside the page's scroller).</summary>
    public static Control? ViewIn(Decorator host)
        => host.Child is ScrollViewer { Content: Decorator { Child: Control view } } page && page.Classes.Contains(PhonePageClass)
            ? view : host.Child;

    // Keyed by the nav Tag shared by both shells. The VMs come from MainViewModel's lazy getters (the one
    // source of VMs); TELEGRAM BOT, SPEED TEST, TLS and SOCKET have no slot there and own their VM (the view,
    // kept by its host for the session, keeps it alive): they save each change at once (Telegram's debounced save is
    // flushed through TgViewModel.FlushAll), so MainViewModel.FlushPersistence has nothing of theirs to write.
    private static Control? Create(string tool, MainViewModel vm) => tool switch
    {
        "PING" => new PingView { DataContext = vm.PingVM },
        "DOCTOR" => new DoctorView { DataContext = vm.DoctorVM },
        "DNS" => new DnsView { DataContext = vm.DnsVM },
        "CURL" => new CurlView { DataContext = vm.CurlVM },
        "IP INFO" => new IpInfoView { DataContext = vm.IpInfoVM },
        "CHECK-HOST" => new CheckHostView { DataContext = vm.CheckHostVM },
        "CLOUDFLARE" => new CloudflareView { DataContext = vm.CloudflareVM },
        "HETZNER" => new HetznerView { DataContext = vm.HetznerVM },
        "SCANNER" => new PortScannerView { DataContext = vm.PortScannerVM },
        "WEB SERVER" => new WebServerView { DataContext = vm.WebServerVM },
        "PROXY" => new ProxyView { DataContext = vm.ProxyVM },
        "NETWORK" => new NetworkInfoView { DataContext = vm.NetworkVM },
        "CAPTURE" => new CaptureView { DataContext = new CaptureViewModel() },
        "DEVICE" => new DeviceView { DataContext = new DeviceViewModel(vm.CurrentVersion) },
        "MONITOR" => new MonitorView { DataContext = vm.MonitorVM },
        "SSH" => new SshView { DataContext = vm.SshVM },
        "TELEGRAM BOT" => new TgView { DataContext = new TgViewModel() },
        "SPEED TEST" => new SpeedTestView { DataContext = new SpeedTestViewModel() },
        "TLS" => new TlsView { DataContext = new TlsViewModel() },
        "SOCKET" => new SocketView { DataContext = new SocketViewModel() },
        "STRING LAB" => new StringLabView { DataContext = vm.StringTool },
        "NOTES" => new NoteView { DataContext = vm.NoteVM },
        "HISTORY" => new HistoryView { DataContext = vm.HistoryVM },
        "BACKUP" => new BackupView { DataContext = vm.BackupVM },
        _ => null,
    };

    // A further tab of a tool that runs in several (ToolInfo.AllowsMany): its own view-model, made with the tab's store
    // (each view-model takes ToolStore.Current when it is made), and its own view.
    private static Control? CreateFor(string tool, MainViewModel vm, ToolStore store)
    {
        object? model = ToolStore.Construct<object?>(store, () => tool switch
        {
            "PING" => new PingViewModel(vm),
            "DOCTOR" => new DoctorViewModel(),
            "DNS" => new DnsViewModel(vm),
            "CURL" => new CurlViewModel(),
            "IP INFO" => new IpInfoViewModel(),
            "CHECK-HOST" => new CheckHostViewModel(),
            "SCANNER" => new PortScannerViewModel(),
            "SSH" => new SshViewModel(),
            "TELEGRAM BOT" => new TgViewModel(),
            "TLS" => new TlsViewModel(),
            "SOCKET" => new SocketViewModel(),
            "STRING LAB" => new StringLabViewModel(),
            _ => null,
        });
        return model switch
        {
            PingViewModel m => new PingView { DataContext = m },
            DoctorViewModel m => new DoctorView { DataContext = m },
            DnsViewModel m => new DnsView { DataContext = m },
            CurlViewModel m => new CurlView { DataContext = m },
            IpInfoViewModel m => new IpInfoView { DataContext = m },
            CheckHostViewModel m => new CheckHostView { DataContext = m },
            PortScannerViewModel m => new PortScannerView { DataContext = m },
            SshViewModel m => new SshView { DataContext = m },
            TgViewModel m => new TgView { DataContext = m },
            TlsViewModel m => new TlsView { DataContext = m },
            SocketViewModel m => new SocketView { DataContext = m },
            StringLabViewModel m => new StringLabView { DataContext = m },
            _ => Create(tool, vm),   // a tool with one tab: its usual view
        };
    }
}
