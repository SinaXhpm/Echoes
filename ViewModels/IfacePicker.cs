using CommunityToolkit.Mvvm.ComponentModel;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;

namespace Echoes.ViewModels;

/// <summary>One line of an interface picker. <paramref name="Name"/>: the interface's system name (what is saved and
/// looked up again at Start); null = no choice, the system's routing decides.</summary>
public sealed record IfaceOption(string? Name, string Label, string Tip);

/// <summary>
/// An interface picker's state, shared by the tools that send from, or listen on, a chosen network interface (Ping's
/// four modes, the Speed Test, Capture). The list is read when the picker opens (interfaces come and go: Wi-Fi, a
/// VPN); the choice is saved by the interface's name, so it survives a new address. A saved interface that is down
/// right now stays in the list, marked, instead of the choice silently falling back to the default route: the run
/// says it isn't connected.
/// <para>A picker with a "no choice" line doesn't read the interfaces until it first opens: listing the adapters
/// takes some 20 ms on a computer with many, and the Ping page is built at start-up. Until then it holds that line
/// and the saved choice by its name.</para>
/// </summary>
public sealed partial class IfacePicker : ObservableObject
{
    private readonly ISettings _settings;
    private readonly string _key;
    private readonly string? _autoLabel, _autoTip;
    private readonly bool _withLoopback;
    private bool _filling;
    private string? _shown;   // the name of the line last selected (null: the "no choice" line), for RestoreSelection

    public ObservableCollection<IfaceOption> Options { get; } = new();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsSet), nameof(Name))]
    private IfaceOption? _selected;

    /// <summary>An interface is chosen (not the "let the system decide" line).</summary>
    public bool IsSet => Selected?.Name is not null;

    /// <summary>The chosen interface's name; null = the system decides.</summary>
    public string? Name => Selected?.Name;

    /// <summary>Raised when the user picks another line (not while the list is refilled).</summary>
    public event Action? Changed;

    /// <param name="autoLabel">The first line, for "no choice" (Ping: "Default route"); null = no such line, the
    /// first interface is the default (Capture has to listen somewhere).</param>
    public IfacePicker(ISettings settings, string key, string? autoLabel, string? autoTip = null, bool withLoopback = false)
    {
        _settings = settings;
        _key = key;
        _autoLabel = autoLabel;
        _autoTip = autoTip;
        _withLoopback = withLoopback;
        string? saved = settings.GetSetting(key);
        if (autoLabel is null)
        {
            // It has to show an interface. None saved yet: the adapters are read now (the first one is the default). One
            // saved: it shows that one by name, and the adapters are read on the thread pool (Capture's page can be the
            // one a start restores, and the read held up its first frame).
            if (string.IsNullOrEmpty(saved)) { Refresh(saved); return; }
            _filling = true;
            try
            {
                Options.Add(new IfaceOption(saved, saved, saved));
                Selected = Options[0];
            }
            finally { _filling = false; }
            _ = System.Threading.Tasks.Task.Run(() => NetIfaces.Up(withLoopback)).ContinueWith(
                // (unless the list was read again meanwhile: the picker opened)
                t => Avalonia.Threading.Dispatcher.UIThread.Post(() => { if (_fills == 0) Fill(Name, t.Result); }),
                System.Threading.CancellationToken.None, System.Threading.Tasks.TaskContinuationOptions.OnlyOnRanToCompletion,
                System.Threading.Tasks.TaskScheduler.Default);
            return;
        }

        _filling = true;
        try
        {
            Options.Add(new IfaceOption(null, autoLabel, autoTip ?? autoLabel));
            if (!string.IsNullOrEmpty(saved)) Options.Add(new IfaceOption(saved, saved, saved));
            Selected = Options[^1];
        }
        finally { _filling = false; }
    }

    /// <summary>Reads the interfaces again and keeps the choice (the picker's DropDownOpened).</summary>
    public void Refresh() => Refresh(Name);

    private void Refresh(string? want) => Fill(want, NetIfaces.Up(_withLoopback));

    private int _fills;   // lists shown so far (a read on the thread pool doesn't replace a newer one)

    private void Fill(string? want, IReadOnlyList<NetIface> up)
    {
        _fills++;
        if (string.IsNullOrEmpty(want)) want = null;
        var list = new List<IfaceOption>();
        if (_autoLabel is not null) list.Add(new IfaceOption(null, _autoLabel, _autoTip ?? _autoLabel));
        foreach (var i in up) list.Add(new IfaceOption(i.Name, i.Label, Tip(i)));
        if (want is not null && !list.Any(o => o.Name == want))
            list.Add(new IfaceOption(want, want + " (not connected)", want + " isn't connected right now"));

        var pick = list.FirstOrDefault(o => o.Name == want) ?? list.FirstOrDefault();
        if (list.SequenceEqual(Options) && Equals(pick, Selected)) return;   // nothing changed: the open list stays as it is

        _filling = true;
        try
        {
            Options.Clear();
            foreach (var o in list) Options.Add(o);
            Selected = pick;
        }
        finally { _filling = false; }
    }

    partial void OnSelectedChanged(IfaceOption? value)
    {
        if (value is not null) _shown = value.Name;
        // (a ComboBox pushes null while its list is replaced: neither saved nor reported)
        if (_filling) return;
        if (value is null)
        {
            // ...and when its selection is lost some other way (the view re-templated or taken off the screen): the box
            // must not stay blank, so the line chosen is shown again once the change has settled (RestoreSelection).
            // Without an app (a unit test) there is no UI thread to post to: Avalonia 12's UIThread then isn't a working
            // dispatcher (a test run crashed in Post), and the test calls RestoreSelection itself.
            if (Avalonia.Application.Current is not null) Avalonia.Threading.Dispatcher.UIThread.Post(RestoreSelection);
            return;
        }
        string stored = value.Name ?? string.Empty;
        if ((_settings.GetSetting(_key) ?? string.Empty) != stored) _settings.SetSetting(_key, stored);
        Changed?.Invoke();
    }

    /// <summary>After the box lost its selection: the line it showed (the choice saved, or the interface shown in its
    /// place) is selected again the way a refill selects one, so nothing is saved or reported; the first line only when
    /// that one isn't listed any more. The box losing its selection is not the user choosing the first line, and must
    /// not overwrite the saved interface.</summary>
    internal void RestoreSelection()
    {
        if (Selected is not null || Options.Count == 0) return;
        _filling = true;
        try { Selected = Options.FirstOrDefault(o => o.Name == _shown) ?? Options[0]; }
        finally { _filling = false; }
    }

    /// <summary>The chosen interface as it is now; null when none is chosen, or it isn't up (see <see cref="IsSet"/>).</summary>
    public NetIface? Resolve() => NetIfaces.Find(Name, _withLoopback);

    private static string Tip(NetIface i)
    {
        var parts = new List<string>(4) { i.Description == i.Name ? i.Name : $"{i.Name}: {i.Description}" };
        if (i.V4 is { } v4) parts.Add("IPv4 " + v4);
        if (i.V6 is { } v6) parts.Add("IPv6 " + v6);
        else if (i.V6Link is { } link) parts.Add("IPv6 " + new System.Net.IPAddress(link.GetAddressBytes()) + " (link-local)");
        return string.Join("\n", parts);
    }
}
