using Echoes.Helpers;
using Echoes.Tests.Support;
using Echoes.ViewModels;

namespace Echoes.Tests;

/// <summary>The interface picker's state (Ping, Speed Test, DNS, the scanner, Capture, Devices): what it lists, what
/// it saves, and what happens to a saved interface that isn't connected right now.</summary>
[Collection(Live.Collection)]
public class IfacePickerTests
{
    private sealed class Settings : ISettings
    {
        public readonly Dictionary<string, string?> Values = new();
        public int Writes;

        public string? GetSetting(string key) => Values.GetValueOrDefault(key);
        public void SetSetting(string key, string? value) { Values[key] = value; Writes++; }
        public void Remove(string key) => Values.Remove(key);
        public bool GetBool(string key, bool def = false) => Values.TryGetValue(key, out var v) ? v == "true" : def;
        public void SetBool(string key, bool value) => SetSetting(key, value ? "true" : "false");
        public int GetInt(string key, int def = 0) => Values.TryGetValue(key, out var v) && int.TryParse(v, out int n) ? n : def;
        public void SetMany(params (string key, string? value)[] items) { foreach (var (key, value) in items) SetSetting(key, value); }
    }

    private const string Key = "test.iface";

    [Fact]
    public void A_picker_with_a_default_line_starts_with_only_that_line()
    {
        var settings = new Settings();
        var picker = new IfacePicker(settings, Key, "Default route", "The system decides");
        // (the interfaces aren't read until the list is opened: the pages are built at start-up)
        var only = Assert.Single(picker.Options);
        Assert.Null(only.Name);
        Assert.Equal("Default route", only.Label);
        Assert.Equal("The system decides", only.Tip);
        Assert.Same(only, picker.Selected);
        Assert.False(picker.IsSet);
        Assert.Null(picker.Name);
        Assert.Null(picker.Resolve());
        Assert.Equal(0, settings.Writes);
    }

    [Fact]
    public void Opening_the_list_reads_the_interfaces_and_keeps_the_choice()
    {
        var settings = new Settings();
        var picker = new IfacePicker(settings, Key, "Default route");
        int changes = 0;
        picker.Changed += () => changes++;

        picker.Refresh();
        var up = NetIfaces.Up();
        Assert.Equal(up.Count + 1, picker.Options.Count);
        Assert.Null(picker.Options[0].Name);
        Assert.Equal(up.Select(i => i.Name), picker.Options.Skip(1).Select(o => o.Name));
        Assert.Equal(up.Select(i => i.Label), picker.Options.Skip(1).Select(o => o.Label));
        Assert.False(picker.IsSet);
        // filling the list is not the user choosing something
        Assert.Equal(0, changes);
        Assert.Equal(0, settings.Writes);

        // opened again with nothing new: the same list object by object (an open drop-down must not be rebuilt)
        var before = picker.Options.ToArray();
        picker.Refresh();
        Assert.Equal(before.Length, picker.Options.Count);
        for (int i = 0; i < before.Length; i++) Assert.Same(before[i], picker.Options[i]);
    }

    [Fact]
    public void Choosing_an_interface_saves_its_name_and_says_so_once()
    {
        var nic = Live.Network();
        var settings = new Settings();
        var picker = new IfacePicker(settings, Key, "Default route");
        int changes = 0;
        picker.Changed += () => changes++;
        picker.Refresh();

        picker.Selected = picker.Options.First(o => o.Name == nic.Name);
        Assert.True(picker.IsSet);
        Assert.Equal(nic.Name, picker.Name);
        Assert.Equal(nic.Name, settings.Values[Key]);
        Assert.Equal(1, changes);
        Assert.Equal(nic.Name, picker.Resolve()?.Name);

        // back to the default: saved as "no choice"
        picker.Selected = picker.Options[0];
        Assert.False(picker.IsSet);
        Assert.Equal(string.Empty, settings.Values[Key]);
        Assert.Equal(2, changes);
        Assert.Null(picker.Resolve());

        // a new picker (the next start, another tab) comes back with what was saved
        picker.Selected = picker.Options.First(o => o.Name == nic.Name);
        var next = new IfacePicker(settings, Key, "Default route");
        Assert.Equal(nic.Name, next.Name);
        Assert.Equal(2, next.Options.Count);
        next.Refresh();
        Assert.Equal(nic.Name, next.Name);
        Assert.Equal(NetIfaces.Up().Count + 1, next.Options.Count);
    }

    [Fact]
    public void A_saved_interface_that_is_not_connected_stays_chosen_and_is_marked()
    {
        var settings = new Settings();
        settings.Values[Key] = "echoes-none0";
        var picker = new IfacePicker(settings, Key, "Default route");
        Assert.True(picker.IsSet);
        Assert.Equal("echoes-none0", picker.Name);

        picker.Refresh();
        // not silently the default route: the run has to say the interface isn't connected
        Assert.Equal("echoes-none0", picker.Name);
        Assert.Contains("not connected", picker.Selected!.Label);
        Assert.Null(picker.Resolve());
        Assert.Equal("echoes-none0", settings.Values[Key]);
    }

    [Fact]
    public void A_selection_the_box_loses_comes_back_without_being_saved_or_reported()
    {
        var settings = new Settings();
        settings.Values[Key] = "echoes-none0";
        var picker = new IfacePicker(settings, Key, "Default route");
        int changes = 0;
        picker.Changed += () => changes++;

        // the ComboBox pushes null (its view re-templated, or taken off the screen); once that has settled the picker
        // shows its line again: not the default route, and nothing saved over the choice
        picker.Selected = null;
        picker.RestoreSelection();
        Assert.Equal("echoes-none0", picker.Name);
        Assert.Equal("echoes-none0", settings.Values[Key]);
        Assert.Equal(0, settings.Writes);
        Assert.Equal(0, changes);

        // the "no choice" line, when that is what was chosen, comes back as that line
        picker.Selected = picker.Options[0];
        Assert.Equal(1, changes);
        picker.Selected = null;
        picker.RestoreSelection();
        Assert.Same(picker.Options[0], picker.Selected);
        Assert.Equal(1, changes);
        Assert.Equal(1, settings.Writes);
        Assert.Equal(string.Empty, settings.Values[Key]);
    }

    [Fact]
    public void A_picker_without_a_default_line_shows_an_interface_from_the_start()
    {
        // Capture's picker: it has to listen somewhere, and loopback is one of the choices
        var settings = new Settings();
        var picker = new IfacePicker(settings, Key, null, withLoopback: true);
        var up = NetIfaces.Up(withLoopback: true);
        Assert.SkipWhen(up.Count == 0, "this computer lists no interface");
        Assert.Equal(up.Select(i => i.Name), picker.Options.Select(o => o.Name));
        Assert.Equal(up[0].Name, picker.Name);
        Assert.True(picker.IsSet);
        Assert.Contains(picker.Options, o => o.Name == Live.Loopback().Name);
        // showing the first interface is not a choice the user made: nothing is saved for it
        Assert.Equal(0, settings.Writes);

        var saved = new Settings();
        saved.Values[Key] = up[^1].Name;
        Assert.Equal(up[^1].Name, new IfacePicker(saved, Key, null, withLoopback: true).Name);
    }

    [Fact]
    public void Every_line_has_a_tip_that_says_what_the_interface_is()
    {
        var picker = new IfacePicker(new Settings(), Key, "Default route");
        picker.Refresh();
        foreach (var option in picker.Options)
        {
            Assert.False(string.IsNullOrWhiteSpace(option.Label));
            Assert.False(string.IsNullOrWhiteSpace(option.Tip));
            if (option.Name is { } name) Assert.Contains(name, option.Tip);
        }
    }
}
