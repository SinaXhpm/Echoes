using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;

namespace Echoes.Helpers;

/// <summary>The settings calls a tool makes: <see cref="ProfileService"/> itself, or one tab's copy of it (<see cref="ToolStore"/>).</summary>
public interface ISettings
{
    string? GetSetting(string key);
    void SetSetting(string key, string? value);
    void Remove(string key);
    bool GetBool(string key, bool def = false);
    void SetBool(string key, bool value);
    int GetInt(string key, int def = 0);
    void SetMany(params (string key, string? value)[] items);
}

/// <summary>
/// Where one tool instance keeps its inputs and options. A tool's first tab (and the phone, which has one page per tool)
/// uses <see cref="Main"/>: the profile's keys as they always were. Each further tab of a tool that may run in several
/// (two Ping tabs, three SSH sessions) gets <see cref="ForTab"/>: its own copy under "tab{id}:" keys. A key the tab has
/// no value for yet is copied from the main one when first read, so the new tab starts from the tool's last options and
/// later changes in another tab never reach it; the copy stays with the tab across restarts and goes when it is closed.
///
/// <para>The recent-input lists stay one per tool (every tab offers the same history). The last value a store added to a
/// list is its own ("last:" keys), so each tab comes back with its own host, URL or address.</para>
///
/// <para>A view-model takes its store in a field initializer (<c>private readonly ToolStore Store = ToolStore.Current;</c>):
/// <see cref="Construct"/> sets <see cref="Current"/> around the constructor of a tab's instance, and everything else
/// (the main instances, the phone) gets <see cref="Main"/>.</para>
/// </summary>
public sealed class ToolStore
{
    public static ToolStore Main { get; } = new(0);

    [ThreadStatic] private static ToolStore? t_current;

    /// <summary>The store a view-model being made right now belongs to.</summary>
    public static ToolStore Current => t_current ?? Main;

    /// <summary>Runs <paramref name="make"/> (a view-model's constructor) with <paramref name="store"/> as <see cref="Current"/>.</summary>
    public static T Construct<T>(ToolStore store, Func<T> make)
    {
        var previous = t_current;
        t_current = store;
        try { return make(); }
        finally { t_current = previous; }
    }

    private static readonly Dictionary<int, ToolStore> s_tabs = new();

    /// <summary>The store of the tab with this id (the same object for the same id); 0 or less is <see cref="Main"/>.</summary>
    public static ToolStore ForTab(int id)
    {
        if (id <= 0) return Main;
        lock (s_tabs)
        {
            if (!s_tabs.TryGetValue(id, out var store)) s_tabs[id] = store = new ToolStore(id);
            return store;
        }
    }

    public int TabId { get; }
    public bool IsMain => TabId == 0;
    private readonly string _prefix;   // "tab7:"; empty for Main
    // The tab was closed: a late write (a debounced save, a lookup finishing after the close) changes nothing.
    private volatile bool _closed;

    /// <summary>The settings, in place of <c>ProfileService.Instance</c>.</summary>
    public Settings Profile { get; }

    /// <summary>The recent-input lists, in place of <c>HistoryService.Instance</c>.</summary>
    public RecentInputs History { get; }

    /// <summary>This store added a value to the history list with this key (raised on the thread that added it).</summary>
    public event Action<string>? LastChanged;

    private ToolStore(int id)
    {
        TabId = id;
        _prefix = id == 0 ? string.Empty : TabPrefix(id);
        Profile = new Settings(this);
        History = new RecentInputs(this);
    }

    public static string TabPrefix(int id) => "tab" + id.ToString(CultureInfo.InvariantCulture) + ":";

    private const string LastPrefix = "last:";

    // A tab's "no value": the main store had none when the tab took its copy, or the tab removed it. Not a value anyone
    // types (a control character).
    private static readonly string Unset = (char)1 + "unset";

    /// <summary>A "tab{id}:…" key, and its id.</summary>
    public static bool IsTabKey(string key, out int id)
    {
        id = 0;
        if (!key.StartsWith("tab", StringComparison.Ordinal)) return false;
        int colon = key.IndexOf(':', 3);
        return colon > 3 && int.TryParse(key.AsSpan(3, colon - 3), NumberStyles.None, CultureInfo.InvariantCulture, out id) && id > 0;
    }

    /// <summary>A store's own last input (main "last:…" or a tab's "tab{id}:last:…"): cleared with the history.</summary>
    public static bool IsLastValueKey(string key)
        => key.StartsWith(LastPrefix, StringComparison.Ordinal)
           || (IsTabKey(key, out _) && key.AsSpan(key.IndexOf(':') + 1).StartsWith(LastPrefix, StringComparison.Ordinal));

    // ---- settings ----

    private string Own(string key) => _prefix + key;

    // The tab's value: its own once it has one, else the main value at this moment, copied into the tab.
    private string? Read(string key)
    {
        var ps = ProfileService.Instance;
        if (IsMain) return ps.GetSetting(key);
        string own = Own(key);
        if (ps.GetSetting(own) is { } value) return value == Unset ? null : value;
        string? main = ps.GetSetting(key);
        if (!_closed) ps.SetSetting(own, main ?? Unset);
        return main;
    }

    // ---- last inputs ----

    private string? ReadLast(string key)
    {
        var ps = ProfileService.Instance;
        string own = _prefix + LastPrefix + key;
        if (ps.GetSetting(own) is { } value) return value == Unset ? null : value;
        string? shared = HistoryService.Instance.Last(key);
        if (!_closed) ps.SetSetting(own, shared ?? Unset);
        return shared;
    }

    /// <summary>The store's last value for a history key as it stands, without taking a copy (a tab's label).</summary>
    public string? PeekLast(string key)
    {
        string? own = ProfileService.Instance.GetSetting(_prefix + LastPrefix + key);
        if (own is not null) return own == Unset ? null : own;
        return IsMain ? HistoryService.Instance.Last(key) : null;
    }

    /// <summary>A new tab of a tool that is open already starts with its main input (a host, a URL) empty; its other
    /// options still come from the tool's last ones.</summary>
    public void StartFresh(string key)
    {
        if (IsMain || _closed) return;
        ProfileService.Instance.SetMany((_prefix + LastPrefix + key, Unset), (Own(key), Unset));
    }

    private void AddLast(string key, string? value)
    {
        var ps = ProfileService.Instance;
        long before = ps.HistoryVersion;
        HistoryService.Instance.Add(key, value);
        if (_closed) return;
        string? head = HistoryService.Instance.Last(key);
        // the list took it (cleaned of credentials) or already had it first; a refused value (empty, too long) isn't ours
        if (head is null || (ps.HistoryVersion == before && head != value?.Trim())) return;
        ps.SetSetting(_prefix + LastPrefix + key, head);
        LastChanged?.Invoke(key);
    }

    // ---- a tab's life ----

    /// <summary>A duplicated tab: everything <paramref name="source"/> has of its own is copied into this store. From a
    /// tool's first tab, only its last input for <paramref name="subjectKey"/>: this store's first reads copy the rest.</summary>
    public void CopyFrom(ToolStore source, string? subjectKey)
    {
        if (IsMain || _closed || source == this) return;
        if (!source.IsMain) ProfileService.Instance.CopyKeys(source._prefix, _prefix);
        else if (subjectKey is not null && source.PeekLast(subjectKey) is { } last)
            ProfileService.Instance.SetSetting(_prefix + LastPrefix + subjectKey, last);
    }

    /// <summary>The tab was closed: its copy goes.</summary>
    public void Clear()
    {
        if (IsMain) return;
        _closed = true;
        string prefix = _prefix;
        ProfileService.Instance.RemoveWhere(k => k.StartsWith(prefix, StringComparison.Ordinal));
        lock (s_tabs) s_tabs.Remove(TabId);
    }

    /// <summary>At start-up: the copies of tabs that aren't open any more (left by a crash between closing and saving).</summary>
    public static void RemoveOrphans(IReadOnlyCollection<int> openTabs)
    {
        var open = new HashSet<int>(openTabs);
        ProfileService.Instance.RemoveWhere(k => IsTabKey(k, out int id) && !open.Contains(id));
    }

    /// <summary>The settings half: <see cref="ProfileService"/>'s calls, on the store's own keys.</summary>
    public sealed class Settings : ISettings
    {
        private readonly ToolStore _store;
        internal Settings(ToolStore store) => _store = store;

        public string? GetSetting(string key) => _store.Read(key);

        public void SetSetting(string key, string? value)
        {
            if (!_store._closed) ProfileService.Instance.SetSetting(_store.Own(key), value);
        }

        public void Remove(string key)
        {
            if (_store.IsMain) ProfileService.Instance.Remove(key);
            else if (!_store._closed) ProfileService.Instance.SetSetting(_store.Own(key), Unset);   // not back to the main value
        }

        public bool GetBool(string key, bool def = false)
            => _store.Read(key) is { } v && bool.TryParse(v, out bool b) ? b : def;

        public void SetBool(string key, bool value) => SetSetting(key, value ? "true" : "false");

        public int GetInt(string key, int def = 0)
            => _store.Read(key) is { } v && int.TryParse(v, out int i) ? i : def;

        public void SetMany(params (string key, string? value)[] items)
        {
            if (_store.IsMain) { ProfileService.Instance.SetMany(items); return; }
            if (_store._closed) return;
            var own = new (string key, string? value)[items.Length];
            for (int i = 0; i < items.Length; i++) own[i] = (_store.Own(items[i].key), items[i].value);
            ProfileService.Instance.SetMany(own);
        }
    }

    /// <summary>The history half: <see cref="HistoryService"/>'s calls. The lists are shared; the last value is the store's.</summary>
    public sealed class RecentInputs
    {
        private readonly ToolStore _store;
        internal RecentInputs(ToolStore store) => _store = store;

        public ObservableCollection<string> Get(string key) => HistoryService.Instance.Get(key);

        public string? Last(string key) => _store.ReadLast(key);

        public void Add(string key, string? value) => _store.AddLast(key, value);
    }
}
