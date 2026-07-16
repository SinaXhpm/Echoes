using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;

namespace Echoes.Helpers;

/// <summary>
/// Single source of truth for all app settings/state, persisted to ONE profile file
/// (echoes.profile.json in the user data dir). Holds input history, simple settings
/// (DNS servers, Cloudflare credentials, ...), and SSH known-host pins.
/// Encrypted notes (notes.dat) stay separate by design.
/// </summary>
public sealed class ProfileService
{
    public static ProfileService Instance { get; } = new();

    private const int MaxPerKey = 50;
    private readonly string _path = AppStorage.UserPath("echoes.profile.json");
    private readonly object _gate = new();

    private readonly Dictionary<string, ObservableCollection<string>> _history = new();
    private readonly Dictionary<string, string> _settings = new();
    private readonly Dictionary<string, string> _knownHosts = new();

    private ProfileService() => Load();

    // ---------- Input history ----------
    // Assumes _gate is already held.
    private ObservableCollection<string> GetHistoryLocked(string key)
    {
        if (!_history.TryGetValue(key, out var list))
        {
            list = new ObservableCollection<string>();
            _history[key] = list;
        }
        return list;
    }

    public ObservableCollection<string> GetHistory(string key)
    {
        lock (_gate) { return GetHistoryLocked(key); }
    }

    public string? LastHistory(string key)
    {
        lock (_gate)
        {
            var list = GetHistoryLocked(key);
            return list.Count > 0 ? list[0] : null;
        }
    }

    public void AddHistory(string key, string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        value = Sanitize(value.Trim());

        lock (_gate)
        {
            var list = GetHistoryLocked(key);
            int existing = -1;
            for (int i = 0; i < list.Count; i++)
                if (string.Equals(list[i], value, StringComparison.Ordinal)) { existing = i; break; }

            if (existing == 0) return;
            if (existing > 0) list.RemoveAt(existing);
            list.Insert(0, value);
            while (list.Count > MaxPerKey) list.RemoveAt(list.Count - 1);

            Save();
        }
    }

    // Snapshot of every non-empty history list (key → values), for the History tab.
    public IReadOnlyList<(string Key, IReadOnlyList<string> Values)> AllHistory()
    {
        lock (_gate)
            return _history
                .Where(kv => kv.Value.Count > 0)
                .Select(kv => (kv.Key, (IReadOnlyList<string>)kv.Value.ToList()))
                .ToList();
    }

    // Wipe all input history (empties the live UI-bound lists too), then persist.
    public void ClearAllHistory()
    {
        lock (_gate)
        {
            foreach (var list in _history.Values) list.Clear();
            Save();
        }
    }

    // Strip credentials embedded in a URL (scheme://user:pass@host) before persisting.
    private static string Sanitize(string value)
        => System.Text.RegularExpressions.Regex.Replace(value, @"(://)[^/@\s]+@", "$1");

    // ---------- Simple settings ----------
    // Every accessor holds _gate: mutators can run off the UI thread (SSH TOFU pin on a
    // background thread, debounced persistence), racing Save()'s enumeration of the stores.
    public string? GetSetting(string key)
    {
        lock (_gate) { return _settings.TryGetValue(key, out var v) ? v : null; }
    }
    public void SetSetting(string key, string? value)
    {
        lock (_gate) { _settings[key] = value ?? string.Empty; Save(); }
    }
    public void Remove(string key)
    {
        lock (_gate) { if (_settings.Remove(key)) Save(); }
    }
    public bool GetBool(string key, bool def = false)
    {
        lock (_gate) { return _settings.TryGetValue(key, out var v) && bool.TryParse(v, out var b) ? b : def; }
    }
    public void SetBool(string key, bool value) => SetSetting(key, value ? "true" : "false");
    public int GetInt(string key, int def = 0)
    {
        lock (_gate) { return _settings.TryGetValue(key, out var v) && int.TryParse(v, out var i) ? i : def; }
    }

    // Set several settings and write the file once (avoids one write per field).
    public void SetMany(params (string key, string? value)[] items)
    {
        lock (_gate)
        {
            foreach (var (k, v) in items) _settings[k] = v ?? string.Empty;
            Save();
        }
    }

    // ---------- SSH known hosts (trust-on-first-use pins) ----------
    public string? GetKnownHost(string host)
    {
        lock (_gate) { return _knownHosts.TryGetValue(host, out var v) ? v : null; }
    }
    public void SetKnownHost(string host, string fingerprint)
    {
        lock (_gate) { _knownHosts[host] = fingerprint; Save(); }
    }

    // Atomically replace the on-disk profile with the given JSON AND refresh the in-memory stores,
    // all under _gate. Used by backup import so a concurrent background Save() (e.g. an SSH TOFU pin)
    // can neither hit a sharing violation on the raw write nor serialize stale pre-import state back
    // over the restore between the write and the reload. Throws on invalid JSON (nothing is written).
    public void ReplaceFromJson(string json)
    {
        if (JsonNode.Parse(json) is not JsonObject) throw new InvalidOperationException("Invalid profile JSON.");
        lock (_gate)
        {
            var tmp = _path + ".tmp";
            File.WriteAllText(tmp, json);
            if (File.Exists(_path)) File.Replace(tmp, _path, null);
            else File.Move(tmp, _path);
            Reload();   // Monitor is reentrant → refreshes in-memory from the just-written file under the same lock
        }
    }

    // Re-read the profile file from disk and refresh the in-memory stores IN PLACE. Called after a
    // backup import so the running singleton reflects the restored file — otherwise the next Save()
    // (a settings change, an SSH TOFU pin, a debounced edit) serializes the pre-import state straight
    // back over the just-restored profile, silently losing the restore. History collections are
    // cleared + repopulated (not replaced) so existing UI bindings stay attached.
    public void Reload()
    {
        lock (_gate)
        {
            JsonObject? root;
            try { root = File.Exists(_path) ? JsonNode.Parse(File.ReadAllText(_path)) as JsonObject : null; }
            catch { return; }        // unreadable → keep current in-memory state
            if (root is null) return;

            _settings.Clear();
            if (root["settings"] is JsonObject s)
                foreach (var kv in s) _settings[kv.Key] = kv.Value?.GetValue<string>() ?? string.Empty;

            _knownHosts.Clear();
            if (root["knownHosts"] is JsonObject k)
                foreach (var kv in k) _knownHosts[kv.Key] = kv.Value?.GetValue<string>() ?? string.Empty;

            var fresh = new Dictionary<string, List<string>>();
            if (root["history"] is JsonObject h)
                foreach (var kv in h)
                    if (kv.Value is JsonArray arr)
                        fresh[kv.Key] = arr.Select(n => n?.GetValue<string>() ?? string.Empty)
                                           .Where(x => x.Length > 0).ToList();

            foreach (var key in _history.Keys)
                if (!fresh.ContainsKey(key)) _history[key].Clear();     // gone in the restore
            foreach (var kv in fresh)
            {
                var list = GetHistoryLocked(kv.Key);
                list.Clear();
                foreach (var v in kv.Value) list.Add(v);
            }
        }
    }

    // ---------- Persistence ----------
    private void Load()
    {
        try
        {
            if (File.Exists(_path))
            {
                Parse(File.ReadAllText(_path));
                return;
            }
        }
        catch
        {
            // Corrupt/unreadable profile: keep a copy as .corrupt.bak instead of silently
            // discarding it, then fall through so the app still starts (fresh state).
            try
            {
                if (File.Exists(_path)) File.Copy(_path, _path + ".corrupt.bak", overwrite: true);
            }
            catch { }
        }
        MigrateLegacy();
    }

    private void Parse(string text)
    {
        if (JsonNode.Parse(text) is not JsonObject root) return;

        if (root["history"] is JsonObject h)
            foreach (var kv in h)
                if (kv.Value is JsonArray arr)
                    _history[kv.Key] = new ObservableCollection<string>(
                        arr.Select(n => n?.GetValue<string>() ?? string.Empty).Where(s => s.Length > 0));

        if (root["settings"] is JsonObject s)
            foreach (var kv in s)
                _settings[kv.Key] = kv.Value?.GetValue<string>() ?? string.Empty;

        if (root["knownHosts"] is JsonObject k)
            foreach (var kv in k)
                _knownHosts[kv.Key] = kv.Value?.GetValue<string>() ?? string.Empty;
    }

    private void Save()
    {
        try
        {
            lock (_gate)
            {
                var history = new JsonObject();
                foreach (var kv in _history)
                {
                    var arr = new JsonArray();
                    // Cast to JsonNode so the non-generic Add(JsonNode?) is chosen (AOT-safe;
                    // the generic Add<T> is RequiresDynamicCode).
                    foreach (var v in kv.Value) arr.Add((JsonNode?)v);
                    history[kv.Key] = arr;
                }
                var settings = new JsonObject();
                foreach (var kv in _settings) settings[kv.Key] = kv.Value;
                var hosts = new JsonObject();
                foreach (var kv in _knownHosts) hosts[kv.Key] = kv.Value;

                var root = new JsonObject { ["history"] = history, ["settings"] = settings, ["knownHosts"] = hosts };

                // Atomic write: serialize to a temp file in the same directory, then swap it in.
                // A crash / power loss mid-write can never leave the profile truncated, and the
                // whole method is inside _gate so two writers can't race the same path.
                var tmp = _path + ".tmp";
                File.WriteAllText(tmp, root.ToJsonString());
                if (File.Exists(_path)) File.Replace(tmp, _path, null);
                else File.Move(tmp, _path);
            }
        }
        catch { }
    }

    // One-time import from the old per-feature files, then delete them (single-file profile).
    private void MigrateLegacy()
    {
        bool any = false;

        try
        {
            var hp = AppStorage.ResolvePath("history.dat");
            if (File.Exists(hp) && JsonNode.Parse(File.ReadAllText(hp)) is JsonObject node
                && node["Entries"] is JsonObject entries)
            {
                foreach (var kv in entries)
                    if (kv.Value is JsonArray arr)
                        _history[kv.Key] = new ObservableCollection<string>(
                            arr.Select(n => n?.GetValue<string>() ?? string.Empty).Where(s => s.Length > 0));
                any = true;
            }
        }
        catch { }

        try
        {
            var dp = AppStorage.ResolvePath("dns_settings.txt");
            if (File.Exists(dp)) { _settings["dns.servers"] = File.ReadAllText(dp); any = true; }
        }
        catch { }

        try
        {
            var cp = AppStorage.UserPath("cloudflare.dat");
            if (File.Exists(cp) && JsonNode.Parse(File.ReadAllText(cp)) is JsonObject n)
            {
                _settings["cf.useToken"] = (n["useToken"]?.GetValue<bool>() ?? true) ? "true" : "false";
                _settings["cf.token"] = n["token"]?.GetValue<string>() ?? string.Empty;
                _settings["cf.email"] = n["email"]?.GetValue<string>() ?? string.Empty;
                _settings["cf.key"] = n["key"]?.GetValue<string>() ?? string.Empty;
                _settings["cf.useProxy"] = (n["useProxy"]?.GetValue<bool>() ?? false) ? "true" : "false";
                _settings["cf.proxy"] = n["proxy"]?.GetValue<string>() ?? string.Empty;
                any = true;
            }
        }
        catch { }

        try
        {
            var kp = AppStorage.UserPath("known_hosts.txt");
            if (File.Exists(kp))
            {
                foreach (var line in File.ReadAllLines(kp))
                {
                    var parts = line.Split(' ', 2);
                    if (parts.Length == 2) _knownHosts[parts[0].Trim()] = parts[1].Trim();
                }
                any = true;
            }
        }
        catch { }

        if (!any) return;
        Save();
        TryDelete(AppStorage.ResolvePath("history.dat"));
        TryDelete(AppStorage.ResolvePath("dns_settings.txt"));
        TryDelete(AppStorage.UserPath("cloudflare.dat"));
        TryDelete(AppStorage.UserPath("known_hosts.txt"));
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}
