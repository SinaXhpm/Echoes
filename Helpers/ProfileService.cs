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
    public ObservableCollection<string> GetHistory(string key)
    {
        lock (_gate)
        {
            if (!_history.TryGetValue(key, out var list))
            {
                list = new ObservableCollection<string>();
                _history[key] = list;
            }
            return list;
        }
    }

    public string? LastHistory(string key)
    {
        var list = GetHistory(key);
        return list.Count > 0 ? list[0] : null;
    }

    public void AddHistory(string key, string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        value = Sanitize(value.Trim());

        var list = GetHistory(key);
        int existing = -1;
        for (int i = 0; i < list.Count; i++)
            if (string.Equals(list[i], value, StringComparison.Ordinal)) { existing = i; break; }

        if (existing == 0) return;
        if (existing > 0) list.RemoveAt(existing);
        list.Insert(0, value);
        while (list.Count > MaxPerKey) list.RemoveAt(list.Count - 1);

        Save();
    }

    // Strip credentials embedded in a URL (scheme://user:pass@host) before persisting.
    private static string Sanitize(string value)
        => System.Text.RegularExpressions.Regex.Replace(value, @"(://)[^/@\s]+@", "$1");

    // ---------- Simple settings ----------
    public string? GetSetting(string key) => _settings.TryGetValue(key, out var v) ? v : null;
    public void SetSetting(string key, string? value) { _settings[key] = value ?? string.Empty; Save(); }
    public void Remove(string key) { if (_settings.Remove(key)) Save(); }
    public bool GetBool(string key, bool def = false)
        => _settings.TryGetValue(key, out var v) && bool.TryParse(v, out var b) ? b : def;
    public void SetBool(string key, bool value) => SetSetting(key, value ? "true" : "false");
    public int GetInt(string key, int def = 0)
        => _settings.TryGetValue(key, out var v) && int.TryParse(v, out var i) ? i : def;

    // Set several settings and write the file once (avoids one write per field).
    public void SetMany(params (string key, string? value)[] items)
    {
        foreach (var (k, v) in items) _settings[k] = v ?? string.Empty;
        Save();
    }

    // ---------- SSH known hosts (trust-on-first-use pins) ----------
    public string? GetKnownHost(string host) => _knownHosts.TryGetValue(host, out var v) ? v : null;
    public void SetKnownHost(string host, string fingerprint) { _knownHosts[host] = fingerprint; Save(); }

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
        catch { }
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
                    foreach (var v in kv.Value) arr.Add(v);
                    history[kv.Key] = arr;
                }
                var settings = new JsonObject();
                foreach (var kv in _settings) settings[kv.Key] = kv.Value;
                var hosts = new JsonObject();
                foreach (var kv in _knownHosts) hosts[kv.Key] = kv.Value;

                var root = new JsonObject { ["history"] = history, ["settings"] = settings, ["knownHosts"] = hosts };
                File.WriteAllText(_path, root.ToJsonString());
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
