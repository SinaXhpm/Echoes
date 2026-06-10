using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Echoes.Helpers;

public class HistoryStore
{
    public Dictionary<string, List<string>> Entries { get; set; } = new();
}

[JsonSerializable(typeof(HistoryStore))]
[JsonSerializable(typeof(Dictionary<string, List<string>>))]
[JsonSerializable(typeof(List<string>))]
internal partial class HistoryContext : JsonSerializerContext
{
}

public sealed class HistoryService
{
    private const int MaxPerKey = 50;

    public static HistoryService Instance { get; } = new();

    private readonly string _filePath = AppStorage.ResolvePath("history.dat");
    private readonly Dictionary<string, ObservableCollection<string>> _lists = new();
    private readonly object _gate = new();

    private HistoryService() => Load();

    public ObservableCollection<string> Get(string key)
    {
        lock (_gate)
        {
            if (!_lists.TryGetValue(key, out var list))
            {
                list = new ObservableCollection<string>();
                _lists[key] = list;
            }
            return list;
        }
    }

    public string? Last(string key)
    {
        var list = Get(key);
        return list.Count > 0 ? list[0] : null;
    }

    public void Add(string key, string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        value = Sanitize(value.Trim());

        var list = Get(key);

        int existing = -1;
        for (int i = 0; i < list.Count; i++)
        {
            if (string.Equals(list[i], value, StringComparison.Ordinal)) { existing = i; break; }
        }

        if (existing == 0) return;
        if (existing > 0) list.RemoveAt(existing);

        list.Insert(0, value);

        while (list.Count > MaxPerKey)
            list.RemoveAt(list.Count - 1);

        Save();
    }

    // Strip credentials embedded in a URL (scheme://user:pass@host) before persisting to disk.
    private static string Sanitize(string value)
        => System.Text.RegularExpressions.Regex.Replace(value, @"(://)[^/@\s]+@", "$1");

    private void Load()
    {
        try
        {
            if (!File.Exists(_filePath)) return;

            string json = File.ReadAllText(_filePath);
            var store = JsonSerializer.Deserialize(json, HistoryContext.Default.HistoryStore);
            if (store?.Entries == null) return;

            foreach (var (key, values) in store.Entries)
                _lists[key] = new ObservableCollection<string>(values);
        }
        catch { }
    }

    private void Save()
    {
        try
        {
            var store = new HistoryStore
            {
                Entries = _lists.ToDictionary(kv => kv.Key, kv => kv.Value.ToList())
            };

            string json = JsonSerializer.Serialize(store, HistoryContext.Default.HistoryStore);
            File.WriteAllText(_filePath, json);
        }
        catch { }
    }
}
