using System.Collections.ObjectModel;

namespace Echoes.Helpers;

/// <summary>
/// Backwards-compatible facade. All history now lives in the single profile file
/// managed by <see cref="ProfileService"/>.
/// </summary>
public sealed class HistoryService
{
    public static HistoryService Instance { get; } = new();
    private HistoryService() { }

    public ObservableCollection<string> Get(string key) => ProfileService.Instance.GetHistory(key);
    public string? Last(string key) => ProfileService.Instance.LastHistory(key);
    public void Add(string key, string? value) => ProfileService.Instance.AddHistory(key, value);
}
