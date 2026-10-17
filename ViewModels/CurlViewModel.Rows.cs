using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

/// <summary>One editable name/value row (query parameter, header, cookie, form field). The list always ends with an empty
/// "add" row (<see cref="IsNew"/>): typing into it makes it a real row and opens a fresh one below.</summary>
public sealed partial class CurlKvRow : ObservableObject
{
    private readonly CurlKvList _list;
    internal CurlKvRow(CurlKvList list) => _list = list;

    [ObservableProperty] private bool _enabled = true;
    [ObservableProperty] private string _name = string.Empty;
    [ObservableProperty] private string _value = string.Empty;
    [ObservableProperty] private bool _isNew;

    /// <summary>Query parameters only: a bare "?flag" is written back without '='.</summary>
    public bool HasEquals { get; set; } = true;

    public bool IsReal => !IsNew;

    /// <summary>Common values for this header name (the value box's suggestions).</summary>
    public IReadOnlyList<string> ValueSuggestions => CurlHeaderHints.ValuesFor(Name);

    partial void OnEnabledChanged(bool value) => _list.RowChanged(this);
    partial void OnNameChanged(string value)
    {
        OnPropertyChanged(nameof(ValueSuggestions));
        _list.RowChanged(this);
    }
    partial void OnValueChanged(string value)
    {
        if (value.Length > 0) HasEquals = true;
        _list.RowChanged(this);
    }
    partial void OnIsNewChanged(bool value) => OnPropertyChanged(nameof(IsReal));

    [RelayCommand]
    private void Remove() => _list.Remove(this);
}

/// <summary>An editable list of <see cref="CurlKvRow"/> with the trailing "add" row kept in place.</summary>
public sealed class CurlKvList
{
    private readonly Action _changed;
    private int _suspend;

    public ObservableCollection<CurlKvRow> Rows { get; } = new();

    public CurlKvList(Action changed)
    {
        _changed = changed;
        AddBlank();
    }

    private void AddBlank() => Rows.Add(new CurlKvRow(this) { IsNew = true });

    internal void RowChanged(CurlKvRow row)
    {
        if (_suspend > 0) return;
        if (row.IsNew && (row.Name.Length > 0 || row.Value.Length > 0))
        {
            row.IsNew = false;
            AddBlank();
        }
        _changed();
    }

    public void Remove(CurlKvRow row)
    {
        if (row.IsNew) return;
        Rows.Remove(row);
        _changed();
    }

    /// <summary>Replace every row (an import, a saved request, the URL's query) without firing per-row changes.</summary>
    public void Load(IEnumerable<CurlPair> pairs, bool notify = true)
    {
        _suspend++;
        try
        {
            Rows.Clear();
            foreach (var p in pairs)
                Rows.Add(new CurlKvRow(this) { Name = p.Name, Value = p.Value, Enabled = p.Enabled, HasEquals = p.HasEquals });
            AddBlank();
        }
        finally { _suspend--; }
        if (notify) _changed();
    }

    public List<CurlPair> ToPairs() =>
        Rows.Where(r => !r.IsNew).Select(r => new CurlPair(r.Name, r.Value, r.Enabled) { HasEquals = r.HasEquals }).ToList();

    /// <summary>Copy <paramref name="pairs"/> onto the enabled rows, in order, without rebuilding them (same count only).</summary>
    public bool UpdateEnabledInPlace(IReadOnlyList<CurlPair> pairs)
    {
        var enabled = Rows.Where(r => !r.IsNew && r.Enabled).ToList();
        if (enabled.Count != pairs.Count) return false;
        _suspend++;
        try
        {
            for (int i = 0; i < pairs.Count; i++)
            {
                enabled[i].HasEquals = pairs[i].HasEquals;
                if (enabled[i].Name != pairs[i].Name) enabled[i].Name = pairs[i].Name;
                if (enabled[i].Value != pairs[i].Value) enabled[i].Value = pairs[i].Value;
            }
        }
        finally { _suspend--; }
        return true;
    }

    /// <summary>Enabled rows with a name — the number shown on the tab.</summary>
    public int ActiveCount => Rows.Count(r => !r.IsNew && r.Enabled && r.Name.Trim().Length > 0);
}

/// <summary>One multipart/form-data part: a text field or a file.</summary>
public sealed partial class CurlPartRow : ObservableObject
{
    private readonly CurlPartList _list;
    internal CurlPartRow(CurlPartList list) => _list = list;

    [ObservableProperty] private bool _enabled = true;
    [ObservableProperty] private string _name = string.Empty;
    [ObservableProperty] private string _value = string.Empty;
    [ObservableProperty] private bool _isFile;
    [ObservableProperty] private string _filePath = string.Empty;
    [ObservableProperty] private string _contentType = string.Empty;
    [ObservableProperty] private string _fileNameOverride = string.Empty;
    [ObservableProperty] private bool _isNew;

    public bool IsReal => !IsNew;
    public bool IsText => !IsFile;
    public bool HasFile => IsFile && FilePath.Length > 0;
    public bool NeedsFile => IsFile && FilePath.Length == 0;
    /// <summary>The file's own name, for the chip.</summary>
    public string FileLabel => FilePath.Length == 0 ? string.Empty : DisplayName(FilePath);

    internal static string DisplayName(string path)
    {
        if (path.StartsWith("content://", StringComparison.OrdinalIgnoreCase))
        {
            string last = Uri.UnescapeDataString(path.TrimEnd('/'));
            int slash = Math.Max(last.LastIndexOf('/'), last.LastIndexOf(':'));
            return slash >= 0 ? last[(slash + 1)..] : last;
        }
        return System.IO.Path.GetFileName(path);
    }

    partial void OnEnabledChanged(bool value) => _list.RowChanged(this);
    partial void OnNameChanged(string value) => _list.RowChanged(this);
    partial void OnValueChanged(string value) => _list.RowChanged(this);
    partial void OnContentTypeChanged(string value) => _list.RowChanged(this);
    partial void OnIsFileChanged(bool value)
    {
        OnPropertyChanged(nameof(IsText));
        OnPropertyChanged(nameof(HasFile));
        OnPropertyChanged(nameof(NeedsFile));
        _list.RowChanged(this);
    }
    partial void OnFilePathChanged(string value)
    {
        OnPropertyChanged(nameof(HasFile));
        OnPropertyChanged(nameof(NeedsFile));
        OnPropertyChanged(nameof(FileLabel));
        _list.RowChanged(this);
    }
    partial void OnIsNewChanged(bool value) => OnPropertyChanged(nameof(IsReal));

    [RelayCommand] private void Remove() => _list.Remove(this);
    [RelayCommand] private void ClearFile() => FilePath = string.Empty;
    [RelayCommand] private void UseText() => IsFile = false;
    [RelayCommand] private void UseFile() => IsFile = true;
}

public sealed class CurlPartList
{
    private readonly Action _changed;
    private int _suspend;
    public ObservableCollection<CurlPartRow> Rows { get; } = new();

    public CurlPartList(Action changed)
    {
        _changed = changed;
        AddBlank();
    }

    private void AddBlank() => Rows.Add(new CurlPartRow(this) { IsNew = true });

    internal void RowChanged(CurlPartRow row)
    {
        if (_suspend > 0) return;
        if (row.IsNew && (row.Name.Length > 0 || row.Value.Length > 0 || row.FilePath.Length > 0 || row.IsFile))
        {
            row.IsNew = false;
            AddBlank();
        }
        _changed();
    }

    public void Remove(CurlPartRow row)
    {
        if (row.IsNew) return;
        Rows.Remove(row);
        _changed();
    }

    public void Load(IEnumerable<CurlPart> parts, bool notify = true)
    {
        _suspend++;
        try
        {
            Rows.Clear();
            foreach (var p in parts)
                Rows.Add(new CurlPartRow(this)
                {
                    Name = p.Name, Enabled = p.Enabled, IsFile = p.IsFile,
                    Value = p.IsFile ? string.Empty : p.Value, FilePath = p.IsFile ? p.Value : string.Empty,
                    ContentType = p.ContentType ?? string.Empty, FileNameOverride = p.FileName ?? string.Empty,
                });
            AddBlank();
        }
        finally { _suspend--; }
        if (notify) _changed();
    }

    public List<CurlPart> ToParts() => Rows.Where(r => !r.IsNew).Select(r => new CurlPart
    {
        Enabled = r.Enabled, Name = r.Name, IsFile = r.IsFile, Value = r.IsFile ? r.FilePath : r.Value,
        ContentType = r.ContentType.Trim().Length > 0 ? r.ContentType.Trim() : null,
        FileName = r.FileNameOverride.Trim().Length > 0 ? r.FileNameOverride.Trim() : null,
    }).ToList();

    public int ActiveCount => Rows.Count(r => !r.IsNew && r.Enabled && r.Name.Length > 0);
}

/// <summary>A response (or sent request) header line.</summary>
public sealed record CurlHeaderRow(string Name, string Value);

/// <summary>One bar of the timing waterfall: offset and length as fractions of the total.</summary>
public sealed record CurlTimingRow(string Label, string Value, double Start, double Length, string Kind)
{
    public bool IsDns => Kind == "dns";
    public bool IsConnect => Kind == "connect";
    public bool IsTls => Kind == "tls";
    public bool IsWait => Kind == "wait";
    public bool IsDownload => Kind == "download";
}

/// <summary>One step of the redirect chain.</summary>
public sealed record CurlHopRow(string Status, string Method, string Url, string Kind)
{
    public bool IsSuccess => Kind == "success";
    public bool IsInfo => Kind == "info";
    public bool IsWarning => Kind == "warning";
    public bool IsDanger => Kind == "danger";
}

/// <summary>Header names and common values for the suggestion boxes.</summary>
public static class CurlHeaderHints
{
    public static readonly string[] Names =
    {
        "Accept", "Accept-Charset", "Accept-Encoding", "Accept-Language", "Authorization", "Cache-Control", "Connection",
        "Content-Encoding", "Content-Language", "Content-Type", "Cookie", "DNT", "Expect", "Forwarded", "From", "Host",
        "If-Match", "If-Modified-Since", "If-None-Match", "If-Range", "If-Unmodified-Since", "Origin", "Pragma", "Priority",
        "Proxy-Authorization", "Range", "Referer", "TE", "Upgrade", "User-Agent", "Via", "X-Api-Key", "X-Correlation-ID",
        "X-CSRF-Token", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP", "X-Request-ID",
        "X-Requested-With",
    };

    private static readonly Dictionary<string, string[]> Values = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Accept"] = new[] { "application/json", "*/*", "text/html", "application/xml", "text/plain", "text/event-stream" },
        ["Content-Type"] = new[] { "application/json", "application/x-www-form-urlencoded", "multipart/form-data", "text/plain", "application/xml", "text/xml", "application/octet-stream" },
        ["Accept-Encoding"] = new[] { "gzip, deflate, br", "gzip", "identity" },
        ["Accept-Language"] = new[] { "en-US,en;q=0.9", "en" },
        ["Cache-Control"] = new[] { "no-cache", "no-store", "max-age=0" },
        ["Connection"] = new[] { "keep-alive", "close" },
        ["Authorization"] = new[] { "Bearer ", "Basic " },
        ["X-Requested-With"] = new[] { "XMLHttpRequest" },
        ["Pragma"] = new[] { "no-cache" },
        ["DNT"] = new[] { "1" },
        ["Upgrade"] = new[] { "websocket", "h2c" },
    };

    public static IReadOnlyList<string> ValuesFor(string? name)
        => name != null && Values.TryGetValue(name.Trim(), out var v) ? v : Array.Empty<string>();
}
