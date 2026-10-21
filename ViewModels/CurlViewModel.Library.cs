using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

/// <summary>Colour of a method / status for the lists (GET green, POST amber, PUT blue, PATCH violet, DELETE red).</summary>
public abstract class CurlToneItem : ObservableObject
{
    public abstract string MethodName { get; }
    public bool IsGet => MethodName == "GET";
    public bool IsPost => MethodName == "POST";
    public bool IsPut => MethodName == "PUT";
    public bool IsPatch => MethodName == "PATCH";
    public bool IsDelete => MethodName == "DELETE";
}

/// <summary>A named request kept in the profile.</summary>
public sealed partial class CurlSavedItem : CurlToneItem
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    [ObservableProperty] private string _name = string.Empty;
    [ObservableProperty] private bool _isEditing;
    [ObservableProperty] private string _editName = string.Empty;
    [ObservableProperty] private bool _isCurrent;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(MethodName), nameof(UrlText), nameof(IsGet), nameof(IsPost), nameof(IsPut), nameof(IsPatch), nameof(IsDelete))]
    private CurlRequest _request = new();
    public long SavedAt { get; set; }

    public override string MethodName => Request.Method;
    public string UrlText => CurlViewModel.StripUserInfo(Request.Url.Trim());
    public bool IsNotEditing => !IsEditing;
    partial void OnIsEditingChanged(bool value) => OnPropertyChanged(nameof(IsNotEditing));
}

/// <summary>A request that was sent. Headers / body are kept for the session only (never written to disk).</summary>
public sealed class CurlRecentItem : CurlToneItem
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public string Method { get; init; } = "GET";
    public string Url { get; init; } = string.Empty;
    public int Status { get; init; }
    public double Ms { get; init; }
    public long At { get; init; }
    public CurlRequest? Snapshot { get; init; }

    public override string MethodName => Method;
    public string StatusText => Status > 0 ? Status.ToString() : "ERR";
    public bool StatusOk => Status is > 0 and < 300;
    public bool StatusRedirect => Status is >= 300 and < 400;
    public bool StatusClientError => Status is >= 400 and < 500;
    public bool StatusBad => Status >= 500 || Status <= 0;
    public string MetaText
    {
        get
        {
            var when = DateTimeOffset.FromUnixTimeMilliseconds(At).ToLocalTime();
            string day = when.Date == DateTime.Today ? when.ToString("HH:mm:ss") : when.ToString("MMM d, HH:mm");
            return Ms > 0 ? $"{day} · {CurlViewModel.FormatMs(Ms)}" : day;
        }
    }
}

public partial class CurlViewModel
{
    public ObservableCollection<CurlSavedItem> SavedRequests { get; } = new();
    public ObservableCollection<CurlRecentItem> RecentRequests { get; } = new();

    /// <summary>0 Saved · 1 History.</summary>
    [ObservableProperty] private int _libraryIndex;
    public bool LibraryShowSaved => LibraryIndex == 0;
    public bool LibraryShowHistory => LibraryIndex == 1;
    public bool NoSaved => SavedRequests.Count == 0;
    public bool NoRecent => RecentRequests.Count == 0;
    public string SavedTabText => SavedRequests.Count > 0 ? $"Saved ({SavedRequests.Count})" : "Saved";
    public string HistoryTabText => RecentRequests.Count > 0 ? $"History ({RecentRequests.Count})" : "History";
    partial void OnLibraryIndexChanged(int value)
    {
        OnPropertyChanged(nameof(LibraryShowSaved));
        OnPropertyChanged(nameof(LibraryShowHistory));
    }

    private void LibraryCountsChanged()
    {
        OnPropertyChanged(nameof(NoSaved));
        OnPropertyChanged(nameof(NoRecent));
        OnPropertyChanged(nameof(SavedTabText));
        OnPropertyChanged(nameof(HistoryTabText));
    }

    // ---- the open saved request (shown as a chip; Save updates it in place)
    private string? _currentSavedId;
    public string? CurrentSavedId
    {
        get => _currentSavedId;
        set
        {
            if (_currentSavedId == value) return;
            _currentSavedId = value;
            foreach (var s in SavedRequests) s.IsCurrent = s.Id == value;
            OnPropertyChanged(nameof(CurrentSavedId));
            OnPropertyChanged(nameof(CurrentSavedName));
            OnPropertyChanged(nameof(HasSavedName));
            OnPropertyChanged(nameof(HasOptionChips));
            OnPropertyChanged(nameof(SaveMenuText));
        }
    }
    public string CurrentSavedName => SavedRequests.FirstOrDefault(s => s.Id == CurrentSavedId)?.Name ?? string.Empty;
    public bool HasSavedName => CurrentSavedName.Length > 0;
    public string SaveMenuText => HasSavedName ? $"Save \"{CurrentSavedName}\"" : "Save request…";

    // ---- the Save panel
    [ObservableProperty] private bool _isSaveOpen;
    [ObservableProperty] private string _saveName = string.Empty;

    // Saved lives in the profile file, which is rewritten after every settings change: a multi-MB body there made each of
    // those writes (several a second while typing elsewhere) re-serialize and seal it again under the profile's lock, which
    // the UI thread waits on. Bodies and text parts over this size aren't kept in Saved; a file body (Body → File) is.
    private const int MaxSavedTextChars = 256 * 1024;

    private CurlRequest ForLibrary(CurlRequest m)
    {
        bool cut = false;
        if (m.RawBody.Length > MaxSavedTextChars) { m.RawBody = string.Empty; cut = true; }
        foreach (var f in m.Form)
            if (f.Value.Length > MaxSavedTextChars) { f.Value = string.Empty; cut = true; }
        foreach (var p in m.Parts)
            if (!p.IsFile && p.Value.Length > MaxSavedTextChars) { p.Value = string.Empty; cut = true; }
        if (cut)
            ShowNote($"Saved without its body: Saved keeps bodies up to {MaxSavedTextChars / 1024} KB. "
                     + "For a bigger one, put it in a file and use Body → File.", isError: false);
        return m;
    }

    [RelayCommand]
    private void SaveRequest()
    {
        var item = SavedRequests.FirstOrDefault(s => s.Id == CurrentSavedId);
        if (item is null) { OpenSave(); return; }
        item.Request = ForLibrary(BuildModel());
        item.SavedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        PersistSaved();
        Flash($"Saved \"{item.Name}\"");
    }

    [RelayCommand]
    private void OpenSave()
    {
        IsImportOpen = false;
        var m = BuildModel();
        SaveName = HasSavedName ? CurrentSavedName + " copy" : $"{m.Method} {m.ShortLabel()}";
        IsSaveOpen = true;
    }

    [RelayCommand]
    private void CloseSave() => IsSaveOpen = false;

    [RelayCommand]
    private void ConfirmSave()
    {
        string name = SaveName.Trim();
        var m = ForLibrary(BuildModel());
        if (name.Length == 0) name = $"{m.Method} {m.ShortLabel()}";
        var item = new CurlSavedItem { Name = name, Request = m, SavedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() };
        SavedRequests.Insert(0, item);
        CurrentSavedId = item.Id;
        IsSaveOpen = false;
        LibraryCountsChanged();
        PersistSaved();
        Flash($"Saved \"{name}\" — it's under Saved");
    }

    [RelayCommand]
    private void OpenSaved(CurlSavedItem? item)
    {
        if (item is null) return;
        ApplyModel(item.Request.Clone());
        CurrentSavedId = item.Id;
        ClearResponse();
        DismissNote();
        SectionIndex = 0;
    }

    [RelayCommand]
    private void RenameSaved(CurlSavedItem? item)
    {
        if (item is null) return;
        foreach (var s in SavedRequests) s.IsEditing = false;
        item.EditName = item.Name;
        item.IsEditing = true;
    }

    [RelayCommand]
    private void CommitRename(CurlSavedItem? item)
    {
        if (item is null || !item.IsEditing) return;
        string name = item.EditName.Trim();
        item.IsEditing = false;
        if (name.Length == 0 || name == item.Name) return;
        item.Name = name;
        if (item.Id == CurrentSavedId) { OnPropertyChanged(nameof(CurrentSavedName)); OnPropertyChanged(nameof(SaveMenuText)); }
        PersistSaved();
    }

    [RelayCommand]
    private void CancelRename(CurlSavedItem? item)
    {
        if (item != null) item.IsEditing = false;
    }

    [RelayCommand]
    private void DeleteSaved(CurlSavedItem? item)
    {
        if (item is null) return;
        SavedRequests.Remove(item);
        if (item.Id == CurrentSavedId) CurrentSavedId = null;
        LibraryCountsChanged();
        PersistSaved();
        Flash($"Deleted \"{item.Name}\"");
    }

    [RelayCommand]
    private void OpenRecent(CurlRecentItem? item)
    {
        if (item is null) return;
        if (item.Snapshot != null) ApplyModel(item.Snapshot.Clone());
        else
        {
            // from an earlier session: only the method and URL were kept (headers / body can hold credentials)
            var m = BuildModel();
            m.Method = item.Method;
            m.Url = item.Url;
            m.Headers.Clear(); m.Cookies.Clear(); m.Form.Clear(); m.Parts.Clear();
            m.BodyMode = CurlBodyMode.None; m.RawBody = string.Empty; m.BodyFile = string.Empty;
            m.Auth = CurlAuthMode.None; m.AuthUser = m.AuthPass = m.AuthToken = string.Empty;
            ApplyModel(m, includeConnection: false);
            ShowNote("From an earlier session: only the method and URL are kept — headers and body aren't stored. Save a request to keep them.", isError: false);
        }
        CurrentSavedId = null;
        SectionIndex = 0;
    }

    [RelayCommand]
    private async Task RerunRecent(CurlRecentItem? item)
    {
        if (item is null || IsWorking) return;
        OpenRecent(item);
        await SendAsync();
    }

    [RelayCommand]
    private void ClearRecent()
    {
        RecentRequests.Clear();
        LibraryCountsChanged();
        PersistRecent();
    }

    private const int MaxRecent = 50;

    private void AddRecent(CurlRequest req, CurlResult res)
    {
        if (res.Cancelled) return;
        RecentRequests.Insert(0, new CurlRecentItem
        {
            Method = req.Method, Url = req.Url, Status = res.Responded ? res.Status : 0,
            Ms = res.Timing.TotalMs, At = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), Snapshot = req.Clone(),
        });
        while (RecentRequests.Count > MaxRecent) RecentRequests.RemoveAt(RecentRequests.Count - 1);
        LibraryCountsChanged();
        PersistRecent();
    }

    // ================================================================== storage
    // Saved requests are kept in the profile, sealed with SecretProtector (they may hold Authorization / cookies — the
    // user saved them on purpose, and the Saved list says what is kept). The history keeps only method, URL (no
    // user:pass@), status and time.

    private const string SavedKey = "curl.saved";
    private const string RecentKey = "curl.recent";
    private readonly object _libraryGate = new();
    private string? _pendingSaved, _pendingRecent;

    private void LoadLibrary()
    {
        _ = Task.Run(() =>
        {
            List<CurlSavedItem> saved = new();
            List<CurlRecentItem> recent = new();
            bool locked = false;
            try
            {
                string sealedJson = ProfileService.Instance.GetSetting(SavedKey) ?? string.Empty;
                string json = SecretProtector.Unprotect(sealedJson);
                // Sealed, but this run has no readable key file: the list is intact on disk and a later run opens it.
                // Nothing may be written over it meanwhile (see PersistSaved). (With the key loaded, a list that still
                // doesn't open was sealed on another machine: it reads as empty and the next save replaces it, as
                // SecretProtector documents.)
                locked = json.Length == 0 && sealedJson.Length > 0 && !SecretProtector.IsKeyAvailable;
                if (json.Length > 0)
                {
                    using var doc = JsonDocument.Parse(json);
                    if (doc.RootElement.TryGetProperty("items", out var items) && items.ValueKind == JsonValueKind.Array)
                        foreach (var e in items.EnumerateArray())
                        {
                            if (!e.TryGetProperty("req", out var req)) continue;
                            saved.Add(new CurlSavedItem
                            {
                                Id = CurlRequest.Str(e, "id", Guid.NewGuid().ToString("N")),
                                Name = CurlRequest.Str(e, "name", "Request"),
                                SavedAt = CurlRequest.Long(e, "at", 0),
                                Request = CurlRequest.FromJson(req),
                            });
                        }
                }
            }
            catch (Exception ex) { CrashLog.Write("Curl.LoadSaved", ex); }
            try
            {
                string json = ProfileService.Instance.GetSetting(RecentKey) ?? string.Empty;
                if (json.Length > 0)
                {
                    using var doc = JsonDocument.Parse(json);
                    if (doc.RootElement.ValueKind == JsonValueKind.Array)
                        foreach (var e in doc.RootElement.EnumerateArray())
                            recent.Add(new CurlRecentItem
                            {
                                Method = CurlRequest.Str(e, "m", "GET"), Url = CurlRequest.Str(e, "u", string.Empty),
                                Status = CurlRequest.Int(e, "s", 0), Ms = CurlRequest.Long(e, "ms", 0), At = CurlRequest.Long(e, "at", 0),
                            });
                }
            }
            catch (Exception ex) { CrashLog.Write("Curl.LoadRecent", ex); }
            Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                foreach (var s in saved) SavedRequests.Add(s);
                // the session's own sends (made before the load finished) stay first
                foreach (var r in recent.Take(MaxRecent - RecentRequests.Count)) RecentRequests.Add(r);
                _savedLocked = locked;
                _libraryLoaded = true;
                LibraryCountsChanged();
                // anything saved / sent meanwhile is written now — together with what was loaded, never instead of it
                if (_savedDirty) PersistSaved();
                if (_recentDirty) PersistRecent();
            });
        });
    }

    private bool _libraryLoaded, _savedDirty, _recentDirty;
    // The saved list on disk couldn't be opened this run (no readable key file, see LoadLibrary): this session's saves
    // stay in memory, and the stored list is never replaced by them. UI thread.
    private bool _savedLocked;

    private void PersistSaved()
    {
        if (!_libraryLoaded) { _savedDirty = true; return; }
        _savedDirty = false;
        if (_savedLocked)
        {
            ShowNote("Changes to Saved last for this session only: the requests saved before can't be unlocked right now "
                     + "(Echoes couldn't read its key file), so they are left as they are. Restart Echoes to try again.", isError: true);
            return;
        }
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            w.WriteNumber("v", 1);
            w.WriteStartArray("items");
            foreach (var s in SavedRequests)
            {
                w.WriteStartObject();
                w.WriteString("id", s.Id);
                w.WriteString("name", s.Name);
                w.WriteNumber("at", s.SavedAt);
                w.WritePropertyName("req");
                s.Request.WriteJson(w, includeSecrets: true);
                w.WriteEndObject();
            }
            w.WriteEndArray();
            w.WriteEndObject();
        }
        string json = Encoding.UTF8.GetString(ms.ToArray());
        lock (_libraryGate) _pendingSaved = json;
        _ = Task.Run(WriteLibrary);
    }

    private void PersistRecent()
    {
        if (!_libraryLoaded) { _recentDirty = true; return; }
        _recentDirty = false;
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartArray();
            foreach (var r in RecentRequests)
            {
                w.WriteStartObject();
                w.WriteString("m", r.Method);
                w.WriteString("u", UrlSecrets.Redact(StripUserInfo(r.Url)));
                w.WriteNumber("s", r.Status);
                w.WriteNumber("ms", (long)Math.Round(r.Ms));
                w.WriteNumber("at", r.At);
                w.WriteEndObject();
            }
            w.WriteEndArray();
        }
        string json = Encoding.UTF8.GetString(ms.ToArray());
        lock (_libraryGate) _pendingRecent = json;
        _ = Task.Run(WriteLibrary);
    }

    private void WriteLibrary()
    {
        lock (_libraryGate)
        {
            try
            {
                if (_pendingSaved is { } saved)
                {
                    ProfileService.Instance.SetSetting(SavedKey, saved.Length == 0 || saved.Contains("\"items\":[]") ? string.Empty : SecretProtector.Protect(saved));
                    _pendingSaved = null;
                }
                if (_pendingRecent is { } recent)
                {
                    ProfileService.Instance.SetSetting(RecentKey, recent == "[]" ? string.Empty : recent);
                    _pendingRecent = null;
                }
            }
            catch (Exception ex) { CrashLog.Write("Curl.WriteLibrary", ex); }
        }
    }

    private void FlushLibrary() => WriteLibrary();
}
