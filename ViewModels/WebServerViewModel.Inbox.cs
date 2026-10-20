using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

/// <summary>A file a browser sent (or is sending) to this device.</summary>
public sealed partial class ReceivedFileRow : ObservableObject
{
    public required string Id { get; init; }
    public required long Size { get; init; }
    public required string From { get; init; }
    public required DateTime Time { get; init; }

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(CanOpen))] private string _name = string.Empty;
    /// <summary>Where the file is on this device (null once an Android copy moved into the picked folder).</summary>
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(CanOpen), nameof(CanShow), nameof(CanSave))] private string? _path;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(Detail), nameof(CanOpen), nameof(CanShow), nameof(CanSave))] private bool _isPending;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(Detail))] private double _percent;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(Detail), nameof(IsFailed), nameof(CanOpen), nameof(CanShow), nameof(CanSave))] private string? _error;
    /// <summary>Android: the folder / file it was saved to.</summary>
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(Detail), nameof(CanSave))] private string? _savedTo;

    public string SizeText => FileHttpServer.HumanSize(Size);
    public bool IsFailed => Error is not null;
    public bool IsDone => !IsPending && !IsFailed;
    public string Detail => Error
        ?? (IsPending
            ? $"{Percent.ToString("0", CultureInfo.InvariantCulture)}% of {SizeText} · from {From}"
            : $"{SizeText} · from {From} · {Time.ToString("HH:mm", CultureInfo.InvariantCulture)}" + (SavedTo is null ? string.Empty : " · saved to " + SavedTo));

    /// <summary>Desktop: open with its app — not for programs and scripts (those get "Show" only).</summary>
    public bool CanOpen => AppPlatform.IsDesktop && IsDone && Path is not null && !ShareInbox.IsRiskyToOpen(Name);
    public bool CanShow => AppPlatform.IsDesktop && IsDone && Path is not null;
    /// <summary>Android: the file is in the app's own storage until saved somewhere. (iOS: it is already in the Files app.)</summary>
    public bool CanSave => AppPlatform.IsMobile && !OperatingSystem.IsIOS() && IsDone && Path is not null && SavedTo is null;
}

/// <summary>
/// "Share &amp; chat" — files from browsers. Desktop: they land in a folder (Downloads\Echoes unless changed), with
/// Open (not for programs / scripts), Show in folder and Open folder. Android: they arrive in the app's own storage;
/// once a folder is picked (the system folder picker) every new file is copied into it, until then each has Save.
/// iOS: they arrive in Documents/Received, which the Files app shows (On My iPhone › Echoes).
/// A per-file size cap (MB) is checked before anything is sent, together with the free space.
/// </summary>
public partial class WebServerViewModel
{
    private const string KInbox = "webserver.inbox", KMaxUpload = "webserver.maxUploadMb";
    public const int DefaultMaxUploadMb = 4096;
    private const int MaxReceivedRows = 200, MaxPendingRows = 100;

    public ObservableCollection<ReceivedFileRow> ReceivedFiles { get; } = new();
    /// <summary>Desktop: the folder path. Android: the picked folder's name (empty = the app's own storage).</summary>
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(InboxDisplay))] private string _inboxPath = string.Empty;
    [ObservableProperty] private int _maxUploadMb = DefaultMaxUploadMb;
    /// <summary>A file / folder picker that failed (shown on the Files tab).</summary>
    [ObservableProperty] private string? _filesError;

    private IStorageFolder? _androidFolder;
    private bool _restoringInbox;

    // ---- what is stored, and Clean up. Desktop: a list of the files THIS app received (path, size, sender, time) is kept
    // in the profile, so they are listed again after a restart and Clean up deletes those and nothing else — the folder may
    // be Downloads itself. A file whose size changed since (edited, replaced) is the user's now: left alone, dropped from
    // the list. A backup never brings the list along (ProfileService.ClearedOnImport). Android: the app's own inbox folder
    // only ever holds what Echoes received, so it is measured and cleaned as a whole; files moved into a picked folder are
    // out of the app's storage and not touched.
    private const string KReceived = "webserver.received";
    private const int MaxTracked = 500;
    private readonly record struct Tracked(string Path, long Size, string From, long TimeMs);
    private readonly object _trackedGate = new();
    private List<Tracked>? _tracked;   // under _trackedGate

    /// <summary>"4 files · 12.4 MB" (what Clean up would free), or what's stored when nothing is.</summary>
    [ObservableProperty] private string _storedText = string.Empty;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(CanCleanUp))] private long _storedBytes;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(CanCleanUp))] private int _storedFiles;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(IsNotConfirmingCleanup))] private bool _isConfirmingCleanup;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(CanCleanUp))] private bool _isCleaning;
    public bool CanCleanUp => (StoredFiles > 0 || StoredBytes > 0) && !IsCleaning;
    public bool IsNotConfirmingCleanup => !IsConfirmingCleanup;
    public string CleanupPrompt => $"Delete {FileCount(StoredFiles)} ({FileHttpServer.HumanSize(StoredBytes)}) that Echoes received?";

    private static string FileCount(int n) => n == 1 ? "1 file" : $"{n.ToString(CultureInfo.InvariantCulture)} files";

    public bool HasReceived => ReceivedFiles.Count > 0;
    public long MaxUploadBytes => (long)Math.Clamp(MaxUploadMb, 1, 1_048_576) * 1024 * 1024;
    public string InboxDisplay => OperatingSystem.IsIOS() ? "Files app › Echoes › Received"
        : OperatingSystem.IsAndroid() || AppPlatform.IsMobile && InboxPath.Length == 0
            ? (InboxPath.Length > 0 ? InboxPath : "App storage (tap Save on each)")
            : InboxPath;
    public bool CanOpenInbox => LinkHelper.CanOpenFolder && AppPlatform.IsDesktop;
    /// <summary>iOS can't write outside the app's own folders (the Files app shows this one), so there is nothing to pick.</summary>
    public bool CanChangeInbox => !OperatingSystem.IsIOS();

    private void InitInbox()
    {
        HookForeground();
        // back on Share & chat with the Chat tab showing: what arrived is read
        PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ModeIndex) && IsChatInView) UnreadCount = 0;
        };
        var p = ProfileService.Instance;
        _restoringInbox = true;
        try
        {
            MaxUploadMb = Math.Clamp(p.GetInt(KMaxUpload, DefaultMaxUploadMb), 1, 1_048_576);
            if (!OperatingSystem.IsAndroid())
            {
                string? saved = OperatingSystem.IsIOS() ? null : p.GetSetting(KInbox);
                InboxPath = saved is { Length: > 0 } && Path.IsPathFullyQualified(saved) ? saved : ShareInbox.DefaultFolder();
                // iOS: the Files app lists the Echoes folder once it holds something
                if (OperatingSystem.IsIOS()) { try { Directory.CreateDirectory(InboxPath); } catch { } }
            }
        }
        finally { _restoringInbox = false; }
        if (OperatingSystem.IsAndroid()) _ = Task.Run(ListEarlierAndroidFiles);
        else _ = Task.Run(ListTrackedFiles);
        RefreshStored();
    }

    partial void OnMaxUploadMbChanged(int value)
    {
        if (value is < 1 or > 1_048_576) return;
        if (!_restoringInbox) ProfileService.Instance.SetSetting(KMaxUpload, value.ToString(CultureInfo.InvariantCulture));
        if (_hub is { } hub) hub.MaxUploadBytes = MaxUploadBytes;
    }

    /// <summary>Where the hub saves finished files: the chosen folder (desktop) or the app's inbox (Android).</summary>
    private string HubInboxFolder()
        => OperatingSystem.IsAndroid() ? ShareInbox.AppInboxFolder()
            : InboxPath.Length > 0 && Path.IsPathFullyQualified(InboxPath) ? InboxPath : ShareInbox.DefaultFolder();

    /// <summary>Desktop: a folder from the folder picker.</summary>
    public void SetInboxFolder(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path)) return;
        InboxPath = path;
        ProfileService.Instance.SetSetting(KInbox, path);
        if (_hub is { } hub) hub.InboxFolder = path;
    }

    /// <summary>Android: the picked folder (and its bookmark to reopen it next time; null = restored from one).</summary>
    public void SetAndroidFolder(IStorageFolder folder, string? bookmark)
    {
        _androidFolder = folder;
        InboxPath = folder.Name;
        if (bookmark is { Length: > 0 }) ProfileService.Instance.SetSetting(KInbox, bookmark);
        // files that arrived before the folder was there: move them in now
        foreach (var r in ReceivedFiles.Where(r => r.IsDone && r.Path is not null && r.SavedTo is null).ToList()) _ = DeliverAsync(r);
    }

    /// <summary>Android: the saved folder bookmark (the view reopens it through the storage provider).</summary>
    public string? AndroidFolderBookmark => OperatingSystem.IsAndroid() ? ProfileService.Instance.GetSetting(KInbox) : null;
    public bool NeedsAndroidFolder => OperatingSystem.IsAndroid() && _androidFolder is null;

    [RelayCommand]
    private void OpenInbox()
    {
        string folder = HubInboxFolder();
        try { Directory.CreateDirectory(folder); } catch { }
        LinkHelper.OpenFolder(folder);
    }

    /// <summary>Desktop: the file selected in its folder (Windows), else the folder.</summary>
    [RelayCommand]
    private void ShowReceived(ReceivedFileRow? row)
    {
        if (row?.Path is not { } path) return;
        if (OperatingSystem.IsWindows() && File.Exists(path))
        {
            try
            {
                var psi = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"))
                {
                    UseShellExecute = false,
                    // a Windows path can't hold a quote: the argument can't be broken out of
                    Arguments = "/select,\"" + path + "\"",
                };
                Process.Start(psi)?.Dispose();
                return;
            }
            catch { }
        }
        LinkHelper.OpenFolder(Path.GetDirectoryName(path));
    }

    // ---------------------------------------------------------------- stored files, Clean up

    [RelayCommand]
    private void AskCleanUp()
    {
        if (!CanCleanUp) return;
        OnPropertyChanged(nameof(CleanupPrompt));
        IsConfirmingCleanup = true;
    }

    [RelayCommand]
    private void CancelCleanUp() => IsConfirmingCleanup = false;

    /// <summary>Deletes what Echoes received (desktop: the tracked files; Android: the app's inbox), then the rows of
    /// files that are gone. Partial files of uploads still running stay.</summary>
    [RelayCommand]
    private async Task ConfirmCleanUp()
    {
        IsConfirmingCleanup = false;
        if (IsCleaning) return;
        IsCleaning = true;
        try
        {
            bool hubRunning = _hub is not null;
            string inbox = HubInboxFolder();
            var (deleted, failed, bytes) = await Task.Run(() => OperatingSystem.IsAndroid() ? CleanAppInbox(hubRunning) : CleanTracked(inbox, hubRunning));
            foreach (var row in ReceivedFiles.Where(x => !x.IsPending && x.Path is not null && !File.Exists(x.Path)).ToList())
                ReceivedFiles.Remove(row);
            OnPropertyChanged(nameof(HasReceived));
            FilesError = failed > 0 ? $"{FileCount(failed)} couldn't be deleted (open in another app?)." : null;
            AppendLog($"clean up: {FileCount(deleted)} deleted, {FileHttpServer.HumanSize(bytes)} freed" + (failed > 0 ? $", {FileCount(failed)} left (in use)" : string.Empty));
        }
        catch (Exception ex) { FilesError = "Clean up failed: " + ex.Message; }
        finally
        {
            IsCleaning = false;
            RefreshStored();
        }
    }

    // Background: the tracked files that are still the ones Echoes wrote (same size, a plain file) are deleted; vanished or
    // changed ones just leave the list; leftover partial uploads go too when no upload can be running.
    private (int Deleted, int Failed, long Bytes) CleanTracked(string inbox, bool hubRunning)
    {
        int deleted = 0, failed = 0;
        long bytes = 0;
        List<Tracked> snapshot;
        lock (_trackedGate) snapshot = new List<Tracked>(TrackedLocked());
        var keep = new List<Tracked>();
        foreach (var t in snapshot)
        {
            try
            {
                var fi = new FileInfo(t.Path);
                if (!fi.Exists || (fi.Attributes & FileAttributes.ReparsePoint) != 0 || fi.Length != t.Size) continue;
                fi.Delete();
                deleted++;
                bytes += t.Size;
            }
            catch
            {
                failed++;
                keep.Add(t);
            }
        }
        if (!hubRunning) bytes += DeletePartials(inbox, ref deleted);
        lock (_trackedGate)
        {
            // files that arrived during the clean up stay tracked
            var now = TrackedLocked();
            _tracked = now.Where(e => !snapshot.Contains(e)).Concat(keep).ToList();
        }
        SaveTracked();
        return (deleted, failed, bytes);
    }

    // Android: the app's inbox only ever holds what Echoes received (until it is saved / moved out).
    private static (int Deleted, int Failed, long Bytes) CleanAppInbox(bool hubRunning)
    {
        int deleted = 0, failed = 0;
        long bytes = 0;
        string dir = ShareInbox.AppInboxFolder();
        if (!Directory.Exists(dir)) return (0, 0, 0);
        foreach (var f in new DirectoryInfo(dir).EnumerateFiles())
        {
            if (hubRunning && f.Name.StartsWith(".echoes-", StringComparison.Ordinal)) continue;
            try
            {
                long len = f.Length;
                f.Delete();
                deleted++;
                bytes += len;
            }
            catch { failed++; }
        }
        return (deleted, failed, bytes);
    }

    private static long DeletePartials(string folder, ref int deleted)
    {
        long bytes = 0;
        try
        {
            if (!Directory.Exists(folder)) return 0;
            foreach (var f in new DirectoryInfo(folder).EnumerateFiles(".echoes-*.part"))
            {
                try
                {
                    long len = f.Length;
                    f.Delete();
                    deleted++;
                    bytes += len;
                }
                catch { }
            }
        }
        catch { }
        return bytes;
    }

    /// <summary>Measures what is stored (off the UI thread) and shows it: the count and size Clean up would free.</summary>
    private void RefreshStored()
    {
        bool hubRunning = _hub is not null;
        string inbox = HubInboxFolder();
        _ = Task.Run(() =>
        {
            int files = 0;
            long bytes = 0;
            try
            {
                if (OperatingSystem.IsAndroid())
                {
                    string dir = ShareInbox.AppInboxFolder();
                    if (Directory.Exists(dir))
                        foreach (var f in new DirectoryInfo(dir).EnumerateFiles())
                        {
                            if (hubRunning && f.Name.StartsWith(".echoes-", StringComparison.Ordinal)) continue;
                            files++;
                            bytes += f.Length;
                        }
                }
                else
                {
                    List<Tracked> list;
                    lock (_trackedGate) list = new List<Tracked>(TrackedLocked());
                    foreach (var t in list)
                    {
                        var fi = new FileInfo(t.Path);
                        if (!fi.Exists || fi.Length != t.Size) continue;
                        files++;
                        bytes += t.Size;
                    }
                    if (!hubRunning && Directory.Exists(inbox))
                        foreach (var f in new DirectoryInfo(inbox).EnumerateFiles(".echoes-*.part"))
                        {
                            files++;
                            bytes += f.Length;
                        }
                }
            }
            catch { }
            Dispatcher.UIThread.Post(() =>
            {
                StoredFiles = files;
                StoredBytes = bytes;
                StoredText = files == 0 && bytes == 0
                    ? "Nothing stored"
                    : $"{FileCount(files)} · {FileHttpServer.HumanSize(bytes)}" + (OperatingSystem.IsAndroid() ? " in the app" : string.Empty);
                OnPropertyChanged(nameof(CleanupPrompt));
            });
        });
    }

    // ---- the tracked list (desktop) ----

    private List<Tracked> TrackedLocked() => _tracked ??= ParseTracked(ProfileService.Instance.GetSetting(KReceived));

    private void Track(string path, string from)
    {
        long size;
        try { size = new FileInfo(path).Length; } catch { return; }
        lock (_trackedGate)
        {
            var list = TrackedLocked();
            list.RemoveAll(t => string.Equals(t.Path, path, StringComparison.OrdinalIgnoreCase));
            list.Insert(0, new Tracked(path, size, from, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()));
            if (list.Count > MaxTracked) list.RemoveRange(MaxTracked, list.Count - MaxTracked);
        }
        SaveTracked();
        RefreshStored();
    }

    private void SaveTracked()
    {
        string json;
        lock (_trackedGate)
        {
            using var ms = new MemoryStream();
            using (var w = new System.Text.Json.Utf8JsonWriter(ms))
            {
                w.WriteStartArray();
                foreach (var t in TrackedLocked())
                {
                    w.WriteStartObject();
                    w.WriteString("p", t.Path);
                    w.WriteNumber("s", t.Size);
                    w.WriteString("f", t.From);
                    w.WriteNumber("t", t.TimeMs);
                    w.WriteEndObject();
                }
                w.WriteEndArray();
            }
            json = System.Text.Encoding.UTF8.GetString(ms.ToArray());
        }
        ProfileService.Instance.SetSetting(KReceived, json);
    }

    private static List<Tracked> ParseTracked(string? json)
    {
        var list = new List<Tracked>();
        if (string.IsNullOrWhiteSpace(json)) return list;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != System.Text.Json.JsonValueKind.Array) return list;
            foreach (var e in doc.RootElement.EnumerateArray())
            {
                if (e.ValueKind != System.Text.Json.JsonValueKind.Object) continue;
                string? p = e.TryGetProperty("p", out var pv) && pv.ValueKind == System.Text.Json.JsonValueKind.String ? pv.GetString() : null;
                if (p is not null && OperatingSystem.IsIOS()) p = ShareInbox.RebaseIos(p);   // the container folder changes with an update
                if (p is null || !Path.IsPathFullyQualified(p)) continue;
                long s = e.TryGetProperty("s", out var sv) && sv.TryGetInt64(out long sl) && sl >= 0 ? sl : -1;
                if (s < 0) continue;
                string f = e.TryGetProperty("f", out var fv) && fv.ValueKind == System.Text.Json.JsonValueKind.String ? fv.GetString() ?? "" : "";
                long t = e.TryGetProperty("t", out var tv) && tv.TryGetInt64(out long tl) ? tl : 0;
                list.Add(new Tracked(p, s, ShareHub.CleanName(f), t));
                if (list.Count >= MaxTracked) break;
            }
        }
        catch (System.Text.Json.JsonException) { }
        return list;
    }

    // Desktop: the files received in earlier runs (still there, still the same size) are listed again.
    private void ListTrackedFiles()
    {
        try
        {
            List<Tracked> list;
            lock (_trackedGate) list = new List<Tracked>(TrackedLocked());
            var rows = new List<ReceivedFileRow>();
            foreach (var t in list.Take(MaxReceivedRows))
            {
                var fi = new FileInfo(t.Path);
                if (!fi.Exists || fi.Length != t.Size) continue;
                rows.Add(new ReceivedFileRow
                {
                    Id = "t:" + t.Path, Name = fi.Name, Size = t.Size, From = t.From.Length > 0 ? t.From : "earlier",
                    Time = t.TimeMs > 0 ? DateTimeOffset.FromUnixTimeMilliseconds(t.TimeMs).LocalDateTime : fi.LastWriteTime, Path = fi.FullName,
                });
            }
            if (rows.Count == 0) return;
            Dispatcher.UIThread.Post(() =>
            {
                foreach (var r in rows)
                    if (ReceivedFiles.All(x => !string.Equals(x.Path, r.Path, StringComparison.OrdinalIgnoreCase))) ReceivedFiles.Add(r);
                OnPropertyChanged(nameof(HasReceived));
            });
        }
        catch { }
    }

    // UI thread (FlushUi): upload events into rows, and the progress of the ones arriving.
    private void DrainUploads()
    {
        bool changed = false;
        while (_pendingUploads.TryDequeue(out var u))
        {
            changed = true;
            var row = ReceivedFiles.FirstOrDefault(r => r.Id == u.Upload.Id);
            if (u.Started)
            {
                if (row is not null) continue;
                ReceivedFiles.Insert(0, new ReceivedFileRow
                {
                    Id = u.Upload.Id, Name = u.Upload.Name, Size = u.Upload.Size, From = u.Upload.From, Time = u.Upload.Started,
                    IsPending = true,
                });
                continue;
            }
            if (row is null)
            {
                row = new ReceivedFileRow { Id = u.Upload.Id, Name = u.Upload.Name, Size = u.Upload.Size, From = u.Upload.From, Time = u.Upload.Started };
                ReceivedFiles.Insert(0, row);
            }
            row.IsPending = false;
            if (u.Path is not null)
            {
                row.Name = Path.GetFileName(u.Path);
                row.Path = u.Path;
                row.Percent = 100;
                if (OperatingSystem.IsAndroid())
                {
                    if (_androidFolder is not null) _ = DeliverAsync(row);
                    RefreshStored();
                }
                else Track(u.Path, u.Upload.From);
            }
            else if (u.Error is "Canceled by the sender.") ReceivedFiles.Remove(row);
            else row.Error = u.Error ?? "Not received.";
        }

        if (_hub is { } hub && ReceivedFiles.Any(r => r.IsPending))
        {
            var active = hub.ActiveUploads();
            foreach (var r in ReceivedFiles)
            {
                if (!r.IsPending) continue;
                var a = active.FirstOrDefault(x => x.Id == r.Id);
                if (a is not null && a.Size > 0) r.Percent = Math.Floor(a.Received * 100.0 / a.Size);
            }
        }
        if (!changed) return;
        while (ReceivedFiles.Count > MaxReceivedRows)
        {
            var oldest = ReceivedFiles.LastOrDefault(r => !r.IsPending && !(OperatingSystem.IsAndroid() && r.SavedTo is null && r.Path is not null));
            if (oldest is null) break;
            ReceivedFiles.Remove(oldest);
        }
        // Files still arriving: the newest MaxPendingRows (many browsers starting files at once can't flood the list; a
        // file whose row went gets a row again when it finishes)
        int pending = ReceivedFiles.Count(r => r.IsPending);
        for (int i = ReceivedFiles.Count - 1; i >= 0 && pending > MaxPendingRows; i--)
        {
            if (!ReceivedFiles[i].IsPending) continue;
            ReceivedFiles.RemoveAt(i);
            pending--;
        }
        OnPropertyChanged(nameof(HasReceived));
    }

    /// <summary>Android: a received file into the picked folder (a free name there), then out of the app's storage.</summary>
    private async Task DeliverAsync(ReceivedFileRow row)
    {
        var folder = _androidFolder;
        string? src = row.Path;
        if (folder is null || src is null || row.SavedTo is not null) return;
        try
        {
            string name = await FreeNameAsync(folder, row.Name);
            var file = await folder.CreateFileAsync(name) ?? throw new IOException("the folder didn't accept a new file");
            await Task.Run(async () =>
            {
                await using var dst = await file.OpenWriteAsync();
                await using var s = File.OpenRead(src);
                await s.CopyToAsync(dst);
            });
            try { File.Delete(src); } catch { }
            row.Name = file.Name;
            row.SavedTo = folder.Name;
            row.Path = null;
        }
        catch (Exception ex)
        {
            AppendLog($"couldn't move {row.Name} into {folder.Name}: {ex.Message} — it stays in the app (Save)");
        }
        RefreshStored();
    }

    private static async Task<string> FreeNameAsync(IStorageFolder folder, string name)
    {
        for (int n = 1; n <= 50; n++)
        {
            string candidate = n == 1 ? name : ShareInbox.WithCounter(name, n);
            IStorageFile? existing = null;
            try { existing = await folder.GetFileAsync(candidate); } catch { }
            if (existing is null) return candidate;
            existing.Dispose();
        }
        return ShareInbox.WithCounter(name, (int)(DateTime.Now.Ticks % 100_000) + 501);
    }

    /// <summary>Phone: a received file saved where the user picks (the system "save as"); then it leaves app storage.</summary>
    public async Task SaveReceivedAsync(ReceivedFileRow row, IStorageProvider storage)
    {
        if (row.Path is not { } src || !File.Exists(src)) return;
        try
        {
            var file = await storage.SaveFilePickerAsync(new FilePickerSaveOptions { Title = "Save the received file", SuggestedFileName = row.Name });
            if (file is null) return;
            await Task.Run(async () =>
            {
                await using var dst = await file.OpenWriteAsync();
                await using var s = File.OpenRead(src);
                await s.CopyToAsync(dst);
            });
            row.SavedTo = file.Name;
            if (OperatingSystem.IsAndroid())
            {
                try { File.Delete(src); } catch { }
                row.Path = null;
            }
        }
        catch (Exception ex) { AppendLog($"saving {row.Name} failed: {ex.Message}"); }
        RefreshStored();
    }

    // Android: files from an earlier run still in the app's storage (never saved) are listed again.
    private void ListEarlierAndroidFiles()
    {
        try
        {
            string dir = ShareInbox.AppInboxFolder();
            if (!Directory.Exists(dir)) return;
            var rows = new DirectoryInfo(dir).EnumerateFiles()
                .Where(f => !f.Name.StartsWith(".echoes-", StringComparison.Ordinal))
                .OrderByDescending(f => f.LastWriteTimeUtc).Take(MaxReceivedRows)
                .Select(f => new ReceivedFileRow
                {
                    Id = "earlier:" + f.Name, Name = f.Name, Size = f.Length, From = "earlier", Time = f.LastWriteTime, Path = f.FullName,
                }).ToList();
            if (rows.Count == 0) return;
            Dispatcher.UIThread.Post(() =>
            {
                foreach (var r in rows) if (ReceivedFiles.All(x => x.Path != r.Path)) ReceivedFiles.Add(r);
                OnPropertyChanged(nameof(HasReceived));
            });
        }
        catch { }
    }
}
