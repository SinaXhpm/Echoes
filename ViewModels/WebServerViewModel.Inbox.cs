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
    /// <summary>Phone: the file is in the app's own storage until saved somewhere.</summary>
    public bool CanSave => AppPlatform.IsMobile && IsDone && Path is not null && SavedTo is null;
}

/// <summary>
/// "Share &amp; chat" — files from browsers. Desktop: they land in a folder (Downloads\Echoes unless changed), with
/// Open (not for programs / scripts), Show in folder and Open folder. Android: they arrive in the app's own storage;
/// once a folder is picked (the system folder picker) every new file is copied into it, until then each has Save.
/// A per-file size cap (MB) is checked before anything is sent, together with the free space.
/// </summary>
public partial class WebServerViewModel
{
    private const string KInbox = "webserver.inbox", KMaxUpload = "webserver.maxUploadMb";
    public const int DefaultMaxUploadMb = 4096;
    private const int MaxReceivedRows = 200;

    public ObservableCollection<ReceivedFileRow> ReceivedFiles { get; } = new();
    /// <summary>Desktop: the folder path. Android: the picked folder's name (empty = the app's own storage).</summary>
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(InboxDisplay))] private string _inboxPath = string.Empty;
    [ObservableProperty] private int _maxUploadMb = DefaultMaxUploadMb;
    /// <summary>A file / folder picker that failed (shown on the Files tab).</summary>
    [ObservableProperty] private string? _filesError;

    private IStorageFolder? _androidFolder;
    private bool _restoringInbox;

    public bool HasReceived => ReceivedFiles.Count > 0;
    public long MaxUploadBytes => (long)Math.Clamp(MaxUploadMb, 1, 1_048_576) * 1024 * 1024;
    public string InboxDisplay => OperatingSystem.IsAndroid() || AppPlatform.IsMobile && InboxPath.Length == 0
        ? (InboxPath.Length > 0 ? InboxPath : "App storage (tap Save on each)")
        : InboxPath;
    public bool CanOpenInbox => LinkHelper.CanOpenFolder && AppPlatform.IsDesktop;

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
                string? saved = p.GetSetting(KInbox);
                InboxPath = saved is { Length: > 0 } && Path.IsPathFullyQualified(saved) ? saved : ShareInbox.DefaultFolder();
            }
        }
        finally { _restoringInbox = false; }
        if (OperatingSystem.IsAndroid()) _ = Task.Run(ListEarlierAndroidFiles);
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

    /// <summary>Removes the finished rows (desktop: the files stay in the folder; phone: rows not saved yet stay).</summary>
    [RelayCommand]
    private void ClearReceived()
    {
        foreach (var r in ReceivedFiles.ToList())
        {
            if (r.IsPending) continue;
            if (OperatingSystem.IsAndroid() && r.IsDone && r.Path is not null && r.SavedTo is null) continue;
            ReceivedFiles.Remove(r);
        }
        OnPropertyChanged(nameof(HasReceived));
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
                if (OperatingSystem.IsAndroid() && _androidFolder is not null) _ = DeliverAsync(row);
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
    }

    private static async Task<string> FreeNameAsync(IStorageFolder folder, string name)
    {
        for (int n = 1; n <= 500; n++)
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
