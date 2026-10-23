using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using Renci.SshNet;
using Renci.SshNet.Common;
using Renci.SshNet.Sftp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>
/// The Files sub-tab: an SFTP browser over a second SSH connection (opened on first use with the same login, and
/// required to present exactly the host key the session saw). Listings are built and sorted off the UI thread and
/// handed over in one piece (the list is virtualized); one transfer runs at a time with progress and Cancel.
/// </summary>
public partial class SshViewModel
{
    /// <summary>Rows beyond this aren't kept (a directory with millions of entries).</summary>
    internal const int MaxFileRows = 20000;

    [ObservableProperty] private string _filesPath = string.Empty;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasFiles), nameof(ShowFilesEmpty))] private IReadOnlyList<SshFileRow> _fileRows = Array.Empty<SshFileRow>();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelectedFile), nameof(CanDownload))]
    private SshFileRow? _selectedFile;

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(ShowFilesEmpty))] private bool _filesBusy;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasFilesError))] private string _filesError = string.Empty;
    /// <summary>"24 items" / "Downloaded a.txt (1.2 MB)." — the status line under the list.</summary>
    [ObservableProperty] private string _filesInfo = string.Empty;
    [ObservableProperty] private bool _filesViewShown;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(ShowFilesEmpty))] private bool _filesLoaded;

    /// <summary>The inline name box: 0 none, 1 new folder, 2 rename.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsNaming), nameof(FilesNameLabel), nameof(FilesNameAction))]
    private int _filesNameMode;

    [ObservableProperty] private string _filesNameInput = string.Empty;
    [ObservableProperty] private bool _filesDeleteConfirm;
    [ObservableProperty] private string _filesDeletePrompt = string.Empty;
    [ObservableProperty] private bool _uploadReplaceConfirm;
    [ObservableProperty] private string _uploadReplacePrompt = string.Empty;

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(CanTransfer), nameof(CanDownload))] private bool _transferActive;
    [ObservableProperty] private string _transferText = string.Empty;
    [ObservableProperty] private double _transferPercent;
    [ObservableProperty] private bool _transferIndeterminate;

    public bool HasFiles => FileRows.Count > 0;
    public bool HasSelectedFile => SelectedFile is not null;
    public bool HasFilesError => FilesError.Length > 0;
    public bool ShowFilesEmpty => FilesLoaded && !FilesBusy && FileRows.Count == 0;
    public bool IsNaming => FilesNameMode != 0;
    public string FilesNameLabel => FilesNameMode == 1 ? "New folder" : "Rename to";
    public string FilesNameAction => FilesNameMode == 1 ? "Create" : "Rename";
    public bool CanTransfer => !TransferActive;
    public bool CanDownload => !TransferActive && SelectedFile is { IsDirectory: false };

    private string _filesDir = string.Empty;       // the directory FileRows lists
    private CancellationTokenSource? _listCts;
    private CancellationTokenSource? _transferCts;
    private List<SshUploadItem>? _pendingUploads;
    private string _pendingUploadDir = string.Empty;

    partial void OnFilesViewShownChanged(bool value)
    {
        if (value && IsConnected && !FilesLoaded && !FilesBusy) _ = LoadDirAsync(_filesDir);
    }

    partial void OnSelectedFileChanged(SshFileRow? value)
    {
        FilesDeleteConfirm = false;
        if (FilesNameMode == 2) FilesNameMode = 0;
    }

    private void ResetFiles()
    {
        _filesDir = string.Empty;
        FileRows = Array.Empty<SshFileRow>();
        FilesPath = string.Empty;
        FilesLoaded = false;
        // a listing cancelled with the session no longer owns the flag (its finally clears it only while still current),
        // and "Loading…" stayed over "Not connected"; the next connect then never listed the folder on its own
        FilesBusy = false;
        FilesError = string.Empty;
        FilesInfo = string.Empty;
        FilesNameMode = 0;
        FilesDeleteConfirm = false;
        UploadReplaceConfirm = false;
        _pendingUploads = null;
    }

    private void CancelFilesWork()
    {
        _listCts?.Cancel();
        _listCts = null;
        _transferCts?.Cancel();
    }

    // ===================================================================== SFTP connection
    private async Task<SftpClient> EnsureSftpAsync(SshSession s, CancellationToken ct)
    {
        if (s.Sftp is { IsConnected: true } ready) return ready;
        await s.SftpGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (s.Sftp is { IsConnected: true } ready2) return ready2;
            if (s.Closed) throw new SshLoginException("Not connected.");
            try { s.Sftp?.Dispose(); } catch { }
            s.Sftp = null;

            var log = new SshAuthLog();
            var check = new SshHostKeyCheck { HostId = s.HostId, LegacyId = s.LegacyId, Expected = s.HostKey };
            var ci = s.Login.CreateConnectionInfo(log);
            var sftp = new SftpClient(ci) { OperationTimeout = TimeSpan.FromSeconds(30) };
            sftp.HostKeyReceived += check.OnHostKey;
            try
            {
                await sftp.ConnectAsync(ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                try { sftp.Dispose(); } catch { }
                string msg = ex is SshException && ex.Message.Contains("ubsystem", StringComparison.Ordinal)
                    ? "The server doesn't offer SFTP (no sftp subsystem)."
                    : SshErrors.Explain(ex, s.Login, log, check);
                throw new SshLoginException(msg);
            }
            finally
            {
                log.Wipe();
                foreach (var m in ci.AuthenticationMethods) { try { m.Dispose(); } catch { } }
            }
            if (s.Closed) { try { sftp.Dispose(); } catch { } throw new SshLoginException("Not connected."); }
            s.Sftp = sftp;
            return sftp;
        }
        finally { s.SftpGate.Release(); }
    }

    private static string FilesErrorText(Exception ex, string path)
    {
        if (ex is AggregateException { InnerException: { } inner }) ex = inner;
        return ex switch
        {
            OperationCanceledException => "Cancelled.",
            SftpPathNotFoundException => $"Not found: {path}",
            SftpPermissionDeniedException => $"Permission denied: {path}",
            SshLoginException => ex.Message,
            SshConnectionException => "The connection was lost.",
            SshOperationTimeoutException => "The server didn't answer in time.",
            _ => ex.Message,
        };
    }

    // ===================================================================== listing
    /// <summary>Lists <paramref name="path"/> ("" = the login's home folder) and selects <paramref name="select"/>. After an
    /// operation, <paramref name="note"/> / <paramref name="error"/> are its outcome: shown instead of the item count / kept
    /// (the refresh itself must not wipe them).</summary>
    internal async Task LoadDirAsync(string path, string? select = null, string? note = null, string? error = null)
    {
        var s = _session;
        if (s is null) return;
        _listCts?.Cancel();
        var cts = _listCts = new CancellationTokenSource();
        FilesBusy = true;
        FilesError = error ?? string.Empty;
        string target = path.Trim();
        if (target == "~") target = string.Empty;
        if (target.Length > 0 && !target.StartsWith('/') && _filesDir.Length > 0) target = SshPaths.Combine(_filesDir, target);
        else if (target.StartsWith('/')) target = SshPaths.Normalize(target);
        try
        {
            var (rows, resolved, total) = await Task.Run(async () =>
            {
                var sftp = await EnsureSftpAsync(s, cts.Token).ConfigureAwait(false);
                string dir = target.Length == 0 ? sftp.WorkingDirectory : target;
                var list = new List<SshFileRow>();
                int count = 0;
                await foreach (var f in sftp.ListDirectoryAsync(dir, cts.Token).ConfigureAwait(false))
                {
                    if (f.Name is "." or "..") continue;
                    count++;
                    if (list.Count < MaxFileRows) list.Add(SshFileRow.From(f));
                }
                list.Sort(SshFileRow.Compare);
                return (list, dir, count);
            }, cts.Token);
            if (!ReferenceEquals(cts, _listCts)) return;
            _filesDir = resolved;
            FilesPath = resolved;
            FileRows = rows;
            FilesLoaded = true;
            SelectedFile = select is null ? null : rows.FirstOrDefault(r => r.Name == select);
            FilesInfo = note ?? (total > rows.Count
                ? $"Showing the first {rows.Count:N0} of {total:N0} items"
                : total == 1 ? "1 item" : $"{total:N0} items");
        }
        catch (Exception ex)
        {
            if (!ReferenceEquals(cts, _listCts)) return;
            string listError = FilesErrorText(ex, target.Length == 0 ? "home folder" : target);
            FilesError = error is null ? listError : error + " " + listError;
            FilesPath = _filesDir;   // the path box goes back to what is listed
        }
        finally
        {
            if (ReferenceEquals(cts, _listCts)) { FilesBusy = false; _listCts = null; }
            cts.Dispose();
        }
    }

    [RelayCommand]
    private Task FilesRefresh() => IsConnected ? LoadDirAsync(_filesDir, SelectedFile?.Name) : Task.CompletedTask;

    [RelayCommand]
    private Task FilesUp() => IsConnected && _filesDir.Length > 0 ? LoadDirAsync(SshPaths.Parent(_filesDir), SshPaths.FileName(_filesDir)) : Task.CompletedTask;

    /// <summary>The path box's Enter.</summary>
    [RelayCommand]
    private Task FilesGo() => IsConnected ? LoadDirAsync(FilesPath) : Task.CompletedTask;

    /// <summary>Double-click / Enter on a row: opens a folder (or a link to one). Returns true for a file (the view then
    /// offers to download it).</summary>
    public async Task<bool> OpenRowAsync(SshFileRow? row)
    {
        if (row is null || _session is not { } s) return false;
        if (row.IsDirectory) { await LoadDirAsync(row.FullPath); return false; }
        if (!row.IsLink) return true;
        try
        {
            // A link: follow it (stat) to see whether it is a folder.
            var attrs = await Task.Run(async () =>
            {
                var sftp = await EnsureSftpAsync(s, CancellationToken.None).ConfigureAwait(false);
                return await sftp.GetAttributesAsync(row.FullPath, CancellationToken.None).ConfigureAwait(false);
            });
            if (attrs.IsDirectory) { await LoadDirAsync(row.FullPath); return false; }
            return true;
        }
        catch (Exception ex)
        {
            FilesError = "The link's target can't be opened: " + FilesErrorText(ex, row.FullPath);
            return false;
        }
    }

    // ===================================================================== new folder / rename / delete
    [RelayCommand]
    private void StartNewFolder()
    {
        if (!IsConnected || !FilesLoaded) return;
        FilesDeleteConfirm = false;
        FilesError = string.Empty;
        FilesNameInput = string.Empty;
        FilesNameMode = 1;
    }

    [RelayCommand]
    private void StartRename()
    {
        if (!IsConnected || SelectedFile is null) return;
        FilesDeleteConfirm = false;
        FilesError = string.Empty;
        FilesNameInput = SelectedFile.Name;
        FilesNameMode = 2;
    }

    [RelayCommand]
    private void CancelName() => FilesNameMode = 0;

    [RelayCommand]
    private async Task ConfirmName()
    {
        if (_session is not { } s || FilesNameMode == 0) return;
        string name = FilesNameInput.Trim();
        if (SshPaths.NameProblem(name) is { } problem) { FilesError = problem; return; }
        int mode = FilesNameMode;
        var row = SelectedFile;
        if (mode == 2 && (row is null || row.Name == name)) { FilesNameMode = 0; return; }
        if (FileRows.Any(r => r.Name == name)) { FilesError = $"\"{name}\" already exists here."; return; }
        string dir = _filesDir;
        string target = SshPaths.Combine(dir, name);
        FilesError = string.Empty;
        FilesBusy = true;
        try
        {
            await Task.Run(async () =>
            {
                var sftp = await EnsureSftpAsync(s, CancellationToken.None).ConfigureAwait(false);
                if (mode == 1) await sftp.CreateDirectoryAsync(target, CancellationToken.None).ConfigureAwait(false);
                else if (row!.Entry is { } entry) entry.MoveTo(target);   // a link is renamed itself, not its target
                else await sftp.RenameFileAsync(row.FullPath, target, CancellationToken.None).ConfigureAwait(false);
            });
            FilesNameMode = 0;
            await LoadDirAsync(dir, name, note: mode == 1 ? $"Created \"{name}\"." : $"Renamed to \"{name}\".");
        }
        catch (Exception ex)
        {
            FilesError = FilesErrorText(ex, target);
            FilesBusy = false;
        }
    }

    [RelayCommand]
    private void RequestDeleteFile()
    {
        if (SelectedFile is not { } row || TransferActive) return;
        FilesNameMode = 0;
        FilesDeletePrompt = row.IsDirectory
            ? $"Delete the folder \"{row.Name}\" and everything in it?"
            : $"Delete \"{row.Name}\"?";
        FilesDeleteConfirm = true;
    }

    [RelayCommand]
    private void CancelDeleteFile() => FilesDeleteConfirm = false;

    /// <summary>Only through the confirmation strip. A folder goes with everything in it (links are removed, never
    /// followed); runs as a cancellable operation.</summary>
    [RelayCommand]
    private async Task ConfirmDeleteFile()
    {
        if (!FilesDeleteConfirm || SelectedFile is not { } row || _session is not { } s || TransferActive) return;
        FilesDeleteConfirm = false;
        string dir = _filesDir;
        var cts = BeginTransfer($"Deleting {row.Name}…", total: -1);
        int removed = 0;
        string? note = null, error = null;
        try
        {
            await Task.Run(async () =>
            {
                var sftp = await EnsureSftpAsync(s, cts.Token).ConfigureAwait(false);
                if (row.IsDirectory)
                    await DeleteTreeAsync(sftp, row.FullPath, 0, cts.Token, () =>
                    {
                        int n = Interlocked.Increment(ref removed);
                        if (n % 25 == 0) PostTransferText($"Deleting {row.Name}… {n:N0} items");
                    }).ConfigureAwait(false);
                else
                {
                    // through the listed entry: a link goes, never the file it points to
                    if (row.Entry is { } entry) await entry.DeleteAsync(cts.Token).ConfigureAwait(false);
                    else await sftp.DeleteFileAsync(row.FullPath, cts.Token).ConfigureAwait(false);
                    removed = 1;
                }
            }, cts.Token);
            note = row.IsDirectory ? $"Deleted \"{row.Name}\" ({removed:N0} items)." : $"Deleted \"{row.Name}\".";
        }
        catch (Exception ex)
        {
            error = FilesErrorText(ex, row.FullPath) + (removed > 0 ? $" ({removed:N0} items were deleted.)" : string.Empty);
            FilesError = error;
        }
        finally { EndTransfer(cts); }
        if (IsConnected) await LoadDirAsync(dir, note: note, error: error);
    }

    private static async Task DeleteTreeAsync(SftpClient sftp, string path, int depth, CancellationToken ct, Action removed)
    {
        if (depth > 64) throw new IOException("The folder nesting is too deep.");
        var children = new List<ISftpFile>();
        await foreach (var f in sftp.ListDirectoryAsync(path, ct).ConfigureAwait(false))
            if (f.Name is not "." and not "..") children.Add(f);
        foreach (var c in children)
        {
            ct.ThrowIfCancellationRequested();
            if (c.IsDirectory && !c.IsSymbolicLink) await DeleteTreeAsync(sftp, c.FullName, depth + 1, ct, removed).ConfigureAwait(false);
            else { await c.DeleteAsync(ct).ConfigureAwait(false); removed(); }   // the entry itself: a link, not its target
        }
        await sftp.DeleteDirectoryAsync(path, ct).ConfigureAwait(false);
        removed();
    }

    // ===================================================================== transfers
    private long _xferTotal = -1, _xferDone;
    private string _xferLabel = string.Empty;
    private int _xferPosted;
    private long _xferLastPost;

    private CancellationTokenSource BeginTransfer(string label, long total)
    {
        var cts = _transferCts = new CancellationTokenSource();
        FilesError = string.Empty;
        _xferLabel = label;
        _xferTotal = total;
        Interlocked.Exchange(ref _xferDone, 0);
        TransferIndeterminate = total <= 0;
        TransferPercent = 0;
        TransferText = label;
        TransferActive = true;
        return cts;
    }

    private void EndTransfer(CancellationTokenSource cts)
    {
        if (ReferenceEquals(_transferCts, cts)) _transferCts = null;
        cts.Dispose();
        TransferActive = false;
        TransferText = string.Empty;
        TransferPercent = 0;
    }

    // Any thread: progress callbacks come every 32 KB or so — at most one UI update is queued at a time, and at most ~7 a
    // second (a fast transfer otherwise redrew the bar at the frame rate for its whole length).
    private void ReportTransfer(long done)
    {
        Interlocked.Exchange(ref _xferDone, done);
        long now = Environment.TickCount64;
        if (now - Interlocked.Read(ref _xferLastPost) < 150) return;
        if (Interlocked.Exchange(ref _xferPosted, 1) == 1) return;
        Interlocked.Exchange(ref _xferLastPost, now);
        Dispatcher.UIThread.Post(() =>
        {
            Interlocked.Exchange(ref _xferPosted, 0);
            if (!TransferActive) return;
            long d = Interlocked.Read(ref _xferDone), t = _xferTotal;
            if (t > 0)
            {
                double pct = Math.Clamp(100.0 * d / t, 0, 100);
                TransferPercent = pct;
                TransferText = $"{_xferLabel} · {pct:0}% · {SshText.Bytes(d)} of {SshText.Bytes(t)}";
            }
            else TransferText = $"{_xferLabel} · {SshText.Bytes(d)}";
        }, DispatcherPriority.Background);
    }

    private void PostTransferText(string text) => Dispatcher.UIThread.Post(() => { if (TransferActive) TransferText = text; });

    [RelayCommand]
    private void CancelTransfer() => _transferCts?.Cancel();

    /// <summary>Downloads <paramref name="row"/> into the stream <paramref name="openTarget"/> gives (the save dialog's
    /// file). On failure or Cancel the partial target is removed through <paramref name="deleteTarget"/>.</summary>
    public async Task DownloadAsync(SshFileRow row, Func<Task<Stream>> openTarget, Func<Task>? deleteTarget = null)
    {
        if (_session is not { } s || TransferActive || row.IsDirectory) return;
        var cts = BeginTransfer($"Downloading {row.Name}", row.Size);
        long bytes = 0;
        try
        {
            await Task.Run(async () =>
            {
                var sftp = await EnsureSftpAsync(s, cts.Token).ConfigureAwait(false);
                if (row.IsLink)
                {
                    // a link downloads what it points to — unless that is a folder
                    var pointsTo = await sftp.GetAttributesAsync(row.FullPath, cts.Token).ConfigureAwait(false);
                    if (pointsTo.IsDirectory) throw new SshLoginException($"\"{row.Name}\" points to a folder: open it instead.");
                    if (pointsTo.Size > 0) _xferTotal = pointsTo.Size;
                }
                var target = await openTarget().ConfigureAwait(false);
                await using (target.ConfigureAwait(false))
                {
                    var progress = new InlineProgress<DownloadFileProgressReport>(r => ReportTransfer((long)r.TotalBytesDownloaded));
                    await sftp.DownloadFileAsync(row.FullPath, target, progress, cts.Token).ConfigureAwait(false);
                    await target.FlushAsync(cts.Token).ConfigureAwait(false);
                }
                bytes = Interlocked.Read(ref _xferDone);
            }, cts.Token);
            FilesInfo = $"Downloaded \"{row.Name}\" ({SshText.Bytes(Math.Max(bytes, row.Size))}).";
        }
        catch (Exception ex)
        {
            FilesError = FilesErrorText(ex, row.FullPath);
            if (deleteTarget is not null) { try { await deleteTarget(); } catch { } }
        }
        finally { EndTransfer(cts); }
    }

    /// <summary>Uploads local files into the listed folder. Names that already exist there ask first (Replace / Cancel).</summary>
    public async Task UploadAsync(IReadOnlyList<SshUploadItem> items, bool replace = false)
    {
        if (_session is not { } s || TransferActive || items.Count == 0) return;
        string dir = replace ? _pendingUploadDir : _filesDir;
        UploadReplaceConfirm = false;
        _pendingUploads = null;
        if (dir.Length == 0) { FilesError = "Open a folder first: files are uploaded into the listed folder."; return; }
        if (!replace)
        {
            var existing = new HashSet<string>(FileRows.Select(r => r.Name), StringComparer.Ordinal);
            var clash = items.Where(i => existing.Contains(i.Name)).Select(i => i.Name).ToList();
            if (clash.Count > 0)
            {
                _pendingUploads = items.ToList();
                _pendingUploadDir = dir;
                UploadReplacePrompt = clash.Count == 1
                    ? $"\"{clash[0]}\" already exists here. Replace it?"
                    : $"{clash.Count} of these files already exist here. Replace them?";
                UploadReplaceConfirm = true;
                return;
            }
        }

        var cts = BeginTransfer("Uploading", total: -1);
        int done = 0;
        string? last = null, note = null, error = null;
        try
        {
            for (int i = 0; i < items.Count; i++)
            {
                var item = items[i];
                cts.Token.ThrowIfCancellationRequested();
                if (SshPaths.NameProblem(item.Name) is { } problem) throw new SshLoginException($"\"{item.Name}\": {problem}");
                string remote = SshPaths.Combine(dir, item.Name);
                _xferLabel = items.Count > 1 ? $"Uploading {item.Name} ({i + 1} of {items.Count})" : $"Uploading {item.Name}";
                _xferTotal = item.Size ?? -1;
                TransferIndeterminate = _xferTotal <= 0;
                TransferPercent = 0;
                TransferText = _xferLabel;
                bool started = false;
                try
                {
                    await Task.Run(async () =>
                    {
                        var sftp = await EnsureSftpAsync(s, cts.Token).ConfigureAwait(false);
                        var src = await item.Open().ConfigureAwait(false);
                        await using (src.ConfigureAwait(false))
                        {
                            if (_xferTotal <= 0 && src.CanSeek) _xferTotal = src.Length;
                            started = true;
                            var progress = new InlineProgress<UploadFileProgressReport>(r => ReportTransfer((long)r.TotalBytesUploaded));
                            await sftp.UploadFileAsync(src, remote, replace, progress, cts.Token).ConfigureAwait(false);
                        }
                    }, cts.Token);
                }
                catch (Exception) when (started && cts.IsCancellationRequested)
                {
                    // Cancelled mid-file: don't leave a truncated copy behind.
                    try { if (s.Sftp is { } sftp) await sftp.DeleteFileAsync(remote, CancellationToken.None); } catch { }
                    throw;
                }
                done++;
                last = item.Name;
            }
            note = done == 1 ? $"Uploaded \"{last}\"." : $"Uploaded {done} files.";
        }
        catch (Exception ex)
        {
            error = FilesErrorText(ex, dir) + (done > 0 ? $" ({done} of {items.Count} uploaded.)" : string.Empty);
            FilesError = error;
        }
        finally { EndTransfer(cts); }
        if (IsConnected && _filesDir == dir) await LoadDirAsync(dir, last, note, error);
        else if (note is not null) FilesInfo = note;
    }

    [RelayCommand]
    private Task ConfirmReplace() => _pendingUploads is { } items ? UploadAsync(items, replace: true) : Task.CompletedTask;

    [RelayCommand]
    private void CancelReplace()
    {
        UploadReplaceConfirm = false;
        _pendingUploads = null;
    }
}
