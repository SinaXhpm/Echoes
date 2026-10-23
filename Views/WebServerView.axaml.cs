using System;
using System.Collections.Specialized;
using System.IO;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Echoes.Helpers;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class WebServerView : UserControl
{
    private WebServerViewModel? _vm;
    private ScrollViewer? _chatScroll;
    private bool _stick = true;        // follow new messages while the user is at the bottom
    private bool _scrollQueued;
    private bool _macRestoreTried;

    private void CtBindBox_DropDownOpened(object? sender, EventArgs e)
    {
        if (DataContext is WebServerViewModel { IsCatching: false } vm) vm.RebuildCatchBinds();
    }

    public WebServerView()
    {
        InitializeComponent();
        // interfaces come and go (VPN, Wi-Fi): the pickers list the current ones whenever they open (the Catch page's
        // handler is in the XAML: that page is built when first shown)
        ShBindBox.DropDownOpened += (_, _) => _vm?.RebuildShareBinds();

        // Tunnel: see Enter before the multi-line box turns it into a newline. Desktop: Enter sends, Shift+Enter is a
        // new line. Phone keyboards have no Shift+Enter, so there Enter stays a newline and the Send button sends.
        ChatBox.AddHandler(KeyDownEvent, OnChatKeyDown, RoutingStrategies.Tunnel);

        ChatList.TemplateApplied += (_, e) =>
        {
            if (_chatScroll != null) _chatScroll.ScrollChanged -= OnChatScrollChanged;
            _chatScroll = e.NameScope.Find<ScrollViewer>("PART_Scroll");
            if (_chatScroll != null) _chatScroll.ScrollChanged += OnChatScrollChanged;
            if (_vm is { ChatItems.Count: > 0 }) Dispatcher.UIThread.Post(() => ScrollToBottom(3), DispatcherPriority.Background);
        };
        // back on screen after another tool: messages that came meanwhile scrolled nothing, so catch up to the end
        ChatList.AttachedToVisualTree += (_, _) =>
        {
            if (_stick && _vm is { ChatItems.Count: > 0 }) QueueScroll();
        };
    }

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);
        if (_vm != null) _vm.ChatItems.CollectionChanged -= OnChatChanged;
        _vm = DataContext as WebServerViewModel;
        if (_vm != null) _vm.ChatItems.CollectionChanged += OnChatChanged;
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        if (_vm is null) return;
        _vm.ViewShown = true;
        // Android: reopen the folder picked last time (its permission was kept with the bookmark)
        if (_vm.NeedsAndroidFolder && _vm.AndroidFolderBookmark is { Length: > 0 } bookmark)
            _ = RestoreAndroidFolderAsync(bookmark);
        // Mac App Store sandbox: the same for the folder picked in an earlier run (once: a bookmark that doesn't open the
        // folder for writing won't do so on the next visit either)
        else if (!_macRestoreTried && _vm.MacFolderBookmark is { Length: > 0 } macBookmark)
        {
            _macRestoreTried = true;
            _ = RestoreMacFolderAsync(macBookmark);
        }
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnDetachedFromVisualTree(e);
        if (_vm != null) _vm.ViewShown = false;
    }

    // ---------------- chat: follow the newest message ----------------

    private void OnChatScrollChanged(object? sender, ScrollChangedEventArgs e)
    {
        if (_chatScroll is null) return;
        // only a scroll by the user (offset moved) decides whether to keep following; growth alone doesn't
        if (Math.Abs(e.OffsetDelta.Y) > 0.01) _stick = AtBottom(_chatScroll);
        // growth that wasn't followed (messages that came while the chat was behind the Files / Log sub-tab or another
        // page) is caught up as soon as the list is laid out again
        else if (_stick && Math.Abs(e.ExtentDelta.Y) > 0.01 && !AtBottom(_chatScroll)) QueueScroll();
    }

    private static bool AtBottom(ScrollViewer sv) => sv.Offset.Y >= sv.Extent.Height - sv.Viewport.Height - 24;

    private void OnChatChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (e.Action == NotifyCollectionChangedAction.Reset) _stick = true;
        if (_stick) QueueScroll();
    }

    private void QueueScroll()
    {
        if (_scrollQueued) return;
        _scrollQueued = true;
        Dispatcher.UIThread.Post(() => { _scrollQueued = false; ScrollToBottom(3); }, DispatcherPriority.Background);
    }

    // the virtualizing panel estimates the extent: a second pass lands exactly on the end
    private void ScrollToBottom(int attempts)
    {
        if (_chatScroll is null) return;
        _chatScroll.ScrollToEnd();
        _stick = true;
        if (attempts > 1)
            Dispatcher.UIThread.Post(() =>
            {
                if (_chatScroll != null && _stick && !AtBottom(_chatScroll)) ScrollToBottom(attempts - 1);
            }, DispatcherPriority.Background);
    }

    private void OnChatKeyDown(object? sender, KeyEventArgs e)
    {
        if (_vm is null || e.Key != Key.Enter) return;
        bool send = e.KeyModifiers == KeyModifiers.Control || (!AppPlatform.IsMobile && e.KeyModifiers == KeyModifiers.None);
        if (!send) return;
        e.Handled = true;
        if (_vm.SendChatCommand.CanExecute(null)) _vm.SendChatCommand.Execute(null);
    }

    // ---------------- files this device shares ----------------

    private async void AddFiles_Click(object? sender, RoutedEventArgs e) => await PickAndShareAsync(postToChat: false);

    // The chat's "+": shared files are posted in the chat as download links.
    private async void Attach_Click(object? sender, RoutedEventArgs e) => await PickAndShareAsync(postToChat: true);

    private async Task PickAndShareAsync(bool postToChat)
    {
        if (DataContext is not WebServerViewModel vm) return;
        if (!postToChat) vm.FilesError = null;
        var top = TopLevel.GetTopLevel(this);
        if (top is null) return;

        var added = new List<SharedItem>();
        try
        {
            var files = await top.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = postToChat ? "Send files in the chat" : "Add files to share",
                AllowMultiple = true,
            });

            foreach (var f in files)
            {
                string name = f.Name;
                long size = 0;
                DateTime? mtime = null;
                Func<Task<Stream>> open;

                // Desktop: a real filesystem path → seekable FileStream (Range/resume works).
                // Android: content:// URI (no path) → read via the storage stream.
                string? localPath = f.TryGetLocalPath();
                if (!string.IsNullOrEmpty(localPath) && File.Exists(localPath))
                {
                    var fi = new FileInfo(localPath);
                    long pickedLen = fi.Length;
                    DateTime pickedMtime = fi.LastWriteTimeUtc;
                    size = pickedLen;
                    mtime = pickedMtime;
                    string path = localPath;
                    // Re-opened by path per request, so pin it to the picked version: if the file was
                    // overwritten since, refuse (410) rather than let a resumed download splice the old
                    // head onto the new tail. Checked AFTER opening (File.OpenRead's FileShare.Read then
                    // blocks in-place writers while we serve), with the SAME FileInfo stat as at pick
                    // time — mixing handle/path metadata could differ (e.g. a symlink) and 410 forever.
                    open = () =>
                    {
                        var fs = File.OpenRead(path);
                        bool same;
                        try
                        {
                            var cur = new FileInfo(path);
                            same = cur.Length == pickedLen && cur.LastWriteTimeUtc == pickedMtime;
                        }
                        catch { fs.Dispose(); throw; }   // e.g. deleted right after opening — don't leak the handle
                        if (!same)
                        {
                            fs.Dispose();
                            throw new SharedItemChangedException();
                        }
                        return Task.FromResult<Stream>(fs);
                    };
                }
                else
                {
                    try
                    {
                        var props = await f.GetBasicPropertiesAsync();
                        size = (long)(props.Size ?? 0UL);
                    }
                    catch { }
                    var file = f;   // keep the IStorageFile alive for lazy opens
                    open = () => file.OpenReadAsync();
                }

                added.Add(vm.AddSharedFile(name, size, open, mtime, notify: false));
            }
        }
        catch (Exception ex)
        {
            string why = "Adding files failed: " + ex.Message;
            if (postToChat) vm.ChatError = why; else vm.FilesError = why;
        }
        finally
        {
            // the pages hear of the batch once, then each file goes into the chat
            if (added.Count > 0)
            {
                vm.SharedFilesAdded();
                if (postToChat) foreach (var item in added) vm.ShareInChat(item);
            }
        }
    }

    // ---------------- files received ----------------

    private async void ChangeInbox_Click(object? sender, RoutedEventArgs e)
    {
        if (_vm is null || !_vm.CanChangeInbox || TopLevel.GetTopLevel(this) is not { } top) return;
        _vm.FilesError = null;
        try
        {
            var picked = await top.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
            {
                Title = "Folder for received files",
                AllowMultiple = false,
            });
            if (picked.Count == 0) return;
            var folder = picked[0];
            if (OperatingSystem.IsAndroid())
            {
                string? bookmark = null;
                try { bookmark = await folder.SaveBookmarkAsync(); } catch { }
                _vm.SetAndroidFolder(folder, bookmark);
            }
            else if (folder.TryGetLocalPath() is { Length: > 0 } path)
            {
                if (AppInfo.IsMacSandbox)
                {
                    // the sandbox opens the folder for this run; its bookmark opens it again next time
                    string? bookmark = null;
                    try { bookmark = await folder.SaveBookmarkAsync(); } catch { }
                    _vm.SetMacFolder(folder, path, bookmark);
                }
                else _vm.SetInboxFolder(path);
            }
        }
        catch (Exception ex) { _vm.FilesError = "Picking the folder failed: " + ex.Message; }
    }

    // Mac App Store sandbox: reopens the folder picked in an earlier run. If the bookmark doesn't open it for writing, the
    // default folder (Downloads/Echoes) stays.
    private async Task RestoreMacFolderAsync(string bookmark)
    {
        if (_vm is null || TopLevel.GetTopLevel(this) is not { } top) return;
        IStorageFolder? folder = null;
        try
        {
            folder = await top.StorageProvider.OpenFolderBookmarkAsync(bookmark);
            if (folder is not null && folder.TryGetLocalPath() is { Length: > 0 } path && ShareInbox.IsWritableFolder(path))
            {
                _vm.SetMacFolder(folder, path, null, restored: true);
                folder = null;   // the view-model keeps it (and with it the folder's access)
            }
        }
        catch { /* the permission is gone: received files keep going to the default folder */ }
        finally { folder?.Dispose(); }   // opened but not used: give its access back
    }

    private async Task RestoreAndroidFolderAsync(string bookmark)
    {
        if (_vm is null || TopLevel.GetTopLevel(this) is not { } top) return;
        try
        {
            if (await top.StorageProvider.OpenFolderBookmarkAsync(bookmark) is { } folder && _vm.NeedsAndroidFolder)
                _vm.SetAndroidFolder(folder, null);
        }
        catch { /* the permission is gone: received files stay in the app (Save) until a folder is picked again */ }
    }

    private async void OpenReceived_Click(object? sender, RoutedEventArgs e)
    {
        if ((sender as Control)?.DataContext is not ReceivedFileRow { CanOpen: true, Path: { } path }) return;
        if (TopLevel.GetTopLevel(this)?.Launcher is not { } launcher || !File.Exists(path)) return;
        try { await launcher.LaunchFileInfoAsync(new FileInfo(path)); } catch { }
    }

    private async void SaveReceived_Click(object? sender, RoutedEventArgs e)
    {
        if (_vm is null || (sender as Control)?.DataContext is not ReceivedFileRow row) return;
        if (TopLevel.GetTopLevel(this) is not { } top) return;
        await _vm.SaveReceivedAsync(row, top.StorageProvider);
    }
}
