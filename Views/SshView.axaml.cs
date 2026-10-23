using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Echoes.Helpers;
using Echoes.ViewModels;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace Echoes.Views;

public partial class SshView : UserControl
{
    private SshViewModel? _vm;
    private bool _termFollow = true;

    public SshView()
    {
        InitializeComponent();

        // The terminal follows its output while the user is at the bottom: scrolled up to read or select earlier output
        // (tail -f, top), it stays there instead of being pulled down every second. Back at the end, it follows again.
        TerminalOutputBlock.PropertyChanged += (_, e) =>
        {
            if (e.Property != SelectableTextBlock.TextProperty) return;
            if (string.IsNullOrEmpty(TerminalOutputBlock.Text)) _termFollow = true;   // cleared / a new session
            if (_termFollow)
                Dispatcher.UIThread.Post(() => TermScroll.Offset = new Vector(TermScroll.Offset.X, double.MaxValue), DispatcherPriority.Background);
        };
        TermScroll.ScrollChanged += (_, e) =>
        {
            if (Math.Abs(e.OffsetDelta.Y) > 0.01)
                _termFollow = TermScroll.Offset.Y >= TermScroll.Extent.Height - TermScroll.Viewport.Height - 24;
        };

        if (AppPlatform.IsMobile) SshRoot.Classes.Add("touch");
    }

    // A sub-tab's content is in the visual tree only while it is shown: the Files listing loads on first view, and the
    // Server view polls only while it is attached (switching tools detaches the whole page too). Both tabs are built the
    // first time they are shown (Views/Controls/Deferred), so their panes report themselves (XAML events) as they come.
    private Control? _filesPane, _serverPane;

    private void FilesPane_Attached(object? sender, VisualTreeAttachmentEventArgs e)
    {
        _filesPane = sender as Control;
        if (_vm is not null) _vm.FilesViewShown = true;
    }

    private void FilesPane_Detached(object? sender, VisualTreeAttachmentEventArgs e)
    {
        if (_vm is not null) _vm.FilesViewShown = false;
    }

    private void ServerPane_Attached(object? sender, VisualTreeAttachmentEventArgs e)
    {
        _serverPane = sender as Control;
        if (_vm is not null) _vm.ServerViewShown = true;
    }

    private void ServerPane_Detached(object? sender, VisualTreeAttachmentEventArgs e)
    {
        if (_vm is not null) _vm.ServerViewShown = false;
    }

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);
        if (_vm is not null) _vm.ServerViewProbe = null;
        _vm = DataContext as SshViewModel;
        if (_vm is null) return;
        // a minimized window or a phone app in the background keeps the pane "visible": no commands on the server then
        _vm.ServerViewProbe = () => _serverPane is { } pane && AppPlatform.OnScreen(pane);
        _vm.FilesViewShown = _filesPane is { } files && TopLevel.GetTopLevel(files) is not null;
        _vm.ServerViewShown = _serverPane is { } server && TopLevel.GetTopLevel(server) is not null;
    }

    // ---------------------------------------------------------------- key file
    private async void OnBrowseKey(object? sender, RoutedEventArgs e)
    {
        if (_vm is null) return;
        try
        {
            var top = TopLevel.GetTopLevel(this);
            if (top is null) return;
            var files = await top.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Pick a private key (OpenSSH, PEM or PuTTY .ppk)",
                AllowMultiple = false,
                FileTypeFilter = new[] { FilePickerFileTypes.All },
            });
            if (files is not { Count: > 0 }) return;
            var file = files[0];
            // desktop: the real path (kept with a saved server); Android: the content URI, opened through the provider
            _vm.SetPickedKey(file.TryGetLocalPath() ?? file.Path.ToString(), file);
        }
        catch (Exception ex) { CrashLog.Write("Ssh.BrowseKey", ex); }
    }

    // ---------------------------------------------------------------- files
    private async void OnFileDoubleTapped(object? sender, TappedEventArgs e)
    {
        if (_vm is null || (e.Source as Control)?.DataContext is not SshFileRow row) return;
        await OpenRow(row);
    }

    private async void OnFileListKeyDown(object? sender, KeyEventArgs e)
    {
        if (_vm is null) return;
        switch (e.Key)
        {
            case Key.Enter when _vm.SelectedFile is { } row:
                e.Handled = true;
                await OpenRow(row);
                break;
            case Key.Back:
                e.Handled = true;
                _vm.FilesUpCommand.Execute(null);
                break;
            case Key.Delete when _vm.SelectedFile is not null:
                e.Handled = true;
                _vm.RequestDeleteFileCommand.Execute(null);
                break;
            case Key.F2 when _vm.SelectedFile is not null:
                e.Handled = true;
                _vm.StartRenameCommand.Execute(null);
                break;
        }
    }

    private async Task OpenRow(SshFileRow row)
    {
        try
        {
            if (await _vm!.OpenRowAsync(row)) await DownloadRow(row);
        }
        catch (Exception ex) { CrashLog.Write("Ssh.OpenRow", ex); }
    }

    private async void OnDownload(object? sender, RoutedEventArgs e)
    {
        if (_vm?.SelectedFile is not { IsDirectory: false } row) return;
        await DownloadRow(row);
    }

    // The server names the file: a POSIX name may hold '\' (a folder separator on Windows: "..\..\Startup\x.cmd" would
    // point the save dialog outside the folder it shows), control characters, or a right-to-left override that disguises
    // the extension. Only the last segment is kept, those characters dropped and the ones Windows refuses replaced.
    internal static string SafeLocalName(string remoteName)
    {
        string name = remoteName;
        int cut = Math.Max(name.LastIndexOf('/'), name.LastIndexOf('\\'));
        if (cut >= 0) name = name[(cut + 1)..];
        var sb = new System.Text.StringBuilder(name.Length);
        foreach (char c in name)
        {
            if (c < 0x20 || c == 0x7F || c is '‎' or '‏' or >= '‪' and <= '‮' or >= '⁦' and <= '⁩') continue;
            sb.Append(c is '<' or '>' or ':' or '"' or '|' or '?' or '*' ? '_' : c);
        }
        string clean = sb.ToString().Trim().TrimEnd('.');
        return clean.Length == 0 || clean == ".." ? "download" : clean;
    }

    private async Task DownloadRow(SshFileRow row)
    {
        if (_vm is null || _vm.TransferActive || row.IsDirectory) return;
        try
        {
            var top = TopLevel.GetTopLevel(this);
            if (top is null) return;
            var file = await top.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = "Save the downloaded file",
                SuggestedFileName = SafeLocalName(row.Name),
                ShowOverwritePrompt = true,
            });
            if (file is null) return;
            await _vm.DownloadAsync(row, async () => await file.OpenWriteAsync(), async () => await file.DeleteAsync());
        }
        catch (Exception ex) { CrashLog.Write("Ssh.Download", ex); }
    }

    private async void OnUpload(object? sender, RoutedEventArgs e)
    {
        if (_vm is null || !_vm.IsConnected) return;
        try
        {
            var top = TopLevel.GetTopLevel(this);
            if (top is null) return;
            var files = await top.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Upload to " + (_vm.FilesPath.Length > 0 ? _vm.FilesPath : "the server"),
                AllowMultiple = true,
                FileTypeFilter = new[] { FilePickerFileTypes.All },
            });
            if (files is not { Count: > 0 }) return;
            var items = new List<SshUploadItem>(files.Count);
            foreach (var f in files)
            {
                long? size = null;
                try
                {
                    var props = await f.GetBasicPropertiesAsync();
                    if (props.Size is ulong s) size = (long)Math.Min(s, long.MaxValue);
                }
                catch (Exception) { /* some providers don't report a size: the progress shows bytes only */ }
                var picked = f;
                items.Add(new SshUploadItem(picked.Name, async () => await picked.OpenReadAsync(), size));
            }
            await _vm.UploadAsync(items);
        }
        catch (Exception ex) { CrashLog.Write("Ssh.Upload", ex); }
    }
}
