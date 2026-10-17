using System;
using System.IO;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Echoes.Helpers;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class WebServerView : UserControl
{
    public WebServerView()
    {
        InitializeComponent();
        // interfaces come and go (VPN, Wi-Fi): the catcher lists the current ones whenever its picker opens
        CtBindBox.DropDownOpened += (_, _) =>
        {
            if (DataContext is WebServerViewModel { IsCatching: false } vm) vm.RebuildCatchBinds();
        };
    }

    private async void AddFiles_Click(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not WebServerViewModel vm) return;
        var top = TopLevel.GetTopLevel(this);
        if (top is null) return;

        try
        {
            var files = await top.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Add files to share",
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

                vm.AddSharedFile(name, size, open, mtime);
            }
        }
        catch (Exception ex) { vm.StatusMessage = "Add failed: " + ex.Message; }
    }
}
