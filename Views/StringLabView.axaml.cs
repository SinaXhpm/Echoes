using System;
using System.IO;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class StringLabView : UserControl
{
    // No DataContext here: the shell assigns the shared view-model (ToolViews.Create in MainView.axaml.cs).
    // Setting one in the constructor built a throwaway VM and bound every control to it first.
    public StringLabView() => InitializeComponent();

    // HASH → FILE…: the picker needs this view's TopLevel, so it lives here (as in WebServerView /
    // BackupView); the view-model only receives a stream opener and does the hashing off the UI thread.
    private async void HashFile_Click(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not StringLabViewModel vm || vm.IsHashingFile) return;
        var top = TopLevel.GetTopLevel(this);
        if (top is null) return;

        IStorageFile? file = null;
        try
        {
            var files = await top.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Hash a file",
                AllowMultiple = false,
            });
            if (files.Count == 0) return;
            file = files[0];

            long size = -1;
            Func<Task<Stream>> open;
            // Desktop: a real path → FileStream with sequential-scan read-ahead (multi-GB friendly).
            // Android: content:// URI (no path) → the storage provider's stream.
            string? localPath = file.TryGetLocalPath();
            if (!string.IsNullOrEmpty(localPath) && File.Exists(localPath))
            {
                size = new FileInfo(localPath).Length;
                string path = localPath;
                open = () => Task.FromResult<Stream>(new FileStream(path, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.Asynchronous | FileOptions.SequentialScan));
            }
            else
            {
                try
                {
                    var props = await file.GetBasicPropertiesAsync();
                    size = props.Size is ulong s ? (long)s : -1;
                }
                catch { /* size is only used for the progress percentage */ }
                var picked = file;
                open = () => picked.OpenReadAsync();
            }

            await vm.HashFileAsync(file.Name, size, open);
        }
        catch (Exception ex) { vm.ErrorMessage = "File hash: " + ex.Message; }   // picker/provider failure — never crash async void
        finally { file?.Dispose(); }
    }
}
