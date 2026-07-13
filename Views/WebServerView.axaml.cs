using System;
using System.IO;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class WebServerView : UserControl
{
    public WebServerView()
    {
        InitializeComponent();
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
                Func<Task<Stream>> open;

                // Desktop: a real filesystem path → seekable FileStream (Range/resume works).
                // Android: content:// URI (no path) → read via the storage stream.
                string? localPath = f.TryGetLocalPath();
                if (!string.IsNullOrEmpty(localPath) && File.Exists(localPath))
                {
                    size = new FileInfo(localPath).Length;
                    string path = localPath;
                    open = () => Task.FromResult<Stream>(File.OpenRead(path));
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

                vm.AddSharedFile(name, size, open);
            }
        }
        catch (Exception ex) { vm.StatusMessage = "Add failed: " + ex.Message; }
    }
}
