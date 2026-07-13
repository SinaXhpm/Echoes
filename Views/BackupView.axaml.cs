using System;
using System.IO;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class BackupView : UserControl
{
    private static readonly FilePickerFileType EchoesBackup = new("Echoes backup")
    {
        Patterns = new[] { "*.echoesbak" }
    };

    public BackupView()
    {
        InitializeComponent();
    }

    private async void OnExport(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not BackupViewModel vm) return;

        byte[] data;
        try { data = vm.BuildExport(); }
        catch (Exception ex) { vm.Status = ex.Message; return; }   // e.g. missing/short password

        var top = TopLevel.GetTopLevel(this);
        if (top is null) return;

        IStorageFile? file;
        try
        {
            file = await top.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = "Export Echoes backup",
                SuggestedFileName = "echoes-backup",
                DefaultExtension = "echoesbak",
                FileTypeChoices = new[] { EchoesBackup }
            });
        }
        catch (Exception ex) { vm.Status = "Export failed: " + ex.Message; return; }   // picker/provider failure
        if (file is null) { vm.Status = "Export cancelled."; return; }

        vm.IsBusy = true;
        try
        {
            await using var stream = await file.OpenWriteAsync();
            await stream.WriteAsync(data);
            vm.Status = $"Exported ✓  {data.Length / 1024} KB → {file.Name}";
        }
        catch (Exception ex) { vm.Status = "Export failed: " + ex.Message; }
        finally { vm.IsBusy = false; }
    }

    private async void OnImport(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not BackupViewModel vm) return;
        if (string.IsNullOrEmpty(vm.Password)) { vm.Status = "Enter the backup's password first."; return; }

        var top = TopLevel.GetTopLevel(this);
        if (top is null) return;

        System.Collections.Generic.IReadOnlyList<IStorageFile> files;
        try
        {
            files = await top.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Import Echoes backup",
                AllowMultiple = false,
                FileTypeFilter = new[] { EchoesBackup }
            });
        }
        catch (Exception ex) { vm.Status = "Import failed: " + ex.Message; return; }   // picker/provider failure
        if (files is null || files.Count == 0) { vm.Status = "Import cancelled."; return; }

        vm.IsBusy = true;
        try
        {
            byte[] data;
            await using (var stream = await files[0].OpenReadAsync())
            using (var ms = new MemoryStream())
            {
                await stream.CopyToAsync(ms);
                data = ms.ToArray();
            }
            vm.ApplyImport(data);   // throws on wrong password / bad file
            vm.Status = "Imported ✓  Restart Echoes to load the restored data.";
        }
        catch (Exception ex) { vm.Status = "Import failed: " + ex.Message; }
        finally { vm.IsBusy = false; }
    }
}
