using System;
using System.ComponentModel;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Echoes.Helpers;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class BackupView : UserControl
{
    private static readonly FilePickerFileType EchoesBackup = new("Echoes backup")
    {
        Patterns = new[] { "*.echoesbak" }
    };

    private BackupViewModel? _vm;

    public BackupView()
    {
        InitializeComponent();
    }

    // The status line is tinted by outcome (the .success / .danger / .busy styles in the XAML). Its text comes from the
    // handlers below and the view-model's password checks: a success carries "✓", a failure says "failed" or asks for
    // the password; anything else (the intro, "cancelled") stays neutral.
    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);
        if (_vm is not null) _vm.PropertyChanged -= OnVmPropertyChanged;
        _vm = DataContext as BackupViewModel;
        if (_vm is not null) _vm.PropertyChanged += OnVmPropertyChanged;
        UpdateStatusTone();
    }

    private void OnVmPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(BackupViewModel.Status) or nameof(BackupViewModel.IsBusy)) UpdateStatusTone();
    }

    private void UpdateStatusTone()
    {
        string status = _vm?.Status ?? string.Empty;
        bool busy = _vm?.IsBusy == true;
        bool ok = !busy && status.Contains('✓');
        bool failed = !busy && !ok && (status.Contains("failed", StringComparison.OrdinalIgnoreCase)
                                       || status.StartsWith("Enter ", StringComparison.Ordinal)
                                       || status.StartsWith("Use a password", StringComparison.Ordinal));
        StatusBox.Classes.Set("busy", busy);
        StatusBox.Classes.Set("success", ok);
        StatusBox.Classes.Set("danger", failed);
    }

    private async void OnExport(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not BackupViewModel vm || vm.IsBusy) return;

        byte[] data;
        vm.IsBusy = true;   // the encryption runs off the UI thread; the disabled buttons block a second click
        try { data = await vm.BuildExportAsync(); }
        catch (Exception ex) { vm.Status = ex.Message; return; }   // e.g. missing/short password
        finally { vm.IsBusy = false; }

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
            vm.ClearPassword();   // done with it: don't keep the backup password in the bound field
        }
        catch (Exception ex) { vm.Status = "Export failed: " + ex.Message; }
        finally { vm.IsBusy = false; }
    }

    private async void OnImport(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not BackupViewModel vm || vm.IsBusy) return;
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
                data = await BackupVault.ReadFileAsync(stream);   // magic checked first, size capped
            string note = await vm.ApplyImportAsync(data);   // throws on wrong password / bad file
            vm.Status = "Imported ✓  Restart Echoes now to load it: until then, changes aren't saved."
                        + (note.Length > 0 ? "\n" + note : string.Empty);
            vm.ClearPassword();
        }
        catch (Exception ex) { vm.Status = "Import failed: " + ex.Message; }
        finally { vm.IsBusy = false; }
    }
}
