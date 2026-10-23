using System;
using System.Collections.Generic;
using System.Text;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Avalonia.VisualTree;
using Echoes.Helpers;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class CloudflareView : UserControl
{
    private static readonly FilePickerFileType JsonBackup = new("DNS backup (JSON)")
    {
        Patterns = new[] { "*.json" },
        MimeTypes = new[] { "application/json" },
    };

    private static readonly FilePickerFileType ZoneFile = new("BIND zone file")
    {
        Patterns = new[] { "*.txt", "*.zone" },
        MimeTypes = new[] { "text/plain" },
    };

    public CloudflareView()
    {
        InitializeComponent();
        // phones: a narrow record row drops its Edit / Delete buttons (styles: CfMain.narrow.touch) and opens on a tap
        if (AppPlatform.IsMobile) CfMain.Classes.Add("touch");
    }

    // Avalonia.Android turns the filters into MIME types and drops "All" once another type is listed, so a .zone file (no
    // MIME type of its own) couldn't be picked: Android offers every file. The contents are checked either way.
    private static FilePickerFileType[] OpenTypes(FilePickerFileType type)
        => OperatingSystem.IsAndroid() ? new[] { FilePickerFileTypes.All } : new[] { type, FilePickerFileTypes.All };

    // ---------- backup: the zone's records → a JSON file ----------
    private async void OnBackup(object? sender, RoutedEventArgs e)
    {
        try
        {
            if (DataContext is not CloudflareViewModel vm || await vm.BuildBackupAsync() is not { } backup) return;
            var file = await PickSaveAsync("Back up DNS records", backup.FileName, "json", JsonBackup);
            if (file is null) return;
            await using (var stream = await file.OpenWriteAsync())
                await stream.WriteAsync(backup.Data);
            vm.ReportSaved($"Backup of {backup.Count} record{(backup.Count == 1 ? "" : "s")}", file.Name);
        }
        catch (Exception ex) { Report("Backup failed: " + ex.Message); }
    }

    // ---------- export: Cloudflare's BIND rendering of the zone ----------
    private async void OnExportZoneFile(object? sender, RoutedEventArgs e)
    {
        try
        {
            if (DataContext is not CloudflareViewModel vm || await vm.ExportZoneFileAsync() is not { } export) return;
            var file = await PickSaveAsync("Export BIND zone file", export.FileName, "txt", ZoneFile);
            if (file is null) return;
            await using (var stream = await file.OpenWriteAsync())
                await stream.WriteAsync(Encoding.UTF8.GetBytes(export.Text));
            vm.ReportSaved("Zone file", file.Name);
        }
        catch (Exception ex) { Report("Export failed: " + ex.Message); }
    }

    // ---------- restore: pick a backup → the view-model validates it and shows a preview ----------
    private async void OnRestore(object? sender, RoutedEventArgs e)
    {
        try
        {
            if (DataContext is not CloudflareViewModel vm) return;
            var top = TopLevel.GetTopLevel(this);
            if (top is null) return;
            IReadOnlyList<IStorageFile> files = await top.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Restore DNS records",
                AllowMultiple = false,
                FileTypeFilter = OpenTypes(JsonBackup),
            });
            if (files is not { Count: > 0 }) return;

            byte[] data;
            await using (var stream = await files[0].OpenReadAsync())
                data = await CloudflareBackup.ReadCappedAsync(stream);   // size-capped: the file is untrusted
            await vm.OpenRestoreAsync(data, files[0].Name);
        }
        catch (FormatException ex) { Report("Restore: " + ex.Message); }
        catch (Exception ex) { Report("Restore failed: " + ex.Message); }
    }

    // ---------- import: pick a BIND zone file → the view-model parses it and shows what would be added ----------
    private async void OnImportZoneFile(object? sender, RoutedEventArgs e)
    {
        try
        {
            if (DataContext is not CloudflareViewModel vm) return;
            var top = TopLevel.GetTopLevel(this);
            if (top is null) return;
            IReadOnlyList<IStorageFile> files = await top.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Import a BIND zone file",
                AllowMultiple = false,
                FileTypeFilter = OpenTypes(ZoneFile),
            });
            if (files is not { Count: > 0 }) return;

            byte[] data;
            await using (var stream = await files[0].OpenReadAsync())
                data = await CloudflareBackup.ReadCappedAsync(stream, CloudflareZoneFile.MaxBytes);   // the file is untrusted
            await vm.OpenImportAsync(data, files[0].Name);
        }
        catch (FormatException) { Report($"Import: the file is larger than {CloudflareZoneFile.MaxBytes / 1024} KB, Cloudflare's limit for a zone file."); }
        catch (Exception ex) { Report("Import failed: " + ex.Message); }
    }

    private async System.Threading.Tasks.Task<IStorageFile?> PickSaveAsync(string title, string name, string extension, FilePickerFileType type)
    {
        var top = TopLevel.GetTopLevel(this);
        if (top is null) return null;
        return await top.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = title,
            SuggestedFileName = name,
            DefaultExtension = extension,
            FileTypeChoices = new[] { type },
            ShowOverwritePrompt = true,
        });
    }

    private void Report(string message)
    {
        if (DataContext is CloudflareViewModel vm) vm.ReportFileError(message);
    }

    // ---------- double-click / double-tap a record to edit it (not on its pill or buttons) ----------
    // A phone opens it on one tap: its narrow rows have no Edit / Delete buttons, and the editor has Delete.
    private void OnRecordTapped(object? sender, TappedEventArgs e)
    {
        if (AppPlatform.IsMobile) OnRecordDoubleTapped(sender, e);
    }

    private void OnRecordDoubleTapped(object? sender, TappedEventArgs e)
    {
        if (DataContext is not CloudflareViewModel vm) return;
        // (sender: the record list, built when its tab is first shown)
        for (var v = e.Source as Avalonia.Visual; v != null && !ReferenceEquals(v, sender); v = v.GetVisualParent())
        {
            if (v is Button) return;
            if (v is ListBoxItem { DataContext: CfRecord rec })
            {
                if (vm.EditRecordCommand.CanExecute(rec)) vm.EditRecordCommand.Execute(rec);
                e.Handled = true;
                return;
            }
        }
    }
}
