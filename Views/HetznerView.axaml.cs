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

/// <summary>
/// The Hetzner Cloud tool. Code here is only what the view-model can't do itself: the file pickers of the zone file
/// export and import, and the taps that open a server's details or a record set on a phone.
/// </summary>
public partial class HetznerView : UserControl
{
    private static readonly FilePickerFileType ZoneFile = new("Zone file")
    {
        Patterns = new[] { "*.zone", "*.txt" },
        MimeTypes = new[] { "text/plain" },
    };

    public HetznerView()
    {
        InitializeComponent();
    }

    // phones: a narrow record set row drops its Edit / Delete buttons and opens on a tap
    private void HzMain_Attached(object? sender, Avalonia.VisualTreeAttachmentEventArgs e)
    {
        if (sender is Control main) main.Classes.Set("touch", AppPlatform.IsMobile);
    }

    private bool IsNarrow => this.FindControl<Grid>("HzMain")?.Classes.Contains("narrow") == true;

    // ---------- servers: a tap on a phone shows the server's details in place of the list ----------
    private void OnServerTapped(object? sender, TappedEventArgs e)
    {
        if (!IsNarrow || DataContext is not HetznerViewModel vm) return;
        for (var v = e.Source as Avalonia.Visual; v != null && !ReferenceEquals(v, sender); v = v.GetVisualParent())
            if (v is ListBoxItem { DataContext: HzServer })
            {
                vm.OpenServerDetails();
                return;
            }
    }

    // ---------- record sets: double-click (a tap on a phone) opens the editor, not on the row's buttons ----------
    private void OnRrsetTapped(object? sender, TappedEventArgs e)
    {
        if (AppPlatform.IsMobile) OnRrsetDoubleTapped(sender, e);
    }

    private void OnRrsetDoubleTapped(object? sender, TappedEventArgs e)
    {
        if (DataContext is not HetznerViewModel vm) return;
        for (var v = e.Source as Avalonia.Visual; v != null && !ReferenceEquals(v, sender); v = v.GetVisualParent())
        {
            if (v is Button) return;
            if (v is ListBoxItem { DataContext: HzRrset set })
            {
                if (vm.EditRrsetCommand.CanExecute(set)) vm.EditRrsetCommand.Execute(set);
                e.Handled = true;
                return;
            }
        }
    }

    // Avalonia.Android turns the filters into MIME types and drops "All" once another type is listed: a .zone file (no
    // MIME type of its own) couldn't be picked, so Android offers every file. The contents are checked either way.
    private static FilePickerFileType[] OpenTypes(FilePickerFileType type)
        => OperatingSystem.IsAndroid() ? new[] { FilePickerFileTypes.All } : new[] { type, FilePickerFileTypes.All };

    // ---------- export: Hetzner's zone file of the zone → a file ----------
    private async void OnExportZoneFile(object? sender, RoutedEventArgs e)
    {
        try
        {
            if (DataContext is not HetznerViewModel vm || await vm.ExportZoneFileAsync() is not { } export) return;
            var top = TopLevel.GetTopLevel(this);
            if (top is null) return;
            var file = await top.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = "Export the zone file",
                SuggestedFileName = export.FileName,
                DefaultExtension = "zone",
                FileTypeChoices = new[] { ZoneFile },
                ShowOverwritePrompt = true,
            });
            if (file is null) return;
            await using (var stream = await file.OpenWriteAsync())
                await stream.WriteAsync(Encoding.UTF8.GetBytes(export.Text));
            vm.ReportSaved("Zone file", file.Name);
        }
        catch (Exception ex) { Report("Export failed: " + ex.Message); }
    }

    // ---------- import: pick a zone file → the view-model checks it and asks before it replaces the records ----------
    private async void OnImportZoneFile(object? sender, RoutedEventArgs e)
    {
        try
        {
            if (DataContext is not HetznerViewModel vm) return;
            var top = TopLevel.GetTopLevel(this);
            if (top is null) return;
            IReadOnlyList<IStorageFile> files = await top.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Import a zone file",
                AllowMultiple = false,
                FileTypeFilter = OpenTypes(ZoneFile),
            });
            if (files is not { Count: > 0 }) return;
            byte[] data;
            await using (var stream = await files[0].OpenReadAsync())
                data = await CloudflareBackup.ReadCappedAsync(stream, HetznerViewModel.MaxZoneFileBytes);   // the file is untrusted
            vm.OpenZoneImport(data, files[0].Name);
        }
        catch (FormatException) { Report($"Import: the file is larger than {HetznerViewModel.MaxZoneFileBytes / 1024} KB."); }
        catch (Exception ex) { Report("Import failed: " + ex.Message); }
    }

    private void Report(string message)
    {
        if (DataContext is HetznerViewModel vm) vm.ReportFileError(message);
    }
}
