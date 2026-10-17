using System;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Echoes.Helpers;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class TlsView : UserControl
{
    public TlsView()
    {
        InitializeComponent();
        // a phone's narrower box cut the example off mid-name
        if (AppPlatform.IsMobile) TargetBox.PlaceholderText = "Host, host:port or URL";
    }

    // The bulk table as a CSV file (the picker needs the TopLevel, hence code-behind).
    private async void OnExportClick(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not TlsViewModel vm || vm.BulkRows.Count == 0) return;
        var top = TopLevel.GetTopLevel(this);
        if (top is null) return;
        try
        {
            var file = await top.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = "Export the TLS check",
                SuggestedFileName = vm.SuggestedCsvName,
                DefaultExtension = "csv",
                ShowOverwritePrompt = true,
                FileTypeChoices = new[] { new FilePickerFileType("CSV") { Patterns = new[] { "*.csv" }, MimeTypes = new[] { "text/csv" } } },
            });
            if (file is null) return;
            await using (var stream = await file.OpenWriteAsync())
                await vm.ExportCsvAsync(stream);
            vm.ReportExport(file.Name, null);
        }
        catch (Exception ex)
        {
            vm.ReportExport(null, ex.Message);
        }
    }
}
