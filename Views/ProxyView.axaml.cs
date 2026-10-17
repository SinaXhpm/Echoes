using System;
using System.Text;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class ProxyView : UserControl
{
    private static readonly FilePickerFileType TextFile = new("Text file")
    {
        Patterns = new[] { "*.txt" },
        MimeTypes = new[] { "text/plain" },
    };

    private static readonly FilePickerFileType CsvFile = new("CSV file")
    {
        Patterns = new[] { "*.csv" },
        MimeTypes = new[] { "text/csv" },
    };

    public ProxyView()
    {
        InitializeComponent();
    }

    // ---------- the proxy checker's exports ----------

    private async void OnExportWorking(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not ProxyViewModel vm) return;
        string text = vm.WorkingText();
        if (text.Length == 0) { vm.CheckSummary = "No working proxy to export yet."; return; }
        await SaveAsync(vm, "Save the working proxies", "working-proxies.txt", "txt", TextFile, text + Environment.NewLine, "Working proxies");
    }

    private async void OnExportCsv(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not ProxyViewModel vm || !vm.HasCheckRows) return;
        await SaveAsync(vm, "Save the results", "proxy-check.csv", "csv", CsvFile, vm.ResultsCsv(), "Results");
    }

    private async Task SaveAsync(ProxyViewModel vm, string title, string name, string ext, FilePickerFileType type, string content, string what)
    {
        try
        {
            var top = TopLevel.GetTopLevel(this);
            if (top is null) return;
            var file = await top.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = title,
                SuggestedFileName = name,
                DefaultExtension = ext,
                FileTypeChoices = new[] { type },
            });
            if (file is null) return;
            await using (var stream = await file.OpenWriteAsync())
                await stream.WriteAsync(Encoding.UTF8.GetBytes(content));
            vm.ReportExport(what, file.Name);
        }
        catch (Exception ex) { vm.CheckSummary = "Couldn't save: " + ex.Message; }
    }
}
