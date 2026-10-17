using System;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class CheckHostView : UserControl
{
    public CheckHostView()
    {
        InitializeComponent();
        ChNodes.KeyDown += Nodes_KeyDown;
        ChNodes.ContextRequested += Nodes_ContextRequested;
    }

    private CheckHostViewModel? Vm => DataContext as CheckHostViewModel;

    // The selected row: Enter / Space opens a node's details; the copy shortcut copies the row as one line.
    private void Nodes_KeyDown(object? sender, KeyEventArgs e)
    {
        var item = ChNodes.SelectedItem;
        if (item is null) return;
        if (e.Key is Key.Enter or Key.Space && e.KeyModifiers == KeyModifiers.None && item is CheckHostNodeRow node)
        {
            node.IsExpanded = !node.IsExpanded;
            e.Handled = true;
        }
        else if (e.Key == Key.C && e.KeyModifiers is KeyModifiers.Control or KeyModifiers.Meta)   // Ctrl+C, Cmd+C on a Mac
        {
            if (item is CheckHostNodeRow n) n.CopyRowCommand.Execute(null);
            else if (item is CheckHostGroupRow g) g.CopyCommand.Execute(null);
            e.Handled = true;
        }
    }

    // The menu key (no pointer): the selected row's copy menu. Right-click / long-press reach the line itself.
    private void Nodes_ContextRequested(object? sender, ContextRequestedEventArgs e)
    {
        if (e.Handled || e.TryGetPosition(ChNodes, out _) || ChNodes.SelectedItem is not { } item) return;
        if (ChNodes.ContainerFromItem(item) is ListBoxItem { Presenter.Child: Controls.ChLine line })
            e.Handled = line.OpenMenu();
    }

    // The picker opened: load check-host.net's node list (once a session) and tick the current choice.
    private void NodesFlyout_Opened(object? sender, EventArgs e) => _ = Vm?.EnsureCatalogAsync();

    private void SaveText_Click(object? sender, RoutedEventArgs e) => Export("txt");
    private void SaveCsv_Click(object? sender, RoutedEventArgs e) => Export("csv");
    private void SaveJson_Click(object? sender, RoutedEventArgs e) => Export("json");

    // (the save picker needs the TopLevel, hence code-behind)
    private async void Export(string format)
    {
        if (Vm is not { } vm || TopLevel.GetTopLevel(this) is not { } top) return;
        // async void: an I/O failure (disk full, read-only target, locked file) must not escape and crash the app.
        try
        {
            await vm.ExportAsync(top.StorageProvider, format);
        }
        catch (Exception ex)
        {
            vm.ErrorText = "Couldn't save the file: " + ex.Message;
        }
    }
}
