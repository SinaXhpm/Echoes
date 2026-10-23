using System;
using System.Collections.Generic;
using System.IO;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Avalonia.VisualTree;
using Echoes.Helpers;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class TgView : UserControl
{
    private TgViewModel? _subscribed;

    public TgView()
    {
        InitializeComponent();
        // Tunnel: before a TextBox turns Enter into a new line.
        AddHandler(KeyDownEvent, OnKeyDownTunnel, RoutingStrategies.Tunnel);
        if (AppPlatform.IsMobile)
        {
            // A phone's box cut "from @BotFather" in half; the line under it already says where the token comes from.
            TokenBox.PlaceholderText = "Bot token";
            // A phone has no Ctrl+Enter, and is tapped rather than clicked.
            SendStepText.Text = "Fill in the fields and press Send.";
            HistoryEmptyText.Text = "Sent calls show up here until you close Echoes. Tap one to reopen it.";
        }
    }

    private TgViewModel? Vm => DataContext as TgViewModel;

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);
        if (_subscribed is not null) _subscribed.PropertyChanged -= OnVmPropertyChanged;
        _subscribed = Vm;
        if (_subscribed is not null) _subscribed.PropertyChanged += OnVmPropertyChanged;
    }

    // The picker opened in place of the form (narrow layouts): put the caret in its search box on desktop. Not on
    // phones, where focusing a box pops the keyboard over the list.
    private void OnVmPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(TgViewModel.IsBrowsing) || Vm is not { IsBrowsing: true, ShowMethods: true } || AppPlatform.IsMobile) return;
        Avalonia.Threading.Dispatcher.UIThread.Post(() => MethodSearchBox.Focus(), Avalonia.Threading.DispatcherPriority.Input);
    }

    // Ctrl+Enter sends from anywhere in the tool; Enter sends from a one-line parameter box (not on a phone, where the
    // keyboard's Return / Done would send a half-filled call); Escape closes the picker.
    private void OnKeyDownTunnel(object? sender, KeyEventArgs e)
    {
        if (Vm is not { } vm) return;
        bool command = e.KeyModifiers.HasFlag(KeyModifiers.Control) || e.KeyModifiers.HasFlag(KeyModifiers.Meta);
        if (e.Key == Key.Enter && command)
        {
            if (!vm.IsSending) vm.SendCommand.Execute(null);
            e.Handled = true;
        }
        else if (e.Key == Key.Enter && e.KeyModifiers == KeyModifiers.None && !AppPlatform.IsMobile
                 && e.Source is Visual v && v.FindAncestorOfType<TextBox>(includeSelf: true) is { AcceptsReturn: false } tb
                 && tb.Classes.Contains("sendOnEnter"))
        {
            if (!vm.IsSending) vm.SendCommand.Execute(null);
            e.Handled = true;
        }
        else if (e.Key == Key.Enter && e.KeyModifiers == KeyModifiers.None && e.Source is Visual lv
                 && Find<ListBox>(lv, this) is { } list && ReferenceEquals(list, MethodList))
        {
            vm.PickRow(vm.SelectedNavRow);   // the arrows moved the selection; Enter takes it (and closes the picker)
            e.Handled = true;
        }
        else if (e.Key == Key.Escape && vm.IsBrowsing)
        {
            vm.CloseBrowseCommand.Execute(null);
            e.Handled = true;
        }
    }

    // ---------- method picker: a tap opens the method (and closes the picker on narrow layouts) ----------
    private void OnMethodTapped(object? sender, TappedEventArgs e)
    {
        if (Vm is not { } vm) return;
        if (Find<ListBoxItem>(e.Source as Visual, MethodList) is { DataContext: TgNavRow row }) vm.PickRow(row);
    }

    // ---------- history: a tap re-opens the call (its ↻ button sends it again instead) ----------
    private void OnHistoryTapped(object? sender, TappedEventArgs e)
    {
        if (Vm is not { } vm) return;
        if (Find<Button>(e.Source as Visual, HistoryList) is not null) return;
        if (Find<ListBoxItem>(e.Source as Visual, HistoryList) is { DataContext: TgHistoryItem item }) vm.Reopen(item);
    }

    // ---------- updates: a double tap uses the chat ----------
    private void OnUpdateDoubleTapped(object? sender, TappedEventArgs e)
    {
        if (Vm is not { } vm || sender is not ListBox list) return;
        if (Find<Button>(e.Source as Visual, list) is not null) return;
        if (Find<ListBoxItem>(e.Source as Visual, list) is { DataContext: TgUpdateRow { HasChat: true } row })
            vm.UseChatCommand.Execute(row);
    }

    private static T? Find<T>(Visual? from, Visual stop) where T : Visual
    {
        for (var v = from; v is not null && !ReferenceEquals(v, stop); v = v.GetVisualParent())
            if (v is T t) return t;
        return null;
    }

    // ---------- file parameters: pick a local file to upload (multipart) ----------
    private async void OnChooseFile(object? sender, RoutedEventArgs e)
    {
        if ((sender as Control)?.DataContext is not TgFileField field) return;
        try
        {
            var top = TopLevel.GetTopLevel(this);
            if (top is null) return;
            IReadOnlyList<IStorageFile> files = await top.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = $"Choose a file for {field.Name}",
                AllowMultiple = false,
                FileTypeFilter = PickerTypes(field.Name),
            });
            if (files is not { Count: > 0 }) return;
            var file = files[0];

            long? size = null;
            try
            {
                var props = await file.GetBasicPropertiesAsync();
                if (props.Size is ulong s) size = (long)Math.Min(s, long.MaxValue);
            }
            catch (Exception) { /* some providers don't report a size: the upload is capped while it streams */ }

            if (size is long len && len > field.Def.MaxUploadBytes)
            {
                field.Error = $"{file.Name} is {TelegramApi.FormatBytes(len)}: the limit here is {TelegramApi.FormatBytes(field.Def.MaxUploadBytes)}.";
                return;
            }
            // Opened only when the request is sent (and again for each re-send from the history).
            field.Upload = new TgUpload(file.Name, size, async _ => await file.OpenReadAsync());
        }
        catch (Exception ex)
        {
            field.Error = "Couldn't open the file: " + TelegramApi.RedactStatic(ex.Message);
        }
    }

    private static IReadOnlyList<FilePickerFileType> PickerTypes(string param) => param switch
    {
        "photo" => new[] { FilePickerFileTypes.ImageAll, FilePickerFileTypes.All },
        "video" => new[] { new FilePickerFileType("Video") { Patterns = new[] { "*.mp4", "*.mov", "*.mkv", "*.webm" }, MimeTypes = new[] { "video/*" } }, FilePickerFileTypes.All },
        "audio" => new[] { new FilePickerFileType("Audio") { Patterns = new[] { "*.mp3", "*.m4a", "*.ogg", "*.flac", "*.wav" }, MimeTypes = new[] { "audio/*" } }, FilePickerFileTypes.All },
        "certificate" => new[] { new FilePickerFileType("Certificate (PEM)") { Patterns = new[] { "*.pem", "*.crt", "*.cer" } }, FilePickerFileTypes.All },
        _ => new[] { FilePickerFileTypes.All },
    };

    // ---------- getFile: download the file and save it ----------
    private async void OnSaveFile(object? sender, RoutedEventArgs e)
    {
        if (Vm is not { } vm) return;
        try
        {
            var top = TopLevel.GetTopLevel(this);
            if (top is null) return;
            var file = await top.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = "Save the Telegram file",
                SuggestedFileName = vm.DownloadName,
                ShowOverwritePrompt = true,
            });
            if (file is null) return;
            string? error;
            await using (var stream = await file.OpenWriteAsync())
                error = await vm.DownloadFileAsync(stream);
            // A failed or stopped download leaves a truncated file (the dialog created it): don't keep one that looks
            // like the real thing.
            if (error is not null)
            {
                try { await file.DeleteAsync(); }
                catch (Exception) { /* a provider that can't delete: the message still says it failed */ }
            }
            vm.ReportFileSaved(file.Name, error);
        }
        catch (Exception ex)
        {
            vm.ReportFileSaved(null, "Couldn't save the file: " + TelegramApi.RedactStatic(ex.Message));
        }
    }
}
