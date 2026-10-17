using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

// Importing a curl command: pasted into the URL box, typed there, or through the Import panel.
public partial class CurlViewModel
{
    // ---- the note under the request line (import result, an automatic change) — dismissable
    [ObservableProperty] private string _noteText = string.Empty;
    [ObservableProperty] private bool _noteIsError;
    public bool HasNote => NoteText.Length > 0;
    partial void OnNoteTextChanged(string value) => OnPropertyChanged(nameof(HasNote));

    private void ShowNote(string text, bool isError)
    {
        NoteIsError = isError;
        NoteText = text;
    }

    [RelayCommand]
    private void DismissNote() => NoteText = string.Empty;

    // ---- the Import panel
    [ObservableProperty] private bool _isImportOpen;
    [ObservableProperty] private string _importText = string.Empty;
    [ObservableProperty] private string _importError = string.Empty;
    public bool HasImportError => ImportError.Length > 0;
    partial void OnImportErrorChanged(string value) => OnPropertyChanged(nameof(HasImportError));
    partial void OnImportTextChanged(string value) => ImportError = string.Empty;

    [RelayCommand]
    private async Task OpenImport()
    {
        IsSaveOpen = false;
        ImportError = string.Empty;
        // a curl command already on the clipboard is filled in
        try
        {
            string? clip = await ClipboardHelper.GetTextAsync();
            if (CurlCommand.LooksLikeCurl(clip)) ImportText = clip!.Trim();
        }
        catch { /* clipboard busy */ }
        IsImportOpen = true;
    }

    [RelayCommand]
    private void CloseImport()
    {
        IsImportOpen = false;
        ImportError = string.Empty;
    }

    [RelayCommand]
    private void ImportFromPanel()
    {
        var r = CurlCommand.Parse(ImportText);
        if (!r.Ok) { ImportError = r.Error ?? "That isn't a curl command."; return; }
        Apply(r);
        IsImportOpen = false;
        ImportText = string.Empty;
    }

    /// <summary>The URL box received a paste. A curl command is imported whole; anything else is reduced to the URL in it
    /// (as the other tools' boxes do). Returns the text to insert, or null when the paste was handled.</summary>
    public string? HandleUrlPaste(string raw, out string? hint)
    {
        hint = null;
        if (CurlCommand.LooksLikeCurl(raw))
        {
            ImportCurl(raw, fromUrlBox: true);
            return null;
        }
        if (raw.Length > 2_000_000) return raw;
        var url = HostExtractor.ExtractUrl(raw, out _);
        if (url is null) return raw.Trim();
        if (url != raw.Trim()) hint = "URL extracted";
        return url;
    }

    public void ImportCurl(string text, bool fromUrlBox)
    {
        var r = CurlCommand.Parse(text);
        if (!r.Ok)
        {
            ShowNote((fromUrlBox ? "Couldn't import the curl command: " : string.Empty) + (r.Error ?? "not a curl command"), isError: true);
            return;
        }
        Apply(r);
    }

    private void Apply(CurlImportResult r)
    {
        var current = BuildModel();
        var merged = CurlCommand.Merge(current, r);
        ApplyModel(merged, includeConnection: false);

        // connection settings only when the command names them
        if (r.SetsProxy)
        {
            Proxy = merged.Proxy ?? string.Empty;
            ProxyUser = merged.ProxyUser ?? string.Empty;
            ProxyPass = merged.ProxyPass ?? string.Empty;
            UseProxy = Proxy.Length > 0;
        }
        else if (r.SetsProxyUser)
        {
            ProxyUser = merged.ProxyUser ?? string.Empty;
            ProxyPass = merged.ProxyPass ?? string.Empty;
        }
        OverrideIp = merged.OverrideIp ?? string.Empty;

        var notes = new List<string>(r.Notes);
        if (r.Interface is { } nic)
        {
            var match = MatchInterface(nic);
            if (match != null) SelectedInterface = match;
            else notes.Add($"--interface {nic} isn't on this machine — the default route is used");
        }

        CurrentSavedId = null;
        ClearResponse();
        SectionIndex = 0;
        RequestTabIndex = r.Request.BodyMode != CurlBodyMode.None ? 2 : r.Request.Headers.Count > 0 ? 1 : 0;

        string text = "Imported: " + r.Summary();
        if (r.Ignored.Count > 0) text += " · Ignored: " + string.Join(", ", r.Ignored.Take(6)) + (r.Ignored.Count > 6 ? $" (+{r.Ignored.Count - 6})" : string.Empty);
        if (notes.Count > 0) text += " · " + string.Join(" · ", notes);
        ShowNote(text, isError: false);
    }

    // "eth0", "192.168.1.5", "if!eth0", "host!192.168.1.5" → a NIC option of this machine
    private NicOption? MatchInterface(string value)
    {
        string v = value.Trim();
        int bang = v.IndexOf('!');
        if (bang >= 0) v = v[(bang + 1)..];
        var byIp = Interfaces.FirstOrDefault(n => n.Ip != null && n.Ip.Equals(v, StringComparison.OrdinalIgnoreCase));
        if (byIp != null) return byIp;
        return Interfaces.FirstOrDefault(n => n.Ip != null && n.Display.StartsWith(v + " — ", StringComparison.OrdinalIgnoreCase));
    }
}
