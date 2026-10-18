using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Collections;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

/// <summary>One chat message as the app shows it.</summary>
public sealed class ChatRow
{
    public required long Seq { get; init; }
    /// <summary>"You" for this device's own messages, else the sender's name.</summary>
    public required string Header { get; init; }
    public required string TimeText { get; init; }
    public required string Body { get; init; }
    public bool IsMine { get; init; }
    /// <summary>A file line (shared by this device, or received from a browser) rather than text.</summary>
    public bool IsFile { get; init; }
    /// <summary>The first web link in the text (an "open" button), or null.</summary>
    public string? Url { get; init; }
    public bool HasUrl => Url is not null;
    public bool CanCopy => !IsFile;
    public bool IsOther => !IsMine;
    /// <summary>Right to left when the text starts in an RTL script (Persian, Arabic, Hebrew): laid out from the right,
    /// like the browsers do with dir="auto".</summary>
    public Avalonia.Media.FlowDirection TextFlow => StartsRtl(Body) ? Avalonia.Media.FlowDirection.RightToLeft : Avalonia.Media.FlowDirection.LeftToRight;

    /// <summary>The first letter with a direction is from an RTL script.</summary>
    internal static bool StartsRtl(string text)
    {
        foreach (var r in text.EnumerateRunes())
        {
            int v = r.Value;
            if (v is >= 0x0590 and <= 0x08FF or >= 0xFB1D and <= 0xFDFF or >= 0xFE70 and <= 0xFEFF) return true;
            if (System.Text.Rune.IsLetter(r)) return false;
        }
        return false;
    }
}

/// <summary>
/// "Share &amp; chat" — the chat: every message (from each browser and from this device) in a virtualized list, a reply
/// box (Enter sends, Shift+Enter is a new line; on a phone Enter stays a new line), a copy button per message, an
/// unread badge on the Chat tab while it isn't in view, and a short sound when a message arrives while the window isn't
/// focused (the alert volume from the Monitor settings; off at 0).
/// </summary>
public partial class WebServerViewModel
{
    private const int MaxChatRows = 500;
    private static readonly Regex UrlRe = new(@"\bhttps?://[^\s<>""']+", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    public AvaloniaList<ChatRow> ChatItems { get; } = new() { ResetBehavior = ResetBehavior.Reset };
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(CanSendChat))] private string _chatDraft = string.Empty;
    [ObservableProperty] private string? _chatError;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasUnread), nameof(UnreadText))] private int _unreadCount;

    /// <summary>0 Chat · 1 Files · 2 Log.</summary>
    [ObservableProperty] private int _subTabIndex;

    public bool HasChat => ChatItems.Count > 0;
    public bool HasUnread => UnreadCount > 0;
    public string UnreadText => UnreadCount > 99 ? "99+" : UnreadCount.ToString(CultureInfo.InvariantCulture);
    public bool CanSendChat => IsRunning && !string.IsNullOrWhiteSpace(ChatDraft);
    public bool CanAttach => IsRunning;
    public bool IsChatTab => SubTabIndex == 0;
    public bool IsFilesTab => SubTabIndex == 1;
    public bool IsLogTab => SubTabIndex == 2;

    // The view tells whether the page is on screen (attached); with the Chat tab of Share & chat it means "read".
    private bool _viewShown;
    private long _lastSound = -10_000;

    /// <summary>Test hook: whether the app counts as focused (null = ask the window / the Android activity).</summary>
    internal Func<bool>? FocusProbe { get; set; }
    /// <summary>Test hook: sounds played for arriving messages.</summary>
    internal int ChatSounds { get; private set; }

    public bool ViewShown
    {
        get => _viewShown;
        set
        {
            if (_viewShown == value) return;
            _viewShown = value;
            if (IsChatInView) UnreadCount = 0;
        }
    }

    private bool IsChatInView => _viewShown && IsShareMode && SubTabIndex == 0;

    partial void OnSubTabIndexChanged(int value)
    {
        OnPropertyChanged(nameof(IsChatTab));
        OnPropertyChanged(nameof(IsFilesTab));
        OnPropertyChanged(nameof(IsLogTab));
        if (!_restoringShare && value is >= 0 and <= 2) ProfileService.Instance.SetSetting(KSubTab, value.ToString(CultureInfo.InvariantCulture));
        if (IsChatInView) UnreadCount = 0;
    }

    partial void OnChatDraftChanged(string value)
    {
        if (ChatError is not null) ChatError = null;
    }

    [RelayCommand]
    private void SendChat()
    {
        if (_hub is not { } hub) { ChatError = "Start sharing first."; return; }
        string text = ChatDraft ?? string.Empty;
        if (string.IsNullOrWhiteSpace(text)) return;
        try
        {
            hub.PostFromHost(text);
            ChatDraft = string.Empty;
            ChatError = null;
        }
        catch (ArgumentException ex) { ChatError = ex.Message; }
        FlushUi();   // the message is queued already: show it now, not on the next tick
    }

    /// <summary>Empties the chat here and on every page.</summary>
    [RelayCommand]
    private void ClearChat()
    {
        if (_hub is { } hub) hub.ClearChat();
        _history = Array.Empty<ShareMessage>();
        _pendingChat.Clear();
        ChatItems.Clear();
        UnreadCount = 0;
        OnPropertyChanged(nameof(HasChat));
    }

    [RelayCommand]
    private async Task CopyChat(ChatRow? row)
    {
        if (row is { CanCopy: true }) await ClipboardHelper.SetTextAsync(row.Body);
    }

    [RelayCommand]
    private void OpenChatLink(ChatRow? row) => LinkHelper.Open(row?.Url);

    /// <summary>Shares the picked files and posts each in the chat as a download link (the view's attach button).</summary>
    public void ShareInChat(SharedItem item)
    {
        if (_hub is not { } hub) return;
        hub.PostFileFromHost(item);
        FlushUi();
    }

    // UI thread (FlushUi): queued messages into the list, newest last, at most 500 kept.
    private void DrainChat()
    {
        if (_pendingChat.IsEmpty) return;
        var fresh = new List<ChatRow>();
        int incoming = 0;
        while (_pendingChat.TryDequeue(out var m))
        {
            if (m is null)
            {
                fresh.Clear();
                ChatItems.Clear();
                incoming = 0;
                continue;
            }
            fresh.Add(RowFor(m));
            if (!m.IsHost) incoming++;
        }
        if (fresh.Count > 0)
        {
            ChatItems.AddRange(fresh);
            const int max = MaxChatRows;
            if (ChatItems.Count > max) ChatItems.RemoveRange(0, ChatItems.Count - max);
        }
        OnPropertyChanged(nameof(HasChat));
        if (incoming == 0) return;
        if (!IsChatInView) UnreadCount += incoming;
        if (!AppFocused()) PlayChatSound();
    }

    private static ChatRow RowFor(ShareMessage m)
    {
        string time = m.Time.Date == DateTime.Today
            ? m.Time.ToString("HH:mm", CultureInfo.InvariantCulture)
            : m.Time.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
        string body = m.Kind switch
        {
            ShareMessageKind.File => $"Shared {m.FileName} ({FileHttpServer.HumanSize(m.FileSize)}) — a download link on the page",
            ShareMessageKind.Received => $"Sent {m.FileName} ({FileHttpServer.HumanSize(m.FileSize)}) to this device",
            _ => m.Text,
        };
        return new ChatRow
        {
            Seq = m.Seq,
            Header = m.IsHost ? "You" : m.From,
            TimeText = time,
            Body = body,
            IsMine = m.IsHost,
            IsFile = m.Kind != ShareMessageKind.Text,
            Url = m.Kind == ShareMessageKind.Text ? FirstUrl(m.Text) : null,
        };
    }

    internal static string? FirstUrl(string text)
    {
        var match = UrlRe.Match(text);
        if (!match.Success) return null;
        string u = match.Value.TrimEnd('.', ',', ';', ':', '!', '?', ')', ']', '}');
        return Uri.TryCreate(u, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https" ? u : null;
    }

    // At most one chime per 3 s, whatever arrives (SoundHelper also skips at volume 0).
    private void PlayChatSound()
    {
        long now = Environment.TickCount64;
        if (now - _lastSound < 3000) return;
        _lastSound = now;
        ChatSounds++;
        SoundHelper.Play(AlertTone.Up);
    }

    private bool AppFocused()
    {
        if (FocusProbe is { } probe) return probe();
        return Avalonia.Application.Current?.ApplicationLifetime switch
        {
            IClassicDesktopStyleApplicationLifetime d => d.MainWindow is { IsActive: true, IsVisible: true } w && w.WindowState != WindowState.Minimized,
            ISingleViewApplicationLifetime => s_foreground,
            _ => true,
        };
    }

    // Android: in front or not (the activity's own lifetime events); hooked once.
    private static bool s_foreground = true;
    private static bool s_foregroundHooked;

    private static void HookForeground()
    {
        if (s_foregroundHooked) return;
        s_foregroundHooked = true;
        try
        {
            if (Avalonia.Application.Current?.TryGetFeature<IActivatableLifetime>() is { } a)
            {
                a.Activated += (_, _) => s_foreground = true;
                a.Deactivated += (_, e) => { if (e.Kind == ActivationKind.Background) s_foreground = false; };
            }
        }
        catch { /* no lifetime events here: always "in front" (no sound) */ }
    }
}
