using System;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

// Starting by itself — the top of the Monitor settings:
//  • "Start monitoring when Echoes opens": a profile setting (desktop and Android), read by App at launch.
//  • desktop: "Open Echoes when I sign in" — the OS login entry itself (Helpers/AutoStart), read back rather than stored.
//  • Android: "Start when the phone starts" — a profile setting the boot receiver reads (Helpers/BootStart,
//    Echoes.Android/BootReceiver.cs); the receiver component is switched on only while it is wanted.
// A start nobody clicked (launch, sign-in, boot) waits for a network first, so a phone or laptop that is still
// connecting doesn't log every monitor as down (and alert on it) in its first seconds.
public sealed partial class MonitorViewModel
{
    private const string KeyAutoStart = "monitor.autoStart";

    /// <summary>What the Android background-service notification says while monitoring runs.</summary>
    internal const string BackgroundReason = "Monitoring targets";

    // A start at launch / boot waits at most this long for a network; then it starts anyway (offline is worth knowing).
    private static readonly TimeSpan NetworkWaitLimit = TimeSpan.FromSeconds(90);
    private static readonly TimeSpan NetworkPoll = TimeSpan.FromSeconds(2);
    // After a reboot the network that just came up is often not routing yet (DHCP, Wi-Fi validation): a short grace.
    internal static TimeSpan BootSettle { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>Is there a network to check over? Swappable for tests. Any error counts as yes (never block a start).</summary>
    internal static Func<bool> IsNetworkUp { get; set; } = () =>
    {
        try { return NetworkInterface.GetIsNetworkAvailable(); }
        catch { return true; }
    };

    /// <summary>
    /// "Start monitoring when Echoes opens", read by App at launch WITHOUT creating this view-model: when it's off the
    /// Monitor costs nothing until its tab is opened.
    /// </summary>
    public static bool StartsWithApp => ProfileService.Instance.GetBool(KeyAutoStart, false);

    [ObservableProperty] private bool _startWithApp;
    [ObservableProperty] private bool _openAtLogin;
    [ObservableProperty] private string _openAtLoginNote = string.Empty;
    [ObservableProperty] private bool _openAtLoginNoteIsError;
    [ObservableProperty] private bool _canUseThisCopy;
    private bool _syncingLogin;   // OpenAtLogin is being set FROM the system: don't write it back

    /// <summary>Android: "Start when the phone starts" (after a reboot or an update of Echoes).</summary>
    [ObservableProperty] private bool _startOnBoot;
    [ObservableProperty] private string _bootNote = string.Empty;
    [ObservableProperty] private bool _bootNoteIsError;

    private bool _waitingForNetwork;   // a launch / boot start is waiting for a network
    private int _launchToken;          // bumped to cancel that waiting start (a click on Start / Stop decides instead)

    /// <summary>Only where the desktop head has armed it (not on Android, not in the designer or a test harness).</summary>
    public bool ShowOpenAtLogin => AutoStart.IsSupported && !AppPlatform.IsMobile;
    public bool HasOpenAtLoginNote => OpenAtLoginNote.Length > 0;

    /// <summary>Only where the Android head has registered its boot receiver.</summary>
    public bool ShowStartOnBoot => BootStart.IsSupported;
    public bool HasBootNote => ShowStartOnBoot && BootNote.Length > 0;

    private void LoadStartupSettings(ProfileService ps)
    {
        StartWithApp = ps.GetBool(KeyAutoStart, false);
        StartOnBoot = ps.GetBool(BootStart.ProfileKey, false);
        // Still !_loaded: nothing is written back. The receiver follows the setting (a restored backup, a reinstall).
        if (BootStart.IsSupported) SetBootNote(StartOnBoot ? BootStart.Apply(true) : null);
    }

    /// <summary>
    /// App launch with "Start monitoring when Echoes opens" on, or a login launch (--background): starts monitoring when
    /// there is something to check — once a network is up (at most <see cref="NetworkWaitLimit"/> later). An empty list
    /// just stays idle (no "add a monitor" notice for a start nobody asked for).
    /// </summary>
    public void StartAtLaunch() => _ = StartWhenOnlineAsync(" · started with Echoes", TimeSpan.Zero);

    /// <summary>
    /// The boot receiver (Android, "Start when the phone starts"): the same as a launch start, with a short grace after
    /// the network comes up. Completes once monitoring runs, or it's clear that it won't (nothing to check, Start /
    /// Stop clicked meanwhile). UI thread.
    /// </summary>
    public Task StartAtBootAsync() => StartWhenOnlineAsync(" · started with the phone", BootSettle);

    private async Task StartWhenOnlineAsync(string note, TimeSpan settle)
    {
        try { await WaitAndStartAsync(note, settle); }
        catch (Exception ex) { CrashLog.Write("Monitor.StartAtLaunch", ex); }
    }

    private async Task WaitAndStartAsync(string note, TimeSpan settle)
    {
        if (IsMonitoring || Targets.Count == 0) return;
        int token = ++_launchToken;
        // This start takes over from one still waiting (a boot start, then the launch start): the old wait won't clear
        // its "waiting for the network" flag (its token is stale now), so clear it here; a wait below sets it again.
        if (_waitingForNetwork) SetWaitingForNetwork(false);
        if (!IsNetworkUp() || settle > TimeSpan.Zero)
        {
            SetWaitingForNetwork(true);
            try
            {
                var waited = TimeSpan.Zero;
                bool hadNetwork = IsNetworkUp();
                while (!hadNetwork && waited < NetworkWaitLimit)
                {
                    await Task.Delay(NetworkPoll);
                    waited += NetworkPoll;
                    if (token != _launchToken) return;
                    hadNetwork = IsNetworkUp();
                }
                if (hadNetwork && settle > TimeSpan.Zero) await Task.Delay(settle);
            }
            finally
            {
                if (token == _launchToken) SetWaitingForNetwork(false);
            }
        }
        if (token != _launchToken || IsMonitoring || Targets.Count == 0) return;
        StartMonitoring(atLaunch: true, note);
    }

    // Start / Stop clicked while a launch start waits: the click wins, the waiting start is dropped.
    private void CancelPendingLaunch()
    {
        if (!_waitingForNetwork) return;
        _launchToken++;
        SetWaitingForNetwork(false);
    }

    private void SetWaitingForNetwork(bool value)
    {
        _waitingForNetwork = value;
        UpdateRunState();
    }

    partial void OnStartWithAppChanged(bool value)
    {
        if (_loaded) PersistSettings();
    }

    partial void OnStartOnBootChanged(bool value)
    {
        if (!_loaded) return;
        PersistSettings();
        string? error = BootStart.Apply(value);
        if (error is not null)
        {
            // The receiver couldn't follow: show what is really in effect (posted — this runs inside the box's own write).
            ProfileService.Instance.SetBool(BootStart.ProfileKey, !value);
            Dispatcher.UIThread.Post(() =>
            {
                StartOnBoot = !value;
                SetBootNote(error);
            });
            return;
        }
        SetBootNote(null);
    }

    // The note under "Start when the phone starts": a failure, or — while it is on — what some phones also need.
    private void SetBootNote(string? error)
    {
        BootNoteIsError = error is not null;
        BootNote = error ?? (StartOnBoot
            ? "Also allow Auto launch for Echoes in the phone settings."
            : string.Empty);
    }

    [RelayCommand]
    private void OpenAppSettings() => BootStart.OpenAppSettings();

    partial void OnBootNoteChanged(string value) => OnPropertyChanged(nameof(HasBootNote));

    partial void OnOpenAtLoginChanged(bool value)
    {
        if (!_loaded || _syncingLogin || !AutoStart.IsSupported) return;
        string? error = value ? AutoStart.Enable() : AutoStart.Disable();
        // Posted: this runs inside the check box's own write to the property, and a change made in the middle of that
        // doesn't reach the box — after a failure it would stay ticked while nothing is registered.
        Dispatcher.UIThread.Post(() => SyncOpenAtLogin(error));
    }

    partial void OnOpenAtLoginNoteChanged(string value) => OnPropertyChanged(nameof(HasOpenAtLoginNote));

    // The panel opens: read the entry again (Task Manager, GNOME's startup apps or another copy may have changed it).
    partial void OnIsSettingsOpenChanged(bool value)
    {
        if (value && _loaded) SyncOpenAtLogin();
    }

    /// <summary>"Use this copy": the entry starts another copy of Echoes; point it at this one.</summary>
    [RelayCommand]
    private void UseThisCopy() => SyncOpenAtLogin(AutoStart.Enable());

    // Shows what is really registered; error = the one reason the last change failed. An entry whose program is gone
    // (Echoes moved) is pointed at this copy on the spot.
    private void SyncOpenAtLogin(string? error = null)
    {
        if (!AutoStart.IsSupported) return;
        var status = AutoStart.Read();
        if (status.State == AutoStartState.Moved && error is null)
        {
            error = AutoStart.Enable();
            status = AutoStart.Read();
        }

        _syncingLogin = true;
        try { OpenAtLogin = status.State != AutoStartState.Off; }
        finally { _syncingLogin = false; }

        CanUseThisCopy = error is null && status.State == AutoStartState.OtherCopy;
        if (error is not null)
        {
            OpenAtLoginNoteIsError = true;
            OpenAtLoginNote = error;
        }
        else if (status.State == AutoStartState.OtherCopy)
        {
            OpenAtLoginNoteIsError = false;
            OpenAtLoginNote = "Opens the copy at " + status.RegisteredPath;
        }
        else
        {
            OpenAtLoginNoteIsError = false;
            OpenAtLoginNote = string.Empty;
        }
    }
}
