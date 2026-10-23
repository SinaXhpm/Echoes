using System;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

public enum UpdateCheckState { NotChecked, Checking, UpToDate, Available, Failed }

// The About box (the ⓘ in the desktop sidebar, "About" in the phone drawer): version, the update check, links, and the
// platform details a bug report needs. Both shells host the same AboutView over their content.
public partial class MainViewModel
{
    private const string RepoUrl = "https://github.com/SinaXhpm/Echoes";

    // A good answer is reused for a while; the box re-checks on open after this, or after a failure.
    private static readonly TimeSpan RecheckAfter = TimeSpan.FromMinutes(30);
    private DateTime _lastUpdateCheck;

    [ObservableProperty] private bool _isAboutOpen;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsCheckingUpdate), nameof(IsUpToDate), nameof(IsUpdateCheckFailed),
                              nameof(IsUpdateBadgeAccent), nameof(UpdateBadge))]
    private UpdateCheckState _updateState;

    [ObservableProperty] private string _updateDetail = "Not checked yet";
    [ObservableProperty] private string? _updateDetailTip;
    [ObservableProperty] private string _copyInfoLabel = "Copy info";
    [ObservableProperty] private string _copyLogLabel = "Copy log";

    public bool IsCheckingUpdate => UpdateState == UpdateCheckState.Checking;
    public bool IsUpToDate => UpdateState == UpdateCheckState.UpToDate;
    public bool IsUpdateCheckFailed => UpdateState == UpdateCheckState.Failed;
    public bool IsUpdateBadgeAccent => UpdateState == UpdateCheckState.Available;

    public string UpdateBadge => UpdateState switch
    {
        UpdateCheckState.Checking => "Checking…",
        UpdateCheckState.UpToDate => "Up to date",
        UpdateCheckState.Available => "Update available",
        UpdateCheckState.Failed => "Check failed",
        _ => "Not checked",
    };

    /// <summary>False in an app store's build (<see cref="AppInfo.IsStoreBuild"/>): the update section and the Releases link are hidden.</summary>
    public bool ShowUpdates => !AppInfo.IsStoreBuild;

    public string PlatformText => AppInfo.Platform;
    public string RuntimeText => AppInfo.Runtime;
    public string UiText => AppInfo.Ui;
    public bool CanOpenDataFolder => LinkHelper.CanOpenFolder;
    /// <summary>A phone can't open the data folder, so the errors Echoes recorded are copied from here instead.</summary>
    public bool CanCopyLog => !LinkHelper.CanOpenFolder;
    public string DataFolder => AppStorage.UserDir();

    [RelayCommand]
    private void OpenAbout()
    {
        IsAboutOpen = true;
        _ = CheckForUpdatesIfStale();
    }

    /// <summary>Automatic: a fresh answer from this run is kept as is; none yet, a failed one or an old one is re-checked.
    /// (The shell's Loaded comes again with every new Android activity: it asked GitHub again each time.)</summary>
    public Task CheckForUpdatesIfStale()
        => UpdateState is UpdateCheckState.NotChecked or UpdateCheckState.Failed
           || (UpdateState is not UpdateCheckState.Checking && DateTime.Now - _lastUpdateCheck > RecheckAfter)
            ? CheckForUpdatesAsync()
            : Task.CompletedTask;

    [RelayCommand]
    private void CloseAbout() => IsAboutOpen = false;

    [RelayCommand]
    private Task CheckUpdatesNow() => CheckForUpdatesAsync();

    [RelayCommand]
    private void OpenIssues() => OpenUrl(RepoUrl + "/issues/new");

    [RelayCommand]
    private void OpenLicense() => OpenUrl(RepoUrl + "/blob/master/LICENSE");

    [RelayCommand]
    private void OpenPrivacy() => OpenUrl(RepoUrl + "/blob/master/PRIVACY.md");

    [RelayCommand]
    private void OpenDataFolderInShell() => LinkHelper.OpenFolder(DataFolder);

    [RelayCommand]
    private async Task CopyInfo()
    {
        await ClipboardHelper.SetTextAsync(AppInfo.Summary(CurrentVersion));
        CopyInfoLabel = "Copied";
        await Task.Delay(1500);
        CopyInfoLabel = "Copy info";
    }

    // The version and platform, then the end of the crash log (secrets are already left out of it): what a bug report needs
    // from a phone, where the log file can't be opened.
    [RelayCommand]
    private async Task CopyLog()
    {
        string log = await Task.Run(() => CrashLog.ReadTail());
        if (log.Length == 0)
        {
            CopyLogLabel = "No errors";
        }
        else
        {
            await ClipboardHelper.SetTextAsync(AppInfo.Summary(CurrentVersion) + Environment.NewLine + Environment.NewLine + log);
            CopyLogLabel = "Copied";
        }
        await Task.Delay(1500);
        CopyLogLabel = "Copy log";
    }
}
