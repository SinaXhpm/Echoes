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

    public string PlatformText => AppInfo.Platform;
    public string RuntimeText => AppInfo.Runtime;
    public string UiText => AppInfo.Ui;
    public bool CanOpenDataFolder => LinkHelper.CanOpenFolder;
    public string DataFolder => AppStorage.UserDir();

    [RelayCommand]
    private void OpenAbout()
    {
        IsAboutOpen = true;
        // Automatic: a fresh answer from this run is shown as is; none yet, a failed one or an old one is re-checked.
        if (UpdateState is UpdateCheckState.NotChecked or UpdateCheckState.Failed
            || (UpdateState is not UpdateCheckState.Checking && DateTime.Now - _lastUpdateCheck > RecheckAfter))
            _ = CheckForUpdatesAsync();
    }

    [RelayCommand]
    private void CloseAbout() => IsAboutOpen = false;

    [RelayCommand]
    private Task CheckUpdatesNow() => CheckForUpdatesAsync();

    [RelayCommand]
    private void OpenIssues() => OpenUrl(RepoUrl + "/issues/new");

    [RelayCommand]
    private void OpenLicense() => OpenUrl(RepoUrl + "/blob/master/LICENSE");

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
}
