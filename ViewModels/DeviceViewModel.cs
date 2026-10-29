using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

/// <summary>
/// The Device page: this machine's hardware and system (Helpers/DeviceInfo). Read the first time the page is shown
/// and again on Refresh, off the UI thread; nothing ticks in between and nothing leaves the device.
/// </summary>
public partial class DeviceViewModel : ObservableObject
{
    private readonly string _appVersion;
    private bool _read;

    public DeviceViewModel(string appVersion) => _appVersion = appVersion;

    public ObservableCollection<DeviceSection> Sections { get; } = new();

    [ObservableProperty] private string _headline = "This device";
    [ObservableProperty] private string _status = string.Empty;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(ShowReading))] private bool _isBusy;

    /// <summary>The first read is under way: the page has nothing to show yet.</summary>
    public bool ShowReading => IsBusy && Sections.Count == 0;

    /// <summary>Set by the view: the screens as the UI framework sees them (read on the UI thread), for the platforms
    /// without a richer source of their own.</summary>
    public Func<IReadOnlyList<DeviceInfo.ScreenInfo>>? ScreensProbe { get; set; }

    /// <summary>The view is on screen for the first time.</summary>
    public void EnsureRead()
    {
        if (!_read) _ = Refresh();
    }

    [RelayCommand]
    private async Task Refresh()
    {
        if (IsBusy) return;
        _read = true;
        IsBusy = true;
        Status = "Reading…";
        try
        {
            var screens = DeviceInfo.Try(() => ScreensProbe?.Invoke(), null) ?? Array.Empty<DeviceInfo.ScreenInfo>();
            var report = await Task.Run(() => DeviceInfo.Collect(screens, _appVersion));
            Sections.Clear();
            foreach (var s in report.Sections) Sections.Add(s);
            Headline = DeviceInfo.Headline(report);
            Status = $"Read at {DateTime.Now:HH:mm:ss} · read on this device, sent nowhere";
        }
        catch (Exception ex)
        {
            CrashLog.Write("Device.Refresh", ex);
            Status = "Couldn't read this device: " + ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private Task CopyAll()
        => Sections.Count == 0 ? Task.CompletedTask
         : ClipboardHelper.SetTextAsync(Headline + "\n\n" + string.Join("\n", Sections.Select(s => s.Text)));

    [RelayCommand]
    private Task CopySection(DeviceSection? section)
        => section is null ? Task.CompletedTask : ClipboardHelper.SetTextAsync(section.Text);
}
