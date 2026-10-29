using System;
using System.Collections.Generic;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Echoes.Helpers;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class DeviceView : UserControl
{
    public DeviceView()
    {
        InitializeComponent();
    }

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);
        if (DataContext is DeviceViewModel vm) vm.ScreensProbe = Screens;
    }

    // Read the device the first time the page is on screen (the tool is built on its first visit, the read waits for it).
    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        (DataContext as DeviceViewModel)?.EnsureRead();
    }

    private IReadOnlyList<DeviceInfo.ScreenInfo> Screens()
    {
        if (TopLevel.GetTopLevel(this)?.Screens is not { } screens) return Array.Empty<DeviceInfo.ScreenInfo>();
        return screens.All
            .Select(s => new DeviceInfo.ScreenInfo(s.DisplayName ?? string.Empty, s.Bounds.Width, s.Bounds.Height, s.Scaling, s.IsPrimary))
            .ToList();
    }
}
