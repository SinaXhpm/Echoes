using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;
using CoreFoundation;
using Echoes.Helpers;
using Foundation;
using Metal;
using UIKit;

namespace Echoes.iOS;

/// <summary>
/// What only UIKit, Foundation and Metal know for the Device page (registered as DeviceInfo.PlatformCollector): the
/// iPhone's model and chip, iOS version, the screen, battery, Low Power Mode and thermal state, memory available to the
/// app, storage and the GPU. sysctl (DeviceInfoApple) adds the cores, caches and OS build. UIKit is read on the main
/// thread (this runs on a worker).
/// </summary>
internal static class IosDeviceInfo
{
    // Model identifier → name and chip, for the iPhones this app runs on (iOS 17+). An unknown one shows its identifier.
    private static readonly Dictionary<string, (string Name, string Chip)> Models = new()
    {
        ["iPhone12,1"] = ("iPhone 11", "A13 Bionic"), ["iPhone12,3"] = ("iPhone 11 Pro", "A13 Bionic"),
        ["iPhone12,5"] = ("iPhone 11 Pro Max", "A13 Bionic"), ["iPhone12,8"] = ("iPhone SE (2nd generation)", "A13 Bionic"),
        ["iPhone13,1"] = ("iPhone 12 mini", "A14 Bionic"), ["iPhone13,2"] = ("iPhone 12", "A14 Bionic"),
        ["iPhone13,3"] = ("iPhone 12 Pro", "A14 Bionic"), ["iPhone13,4"] = ("iPhone 12 Pro Max", "A14 Bionic"),
        ["iPhone14,4"] = ("iPhone 13 mini", "A15 Bionic"), ["iPhone14,5"] = ("iPhone 13", "A15 Bionic"),
        ["iPhone14,2"] = ("iPhone 13 Pro", "A15 Bionic"), ["iPhone14,3"] = ("iPhone 13 Pro Max", "A15 Bionic"),
        ["iPhone14,6"] = ("iPhone SE (3rd generation)", "A15 Bionic"), ["iPhone14,7"] = ("iPhone 14", "A15 Bionic"),
        ["iPhone14,8"] = ("iPhone 14 Plus", "A15 Bionic"), ["iPhone15,2"] = ("iPhone 14 Pro", "A16 Bionic"),
        ["iPhone15,3"] = ("iPhone 14 Pro Max", "A16 Bionic"), ["iPhone15,4"] = ("iPhone 15", "A16 Bionic"),
        ["iPhone15,5"] = ("iPhone 15 Plus", "A16 Bionic"), ["iPhone16,1"] = ("iPhone 15 Pro", "A17 Pro"),
        ["iPhone16,2"] = ("iPhone 15 Pro Max", "A17 Pro"), ["iPhone17,3"] = ("iPhone 16", "A18"),
        ["iPhone17,4"] = ("iPhone 16 Plus", "A18"), ["iPhone17,1"] = ("iPhone 16 Pro", "A18 Pro"),
        ["iPhone17,2"] = ("iPhone 16 Pro Max", "A18 Pro"), ["iPhone17,5"] = ("iPhone 16e", "A18"),
    };

    [DllImport("/usr/lib/libSystem.dylib")]
    private static extern nuint os_proc_available_memory();

    public static void Collect(DeviceReport r)
    {
        string? simulated = Environment.GetEnvironmentVariable("SIMULATOR_MODEL_IDENTIFIER");
        string? id = simulated ?? DeviceInfoApple.Str("hw.machine");
        (string Name, string Chip) known = id is not null && Models.TryGetValue(id, out var k) ? k : (string.Empty, string.Empty);
        r.Row("device", "Manufacturer", "Apple");
        r.Row("device", "Model", (known.Name.Length > 0 ? known.Name : id) + (simulated is not null ? " (Simulator)" : string.Empty));
        r.Row("device", "Model identifier", id);
        r.Row("device", "Board", DeviceInfoApple.Str("hw.model"));
        if (known.Chip.Length > 0) r.Row("cpu", "Chip", $"Apple {known.Chip}");

        DeviceInfo.Try(() => DispatchQueue.MainQueue.DispatchSync(() => DeviceInfo.Try(() => UiKit(r))));

        DeviceInfo.Try(() =>
        {
            var pi = NSProcessInfo.ProcessInfo;
            r.Row("memory", "Total", DeviceInfo.Bytes((long)pi.PhysicalMemory));
            if (OperatingSystem.IsIOSVersionAtLeast(13)) r.Row("memory", "Available to Echoes", DeviceInfo.Bytes((long)os_proc_available_memory()));
            r.Row("cpu", "Active cores", pi.ActiveProcessorCount.ToString(CultureInfo.InvariantCulture));
            r.Row("os", "Uptime", DeviceInfo.Duration(TimeSpan.FromSeconds(pi.SystemUptime)));
            r.Row("battery", "Low Power Mode", pi.LowPowerModeEnabled ? "On" : "Off");
            r.Row("thermal", "Thermal state", pi.ThermalState switch
            {
                NSProcessInfoThermalState.Nominal => "Normal",
                NSProcessInfoThermalState.Fair => "Slightly warm",
                NSProcessInfoThermalState.Serious => "Hot (performance reduced)",
                NSProcessInfoThermalState.Critical => "Critical",
                _ => null,
            });
        });

        DeviceInfo.Try(() =>
        {
            var attrs = NSFileManager.DefaultManager.GetFileSystemAttributes(NSFileManager.HomeDirectory ?? "/", out NSError? error);
            if (attrs is null || error is not null) return;
            long total = (long)attrs.Size, free = (long)attrs.FreeSize;
            r.Heading("storage", "Internal storage");
            r.Row("storage", "Capacity", DeviceInfo.DiskBytes(total));
            r.Row("storage", "Free", $"{DeviceInfo.Bytes(free)} ({DeviceInfo.Percent(total - free, total)} used)");
        });

        DeviceInfo.Try(() =>
        {
            var gpu = MTLDevice.SystemDefault;
            if (gpu is null) return;
            r.Row("gpu", "Name", gpu.Name);
            r.Row("gpu", "Memory", gpu.HasUnifiedMemory ? "Unified (shared with the CPU)" : null);
            if (gpu.RecommendedMaxWorkingSetSize > 0) r.Row("gpu", "Working set", DeviceInfo.Bytes((long)gpu.RecommendedMaxWorkingSetSize));
            string? family = null;
            foreach (var (f, name) in new[]
            {
                (MTLGpuFamily.Apple9, "Apple 9"), (MTLGpuFamily.Apple8, "Apple 8"), (MTLGpuFamily.Apple7, "Apple 7"),
                (MTLGpuFamily.Apple6, "Apple 6"), (MTLGpuFamily.Apple5, "Apple 5"),
            })
                if (gpu.SupportsFamily(f)) { family = name; break; }
            r.Row("gpu", "Metal family", family);
        });
    }

    private static void UiKit(DeviceReport r)
    {
        var dev = UIDevice.CurrentDevice;
        bool pad = dev.UserInterfaceIdiom == UIUserInterfaceIdiom.Pad;
        r.Row("os", "Name", $"{(pad ? "iPadOS" : dev.SystemName)} {dev.SystemVersion}");
        r.Row("device", "Name", dev.Name);
        r.Row("device", "Type", dev.Model);

        var screen = UIScreen.MainScreen;
        var px = screen.NativeBounds;
        r.Heading("display", "Built-in screen");
        r.Row("display", "Resolution", $"{(int)Math.Min(px.Width, px.Height)} × {(int)Math.Max(px.Width, px.Height)}");
        r.Row("display", "Points", $"{(int)Math.Min(screen.Bounds.Width, screen.Bounds.Height)} × {(int)Math.Max(screen.Bounds.Width, screen.Bounds.Height)} (@{screen.NativeScale:0.##}x)");
        r.Row("display", "Refresh rate", $"up to {screen.MaximumFramesPerSecond} Hz");
        r.Row("display", "Brightness", $"{screen.Brightness * 100:0}%");

        bool wasOn = dev.BatteryMonitoringEnabled;
        dev.BatteryMonitoringEnabled = true;
        try
        {
            float level = dev.BatteryLevel;
            if (level >= 0) r.Row("battery", "Charge", $"{level * 100:0}%");
            r.Row("battery", "Status", dev.BatteryState switch
            {
                UIDeviceBatteryState.Charging => "Charging",
                UIDeviceBatteryState.Full => "Full",
                UIDeviceBatteryState.Unplugged => "On battery",
                _ => null,
            });
        }
        finally { dev.BatteryMonitoringEnabled = wasOn; }
    }
}
