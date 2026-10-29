using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.Hardware;
using Android.Hardware.Camera2;
using Android.Hardware.Display;
using Android.Opengl;
using Android.OS;
using Android.Runtime;
using Android.Util;
using Echoes.Helpers;

namespace Echoes.Android;

/// <summary>
/// What only Android's SDK knows for the Device page (registered as DeviceInfo.PlatformCollector): the phone's
/// marketing name and SoC (Build, system properties), Android's version and patch level, memory as Android counts it,
/// the screen and its modes, the battery (BatteryManager), the GPU (a throwaway EGL context), storage, every camera and
/// sensor, and the hardware features. No permission is needed for any of it. The shared Linux reader adds the kernel,
/// the CPU clusters and the thermal zones Android lets apps read.
/// </summary>
internal static class AndroidDeviceInfo
{
    public static void Collect(DeviceReport r)
    {
        var ctx = global::Android.App.Application.Context;
        var props = DeviceInfo.Try(SystemProperties, new Dictionary<string, string>());
        DeviceInfo.Try(() => Device(r, props));
        DeviceInfo.Try(() => Os(r, props));
        DeviceInfo.Try(() => Memory(r, ctx));
        DeviceInfo.Try(() => Gpu(r, ctx));
        DeviceInfo.Try(() => Screen(r, ctx));
        DeviceInfo.Try(() => Storage(r));
        DeviceInfo.Try(() => Battery(r, ctx));
        DeviceInfo.Try(() => Cameras(r, ctx));
        DeviceInfo.Try(() => Sensors(r, ctx));
        DeviceInfo.Try(() => Features(r, ctx));
    }

    private static void Device(DeviceReport r, Dictionary<string, string> p)
    {
        string? P(params string[] keys) => keys.Select(k => p.GetValueOrDefault(k)).FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));
        string maker = Build.Manufacturer ?? string.Empty;
        string? market = P("ro.vendor.oplus.market.name", "ro.product.marketname", "ro.product.vendor.marketname",
                           "ro.config.marketing_name", "ro.product.odm.marketname", "ro.vendor.product.display");
        r.Row("device", "Manufacturer", Capital(maker));
        r.Row("device", "Model", market ?? Build.Model);
        r.Row("device", "Model number", Build.Model);
        r.Row("device", "Brand", Capital(Build.Brand ?? string.Empty));
        r.Row("device", "Codename", Build.Device);
        r.Row("device", "Product", Build.Product);
        r.Row("device", "Board", Build.Board);
        r.Row("device", "Name", AppInfo.DeviceName);
        if (OperatingSystem.IsAndroidVersionAtLeast(31))
            r.Row("cpu", "SoC", string.Join(" ", new[] { Build.SocManufacturer, Build.SocModel }.Where(s => DeviceInfo.Clean(s) is not null)));
        r.Row("cpu", "Platform", P("ro.board.platform", "ro.hardware.chipname", "ro.soc.model"));
        r.Row("cpu", "ABIs", Build.SupportedAbis is { Count: > 0 } abis ? string.Join(", ", abis) : null);
    }

    private static void Os(DeviceReport r, Dictionary<string, string> p)
    {
        r.Row("os", "Name", $"Android {Build.VERSION.Release} (API {(int)Build.VERSION.SdkInt})");
        string? skin = p.GetValueOrDefault("ro.build.version.realmeui") is { Length: > 0 } rui ? $"realme UI {rui}"
                     : p.GetValueOrDefault("ro.build.version.opporom") is { Length: > 0 } cos ? $"ColorOS {cos.TrimStart('V', 'v')}"
                     : p.GetValueOrDefault("ro.mi.os.version.name") is { Length: > 0 } hos ? $"Xiaomi HyperOS {hos}"
                     : p.GetValueOrDefault("ro.miui.ui.version.name") is { Length: > 0 } miui ? $"MIUI {miui.TrimStart('V')}"
                     : p.GetValueOrDefault("ro.build.version.oneui") is { Length: >= 5 } one && int.TryParse(one, out int o) ? $"One UI {o / 10000}.{o / 100 % 100}"
                     : p.GetValueOrDefault("ro.build.version.emui") is { Length: > 0 } emui ? emui
                     : p.GetValueOrDefault("ro.vivo.os.version") is { Length: > 0 } vivo ? $"Funtouch / OriginOS {vivo}"
                     : null;
        r.Row("os", "Skin", skin);
        r.Row("os", "Security patch", Build.VERSION.SecurityPatch);
        r.Row("os", "Vendor patch", p.GetValueOrDefault("ro.vendor.build.security_patch"));
        r.Row("os", "Build number", Build.Display);
        r.Row("os", "Built", DateTimeOffset.FromUnixTimeMilliseconds(Build.Time).ToLocalTime().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
        r.Row("os", "Baseband", Build.RadioVersion is { Length: > 0 } radio && radio != "unknown" ? radio : null);
        r.Row("os", "Bootloader", DeviceInfo.Clean(Build.Bootloader));
        r.Row("os", "Fingerprint", Build.Fingerprint);
        if (OperatingSystem.IsAndroidVersionAtLeast(31) && Build.VERSION.MediaPerformanceClass is var pc and > 0)
            r.Row("os", "Performance class", pc switch   // the API level of the Android version the class is named after
            {
                30 => "Android 11", 31 => "Android 12", 33 => "Android 13", 34 => "Android 14", 35 => "Android 15", 36 => "Android 16",
                _ => $"API {pc}",
            });
        r.Row("os", "Uptime", DeviceInfo.Duration(TimeSpan.FromMilliseconds(SystemClock.ElapsedRealtime())));
    }

    private static void Memory(DeviceReport r, Context ctx)
    {
        if (ctx.GetSystemService(Context.ActivityService) is not ActivityManager am) return;
        var mi = new ActivityManager.MemoryInfo();
        am.GetMemoryInfo(mi);
        r.Row("memory", "Total", DeviceInfo.Bytes(mi.TotalMem));
        r.Row("memory", "In use", $"{DeviceInfo.Bytes(mi.TotalMem - mi.AvailMem)} ({DeviceInfo.Percent(mi.TotalMem - mi.AvailMem, mi.TotalMem)}), {DeviceInfo.Bytes(mi.AvailMem)} free");
        r.Row("memory", "Low-memory line", DeviceInfo.Bytes(mi.Threshold) + (mi.LowMemory ? " (memory is low now)" : string.Empty));
        r.Row("memory", "Per-app heap", $"{am.MemoryClass} MB ({am.LargeMemoryClass} MB large)");
        if (am.IsLowRamDevice) r.Row("memory", "Low-RAM device", "Yes");
    }

    // GL_RENDERER etc. from a 1 × 1 pbuffer context on this thread. The display is shared with the UI's renderer, so it
    // is never terminated, only this context and surface are destroyed.
    private static void Gpu(DeviceReport r, Context ctx)
    {
        var display = EGL14.EglGetDisplay(EGL14.EglDefaultDisplay);
        if (display is null || display == EGL14.EglNoDisplay) return;
        var v = new int[2];
        if (!EGL14.EglInitialize(display, v, 0, v, 1)) return;
        int[] attribs = { EGL14.EglRenderableType, EGL14.EglOpenglEs2Bit, EGL14.EglSurfaceType, EGL14.EglPbufferBit, EGL14.EglNone };
        var configs = new global::Android.Opengl.EGLConfig[1];
        var count = new int[1];
        if (!EGL14.EglChooseConfig(display, attribs, 0, configs, 0, 1, count, 0) || count[0] == 0 || configs[0] is null) return;
        var context = EGL14.EglCreateContext(display, configs[0], EGL14.EglNoContext, new[] { EGL14.EglContextClientVersion, 2, EGL14.EglNone }, 0);
        if (context is null || context == EGL14.EglNoContext) return;
        var surface = EGL14.EglCreatePbufferSurface(display, configs[0], new[] { EGL14.EglWidth, 1, EGL14.EglHeight, 1, EGL14.EglNone }, 0);
        try
        {
            if (surface is null || !EGL14.EglMakeCurrent(display, surface, surface, context)) return;
            r.Row("gpu", "Name", GLES20.GlGetString(GLES20.GlRenderer));
            r.Row("gpu", "Maker", GLES20.GlGetString(GLES20.GlVendor));
            r.Row("gpu", "OpenGL ES", GLES20.GlGetString(GLES20.GlVersion));
        }
        finally
        {
            EGL14.EglMakeCurrent(display, EGL14.EglNoSurface, EGL14.EglNoSurface, EGL14.EglNoContext);
            if (surface is not null) EGL14.EglDestroySurface(display, surface);
            EGL14.EglDestroyContext(display, context);
        }
        foreach (var f in ctx.PackageManager?.GetSystemAvailableFeatures() ?? Array.Empty<FeatureInfo>())
        {
            if (f.Name == "android.hardware.vulkan.version" && f.Version > 0)
                r.Row("gpu", "Vulkan", $"{(uint)f.Version >> 22}.{((uint)f.Version >> 12) & 0x3FF}.{f.Version & 0xFFF}");
            if (f.Name == "android.hardware.vulkan.level") r.Row("gpu", "Vulkan hardware level", f.Version.ToString(CultureInfo.InvariantCulture));
        }
    }

    private static void Screen(DeviceReport r, Context ctx)
    {
        if (ctx.GetSystemService(Context.DisplayService) is not DisplayManager dm) return;
        var d = dm.GetDisplay(global::Android.Views.Display.DefaultDisplay);
        if (d is null) return;
        var m = new DisplayMetrics();
#pragma warning disable CA1422   // replaced by WindowMetrics, which needs a visual context: the real metrics of the display are what's wanted
        d.GetRealMetrics(m);
#pragma warning restore CA1422
        int w = Math.Min(m.WidthPixels, m.HeightPixels), h = Math.Max(m.WidthPixels, m.HeightPixels);
        r.Heading("display", d.Name ?? "Built-in screen");
        r.Row("display", "Resolution", $"{w} × {h}");
        if (m.Xdpi > 0 && m.Ydpi > 0)
        {
            double wi = w / m.Xdpi, hi = h / m.Ydpi;
            r.Row("display", "Size", $"{Math.Sqrt(wi * wi + hi * hi):0.0}″ ({wi * 25.4:0} × {hi * 25.4:0} mm)");
            r.Row("display", "Pixel density", $"{(m.Xdpi + m.Ydpi) / 2:0} ppi");
        }
        r.Row("display", "Density", $"{(int)m.DensityDpi} dpi ({m.Density:0.##}×)");
        r.Row("display", "Refresh rate", $"{d.RefreshRate:0} Hz");
        var rates = d.GetSupportedModes()?.Select(mode => (int)Math.Round(mode.RefreshRate)).Distinct().OrderBy(x => x).ToList();
        if (rates is { Count: > 1 }) r.Row("display", "Refresh rates", string.Join(", ", rates) + " Hz");
        if (d.GetHdrCapabilities()?.GetSupportedHdrTypes() is { Length: > 0 } hdr)
            r.Row("display", "HDR", string.Join(", ", hdr.Select(t => (int)t switch { 1 => "Dolby Vision", 2 => "HDR10", 3 => "HLG", 4 => "HDR10+", var n => $"type {n}" })));
        if (OperatingSystem.IsAndroidVersionAtLeast(26)) r.Row("display", "Wide color", d.IsWideColorGamut ? "Yes" : "No");
    }

    private static void Storage(DeviceReport r)
    {
        var data = global::Android.OS.Environment.DataDirectory;
        if (data?.AbsolutePath is not { } path) return;
        var fs = new StatFs(path);
        long total = fs.TotalBytes, free = fs.AvailableBytes;
        r.Heading("storage", "Internal storage");
        r.Row("storage", "Capacity", DeviceInfo.DiskBytes(total));
        r.Row("storage", "Free", $"{DeviceInfo.Bytes(free)} ({DeviceInfo.Percent(total - free, total)} used)");
    }

    private static void Battery(DeviceReport r, Context ctx)
    {
        var status = ctx.RegisterReceiver(null, new IntentFilter(Intent.ActionBatteryChanged));
        if (status is null) return;
        bool charging = status.GetIntExtra(BatteryManager.ExtraStatus, -1) is 2 or 5;
        int level = status.GetIntExtra(BatteryManager.ExtraLevel, -1), scale = status.GetIntExtra(BatteryManager.ExtraScale, 100);
        if (level >= 0 && scale > 0) r.Row("battery", "Charge", $"{level * 100 / scale}%");
        r.Row("battery", "Status", status.GetIntExtra(BatteryManager.ExtraStatus, -1) switch
        {
            2 => "Charging", 3 => "Discharging", 4 => "Not charging", 5 => "Full", _ => null,
        });
        r.Row("battery", "Power", status.GetIntExtra(BatteryManager.ExtraPlugged, 0) switch
        {
            1 => "AC charger", 2 => "USB", 4 => "Wireless", 8 => "Dock", _ => "On battery",
        });
        r.Row("battery", "Health", status.GetIntExtra(BatteryManager.ExtraHealth, -1) switch
        {
            2 => "Good", 3 => "Overheating", 4 => "Dead", 5 => "Over voltage", 6 => "Failure", 7 => "Cold", _ => null,
        });
        r.Row("battery", "Chemistry", status.GetStringExtra(BatteryManager.ExtraTechnology));
        int temp = status.GetIntExtra(BatteryManager.ExtraTemperature, int.MinValue);
        if (temp != int.MinValue) r.Row("battery", "Temperature", $"{temp / 10.0:0.0} °C");
        int mv = status.GetIntExtra(BatteryManager.ExtraVoltage, -1);
        // millivolts by the documentation; a few phones give whole volts
        if (mv > 0) r.Row("battery", "Voltage", mv < 100 ? $"{mv} V" : $"{mv / 1000.0:0.00} V");
        if (OperatingSystem.IsAndroidVersionAtLeast(34))
        {
            int cycles = status.GetIntExtra(BatteryManager.ExtraCycleCount, -1);
            if (cycles > 0) r.Row("battery", "Charge cycles", cycles.ToString(CultureInfo.InvariantCulture));
        }
        if (ctx.GetSystemService(Context.BatteryService) is BatteryManager bm)
        {
            int counter = bm.GetIntProperty((int)BatteryProperty.ChargeCounter);   // µAh left
            int pct = bm.GetIntProperty((int)BatteryProperty.Capacity);
            if (counter > 0 && pct > 0) r.Row("battery", "Estimated capacity", $"{counter / 1000.0 / pct * 100:0} mAh (from the charge left)");
            int ua = bm.GetIntProperty((int)BatteryProperty.CurrentNow);
            if (ua != 0 && ua != int.MinValue && Math.Abs(ua) < 20_000_000)
            {
                // most phones report µA, a few mA: values under 20 000 are taken as mA
                double ma = Math.Abs(ua) > 20_000 ? ua / 1000.0 : ua;
                // the sign isn't the same on every phone: the charging state says which way it flows
                r.Row("battery", charging ? "Charge current" : "Discharge current", $"{Math.Abs(ma):0} mA");
            }
        }
    }

    private static void Cameras(DeviceReport r, Context ctx)
    {
        if (ctx.GetSystemService(Context.CameraService) is not CameraManager cm) return;
        foreach (string id in cm.GetCameraIdList())
        {
            var ch = cm.GetCameraCharacteristics(id);
            int facing = (ch.Get(CameraCharacteristics.LensFacing) as Java.Lang.Integer)?.IntValue() ?? -1;
            var pixels = ch.Get(CameraCharacteristics.SensorInfoPixelArraySize) as Size;
            double mp = pixels is null ? 0 : pixels.Width * (double)pixels.Height / 1e6;
            string side = facing switch { 0 => "Front", 1 => "Back", 2 => "External", _ => "Camera" };
            r.Heading("camera", $"{side} camera {id}{(mp > 0 ? $" — {mp:0.#} MP" : "")}");
            if (pixels is not null) r.Row("camera", "Sensor", $"{pixels.Width} × {pixels.Height}");
            float[]? apertures = Floats(ch.Get(CameraCharacteristics.LensInfoAvailableApertures));
            if (apertures is { Length: > 0 }) r.Row("camera", "Aperture", string.Join(", ", apertures.Select(a => $"f/{a:0.0#}")));
            float[]? focal = Floats(ch.Get(CameraCharacteristics.LensInfoAvailableFocalLengths));
            var size = ch.Get(CameraCharacteristics.SensorInfoPhysicalSize) as SizeF;
            if (focal is { Length: > 0 })
            {
                string eq = string.Empty;
                if (size is { Width: > 0, Height: > 0 })
                {
                    double diag = Math.Sqrt(size.Width * size.Width + size.Height * size.Height);
                    eq = $" ({focal[0] * 43.27 / diag:0} mm equivalent)";
                }
                r.Row("camera", "Focal length", string.Join(", ", focal.Select(f => $"{f:0.##} mm")) + eq);
            }
            if (size is { Width: > 0 }) r.Row("camera", "Sensor size", $"{size.Width:0.##} × {size.Height:0.##} mm");
            int[]? ois = Ints(ch.Get(CameraCharacteristics.LensInfoAvailableOpticalStabilization));
            r.Row("camera", "Optical stabilization", ois is null ? null : ois.Contains(1) ? "Yes" : "No");
            r.Row("camera", "Flash", (ch.Get(CameraCharacteristics.FlashInfoAvailable) as Java.Lang.Boolean)?.BooleanValue() switch { true => "Yes", false => "No", _ => null });
            r.Row("camera", "API level", (ch.Get(CameraCharacteristics.InfoSupportedHardwareLevel) as Java.Lang.Integer)?.IntValue() switch
            {
                0 => "Limited", 1 => "Full", 2 => "Legacy", 3 => "Level 3", 4 => "External", _ => null,
            });
            if (OperatingSystem.IsAndroidVersionAtLeast(28) && ch.PhysicalCameraIds is { Count: > 1 } physical)
                r.Row("camera", "Made of cameras", string.Join(", ", physical));
        }
    }

    private static void Sensors(DeviceReport r, Context ctx)
    {
        if (ctx.GetSystemService(Context.SensorService) is not SensorManager sm) return;
        var list = sm.GetSensorList(SensorType.All);
        if (list is null || list.Count == 0) return;
        r.Heading("sensor", $"{list.Count} sensors");
        foreach (var s in list.OrderBy(s => s.StringType))
        {
            string type = (s.StringType ?? s.Type.ToString()).Replace("android.sensor.", string.Empty).Replace('_', ' ');
            string label = type.Length > 0 ? char.ToUpperInvariant(type[0]) + type[1..] : "Sensor";
            r.Row("sensor", $"{label}{(s.IsWakeUpSensor ? " (wake-up)" : "")} · {s.Name}",
                  $"{s.Vendor} · range {s.MaximumRange:0.###} · {s.Power:0.###} mA");
        }
    }

    private static void Features(DeviceReport r, Context ctx)
    {
        var pm = ctx.PackageManager;
        if (pm is null) return;
        var have = new List<string>();
        foreach (var (feature, label) in new[]
        {
            ("android.hardware.telephony", "Mobile network"), ("android.hardware.telephony.euicc", "eSIM"), ("android.hardware.nfc", "NFC"),
            ("android.hardware.bluetooth_le", "Bluetooth LE"), ("android.hardware.wifi.direct", "Wi-Fi Direct"),
            ("android.hardware.wifi.aware", "Wi-Fi Aware"), ("android.hardware.wifi.rtt", "Wi-Fi RTT"), ("android.hardware.uwb", "UWB"),
            ("android.hardware.usb.host", "USB host (OTG)"), ("android.hardware.fingerprint", "Fingerprint"),
            ("android.hardware.biometrics.face", "Face unlock"), ("android.hardware.consumerir", "IR blaster"),
            ("android.hardware.location.gps", "GPS"), ("android.hardware.audio.low_latency", "Low-latency audio"),
            ("android.hardware.audio.pro", "Pro audio"), ("android.hardware.camera.flash", "Camera flash"),
            ("android.hardware.touchscreen.multitouch.jazzhand", "5+ finger touch"), ("android.software.vulkan.deqp.level", "Vulkan conformance"),
            ("android.hardware.strongbox_keystore", "StrongBox keystore"), ("android.hardware.ram.normal", "Normal-RAM device"),
        })
            if (pm.HasSystemFeature(feature)) have.Add(label);
        if (have.Count > 0) r.Row("feature", "Has", string.Join(", ", have));
    }

    // ---------------------------------------------------------------- helpers

    // `getprop` (allowed to apps): the build properties Build doesn't expose (marketing name, the maker's own Android skin).
    private static Dictionary<string, string> SystemProperties()
    {
        var d = new Dictionary<string, string>(StringComparer.Ordinal);
        var proc = Java.Lang.Runtime.GetRuntime()?.Exec(new[] { "/system/bin/getprop" });
        if (proc?.InputStream is null) return d;
        try
        {
            using var reader = new StreamReader(proc.InputStream);
            string? line;
            while ((line = reader.ReadLine()) is not null)
            {
                // [ro.product.model]: [RMX3941]
                int split = line.IndexOf("]: [", StringComparison.Ordinal);
                if (line.StartsWith('[') && split > 1 && line.EndsWith(']'))
                    d[line[1..split]] = line[(split + 4)..^1];
            }
        }
        finally { proc.Destroy(); }
        return d;
    }

    private static float[]? Floats(Java.Lang.Object? o) => o is null ? null : JNIEnv.GetArray<float>(o.Handle);

    private static int[]? Ints(Java.Lang.Object? o) => o is null ? null : JNIEnv.GetArray<int>(o.Handle);

    private static string Capital(string s) => s.Length > 0 ? char.ToUpperInvariant(s[0]) + s[1..] : s;
}
