using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace Echoes.Helpers;

/// <summary>
/// Wi-Fi on desktop Linux through NetworkManager's CLI: <c>nmcli -t -e yes -f … device wifi list</c> (terse, escaped
/// output: fields split on unescaped ':' with '\:' and '\\' inside values), plus the connected link's level in dBm from
/// /proc/net/wireless. Newer nmcli versions also report the channel width (BANDWIDTH); an older one that refuses the
/// field is asked again without it. Without nmcli (or with NetworkManager not running) the view shows one note.
/// </summary>
public static class WifiLinux
{
    public static readonly string[] FieldsFull = { "IN-USE", "BSSID", "SSID", "CHAN", "FREQ", "RATE", "SIGNAL", "SECURITY", "BANDWIDTH", "DEVICE" };
    public static readonly string[] FieldsBasic = { "IN-USE", "BSSID", "SSID", "CHAN", "FREQ", "RATE", "SIGNAL", "SECURITY", "DEVICE" };

    private const int MaxOutput = 2 * 1024 * 1024;

    [System.Runtime.Versioning.SupportedOSPlatform("linux")]
    public static WifiScanResult Read(bool requestScan)
    {
        string? nmcli = ExecutablePath.Find("nmcli");
        if (nmcli is null)
            return WifiScanResult.Unsupported("The Wi-Fi analyzer needs NetworkManager's nmcli, which isn't installed on this system.");

        string[] fields = FieldsFull;
        var (code, output, error) = List(nmcli, fields, requestScan ? "yes" : "auto");
        if (code != 0 && error.Contains("BANDWIDTH", StringComparison.OrdinalIgnoreCase))
        {
            fields = FieldsBasic;
            (code, output, error) = List(nmcli, fields, requestScan ? "yes" : "auto");
        }
        if (code != 0 && requestScan)   // a rescan may be refused (permissions, busy radio): the cached list then
            (code, output, error) = List(nmcli, fields, "auto");
        if (code != 0)
        {
            string why = FirstLine(error);
            if (why.Contains("not running", StringComparison.OrdinalIgnoreCase))
                return WifiScanResult.Unsupported("NetworkManager isn't running, so nmcli can't list Wi-Fi networks.");
            return WifiScanResult.Unsupported("nmcli couldn't list Wi-Fi networks" + (why.Length > 0 ? $": {why}" : "."));
        }

        var networks = ParseList(output, fields);
        var result = new WifiScanResult { Supported = true, Networks = networks };
        var inUse = networks.FirstOrDefault(n => n.IsConnected);
        string device = inUse is null ? "" : DeviceOf(output, fields, inUse.Bssid);
        if (inUse is not null)
        {
            int dbm = 0;
            try { if (File.Exists("/proc/net/wireless")) dbm = ParseProcWireless(File.ReadAllText("/proc/net/wireless"), device); }
            catch { }
            result.Current = Connection(inUse, device, dbm, RateOf(output, fields, inUse.Bssid));
        }
        if (networks.Count == 0)
        {
            var (dc, devices, _) = Run(nmcli, new[] { "-t", "-e", "yes", "-f", "DEVICE,TYPE", "device" });
            if (dc == 0 && !devices.Split('\n').Any(l => SplitTerse(l.TrimEnd('\r')).ElementAtOrDefault(1) == "wifi"))
                result.Note = "No Wi-Fi adapter found on this system.";
        }
        return result;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("linux")]
    private static (int Code, string Output, string Error) List(string nmcli, string[] fields, string rescan)
        => Run(nmcli, new[] { "-t", "-e", "yes", "-f", string.Join(',', fields), "device", "wifi", "list", "--rescan", rescan });

    [System.Runtime.Versioning.SupportedOSPlatform("linux")]
    private static (int Code, string Output, string Error) Run(string exe, string[] args)
    {
        try
        {
            var psi = new ProcessStartInfo(exe)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                CreateNoWindow = true,
            };
            foreach (var a in args) psi.ArgumentList.Add(a);
            psi.Environment["LC_ALL"] = "C";   // units and messages in English, whatever the desktop's locale
            using var p = Process.Start(psi);
            if (p is null) return (-1, "", "nmcli didn't start");
            // Both pipes are read in the background, so the deadline holds even while the tool keeps its output open (a
            // scan that hangs used to block the read — and every later refresh — until nmcli gave up on its own); past
            // the cap the rest is read and dropped, so a tool that writes more can still finish.
            var output = ReadCappedAsync(p.StandardOutput, MaxOutput);
            var err = ReadCappedAsync(p.StandardError, 64 * 1024);
            if (!p.WaitForExit((int)RunTimeout.TotalMilliseconds))
            {
                try { p.Kill(true); } catch { }
                return (-1, "", "nmcli didn't answer in time");
            }
            Task.WaitAll(new Task[] { output, err }, 2000);   // the pipes close with the process
            return (p.ExitCode, output.IsCompletedSuccessfully ? output.Result : "", err.IsCompletedSuccessfully ? err.Result : "");
        }
        catch (Exception ex)
        {
            return (-1, "", ex.Message);
        }
    }

    /// <summary>How long one nmcli run may take (a rescan usually finishes in a few seconds). Settable for the harness.</summary>
    internal static TimeSpan RunTimeout { get; set; } = TimeSpan.FromSeconds(20);

    private static async Task<string> ReadCappedAsync(StreamReader reader, int max)
    {
        var sb = new StringBuilder();
        var buf = new char[8192];
        int n;
        while ((n = await reader.ReadAsync(buf, 0, buf.Length).ConfigureAwait(false)) > 0)
            if (sb.Length < max) sb.Append(buf, 0, Math.Min(n, max - sb.Length));
        return sb.ToString();
    }

    private static string FirstLine(string s)
    {
        s = s.Trim();
        int nl = s.IndexOf('\n');
        if (nl >= 0) s = s[..nl].Trim();
        if (s.StartsWith("Error:", StringComparison.OrdinalIgnoreCase)) s = s[6..].Trim();
        return s.Length > 160 ? s[..160] + "…" : s;
    }

    /// <summary>One terse line split on unescaped ':' (with -e yes, nmcli writes ':' as '\:' and '\' as '\\').</summary>
    public static List<string> SplitTerse(string line)
    {
        var parts = new List<string>();
        var sb = new StringBuilder();
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (c == '\\' && i + 1 < line.Length)
            {
                sb.Append(line[++i]);
                continue;
            }
            if (c == ':')
            {
                parts.Add(sb.ToString());
                sb.Clear();
                continue;
            }
            sb.Append(c);
        }
        parts.Add(sb.ToString());
        return parts;
    }

    private static int Index(IReadOnlyList<string> fields, string name)
    {
        for (int i = 0; i < fields.Count; i++) if (fields[i] == name) return i;
        return -1;
    }

    private static string Field(List<string> cols, IReadOnlyList<string> fields, string name)
    {
        int i = Index(fields, name);
        return i >= 0 && i < cols.Count ? cols[i].Trim() : "";
    }

    private static int LeadingInt(string s)
    {
        int i = 0;
        while (i < s.Length && char.IsAsciiDigit(s[i])) i++;
        return i > 0 && int.TryParse(s.AsSpan(0, Math.Min(i, 9)), NumberStyles.None, CultureInfo.InvariantCulture, out int v) ? v : 0;
    }

    /// <summary>Every access point of an <c>nmcli -t -e yes -f &lt;fields&gt; device wifi list</c> output.</summary>
    public static List<WifiNetwork> ParseList(string output, IReadOnlyList<string> fields)
    {
        var list = new List<WifiNetwork>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in output.Split('\n'))
        {
            string line = raw.TrimEnd('\r');
            if (line.Length == 0) continue;
            var cols = SplitTerse(line);
            if (cols.Count < fields.Count) continue;   // a line we don't understand
            string bssid = Field(cols, fields, "BSSID").ToUpperInvariant();
            if (bssid.Length == 0 || !seen.Add(bssid + "|" + Field(cols, fields, "DEVICE"))) continue;
            string ssid = Clean(Field(cols, fields, "SSID"));
            if (ssid == "--") ssid = "";
            int freq = LeadingInt(Field(cols, fields, "FREQ"));
            int chan = LeadingInt(Field(cols, fields, "CHAN"));
            var band = WifiChannels.BandOf(freq);
            if (band == WifiBand.Unknown) band = WifiChannels.GuessBand(chan);
            if (freq > 0 && WifiChannels.ChannelOf(freq) > 0) chan = WifiChannels.ChannelOf(freq);
            int width = LeadingInt(Field(cols, fields, "BANDWIDTH"));
            list.Add(new WifiNetwork
            {
                Ssid = ssid,
                Bssid = bssid,
                Channel = chan,
                FrequencyMhz = freq,
                Band = band,
                WidthMhz = width,
                CenterChannel = width > 20 ? WifiChannels.StandardCenter(chan, width, band) : chan,
                SignalPercent = Math.Clamp(LeadingInt(Field(cols, fields, "SIGNAL")), 0, 100),
                Security = SecurityLabel(Field(cols, fields, "SECURITY")),
                IsConnected = Field(cols, fields, "IN-USE") == "*",
            });
        }
        return list;
    }

    private static string DeviceOf(string output, IReadOnlyList<string> fields, string bssid)
        => RowFor(output, fields, bssid) is { } cols ? Field(cols, fields, "DEVICE") : "";

    private static double RateOf(string output, IReadOnlyList<string> fields, string bssid)
    {
        if (RowFor(output, fields, bssid) is not { } cols) return double.NaN;
        int r = LeadingInt(Field(cols, fields, "RATE"));
        return r > 0 ? r : double.NaN;
    }

    private static List<string>? RowFor(string output, IReadOnlyList<string> fields, string bssid)
    {
        foreach (var raw in output.Split('\n'))
        {
            var cols = SplitTerse(raw.TrimEnd('\r'));
            if (cols.Count >= fields.Count && string.Equals(Field(cols, fields, "BSSID"), bssid, StringComparison.OrdinalIgnoreCase)
                && Field(cols, fields, "IN-USE") == "*")
                return cols;
        }
        return null;
    }

    /// <summary>nmcli's SECURITY ("WPA2 WPA3", "WPA1 WPA2 802.1X", "OWE", "" …) as the label the view uses.</summary>
    public static string SecurityLabel(string nm)
    {
        var t = nm.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries).Select(s => s.ToUpperInvariant()).ToHashSet();
        if (t.Count == 0 || (t.Count == 1 && t.Contains("--"))) return "Open";
        bool ent = t.Contains("802.1X");
        bool w1 = t.Contains("WPA1") || t.Contains("WPA"), w2 = t.Contains("WPA2"), w3 = t.Contains("WPA3");
        if (t.Contains("OWE") && !w2 && !w3) return "OWE";
        if (ent) return w3 && !w2 ? "WPA3-Enterprise" : w2 || w3 ? "WPA2-Enterprise" : "WPA-Enterprise";
        if (w2 && w3) return "WPA2/WPA3-Personal";
        if (w3) return "WPA3-Personal";
        if (w1 && w2) return "WPA/WPA2-Personal";
        if (w2) return "WPA2-Personal";
        if (w1) return "WPA-Personal";
        if (t.Contains("WEP")) return "WEP";
        return string.Join(' ', t);
    }

    /// <summary>The link level (dBm) of <paramref name="device"/> in /proc/net/wireless ("wlp2s0: 0000   54.  -56.  -256 …");
    /// 0 when it isn't listed.</summary>
    public static int ParseProcWireless(string content, string device)
    {
        if (device.Length == 0) return 0;
        foreach (var raw in content.Split('\n'))
        {
            string line = raw.Trim();
            int colon = line.IndexOf(':');
            if (colon <= 0 || line[..colon].Trim() != device) continue;
            var cols = line[(colon + 1)..].Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            // status, link quality, level, noise …
            if (cols.Length < 3) return 0;
            string level = cols[2].TrimEnd('.');
            if (double.TryParse(level, NumberStyles.Float, CultureInfo.InvariantCulture, out double v))
            {
                if (v > 0 && v <= 255) v -= 256;   // some drivers report the unsigned 8-bit form
                return v is < 0 and > -128 ? (int)Math.Round(v) : 0;
            }
            return 0;
        }
        return 0;
    }

    private static WifiConnection Connection(WifiNetwork ap, string device, int dbm, double rateMbps) => new()
    {
        Ssid = ap.Ssid,
        Bssid = ap.Bssid,
        Channel = ap.Channel,
        FrequencyMhz = ap.FrequencyMhz,
        Band = ap.Band,
        WidthMhz = ap.WidthMhz,
        SignalPercent = ap.SignalPercent,
        // NetworkManager's percentage is linear between −100 and −40 dBm: the inverse when the kernel has no level
        RssiDbm = dbm != 0 ? dbm : (int)Math.Round(-100 + ap.SignalPercent * 0.6),
        RssiEstimated = dbm == 0,
        RxMbps = rateMbps,
        Security = ap.Security,
        Adapter = device,
    };

    private static string Clean(string s)
    {
        var sb = new StringBuilder(Math.Min(s.Length, 64));
        foreach (char c in s)
        {
            if (sb.Length >= 64) break;
            sb.Append(char.IsControl(c) || c is >= (char)0x202A and <= (char)0x202E || c is >= (char)0x2066 and <= (char)0x2069 ? '?' : c);
        }
        return sb.ToString();
    }
}

/// <summary>The Wi-Fi analyzer's one entry point: the platform's reader, or a "not available" note.</summary>
public static class WifiScanner
{
    /// <summary>Whether this platform has a reader at all (elsewhere Read only ever says "not available").</summary>
    public static bool IsAvailable => OperatingSystem.IsWindows() || (OperatingSystem.IsLinux() && !OperatingSystem.IsAndroid());

    /// <summary>Reads the connection and the networks around. <paramref name="requestScan"/> also asks the radio for a
    /// fresh scan (Windows: results land a few seconds later, so the caller reads again). Never throws; blocking — call
    /// it off the UI thread.</summary>
    public static WifiScanResult Read(bool requestScan)
    {
        try
        {
            if (OperatingSystem.IsWindows()) return WifiWindows.Read(requestScan);
            if (OperatingSystem.IsLinux() && !OperatingSystem.IsAndroid()) return WifiLinux.Read(requestScan);
        }
        catch (Exception ex)
        {
            return WifiScanResult.Unsupported($"Couldn't read the Wi-Fi state: {ex.Message.TrimEnd('.')}.");
        }
        return WifiScanResult.Unsupported("The Wi-Fi analyzer isn't available on this platform.");
    }
}
