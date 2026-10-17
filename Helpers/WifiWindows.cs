using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Echoes.Helpers;

/// <summary>
/// Wi-Fi through the Native Wifi API (wlanapi.dll): the adapters, the current connection (WlanQueryInterface), the
/// access points of the last scan with their information elements (WlanGetNetworkBssList) and Windows' own security
/// classification per network (WlanGetAvailableNetworkList). Read-only: it never connects, disconnects or changes a
/// profile. Plain blittable DllImports with manual offsets (AOT- and trim-safe); every buffer the API hands out is
/// freed with WlanFreeMemory in a finally.
///
/// <para>Windows 11 24H2+ gates the SSID / BSSID data behind location privacy: without "Let desktop apps access your
/// location" these calls answer ERROR_ACCESS_DENIED (or an empty list). That becomes the one note the view shows,
/// with whatever the API still reports (the connection's channel and signal).</para>
/// </summary>
[SupportedOSPlatform("windows")]
internal static class WifiWindows
{
    private const uint ErrorAccessDenied = 5;
    private const uint ErrorServiceNotActive = 1062;
    private const uint ErrorInvalidState = 5023;
    private const uint ErrorDot11PowerStateInvalid = 0x80342002;

    private const int OpRadioState = 4, OpCurrentConnection = 7, OpChannelNumber = 8, OpRssi = 0x10000102;
    private const int BssTypeAny = 3;

    // struct sizes / offsets (wlanapi.h, x64 and x86 alike)
    private const int IfaceInfoSize = 532;      // GUID(16) + WCHAR[256] + state(4)
    private const int BssEntrySize = 360;
    private const int AvailSize = 628;
    private const int MaxIeBytes = 16 * 1024;

    [DllImport("wlanapi.dll")]
    private static extern uint WlanOpenHandle(uint clientVersion, IntPtr reserved, out uint negotiatedVersion, out IntPtr handle);

    [DllImport("wlanapi.dll")]
    private static extern uint WlanCloseHandle(IntPtr handle, IntPtr reserved);

    [DllImport("wlanapi.dll")]
    private static extern uint WlanEnumInterfaces(IntPtr handle, IntPtr reserved, out IntPtr interfaceList);

    [DllImport("wlanapi.dll")]
    private static extern void WlanFreeMemory(IntPtr memory);

    [DllImport("wlanapi.dll")]
    private static extern uint WlanScan(IntPtr handle, ref Guid interfaceGuid, IntPtr ssid, IntPtr ieData, IntPtr reserved);

    [DllImport("wlanapi.dll")]
    private static extern uint WlanGetNetworkBssList(IntPtr handle, ref Guid interfaceGuid, IntPtr ssid, int bssType,
                                                     int securityEnabled, IntPtr reserved, out IntPtr bssList);

    [DllImport("wlanapi.dll")]
    private static extern uint WlanGetAvailableNetworkList(IntPtr handle, ref Guid interfaceGuid, uint flags, IntPtr reserved,
                                                           out IntPtr networkList);

    [DllImport("wlanapi.dll")]
    private static extern uint WlanQueryInterface(IntPtr handle, ref Guid interfaceGuid, int opCode, IntPtr reserved,
                                                  out uint dataSize, out IntPtr data, IntPtr opcodeValueType);

    private sealed record Iface(Guid Guid, string Description, int State);

    public const string LocationNote =
        "Windows shows nearby Wi-Fi networks only to apps allowed to use your location. Turn on Settings → Privacy & security → " +
        "Location → Let desktop apps access your location, then refresh.";

    public static WifiScanResult Read(bool requestScan)
    {
        IntPtr h;
        uint rc;
        try { rc = WlanOpenHandle(2, IntPtr.Zero, out _, out h); }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return WifiScanResult.Unsupported("Wi-Fi isn't available on this PC: the wireless LAN service isn't installed.");
        }
        if (rc == ErrorServiceNotActive)
            return WifiScanResult.Unsupported("The WLAN AutoConfig service isn't running, so Windows can't list Wi-Fi networks. Start it (Services → WLAN AutoConfig), then refresh.");
        if (rc != 0)
            return WifiScanResult.Unsupported($"Windows couldn't open its Wi-Fi service (error {rc}).");

        try
        {
            var ifaces = EnumInterfaces(h);
            if (ifaces.Count == 0)
                return new WifiScanResult { Supported = true, Note = "No Wi-Fi adapter found on this PC." };
            var iface = ifaces.FirstOrDefault(i => i.State == 1) ?? ifaces[0];   // a connected adapter first
            var guid = iface.Guid;

            if (RadioOff(h, guid))
                return new WifiScanResult { Supported = true, Note = "Wi-Fi is turned off on this PC. Turn it on to see networks.", Current = null };

            bool denied = false;
            if (requestScan)
            {
                uint s = WlanScan(h, ref guid, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                if (s == ErrorAccessDenied) denied = true;
                else if (s == ErrorDot11PowerStateInvalid)
                    return new WifiScanResult { Supported = true, Note = "Wi-Fi is turned off on this PC. Turn it on to see networks." };
            }

            var security = AvailableSecurity(h, guid, ref denied);
            var networks = BssList(h, guid, security, ref denied);
            var current = iface.State == 1 ? Connection(h, guid, iface, networks, ref denied) : null;

            if (current is not null && !current.SsidHidden)
            {
                // mark the connected access point (and fill its row's security from the connection when the IEs had none)
                for (int i = 0; i < networks.Count; i++)
                {
                    var n = networks[i];
                    if (string.Equals(n.Bssid, current.Bssid, StringComparison.OrdinalIgnoreCase))
                        networks[i] = Copy(n, connected: true);
                }
            }

            var result = new WifiScanResult { Supported = true, Current = current, Networks = networks };
            // the location gate: refused outright, or nothing at all while plainly connected
            if (denied || (networks.Count == 0 && iface.State == 1))
            {
                result.Note = LocationNote;
                result.NoteIsLocation = true;
            }
            return result;
        }
        finally
        {
            WlanCloseHandle(h, IntPtr.Zero);
        }
    }

    private static WifiNetwork Copy(WifiNetwork n, bool connected) => new()
    {
        Ssid = n.Ssid, Bssid = n.Bssid, Channel = n.Channel, FrequencyMhz = n.FrequencyMhz, Band = n.Band,
        WidthMhz = n.WidthMhz, CenterChannel = n.CenterChannel, SignalPercent = n.SignalPercent, RssiDbm = n.RssiDbm,
        Security = n.Security, IsConnected = connected,
    };

    private static List<Iface> EnumInterfaces(IntPtr h)
    {
        var list = new List<Iface>();
        if (WlanEnumInterfaces(h, IntPtr.Zero, out IntPtr p) != 0 || p == IntPtr.Zero) return list;
        try
        {
            int count = Marshal.ReadInt32(p, 0);
            for (int i = 0; i < count && i < 64; i++)
            {
                IntPtr e = p + 8 + i * IfaceInfoSize;
                var g = ReadGuid(e);
                string desc = Marshal.PtrToStringUni(e + 16, 256).TrimEnd('\0');
                int nul = desc.IndexOf('\0');
                if (nul >= 0) desc = desc[..nul];
                list.Add(new Iface(g, desc, Marshal.ReadInt32(e, 528)));
            }
        }
        finally { WlanFreeMemory(p); }
        return list;
    }

    private static Guid ReadGuid(IntPtr p)
    {
        var b = new byte[16];
        Marshal.Copy(p, b, 0, 16);
        return new Guid(b);
    }

    // WLAN_RADIO_STATE: dwNumberOfPhys, then per PHY { index, software state, hardware state } (1 on, 2 off)
    private static bool RadioOff(IntPtr h, Guid guid)
    {
        if (WlanQueryInterface(h, ref guid, OpRadioState, IntPtr.Zero, out uint size, out IntPtr data, IntPtr.Zero) != 0 || data == IntPtr.Zero)
            return false;
        try
        {
            if (size < 4) return false;
            int phys = Marshal.ReadInt32(data, 0);
            if (phys <= 0) return false;
            for (int i = 0; i < phys && i < 64 && 4 + (i + 1) * 12 <= size; i++)
            {
                int sw = Marshal.ReadInt32(data, 4 + i * 12 + 4), hw = Marshal.ReadInt32(data, 4 + i * 12 + 8);
                if (sw == 1 && hw == 1) return false;   // one radio on is enough
            }
            return true;
        }
        finally { WlanFreeMemory(data); }
    }

    private static int QueryInt(IntPtr h, Guid guid, int op, out bool ok)
    {
        ok = false;
        if (WlanQueryInterface(h, ref guid, op, IntPtr.Zero, out uint size, out IntPtr data, IntPtr.Zero) != 0 || data == IntPtr.Zero)
            return 0;
        try
        {
            if (size < 4) return 0;
            ok = true;
            return Marshal.ReadInt32(data, 0);
        }
        finally { WlanFreeMemory(data); }
    }

    private static WifiConnection Connection(IntPtr h, Guid guid, Iface iface, List<WifiNetwork> networks, ref bool denied)
    {
        int rssi = QueryInt(h, guid, OpRssi, out bool rssiOk);
        int channel = QueryInt(h, guid, OpChannelNumber, out _);
        string adapter = AdapterLabel(guid, iface.Description);

        uint rc = WlanQueryInterface(h, ref guid, OpCurrentConnection, IntPtr.Zero, out uint size, out IntPtr data, IntPtr.Zero);
        if (rc != 0 || data == IntPtr.Zero)
        {
            if (rc == ErrorAccessDenied) denied = true;
            var band = WifiChannels.GuessBand(channel);
            return new WifiConnection
            {
                SsidHidden = rc == ErrorAccessDenied,
                Channel = channel,
                Band = band,
                FrequencyMhz = channel > 0 ? WifiChannels.FrequencyOf(channel, band) : 0,
                RssiDbm = rssiOk && rssi < 0 ? rssi : 0,
                SignalPercent = rssiOk && rssi < 0 ? PercentFromRssi(rssi) : -1,
                Adapter = adapter,
            };
        }
        try
        {
            if (size < 604) return new WifiConnection { Adapter = adapter, Channel = channel };
            int ssidLen = Math.Clamp(Marshal.ReadInt32(data, 520), 0, 32);
            var ssidBytes = new byte[ssidLen];
            if (ssidLen > 0) Marshal.Copy(data + 524, ssidBytes, 0, ssidLen);
            var mac = new byte[6];
            Marshal.Copy(data + 560, mac, 0, 6);
            int phy = Marshal.ReadInt32(data, 568);
            int quality = Marshal.ReadInt32(data, 576);
            uint rx = (uint)Marshal.ReadInt32(data, 580), tx = (uint)Marshal.ReadInt32(data, 584);
            int auth = Marshal.ReadInt32(data, 596), cipher = Marshal.ReadInt32(data, 600);
            bool secured = Marshal.ReadInt32(data, 588) != 0;

            string bssid = WifiIe.FormatBssid(mac);
            var ap = networks.FirstOrDefault(n => string.Equals(n.Bssid, bssid, StringComparison.OrdinalIgnoreCase));
            int ch = channel > 0 ? channel : ap?.Channel ?? 0;
            var band = ap?.Band is { } b and not WifiBand.Unknown ? b : WifiChannels.GuessBand(ch);
            // a 6 GHz channel number collides with 2.4 / 5 GHz ones: trust the access point's own frequency when seen
            if (ap is not null && ap.Channel == ch) band = ap.Band;
            bool allZero = bssid == "00:00:00:00:00:00";
            return new WifiConnection
            {
                Ssid = WifiIe.DecodeSsid(ssidBytes),
                SsidHidden = ssidLen == 0 && allZero,
                Bssid = allZero ? "" : bssid,
                Channel = ch,
                Band = band,
                FrequencyMhz = ap?.FrequencyMhz ?? (ch > 0 ? WifiChannels.FrequencyOf(ch, band) : 0),
                WidthMhz = ap?.WidthMhz ?? 0,
                SignalPercent = Math.Clamp(quality, 0, 100),
                RssiDbm = rssiOk && rssi < 0 ? rssi : ap?.RssiDbm ?? 0,
                RxMbps = rx > 0 ? rx / 1000.0 : double.NaN,
                TxMbps = tx > 0 ? tx / 1000.0 : double.NaN,
                Security = AuthLabel(auth, cipher, secured),
                Standard = PhyLabel(phy, band),
                Adapter = adapter,
            };
        }
        finally { WlanFreeMemory(data); }
    }

    /// <summary>"Wi-Fi · Intel(R) Wi-Fi 6 AX201": the connection name Windows shows plus the adapter model.</summary>
    private static string AdapterLabel(Guid guid, string description)
    {
        try
        {
            string id = guid.ToString("B");
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                if (string.Equals(ni.Id, id, StringComparison.OrdinalIgnoreCase))
                    return string.IsNullOrEmpty(description) ? ni.Name : $"{ni.Name} · {description}";
        }
        catch { }
        return description;
    }

    // Windows' signal quality is linear between −100 dBm (0 %) and −50 dBm (100 %).
    internal static int PercentFromRssi(int dbm) => Math.Clamp((dbm + 100) * 2, 0, 100);

    private static Dictionary<string, string> AvailableSecurity(IntPtr h, Guid guid, ref bool denied)
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        uint rc = WlanGetAvailableNetworkList(h, ref guid, 0, IntPtr.Zero, out IntPtr p);
        if (rc == ErrorAccessDenied) { denied = true; return map; }
        if (rc != 0 || p == IntPtr.Zero) return map;
        try
        {
            int count = Marshal.ReadInt32(p, 0);
            for (int i = 0; i < count && i < 4096; i++)
            {
                IntPtr e = p + 8 + i * AvailSize;
                int len = Math.Clamp(Marshal.ReadInt32(e, 512), 0, 32);
                var raw = new byte[len];
                if (len > 0) Marshal.Copy(e + 516, raw, 0, len);
                string ssid = WifiIe.DecodeSsid(raw);
                if (ssid.Length == 0 || map.ContainsKey(ssid)) continue;
                bool secured = Marshal.ReadInt32(e, 608) != 0;
                map[ssid] = AuthLabel(Marshal.ReadInt32(e, 612), Marshal.ReadInt32(e, 616), secured);
            }
        }
        finally { WlanFreeMemory(p); }
        return map;
    }

    private static List<WifiNetwork> BssList(IntPtr h, Guid guid, Dictionary<string, string> security, ref bool denied)
    {
        var list = new List<WifiNetwork>();
        uint rc = WlanGetNetworkBssList(h, ref guid, IntPtr.Zero, BssTypeAny, 0, IntPtr.Zero, out IntPtr p);
        if (rc == ErrorAccessDenied) { denied = true; return list; }
        if (rc == ErrorInvalidState || rc != 0 || p == IntPtr.Zero) return list;
        try
        {
            uint total = (uint)Marshal.ReadInt32(p, 0);
            int count = Marshal.ReadInt32(p, 4);
            if (count < 0 || 8L + (long)count * BssEntrySize > total) return list;   // not the layout we expect: show nothing rather than garbage
            var ieBuf = new byte[MaxIeBytes];
            for (int i = 0; i < count && i < 4096; i++)
            {
                long entryOff = 8L + (long)i * BssEntrySize;
                IntPtr e = p + (int)entryOff;
                int ssidLen = Math.Clamp(Marshal.ReadInt32(e, 0), 0, 32);
                var ssidRaw = new byte[ssidLen];
                if (ssidLen > 0) Marshal.Copy(e + 4, ssidRaw, 0, ssidLen);
                var mac = new byte[6];
                Marshal.Copy(e + 40, mac, 0, 6);
                int rssi = Marshal.ReadInt32(e, 56);
                int quality = Marshal.ReadInt32(e, 60);
                int capability = (ushort)Marshal.ReadInt16(e, 88);
                int freqKhz = Marshal.ReadInt32(e, 92);
                uint ieOffset = (uint)Marshal.ReadInt32(e, 352), ieSize = (uint)Marshal.ReadInt32(e, 356);

                int mhz = freqKhz / 1000;
                var band = WifiChannels.BandOf(mhz);
                ReadOnlySpan<byte> ies = default;
                if (ieSize > 0 && ieSize <= MaxIeBytes && entryOff + ieOffset + ieSize <= total)
                {
                    Marshal.Copy(e + (int)ieOffset, ieBuf, 0, (int)ieSize);
                    ies = ieBuf.AsSpan(0, (int)ieSize);
                }
                var info = WifiIe.Parse(ies, privacy: (capability & 0x0010) != 0, band);
                string ssid = WifiIe.DecodeSsid(ssidRaw);
                if (ssid.Length == 0 && !string.IsNullOrEmpty(info.Ssid)) ssid = info.Ssid!;
                int channel = WifiChannels.ChannelOf(mhz);
                if (channel <= 0) channel = info.PrimaryChannel;
                if (band == WifiBand.Unknown) band = WifiChannels.GuessBand(channel);
                string sec = ies.IsEmpty && ssid.Length > 0 && security.TryGetValue(ssid, out var s) ? s : info.Security;
                list.Add(new WifiNetwork
                {
                    Ssid = ssid,
                    Bssid = WifiIe.FormatBssid(mac),
                    Channel = channel,
                    FrequencyMhz = mhz,
                    Band = band,
                    WidthMhz = info.WidthMhz,
                    CenterChannel = info.CenterChannel,
                    SignalPercent = Math.Clamp(quality, 0, 100),
                    RssiDbm = rssi is < 0 and > -128 ? rssi : 0,
                    Security = sec,
                });
            }
        }
        finally { WlanFreeMemory(p); }
        return list;
    }

    /// <summary>DOT11_AUTH_ALGORITHM (+ cipher) as the security people know.</summary>
    internal static string AuthLabel(int auth, int cipher, bool secured) => auth switch
    {
        1 => secured || cipher is 1 or 5 or 0x101 ? "WEP" : "Open",
        2 => "WEP",
        3 => "WPA-Enterprise",
        4 => "WPA-Personal",
        6 => "WPA2-Enterprise",
        7 => "WPA2-Personal",
        8 => "WPA3-Enterprise 192-bit",
        9 => "WPA3-Personal",
        10 => "OWE",
        11 => "WPA3-Enterprise",
        _ => secured ? "Secured" : "Open",
    };

    /// <summary>DOT11_PHY_TYPE as the Wi-Fi generation.</summary>
    internal static string PhyLabel(int phy, WifiBand band) => phy switch
    {
        4 => "802.11a",
        5 => "802.11b",
        6 => "802.11g",
        7 => "Wi-Fi 4 (802.11n)",
        8 => "Wi-Fi 5 (802.11ac)",
        10 => band == WifiBand.Ghz6 ? "Wi-Fi 6E (802.11ax)" : "Wi-Fi 6 (802.11ax)",
        11 => "Wi-Fi 7 (802.11be)",
        _ => "",
    };
}
