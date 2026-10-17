using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace Echoes.Helpers;

public enum WifiBand { Unknown = 0, Ghz24 = 1, Ghz5 = 2, Ghz6 = 3 }

/// <summary>One access point (BSSID) seen by the last scan.</summary>
public sealed class WifiNetwork
{
    public string Ssid { get; init; } = "";          // "" = a hidden network
    public string Bssid { get; init; } = "";         // AA:BB:CC:DD:EE:FF
    public int Channel { get; init; }                // primary 20 MHz channel; 0 unknown
    public int FrequencyMhz { get; init; }
    public WifiBand Band { get; init; }
    public int WidthMhz { get; init; }               // 20 / 40 / 80 / 160 / 320; 0 unknown
    public int CenterChannel { get; init; }          // center of the whole (bonded) channel; 0 unknown
    public int SignalPercent { get; init; }          // 0..100
    public int RssiDbm { get; init; }                // 0 unknown
    public string Security { get; init; } = "";
    public bool IsConnected { get; init; }

    public bool Hidden => Ssid.Length == 0;
    public string SsidText => Hidden ? "(hidden network)" : Ssid;
    public string BandText => WifiChannels.BandLabel(Band);
    public string ChannelText => Channel <= 0 ? "—" : WidthMhz > 20 ? $"{Channel} · {WidthMhz}" : Channel.ToString(CultureInfo.InvariantCulture);
    public string SignalText => RssiDbm != 0 ? $"{SignalPercent}% · {RssiDbm} dBm" : $"{SignalPercent}%";
    /// <summary>The table's text beside the bar (which already shows the percentage): dBm when known.</summary>
    public string SignalShort => RssiDbm != 0 ? $"{RssiDbm} dBm" : $"{SignalPercent}%";
    public string SecurityText => Security.Length == 0 ? "—" : Security;
    public string Tip => $"{SsidText} · {Bssid}{Environment.NewLine}{BandText}, channel {(Channel > 0 ? Channel.ToString(CultureInfo.InvariantCulture) : "?")}"
                         + (WidthMhz > 0 ? $", {WidthMhz} MHz wide" : "") + (FrequencyMhz > 0 ? $" ({FrequencyMhz} MHz)" : "")
                         + $"{Environment.NewLine}Signal {SignalText} · {SecurityText}" + (IsConnected ? " · connected" : "");

    /// <summary>The signal bar's fill (px) in its 40 px track.</summary>
    public double SignalBarWidth => Math.Clamp(SignalPercent, 0, 100) * 0.4;
    public bool SignalGood => SignalPercent >= 60;
    public bool SignalFair => SignalPercent is >= 35 and < 60;
    public bool SignalWeak => SignalPercent < 35;
}

/// <summary>The link this device is on right now.</summary>
public sealed class WifiConnection
{
    public string Ssid { get; init; } = "";
    public bool SsidHidden { get; init; }            // Windows withheld the name (location access off)
    public string Bssid { get; init; } = "";
    public int Channel { get; init; }
    public int FrequencyMhz { get; init; }
    public WifiBand Band { get; init; }
    public int WidthMhz { get; init; }
    public int SignalPercent { get; init; } = -1;    // -1 unknown
    public int RssiDbm { get; init; }                // 0 unknown
    public bool RssiEstimated { get; init; }         // derived from the percentage
    public double RxMbps { get; init; } = double.NaN;
    public double TxMbps { get; init; } = double.NaN;
    public string Security { get; init; } = "";
    public string Standard { get; init; } = "";      // "Wi-Fi 6 (802.11ax)"
    public string Adapter { get; init; } = "";
}

/// <summary>What the Wi-Fi view shows after one read: the connection, the networks around, and at most ONE note
/// (not supported / location access / no adapter …).</summary>
public sealed class WifiScanResult
{
    public bool Supported { get; init; }
    public string? Note { get; set; }
    /// <summary>The note is Windows' location privacy gate: the view offers to open that setting.</summary>
    public bool NoteIsLocation { get; set; }
    public WifiConnection? Current { get; set; }
    public List<WifiNetwork> Networks { get; init; } = new();
    public DateTimeOffset Time { get; init; } = DateTimeOffset.Now;

    public static WifiScanResult Unsupported(string note) => new() { Supported = false, Note = note };
}

/// <summary>Channel / frequency arithmetic for the three Wi-Fi bands.</summary>
public static class WifiChannels
{
    public static WifiBand BandOf(int mhz) => mhz switch
    {
        >= 2400 and < 2500 => WifiBand.Ghz24,
        >= 5150 and < 5925 => WifiBand.Ghz5,
        >= 5925 and <= 7125 => WifiBand.Ghz6,
        _ => WifiBand.Unknown,
    };

    public static int ChannelOf(int mhz)
    {
        if (mhz == 2484) return 14;
        return BandOf(mhz) switch
        {
            WifiBand.Ghz24 => (mhz - 2407) / 5,
            WifiBand.Ghz5 => (mhz - 5000) / 5,
            WifiBand.Ghz6 => mhz == 5935 ? 2 : (mhz - 5950) / 5,
            _ => 0,
        };
    }

    public static int FrequencyOf(int channel, WifiBand band) => band switch
    {
        WifiBand.Ghz24 => channel == 14 ? 2484 : 2407 + channel * 5,
        WifiBand.Ghz5 => 5000 + channel * 5,
        WifiBand.Ghz6 => channel == 2 ? 5935 : 5950 + channel * 5,
        _ => 0,
    };

    /// <summary>A band for a bare channel number (no frequency known): 1–14 → 2.4 GHz, 32–177 → 5 GHz.</summary>
    public static WifiBand GuessBand(int channel) => channel switch
    {
        >= 1 and <= 14 => WifiBand.Ghz24,
        >= 32 and <= 177 => WifiBand.Ghz5,
        _ => WifiBand.Unknown,
    };

    public static string BandLabel(WifiBand b) => b switch
    {
        WifiBand.Ghz24 => "2.4 GHz",
        WifiBand.Ghz5 => "5 GHz",
        WifiBand.Ghz6 => "6 GHz",
        _ => "—",
    };

    // 20 MHz channels drawn for each band (others seen in a scan are added).
    public static readonly int[] Chart24 = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 };
    public static readonly int[] Chart5 = { 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165 };
    /// <summary>6 GHz preferred scanning channels (PSC): where 6 GHz access points normally sit.</summary>
    public static readonly int[] Chart6 = { 5, 21, 37, 53, 69, 85, 101, 117, 133, 149, 165, 181, 197, 213, 229 };

    /// <summary>The center channel of a <paramref name="width"/> MHz channel holding primary <paramref name="channel"/>,
    /// from the standard channel plan (used when only the width is known, e.g. from nmcli).</summary>
    public static int StandardCenter(int channel, int width, WifiBand band)
    {
        if (channel <= 0 || width <= 20) return channel;
        if (band == WifiBand.Ghz24) return channel <= 7 ? channel + 2 : channel - 2;
        int span = width / 5;                                   // channel numbers covered: 40 → 8, 80 → 16, 160 → 32
        int first = band == WifiBand.Ghz6 ? 1 : channel >= 149 ? 149 : 36;
        if (channel < first) return channel;
        int start = first + (channel - first) / span * span;
        return start + (span - 4) / 2;
    }

    /// <summary>5 GHz radar (DFS) channels: usable, but an access point must vacate them when radar shows up.</summary>
    public static bool IsDfs(int channel) => channel is >= 52 and <= 144;

    /// <summary>The 20 MHz channels a network occupies: its whole bonded width around the center channel, else just
    /// the primary channel. 2.4 GHz: the primary only (the overlap there is handled separately).</summary>
    public static IEnumerable<int> Span(WifiNetwork n)
    {
        if (n.Channel <= 0) yield break;
        if (n.Band == WifiBand.Ghz24 || n.WidthMhz <= 20 || n.CenterChannel <= 0)
        {
            yield return n.Channel;
            yield break;
        }
        int half = (n.WidthMhz / 5 - 4) / 2;   // 40 MHz → ±2, 80 → ±6, 160 → ±14, 320 → ±30 (in channel numbers)
        int from = n.CenterChannel - half, to = n.CenterChannel + half;
        if (n.Channel < from || n.Channel > to)   // inconsistent element: trust the primary channel
        {
            yield return n.Channel;
            yield break;
        }
        for (int c = from; c <= to; c += 4) yield return c;
    }
}

/// <summary>One bar of the channel usage chart.</summary>
public sealed class WifiChannelBar
{
    public int Channel { get; init; }
    public int Count { get; init; }
    public double Load { get; init; }
    public double BarHeight { get; init; }
    public bool IsCurrent { get; init; }
    public bool IsBusy { get; init; }
    public string Label => Channel.ToString(CultureInfo.InvariantCulture);
    public string CountText => Count > 0 ? Count.ToString(CultureInfo.InvariantCulture) : "";
    public bool IsEmpty => Count == 0;
    public string Tip { get; init; } = "";
}

/// <summary>
/// Channel usage per band and the one recommendation line. A network counts by its signal (a strong neighbor
/// interferes more than one at the edge of range): weight 0.05..1 from its RSSI (−95..−45 dBm), else its percentage.
/// 2.4 GHz channels overlap (a 20 MHz channel spreads over ±4 channel numbers), so the recommendation weighs every
/// network by how much it overlaps each of the non-overlapping channels 1 / 6 / 11; on 5 and 6 GHz a network loads
/// every 20 MHz channel of its full (bonded) width. The user's own network (same name) doesn't count against itself.
/// </summary>
public static class WifiAnalysis
{
    public const double ChartHeight = 56;

    public static double Weight(WifiNetwork n)
    {
        if (n.RssiDbm < 0) return Math.Clamp((n.RssiDbm + 95) / 50.0, 0.05, 1);
        return Math.Clamp(n.SignalPercent / 100.0, 0.05, 1);
    }

    /// <summary>The channels to draw for a band: its standard set plus any other seen there.</summary>
    public static List<int> ChartChannels(WifiBand band, IEnumerable<WifiNetwork> nets)
    {
        var set = new SortedSet<int>(band switch
        {
            WifiBand.Ghz24 => WifiChannels.Chart24,
            WifiBand.Ghz5 => WifiChannels.Chart5,
            WifiBand.Ghz6 => WifiChannels.Chart6,
            _ => Array.Empty<int>(),
        });
        foreach (var n in nets)
            if (n.Band == band && n.Channel > 0)
                foreach (int c in WifiChannels.Span(n)) set.Add(c);
        return set.ToList();
    }

    /// <summary>Per drawn channel: how many networks sit there, and their summed weight (the bar height).</summary>
    public static List<WifiChannelBar> Bars(WifiBand band, IReadOnlyList<WifiNetwork> nets, int currentChannel)
    {
        var channels = ChartChannels(band, nets);
        var count = new Dictionary<int, int>();
        var load = new Dictionary<int, double>();
        var here = new Dictionary<int, int>();
        foreach (var n in nets)
        {
            if (n.Band != band || n.Channel <= 0) continue;
            here[n.Channel] = here.GetValueOrDefault(n.Channel) + 1;
            foreach (int c in WifiChannels.Span(n))
            {
                count[c] = count.GetValueOrDefault(c) + 1;
                load[c] = load.GetValueOrDefault(c) + Weight(n);
            }
        }
        double max = load.Count > 0 ? Math.Max(1.0, load.Values.Max()) : 1.0;
        double busyFrom = max * 0.66;
        var bars = new List<WifiChannelBar>(channels.Count);
        foreach (int c in channels)
        {
            int k = count.GetValueOrDefault(c);
            double l = load.GetValueOrDefault(c);
            int own = here.GetValueOrDefault(c);
            string tip = k == 0 ? $"Channel {c}: no networks"
                : $"Channel {c}: {k} network{(k == 1 ? "" : "s")}" + (own != k ? $" ({own} here, {k - own} from wider channels)" : "")
                  + $", load {l.ToString("0.0", CultureInfo.InvariantCulture)}";
            if (band == WifiBand.Ghz5 && WifiChannels.IsDfs(c)) tip += " · radar (DFS) channel";
            bars.Add(new WifiChannelBar
            {
                Channel = c,
                Count = k,
                Load = l,
                BarHeight = k == 0 ? 2 : Math.Max(4, l / max * ChartHeight),
                IsCurrent = c == currentChannel,
                IsBusy = k > 0 && l >= busyFrom && l >= 1.0,
                Tip = tip,
            });
        }
        return bars;
    }

    // 2.4 GHz: how much of a 20 MHz channel at distance d (channel numbers) overlaps; ≥ 5 apart: none.
    private static double Overlap24(int a, int b) => Math.Max(0, 1 - Math.Abs(a - b) / 5.0);

    /// <summary>Interference on a channel from the given networks (the user's own network left out).</summary>
    public static double LoadOn(WifiBand band, int channel, IEnumerable<WifiNetwork> nets)
    {
        double sum = 0;
        foreach (var n in nets)
        {
            if (n.Band != band || n.Channel <= 0) continue;
            double w = Weight(n);
            if (band == WifiBand.Ghz24)
            {
                double o = Overlap24(channel, n.Channel);
                if (n.WidthMhz >= 40 && n.CenterChannel > 0)   // a 40 MHz network also sits on its secondary channel
                    o = Math.Max(o, Overlap24(channel, n.CenterChannel * 2 - n.Channel));
                sum += w * o;
            }
            else if (WifiChannels.Span(n).Contains(channel)) sum += w;
        }
        return sum;
    }

    /// <summary>The recommendation line for one band (empty when there's nothing to say).</summary>
    public static string Recommend(WifiBand band, IReadOnlyList<WifiNetwork> nets, WifiConnection? current)
    {
        var inBand = nets.Where(n => n.Band == band && n.Channel > 0).ToList();
        string bandText = WifiChannels.BandLabel(band);
        if (inBand.Count == 0) return $"No networks seen on {bandText}.";

        // the user's own network (every access point of it) doesn't interfere with itself
        string? ownSsid = current is { SsidHidden: false, Ssid.Length: > 0 } ? current.Ssid : null;
        var others = inBand.Where(n => ownSsid is null ? !n.IsConnected : !string.Equals(n.Ssid, ownSsid, StringComparison.Ordinal)).ToList();

        int[] candidates = band switch
        {
            WifiBand.Ghz24 => new[] { 1, 6, 11 },
            WifiBand.Ghz5 => WifiChannels.Chart5,
            WifiBand.Ghz6 => WifiChannels.Chart6,
            _ => Array.Empty<int>(),
        };
        if (candidates.Length == 0) return "";
        var scored = candidates
            .Select(c => (Channel: c, Load: LoadOn(band, c, others), Dfs: band == WifiBand.Ghz5 && WifiChannels.IsDfs(c)))
            // the clearest first; at (almost) equal load a non-radar 5 GHz channel, then the lower number
            .OrderBy(s => Math.Round(s.Load, 1)).ThenBy(s => s.Dfs).ThenBy(s => s.Channel)
            .ToList();
        var best = scored.Take(2).Select(s => s.Channel).ToList();
        double bestLoad = scored[0].Load;
        string clearer = best.Count == 2 ? $"{best[0]} or {best[1]}" : $"{best[0]}";

        int mine = current is not null && current.Band == band ? current.Channel : 0;
        if (mine > 0)
        {
            double myLoad = LoadOn(band, mine, others);
            if (myLoad <= bestLoad + 0.35 || best.Contains(mine))
                return $"Your channel {mine} is among the clearest on {bandText}.";
            return $"Channel {mine} is crowded; {clearer} {(best.Count == 2 ? "are" : "is")} clearer on {bandText}.";
        }

        // not on this band: name the busiest channel and the clearest ones
        (int Channel, double Load)? busiest = others.Count == 0 ? null
            : others.GroupBy(n => n.Channel).Select(g => (Channel: g.Key, Load: LoadOn(band, g.Key, others)))
                    .OrderByDescending(g => g.Load).First();
        if (busiest is { } b && b.Load >= bestLoad + 0.5 && !best.Contains(b.Channel))
            return $"Channel {b.Channel} is the most crowded; {clearer} {(best.Count == 2 ? "are" : "is")} clearer on {bandText}.";
        return $"Clearest on {bandText}: channel {clearer}.";
    }

    /// <summary>The band whose chart opens first: the connection's, else the one with the most networks.</summary>
    public static WifiBand DefaultBand(WifiConnection? current, IReadOnlyList<WifiNetwork> nets)
    {
        if (current is { Band: not WifiBand.Unknown }) return current.Band;
        var top = nets.Where(n => n.Band != WifiBand.Unknown).GroupBy(n => n.Band).OrderByDescending(g => g.Count()).FirstOrDefault();
        return top?.Key ?? WifiBand.Ghz24;
    }
}

/// <summary>
/// Reads the security and the channel geometry out of a beacon's information elements (802.11 IEs): SSID (0),
/// DS parameter set (3), RSN (48), HT operation (61), VHT operation (191), HE operation (255/36, with its 6 GHz
/// operation info) and EHT operation (255/106), and WPA (221 00-50-F2-01). Every length is checked: a truncated or
/// hostile element is skipped, never read past.
/// </summary>
public static class WifiIe
{
    public sealed class Info
    {
        public string? Ssid;
        public int DsChannel;
        public int PrimaryChannel;
        public int WidthMhz = 20;
        public int CenterChannel;
        public string Security = "";
    }

    public static Info Parse(ReadOnlySpan<byte> ies, bool privacy, WifiBand band)
    {
        var info = new Info();
        bool rsn = false, wpa = false;
        bool rsnPsk = false, rsnSae = false, rsnEnt = false, rsnEnt192 = false, rsnOwe = false;
        bool wpaPsk = false, wpaEnt = false;
        int htPrimary = 0, htWidth = 20, htCenter = 0;
        int vhtWidth = 0, vhtCenter = 0;
        int heWidth = 0, heCenter = 0, hePrimary = 0;
        int ehtWidth = 0, ehtCenter = 0;

        int i = 0;
        while (i + 2 <= ies.Length)
        {
            int id = ies[i], len = ies[i + 1];
            if (i + 2 + len > ies.Length) break;
            var d = ies.Slice(i + 2, len);
            switch (id)
            {
                case 0:
                    info.Ssid = DecodeSsid(d);
                    break;
                case 3 when len >= 1:
                    info.DsChannel = d[0];
                    break;
                case 48:
                    rsn = true;
                    ParseAkms(d, rsnStyle: true, ref rsnPsk, ref rsnSae, ref rsnEnt, ref rsnEnt192, ref rsnOwe);
                    break;
                case 61 when len >= 2:
                    htPrimary = d[0];
                    int offset = d[1] & 0x03;
                    bool any = (d[1] & 0x04) != 0;
                    if (any && offset is 1 or 3)
                    {
                        htWidth = 40;
                        htCenter = offset == 1 ? htPrimary + 2 : htPrimary - 2;
                    }
                    break;
                case 191 when len >= 3:
                    {
                        int chw = d[0], s0 = d[1], s1 = d[2];
                        if (chw == 1 && s0 > 0)
                        {
                            if (s1 > 0 && Math.Abs(s1 - s0) == 8) { vhtWidth = 160; vhtCenter = s1; }
                            else if (s1 > 0 && Math.Abs(s1 - s0) > 16) { vhtWidth = 160; vhtCenter = s0; }   // 80+80
                            else { vhtWidth = 80; vhtCenter = s0; }
                        }
                        else if (chw is 2 or 3 && s0 > 0) { vhtWidth = 160; vhtCenter = s0; }
                        break;
                    }
                case 221 when len >= 4 && d[0] == 0x00 && d[1] == 0x50 && d[2] == 0xF2 && d[3] == 0x01:
                    {
                        wpa = true;
                        bool dummySae = false, dummy192 = false, dummyOwe = false;
                        ParseAkms(d[4..], rsnStyle: false, ref wpaPsk, ref dummySae, ref wpaEnt, ref dummy192, ref dummyOwe);
                        break;
                    }
                case 255 when len >= 1:
                    {
                        int ext = d[0];
                        var p = d[1..];
                        if (ext == 36 && p.Length >= 6)   // HE operation
                        {
                            int prm = p[0] | (p[1] << 8) | (p[2] << 16);
                            int at = 6;
                            if ((prm & (1 << 14)) != 0) at += 3;   // VHT operation information
                            if ((prm & (1 << 15)) != 0) at += 1;   // co-hosted BSS indicator
                            if ((prm & (1 << 17)) != 0 && p.Length >= at + 5)   // 6 GHz operation information
                            {
                                hePrimary = p[at];
                                int w = p[at + 1] & 0x03;
                                int c0 = p[at + 2], c1 = p[at + 3];
                                (heWidth, heCenter) = w switch
                                {
                                    0 => (20, hePrimary),
                                    1 => (40, c0),
                                    2 => (80, c0),
                                    _ => c1 > 0 && Math.Abs(c1 - c0) == 8 ? (160, c1) : (80, c0),
                                };
                            }
                        }
                        else if (ext == 106 && p.Length >= 5 && (p[0] & 0x01) != 0 && p.Length >= 8)   // EHT operation
                        {
                            int w = p[5] & 0x07;
                            int c0 = p[6], c1 = p[7];
                            (ehtWidth, ehtCenter) = w switch
                            {
                                4 => (320, c1 > 0 ? c1 : c0),
                                3 => (160, c1 > 0 ? c1 : c0),
                                2 => (80, c0),
                                1 => (40, c0),
                                _ => (0, 0),
                            };
                        }
                        break;
                    }
            }
            i += 2 + len;
        }

        info.PrimaryChannel = hePrimary > 0 && band == WifiBand.Ghz6 ? hePrimary : htPrimary > 0 ? htPrimary : info.DsChannel;
        // the widest the elements agree on; VHT only applies to 5 GHz, the HE 6 GHz info only to 6 GHz
        (int width, int center) = (htWidth, htCenter);
        if (band != WifiBand.Ghz24 && vhtWidth > width) (width, center) = (vhtWidth, vhtCenter);
        if (heWidth > width) (width, center) = (heWidth, heCenter);
        if (ehtWidth > width && band != WifiBand.Ghz24) (width, center) = (ehtWidth, ehtCenter);
        info.WidthMhz = width;
        info.CenterChannel = width > 20 ? center : info.PrimaryChannel;

        info.Security = rsn
            ? RsnLabel(rsnPsk, rsnSae, rsnEnt, rsnEnt192, rsnOwe, wpa)
            : wpa ? (wpaEnt ? "WPA-Enterprise" : "WPA-Personal")
            : privacy ? "WEP" : "Open";
        return info;
    }

    private static string RsnLabel(bool psk, bool sae, bool ent, bool ent192, bool owe, bool alsoWpa)
    {
        if (ent192) return "WPA3-Enterprise 192-bit";
        if (sae && psk) return "WPA2/WPA3-Personal";
        if (sae) return "WPA3-Personal";
        if (psk) return alsoWpa ? "WPA/WPA2-Personal" : "WPA2-Personal";
        if (ent) return "WPA2-Enterprise";
        if (owe) return "OWE";
        return "WPA2";
    }

    // RSN: version(2) group(4) pairwise count(2)+n×4 AKM count(2)+m×4 …; WPA (after the OUI+type): the same layout.
    private static void ParseAkms(ReadOnlySpan<byte> d, bool rsnStyle, ref bool psk, ref bool sae, ref bool ent, ref bool ent192, ref bool owe)
    {
        int at = 2 + 4;   // version + group cipher
        if (d.Length < at + 2) return;
        int pairwise = d[at] | (d[at + 1] << 8);
        at += 2 + pairwise * 4;
        if (pairwise > 64 || d.Length < at + 2) return;
        int akms = d[at] | (d[at + 1] << 8);
        at += 2;
        if (akms > 64) return;
        for (int k = 0; k < akms && at + 4 <= d.Length; k++, at += 4)
        {
            int type = d[at + 3];
            bool ours = rsnStyle ? d[at] == 0x00 && d[at + 1] == 0x0F && d[at + 2] == 0xAC
                                 : d[at] == 0x00 && d[at + 1] == 0x50 && d[at + 2] == 0xF2;
            if (!ours) continue;
            if (!rsnStyle)
            {
                if (type == 1) ent = true;
                else if (type == 2) psk = true;
                continue;
            }
            switch (type)
            {
                case 1 or 3 or 5: ent = true; break;
                case 2 or 4 or 6: psk = true; break;
                case 8 or 9 or 24 or 25: sae = true; break;
                case 11 or 12 or 13: ent192 = true; break;
                case 18: owe = true; break;
            }
        }
    }

    /// <summary>An SSID as text: UTF-8 when it is valid UTF-8, else Latin-1; control characters become '?';
    /// all-zero / empty = hidden ("").</summary>
    public static string DecodeSsid(ReadOnlySpan<byte> raw)
    {
        if (raw.Length == 0 || raw.IndexOfAnyExcept((byte)0) < 0) return "";
        if (raw.Length > 32) raw = raw[..32];
        string s;
        try { s = new System.Text.UTF8Encoding(false, true).GetString(raw); }
        catch (System.Text.DecoderFallbackException) { s = System.Text.Encoding.Latin1.GetString(raw); }
        var sb = new System.Text.StringBuilder(s.Length);
        foreach (char c in s)
            sb.Append(char.IsControl(c) || c is >= (char)0x202A and <= (char)0x202E || c is >= (char)0x2066 and <= (char)0x2069 ? '?' : c);
        return sb.ToString();
    }

    public static string FormatBssid(ReadOnlySpan<byte> mac)
    {
        if (mac.Length < 6) return "";
        return string.Create(17, mac[..6].ToArray(), static (span, b) =>
        {
            const string hex = "0123456789ABCDEF";
            for (int k = 0; k < 6; k++)
            {
                span[k * 3] = hex[b[k] >> 4];
                span[k * 3 + 1] = hex[b[k] & 0xF];
                if (k < 5) span[k * 3 + 2] = ':';
            }
        });
    }
}
