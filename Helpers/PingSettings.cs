using System;
using System.Collections.Generic;
using System.Globalization;

namespace Echoes.Helpers;

/// <summary>
/// The Ping tab's probe settings (its options flyout): ICMP payload size, interval, count, timeout, TTL, Don't fragment
/// and the IP version. Immutable: the view-model swaps in a new one on every change and the running loop reads the
/// current one before each probe (so a size or interval change applies to the next probe). Every value is clamped to
/// what all platforms accept; persisted under "ping.*".
/// </summary>
public sealed record PingSettings
{
    public const int DefaultSize = IcmpPinger.PayloadSize;      // 32, like ping on Windows
    public const int MaxSize = IcmpPinger.MaxPayloadSize;       // 65500: managed Ping's ceiling (Windows' ping -l too)
    public const int DefaultIntervalMs = 1000, MinIntervalMs = 200, MaxIntervalMs = 3_600_000;
    public const int DefaultTimeoutMs = 2000, MinTimeoutMs = 100, MaxTimeoutMs = 60_000;
    public const int MaxCount = 1_000_000;
    public const int MaxTtl = 255;
    public const int DefaultTcpPort = 443;

    public static readonly PingSettings Default = new();

    /// <summary>ICMP payload bytes (the IP packet is 28 more over IPv4, 48 over IPv6).</summary>
    public int Size { get; init; } = DefaultSize;
    /// <summary>Start-to-start spacing of the probes.</summary>
    public int IntervalMs { get; init; } = DefaultIntervalMs;
    /// <summary>Probes to send, then stop; 0 = until stopped.</summary>
    public int Count { get; init; }
    public int TimeoutMs { get; init; } = DefaultTimeoutMs;
    /// <summary>0 = the system's default TTL.</summary>
    public int Ttl { get; init; }
    public bool DontFragment { get; init; }
    public IpPreference Ip { get; init; }

    public PingSettings Clamped() => this with
    {
        Size = Math.Clamp(Size, 0, MaxSize),
        IntervalMs = Math.Clamp(IntervalMs, MinIntervalMs, MaxIntervalMs),
        Count = Math.Clamp(Count, 0, MaxCount),
        TimeoutMs = Math.Clamp(TimeoutMs, MinTimeoutMs, MaxTimeoutMs),
        Ttl = Math.Clamp(Ttl, 0, MaxTtl),
        Ip = Ip is IpPreference.IPv4 or IpPreference.IPv6 ? Ip : IpPreference.Auto,
    };

    /// <summary>What one ICMP probe is sent with.</summary>
    public IcmpProbeOptions Icmp => new(Size, Ttl, DontFragment);

    /// <summary>True when the ICMP-only values (size, TTL, DF) differ.</summary>
    public bool SamePacket(PingSettings o) => Size == o.Size && Ttl == o.Ttl && DontFragment == o.DontFragment;

    /// <summary>The non-default values in a few characters ("1472 B · DF"); empty when everything is default.
    /// <paramref name="tcp"/>: only what TCP mode uses (no size / TTL / DF).</summary>
    public string Summary(bool tcp)
    {
        var parts = new List<string>(7);
        if (Ip != IpPreference.Auto) parts.Add(Ip == IpPreference.IPv6 ? "IPv6" : "IPv4");
        if (!tcp)
        {
            if (Size != DefaultSize) parts.Add(Size.ToString(CultureInfo.InvariantCulture) + " B");
            if (DontFragment) parts.Add("DF");
            if (Ttl > 0) parts.Add("TTL " + Ttl.ToString(CultureInfo.InvariantCulture));
        }
        if (IntervalMs != DefaultIntervalMs) parts.Add("every " + Seconds(IntervalMs));
        if (Count > 0) parts.Add(Count.ToString(CultureInfo.InvariantCulture) + "×");
        if (TimeoutMs != DefaultTimeoutMs) parts.Add("timeout " + Seconds(TimeoutMs));
        return string.Join(" · ", parts);
    }

    /// <summary>1000 → "1 s", 200 → "0.2 s", 1500 → "1.5 s".</summary>
    public static string Seconds(int ms)
        => (ms / 1000.0).ToString(ms % 1000 == 0 ? "0" : ms % 100 == 0 ? "0.0" : "0.##", CultureInfo.InvariantCulture) + " s";

    // ---------- persistence ----------
    public const string KeySize = "ping.size", KeyInterval = "ping.intervalMs", KeyCount = "ping.count", KeyTimeout = "ping.timeoutMs",
                        KeyTtl = "ping.ttl", KeyDf = "ping.df", KeyIp = "ping.ip", KeyTcpPort = "ping.tcpPort";

    private static readonly string[] IpNames = { "auto", "ipv4", "ipv6" };

    public static PingSettings Load(ProfileService ps) => new PingSettings
    {
        Size = ps.GetInt(KeySize, DefaultSize),
        IntervalMs = ps.GetInt(KeyInterval, DefaultIntervalMs),
        Count = ps.GetInt(KeyCount, 0),
        TimeoutMs = ps.GetInt(KeyTimeout, DefaultTimeoutMs),
        Ttl = ps.GetInt(KeyTtl, 0),
        DontFragment = ps.GetBool(KeyDf),
        Ip = Array.IndexOf(IpNames, ps.GetSetting(KeyIp)) is var i and > 0 ? (IpPreference)i : IpPreference.Auto,
    }.Clamped();

    /// <summary>Writes the values that differ from what is stored (the profile writes behind, off the UI thread).</summary>
    public void Save(ProfileService ps)
    {
        var inv = CultureInfo.InvariantCulture;
        var changes = new List<(string, string?)>(7);
        void Put(string key, string value)
        {
            if (ps.GetSetting(key) != value) changes.Add((key, value));
        }
        Put(KeySize, Size.ToString(inv));
        Put(KeyInterval, IntervalMs.ToString(inv));
        Put(KeyCount, Count.ToString(inv));
        Put(KeyTimeout, TimeoutMs.ToString(inv));
        Put(KeyTtl, Ttl.ToString(inv));
        Put(KeyDf, DontFragment ? "true" : "false");
        Put(KeyIp, IpNames[(int)Ip]);
        if (changes.Count > 0) ps.SetMany(changes.ToArray());
    }
}
