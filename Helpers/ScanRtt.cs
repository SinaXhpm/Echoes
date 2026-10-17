using System;

namespace Echoes.Helpers;

/// <summary>
/// Thread-safe per-host RTT estimator, TCP-RTO style (RFC 6298), fed by every probe that came back — a SYN-ACK, a
/// RST, an ICMP error. It turns the user's fixed timeout into an adaptive one: a nearby host that answers in 8 ms
/// isn't waited on for a full second per silent port, while a distant host still gets the headroom it needs. The
/// user's timeout stays the ceiling, and the estimate only tightens below it after a few samples — a cold first probe
/// (always the slowest) must not declare every following port filtered.
/// </summary>
public sealed class HostRtt
{
    // RFC 6298 smoothing gains.
    private const double Alpha = 1.0 / 8.0;
    private const double Beta = 1.0 / 4.0;

    private readonly object _lock = new();
    private double _srtt, _rttvar;
    private double _minRtt = double.MaxValue;
    // Slowly decaying maximum. Mixed evidence — a local proxy SYN-ACKing in 0.3 ms while the host's own RSTs take
    // 230 ms — drags SRTT far below the real path; a timeout under the path RTT then turns every closed port into
    // "filtered". The timeout never drops below 1.5× this peak.
    private double _peak;
    private int _samples;

    /// <summary>Feed one completed round trip, in milliseconds.</summary>
    public void AddSample(double rttMs)
    {
        if (rttMs < 0) rttMs = 0;
        lock (_lock)
        {
            if (_samples == 0)
            {
                _srtt = rttMs;           // RFC 6298 first measurement: SRTT = R, RTTVAR = R/2
                _rttvar = rttMs / 2.0;
            }
            else
            {
                _rttvar = (1 - Beta) * _rttvar + Beta * Math.Abs(_srtt - rttMs);
                _srtt = (1 - Alpha) * _srtt + Alpha * rttMs;
            }
            if (rttMs < _minRtt) _minRtt = rttMs;
            _peak = Math.Max(rttMs, _peak * 0.98);
            _samples++;
        }
    }

    /// <summary>
    /// Per-probe timeout: clamp(max(SRTT + 4·RTTVAR, 1.5·peak), max(100 ms, 2·minRTT), ceiling) once three samples are
    /// in, the full ceiling before that; doubled per retry (<paramref name="attempt"/>), never above the ceiling.
    /// </summary>
    public int ProbeTimeout(int ceilingMs, int attempt = 0)
    {
        int t = EffectiveTimeout(ceilingMs);
        return (int)Math.Min((long)t << Math.Clamp(attempt, 0, 8), ceilingMs);
    }

    public int EffectiveTimeout(int ceilingMs)
    {
        lock (_lock)
        {
            if (_samples < 3) return ceilingMs;
            // Clamp(min > max) throws: a far host (minRtt 300 ms) with a 400 ms ceiling has floor 600 — cap it.
            double floor = Math.Min(Math.Max(100.0, 2.0 * _minRtt), ceilingMs);
            double rto = Math.Max(_srtt + 4.0 * _rttvar, 1.5 * _peak);
            return Math.Max(1, (int)Math.Ceiling(Math.Clamp(rto, floor, ceilingMs)));
        }
    }

    /// <summary>
    /// Host-discovery variant: clamp(SRTT + 4·RTTVAR, <paramref name="floorMs"/>, ceiling) once <paramref name="minSamples"/>
    /// round trips are in, the full ceiling before that. Discovery shares ONE estimator across a sweep, fed by every
    /// live host's reply — so each dead host doesn't cost the full timeout when the live ones answer in 2 ms.
    /// </summary>
    public int AdaptiveTimeout(int ceilingMs, int minSamples, double floorMs)
    {
        lock (_lock)
        {
            if (_samples < minSamples) return ceilingMs;
            double floor = Math.Min(floorMs, ceilingMs);
            double clamped = Math.Clamp(_srtt + 4.0 * _rttvar, floor, ceilingMs);
            return Math.Max(1, (int)Math.Ceiling(clamped));
        }
    }
}
