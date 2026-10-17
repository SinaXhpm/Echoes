using System;

namespace Echoes.Helpers;

/// <summary>
/// The most recent round-trip times (ms) of one target or hop, oldest first; <see cref="double.NaN"/> marks a probe
/// that got no answer. A fixed ring: adding past <see cref="Capacity"/> drops the oldest. Not synchronized: it has one
/// owner (the UI thread, for the charts that draw it).
/// </summary>
public sealed class LatencySeries
{
    private readonly double[] _items;
    private int _start, _count;

    public LatencySeries(int capacity) => _items = new double[Math.Max(1, capacity)];

    public int Capacity => _items.Length;
    public int Count => _count;

    /// <summary>0 = the oldest kept value.</summary>
    public double this[int index] => _items[(_start + index) % _items.Length];

    public void Add(double ms)
    {
        if (_count < _items.Length) _items[(_start + _count++) % _items.Length] = ms;
        else
        {
            _items[_start] = ms;
            _start = (_start + 1) % _items.Length;
        }
    }

    public void Clear()
    {
        _start = 0;
        _count = 0;
    }

    /// <summary>Replaces the contents with <paramref name="values"/> (oldest first; only the newest that fit are kept).</summary>
    public void Set(ReadOnlySpan<double> values)
    {
        Clear();
        int skip = Math.Max(0, values.Length - _items.Length);
        foreach (double v in values[skip..]) Add(v);
    }
}

/// <summary>
/// Running round-trip statistics without keeping the samples (Welford): count, mean, best / worst, and both standard
/// deviations — the sample one mtr prints as StDev, and the population one ping prints as mdev.
/// </summary>
public struct RttStats
{
    public int Count { get; private set; }
    public double Mean { get; private set; }
    public double Best { get; private set; }
    public double Worst { get; private set; }
    private double _m2;

    public void Add(double ms)
    {
        Count++;
        if (Count == 1)
        {
            Mean = Best = Worst = ms;
            _m2 = 0;
            return;
        }
        double delta = ms - Mean;
        Mean += delta / Count;
        _m2 += delta * (ms - Mean);
        if (ms < Best) Best = ms;
        if (ms > Worst) Worst = ms;
    }

    /// <summary>Sample standard deviation (n − 1), as mtr's StDev; 0 below two samples.</summary>
    public readonly double StDev => Count > 1 ? Math.Sqrt(Math.Max(0, _m2) / (Count - 1)) : 0;

    /// <summary>Population standard deviation, as ping's mdev; 0 below two samples.</summary>
    public readonly double MDev => Count > 1 ? Math.Sqrt(Math.Max(0, _m2) / Count) : 0;
}
