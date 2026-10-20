using System;
using System.Collections.Generic;
using System.Globalization;

namespace Echoes.Helpers;

/// <summary>How long a random secret of a known size lasts against an attacker who tries guesses at a given speed.</summary>
public static class CrackTime
{
    /// <summary>How well the secret holds in one scenario.</summary>
    public enum Level { Weak, Fair, Strong }

    /// <param name="Name">Short, plain name of the attacker's situation.</param>
    /// <param name="Rate">Guesses per second.</param>
    /// <param name="Detail">What the speed assumes (a tooltip).</param>
    public sealed record Scenario(string Name, double Rate, string Detail);

    /// <summary>
    /// Everyday situations, slowest to fastest. The speeds are round figures from public numbers (hashcat benchmarks of one
    /// high-end GPU, scaled by the size of the rig); a faster attacker only shifts every row down by the same factor.
    /// </summary>
    public static IReadOnlyList<Scenario> Scenarios { get; } = new Scenario[]
    {
        new("Login with lockout", 100.0 / 3600, "An online login that allows about 100 tries an hour (lockouts, delays, CAPTCHA)."),
        new("Login, no limit", 1_000, "An online login with no limit: about 1,000 tries a second."),
        new("Stolen, slow hash", 6_000, "A stolen database hashed with bcrypt (cost 10) or Argon2, on one high-end GPU: about 6,000 a second."),
        new("Stolen, fast hash", 1e11, "A stolen database hashed with MD5, NTLM or SHA-1, on one high-end GPU: about 100 billion a second."),
        new("GPU cluster", 1e14, "Fast hash, a cluster of about 1,000 GPUs: 100 trillion a second."),
        new("State-level", 1e16, "Fast hash, a data centre of about 100,000 GPUs: 10 quadrillion a second."),
    };

    /// <summary>Entropy of a value picked uniformly from <paramref name="symbols"/> symbols, <paramref name="length"/> times, in bits.</summary>
    public static double Bits(int symbols, int length) => symbols <= 1 || length <= 0 ? 0 : length * Math.Log2(symbols);

    /// <summary>
    /// Bits of a password drawn uniformly from every string of <paramref name="length"/> characters that uses each of the
    /// character <paramref name="classes"/> (given as their sizes) at least once, which is what the generator makes. Inclusion
    /// and exclusion over the classes; for long passwords the constraint changes nothing measurable.
    /// </summary>
    public static double PasswordBits(int[] classes, int length)
    {
        int pool = 0;
        foreach (int c in classes) pool += c;
        double plain = Bits(pool, length);
        if (length < classes.Length || length > 64 || classes.Length > 8) return plain;

        double total = 0;
        for (int mask = 0; mask < 1 << classes.Length; mask++)
        {
            int left = pool, ones = 0;
            for (int i = 0; i < classes.Length; i++)
                if ((mask >> i & 1) == 1) { left -= classes[i]; ones++; }
            double term = Math.Pow(left, length);
            total += ones % 2 == 0 ? term : -term;
        }
        return total > 1 ? Math.Log2(total) : plain;
    }

    /// <summary>Seconds, on average, to find a secret of <paramref name="bits"/> bits at <paramref name="rate"/> guesses a second
    /// (half the possibilities); the result is a base-2 logarithm so any size fits.</summary>
    public static double Log2Seconds(double bits, double rate) => Math.Max(bits - 1, 0) - Math.Log2(rate);

    /// <summary>Average time to crack, as a short phrase ("3 days", "8.4 million years", "10^25 years").</summary>
    public static string Describe(double bits, double rate)
    {
        double l2 = Log2Seconds(bits, rate);
        if (l2 > 1000) return "10^" + Math.Floor(l2 * 0.30103 - Math.Log10(SecondsPerYear)).ToString("0", Inv) + " years";
        double s = Math.Pow(2, l2);
        return Phrase(s);
    }

    /// <summary>How the time compares with what people need: a day, a few years, a lifetime.</summary>
    public static Level Judge(double bits, double rate)
    {
        double l2 = Log2Seconds(bits, rate);
        if (l2 > 1000) return Level.Strong;
        double s = Math.Pow(2, l2);
        return s < 86_400 * 30 ? Level.Weak : s < SecondsPerYear * 100 ? Level.Fair : Level.Strong;
    }

    private const double SecondsPerYear = 31_557_600;   // 365.25 days
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    // Units are chosen on the ROUNDED value, so 59.6 seconds reads "1 minute", never "60 seconds".
    private static double R(double v) => v < 10 ? Math.Round(v, 1) : Math.Round(v);

    private static string Phrase(double s)
    {
        if (s < 1) return "instantly";
        if (R(s) < 60) return Count(s, "second");
        double m = s / 60;
        if (R(m) < 60) return Count(m, "minute");
        double h = m / 60;
        if (R(h) < 24) return Count(h, "hour");
        double d = h / 24;
        if (R(d) < 60) return Count(d, "day");
        double mo = d / 30.44;
        if (R(mo) < 12) return Count(mo, "month");
        double years = d / 365.25;
        if (R(years) < 1_000) return Count(years, "year");
        string[] big = { "thousand", "million", "billion", "trillion", "quadrillion" };
        double v = years;
        int i = -1;
        while (R(v) >= 1_000 && i < big.Length - 1) { v /= 1_000; i++; }
        if (R(v) >= 1_000) return "10^" + Math.Floor(Math.Log10(years)).ToString("0", Inv) + " years";   // beyond "quadrillion"
        return $"{Short(R(v))} {big[i]} years";
    }
    private static string Count(double v, string unit)
    {
        double r = v < 10 ? Math.Round(v, 1) : Math.Round(v);
        string n = Short(r);
        return $"{n} {unit}{(n == "1" ? "" : "s")}";
    }

    private static string Short(double v) => v < 10 ? v.ToString("0.#", Inv) : v.ToString("0", Inv);
}
