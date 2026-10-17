using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace Echoes.Helpers;

/// <summary>The alert sounds: something came (back) up, something went down, a new warning.</summary>
public enum AlertTone
{
    /// <summary>A bright, rising three-note chime (G5 · B5 · D6) with bell-like partials.</summary>
    Up,
    /// <summary>A clear, falling two-tone (A5 → D5): sustained and warm, to get attention without being harsh.</summary>
    Down,
    /// <summary>A soft double tap (two short marimba-like knocks) for a certificate / domain / DNS warning.</summary>
    Warning,
}

/// <summary>
/// Builds the alert sounds in memory (no asset files): 16-bit mono PCM at 44.1 kHz, 0.6–1.0 s each. Each tone is
/// synthesized once (additive partials, raised-cosine attack and release on every note — no clicks — then a soft-knee
/// limiter and a fixed peak) and cached as a float mix; a volume only scales that mix, so a sound at any volume costs
/// one pass over ~40k samples. The same PCM is played on every platform (<see cref="SoundHelper"/>), so the volume
/// slider sounds the same everywhere. Pure and deterministic.
/// </summary>
public static class SoundTones
{
    public const int SampleRate = 44100;
    private const int HeaderBytes = 44;

    // The test sequence (down, a pause, up) and the gap between its tones.
    public const double TestGapSeconds = 0.35;

    // Peak of each tone at 100 % volume (fraction of full scale). The warning is a little softer on purpose.
    private const double LoudPeak = 0.89;      // ≈ -1 dBFS
    private const double WarningPeak = 0.72;   // ≈ -2.9 dBFS
    // Soft-knee limiter: below this (of the normalized peak) the mix passes unchanged; above it, it bends smoothly.
    private const double KneeStart = 0.72;

    private static readonly Lazy<float[]> UpMix = new(() => Finish(BuildUp(), LoudPeak));
    private static readonly Lazy<float[]> DownMix = new(() => Finish(BuildDown(), LoudPeak));
    private static readonly Lazy<float[]> WarningMix = new(() => Finish(BuildWarning(), WarningPeak));

    /// <summary>The peak a tone reaches at 100 % volume (fraction of full scale).</summary>
    public static double FullScalePeak(AlertTone tone) => tone == AlertTone.Warning ? WarningPeak : LoudPeak;

    /// <summary>Length of a tone in seconds.</summary>
    public static double DurationSeconds(AlertTone tone) => (double)Mix(tone).Length / SampleRate;

    /// <summary>The linear gain of a volume (0–100 %): 0 = silent, 100 = the tone's full peak.</summary>
    public static double Gain(int volumePercent) => Math.Clamp(volumePercent, 0, 100) / 100.0;

    /// <summary>16-bit samples of one tone at <paramref name="volumePercent"/>.</summary>
    public static short[] CreatePcm(AlertTone tone, int volumePercent) => Scale(Mix(tone), Gain(volumePercent));

    /// <summary>Several tones one after another with <paramref name="gapSeconds"/> of silence between them (the Test
    /// button: down, then up), as one buffer — every player then plays it as one sound.</summary>
    public static short[] CreateSequencePcm(IReadOnlyList<AlertTone> tones, int volumePercent, double gapSeconds = TestGapSeconds)
    {
        int gap = (int)Math.Round(Math.Max(0, gapSeconds) * SampleRate);
        int total = 0;
        for (int i = 0; i < tones.Count; i++) total += Mix(tones[i]).Length + (i > 0 ? gap : 0);
        var all = new float[total];
        int at = 0;
        for (int i = 0; i < tones.Count; i++)
        {
            if (i > 0) at += gap;
            var m = Mix(tones[i]);
            Array.Copy(m, 0, all, at, m.Length);
            at += m.Length;
        }
        return Scale(all, Gain(volumePercent));
    }

    /// <summary>A complete RIFF/WAVE file of one tone (PCM, 16-bit, mono, <see cref="SampleRate"/> Hz).</summary>
    public static byte[] CreateWav(AlertTone tone, int volumePercent = 100) => Encode(CreatePcm(tone, volumePercent), SampleRate);

    private static float[] Mix(AlertTone tone) => tone switch
    {
        AlertTone.Up => UpMix.Value,
        AlertTone.Down => DownMix.Value,
        _ => WarningMix.Value,
    };

    private static short[] Scale(float[] mix, double gain)
    {
        var pcm = new short[mix.Length];
        if (gain <= 0) return pcm;
        for (int i = 0; i < mix.Length; i++)
        {
            double v = Math.Clamp(mix[i] * gain, -1.0, 1.0);
            pcm[i] = (short)Math.Round(v * short.MaxValue);
        }
        return pcm;
    }

    // ------------------------------------------------------------------ the three designs

    // Up: G5 → B5 → D6, a major arpeggio struck like small bells: fundamental, octave, twelfth and a slightly stretched
    // double octave, the upper partials dying away faster (that is what makes it sound like a bell, not an organ). The
    // last note rings longest.
    private static double[] BuildUp()
    {
        var mix = new double[Frames(1.00)];
        (double Hz, double At, double Len, double Tau, double Amp)[] notes =
        {
            (783.99, 0.000, 0.62, 0.20, 0.85),
            (987.77, 0.105, 0.62, 0.22, 0.90),
            (1174.66, 0.210, 0.79, 0.30, 1.00),
        };
        (double Ratio, double Amp, double TauScale)[] bell =
        {
            (1.0, 1.00, 1.00),
            (2.0, 0.34, 0.55),
            (3.0, 0.12, 0.38),
            (4.07, 0.05, 0.25),
        };
        foreach (var n in notes)
            AddNote(mix, n.Hz, n.At, n.Len, attack: 0.004, release: 0.060, n.Amp, bell, n.Tau);
        return mix;
    }

    // Down: A5, then a fifth lower to D5 — sustained (a slow decay, not a ping) with a warm, rounded timbre: fundamental
    // plus soft 2nd / 3rd harmonics, no harsh odd-harmonic buzz. The second tone carries a gentle 5.5 Hz tremolo so the
    // fall reads as "something stopped" even at a low volume.
    private static double[] BuildDown()
    {
        var mix = new double[Frames(0.92)];
        (double Ratio, double Amp, double TauScale)[] warm =
        {
            (1.0, 1.00, 1.00),
            (2.0, 0.28, 0.70),
            (3.0, 0.10, 0.50),
        };
        AddNote(mix, 880.00, 0.000, 0.31, attack: 0.012, release: 0.050, 0.95, warm, decayTau: 0.9);
        AddNote(mix, 587.33, 0.300, 0.62, attack: 0.012, release: 0.140, 1.00, warm, decayTau: 0.7, tremoloHz: 5.5, tremoloDepth: 0.16);
        return mix;
    }

    // Warning: two soft knocks on E5 (a marimba-like bar: fundamental + its characteristic ~4x partial, fast decay),
    // the second a touch quieter. Short and gentle — it says "look when you can", not "something is down".
    private static double[] BuildWarning()
    {
        var mix = new double[Frames(0.62)];
        (double Ratio, double Amp, double TauScale)[] bar =
        {
            (1.0, 1.00, 1.00),
            (3.93, 0.16, 0.30),
            (2.0, 0.06, 0.60),
        };
        AddNote(mix, 659.26, 0.000, 0.30, attack: 0.003, release: 0.050, 1.00, bar, decayTau: 0.085);
        AddNote(mix, 659.26, 0.165, 0.45, attack: 0.003, release: 0.080, 0.82, bar, decayTau: 0.100);
        return mix;
    }

    private static int Frames(double seconds) => (int)Math.Ceiling(seconds * SampleRate);

    /// <summary>
    /// Adds one note: each partial is a sine at hz·ratio with its own exponential decay (decayTau·tauScale), the whole
    /// note shaped by a raised-cosine attack and release (smooth start and end: no click), optionally with a tremolo.
    /// </summary>
    private static void AddNote(double[] mix, double hz, double at, double len, double attack, double release, double amp,
        (double Ratio, double Amp, double TauScale)[] partials, double decayTau, double tremoloHz = 0, double tremoloDepth = 0)
    {
        int start = (int)Math.Round(at * SampleRate), count = (int)Math.Round(len * SampleRate);
        int attackN = Math.Max(1, (int)(attack * SampleRate)), releaseN = Math.Max(1, (int)(release * SampleRate));
        double nyquist = SampleRate / 2.0 * 0.9;
        for (int i = 0; i < count && start + i < mix.Length; i++)
        {
            double t = (double)i / SampleRate;
            double edge = 1.0;
            if (i < attackN) edge = 0.5 - 0.5 * Math.Cos(Math.PI * i / attackN);
            int left = count - 1 - i;
            if (left < releaseN) edge = Math.Min(edge, 0.5 - 0.5 * Math.Cos(Math.PI * left / releaseN));
            double trem = tremoloHz > 0 ? 1.0 - tremoloDepth * (0.5 - 0.5 * Math.Cos(2 * Math.PI * tremoloHz * t)) : 1.0;
            double sum = 0;
            foreach (var p in partials)
            {
                double f = hz * p.Ratio;
                if (f >= nyquist) continue;
                sum += p.Amp * Math.Exp(-t / (decayTau * p.TauScale)) * Math.Sin(2 * Math.PI * f * t);
            }
            mix[start + i] += amp * edge * trem * sum;
        }
    }

    /// <summary>
    /// Normalizes a mix to 1, bends whatever is above the knee with a tanh curve (a soft limiter: overlapping notes never
    /// clip or flatten hard), scales it to <paramref name="peak"/>, and fades the last 15 ms so the buffer ends at zero.
    /// </summary>
    private static float[] Finish(double[] mix, double peak)
    {
        double max = 0;
        foreach (double v in mix) max = Math.Max(max, Math.Abs(v));
        var shaped = new double[mix.Length];
        if (max <= 0) return new float[mix.Length];
        double top = 0;
        for (int i = 0; i < mix.Length; i++)
        {
            double x = mix[i] / max;
            double a = Math.Abs(x);
            if (a > KneeStart) a = KneeStart + (1 - KneeStart) * Math.Tanh((a - KneeStart) / (1 - KneeStart));
            shaped[i] = Math.CopySign(a, x);
            top = Math.Max(top, a);
        }
        int fade = Math.Min(mix.Length, SampleRate * 15 / 1000);
        for (int i = 0; i < fade; i++)
        {
            int k = mix.Length - 1 - i;
            shaped[k] *= 0.5 - 0.5 * Math.Cos(Math.PI * i / fade);
        }
        var result = new float[mix.Length];
        double scale = peak / top;
        for (int i = 0; i < mix.Length; i++) result[i] = (float)(shaped[i] * scale);
        return result;
    }

    /// <summary>Wraps 16-bit mono samples in a canonical 44-byte WAV header.</summary>
    internal static byte[] Encode(short[] samples, int sampleRate)
    {
        int dataBytes = samples.Length * 2;
        var wav = new byte[HeaderBytes + dataBytes];
        var s = wav.AsSpan();
        "RIFF"u8.CopyTo(s);
        BinaryPrimitives.WriteInt32LittleEndian(s[4..], 36 + dataBytes);
        "WAVE"u8.CopyTo(s[8..]);
        "fmt "u8.CopyTo(s[12..]);
        BinaryPrimitives.WriteInt32LittleEndian(s[16..], 16);              // fmt chunk size
        BinaryPrimitives.WriteInt16LittleEndian(s[20..], 1);               // PCM
        BinaryPrimitives.WriteInt16LittleEndian(s[22..], 1);               // mono
        BinaryPrimitives.WriteInt32LittleEndian(s[24..], sampleRate);
        BinaryPrimitives.WriteInt32LittleEndian(s[28..], sampleRate * 2);  // byte rate
        BinaryPrimitives.WriteInt16LittleEndian(s[32..], 2);               // block align
        BinaryPrimitives.WriteInt16LittleEndian(s[34..], 16);              // bits per sample
        "data"u8.CopyTo(s[36..]);
        BinaryPrimitives.WriteInt32LittleEndian(s[40..], dataBytes);
        for (int i = 0; i < samples.Length; i++)
            BinaryPrimitives.WriteInt16LittleEndian(s[(HeaderBytes + i * 2)..], samples[i]);
        return wav;
    }
}
