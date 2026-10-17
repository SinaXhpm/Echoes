using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>
/// A platform's own sound output, for where the shared code can't reach the audio API itself. The Android head
/// registers one (Echoes.Android/AndroidSoundPlayer: an AudioTrack on the notification stream); the desktop heads
/// don't — <see cref="SoundHelper"/> plays there itself.
/// </summary>
public interface IAlertSoundPlayer
{
    /// <summary>Starts playing 16-bit mono PCM at <paramref name="sampleRate"/> Hz and returns at once; false when it
    /// couldn't start. Called on a thread-pool thread.</summary>
    bool Play(short[] pcm, int sampleRate);
}

/// <summary>
/// Plays the alert sounds (<see cref="AlertTone"/>, synthesized by <see cref="SoundTones"/>) at the alert volume, without
/// blocking: Windows hands the WAV bytes to winmm's PlaySound (asynchronous, from memory); macOS and Linux play a copy
/// written to a private temp folder with afplay / paplay / pw-play / aplay; Android plays the PCM through the registered
/// <see cref="IAlertSoundPlayer"/> (notification stream: the phone's notification volume, silent mode and Do not
/// disturb apply). The volume scales the samples themselves, so it sounds the same on every platform; 0 = no sound.
/// </summary>
public static class SoundHelper
{
    /// <summary>The alert volume (0–100 %), shared by every Echoes alert sound; set in the Monitor settings.</summary>
    public const string VolumeKey = "monitor.volume";
    public const int DefaultVolume = 70;

    // Fallback when no player can play our file: the desktop's own notification sound, as before.
    private static readonly (string File, string[] Args)[] LinuxFallbacks =
    {
        ("canberra-gtk-play", new[] { "-i", "message-new-instant" }),
    };

    // One alert per short window: a network drop flips every monitored target in the same round, and a sound per
    // target (up to 256 Monitor rows) queued hundreds of plays that tied up the thread pool for seconds — or spawned
    // as many player processes at once on Linux/macOS. Ping flips are >= 1 s apart.
    private const long MinGapMs = 500;
    private static long _lastPlay = -MinGapMs;

    // How long a Unix player gets to fail before the next one is tried (a missing sound server makes paplay exit at
    // once; one that plays is still running after this).
    private const int PlayerGraceMs = 250;

    // What can be played: the three alerts and the Test sequence (down, a pause, up).
    internal enum Clip { Up, Down, Warning, Test }

    private static readonly object Gate = new();
    private static IAlertSoundPlayer? _player;

    // Built for one volume at a time (the slider moves rarely; a change rebuilds on the next play — ~1 ms per clip).
    private static int _cacheVolume = -1;
    private static readonly Dictionary<Clip, short[]> PcmCache = new();
    // Windows: pinned WAVs for the current volume. PlaySound reads them asynchronously, so a WAV of an older volume is
    // kept (retired) a while before it's freed — a sound still playing never loses its buffer.
    private const long RetireMs = 15_000;
    private static readonly Dictionary<Clip, GCHandle> Pinned = new();
    private static readonly List<(GCHandle Handle, long At)> Retired = new();
    // macOS / Linux: the WAV files of the current volume.
    private static readonly Dictionary<Clip, string> Files = new();

    /// <summary>Called once at startup by a head that plays sound itself (Android).</summary>
    public static void RegisterPlayer(IAlertSoundPlayer player) => _player = player;

    /// <summary>The alert volume, 0–100 % (from the profile; the Monitor settings write it).</summary>
    public static int Volume => Math.Clamp(ProfileService.Instance.GetInt(VolumeKey, DefaultVolume), 0, 100);

    /// <summary>Ping's alert: the up sound for a reply, the down sound for a loss (throttled like <see cref="Play"/>).</summary>
    public static void PlayNotify(bool isSuccess) => Play(isSuccess ? AlertTone.Up : AlertTone.Down);

    /// <summary>Plays an alert unless one was played within the last half second, or the volume is 0.</summary>
    public static void Play(AlertTone tone)
    {
        int volume = Volume;
        if (volume <= 0) return;   // muted: sound is off
        long now = Environment.TickCount64, last = Interlocked.Read(ref _lastPlay);
        if (now - last < MinGapMs || Interlocked.CompareExchange(ref _lastPlay, now, last) != last)
            return;
        Task.Run(() => PlayNow(ToClip(tone), volume));
    }

    /// <summary>A ▶ button in the Monitor settings: plays right away, every time it is pressed (at the alert volume).</summary>
    public static void Preview(AlertTone tone) => PlayRightAway(ToClip(tone));

    /// <summary>The Test button: the down sound, a short pause, then the up sound — one sound, at the alert volume.</summary>
    public static void PlayTest() => PlayRightAway(Clip.Test);

    private static void PlayRightAway(Clip clip)
    {
        int volume = Volume;
        if (volume <= 0) return;
        Interlocked.Exchange(ref _lastPlay, Environment.TickCount64);
        Task.Run(() => PlayNow(clip, volume));
    }

    private static Clip ToClip(AlertTone tone) => tone switch
    {
        AlertTone.Up => Clip.Up,
        AlertTone.Down => Clip.Down,
        _ => Clip.Warning,
    };

    /// <summary>The 16-bit samples of a clip at a volume, as every platform plays them (cached for one volume).</summary>
    internal static short[] Pcm(Clip clip, int volume)
    {
        lock (Gate)
        {
            SetCacheVolume(volume);
            if (PcmCache.TryGetValue(clip, out var cached)) return cached;
            var pcm = clip switch
            {
                Clip.Test => SoundTones.CreateSequencePcm(new[] { AlertTone.Down, AlertTone.Up }, volume),
                Clip.Up => SoundTones.CreatePcm(AlertTone.Up, volume),
                Clip.Down => SoundTones.CreatePcm(AlertTone.Down, volume),
                _ => SoundTones.CreatePcm(AlertTone.Warning, volume),
            };
            PcmCache[clip] = pcm;
            return pcm;
        }
    }

    /// <summary>The WAV file bytes of a clip at a volume.</summary>
    internal static byte[] Wav(Clip clip, int volume) => SoundTones.Encode(Pcm(clip, volume), SoundTones.SampleRate);

    // Caller holds Gate. Another volume: drop what was built for the old one (Windows buffers are retired, not freed).
    private static void SetCacheVolume(int volume)
    {
        if (volume == _cacheVolume) return;
        _cacheVolume = volume;
        PcmCache.Clear();
        long now = Environment.TickCount64;
        foreach (var h in Pinned.Values) Retired.Add((h, now));
        Pinned.Clear();
        foreach (var f in Files.Values)
        {
            try { File.Delete(f); } catch { }   // a player still reading it keeps its open file (Unix)
        }
        Files.Clear();
    }

    /// <summary>Plays <paramref name="tone"/> at the alert volume on the calling thread's terms (returns once playback
    /// has started). False when nothing could play it.</summary>
    internal static bool PlayNow(AlertTone tone) => PlayNow(ToClip(tone), Volume);

    internal static bool PlayNow(Clip clip, int volume)
    {
        if (volume <= 0) return false;
        if (_player is { } player)
        {
            try { return player.Play(Pcm(clip, volume), SoundTones.SampleRate); }
            catch (Exception ex)
            {
                CrashLog.Write("Sound.Player", ex);
                return false;
            }
        }
        if (OperatingSystem.IsAndroid() || OperatingSystem.IsBrowser()) return false;   // no player registered (yet)
        try
        {
            if (OperatingSystem.IsWindows())
            {
                bool played;
                try { played = PlayFromMemory(clip, volume); }
                catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException) { played = false; }
                if (played) return true;
                Console.Beep(clip == Clip.Up ? 900 : 400, 250);   // winmm couldn't play (no audio device): the old beep
                return true;
            }
            if (OperatingSystem.IsMacOS())
            {
                if (WavFile(clip, volume) is { } file && TryPlay("afplay", file)) return true;
            }
            else if (OperatingSystem.IsLinux())
            {
                if (WavFile(clip, volume) is { } file)
                {
                    if (TryPlay("paplay", file) || TryPlay("pw-play", file) || TryPlay("aplay", "-q", file)) return true;
                }
                foreach (var (name, args) in LinuxFallbacks)
                    if (TryPlay(name, args)) return true;
            }
        }
        catch (Exception ex)
        {
            CrashLog.Write("Sound.Play", ex);
        }
        try { Console.Write("\a"); } catch { }
        return false;
    }

    // ---------- Windows: winmm PlaySound straight from memory ----------

    private const uint SndAsync = 0x0001, SndNoDefault = 0x0002, SndMemory = 0x0004;

    [DllImport("winmm.dll", EntryPoint = "PlaySoundW", ExactSpelling = true)]
    private static extern int PlaySound(IntPtr sound, IntPtr module, uint flags);

    // SND_ASYNC returns at once and winmm keeps reading the buffer while it plays, so it must neither move nor be freed:
    // each WAV is pinned and kept while its volume is current, then retired for a while (see SetCacheVolume).
    // SND_NODEFAULT: no system "ding" instead.
    private static bool PlayFromMemory(Clip clip, int volume)
    {
        IntPtr wav;
        lock (Gate)
        {
            SetCacheVolume(volume);
            long now = Environment.TickCount64;
            for (int i = Retired.Count - 1; i >= 0; i--)
            {
                if (now - Retired[i].At < RetireMs) continue;
                Retired[i].Handle.Free();
                Retired.RemoveAt(i);
            }
            if (!Pinned.TryGetValue(clip, out var handle))
            {
                handle = GCHandle.Alloc(Wav(clip, volume), GCHandleType.Pinned);
                Pinned[clip] = handle;
            }
            wav = handle.AddrOfPinnedObject();
        }
        return PlaySound(wav, IntPtr.Zero, SndMemory | SndAsync | SndNoDefault) != 0;
    }

    // ---------- macOS / Linux: a player process on a WAV in a private folder ----------

    // Written once per clip and volume. The folder is the user's own: $XDG_RUNTIME_DIR (Linux, per-user, cleared at
    // logout) or a fresh owner-only temp folder (removed at exit) — never a fixed name in the shared /tmp, where another
    // user could plant a file or link.
    private static string? WavFile(Clip clip, int volume)
    {
        lock (Gate)
        {
            SetCacheVolume(volume);
            if (Files.TryGetValue(clip, out var cached) && File.Exists(cached)) return cached;
            try
            {
                string dir = SoundDir();
                string path = Path.Combine(dir, $"alert-{clip.ToString().ToLowerInvariant()}-{volume}.wav");
                File.WriteAllBytes(path, Wav(clip, volume));
                Files[clip] = path;
                return path;
            }
            catch (Exception ex)
            {
                CrashLog.Write("Sound.File", ex);
                return null;
            }
        }
    }

    private static string? _soundDir;

    private static string SoundDir()
    {
        if (_soundDir is { } known && Directory.Exists(known)) return known;
        string? runtime = Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR");
        if (OperatingSystem.IsLinux() && !string.IsNullOrEmpty(runtime) && Path.IsPathFullyQualified(runtime) && Directory.Exists(runtime))
        {
            _soundDir = Path.Combine(runtime, "echoes");
            Directory.CreateDirectory(_soundDir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        else
        {
            string dir = Directory.CreateTempSubdirectory("echoes-sound-").FullName;   // owner-only (0700) on Unix
            AppDomain.CurrentDomain.ProcessExit += (_, _) => { try { Directory.Delete(dir, true); } catch { } };
            _soundDir = dir;
        }
        return _soundDir;
    }

    // Starts a player and gives it a moment: one that exits with an error right away (no sound server, unsupported
    // file) lets the next player try; one still running — or done with exit code 0 — is playing.
    private static bool TryPlay(string file, params string[] args)
    {
        try
        {
            // Absolute path from absolute PATH entries only — never the app / current directory.
            if (ExecutablePath.Find(file) is not { } exe) return false;
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                UseShellExecute = false,
                CreateNoWindow = true,
                // Not redirected: nothing reads these pipes, and a chatty player could block on a full one.
                RedirectStandardOutput = false,
                RedirectStandardError = false
            };
            foreach (var a in args) psi.ArgumentList.Add(a);
            using var process = Process.Start(psi);
            if (process is null) return false;
            return !process.WaitForExit(PlayerGraceMs) || process.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }
}
