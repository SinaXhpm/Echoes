using AVFoundation;
using Echoes.Helpers;
using Foundation;

namespace Echoes.iOS;

/// <summary>
/// iOS implementation of <see cref="IAlertSoundPlayer"/>: the synthesized alert is wrapped in a WAV and played by an
/// <see cref="AVAudioPlayer"/>. The audio session is "ambient" and mixes with other audio, so the ringer switch silences it
/// (like a notification sound) and music that is playing keeps playing. Each sound gets its own short-lived player, released
/// shortly after it ends; at most a few play at once. Registered by <see cref="AppDelegate"/> (SoundHelper.RegisterPlayer).
/// </summary>
internal sealed class IosSoundPlayer : IAlertSoundPlayer
{
    private const int MaxPlaying = 3;
    private const int ReleaseMarginMs = 400;
    private static int _playing;
    private static bool _sessionReady;
    private static readonly object SessionGate = new();

    public bool Play(short[] pcm, int sampleRate)
    {
        if (pcm.Length == 0 || sampleRate <= 0) return false;
        if (Interlocked.Increment(ref _playing) > MaxPlaying)
        {
            Interlocked.Decrement(ref _playing);
            return false;
        }

        AVAudioPlayer? player = null;
        try
        {
            EnsureSession();
            using var data = NSData.FromArray(SoundTones.Encode(pcm, sampleRate));
            player = AVAudioPlayer.FromData(data, out NSError? error);
            if (player is null || error is not null) return Fail(ref player);
            player.Volume = 1f;   // the alert volume is already in the samples
            if (!player.PrepareToPlay() || !player.Play()) return Fail(ref player);

            var playing = player;
            player = null;   // released below, once it has played
            long ms = pcm.Length * 1000L / sampleRate + ReleaseMarginMs;
            _ = Task.Run(async () =>
            {
                await Task.Delay(TimeSpan.FromMilliseconds(ms)).ConfigureAwait(false);
                Release(playing);
            });
            return true;
        }
        catch (Exception ex)
        {
            CrashLog.Write("Sound.AVAudioPlayer", ex);
            if (player is not null) Release(player);
            else Interlocked.Decrement(ref _playing);
            return false;
        }
    }

    // Ambient + mix with others: no other app's audio is stopped, and the silent switch is honoured.
    private static void EnsureSession()
    {
        lock (SessionGate)
        {
            if (_sessionReady) return;
            var session = AVAudioSession.SharedInstance();
            session.SetCategory(AVAudioSessionCategory.Ambient, AVAudioSessionCategoryOptions.MixWithOthers);
            session.SetActive(true);
            _sessionReady = true;
        }
    }

    private static bool Fail(ref AVAudioPlayer? player)
    {
        if (player is not null) Release(player);
        player = null;
        return false;
    }

    private static void Release(AVAudioPlayer player)
    {
        try { player.Stop(); } catch { }
        try { player.Dispose(); } catch { }
        Interlocked.Decrement(ref _playing);
    }
}
