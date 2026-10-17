using Android.Media;
using Echoes.Helpers;

namespace Echoes.Android;

/// <summary>
/// Android implementation of <see cref="IAlertSoundPlayer"/>: plays the synthesized alert PCM with a static-mode
/// <see cref="AudioTrack"/> tagged USAGE_NOTIFICATION_EVENT / CONTENT_TYPE_SONIFICATION, so it goes to the notification
/// stream — the phone's notification volume, silent / vibrate mode and Do not disturb all apply, as for any app's
/// notification sound. Works with Echoes in the background (the Monitor runs under KeepAliveService). Each sound gets
/// its own short-lived track, released shortly after it ends; at most a few play at once.
/// Registered by MainApplication at startup (SoundHelper.RegisterPlayer).
/// </summary>
public sealed class AndroidSoundPlayer : IAlertSoundPlayer
{
    private const int MaxPlaying = 3;
    private const int ReleaseMarginMs = 400;
    private static int _playing;

    public bool Play(short[] pcm, int sampleRate)
    {
        if (pcm.Length == 0 || sampleRate <= 0) return false;
        if (Interlocked.Increment(ref _playing) > MaxPlaying)
        {
            Interlocked.Decrement(ref _playing);
            return false;
        }

        AudioTrack? track = null;
        try
        {
            using var attributes = new AudioAttributes.Builder()
                .SetUsage(AudioUsageKind.NotificationEvent)!
                .SetContentType(AudioContentType.Sonification)!
                .Build()!;
            using var format = new AudioFormat.Builder()
                .SetEncoding(global::Android.Media.Encoding.Pcm16bit)!
                .SetSampleRate(sampleRate)!
                .SetChannelMask(ChannelOut.Mono)!
                .Build()!;
            // Static mode: the whole sound is handed over once and played from the track's own buffer (no streaming
            // thread to feed it). API 23+, Echoes' minimum.
            track = new AudioTrack.Builder()
                .SetAudioAttributes(attributes)!
                .SetAudioFormat(format)!
                .SetTransferMode(AudioTrackMode.Static)!
                .SetBufferSizeInBytes(pcm.Length * 2)!
                .Build();
            if (track.State == AudioTrackState.Uninitialized) return Fail(ref track);
            int written = track.Write(pcm, 0, pcm.Length);
            if (written < pcm.Length || track.State != AudioTrackState.Initialized) return Fail(ref track);
            track.Play();

            var playing = track;
            track = null;   // released below, once it has played
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
            CrashLog.Write("Sound.AudioTrack", ex);
            if (track is not null) Release(track);
            else Interlocked.Decrement(ref _playing);
            return false;
        }
    }

    private static bool Fail(ref AudioTrack? track)
    {
        if (track is not null) Release(track);
        track = null;
        return false;
    }

    private static void Release(AudioTrack track)
    {
        try { track.Stop(); } catch { }
        try { track.Release(); } catch { }
        try { track.Dispose(); } catch { }
        Interlocked.Decrement(ref _playing);
    }
}
