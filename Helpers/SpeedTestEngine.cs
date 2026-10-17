using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>Tuning for <see cref="SpeedTestEngine"/>. Only <see cref="Connections"/> is the user's (the Speed Test
/// tab's setting); the rest are the defaults (tests shorten them).</summary>
public sealed record SpeedTestOptions
{
    /// <summary>
    /// Six parallel connections by default: the per-host connection limit browsers have (HTTP/1.1), which the web speed
    /// tests are built around (LibreSpeed downloads over six streams). One TCP connection is held back by its own window
    /// and slow start on a fast or distant link; six fill it without hammering the server. 1 shows what a single
    /// download gets.
    /// </summary>
    public const int DefaultConnections = 6, MinConnections = 1, MaxConnections = 16;

    public int IdleLatencySamples { get; init; } = 20;
    public TimeSpan DownloadTime { get; init; } = TimeSpan.FromSeconds(10);
    public TimeSpan UploadTime { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Byte caps per phase: a phase ends at its time or its cap, whichever comes first.</summary>
    public long DownloadCap { get; init; } = 1_000_000_000;
    public long UploadCap { get; init; } = 400_000_000;

    /// <summary>Parallel connections for the download (each one HTTP/1.1 connection, so the streams don't share one
    /// TCP window), 1..16.</summary>
    public int Connections { get; init; } = DefaultConnections;

    public int DownloadStreams => Math.Clamp(Connections, MinConnections, MaxConnections);
    public int UploadStreams => UploadStreamsFor(Connections);

    /// <summary>
    /// The upload uses half the connections (rounded up: 6 → 3, as LibreSpeed does, 1 → 1, 16 → 8). Every upload stream
    /// fills its own socket buffer before the link takes it, so extra ones mostly lengthen the queue (bufferbloat) and
    /// the server's work rather than the measured speed, and most links upload slower than they download.
    /// </summary>
    public static int UploadStreamsFor(int connections) => (Math.Clamp(connections, MinConnections, MaxConnections) + 1) / 2;

    /// <summary>Latency probes while the link is loaded (bufferbloat), one at a time with this pause between them.</summary>
    public TimeSpan LoadedLatencyInterval { get; init; } = TimeSpan.FromMilliseconds(400);

    /// <summary>How often a phase samples its byte counter (the live speed and the steady-state math).</summary>
    public TimeSpan SampleInterval { get; init; } = TimeSpan.FromMilliseconds(100);

    /// <summary>Connecting to the server (each of HTTPS and the HTTP fallback).</summary>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>The whole run, a safety net over the phases' own limits.</summary>
    public TimeSpan TotalTime { get; init; } = TimeSpan.FromSeconds(150);

    public bool FetchMeta { get; init; } = true;

    /// <summary>Tests: wrap or replace the HTTP handler.</summary>
    public Func<SocketsHttpHandler, HttpMessageHandler>? WrapHandler { get; init; }
}

public enum SpeedTestPhase { Connecting, Latency, Download, Upload, Done }

/// <summary>Where the test ran and who it saw (Cloudflare's view of the client; the others say nothing about it).</summary>
public sealed class SpeedTestServer
{
    public string? Colo { get; init; }          // IATA code of the Cloudflare data center, e.g. "FRA"
    public string? ColoCity { get; init; }      // "Frankfurt-am-Main"
    public string? ColoCountry { get; init; }   // "DE"
    public string? ClientIp { get; init; }
    public string? Isp { get; init; }           // "Mobile Communication Company of Iran PLC"
    public int Asn { get; init; }
    public string? ClientCity { get; init; }
    public string? ClientCountry { get; init; }

    public string ServerLabel => ColoCity is { Length: > 0 } city
        ? (Colo is { Length: > 0 } c ? $"{city} ({c})" : city)
        : Colo ?? "Cloudflare";

    public string IspLabel => Isp is { Length: > 0 } isp ? isp : Asn > 0 ? $"AS{Asn}" : string.Empty;
}

/// <summary>The server a run connected to, as it turned out (HTTPS or the HTTP fallback, what it can measure).</summary>
public sealed record SpeedTestEndpoint(
    string Name,
    string Host,
    bool Secure,
    SpeedTestKind Kind,
    bool Latency,
    bool Upload,
    int DownloadStreams,
    int UploadStreams);

/// <summary>A live view of a running test, reported a few times a second (from a pool thread).</summary>
public sealed class SpeedTestProgress
{
    public SpeedTestPhase Phase { get; init; }
    /// <summary>0..1 of the current phase.</summary>
    public double PhaseFraction { get; init; }
    /// <summary>Throughput right now (last second), Mbps; NaN outside the transfer phases.</summary>
    public double CurrentMbps { get; init; } = double.NaN;
    /// <summary>The latest latency sample (ms) in the latency phase.</summary>
    public double CurrentLatencyMs { get; init; } = double.NaN;

    // finished figures, NaN until their phase is done (loaded latency: live median while its phase runs)
    public double LatencyMs { get; init; } = double.NaN;
    public double JitterMs { get; init; } = double.NaN;
    public double DownloadMbps { get; init; } = double.NaN;
    public double UploadMbps { get; init; } = double.NaN;
    public double LoadedDownMs { get; init; } = double.NaN;
    public double LoadedUpMs { get; init; } = double.NaN;
    public SpeedTestServer? Server { get; init; }
    /// <summary>Known once connected.</summary>
    public SpeedTestEndpoint? Endpoint { get; init; }
}

public sealed class SpeedTestResult
{
    public DateTimeOffset Time { get; init; }
    public double DownloadMbps { get; init; } = double.NaN;
    public double UploadMbps { get; init; } = double.NaN;
    public double LatencyMs { get; init; } = double.NaN;
    public double JitterMs { get; init; } = double.NaN;
    public double LoadedDownMs { get; init; } = double.NaN;
    public double LoadedUpMs { get; init; } = double.NaN;
    public long DownloadBytes { get; init; }
    public long UploadBytes { get; init; }
    public SpeedTestServer? Server { get; init; }
    public required SpeedTestEndpoint Endpoint { get; init; }
}

/// <summary>A failure explained in one sentence for the user (Message), with the underlying exception attached.</summary>
public sealed class SpeedTestException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// Download / upload throughput, idle latency + jitter, and latency under load (bufferbloat) against one destination,
/// through its <see cref="ISpeedTestProvider"/> (Cloudflare, a Speedtest server, a LibreSpeed server, a big file),
/// measured the same way for all of them:
/// <list type="bullet">
/// <item>Latency = time to the first response byte of a tiny request on a warm keep-alive connection, minus the server's
/// own processing time when it says (Cloudflare's Server-Timing); the median of the samples. Jitter = the mean absolute
/// difference of consecutive samples. The first sample (the connection's warm-up) doesn't count.</item>
/// <item>Throughput: N parallel HTTP/1.1 connections (one TCP stream each; N is the user's setting, the upload uses half)
/// keep requesting chunks whose size adapts so a request takes ~1.5 s (or, for a provider without sized requests, read
/// whole files as streams); a phase runs for its time (~10 s) or until its byte cap. Downloads count the bytes read;
/// uploads count what the server acknowledged (a POST's bytes are delivered when its response is back, less half a round
/// trip each way), not what entered the socket's ever-growing send buffer. A server's own timing isn't subtracted there:
/// Cloudflare's Server-Timing on __up includes the time it spends receiving the body, which would squeeze each POST into
/// a fraction of its real time. Sampled every 100 ms, the result comes from the steady part only: from the first moment
/// past the TCP slow-start ramp that the 1-second rate reaches 80 % of the plateau, to the end. A phase whose streams
/// mostly failed, or that measured next to nothing, ends in one error that says why, never in a silent 0.</item>
/// <item>Loaded latency: the same latency probe on its own warm connection, every 400 ms while a transfer phase runs.</item>
/// </list>
/// The payload is never compressed (no Accept-Encoding), no proxy is used (the link itself is measured), and redirects
/// are followed only on the same host while connecting. Every read is capped: a response at its requested size (or the
/// file's), a phase at its byte budget, small answers at 64 KB.
/// </summary>
public sealed class SpeedTestEngine
{
    private const long MinChunk = 128 * 1024;
    private const long FirstChunk = 256 * 1024;
    private const long StreamBlock = 256 * 1024;               // a streamed download reserves its budget this much at a time
    private const long MaxStreamResponse = 16L * 1024 * 1024 * 1024;
    private const int MaxProbeBody = 64 * 1024;
    private const double TargetRequestSeconds = 1.5;

    // A server that limits requests per address (Hetzner: ~18 quick ones, then HTTP 429 for a while): a whole test asks it
    // about 1 + 5 + N + 4 times (the check, idle samples, a stream per connection, loaded probes).
    private const int FewIdleSamples = 5;
    private const int MinIdleSamples = 3;
    private static readonly TimeSpan FewLoadedInterval = TimeSpan.FromSeconds(2.5);

    /// <summary>How long to wait before asking a busy / limiting server again: its Retry-After (at most 3 s), else 1 s.</summary>
    private static TimeSpan RetryDelay(SpeedTestHttpException e)
        => e.RetryAfter is { } ra && ra > TimeSpan.Zero ? (ra < TimeSpan.FromSeconds(3) ? ra : TimeSpan.FromSeconds(3)) : TimeSpan.FromSeconds(1);

    private ISpeedTestProvider _p = null!;
    private SpeedTestEndpoint _endpoint = null!;
    private SpeedTestServer? _fromHeaders;
    private double _halfRttMs;   // half the idle latency: how long an upload's acknowledgement travels back
    private long _maxUpload;     // shrinks when the server refuses a body that large

    public SpeedTestEngine(SpeedTestDestination destination, SpeedTestOptions? options = null)
    {
        Destination = destination;
        Options = options ?? new SpeedTestOptions();
    }

    public SpeedTestDestination Destination { get; }
    public SpeedTestOptions Options { get; }

    private string Host => _p?.Base.Host ?? Destination.Url.Host;

    /// <summary>Runs the whole test. Throws <see cref="SpeedTestException"/> (a one-sentence reason) when the server
    /// can't be reached or the transfers fail, and <see cref="OperationCanceledException"/> when stopped.</summary>
    public async Task<SpeedTestResult> RunAsync(Action<SpeedTestProgress>? progress, CancellationToken ct)
    {
        using var total = CancellationTokenSource.CreateLinkedTokenSource(ct);
        total.CancelAfter(Options.TotalTime);
        try
        {
            return await RunCoreAsync(progress, total.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException ex) when (!ct.IsCancellationRequested && total.IsCancellationRequested)
        {
            throw new SpeedTestException($"The test was stopped after {Options.TotalTime.TotalSeconds:0} seconds: the connection is too slow or keeps stalling.", ex);
        }
    }

    private async Task<SpeedTestResult> RunCoreAsync(Action<SpeedTestProgress>? progress, CancellationToken ct)
    {
        int downStreams = Options.DownloadStreams, upStreams = Options.UploadStreams;
        // A host that takes only a few connections from one address (DataPacket Istanbul: five) gets fewer streams than
        // the setting, so none of them is refused: the latency probe's own connection counts too. The result says how many ran.
        if (Destination.MaxConnections > 1)
        {
            downStreams = Math.Min(downStreams, Destination.MaxConnections - 1);
            upStreams = Math.Min(upStreams, Destination.MaxConnections - 1);
        }
        using var latencyClient = CreateClient(1);
        using var bulkClient = CreateClient(Math.Max(downStreams, upStreams) + 1);
        var started = DateTimeOffset.Now;

        // ---- connecting: the provider (HTTPS, else the HTTP fallback), who / where in the background, a warm connection
        progress?.Invoke(new SpeedTestProgress { Phase = SpeedTestPhase.Connecting });
        try
        {
            _p = await SpeedTestProviders.ConnectAsync(Destination, latencyClient, Options.ConnectTimeout, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            throw Explain(ex, "connect", ct);
        }
        _maxUpload = Math.Max(MinChunk, _p.MaxUploadChunk);
        _endpoint = new SpeedTestEndpoint(Destination.Name, _p.Base.Host, _p.Base.Scheme == Uri.UriSchemeHttps, _p.Kind,
                                          _p.SupportsLatency, _p.SupportsUpload, downStreams, upStreams);
        progress?.Invoke(new SpeedTestProgress { Phase = SpeedTestPhase.Connecting, Endpoint = _endpoint });
        Task<SpeedTestServer?> meta = Options.FetchMeta ? _p.FetchServerInfoAsync(bulkClient, ct) : Task.FromResult<SpeedTestServer?>(null);

        // ---- idle latency + jitter. The first sample (the connection's warm-up) doesn't count; a server that limits
        // requests per address gets fewer samples (its connection is warm from the check already), and a "slow down"
        // from it ends the sampling once there are enough to go on with.
        double latency = double.NaN, jitter = double.NaN;
        if (_p.SupportsLatency)
        {
            bool few = _p.FewRequests;
            int want = few ? Math.Min(FewIdleSamples, Options.IdleLatencySamples) : Options.IdleLatencySamples;
            if (!few)
            {
                try
                {
                    await MeasureLatencyAsync(latencyClient, null, TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
                {
                    throw Explain(ex, "latency", ct);
                }
            }
            var idle = new List<double>(want);
            int failures = 0;
            while (idle.Count < want)
            {
                try
                {
                    double ms = await MeasureLatencyAsync(latencyClient, null, TimeSpan.FromSeconds(5), ct).ConfigureAwait(false);
                    idle.Add(ms);
                    progress?.Invoke(new SpeedTestProgress
                    {
                        Phase = SpeedTestPhase.Latency,
                        PhaseFraction = (double)idle.Count / want,
                        CurrentLatencyMs = ms,
                        Server = Current(meta),
                        Endpoint = _endpoint,
                    });
                }
                catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
                {
                    if (ex is SpeedTestHttpException { Transient: true } busy)
                    {
                        if (idle.Count >= MinIdleSamples) break;
                        if (++failures >= 3) throw Explain(ex, "latency", ct);
                        await Task.Delay(RetryDelay(busy), ct).ConfigureAwait(false);
                        continue;
                    }
                    if (++failures >= 3) throw Explain(ex, "latency", ct);
                }
            }
            latency = SpeedTestMath.Median(idle);
            jitter = SpeedTestMath.Jitter(idle);
        }
        _halfRttMs = double.IsNaN(latency) ? 0 : latency / 2;

        SpeedTestProgress Snapshot(SpeedTestPhase phase, double fraction, double now, double down, double loadedDown, double loadedUp)
            => new()
            {
                Phase = phase, PhaseFraction = fraction, CurrentMbps = now,
                LatencyMs = latency, JitterMs = jitter, DownloadMbps = down,
                LoadedDownMs = loadedDown, LoadedUpMs = loadedUp, Server = Current(meta), Endpoint = _endpoint,
            };

        // ---- download, then upload (where the server takes it), each with latency probed under the load
        var down = await RunTransferAsync(bulkClient, latencyClient, upload: false, downStreams, ct,
            (f, now, loaded) => progress?.Invoke(Snapshot(SpeedTestPhase.Download, f, now, double.NaN, loaded, double.NaN))).ConfigureAwait(false);
        PhaseOutcome? up = null;
        if (_p.SupportsUpload)
        {
            progress?.Invoke(Snapshot(SpeedTestPhase.Upload, 0, double.NaN, down.Mbps, down.LoadedMs, double.NaN));
            await QuietLinkAsync(latencyClient, latency, ct).ConfigureAwait(false);
            up = await RunTransferAsync(bulkClient, latencyClient, upload: true, upStreams, ct,
                (f, now, loaded) => progress?.Invoke(Snapshot(SpeedTestPhase.Upload, f, now, down.Mbps, down.LoadedMs, loaded))).ConfigureAwait(false);
        }

        SpeedTestServer? server = null;
        try { server = await meta.WaitAsync(TimeSpan.FromSeconds(2), ct).ConfigureAwait(false); }
        catch (Exception) when (!ct.IsCancellationRequested) { }
        server = Merge(server, _fromHeaders);

        var result = new SpeedTestResult
        {
            Time = started,
            DownloadMbps = down.Mbps,
            UploadMbps = up?.Mbps ?? double.NaN,
            LatencyMs = latency,
            JitterMs = jitter,
            LoadedDownMs = down.LoadedMs,
            LoadedUpMs = up?.LoadedMs ?? double.NaN,
            DownloadBytes = down.Bytes,
            UploadBytes = up?.Bytes ?? 0,
            Server = server,
            Endpoint = _endpoint,
        };
        progress?.Invoke(new SpeedTestProgress
        {
            Phase = SpeedTestPhase.Done, PhaseFraction = 1,
            LatencyMs = latency, JitterMs = jitter, DownloadMbps = result.DownloadMbps, UploadMbps = result.UploadMbps,
            LoadedDownMs = result.LoadedDownMs, LoadedUpMs = result.LoadedUpMs, Server = server, Endpoint = _endpoint,
        });
        return result;
    }

    private SpeedTestServer? Current(Task<SpeedTestServer?> meta)
        => Merge(meta.IsCompletedSuccessfully ? meta.Result : null, _fromHeaders);

    private static SpeedTestServer? Merge(SpeedTestServer? meta, SpeedTestServer? headers)
    {
        if (meta is null) return headers;
        if (headers is null) return meta;
        return new SpeedTestServer
        {
            Colo = meta.Colo ?? headers.Colo,
            ColoCity = meta.ColoCity ?? headers.ColoCity,
            ColoCountry = meta.ColoCountry ?? headers.ColoCountry,
            ClientIp = meta.ClientIp ?? headers.ClientIp,
            Isp = meta.Isp ?? headers.Isp,
            Asn = meta.Asn > 0 ? meta.Asn : headers.Asn,
            ClientCity = meta.ClientCity ?? headers.ClientCity,
            ClientCountry = meta.ClientCountry ?? headers.ClientCountry,
        };
    }

    // ---------------- HTTP ----------------

    private HttpClient CreateClient(int connections)
    {
        var handler = new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.None,   // the payload must cross the link as it is
            ConnectTimeout = Options.ConnectTimeout,
            MaxConnectionsPerServer = Math.Max(1, connections),
            PooledConnectionIdleTimeout = TimeSpan.FromSeconds(60),
            UseCookies = false,
            AllowAutoRedirect = false,   // the providers follow same-host redirects themselves, while connecting
            UseProxy = false,            // the link itself is measured, never a proxy's
        };
        var client = new HttpClient(Options.WrapHandler?.Invoke(handler) ?? handler, disposeHandler: true)
        {
            Timeout = Timeout.InfiniteTimeSpan,   // every request has its own deadline / the phase's token
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("Echoes");
        return client;
    }

    /// <summary>One latency sample (ms): time to the first byte minus the server's own time.</summary>
    private async Task<double> MeasureLatencyAsync(HttpClient client, string? during, TimeSpan timeout, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeout);
        using var req = _p.CreateLatencyRequest(during);
        long t0 = Stopwatch.GetTimestamp();
        using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
        double ttfb = Stopwatch.GetElapsedTime(t0).TotalMilliseconds;
        SpeedTestProviders.EnsureOk(resp);
        _fromHeaders ??= _p.ServerFromHeaders(resp);
        double server = _p.ServerTimeMs(resp);
        // the (tiny) body is read to its end, so the connection goes back to the pool for the next sample
        if (await SpeedTestProviders.ReadSmallAsync(resp, MaxProbeBody, deadline.Token).ConfigureAwait(false) is null)
            throw new SpeedTestException($"{Host} answered a latency probe with far more data than asked for.");
        return server > 0 && server < ttfb ? ttfb - server : ttfb;
    }

    // ---------------- transfer phases ----------------

    private sealed record PhaseOutcome(double Mbps, long Bytes, double LoadedMs);

    private async Task<PhaseOutcome> RunTransferAsync(HttpClient bulk, HttpClient latencyClient, bool upload, int streams, CancellationToken ct,
                                                      Action<double, double, double> report)
    {
        string what = upload ? "upload" : "download";
        double duration = (upload ? Options.UploadTime : Options.DownloadTime).TotalSeconds;
        long cap = upload ? Options.UploadCap : Options.DownloadCap;
        streams = Math.Max(1, streams);
        var transfer = new Transfer(cap, streams, upload ? _halfRttMs / 1000 : 0);
        var loaded = new List<double>();

        using var phase = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var workers = new Task[streams];
        for (int i = 0; i < streams; i++)
            workers[i] = upload ? UploadStreamAsync(bulk, transfer, i, phase.Token) : DownloadStreamAsync(bulk, transfer, phase.Token);
        var prober = _p.SupportsLatency ? LoadedLatencyAsync(latencyClient, what, loaded, phase.Token) : Task.CompletedTask;

        // Download: the bytes read are the bytes that arrived. Upload: bytes handed to the socket only enter its send
        // buffer — which the OS keeps growing on a long path, so that count runs ahead of the link. An upload is timed
        // by what the server acknowledges instead: each POST's bytes are delivered once its response is back; see
        // Transfer.Delivered.
        var samples = new List<(double T, long Bytes)> { (0, 0) };
        double openAtEnd = double.PositiveInfinity;
        try
        {
            var all = Task.WhenAll(workers);
            while (true)
            {
                await Task.WhenAny(all, Task.Delay(Options.SampleInterval, ct)).ConfigureAwait(false);
                ct.ThrowIfCancellationRequested();
                double t = transfer.Elapsed;
                long b = transfer.Bytes;
                samples.Add((t, b));
                double fraction = Math.Clamp(Math.Max(t / duration, (double)b / cap), 0, 1);
                double live = upload ? transfer.AcknowledgedMbps(t) : SpeedTestMath.RecentMbps(samples, 1.0);
                double loadedNow;
                lock (loaded) loadedNow = loaded.Count > 0 ? SpeedTestMath.Median(loaded) : double.NaN;
                report(fraction, live, loadedNow);
                if (t >= duration || all.IsCompleted) break;
            }
            openAtEnd = transfer.EarliestOpen;   // before the cancel below abandons the requests still in flight
        }
        finally
        {
            phase.Cancel();
            try { await Task.WhenAll(workers.Append(prober)).ConfigureAwait(false); }
            catch (Exception) { /* each worker records its own failure */ }
        }
        ct.ThrowIfCancellationRequested();

        // A download's budget spent, its streams go idle one by one: the tail is no longer a full load. An upload's budget
        // is spent once it is handed to the sockets, while the bytes are still on their way: its acknowledgements decide.
        double end = upload ? samples[^1].T : Math.Min(samples[^1].T, transfer.IdleAt);
        if (transfer.Bytes == 0 || end < 0.5)
        {
            if (transfer.Error is { } err) throw Explain(err, what, ct);
            throw new SpeedTestException($"The {what} test moved no data.");
        }
        // Every stream died long before the phase's time, the cap not reached: the result would be a fragment.
        if (transfer.Error is { } broke && transfer.IdleAt == double.PositiveInfinity && samples[^1].T < duration * 0.5)
            throw Explain(broke, what, ct);
        // Uploads that all failed before the server acknowledged a single one: what entered the sockets proves nothing.
        if (upload && transfer.Completed == 0 && transfer.Error is { } refused)
            throw Explain(refused, what, ct);
        // Half the streams or more gave up on errors: the rest can't stand for the link, so one clear error, not a low figure.
        if (transfer.Error is { } lost && transfer.LostStreams * 2 >= streams)
            throw Explain(lost, what, ct);

        double mbps;
        if (upload && transfer.Completed > 0)
        {
            // Delivered bytes are known exactly up to the start of the earliest request still in flight at the end. Should
            // that cut the phase short (a very slow uplink, a request stuck since early on), take the latest acknowledgement
            // instead: the bytes still in flight then simply don't count (a low estimate, not most of the phase thrown away).
            double ackEnd = Math.Min(end, openAtEnd);
            if (ackEnd < Math.Max(2.5, end * 0.6)) ackEnd = Math.Max(ackEnd, Math.Min(end, transfer.LastAcknowledged));
            var delivered = new List<(double T, long Bytes)>();
            for (double t = 0; t < ackEnd; t += Options.SampleInterval.TotalSeconds) delivered.Add((t, transfer.Delivered(t)));
            delivered.Add((ackEnd, transfer.Delivered(ackEnd)));
            mbps = SpeedTestMath.SteadyMbps(delivered, 1.5, ackEnd);
            // no steady stretch to be found (the requests too long for the phase): all that was acknowledged, plainly
            if (!(mbps > 0)) mbps = transfer.AcknowledgedAverageMbps;
        }
        else if (upload)
        {
            // Not one POST answered all phase long: what entered the sockets proves nothing (their buffers hold megabytes).
            throw new SpeedTestException($"{Host} acknowledged none of the upload in {duration:0} seconds: the upload stalled on the way, " +
                                         "or the uplink is far below 0.1 Mbps.");
        }
        else mbps = SpeedTestMath.SteadyMbps(samples, 1.0, end);
        // Next to nothing measured is never shown as a speed of 0: it is a failure, said once with its reason.
        if (!(mbps > 0) || double.IsInfinity(mbps))
        {
            if (transfer.Error is { } failed) throw Explain(failed, what, ct);
            throw new SpeedTestException(upload
                ? $"{Host} acknowledged next to none of the upload: it stalled on the way (a firewall, a proxy or the server held it back)."
                : $"The download from {Host} stalled: next to nothing arrived.");
        }
        double loadedMs;
        lock (loaded) loadedMs = loaded.Count > 0 ? SpeedTestMath.Median(loaded) : double.NaN;
        return new PhaseOutcome(mbps, transfer.Bytes, loadedMs);
    }

    /// <summary>
    /// After the download the link is still busy: what the server and the network had in flight towards this device keeps
    /// arriving for a while (seconds on a slow, deeply buffered line). An upload's answers would queue behind it and read as
    /// a slow upload, so the upload waits until a latency probe comes back near the idle latency (at most 4 s), or a
    /// second where probing isn't possible or welcome.
    /// </summary>
    private async Task QuietLinkAsync(HttpClient client, double idleMs, CancellationToken ct)
    {
        if (!_p.SupportsLatency || _p.FewRequests || double.IsNaN(idleMs))
        {
            await Task.Delay(TimeSpan.FromSeconds(1), ct).ConfigureAwait(false);
            return;
        }
        double calm = Math.Max(idleMs * 1.5, idleMs + 30);
        var waited = Stopwatch.StartNew();
        await Task.Delay(TimeSpan.FromMilliseconds(300), ct).ConfigureAwait(false);
        while (waited.Elapsed < TimeSpan.FromSeconds(4))
        {
            try
            {
                if (await MeasureLatencyAsync(client, null, TimeSpan.FromSeconds(2), ct).ConfigureAwait(false) <= calm) return;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception) { /* a lost probe: the time limit still ends the wait */ }
            await Task.Delay(TimeSpan.FromMilliseconds(200), ct).ConfigureAwait(false);
        }
    }

    private async Task LoadedLatencyAsync(HttpClient client, string during, List<double> into, CancellationToken ct)
    {
        var interval = _p.FewRequests && Options.LoadedLatencyInterval < FewLoadedInterval ? FewLoadedInterval : Options.LoadedLatencyInterval;
        try
        {
            // give the transfer a moment to load the link first
            await Task.Delay(_p.FewRequests ? TimeSpan.FromSeconds(1) : Options.LoadedLatencyInterval, ct).ConfigureAwait(false);
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    double ms = await MeasureLatencyAsync(client, during, TimeSpan.FromSeconds(5), ct).ConfigureAwait(false);
                    lock (into) into.Add(ms);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { return; }
                // the server asks to slow down: no more probes this phase (the transfer matters more)
                catch (SpeedTestHttpException e) when (e.Transient) { return; }
                catch (Exception) { /* a lost probe under load: the transfer phase decides about failures */ }
                await Task.Delay(interval, ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { }
    }

    /// <summary>
    /// One download stream. Sized providers: a request for exactly the bytes reserved from the phase's budget, the size
    /// adapting so a request takes ~1.5 s (read no further than asked, should a server send more). Stream providers: a
    /// whole file per request, the budget reserved as it is read; the read stops (and the connection with it) when the
    /// budget or the phase ends, and the next request starts when a file ends.
    /// </summary>
    private async Task DownloadStreamAsync(HttpClient client, Transfer t, CancellationToken ct)
    {
        var buffer = new byte[64 * 1024];
        bool sized = _p.SizedDownloads;
        long maxChunk = Math.Max(MinChunk, _p.MaxDownloadChunk);
        long size = Math.Min(FirstChunk, maxChunk);
        int failures = 0;
        while (!ct.IsCancellationRequested)
        {
            long granted = t.Reserve(sized ? size : StreamBlock);
            if (granted <= 0) { t.MarkIdle(); return; }
            long want = granted, got = 0;
            bool spent = false;
            long t0 = Stopwatch.GetTimestamp();
            try
            {
                using var req = _p.CreateDownloadRequest(want);
                using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                SpeedTestProviders.EnsureOk(resp);
                long limit = sized ? want : Math.Min(resp.Content.Headers.ContentLength ?? MaxStreamResponse, MaxStreamResponse);
                using var body = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                while (got < limit)
                {
                    if (got >= granted)
                    {
                        long more = t.Reserve(Math.Min(StreamBlock, limit - granted));
                        if (more <= 0) { spent = true; break; }
                        granted += more;
                    }
                    int n = await body.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, Math.Min(granted, limit) - got)), ct).ConfigureAwait(false);
                    if (n <= 0) break;
                    got += n;
                    t.Add(n);
                }
                // an empty answer (a file of nothing, a server cutting it short) would only spin: it counts as a failure
                if (got == 0 && !spent) throw new IOException($"{_p.Base.Host} sent an empty answer.");
                failures = 0;
            }
            catch (Exception) when (ct.IsCancellationRequested)
            {
                if (granted > got) t.Unreserve(granted - got);
                return;
            }
            catch (Exception ex)
            {
                t.Fail(ex);
                if (granted > got) t.Unreserve(granted - got);
                // busy / limiting (429, 503): another try after the pause it asks for; any other status ends this stream
                if (++failures >= 3 || ex is SpeedTestHttpException { Transient: false })
                {
                    t.StreamLost();
                    return;
                }
                try { await Task.Delay(ex is SpeedTestHttpException busy ? RetryDelay(busy) : TimeSpan.FromMilliseconds(250), ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
                continue;
            }
            if (granted > got) t.Unreserve(granted - got);
            if (spent) { t.MarkIdle(); return; }
            if (sized) size = SpeedTestMath.NextChunk(size, got, Stopwatch.GetElapsedTime(t0).TotalSeconds, TargetRequestSeconds, MinChunk, maxChunk);
        }
    }

    private async Task UploadStreamAsync(HttpClient client, Transfer t, int stream, CancellationToken ct)
    {
        long size = MinChunk;   // small first: on a slow uplink the first acknowledgements come early
        int failures = 0;
        while (!ct.IsCancellationRequested)
        {
            long want = t.Reserve(Math.Min(size, Interlocked.Read(ref _maxUpload)));
            if (want <= 0) { t.MarkIdle(); return; }
            var content = new CountingContent(want, t);
            double start = t.Opened(stream);
            try
            {
                using var req = _p.CreateUploadRequest(content);
                req.Headers.ExpectContinue = false;   // the body goes at once (no 100-continue round trip, on any platform)
                using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                SpeedTestProviders.EnsureOk(resp);
                if (await SpeedTestProviders.ReadSmallAsync(resp, MaxProbeBody, ct).ConfigureAwait(false) is null)
                    throw new IOException("The server answered an upload with far more data than expected.");
                failures = 0;
            }
            catch (Exception) when (ct.IsCancellationRequested)
            {
                t.Abandoned(stream);
                return;
            }
            catch (Exception ex)
            {
                t.Abandoned(stream);
                if (content.Written < want) t.Unreserve(want - content.Written);
                // A body too large for this server: smaller ones from now on (all streams), and this one isn't a failure.
                if (ex is SpeedTestHttpException { Status: HttpStatusCode.RequestEntityTooLarge } && want > MinChunk)
                {
                    ShrinkUpload(want / 2);
                    size = Math.Max(MinChunk, want / 2);
                    continue;
                }
                t.Fail(ex);
                if (want > 4 * 1024 * 1024) ShrinkUpload(want / 4);   // a cut-off large body: maybe a size limit too
                if (++failures >= 3 || ex is SpeedTestHttpException { Transient: false })
                {
                    t.StreamLost();
                    return;
                }
                try { await Task.Delay(ex is SpeedTestHttpException busy ? RetryDelay(busy) : TimeSpan.FromMilliseconds(250), ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
                continue;
            }
            double answered = t.Elapsed;
            t.Closed(stream, start, answered, want);
            // The next size from the request's whole span, send to answer: a little slow, never fast, so the requests grow
            // only as fast as they really go and each one ends well within the phase.
            size = SpeedTestMath.NextChunk(size, want, answered - start, TargetRequestSeconds, MinChunk, Interlocked.Read(ref _maxUpload));
        }
    }

    private void ShrinkUpload(long to)
    {
        to = Math.Max(MinChunk, to);
        long cur;
        while ((cur = Interlocked.Read(ref _maxUpload)) > to && Interlocked.CompareExchange(ref _maxUpload, to, cur) != cur) { }
    }

    /// <summary>An upload body of random bytes (so nothing on the way can compress it), counted as it's handed to the
    /// socket.</summary>
    private sealed class CountingContent : HttpContent
    {
        private static readonly byte[] Payload = CreatePayload();
        private readonly long _length;
        private readonly Transfer _transfer;
        private long _written;

        public CountingContent(long length, Transfer transfer)
        {
            _length = length;
            _transfer = transfer;
            Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        }

        public long Written => Interlocked.Read(ref _written);

        // 1 MB of random data, sent over and over: far beyond the window of any compression a link might apply.
        private static byte[] CreatePayload()
        {
            var b = new byte[1024 * 1024];
            Random.Shared.NextBytes(b);
            return b;
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
            => SerializeToStreamAsync(stream, context, CancellationToken.None);

        // Should the handler re-send the request (a pooled connection found closed), the body goes out again in full,
        // and is counted again: those bytes do cross the link.
        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context, CancellationToken ct)
        {
            long left = _length;
            int offset = Random.Shared.Next(0, Payload.Length);
            while (left > 0)
            {
                int n = (int)Math.Min(Math.Min(left, 64 * 1024), Payload.Length - offset);
                await stream.WriteAsync(Payload.AsMemory(offset, n), ct).ConfigureAwait(false);
                offset = (offset + n) % Payload.Length;
                left -= n;
                Interlocked.Add(ref _written, n);
                _transfer.Add(n);
            }
        }

        protected override bool TryComputeLength(out long length)
        {
            length = _length;
            return true;
        }
    }

    /// <summary>One phase's shared byte counter and byte budget, and (uploads) what the server acknowledged
    /// (thread-safe).</summary>
    private sealed class Transfer
    {
        private readonly long _start = Stopwatch.GetTimestamp();
        private readonly long _cap;
        private long _bytes, _reserved, _idle = -1;
        private Exception? _error;

        // uploads: per stream the start of its request in flight (NaN: none), its latest finished request's rate and
        // when that was; every finished request as the stretch the server received it in, and its bytes
        private readonly object _ackGate = new();
        private readonly double _halfRtt;
        private readonly double[] _open, _lastRate, _lastAt;
        private readonly List<(double Start, double End, long Bytes)> _done = new();

        public Transfer(long cap, int streams, double halfRttSeconds)
        {
            _cap = cap;
            _halfRtt = Math.Max(0, halfRttSeconds);
            _open = new double[streams];
            _lastRate = new double[streams];
            _lastAt = new double[streams];
            Array.Fill(_open, double.NaN);
            Array.Fill(_lastRate, double.NaN);
        }

        public double Opened(int stream)
        {
            double now = Elapsed;
            lock (_ackGate) _open[stream] = now;
            return now;
        }

        public void Abandoned(int stream)
        {
            lock (_ackGate) _open[stream] = double.NaN;
        }

        /// <summary>A POST was answered: the server received its bytes from half a round trip after the client began
        /// sending until half a round trip before the answer arrived. A request too short to resolve that way (less than
        /// a quarter of its plain span) keeps its plain span.</summary>
        public void Closed(int stream, double sent, double answered, long bytes)
        {
            double start = sent + _halfRtt, end = answered - _halfRtt;
            if (end - start < Math.Max(0.002, (answered - sent) / 4))
            {
                start = sent;
                end = Math.Max(sent + 0.001, answered);
            }
            lock (_ackGate)
            {
                _open[stream] = double.NaN;
                _done.Add((start, end, bytes));
                _lastRate[stream] = bytes * 8 / (end - start) / 1e6;
                _lastAt[stream] = Elapsed;
            }
        }

        /// <summary>Everything acknowledged over the time from the first POST's send to the last answer (Mbps; NaN for
        /// none): the fallback when no steady stretch can be found.</summary>
        public double AcknowledgedAverageMbps
        {
            get
            {
                lock (_ackGate)
                {
                    if (_done.Count == 0) return double.NaN;
                    double from = double.PositiveInfinity, to = 0;
                    long bytes = 0;
                    foreach (var (s, e, b) in _done)
                    {
                        from = Math.Min(from, s);
                        to = Math.Max(to, e);
                        bytes += b;
                    }
                    return to > from ? bytes * 8 / (to - from) / 1e6 : double.NaN;
                }
            }
        }

        /// <summary>Streams that gave up after repeated errors (not the ones that ended with the budget or the phase).</summary>
        public int LostStreams => Volatile.Read(ref _lost);
        private int _lost;
        public void StreamLost() => Interlocked.Increment(ref _lost);

        public int Completed
        {
            get { lock (_ackGate) return _done.Count; }
        }

        /// <summary>When the server had the last byte of the latest finished request.</summary>
        public double LastAcknowledged
        {
            get
            {
                lock (_ackGate)
                {
                    double last = 0;
                    foreach (var d in _done) if (d.End > last) last = d.End;
                    return last;
                }
            }
        }

        /// <summary>Where delivered bytes stop being complete: the earliest request still in flight began reaching the
        /// server half a round trip after it was sent (+∞: none in flight).</summary>
        public double EarliestOpen
        {
            get
            {
                lock (_ackGate)
                {
                    double min = double.PositiveInfinity;
                    foreach (double o in _open) if (!double.IsNaN(o) && o + _halfRtt < min) min = o + _halfRtt;
                    return min;
                }
            }
        }

        /// <summary>Bytes the server had received by <paramref name="t"/>: every finished request's bytes, spread evenly
        /// over its time on the wire.</summary>
        public long Delivered(double t)
        {
            double sum = 0;
            lock (_ackGate)
                foreach (var (s, e, b) in _done)
                    sum += t >= e ? b : t <= s ? 0 : b * (t - s) / (e - s);
            return (long)sum;
        }

        /// <summary>Live upload rate: the sum of every stream's latest acknowledged request rate (streams quiet for 3 s
        /// don't count); NaN before the first acknowledgement.</summary>
        public double AcknowledgedMbps(double now)
        {
            lock (_ackGate)
            {
                double sum = 0;
                bool any = false;
                for (int i = 0; i < _lastRate.Length; i++)
                    if (!double.IsNaN(_lastRate[i]) && now - _lastAt[i] < 3)
                    {
                        sum += _lastRate[i];
                        any = true;
                    }
                return any ? sum : double.NaN;
            }
        }

        public double Elapsed => Stopwatch.GetElapsedTime(_start).TotalSeconds;
        public long Bytes => Interlocked.Read(ref _bytes);
        public Exception? Error => Volatile.Read(ref _error);

        /// <summary>Seconds into the phase at which the first stream found the budget spent (the link no longer fully
        /// loaded after it); +∞ while not.</summary>
        public double IdleAt
        {
            get
            {
                long idle = Interlocked.Read(ref _idle);
                return idle < 0 ? double.PositiveInfinity : Stopwatch.GetElapsedTime(_start, idle).TotalSeconds;
            }
        }

        public void Add(int n) => Interlocked.Add(ref _bytes, n);

        public long Reserve(long want)
        {
            while (true)
            {
                long reserved = Interlocked.Read(ref _reserved);
                long take = Math.Min(want, _cap - reserved);
                if (take <= 0) return 0;
                if (Interlocked.CompareExchange(ref _reserved, reserved + take, reserved) == reserved) return take;
            }
        }

        public void Unreserve(long n) => Interlocked.Add(ref _reserved, -n);
        public void MarkIdle() => Interlocked.CompareExchange(ref _idle, Stopwatch.GetTimestamp(), -1);
        public void Fail(Exception e) => Interlocked.CompareExchange(ref _error, e, null);
    }

    // ---------------- errors ----------------

    /// <summary>One sentence that says why, for the one error the tab shows.</summary>
    private SpeedTestException Explain(Exception ex, string during, CancellationToken ct)
    {
        if (ex is SpeedTestException ste) return ste;
        string host = Host;
        string name = Destination.Name;
        for (Exception? e = ex; e is not null; e = e.InnerException)
        {
            switch (e)
            {
                case SpeedTestException inner:
                    return new(inner.Message, ex);
                case SpeedTestHttpException hs when hs.Status == HttpStatusCode.TooManyRequests:
                    return new(_p?.RateLimitMessage ?? $"{name} is limiting tests from this address (HTTP 429): try again in a minute, or pick another server.", ex);
                case SpeedTestHttpException hs when hs.Status == HttpStatusCode.ServiceUnavailable:
                    return new($"{host} is busy or limits parallel connections (HTTP 503): try fewer connections, or another server.", ex);
                case SpeedTestHttpException hs when hs.Status == HttpStatusCode.Forbidden:
                    return new($"{host} refused the test (HTTP 403): a firewall or proxy on the way may be blocking it.", ex);
                case SpeedTestHttpException hs when hs.Status == HttpStatusCode.NotFound:
                    return new($"{host} doesn't serve the test {(during == "upload" ? "upload" : "data")} at that address (HTTP 404).", ex);
                case SpeedTestHttpException hs when hs.Status == HttpStatusCode.RequestEntityTooLarge:
                    return new($"{host} refuses uploads even in small pieces (HTTP 413).", ex);
                case SpeedTestHttpException hs when (int)hs.Status is >= 300 and < 400:
                    return new($"{host} answered with a redirect (HTTP {(int)hs.Status}) during the {Phase(during)}, which a speed test doesn't follow.", ex);
                case SpeedTestHttpException hs:
                    return new($"{host} answered {hs.Message} during the {Phase(during)}.", ex);
                case SocketException se when se.SocketErrorCode is SocketError.HostNotFound or SocketError.NoData or SocketError.TryAgain:
                    return new($"Can't resolve {host}: check the internet connection or the DNS settings.", ex);
                case SocketException se when se.SocketErrorCode is SocketError.ConnectionRefused:
                    return new($"{host} refused the connection: a firewall may be blocking it.", ex);
                case SocketException se when se.SocketErrorCode is SocketError.NetworkUnreachable or SocketError.HostUnreachable
                                                                  or SocketError.NetworkDown or SocketError.AddressNotAvailable:
                    return new($"No route to {host}: the network is down.", ex);
                case SocketException se when se.SocketErrorCode is SocketError.TimedOut:
                    return new($"{host} didn't answer in time: the network is down or the site is blocked.", ex);
                case SocketException se when se.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionAborted:
                    return during is "connect" or "latency"
                        ? new($"The connection to {host} was cut off: the site may be blocked on this network.", ex)
                        : new($"The connection dropped during the {Phase(during)}.", ex);
                case AuthenticationException ae:
                    return new($"The secure connection to {host} failed ({ae.Message.TrimEnd('.')}): a proxy or firewall may be intercepting HTTPS.", ex);
                case TimeoutException:
                    return new($"{host} didn't answer in time: the network is down or the site is blocked.", ex);
            }
        }
        if (ex is OperationCanceledException && !ct.IsCancellationRequested)
            return new($"{host} didn't answer in time: the network is down or the site is blocked.", ex);
        if (ex is IOException or HttpRequestException && during is "download" or "upload")
            return new($"The connection dropped during the {Phase(during)} ({Innermost(ex).Message.TrimEnd('.')}).", ex);
        if (ex is IOException or HttpRequestException && during is "connect" or "latency")
            return new($"The connection to {host} was cut off: the site may be blocked on this network.", ex);
        return new($"The speed test failed: {Innermost(ex).Message.TrimEnd('.')}.", ex);

        static string Phase(string d) => d switch { "connect" => "connection", "latency" => "latency test", _ => d + " test" };
        static Exception Innermost(Exception e) { while (e.InnerException is not null) e = e.InnerException; return e; }
    }
}
