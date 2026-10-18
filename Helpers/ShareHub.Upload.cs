using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>
/// Files from a browser to this device. The page sends a file in chunks (<see cref="ChunkSize"/>, at most
/// <see cref="MaxChunkBytes"/> per request): /api/up/start names it (size cap and free space checked up front), each
/// /api/up/chunk?id&amp;offset appends at exactly the offset the server has (else 409 with the right one), and a dropped
/// chunk keeps what arrived — the page asks /api/up/status and resumes from there. A chunk that arrives while an older
/// request for the same file still hangs takes over from it. Bytes go to a ".echoes-ID.part" file, renamed into the inbox
/// under the sanitized name (never over an existing file) and marked as downloaded from the internet on Windows. Partial
/// files are deleted on cancel, after 30 idle minutes and on Stop.
/// </summary>
public sealed partial class ShareHub
{
    private const int MaxUploadsPerSession = 8, MaxChunksPerSession = 2, MaxChunksTotal = 8;
    private const long FreeSpaceMargin = 64L * 1024 * 1024;
    private const long UploadIdleMs = 30L * 60 * 1000;

    private readonly ConcurrentDictionary<string, UploadEntry> _uploads = new(StringComparer.Ordinal);
    // Finished uploads for a while: a page whose last answer got lost asks again and hears "done" (instead of sending
    // the whole file a second time).
    private readonly ConcurrentDictionary<string, (HubSession Session, string Name, long Size, long At)> _finished = new(StringComparer.Ordinal);
    private const int MaxFinishedKept = 256;
    private const long FinishedKeptMs = 15L * 60 * 1000;
    private readonly SemaphoreSlim _chunkSlots = new(MaxChunksTotal);
    private string? _inbox;
    private long _maxUpload = -1;

    /// <summary>Where finished files go; may change while running (an upload in flight moves there when it ends).</summary>
    public string InboxFolder
    {
        get => Volatile.Read(ref _inbox) ?? _o.InboxFolder;
        set => Volatile.Write(ref _inbox, value);
    }

    /// <summary>The largest file a browser may send; may change while running.</summary>
    public long MaxUploadBytes
    {
        get { long v = Interlocked.Read(ref _maxUpload); return v >= 0 ? v : _o.MaxUploadBytes; }
        set => Interlocked.Exchange(ref _maxUpload, Math.Max(0, value));
    }

    /// <summary>Files arriving now (for the app's progress rows).</summary>
    public ShareUpload[] ActiveUploads() => _uploads.Values.Select(e => e.Info).ToArray();

    private enum UploadState { Active, Finished, Dropped }

    private sealed class UploadEntry
    {
        public required ShareUpload Info { get; init; }
        public required HubSession Session { get; init; }
        public required string Ip { get; init; }
        public required string PartPath { get; init; }
        public readonly object Gate = new();
        public long Offset;                       // bytes on disk (under Gate)
        public long LastActivity = Environment.TickCount64;
        public UploadState State;                 // under Gate
        public CancellationTokenSource? Writer;   // the chunk request writing now (under Gate)
        public Task WriterDone = Task.CompletedTask;
    }

    private string PartFolder => _o.PartFolder.Length > 0 ? _o.PartFolder : InboxFolder;

    /// <summary>Partial files of an earlier run (the app was closed mid-upload): they can't be resumed.</summary>
    public static void DeleteStaleParts(string folder)
    {
        try
        {
            if (!Directory.Exists(folder)) return;
            foreach (var f in Directory.EnumerateFiles(folder, ".echoes-*.part")) { try { File.Delete(f); } catch { } }
        }
        catch { }
    }

    // ================================================================ start / chunk / status / cancel

    private async Task<bool> UploadStartAsync(HubConn c, HubRequest req, HubSession s, CancellationToken ct)
    {
        byte[]? body = req.ContentLength > 0 ? await c.Reader.ReadBodyAsync(req.ContentLength, BodyIdleMs, ct).ConfigureAwait(false) : Array.Empty<byte>();
        if (body is null) return false;
        using var doc = body.Length > 0 ? HubHttp.ParseObject(body) : null;
        long size = doc is null ? -1 : HubHttp.Num(doc, "size") ?? -1;
        if (doc is null || size < 0) return await JsonAsync(c, req, 400, HubHttp.Error("Bad request."), ct).ConfigureAwait(false);
        string name = ShareInbox.SanitizeName(HubHttp.Str(doc, "name"));

        long cap = MaxUploadBytes;
        if (size > cap)
            return await JsonAsync(c, req, 413, HubHttp.Error($"Too large - {_o.HostName} accepts files up to {FileHttpServer.HumanSize(cap)}.",
                w => w.WriteNumber("max", cap)), ct).ConfigureAwait(false);
        if (_uploads.Values.Count(u => u.Session == s) >= MaxUploadsPerSession)
            return await JsonAsync(c, req, 429, HubHttp.Error("Too many files at once - wait for some to finish."), ct).ConfigureAwait(false);

        string folder = PartFolder;
        long free = ShareInbox.FreeSpace(folder);
        long pending = _uploads.Values.Sum(u => Math.Max(0, u.Info.Size - Interlocked.Read(ref u.Info.ReceivedBytes)));
        if (free >= 0 && free - pending < size + FreeSpaceMargin)
        {
            Log($"{c.Ip}  {Clean(name)} ({FileHttpServer.HumanSize(size)}) refused: not enough free space");
            return await JsonAsync(c, req, 507, HubHttp.Error($"Not enough free space on {_o.HostName} ({FileHttpServer.HumanSize(Math.Max(0, free - pending))} free).")
                , ct).ConfigureAwait(false);
        }

        string id = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
        string part = Path.Combine(folder, ".echoes-" + id + ".part");
        try
        {
            Directory.CreateDirectory(folder);
            new FileStream(part, AppStorage.PrivateFileOptions(FileMode.CreateNew)).Dispose();
        }
        catch (Exception ex)
        {
            Log($"can't write to {folder}: {ex.Message}");
            return await JsonAsync(c, req, 500, HubHttp.Error($"{_o.HostName} can't save files right now (its folder isn't writable)."), ct).ConfigureAwait(false);
        }

        var info = new ShareUpload { Id = id, Name = name, Size = size, From = s.Name, Cid = s.Cid };
        var entry = new UploadEntry { Info = info, Session = s, Ip = c.Ip, PartPath = part };
        _uploads[id] = entry;
        try { _sink.OnUploadStarted(info); } catch { }
        Log($"{c.Ip}  receiving {Clean(name)} ({FileHttpServer.HumanSize(size)}) from {Clean(s.Name)}");

        if (size == 0)
        {
            string? final = Finish(entry, out string? err);
            return final is null
                ? await JsonAsync(c, req, 500, HubHttp.Error(err ?? "Saving failed."), ct).ConfigureAwait(false)
                : await JsonAsync(c, req, 200, Done(id, 0, final), ct).ConfigureAwait(false);
        }
        return await JsonAsync(c, req, 200, HubHttp.Json(w =>
        {
            w.WriteBoolean("ok", true);
            w.WriteString("id", id);
            w.WriteNumber("offset", 0);
            w.WriteNumber("chunk", ChunkSize);
        }), ct).ConfigureAwait(false);
    }

    private static byte[] Done(string id, long offset, string finalPath) => FinishedJson(id, offset, Path.GetFileName(finalPath));

    private async Task<bool> UploadChunkAsync(HubConn c, HubRequest req, HubSession s, CancellationToken ct)
    {
        if (req.ContentLength < 0)
        {
            await HubHttp.SendJsonAsync(c.Stream, 411, HubHttp.Error("Length required."), false, ct).ConfigureAwait(false);
            return false;
        }
        if (req.ContentLength > MaxChunkBytes)
        {
            // not read: answered, then closed gently
            await HubHttp.SendJsonAsync(c.Stream, 413, HubHttp.Error("Chunk too large."), false, ct).ConfigureAwait(false);
            await LingerAsync(c, ct).ConfigureAwait(false);
            return false;
        }
        long length = req.ContentLength;
        string id = req.QueryValue("id") ?? string.Empty;
        bool offsetOk = long.TryParse(req.QueryValue("offset"), NumberStyles.None, CultureInfo.InvariantCulture, out long offset);
        if (_finished.TryGetValue(id, out var fin) && fin.Session == s)
            return await DrainThenAsync(c, req, 200, FinishedJson(id, fin.Size, fin.Name), ct).ConfigureAwait(false);
        if (!_uploads.TryGetValue(id, out var entry) || entry.Session != s || !offsetOk)
            return await DrainThenAsync(c, req, 404, HubHttp.Error("Unknown upload - start it again.", w => w.WriteBoolean("restart", true)), ct).ConfigureAwait(false);

        if (Interlocked.Increment(ref s.Chunks) > MaxChunksPerSession)
        {
            Interlocked.Decrement(ref s.Chunks);
            return await DrainThenAsync(c, req, 429, HubHttp.Error("Too many uploads at once."), ct).ConfigureAwait(false);
        }
        bool slot = false;
        CancellationTokenSource? mine = null;
        var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        try
        {
            using (var wait = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                wait.CancelAfter(BodyIdleMs);
                try { await _chunkSlots.WaitAsync(wait.Token).ConfigureAwait(false); slot = true; }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
            }
            if (!slot) return await DrainThenAsync(c, req, 503, HubHttp.Error("Busy - try again.", w => w.WriteNumber("retry", 2)), ct).ConfigureAwait(false);

            // An older request for this file that still hangs (the page gave up on it): take over.
            CancellationTokenSource? old;
            Task oldDone;
            lock (entry.Gate) { old = entry.Writer; oldDone = entry.WriterDone; }
            if (old is not null)
            {
                try { old.Cancel(); } catch { }
                await Task.WhenAny(oldDone, Task.Delay(5000, ct)).ConfigureAwait(false);
            }

            long expected;
            lock (entry.Gate)
            {
                expected = entry.Offset;
                if (entry.State != UploadState.Active) expected = -1;
                else if (entry.Writer is null && offset == entry.Offset && offset + length <= entry.Info.Size)
                {
                    mine = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    entry.Writer = mine;
                    entry.WriterDone = done.Task;
                    entry.LastActivity = Environment.TickCount64;
                }
            }
            if (expected < 0)
                return await DrainThenAsync(c, req, 404, HubHttp.Error("Unknown upload - start it again.", w => w.WriteBoolean("restart", true)), ct).ConfigureAwait(false);
            if (mine is null)
            {
                bool tooLong = offset == expected && offset + length > entry.Info.Size;
                return await DrainThenAsync(c, req, tooLong ? 400 : 409, tooLong
                    ? HubHttp.Error("More bytes than the file has.")
                    : HubHttp.Error("Resume from the server's offset.", w => w.WriteNumber("offset", expected)), ct).ConfigureAwait(false);
            }

            // ---- write the body at the offset
            string? failure = null;
            bool bodyComplete = false;
            var buf = ArrayPool<byte>.Shared.Rent(64 * 1024);
            try
            {
                await using var fs = new FileStream(entry.PartPath, new FileStreamOptions
                {
                    Mode = FileMode.Open, Access = FileAccess.Write, Share = FileShare.None, BufferSize = 0, Options = FileOptions.Asynchronous,
                });
                fs.Seek(offset, SeekOrigin.Begin);
                fs.SetLength(offset);   // a takeover may have left a few bytes past what's counted
                long left = length;
                using var idle = CancellationTokenSource.CreateLinkedTokenSource(mine.Token);
                try
                {
                    while (left > 0)
                    {
                        idle.CancelAfter(BodyIdleMs);
                        int n = await c.Reader.ReadAsync(buf.AsMemory(0, (int)Math.Min(buf.Length, left)), idle.Token).ConfigureAwait(false);
                        if (n <= 0) break;
                        try { await fs.WriteAsync(buf.AsMemory(0, n), CancellationToken.None).ConfigureAwait(false); }
                        catch (IOException ex) { failure = DiskError(ex); break; }
                        left -= n;
                        lock (entry.Gate)
                        {
                            entry.Offset += n;
                            entry.LastActivity = Environment.TickCount64;
                        }
                        Interlocked.Add(ref entry.Info.ReceivedBytes, n);
                        Interlocked.Add(ref _bytesReceived, n);
                    }
                    bodyComplete = left == 0;
                }
                catch (OperationCanceledException) { /* the page dropped / a newer request took over / stopping */ }
                catch (IOException) { /* the connection broke: what arrived is kept */ }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                failure ??= DiskError(ex);
            }
            finally { ArrayPool<byte>.Shared.Return(buf); }

            if (failure is not null)
            {
                Drop(entry, failure);
                Log($"{entry.Ip}  {Clean(entry.Info.Name)}: {failure}");
                await HubHttp.SendJsonAsync(c.Stream, 507, HubHttp.Error(failure), false, ct).ConfigureAwait(false);
                await LingerAsync(c, ct).ConfigureAwait(false);   // the rest of the body wasn't read
                return false;
            }
            if (!bodyComplete) return false;   // nobody to answer (or a newer request answers): the page resumes

            long now;
            lock (entry.Gate) now = entry.Offset;
            if (now == entry.Info.Size)
            {
                // the writer slot is released first (the file must be closed before it's moved)
                lock (entry.Gate) { if (entry.Writer == mine) entry.Writer = null; }
                string? final = Finish(entry, out string? err);
                return final is null
                    ? await JsonAsync(c, req, 500, HubHttp.Error(err ?? "Saving failed."), ct).ConfigureAwait(false)
                    : await JsonAsync(c, req, 200, Done(id, now, final), ct).ConfigureAwait(false);
            }
            return await JsonAsync(c, req, 200, HubHttp.Json(w => { w.WriteBoolean("ok", true); w.WriteNumber("offset", now); }), ct).ConfigureAwait(false);
        }
        finally
        {
            if (mine is not null)
            {
                bool dropped;
                lock (entry.Gate)
                {
                    if (entry.Writer == mine) entry.Writer = null;
                    dropped = entry.State == UploadState.Dropped;
                }
                mine.Dispose();
                // dropped while this request still had the file open: it can be deleted now
                if (dropped) TryDelete(entry.PartPath);
            }
            done.TrySetResult();
            if (slot) _chunkSlots.Release();
            Interlocked.Decrement(ref s.Chunks);
        }
    }

    private static string DiskError(Exception ex)
        => ex is IOException io && (io.HResult & 0xFFFF) is 0x70 or 0x27 || ex.Message.Contains("space", StringComparison.OrdinalIgnoreCase)
            ? "This device ran out of disk space."
            : ex is UnauthorizedAccessException ? "This device's folder isn't writable." : "Writing the file failed: " + ex.Message;

    /// <summary>An answer to a chunk that wasn't used: its body is read first (so the connection lives on).</summary>
    private Task<bool> DrainThenAsync(HubConn c, HubRequest req, int status, byte[] json, CancellationToken ct)
        => AnswerAsync(c, req, MaxChunkBytes, keep => HubHttp.SendJsonAsync(c.Stream, status, json, keep, ct), ct);

    private static byte[] FinishedJson(string id, long size, string name) => HubHttp.Json(w =>
    {
        w.WriteBoolean("ok", true);
        w.WriteString("id", id);
        w.WriteNumber("offset", size);
        w.WriteBoolean("done", true);
        w.WriteString("name", name);
    });

    private async Task<bool> UploadStatusAsync(HubConn c, HubRequest req, HubSession s, CancellationToken ct)
    {
        string id = req.QueryValue("id") ?? string.Empty;
        if (_finished.TryGetValue(id, out var fin) && fin.Session == s)
            return await JsonAsync(c, req, 200, FinishedJson(id, fin.Size, fin.Name), ct).ConfigureAwait(false);
        if (!_uploads.TryGetValue(id, out var entry) || entry.Session != s)
            return await JsonAsync(c, req, 404, HubHttp.Error("Unknown upload - start it again.", w => w.WriteBoolean("restart", true)), ct).ConfigureAwait(false);
        long offset;
        bool busy;
        lock (entry.Gate) { offset = entry.Offset; busy = entry.Writer is not null; }
        return await JsonAsync(c, req, 200, HubHttp.Json(w =>
        {
            w.WriteBoolean("ok", true);
            w.WriteNumber("offset", offset);
            w.WriteNumber("size", entry.Info.Size);
            w.WriteBoolean("busy", busy);
        }), ct).ConfigureAwait(false);
    }

    private async Task<bool> UploadCancelAsync(HubConn c, HubRequest req, HubSession s, CancellationToken ct)
    {
        string id = req.QueryValue("id") ?? string.Empty;
        if (_uploads.TryGetValue(id, out var entry) && entry.Session == s)
        {
            Drop(entry, "Canceled by the sender.");
            Log($"{c.Ip}  {Clean(entry.Info.Name)}: canceled by the sender");
        }
        return await JsonAsync(c, req, 200, HubHttp.Json(w => w.WriteBoolean("ok", true)), ct).ConfigureAwait(false);
    }

    // ================================================================ finish / drop

    /// <summary>Renames the complete file into the inbox (never over another file), marks it, and posts it in the chat.
    /// Null = it couldn't be saved (<paramref name="error"/>).</summary>
    private string? Finish(UploadEntry entry, out string? error)
    {
        error = null;
        lock (entry.Gate)
        {
            if (entry.State != UploadState.Active) { error = "The upload was canceled."; return null; }
            entry.State = UploadState.Finished;
        }
        _uploads.TryRemove(entry.Info.Id, out _);
        string final;
        try
        {
            final = ShareInbox.FinalizeInto(entry.PartPath, InboxFolder, entry.Info.Name);
        }
        catch (Exception ex)
        {
            TryDelete(entry.PartPath);
            error = "Saving the file failed: " + ex.Message;
            Log($"{entry.Ip}  {Clean(entry.Info.Name)}: {error}");
            try { _sink.OnUploadFinished(entry.Info, null, error); } catch { }
            return null;
        }
        ShareInbox.MarkOfTheWeb(final);
        if (_finished.Count >= MaxFinishedKept) _finished.Clear();
        _finished[entry.Info.Id] = (entry.Session, Path.GetFileName(final), entry.Info.Size, Environment.TickCount64);
        Log($"{entry.Ip}  received {Clean(Path.GetFileName(final))} ({FileHttpServer.HumanSize(entry.Info.Size)}) from {Clean(entry.Session.Name)}");
        try { _sink.OnUploadFinished(entry.Info, final, null); } catch { }
        Post(seq => new ShareMessage
        {
            Seq = seq, Cid = entry.Session.Cid, From = entry.Session.Name, Time = DateTime.Now, Kind = ShareMessageKind.Received,
            FileName = Path.GetFileName(final), FileSize = entry.Info.Size,
        });
        return final;
    }

    /// <summary>Ends an upload that won't complete: its partial file goes (now, or when the request writing it lets go).</summary>
    private void Drop(UploadEntry entry, string why)
    {
        CancellationTokenSource? writer;
        lock (entry.Gate)
        {
            if (entry.State != UploadState.Active) return;
            entry.State = UploadState.Dropped;
            writer = entry.Writer;
        }
        _uploads.TryRemove(entry.Info.Id, out _);
        if (writer is not null) { try { writer.Cancel(); } catch { } }
        else TryDelete(entry.PartPath);
        try { _sink.OnUploadFinished(entry.Info, null, why); } catch { }
    }

    private void DropAllUploads(string why)
    {
        foreach (var e in _uploads.Values.ToArray()) Drop(e, why);
    }

    private void ExpireUploads()
    {
        long now = Environment.TickCount64;
        foreach (var kv in _finished) if (now - kv.Value.At > FinishedKeptMs) _finished.TryRemove(kv.Key, out _);
        foreach (var e in _uploads.Values.ToArray())
        {
            bool idle;
            lock (e.Gate) idle = e.Writer is null && now - e.LastActivity > UploadIdleMs;
            if (!idle) continue;
            Drop(e, "It stopped arriving (30 minutes without data).");
            Log($"{e.Ip}  {Clean(e.Info.Name)}: stopped arriving - partial file deleted");
        }
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch { }
    }
}
