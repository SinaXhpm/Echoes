using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>
/// The chat side of the hub. Every change (a message, "chat cleared", the shared files list) is an event with a growing
/// sequence number, kept in a ring of the last <see cref="RingSize"/>. A page loads /api/state (messages + files +
/// the current number), then follows the events from that number on: pushed over its WebSocket, or — where a proxy or
/// firewall blocks WebSockets — fetched by long polls that wait up to 25 s for the next one. A page that fell further
/// behind than the ring gets "reset" and loads the state again. Pages send through POST /api/send either way.
/// </summary>
public sealed partial class ShareHub
{
    private const int RingSize = 600;
    private const int MsgBurst = 20;
    private const double MsgPerSec = 2.0;
    private const int MaxWsPerSession = 4, MaxWsPerIp = 8, MaxWsTotal = 64;
    private const int MaxPollsPerSession = 2;
    private const int PollWaitMs = 25_000;
    private const int MaxStateTextBytes = 2 * 1024 * 1024;
    private const long MaxPeerBacklog = 2L * 1024 * 1024;

    private readonly object _evGate = new();
    private long _seq;
    private readonly Queue<(long Seq, byte[] Json)> _ring = new();
    private readonly List<ShareMessage> _messages = new();
    private readonly Dictionary<long, WsPeer> _peers = new();
    private TaskCompletionSource _pulse = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>The messages kept (oldest first).</summary>
    public IReadOnlyList<ShareMessage> Messages()
    {
        lock (_evGate) return _messages.ToArray();
    }

    /// <summary>A message from this device. Throws <see cref="ArgumentException"/> (empty, over 16 KB).</summary>
    public ShareMessage PostFromHost(string text)
    {
        string t = NormalizeText(text);
        if (t.Length == 0) throw new ArgumentException("Type a message first.");
        if (Encoding.UTF8.GetByteCount(t) > MaxMessageBytes) throw new ArgumentException($"A message can be at most {MaxMessageBytes / 1024} KB.");
        return Post(seq => new ShareMessage { Seq = seq, Cid = HostCid, From = _o.HostName, Time = DateTime.Now, Text = t });
    }

    /// <summary>A file this device shares, posted as a download link.</summary>
    public ShareMessage PostFileFromHost(SharedItem item)
        => Post(seq => new ShareMessage
        {
            Seq = seq, Cid = HostCid, From = _o.HostName, Time = DateTime.Now, Kind = ShareMessageKind.File,
            FileId = item.Id, FileName = item.Name, FileSize = item.Size,
        });

    /// <summary>Empties the chat for everyone.</summary>
    public void ClearChat()
        => AppendEvent(seq => HubHttp.Json(w => { w.WriteString("t", "clear"); w.WriteNumber("seq", seq); }), clear: true);

    /// <summary>The shared files changed: pages refresh their list.</summary>
    public void NotifyFilesChanged()
        => AppendEvent(seq => HubHttp.Json(w => { w.WriteString("t", "files"); w.WriteNumber("seq", seq); WriteFiles(w); }));

    private ShareMessage Post(Func<long, ShareMessage> make)
    {
        ShareMessage? made = null;
        AppendEvent(seq =>
        {
            made = make(seq);
            var m = made;
            return HubHttp.Json(w => { w.WriteString("t", "msg"); w.WriteNumber("seq", seq); w.WritePropertyName("m"); WriteMessage(w, m); });
        }, message: () => made);
        return made!;
    }

    // The app is told inside the lock (its callbacks only queue): it sees the same order as the pages, and a message
    // right after "clear" isn't cleared with it.
    private void AppendEvent(Func<long, byte[]> build, Func<ShareMessage?>? message = null, bool clear = false)
    {
        TaskCompletionSource pulse;
        lock (_evGate)
        {
            long seq = ++_seq;
            byte[] json = build(seq);
            _ring.Enqueue((seq, json));
            while (_ring.Count > RingSize) _ring.Dequeue();
            if (clear)
            {
                _messages.Clear();
                try { _sink.OnChatCleared(); } catch { }
            }
            if (message?.Invoke() is { } m)
            {
                _messages.Add(m);
                if (_messages.Count > MaxChatHistory) _messages.RemoveRange(0, _messages.Count - MaxChatHistory);
                try { _sink.OnMessage(m); } catch { }
            }
            foreach (var p in _peers.Values) p.Enqueue(seq, json);   // queued only: each peer sends on its own
            pulse = _pulse;
            _pulse = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        }
        pulse.TrySetResult();
    }

    // Under _evGate. Wakes every waiting long poll (they re-check: stopping / logged out).
    private void WakePollsLocked()
    {
        var pulse = _pulse;
        _pulse = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        pulse.TrySetResult();
    }

    // Under _evGate: the events after `since`; reset = the page must load the state again (it fell behind the ring, or
    // its number is from an earlier run).
    private (List<(long Seq, byte[] Json)> Events, long Latest, bool Reset) SinceLocked(long since)
    {
        var list = new List<(long, byte[])>();
        if (since == _seq) return (list, _seq, false);
        if (since > _seq || since < 0) return (list, _seq, true);
        if (_ring.Count == 0 || since < _ring.Peek().Seq - 1) return (list, _seq, true);
        foreach (var e in _ring) if (e.Seq > since) list.Add(e);
        return (list, _seq, false);
    }

    private static long ParseSince(string? s)
        => long.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out long v) ? v : -1;

    // ================================================================ JSON

    private static void WriteMessage(Utf8JsonWriter w, ShareMessage m)
    {
        w.WriteStartObject();
        w.WriteNumber("seq", m.Seq);
        w.WriteString("cid", m.Cid);
        w.WriteString("from", m.From);
        w.WriteBoolean("host", m.IsHost);
        HubHttp.WriteUnixMs(w, "time", m.Time);
        w.WriteString("kind", m.Kind switch { ShareMessageKind.File => "file", ShareMessageKind.Received => "in", _ => "text" });
        if (m.Text.Length > 0) w.WriteString("text", m.Text);
        if (m.FileName is not null)
        {
            w.WriteStartObject("file");
            if (m.FileId is not null) w.WriteString("id", m.FileId);
            w.WriteString("name", m.FileName);
            w.WriteNumber("size", m.FileSize);
            w.WriteEndObject();
        }
        w.WriteEndObject();
    }

    private void WriteFiles(Utf8JsonWriter w)
    {
        w.WriteStartArray("files");
        foreach (var it in _o.Items())
        {
            w.WriteStartObject();
            w.WriteString("id", it.Id);
            w.WriteString("name", it.Name);
            w.WriteNumber("size", it.Size);
            w.WriteEndObject();
        }
        w.WriteEndArray();
    }

    private byte[] StateJson(HubSession s, bool https)
    {
        ShareMessage[] all;
        long seq;
        lock (_evGate)
        {
            all = _messages.ToArray();
            seq = _seq;
        }
        // the newest messages, at most MaxStateTextBytes of text (a phone parses this in one go)
        int from = all.Length;
        long bytes = 0;
        while (from > 0 && bytes + all[from - 1].Text.Length * 3L < MaxStateTextBytes) bytes += all[--from].Text.Length * 3L;
        return HubHttp.Json(w =>
        {
            w.WriteBoolean("ok", true);
            w.WriteNumber("seq", seq);
            WriteMe(w, s);
            w.WriteString("host", _o.HostName);
            w.WriteBoolean("https", https);
            w.WriteBoolean("pin", _o.RequirePin);
            w.WriteStartArray("messages");
            for (int i = from; i < all.Length; i++) WriteMessage(w, all[i]);
            w.WriteEndArray();
            WriteFiles(w);
            w.WriteStartObject("limits");
            w.WriteNumber("msg", MaxMessageBytes);
            w.WriteNumber("upload", MaxUploadBytes);
            w.WriteNumber("chunk", ChunkSize);
            w.WriteEndObject();
        });
    }

    private static byte[] EventsJson(List<(long Seq, byte[] Json)> events, long latest, bool reset)
    {
        var buf = new System.Buffers.ArrayBufferWriter<byte>(256);
        using (var w = new Utf8JsonWriter(buf))
        {
            w.WriteStartObject();
            w.WriteBoolean("ok", true);
            w.WriteNumber("seq", latest);
            w.WriteBoolean("reset", reset);
            w.WriteStartArray("events");
            foreach (var e in events) w.WriteRawValue(e.Json, skipInputValidation: true);
            w.WriteEndArray();
            w.WriteEndObject();
        }
        return buf.WrittenSpan.ToArray();
    }

    /// <summary>Line ends as \n; control characters other than tab / newline dropped; trimmed.</summary>
    internal static string NormalizeText(string? raw)
    {
        if (string.IsNullOrEmpty(raw)) return string.Empty;
        var sb = new StringBuilder(raw.Length);
        for (int i = 0; i < raw.Length; i++)
        {
            char ch = raw[i];
            if (ch == '\r')
            {
                sb.Append('\n');
                if (i + 1 < raw.Length && raw[i + 1] == '\n') i++;
                continue;
            }
            if (ch is '\n' or '\t') { sb.Append(ch); continue; }
            if (ch < 0x20 || ch is >= (char)0x7F and <= (char)0x9F || ch is (char)0x202D or (char)0x202E) continue;
            sb.Append(ch);
        }
        return sb.ToString().Trim();
    }

    // ================================================================ requests

    private async Task<bool> RenameAsync(HubConn c, HubRequest req, HubSession s, CancellationToken ct)
    {
        byte[]? body = req.ContentLength > 0 ? await c.Reader.ReadBodyAsync(req.ContentLength, BodyIdleMs, ct).ConfigureAwait(false) : Array.Empty<byte>();
        if (body is null) return false;
        using var doc = body.Length > 0 ? HubHttp.ParseObject(body) : null;
        if (doc is null) return await JsonAsync(c, req, 400, HubHttp.Error("Bad request."), ct).ConfigureAwait(false);
        string name = CleanName(HubHttp.Str(doc, "name"));
        if (name != s.Name)
        {
            // the setter may add " (guest)" to a name equal to the host's, so log what the name became
            string before = s.Name;
            s.Name = name;
            if (s.Name != before) Log($"{c.Ip}  {Clean(before)} is now {Clean(s.Name)}");
        }
        return await JsonAsync(c, req, 200, HubHttp.Json(w => { w.WriteBoolean("ok", true); WriteMe(w, s); }), ct).ConfigureAwait(false);
    }

    private async Task<bool> SendMessageAsync(HubConn c, HubRequest req, HubSession s, CancellationToken ct)
    {
        byte[]? body = req.ContentLength > 0 ? await c.Reader.ReadBodyAsync(req.ContentLength, BodyIdleMs, ct).ConfigureAwait(false) : Array.Empty<byte>();
        if (body is null) return false;
        using var doc = body.Length > 0 ? HubHttp.ParseObject(body) : null;
        if (doc is null) return await JsonAsync(c, req, 400, HubHttp.Error("Bad request."), ct).ConfigureAwait(false);
        string text = NormalizeText(HubHttp.Str(doc, "text"));
        if (text.Length == 0) return await JsonAsync(c, req, 400, HubHttp.Error("The message is empty."), ct).ConfigureAwait(false);
        if (Encoding.UTF8.GetByteCount(text) > MaxMessageBytes)
            return await JsonAsync(c, req, 413, HubHttp.Error($"A message can be at most {MaxMessageBytes / 1024} KB - send a longer text as a file."), ct).ConfigureAwait(false);
        if (!TakeMessageToken(s))
            return await JsonAsync(c, req, 429, HubHttp.Error("Slow down - too many messages at once.", w => w.WriteNumber("retry", 2)), ct, "Retry-After: 2\r\n").ConfigureAwait(false);
        var m = Post(seq => new ShareMessage { Seq = seq, Cid = s.Cid, From = s.Name, Time = DateTime.Now, Text = text });
        return await JsonAsync(c, req, 200, HubHttp.Json(w => { w.WriteBoolean("ok", true); w.WriteNumber("seq", m.Seq); }), ct).ConfigureAwait(false);
    }

    private static bool TakeMessageToken(HubSession s)
    {
        lock (s)
        {
            long now = Environment.TickCount64;
            s.Tokens = Math.Min(MsgBurst, s.Tokens + (now - s.TokensAt) / 1000.0 * MsgPerSec);
            s.TokensAt = now;
            if (s.Tokens < 1) return false;
            s.Tokens -= 1;
            return true;
        }
    }

    private async Task<bool> PollAsync(HubConn c, HubRequest req, HubSession s, CancellationToken ct)
    {
        if (Interlocked.Increment(ref s.Polls) > MaxPollsPerSession)
        {
            Interlocked.Decrement(ref s.Polls);
            return await JsonAsync(c, req, 429, HubHttp.Error("Too many open polls."), ct).ConfigureAwait(false);
        }
        try
        {
            long since = ParseSince(req.QueryValue("since"));
            (List<(long Seq, byte[] Json)> Events, long Latest, bool Reset) r;
            Task wake;
            lock (_evGate)
            {
                r = SinceLocked(since);
                wake = _pulse.Task;
            }
            if (r.Events.Count == 0 && !r.Reset)
            {
                using var wcts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                await Task.WhenAny(wake, Task.Delay(PollWaitMs, wcts.Token)).ConfigureAwait(false);
                wcts.Cancel();
                if (ct.IsCancellationRequested) return false;
                lock (_evGate) r = SinceLocked(since);
            }
            if (s.Revoked)
                return await JsonAsync(c, req, 401, HubHttp.Error("Enter the PIN.", w => w.WriteBoolean("login", true)), ct).ConfigureAwait(false);
            Volatile.Write(ref s.LastSeen, Environment.TickCount64);
            return await JsonAsync(c, req, 200, EventsJson(r.Events, r.Latest, r.Reset), ct).ConfigureAwait(false);
        }
        finally { Interlocked.Decrement(ref s.Polls); }
    }

    // ================================================================ WebSocket

    private async Task<bool> WebSocketAsync(HubConn c, HubRequest req, CancellationToken ct)
    {
        if (req.Method != "GET" || !WsProtocol.HasToken(req.Header("Upgrade"), "websocket"))
            return await RefuseAsync(c, req, 426, "Upgrade Required", ct, extraHeaders: "Upgrade: websocket\r\n").ConfigureAwait(false);
        if (!SameOrigin(c, req, requireHeader: false))
        {
            Log($"{c.Ip}  WebSocket  → 403 (not from this page)");
            return await RefuseAsync(c, req, 403, "Forbidden", ct, quiet: true).ConfigureAwait(false);
        }
        var s = SessionOf(req);
        if (s is null) return await RefuseAsync(c, req, 401, "Enter the PIN on the page first", ct, quiet: true).ConfigureAwait(false);
        string? key = req.Header("Sec-WebSocket-Key");
        bool keyOk = false;
        try { keyOk = key is not null && Convert.FromBase64String(key.Trim()).Length == 16; } catch { }
        if (!keyOk || !WsProtocol.HasToken(req.Header("Connection"), "upgrade"))
            return await RefuseAsync(c, req, 400, "Bad WebSocket handshake", ct).ConfigureAwait(false);
        if (req.Header("Sec-WebSocket-Version")?.Trim() != "13")
            return await RefuseAsync(c, req, 426, "Upgrade Required", ct, extraHeaders: "Sec-WebSocket-Version: 13\r\n").ConfigureAwait(false);
        lock (_evGate)
        {
            int fromSession = _peers.Values.Count(p => p.Session == s), fromIp = _peers.Values.Count(p => p.Ip == c.Ip);
            if (_peers.Count >= MaxWsTotal || fromSession >= MaxWsPerSession || fromIp >= MaxWsPerIp) key = null;
        }
        if (key is null)
            return await RefuseAsync(c, req, 503, "Too many live connections - the page falls back to polling", ct, quiet: true).ConfigureAwait(false);
        if (!await c.Reader.DrainAsync(req.ContentLength, MaxJsonBody, BodyIdleMs, ct).ConfigureAwait(false)) return false;

        string head = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "
                      + WsProtocol.AcceptFor(key.Trim()) + "\r\nServer: Echoes\r\n\r\n";
        await FileHttpServer.WriteWithTimeout(c.Stream, Encoding.ASCII.GetBytes(head), ct).ConfigureAwait(false);
        await c.Stream.FlushAsync(ct).ConfigureAwait(false);

        byte[] left = c.Reader.TakeBuffered();
        Stream ws = left.Length > 0 ? new PrefixedStream(c.Stream, left) : c.Stream;
        var peer = new WsPeer(s, c.Ip, Interlocked.Increment(ref _nextConn));
        // pages only listen on it (they send through POST /api/send): small messages, anything big ends it
        peer.Conn = new WsConnection(ws, isServer: true, peer, maxMessageBytes: 4096, closeOnOversize: true);
        long since = ParseSince(req.QueryValue("since"));
        lock (_evGate)
        {
            if (ct.IsCancellationRequested) return false;
            var r = SinceLocked(since < 0 ? _seq : since);
            _peers[peer.Key] = peer;
            if (r.Reset) peer.EnqueueRaw(HubHttp.Json(w => { w.WriteString("t", "reset"); w.WriteNumber("seq", r.Latest); }), r.Latest);
            else foreach (var e in r.Events) peer.Enqueue(e.Seq, e.Json);
            peer.Floor(r.Latest);
        }
        Interlocked.Increment(ref s.Ws);
        Volatile.Write(ref s.LastSeen, Environment.TickCount64);
        try
        {
            peer.Conn.Start();
            // Stop closes it ("going away", then Done); the token only backs that up — ending here at once disposed the
            // stream before the close frame was out, and pages said "connection lost" instead of "stopped".
            using (ct.Register(() => _ = Task.Delay(1500).ContinueWith(_ => peer.Done.TrySetResult(), TaskScheduler.Default)))
                await peer.Done.Task.ConfigureAwait(false);
        }
        finally
        {
            lock (_evGate) _peers.Remove(peer.Key);
            Interlocked.Decrement(ref s.Ws);
            Volatile.Write(ref s.LastSeen, Environment.TickCount64);
        }
        return false;   // the connection was the WebSocket's
    }

    /// <summary>One page's WebSocket: events are queued in order and sent by one pump at a time; a page that stops
    /// reading (2 MB waiting) is dropped instead of buffered on.</summary>
    private sealed class WsPeer : IWsSink
    {
        private readonly Queue<byte[]> _q = new();
        private long _qBytes, _lastSeq;
        private bool _pumping;

        public WsPeer(HubSession session, string ip, long key)
        {
            Session = session;
            Ip = ip;
            Key = key;
        }

        public HubSession Session { get; }
        public string Ip { get; }
        public long Key { get; }
        public WsConnection Conn { get; set; } = null!;
        public readonly TaskCompletionSource Done = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void Enqueue(long seq, byte[] json)
        {
            lock (_q)
            {
                if (seq <= _lastSeq) return;
                _lastSeq = seq;
            }
            EnqueueRaw(json, seq);
        }

        /// <summary>Nothing at or below <paramref name="seq"/> is sent from now on (it was in the backlog, or is older).</summary>
        public void Floor(long seq)
        {
            lock (_q) if (seq > _lastSeq) _lastSeq = seq;
        }

        public void EnqueueRaw(byte[] json, long seq)
        {
            bool start = false, drop = false;
            lock (_q)
            {
                if (seq > _lastSeq) _lastSeq = seq;
                if (_qBytes + json.Length > MaxPeerBacklog) drop = true;
                else
                {
                    _q.Enqueue(json);
                    _qBytes += json.Length;
                    if (!_pumping) { _pumping = true; start = true; }
                }
            }
            if (drop) _ = Task.Run(() => Conn.Abort("The page stopped reading its messages."));
            else if (start) _ = Task.Run(PumpAsync);
        }

        private async Task PumpAsync()
        {
            while (true)
            {
                byte[] next;
                lock (_q)
                {
                    if (_q.Count == 0) { _pumping = false; return; }
                    next = _q.Dequeue();
                    _qBytes -= next.Length;
                }
                try { await Conn.SendAsync(WsOpcode.Text, next).ConfigureAwait(false); }
                catch
                {
                    lock (_q) { _q.Clear(); _qBytes = 0; _pumping = false; }
                    return;
                }
            }
        }

        public void Ping()
        {
            try { _ = Conn.PingAsync().ContinueWith(static t => _ = t.Exception, TaskScheduler.Default); } catch { }
        }

        public async Task CloseAsync(int code, string reason)
        {
            try { await Conn.CloseAsync(code, reason, 400).ConfigureAwait(false); } catch { }
            Done.TrySetResult();
        }

        public void OnMessage(WsConnection connection, WsMessage message) => Volatile.Write(ref Session.LastSeen, Environment.TickCount64);
        public void OnControl(WsConnection connection, WsOpcode opcode, byte[] payload, double? rttMs) => Volatile.Write(ref Session.LastSeen, Environment.TickCount64);
        public void OnClosed(WsConnection connection, WsCloseInfo info) => Done.TrySetResult();
    }
}
