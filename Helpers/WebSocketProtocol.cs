using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>RFC 6455 frame opcodes.</summary>
public enum WsOpcode : byte { Continuation = 0, Text = 1, Binary = 2, Close = 8, Ping = 9, Pong = 10 }

/// <summary>One complete data message (all its frames joined). <see cref="Data"/> holds at most the connection's message
/// cap; <see cref="Length"/> is the whole size.</summary>
public sealed class WsMessage
{
    public WsMessage(WsOpcode opcode, byte[] data, long length, int frames)
    {
        Opcode = opcode;
        Data = data;
        Length = length;
        Frames = frames;
    }

    public WsOpcode Opcode { get; }
    public byte[] Data { get; }
    public long Length { get; }
    public int Frames { get; }
    public bool IsText => Opcode == WsOpcode.Text;
    public bool Truncated => Data.Length < Length;
}

/// <summary>How a connection ended. <see cref="Code"/> is the close code received (or 1006 when there was none).</summary>
public sealed record WsCloseInfo(int Code, string Reason, bool ByPeer, bool Clean, string? Error)
{
    /// <summary>"1000 normal closure" · "4001" · "1006 abnormal closure".</summary>
    public string CodeText => WsProtocol.CloseCodeText(Code);
}

/// <summary>Where a <see cref="WsConnection"/> reports what happens. Called on the connection's read thread.</summary>
public interface IWsSink
{
    void OnMessage(WsConnection connection, WsMessage message);
    /// <summary>A ping or pong arrived. <paramref name="rttMs"/>: for a pong answering our ping, the round trip.</summary>
    void OnControl(WsConnection connection, WsOpcode opcode, byte[] payload, double? rttMs);
    /// <summary>Exactly once, when the connection is over (closed by either side, or dropped).</summary>
    void OnClosed(WsConnection connection, WsCloseInfo info);
}

/// <summary>
/// Handshake helpers and code names shared by the WebSocket client (Socket tool) and the request catcher's WebSocket
/// echo server.
/// </summary>
public static class WsProtocol
{
    private const string Guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    /// <summary>A fresh Sec-WebSocket-Key (16 random bytes, base64).</summary>
    public static string NewKey()
    {
        Span<byte> b = stackalloc byte[16];
        RandomNumberGenerator.Fill(b);
        return Convert.ToBase64String(b);
    }

    /// <summary>Sec-WebSocket-Accept for a key: base64(SHA-1(key + GUID)).</summary>
    public static string AcceptFor(string key)
        => Convert.ToBase64String(SHA1.HashData(Encoding.ASCII.GetBytes(key.Trim() + Guid)));

    /// <summary>"1000 normal closure", "1001 going away" … ; app codes (3000–4999) as the bare number.</summary>
    public static string CloseCodeText(int code) => code switch
    {
        1000 => "1000 normal closure",
        1001 => "1001 going away",
        1002 => "1002 protocol error",
        1003 => "1003 unsupported data",
        1005 => "1005 no status code",
        1006 => "1006 abnormal closure",
        1007 => "1007 invalid payload data",
        1008 => "1008 policy violation",
        1009 => "1009 message too big",
        1010 => "1010 mandatory extension",
        1011 => "1011 internal server error",
        1012 => "1012 service restart",
        1013 => "1013 try again later",
        1014 => "1014 bad gateway",
        1015 => "1015 TLS handshake failure",
        _ => code.ToString(System.Globalization.CultureInfo.InvariantCulture),
    };

    /// <summary>Codes a close frame may carry (RFC 6455 7.4 + the IANA registry).</summary>
    public static bool IsValidWireCode(int code)
        => code is >= 1000 and <= 1003 or >= 1007 and <= 1014 or >= 3000 and <= 4999;

    /// <summary>A header token (RFC 7230): letters, digits and !#$%&amp;'*+-.^_`|~.</summary>
    public static bool IsToken(string s)
    {
        if (s.Length == 0) return false;
        foreach (char c in s)
            if (!(c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9'
                  || c is '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or '^' or '_' or '`' or '|' or '~'))
                return false;
        return true;
    }

    /// <summary>True when a comma-separated header value (Connection, Upgrade) holds <paramref name="token"/>.</summary>
    public static bool HasToken(string? headerValue, string token)
    {
        if (string.IsNullOrEmpty(headerValue)) return false;
        foreach (var part in headerValue.Split(','))
            if (part.Trim().Equals(token, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    /// <summary>At most <paramref name="max"/> characters, "…" when cut (never half a surrogate pair).</summary>
    public static string Short(string? s, int max)
    {
        if (string.IsNullOrEmpty(s) || s.Length <= max) return s ?? string.Empty;
        int cut = max - 1;
        if (cut > 0 && char.IsHighSurrogate(s[cut - 1])) cut--;
        return s[..cut] + "…";
    }

    /// <summary>Strict UTF-8 check; a sequence cut off at the very end counts as valid when <paramref name="allowCutEnd"/>.</summary>
    public static bool IsValidUtf8(ReadOnlySpan<byte> data, bool allowCutEnd)
    {
        int i = 0;
        while (i < data.Length)
        {
            var st = Rune.DecodeFromUtf8(data[i..], out _, out int used);
            if (st == OperationStatus.Done) { i += used; continue; }
            return st == OperationStatus.NeedMoreData && allowCutEnd;
        }
        return true;
    }
}

/// <summary>
/// One WebSocket connection over an already-upgraded stream: RFC 6455 framing (masking, fragmentation, control frames,
/// the close handshake), no extensions. Used for both ends — the client masks what it sends and refuses masked frames,
/// the server the other way round. A read loop on the thread pool reports to an <see cref="IWsSink"/>; pings are
/// answered automatically. Messages larger than the cap are kept up to the cap (and counted) or, with
/// <c>closeOnOversize</c>, end the connection with 1009.
/// </summary>
public sealed class WsConnection : IDisposable
{
    private const int MaxControlPayload = 125;
    private const int WriteTimeoutMs = 30_000;
    private const int MaxPendingPings = 32;

    private readonly Stream _stream;
    private readonly bool _isServer;
    private readonly int _maxMessage;
    private readonly bool _closeOnOversize;
    private readonly IWsSink _sink;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly CancellationTokenSource _cts = new();
    private readonly ConcurrentDictionary<string, long> _pings = new(StringComparer.Ordinal);
    private readonly TaskCompletionSource _readDone = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _closeSent;        // 1 once a close frame went out
    private int _ended;            // 1 once OnClosed fired
    private int _pingSeq;
    private long _in, _out;
    private long _pendingSend;     // payload bytes waiting for (or in) a write
    private (int Code, string Reason)? _sentClose;

    public WsConnection(Stream stream, bool isServer, IWsSink sink, int maxMessageBytes, bool closeOnOversize = false)
    {
        _stream = stream;
        _isServer = isServer;
        _sink = sink;
        _maxMessage = Math.Max(1024, maxMessageBytes);
        _closeOnOversize = closeOnOversize;
    }

    /// <summary>Free for the caller (the catcher keeps its client record here).</summary>
    public object? Tag { get; set; }
    public long BytesIn => Interlocked.Read(ref _in);
    public long BytesOut => Interlocked.Read(ref _out);
    public bool IsOpen => Volatile.Read(ref _closeSent) == 0 && Volatile.Read(ref _ended) == 0;
    /// <summary>Payload bytes queued for sending and not written yet (a peer that doesn't read makes this grow).</summary>
    public long PendingSendBytes => Interlocked.Read(ref _pendingSend);
    public int MaxMessageBytes => _maxMessage;

    /// <summary>Starts the read loop.</summary>
    public void Start() => _ = Task.Run(ReadLoopAsync);

    // ================================================================ reading

    private async Task ReadLoopAsync()
    {
        var ct = _cts.Token;
        var head = new byte[14];
        byte[]? msg = null;            // the message being assembled (capped)
        int msgLen = 0;                // bytes kept
        long msgTotal = 0;             // bytes received for it
        int msgFrames = 0;
        WsOpcode msgOp = WsOpcode.Continuation;
        bool inMessage = false;
        try
        {
            while (true)
            {
                if (!await ReadExactAsync(head, 0, 2, ct).ConfigureAwait(false))
                {
                    End(new WsCloseInfo(1006, "", true, false, Volatile.Read(ref _closeSent) != 0
                        ? null : "The connection dropped without a close frame."));
                    return;
                }
                bool fin = (head[0] & 0x80) != 0;
                int rsv = head[0] & 0x70;
                var op = (WsOpcode)(head[0] & 0x0F);
                bool masked = (head[1] & 0x80) != 0;
                long len = head[1] & 0x7F;

                if (rsv != 0) { await FailAsync(1002, "A frame had reserved bits set (an extension nobody agreed on).").ConfigureAwait(false); return; }
                if (op is not (WsOpcode.Continuation or WsOpcode.Text or WsOpcode.Binary or WsOpcode.Close or WsOpcode.Ping or WsOpcode.Pong))
                { await FailAsync(1002, $"Unknown frame opcode 0x{(int)op:x}.").ConfigureAwait(false); return; }
                if (masked != _isServer)
                {
                    await FailAsync(1002, _isServer ? "The client sent an unmasked frame (clients must mask)." : "The server sent a masked frame (servers must not mask).").ConfigureAwait(false);
                    return;
                }
                if (len == 126)
                {
                    if (!await ReadExactAsync(head, 2, 2, ct).ConfigureAwait(false)) { Dropped(); return; }
                    len = BinaryPrimitives.ReadUInt16BigEndian(head.AsSpan(2));
                }
                else if (len == 127)
                {
                    if (!await ReadExactAsync(head, 2, 8, ct).ConfigureAwait(false)) { Dropped(); return; }
                    ulong l = BinaryPrimitives.ReadUInt64BigEndian(head.AsSpan(2));
                    if (l > long.MaxValue) { await FailAsync(1002, "A frame declared an impossible length.").ConfigureAwait(false); return; }
                    len = (long)l;
                }
                byte[] maskArr = Array.Empty<byte>();
                if (masked)
                {
                    if (!await ReadExactAsync(head, 10, 4, ct).ConfigureAwait(false)) { Dropped(); return; }
                    maskArr = new byte[] { head[10], head[11], head[12], head[13] };
                }

                bool control = (int)op >= 8;
                if (control)
                {
                    if (!fin || len > MaxControlPayload)
                    {
                        await FailAsync(1002, "A control frame was fragmented or longer than 125 bytes.").ConfigureAwait(false);
                        return;
                    }
                    var payload = new byte[len];
                    if (len > 0 && !await ReadExactAsync(payload, 0, (int)len, ct).ConfigureAwait(false)) { Dropped(); return; }
                    if (masked) Unmask(payload, 0, payload.Length, maskArr, 0);
                    Interlocked.Add(ref _in, 2 + len);
                    if (!await HandleControlAsync(op, payload).ConfigureAwait(false)) return;
                    continue;
                }

                // data frames
                if (op == WsOpcode.Continuation)
                {
                    if (!inMessage) { await FailAsync(1002, "A continuation frame arrived with no message to continue.").ConfigureAwait(false); return; }
                }
                else
                {
                    if (inMessage) { await FailAsync(1002, "A new message started before the previous one was finished.").ConfigureAwait(false); return; }
                    inMessage = true;
                    msgOp = op;
                    msgLen = 0;
                    msgTotal = 0;
                    msgFrames = 0;
                    msg = null;
                }
                msgFrames++;
                if (_closeOnOversize && msgTotal + len > _maxMessage)
                {
                    await FailAsync(1009, $"A message was larger than {SocketPayload.FormatBytes(_maxMessage)}.").ConfigureAwait(false);
                    return;
                }

                // payload: keep up to the cap, count (and skip) the rest
                long remaining = len;
                long frameOffset = 0;
                while (remaining > 0)
                {
                    int room = _maxMessage - msgLen;
                    if (room > 0)
                    {
                        int want = (int)Math.Min(remaining, Math.Min(room, 64 * 1024));
                        msg = Grow(msg, msgLen + want);
                        int n = await _stream.ReadAsync(msg.AsMemory(msgLen, want), ct).ConfigureAwait(false);
                        if (n <= 0) { Dropped(); return; }
                        if (masked) Unmask(msg, msgLen, n, maskArr, frameOffset);
                        msgLen += n;
                        remaining -= n;
                        frameOffset += n;
                    }
                    else
                    {
                        var sink = ArrayPool<byte>.Shared.Rent((int)Math.Min(remaining, 64 * 1024));
                        try
                        {
                            int n = await _stream.ReadAsync(sink.AsMemory(0, (int)Math.Min(remaining, sink.Length)), ct).ConfigureAwait(false);
                            if (n <= 0) { Dropped(); return; }
                            remaining -= n;
                            frameOffset += n;
                        }
                        finally { ArrayPool<byte>.Shared.Return(sink); }
                    }
                }
                msgTotal += len;
                Interlocked.Add(ref _in, len + 2);

                if (fin)
                {
                    inMessage = false;
                    byte[] data = msg is null ? Array.Empty<byte>() : msgLen == msg.Length ? msg : msg.AsSpan(0, msgLen).ToArray();
                    msg = null;
                    if (msgOp == WsOpcode.Text && !WsProtocol.IsValidUtf8(data, allowCutEnd: msgTotal > msgLen))
                    {
                        await FailAsync(1007, "A text message wasn't valid UTF-8.").ConfigureAwait(false);
                        return;
                    }
                    if (Volatile.Read(ref _closeSent) == 0 || !_isServer)
                        _sink.OnMessage(this, new WsMessage(msgOp, data, msgTotal, msgFrames));
                }
            }
        }
        catch (Exception ex)
        {
            if (Volatile.Read(ref _ended) != 0) return;
            bool closing = Volatile.Read(ref _closeSent) != 0;
            End(new WsCloseInfo(1006, "", true, false, closing || _cts.IsCancellationRequested
                ? null : "Connection lost: " + SocketErrors.Describe(ex, SocketAction.Receive, "the server")));
        }
        finally
        {
            _readDone.TrySetResult();
        }
    }

    private void Dropped()
        => End(new WsCloseInfo(1006, "", true, false, Volatile.Read(ref _closeSent) != 0 ? null : "The connection dropped in the middle of a frame."));

    private static byte[] Grow(byte[]? buf, int need)
    {
        if (buf != null && buf.Length >= need) return buf;
        int size = Math.Max(need, buf == null ? 4096 : Math.Min(int.MaxValue / 2, buf.Length * 2));
        var nb = new byte[size];
        if (buf != null) Buffer.BlockCopy(buf, 0, nb, 0, buf.Length);
        return nb;
    }

    private static void Unmask(byte[] data, int offset, int count, byte[] mask, long maskOffset)
    {
        for (int i = 0; i < count; i++)
            data[offset + i] ^= mask[(int)((maskOffset + i) & 3)];
    }

    private async Task<bool> ReadExactAsync(byte[] buf, int offset, int count, CancellationToken ct)
    {
        int got = 0;
        while (got < count)
        {
            int n = await _stream.ReadAsync(buf.AsMemory(offset + got, count - got), ct).ConfigureAwait(false);
            if (n <= 0) return false;
            got += n;
        }
        return true;
    }

    /// <summary>False when the connection is over (a close frame finished it).</summary>
    private async Task<bool> HandleControlAsync(WsOpcode op, byte[] payload)
    {
        switch (op)
        {
            case WsOpcode.Ping:
                _sink.OnControl(this, op, payload, null);
                if (Volatile.Read(ref _closeSent) == 0) await SendFrameAsync(WsOpcode.Pong, payload, quiet: true).ConfigureAwait(false);
                return true;
            case WsOpcode.Pong:
            {
                double? rtt = null;
                string key = Convert.ToHexString(payload);
                if (_pings.TryRemove(key, out long t0)) rtt = Stopwatch.GetElapsedTime(t0).TotalMilliseconds;
                _sink.OnControl(this, op, payload, rtt);
                return true;
            }
            default:   // close
            {
                int code = 1005;
                string reason = string.Empty;
                if (payload.Length == 1) { await FailAsync(1002, "A close frame had a 1-byte payload.").ConfigureAwait(false); return false; }
                if (payload.Length >= 2)
                {
                    code = BinaryPrimitives.ReadUInt16BigEndian(payload);
                    if (!WsProtocol.IsValidWireCode(code)) { await FailAsync(1002, $"A close frame carried the reserved code {code}.").ConfigureAwait(false); return false; }
                    if (!WsProtocol.IsValidUtf8(payload.AsSpan(2), allowCutEnd: false)) { await FailAsync(1007, "A close reason wasn't valid UTF-8.").ConfigureAwait(false); return false; }
                    reason = Encoding.UTF8.GetString(payload, 2, payload.Length - 2);
                }
                if (Interlocked.Exchange(ref _closeSent, 1) == 0)
                {
                    // the other side started it: answer with the same code, then hang up
                    await SendCloseFrameAsync(code == 1005 ? 1000 : code, string.Empty, force: true).ConfigureAwait(false);
                    End(new WsCloseInfo(code, reason, true, true, null));
                }
                else
                {
                    // the answer to our close
                    End(new WsCloseInfo(code, reason, false, true, null));
                }
                Teardown();
                return false;
            }
        }
    }

    /// <summary>A protocol violation by the other side: send a close with <paramref name="code"/>, report, hang up.</summary>
    private async Task FailAsync(int code, string why)
    {
        if (Interlocked.Exchange(ref _closeSent, 1) == 0)
            await SendCloseFrameAsync(code, TrimReason(why), force: true).ConfigureAwait(false);
        End(new WsCloseInfo(code, string.Empty, false, false, why));
        // The other side may still be sending (the rest of an oversized message): hanging up with unread bytes makes the
        // OS send a reset, which can destroy our close frame before it's read. Read and drop what comes for a moment
        // (the read loop's own thread — nothing else reads), then hang up.
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
            cts.CancelAfter(2000);
            var buf = ArrayPool<byte>.Shared.Rent(16 * 1024);
            try
            {
                long total = 0;
                while (total < 8L * 1024 * 1024)
                {
                    int n = await _stream.ReadAsync(buf.AsMemory(), cts.Token).ConfigureAwait(false);
                    if (n <= 0) break;
                    total += n;
                }
            }
            finally { ArrayPool<byte>.Shared.Return(buf); }
        }
        catch { /* gone or timed out */ }
        Teardown();
    }

    private void End(WsCloseInfo info)
    {
        if (Interlocked.Exchange(ref _ended, 1) != 0) return;
        try { _sink.OnClosed(this, info); } catch { }
    }

    // ================================================================ sending

    /// <summary>Sends one text or binary message as a single frame. Throws <see cref="IOException"/> worded for the user.</summary>
    public Task SendAsync(WsOpcode opcode, byte[] data)
    {
        if (opcode is not (WsOpcode.Text or WsOpcode.Binary)) throw new ArgumentException("Only text or binary messages.", nameof(opcode));
        if (!IsOpen) throw new IOException("The connection is closed.");
        return SendFrameAsync(opcode, data, quiet: false);
    }

    /// <summary>Sends a ping; the matching pong reports the round trip. Payload: up to 125 bytes (null = a numbered one).</summary>
    public async Task<byte[]> PingAsync(byte[]? payload = null)
    {
        if (!IsOpen) throw new IOException("The connection is closed.");
        payload ??= Encoding.ASCII.GetBytes("echoes-ping-" + Interlocked.Increment(ref _pingSeq).ToString(System.Globalization.CultureInfo.InvariantCulture));
        if (payload.Length > MaxControlPayload) throw new ArgumentException("A ping carries at most 125 bytes.");
        if (_pings.Count >= MaxPendingPings) _pings.Clear();   // a peer that never answers: don't grow
        _pings[Convert.ToHexString(payload)] = Stopwatch.GetTimestamp();
        await SendFrameAsync(WsOpcode.Ping, payload, quiet: false).ConfigureAwait(false);
        return payload;
    }

    /// <summary>
    /// Starts the close handshake (code + reason) and waits up to <paramref name="timeoutMs"/> for the other side's
    /// close; then hangs up either way. <see cref="IWsSink.OnClosed"/> reports how it went.
    /// </summary>
    public async Task CloseAsync(int code, string reason, int timeoutMs = 3000)
    {
        if (Interlocked.Exchange(ref _closeSent, 1) == 0)
        {
            _sentClose = (code, reason);
            await SendCloseFrameAsync(code, TrimReason(reason), force: true).ConfigureAwait(false);
            var done = await Task.WhenAny(_readDone.Task, Task.Delay(timeoutMs)).ConfigureAwait(false);
            if (done != _readDone.Task)
                End(new WsCloseInfo(code, reason, false, false, "The other side didn't answer the close within " + (timeoutMs / 1000) + " s."));
        }
        Teardown();
        // the read loop may still be unwinding after the teardown: give it a moment to report
        await Task.WhenAny(_readDone.Task, Task.Delay(500)).ConfigureAwait(false);
        End(new WsCloseInfo(code, reason, false, false, null));
    }

    /// <summary>The code / reason this side sent, when it started the close.</summary>
    public (int Code, string Reason)? SentClose => _sentClose;

    /// <summary>Hangs up at once (no close handshake). Reports 1006 (with <paramref name="why"/>) when nothing was
    /// reported yet.</summary>
    public void Abort(string? why = null)
    {
        Interlocked.Exchange(ref _closeSent, 1);
        Teardown();
        End(new WsCloseInfo(1006, string.Empty, false, false, why));
    }

    private static string TrimReason(string reason)
    {
        // a close payload is at most 125 bytes: 2 for the code, 123 for the UTF-8 reason
        if (Encoding.UTF8.GetByteCount(reason) <= 123) return reason;
        var sb = new StringBuilder();
        foreach (var r in reason.EnumerateRunes())
        {
            if (Encoding.UTF8.GetByteCount(sb.ToString() + r) > 123) break;
            sb.Append(r.ToString());
        }
        return sb.ToString();
    }

    private Task SendCloseFrameAsync(int code, string reason, bool force)
    {
        byte[] r = Encoding.UTF8.GetBytes(reason);
        var payload = new byte[2 + r.Length];
        BinaryPrimitives.WriteUInt16BigEndian(payload, (ushort)code);
        r.CopyTo(payload, 2);
        return SendFrameAsync(WsOpcode.Close, payload, quiet: true, force: force);
    }

    private async Task SendFrameAsync(WsOpcode op, byte[] payload, bool quiet, bool force = false)
    {
        if (!force && op != WsOpcode.Close && Volatile.Read(ref _closeSent) != 0 && op != WsOpcode.Pong)
        {
            if (quiet) return;
            throw new IOException("The connection is closing.");
        }
        // Counted while waiting, and the frame (a copy of the payload) is built only once the lock is held: senders
        // queued behind a peer that doesn't read hold a reference to the payload, not a copy each.
        Interlocked.Add(ref _pendingSend, payload.Length);
        bool locked = false;
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
            cts.CancelAfter(WriteTimeoutMs);
            await _writeLock.WaitAsync(cts.Token).ConfigureAwait(false);
            locked = true;
            byte[] frame = BuildFrame(op, payload, mask: !_isServer);
            await _stream.WriteAsync(frame, cts.Token).ConfigureAwait(false);
            await _stream.FlushAsync(cts.Token).ConfigureAwait(false);
            Interlocked.Add(ref _out, frame.Length);
        }
        catch (Exception ex)
        {
            if (quiet) return;
            if (ex is OperationCanceledException && !_cts.IsCancellationRequested)
                throw new IOException("Send timed out — the other side isn't reading.", ex);
            if (_cts.IsCancellationRequested || Volatile.Read(ref _ended) != 0) throw new IOException("The connection is closed.", ex);
            throw new IOException("Send failed: " + SocketErrors.Describe(ex, SocketAction.Send, "the other side"), ex);
        }
        finally
        {
            if (locked) _writeLock.Release();
            Interlocked.Add(ref _pendingSend, -payload.Length);
        }
    }

    /// <summary>One complete frame (FIN set): header, the client's mask key, the (masked) payload.</summary>
    internal static byte[] BuildFrame(WsOpcode op, ReadOnlySpan<byte> payload, bool mask)
    {
        int len = payload.Length;
        int headLen = 2 + (len < 126 ? 0 : len <= ushort.MaxValue ? 2 : 8) + (mask ? 4 : 0);
        var frame = new byte[headLen + len];
        frame[0] = (byte)(0x80 | (int)op);
        int p = 2;
        if (len < 126) frame[1] = (byte)len;
        else if (len <= ushort.MaxValue) { frame[1] = 126; BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(2), (ushort)len); p = 4; }
        else { frame[1] = 127; BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(2), (ulong)len); p = 10; }
        if (!mask)
        {
            payload.CopyTo(frame.AsSpan(p));
            return frame;
        }
        frame[1] |= 0x80;
        Span<byte> key = frame.AsSpan(p, 4);
        RandomNumberGenerator.Fill(key);
        p += 4;
        for (int i = 0; i < len; i++) frame[p + i] = (byte)(payload[i] ^ key[i & 3]);
        return frame;
    }

    private int _torn;

    private void Teardown()
    {
        if (Interlocked.Exchange(ref _torn, 1) != 0) return;
        try { _cts.Cancel(); } catch { }
        try { _stream.Dispose(); } catch { }
    }

    public void Dispose() => Abort();
}

/// <summary>A stream that first returns bytes already read past the HTTP handshake head, then the inner stream.</summary>
internal sealed class PrefixedStream : Stream
{
    private readonly Stream _inner;
    private byte[] _prefix;
    private int _pos;

    public PrefixedStream(Stream inner, byte[] prefix)
    {
        _inner = inner;
        _prefix = prefix;
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() => _inner.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_pos < _prefix.Length)
        {
            int n = Math.Min(count, _prefix.Length - _pos);
            Buffer.BlockCopy(_prefix, _pos, buffer, offset, n);
            Advance(n);
            return n;
        }
        return _inner.Read(buffer, offset, count);
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_pos < _prefix.Length)
        {
            int n = Math.Min(buffer.Length, _prefix.Length - _pos);
            _prefix.AsSpan(_pos, n).CopyTo(buffer.Span);
            Advance(n);
            return new ValueTask<int>(n);
        }
        return _inner.ReadAsync(buffer, cancellationToken);
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    private void Advance(int n)
    {
        _pos += n;
        if (_pos >= _prefix.Length) { _prefix = Array.Empty<byte>(); _pos = 0; }
    }

    public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => _inner.WriteAsync(buffer, cancellationToken);
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => _inner.WriteAsync(buffer, offset, count, cancellationToken);

    protected override void Dispose(bool disposing)
    {
        if (disposing) _inner.Dispose();
        base.Dispose(disposing);
    }
}
