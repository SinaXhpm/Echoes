using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>Which anti-DPI trick got a ClientHello past the filter.</summary>
public enum DoctorDpiTrick
{
    /// <summary>The ClientHello split across TCP segments (the first few bytes, a short pause, then the rest).</summary>
    TcpSegments,
    /// <summary>The ClientHello split into two TLS records, so the name spans the record boundary.</summary>
    TlsRecordSplit,
    /// <summary>The server name sent in mixed letter-case (a filter that matches exact case misses it).</summary>
    SniCaseMix,
}

/// <summary>One anti-DPI attempt: did a split / disguised ClientHello get an answer the plain one didn't.</summary>
public sealed record DoctorDpiAttempt(DoctorDpiTrick Trick, bool Answered, double Ms, string? Note);

/// <summary>What the anti-DPI retries found when the plain handshake with the name was cut.</summary>
public sealed class DoctorDpiResult
{
    public bool Ran { get; set; }
    public List<DoctorDpiAttempt> Attempts { get; } = new();
    /// <summary>The first trick that got an answer, or null when none did.</summary>
    public DoctorDpiTrick? Working => Attempts.FirstOrDefault(a => a.Answered)?.Trick;
    public bool AnyWorked => Attempts.Any(a => a.Answered);

    public static string Name(DoctorDpiTrick t) => t switch
    {
        DoctorDpiTrick.TcpSegments => "split across TCP segments",
        DoctorDpiTrick.TlsRecordSplit => "split into two TLS records",
        _ => "name in mixed letter-case",
    };

    /// <summary>Short label for the trace / report.</summary>
    public static string Short(DoctorDpiTrick t) => t switch
    {
        DoctorDpiTrick.TcpSegments => "TCP fragment",
        DoctorDpiTrick.TlsRecordSplit => "TLS record split",
        _ => "SNI case-mix",
    };
}

/// <summary>Whether UDP/443 (QUIC, and so HTTP/3, Hysteria2, TUIC) is open from here.</summary>
public sealed class DoctorQuicResult
{
    public bool Ran { get; set; }
    /// <summary>A QUIC packet came back (a Version Negotiation to the greased version): UDP/443 is open.</summary>
    public bool Open { get; set; }
    public double Ms { get; set; }
    public string? Note { get; set; }
}

/// <summary>
/// The Doctor's deep-probe helpers, added for the granular trace: anti-DPI ClientHello tricks (used only when the plain
/// TLS handshake with the site's name is cut but the address answers otherwise) and a QUIC reachability probe on UDP/443.
/// It reuses <see cref="TlsHello.BuildClientHello"/> read-only to build the raw hellos; the fragmentation is done here, by
/// how the bytes are written to the socket, so <c>TlsHello</c> is left untouched. Plain sockets only — AOT- and
/// Android-safe (UDP needs only the INTERNET permission; no raw sockets).
/// </summary>
public static class DoctorDpi
{
    // ------------------------------------------------------------------ anti-DPI TLS tricks

    /// <summary>
    /// Tries, in parallel, each anti-DPI way of sending the ClientHello to <paramref name="addr"/>:<paramref name="port"/>
    /// with the real <paramref name="sni"/>, and records which ones got a TLS answer the plain hello didn't. Each attempt
    /// is a fresh connection with a short deadline.
    /// </summary>
    public static async Task<DoctorDpiResult> TryBypassAsync(IPAddress addr, int port, string sni, CancellationToken ct)
    {
        var res = new DoctorDpiResult { Ran = true };
        var tasks = new[]
        {
            AttemptAsync(DoctorDpiTrick.TcpSegments, addr, port, sni, ct),
            AttemptAsync(DoctorDpiTrick.TlsRecordSplit, addr, port, sni, ct),
            AttemptAsync(DoctorDpiTrick.SniCaseMix, addr, port, sni, ct),
        };
        var done = await Task.WhenAll(tasks).ConfigureAwait(false);
        // keep the fixed order (TCP fragment, record split, case-mix) so the verdict names the simplest working one
        res.Attempts.AddRange(done);
        return res;
    }

    private static async Task<DoctorDpiAttempt> AttemptAsync(DoctorDpiTrick trick, IPAddress addr, int port, string sni, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(4500);
            using var s = new Socket(addr.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            await s.ConnectAsync(new IPEndPoint(addr, port), cts.Token).ConfigureAwait(false);
            await using var ns = new NetworkStream(s, ownsSocket: false);

            byte[] hello = trick == DoctorDpiTrick.SniCaseMix
                ? TlsHello.BuildClientHello(TlsHello.Tls12, MixCase(sni), statusRequest: false)
                : TlsHello.BuildClientHello(TlsHello.Tls12, sni, statusRequest: false);

            switch (trick)
            {
                case DoctorDpiTrick.TcpSegments:
                    await WriteSplitTcpAsync(ns, hello, cts.Token).ConfigureAwait(false);
                    break;
                case DoctorDpiTrick.TlsRecordSplit:
                    await WriteSplitRecordsAsync(ns, hello, cts.Token).ConfigureAwait(false);
                    break;
                default:
                    await ns.WriteAsync(hello, cts.Token).ConfigureAwait(false);
                    await ns.FlushAsync(cts.Token).ConfigureAwait(false);
                    break;
            }

            bool answered = await ReadAnswerAsync(ns, cts.Token).ConfigureAwait(false);
            return new DoctorDpiAttempt(trick, answered, sw.Elapsed.TotalMilliseconds, answered ? null : "cut again");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { return new DoctorDpiAttempt(trick, false, sw.Elapsed.TotalMilliseconds, "no answer"); }
        catch (Exception e) { return new DoctorDpiAttempt(trick, false, sw.Elapsed.TotalMilliseconds, DoctorDns.Short(e)); }
    }

    // trick (a): the record goes out in two TCP segments — the first few bytes, a short pause (so they ride their own
    // packet), then the rest. A DPI box that only inspects the first segment never sees the name.
    private static async Task WriteSplitTcpAsync(Stream s, byte[] hello, CancellationToken ct)
    {
        int first = Math.Clamp(hello.Length / 8, 5, 40);
        await s.WriteAsync(hello.AsMemory(0, first), ct).ConfigureAwait(false);
        await s.FlushAsync(ct).ConfigureAwait(false);
        await Task.Delay(40, ct).ConfigureAwait(false);
        await s.WriteAsync(hello.AsMemory(first), ct).ConfigureAwait(false);
        await s.FlushAsync(ct).ConfigureAwait(false);
    }

    // trick (b): the one ClientHello handshake is carried in two TLS records, so the name falls in the second record.
    // A DPI box that parses one record at a time can't reassemble the name.
    private static async Task WriteSplitRecordsAsync(Stream s, byte[] hello, CancellationToken ct)
    {
        // hello = [22, 03, 01, len_hi, len_lo, <handshake bytes>]
        if (hello.Length < 11) { await s.WriteAsync(hello, ct).ConfigureAwait(false); await s.FlushAsync(ct).ConfigureAwait(false); return; }
        var hs = hello.AsMemory(5);
        int cut = Math.Clamp(hs.Length / 3, 6, 48);   // early split: the name (in the extensions) stays in record two
        byte[] rec1 = Record(hs.Span[..cut]);
        byte[] rec2 = Record(hs.Span[cut..]);
        await s.WriteAsync(rec1, ct).ConfigureAwait(false);
        await s.FlushAsync(ct).ConfigureAwait(false);
        await Task.Delay(20, ct).ConfigureAwait(false);
        await s.WriteAsync(rec2, ct).ConfigureAwait(false);
        await s.FlushAsync(ct).ConfigureAwait(false);

        static byte[] Record(ReadOnlySpan<byte> payload)
        {
            var r = new byte[5 + payload.Length];
            r[0] = 22; r[1] = 0x03; r[2] = 0x01;
            r[3] = (byte)(payload.Length >> 8); r[4] = (byte)payload.Length;
            payload.CopyTo(r.AsSpan(5));
            return r;
        }
    }

    // "ExAmple.cOm" — flip the case of some letters; the name still resolves, but an exact-case filter misses it.
    private static string MixCase(string host)
    {
        var c = host.ToCharArray();
        for (int i = 0; i < c.Length; i++)
            if (char.IsLetter(c[i])) c[i] = (i & 1) == 0 ? char.ToUpperInvariant(c[i]) : char.ToLowerInvariant(c[i]);
        return new string(c);
    }

    // true when the server's TLS answered (a record of type 20-23 with a TLS version byte), false on reset / silence.
    private static async Task<bool> ReadAnswerAsync(Stream s, CancellationToken ct)
    {
        var head = new byte[5];
        int n = 0;
        try
        {
            while (n < 5)
            {
                int r = await s.ReadAsync(head.AsMemory(n, 5 - n), ct).ConfigureAwait(false);
                if (r == 0) return false;   // EOF: the connection was closed with no answer
                n += r;
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return false; }   // reset, or silence until the deadline
        return head[0] is 20 or 21 or 22 or 23 && head[1] == 3;
    }

    // ------------------------------------------------------------------ QUIC / UDP 443

    /// <summary>
    /// Sends one QUIC long-header Initial with a reserved "greasing" version (0x?a?a?a?a) to
    /// <paramref name="addr"/>:<paramref name="port"/>. A server that speaks QUIC must answer an unknown version with a
    /// Version Negotiation packet — any datagram back means UDP/<paramref name="port"/> is open (so HTTP/3, Hysteria2 and
    /// TUIC can work); silence means it's blocked. Light: one packet, a short wait, a plain UDP socket.
    /// </summary>
    public static async Task<DoctorQuicResult> QuicProbeAsync(IPAddress addr, int port, int timeoutMs, CancellationToken ct)
    {
        var res = new DoctorQuicResult { Ran = true };
        var sw = Stopwatch.StartNew();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        try
        {
            using var s = new Socket(addr.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            await s.ConnectAsync(new IPEndPoint(addr, port), cts.Token).ConfigureAwait(false);
            await s.SendAsync(BuildInitial(), SocketFlags.None, cts.Token).ConfigureAwait(false);
            var buf = new byte[2048];
            // one retransmit, as a datagram can be lost
            var recv = s.ReceiveAsync(buf, SocketFlags.None, cts.Token).AsTask();
            var first = await Task.WhenAny(recv, Task.Delay(Math.Min(700, timeoutMs / 2), cts.Token)).ConfigureAwait(false);
            if (first != recv)
            {
                await s.SendAsync(BuildInitial(), SocketFlags.None, cts.Token).ConfigureAwait(false);
            }
            int got = await recv.ConfigureAwait(false);
            res.Open = got > 0 && (buf[0] & 0x80) != 0;   // a long-header packet back (Version Negotiation)
            res.Ms = sw.Elapsed.TotalMilliseconds;
            res.Note = res.Open ? "Version Negotiation" : "a non-QUIC datagram";
            if (got > 0 && (buf[0] & 0x80) == 0) res.Open = true;   // any answer at all still proves UDP/443 reaches it
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { res.Open = false; res.Ms = sw.Elapsed.TotalMilliseconds; res.Note = "no answer"; }
        catch (SocketException e) when (e.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionRefused)
        {
            // ICMP port unreachable: the datagram reached the host, nothing listens on UDP/443 there
            res.Open = false; res.Ms = sw.Elapsed.TotalMilliseconds; res.Note = "port unreachable";
        }
        catch (Exception e) { res.Open = false; res.Ms = sw.Elapsed.TotalMilliseconds; res.Note = DoctorDns.Short(e); }
        return res;
    }

    // A QUIC v1 long-header Initial with a greased version so the server must answer Version Negotiation. Padded to the
    // 1200-byte minimum, with random connection ids. The contents past the header don't matter: an unknown version is
    // rejected before they're read.
    private static byte[] BuildInitial()
    {
        var p = new byte[1200];
        p[0] = (byte)(0xC0 | (RandomNumberGenerator.GetInt32(0, 16)));   // long header, fixed bit, random low bits
        // version 0x?a?a?a?a (reserved to force Version Negotiation, RFC 9000 §15)
        p[1] = (byte)((RandomNumberGenerator.GetInt32(0, 16) << 4) | 0x0A);
        p[2] = (byte)((RandomNumberGenerator.GetInt32(0, 16) << 4) | 0x0A);
        p[3] = (byte)((RandomNumberGenerator.GetInt32(0, 16) << 4) | 0x0A);
        p[4] = (byte)((RandomNumberGenerator.GetInt32(0, 16) << 4) | 0x0A);
        p[5] = 8;                                                        // DCID length
        RandomNumberGenerator.Fill(p.AsSpan(6, 8));
        p[14] = 8;                                                       // SCID length
        RandomNumberGenerator.Fill(p.AsSpan(15, 8));
        // the rest stays zero padding (Initial packets must be at least 1200 bytes)
        return p;
    }
}
