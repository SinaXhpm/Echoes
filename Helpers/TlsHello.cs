using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>What one raw ClientHello got back.</summary>
public sealed class TlsHelloResult
{
    /// <summary>The server answered with a ServerHello (or a TLS 1.3 HelloRetryRequest).</summary>
    public bool GotServerHello { get; internal set; }
    /// <summary>The version the server picked (0x0301 … 0x0304).</summary>
    public ushort Version { get; internal set; }
    public ushort CipherSuite { get; internal set; }
    public bool HelloRetry { get; internal set; }
    /// <summary>A TLS alert instead of a ServerHello (description code, e.g. 70 protocol_version, 40 handshake_failure).</summary>
    public byte? Alert { get; internal set; }
    /// <summary>The connection closed / reset before any answer.</summary>
    public bool Closed { get; internal set; }
    /// <summary>The reply wasn't TLS at all — its first bytes as text ("HTTP/1.1 400 …", "SSH-2.0-…").</summary>
    public string? NotTls { get; internal set; }
    /// <summary>The ServerHello acknowledged the status_request extension (the server staples OCSP).</summary>
    public bool StaplingAcknowledged { get; internal set; }
    /// <summary>The stapled OCSP response (TLS ≤ 1.2 CertificateStatus message).</summary>
    public byte[]? OcspResponse { get; internal set; }
    /// <summary>The certificates of the Certificate message (sent in the clear up to TLS 1.2).</summary>
    public List<byte[]> Certificates { get; } = new();
}

/// <summary>An OCSP response, decoded: the leaf's status and the response's dates.</summary>
public sealed record TlsOcspStatus(string Status, DateTime? ProducedAt, DateTime? ThisUpdate, DateTime? NextUpdate, DateTime? RevokedAt);

/// <summary>
/// A hand-built ClientHello for exactly one TLS version, and a reader for the server's first flight — so each
/// version is tested against the SERVER, whatever this system's own TLS stack is willing to offer (Windows 11 and
/// recent OpenSSL / Android refuse TLS 1.0 / 1.1 locally). It also asks for an OCSP staple (status_request) and, up
/// to TLS 1.2, reads the certificate chain and the staple, which travel unencrypted. The handshake is never
/// completed: the connection is closed after the server's hello.
/// </summary>
public static class TlsHello
{
    public const ushort Tls10 = 0x0301, Tls11 = 0x0302, Tls12 = 0x0303, Tls13 = 0x0304;

    public static string VersionName(ushort v) => v switch
    {
        0x0300 => "SSL 3.0",
        Tls10 => "TLS 1.0",
        Tls11 => "TLS 1.1",
        Tls12 => "TLS 1.2",
        Tls13 => "TLS 1.3",
        _ => $"0x{v:x4}",
    };

    // TLS 1.2 AEAD + SHA-2 CBC suites (never offered in a TLS 1.0 / 1.1 hello)
    private static readonly ushort[] Suites12 =
    {
        0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0x009E, 0x009F, 0xCCAA, 0x009C, 0x009D,
        0xC023, 0xC027, 0xC024, 0xC028, 0x0067, 0x006B, 0x003C, 0x003D, 0xC0AC, 0xC0AD, 0xC09C, 0xC09D,
    };

    // every era: CBC-SHA (AES, Camellia, 3DES, SEED), RC4 — broad on purpose, to find old servers
    private static readonly ushort[] SuitesLegacy =
    {
        0xC009, 0xC013, 0xC00A, 0xC014, 0x0033, 0x0039, 0x0032, 0x0038, 0x002F, 0x0035,
        0x0045, 0x0088, 0x0041, 0x0084, 0x0096, 0x009A, 0xC012, 0xC008, 0x0016, 0x0013, 0x000A,
        0xC011, 0xC007, 0x0005, 0x0004,
    };

    private static readonly ushort[] Suites13 = { 0x1301, 0x1302, 0x1303, 0x1304 };

    private static readonly byte[] HelloRetryRandom = Convert.FromHexString("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");

    /// <summary>A ClientHello offering only <paramref name="version"/>.</summary>
    public static byte[] BuildClientHello(ushort version, string? sni, bool statusRequest)
    {
        var body = new List<byte>(512);
        ushort legacy = version >= Tls13 ? Tls12 : version;
        Add16(body, legacy);
        body.AddRange(RandomNumberGenerator.GetBytes(32));
        body.Add(32);
        body.AddRange(RandomNumberGenerator.GetBytes(32));   // session id (TLS 1.3 middlebox compatibility; harmless before)

        var suites = new List<ushort>();
        if (version >= Tls13) suites.AddRange(Suites13);
        else
        {
            if (version == Tls12) suites.AddRange(Suites12);
            suites.AddRange(SuitesLegacy);
        }
        suites.Add(0x00FF);   // TLS_EMPTY_RENEGOTIATION_INFO_SCSV (never TLS_FALLBACK_SCSV: it would make servers refuse on purpose)
        Add16(body, (ushort)(suites.Count * 2));
        foreach (var s in suites) Add16(body, s);
        body.Add(1);
        body.Add(0);   // compression: null

        var ext = new List<byte>(256);
        if (!string.IsNullOrEmpty(sni) && !IPAddress.TryParse(sni.Trim('[', ']'), out _))
        {
            byte[] name = Encoding.ASCII.GetBytes(SocketNet.AsciiHost(sni));
            var d = new List<byte>();
            Add16(d, (ushort)(name.Length + 3));
            d.Add(0);
            Add16(d, (ushort)name.Length);
            d.AddRange(name);
            AddExt(ext, 0x0000, d);
        }
        // supported groups: x25519, P-256, P-384, P-521, x448, ffdhe2048, ffdhe3072 — P-256 first for TLS 1.3, where
        // the key share sent is a P-256 one (a server preferring another group answers with a HelloRetryRequest)
        AddExt(ext, 0x000A, version >= Tls13
            ? List16(0x0017, 0x001D, 0x0018, 0x0019, 0x001E, 0x0100, 0x0101)
            : List16(0x001D, 0x0017, 0x0018, 0x0019, 0x001E, 0x0100, 0x0101), withLength: true);
        if (version <= Tls12) AddExt(ext, 0x000B, new List<byte> { 1, 0 });   // ec point formats: uncompressed
        if (version >= Tls12)
            AddExt(ext, 0x000D, List16(0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
                                       0x0807, 0x0808, 0x0809, 0x080A, 0x080B, 0x0201, 0x0203, 0x0202, 0x0402), withLength: true);
        if (statusRequest) AddExt(ext, 0x0005, new List<byte> { 1, 0, 0, 0, 0 });   // OCSP, no responder ids / extensions
        if (version <= Tls12) AddExt(ext, 0x0017, new List<byte>());               // extended master secret
        if (version >= Tls13)
        {
            AddExt(ext, 0x002B, new List<byte> { 2, (byte)(Tls13 >> 8), (byte)(Tls13 & 0xFF) });   // supported_versions: 1.3 only
            // A real P-256 public key: servers validate the share (SChannel drops a hello whose random "x25519 key"
            // isn't a canonical point), and P-256 is available on every platform .NET runs on.
            var ks = new List<byte>();
            Add16(ks, 69);
            Add16(ks, 0x0017);
            Add16(ks, 65);
            ks.Add(4);
            using (var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256))
            {
                var q = ecdh.ExportParameters(false).Q;
                ks.AddRange(q.X!);
                ks.AddRange(q.Y!);
            }
            AddExt(ext, 0x0033, ks);
            AddExt(ext, 0x002D, new List<byte> { 1, 1 });       // psk_dhe_ke
        }
        Add16(body, (ushort)ext.Count);
        body.AddRange(ext);

        var hs = new List<byte>(body.Count + 4) { 1 };
        Add24(hs, body.Count);
        hs.AddRange(body);

        var rec = new List<byte>(hs.Count + 5) { 22, 0x03, 0x01 };
        Add16(rec, (ushort)hs.Count);
        rec.AddRange(hs);
        return rec.ToArray();
    }

    /// <summary>
    /// Sends the hello and reads the server's flight: ServerHello, then (up to TLS 1.2) Certificate and
    /// CertificateStatus, up to ServerHelloDone — or an alert / EOF / not-TLS bytes.
    /// </summary>
    public static async Task<TlsHelloResult> ExchangeAsync(Stream s, ushort version, string? sni, bool statusRequest, CancellationToken ct)
    {
        var result = new TlsHelloResult();
        byte[] hello = BuildClientHello(version, sni, statusRequest);
        await s.WriteAsync(hello, ct).ConfigureAwait(false);
        await s.FlushAsync(ct).ConfigureAwait(false);

        var hsBuf = new List<byte>(8192);
        int consumed = 0;
        int total = 0;
        var header = new byte[5];
        while (total < 512 * 1024)
        {
            int got = await ReadAtMostAsync(s, header, 5, ct).ConfigureAwait(false);
            if (got == 0) { if (!result.GotServerHello) result.Closed = true; return result; }
            if (got < 5 || !(header[0] is 20 or 21 or 22 or 23) || header[1] != 3)
            {
                if (!result.GotServerHello) result.NotTls = await NotTlsTextAsync(s, header, got, ct).ConfigureAwait(false);
                return result;
            }
            int len = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(3));
            if (len == 0 || len > 18 * 1024) { if (!result.GotServerHello) result.NotTls = "an invalid TLS record"; return result; }
            var payload = new byte[len];
            if (await ReadAtMostAsync(s, payload, len, ct).ConfigureAwait(false) < len) { if (!result.GotServerHello) result.Closed = true; return result; }
            total += len + 5;

            if (header[0] == 21)
            {
                if (!result.GotServerHello && len >= 2) result.Alert = payload[1];
                return result;
            }
            if (header[0] != 22) return result;   // ChangeCipherSpec / encrypted data: the readable part is over
            hsBuf.AddRange(payload);

            // whole handshake messages
            while (hsBuf.Count - consumed >= 4)
            {
                int mlen = (hsBuf[consumed + 1] << 16) | (hsBuf[consumed + 2] << 8) | hsBuf[consumed + 3];
                if (hsBuf.Count - consumed - 4 < mlen) break;
                byte type = hsBuf[consumed];
                var msg = hsBuf.GetRange(consumed + 4, mlen).ToArray();
                consumed += 4 + mlen;
                switch (type)
                {
                    case 2:
                        ParseServerHello(msg, result);
                        if (!result.GotServerHello || result.Version >= Tls13 || result.HelloRetry) return result;
                        break;
                    case 11:
                        ParseCertificates(msg, result);
                        break;
                    case 22:
                        if (msg.Length > 4 && msg[0] == 1)
                        {
                            int olen = (msg[1] << 16) | (msg[2] << 8) | msg[3];
                            if (olen > 0 && olen <= msg.Length - 4) result.OcspResponse = msg.AsSpan(4, olen).ToArray();
                        }
                        break;
                    case 14:   // ServerHelloDone
                    case 13:   // CertificateRequest
                        return result;
                }
            }
        }
        return result;
    }

    private static void ParseServerHello(byte[] m, TlsHelloResult r)
    {
        if (m.Length < 38) return;
        ushort legacy = BinaryPrimitives.ReadUInt16BigEndian(m);
        bool hrr = m.AsSpan(2, 32).SequenceEqual(HelloRetryRandom);
        int p = 34;
        int sidLen = m[p];
        p += 1 + sidLen;
        if (p + 3 > m.Length) return;
        r.CipherSuite = BinaryPrimitives.ReadUInt16BigEndian(m.AsSpan(p));
        p += 3;   // suite + compression
        ushort version = legacy;
        if (p + 2 <= m.Length)
        {
            int extLen = BinaryPrimitives.ReadUInt16BigEndian(m.AsSpan(p));
            p += 2;
            int end = Math.Min(m.Length, p + extLen);
            while (p + 4 <= end)
            {
                ushort type = BinaryPrimitives.ReadUInt16BigEndian(m.AsSpan(p));
                int len = BinaryPrimitives.ReadUInt16BigEndian(m.AsSpan(p + 2));
                p += 4;
                if (p + len > end) break;
                if (type == 0x002B && len == 2) version = BinaryPrimitives.ReadUInt16BigEndian(m.AsSpan(p));
                else if (type == 0x0005) r.StaplingAcknowledged = true;
                p += len;
            }
        }
        r.GotServerHello = true;
        r.HelloRetry = hrr;
        r.Version = version;
    }

    private static void ParseCertificates(byte[] m, TlsHelloResult r)
    {
        if (m.Length < 3) return;
        int listLen = (m[0] << 16) | (m[1] << 8) | m[2];
        int p = 3, end = Math.Min(m.Length, 3 + listLen);
        while (p + 3 <= end && r.Certificates.Count < 10)
        {
            int clen = (m[p] << 16) | (m[p + 1] << 8) | m[p + 2];
            p += 3;
            if (clen <= 0 || p + clen > end) break;
            r.Certificates.Add(m.AsSpan(p, clen).ToArray());
            p += clen;
        }
    }

    // What a non-TLS service said, readable: "HTTP/1.1 400 Bad Request", "SSH-2.0-OpenSSH_9.6", "220 mail ESMTP"
    private static async Task<string> NotTlsTextAsync(Stream s, byte[] first, int got, CancellationToken ct)
    {
        var buf = new byte[256];
        Array.Copy(first, buf, got);
        int n = got;
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(300);
            while (n < 120)
            {
                int r = await s.ReadAsync(buf.AsMemory(n, buf.Length - n), cts.Token).ConfigureAwait(false);
                if (r == 0) break;
                n += r;
            }
        }
        catch { /* whatever arrived is enough */ }
        var sb = new StringBuilder();
        for (int i = 0; i < n && sb.Length < 80; i++)
        {
            byte b = buf[i];
            if (b == '\r' || b == '\n') { if (sb.Length > 0) break; continue; }
            sb.Append(b is >= 0x20 and < 0x7F ? (char)b : '·');
        }
        string text = sb.ToString().Trim();
        int printable = 0;
        foreach (char c in text) if (c != '·') printable++;
        return text.Length == 0 || printable < text.Length * 3 / 4 ? "binary data that isn't TLS" : text;
    }

    private static async Task<int> ReadAtMostAsync(Stream s, byte[] buf, int count, CancellationToken ct)
    {
        int n = 0;
        while (n < count)
        {
            int r;
            try { r = await s.ReadAsync(buf.AsMemory(n, count - n), ct).ConfigureAwait(false); }
            catch (IOException) when (n == 0) { return 0; }   // reset before any reply = closed
            if (r == 0) break;
            n += r;
        }
        return n;
    }

    /// <summary>"protocol version", "handshake failure", … for an alert code.</summary>
    public static string AlertName(byte code) => code switch
    {
        0 => "close notify",
        10 => "unexpected message",
        20 => "bad record MAC",
        40 => "handshake failure",
        42 => "bad certificate",
        47 => "illegal parameter",
        50 => "decode error",
        51 => "decrypt error",
        70 => "protocol version",
        71 => "insufficient security",
        80 => "internal error",
        86 => "inappropriate fallback",
        90 => "user canceled",
        109 => "missing extension",
        110 => "unsupported extension",
        112 => "unrecognized name",
        116 => "certificate required",
        120 => "no application protocol",
        _ => $"alert {code}",
    };

    // ------------------------------------------------------------------ OCSP

    /// <summary>
    /// Decodes a DER OCSP response (RFC 6960): the status of the certificate with <paramref name="serial"/>
    /// (big-endian; null = the first response) and the response's dates. Null when it can't be read.
    /// </summary>
    public static TlsOcspStatus? ParseOcsp(byte[] der, byte[]? serial)
    {
        try
        {
            var outer = new AsnReader(der, AsnEncodingRules.DER).ReadSequence();
            byte[] statusBytes = outer.ReadEnumeratedBytes().ToArray();
            int status = statusBytes.Length > 0 ? statusBytes[^1] : -1;
            if (status != 0)
                return new TlsOcspStatus(status switch
                {
                    1 => "responder error (malformed request)",
                    2 => "responder error (internal error)",
                    3 => "responder error (try later)",
                    5 => "responder error (signature required)",
                    6 => "responder error (unauthorized)",
                    _ => $"responder error {status}",
                }, null, null, null, null);
            var bytesWrap = outer.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
            var responseBytes = bytesWrap.ReadSequence();
            responseBytes.ReadObjectIdentifier();
            byte[] basicDer = responseBytes.ReadOctetString();

            var basic = new AsnReader(basicDer, AsnEncodingRules.DER).ReadSequence();
            var tbs = basic.ReadSequence();
            if (tbs.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0))) tbs.ReadEncodedValue();   // version
            tbs.ReadEncodedValue();                                                                                      // responder id
            DateTime producedAt = tbs.ReadGeneralizedTime().UtcDateTime;
            var responses = tbs.ReadSequence();
            TlsOcspStatus? first = null;
            while (responses.HasData)
            {
                var single = responses.ReadSequence();
                var certId = single.ReadSequence();
                certId.ReadEncodedValue();   // hash algorithm
                certId.ReadOctetString();    // issuer name hash
                certId.ReadOctetString();    // issuer key hash
                byte[] sn = certId.ReadIntegerBytes().ToArray();

                var tag = single.PeekTag();
                string st;
                DateTime? revokedAt = null;
                if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 0) { single.ReadEncodedValue(); st = "good"; }
                else if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 1)
                {
                    var info = single.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true));
                    revokedAt = info.ReadGeneralizedTime().UtcDateTime;
                    st = "revoked";
                }
                else { single.ReadEncodedValue(); st = "unknown"; }

                DateTime thisUpdate = single.ReadGeneralizedTime().UtcDateTime;
                DateTime? next = null;
                if (single.HasData && single.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
                    next = single.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)).ReadGeneralizedTime().UtcDateTime;

                var item = new TlsOcspStatus(st, producedAt, thisUpdate, next, revokedAt);
                if (serial == null || TrimZeros(sn).SequenceEqual(TrimZeros(serial))) return item;
                first ??= item;
            }
            return first;
        }
        catch
        {
            return null;
        }
    }

    private static ReadOnlySpan<byte> TrimZeros(ReadOnlySpan<byte> b)
    {
        int i = 0;
        while (i < b.Length - 1 && b[i] == 0) i++;
        return b[i..];
    }

    // ------------------------------------------------------------------ bytes

    private static void Add16(List<byte> l, ushort v) { l.Add((byte)(v >> 8)); l.Add((byte)v); }
    private static void Add24(List<byte> l, int v) { l.Add((byte)(v >> 16)); l.Add((byte)(v >> 8)); l.Add((byte)v); }

    private static List<byte> List16(params ushort[] values)
    {
        var l = new List<byte>(values.Length * 2);
        foreach (var v in values) Add16(l, v);
        return l;
    }

    private static void AddExt(List<byte> ext, ushort type, List<byte> data, bool withLength = false)
    {
        Add16(ext, type);
        if (withLength)
        {
            Add16(ext, (ushort)(data.Count + 2));
            Add16(ext, (ushort)data.Count);
        }
        else Add16(ext, (ushort)data.Count);
        ext.AddRange(data);
    }
}
