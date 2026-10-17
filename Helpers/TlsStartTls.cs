using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>Plain-text protocols that upgrade to TLS in-band.</summary>
public enum StartTlsKind { None = 0, Smtp = 1, Imap = 2, Pop3 = 3, Ftp = 4 }

/// <summary>
/// STARTTLS for SMTP (25 / 587), IMAP (143), POP3 (110) and FTP (21): the plain-text exchange that turns the
/// connection into a TLS one. Reads byte by byte so no handshake byte is swallowed by a buffer. Refusals throw a
/// <see cref="SocketFailure"/> quoting what the server said.
/// </summary>
public static class TlsStartTls
{
    private const int MaxLine = 4096;
    private const int MaxLines = 100;

    /// <summary>The dialect a port implies; <see cref="StartTlsKind.None"/> = TLS from the first byte.</summary>
    public static StartTlsKind ForPort(int port) => port switch
    {
        25 or 587 or 2525 => StartTlsKind.Smtp,
        143 => StartTlsKind.Imap,
        110 => StartTlsKind.Pop3,
        21 => StartTlsKind.Ftp,
        _ => StartTlsKind.None,
    };

    public static string Name(StartTlsKind k) => k switch
    {
        StartTlsKind.Smtp => "SMTP",
        StartTlsKind.Imap => "IMAP",
        StartTlsKind.Pop3 => "POP3",
        StartTlsKind.Ftp => "FTP",
        _ => "none",
    };

    public static async Task NegotiateAsync(Stream s, StartTlsKind kind, CancellationToken ct)
    {
        switch (kind)
        {
            case StartTlsKind.Smtp:
            {
                var greet = await ReadReplyAsync(s, ct).ConfigureAwait(false);
                Expect(greet, "220", "SMTP", "greeting");
                await WriteAsync(s, "EHLO echoes.invalid\r\n", ct).ConfigureAwait(false);
                var ehlo = await ReadReplyAsync(s, ct).ConfigureAwait(false);
                Expect(ehlo, "250", "SMTP", "EHLO");
                if (!ehlo.Any(l => l.Length > 4 && l[4..].Trim().Split(' ')[0].Equals("STARTTLS", StringComparison.OrdinalIgnoreCase)))
                    throw new SocketFailure("The SMTP server doesn't offer STARTTLS (it isn't in its EHLO reply), so there is no TLS to inspect on this port.");
                await WriteAsync(s, "STARTTLS\r\n", ct).ConfigureAwait(false);
                Expect(await ReadReplyAsync(s, ct).ConfigureAwait(false), "220", "SMTP", "STARTTLS");
                break;
            }
            case StartTlsKind.Imap:
            {
                string greet = await ReadLineAsync(s, ct).ConfigureAwait(false);
                if (!greet.StartsWith("* OK", StringComparison.OrdinalIgnoreCase) && !greet.StartsWith("* PREAUTH", StringComparison.OrdinalIgnoreCase))
                    throw NotThat("IMAP", greet);
                await WriteAsync(s, "a1 STARTTLS\r\n", ct).ConfigureAwait(false);
                string line;
                int n = 0;
                do
                {
                    line = await ReadLineAsync(s, ct).ConfigureAwait(false);
                    if (++n > MaxLines) throw new SocketFailure("The IMAP server never answered STARTTLS.");
                } while (!line.StartsWith("a1 ", StringComparison.OrdinalIgnoreCase));
                if (!line.StartsWith("a1 OK", StringComparison.OrdinalIgnoreCase))
                    throw new SocketFailure($"The IMAP server refused STARTTLS: \"{Clip(line[3..])}\".");
                break;
            }
            case StartTlsKind.Pop3:
            {
                string greet = await ReadLineAsync(s, ct).ConfigureAwait(false);
                if (!greet.StartsWith("+OK", StringComparison.OrdinalIgnoreCase)) throw NotThat("POP3", greet);
                await WriteAsync(s, "STLS\r\n", ct).ConfigureAwait(false);
                string r = await ReadLineAsync(s, ct).ConfigureAwait(false);
                if (!r.StartsWith("+OK", StringComparison.OrdinalIgnoreCase))
                    throw new SocketFailure($"The POP3 server refused STLS: \"{Clip(r)}\".");
                break;
            }
            case StartTlsKind.Ftp:
            {
                var greet = await ReadReplyAsync(s, ct).ConfigureAwait(false);
                Expect(greet, "220", "FTP", "greeting");
                await WriteAsync(s, "AUTH TLS\r\n", ct).ConfigureAwait(false);
                Expect(await ReadReplyAsync(s, ct).ConfigureAwait(false), "234", "FTP", "AUTH TLS");
                break;
            }
        }
    }

    // A reply that isn't what this step needs: the greeting of some other protocol, or a refusal.
    private static void Expect(List<string> reply, string code, string proto, string step)
    {
        string last = reply.Count > 0 ? reply[^1] : string.Empty;
        if (last.StartsWith(code, StringComparison.Ordinal)) return;
        if (step == "greeting") throw NotThat(proto, last);
        throw new SocketFailure($"The {proto} server refused {step}: \"{Clip(last)}\".");
    }

    private static SocketFailure NotThat(string proto, string said)
        => new($"The server didn't greet like an {proto} server (it said \"{Clip(said)}\") — check the port, or pick the right STARTTLS protocol.");

    private static string Clip(string s)
    {
        s = s.Trim();
        return s.Length <= 120 ? s : s[..120] + "…";
    }

    private static Task WriteAsync(Stream s, string text, CancellationToken ct)
        => s.WriteAsync(Encoding.ASCII.GetBytes(text), ct).AsTask();

    /// <summary>SMTP / FTP multi-line reply: "250-…" lines up to the "250 …" one.</summary>
    private static async Task<List<string>> ReadReplyAsync(Stream s, CancellationToken ct)
    {
        var lines = new List<string>();
        while (true)
        {
            string line = await ReadLineAsync(s, ct).ConfigureAwait(false);
            lines.Add(line);
            bool final = line.Length < 4 || line[3] != '-' || !char.IsAsciiDigit(line[0]);
            if (final) return lines;
            if (lines.Count >= MaxLines) throw new SocketFailure("The server's reply never ended.");
        }
    }

    private static async Task<string> ReadLineAsync(Stream s, CancellationToken ct)
    {
        var buf = new byte[1];
        var sb = new StringBuilder();
        while (true)
        {
            int n = await s.ReadAsync(buf, ct).ConfigureAwait(false);
            if (n == 0)
            {
                if (sb.Length == 0) throw new SocketFailure("The server closed the connection before upgrading to TLS.");
                return sb.ToString();
            }
            char c = (char)buf[0];
            if (c == '\n') return sb.ToString().TrimEnd('\r');
            if (sb.Length >= MaxLine) throw new SocketFailure("The server sent a line too long for this protocol — is it the right port?");
            sb.Append(c is >= ' ' or '\r' or '\t' ? c : '?');
        }
    }
}
