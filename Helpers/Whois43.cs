using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>
/// Classic WHOIS (RFC 3912: the query as one line over TCP port 43, the answer as text). The DNS tool asks it first for a
/// domain and last for an address or AS number: many country domains have no RDAP (.ir among them), and from some networks
/// the registry RDAP that rdap.org forwards to is out of reach (Verisign's, for .com and .net, from Iran) while port 43
/// isn't. IANA names the server that holds the TLD, block or AS; a thin registry (.com, .net) names the registrar's server,
/// which has the rest; ARIN names the registry a block or AS moved to.
/// </summary>
public static class Whois43
{
    public enum Kind { Domain, Ip, Asn }

    /// <summary>The deepest answer along the chain (cleaned for display), the servers asked in order, and a note when a
    /// later server didn't answer (its predecessor's answer is the text then).</summary>
    public sealed record Answer(string Text, IReadOnlyList<string> Servers, string? Note);

    private const string Iana = "whois.iana.org";
    private const int Port = 43;
    private const int MaxBytes = 512 * 1024;
    private const int MaxHops = 4;
    private static readonly TimeSpan HopTimeout = TimeSpan.FromSeconds(8);

    // IANA's server didn't answer this session (port 43 blocked here): the WHOIS pane asks RDAP first from then on.
    private static volatile bool s_unreachable;

    /// <summary>Port 43 didn't answer earlier this session.</summary>
    public static bool Unreachable => s_unreachable;

    /// <summary>
    /// Asks IANA, then the servers it and each answer point to. Throws for a network failure of the first server (and
    /// remembers it, see <see cref="Unreachable"/>) and <see cref="OperationCanceledException"/> when
    /// <paramref name="ct"/> is cancelled or <paramref name="timeout"/> (the whole chain) runs out.
    /// </summary>
    public static async Task<Answer> LookUpAsync(string query, Kind kind, CancellationToken ct, TimeSpan? timeout = null)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        if (timeout is { } t) deadline.CancelAfter(t);
        var token = deadline.Token;

        var servers = new List<string> { Iana };
        string text;
        try { text = await AskAsync(Iana, query, token).ConfigureAwait(false); }
        catch (Exception ex) when (ex is SocketException or IOException || (ex is OperationCanceledException && !ct.IsCancellationRequested))
        {
            s_unreachable = true;
            throw;
        }
        s_unreachable = false;

        // IANA's own record is the answer for what it holds itself (example.com, a reserved block); otherwise its
        // "refer:" (or "whois:") names the next server. A TLD it lists no server for may still have whois.nic.<tld>.
        string? next = Field(text, "refer") ?? Field(text, "whois");
        if (next == null && kind == Kind.Domain && query.LastIndexOf('.') is int dot and > 0)
            next = "whois.nic." + query[(dot + 1)..];
        string? note = null;
        for (int hop = 1; hop < MaxHops && next != null; hop++)
        {
            if (!IsHostName(next) || servers.Contains(next, StringComparer.OrdinalIgnoreCase)) break;
            string answer;
            try { answer = await AskAsync(next, QueryFor(next, query, kind), token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                note = $"{next} didn't answer ({Reason(ex)})";
                break;
            }
            servers.Add(next);
            text = answer;
            // a thin registry's pointer to the registrar, or ARIN's to the registry that holds the block now
            next = Field(answer, "Registrar WHOIS Server") ?? Field(answer, "ReferralServer");
        }
        // servers end lines with CRLF; Clean would show each CR as '?'
        string clean = RemoteText.Clean(text.ReplaceLineEndings("\n").Trim(), keepNewlines: true).ReplaceLineEndings();
        return new Answer(TextLimit.Cap(clean), servers, note);
    }

    /// <summary>The answer's "key: value" objects (a blank line between objects, % and # lines are comments), what the
    /// inline address WHOIS reads its fields from.</summary>
    public static List<List<(string key, string value)>> Objects(string text)
    {
        var groups = new List<List<(string, string)>>();
        var group = new List<(string, string)>();
        foreach (string line in text.ReplaceLineEndings("\n").Split('\n'))
        {
            if (line.Trim().Length == 0)
            {
                if (group.Count > 0) { groups.Add(group); group = new List<(string, string)>(); }
                continue;
            }
            if (line.StartsWith('%') || line.StartsWith('#')) continue;
            int colon = line.IndexOf(':');
            if (colon <= 0) continue;
            string key = line[..colon].Trim(), value = line[(colon + 1)..].Trim();
            if (key.Length > 0 && key.Length <= 64) group.Add((key, value));
        }
        if (group.Count > 0) groups.Add(group);
        return groups;
    }

    // How each server wants the question: ARIN answers "n + <address>" / "a + <number>" with the full record (its plain
    // form can be a list of matches); Verisign's "domain <name>" leaves out hosts that merely share the name.
    private static string QueryFor(string server, string query, Kind kind)
    {
        if (server.Equals("whois.arin.net", StringComparison.OrdinalIgnoreCase))
            return kind switch { Kind.Ip => "n + " + query, Kind.Asn => "a + " + query.TrimStart('A', 'S', 'a', 's'), _ => query };
        if (server.Equals("whois.verisign-grs.com", StringComparison.OrdinalIgnoreCase) && kind == Kind.Domain)
            return "domain " + query;
        if (kind == Kind.Asn && !query.StartsWith("AS", StringComparison.OrdinalIgnoreCase)) return "AS" + query;
        return query;
    }

    // One question to one server: connect (public addresses only: a referral is someone else's text), send the line,
    // read to the end, capped.
    private static async Task<string> AskAsync(string server, string query, CancellationToken ct)
    {
        using var hop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        hop.CancelAfter(HopTimeout);
        var addresses = (await Dns.GetHostAddressesAsync(server, hop.Token).ConfigureAwait(false))
            .Where(a => Rdap.SpecialPurpose(a) == null)
            .OrderBy(a => a.AddressFamily == AddressFamily.InterNetworkV6)   // IPv4 first: some servers' IPv6 drops it
            .ToArray();
        if (addresses.Length == 0) throw new SocketException((int)SocketError.HostNotFound);
        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(addresses, Port, hop.Token).ConfigureAwait(false);
        using var stream = new NetworkStream(socket, ownsSocket: false);
        await stream.WriteAsync(Encoding.UTF8.GetBytes(query + "\r\n"), hop.Token).ConfigureAwait(false);
        using var ms = new MemoryStream();
        byte[] buf = new byte[8 * 1024];
        int n;
        while ((n = await stream.ReadAsync(buf, hop.Token).ConfigureAwait(false)) > 0)
        {
            if (ms.Length + n > MaxBytes) throw new InvalidDataException($"the answer is larger than {MaxBytes / 1024} KB");
            ms.Write(buf, 0, n);
        }
        string text = Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);
        if (text.Trim().Length == 0) throw new InvalidDataException("an empty answer");
        return text;
    }

    // The first "key: value" line with this key; a whois:// or rwhois:// pointer is reduced to its host (port 43 only).
    private static string? Field(string text, string key)
    {
        var m = Regex.Match(text, @"^[ \t]*" + Regex.Escape(key) + @"[ \t]*:[ \t]*(\S+)", RegexOptions.Multiline | RegexOptions.IgnoreCase);
        if (!m.Success) return null;
        string value = m.Groups[1].Value.Trim();
        int scheme = value.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0)
        {
            if (!value.StartsWith("whois://", StringComparison.OrdinalIgnoreCase)) return null;   // rwhois / http: not port 43
            value = value[(scheme + 3)..];
        }
        int end = value.IndexOfAny(new[] { '/', ':' });
        if (end >= 0) value = value[..end];
        return value.Length > 0 ? value.ToLowerInvariant() : null;
    }

    private static bool IsHostName(string s)
        => s.Length <= 253 && Regex.IsMatch(s, @"^(?=.*[a-z])[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$");

    /// <summary>A few words for the error line: why a server didn't answer.</summary>
    public static string Reason(Exception ex) => SocketErrors.Unwrap(ex) switch
    {
        OperationCanceledException or TimeoutException => "timed out",
        SocketException { SocketErrorCode: SocketError.ConnectionRefused } => "refused",
        SocketException { SocketErrorCode: SocketError.HostNotFound or SocketError.NoData or SocketError.TryAgain } => "host unknown",
        SocketException => "unreachable",
        IOException => "connection reset",
        var e => RemoteText.Clean(e.Message.ReplaceLineEndings(" ").Trim(), 120),
    };
}
