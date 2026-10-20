using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;

namespace Echoes.Helpers;

/// <summary>What was being done when a socket call failed — the same error code means different things
/// (access denied while listening is a privileged / reserved port, while connecting a firewall).</summary>
public enum SocketAction { Resolve, Connect, Listen, Send, Receive, Tls }

/// <summary>
/// Turns socket / TLS exceptions into ONE clear sentence that says why (refused, timed out, unreachable, address in
/// use, privileged port, not TLS, no common protocol …) instead of the OS's raw text. Shared by the Socket tool and
/// the TLS inspector.
/// </summary>
public static class SocketErrors
{
    /// <summary>
    /// <paramref name="target"/> is what the user asked for ("example.com:443", "udp 10.0.0.5:53", "port 80"),
    /// <paramref name="port"/> the port involved (for the privileged-port explanation).
    /// </summary>
    public static string Describe(Exception ex, SocketAction action, string target, int port = 0)
    {
        var e = Unwrap(ex);
        switch (e)
        {
            case SocketException se:
                return FromCode(se.SocketErrorCode, action, target, port, se.Message);
            case AuthenticationException ae:
                return TlsFailure(ae, target);
            case TimeoutException:
            case OperationCanceledException:
                return action switch
                {
                    SocketAction.Resolve => $"Timed out looking up {HostOf(target)} — DNS didn't answer.",
                    SocketAction.Tls => $"Timed out during the TLS handshake with {target} — the server accepted the connection but never answered the handshake.",
                    _ => $"Timed out — {target} didn't answer (the host may be down, or a firewall silently drops the connection).",
                };
            case ObjectDisposedException:
                return "The connection is closed.";
            case IOException io when IsEof(io):
                return action == SocketAction.Tls
                    ? $"{target} closed the connection during the TLS handshake (it may not speak TLS on this port, or it rejected this client's TLS versions)."
                    : "The remote side closed the connection.";
            case IOException io when action == SocketAction.Tls:
                return TlsFailure(io, target);
            case ArgumentOutOfRangeException when action is SocketAction.Connect or SocketAction.Listen:
                return "Port must be a number from 1 to 65535.";
        }
        return string.IsNullOrWhiteSpace(e.Message) ? e.GetType().Name : e.Message.Trim();
    }

    /// <summary>The innermost meaningful exception (aggregate / IO wrappers peeled off).</summary>
    public static Exception Unwrap(Exception ex)
    {
        var e = ex;
        for (int guard = 0; guard < 8; guard++)
        {
            if (e is AggregateException { InnerException: { } a }) { e = a; continue; }
            if (e is IOException { InnerException: SocketException s }) { e = s; continue; }
            break;
        }
        return e;
    }

    private static string FromCode(SocketError code, SocketAction action, string target, int port, string raw)
    {
        if (action == SocketAction.Tls && code is SocketError.ConnectionReset or SocketError.ConnectionAborted or SocketError.Shutdown)
            return $"{target} closed the connection during the TLS handshake (it may not speak TLS on this port, or it rejected this client's TLS versions / ciphers).";
        switch (code)
        {
            case SocketError.ConnectionRefused:
                return action == SocketAction.Send || target.StartsWith("udp", StringComparison.Ordinal)
                    ? $"Port unreachable — nothing is listening on {target} (the host answered with ICMP port unreachable)."
                    : $"Connection refused — nothing is listening on {target} (or a firewall rejected the connection).";
            case SocketError.TimedOut:
                return $"Timed out — {target} didn't answer (the host may be down, or a firewall silently drops the connection).";
            case SocketError.HostUnreachable:
                // macOS 15+ and iOS answer "no route to host" for every LAN address when Local Network access is off for the app
                if (OperatingSystem.IsIOS() && IsLocalNetwork(HostOf(target)))
                    return $"Host unreachable — no route to {HostOf(target)}. On an iPhone or iPad this is also what blocked Local Network access looks like: " +
                           "turn on Echoes in Settings › Privacy & Security › Local Network.";
                return OperatingSystem.IsMacOS() && IsLocalNetwork(HostOf(target))
                    ? $"Host unreachable — no route to {HostOf(target)}. On macOS this is also what blocked Local Network access looks like: " +
                      "allow Echoes in System Settings › Privacy & Security › Local Network."
                    : $"Host unreachable — there's no route to {HostOf(target)} (it may be offline, or on a network you aren't connected to).";
            case SocketError.NetworkUnreachable:
            case SocketError.NetworkDown:
                return "Network unreachable — this device has no route to that network (check the connection or VPN).";
            case SocketError.HostNotFound:
            case SocketError.NoData:
                return $"Host not found — {HostOf(target)} doesn't resolve to an address (check the spelling).";
            case SocketError.TryAgain:
                return $"Couldn't look up {HostOf(target)} — the DNS server didn't answer (check the connection).";
            case SocketError.AddressAlreadyInUse:
                return $"Port {PortText(port, target)} is already in use — another program (or another Echoes tool) is listening on it. Pick another port or stop that program.";
            case SocketError.AccessDenied:
                if (action == SocketAction.Listen)
                {
                    if (OperatingSystem.IsWindows())
                        return $"Access denied for port {PortText(port, target)} — Windows reserves it (an excluded port range, e.g. for Hyper-V / WSL), or another program holds it exclusively. Pick another port.";
                    if (port is > 0 and < 1024)
                        return $"Access denied — ports below 1024 need root on this system. Use a port from 1024 up (e.g. {port + 8000}).";
                    return $"Access denied — this system doesn't allow listening on {target}.";
                }
                if (action == SocketAction.Send && target.Contains("255", StringComparison.Ordinal))
                    return "Access denied — sending to a broadcast address isn't allowed on this socket.";
                return $"Access denied — the system (a firewall or security policy) blocked the connection to {target}.";
            case SocketError.AddressNotAvailable:
                return action == SocketAction.Listen
                    ? "That address isn't on this device any more (the network interface may be down, or its IP changed). Pick another address."
                    : $"Can't reach {target} — that address isn't valid as a destination.";
            case SocketError.AddressFamilyNotSupported:
            case SocketError.ProtocolFamilyNotSupported:
                return "This address type (IPv4 / IPv6) isn't available on this device's network.";
            case SocketError.ConnectionReset:
                return target.StartsWith("udp", StringComparison.Ordinal)
                    ? $"Port unreachable — nothing is listening on {target} (the host answered with ICMP port unreachable)."
                    : "Connection reset by the remote side.";
            case SocketError.ConnectionAborted:
                return "Connection aborted — the other side closed it while data was in flight, or this system's network stack dropped it.";
            case SocketError.Shutdown:
            case SocketError.NotConnected:
            case SocketError.OperationAborted:
                return "The connection is closed.";
            case SocketError.MessageSize:
                return "Datagram too large — UDP carries at most 65,507 bytes per datagram (and much less without fragmentation).";
            case SocketError.NoBufferSpaceAvailable:
            case SocketError.TooManyOpenSockets:
                return "The system ran out of sockets / buffers — close some connections and try again.";
        }
        return string.IsNullOrWhiteSpace(raw) ? code.ToString() : raw.Trim();
    }

    /// <summary>
    /// Why a TLS handshake failed, from the platform's message (SChannel, OpenSSL, Android and Apple word it
    /// differently): not TLS at all, closed mid-handshake, an alert from the server, no common version / cipher.
    /// </summary>
    public static string TlsFailure(Exception ex, string target)
    {
        string all = AllMessages(ex);
        bool Has(string s) => all.Contains(s, StringComparison.OrdinalIgnoreCase);

        if (Has("frame size") || Has("corrupted frame") || Has("wrong version number") || Has("unknown protocol")
            || Has("packet length too long") || Has("record layer failure") || Has("http request") || Has("not a TLS")
            || Has("invalid record") || Has("SEC_E_INVALID_TOKEN") || Has("message received was unexpected or badly formatted"))
            return $"{target} isn't speaking TLS on this port (it answered with something else — plain text, or another protocol).";

        if (Has("unexpected EOF") || Has("0 bytes from the transport") || Has("unexpected eof") || Has("connection closed"))
            return $"{target} closed the connection during the TLS handshake (it may not speak TLS here, or it rejected this client's TLS versions / ciphers).";

        int alert = all.IndexOf("TLS alert:", StringComparison.OrdinalIgnoreCase);
        if (alert >= 0)
        {
            string name = ExtractQuoted(all, alert) ?? "";
            return $"{target} refused the TLS handshake ({AlertText(name)}).";
        }
        if (Has("alert handshake failure") || Has("sslv3 alert handshake failure") || Has("handshake failure"))
            return $"{target} refused the TLS handshake (handshake failure — no TLS version / cipher in common, or it requires a client certificate).";
        if (Has("alert protocol version") || Has("unsupported protocol") || Has("no protocols available")
            || Has("do not possess a common algorithm") || Has("no shared cipher") || Has("SEC_E_ALGORITHM_MISMATCH"))
            return $"No TLS version or cipher in common with {target} — it may only offer versions this system has turned off (e.g. TLS 1.0 / 1.1).";
        if (Has("unrecognized name") || Has("unrecognised name"))
            return $"{target} doesn't know the requested server name (SNI) — check the host name or the SNI override.";
        if (Has("certificate required") || Has("peer did not return a certificate"))
            return $"{target} requires a client certificate.";
        if (Has("remote certificate is invalid") || Has("RemoteCertificate"))
            return $"{target}'s certificate was rejected.";
        if (Has("timed out") || Has("timeout"))
            return $"Timed out during the TLS handshake with {target}.";

        return $"TLS handshake with {target} failed: {Innermost(ex)}";
    }

    // "HandshakeFailure" → "handshake failure"; known alerts get a short explanation.
    private static string AlertText(string name)
    {
        string n = name.Replace(" ", "", StringComparison.Ordinal).ToLowerInvariant();
        return n switch
        {
            "handshakefailure" => "handshake failure — no TLS version / cipher in common, or it requires a client certificate",
            "protocolversion" => "protocol version — it doesn't support the TLS versions this system offers",
            "insufficientsecurity" => "insufficient security — it wants stronger ciphers than offered",
            "unrecognizedname" => "unrecognized name — it doesn't host the requested server name (SNI)",
            "internalerror" => "internal error on the server",
            "accessdenied" => "access denied",
            "certificaterequired" => "a client certificate is required",
            "decodeerror" => "decode error — it couldn't parse this client's handshake",
            "illegalparameter" => "illegal parameter",
            "noapplicationprotocol" => "no application protocol in common (ALPN)",
            _ => Humanize(name),
        };
    }

    private static string Humanize(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return "alert";
        var sb = new StringBuilder(name.Length + 8);
        for (int i = 0; i < name.Length; i++)
        {
            char c = name[i];
            if (i > 0 && char.IsUpper(c) && !char.IsUpper(name[i - 1])) sb.Append(' ');
            sb.Append(char.ToLowerInvariant(c));
        }
        return "alert: " + sb;
    }

    private static string? ExtractQuoted(string s, int from)
    {
        int a = s.IndexOf('\'', from);
        if (a < 0) return null;
        int b = s.IndexOf('\'', a + 1);
        return b > a ? s[(a + 1)..b] : null;
    }

    private static string AllMessages(Exception ex)
    {
        var sb = new StringBuilder();
        for (Exception? e = ex; e != null; e = e.InnerException) sb.Append(e.Message).Append(" | ");
        return sb.ToString();
    }

    private static string Innermost(Exception ex)
    {
        var e = ex;
        while (e.InnerException != null) e = e.InnerException;
        string m = e.Message.Trim();
        return m.Length == 0 ? e.GetType().Name : m.TrimEnd('.') + ".";
    }

    private static bool IsEof(IOException io)
    {
        string m = AllMessages(io);
        return m.Contains("unexpected EOF", StringComparison.OrdinalIgnoreCase)
               || m.Contains("0 bytes from the transport", StringComparison.OrdinalIgnoreCase);
    }

    // "example.com:443" → "example.com"; "[::1]:80" → "::1"; "udp 10.0.0.5:53" → "10.0.0.5"
    // A private / link-local / unique-local address literal (a LAN host). Names aren't resolved here: false.
    private static bool IsLocalNetwork(string host)
    {
        if (!System.Net.IPAddress.TryParse(host, out var a)) return false;
        if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
        var b = a.GetAddressBytes();
        if (b.Length == 4)
            return b[0] == 10 || (b[0] == 172 && (b[1] & 0xF0) == 16) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254);
        return (b[0] & 0xFE) == 0xFC || (b[0] == 0xFE && (b[1] & 0xC0) == 0x80);
    }

    private static string HostOf(string target)
    {
        string t = target.StartsWith("udp ", StringComparison.Ordinal) ? target[4..] : target;
        if (t.StartsWith('['))
        {
            int close = t.IndexOf(']');
            return close > 1 ? t[1..close] : t;
        }
        int colon = t.LastIndexOf(':');
        return colon > 0 && t.IndexOf(':') == colon ? t[..colon] : t;
    }

    private static string PortText(int port, string target)
    {
        if (port > 0) return port.ToString(System.Globalization.CultureInfo.InvariantCulture);
        int colon = target.LastIndexOf(':');
        return colon >= 0 ? target[(colon + 1)..] : target;
    }
}
