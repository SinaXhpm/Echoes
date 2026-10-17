using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>Which address of a name that has both kinds a ping uses.</summary>
public enum IpPreference { Auto = 0, IPv4 = 1, IPv6 = 2 }

/// <summary>A target that couldn't be resolved; <see cref="Exception.Message"/> says why in plain words.</summary>
public sealed class PingTargetException(string message, bool dnsFailure = true) : Exception(message)
{
    /// <summary>The name server failed or the name doesn't exist (as opposed to "no address of the wanted IP version").</summary>
    public bool DnsFailure { get; } = dnsFailure;
}

/// <summary>
/// The Ping tab's target: what was typed or pasted (a host, "host:port", "[v6]:port", a URL, "user@host") split into
/// the host and, for TCP mode, the port; and the host resolved with the IP version the options ask for.
/// </summary>
public static class PingTarget
{
    public readonly record struct Parsed(string Host, int? Port);

    /// <summary>The host and any port the text names: an explicit ":port", else a URL scheme's own port
    /// (https → 443, http → 80, …). A bare host or IP comes back with no port.</summary>
    public static Parsed Parse(string? raw)
    {
        string text = raw?.Trim() ?? string.Empty;
        if (text.Length == 0) return new Parsed(string.Empty, null);
        if (HostExtractor.Best(text) is not { } best) return new Parsed(text, null);
        int? port = best.Port;
        if (port is null && best.Via == "url" && best.Url is { } url) port = SchemePort(url);
        if (port is < 1 or > 65535) port = null;
        return new Parsed(best.Host, port);
    }

    private static int? SchemePort(string url)
    {
        int i = url.IndexOf("://", StringComparison.Ordinal);
        if (i <= 0) return null;
        return url[..i].ToLowerInvariant() switch
        {
            "https" or "wss" => 443,
            "http" or "ws" => 80,
            "ftp" => 21,
            "ssh" or "sftp" => 22,
            "telnet" => 23,
            "smtp" => 25,
            "imap" => 143,
            "imaps" => 993,
            "pop3" => 110,
            "pop3s" => 995,
            "ldap" => 389,
            "ldaps" => 636,
            "rdp" => 3389,
            "mysql" => 3306,
            "postgres" or "postgresql" => 5432,
            "redis" => 6379,
            "mongodb" => 27017,
            _ => null,
        };
    }

    /// <summary>"host:port", the IPv6 address bracketed.</summary>
    public static string Endpoint(IPAddress addr, int port)
        => addr.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{addr}]:{port}" : $"{addr}:{port}";

    /// <summary>
    /// The address to ping. An IP literal is used as it is (whatever the preference). A name: Auto prefers IPv4, as
    /// ping does; IPv4 / IPv6 take only that kind. Throws <see cref="PingTargetException"/> with a plain reason
    /// ("DNS failed: …", "… has no IPv6 address") and <see cref="OperationCanceledException"/> when stopped.
    /// </summary>
    public static async Task<IPAddress> ResolveAsync(string host, IpPreference pref, CancellationToken ct)
    {
        string h = host.Trim();
        if (h.StartsWith('[') && h.EndsWith(']')) h = h[1..^1];
        if (IPAddress.TryParse(h, out var ip)) return ip;

        IPAddress[] all;
        try
        {
            all = await Dns.GetHostAddressesAsync(IcmpPinger.AsciiHost(h), ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (SocketException se)
        {
            throw new PingTargetException("DNS failed for " + h + ": " + se.SocketErrorCode switch
            {
                SocketError.HostNotFound => "no such host (or this network's DNS doesn't answer for it)",
                SocketError.TryAgain => "the DNS server didn't answer (try again)",
                SocketError.NoData => "the name exists but has no address",
                _ => se.Message,
            });
        }
        catch (Exception ex) when (ex is ArgumentException)
        {
            throw new PingTargetException("Not a valid host name: " + h);
        }

        var v4 = all.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
        var v6 = all.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetworkV6);
        return pref switch
        {
            IpPreference.IPv4 => v4 ?? throw new PingTargetException(
                v6 != null ? $"{h} has no IPv4 address (only IPv6): choose IPv6 or Auto" : $"DNS failed for {h}: no address", v6 == null),
            IpPreference.IPv6 => v6 ?? throw new PingTargetException(
                v4 != null ? $"{h} has no IPv6 address (only IPv4): choose IPv4 or Auto" : $"DNS failed for {h}: no address", v4 == null),
            _ => v4 ?? v6 ?? all.FirstOrDefault() ?? throw new PingTargetException($"DNS failed for {h}: no address"),
        };
    }
}
