using System.Net;

namespace Echoes.Helpers;

/// <summary>A --resolve / --connect-to pin: dial <see cref="Addr"/> (and <see cref="Port"/> when set, else the
/// URL's port) instead of resolving the host. <see cref="FromPort"/> limits it to that origin port, like curl.</summary>
public readonly record struct HostOverride(string Addr, int? Port = null, int? FromPort = null)
{
    public override string ToString() => Port is int p
        ? (Addr.Contains(':') ? $"[{Addr}]:{p}" : $"{Addr}:{p}")
        : Addr;
}

/// <summary>
/// The cURL tab's "Override IP" field (curl --resolve / --connect-to). Reading a whole pasted curl command is
/// <see cref="CurlCommand"/>'s job.
/// </summary>
public static class CurlFlagParser
{
    /// <summary>
    /// Splits the cURL tab's "Override IP" field into the address to dial and the port: a trailing
    /// ":port" is honoured unless the whole value is a bare IP (keeps an unbracketed IPv6 intact);
    /// brackets are stripped. Returns false for an empty field.
    /// </summary>
    public static bool TryParseOverride(string? overrideIp, int urlPort, out string ip, out int port)
    {
        ip = string.Empty;
        port = urlPort;
        if (string.IsNullOrWhiteSpace(overrideIp)) return false;
        string ipPart = overrideIp.Trim();
        int close = ipPart.StartsWith('[') ? ipPart.IndexOf(']') : -1;
        if (close > 0)
        {
            // "[v6]" / "[v6]:port" — checked first: IPAddress.TryParse accepts "[v6]:port" and drops the port.
            if (close + 1 < ipPart.Length && ipPart[close + 1] == ':' && int.TryParse(ipPart[(close + 2)..], out int bp))
                port = bp;
            ip = ipPart[1..close];
            return ip.Length > 0;
        }
        if (!IPAddress.TryParse(ipPart, out _))
        {
            int idx = ipPart.LastIndexOf(':');
            if (idx > ipPart.LastIndexOf(']') && int.TryParse(ipPart[(idx + 1)..], out int p))
            {
                port = p;
                ipPart = ipPart[..idx];
            }
        }
        ip = ipPart.Trim('[', ']');
        return ip.Length > 0;
    }
}
