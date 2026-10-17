using System;
using System.Text;

namespace Echoes.Helpers;

/// <summary>
/// Per-service UDP probe payloads (nmap-payloads spirit). A CLOSED UDP port answers with an ICMP
/// port-unreachable; an OPEN one usually stays silent unless we actually speak its protocol — so
/// instead of 4 zero bytes we send a real, minimal, read-only request for the common services and
/// treat any reply as OPEN. Every array is hand-built and commented so the wire bytes are auditable;
/// unknown ports fall back to a tiny generic probe. None of these mutate state on the target.
/// </summary>
public static class ScanPayloads
{
    /// <summary>The UDP probe bytes for a port (never null, never empty).</summary>
    public static byte[] Udp(int port) => port switch
    {
        53 => Dns,
        123 => Ntp,
        161 => Snmp,
        137 => NetbiosNs,
        1900 => Ssdp,
        5353 => Mdns,
        5060 => Sip,
        111 => RpcNull,
        3478 => Stun,
        5683 => Coap,
        1434 => MssqlBrowser,
        5351 => NatPmp,
        1194 => OpenVpn,
        500 => Ike,
        11211 => Memcached,
        7 or 13 or 17 or 19 or 37 => SingleByte,   // echo/daytime/qotd/chargen/time — one byte elicits data
        _ => Generic,
    };

    /// <summary>
    /// What a UDP reply says beyond "open" — the service and a version line, for the protocols we probe (the UDP side
    /// of -sV): DNS recursion, NTP version/stratum, SNMP sysDescr, NetBIOS name, SSDP/SIP server headers, SQL Server
    /// instance, memcached version, STUN software. ("", "") when it says nothing more. Never throws.
    /// </summary>
    public static (string Service, string Version) Describe(int port, ReadOnlySpan<byte> r)
    {
        try
        {
            switch (port)
            {
                case 53 or 5353 when r.Length >= 12 && (r[2] & 0x80) != 0:          // QR set: a DNS response
                    string dns = (r[3] & 0x0F) switch
                    {
                        0 => (r[3] & 0x80) != 0 ? "recursion available" : "",
                        2 => "server failure",
                        5 => "refuses queries",
                        _ => "",
                    };
                    return (port == 53 ? "domain" : "mdns", dns);
                case 123 when r.Length >= 48 && (r[0] & 0x07) is 4 or 5:            // server / broadcast mode
                    return ("ntp", $"NTP v{(r[0] >> 3) & 0x07}, stratum {r[1]}");
                case 161 when r.Length > 2 && r[0] == 0x30:
                    return ("snmp", SnmpDescr(r));
                case 137 when r.Length > 60:
                    return ("netbios-ns", Nbstat(r));
                case 1434 when r.Length > 3 && r[0] == 0x05:
                    return ("ms-sql-m", SqlBrowser(Encoding.ASCII.GetString(r[3..])));
                case 1900:
                    return ("upnp", HeaderValue(r, "SERVER"));
                case 5060:
                    string sip = HeaderValue(r, "Server");
                    return ("sip", sip.Length > 0 ? sip : HeaderValue(r, "User-Agent"));
                case 11211 when r.Length > 8:
                    string mc = FirstLine(r[8..]);
                    return ("memcached", mc.StartsWith("VERSION ", StringComparison.Ordinal) ? "memcached " + mc[8..] : "");
                case 3478 when r.Length >= 20 && r[0] == 0x01 && r[1] == 0x01:
                    return ("stun", StunSoftware(r));
            }
        }
        catch { /* malformed reply: still open, just undescribed */ }
        return ("", Printable(r) ? FirstLine(r) : "");
    }

    private static string FirstLine(ReadOnlySpan<byte> r)
    {
        int n = r.IndexOfAny((byte)'\r', (byte)'\n');
        string s = Encoding.ASCII.GetString(n >= 0 ? r[..n] : r).Trim();
        return ServiceScanner.Sanitize(s.Length > 80 ? s[..80] : s);
    }

    // Mostly printable ASCII (a banner-like reply rather than binary).
    private static bool Printable(ReadOnlySpan<byte> r)
    {
        if (r.Length < 4) return false;
        int ok = 0;
        foreach (byte b in r) if (b is >= 0x20 and < 0x7F or (byte)'\r' or (byte)'\n' or (byte)'\t') ok++;
        return ok >= r.Length * 9 / 10;
    }

    private static string HeaderValue(ReadOnlySpan<byte> r, string name)
    {
        foreach (var line in Encoding.ASCII.GetString(r).Split('\n'))
        {
            int colon = line.IndexOf(':');
            if (colon > 0 && line.AsSpan(0, colon).Trim().Equals(name, StringComparison.OrdinalIgnoreCase))
                return ServiceScanner.Sanitize(line[(colon + 1)..].Trim());
        }
        return "";
    }

    // The sysDescr.0 value: the OCTET STRING right after its OID in the GetResponse.
    private static string SnmpDescr(ReadOnlySpan<byte> r)
    {
        ReadOnlySpan<byte> oid = stackalloc byte[] { 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00 };
        int at = r.IndexOf(oid);
        if (at < 0) return "";
        int p = at + oid.Length;
        if (p + 2 > r.Length || r[p] != 0x04) return "";
        int len = r[p + 1], start = p + 2;
        if ((len & 0x80) != 0)                     // long form: 0x81 nn / 0x82 nn nn
        {
            int bytes = len & 0x7F;
            if (bytes is < 1 or > 2 || start + bytes > r.Length) return "";
            len = bytes == 1 ? r[start] : (r[start] << 8) | r[start + 1];
            start += bytes;
        }
        if (start + len > r.Length) len = r.Length - start;
        string s = ServiceScanner.Sanitize(Encoding.ASCII.GetString(r.Slice(start, len)));
        return s.Length > 100 ? s[..100] : s;
    }

    // NBSTAT answer: [header 12][name: 34 bytes, or a 2-byte pointer][type 2][class 2][ttl 4][rdlength 2]
    // [count 1][count × (15-char name, suffix, 2 flag bytes)][MAC 6] — the workstation and workgroup names.
    private static string Nbstat(ReadOnlySpan<byte> r)
    {
        int p = 12;
        p += (r[p] & 0xC0) == 0xC0 ? 2 : r[p] + 2;
        p += 10;
        int count = r[p++];
        string host = "", group = "";
        for (int i = 0; i < count && p + 18 <= r.Length; i++, p += 18)
        {
            string name = Encoding.ASCII.GetString(r.Slice(p, 15)).TrimEnd(' ', '\0');
            byte suffix = r[p + 15];
            bool isGroup = (r[p + 16] & 0x80) != 0;
            if (suffix != 0x00) continue;
            if (isGroup) { if (group.Length == 0) group = name; }
            else if (host.Length == 0) host = name;
        }
        string s = host.Length > 0 ? "NetBIOS name " + host : "";
        if (group.Length > 0) s += (s.Length > 0 ? ", " : "") + "workgroup " + group;
        return ServiceScanner.Sanitize(s);
    }

    // "ServerName;SQL1;InstanceName;MSSQLSERVER;IsClustered;No;Version;15.0.2000.5;tcp;1433;;"
    private static string SqlBrowser(string s)
    {
        var f = s.Split(';');
        string version = "", instance = "";
        for (int i = 0; i + 1 < f.Length; i += 2)
        {
            if (f[i] == "Version") version = f[i + 1];
            else if (f[i] == "InstanceName") instance = f[i + 1];
        }
        if (version.Length == 0) return "";
        return ServiceScanner.Sanitize($"Microsoft SQL Server {version}" + (instance.Length > 0 ? $" (instance {instance})" : ""));
    }

    // STUN Binding success: walk the attributes for SOFTWARE (0x8022).
    private static string StunSoftware(ReadOnlySpan<byte> r)
    {
        for (int p = 20; p + 4 <= r.Length;)
        {
            int type = (r[p] << 8) | r[p + 1], len = (r[p + 2] << 8) | r[p + 3];
            if (p + 4 + len > r.Length) break;
            if (type == 0x8022) return ServiceScanner.Sanitize(Encoding.UTF8.GetString(r.Slice(p + 4, len)));
            p += 4 + ((len + 3) & ~3);
        }
        return "";
    }

    // Fallbacks.
    private static readonly byte[] Generic = { 0x00, 0x00, 0x00, 0x00 };
    private static readonly byte[] SingleByte = { 0x0A };

    // DNS 53 — standard recursive A query for "www.example.com" (any well-formed reply proves open).
    private static readonly byte[] Dns =
    {
        0x12, 0x34,             // transaction id
        0x01, 0x00,             // flags: standard query, recursion desired
        0x00, 0x01,             // QDCOUNT = 1
        0x00, 0x00,             // ANCOUNT = 0
        0x00, 0x00,             // NSCOUNT = 0
        0x00, 0x00,             // ARCOUNT = 0
        0x03, (byte)'w', (byte)'w', (byte)'w',                                              // label "www"
        0x07, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e',  // "example"
        0x03, (byte)'c', (byte)'o', (byte)'m',                                              // "com"
        0x00,                   // root label (end of QNAME)
        0x00, 0x01,             // QTYPE = A
        0x00, 0x01,             // QCLASS = IN
    };

    // NTP 123 — 48-byte mode-3 (client) request; first byte LI=0, VN=3, Mode=3 = 0x1B, rest zero.
    private static readonly byte[] Ntp = BuildNtp();
    private static byte[] BuildNtp()
    {
        var p = new byte[48];
        p[0] = 0x1B;            // 00 011 011 : Leap=0, Version=3, Mode=3 (client)
        return p;
    }

    // SNMP 161 — SNMPv1 GetRequest, community "public", for sysDescr.0 (OID 1.3.6.1.2.1.1.1.0).
    private static readonly byte[] Snmp =
    {
        0x30, 0x29,                                     // SEQUENCE, len 41
        0x02, 0x01, 0x00,                               // INTEGER version = 0 (SNMPv1)
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, // OCTET STRING community = "public"
        0xA0, 0x1C,                                     // GetRequest PDU, len 28
        0x02, 0x04, 0x26, 0x4A, 0x5B, 0x3C,             // INTEGER request-id (4 bytes)
        0x02, 0x01, 0x00,                               // INTEGER error-status = 0
        0x02, 0x01, 0x00,                               // INTEGER error-index = 0
        0x30, 0x0E,                                     // SEQUENCE (varbind list), len 14
        0x30, 0x0C,                                     // SEQUENCE (varbind), len 12
        0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID 1.3.6.1.2.1.1.1.0
        0x05, 0x00,                                     // value = NULL
    };

    // NetBIOS-NS 137 — NBSTAT node-status query for the wildcard name "*".
    private static readonly byte[] NetbiosNs = BuildNetbiosNs();
    private static byte[] BuildNetbiosNs()
    {
        var p = new byte[50];
        p[0] = 0x13; p[1] = 0x37;   // transaction id
        p[2] = 0x00; p[3] = 0x00;   // flags (query)
        p[4] = 0x00; p[5] = 0x01;   // QDCOUNT = 1
        // p[6..11] ANCOUNT/NSCOUNT/ARCOUNT already zero
        p[12] = 0x20;               // encoded-name length = 32
        // NetBIOS name "*" = 0x2A + 15 zero bytes, first-level encoded (each nibble + 'A'):
        //   0x2A -> ('A'+2)='C', ('A'+0x0A)='K' ; 0x00 -> 'A','A'
        p[13] = (byte)'C'; p[14] = (byte)'K';
        for (int i = 0; i < 30; i++) p[15 + i] = (byte)'A';   // the 15 trailing zero bytes -> 30 'A's
        p[45] = 0x00;               // name terminator
        p[46] = 0x00; p[47] = 0x21; // QTYPE = NBSTAT (33)
        p[48] = 0x00; p[49] = 0x01; // QCLASS = IN
        return p;
    }

    // SSDP 1900 — UPnP M-SEARCH discovery over the unicast socket.
    private static readonly byte[] Ssdp = Encoding.ASCII.GetBytes(
        "M-SEARCH * HTTP/1.1\r\n" +
        "HOST: 239.255.255.250:1900\r\n" +
        "MAN: \"ssdp:discover\"\r\n" +
        "MX: 1\r\n" +
        "ST: ssdp:all\r\n\r\n");

    // mDNS 5353 — PTR query for "_services._dns-sd._udp.local" (DNS-SD service enumeration).
    private static readonly byte[] Mdns =
    {
        0x00, 0x00,             // transaction id (mDNS uses 0)
        0x00, 0x00,             // flags: standard query
        0x00, 0x01,             // QDCOUNT = 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x09, (byte)'_', (byte)'s', (byte)'e', (byte)'r', (byte)'v', (byte)'i', (byte)'c', (byte)'e', (byte)'s', // "_services"
        0x07, (byte)'_', (byte)'d', (byte)'n', (byte)'s', (byte)'-', (byte)'s', (byte)'d',                       // "_dns-sd"
        0x04, (byte)'_', (byte)'u', (byte)'d', (byte)'p',                                                        // "_udp"
        0x05, (byte)'l', (byte)'o', (byte)'c', (byte)'a', (byte)'l',                                             // "local"
        0x00,                   // end of QNAME
        0x00, 0x0C,             // QTYPE = PTR
        0x00, 0x01,             // QCLASS = IN
    };

    // SIP 5060 — an OPTIONS request; any SIP responder answers with a status line.
    private static readonly byte[] Sip = Encoding.ASCII.GetBytes(
        "OPTIONS sip:nm SIP/2.0\r\n" +
        "Via: SIP/2.0/UDP nm;branch=z9hG4bK-echoes\r\n" +
        "Max-Forwards: 70\r\n" +
        "To: <sip:nm@nm>\r\n" +
        "From: <sip:nm@nm>;tag=echoes\r\n" +
        "Call-ID: echoes-scan\r\n" +
        "CSeq: 1 OPTIONS\r\n" +
        "Content-Length: 0\r\n\r\n");

    // RPC portmapper 111 — Sun RPC NULL call to program 100000 (portmap) v2, proc 0, AUTH_NULL.
    private static readonly byte[] RpcNull =
    {
        0x00, 0x00, 0x00, 0x01,  // XID
        0x00, 0x00, 0x00, 0x00,  // message type = CALL (0)
        0x00, 0x00, 0x00, 0x02,  // RPC version = 2
        0x00, 0x01, 0x86, 0xA0,  // program = 100000 (portmapper)
        0x00, 0x00, 0x00, 0x02,  // program version = 2
        0x00, 0x00, 0x00, 0x00,  // procedure = 0 (NULL)
        0x00, 0x00, 0x00, 0x00,  // credentials: AUTH_NULL flavor
        0x00, 0x00, 0x00, 0x00,  // credentials: length 0
        0x00, 0x00, 0x00, 0x00,  // verifier: AUTH_NULL flavor
        0x00, 0x00, 0x00, 0x00,  // verifier: length 0
    };

    // STUN 3478 — Binding Request with the magic cookie and a 12-byte transaction id.
    private static readonly byte[] Stun =
    {
        0x00, 0x01,              // message type = Binding Request
        0x00, 0x00,              // message length = 0 (no attributes)
        0x21, 0x12, 0xA4, 0x42,  // magic cookie
        0x45, 0x63, 0x68, 0x6F, 0x65, 0x73, 0x2D, 0x53, 0x54, 0x55, 0x4E, 0x31, // txid "Echoes-STUN1"
    };

    // CoAP 5683 — confirmable GET of /.well-known/core (two Uri-Path options).
    private static readonly byte[] Coap =
    {
        0x40,                    // Ver=1, Type=CON(0), Token length=0
        0x01,                    // Code = 0.01 (GET)
        0x12, 0x34,              // Message ID
        0xBB,                    // option: delta=11 (Uri-Path), length=11
        (byte)'.', (byte)'w', (byte)'e', (byte)'l', (byte)'l', (byte)'-', (byte)'k', (byte)'n', (byte)'o', (byte)'w', (byte)'n', // ".well-known"
        0x04,                    // option: delta=0 (Uri-Path), length=4
        (byte)'c', (byte)'o', (byte)'r', (byte)'e',   // "core"
    };

    // MSSQL browser 1434 — CLNT_UCAST_EX (0x02) elicits the instance list.
    private static readonly byte[] MssqlBrowser = { 0x02 };

    // NAT-PMP 5351 — version 0, opcode 0 (external address request).
    private static readonly byte[] NatPmp = { 0x00, 0x00 };

    // OpenVPN 1194 — P_CONTROL_HARD_RESET_CLIENT_V2 (no tls-auth HMAC).
    private static readonly byte[] OpenVpn =
    {
        0x38,                                            // opcode 7 (<<3) | key_id 0
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,  // 8-byte session id
        0x00,                                            // ACK array length = 0
        0x00, 0x00, 0x00, 0x00,                          // message packet-id = 0
    };

    // IKE 500 — ISAKMP main-mode header + one SA proposal (3DES / SHA1 / PSK / MODP1024).
    private static readonly byte[] Ike =
    {
        // ISAKMP header (28 bytes)
        0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, // initiator cookie
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // responder cookie (zero)
        0x01,                    // next payload = SA (1)
        0x10,                    // version = 1.0
        0x02,                    // exchange type = Identity Protection (Main Mode)
        0x00,                    // flags
        0x00, 0x00, 0x00, 0x00,  // message id
        0x00, 0x00, 0x00, 0x54,  // total length = 84
        // SA payload (12 + 44 bytes)
        0x00,                    // next payload = none
        0x00,                    // reserved
        0x00, 0x38,              // payload length = 56
        0x00, 0x00, 0x00, 0x01,  // DOI = IPSEC
        0x00, 0x00, 0x00, 0x01,  // situation = identity only
        // Proposal payload (8 + 36 bytes)
        0x00,                    // next payload = none
        0x00,                    // reserved
        0x00, 0x2C,              // payload length = 44
        0x01,                    // proposal #1
        0x01,                    // protocol = ISAKMP
        0x00,                    // SPI size = 0
        0x01,                    // number of transforms = 1
        // Transform payload (8 + 28 bytes)
        0x00,                    // next payload = none
        0x00,                    // reserved
        0x00, 0x24,              // payload length = 36
        0x01,                    // transform #1
        0x01,                    // transform id = KEY_IKE
        0x00, 0x00,              // reserved
        0x80, 0x01, 0x00, 0x05,  // attr: Encryption Algorithm = 3DES-CBC
        0x80, 0x02, 0x00, 0x02,  // attr: Hash Algorithm = SHA1
        0x80, 0x03, 0x00, 0x01,  // attr: Authentication Method = pre-shared key
        0x80, 0x04, 0x00, 0x02,  // attr: Group Description = MODP1024 (group 2)
        0x80, 0x0B, 0x00, 0x01,  // attr: Life Type = seconds
        0x00, 0x0C, 0x00, 0x04, 0x00, 0x00, 0x70, 0x80, // attr: Life Duration = 28800 s (TLV form)
    };

    // memcached 11211 — 8-byte UDP frame header + the read-only "version" command.
    private static readonly byte[] Memcached =
    {
        0x00, 0x00,             // request id
        0x00, 0x00,             // sequence number = 0
        0x00, 0x01,             // total datagrams = 1
        0x00, 0x00,             // reserved
        (byte)'v', (byte)'e', (byte)'r', (byte)'s', (byte)'i', (byte)'o', (byte)'n', (byte)'\r', (byte)'\n', // "version\r\n"
    };
}
