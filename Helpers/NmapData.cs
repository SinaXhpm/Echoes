using System.Collections.Generic;

namespace Echoes.Helpers;

/// <summary>
/// Static, AOT-safe reference data for the nmap-style scanner: well-known port → service names,
/// a frequency-ordered "top ports" list (for --top-ports), and timing templates (-T0..-T5).
/// Curated subset — not the full nmap-services database, but covers the ports people actually scan.
/// </summary>
public static class NmapData
{
    // port → default service name (nmap-services style). TCP-centric; UDP shares most of these.
    public static readonly IReadOnlyDictionary<int, string> Services = new Dictionary<int, string>
    {
        [7] = "echo", [9] = "discard", [13] = "daytime", [17] = "qotd", [19] = "chargen",
        [20] = "ftp-data", [21] = "ftp", [22] = "ssh", [23] = "telnet", [25] = "smtp",
        [37] = "time", [43] = "whois", [49] = "tacacs", [53] = "domain", [67] = "dhcps",
        [68] = "dhcpc", [69] = "tftp", [70] = "gopher", [79] = "finger", [80] = "http",
        [88] = "kerberos-sec", [102] = "iso-tsap", [110] = "pop3", [111] = "rpcbind",
        [113] = "ident", [119] = "nntp", [123] = "ntp", [135] = "msrpc", [137] = "netbios-ns",
        [138] = "netbios-dgm", [139] = "netbios-ssn", [143] = "imap", [161] = "snmp",
        [162] = "snmptrap", [179] = "bgp", [194] = "irc", [389] = "ldap", [427] = "svrloc",
        [443] = "https", [445] = "microsoft-ds", [464] = "kpasswd", [465] = "smtps",
        [500] = "isakmp", [512] = "exec", [513] = "login", [514] = "shell", [515] = "printer",
        [520] = "route", [523] = "ibm-db2", [540] = "uucp", [548] = "afp", [554] = "rtsp",
        [587] = "submission", [593] = "http-rpc-epmap", [623] = "ipmi", [631] = "ipp",
        [636] = "ldaps", [646] = "ldp", [873] = "rsync", [902] = "vmware-auth", [989] = "ftps-data",
        [990] = "ftps", [993] = "imaps", [995] = "pop3s", [1025] = "NFS-or-IIS", [1080] = "socks",
        [1099] = "rmiregistry", [1194] = "openvpn", [1241] = "nessus", [1311] = "dell-openmanage",
        [1352] = "lotusnotes", [1433] = "ms-sql-s", [1434] = "ms-sql-m", [1521] = "oracle",
        [1604] = "citrix-ica", [1701] = "l2tp", [1723] = "pptp", [1755] = "ms-streaming",
        [1812] = "radius", [1813] = "radius-acct", [1883] = "mqtt", [1900] = "upnp",
        [2000] = "cisco-sccp", [2049] = "nfs", [2082] = "cpanel", [2083] = "cpanel-ssl",
        [2086] = "whm", [2087] = "whm-ssl", [2095] = "webmail", [2096] = "webmail-ssl",
        [2121] = "ftp-proxy", [2181] = "zookeeper", [2222] = "ssh-alt", [2375] = "docker",
        [2376] = "docker-ssl", [2483] = "oracle-db", [2484] = "oracle-db-ssl", [2638] = "sybase",
        [3000] = "http-alt", [3128] = "squid-http", [3260] = "iscsi", [3268] = "globalcat-ldap",
        [3299] = "saprouter", [3306] = "mysql", [3389] = "ms-wbt-server", [3478] = "stun",
        [3689] = "daap", [3690] = "svn", [4000] = "remoteanything", [4369] = "epmd",
        [4443] = "pharos", [4444] = "krb524", [4500] = "nat-t-ike", [4662] = "edonkey",
        [4786] = "smart-install", [4899] = "radmin", [5000] = "upnp", [5001] = "commplex-link",
        [5004] = "rtp", [5005] = "rtp-alt", [5038] = "asterisk", [5060] = "sip", [5061] = "sips",
        [5222] = "xmpp-client", [5223] = "xmpp-client-ssl", [5269] = "xmpp-server", [5353] = "mdns",
        [5357] = "wsdapi", [5432] = "postgresql", [5555] = "freeciv", [5601] = "kibana",
        [5631] = "pcanywhere", [5666] = "nrpe", [5672] = "amqp", [5683] = "coap", [5800] = "vnc-http",
        [5900] = "vnc", [5901] = "vnc-1", [5938] = "teamviewer", [5984] = "couchdb",
        [5985] = "wsman", [5986] = "wsmans", [6000] = "x11", [6001] = "x11-1", [6379] = "redis",
        [6443] = "https-alt", [6514] = "syslog-tls", [6566] = "sane", [6660] = "irc",
        [6667] = "irc", [6697] = "ircs-tls", [6881] = "bittorrent", [6969] = "acmsoda",
        [7000] = "afs3-fileserver", [7001] = "weblogic", [7070] = "realserver", [7443] = "https-alt",
        [7474] = "neo4j", [7547] = "cwmp", [7687] = "bolt", [8000] = "http-alt", [8008] = "http",
        [8009] = "ajp13", [8080] = "http-proxy", [8081] = "http-alt", [8086] = "influxdb",
        [8089] = "splunkd", [8091] = "couchbase", [8096] = "jellyfin", [8123] = "home-assistant",
        [8140] = "puppet", [8291] = "winbox", [8333] = "bitcoin", [8443] = "https-alt",
        [8500] = "consul", [8530] = "wsus", [8545] = "ethereum-rpc", [8728] = "mikrotik-api",
        [8834] = "nessus-web", [8888] = "http-alt", [8983] = "solr", [9000] = "cslistener",
        [9001] = "tor-orport", [9042] = "cassandra", [9090] = "prometheus", [9091] = "transmission",
        [9092] = "kafka", [9100] = "jetdirect", [9200] = "elasticsearch", [9300] = "elasticsearch",
        [9418] = "git", [9443] = "https-alt", [9999] = "abyss", [10000] = "webmin",
        [10250] = "kubelet", [11211] = "memcached", [11371] = "hkp", [15672] = "rabbitmq-mgmt",
        [25565] = "minecraft", [27015] = "source-rcon", [27017] = "mongodb", [27018] = "mongodb",
        [28017] = "mongodb-web", [32400] = "plex", [49152] = "upnp", [50000] = "sap",
        [50070] = "hadoop-namenode", [51820] = "wireguard",
    };

    /// <summary>Well-known service name for a port, or "unknown".</summary>
    public static string ServiceName(int port)
        => Services.TryGetValue(port, out var name) ? name : "unknown";

    // Most-commonly-scanned TCP ports, roughly frequency-ordered (nmap --top-ports spirit).
    // The first 20 mirror nmap's classic top-20; the rest fill out the common services.
    private static readonly int[] TopTcp =
    {
        80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
        1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
        26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
        2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
        7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
        1000, 3001, 5001, 82, 10010, 1030, 9090, 2107, 1024, 2103, 6004, 1801, 5050, 19, 8031, 1041, 255, 1049, 1048, 2967,
        1053, 3703, 1056, 1065, 1064, 1054, 17, 808, 3689, 1031, 1044, 1071, 5901, 100, 9102, 8010, 2869, 1039, 5120, 4001,
        9000, 2105, 636, 1038, 2601, 7000, 1, 1066, 1069, 625, 311, 280, 254, 4000, 1761, 5003, 2002, 2005, 1998, 1032,
        1050, 6112, 3690, 1521, 2161, 6002, 1080, 2401, 4045, 902, 7937, 787, 1058, 2383, 32771, 1033, 1040, 1059, 50000,
        5555, 10001, 1494, 3, 593, 2301, 3268, 7938, 1234, 1022, 1035, 9001, 8082, 5985, 6379, 27017, 9200, 11211, 5672, 9092,
    };

    /// <summary>The <paramref name="n"/> most-common TCP ports (nmap --top-ports N).</summary>
    public static List<int> TopPorts(int n)
    {
        if (n <= 0) return new List<int>();
        if (n >= TopTcp.Length) return new List<int>(TopTcp);
        var list = new List<int>(n);
        for (int i = 0; i < n; i++) list.Add(TopTcp[i]);
        return list;
    }

    // -T0..-T5: (label, max concurrency, per-port timeout ms). Managed-socket equivalents of
    // nmap's timing templates — not the exact microsecond timings, but the same behaviour spectrum.
    public static readonly TimingTemplate[] Timings =
    {
        new(0, "T0 · Paranoid",   1,   6000),
        new(1, "T1 · Sneaky",     3,   5000),
        new(2, "T2 · Polite",     10,  3000),
        new(3, "T3 · Normal",     64,  1500),
        new(4, "T4 · Aggressive", 200, 800),
        new(5, "T5 · Insane",     400, 400),
    };

    public static TimingTemplate Timing(int level)
    {
        foreach (var t in Timings) if (t.Level == level) return t;
        return Timings[3]; // default Normal
    }
}

public sealed record TimingTemplate(int Level, string Label, int Concurrency, int TimeoutMs)
{
    public override string ToString() => Label;
}
