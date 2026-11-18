using System;
using System.Collections.Generic;

namespace Echoes.Views.Controls;

/// <summary>
/// One desktop tool: its id (the nav tag both shells and the tool views key on), the launcher group it sits in, the tab's
/// label (<see cref="Header"/>), its name and one-line description (<see cref="Title"/>, <see cref="Summary"/>: the
/// launcher card), its glyph (a key in Assets/ToolIcons.axaml), and the details its (!) popover lists.
/// <see cref="AllowsMany"/>: the tool can run in several tabs at once, each with its own inputs (ToolStore).
/// <see cref="SubjectKey"/>: the history key whose last value is what the tab works on ("Ping · 1.1.1.1"); a further tab
/// starts with it empty.
/// </summary>
public sealed record ToolInfo(
    string Tag, string Group, string Header, string Title, string Summary, string IconKey,
    bool AllowsMany, string? SubjectKey, string[] Details, string? SimilarTo);

/// <summary>Every desktop tool, in launcher order (grouped by what you're doing).</summary>
public static class ToolCatalog
{
    private const string Diagnose = "Diagnose", Web = "Web & API", Serve = "Serve & Connect", Workspace = "Workspace";

    public static IReadOnlyList<ToolInfo> All { get; } = new ToolInfo[]
    {
        new("PING", Diagnose, "Ping", "Ping", "Latency, loss, route and MTR", "IcoPing", true, "ping.host",
            new[]
            {
                "Live replies with loss, min / avg / max and a graph",
                "TCP ping to a port, where ICMP is blocked",
                "Traceroute, and MTR: a live table for every hop",
                "Click a hop to see who runs it",
                "No admin rights needed: falls back to UDP",
            }, "ping, tcping, tracert, mtr, WinMTR, PingPlotter"),
        new("DOCTOR", Diagnose, "Doctor", "Doctor", "Why a site won't open for you", "IcoDoctor", true, "doctor",
            new[]
            {
                "Names the cause: DNS tampering, SNI filtering, a blocked IP, a filter page, or a site down for everyone",
                "Compares your DNS with encrypted DNS",
                "Tests HTTP and HTTPS side by side, with a step-by-step trace",
                "Optional proxy, override IP and pasted browser requests",
                "Anti-DPI and QUIC / UDP 443 checks",
            }, "OONI Probe, dig + curl + openssl by hand"),
        new("DNS", Diagnose, "DNS", "DNS & WHOIS", "Lookups, DoH / DoT, WHOIS", "IcoDns", true, "dns.domain",
            new[]
            {
                "DNS over UDP, HTTPS or TLS, with any resolver",
                "Compare resolvers: speed, success and answers",
                "Email check: MX, SPF, DKIM, DMARC, MTA-STS",
                "WHOIS that keeps working: port 43, RDAP and web sources",
                "Who runs each address in an answer",
            }, "dig, kdig, DNS benchmark, MXToolbox"),
        new("SCANNER", Diagnose, "Scanner", "Port Scanner", "Open ports and their services", "IcoScanner", true, "portscan.target",
            new[]
            {
                "IPs, names, ranges and CIDR blocks, IPv4 and IPv6",
                "Top 20 / 100 / 1000 lists, your own ranges, UDP",
                "Open, closed or filtered, with the reason",
                "Service and version detection",
                "Flags fake open ports (tarpits, proxies, antivirus)",
            }, "nmap, Zenmap, Angry IP Scanner"),
        new("CHECK-HOST", Diagnose, "Check Host", "Check Host", "Checks from around the world", "IcoCheckHost", true, "checkhost.host",
            new[]
            {
                "Ping, HTTP, TCP, UDP and DNS from servers worldwide",
                "Uses Globalping when check-host.net is blocked",
                "Flags DNS answers that differ from the rest",
            }, "check-host.net, Globalping"),
        new("MONITOR", Diagnose, "Monitor", "Monitor", "Uptime and expiry alerts", "IcoMonitor", false, null,
            new[]
            {
                "Watches servers and websites, with no false alarms",
                "Alerts from your own Telegram bot, and alert sounds",
                "Warns before certificates and domains expire",
                "Optional checks: DNS answers that change, page text",
                "Can start with Echoes",
            }, "Uptime Kuma, UptimeRobot"),
        new("NETWORK", Diagnose, "Network", "Network", "Adapters, Wi-Fi and routes", "IcoNetwork", false, null,
            new[]
            {
                "Every adapter: addresses, MAC, gateway, DNS, speed",
                "Wi-Fi analyzer: signal, channels, nearby networks",
                "Finds the devices on your network: ARP, mDNS, SSDP, names",
                "Listening ports and connections",
                "The routing table",
            }, "ipconfig, arp, arp-scan, netstat, Wi-Fi analyzers, Fing"),
        new("CAPTURE", Diagnose, "Capture", "Packet Capture", "Packets on an interface, live", "IcoCapture", false, null,
            new[]
            {
                "Every packet on an interface as it passes, one line each",
                "Filters as in tcpdump and Wireshark, or plain text",
                "The selected packet's layers and bytes",
                "Reads DNS names, TLS server names and HTTP requests",
                "Saves pcap for Wireshark, CSV or text, and opens pcap files",
                "On Windows with Npcap, or as administrator",
            }, "Wireshark, tcpdump"),
        new("DEVICE", Diagnose, "Device", "Device", "Hardware and system details", "IcoDevice", false, null,
            new[]
            {
                "Model, firmware, Secure Boot and TPM",
                "Processor, memory modules, GPUs and displays",
                "Disks, and the battery's health and cycles",
                "On phones: the chip, cameras and sensors",
            }, "CPU-Z, HWiNFO, Speccy, CPU-X"),
        new("SPEED TEST", Diagnose, "Speed Test", "Speed Test", "Internet speed and latency", "IcoSpeed", false, null,
            new[]
            {
                "Download, upload, latency and jitter",
                "Bufferbloat grade: your latency while the line is busy",
                "Pick the server, or let Echoes choose",
                "Moves on by itself when a server can't be reached",
            }, "Speedtest, fast.com"),

        new("CURL", Web, "cURL", "cURL", "Build and send HTTP requests", "IcoCurl", true, "curl.url",
            new[]
            {
                "Any method, headers, body, auth and cookies",
                "Imports curl commands and browser requests",
                "Response, timing and TLS details, and a web preview",
                "Saved requests and history, shared by every cURL tab",
            }, "curl, Postman, Insomnia"),
        new("TLS", Web, "TLS Inspector", "TLS Inspector", "Certificates and TLS setup", "IcoTls", true, "tls.target",
            new[]
            {
                "Certificate chain, names and expiry",
                "Supported TLS versions and ciphers",
                "STARTTLS for mail and other services",
                "Bulk check: the expiry dates of many hosts at once",
            }, "openssl s_client, SSL checkers"),
        new("IP INFO", Web, "IP Info", "IP Info", "Your public IP and GeoIP", "IcoIpInfo", true, "ip.target",
            new[]
            {
                "Your public IP, from many providers",
                "Location, network and owner of any IP",
                "Optional proxy for the lookups",
            }, "what-is-my-IP sites, ipinfo"),
        new("CLOUDFLARE", Web, "Cloudflare", "Cloudflare", "DNS, DDNS, SSL and rules", "IcoCloudflare", false, null,
            new[]
            {
                "DNS records: edit, proxy on or off, backup and restore",
                "Dynamic DNS for a home server or router",
                "SSL/TLS, security, speed and cache, rules",
                "Traffic overview, and several accounts",
            }, "Cloudflare dashboard, ddclient"),
        new("HETZNER", Web, "Hetzner", "Hetzner Cloud", "Servers, firewalls and DNS", "IcoHetzner", false, null,
            new[]
            {
                "Servers: status, addresses, traffic, and power on, reboot or shut down",
                "Firewalls: see and edit the rules, add your own IP",
                "DNS zones and records, zone files, and dynamic DNS",
                "Several projects, their API tokens kept encrypted",
            }, "Hetzner Console, hcloud CLI"),
        new("TELEGRAM BOT", Web, "Telegram Bot", "Telegram Bot", "Call any Bot API method", "IcoTelegram", true, null,
            new[]
            {
                "Call any Bot API method and see the raw reply",
                "Forms for the common methods, and file uploads",
                "Updates, and an optional proxy",
            }, "curl, Postman"),

        new("SSH", Serve, "SSH", "SSH", "Terminal, files and tunnels", "IcoSsh", true, "ssh.host",
            new[]
            {
                "Terminal, with saved servers",
                "Files over SFTP: upload, download, rename, delete",
                "Port forwarding: -L, -R and a SOCKS5 tunnel",
                "Server health: CPU, memory, disks, processes",
                "Warns when a server's key changes",
            }, "PuTTY, WinSCP, ssh"),
        new("SOCKET", Serve, "Socket", "Socket", "TCP / UDP and WebSocket", "IcoSocket", true, "socket.target",
            new[]
            {
                "Raw TCP and UDP client",
                "TCP and UDP server that lists its peers",
                "WebSocket client with headers and a proxy",
                "Send text, hex or JSON",
            }, "netcat (nc), telnet, wscat"),
        new("WEB SERVER", Serve, "Web Server", "Web Server", "Share files, chat, webhooks", "IcoWebServer", false, null,
            new[]
            {
                "Chat and swap files with any browser on your network",
                "A QR code opens the page on a phone",
                "HTTPS with this device's own certificate",
                "Catch webhook requests and see every detail",
                "Starts only when you press Start",
            }, "python -m http.server, Snapdrop, webhook.site"),
        new("PROXY", Serve, "Proxy", "Proxy", "SOCKS5 / HTTP proxy, checker", "IcoProxy", false, null,
            new[]
            {
                "SOCKS5 and HTTP proxy server on this device",
                "Safe by default: this device's own services stay out of reach",
                "Checks proxy lists in any common format",
            }, "3proxy, microsocks, proxy checkers"),

        new("STRING LAB", Workspace, "String Lab", "String Lab", "Encode, hash, convert, diff", "IcoStringLab", true, null,
            new[]
            {
                "Base64, URL, hex and HTML encoding",
                "Hashes, HMAC and JWT",
                "JSON, YAML and XML; a regex tester; text diff",
                "Subnets, timestamps, number bases, cron",
                "UUIDs and strong passwords, with time to crack",
            }, "CyberChef, jwt.io"),
        new("NOTES", Workspace, "Notes", "Notes", "Encrypted notes", "IcoNotes", false, null,
            new[]
            {
                "Notes locked with a master password",
                "Kept encrypted on this device",
            }, null),
        new("DATA", Workspace, "History & Backup", "History & Backup", "Recent inputs and backups", "IcoBackup", false, null,
            new[]
            {
                "Recent inputs of every tool, in one place",
                "One encrypted backup file of your settings",
                "Safe restore: nothing risky switches on by itself",
            }, null),
    };

    private static readonly Dictionary<string, ToolInfo> s_byTag = Index();

    private static Dictionary<string, ToolInfo> Index()
    {
        var map = new Dictionary<string, ToolInfo>(StringComparer.Ordinal);
        foreach (var tool in All) map[tool.Tag] = tool;
        return map;
    }

    public static ToolInfo? Find(string? tag) => tag is not null && s_byTag.TryGetValue(tag, out var tool) ? tool : null;

    /// <summary>
    /// How well a tool answers the launcher's search; 0 when it doesn't. Every word has to be found somewhere: in the
    /// tool's name, its line on what it does, the tools it stands in for ("dig" finds DNS, "nmap" the scanner), its
    /// details or its group. A name that starts with the word counts most, then a later word of the name, then the
    /// name anywhere, the similar tools, the description, and last the details and the group.
    /// </summary>
    public static int Match(ToolInfo tool, IReadOnlyList<string> words)
    {
        int total = 0;
        foreach (string word in words)
        {
            int score = MatchWord(tool, word);
            if (score == 0) return 0;
            total += score;
        }
        return total;
    }

    private static int MatchWord(ToolInfo tool, string word)
    {
        const StringComparison Ignore = StringComparison.OrdinalIgnoreCase;
        if (tool.Title.StartsWith(word, Ignore) || tool.Header.StartsWith(word, Ignore)) return 100;
        if (StartsAWord(tool.Title, word) || StartsAWord(tool.Header, word)) return 80;
        if (tool.Title.Contains(word, Ignore) || tool.Header.Contains(word, Ignore)) return 60;
        if (tool.SimilarTo is { } similar && StartsAWord(similar, word)) return 50;
        if (StartsAWord(tool.Summary, word)) return 40;
        if (tool.Summary.Contains(word, Ignore) || tool.SimilarTo?.Contains(word, Ignore) == true) return 30;
        foreach (string detail in tool.Details)
            if (StartsAWord(detail, word)) return 20;
        foreach (string detail in tool.Details)
            if (detail.Contains(word, Ignore)) return 10;
        return tool.Group.Contains(word, Ignore) ? 5 : 0;
    }

    // The text has a word that begins with this one ("scan" in "Port Scanner", not in "Speccy").
    private static bool StartsAWord(string text, string word)
    {
        for (int at = text.IndexOf(word, StringComparison.OrdinalIgnoreCase); at >= 0;
             at = text.IndexOf(word, at + 1, StringComparison.OrdinalIgnoreCase))
        {
            if (at == 0 || !char.IsLetterOrDigit(text[at - 1])) return true;
        }
        return false;
    }
}
