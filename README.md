# Echoes — Free Network Toolkit for Windows, macOS, Linux and Android

**Connection doctor, ping, traceroute and MTR, internet speed test, port scanner, SSH and SFTP client, cURL / HTTP client, DNS over HTTPS and WHOIS lookup, SSL/TLS checker, Cloudflare manager with dynamic DNS, uptime monitor with Telegram alerts and LAN file sharing: 20 network and developer tools in one free, open-source app.**

[![License: MIT](https://img.shields.io/github/license/SinaXhpm/Echoes)](https://github.com/SinaXhpm/Echoes/blob/master/LICENSE)
![Platforms: Windows, macOS, Linux, Android](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux%20%7C%20Android-blue)
[![Latest release](https://img.shields.io/github/v/release/SinaXhpm/Echoes)](https://github.com/SinaXhpm/Echoes/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/SinaXhpm/Echoes/total)](https://github.com/SinaXhpm/Echoes/releases)

**[Download](https://github.com/SinaXhpm/Echoes/releases/latest)** · [Tools](#tools-at-a-glance) · [Screenshots](#screenshots) · [Install](#download-and-install) · [FAQ](#faq) · [Telegram](https://t.me/the_pink_palace)

<p align="center">
  <img src="docs/screenshots/demo.gif" width="860" alt="Echoes network toolkit slideshow: connection doctor finding SNI filtering with an anti-DPI fragment test, internet speed test with bufferbloat grade, ping latency graph, LAN file sharing and chat with QR code, uptime monitor, DNS over HTTPS resolver comparison, Wi-Fi analyzer, port scanner, cURL HTTP client, SSL/TLS inspector, proxy checker, Cloudflare DNS manager, SSH server health and String Lab JWT decoder">
</p>

## What is Echoes?

Echoes is a free, open-source network toolkit with a simple graphical interface. It brings the tools you would normally run one by one (ping, traceroute, MTR, nmap, curl, PuTTY, netcat, dig, whois, a speed-test website, the Cloudflare dashboard) into one small app.

- **One app, 20 tools.** Test a connection, find the problem, fix your DNS and share a file without switching windows.
- **Finds the cause for you.** The Doctor tells you in one sentence why a site won't open: DNS tampering, SNI filtering, a blocked IP, a filter page, or a server that is down for everyone.
- **Runs everywhere.** Windows, macOS (Intel and Apple Silicon), Linux and Android, from one codebase.
- **Nothing extra to install.** Desktop builds are self-contained native apps: no .NET runtime, fast start-up, low memory use.
- **No admin rights needed.** Where the system blocks normal (ICMP) ping, Echoes switches to UDP by itself.
- **Private.** No account, no ads, no telemetry. Your data stays on your device and secrets are encrypted.
- **Easy on the eyes.** Dark and light themes, a compact window, and layouts that also fit phone screens.

## Contents

- [Download and install](#download-and-install)
- [Tools at a glance](#tools-at-a-glance)
- [Screenshots](#screenshots)
- [Network diagnostics](#network-diagnostics)
- [Web and API tools](#web-and-api-tools)
- [Servers and connections](#servers-and-connections)
- [Workspace and developer tools](#workspace-and-developer-tools)
- [Interface](#interface)
- [Android](#android)
- [Privacy and security](#privacy-and-security)
- [FAQ](#faq)
- [Build from source](#build-from-source)
- [License](#license)

## Download and install

Get the latest version from the **[Releases page](https://github.com/SinaXhpm/Echoes/releases/latest)**.

| Platform | File | How to install |
| :--- | :--- | :--- |
| **Windows 10 / 11** (x64) | `Echoes-Windows-x64.zip` | Extract the zip and run `Echoes.exe`. |
| **macOS** (Intel) | `Echoes-osx-x64.dmg` | Open the .dmg and drag `Echoes.app` to Applications. |
| **macOS** (Apple Silicon M1 / M2 / M3 / M4) | `Echoes-osx-arm64.dmg` | Open the .dmg and drag `Echoes.app` to Applications. |
| **Linux** (x64) | `Echoes-Linux-x64.AppImage` | `chmod +x Echoes-Linux-x64.AppImage`, then run it. If it says FUSE is missing: `sudo apt install libfuse2t64` (`libfuse2` on older releases), or run it with `--appimage-extract-and-run`. |
| **Debian / Ubuntu** | `echoes.deb` | `sudo apt install ./echoes.deb` |
| **Fedora / RHEL / openSUSE** | `echoes-<version>-1.x86_64.rpm` | `sudo dnf install ./echoes-*.rpm` (or `zypper install`) |
| **Android 6.0+** | `Echoes-Android.apk` | Allow installing apps from unknown sources, then open the APK. |

First launch:

- **Windows:** the app isn't code-signed, so SmartScreen may show "Windows protected your PC". Click **More info → Run anyway**.
- **macOS:** the app isn't notarized. If macOS blocks it, open **System Settings → Privacy & Security** and click **Open Anyway**, or run `xattr -dr com.apple.quarantine /Applications/Echoes.app`.
- **Linux:** needs glibc 2.35 or newer (Ubuntu 22.04+, Debian 12+, Fedora 36+). The tray icon needs a StatusNotifierItem host (KDE Plasma, or GNOME with the AppIndicator extension).
- **macOS:** needs macOS 12 or newer. On macOS 15+, allow **Local Network** access when asked (or later in System Settings › Privacy & Security), or local devices look unreachable. Sites that accept only TLS 1.3 can't be opened by the macOS TLS stack of .NET 8; the TLS Inspector still analyses them.

Echoes shows a small notice in the sidebar when a new version is out. The **About** box (the ⓘ button next to the name, or **About** in the Android menu) shows your version, checks for updates on demand, links to GitHub, the releases and the issue tracker, and copies your version and platform details for a bug report.

<p align="center">
  <img src="docs/screenshots/about-box.png" width="640" alt="Echoes About box: version, update check against GitHub releases, platform and runtime details, data folder, and links to GitHub, releases and bug reports">
</p>

## Tools at a glance

| Tool | What it does | Similar to |
| :--- | :--- | :--- |
| [Ping, Traceroute & MTR](#ping-traceroute-and-mtr) | Live ping stats, TCP ping, the route to a host, and where packets get lost | ping, tcping, tracert, mtr, WinMTR, PingPlotter |
| [Doctor](#connection-doctor) | Finds why a site won't open: DNS tampering, SNI filtering, blocked IP, HTTP vs HTTPS, MTU, down for everyone; also through a proxy | OONI Probe, manual dig + curl + openssl |
| [DNS & WHOIS](#dns-lookup-and-whois) | DNS over UDP, HTTPS or TLS, resolver comparison, email (SPF / DKIM / DMARC) check, WHOIS | dig, kdig, DNS benchmark, MXToolbox |
| [Port Scanner](#port-scanner) | Finds open TCP / UDP ports and the services behind them | nmap, Zenmap, Angry IP Scanner |
| [Check Host](#check-host-from-around-the-world) | Ping, HTTP, TCP, UDP and DNS checks from servers worldwide | check-host.net |
| [Monitor](#uptime-monitor) | Watches servers and websites, certificate and domain expiry, with Telegram alerts | Uptime Kuma, UptimeRobot |
| [Network](#network-info) | Your adapters, Wi-Fi networks and channels, ARP neighbors, open ports and routing table | ipconfig, arp, netstat, Wi-Fi analyzers |
| [Speed Test](#internet-speed-test) | Internet speed, latency, jitter and bufferbloat to the server you pick | Speedtest, fast.com |
| [cURL](#curl-http-client) | Builds and sends HTTP requests, imports curl commands | curl, Postman, Insomnia |
| [TLS Inspector](#ssltls-inspector) | Certificate chain, expiry, TLS versions and ciphers | openssl s_client, SSL checkers |
| [IP Info](#ip-lookup-and-geoip) | Your public IP and the location of any IP | what-is-my-IP sites, ipinfo |
| [Cloudflare](#cloudflare-manager) | DNS, dynamic DNS, SSL/TLS, security, rules, cache and analytics | Cloudflare dashboard, ddclient |
| [Telegram Bot](#telegram-bot-api-tester) | Calls any Bot API method and shows the raw reply | curl, Postman |
| [SSH](#ssh-client) | SSH terminal, SFTP files, port forwarding and server health | PuTTY, WinSCP, ssh |
| [Socket](#tcp-udp-and-websocket-tool) | Raw TCP / UDP client and server, and a WebSocket client | netcat (nc), telnet, wscat |
| [Web Server](#file-sharing-web-server-and-request-catcher) | Chat and swap files with any browser on your network, or catch webhook requests | python -m http.server, Snapdrop, webhook.site |
| [Proxy](#socks5-and-http-proxy-server-and-proxy-checker) | SOCKS5 + HTTP proxy server, and a checker for proxy lists | 3proxy, microsocks, proxy checkers |
| [String Lab](#string-lab) | Encoding, hashes, JWT, JSON / YAML, regex, subnets, cron and more | CyberChef, jwt.io |
| [Notes](#encrypted-notes) | Notes locked with a master password | encrypted notepad |
| [History & Backup](#history-and-encrypted-backup) | Recent inputs per tool, and one encrypted backup file | — |

## Screenshots

<table>
  <tr>
    <td><img src="docs/screenshots/doctor-sni-filtering.png" width="380" alt="Connection doctor finding SNI filtering, with the TLS handshake trace and anti-DPI retries"><br><b>Doctor</b>: SNI filtering found, and the fix that gets through</td>
    <td><img src="docs/screenshots/doctor-step-trace.png" width="380" alt="Connection doctor with Details on: TCP, QUIC, TLS and HTTPS checks traced step by step"><br><b>Doctor</b>: every check traced step by step, with timings</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/speed-test-result.png" width="380" alt="Internet speed test result with download, upload, ping, jitter, bufferbloat grade and history"><br><b>Speed test</b>: speed, latency under load, bufferbloat</td>
    <td><img src="docs/screenshots/speed-test-server-picker.png" width="380" alt="Speed test server picker: Cloudflare and test-file hosts by region, searchable"><br><b>Speed test</b>: pick the server, or add your own</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/ping-live-graph.png" width="380" alt="Ping with live replies, packet loss, min / avg / max / mdev and a latency graph"><br><b>Ping</b>: live replies, stats and latency graph</td>
    <td><img src="docs/screenshots/ping-packet-options.png" width="380" alt="Ping packet options: payload size, Don't fragment, TTL, interval, count, timeout, IPv4 / IPv6"><br><b>Ping</b>: size, Don't fragment, TTL, count and more</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/share-chat.png" width="380" alt="File sharing web server: HTTPS link, PIN and QR code, and a chat with a phone and a laptop"><br><b>Share &amp; chat</b>: link, PIN and QR code, live chat</td>
    <td><img src="docs/screenshots/share-files.png" width="380" alt="Share and chat files: shared and received files, the download folder, stored size and Clean up"><br><b>Share &amp; chat</b>: files both ways, folder and Clean up</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/share-browser-desktop.png" width="380" alt="The share page in a desktop browser: chat, drop files to send, shared files to download"><br><b>The other side</b>: just a browser, no app</td>
    <td><img src="docs/screenshots/uptime-monitor.png" width="380" alt="Uptime monitor with up, down, pending and paused servers, history bars and uptime"><br><b>Monitor</b>: up, down and pending, history and uptime</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/uptime-monitor-telegram-alerts.png" width="380" alt="Uptime monitor settings: checks, thresholds, alert sounds and Telegram alerts through a proxy"><br><b>Monitor</b>: sounds and Telegram alerts</td>
    <td><img src="docs/screenshots/dns-compare-resolvers.png" width="380" alt="DNS resolver comparison over plain DNS, DNS over HTTPS and DNS over TLS, with tampered and filtered answers flagged"><br><b>DNS</b>: compare resolvers, tampering flagged</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/android-drawer.png" width="185" alt="Echoes on Android: the slide-out tool menu"> <img src="docs/screenshots/android-doctor.png" width="185" alt="Connection doctor on an Android phone"><br><b>Android</b>: menu and Doctor</td>
    <td><img src="docs/screenshots/android-share-chat.png" width="185" alt="Share and chat on an Android phone"> <img src="docs/screenshots/share-browser-phone.png" width="185" alt="The share page in a phone browser"><br><b>Phones</b>: the app, and the page in a phone browser</td>
  </tr>
</table>

<details>
<summary><b>More screenshots</b>: TCP ping, email check, DoH / DoT, port scanner, network and Wi-Fi, cURL, TLS, proxy, Cloudflare, SSH, String Lab, About, light theme</summary>

<table>
  <tr>
    <td><img src="docs/screenshots/ping-tcp.png" width="380" alt="TCP ping to port 443 with connect times"><br><b>Ping</b>: TCP ping to a port</td>
    <td><img src="docs/screenshots/dns-email-check.png" width="380" alt="Email check: MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT and blocklists"><br><b>DNS</b>: email check (MX, SPF, DKIM, DMARC…)</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/dns-doh-dot-lookup.png" width="380" alt="DNS lookup over DNS over HTTPS, DNS over TLS and plain DNS"><br><b>DNS</b>: lookups over DoH, DoT and plain DNS</td>
    <td><img src="docs/screenshots/port-scanner.png" width="380" alt="Port scanner results with open and closed ports and service version detection"><br><b>Port scanner</b>: open ports and service versions</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/network-interfaces.png" width="380" alt="Network interfaces with IPv4, IPv6, gateway, DNS servers and MAC"><br><b>Network</b>: interfaces</td>
    <td><img src="docs/screenshots/wifi-analyzer.png" width="380" alt="Wi-Fi analyzer with signal, channel chart per band and nearby networks"><br><b>Network</b>: Wi-Fi analyzer and channel chart</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/curl-http-client.png" width="380" alt="cURL HTTP client with a POST request and a pretty-printed JSON response"><br><b>cURL</b>: request and pretty JSON response</td>
    <td><img src="docs/screenshots/tls-inspector.png" width="380" alt="SSL/TLS inspector: trusted certificate, TLS versions, HSTS, OCSP and the chain"><br><b>TLS inspector</b>: verdict, versions, HSTS, chain</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/proxy-server.png" width="380" alt="SOCKS5 and HTTP proxy server with a live connection log and traffic stats"><br><b>Proxy</b>: server with a live log</td>
    <td><img src="docs/screenshots/proxy-checker.png" width="380" alt="Proxy checker results: type, speed, exit IP and country for each proxy"><br><b>Proxy</b>: checker with exit IP and country</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/cloudflare-dns-records.png" width="380" alt="Cloudflare DNS records with proxied and DNS-only switches"><br><b>Cloudflare</b>: DNS records</td>
    <td><img src="docs/screenshots/cloudflare-overview.png" width="380" alt="Cloudflare overview: traffic for 24 hours, cache share, threats and quick switches"><br><b>Cloudflare</b>: traffic overview</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/ssh-server-health.png" width="380" alt="SSH client server health: CPU, load, memory, swap, disks and top processes"><br><b>SSH</b>: server health</td>
    <td><img src="docs/screenshots/string-lab-jwt.png" width="380" alt="String Lab JWT decoder verifying an HS256 signature"><br><b>String Lab</b>: JWT decode and verify</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/about-box.png" width="380" alt="About box with version, update check and platform details"><br><b>About</b>: version, update check, bug-report info</td>
    <td><img src="docs/screenshots/doctor-sni-filtering-light.png" width="380" alt="Connection doctor in the light theme"><br><b>Light theme</b>: Doctor</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/speed-test-result-light.png" width="380" alt="Internet speed test in the light theme"><br><b>Light theme</b>: speed test</td>
    <td><img src="docs/screenshots/share-chat-light.png" width="380" alt="Share and chat in the light theme"><br><b>Light theme</b>: share &amp; chat</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/android-speed-test.png" width="185" alt="Internet speed test on an Android phone"> <img src="docs/screenshots/android-monitor.png" width="185" alt="Uptime monitor on an Android phone"><br><b>Android</b>: speed test and monitor</td>
    <td><img src="docs/screenshots/android-share-files.png" width="185" alt="Received files on an Android phone with Save and Clean up"><br><b>Android</b>: received files, Save and Clean up</td>
  </tr>
</table>

</details>

## Network diagnostics

### Ping, traceroute and MTR

See whether a host is up, how fast it answers, which route your traffic takes, and where packets get lost.

<p align="center">
  <img src="docs/screenshots/ping-live-graph.png" width="640" alt="Echoes ping tool: live ICMP replies with packet loss, min / avg / max / mdev and a latency graph">
</p>

- **Ping:** live replies with loss and min / avg / max / mdev, plus a latency graph. IPv4 and IPv6.
- **Packet options:** payload size, interval, count, timeout, TTL, Don't fragment and IPv4 / IPv6. With Don't fragment, a packet too big for the path says so ("Packet too big", with the MTU where the system reports it): an easy way to find the path MTU.
- **TCP ping:** connects to a port (443, or the port in a pasted host:port or URL) every interval and times it (SYN to SYN/ACK). Works where ICMP is blocked and on Android, and tells a closed port (refused), a silent drop (timeout) and a DNS failure apart.
- **Traceroute:** the classic hop-by-hop route.
- **MTR:** a live table for every hop (loss, last / avg / best / worst, jitter, reverse DNS, multiple paths) that shows exactly where a problem starts.
- **Works without admin rights:** where ICMP isn't allowed (locked-down Linux, containers), Echoes uses UDP datagrams by itself, for traceroute and MTR too on Linux and Android. If neither works, it tells you why.
- Optional alerts when a host comes online or goes offline.

### Connection doctor

Type a site or server and press Diagnose. Echoes checks everything between you and it, then says in one plain sentence why it doesn't work, and what to do.

<p align="center">
  <img src="docs/screenshots/doctor-sni-filtering.png" width="640" alt="Echoes connection doctor diagnosing SNI filtering: the TLS handshake traced step by step, anti-DPI fragment retries that get through, and the filter's HTTP block page">
</p>

- **Your network:** adapter, gateway, VPN and system proxy, internet access, and captive portals.
- **DNS:** your system resolver and plain DNS compared with encrypted DNS (DoH). Spots tampered answers (including the known filter addresses such as `10.10.34.x`), forged replies, and names whose lookups are dropped.
- **Connection and TLS:** TCP, ping and path MTU (not on macOS) to the real address, and TLS with and without the site's name, which tells apart SNI filtering, a blocked IP and a cut handshake. Certificate problems are reported separately.
- **HTTP and HTTPS together:** both are tested side by side (status, redirects, filter block pages, country blocks 403 / 451), so you see when only one of them is cut.
- **Outside view:** the same site checked from several countries through check-host.net, so you know if it is down for everyone or just for you.
- **Through a proxy (optional):** run the same connection, TLS, HTTP and HTTPS checks through an HTTP, HTTPS or SOCKS proxy and compare: "blocked on your network, works through the proxy", or the proxy itself refusing the login.
- **Step-by-step trace:** expand any check (or turn on **Details**) to see exactly where it stops, with timings: each DNS record and resolver, every TCP connect per address and port (answered, refused or dropped), the TLS handshake stage by stage (ClientHello → ServerHello → certificate → done), and each HTTP stage.
- **Anti-DPI test:** when SNI filtering cuts a site, Doctor retries with the ClientHello split across TCP segments or TLS records and with mixed-case names, and tells you when **fragment** in your client (v2rayNG, Hiddify, Xray) would get through.
- **QUIC / UDP 443:** shows whether UDP-based protocols (HTTP/3, Hysteria2, TUIC) can work on your network.
- Every check appears live with its evidence; copy the whole report, trace included, with one click.

### DNS lookup and WHOIS

<p align="center">
  <img src="docs/screenshots/dns-compare-resolvers.png" width="640" alt="Echoes DNS resolver comparison: plain DNS, DNS over HTTPS and DNS over TLS resolvers ranked by speed, with tampered, filtered and differing answers flagged">
</p>

- Look up A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA and PTR records, several types at once.
- **Encrypted DNS:** use plain resolvers (`1.1.1.1`, `8.8.8.8:53`), DNS over HTTPS (`https://1.1.1.1/dns-query`) or DNS over TLS (`tls://1.1.1.1`), picked from a presets menu (Cloudflare, Google, Quad9, OpenDNS, AdGuard, Shecan, Electro) or typed in. Each answer shows which transport answered and how fast.
- **Compare resolvers:** query one name through many resolvers at once: median speed, success rate and answers, with tampered or filtered answers flagged and the fastest trustworthy resolver recommended.
- **Email check:** MX, SPF (with the 10-lookup limit), DMARC, DKIM (common selectors), MTA-STS, TLS-RPT and spam blocklists for a domain, each with a one-line fix.
- Domain registration details through RDAP, the modern WHOIS.
- Paste a full URL and Echoes takes the host name out of it.

### Port scanner

A fast and accurate TCP / UDP port scanner that reports ports the way nmap does.

<p align="center">
  <img src="docs/screenshots/port-scanner.png" width="640" alt="Echoes port scanner results like nmap -sV: open and closed TCP ports with service and version detection (FTP, SSH, SMTP, HTTP)">
</p>

- **Targets:** IPs, host names, ranges (`10.0.0.1-50`) and CIDR blocks (`10.0.0.0/24`), IPv4 and IPv6. Paste any text and the addresses are picked out of it.
- **Ports:** ready-made lists (top 20 / 100 / 1000), your own ranges, and `U:` for UDP ports.
- **Clear results:** open, closed or filtered, with the reason for each.
- **Service and version detection** (`-sV`), real UDP probes (DNS, NTP, SNMP, SSDP, NetBIOS, SIP, STUN, …), reverse DNS, and the device maker (from the MAC address, on Windows and Linux) on your local network.
- Host discovery before scanning (`-Pn` to skip it), ping-only sweeps (`-sn`) and nmap-style timing templates.
- **No fake open ports:** tarpits, proxies and antivirus interception are detected and flagged.
- Live progress with speed and time left, a repeat mode that highlights what changed, an nmap-style report, and JSON / CSV export.

### Check host from around the world

Test a website or server from many countries at once, powered by [check-host.net](https://check-host.net).

- Ping, HTTP, TCP, UDP and DNS checks from many nodes at the same time.
- For every node: each ping with loss and jitter, the HTTP status and error, connect time, DNS answers with their TTL, and the node's country, city and ASN.
- **Spot DNS tampering:** answers that differ from the majority are flagged.
- A summary (fastest and slowest node, countries covered), filters and sorting, and nodes picked by region or one by one.
- Copy the results, or save them as text, CSV or JSON. Optional proxy.

### Uptime monitor

Keep an eye on your servers and websites, and hear when something changes.

<p align="center">
  <img src="docs/screenshots/uptime-monitor.png" width="640" alt="Echoes uptime monitor: websites and servers up, down, pending and paused, with history bars, uptime and response times">
</p>

- Ping, TCP and HTTP checks for every target, with your own interval and timeout. Paste a whole list at once.
- Live uptime, response-time graphs and an event log.
- **No false alarms:** a target counts as down only after several failed checks in a row, and as up again after several successes (you choose how many).
- **Telegram alerts:** get "down", "back up" and warnings from your own Telegram bot on your phone. "Find my chat" sets it up, a test message checks it, and alerts can go through a proxy where Telegram is blocked. The bot token is stored encrypted.
- **Expiry warnings, automatic:** HTTPS certificates expiring within 14 days, and domains expiring within 30 days (via RDAP).
- **Optional checks per target:** alert when DNS answers change (spot hijacking), or when a page does or doesn't contain a text.
- Warnings are a third state next to up and down, and don't count as downtime.
- **Alert sounds on every platform:** distinct chimes for "went down", "back up" and warnings, each with its own switch, a volume slider and a Test button. On Android they follow the phone's notification volume and Do not disturb.
- **Starts by itself:** monitoring can start when Echoes opens; on desktop, Echoes can also start at sign-in straight into the system tray, and on Android when the phone starts. Starts nobody clicked wait for the network first, so a slow connection at boot doesn't raise false alarms.
- Your monitors, their checks and all settings are saved as you change them.

### Network info

<p align="center">
  <img src="docs/screenshots/wifi-analyzer.png" width="640" alt="Echoes Wi-Fi analyzer: the connected network's signal and link rate, a 5 GHz channel chart with the clearest channels, and nearby Wi-Fi networks">
</p>

- **Interfaces:** every adapter with its IPv4 / IPv6 addresses, MAC, gateway, DNS servers and link speed.
- **Wi-Fi analyzer:** your connection (signal in % and dBm, channel and width, band, link rate, security), nearby networks, and a channel chart per band (2.4 / 5 / 6 GHz) with a hint about the clearest channel. Windows and Linux.
- **Neighbors:** the devices your computer has talked to (the ARP cache, IP ↔ MAC).
- **Ports:** listening ports and active TCP / UDP connections, like `netstat`.
- **Routing:** the routing table.

Interfaces work everywhere. Open ports are listed on every desktop system; neighbors, routing and the Wi-Fi analyzer on Windows and Linux.

### Internet speed test

Measure your connection the way it feels in real use.

<p align="center">
  <img src="docs/screenshots/speed-test-result.png" width="640" alt="Echoes internet speed test: download and upload speed, ping, jitter, loaded latency with a bufferbloat grade, and the test history">
</p>

- Download and upload speed, ping and jitter.
- **Bufferbloat grade:** your latency while the line is busy, the reason calls and games lag during big downloads.
- **Pick where to test:** Cloudflare's nearest data center, or public test files from DataPacket, Leaseweb, Linode, Scaleway, Selectel and Tele2 in over 20 cities across Europe (Istanbul, Frankfurt, Amsterdam, London, Paris, Vienna, Stockholm and more), Asia and the Americas, or your own server or file. Search by city, country or provider. Plain test files measure download and latency; Cloudflare and Tele2 also measure upload.
- **Connections:** 1 to 16 parallel connections (6 by default, like web speed tests); the upload uses half.
- Keeps your last 20 results; copy a result with one click.

## Web and API tools

### cURL HTTP client

A complete HTTP client, like Postman or Insomnia, that understands curl.

<p align="center">
  <img src="docs/screenshots/curl-http-client.png" width="640" alt="Echoes cURL HTTP client: a POST request with a JSON body and the pretty-printed JSON response with status, time and size">
</p>

- **Import curl commands:** paste any `curl` command (bash, cmd or PowerShell, or a browser's "Copy as cURL") and the method, URL, headers, body, auth, cookies, proxy and options are filled in.
- Edit query parameters, headers, the body (JSON / XML / text with validation, form, multipart with files), auth and cookies.
- Send with your system's curl or the built-in engine (HTTP/1.1, HTTP/2, and HTTP/3 on Windows 11 and on Linux with libmsquic), through an HTTP or SOCKS proxy, with an IP override or from a chosen network interface.
- A response viewer that stays fast on large bodies: JSON / XML highlighting and search, headers and cookies, a timing breakdown (DNS, connect, TLS, first byte), the redirect chain, TLS details and a page preview. Save the body to a file.
- Code snippets for curl, PowerShell, Python, JavaScript, HTTPie and wget.
- Saved requests (encrypted) and a request history.

### SSL/TLS inspector

Check a site's certificate and TLS setup in seconds.

<p align="center">
  <img src="docs/screenshots/tls-inspector.png" width="640" alt="Echoes SSL/TLS inspector: trusted certificate verdict, TLS 1.3 and 1.2 supported, cipher, ALPN, HSTS, OCSP stapling, expiry and the certificate chain">
</p>

- A clear verdict, with the exact problem when there is one: name mismatch, untrusted, expired, revoked, …
- The full certificate chain with details, fingerprints and PEM export.
- Which TLS versions (1.0 to 1.3) the server accepts, each tested on its own, plus the cipher, ALPN, OCSP stapling and HSTS.
- Custom SNI, and mail and FTP servers too (it switches to STARTTLS by itself).
- **Bulk check:** the certificate expiry dates of many hosts at once.

### IP lookup and GeoIP

- Your public IP address, and the location and network (ISP, ASN) of any IP.
- Answers from several providers (ip-api.com, ipwho.is, ipapi.co, ipinfo.io, freeipapi, GeoJS, iplocation.net) cross-checked side by side, or one provider of your choice.
- Country flags, a map link, and HTTP / SOCKS5 proxy support, to see the IP your proxy or VPN shows the world.

### Cloudflare manager

Manage your Cloudflare domains without opening the dashboard.

<p align="center">
  <img src="docs/screenshots/cloudflare-dns-records.png" width="640" alt="Echoes Cloudflare manager: a zone's DNS records with proxied and DNS-only switches, dynamic DNS, backup and restore">
</p>

- **Overview:** traffic for the last 24 hours or 7 days (requests, cached share, bandwidth, visitors, threats, top countries) and quick switches for "I'm under attack" and development mode.
- **DNS records** (A, AAAA, CNAME, TXT, MX, NS, PTR, CAA, SRV): search, edit, a one-click proxied / DNS-only switch, TTL and comments. DNSSEC on / off, with the DS record for your registrar.
- **Backup and restore:** save a zone's records to a JSON file and restore them. A restore shows what will change first, never deletes, and can copy records to another domain. BIND zone files can be exported and imported.
- **SSL/TLS:** encryption mode (Off / Flexible / Full / Full (strict)), Encrypted Client Hello (ECH), Always Use HTTPS, minimum TLS version, TLS 1.3, HSTS, Universal SSL and edge certificates with their expiry.
- **Security:** security level, challenge passage, bot fight mode, blocking AI crawlers, WAF custom rules, and IP access rules for an IP, range, ASN or country.
- **Speed and cache:** Early Hints, Rocket Loader, Tiered Cache, cache purge (everything or chosen URLs), HTTP/3, WebSockets, IPv6, and pausing Cloudflare for a site.
- **Rules and sites:** redirect rules (301 / 302 / 307 / 308), and adding a new site with its nameservers.
- **Dynamic DNS (DDNS):** keep A / AAAA records pointed at your current public IP, so a home server or router stays reachable by name. The IP is cross-checked between several services, records change only when needed, and updates continue in the background (also from the tray) without unlocking the vault.
- **Several accounts:** add each Cloudflare account with an API token (or a Global API key and email) and switch between them from the top of the page. Echoes checks a new account with Cloudflare before saving it, and each account can use its own proxy. Everything is kept in an encrypted vault.
- When something isn't allowed, Echoes says which token permission or plan it needs.

### Telegram Bot API tester

- Pick any Bot API method (getMe, getUpdates, sendMessage, sendPhoto, setWebhook, …) and fill in a simple form for its parameters.
- Upload files, or use a file_id or URL.
- See the raw JSON reply.
- Your bot token (and proxy password) is kept so you don't paste it again, saved only encrypted on this device, and never logged or shown.

## Servers and connections

### SSH client

<p align="center">
  <img src="docs/screenshots/ssh-server-health.png" width="640" alt="Echoes SSH client: server health over SSH with CPU, load, memory, swap, disk usage and the top processes, and a saved server">
</p>

- An SSH terminal with command history; password, private key (OpenSSH, PEM, PuTTY .ppk) or keyboard-interactive login, tried automatically in that order.
- **Saved servers:** pick one and connect in one click; passwords and passphrases are stored encrypted.
- **Files (SFTP):** browse, upload, download, rename and delete, with progress and cancel.
- **Port forwarding:** local (`-L`), remote (`-R`) and a SOCKS5 tunnel (`-D`), each with its own status.
- **Server health:** CPU, load, memory, swap, disks and the busiest processes, with nothing installed on the server.
- **Host-key pinning:** each server's key is remembered on first use (SHA-256 fingerprint), and you are warned if it changes.
- Connect through a SOCKS5 proxy. Paste `ssh -p 2222 root@host` and the host, user and port fields fill themselves.

### TCP, UDP and WebSocket tool

A netcat-style tool for raw TCP and UDP, plus a WebSocket client.

- TCP / UDP client or server mode. The server talks to several clients at once.
- Send text or hex, with the line ending you choose; optional TLS.
- **WebSocket client:** `ws://` and `wss://` with custom headers, subprotocols and an optional proxy; send text, JSON (checked before sending) or binary; ping with round-trip time; close codes and TLS details.
- A timestamped transcript as text, hex or both.

### File sharing web server and request catcher

Chat and swap files with any phone or computer on your network. The other side only needs a web browser, even when the two systems can't reach each other any other way (no remote desktop, no shared folder).

<p align="center">
  <img src="docs/screenshots/share-chat.png" width="640" alt="Echoes LAN file sharing and chat: HTTPS share link, 6-digit PIN and QR code, and a live chat with a phone and a laptop in their browsers">
</p>

- **Share & chat:** one link or QR code opens a page that works in every browser, phones included: a live chat with copy buttons and clickable links, sending files to this device (drag & drop, paste, resumed after a dropped connection), and downloads of the files you share. Files you share also appear in the chat.
- **HTTPS by default** with this device's own certificate (the browser warns once; compare the fingerprint shown in Echoes), on the same port that redirects plain HTTP. A 6-digit **PIN** protects the page, and the QR code carries it, so scanning logs straight in.
- Received files land in Downloads\Echoes (or a folder you pick; on Android one you choose), are never overwritten, are marked as downloaded on Windows, and respect a size cap and the free disk space. The Files tab shows that folder in full and how much Echoes has stored there; **Clean up** deletes the files Echoes received (nothing else in the folder) after asking.
- Choose the network interface and port, limit connections, and see live stats and a request log. Scripts can download with the PIN as the password (`curl -k -u :PIN -OJ <link>`).
- **Catch requests (webhook tester):** a local endpoint that lists every request it receives (method, path, headers, query, body as pretty JSON, form fields or hex) with "Copy as curl", a reply you choose (status, body, delay), automatic CORS, and a WebSocket echo endpoint.
- Built in, no extra software: works on desktop and Android.

### SOCKS5 and HTTP proxy server and proxy checker

<p align="center">
  <img src="docs/screenshots/proxy-checker.png" width="640" alt="Echoes proxy checker: a SOCKS5 and HTTP proxy list tested for type, connect time, first byte, exit IP and country">
</p>

- A SOCKS5 and HTTP proxy on a single port; the protocol is detected for each connection.
- Optional username and password, a live connection log and traffic stats.
- **Safe by default:** other devices can't reach this device's own services through it, and while it has no password they reach only the internet and their own local network, not the private networks behind this device (WSL, Docker, virtual machines, VPN ranges).
- **Check proxies:** paste a list in any common format; each proxy is tested (SOCKS5, SOCKS4 or HTTP detected automatically) for speed, exit IP and country. Copy the working ones or export them.
- Built in, no extra software: works on desktop and Android.

## Workspace and developer tools

### String Lab

Everyday developer text tools in one place.

<p align="center">
  <img src="docs/screenshots/string-lab-jwt.png" width="640" alt="Echoes String Lab JWT decoder: an HS256 token decoded and its signature verified">
</p>

- **Encode / decode:** Base64 and Base64URL, URL encoding (plus a URL parser), hex, binary, and HTML / XML / JSON / Unicode escaping.
- **Hashes:** MD5, SHA-1, SHA-2, SHA-3 (where the system supports it: Windows 11, Linux), CRC32 and HMAC, file checksums with comparison, and a hash identifier that guesses a hash's type (bcrypt, Argon2, NTLM, SHA, …).
- **Regex tester:** matches with capture groups, replace and split, and ready-made patterns (IP, domain, URL, email, MAC, JWT, GUID, dates, …).
- **JSON / XML:** format, minify, validate (with line and column) and sort keys; convert JSON ↔ YAML, JSON ↔ CSV, query string ↔ JSON, and CSV → Markdown table.
- **JWT:** decode, verify (HS / RS / PS / ES) and sign (HS256 / 384 / 512).
- **Network math:** subnet / CIDR calculator, and an IP converter (IPv4 ↔ integer / hex / binary, IPv6 forms, PTR names).
- **Converters:** Unix timestamp ↔ date, number bases 2 to 36, and a cron expression explainer that lists the next run times.
- **Text:** compare two texts (diff), change case (camel, Pascal, snake, kebab, …), and line tools (sort, remove duplicates, trim, join, find and replace, …).
- **Generators:** UUID v4 / v7, ULID, NanoID, strong passwords, tokens and PINs, from a cryptographically secure random source.

### Encrypted notes

- Notes encrypted with AES-256-GCM, with a key made from your master password (PBKDF2-SHA256, 600,000 iterations).
- The master password is never stored. If you lose it, the notes can't be recovered.

### History and encrypted backup

- Recent hosts, URLs and other inputs are remembered for each tool and suggested as you type.
- Export everything (profiles, settings and notes) to one password-protected file, and restore it on another computer. Fully offline: no account, no cloud.
- **Safe restore:** a backup can't switch anything risky on behind your back. Proxies, TLS-skip, a saved request's own proxy or IP override, Telegram alerts and the monitor's start-with-Echoes / start-at-boot come in switched off (and are listed), SSH port forwards and the WebSocket proxy aren't imported, and this device's SSH host-key pins are kept.

## Interface

<p align="center">
  <img src="docs/screenshots/doctor-sni-filtering-light.png" width="640" alt="Echoes in the light theme: the connection doctor's SNI filtering verdict with the sidebar of all 20 tools">
</p>

- **Dark and light themes,** built only from solid colors (no blur or transparency), so they stay light on older computers. Switch with the sun / moon button next to the Echoes logo (in the drawer on Android). The change is instant and remembered.
- **Compact window:** the sidebar groups the tools (Diagnose, Web & API, Serve & Connect, Workspace) and always shows their names; the window opens just tall enough for the list.
- **Runs in the system tray:** closing the window keeps the web server, proxy, monitor and scans running. Reopen Echoes from the tray icon or by launching it again; quit from the tray menu, where "Close to tray" can also be turned off.
- **Smart paste:** every host, URL and proxy field cleans what you paste. It takes the host out of a URL, log line, e-mail address, `user@host:port` or defanged link (`hxxps://evil[.]com`), and the addresses out of a block of text for the scanner. A short hint says what was cleaned; **Ctrl+Z** undoes it, and **Ctrl+Shift+V** pastes the raw text.
- The Inter font on every platform.

## Android

The Android app has the same tools, made for touch: a slide-out menu, bigger touch targets and layouts that fit phone screens. The Uptime Monitor, Port Scanner, Web Server and Proxy keep running in the background, so a scan or a file share isn't cut off when you switch apps.

<p align="center">
  <img src="docs/screenshots/android-screens.png" width="640" alt="Echoes on Android: the slide-out tool menu, the connection doctor and the file sharing chat on a phone">
</p>

Not available on Android: the system curl engine (the built-in engine is used instead), the Wi-Fi analyzer, and the Neighbors / Ports / Routing views of the Network tool. Dynamic DNS updates run while the app is running.

## Privacy and security

- **No account, no ads, no telemetry.** Echoes only contacts the hosts you test and the services a tool is built on (for example check-host.net, the speed test's servers (Cloudflare, or the server you pick), public DNS-over-HTTPS resolvers, the IP-info providers and rdap.org / rdap.verisign.com; the uptime monitor looks up its domains' expiry there; the Doctor checks internet access with connectivitycheck.gstatic.com; Dynamic DNS reads your public IP from Cloudflare, ipify, ident.me and icanhazip), plus GitHub to check for updates.
- **Your data stays on your device:** `%APPDATA%\Echoes` on Windows, `~/.config/Echoes` on macOS and Linux.
- **Secrets are encrypted:** notes and the Cloudflare vault use AES-256-GCM with a key made from your master password; saved requests, SSH passwords, the Telegram alert token and other secrets are encrypted on disk with a per-install key. Dynamic DNS keeps such a device-encrypted copy of its account's token so it can run while the vault is locked; removing the record or the account deletes it. In memory, keys and decrypted data are wiped after use, on lock and on exit.
- **Open source (MIT):** every line can be read, checked and built by anyone.

## FAQ

**What is Echoes?**
A free, open-source, all-in-one network and developer toolkit for Windows, macOS, Linux and Android: ping and MTR, speed test, port scanner, SSH, raw sockets, DNS and WHOIS, check host, cURL, TLS inspector, file-sharing web server, proxy server, Cloudflare manager, IP lookup, uptime monitor, encrypted notes and string / JSON tools.

**Is Echoes really free?**
Yes. It is MIT-licensed, with no ads, no paid version and no account.

**Do I need admin or root rights?**
No. Echoes runs as a normal user. Where the system doesn't allow normal (ICMP) ping, it switches to UDP by itself.

**Do I need to install .NET?**
No. The desktop builds are self-contained native apps: download and run.

**Why won't a website open for me?**
Open the Doctor and enter the site. It checks your network, DNS, the connection, TLS and HTTP, and compares with servers abroad, then tells you whether it's DNS tampering, SNI filtering, a blocked IP, a filter page, or a site that is down for everyone.

**How do I find where packet loss happens?**
Open Ping, choose **MTR** and enter the host. The hop where loss starts, and continues on every hop after it, is where the problem is.

**How do I check if a port is open?**
Use the Port Scanner for your own network or a server you manage. To test from outside, use Check Host with a TCP check, which tries the port from servers around the world.

**How do I check if a website is down for everyone or just me?**
Run a Check Host HTTP or ping check: it tests the site from many countries at once.

**How do I test my internet speed and bufferbloat?**
Open Speed Test and press Start. Besides download and upload, it measures your latency under load and gives a bufferbloat grade.

**Can I import a curl command, or "Copy as cURL" from my browser?**
Yes. Paste it into the cURL tool and every part of the request is filled in.

**Can I manage Cloudflare DNS without the dashboard?**
Yes. Add an API token in the Cloudflare tool to edit DNS records, SSL/TLS, security, cache and rules, and to back up or restore a zone.

**Can I get uptime alerts on my phone?**
Yes. In Monitor settings, add your Telegram bot's token and press "Find my chat"; down, back-up and expiry alerts then arrive in Telegram, through a proxy if needed.

**How do I keep a domain pointed at my home IP (dynamic DNS)?**
In the Cloudflare tool, turn on "Keep updated with my IP" for an A or AAAA record. Echoes updates it whenever your public IP changes.

**How do I test DNS over HTTPS or find the fastest DNS server?**
In DNS, type a resolver such as `https://1.1.1.1/dns-query` or `tls://1.1.1.1`, or use Compare to test many resolvers at once.

**How do I share files between my phone and PC on the same Wi-Fi?**
Press Start sharing in Web Server and scan the QR code with the other device. It opens a chat page in the browser where you can send text and files both ways; add files in Echoes to offer them for download.

**Is Echoes a replacement for nmap, Postman, PuTTY or Wireshark?**
It covers the everyday tasks of nmap, curl / Postman, PuTTY, WinSCP and netcat in one app. For deep, specialized work the dedicated tools still go further, and Echoes doesn't capture packets the way Wireshark does.

**Does Echoes collect any data?**
No. There is no telemetry and no account, and everything is stored locally. See [Privacy and security](#privacy-and-security).

## Build from source

You need the **.NET 10 SDK** (or 9.0.300 and later; the desktop app still targets .NET 8), plus the Android workload for Android.

```bash
git clone https://github.com/SinaXhpm/Echoes.git
cd Echoes

# run the desktop app
dotnet run --project Echoes.csproj -c Release

# self-contained Native AOT build, like the releases (rid: win-x64, linux-x64, osx-x64, osx-arm64)
dotnet publish Echoes.csproj -c Release -r win-x64 --self-contained true -p:PublishAot=true -o publish

# Android APK
dotnet workload install android
dotnet build Echoes.Android/Echoes.Android.csproj -c Release -f net10.0-android
```

Native AOT on Windows also needs Visual Studio's "Desktop development with C++" tools.

## Built with

- **[Avalonia UI](https://avaloniaui.net/)** with **.NET 8** (desktop, Native AOT) and **.NET 10** (Android).
- [CommunityToolkit.Mvvm](https://github.com/CommunityToolkit/dotnet), [SSH.NET](https://github.com/sshnet/SSH.NET), [DnsClient.NET](https://github.com/MichaCo/DnsClient.NET) and the [Inter](https://rsms.me/inter/) font.
- Developed with AI assistance. Named after *"Echoes"* by Pink Floyd.

Primary development and testing happen on **Windows**; the macOS, Linux and Android builds may have small rough edges. Bug reports and ideas are welcome in [Issues](https://github.com/SinaXhpm/Echoes/issues) or on [Telegram](https://t.me/the_pink_palace).

## License

Echoes is released under the **[MIT License](LICENSE)**. You are free to use, copy, modify, share and even sell it, for personal or commercial use, as long as the copyright notice and license text stay included. The software is provided "as is", without warranty.

---

## Keywords

**Diagnosis:** connection doctor, why won't a website open, website not loading, DNS tampering test, DNS hijacking check, SNI filtering test, internet censorship test, blocked website checker, OONI alternative, captive portal detection, path MTU test, MTU finder, is it down for everyone or just me.

**Network tools:** network toolkit, network tools, network utility, network diagnostic tool, network troubleshooting, Wi-Fi analyzer, WiFi channel scanner, Wi-Fi signal strength, ping tool, ping GUI, IPv6 ping, ping without admin, UDP ping, traceroute, tracert GUI, visual traceroute, MTR, WinMTR alternative, PingPlotter alternative, packet loss test, latency test, jitter test, internet speed test, bandwidth test, bufferbloat test, port scanner, TCP port scanner, UDP port scanner, open port checker, nmap GUI, nmap alternative, Zenmap alternative, Angry IP Scanner alternative, IP scanner, LAN scanner, network scanner, service version detection, host checker, check-host, website down checker, global ping, ping from multiple locations, DNS lookup, DNS checker, dig GUI, nslookup GUI, reverse DNS, WHOIS lookup, RDAP, DNS propagation, DNS over HTTPS client, DoH, DNS over TLS, DoT, DNS benchmark, fastest DNS server, DNS resolver comparison, SPF checker, DKIM checker, DMARC checker, email deliverability check, MX lookup, blacklist check, DNSBL, ARP table, netstat GUI, routing table, network interfaces, uptime monitor, server monitor, website monitor, ping monitor, latency monitor, SSL expiry monitor, domain expiry monitor, Telegram uptime alerts.

**Web and API:** cURL GUI, curl client, curl import, Copy as cURL, HTTP client, REST client, API tester, Postman alternative, Insomnia alternative, HTTP/3 client, HTTP request timing, SSL checker, TLS checker, SSL certificate checker, certificate expiry checker, TLS inspector, STARTTLS test, OCSP, HSTS, what is my IP, IP lookup, GeoIP lookup, IP geolocation, ASN lookup, proxy checker, Cloudflare manager, Cloudflare DNS manager, Cloudflare API client, Cloudflare DNS backup, Cloudflare zone export, BIND zone file, Cloudflare WAF rules, Cloudflare cache purge, Cloudflare SSL mode, Cloudflare ECH, DNSSEC, Cloudflare DDNS, dynamic DNS client, DDNS updater, ddclient alternative, Telegram Bot API tester, Telegram bot tool, WebSocket client, WebSocket tester, wscat alternative, webhook tester, webhook.site alternative, request bin, HTTP request inspector.

**Servers and connections:** SSH client, SSH terminal, PuTTY alternative, SFTP client, WinSCP alternative, SSH key login, SSH port forwarding, SSH local and remote forwarding, server monitoring over SSH, SSH tunnel, SOCKS5 tunnel, SSH dynamic port forwarding, netcat GUI, TCP client, UDP client, TCP server, socket tester, hex sender, telnet alternative, web server, HTTP file server, LAN file sharing, share files over Wi-Fi, phone to PC file transfer, QR code file sharing, SOCKS5 proxy server, HTTP proxy server, local proxy server, proxy checker, proxy list tester, SOCKS5 checker, bulk proxy checker.

**Developer tools:** developer toolbox, CyberChef alternative, Base64 encoder decoder, URL encoder decoder, hash generator, hash identifier, MD5, SHA-256, HMAC, file checksum, regex tester, JSON formatter, JSON validator, JSON to YAML, JSON to CSV, XML formatter, JWT decoder, JWT verifier, subnet calculator, CIDR calculator, IP converter, Unix timestamp converter, epoch converter, cron expression parser, base converter, text diff, case converter, UUID generator, ULID generator, NanoID generator, password generator, encrypted notes, encrypted backup, AES-256-GCM.

**Platforms:** Windows network tools, macOS network tools, Linux network tools, Android network tools, Apple Silicon, cross-platform, portable app, no install, Native AOT, Avalonia UI, .NET 8, C#, free, open source, MIT license.
