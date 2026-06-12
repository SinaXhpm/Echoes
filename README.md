# Echoes 🛰️
> Small utilities for network, API, and string tasks — in one app.

[GitHub Repository](https://github.com/SinaXhpm/Echoes) | [Telegram](https://t.me/the_pink_palace)

https://github.com/user-attachments/assets/a4364c4b-e79f-4680-bef9-605c7a9c8915


## Install

Download the file for your platform from the **[Releases](https://github.com/SinaXhpm/Echoes/releases)** page:

| Platform | File | How to install |
| :--- | :--- | :--- |
| **Windows** | `.zip` | Extract and run `Echoes.exe` |
| **macOS** | `.dmg` | Open it and drag `Echoes.app` to Applications |
| **Linux** | `.AppImage` | `chmod +x` then run |
| **Debian/Ubuntu** | `.deb` | `sudo dpkg -i echoes.deb` |
| **Android** | `.apk` | Allow "install from unknown sources", then open the APK (needs Android 6.0+) |

The desktop builds are self-contained (Native AOT) — no .NET runtime needed.

## Features

### Network
- **Ping & Traceroute** — live ICMP ping with packet-loss stats and hop-by-hop tracing.
- **Port Scanner** — TCP/UDP scan for single IPs, ranges, and CIDR; export to CSV.
- **SSH Terminal** — terminal with ANSI colors, command history, and SOCKS5 proxy/tunneling.
- **DNS & WHOIS** — query DNS records (A, MX, TXT, …) via custom resolvers, plus RDAP domain lookups.
- **NIC Explorer** — network adapters with IPv4/IPv6, MAC, and status (desktop only).

### Web & API
- **cURL Client** — a GUI for requests with HTTP/SOCKS proxy, IP override, and full logging.
- **Telegram Bot Tester** — call Bot API methods and see the raw verbose response.
- **SSL Inspector** — read a site's TLS certificate (subject, issuer, validity, key, chain).
- **IP Info** — your public IP and GeoIP lookup, with SOCKS5/HTTP proxy support.
- **Service Monitor** — track uptime and latency for a list of hosts/URLs.

### Tools
- **Encrypted Notes** — local notes encrypted with AES-256 + a master key. The key is never stored; if you lose it, the notes can't be recovered.
- **String Lab** — Base64/URL encoding, hashing (MD5/SHA256), regex testing, JSON format/minify, case conversion, text cleanup, and token generators.

## Android notes
The Android app runs the same UI. A few desktop features don't work inside the Android sandbox: the real `curl` engine (use the built-in .NET engine instead), notification sounds, and NIC Explorer. Everything else (ping, SSH, DNS, IP info, scanner, monitor, cURL via .NET) works.

## Built with
- **Avalonia UI** + **.NET 8** (Android head on .NET 10).
- **Native AOT** on desktop for fast startup and low memory use.
- Developed with AI assistance. Named after *"Echoes"* by Pink Floyd.

## Note
Primary development and testing is on **Windows**. macOS, Linux, and Android builds may have minor rough edges.

## License
MIT.
