# Echoes 🛰️
> *Small utilities for network, API, and string tasks;

[GitHub Repository](https://github.com/SinaXhpm/Echoes) | [Telegram](https://t.me/the_pink_palace)

<video src="https://github.com/SinaXhpm/Echoes/raw/refs/heads/master/Assets/echoes.mp4" width="100%" autoplay muted loop>
</video>
--
## 🚀 Installation & Usage

Choose the package that fits your OS from the **[Releases](https://github.com/SinaXhpm/Echoes/releases)** section:

| OS | Recommended Format | Installation |
| :--- | :--- | :--- |
| **Windows** | `.zip` | Extract and run `Echoes.exe` |
| **macOS** | `.dmg` | Mount and drag `Echoes.app` to Applications |
| **Linux (Universal)** | `.AppImage` | Make executable (`chmod +x`) and run |
| **Debian/Ubuntu** | `.deb` | Install via `sudo dpkg -i echoes.deb` |

> **Note:** Echoes is powered by **Native AOT**, meaning it's a zero-dependency standalone binary. You don't need to install .NET or any other runtime to use it.
--

## Features

### 📡 Network & Shell
- **Ping & Traceroute:** Real-time ICMP pinging with packet loss statistics and hop-by-hop route tracing.
- **Port Scanner:** TCP and UDP scanning supporting IP ranges, CIDR notation, and CSV export.
- **SSH Terminal:** Integrated terminal with ANSI-color support, command history, and **SOCKS5 proxy connection/tunneling**.
- **DNS & WHOIS:** Multi-record DNS querying (A, MX, TXT, etc.) via custom servers and RDAP domain lookups.
- **NIC Explorer**: Detailed view of network adapters including IPv4, IPv6, MAC addresses, and operational status.

### 🌐 Web & API
- **cURL Client:** GUI for cURL supporting **HTTP/SOCKS proxies**, custom flags, IP Override (Resolve), and detailed logging.
- **Telegram Bot Tester:** Specialized interface for testing Bot API methods with **built-in proxy support**.
- **SSL Inspector:** Extracts native Windows certificate details including Subject, Issuer, Validity, and Key Size.
- **IP Intelligence:** Public IP detection and GeoIP lookup across multiple providers.
- **Service Monitor:** Automated uptime and latency tracking for URLs and hosts.

### 🧪 String & JSON Lab
- **JSON Surgeon:** Advanced formatter that automatically repairs missing quotes and trailing commas.
- **Regex Engine:** Pattern testing and data extraction (IPs, Emails, URLs) from bulk text.
- **Encoders & Hashes:** Base64, URL encoding, and cryptographic hashing (MD5, SHA256).
- **Text Processing:** Tools for sorting, filtering unique lines, and character/word/line counting.

## Technical Specifications
- **Inspiration:** Artistically inspired by the track **"Echoes" by Pink Floyd**.
- **AI-Assisted Development:** This project was developed entirely with the assistance of **Gemini**.
- **The Story:** These are simply utilities I needed for my daily tasks; this project started primarily for my personal use.
- **Framework:** Built with **Avalonia UI** and **.NET 8**.
- **Performance:** Optimized for **Native AOT** for instant startup and low memory usage.
- **Code Style:** Strict **no-comment** architecture for clean, self-documenting logic.

## ⚠️ Platform Note
While I provide builds for **Windows, macOS, and Linux**, please note that I primarily develop and test on **Windows**. You might encounter "experimental" behavior or minor bugs on non-Windows devices.

## Getting Started
1. Download the latest standalone executable for your OS from the [Releases](https://github.com/SinaXhpm/Echoes/releases) section.
2. Run the application; no installation or .NET runtime is required.

## License
Distributed under the **MIT License**.