# App Store Connect: the text to paste

Everything App Store Connect asks for when you create the Echoes app record (iOS and macOS), ready to copy. Character
limits are Apple's; every value below was counted against them. The iOS wording is a draft: adjust it to what the iOS
build can really do when it ships (see [README.md](README.md), "iOS: what works and what is left").

## App record (New App)

| Field | Value |
| :--- | :--- |
| Platforms | iOS, macOS (one record, universal purchase) |
| Name (max 30) | `Echoes Network Toolkit` (the name `Echoes` alone is taken) |
| Primary language | English (U.S.) |
| Bundle ID | `com.sinaxhpm.echoes` (register it first: Certificates, Identifiers & Profiles > Identifiers) |
| SKU | `echoes` (internal, never shown, can't change later) |
| User access | Full access |

## Version page (same text for iOS and macOS unless noted)

**Subtitle (max 30):**
```
Ping, DNS, speed and port scan
```

**Promotional text (max 170, can change without a new build):**
```
Find out why a site won't open. Ping, trace routes, test speed, scan ports, look up DNS and share files: 20 network tools in one free, open-source app.
```

**Keywords (max 100, comma-separated, no spaces after commas):**
```
ping,traceroute,dns,whois,port scanner,ssh,sftp,curl,tls,ssl,bandwidth,mtr,proxy,uptime,diagnostics
```

**Description (max 4000):**
```
Echoes is a free, open-source toolkit for diagnosing a network and working with servers. Twenty tools in one app, with no account, no ads and no tracking.

FIND OUT WHY A SITE WON'T OPEN
The Doctor checks your network, DNS, the connection, TLS and HTTP step by step, compares with servers abroad and tells you in one sentence what is wrong: DNS tampering, SNI filtering, a blocked IP, a filter page, or a site that is down for everyone.

TEST THE CONNECTION
• Ping with a live latency graph, loss and jitter (ICMP, UDP or TCP)
• Traceroute and MTR: see the hop where packet loss starts
• Speed test: download, upload, latency under load and a bufferbloat grade
• Port scanner and ping sweep for your own network or a server you manage
• Check Host: test a site or a port from servers around the world

LOOK THINGS UP
• DNS lookups, DNS over HTTPS and a resolver comparison
• WHOIS / RDAP, IP information and an SSL/TLS certificate inspector
• Mail check: MX, SPF, DKIM, DMARC and blocklists

WORK WITH SERVERS
• SSH and SFTP client with port forwarding
• cURL / HTTP client: paste a "Copy as cURL" command and send it
• Raw TCP, UDP and WebSocket sockets, as client or server
• Cloudflare manager for DNS records and settings, with dynamic DNS
• Uptime monitor with Telegram alerts

SHARE AND CONNECT
• File sharing and chat over HTTPS: start the server, scan the QR code, and send text and files both ways with any device that has a browser
• Request catcher for webhooks, and a proxy server
• Servers and monitors run while Echoes is open

AND MORE
• Encrypted notes, string and JSON tools, and a history for every tool
• Dark and light themes

PRIVATE BY DESIGN
No account, no ads, no analytics. Your data stays on your device and secrets are encrypted. Echoes contacts only the hosts you test and the public services a tool needs. Open source under the MIT license: github.com/SinaXhpm/Echoes
```

**What's new (max 4000), first version:**
```
First release on the App Store.
```

**URLs and legal:**

| Field | Value |
| :--- | :--- |
| Support URL | `https://github.com/SinaXhpm/Echoes/issues` |
| Marketing URL | `https://github.com/SinaXhpm/Echoes` |
| Privacy Policy URL | `https://github.com/SinaXhpm/Echoes/blob/master/PRIVACY.md` |
| Copyright | `2026 Echoes contributors` |
| Category | Primary: Utilities. Secondary: Developer Tools |
| Price | Free, no in-app purchases |
| Sign-in required | No (there is no account) |

## App Review information

Contact: your name, phone and e-mail. Demo account: not needed (no account). Notes (max 4000), paste as is:

```
Echoes is a network diagnostic and developer toolkit (ping, traceroute, DNS, port scanner, SSH client, speed test, HTTP client, file sharing). There is no account, login or in-app purchase, so no demo account is needed. It is open source (MIT): https://github.com/SinaXhpm/Echoes

Every network action starts from the user's own button press and targets a host the user typed. Nothing runs in the background and nothing is sent to the developer: there is no analytics, advertising or tracking SDK.

- Local Network permission: the scanner, ping sweep and LAN file sharing talk to devices on the user's own Wi-Fi. The first use shows the system prompt with the purpose string.
- Port scanner: a plain TCP connect scan of an address range the user enters, meant for their own network or servers they manage (like other network utilities on the App Store).
- Web Server / Proxy / Request catcher / Socket servers: they start only when the user taps Start, listen only while the app is in the foreground, and stop on Stop. While one of them (or the monitor or a scan) runs, the screen is kept on (the idle timer is off), because iOS suspends the app when the phone locks; a short background task covers a quick switch to another app, and both end when the job stops. They do not touch other apps' traffic, and Echoes does not use VPN or Network Extension APIs. The file-sharing page is served over HTTPS with a self-signed certificate that the app creates on the device (a browser shows a one-time warning, which is expected) and is protected by an 8-digit PIN shown in the app. Files a browser sends are kept in the app's Documents/Received folder, which the Files app shows (UIFileSharingEnabled).
- Telegram alerts and Cloudflare management are optional: they work only after the user pastes their own bot token or API token, which is stored encrypted on the device.
- Encryption: HTTPS and TLS through the system, SSH through the standard SSH protocol, and AES-GCM for the user's own notes and secrets. All are standard algorithms.

To try it quickly: open Ping and enter apple.com, open Doctor and enter apple.com, or open DNS and look up apple.com.
```

## App Privacy ("nutrition label")

Recommended answer: **Data Not Collected.** Echoes has no developer-side server, no account, no analytics and no
third-party SDK; what it sends is the request the user starts, in real time, to the host they chose. If you add analytics,
crash reporting or any SDK later, redo this questionnaire first. Privacy Policy URL: see above.

## Age rating

Answer the questionnaire **None** for violence, sexual content, profanity, gambling, horror, medical and drug
questions. Two need a deliberate answer:

- **Unrestricted web access:** answer **No**. The cURL tool shows a page's HTML in a web view with scripts and outside
  resources blocked, and it is not a browser. (If App Review disagrees, the rating moves up; it is not a rejection.)
- **Messaging and chat:** answer **Yes**: the Web Server's chat lets the people the owner lets in with a PIN write to
  each other. **User-generated content:** **No**, there is nothing public. Declaring the chat does not change the
  rating: App Store Connect still computes 4+.

Expected rating: 4+. (The answers are already entered through the API; check them under App Information.)

## Export compliance (encryption)

Echoes uses encryption: HTTPS / TLS through the operating system, the SSH protocol through the SSH.NET library, and AES-GCM
for local data. Suggested answers, which are legal declarations you must confirm yourself:

- Uses encryption: **Yes.**
- Exempt (only uses encryption in the OS or for authentication): **No**, because the app implements the SSH protocol itself.
- Uses only standard, internationally accepted algorithms (TLS, SSH, AES, SHA-2, RSA / ECDSA): **Yes.**
- Because of the SSH client, the app is "mass market" encryption software: a self-classification report to the U.S. BIS is
  due once a year (a short e-mail / CSV, no license needed). A French distribution declaration may also apply; if you don't
  want to deal with it, exclude France in the app's availability.

## Screenshots

At least one set per device class; up to 10 each. They come from the real app, not from Windows or Android, and need no
device frames. App Store Connect shows the exact current sizes next to the upload box; the usual ones:

| Device | Size (px) | API display type |
| :--- | :--- | :--- |
| iPhone 6.9" | 1320 x 2868 (or 1290 x 2796) | `APP_IPHONE_67` |
| iPad 13" | 2064 x 2752 | `APP_IPAD_PRO_3GEN_129` |
| Mac | 1440 x 900, 2560 x 1600 or 2880 x 1800 (16:10) | (not used) |

**How they are made.** Run the workflow `.github/workflows/ios-screenshots.yml` by hand. It builds the app with
`-p:StoreShots=true` (the scenes in `Echoes.iOS/StoreShots.cs`, compiled only in that build), starts it on an iPhone 17 Pro Max
and an iPad Pro 13-inch simulator, and takes a native-size screenshot of seven scenes with the simulator's own status bar
(9:41, full battery): Doctor on `example.com`, a TCP ping of `1.1.1.1`, the Web Server with a chat, a DNS lookup, the TLS
Inspector, cURL, and the password generator with its "time to crack" card. Everything is real: the checks run against the real
network, and the only addresses on screen are public ones (`example.com`, `1.1.1.1`) and the runner's own private one. The
pictures are the artifact `Echoes-store-screenshots` (7 days); they go into App Store Connect through the API (a screenshot set
per display type, one file per picture, in file-name order). A scene that fails is written to `errors.txt` and skipped.
