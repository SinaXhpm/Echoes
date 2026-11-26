# Google Play Console: the text to paste

Everything Play Console asks for in the Echoes app (package `com.sinaxhpm.echoes`), ready to copy. Character limits are
Google's. The text follows [the App Store one](../apple/app-store-listing.md), but every claim must hold on Android (see
README, "Android": no packet capture, Wi-Fi analyzer or system curl engine there). Play's metadata policy: no "free",
"best", "#1" or the like in the app name, and no other app's or platform's name used for search.

## App (Create app)

| Field | Value |
| :--- | :--- |
| App name (max 30) | `Echoes: Network Tools & Ping` |
| Default language | English (United States) – en-US |
| App or game | App |
| Free or paid | Free (can't become paid later), no in-app purchases, no ads |

## Main store listing

**Short description (max 80):**
```
Ping, speed test, DNS, port scanner, SSH and more network tools in one app
```

**Full description (max 4000):**
```
Echoes puts over 20 network tools in one app. Find out why a website won't open, test your internet speed, ping a server, look up a domain, check a website's security certificate, or send files to another phone or computer on your Wi-Fi. No account, no ads, no tracking.

WEBSITE NOT OPENING?
Tap Doctor and Echoes checks everything for you: your connection, DNS, the server and its certificate. Then it tells you in plain words what is wrong and what you can do about it.

TEST YOUR CONNECTION
• Ping any website or server and watch the delay and packet loss live
• Traceroute and MTR: see where on the way the slowdown starts
• Speed test: download, upload and ping in seconds
• Port scanner: find the devices on your network and what they run
• Check Host: test a website from servers around the world

LOOK THINGS UP
• DNS lookup, also over HTTPS and TLS
• WHOIS: where a domain is registered and when it expires
• Your IP address and where it is
• SSL certificate check: who issued it and when it runs out
• Email check: MX, SPF, DKIM and DMARC records

FOR DEVELOPERS AND ADMINS
• SSH terminal and SFTP file transfer
• HTTP client: paste a curl command and send it
• TCP, UDP and WebSocket tester
• Uptime monitor with sound and Telegram alerts
• Cloudflare DNS manager with dynamic DNS
• Hetzner Cloud: servers, firewalls and DNS
• Telegram bot tester

SEND FILES WITHOUT CABLES
Start the web server and scan its QR code with another phone or computer: you can send files and messages both ways in the browser. Every file you share also gets its own download link and QR code.

KEEPS RUNNING
The uptime monitor, the servers and scans keep running when you switch apps, with a notification that shows what runs. The monitor can also start when the phone starts.

HANDY EXTRAS
• Strong password generator
• Hash, Base64, URL, JSON and JWT tools
• Encrypted notes
• A history in every tool, and dark and light mode

PRIVATE BY DESIGN
No account, no ads, no analytics. Your data stays on your device, and passwords and tokens are stored encrypted. Echoes only talks to the servers you choose to test. Open source: github.com/SinaXhpm/Echoes
```

**Graphics:** app icon 512 x 512 (the iOS 1024 icon scaled down; Play rounds the corners), feature graphic 1024 x 500
(the icon on its own navy, the name and a line), phone screenshots 1080 x 1920 (9:16; Play takes at most 2:1, so the
412 x 880 README pictures don't fit): Doctor, speed test, ping, monitor, file sharing and the tool menu, rendered by the
README screenshot harness with demo data at 412 x 732 and a scale of 2.62.

**Store settings:** category Tools; tags network-related; contact e-mail (the developer account's); website
`https://github.com/SinaXhpm/Echoes`; privacy policy `https://github.com/SinaXhpm/Echoes/blob/master/PRIVACY.md`.

## App content

| Declaration | Answer |
| :--- | :--- |
| Privacy policy | `https://github.com/SinaXhpm/Echoes/blob/master/PRIVACY.md` |
| App access | All functionality is available without special access (no account) |
| Ads | No ads |
| Content rating (IARC) | Utility / productivity; no violence, sex, language, drugs, gambling. Users can interact (the Web Server's chat between devices the owner lets in with a PIN): yes. Shares location: no. Digital purchases: no |
| Target audience | 18 and over (a toolkit for adults; not designed for children) |
| News app | No |
| Data safety | No data collected, no data shared. Data is encrypted in transit (HTTPS / TLS / SSH to hosts the user picks). No account, so no deletion request page |
| Government app | No |
| Financial features | None |
| Health | None |
| Advertising ID | No (no ads or analytics SDK; the manifest doesn't ask for AD_ID) |
| Foreground service | Special use (see below) |

**Foreground service (specialUse) declaration.** The service (`KeepAliveService`) runs only while a tool the user started
is active, shows an ongoing notification naming it, and stops when the tool stops. Text for "describe the use":
```
Echoes is a network toolkit. A foreground service keeps a tool the user started running while the app is in the background: the uptime monitor that checks the user's own servers and alerts when one goes down, local servers the user starts (file sharing web server, proxy, TCP/UDP socket servers), SSH sessions and port scans. The service starts only when the user starts one of these tools (or turns on "start monitoring when the phone starts"), shows an ongoing notification that names what is running, and stops as soon as the user stops the tool. None of these fit another foreground service type: they are not data transfers with an end (dataSync), media, location or a phone call. Without it, Android stops the monitor and the servers a few minutes after the user switches apps, and the user misses a down alert or loses a file transfer in progress.
```
It also asks for a video link that shows the feature: a short screen recording (start the monitor, leave the app, the
notification, the alert), shared as a Google Drive link anyone with it can view.

**AI-generated assets:** "Don't label assets" (the art comes from the app's own icon and screenshots).

## Releases

- The bundle comes from `.github/workflows/play.yml` (by hand): a store build (`-p:StoreBuild=true`: no update check,
  no Releases link) signed with the GitHub APK's key, checked for the certificate, targetSdk 36 and 16 KB alignment.
- App signing: Play App Signing holds the same key (exported once with Google's PEPK tool from a one-off workflow, since
  removed), so an install from Play and the APK from GitHub update each other. Certificate SHA-256
  `47:FA:2F:FD:…:88:4E:FD`; it is the upload key too.
- Package name: registered to the account under Play Console > Android developer verification, proved with a one-off
  APK signed by this key.
- Version codes: Play refuses a code it has had. 22 went to Play first (1.2.0); every later build, for GitHub or Play,
  takes the next number.
- Play's automatic protection is off: it needs minSdk 24, and Echoes supports Android 6 (minSdk 23).
- Production needs a closed test first (personal account): at least 12 testers opted in for 14 days in a row. Track
  "Closed testing - Alpha", all countries, testers from the email list "Echoes testers", feedback URL
  `https://github.com/SinaXhpm/Echoes/issues`.
