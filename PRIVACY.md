# Echoes privacy policy

Last updated: 21 October 2026

Echoes is a free, open-source network toolkit (ping, traceroute, port scanner, DNS, SSH, speed test, file-sharing web server and more). This page says what it does with your data. The short version: **it collects none.**

## What the developer collects

Nothing. Echoes has no account, no advertising, no analytics, no crash-reporting service and no tracking SDK. Nothing is sent to the developer, who can't see what you test, where you connect or what you save.

## What stays on your device

Your settings, the hosts and URLs you typed (history), notes, saved requests, SSH profiles and the tokens you add (Telegram, Cloudflare) are stored only on your device, in the app's own data folder.

- Secrets (passwords, tokens) are encrypted on disk. Notes and the Cloudflare vault are encrypted with a key made from your master password.
- You can export everything to one password-protected backup file and restore it on another device. The file goes only where you save it.
- On an iPhone or iPad, the files that browsers send to the file-sharing page are kept in the Echoes folder of the Files app (On My iPhone), so you can open, move or delete them there.
- Deleting the app, or its data folder, deletes the data.

## What leaves your device, and why

Echoes is a network tool, so it makes network requests: the ones you start, to the hosts you ask about, plus a few public services some tools are built on. Those services receive the request itself and so, as with any website you visit, your public IP address. Echoes doesn't control them; each has its own privacy policy.

- **The hosts, ports and URLs you test** (ping, traceroute, port scan, cURL, DNS, TLS, SSH, sockets, Doctor).
- **check-host.net**, to test a host from servers around the world.
- **Speed test servers:** speed.cloudflare.com, or the file host you choose (Cloudflare, Tele2, Leaseweb, Linode, Selectel, DataPacket and similar).
- **Public DNS-over-HTTPS resolvers** (Cloudflare, Google, Quad9, OpenDNS, AdGuard) when you use the DNS tool.
- **IP-information providers** (ipinfo.io, ipwho.is, ipapi.co, ip-api.com, geojs.io, freeipapi.com, iplocation.net) to look up the IP address you enter, or your own.
- **RDAP** (rdap.org, rdap.verisign.com) for a domain's registration and expiry.
- **DNS blocklists** (Spamhaus, SpamCop, Barracuda) and the domain's own mail records, when you run the mail check on a domain.
- **Connectivity and public-IP services:** well-known sites such as Google, Microsoft and Cloudflare, and connectivitycheck.gstatic.com (the Doctor checks that the internet works), and Cloudflare, ipify, ident.me and icanhazip (Dynamic DNS reads your public IP).
- **Telegram** (api.telegram.org), only if you add your own bot token for uptime alerts, and **Cloudflare** (api.cloudflare.com), only if you add your own API token. A token stays on your device and is sent only to its own service.
- **GitHub** (api.github.com), only in the builds you download from GitHub, to see whether a newer version exists. Builds from an app store don't check: the store updates the app.

## Servers Echoes can run

The web server (file sharing and chat), the request catcher, the proxy and the socket listeners start only when you press Start, and stop when you press Stop or quit Echoes. While one runs, a device that can reach its port can connect to it; the file-sharing page asks for a PIN, and data passes only between your device and the devices that connect. Echoes doesn't send it anywhere else.

## Permissions

- **Network** (all platforms): Echoes is a network tool.
- **Local network** (macOS and iOS): asked the first time you scan, ping or share with a device on your local network. If you decline, local devices look unreachable.
- **Notifications, foreground service and start at boot** (Android): for uptime alerts and to keep a scan, monitor or file share running while the app is in the background. Start at boot is off unless you turn it on.
- **Location** (Windows): Windows lets an app see the names of nearby Wi-Fi networks only when location access is on. Echoes reads them locally for the Wi-Fi analyzer and sends them nowhere.

## Children

Echoes is a general-purpose tool and isn't directed at children. It collects no personal information from anyone.

## Open source

Echoes is released under the MIT license. Anyone can read the source code, check the claims on this page and build the app: <https://github.com/SinaXhpm/Echoes>.

## Changes

If this policy changes, the new version replaces this page, with a new date at the top.

## Contact

Questions or concerns: open an issue at <https://github.com/SinaXhpm/Echoes/issues>.
