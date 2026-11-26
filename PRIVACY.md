# Echoes privacy policy

Last updated: 19 November 2026

Echoes is a free, open-source network toolkit (ping, traceroute, port scanner, DNS, SSH, speed test, file-sharing web server and more). This page says what it does with your data. The short version: **it collects none.**

## What the developer collects

Nothing. Echoes has no account, no advertising, no analytics, no crash-reporting service and no tracking SDK. Nothing is sent to the developer, who can't see what you test, where you connect or what you save.

## What stays on your device

Your settings, the hosts and URLs you typed (history), notes, saved requests, SSH profiles and the tokens you add (Telegram, Cloudflare, Hetzner) are stored only on your device, in the app's own data folder.

- Secrets (passwords, tokens) are encrypted on disk. Notes and the Cloudflare vault are encrypted with a key made from your master password.
- You can export everything to one password-protected backup file and restore it on another device. The file goes only where you save it.
- On an iPhone or iPad, the files that browsers send to the file-sharing page are kept in the Echoes folder of the Files app (On My iPhone), so you can open, move or delete them there.
- Deleting the app, or its data folder, deletes the data.
- The Device page reads this computer's or phone's hardware details (model, serial numbers, memory, disks, battery …) on the device when you open it. They are shown and, if you press Copy, put on your clipboard; they are never sent anywhere.
- The Capture tool (desktop) shows the packets on the network interface you choose, only between Start and Stop. They are kept in memory and shown on your screen; they are written only to a file you save, and never sent anywhere. A capture can hold other people's traffic on a shared network and anything sent unencrypted, so treat a saved capture file as private.

## What leaves your device, and why

Echoes is a network tool, so it makes network requests: the ones you start, to the hosts you ask about, plus a few public services some tools are built on. Those services receive the request itself and so, as with any website you visit, your public IP address. Echoes doesn't control them; each has its own privacy policy.

- **The hosts, ports and URLs you test** (ping, traceroute, port scan, cURL, DNS, TLS, SSH, sockets, Doctor).
- **Your own local network**, when you press Find devices in the Network tool: every address of the chosen interface's subnet is asked whether a device is there (ARP), one question each goes to the link's mDNS and SSDP groups, and each device found is asked its name (NetBIOS, LLMNR, a reverse lookup at the interface's DNS server when that is your router). A UPnP device's own description is read from that device only. None of this leaves the local network, and the devices found are shown and, if you press Copy, put on your clipboard; they are not stored or sent anywhere.
- **check-host.net**, to test a host from servers around the world, and **Globalping** (api.globalping.io), which runs the same check when check-host.net can't be reached.
- **Speed test servers:** speed.cloudflare.com, or the file host you choose (Cloudflare, Tele2, Leaseweb, Linode, Selectel, DataPacket and similar). When speed.cloudflare.com doesn't work, the automatic test goes on to a file host in your part of the world, chosen from your time zone (Tele2, DataPacket, Leaseweb or Linode).
- **Public DNS-over-HTTPS resolvers** (Cloudflare, Google, Quad9, OpenDNS, AdGuard) when you use the DNS tool. The same resolvers, and DNS.SB, are also asked for the name of a service Echoes itself uses (such as rdap.org or api.github.com), but only when your network's own resolver doesn't answer for it or answers with a filter's address. The hosts you test are always looked up the way your system looks them up. The Doctor also asks encrypted resolvers for the site you diagnose, to compare their answer with your system's, so each resolver it asks learns the site's name: Cloudflare and Google first, then Quad9, OpenDNS and AdGuard when those don't answer, and DNS.SB and DNSPod (run by Tencent) only when none of them does.
- **IP-information providers** (ipinfo.io, ipwho.is, ipapi.co, ip-api.com, geojs.io, freeipapi.com, iplocation.net, ipwhois.app, iplocate.io, ipquery.io, ip2location.io, geoiplookup.io, ifconfig.co, ipleak.net, ip.sb, ip.guide, db-ip.com, geolocation-db.com, country.is and internetdata.io) to look up the IP address you enter, or your own. A few are asked at a time; the others only when one doesn't answer.
- **IP services for the proxy checker:** Cloudflare (www.cloudflare.com), through each proxy you check, for its exit IP and country; when that doesn't come through, ipinfo.io, ipleak.net, ipwho.is, ifconfig.co, ip.sb, country.is or ip-api.com, through the same proxy. They see the proxy's address, not yours.
- **WHOIS and RDAP**, for a domain's registration and expiry and for who holds an IP address or AS number (in the DNS tool, and for an MTR hop when you open it: a running trace asks nothing about the hops you don't). Each lookup asks one source after another until one answers:
  - the WHOIS servers on port 43 (whois.iana.org, then the registry's and the registrar's server it points to; ARIN's whois.arin.net for addresses);
  - RDAP through rdap.org and ARIN (rdap.arin.net, rdap-bootstrap.arin.net), or straight from the registry's own RDAP server, found in IANA's lists (data.iana.org);
  - **RIPEstat** (stat.ripe.net, run by RIPE NCC);
  - the WHOIS web services who-dat.as93.net and networkcalc.com;
  - ip.guide for an address's network and AS.
- **DNS blocklists** (Spamhaus, SpamCop, Barracuda, PSBL, DroneBL) and the domain's own mail records, when you run the mail check on a domain.
- **Connectivity and public-IP services:** well-known sites such as Google, Microsoft and Cloudflare, and the connectivity checks of Cloudflare, Google, Microsoft, Apple, Xiaomi, Huawei and Ubuntu, one after another until one answers (the Doctor checks that the internet works), and Cloudflare, ipify, ident.me and icanhazip (Dynamic DNS reads your public IP).
- **More public-IP services for Dynamic DNS**, asked only when the first two don't agree or don't answer: Cloudflare at one.one.one.one and 1.1.1.1, Amazon (checkip.amazonaws.com), ipinfo.io, ifconfig.me, ifconfig.co, ip.sb, ipecho.net, wtfismyip.com, myexternalip.com, Mullvad (am.i.mullvad.net), and the DNS servers of OpenDNS, Google and Cloudflare, which answer with the address they see.
- **Telegram** (api.telegram.org), only if you add your own bot token for uptime alerts, **Cloudflare** (api.cloudflare.com), only if you add your own API token, and **Hetzner** (api.hetzner.cloud), only if you add your own API token for a Hetzner Cloud project. A token stays on your device, encrypted, and is sent only to its own service.
- **GitHub** (api.github.com, or github.com's page for the latest release when the API doesn't answer), only in the builds you download from GitHub, to see whether a newer version exists. Builds from an app store don't check: the store updates the app.

## Servers Echoes can run

The web server (file sharing and chat), the request catcher, the proxy and the socket listeners start only when you press Start, and stop when you press Stop or quit Echoes. While one runs, a device that can reach its port can connect to it; the file-sharing page asks for a PIN, and data passes only between your device and the devices that connect. Echoes doesn't send it anywhere else.

## Permissions

- **Network** (all platforms): Echoes is a network tool.
- **Local network** (macOS and iOS): asked the first time you scan, ping or share with a device on your local network. If you decline, local devices look unreachable.
- **Notifications, foreground service and start at boot** (Android): for uptime alerts and to keep a scan, monitor or file share running while the app is in the background. Start at boot is off unless you turn it on.
- **Location** (Windows): Windows lets an app see the names of nearby Wi-Fi networks only when location access is on. Echoes reads them locally for the Wi-Fi analyzer and sends them nowhere.
- **Packet capture** (desktop, only for the Capture tool): the system decides who may capture. Windows: Npcap, if you installed it, or Echoes started as administrator. Linux: root or the CAP_NET_RAW capability. macOS: access to /dev/bpf. Echoes never asks for these by itself and nothing else in it needs them.

## Children

Echoes is a general-purpose tool and isn't directed at children. It collects no personal information from anyone.

## Open source

Echoes is released under the MIT license. Anyone can read the source code, check the claims on this page and build the app: <https://github.com/SinaXhpm/Echoes>.

## Changes

If this policy changes, the new version replaces this page, with a new date at the top.

## Contact

Questions or concerns: write to [sinaxhpm@gmail.com](mailto:sinaxhpm@gmail.com), or open an issue at <https://github.com/SinaXhpm/Echoes/issues>.
