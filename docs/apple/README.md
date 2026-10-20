# Echoes on Apple platforms

How Echoes gets to macOS and iOS: what exists, what you do on developer.apple.com, and what is still missing. The text
to paste into App Store Connect is in [app-store-listing.md](app-store-listing.md). The privacy policy Apple asks for is
[PRIVACY.md](../../PRIVACY.md).

## Where things stand

| Piece | State |
| :--- | :--- |
| macOS `.dmg` on GitHub, signed with Developer ID, notarized and stapled | **Shipped** since v0.4.3 (Intel and Apple Silicon): Gatekeeper accepts both as "Notarized Developer ID", and both were opened on a real Mac. Without the secrets below the build is signed ad hoc, as before. |
| macOS `.pkg` for the Mac App Store | Not built. Needs the App Sandbox, which cuts features; see "Mac App Store". |
| iOS / iPadOS app | **On TestFlight** (`Echoes.iOS/`, built and started on iPhone and iPad simulators by `.github/workflows/ios.yml`, signed builds by `ios-testflight.yml`). Not tried on a real iPhone yet; see "iOS: what works and what is left". |
| App Store build mode | `AppInfo.IsStoreBuild` (true on iOS, or on the desktop head with `-p:StoreBuild=true`): no update check, no Releases link. The About box has a Privacy policy link in every build. |
| Privacy policy, store text | Done. |
| App Store Connect record (iOS 1.0.0) | **Filled in through the API** (an App Manager key): texts, URLs, copyright, categories (Utilities, Developer Tools), age rating (4+; the chat is declared as messaging), content rights, price Free, availability in 173 countries (China mainland and France off), the App Review notes, seven iPhone and seven iPad screenshots, and build 1.0.0 (4) attached. **Still for the account holder:** the App Privacy answers (the website only), the EU trader status (without it the 27 EU countries stay off), the review contact details, the export-compliance answers of the build, then Submit. |

## Identifiers

- **Bundle ID:** `com.sinaxhpm.echoes` (explicit). The same string is the Android application id. A single App ID covers iOS,
  iPadOS and macOS, and lets the iOS and macOS apps be one App Store record (universal purchase).
- **Capabilities: tick none.** Echoes uses no iCloud, Push, Network Extensions, Hotspot or Wi-Fi Information. Its network
  access is plain sockets and HTTP(S). The macOS entitlements (network client / server) and the Local Network prompt are
  set in the app's own files (`packaging/macos/`, `Echoes.iOS/Info.plist`), not here. Every capability you tick must also
  be listed in the app's entitlements, or signing fails.
- **Team ID:** Developer account > Membership details. The signing identity's name is
  `Developer ID Application: <name> (<TEAM ID>)`; CI finds it by itself.
- **SKU** `echoes`, **App Store name** `Echoes Network Toolkit` (`Echoes` alone is taken). The name shown under the icon on
  a Mac or iPhone comes from `CFBundleDisplayName` and stays `Echoes`.

## Certificates and keys

Everything private lives in `.signing/` at the repo root. Git ignores that folder (and `*.p12`, `*.p8`,
`*.certSigningRequest`), and the build mirrors skip it. **Back it up somewhere safe: without the private key the certificate
is useless, and Apple can't give the key back.**

| File | What |
| :--- | :--- |
| `developer_id.key` | Private key (2048-bit RSA). Never leaves your machines except inside the `.p12`. |
| `Echoes.certSigningRequest` | The CSR that was uploaded to Apple. |
| `developerID_application.cer` | The **Developer ID Application** certificate Apple issued (valid until 18 Nov 2027). |
| `echoes-developer-id.p12`, `p12-password.txt`, `echoes-developer-id.p12.base64.txt` | Certificate + key packed for CI, its random password, and the base64 text that goes into the secret. |
| `set-github-secrets.sh` | Uploads the secrets below with the GitHub CLI. |

When the certificate expires, new builds can't be signed with it (old, notarized downloads keep working). Create a new
Developer ID Application certificate from a new CSR, rebuild the `.p12` and replace the two secrets.

Other certificates you will need later (create them in Certificates, with the same kind of CSR):

| For | Certificate |
| :--- | :--- |
| iOS App Store / TestFlight | **Apple Distribution** + an **App Store** provisioning profile for `com.sinaxhpm.echoes` |
| Mac App Store | **Apple Distribution** (or Mac App Distribution) + **Mac Installer Distribution** + a **Mac App Store** profile |

## GitHub secrets (Settings > Secrets and variables > Actions)

| Secret | Value |
| :--- | :--- |
| `APPLE_CERT_P12_BASE64` | the content of `.signing/echoes-developer-id.p12.base64.txt` |
| `APPLE_CERT_PASSWORD` | the content of `.signing/p12-password.txt` |
| `APPLE_API_KEY_P8` | the content of the App Store Connect API key file `AuthKey_XXXX.p8` |
| `APPLE_API_KEY_ID` | that key's Key ID |
| `APPLE_API_ISSUER` | the Issuer ID (shown above the keys list) |

For iOS (TestFlight and later the App Store) three more, from the **Apple Distribution** certificate and the **App Store**
provisioning profile for `com.sinaxhpm.echoes` (the API key above uploads the build):

| Secret | Value |
| :--- | :--- |
| `IOS_CERT_P12_BASE64` | the Apple Distribution certificate + private key as a `.p12`, base64 |
| `IOS_CERT_PASSWORD` | its password |
| `IOS_PROFILE_BASE64` | the `.mobileprovision` file, base64 |

`bash .signing/set-github-secrets.sh ios` uploads them from the files in `.signing/`.

The API key: App Store Connect > Users and Access > Integrations > App Store Connect API > Team Keys > **+**, role
**Developer**. The `.p8` downloads only once. Put it in `.signing/` too.

Upload them with `bash .signing/set-github-secrets.sh <AuthKey_XXXX.p8> <KEY_ID> <ISSUER_ID>` (the certificate pair alone:
no arguments). GitHub encrypts them and never shows them again.

## The macOS release

Tag `v*` runs `.github/workflows/release.yml`; each macOS job (`osx-x64`, `osx-arm64`) then:

1. imports the `.p12` into a temporary keychain and finds the Developer ID identity (the keychain is deleted at the end);
2. publishes the Native AOT build, then runs `packaging/macos/package.sh <rid> <version>`, which
   builds `Echoes.app` (Info.plist from `packaging/macos/Info.plist`), signs every dylib and then the bundle with the
   hardened runtime and `packaging/macos/Echoes.entitlements`, sends the app to Apple's notary service, staples the ticket,
   builds the `.dmg`, signs it, notarizes it and staples it;
3. fails the job, printing Apple's log, if Apple does not accept it, so a broken build is never published.

Without the secrets it builds the same `.dmg` signed ad hoc (users do Open Anyway, as today).

**Dry run without a release:** `.github/workflows/macos-test.yml` does the same for `osx-arm64` and `osx-x64` when you start it by hand (Actions, Run workflow, any branch) and keeps the notarized `.dmg` as a workflow artifact for 3 days; it creates no tag, release or asset. 

**Which macOS the app opens on:** the AOT binary is linked for the macOS of the machine that builds it unless
`MACOSX_DEPLOYMENT_TARGET` says otherwise. Builds up to v0.4.2 were linked on macOS 26 and so opened only there
(`open` failed with `kLSIncompatibleSystemVersionErr` on older Macs, whatever Info.plist said). The macOS jobs now run on the
`macos-15` image (Xcode 16) with `MACOSX_DEPLOYMENT_TARGET=12.0`: Xcode 26's classic linker, which .NET 8's NativeAOT uses,
crashes with an older target (`ld: Assertion failed ... dylibToOrdinal`). `package.sh` reads the binary's `minos` with `vtool`
and fails the build if it is newer than 12. Check a binary by hand: `vtool -show-build Echoes.app/Contents/MacOS/Echoes`.

Check a downloaded file on a Mac:

```bash
spctl --assess --type open --context context:primary-signature -v Echoes-osx-arm64.dmg   # accepted, source=Notarized Developer ID
xcrun stapler validate Echoes-osx-arm64.dmg                                               # The validate action worked!
codesign --verify --deep --strict --verbose=2 /Applications/Echoes.app
```

Build and sign one locally (Mac): `dotnet publish Echoes.csproj -c Release -r osx-arm64 -p:PublishAot=true -o publish`, then
`SIGN_IDENTITY="Developer ID Application: ..." packaging/macos/package.sh osx-arm64 0.0.0-local`.

If notarization is rejected, the job log has the reasons. The usual ones: a binary inside the bundle that is not signed
(add it to the signing loop), a missing secure timestamp, or an entitlement the hardened runtime doesn't accept.

When the first notarized release is verified, update the README's "First launch" note for macOS (it still says the app is
not notarized) and drop the `xattr` advice.

## Mac App Store (not built)

The Developer ID `.dmg` above keeps every feature. The Mac App Store needs more, so decide before starting:

- **App Sandbox is mandatory** (`com.apple.security.app-sandbox`) with the entitlements `network.client`, `network.server`
  and `files.user-selected.read-write`, plus the profile's `application-identifier` and `team-identifier`.
- What the sandbox changes for Echoes: "Open at sign-in" (a LaunchAgent in `~/Library/LaunchAgents`) is not allowed, so hide
  it; the data folder moves into the app's container; folders chosen for received files and downloads must be kept as
  security-scoped bookmarks or they are forgotten at restart; helper programs started by the app (the system curl engine,
  anything run with `Process.Start`) must be tested; and `disable-library-validation` / `allow-jit` are not accepted.
- Mac App Store apps may not update themselves or point to downloads elsewhere: publish with `-p:StoreBuild=true` (it
  compiles with the `STORE` constant, and the About box then drops the update check and the Releases link).
- Build a signed `.app` (Apple Distribution), wrap it with `productbuild --component Echoes.app /Applications --sign
  "<Mac Installer Distribution identity>" Echoes.pkg`, and upload with Transporter or `xcrun altool --upload-package`.

## iOS: what works and what is left

`Echoes.iOS` holds the bundle metadata (`Info.plist`, an empty `Entitlements.plist`, a 1024 px opaque icon in
`Assets.xcassets`, Apple's privacy manifest), the Avalonia entry point and the shared sources, the same way the Android head
does. CI (`ios.yml`, on every change to the iOS head or the shared code) builds it for the simulator, starts it on an iPhone
and an iPad simulator, compiles it for devices (the unsigned Release ahead-of-time build), and runs a self-test inside the app
(`Echoes.iOS/SelfTest.cs`, started with `ECHOES_SELFTEST=1`). Last result on iOS 27 simulators, all fine: storage, DNS, TCP,
ICMP and UDP ping, HTTPS, a TLS server, loopback sockets, the network interfaces, the whole share hub (HTTPS page, PIN login, a
chat message), the storage layout, the alert sound, the screen staying on, and **all 20 tools opening in the touch shell**; the
artifact `Echoes-ios-simulator-test` has a picture of each tool (`tour-iphone`, `tour-ipad`). Child processes are not available
on iOS, as expected. Real iOS bugs found this way are fixed: the PKCS#12 `Exportable` flag throws on Apple's mobile platforms
(`ShareTls.Load`), and an IPv4 ping socket hands over the IP header first (`IcmpPinger`). The TestFlight workflow has put signed
builds on TestFlight. **Nothing has been tried on a real iPhone yet**, and the simulator shares the Mac's network.

Done in the shared code for iOS:

- **Platform branches.** Nothing reachable on iOS starts a child process: the system curl engine and "Open folder" are hidden,
  the Wi-Fi analyzer says it isn't available, and the alert sound has its own player. Without a visible routing table the
  Doctor says "can't tell" about the network (as on Android), not "no network".
- **Storage.** The app's own data (profile, secret key, share certificate, logs) is in `Library/Application Support/Echoes`
  (builds up to 0.4.3 build 2 had it in `Documents/.config`: moved once). The Web Server keeps what a browser sends in
  `Documents/Received`, which the Files app shows under On My iPhone › Echoes (`UIFileSharingEnabled`,
  `LSSupportsOpeningDocumentsInPlace`). Paths saved by an earlier run are rebased into the new container folder after an
  update, and only inside `Received`. There is no folder picker and no Save button on iOS: iOS can't write elsewhere.
- **Sound.** `IosSoundPlayer` (an `AVAudioPlayer`, ambient session: the ringer switch silences it, music keeps playing).
- **Background.** iOS suspends an app soon after it leaves the screen or the phone locks, and a suspended app's sockets stop.
  `IosBackgroundGuard` keeps the screen on (the idle timer is off) while a server, the monitor, a scan or a socket session
  runs, and a background task covers a short switch to another app. `BootStart` has no iOS implementation (the option is
  hidden). The listing's "run while Echoes is open" wording stays.
- **Local Network.** `NSLocalNetworkUsageDescription` is in Info.plist; when the permission is off, "host unreachable" for a
  LAN address names Settings › Privacy & Security › Local Network.
- **Reporting.** About › Copy log copies the version line and the end of the crash log, for a tester who can't open the data
  folder.

Still to do, and only a phone can show it:

1. **Test on a device** (TestFlight): the Local Network prompt, real ICMP ping and traceroute, the keyboard, the Files app
   showing `Received`, the sound with the ringer switch on and off, landscape and iPad multitasking widths.
2. **What happens after the phone locks.** If iOS closes the listening socket of a suspended app, the Web Server would still
   say "running" and accept nothing. If a phone test shows that, rebind the listener in the accept loops (`ShareHub`,
   `RequestCatcher`, `ProxyServer`, `SocketSessions`) after repeated accept failures.
3. **WebView.** `Avalonia.Controls.WebView` ships no iOS-specific asset; cURL's rendered preview may be unavailable (the view
   falls back with a message). Check the Response tab's preview.
4. **Native AOT and trimming.** An iOS release is fully ahead-of-time compiled and trimmed (CI only compiles it, the simulator
   run is a Debug build). Run every tool once on a device with the TestFlight build; reflection that works in Debug can fail
   there (the project already roots SSH.NET and DnsClient).
5. **Store screenshots** from real devices.
Then ship it (`.github/workflows/ios-testflight.yml` does steps 2 and 3 when you run it by hand):

1. Create the **Apple Distribution** certificate and an **App Store** provisioning profile for `com.sinaxhpm.echoes`.
2. The workflow imports both on the macOS runner and builds with manual signing (`dotnet publish ... -p:ArchiveOnBuild=true`, the
   build number is the run number, because every upload needs a higher one).
3. It uploads the `.ipa` with `xcrun altool` and the API key; Apple processes it for a few minutes.
4. Test with **TestFlight** first (internal testers need no review), then submit the version for review.

## App Store Connect checklist

1. Identifiers: register `com.sinaxhpm.echoes` with no capabilities.
2. Apps > **+** > New App: iOS and macOS, name `Echoes Network Toolkit`, SKU `echoes`, Full access.
3. App Information: category, content rights, age rating, Privacy Policy URL (all in [app-store-listing.md](app-store-listing.md)).
4. App Privacy: Data Not Collected. Pricing: free. Availability: your countries (see the encryption note for France).
5. A version: text, keywords, URLs, screenshots, the build from TestFlight, review notes, export compliance answers.
6. Submit for review.
