# Echoes on Apple platforms

How Echoes gets to macOS and iOS: what exists, what you do on developer.apple.com, and what is still missing. The text
to paste into App Store Connect is in [app-store-listing.md](app-store-listing.md). The privacy policy Apple asks for is
[PRIVACY.md](../../PRIVACY.md).

## Where things stand

| Piece | State |
| :--- | :--- |
| macOS `.dmg` on GitHub, signed with Developer ID, notarized and stapled | **Ready in CI.** Needs the secrets below; without them the build is signed ad hoc, as before. Not run on a real release yet. |
| macOS `.pkg` for the Mac App Store | Not built. Needs the App Sandbox, which cuts features; see "Mac App Store". |
| iOS / iPadOS app | **Scaffold only** (`Echoes.iOS/`, built for the simulator by `.github/workflows/ios.yml`). It is not a working app yet; see "What iOS still needs". |
| App Store build mode | `AppInfo.IsStoreBuild` (true on iOS, or on the desktop head with `-p:StoreBuild=true`): no update check, no Releases link. The About box has a Privacy policy link in every build. |
| Privacy policy, store text | Done. |

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

**Dry run without a release:** `.github/workflows/macos-test.yml` does the same for `osx-arm64` on the `apple-prep` branch (or by hand) and keeps the notarized `.dmg` as a workflow artifact for 3 days; it creates no tag, release or asset. Remove its branch trigger once the real release has been proven.

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

## What iOS still needs

`Echoes.iOS` holds the bundle metadata (`Info.plist`, an empty `Entitlements.plist`, a 1024 px opaque icon in
`Assets.xcassets`), the Avalonia entry point and the shared sources, the same way the Android head does. It is built for
the simulator in CI; **nobody has run it yet.** To make it a real app:

1. **Build it once** (run `ios.yml` by hand) and fix what the first compile reports. Avalonia.iOS 12 and the .NET 10 iOS
   workload need a recent Xcode on the runner.
2. **Review every platform branch in the shared code.** Many places say `OperatingSystem.IsAndroid()` where they mean "a
   phone" and treat everything else as a desktop. On iOS those fall into the desktop path, which starts child processes
   (`Process.Start`: not allowed on iOS), opens folders, uses the tray or auto-start. Search for `IsAndroid()` (about 35
   files) and `Process.Start` (CurlEngine, LinkHelper, SoundHelper, WifiLinux, the Web Server's Open folder) and give iOS its
   own answer; `AppPlatform.IsMobile` already selects the touch shell.
3. **Storage:** check `AppStorage` paths in the iOS sandbox, and put the received-files folder in Documents (with
   `UIFileSharingEnabled` and `LSSupportsOpeningDocumentsInPlace` in Info.plist) so users can reach files in the Files app.
4. **Background:** iOS suspends an app seconds after it leaves the screen. The monitor, the servers and scans pause with it.
   `BackgroundGuard` and `BootStart` have no iOS implementation (they are no-ops); decide whether to ask for a short
   background task and use local notifications for alerts, and keep the listing's "run while Echoes is open" wording.
5. **Sound:** register a player like the Android head's `SoundHelper.RegisterPlayer`.
6. **WebView:** `Avalonia.Controls.WebView` ships no iOS-specific asset; cURL's rendered preview may be unavailable
   (the view already falls back with a message). Check it.
7. **Network:** ICMP ping through unprivileged datagram sockets, traceroute with TTL, UDP and TCP, IPv6, and the Local
   Network prompt (`NSLocalNetworkUsageDescription` is in Info.plist). Test on a real iPhone: the simulator shares the Mac's
   network and hides the prompt.
8. **Layouts:** safe areas and the notch, the on-screen keyboard (`InputPane`, already handled for Android), landscape and
   iPad multitasking widths. Take the store screenshots from real devices.
9. **Native AOT and trimming:** an iOS release is fully ahead-of-time compiled and trimmed. Run every tool once on a device
   in a Release build; reflection that works in Debug can fail there (the project already roots SSH.NET and DnsClient).

Then ship it:

1. Create the **Apple Distribution** certificate and an **App Store** provisioning profile for `com.sinaxhpm.echoes`.
2. In CI, import both on the macOS runner and build with manual signing:
   `dotnet publish Echoes.iOS/Echoes.iOS.csproj -c Release -f net10.0-ios -r ios-arm64 -p:ArchiveOnBuild=true
   -p:CodesignKey="Apple Distribution: ..." -p:CodesignProvision="<profile name>" -p:ApplicationVersion=<run number>`.
   Every upload needs a build number (`ApplicationVersion`) higher than the last one.
3. Upload the `.ipa` with `xcrun altool --upload-app -f Echoes.ipa -t ios --apiKey <KEY_ID> --apiIssuer <ISSUER_ID>` (the
   `.p8` goes in `~/.appstoreconnect/private_keys/AuthKey_<KEY_ID>.p8`), or with Transporter.
4. Test with **TestFlight** first (internal testers need no review), then submit the version for review.

## App Store Connect checklist

1. Identifiers: register `com.sinaxhpm.echoes` with no capabilities.
2. Apps > **+** > New App: iOS and macOS, name `Echoes Network Toolkit`, SKU `echoes`, Full access.
3. App Information: category, content rights, age rating, Privacy Policy URL (all in [app-store-listing.md](app-store-listing.md)).
4. App Privacy: Data Not Collected. Pricing: free. Availability: your countries (see the encryption note for France).
5. A version: text, keywords, URLs, screenshots, the build from TestFlight, review notes, export compliance answers.
6. Submit for review.
