#!/usr/bin/env bash
# Builds Echoes.app from the Native AOT publish folder and wraps it in a .dmg.
#
#   packaging/macos/package.sh <rid> <version>        e.g. osx-arm64 0.5.0   ->   Echoes-osx-arm64.dmg
#
# Signing is picked up from the environment, nothing is needed to build locally:
#   SIGN_IDENTITY                                          unset: ad-hoc signature (runs here; Gatekeeper asks "Open Anyway")
#   SIGN_IDENTITY="Developer ID Application: ... (TEAM)"   Developer ID signature, hardened runtime, secure timestamp
#   + APPLE_API_KEY_P8, APPLE_API_KEY_ID, APPLE_API_ISSUER the app and then the .dmg are notarized by Apple and stapled,
#                                                          so the downloaded file opens with no warning (even offline)
# APPLE_API_KEY_P8 is the CONTENT of the App Store Connect API key file (AuthKey_XXXX.p8), not a path.
#
# PUBLISH_DIR (default ./publish) is where `dotnet publish` put the AOT output. DRY_RUN=1 only prints the Apple tools'
# command lines (used to check the order of the steps away from a Mac).
set -euo pipefail

rid="${1:?usage: package.sh <rid> <version>}"
version="${2:?usage: package.sh <rid> <version>}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
publish="${PUBLISH_DIR:-$root/publish}"
work="${WORK_DIR:-$root/dist}"
app="$work/Echoes.app"
dmg="${OUT_DIR:-$root}/Echoes-$rid.dmg"
entitlements="$here/Echoes.entitlements"

run() { if [ "${DRY_RUN:-}" = "1" ]; then echo "+ $*"; else "$@"; fi; }

sign_identity="${SIGN_IDENTITY:-}"
notarize=0
if [ -n "$sign_identity" ] && [ -n "${APPLE_API_KEY_P8:-}" ] && [ -n "${APPLE_API_KEY_ID:-}" ] && [ -n "${APPLE_API_ISSUER:-}" ]; then
  notarize=1
fi

if [ -n "$sign_identity" ]; then signing="Developer ID"; else signing="ad hoc"; fi
if [ $notarize = 1 ]; then notarizing=on; else notarizing=off; fi
echo "Echoes $version ($rid): signing = $signing, notarization = $notarizing"

# ---- the bundle ------------------------------------------------------------------------------------------------------
rm -rf "$work"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$publish/Echoes" "$app/Contents/MacOS/"
cp "$publish"/*.dylib "$app/Contents/MacOS/" 2>/dev/null || true
chmod +x "$app/Contents/MacOS/Echoes"
cp "$root/Assets/logo.icns" "$app/Contents/Resources/icon.icns"
sed "s/@VERSION@/$version/g" "$here/Info.plist" > "$app/Contents/Info.plist"
if grep -q '@VERSION@' "$app/Contents/Info.plist"; then echo "Info.plist still has a placeholder" >&2; exit 1; fi

# ---- signing: inner code first, the bundle last (no --deep, Apple advises against it) -----------------------------------
if [ -n "$sign_identity" ]; then
  # --timestamp: a secure timestamp from Apple, which notarization requires; --options runtime: the hardened runtime
  for lib in "$app"/Contents/MacOS/*.dylib; do
    [ -e "$lib" ] || continue
    run codesign --force --timestamp --options runtime --sign "$sign_identity" "$lib"
  done
  run codesign --force --timestamp --options runtime --entitlements "$entitlements" --sign "$sign_identity" "$app"
else
  run codesign --force --options runtime --entitlements "$entitlements" --deep --sign - "$app"
fi
run codesign --verify --strict --verbose=2 "$app"

# ---- notarization (waits for Apple's verdict; a rejection prints Apple's log and stops the build) ------------------------
key_file=""
cleanup() { [ -n "$key_file" ] && rm -f "$key_file"; true; }
trap cleanup EXIT

notarize_file() {   # $1 = a .zip or .dmg to submit
  local out id
  out="$(run xcrun notarytool submit "$1" --key "$key_file" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_ISSUER" --wait --timeout "${NOTARIZE_TIMEOUT:-40m}" 2>&1)" || true
  echo "$out"
  [ "${DRY_RUN:-}" = "1" ] && return 0
  id="$(echo "$out" | awk '/^ *id:/ { print $2; exit }')"
  if ! echo "$out" | grep -q 'status: Accepted'; then
    if echo "$out" | grep -q -E 'status: (Invalid|Rejected)'; then
      echo "Apple REJECTED $1 (submission $id); its log follows" >&2
      [ -n "$id" ] && xcrun notarytool log "$id" --key "$key_file" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_ISSUER" >&2 || true
    else
      # no verdict yet: Apple's queue can take hours for a team's first submissions. Not a rejection.
      echo "Apple has not finished with $1 (submission $id) after ${NOTARIZE_TIMEOUT:-40m}: not rejected, still in its queue." >&2
      echo "Ask later:  xcrun notarytool info $id --key <AuthKey.p8> --key-id <KEY_ID> --issuer <ISSUER_ID>" >&2
    fi
    exit 1
  fi
}

if [ $notarize = 1 ]; then
  key_file="$(mktemp "${TMPDIR:-/tmp}/AuthKey.XXXXXX")"
  printf '%s\n' "$APPLE_API_KEY_P8" > "$key_file"
  chmod 600 "$key_file"

  # the app itself first, so the ticket is stapled INSIDE the .dmg's copy and Gatekeeper needs no network on first launch
  zip_file="$work/Echoes-notarize.zip"
  run ditto -c -k --keepParent "$app" "$zip_file"
  notarize_file "$zip_file"
  run xcrun stapler staple "$app"
  rm -f "$zip_file"
fi

# ---- the .dmg ----------------------------------------------------------------------------------------------------------
stage="$work/dmg"
mkdir -p "$stage"
cp -R "$app" "$stage/"
ln -s /Applications "$stage/Applications"
rm -f "$dmg"
run hdiutil create -volname "Echoes Installer" -srcfolder "$stage" -ov -format UDZO "$dmg"
if [ -n "$sign_identity" ]; then
  run codesign --force --timestamp --sign "$sign_identity" "$dmg"
fi
if [ $notarize = 1 ]; then
  notarize_file "$dmg"
  run xcrun stapler staple "$dmg"
  run xcrun stapler validate "$dmg"
  # what Gatekeeper itself says about both; informational (a runner may have assessments switched off)
  run spctl --assess --type exec --verbose=2 "$app" || echo "spctl did not accept the app (see above)"
  run spctl --assess --type open --context context:primary-signature --verbose=2 "$dmg" || echo "spctl did not accept the dmg (see above)"
fi

echo "built $dmg"
