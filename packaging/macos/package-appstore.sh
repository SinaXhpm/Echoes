#!/usr/bin/env bash
# Builds the Mac App Store package of Echoes from two Native AOT publish folders (arm64 and x64, both published with
# -p:StoreBuild=true so the store switch is compiled in). Two things come out, see docs/apple/README.md ("Mac App Store"):
#
#   $WORK/test/Echoes.app          always: the app signed AD HOC with the store's sandbox entitlements. The workflow runs it with
#                                  ECHOES_STORE_SELFTEST=1 to see what the App Sandbox does to Echoes (no certificate needed).
#   $OUT_DIR/Echoes-AppStore.pkg   when the signing identities are there: the app signed with Apple Distribution and the
#                                  provisioning profile embedded, wrapped by productbuild and signed with Mac Installer Distribution.
#
#   packaging/macos/package-appstore.sh <version> <build>      e.g. 1.0.0 12    (build = CFBundleVersion, rises with every upload)
#
# Environment:
#   PUBLISH_ARM64, PUBLISH_X64   the publish folders (default ./publish-arm64, ./publish-x64); without the x64 one the app is arm64 only
#   APPSTORE_APP_IDENTITY, APPSTORE_INSTALLER_IDENTITY, APPSTORE_PROFILE   set by import-appstore-signing.sh (hashes and a path)
#   APPSTORE_KEYCHAIN            the keychain holding them (optional)
#   WORK_DIR (default ./dist-appstore), OUT_DIR (default .)
# DRY_RUN=1 only prints the Apple tools' command lines.
set -euo pipefail

version="${1:?usage: package-appstore.sh <version> <build>}"
build="${2:?usage: package-appstore.sh <version> <build>}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
arm64="${PUBLISH_ARM64:-$root/publish-arm64}"
x64="${PUBLISH_X64:-$root/publish-x64}"
work="${WORK_DIR:-$root/dist-appstore}"
out="${OUT_DIR:-$root}"
pkg="$out/Echoes-AppStore.pkg"
entitlements_template="$here/Echoes.AppStore.entitlements"

run() { if [ "${DRY_RUN:-}" = "1" ]; then echo "+ $*"; else "$@"; fi; }

[ -f "$arm64/Echoes" ] || { echo "::error::$arm64/Echoes is missing: publish osx-arm64 first" >&2; exit 1; }

# ---- the bundle (universal when both publishes are there) -----------------------------------------------------------------
assemble() {   # $1 = the .app to make
  local app="$1" lib name
  rm -rf "$app"
  mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
  if [ -f "$x64/Echoes" ]; then
    lipo -create "$arm64/Echoes" "$x64/Echoes" -output "$app/Contents/MacOS/Echoes"
  else
    cp "$arm64/Echoes" "$app/Contents/MacOS/Echoes"
  fi
  chmod +x "$app/Contents/MacOS/Echoes"
  # the native libraries ship as universal files; if one isn't, join the two slices
  for lib in "$arm64"/*.dylib; do
    [ -e "$lib" ] || continue
    name="$(basename "$lib")"
    if [ -f "$x64/$name" ] && ! lipo -archs "$lib" | grep -q x86_64 && lipo -archs "$x64/$name" | grep -q x86_64; then
      lipo -create "$lib" "$x64/$name" -output "$app/Contents/MacOS/$name"
    else
      cp "$lib" "$app/Contents/MacOS/$name"
    fi
  done
  cp "$root/Assets/logo.icns" "$app/Contents/Resources/icon.icns"
  sed "s/@VERSION@/$version/g" "$here/Info.plist" > "$app/Contents/Info.plist"
  if grep -q '@VERSION@' "$app/Contents/Info.plist"; then echo "Info.plist still has a placeholder" >&2; exit 1; fi
  # the store wants a build number of its own that rises with every upload
  /usr/libexec/PlistBuddy -c "Set :CFBundleVersion $build" "$app/Contents/Info.plist"
}

rm -rf "$work"
mkdir -p "$work" "$out"
test_app="$work/test/Echoes.app"
assemble "$test_app"
echo "Echoes $version (build $build): $(lipo -archs "$test_app/Contents/MacOS/Echoes")"

# the oldest macOS: every slice's deployment target must match Info.plist (LSMinimumSystemVersion 12.0), as in package.sh
if command -v vtool >/dev/null 2>&1; then
  while read -r minos; do
    echo "Echoes binary: minimum macOS $minos"
    if [ -n "$minos" ] && [ "${minos%%.*}" -gt 12 ]; then
      echo "::error::The binary needs macOS $minos, but Info.plist promises 12.0: set MACOSX_DEPLOYMENT_TARGET=12.0 for dotnet publish." >&2
      exit 1
    fi
  done < <(vtool -show-build "$test_app/Contents/MacOS/Echoes" 2>/dev/null | awk '/minos/ { for (i = 1; i <= NF; i++) if ($i == "minos") print $(i + 1) }')
fi

# ---- 1. the sandboxed ad-hoc copy for the sandbox test ----------------------------------------------------------------------
# The two identifiers are restricted entitlements that only a provisioning profile allows: left out of the ad-hoc copy.
test_ent="$work/test.entitlements"
cp "$entitlements_template" "$test_ent"
/usr/libexec/PlistBuddy -c "Delete :com.apple.application-identifier" "$test_ent"
/usr/libexec/PlistBuddy -c "Delete :com.apple.developer.team-identifier" "$test_ent"
for lib in "$test_app"/Contents/MacOS/*.dylib; do
  [ -e "$lib" ] || continue
  run codesign --force --sign - "$lib"
done
run codesign --force --sign - --entitlements "$test_ent" "$test_app"
run codesign --verify --strict --verbose=2 "$test_app"
echo "built $test_app (ad hoc, sandboxed)"

# ---- 2. the signed package ----------------------------------------------------------------------------------------------------
if [ -z "${APPSTORE_APP_IDENTITY:-}" ] || [ -z "${APPSTORE_INSTALLER_IDENTITY:-}" ] || [ -z "${APPSTORE_PROFILE:-}" ]; then
  echo "No signing identities: the signed package is not built."
  exit 0
fi

app="$work/Echoes.app"
assemble "$app"
cp "$APPSTORE_PROFILE" "$app/Contents/embedded.provisionprofile"

# the identifiers the profile allows
profile_plist="$work/profile.plist"
security cms -D -i "$APPSTORE_PROFILE" > "$profile_plist"
app_identifier="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.application-identifier' "$profile_plist")"
team_id="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.developer.team-identifier' "$profile_plist")"
rm -f "$profile_plist"
ent="$work/Echoes.entitlements"
sed -e "s|@APP_IDENTIFIER@|$app_identifier|" -e "s|@TEAM_ID@|$team_id|" "$entitlements_template" > "$ent"
if grep -q '@' "$ent"; then echo "the entitlements still have a placeholder" >&2; exit 1; fi

# an empty array is an unbound variable for macOS' bash 3.2 under set -u: hence the \+\ form below
# (the ${keychain[@]+...} form below: an empty array is an unbound variable for macOS' bash 3.2 under `set -u`)
keychain=()
[ -n "${APPSTORE_KEYCHAIN:-}" ] && keychain=(--keychain "$APPSTORE_KEYCHAIN")

for lib in "$app"/Contents/MacOS/*.dylib; do
  [ -e "$lib" ] || continue
  run codesign --force --timestamp ${keychain[@]+"${keychain[@]}"} --sign "$APPSTORE_APP_IDENTITY" "$lib"
done
run codesign --force --timestamp ${keychain[@]+"${keychain[@]}"} --entitlements "$ent" --sign "$APPSTORE_APP_IDENTITY" "$app"
run codesign --verify --strict --verbose=2 "$app"
# what the signature carries: the sandbox and the identifiers (the team id is public; not printed anyway)
run codesign -d --entitlements :- "$app" 2>/dev/null | grep -E 'app-sandbox|network|files\.' || true

rm -f "$pkg"
run productbuild --component "$app" /Applications --sign "$APPSTORE_INSTALLER_IDENTITY" --timestamp ${keychain[@]+"${keychain[@]}"} "$pkg"
echo "built $pkg"
