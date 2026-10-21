#!/usr/bin/env bash
# Puts the two certificates of a Mac App Store build into a temporary keychain on a GitHub macOS runner (Apple Distribution, which
# signs the app, and Mac Installer Distribution, which signs the .pkg) and installs the Mac App Store provisioning profile. Hands
# the identities (by their SHA-1 hash, never by name: this log is public) and the profile's path to packaging/macos/package-appstore.sh
# through GITHUB_ENV (APPSTORE_APP_IDENTITY, APPSTORE_INSTALLER_IDENTITY, APPSTORE_PROFILE, APPSTORE_KEYCHAIN).
#
#   env: IOS_CERT_P12_BASE64 + IOS_CERT_PASSWORD         the Apple Distribution .p12 (the same certificate as iOS uses)
#        MACINSTALLER_CERT_P12_BASE64 + MACINSTALLER_CERT_PASSWORD   the Mac Installer Distribution .p12
#        MAC_PROFILE_BASE64                              the Mac App Store .provisionprofile
#        RUNNER_TEMP, GITHUB_ENV
# Without all five secrets it does nothing: the workflow then only runs its sandbox test.
set -euo pipefail

for v in IOS_CERT_P12_BASE64 IOS_CERT_PASSWORD MACINSTALLER_CERT_P12_BASE64 MACINSTALLER_CERT_PASSWORD MAC_PROFILE_BASE64; do
  if [ -z "${!v:-}" ]; then
    echo "The secret $v is not set: the store package is not signed (only the sandbox test runs)."
    exit 0
  fi
done

KEYCHAIN="$RUNNER_TEMP/echoes-appstore-signing.keychain-db"
KEYCHAIN_PASSWORD="$(uuidgen)"
security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security set-keychain-settings -lut 21600 "$KEYCHAIN"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"

# Apple's intermediate certificate (WWDR G3), so the chain to Apple's root is complete (best effort: the runner image
# normally has it, and the identity checks below are the real test)
if curl -fsSL -o "$RUNNER_TEMP/AppleWWDRCAG3.cer" https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer; then
  security import "$RUNNER_TEMP/AppleWWDRCAG3.cer" -k "$KEYCHAIN" || true
fi

import_p12() {   # $1 = base64 .p12, $2 = its password, $3 = what it is (for the message)
  echo "$1" | base64 --decode > "$RUNNER_TEMP/import.p12"
  if ! security import "$RUNNER_TEMP/import.p12" -P "$2" -f pkcs12 -k "$KEYCHAIN" -T /usr/bin/codesign -T /usr/bin/productbuild -T /usr/bin/security; then
    echo "::error::The $3 (.p12) could not be imported: wrong password, damaged secret, or an encoding macOS can't read."
    echo "decoded .p12: $(wc -c < "$RUNNER_TEMP/import.p12" | tr -d ' ') bytes; password: ${#2} characters"
    rm -f "$RUNNER_TEMP/import.p12"
    exit 1
  fi
  rm -f "$RUNNER_TEMP/import.p12"
}
import_p12 "$IOS_CERT_P12_BASE64" "$IOS_CERT_PASSWORD" "Apple Distribution certificate"
import_p12 "$MACINSTALLER_CERT_P12_BASE64" "$MACINSTALLER_CERT_PASSWORD" "Mac Installer Distribution certificate"
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN" > /dev/null
security list-keychains -d user -s "$KEYCHAIN" $(security list-keychains -d user | tr -d '"')

# the identities as SHA-1 hashes (the names inside the certificates are never printed)
APP_ID="$(security find-identity -v -p codesigning "$KEYCHAIN" | awk '/Apple Distribution/ { print $2; exit }')"
INSTALLER_ID="$(security find-identity -v "$KEYCHAIN" | awk '/Mac Installer Distribution|3rd Party Mac Developer Installer/ { print $2; exit }')"
if [ -z "$APP_ID" ]; then
  echo "::error::No valid Apple Distribution identity in the keychain (expired, or Apple's chain is missing)."
  security find-identity -p codesigning "$KEYCHAIN" | sed -E 's/"[^"]*"/"<identity>"/'
  exit 1
fi
if [ -z "$INSTALLER_ID" ]; then
  echo "::error::No valid Mac Installer Distribution identity in the keychain (expired, or Apple's chain is missing)."
  security find-identity "$KEYCHAIN" | sed -E 's/"[^"]*"/"<identity>"/'
  exit 1
fi

PROFILE="$RUNNER_TEMP/echoes-mac.provisionprofile"
echo "$MAC_PROFILE_BASE64" | base64 --decode > "$PROFILE"
security cms -D -i "$PROFILE" > "$RUNNER_TEMP/echoes-mac-profile.plist"
PROFILE_NAME="$(/usr/libexec/PlistBuddy -c 'Print :Name' "$RUNNER_TEMP/echoes-mac-profile.plist")"
PROFILE_APP="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.application-identifier' "$RUNNER_TEMP/echoes-mac-profile.plist")"
rm -f "$RUNNER_TEMP/echoes-mac-profile.plist"

echo "Apple Distribution identity ($APP_ID), Mac Installer identity ($INSTALLER_ID), profile \"$PROFILE_NAME\" for ${PROFILE_APP#*.}"
{
  echo "APPSTORE_APP_IDENTITY=$APP_ID"
  echo "APPSTORE_INSTALLER_IDENTITY=$INSTALLER_ID"
  echo "APPSTORE_PROFILE=$PROFILE"
  echo "APPSTORE_KEYCHAIN=$KEYCHAIN"
} >> "$GITHUB_ENV"
