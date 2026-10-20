#!/usr/bin/env bash
# Puts the Apple Distribution certificate (a .p12 with its private key) into a temporary keychain on a GitHub macOS runner and
# installs the App Store provisioning profile; hands the signing identity and the profile name to the build through GITHUB_ENV
# (IOS_SIGN_IDENTITY, IOS_PROFILE_NAME, IOS_SIGN_KEYCHAIN). The names inside the certificate are never printed: this log is public.
#
#   env: IOS_CERT_P12_BASE64 (base64 of the .p12), IOS_CERT_PASSWORD, IOS_PROFILE_BASE64 (base64 of the .mobileprovision),
#        RUNNER_TEMP, GITHUB_ENV
set -euo pipefail

: "${IOS_CERT_P12_BASE64:?the iOS certificate secret is missing}"
: "${IOS_PROFILE_BASE64:?the iOS provisioning profile secret is missing}"

KEYCHAIN="$RUNNER_TEMP/echoes-ios-signing.keychain-db"
KEYCHAIN_PASSWORD="$(uuidgen)"
echo "$IOS_CERT_P12_BASE64" | base64 --decode > "$RUNNER_TEMP/ios-signing.p12"
security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security set-keychain-settings -lut 21600 "$KEYCHAIN"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"

# Apple's intermediate certificate (WWDR G3) so the chain to Apple's root is complete in this keychain (best effort: the
# runner image normally has it, and the identity check below is the real test)
if curl -fsSL -o "$RUNNER_TEMP/AppleWWDRCAG3.cer" https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer; then
  security import "$RUNNER_TEMP/AppleWWDRCAG3.cer" -k "$KEYCHAIN" || true
else
  echo "Could not download Apple's intermediate certificate; continuing with the runner's own."
fi

if ! security import "$RUNNER_TEMP/ios-signing.p12" -P "$IOS_CERT_PASSWORD" -f pkcs12 -k "$KEYCHAIN" -T /usr/bin/codesign -T /usr/bin/security; then
  echo "::error::The iOS certificate (.p12) could not be imported: wrong password, damaged secret, or an encoding macOS can't read."
  echo "decoded .p12: $(wc -c < "$RUNNER_TEMP/ios-signing.p12" | tr -d ' ') bytes; password: ${#IOS_CERT_PASSWORD} characters"
  rm -f "$RUNNER_TEMP/ios-signing.p12"
  exit 1
fi
security set-key-partition-list -S apple-tool:,apple: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN" > /dev/null
security list-keychains -d user -s "$KEYCHAIN" $(security list-keychains -d user | tr -d '"')
rm -f "$RUNNER_TEMP/ios-signing.p12"

IDENTITY="$(security find-identity -v -p codesigning "$KEYCHAIN" | awk '/Apple Distribution/ { print $2; exit }')"
if [ -z "$IDENTITY" ]; then
  echo "::error::The certificate was imported but it holds no valid Apple Distribution identity (expired, or Apple's chain is missing)."
  security find-identity -p codesigning "$KEYCHAIN" | sed -E 's/"[^"]*"/"<identity>"/'
  exit 1
fi

# the provisioning profile: where both the .NET iOS tooling and Xcode look for it
PROFILE="$RUNNER_TEMP/echoes.mobileprovision"
echo "$IOS_PROFILE_BASE64" | base64 --decode > "$PROFILE"
security cms -D -i "$PROFILE" > "$RUNNER_TEMP/echoes-profile.plist"
PROFILE_UUID="$(/usr/libexec/PlistBuddy -c 'Print :UUID' "$RUNNER_TEMP/echoes-profile.plist")"
PROFILE_NAME="$(/usr/libexec/PlistBuddy -c 'Print :Name' "$RUNNER_TEMP/echoes-profile.plist")"
APP_ID="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:application-identifier' "$RUNNER_TEMP/echoes-profile.plist")"
for dir in "$HOME/Library/MobileDevice/Provisioning Profiles" "$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"; do
  mkdir -p "$dir"
  cp "$PROFILE" "$dir/$PROFILE_UUID.mobileprovision"
done
rm -f "$RUNNER_TEMP/echoes-profile.plist"

echo "Signing identity found ($IDENTITY); provisioning profile \"$PROFILE_NAME\" ($PROFILE_UUID) for ${APP_ID#*.}"
{
  echo "IOS_SIGN_IDENTITY=$IDENTITY"
  echo "IOS_PROFILE_NAME=$PROFILE_NAME"
  echo "IOS_SIGN_KEYCHAIN=$KEYCHAIN"
} >> "$GITHUB_ENV"
