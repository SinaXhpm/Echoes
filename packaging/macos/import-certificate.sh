#!/usr/bin/env bash
# Puts the Developer ID Application certificate (a .p12 with its private key) into a temporary keychain on a GitHub macOS
# runner and hands the signing identity to packaging/macos/package.sh through GITHUB_ENV (SIGN_IDENTITY, SIGN_KEYCHAIN).
# Without APPLE_CERT_P12_BASE64 it does nothing, and the build is signed ad hoc instead.
#
#   env: APPLE_CERT_P12_BASE64 (base64 of the .p12), APPLE_CERT_PASSWORD, RUNNER_TEMP, GITHUB_ENV
set -euo pipefail

if [ -z "${APPLE_CERT_P12_BASE64:-}" ]; then
  echo "No Apple certificate in the secrets: the app will be signed ad hoc."
  exit 0
fi

KEYCHAIN="$RUNNER_TEMP/echoes-signing.keychain-db"
KEYCHAIN_PASSWORD="$(uuidgen)"
echo "$APPLE_CERT_P12_BASE64" | base64 --decode > "$RUNNER_TEMP/signing.p12"
security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security set-keychain-settings -lut 21600 "$KEYCHAIN"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"

# Apple's intermediate certificate, so the chain Developer ID > Apple Root is complete in this keychain (best effort: the
# runner image normally has it already, and the identity check below is the real test)
if curl -fsSL -o "$RUNNER_TEMP/DeveloperIDG2CA.cer" https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer; then
  security import "$RUNNER_TEMP/DeveloperIDG2CA.cer" -k "$KEYCHAIN" || true
else
  echo "Could not download Apple's intermediate certificate; continuing with the runner's own."
fi

security import "$RUNNER_TEMP/signing.p12" -P "$APPLE_CERT_PASSWORD" -f pkcs12 -k "$KEYCHAIN" -T /usr/bin/codesign -T /usr/bin/security
security set-key-partition-list -S apple-tool:,apple: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN" > /dev/null
security list-keychains -d user -s "$KEYCHAIN" $(security list-keychains -d user | tr -d '"')
rm -f "$RUNNER_TEMP/signing.p12"

IDENTITY="$(security find-identity -v -p codesigning "$KEYCHAIN" | awk '/Developer ID Application/ { print $2; exit }')"
if [ -z "$IDENTITY" ]; then
  echo "::error::The certificate was imported but it holds no valid Developer ID Application identity."
  security find-identity -p codesigning "$KEYCHAIN"
  exit 1
fi
echo "Signing with the Developer ID Application identity ($IDENTITY)"
echo "SIGN_IDENTITY=$IDENTITY" >> "$GITHUB_ENV"
echo "SIGN_KEYCHAIN=$KEYCHAIN" >> "$GITHUB_ENV"
