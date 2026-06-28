#!/bin/bash
# make-tray-app.sh - assemble "SIEMBox Menu Bar.app" into a destination dir.
# Shared by build-tray-app.sh (standalone zip) and build-pkg.sh (pkg payload).
# Must run on macOS (CGO + lipo).
#
#   VERSION=1.2.3 packaging/darwin/make-tray-app.sh <dest-dir>
set -euo pipefail

DEST="${1:?usage: make-tray-app.sh <dest-dir>}"
VERSION="${VERSION:-0.0.0}"
REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"

APP="$DEST/SIEMBox Menu Bar.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

LDFLAGS="-s -w -X github.com/cladkins/siembox-endpoint/internal/version.Version=${VERSION}"

echo "building menu bar app (universal) -> $APP"
GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 go build -ldflags "$LDFLAGS" -o /tmp/tray-amd64 ./cmd/siembox-tray
GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build -ldflags "$LDFLAGS" -o /tmp/tray-arm64 ./cmd/siembox-tray
lipo -create -output "$APP/Contents/MacOS/siembox-tray" /tmp/tray-amd64 /tmp/tray-arm64
rm -f /tmp/tray-amd64 /tmp/tray-arm64
chmod 0755 "$APP/Contents/MacOS/siembox-tray"

# LSUIElement=true makes it a menu-bar-only agent (no Dock icon).
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>           <string>SIEMBox Menu Bar</string>
  <key>CFBundleDisplayName</key>    <string>SIEMBox Menu Bar</string>
  <key>CFBundleIdentifier</key>     <string>io.siembox.menubar</string>
  <key>CFBundleExecutable</key>     <string>siembox-tray</string>
  <key>CFBundlePackageType</key>    <string>APPL</string>
  <key>CFBundleShortVersionString</key> <string>${VERSION}</string>
  <key>CFBundleVersion</key>        <string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key> <string>11.0</string>
  <key>LSUIElement</key>            <true/>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

echo "assembled $APP"
