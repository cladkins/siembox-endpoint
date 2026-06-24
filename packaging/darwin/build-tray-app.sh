#!/bin/bash
# build-tray-app.sh - build the SIEMBox EDR menu bar app (.app) for macOS.
#
# Must run on macOS (CGO + lipo). Produces a universal app bundle and zips it.
# The app shells out to the installed siembox-agent CLI, so install the agent
# .pkg first.
#
#   VERSION=1.2.3 packaging/darwin/build-tray-app.sh
set -euo pipefail

VERSION="${VERSION:-0.0.0}"
REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"

OUT="$REPO_ROOT/dist"
APP="$OUT/SIEMBox Menu Bar.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

LDFLAGS="-s -w -X github.com/cladkins/siembox-edr/internal/version.Version=${VERSION}"

echo "building menu bar app (universal)..."
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

( cd "$OUT" && zip -r -q "SIEMBox-Menu-Bar-${VERSION}-macos.zip" "SIEMBox Menu Bar.app" )
echo "built $OUT/SIEMBox-Menu-Bar-${VERSION}-macos.zip"
