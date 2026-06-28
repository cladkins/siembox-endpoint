#!/bin/bash
# build-pkg.sh - build a macOS .pkg installer for the SIEMBox Endpoint agent.
#
# Must run on macOS (uses lipo + pkgbuild). Produces a universal (amd64+arm64)
# binary and a component package that installs the agent, seeds a config
# template, and registers the launchd service via the pkg postinstall script.
#
#   VERSION=1.2.3 packaging/darwin/build-pkg.sh
set -euo pipefail

VERSION="${VERSION:-0.0.0}"
PKGID="io.siembox.agent"
REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"

ROOT=$(mktemp -d)
SCRIPTS=$(mktemp -d)
OUT="$REPO_ROOT/dist"
mkdir -p "$OUT"
trap 'rm -rf "$ROOT" "$SCRIPTS"' EXIT

LDFLAGS="-s -w -X github.com/cladkins/siembox-endpoint/internal/version.Version=${VERSION}"

echo "building universal binary (amd64 + arm64)..."
GOOS=darwin GOARCH=amd64 go build -ldflags "$LDFLAGS" -o "$ROOT/agent-amd64" ./cmd/siembox-agent
GOOS=darwin GOARCH=arm64 go build -ldflags "$LDFLAGS" -o "$ROOT/agent-arm64" ./cmd/siembox-agent

mkdir -p "$ROOT/usr/local/bin" "$ROOT/Library/Application Support/SIEMBox/agent"
lipo -create -output "$ROOT/usr/local/bin/siembox-agent" "$ROOT/agent-amd64" "$ROOT/agent-arm64"
rm -f "$ROOT/agent-amd64" "$ROOT/agent-arm64"
chmod 0755 "$ROOT/usr/local/bin/siembox-agent"

# Ship the uninstaller so the menu bar app's "Uninstall" item (and CLI users)
# can fully remove SIEMBox Endpoint.
cp packaging/darwin/uninstall.sh "$ROOT/usr/local/bin/siembox-uninstall"
chmod 0755 "$ROOT/usr/local/bin/siembox-uninstall"

cp packaging/agent.json.template "$ROOT/Library/Application Support/SIEMBox/agent/agent.json.template"

# Bundle the menu bar app into the payload so it installs to /Applications, and
# a LaunchAgent so it starts at login. (pkg-installed files aren't quarantined,
# so it launches without a Gatekeeper prompt even unsigned.)
mkdir -p "$ROOT/Applications" "$ROOT/Library/LaunchAgents"
VERSION="$VERSION" bash packaging/darwin/make-tray-app.sh "$ROOT/Applications"
cp packaging/darwin/io.siembox.menubar.plist "$ROOT/Library/LaunchAgents/io.siembox.menubar.plist"
chmod 0644 "$ROOT/Library/LaunchAgents/io.siembox.menubar.plist"

cp packaging/darwin/pkg-scripts/postinstall "$SCRIPTS/postinstall"
chmod 0755 "$SCRIPTS/postinstall"

PKG="$OUT/siembox-agent-${VERSION}-macos.pkg"
echo "building $PKG ..."
pkgbuild \
	--root "$ROOT" \
	--identifier "$PKGID" \
	--version "$VERSION" \
	--scripts "$SCRIPTS" \
	--install-location / \
	"$PKG"

echo "built $PKG"
