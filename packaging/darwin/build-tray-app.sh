#!/bin/bash
# build-tray-app.sh - build the SIEMBox Endpoint menu bar app and zip it for release.
# Must run on macOS. The app is also bundled into the .pkg by build-pkg.sh; this
# standalone zip is for manual / non-pkg installs.
#
#   VERSION=1.2.3 packaging/darwin/build-tray-app.sh
set -euo pipefail

VERSION="${VERSION:-0.0.0}"
REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT="$REPO_ROOT/dist"
mkdir -p "$OUT"

VERSION="$VERSION" bash "$REPO_ROOT/packaging/darwin/make-tray-app.sh" "$OUT"

( cd "$OUT" && zip -r -q "SIEMBox-Menu-Bar-${VERSION}-macos.zip" "SIEMBox Menu Bar.app" )
echo "built $OUT/SIEMBox-Menu-Bar-${VERSION}-macos.zip"
