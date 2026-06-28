#!/bin/sh
# uninstall.sh - remove the SIEMBox Endpoint agent from Linux (non-package installs).
#
#   curl -sSfL https://raw.githubusercontent.com/cladkins/siembox-endpoint/main/scripts/uninstall.sh | sudo sh
#
# For .deb/.rpm installs use the package manager instead (apt remove siembox-agent
# / dnf remove siembox-agent), which runs the bundled pre-remove hook. This
# script handles binaries installed via scripts/install.sh.
set -e

BIN=/usr/local/bin/siembox-agent
CONF_DIR=/etc/siembox-agent

if [ -x "$BIN" ]; then
	echo "Stopping and unregistering the service…"
	"$BIN" -dir "$CONF_DIR" stop 2>/dev/null || true
	"$BIN" -dir "$CONF_DIR" uninstall 2>/dev/null || true
fi

rm -f "$BIN"

# Keep config/identity by default; pass --purge to remove it too.
if [ "${1:-}" = "--purge" ]; then
	rm -rf "$CONF_DIR"
	echo "Removed $CONF_DIR (config + identity)."
else
	echo "Left $CONF_DIR in place (pass --purge to remove config + identity)."
fi

echo "SIEMBox Endpoint agent removed. (osquery and grype were left installed.)"
