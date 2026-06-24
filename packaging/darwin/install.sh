#!/bin/sh
# install.sh - SIEMBox EDR agent installer for macOS (launchd).
#
# NOTE: authored against macOS conventions but NOT yet validated on a real Mac.
# Test on a recent macOS host before relying on it.
#
# Run with sudo. Installs osquery + grype (via Homebrew if available, else the
# official osquery .pkg), places the agent, seeds config, and registers a
# launchd service via `siembox-agent install`.
set -e

CONF_DIR="/Library/Application Support/SIEMBox/agent"
CONF_FILE="$CONF_DIR/agent.json"
INSTALL_BIN=/usr/local/bin/siembox-agent

if [ "$(id -u)" != "0" ]; then
	echo "error: run with sudo" >&2
	exit 1
fi

# Expect the agent binary alongside this script (from the release archive).
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
if [ -f "$SCRIPT_DIR/../../siembox-agent" ]; then
	install -m 0755 "$SCRIPT_DIR/../../siembox-agent" "$INSTALL_BIN"
elif [ -f "$SCRIPT_DIR/siembox-agent" ]; then
	install -m 0755 "$SCRIPT_DIR/siembox-agent" "$INSTALL_BIN"
fi

mkdir -p "$CONF_DIR"
if [ ! -f "$CONF_FILE" ]; then
	cat > "$CONF_FILE" <<'JSON'
{
  "server_url": "https://CHANGE-ME.siembox.lan:8421",
  "enrollment_token": "PASTE-ENROLLMENT-TOKEN-FROM-SIEMBOX-UI",
  "ca_cert_path": "",
  "insecure_skip_verify": false
}
JSON
	chmod 600 "$CONF_FILE"
fi

# Dependencies.
OSQUERY_VERSION="5.23.0"
command -v grype >/dev/null 2>&1 || [ -x /usr/local/bin/grype ] || \
	curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin || true

if ! command -v osqueryi >/dev/null 2>&1 \
	&& [ ! -x /usr/local/bin/osqueryi ] \
	&& [ ! -x /opt/osquery/lib/osquery.app/Contents/MacOS/osqueryi ]; then
	if command -v brew >/dev/null 2>&1; then
		brew install --cask osquery || true
	else
		TMP=$(mktemp -d)
		if curl -fsSL -o "$TMP/osquery.pkg" "https://pkg.osquery.io/darwin/osquery-${OSQUERY_VERSION}.pkg"; then
			installer -pkg "$TMP/osquery.pkg" -target / || \
				echo "siembox-agent: WARNING: osquery install failed; detection disabled until installed."
		fi
		rm -rf "$TMP"
	fi
fi

"$INSTALL_BIN" -dir "$CONF_DIR" install || true
echo "siembox-agent: edit \"$CONF_FILE\", then: sudo siembox-agent -dir \"$CONF_DIR\" start"
