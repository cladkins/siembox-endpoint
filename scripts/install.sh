#!/bin/sh
# install.sh - standalone installer for the SIEMBox Endpoint agent on Linux.
#
#   curl -sSfL https://raw.githubusercontent.com/cladkins/siembox-endpoint/main/scripts/install.sh | sudo sh
#
# Downloads the latest release binary, installs osquery + grype if missing,
# seeds a config template, and registers the system service. For .deb/.rpm
# hosts the native package (which runs packaging/linux/postinstall.sh) is
# preferred; this script is the fallback for other distros.
set -e

REPO="cladkins/siembox-endpoint"
CONF_DIR=/etc/siembox-agent
CONF_FILE="$CONF_DIR/agent.json"
INSTALL_BIN=/usr/local/bin/siembox-agent

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' is required" >&2; exit 1; }; }
need curl
need tar

# Detect arch.
case "$(uname -m)" in
	x86_64|amd64) ARCH=amd64 ;;
	aarch64|arm64) ARCH=arm64 ;;
	*) echo "error: unsupported arch $(uname -m)" >&2; exit 1 ;;
esac

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
if [ "$OS" != "linux" ]; then
	echo "error: this script supports Linux; use packaging/darwin or packaging/windows for other OSes" >&2
	exit 1
fi

# Resolve the latest release tag.
echo "siembox-agent: resolving latest release..."
TAG=$(curl -sSfL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
if [ -z "$TAG" ]; then
	echo "error: could not determine latest release tag" >&2
	exit 1
fi
VERSION=${TAG#v}

# goreleaser archive name: siembox-endpoint_<version>_linux_<arch>.tar.gz
ARCHIVE="siembox-endpoint_${VERSION}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/$REPO/releases/download/$TAG/$ARCHIVE"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
echo "siembox-agent: downloading $URL"
curl -sSfL "$URL" -o "$TMP/$ARCHIVE"
tar -xzf "$TMP/$ARCHIVE" -C "$TMP"
install -m 0755 "$TMP/siembox-agent" "$INSTALL_BIN"
echo "siembox-agent: installed $INSTALL_BIN ($("$INSTALL_BIN" version))"

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
	echo "siembox-agent: wrote config template to $CONF_FILE"
fi

# Dependencies.
if ! command -v grype >/dev/null 2>&1; then
	echo "siembox-agent: installing grype..."
	curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin || \
		echo "siembox-agent: WARNING: grype install failed; vuln scanning disabled until installed."
fi
if ! command -v osqueryd >/dev/null 2>&1; then
	echo "siembox-agent: installing osquery..."
	if command -v apt-get >/dev/null 2>&1; then
		mkdir -p /etc/apt/keyrings
		curl -fsSL https://pkg.osquery.io/deb/pubkey.gpg | gpg --dearmor -o /etc/apt/keyrings/osquery.gpg 2>/dev/null || true
		echo "deb [signed-by=/etc/apt/keyrings/osquery.gpg] https://pkg.osquery.io/deb deb main" \
			> /etc/apt/sources.list.d/osquery.list
		apt-get update -qq && apt-get install -y osquery || \
			echo "siembox-agent: WARNING: osquery install failed; detection disabled until installed."
	else
		echo "siembox-agent: install osquery manually to enable detection (no apt-get found)."
	fi
fi

echo ""
echo "siembox-agent installed. Next steps:"
echo "  1. Edit $CONF_FILE (set server_url + enrollment_token)."
echo "  2. Register + start the service:"
echo "       sudo siembox-agent -dir $CONF_DIR install"
echo "       sudo siembox-agent -dir $CONF_DIR start"
echo "  Test locally without a server:"
echo "       sudo siembox-agent scan     # vulnerability findings (JSON)"
echo "       sudo siembox-agent check    # detection check (JSON)"
