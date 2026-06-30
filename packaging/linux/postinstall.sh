#!/bin/sh
# postinstall.sh - run by dpkg/rpm after the siembox-agent package is unpacked.
# Fetches osquery + grype if missing, seeds a config template, and registers the
# system service. Safe to re-run (idempotent).
set -e

CONF_DIR=/etc/siembox-agent
CONF_FILE="$CONF_DIR/agent.json"
BIN=/usr/bin/siembox-agent

echo "siembox-agent: running post-install..."
mkdir -p "$CONF_DIR"

# Seed a config template on first install only (never clobber an existing one).
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
	echo "siembox-agent: wrote config template to $CONF_FILE (edit before starting)."
fi

# Dependency: grype (vulnerability scanner).
if ! command -v grype >/dev/null 2>&1; then
	echo "siembox-agent: installing grype..."
	curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin || \
		echo "siembox-agent: WARNING: grype install failed; vuln scanning will be disabled until installed."
fi

# Dependency: osquery (host telemetry). Prefer the official apt/yum repo.
if ! command -v osqueryd >/dev/null 2>&1; then
	echo "siembox-agent: installing osquery..."
	if command -v apt-get >/dev/null 2>&1; then
		mkdir -p /etc/apt/keyrings
		curl -fsSL https://pkg.osquery.io/deb/pubkey.gpg | gpg --dearmor -o /etc/apt/keyrings/osquery.gpg 2>/dev/null || true
		echo "deb [signed-by=/etc/apt/keyrings/osquery.gpg] https://pkg.osquery.io/deb deb main" \
			> /etc/apt/sources.list.d/osquery.list
		apt-get update -qq && apt-get install -y osquery || \
			echo "siembox-agent: WARNING: osquery install failed; detection will be disabled until installed."
	elif command -v yum >/dev/null 2>&1; then
		curl -fsSL https://pkg.osquery.io/rpm/GPG | tee /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery >/dev/null
		yum-config-manager --add-repo https://pkg.osquery.io/rpm/osquery-s3-rpm.repo 2>/dev/null || true
		yum install -y osquery || \
			echo "siembox-agent: WARNING: osquery install failed; detection will be disabled until installed."
	else
		echo "siembox-agent: WARNING: no apt/yum found; install osquery manually to enable detection."
	fi
fi

# Register the service, then restart it so the just-installed binary is the one
# running. `restart` (not `start`) ensures an UPGRADE picks up the new version
# even if the old daemon is still running; on a fresh install it just starts it.
# kardianos picks systemd/sysv automatically.
"$BIN" -dir "$CONF_DIR" install || echo "siembox-agent: service install reported an error (already installed?)."
"$BIN" -dir "$CONF_DIR" restart || echo "siembox-agent: not started (edit $CONF_FILE then run: siembox-agent -dir $CONF_DIR restart)."

echo "siembox-agent: post-install complete."
