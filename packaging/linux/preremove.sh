#!/bin/sh
# preremove.sh - run by dpkg/rpm before the siembox-agent package is removed.
# Stops and unregisters the service. Leaves /etc/siembox-agent (config,
# identity) in place so reinstalls keep enrollment; remove it manually for a
# full purge.
set -e

CONF_DIR=/etc/siembox-agent
BIN=/usr/bin/siembox-agent

if [ -x "$BIN" ]; then
	echo "siembox-agent: stopping and removing service..."
	"$BIN" -dir "$CONF_DIR" stop || true
	"$BIN" -dir "$CONF_DIR" uninstall || true
fi
