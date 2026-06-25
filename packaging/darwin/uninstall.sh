#!/bin/sh
# uninstall.sh - fully remove SIEMBox EDR from macOS.
# Installed by the .pkg to /usr/local/bin/siembox-uninstall and invoked by the
# menu bar app's "Uninstall" item; also runnable directly: sudo siembox-uninstall
#
# Removes: the background service, the menu bar LaunchAgent + app, the agent
# binary, all config/state, and the package receipt. Leaves osquery and grype
# installed (shared tools).
set -e

BIN=/usr/local/bin/siembox-agent
VENDOR_DIR="/Library/Application Support/SIEMBox"
CONF_DIR="$VENDOR_DIR/agent"

echo "Removing SIEMBox EDR…"

# 1. Stop and unregister the background (launchd daemon) service.
if [ -x "$BIN" ]; then
	"$BIN" -dir "$CONF_DIR" stop 2>/dev/null || true
	"$BIN" -dir "$CONF_DIR" uninstall 2>/dev/null || true
fi

# 2. Unload + remove the per-user menu bar LaunchAgent.
CONSOLE_UID=$(stat -f%u /dev/console 2>/dev/null || echo "")
if [ -n "$CONSOLE_UID" ] && [ "$CONSOLE_UID" != "0" ]; then
	launchctl asuser "$CONSOLE_UID" launchctl bootout "gui/$CONSOLE_UID/io.siembox.menubar" 2>/dev/null || true
fi
rm -f /Library/LaunchAgents/io.siembox.menubar.plist

# 3. Remove the menu bar app and the agent binary. (A running menu bar app keeps
#    executing from its open inode and exits itself after this returns.)
rm -rf "/Applications/SIEMBox Menu Bar.app"
rm -f "$BIN"

# 4. Remove all config/state and forget the package receipt.
rm -rf "$VENDOR_DIR"
pkgutil --forget io.siembox.agent 2>/dev/null || true

echo "SIEMBox EDR uninstalled. (osquery and grype were left installed.)"

# 5. Remove this uninstaller last, detached so sh doesn't lose its own script.
( sleep 2; rm -f /usr/local/bin/siembox-uninstall ) >/dev/null 2>&1 &

exit 0
