#!/bin/sh
# uninstall.sh - fully remove SIEMBox Endpoint from macOS.
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
DAEMON_PLIST=/Library/LaunchDaemons/siembox-agent.plist
AGENT_PLIST=/Library/LaunchAgents/io.siembox.menubar.plist

echo "Removing SIEMBox Endpoint…"

# 1. Stop + unregister the background (launchd daemon) service. Try the binary
#    first for a clean kardianos teardown, then ALWAYS remove the daemon
#    directly — the uninstaller must not depend on the binary being runnable, or
#    a missing/corrupt binary would leave an orphaned root LaunchDaemon behind.
if [ -x "$BIN" ]; then
	"$BIN" -dir "$CONF_DIR" stop 2>/dev/null || true
	"$BIN" -dir "$CONF_DIR" uninstall 2>/dev/null || true
fi
launchctl bootout system/siembox-agent 2>/dev/null || launchctl unload "$DAEMON_PLIST" 2>/dev/null || true
rm -f "$DAEMON_PLIST"

# 2. Remove the menu bar app, the agent binary, config/state, the menu bar
#    LaunchAgent plist, and the package receipt.
rm -rf "/Applications/SIEMBox Menu Bar.app"
rm -f "$BIN"
rm -rf "$VENDOR_DIR"
rm -f "$AGENT_PLIST"
pkgutil --forget io.siembox.agent 2>/dev/null || true

echo "SIEMBox Endpoint uninstalled. (osquery and grype were left installed.)"

# 3. Detached + last: stop the running menu bar app and remove this uninstaller.
#    Booting out the menu bar agent terminates the tray process — which may be
#    the very process that invoked this script via an admin prompt. Deferring it
#    lets that blocking call return first, so the app can show its success
#    notification and quit itself. (If invoked from the CLI, this still stops a
#    running tray.) KeepAlive is false, so it won't relaunch.
CONSOLE_UID=$(stat -f%u /dev/console 2>/dev/null || echo "")
(
	sleep 2
	if [ -n "$CONSOLE_UID" ] && [ "$CONSOLE_UID" != "0" ]; then
		launchctl asuser "$CONSOLE_UID" launchctl bootout "gui/$CONSOLE_UID/io.siembox.menubar" 2>/dev/null || true
	fi
	rm -f /usr/local/bin/siembox-uninstall
) >/dev/null 2>&1 &

exit 0
