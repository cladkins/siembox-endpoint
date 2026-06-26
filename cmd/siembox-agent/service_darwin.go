//go:build darwin

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// On modern macOS (Big Sur+) the legacy `launchctl load`/`unload` calls that the
// kardianos service library uses fail with "Load failed: 5: Input/output
// error". The supported replacements are the per-domain subcommands
// bootstrap/bootout/kickstart. controlServiceOS handles start/stop/restart with
// those so the background daemon actually starts; install/uninstall (which just
// write/remove the plist) still go through kardianos.

// The kardianos system-daemon plist path and launchd domain target for a
// service named "siembox-agent".
const (
	launchdPlistPath     = "/Library/LaunchDaemons/siembox-agent.plist"
	launchdServiceTarget = "system/siembox-agent"
)

// controlServiceOS processes start/stop/restart via modern launchctl. It
// returns handled=false for any other command so the caller falls back to the
// cross-platform kardianos path.
func controlServiceOS(cmd string) (handled bool, err error) {
	switch cmd {
	case "start":
		return true, launchdStart()
	case "stop":
		return true, launchdStop()
	case "restart":
		_ = launchdStop()
		return true, launchdStart()
	default:
		return false, nil
	}
}

// launchdStart loads the daemon (bootstrap, a no-op error if already loaded)
// and then kickstart -k to (re)start it on the current binary.
func launchdStart() error {
	bootOut, _ := runLaunchctl("bootstrap", "system", launchdPlistPath) // tolerated if already bootstrapped
	if out, err := runLaunchctl("kickstart", "-k", launchdServiceTarget); err != nil {
		return fmt.Errorf("launchctl start failed (bootstrap: %q) (kickstart: %q): %w", bootOut, out, err)
	}
	return nil
}

// launchdStop unloads the daemon; "not loaded" is treated as success.
func launchdStop() error {
	out, err := runLaunchctl("bootout", launchdServiceTarget)
	if err != nil {
		l := strings.ToLower(out)
		if strings.Contains(l, "no such process") || strings.Contains(l, "could not find") || out == "" {
			return nil
		}
		return fmt.Errorf("launchctl bootout: %w: %s", err, out)
	}
	return nil
}

func runLaunchctl(args ...string) (string, error) {
	out, err := exec.Command("/bin/launchctl", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
