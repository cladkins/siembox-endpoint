//go:build linux

package update

import (
	"os"
	"os/exec"
	"strings"
	"time"
)

// launchDetached runs c outside the agent service's cgroup via a transient
// systemd unit when systemd is the init system; otherwise (or if systemd-run
// fails) in a new session.
func launchDetached(c Command) error {
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		if sr := resolveTool("systemd-run"); sr != "systemd-run" {
			out, err := exec.Command(sr, systemdRunArgv(sr, c, time.Now())[1:]...).CombinedOutput()
			if err == nil {
				return nil
			}
			// Fall through to Setsid; keep the reason in the log for diagnosis.
			if f, ferr := os.OpenFile(c.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); ferr == nil {
				_, _ = f.WriteString("systemd-run failed (" + err.Error() + "): " + strings.TrimSpace(string(out)) + "\n")
				f.Close()
			}
		}
	}
	return launchSetsid(c)
}
