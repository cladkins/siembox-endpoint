//go:build linux || darwin

package update

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// launchSetsid starts c in a new session so it outlives the agent process.
func launchSetsid(c Command) error {
	logf, err := os.OpenFile(c.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open update log: %w", err)
	}
	defer logf.Close()
	cmd := exec.Command(c.Argv[0], c.Argv[1:]...)
	cmd.Dir = "/"
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", c.Argv[0], err)
	}
	go func() { _ = cmd.Wait() }() // reap if we are still alive when it exits
	return nil
}
