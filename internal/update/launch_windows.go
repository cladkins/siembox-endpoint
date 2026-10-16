//go:build windows

package update

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

const detachedProcess = 0x00000008 // DETACHED_PROCESS

// launchDetached starts c detached from the service's console and process
// group so stopping the service does not terminate the installer.
func launchDetached(c Command) error {
	logf, err := os.OpenFile(c.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open update log: %w", err)
	}
	defer logf.Close()
	cmd := exec.Command(c.Argv[0], c.Argv[1:]...)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedProcess | syscall.CREATE_NEW_PROCESS_GROUP}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", c.Argv[0], err)
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
