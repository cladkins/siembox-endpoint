package osquery

import (
	"os/exec"
	"syscall"
)

const (
	prioDarwinProcess = 4      // PRIO_DARWIN_PROCESS
	prioDarwinBG      = 0x1000 // PRIO_DARWIN_BG: background band, throttles CPU and disk I/O
)

// startLowPriority starts cmd, then moves it to nice 19 and the background
// band. On macOS both apply to the whole process, so setting them on the
// child's pid right after start covers every thread it creates.
func startLowPriority(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	pid := cmd.Process.Pid
	_ = syscall.Setpriority(syscall.PRIO_PROCESS, pid, 19)
	_ = syscall.Setpriority(prioDarwinProcess, pid, prioDarwinBG)
	return nil
}
