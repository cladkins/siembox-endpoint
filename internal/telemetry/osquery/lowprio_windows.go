package osquery

import (
	"os/exec"
	"syscall"
)

const idlePriorityClass = 0x00000040 // IDLE_PRIORITY_CLASS

// startLowPriority starts cmd in the idle priority class, so it runs only when
// no normal-priority work wants the CPU.
func startLowPriority(cmd *exec.Cmd) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= idlePriorityClass
	return cmd.Start()
}
