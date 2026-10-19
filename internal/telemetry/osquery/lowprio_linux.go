package osquery

import (
	"os/exec"
	"runtime"
	"syscall"
)

const (
	ioprioWhoProcess = 1  // IOPRIO_WHO_PROCESS
	ioprioClassIdle  = 3  // IOPRIO_CLASS_IDLE
	ioprioClassShift = 13 // IOPRIO_CLASS_SHIFT
)

// startLowPriority starts cmd at nice 19 and idle I/O class. On Linux both are
// per-thread attributes a child inherits at fork, so the calling thread lowers
// its own priority and then forks: the child runs at low priority from its
// first instruction, with no window at normal priority. The thread is locked
// and never unlocked, so the Go runtime destroys it when this goroutine
// returns and the lowered priority never reaches other goroutines.
func startLowPriority(cmd *exec.Cmd) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		_ = syscall.Setpriority(syscall.PRIO_PROCESS, 0, 19)
		_, _, _ = syscall.Syscall(syscall.SYS_IOPRIO_SET, ioprioWhoProcess, 0,
			ioprioClassIdle<<ioprioClassShift)
		errc <- cmd.Start()
	}()
	return <-errc
}
