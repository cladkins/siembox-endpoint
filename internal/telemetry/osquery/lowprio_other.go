//go:build !linux && !darwin && !windows

package osquery

import "os/exec"

// startLowPriority starts cmd at normal priority: no portable priority control
// exists on the remaining platforms.
func startLowPriority(cmd *exec.Cmd) error { return cmd.Start() }
