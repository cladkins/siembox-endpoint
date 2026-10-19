package osquery

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
)

// runLowPriority runs name like exec.Cmd.Output, except the child starts at the
// lowest CPU and I/O priority the OS offers (startLowPriority, per platform).
// Used for the YARA scan, which reads every file under the watched trees and
// must yield to the host's real workload. Priority changes are best-effort: if
// the OS refuses them, the command still runs at normal priority.
func runLowPriority(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := startLowPriority(cmd); err != nil {
		return nil, err
	}
	err := cmd.Wait()
	// Match Output(): surface stderr on the ExitError for util.StderrText.
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		ee.Stderr = stderr.Bytes()
	}
	return stdout.Bytes(), err
}
