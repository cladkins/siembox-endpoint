package update

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/cladkins/siembox-endpoint/internal/util"
)

// Runner runs a short-lived command and returns its combined output. It is
// injectable so install-method detection can be tested without the real tools.
type Runner interface {
	Output(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ExecRunner is the production Runner. Tools are resolved via PATH plus common
// system directories, so lookup works under minimal service environments.
type ExecRunner struct{}

// Output implements Runner.
func (ExecRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, resolveTool(name), args...).CombinedOutput()
}

// resolveTool turns a bare tool name into an absolute path when it can be
// found; otherwise the name is returned and the OS reports the failure.
func resolveTool(name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	dirs := []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"}
	if runtime.GOOS == "windows" {
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		dirs = []string{filepath.Join(root, "System32")}
	}
	p, _ := util.FindBinary(name, dirs)
	return p
}
