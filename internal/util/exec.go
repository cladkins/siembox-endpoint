package util

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// FindBinary resolves an executable by name. It checks, in order: an explicit
// path (if name contains a separator), the PATH, then each of extraDirs. This
// matters under sudo/launchd, where PATH is often minimal and tools installed
// in /usr/local/bin or /opt/homebrew/bin are otherwise missed. It returns the
// resolved path and true, or the original name and false if not found.
func FindBinary(name string, extraDirs []string) (string, bool) {
	if strings.ContainsAny(name, `/\`) {
		if fi, err := os.Stat(name); err == nil && !fi.IsDir() {
			return name, true
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p, true
	}
	for _, d := range extraDirs {
		cand := filepath.Join(d, name)
		if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
			return cand, true
		}
	}
	return name, false
}

// StderrText extracts the captured stderr from a failed exec.Cmd.Output() call.
// exec.Cmd.Output populates ExitError.Stderr when Cmd.Stderr is nil, but the
// default error string omits it; this surfaces the real diagnostic.
func StderrText(err error) string {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return strings.TrimSpace(string(ee.Stderr))
	}
	return ""
}
