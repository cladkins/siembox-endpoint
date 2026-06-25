package util

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// FindBinary resolves an executable by name. It checks, in order: an explicit
// path (if name contains a separator), the PATH, then each of extraDirs. This
// matters under sudo/launchd/Windows services, where PATH is often minimal and
// tools installed in /usr/local/bin, /opt/homebrew/bin, or C:\Program Files\…
// are otherwise missed. On Windows it also tries the ".exe" suffix when probing
// explicit paths and extraDirs (LookPath already handles PATHEXT). Returns the
// resolved path and true, or the original name and false if not found.
func FindBinary(name string, extraDirs []string) (string, bool) {
	if strings.ContainsAny(name, `/\`) {
		if p, ok := statExec(name); ok {
			return p, true
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p, true
	}
	for _, d := range extraDirs {
		if p, ok := statExec(filepath.Join(d, name)); ok {
			return p, true
		}
	}
	return name, false
}

// statExec returns the path (and true) if it is an existing non-directory file.
// On Windows it also tries path+".exe" when the path lacks an .exe extension.
func statExec(path string) (string, bool) {
	if isRegularFile(path) {
		return path, true
	}
	if runtime.GOOS == "windows" && !strings.EqualFold(filepath.Ext(path), ".exe") {
		if exe := path + ".exe"; isRegularFile(exe) {
			return exe, true
		}
	}
	return "", false
}

func isRegularFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

// EnsureSaneTmpdir clears TMPDIR if it points at a directory that no longer
// exists. A process launched by the macOS installer (e.g. the menu bar app,
// started from the pkg post-install) inherits TMPDIR pointing at the installer's
// PKInstallSandbox temp, which macOS deletes after install. Tools like grype
// create temp files in TMPDIR and fail hard when it's missing; unsetting it
// falls back to the OS default (/tmp).
func EnsureSaneTmpdir() {
	td := os.Getenv("TMPDIR")
	if td == "" {
		return
	}
	if fi, err := os.Stat(td); err != nil || !fi.IsDir() {
		_ = os.Unsetenv("TMPDIR")
	}
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
