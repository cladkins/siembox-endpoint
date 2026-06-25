package osquery

import (
	"os"
	"path/filepath"
	"runtime"
)

// DefaultYaraPaths returns the OS-appropriate set of directories for YARA
// file-monitoring, as osquery FIM globs (a trailing "%%" matches recursively).
// These are the common malware drop / persistence locations: temp dirs, user
// Downloads, local bin, and autostart directories. The set is intentionally
// scoped — watching whole home/app trees would add significant overhead — and
// the server can extend it later.
func DefaultYaraPaths() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			"/tmp/%%",
			"/private/tmp/%%",
			"/usr/local/bin/%%",
			"/Users/%/Downloads/%%",
			"/Users/%/Library/LaunchAgents/%%",
			"/Library/LaunchAgents/%%",
			"/Library/LaunchDaemons/%%",
		}
	case "windows":
		// osquery on Windows wants literal paths; expand the common env roots.
		paths := []string{`\Users\%\Downloads\%%`, `\Users\%\AppData\Local\Temp\%%`,
			`\Users\%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\%%`}
		if pd := os.Getenv("ProgramData"); pd != "" {
			paths = append(paths, filepath.Join(pd, "%%"))
		} else {
			paths = append(paths, `C:\ProgramData\%%`)
		}
		if win := os.Getenv("SystemRoot"); win != "" {
			paths = append(paths, filepath.Join(win, "Temp", "%%"))
		} else {
			paths = append(paths, `C:\Windows\Temp\%%`)
		}
		return paths
	default: // linux and others
		return []string{
			"/tmp/%%",
			"/var/tmp/%%",
			"/dev/shm/%%",
			"/usr/local/bin/%%",
			"/etc/cron%%",
			"/home/%/Downloads/%%",
		}
	}
}
