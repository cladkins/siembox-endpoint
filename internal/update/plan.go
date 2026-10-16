package update

import (
	"fmt"
	"path/filepath"
	"strconv"
	"time"
)

// Command is a process to start detached from the agent's service.
type Command struct {
	Argv    []string
	LogPath string // installer stdout/stderr are appended here
}

const (
	updateLogName = "update.log"
	msiLogName    = "update-msi.log"
)

const debScript = `DEBIAN_FRONTEND=noninteractive apt-get install -y "$1" || DEBIAN_FRONTEND=noninteractive dpkg -i "$1"`

// InstallCommand builds the installer invocation for a verified asset.
// Arguments are passed as separate argv entries (never through a shell string
// built from data); the one shell script used is a constant.
func InstallCommand(m Method, assetPath, stateDir string) (Command, error) {
	log := filepath.Join(stateDir, updateLogName)
	var argv []string
	switch m {
	case MethodDeb:
		argv = []string{"sh", "-c", debScript, "sh", assetPath}
	case MethodRPM:
		argv = []string{"rpm", "-U", assetPath}
	case MethodPkg:
		argv = []string{"installer", "-pkg", assetPath, "-target", "/"}
	case MethodMSI:
		argv = []string{"msiexec", "/i", assetPath, "/qn", "/norestart", "/l*v", filepath.Join(stateDir, msiLogName)}
	default:
		return Command{}, fmt.Errorf("method %s has no installer command", m)
	}
	return Command{Argv: argv, LogPath: log}, nil
}

// RestartCommand builds the service restart that follows an in-place binary
// swap. It runs the freshly placed executable, detached.
func RestartCommand(exe, stateDir string) Command {
	return Command{
		Argv:    []string{exe, "-dir", stateDir, "restart"},
		LogPath: filepath.Join(stateDir, updateLogName),
	}
}

// systemdRunArgv wraps c in a transient systemd unit so it survives the agent
// service being stopped (systemd kills the service's whole cgroup). Output is
// appended to the log through a constant wrapper script.
func systemdRunArgv(systemdRun string, c Command, now time.Time) []string {
	argv := []string{
		systemdRun, "--collect",
		"--unit", "siembox-agent-update-" + strconv.FormatInt(now.Unix(), 10),
		"--", "sh", "-c", `log=$1; shift; exec "$@" >>"$log" 2>&1`, "sh", c.LogPath,
	}
	return append(argv, c.Argv...)
}
