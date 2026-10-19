package update

import (
	"context"
	"fmt"
	"path"
	"strings"
)

// DetectMethod determines how the agent at exe was installed. It is pure apart
// from the injected Runner, so every branch is testable on any host.
//
//   - linux: owned by dpkg -> deb; owned by rpm -> rpm; otherwise archive
//     (scripts/install.sh, /usr/local/bin).
//   - darwin: owned by a pkg receipt -> pkg; otherwise archive.
//   - windows: registered with Windows Installer as the SIEMBox agent AND living
//     in Program Files\SIEMBox -> msi; otherwise zip (scripts/install.ps1).
//
// A missing or failing probe tool means "not owned", i.e. the archive method,
// which only touches the agent binary itself.
func DetectMethod(ctx context.Context, goos, exe, programFiles string, run Runner) (Method, error) {
	switch goos {
	case "linux":
		if out, err := run.Output(ctx, "dpkg-query", "-S", exe); err == nil && strings.TrimSpace(string(out)) != "" {
			return MethodDeb, nil
		}
		if out, err := run.Output(ctx, "rpm", "-qf", exe); err == nil && strings.TrimSpace(string(out)) != "" &&
			!strings.Contains(string(out), "not owned by any package") {
			return MethodRPM, nil
		}
		return MethodLinuxArchive, nil
	case "darwin":
		out, err := run.Output(ctx, "pkgutil", "--file-info", exe)
		if err == nil && hasPkgID(string(out)) {
			return MethodPkg, nil
		}
		return MethodDarwinArchive, nil
	case "windows":
		if isMSIPath(exe, programFiles) && msiRegistered(ctx, run) {
			return MethodMSI, nil
		}
		return MethodWindowsZip, nil
	}
	return "", fmt.Errorf("self-update is not supported on %s", goos)
}

// hasPkgID reports whether `pkgutil --file-info` output names an owning package.
func hasPkgID(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "pkgid:"); ok && strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

// isMSIPath reports whether exe is the file the MSI installs
// (<ProgramFiles>\SIEMBox\siembox-agent.exe), comparing case-insensitively and
// accepting either separator.
func isMSIPath(exe, programFiles string) bool {
	norm := func(p string) string {
		return strings.ToLower(path.Clean(strings.ReplaceAll(p, `\`, "/")))
	}
	if programFiles == "" {
		programFiles = `C:\Program Files`
	}
	return norm(exe) == norm(programFiles)+"/siembox/siembox-agent.exe"
}

const (
	uninstallKey = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	msiProduct   = "SIEMBox Endpoint Agent"
)

// msiRegistered looks for an Uninstall entry named after the MSI product with
// WindowsInstaller=1, which only Windows Installer registrations carry.
func msiRegistered(ctx context.Context, run Runner) bool {
	out, err := run.Output(ctx, "reg", "query", uninstallKey, "/s", "/f", msiProduct, "/d", "/e")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		key := strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToUpper(key), "HKEY_LOCAL_MACHINE\\") {
			continue
		}
		v, err := run.Output(ctx, "reg", "query", key, "/v", "WindowsInstaller")
		if err == nil && strings.Contains(string(v), "0x1") {
			return true
		}
	}
	return false
}
