package packages

import (
	"strings"

	"github.com/cladkins/siembox-endpoint/internal/models"
)

// UninstallEntry holds the values of one Windows Uninstall registry key the
// inventory reads. The registry walk is in collect_windows.go; this mapping is
// plain Go, tested everywhere.
type UninstallEntry struct {
	DisplayName      string
	DisplayVersion   string
	ParentKeyName    string
	ReleaseType      string
	SystemComponent  uint64
	WindowsInstaller uint64
}

// UninstallPackage maps an Uninstall entry to a package, as Programs and
// Features lists them: entries without a DisplayName, hidden system
// components and updates/hotfixes of another product are skipped. Type is
// "msi" for Windows Installer products, else "win".
func UninstallPackage(e UninstallEntry) (models.Package, bool) {
	name := strings.TrimSpace(e.DisplayName)
	if name == "" || e.SystemComponent == 1 || e.ParentKeyName != "" {
		return models.Package{}, false
	}
	switch strings.ToLower(strings.TrimSpace(e.ReleaseType)) {
	case "update", "hotfix", "security update", "service pack":
		return models.Package{}, false
	}
	typ := "win"
	if e.WindowsInstaller == 1 {
		typ = "msi"
	}
	return models.Package{Name: name, Version: strings.TrimSpace(e.DisplayVersion), Type: typ}, true
}
