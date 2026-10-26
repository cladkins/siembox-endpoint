package packages

import (
	"context"
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/cladkins/siembox-endpoint/internal/models"
)

const uninstallPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

func platformSources() []Source {
	return []Source{{Name: "registry", Collect: collectRegistry}}
}

// collectRegistry reads the machine-wide Uninstall keys (64- and 32-bit) and
// those of every loaded user hive (per-user installs: VS Code, Zoom, ...).
func collectRegistry(ctx context.Context) ([]models.Package, error) {
	var out []models.Package
	out = append(out, readUninstall(registry.LOCAL_MACHINE, uninstallPath, registry.WOW64_64KEY)...)
	out = append(out, readUninstall(registry.LOCAL_MACHINE, uninstallPath, registry.WOW64_32KEY)...)
	if users, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS); err == nil {
		sids, _ := users.ReadSubKeyNames(-1)
		users.Close()
		for _, sid := range sids {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if strings.HasSuffix(sid, "_Classes") {
				continue
			}
			out = append(out, readUninstall(registry.USERS, sid+`\`+uninstallPath, 0)...)
		}
	}
	return out, nil
}

func readUninstall(root registry.Key, path string, view uint32) []models.Package {
	k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE|view)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}
	var out []models.Package
	for _, n := range names {
		sub, err := registry.OpenKey(k, n, registry.QUERY_VALUE|view)
		if err != nil {
			continue
		}
		e := UninstallEntry{
			DisplayName:    stringValue(sub, "DisplayName"),
			DisplayVersion: stringValue(sub, "DisplayVersion"),
			ParentKeyName:  stringValue(sub, "ParentKeyName"),
			ReleaseType:    stringValue(sub, "ReleaseType"),
		}
		e.SystemComponent, _, _ = sub.GetIntegerValue("SystemComponent")
		e.WindowsInstaller, _, _ = sub.GetIntegerValue("WindowsInstaller")
		sub.Close()
		if p, ok := UninstallPackage(e); ok {
			out = append(out, p)
		}
	}
	return out
}

func stringValue(k registry.Key, name string) string {
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return v
}
