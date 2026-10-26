package packages

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/cladkins/siembox-endpoint/internal/models"
	"github.com/cladkins/siembox-endpoint/internal/util"
)

// The Linux package databases. Parsers take a reader so they are tested on
// every platform with fixture files.

const (
	dpkgStatusPath   = "/var/lib/dpkg/status"
	apkInstalledPath = "/lib/apk/db/installed"
)

// dpkgSource reads dpkg's status file.
func dpkgSource(path string) Source {
	return Source{Name: "dpkg", Collect: func(context.Context) ([]models.Package, error) {
		return readFile(path, ParseDpkgStatus)
	}}
}

// apkSource reads Alpine's installed database.
func apkSource(path string) Source {
	return Source{Name: "apk", Collect: func(context.Context) ([]models.Package, error) {
		return readFile(path, ParseApkInstalled)
	}}
}

// rpmQueryFormat prints name, [epoch:]version-release; the epoch only when set.
const rpmQueryFormat = `%{NAME}\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\n`

// rpmSource lists packages with `rpm -qa` when rpm is installed.
func rpmSource(binary string, run func(ctx context.Context, name string, args ...string) ([]byte, error)) Source {
	return Source{Name: "rpm", Collect: func(ctx context.Context) ([]models.Package, error) {
		bin, ok := util.FindBinary(binary, []string{"/usr/bin", "/bin"})
		if !ok {
			return nil, ErrNotPresent
		}
		out, err := run(ctx, bin, "-qa", "--queryformat", rpmQueryFormat)
		if err != nil {
			if stderr := util.StderrText(err); stderr != "" {
				return nil, fmt.Errorf("rpm -qa: %w: %s", err, stderr)
			}
			return nil, fmt.Errorf("rpm -qa: %w", err)
		}
		return ParseRpmQuery(out), nil
	}}
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

func readFile(path string, parse func(io.Reader) ([]models.Package, error)) ([]models.Package, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, ErrNotPresent
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parse(f)
}

// ParseDpkgStatus reads /var/lib/dpkg/status: one stanza per package,
// separated by blank lines. Only packages whose Status is "... installed"
// count (not config-files, half-installed or deinstalled ones).
func ParseDpkgStatus(r io.Reader) ([]models.Package, error) {
	var out []models.Package
	var name, version, status string
	flush := func() {
		if name != "" && strings.HasSuffix(strings.TrimSpace(status), " installed") {
			out = append(out, models.Package{Name: name, Version: version, Type: "deb"})
		}
		name, version, status = "", "", ""
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024) // long Description/Conffiles lines
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue // continuation of a multi-line field
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "Package":
			name = value
		case "Version":
			version = value
		case "Status":
			status = value
		}
	}
	flush()
	return out, sc.Err()
}

// ParseApkInstalled reads Alpine's /lib/apk/db/installed: "P:" name and "V:"
// version lines, a blank line between packages.
func ParseApkInstalled(r io.Reader) ([]models.Package, error) {
	var out []models.Package
	var name, version string
	flush := func() {
		if name != "" {
			out = append(out, models.Package{Name: name, Version: version, Type: "apk"})
		}
		name, version = "", ""
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.TrimSpace(line) == "":
			flush()
		case strings.HasPrefix(line, "P:"):
			name = strings.TrimSpace(line[2:])
		case strings.HasPrefix(line, "V:"):
			version = strings.TrimSpace(line[2:])
		}
	}
	flush()
	return out, sc.Err()
}

// ParseRpmQuery reads `rpm -qa --queryformat rpmQueryFormat` output. The
// gpg-pubkey pseudo-packages (imported signing keys) are skipped.
func ParseRpmQuery(raw []byte) []models.Package {
	var out []models.Package
	for _, line := range bytes.Split(raw, []byte("\n")) {
		name, version, ok := strings.Cut(strings.TrimSpace(string(line)), "\t")
		if !ok || name == "" || name == "gpg-pubkey" {
			continue
		}
		out = append(out, models.Package{Name: name, Version: strings.TrimSpace(version), Type: "rpm"})
	}
	return out
}
