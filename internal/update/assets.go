package update

import (
	"fmt"
	"regexp"
	"sort"
)

// Method is how the running agent was installed, which decides the release
// asset and the installer used to update it.
type Method string

// Install methods.
const (
	MethodDeb           Method = "deb"
	MethodRPM           Method = "rpm"
	MethodLinuxArchive  Method = "linux-archive"
	MethodPkg           Method = "macos-pkg"
	MethodDarwinArchive Method = "macos-archive"
	MethodMSI           Method = "msi"
	MethodWindowsZip    Method = "windows-zip"
)

// IsArchive reports whether the method replaces the binary in place from an
// archive (as opposed to running a native installer).
func (m Method) IsArchive() bool {
	return m == MethodLinuxArchive || m == MethodDarwinArchive || m == MethodWindowsZip
}

// SelectAsset picks the release asset for method/arch from the file names listed
// in SHA256SUMS. version must already be validated. Asset names follow the
// release pipeline (goreleaser, pkgbuild and WiX naming).
func SelectAsset(m Method, version, goarch string, names []string) (string, error) {
	var want string
	switch m {
	case MethodDeb:
		a, err := debArch(goarch)
		if err != nil {
			return "", err
		}
		want = fmt.Sprintf("siembox-agent_%s_%s.deb", version, a)
	case MethodRPM:
		a, err := rpmArch(goarch)
		if err != nil {
			return "", err
		}
		// siembox-agent-<V>-<release>.<arch>.rpm
		re := regexp.MustCompile(`^siembox-agent-` + regexp.QuoteMeta(version) + `-[A-Za-z0-9._+~]+\.` + regexp.QuoteMeta(a) + `\.rpm$`)
		return pickMatch(re, names, "rpm for "+a)
	case MethodLinuxArchive:
		if _, err := debArch(goarch); err != nil {
			return "", err
		}
		want = fmt.Sprintf("siembox-endpoint_%s_linux_%s.tar.gz", version, goarch)
	case MethodPkg:
		want = fmt.Sprintf("siembox-agent-%s-macos.pkg", version)
	case MethodDarwinArchive:
		if _, err := debArch(goarch); err != nil {
			return "", err
		}
		want = fmt.Sprintf("siembox-endpoint_%s_darwin_%s.tar.gz", version, goarch)
	case MethodMSI:
		if goarch != "amd64" {
			return "", fmt.Errorf("no Windows release asset for %s", goarch)
		}
		want = fmt.Sprintf("siembox-agent-%s-windows-amd64.msi", version)
	case MethodWindowsZip:
		if goarch != "amd64" {
			return "", fmt.Errorf("no Windows release asset for %s", goarch)
		}
		want = fmt.Sprintf("siembox-endpoint_%s_windows_amd64.zip", version)
	default:
		return "", fmt.Errorf("unsupported install method %q", m)
	}
	for _, n := range names {
		if n == want {
			return n, nil
		}
	}
	return "", fmt.Errorf("release has no asset %s", want)
}

func pickMatch(re *regexp.Regexp, names []string, what string) (string, error) {
	var hits []string
	for _, n := range names {
		if re.MatchString(n) {
			hits = append(hits, n)
		}
	}
	if len(hits) == 0 {
		return "", fmt.Errorf("release has no %s asset", what)
	}
	sort.Strings(hits)
	return hits[0], nil
}

func debArch(goarch string) (string, error) {
	switch goarch {
	case "amd64", "arm64":
		return goarch, nil
	}
	return "", fmt.Errorf("unsupported architecture %s", goarch)
}

func rpmArch(goarch string) (string, error) {
	switch goarch {
	case "amd64":
		return "x86_64", nil
	case "arm64":
		return "aarch64", nil
	}
	return "", fmt.Errorf("unsupported architecture %s", goarch)
}
