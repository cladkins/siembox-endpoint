package packages

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cladkins/siembox-endpoint/internal/models"
)

func fixture(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestParseDpkgStatus(t *testing.T) {
	got, err := ParseDpkgStatus(fixture(t, "dpkg-status"))
	if err != nil {
		t.Fatal(err)
	}
	want := []models.Package{
		{Name: "adduser", Version: "3.137ubuntu1", Type: "deb"},
		{Name: "libc6", Version: "2.39-0ubuntu8.3", Type: "deb"},
		{Name: "libc6", Version: "2.39-0ubuntu8.3", Type: "deb"}, // amd64 + i386; Normalize collapses
		{Name: "openssh-server", Version: "1:9.6p1-3ubuntu13.5", Type: "deb"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestParseApkInstalled(t *testing.T) {
	got, err := ParseApkInstalled(fixture(t, "apk-installed"))
	if err != nil {
		t.Fatal(err)
	}
	want := []models.Package{
		{Name: "musl", Version: "1.2.5-r0", Type: "apk"},
		{Name: "busybox", Version: "1.36.1-r29", Type: "apk"},
		{Name: "openssh-server", Version: "9.7_p1-r4", Type: "apk"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestParseRpmQuery(t *testing.T) {
	raw, _ := os.ReadFile(filepath.Join("testdata", "rpm-qa.txt"))
	got := ParseRpmQuery(raw)
	want := []models.Package{
		{Name: "bash", Version: "5.1.8-9.el9", Type: "rpm"},
		{Name: "openssl", Version: "1:3.0.7-27.el9", Type: "rpm"},
		{Name: "kernel", Version: "5.14.0-427.13.1.el9_4", Type: "rpm"},
		{Name: "kernel", Version: "5.14.0-362.24.1.el9_3", Type: "rpm"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestRpmSourceRunsQuery(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "rpm")
	if err := os.WriteFile(bin, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	var args []string
	src := rpmSource(bin, func(_ context.Context, name string, a ...string) ([]byte, error) {
		args = a
		return []byte("bash\t5.1.8-9.el9\n"), nil
	})
	got, err := src.Collect(context.Background())
	if err != nil || len(got) != 1 || got[0].Name != "bash" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if len(args) != 3 || args[0] != "-qa" || args[2] != rpmQueryFormat {
		t.Errorf("args = %q", args)
	}
	missing := rpmSource(filepath.Join(t.TempDir(), "no-rpm"), nil)
	if _, err := missing.Collect(context.Background()); !errors.Is(err, ErrNotPresent) {
		t.Errorf("missing rpm: err = %v, want ErrNotPresent", err)
	}
}

func TestMissingDatabaseIsNotPresent(t *testing.T) {
	if _, err := dpkgSource(filepath.Join(t.TempDir(), "status")).Collect(context.Background()); !errors.Is(err, ErrNotPresent) {
		t.Errorf("dpkg: %v", err)
	}
	if _, err := apkSource(filepath.Join(t.TempDir(), "installed")).Collect(context.Background()); !errors.Is(err, ErrNotPresent) {
		t.Errorf("apk: %v", err)
	}
}

func TestParsePlistStrings(t *testing.T) {
	got, err := ParsePlistStrings(fixture(t, "Info.plist"))
	if err != nil {
		t.Fatal(err)
	}
	if got["CFBundleShortVersionString"] != "131.0.3" || got["CFBundleName"] != "Firefox" {
		t.Errorf("got %v", got)
	}
	if _, ok := got["CFBundleTypeName"]; ok {
		t.Error("a nested dictionary's key leaked into the top level")
	}
	if _, ok := got["LSRequiresNativeExecution"]; ok {
		t.Error("a non-string value was read as a string")
	}
}

func TestAppBundleSource(t *testing.T) {
	root := t.TempDir()
	plist, _ := os.ReadFile(filepath.Join("testdata", "Info.plist"))
	for _, b := range []string{"Firefox.app", "Utilities/Terminal Helper.app", "NoPlist.app"} {
		if err := os.MkdirAll(filepath.Join(root, b, "Contents"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(root, "Firefox.app", "Contents", "Info.plist"), plist, 0o644)
	os.WriteFile(filepath.Join(root, "Utilities", "Terminal Helper.app", "Contents", "Info.plist"),
		[]byte(`<plist><dict><key>CFBundleVersion</key><string>2.1</string></dict></plist>`), 0o644)
	got, err := appBundleSource([]string{root}, readInfoPlist).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got = Normalize(got)
	want := []models.Package{
		{Name: "Firefox", Version: "131.0.3", Type: "app"},
		{Name: "NoPlist", Version: "", Type: "app"},
		{Name: "Terminal Helper", Version: "2.1", Type: "app"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	if _, err := appBundleSource([]string{filepath.Join(root, "nope")}, readInfoPlist).Collect(context.Background()); !errors.Is(err, ErrNotPresent) {
		t.Errorf("missing dir: %v", err)
	}
}

func TestBrewSource(t *testing.T) {
	prefix := t.TempDir()
	for _, d := range []string{"Cellar/openssl@3/3.3.1", "Cellar/openssl@3/3.3.2", "Cellar/wget/1.24.5", "Cellar/.metadata/x", "Caskroom/firefox/131.0.3"} {
		if err := os.MkdirAll(filepath.Join(prefix, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got, err := brewSource([]string{prefix, filepath.Join(prefix, "missing")}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got = Normalize(got)
	want := []models.Package{
		{Name: "openssl@3", Version: "3.3.1", Type: "brew"},
		{Name: "openssl@3", Version: "3.3.2", Type: "brew"},
		{Name: "wget", Version: "1.24.5", Type: "brew"},
		{Name: "firefox", Version: "131.0.3", Type: "brew-cask"},
	}
	// Normalize sorts by type: "brew" < "brew-cask".
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestPkgutil(t *testing.T) {
	list, _ := os.ReadFile(filepath.Join("testdata", "pkgutil-pkgs.txt"))
	info, _ := os.ReadFile(filepath.Join("testdata", "pkgutil-info.txt"))
	if got := ParsePkgutilList(list); !reflect.DeepEqual(got, []string{"org.wireshark.Wireshark", "com.tailscale.ipn.macsys"}) {
		t.Errorf("list = %q", got)
	}
	if got := ParsePkgutilInfo(info); got != "4.2.5" {
		t.Errorf("version = %q", got)
	}
}

func TestUninstallPackage(t *testing.T) {
	cases := []struct {
		in   UninstallEntry
		want models.Package
		ok   bool
	}{
		{UninstallEntry{DisplayName: "7-Zip 23.01 (x64)", DisplayVersion: "23.01"}, models.Package{Name: "7-Zip 23.01 (x64)", Version: "23.01", Type: "win"}, true},
		{UninstallEntry{DisplayName: "Mozilla Firefox (x64 en-US) ", DisplayVersion: "131.0.3", WindowsInstaller: 0}, models.Package{Name: "Mozilla Firefox (x64 en-US)", Version: "131.0.3", Type: "win"}, true},
		{UninstallEntry{DisplayName: "Python 3.12.4 Core Interpreter (64-bit)", DisplayVersion: "3.12.4150.0", WindowsInstaller: 1}, models.Package{Name: "Python 3.12.4 Core Interpreter (64-bit)", Version: "3.12.4150.0", Type: "msi"}, true},
		{UninstallEntry{DisplayName: "", DisplayVersion: "1.0"}, models.Package{}, false},
		{UninstallEntry{DisplayName: "Hidden", SystemComponent: 1}, models.Package{}, false},
		{UninstallEntry{DisplayName: "Security Update for X (KB123)", ParentKeyName: "X"}, models.Package{}, false},
		{UninstallEntry{DisplayName: "Hotfix", ReleaseType: "Hotfix"}, models.Package{}, false},
	}
	for _, c := range cases {
		got, ok := UninstallPackage(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("%+v: got %+v %v, want %+v %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestNormalizeAndHash(t *testing.T) {
	in := []models.Package{
		{Name: " zlib ", Version: "1.3", Type: "DEB"},
		{Name: "zlib", Version: "1.3", Type: "deb"},
		{Name: "", Version: "1", Type: "deb"},
		{Name: "a\x00b" + strings.Repeat("x", 400), Version: strings.Repeat("9", 300), Type: "rpm"},
	}
	got := Normalize(in)
	if len(got) != 2 || got[0].Name != "zlib" || got[0].Type != "deb" {
		t.Fatalf("got %+v", got)
	}
	if n := len([]rune(got[1].Name)); n != maxName || strings.ContainsRune(got[1].Name, 0) {
		t.Errorf("name not cut/cleaned: %d runes", n)
	}
	if len(got[1].Version) != maxVersion {
		t.Errorf("version length %d", len(got[1].Version))
	}
	h := Hash(got)
	if !strings.HasPrefix(h, "sha256:") || len(h) != 7+64 {
		t.Errorf("hash = %q", h)
	}
	if Hash([]models.Package{got[1], got[0]}) != h {
		t.Error("hash depends on order")
	}
	if Hash(got[:1]) == h {
		t.Error("hash ignores a package")
	}
	// The same lines the server hashes (backend edrPackages.computeSnapshotHash).
	if Hash([]models.Package{{Name: "libc6", Version: "2.39", Type: "deb"}}) !=
		"sha256:"+sha256hex("deb\x00libc6\x002.39") {
		t.Error("hash format differs from the server's")
	}
}

func TestCollectFromMergesAndReportsErrors(t *testing.T) {
	res := CollectFrom(context.Background(), []Source{
		{Name: "a", Collect: func(context.Context) ([]models.Package, error) {
			return []models.Package{{Name: "x", Version: "1", Type: "deb"}, {Name: "x", Version: "1", Type: "deb"}}, nil
		}},
		{Name: "absent", Collect: func(context.Context) ([]models.Package, error) { return nil, ErrNotPresent }},
		{Name: "broken", Collect: func(context.Context) ([]models.Package, error) { return nil, errors.New("boom") }},
	})
	if len(res.Packages) != 1 || res.Sources["a"] != 2 {
		t.Errorf("packages %+v sources %v", res.Packages, res.Sources)
	}
	if _, ok := res.Sources["absent"]; ok {
		t.Error("an absent source is listed")
	}
	if res.Errors["broken"] == nil || len(res.Errors) != 1 {
		t.Errorf("errors = %v", res.Errors)
	}
}

// TestCollectOnThisHost runs the real platform sources: never an error from a
// source that is merely absent. Packages may be zero (a bare CI container).
func TestCollectOnThisHost(t *testing.T) {
	res := Collect(context.Background())
	for name, err := range res.Errors {
		t.Errorf("source %s failed: %v", name, err)
	}
	t.Logf("collected %d packages from %v", len(res.Packages), res.Sources)
}
