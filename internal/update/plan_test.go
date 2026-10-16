package update

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestInstallCommand(t *testing.T) {
	dir := "/etc/siembox-agent"
	tests := []struct {
		m    Method
		want []string
	}{
		{MethodDeb, []string{"sh", "-c", debScript, "sh", "/p/a.deb"}},
		{MethodRPM, []string{"rpm", "-U", "/p/a.deb"}},
		{MethodPkg, []string{"installer", "-pkg", "/p/a.deb", "-target", "/"}},
		{MethodMSI, []string{"msiexec", "/i", "/p/a.deb", "/qn", "/norestart", "/l*v", filepath.Join(dir, "update-msi.log")}},
	}
	for _, tt := range tests {
		c, err := InstallCommand(tt.m, "/p/a.deb", dir)
		if err != nil || !reflect.DeepEqual(c.Argv, tt.want) || c.LogPath != filepath.Join(dir, "update.log") {
			t.Errorf("%s: %+v err=%v", tt.m, c, err)
		}
	}
	if _, err := InstallCommand(MethodLinuxArchive, "x", dir); err == nil {
		t.Error("archive method has no installer command")
	}
}

func TestSystemdRunArgv(t *testing.T) {
	c := Command{Argv: []string{"rpm", "-U", "/p/x.rpm"}, LogPath: "/etc/siembox-agent/update.log"}
	got := systemdRunArgv("/usr/bin/systemd-run", c, time.Unix(1700000000, 0))
	want := []string{"/usr/bin/systemd-run", "--collect", "--unit", "siembox-agent-update-1700000000", "--",
		"sh", "-c", `log=$1; shift; exec "$@" >>"$log" 2>&1`, "sh", "/etc/siembox-agent/update.log", "rpm", "-U", "/p/x.rpm"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q", got)
	}
}

func writeTarGz(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, _ := os.Create(path)
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for n, c := range files {
		tw.WriteHeader(&tar.Header{Name: n, Mode: 0o755, Size: int64(len(c)), Typeflag: tar.TypeReg})
		tw.Write([]byte(c))
	}
	tw.Close()
	gz.Close()
}

func TestExtractBinary(t *testing.T) {
	d := t.TempDir()
	tgz := filepath.Join(d, "a.tar.gz")
	writeTarGz(t, tgz, map[string]string{"README.md": "x", "siembox-agent": "BIN"})
	dest := filepath.Join(d, "out")
	if err := ExtractBinary(tgz, dest, false, 1<<20); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "BIN" {
		t.Fatalf("got %q", b)
	}
	if fi, _ := os.Stat(dest); fi.Mode().Perm() != 0o755 {
		t.Errorf("mode %v", fi.Mode())
	}
	if err := ExtractBinary(tgz, dest, false, 2); err == nil {
		t.Error("over-limit extraction must fail")
	}
	if _, err := os.Stat(dest); err == nil {
		t.Error("partial output must be removed")
	}
	empty := filepath.Join(d, "e.tar.gz")
	writeTarGz(t, empty, map[string]string{"other": "x"})
	if err := ExtractBinary(empty, dest, false, 1<<20); err == nil {
		t.Error("archive without the binary must fail")
	}

	zp := filepath.Join(d, "a.zip")
	zf, _ := os.Create(zp)
	zw := zip.NewWriter(zf)
	w, _ := zw.Create("siembox-agent.exe")
	w.Write([]byte("EXE"))
	zw.Close()
	zf.Close()
	if err := ExtractBinary(zp, dest, true, 1<<20); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "EXE" {
		t.Fatalf("got %q", b)
	}
}

func TestReplaceExecutable(t *testing.T) {
	for _, win := range []bool{false, true} {
		d := t.TempDir()
		exe, nw := filepath.Join(d, "agent"), filepath.Join(d, "agent.new")
		os.WriteFile(exe, []byte("old"), 0o755)
		os.WriteFile(nw, []byte("new"), 0o755)
		if err := ReplaceExecutable(exe, nw, win); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(exe); string(b) != "new" {
			t.Errorf("win=%v exe=%q", win, b)
		}
		if win {
			if b, _ := os.ReadFile(exe + ".old"); string(b) != "old" {
				t.Errorf("old not kept aside: %q", b)
			}
		}
	}
	// Windows failure path restores the original.
	d := t.TempDir()
	exe := filepath.Join(d, "agent")
	os.WriteFile(exe, []byte("old"), 0o755)
	if err := ReplaceExecutable(exe, filepath.Join(d, "missing"), true); err == nil {
		t.Fatal("expected error")
	}
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Errorf("original not restored: %q", b)
	}
}
