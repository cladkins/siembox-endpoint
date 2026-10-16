package update

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeRunner answers by "name arg arg" key; unknown commands fail like a
// missing tool.
type fakeRunner struct {
	out   map[string]string
	calls []string
}

func (f *fakeRunner) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, key)
	if v, ok := f.out[key]; ok {
		return []byte(v), nil
	}
	return nil, errors.New("exit status 1")
}

func TestDetectMethod(t *testing.T) {
	const exe = "/usr/bin/siembox-agent"
	const macExe = "/usr/local/bin/siembox-agent"
	const win = `C:\Program Files\SIEMBox\siembox-agent.exe`
	const regQ = `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s /f SIEMBox Endpoint Agent /d /e`
	const key = `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}`
	msiOut := map[string]string{
		regQ: "\r\n" + key + "\r\n    DisplayName    REG_SZ    SIEMBox Endpoint Agent\r\n",
		"reg query " + key + " /v WindowsInstaller": "    WindowsInstaller    REG_DWORD    0x1\r\n",
	}
	tests := []struct {
		name, goos, exe string
		out             map[string]string
		want            Method
	}{
		{"deb", "linux", exe, map[string]string{"dpkg-query -S " + exe: "siembox-agent: " + exe + "\n"}, MethodDeb},
		{"rpm", "linux", exe, map[string]string{"rpm -qf " + exe: "siembox-agent-1.3.2-1.x86_64\n"}, MethodRPM},
		{"rpm unowned text", "linux", exe, map[string]string{"rpm -qf " + exe: "file is not owned by any package\n"}, MethodLinuxArchive},
		{"linux script install", "linux", "/usr/local/bin/siembox-agent", nil, MethodLinuxArchive},
		{"pkg", "darwin", macExe, map[string]string{
			"pkgutil --file-info " + macExe: "volume: /\npath: " + macExe + "\n\npkgid: io.siembox.agent\n"}, MethodPkg},
		{"pkg without pkgid", "darwin", macExe, map[string]string{
			"pkgutil --file-info " + macExe: "volume: /\npath: " + macExe + "\n"}, MethodDarwinArchive},
		{"darwin archive", "darwin", macExe, nil, MethodDarwinArchive},
		{"msi", "windows", win, msiOut, MethodMSI},
		{"msi path case-insensitive", "windows", `c:\program files\siembox\SIEMBOX-AGENT.EXE`, msiOut, MethodMSI},
		{"windows install.ps1 (no MSI registration)", "windows", win, nil, MethodWindowsZip},
		{"windows MSI elsewhere", "windows", `D:\tools\siembox-agent.exe`, msiOut, MethodWindowsZip},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DetectMethod(context.Background(), tt.goos, tt.exe, `C:\Program Files`, &fakeRunner{out: tt.out})
			if err != nil || got != tt.want {
				t.Fatalf("got %q err=%v want %q", got, err, tt.want)
			}
		})
	}
	if _, err := DetectMethod(context.Background(), "plan9", "x", "", &fakeRunner{}); err == nil {
		t.Error("unsupported OS must error")
	}
}
