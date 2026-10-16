package update

import "testing"

var releaseNames = []string{
	"SHA256SUMS", "checksums.txt",
	"siembox-agent_1.4.0_amd64.deb", "siembox-agent_1.4.0_arm64.deb",
	"siembox-agent-1.4.0-1.x86_64.rpm", "siembox-agent-1.4.0-1.aarch64.rpm",
	"siembox-agent-1.4.0-macos.pkg", "siembox-agent-1.4.0-windows-amd64.msi",
	"siembox-endpoint_1.4.0_linux_amd64.tar.gz", "siembox-endpoint_1.4.0_linux_arm64.tar.gz",
	"siembox-endpoint_1.4.0_darwin_amd64.tar.gz", "siembox-endpoint_1.4.0_darwin_arm64.tar.gz",
	"siembox-endpoint_1.4.0_windows_amd64.zip",
	"siembox-agent-1.40.0-1.x86_64.rpm", // different version must never match
}

func TestSelectAsset(t *testing.T) {
	tests := []struct {
		m       Method
		arch    string
		want    string
		wantErr bool
	}{
		{MethodDeb, "amd64", "siembox-agent_1.4.0_amd64.deb", false},
		{MethodDeb, "arm64", "siembox-agent_1.4.0_arm64.deb", false},
		{MethodRPM, "amd64", "siembox-agent-1.4.0-1.x86_64.rpm", false},
		{MethodRPM, "arm64", "siembox-agent-1.4.0-1.aarch64.rpm", false},
		{MethodLinuxArchive, "arm64", "siembox-endpoint_1.4.0_linux_arm64.tar.gz", false},
		{MethodPkg, "arm64", "siembox-agent-1.4.0-macos.pkg", false},
		{MethodDarwinArchive, "amd64", "siembox-endpoint_1.4.0_darwin_amd64.tar.gz", false},
		{MethodMSI, "amd64", "siembox-agent-1.4.0-windows-amd64.msi", false},
		{MethodWindowsZip, "amd64", "siembox-endpoint_1.4.0_windows_amd64.zip", false},
		{MethodMSI, "arm64", "", true},
		{MethodDeb, "386", "", true},
		{MethodRPM, "386", "", true},
		{Method("bogus"), "amd64", "", true},
	}
	for _, tt := range tests {
		got, err := SelectAsset(tt.m, "1.4.0", tt.arch, releaseNames)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("%s/%s: got %q err=%v, want %q err=%v", tt.m, tt.arch, got, err, tt.want, tt.wantErr)
		}
	}
	if _, err := SelectAsset(MethodDeb, "1.5.0", "amd64", releaseNames); err == nil {
		t.Error("asset for another version must not be selected")
	}
	if _, err := SelectAsset(MethodRPM, "1.5.0", "amd64", releaseNames); err == nil {
		t.Error("rpm for another version must not be selected")
	}
}
