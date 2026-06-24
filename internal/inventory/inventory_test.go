package inventory

import (
	"runtime"
	"testing"
)

func TestCollect(t *testing.T) {
	inv := Collect()
	if inv.OS != runtime.GOOS {
		t.Errorf("OS = %q, want %q", inv.OS, runtime.GOOS)
	}
	if inv.Arch != runtime.GOARCH {
		t.Errorf("Arch = %q, want %q", inv.Arch, runtime.GOARCH)
	}
	if inv.Hostname == "" {
		t.Error("hostname is empty")
	}
	if inv.CollectedAt.IsZero() {
		t.Error("CollectedAt not set")
	}
}
