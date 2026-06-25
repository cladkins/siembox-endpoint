package yara

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBaselineContainsSelfTest(t *testing.T) {
	b, err := Baseline()
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}
	if !strings.Contains(string(b), "SIEMBOX_YARA_SELFTEST") {
		t.Error("baseline missing self-test marker")
	}
	if !strings.Contains(string(b), "rule ") {
		t.Error("baseline does not look like YARA rules")
	}
}

func TestWriteSignatures(t *testing.T) {
	dir := t.TempDir()
	extra := []byte("rule Extra { condition: true }\n")
	path, err := WriteSignatures(dir, extra)
	if err != nil {
		t.Fatalf("WriteSignatures: %v", err)
	}
	if filepath.Base(path) != SignatureFileName {
		t.Errorf("path = %q, want basename %q", path, SignatureFileName)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, "SIEMBOX_YARA_SELFTEST") {
		t.Error("written signatures missing baseline")
	}
	if !strings.Contains(s, "rule Extra") {
		t.Error("written signatures missing extra rule")
	}
	// Baseline must precede server-delivered rules.
	if strings.Index(s, "SIEMBOX_YARA_SELFTEST") > strings.Index(s, "rule Extra") {
		t.Error("baseline should come before extra rules")
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("signature file perm = %o, want 600", perm)
	}
}
