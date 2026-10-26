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
	if !strings.Contains(string(b), "rule SIEMBox_YARA_SelfTest") {
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
	if !strings.Contains(s, "rule SIEMBox_YARA_SelfTest") {
		t.Error("written signatures missing baseline")
	}
	if !strings.Contains(s, "rule Extra") {
		t.Error("written signatures missing extra rule")
	}
	// Baseline must precede server-delivered rules.
	if strings.Index(s, "rule SIEMBox_YARA_SelfTest") > strings.Index(s, "rule Extra") {
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

// The baseline is embedded in the agent binary, so its text must not contain
// the self-test marker: if it did, every YARA pass that reaches the agent's
// executable (e.g. /usr/local/bin) would raise a self-test detection.
func TestBaselineDoesNotContainMarkerText(t *testing.T) {
	b, err := Baseline()
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}
	if strings.Contains(string(b), "SIEMBOX_"+"YARA_SELFTEST") {
		t.Error("baseline text contains the self-test marker; the agent binary would match its own rule")
	}
}
