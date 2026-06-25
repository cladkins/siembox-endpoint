package util

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindBinaryInExtraDir(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "mytool")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, ok := FindBinary("mytool", []string{"/nonexistent", dir})
	if !ok {
		t.Fatal("expected to find mytool in extra dir")
	}
	if got != bin {
		t.Errorf("got %q, want %q", got, bin)
	}
}

func TestFindBinaryExplicitPath(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tool")
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, ok := FindBinary(bin, nil); !ok || got != bin {
		t.Errorf("explicit path: got %q ok=%v", got, ok)
	}
}

func TestFindBinaryNotFound(t *testing.T) {
	if got, ok := FindBinary("definitely-not-a-real-binary-xyz", []string{t.TempDir()}); ok {
		t.Errorf("expected not found, got %q", got)
	}
}

func TestEnsureSaneTmpdir(t *testing.T) {
	// A missing TMPDIR dir should be cleared.
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "deleted-sandbox"))
	EnsureSaneTmpdir()
	if v := os.Getenv("TMPDIR"); v != "" {
		t.Errorf("expected TMPDIR cleared for missing dir, got %q", v)
	}

	// An existing TMPDIR dir should be left as-is.
	good := t.TempDir()
	t.Setenv("TMPDIR", good)
	EnsureSaneTmpdir()
	if v := os.Getenv("TMPDIR"); v != good {
		t.Errorf("expected TMPDIR preserved, got %q want %q", v, good)
	}
}
