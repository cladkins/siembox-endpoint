// Package yara manages the agent's YARA signature files: a small baseline set
// embedded in the binary (so a fresh, offline agent can detect on day one) plus
// rules delivered later by the SIEMBox server. osquery's yara_events table reads
// these signature files to scan files as they are created or modified in
// monitored directories.
package yara

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed baseline/*.yar
var baselineFS embed.FS

// SignatureFileName is the on-disk name of the materialized signature file that
// osquery is pointed at.
const SignatureFileName = "siembox.yar"

// Baseline returns the embedded baseline YARA rules concatenated into a single
// signature document, in a stable (filename-sorted) order.
func Baseline() ([]byte, error) {
	entries, err := baselineFS.ReadDir("baseline")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yar") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var b strings.Builder
	for _, n := range names {
		raw, err := baselineFS.ReadFile("baseline/" + n)
		if err != nil {
			return nil, fmt.Errorf("read embedded yara rule %s: %w", n, err)
		}
		b.Write(raw)
		if !strings.HasSuffix(string(raw), "\n") {
			b.WriteByte('\n')
		}
	}
	return []byte(b.String()), nil
}

// WriteSignatures writes the given rule documents (plus the embedded baseline)
// into dir as a single signature file and returns its path. extra holds
// server-delivered rule documents and may be empty. The baseline always comes
// first so a fresh agent still detects even if the server delivers nothing.
func WriteSignatures(dir string, extra ...[]byte) (string, error) {
	base, err := Baseline()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create yara dir: %w", err)
	}

	var b strings.Builder
	b.Write(base)
	for _, e := range extra {
		if len(e) == 0 {
			continue
		}
		b.Write(e)
		if !strings.HasSuffix(string(e), "\n") {
			b.WriteByte('\n')
		}
	}

	path := filepath.Join(dir, SignatureFileName)
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return "", fmt.Errorf("write yara signatures: %w", err)
	}
	return path, nil
}
