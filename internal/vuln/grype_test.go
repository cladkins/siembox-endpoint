package vuln

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cladkins/siembox-endpoint/internal/models"
)

const sampleGrypeJSON = `{
  "matches": [
    {
      "vulnerability": {
        "id": "CVE-2024-1234",
        "severity": "High",
        "description": "A flaw in openssl.",
        "fix": { "versions": ["3.0.13"], "state": "fixed" },
        "cvss": [ { "metrics": { "baseScore": 7.5 } }, { "metrics": { "baseScore": 6.1 } } ]
      },
      "artifact": { "name": "openssl", "version": "3.0.2" }
    },
    {
      "vulnerability": {
        "id": "CVE-2023-9999",
        "severity": "Negligible",
        "fix": { "versions": [], "state": "not-fixed" },
        "cvss": []
      },
      "artifact": { "name": "zlib", "version": "1.2.11" }
    }
  ]
}`

func TestParseGrypeJSON(t *testing.T) {
	vulns, err := parseGrypeJSON([]byte(sampleGrypeJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(vulns) != 2 {
		t.Fatalf("got %d vulns, want 2", len(vulns))
	}

	v := vulns[0]
	if v.CVE != "CVE-2024-1234" || v.Package != "openssl" || v.InstalledVersion != "3.0.2" {
		t.Errorf("unexpected vuln[0]: %+v", v)
	}
	if v.Severity != models.SeverityHigh {
		t.Errorf("severity = %q, want high", v.Severity)
	}
	if v.FixedVersion != "3.0.13" {
		t.Errorf("fixed version = %q, want 3.0.13", v.FixedVersion)
	}
	if v.CVSS != 7.5 {
		t.Errorf("cvss = %v, want 7.5 (max)", v.CVSS)
	}
	if v.Source != "grype" {
		t.Errorf("source = %q", v.Source)
	}

	// Negligible -> low, no fix, no cvss.
	if vulns[1].Severity != models.SeverityLow {
		t.Errorf("vuln[1] severity = %q, want low", vulns[1].Severity)
	}
	if vulns[1].FixedVersion != "" {
		t.Errorf("vuln[1] should have no fixed version, got %q", vulns[1].FixedVersion)
	}
}

func TestGrypeScanMapsBatch(t *testing.T) {
	s := NewGrypeScanner("grype", "dir:/")
	var gotArgs []string
	s.runner = func(_ context.Context, name string, args ...string) ([]byte, error) {
		gotArgs = append([]string{name}, args...)
		return []byte(sampleGrypeJSON), nil
	}

	batch, err := s.Scan(context.Background(), "agent-9")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if batch.AgentID != "agent-9" {
		t.Errorf("agent = %q", batch.AgentID)
	}
	if len(batch.Vulnerabilities) != 2 {
		t.Errorf("got %d vulns", len(batch.Vulnerabilities))
	}
	if batch.ScanCompletedAt.Before(batch.ScanStartedAt) {
		t.Error("completed before started")
	}
	// Verify the invocation requests JSON output.
	wantJSON := false
	for _, a := range gotArgs {
		if a == "json" {
			wantJSON = true
		}
	}
	if !wantJSON {
		t.Errorf("grype not invoked with json output: %v", gotArgs)
	}
}

func TestGrypeScanRunnerError(t *testing.T) {
	s := NewGrypeScanner("grype", "dir:/")
	s.runner = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return nil, errors.New("boom")
	}
	if _, err := s.Scan(context.Background(), "a"); err == nil {
		t.Fatal("expected error when grype fails")
	}
}

func TestGrypeDefaults(t *testing.T) {
	// Explicit target overrides OS defaults with a single target.
	s := NewGrypeScanner("", "dir:/custom")
	if s.binary != "grype" {
		t.Errorf("binary = %q, want grype", s.binary)
	}
	if len(s.targets) != 1 || s.targets[0] != "dir:/custom" {
		t.Errorf("targets = %v, want [dir:/custom]", s.targets)
	}

	// Empty target uses OS defaults.
	d := NewGrypeScanner("", "")
	if len(d.targets) == 0 {
		t.Error("expected default targets for empty target")
	}
}

func TestDefaultGrypeTargets(t *testing.T) {
	if got := defaultGrypeTargets("linux"); len(got) != 1 || got[0] != "dir:/" {
		t.Errorf("linux targets = %v, want [dir:/]", got)
	}
	mac := defaultGrypeTargets("darwin")
	if len(mac) < 2 {
		t.Fatalf("darwin targets too few: %v", mac)
	}
	for _, tt := range mac {
		if strings.Contains(tt, "/Users") {
			t.Errorf("darwin default scans a user dir (TCC risk): %q", tt)
		}
	}
}

func TestExistingTargets(t *testing.T) {
	dir := t.TempDir()
	got := existingTargets([]string{"dir:" + dir, "dir:/no/such/path/here", "registry:alpine:latest"})
	// existing dir kept, missing dir dropped, non-dir source kept.
	if len(got) != 2 {
		t.Fatalf("got %v, want 2 entries (existing dir + registry source)", got)
	}
}

func TestGrypeScanMergesAndDedupes(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	s := NewGrypeScanner("grype", "")
	s.targets = []string{"dir:" + dirA, "dir:" + dirB}
	// Both targets return the same finding; it should be deduped to one.
	s.runner = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte(sampleGrypeJSON), nil
	}
	batch, err := s.Scan(context.Background(), "a")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// sampleGrypeJSON has 2 distinct vulns; across 2 identical targets, dedupe
	// keeps 2 (not 4).
	if len(batch.Vulnerabilities) != 2 {
		t.Errorf("got %d vulns after merge/dedupe, want 2", len(batch.Vulnerabilities))
	}
}
