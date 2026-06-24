package vuln

import (
	"context"
	"errors"
	"testing"

	"github.com/cladkins/siembox-edr/internal/models"
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
	s := NewGrypeScanner("", "")
	if s.binary != "grype" || s.target != "dir:/" {
		t.Errorf("defaults not applied: binary=%q target=%q", s.binary, s.target)
	}
}
