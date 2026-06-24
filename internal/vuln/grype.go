package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/cladkins/siembox-edr/internal/models"
)

// GrypeScanner runs the bundled `grype` binary against the host and maps its
// JSON output into the SIEMBox vulnerability model. We shell out to grype
// (rather than embedding it as a library) because grype/syft's Go APIs are not
// a stable public contract and embedding them bloats the agent binary; the
// binary is shipped alongside the agent by the installer.
type GrypeScanner struct {
	// binary is the grype executable (name on PATH or absolute path).
	binary string
	// target is the grype source argument, e.g. "dir:/" to catalog the host's
	// installed OS packages and application dependencies.
	target string
	// runner executes a command and returns combined stdout. Overridable in
	// tests so the scanner can be exercised without grype installed.
	runner func(ctx context.Context, name string, args ...string) ([]byte, error)
}

// NewGrypeScanner constructs a scanner. Empty binary/target fall back to
// "grype" and "dir:/".
func NewGrypeScanner(binary, target string) *GrypeScanner {
	if binary == "" {
		binary = "grype"
	}
	if target == "" {
		target = "dir:/"
	}
	return &GrypeScanner{binary: binary, target: target, runner: defaultRunner}
}

func defaultRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Output()
}

// Available reports whether the grype binary can be located. Callers can use
// this to decide whether to fall back to NoopScanner.
func (g *GrypeScanner) Available() bool {
	if strings.ContainsAny(g.binary, `/\`) {
		return true // explicit path; trust it and let Scan surface errors
	}
	_, err := exec.LookPath(g.binary)
	return err == nil
}

// Name implements Scanner.
func (g *GrypeScanner) Name() string { return "grype" }

// Scan runs grype and returns the mapped findings.
func (g *GrypeScanner) Scan(ctx context.Context, agentID string) (models.VulnBatch, error) {
	started := time.Now().UTC()
	out, err := g.runner(ctx, g.binary, g.target, "-o", "json", "-q")
	if err != nil {
		return models.VulnBatch{}, fmt.Errorf("run grype: %w", err)
	}
	vulns, err := parseGrypeJSON(out)
	if err != nil {
		return models.VulnBatch{}, err
	}
	return models.VulnBatch{
		AgentID:         agentID,
		ScanStartedAt:   started,
		ScanCompletedAt: time.Now().UTC(),
		Vulnerabilities: vulns,
	}, nil
}

// UpdateDB refreshes grype's local vulnerability database. Grype auto-updates
// by default, so this is best-effort and its failure should not block a scan.
func (g *GrypeScanner) UpdateDB(ctx context.Context) error {
	_, err := g.runner(ctx, g.binary, "db", "update")
	return err
}

// --- grype JSON document model (subset we consume) ---

type grypeDoc struct {
	Matches []grypeMatch `json:"matches"`
}

type grypeMatch struct {
	Vulnerability grypeVuln     `json:"vulnerability"`
	Artifact      grypeArtifact `json:"artifact"`
}

type grypeVuln struct {
	ID          string     `json:"id"`
	Severity    string     `json:"severity"`
	Description string     `json:"description"`
	Fix         grypeFix   `json:"fix"`
	CVSS        []grypeCVSS `json:"cvss"`
}

type grypeFix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

type grypeCVSS struct {
	Metrics struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"metrics"`
}

type grypeArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func parseGrypeJSON(raw []byte) ([]models.Vulnerability, error) {
	var doc grypeDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse grype json: %w", err)
	}
	out := make([]models.Vulnerability, 0, len(doc.Matches))
	for _, m := range doc.Matches {
		v := models.Vulnerability{
			CVE:              m.Vulnerability.ID,
			Package:          m.Artifact.Name,
			InstalledVersion: m.Artifact.Version,
			Severity:         normalizeSeverity(m.Vulnerability.Severity),
			CVSS:             maxBaseScore(m.Vulnerability.CVSS),
			Description:      m.Vulnerability.Description,
			Source:           "grype",
		}
		if m.Vulnerability.Fix.State == "fixed" && len(m.Vulnerability.Fix.Versions) > 0 {
			v.FixedVersion = m.Vulnerability.Fix.Versions[0]
		}
		out = append(out, v)
	}
	return out, nil
}

// normalizeSeverity maps grype severities onto the SIEMBox severity scale.
func normalizeSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return models.SeverityCritical
	case "high":
		return models.SeverityHigh
	case "medium":
		return models.SeverityMedium
	default: // low, negligible, unknown, empty
		return models.SeverityLow
	}
}

// maxBaseScore returns the highest CVSS base score present, or 0 if none.
func maxBaseScore(cvss []grypeCVSS) float64 {
	var max float64
	for _, c := range cvss {
		if c.Metrics.BaseScore > max {
			max = c.Metrics.BaseScore
		}
	}
	return max
}
