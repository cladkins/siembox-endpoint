package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/cladkins/siembox-edr/internal/models"
	"github.com/cladkins/siembox-edr/internal/util"
)

// grypeExtraDirs are non-PATH locations to look for the grype binary, which
// matters under sudo/launchd where PATH is minimal.
var grypeExtraDirs = []string{"/usr/local/bin", "/opt/homebrew/bin"}

// GrypeScanner runs the bundled `grype` binary against the host and maps its
// JSON output into the SIEMBox vulnerability model. We shell out to grype
// (rather than embedding it as a library) because grype/syft's Go APIs are not
// a stable public contract and embedding them bloats the agent binary; the
// binary is shipped alongside the agent by the installer.
type GrypeScanner struct {
	// binary is the grype executable (name on PATH or absolute path).
	binary string
	// targets are the grype source arguments, e.g. "dir:/Applications". One
	// grype invocation runs per target and results are merged. Defaults are
	// OS-specific (see defaultGrypeTargets) to avoid walking protected user
	// directories on macOS, which both triggers TCC prompts and can fail the
	// scan.
	targets []string
	// runner executes a command and returns stdout. Overridable in tests so the
	// scanner can be exercised without grype installed.
	runner func(ctx context.Context, name string, args ...string) ([]byte, error)
}

// NewGrypeScanner constructs a scanner. Empty binary falls back to "grype". A
// non-empty target overrides the OS defaults with a single target; empty uses
// defaultGrypeTargets for the current OS.
func NewGrypeScanner(binary, target string) *GrypeScanner {
	if binary == "" {
		binary = "grype"
	}
	var targets []string
	if target != "" {
		targets = []string{target}
	} else {
		targets = defaultGrypeTargets(runtime.GOOS)
	}
	return &GrypeScanner{binary: binary, targets: targets, runner: defaultRunner}
}

// defaultGrypeTargets returns the scan roots for an OS. macOS is scoped to
// installed-software locations (avoiding /Users and other TCC-protected
// trees); Linux scans the whole filesystem to catch OS package databases.
func defaultGrypeTargets(goos string) []string {
	switch goos {
	case "darwin":
		return []string{"dir:/Applications", "dir:/System/Applications", "dir:/Library", "dir:/usr/local", "dir:/opt"}
	case "windows":
		return []string{`dir:C:\Program Files`, `dir:C:\Program Files (x86)`}
	default: // linux and others
		return []string{"dir:/"}
	}
}

func defaultRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Output()
}

// resolveBinary locates the grype executable, falling back to known dirs.
func (g *GrypeScanner) resolveBinary() (string, bool) {
	return util.FindBinary(g.binary, grypeExtraDirs)
}

// Available reports whether the grype binary can be located.
func (g *GrypeScanner) Available() bool {
	_, ok := g.resolveBinary()
	return ok
}

// Name implements Scanner.
func (g *GrypeScanner) Name() string { return "grype" }

// Scan runs grype against each existing target and returns the merged,
// de-duplicated findings.
func (g *GrypeScanner) Scan(ctx context.Context, agentID string) (models.VulnBatch, error) {
	started := time.Now().UTC()
	bin, _ := g.resolveBinary()

	targets := existingTargets(g.targets)
	if len(targets) == 0 {
		return models.VulnBatch{}, fmt.Errorf("no scan targets exist on this host (looked for %s)", strings.Join(g.targets, ", "))
	}

	seen := map[string]bool{}
	var merged []models.Vulnerability
	for _, t := range targets {
		// No -q: grype writes the JSON report to stdout and logs/errors to
		// stderr, so dropping quiet mode lets us surface the real failure
		// reason (e.g. a permission/TCC denial) without polluting the JSON.
		out, err := g.runner(ctx, bin, t, "-o", "json")
		if err != nil {
			if stderr := util.StderrText(err); stderr != "" {
				return models.VulnBatch{}, fmt.Errorf("run grype on %s: %w: %s", t, err, stderr)
			}
			return models.VulnBatch{}, fmt.Errorf("run grype on %s: %w", t, err)
		}
		vulns, err := parseGrypeJSON(out)
		if err != nil {
			return models.VulnBatch{}, err
		}
		for _, v := range vulns {
			key := v.CVE + "|" + v.Package + "|" + v.InstalledVersion
			if seen[key] {
				continue
			}
			seen[key] = true
			merged = append(merged, v)
		}
	}

	return models.VulnBatch{
		AgentID:         agentID,
		ScanStartedAt:   started,
		ScanCompletedAt: time.Now().UTC(),
		Vulnerabilities: merged,
	}, nil
}

// existingTargets drops "dir:" targets whose path does not exist (grype errors
// on a missing directory). Non-directory sources are always kept.
func existingTargets(targets []string) []string {
	var out []string
	for _, t := range targets {
		path, ok := strings.CutPrefix(t, "dir:")
		if !ok {
			out = append(out, t) // not a dir source; let grype handle it
			continue
		}
		if fi, err := os.Stat(path); err == nil && fi.IsDir() {
			out = append(out, t)
		}
	}
	return out
}

// UpdateDB refreshes grype's local vulnerability database. Grype auto-updates
// by default, so this is best-effort and its failure should not block a scan.
func (g *GrypeScanner) UpdateDB(ctx context.Context) error {
	bin, _ := g.resolveBinary()
	_, err := g.runner(ctx, bin, "db", "update")
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
