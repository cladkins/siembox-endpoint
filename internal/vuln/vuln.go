// Package vuln defines the endpoint vulnerability scanning interface. The
// production implementation (Syft SBOM + Grype CVE matching) is added in the
// vulnerability-scanning phase; this file establishes the contract and a noop
// scanner used until then and in tests.
package vuln

import (
	"context"
	"time"

	"github.com/cladkins/siembox-edr/internal/models"
)

// Scanner produces a batch of vulnerability findings for the local host.
type Scanner interface {
	// Name identifies the scanner backend (e.g. "grype").
	Name() string
	// Scan performs a full local scan. agentID is stamped onto the result.
	Scan(ctx context.Context, agentID string) (models.VulnBatch, error)
}

// NoopScanner is a placeholder that returns an empty result. It lets the agent
// run end-to-end before the Grype backend lands.
type NoopScanner struct{}

// Name implements Scanner.
func (NoopScanner) Name() string { return "noop" }

// Scan implements Scanner.
func (NoopScanner) Scan(_ context.Context, agentID string) (models.VulnBatch, error) {
	now := time.Now().UTC()
	return models.VulnBatch{
		AgentID:         agentID,
		ScanStartedAt:   now,
		ScanCompletedAt: now,
		Vulnerabilities: nil,
	}, nil
}
