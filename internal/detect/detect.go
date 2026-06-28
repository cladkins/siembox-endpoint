// Package detect defines the local detection engine interface. The production
// implementation (osquery telemetry + Sigma rule evaluation) is added in the
// detection phase; this file establishes the contract and a noop engine used
// until then and in tests.
package detect

import (
	"context"

	"github.com/cladkins/siembox-endpoint/internal/models"
	"github.com/cladkins/siembox-endpoint/internal/telemetry"
)

// Engine evaluates host telemetry against loaded rules and emits detections.
type Engine interface {
	// LoadRules replaces the active rule set with the provided Sigma YAML
	// documents. Safe to call when config changes.
	LoadRules(rules []string) error
	// Run starts the engine, streaming detections to out until ctx is
	// cancelled. Implementations block until ctx is done.
	Run(ctx context.Context, out chan<- models.Event) error
	// Evaluate runs the loaded rules against a batch of records and returns the
	// resulting detection events, without needing a streaming source. Used for
	// on-demand scans (e.g. the agent's YARA scan).
	Evaluate(ctx context.Context, records []telemetry.Record) []models.Event
}

// NoopEngine satisfies Engine without producing detections. It lets the agent
// run before the osquery/Sigma backend lands.
type NoopEngine struct{}

// LoadRules implements Engine.
func (NoopEngine) LoadRules([]string) error { return nil }

// Run implements Engine: it simply blocks until the context is cancelled.
func (NoopEngine) Run(ctx context.Context, _ chan<- models.Event) error {
	<-ctx.Done()
	return ctx.Err()
}

// Evaluate implements Engine: it produces no detections.
func (NoopEngine) Evaluate(context.Context, []telemetry.Record) []models.Event { return nil }
