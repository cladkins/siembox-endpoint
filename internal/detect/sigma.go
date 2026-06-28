package detect

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	sigma "github.com/bradleyjkemp/sigma-go"
	"github.com/bradleyjkemp/sigma-go/evaluator"

	"github.com/cladkins/siembox-endpoint/internal/models"
	"github.com/cladkins/siembox-endpoint/internal/telemetry"
	"github.com/cladkins/siembox-endpoint/internal/util"
)

// compiledRule pairs a parsed Sigma rule with its evaluator.
type compiledRule struct {
	rule sigma.Rule
	eval *evaluator.RuleEvaluator
}

// SigmaEngine evaluates telemetry records against Sigma rules and emits
// detection events. It implements detect.Engine.
type SigmaEngine struct {
	source    telemetry.Source
	log       *slog.Logger
	baseRules []string // always-active rules (e.g. the embedded default pack)

	mu    sync.RWMutex
	rules []compiledRule
}

// NewSigmaEngine builds an engine reading from source. baseRules are always
// active; LoadRules adds server-pushed rules on top of them.
func NewSigmaEngine(source telemetry.Source, baseRules []string, log *slog.Logger) *SigmaEngine {
	return &SigmaEngine{source: source, baseRules: baseRules, log: log}
}

// LoadRules parses and compiles the base rules plus the given server-pushed
// Sigma YAML documents, replacing the active rule set. Invalid rules are
// skipped (logged) so one bad rule does not disable detection entirely.
func (e *SigmaEngine) LoadRules(serverRules []string) error {
	rules := make([]string, 0, len(e.baseRules)+len(serverRules))
	rules = append(rules, e.baseRules...)
	rules = append(rules, serverRules...)

	compiled := make([]compiledRule, 0, len(rules))
	var firstErr error
	for i, raw := range rules {
		r, err := sigma.ParseRule([]byte(raw))
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("rule %d: %w", i, err)
			}
			if e.log != nil {
				e.log.Warn("skipping invalid sigma rule", "index", i, "err", err)
			}
			continue
		}
		compiled = append(compiled, compiledRule{rule: r, eval: evaluator.ForRule(r)})
	}

	e.mu.Lock()
	e.rules = compiled
	e.mu.Unlock()

	if e.log != nil {
		e.log.Info("loaded sigma rules", "count", len(compiled))
	}
	return firstErr
}

// Run starts the telemetry source and evaluates each record until ctx ends.
func (e *SigmaEngine) Run(ctx context.Context, out chan<- models.Event) error {
	records := make(chan telemetry.Record, 256)
	srcErr := make(chan error, 1)
	go func() { srcErr <- e.source.Start(ctx, records) }()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-srcErr:
			return err
		case rec := <-records:
			e.evaluate(ctx, rec, out)
		}
	}
}

// evaluate runs all rules against one record, emitting an event per match.
func (e *SigmaEngine) evaluate(ctx context.Context, rec telemetry.Record, out chan<- models.Event) {
	for _, ev := range e.matchRecord(ctx, rec) {
		select {
		case <-ctx.Done():
			return
		case out <- ev:
		}
	}
}

// Evaluate runs the loaded rules against a batch of records and returns all
// resulting detection events. Used by one-shot "check" mode, which needs no
// telemetry source or server.
func (e *SigmaEngine) Evaluate(ctx context.Context, records []telemetry.Record) []models.Event {
	out := make([]models.Event, 0) // non-nil so JSON marshals to [] not null
	for _, rec := range records {
		out = append(out, e.matchRecord(ctx, rec)...)
	}
	return out
}

// matchRecord evaluates every loaded rule against a single record and returns
// the detection events for the rules that matched.
func (e *SigmaEngine) matchRecord(ctx context.Context, rec telemetry.Record) []models.Event {
	event := buildEvent(rec)

	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	var out []models.Event
	for _, cr := range rules {
		res, err := cr.eval.Matches(ctx, event)
		if err != nil {
			if e.log != nil {
				e.log.Debug("rule evaluation error", "rule", cr.rule.Title, "err", err)
			}
			continue
		}
		if !res.Match {
			continue
		}
		out = append(out, toEvent(cr.rule, rec))
	}
	return out
}

// buildEvent turns a telemetry record into the field map Sigma matches against:
// the row's columns plus the synthetic "query" and "action" fields.
func buildEvent(rec telemetry.Record) map[string]interface{} {
	event := make(map[string]interface{}, len(rec.Columns)+2)
	for k, v := range rec.Columns {
		event[k] = v
	}
	event["query"] = rec.Query
	event["action"] = rec.Action
	return event
}

// toEvent converts a rule match into a detection event for SIEMBox.
func toEvent(rule sigma.Rule, rec telemetry.Record) models.Event {
	ts := rec.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	fields := make(map[string]interface{}, len(rec.Columns)+1)
	for k, v := range rec.Columns {
		fields[k] = v
	}
	fields["action"] = rec.Action

	return models.Event{
		ID:        util.NewID(),
		Timestamp: ts,
		Type:      models.EventTypeDetection,
		Severity:  severityFromLevel(rule.Level),
		Title:     rule.Title,
		RuleID:    rule.ID,
		RuleName:  rule.Title,
		Source:    "osquery:" + rec.Query,
		Fields:    fields,
	}
}

// severityFromLevel maps Sigma levels onto the SIEMBox severity scale.
func severityFromLevel(level string) string {
	switch strings.ToLower(level) {
	case "critical":
		return models.SeverityCritical
	case "high":
		return models.SeverityHigh
	case "medium":
		return models.SeverityMedium
	default: // low, informational, empty
		return models.SeverityLow
	}
}
