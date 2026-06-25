// Package agent implements the EDR agent lifecycle: enrollment, heartbeat,
// config polling, inventory reporting, vulnerability scanning, detection event
// delivery, and offline-resilient transport via the spool.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/cladkins/siembox-edr/internal/config"
	"github.com/cladkins/siembox-edr/internal/detect"
	"github.com/cladkins/siembox-edr/internal/detect/yara"
	"github.com/cladkins/siembox-edr/internal/inventory"
	"github.com/cladkins/siembox-edr/internal/models"
	"github.com/cladkins/siembox-edr/internal/transport"
	"github.com/cladkins/siembox-edr/internal/version"
	"github.com/cladkins/siembox-edr/internal/vuln"
)

// spool kinds and their target endpoints, used when replaying queued payloads.
var spoolPaths = map[string]string{
	"events":    "/api/edr/events",
	"vulns":     "/api/edr/vulnerabilities",
	"inventory": "/api/edr/inventory",
}

// Defaults used when the server config leaves an interval unset.
const (
	defaultHeartbeatSec  = 60
	defaultConfigPollSec = 300
	defaultInventorySec  = 3600
	defaultVulnScanSec   = 86400
	eventBatchMax        = 100
	eventBatchWait       = 10 * time.Second
	spoolFlushSec        = 30
)

// Agent ties together transport, collectors, and the detection engine.
type Agent struct {
	state   *config.State
	client  *transport.Client
	spool   *transport.Spool
	scanner vuln.Scanner
	engine  detect.Engine
	log     *slog.Logger

	// restartDetection signals the detection supervisor to stop and restart the
	// engine (re-reading the on-disk YARA signature file) after a rule update.
	restartDetection chan struct{}
}

// New constructs an Agent from loaded state. The transport client is created
// with whatever identity is already persisted (empty until enrollment).
func New(state *config.State, spool *transport.Spool, log *slog.Logger) (*Agent, error) {
	client, err := transport.New(transport.Options{
		ServerURL:          state.Settings.ServerURL,
		AgentID:            state.Identity.AgentID,
		AgentAPIKey:        state.Identity.AgentAPIKey,
		CACertPath:         state.Settings.CACertPath,
		InsecureSkipVerify: state.Settings.InsecureSkipVerify,
	})
	if err != nil {
		return nil, err
	}
	return &Agent{
		state:            state,
		client:           client,
		spool:            spool,
		scanner:          vuln.NoopScanner{},
		engine:           detect.NoopEngine{},
		log:              log,
		restartDetection: make(chan struct{}, 1),
	}, nil
}

// WithScanner overrides the vulnerability scanner backend.
func (a *Agent) WithScanner(s vuln.Scanner) *Agent { a.scanner = s; return a }

// WithEngine overrides the detection engine backend.
func (a *Agent) WithEngine(e detect.Engine) *Agent { a.engine = e; return a }

// Run enrolls if needed and then runs all loops until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	if !a.state.Enrolled() {
		if err := a.enrollWithRetry(ctx); err != nil {
			return err // only returns on ctx cancellation
		}
	}
	a.log.Info("agent running", "agent_id", a.state.Identity.AgentID, "version", version.Version)

	// Pull any server-curated YARA rules before detection starts so the first
	// osquery launch already uses them. Best-effort; baseline rules apply
	// regardless. The detection supervisor (runDetection) calls LoadRules.
	a.syncYaraRules(ctx)
	// Detection hasn't started yet, so the signature file is already current;
	// drop the restart the initial sync queued to avoid an immediate bounce.
	select {
	case <-a.restartDetection:
	default:
	}

	// Send an inventory snapshot immediately on startup.
	a.reportInventory(ctx)

	var wg sync.WaitGroup
	events := make(chan models.Event, 256)

	run := func(fn func()) {
		wg.Add(1)
		go func() { defer wg.Done(); fn() }()
	}

	// Run an initial vulnerability scan shortly after startup so a newly
	// enrolled endpoint surfaces vuln data without waiting for the first tick.
	run(func() { a.runVulnScan(ctx) })

	cfg := a.state.Identity.Config
	run(func() { a.tick(ctx, sec(cfg.HeartbeatIntervalSec, defaultHeartbeatSec), a.heartbeat) })
	run(func() { a.tick(ctx, sec(cfg.ConfigPollIntervalSec, defaultConfigPollSec), a.pollConfig) })
	run(func() { a.tick(ctx, sec(cfg.InventoryIntervalSec, defaultInventorySec), a.reportInventory) })
	run(func() { a.tick(ctx, sec(cfg.VulnScanIntervalSec, defaultVulnScanSec), a.runVulnScan) })
	run(func() { a.tick(ctx, spoolFlushSec, a.flushSpool) })
	run(func() { a.batchEvents(ctx, events) })
	run(func() { a.runDetection(ctx, events) })

	<-ctx.Done()
	a.log.Info("shutting down")
	wg.Wait()
	return nil
}

// enrollWithRetry keeps trying to enroll with exponential backoff until it
// succeeds or ctx is cancelled, so a missing token or an unreachable server
// leaves the agent idling (and the service "running") rather than crash-looping.
func (a *Agent) enrollWithRetry(ctx context.Context) error {
	backoff := 5 * time.Second
	const maxBackoff = 5 * time.Minute
	for {
		err := a.enroll(ctx)
		if err == nil {
			return nil
		}
		a.log.Warn("not enrolled yet; will retry", "err", err, "retry_in", backoff.String())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// enroll exchanges the enrollment token for a persisted identity.
func (a *Agent) enroll(ctx context.Context) error {
	if a.state.Settings.EnrollmentToken == "" {
		return fmt.Errorf("no enrollment_token configured and agent is not yet enrolled")
	}
	inv := inventory.Collect()
	resp, err := a.client.Enroll(ctx, models.EnrollRequest{
		EnrollmentToken: a.state.Settings.EnrollmentToken,
		Hostname:        inv.Hostname,
		OS:              inv.OS,
		OSVersion:       inv.OSVersion,
		Arch:            inv.Arch,
		AgentVersion:    version.Version,
		IP:              inv.IP,
	})
	if err != nil {
		return err
	}

	a.state.Identity = config.Identity{
		AgentID:     resp.AgentID,
		AgentAPIKey: resp.AgentAPIKey,
		Config:      resp.Config,
	}
	if err := a.state.SaveIdentity(); err != nil {
		return err
	}
	// Consume the one-time enrollment token.
	a.state.Settings.EnrollmentToken = ""
	if err := a.state.SaveSettings(); err != nil {
		a.log.Warn("clear enrollment token", "err", err)
	}
	a.client.SetIdentity(resp.AgentID, resp.AgentAPIKey)
	a.log.Info("enrolled", "agent_id", resp.AgentID)
	return nil
}

// runDetection supervises the detection engine, restarting it when YARA rules
// are updated. The engine and its osquery source are re-entrant: each Run
// re-reads the on-disk signature file, so a restart applies new rules. Blocks
// until ctx is cancelled.
func (a *Agent) runDetection(ctx context.Context, events chan<- models.Event) {
	for {
		if err := a.engine.LoadRules(a.state.Identity.Config.Rules); err != nil {
			a.log.Warn("load rules", "err", err)
		}
		child, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			if err := a.engine.Run(child, events); err != nil && child.Err() == nil {
				a.log.Error("detection engine stopped", "err", err)
			}
		}()

		select {
		case <-ctx.Done():
			cancel()
			<-done
			return
		case <-a.restartDetection:
			a.log.Info("restarting detection to apply updated YARA rules")
			cancel()
			<-done
			// loop: restart with the refreshed signature file
		case <-done:
			// Engine exited on its own (e.g. osquery crashed); cancel and retry
			// after a short pause rather than spinning.
			cancel()
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}
}

// syncYaraRules downloads the server's YARA bundle when its version exceeds the
// applied one, writes it (alongside the embedded baseline) to the signature
// file, persists the applied version, and signals a detection restart so
// osquery reloads. Best-effort: failures leave the previous rules in place.
func (a *Agent) syncYaraRules(ctx context.Context) {
	cfg := a.state.Identity.Config
	if cfg.YaraRulesVersion <= a.state.Identity.AppliedYaraRulesVersion {
		return
	}
	raw, err := a.client.FetchYaraRules(ctx)
	if err != nil {
		a.log.Debug("yara rules fetch failed", "err", err)
		return
	}
	if _, err := yara.WriteSignatures(filepath.Join(a.state.Dir, "yara"), raw); err != nil {
		a.log.Warn("write yara rules", "err", err)
		return
	}
	a.state.Identity.AppliedYaraRulesVersion = cfg.YaraRulesVersion
	if err := a.state.SaveIdentity(); err != nil {
		a.log.Warn("persist applied yara version", "err", err)
	}
	a.log.Info("applied updated YARA rules", "version", cfg.YaraRulesVersion, "bytes", len(raw))

	// Nudge detection to restart; non-blocking so we never stall if the
	// supervisor isn't ready or detection is disabled.
	select {
	case a.restartDetection <- struct{}{}:
	default:
	}
}

func (a *Agent) heartbeat(ctx context.Context) {
	resp, err := a.client.Heartbeat(ctx, models.HeartbeatRequest{
		Status:       "online",
		AgentVersion: version.Version,
	})
	if err != nil {
		a.log.Debug("heartbeat failed", "err", err)
		return
	}
	if resp.ConfigVersion > a.state.Identity.Config.ConfigVersion {
		a.log.Info("new config available", "version", resp.ConfigVersion)
		a.pollConfig(ctx)
	}
}

func (a *Agent) pollConfig(ctx context.Context) {
	cfg, err := a.client.FetchConfig(ctx)
	if err != nil {
		a.log.Debug("config fetch failed", "err", err)
		return
	}
	if cfg.ConfigVersion == a.state.Identity.Config.ConfigVersion {
		return
	}
	a.state.Identity.Config = cfg
	if err := a.state.SaveIdentity(); err != nil {
		a.log.Warn("persist config", "err", err)
	}
	if err := a.engine.LoadRules(cfg.Rules); err != nil {
		a.log.Warn("reload rules", "err", err)
	}
	a.log.Info("applied config", "version", cfg.ConfigVersion, "rules", len(cfg.Rules))

	// A new config may bump the YARA bundle version; pull + apply if so.
	a.syncYaraRules(ctx)
}

func (a *Agent) reportInventory(ctx context.Context) {
	req := models.InventoryRequest{
		AgentID:   a.state.Identity.AgentID,
		Inventory: inventory.Collect(),
	}
	if err := a.client.SendInventory(ctx, req); err != nil {
		a.log.Debug("inventory send failed, spooling", "err", err)
		a.spoolJSON("inventory", req)
	}
}

func (a *Agent) runVulnScan(ctx context.Context) {
	a.log.Info("starting vulnerability scan", "scanner", a.scanner.Name())
	batch, err := a.scanner.Scan(ctx, a.state.Identity.AgentID)
	if err != nil {
		a.log.Error("vuln scan failed", "err", err)
		return
	}
	a.log.Info("vuln scan complete", "findings", len(batch.Vulnerabilities))
	if err := a.client.SendVulnerabilities(ctx, batch); err != nil {
		a.log.Debug("vuln send failed, spooling", "err", err)
		a.spoolJSON("vulns", batch)
	}
}

// batchEvents accumulates detection events and flushes them by size or time.
func (a *Agent) batchEvents(ctx context.Context, in <-chan models.Event) {
	ticker := time.NewTicker(eventBatchWait)
	defer ticker.Stop()
	var buf []models.Event

	flush := func() {
		if len(buf) == 0 {
			return
		}
		batch := models.EventBatch{AgentID: a.state.Identity.AgentID, Events: buf}
		if err := a.client.SendEvents(ctx, batch); err != nil {
			a.log.Debug("events send failed, spooling", "err", err)
			a.spoolJSON("events", batch)
		}
		buf = nil
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case ev := <-in:
			// Log every detection as it's produced so the running service is
			// observable (otherwise detections ship silently to the server).
			a.log.Info("detection",
				"title", ev.Title,
				"severity", ev.Severity,
				"rule_id", ev.RuleID,
				"source", ev.Source)
			buf = append(buf, ev)
			if len(buf) >= eventBatchMax {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// flushSpool replays queued payloads in order, stopping at the first failure so
// ordering is preserved and the server is not hammered while still unreachable.
func (a *Agent) flushSpool(ctx context.Context) {
	entries, err := a.spool.List()
	if err != nil {
		a.log.Warn("spool list", "err", err)
		return
	}
	for _, e := range entries {
		path, ok := spoolPaths[e.Kind]
		if !ok {
			a.log.Warn("unknown spool kind, removing", "kind", e.Kind)
			_ = a.spool.Remove(e.Path)
			continue
		}
		raw, err := a.spool.Read(e.Path)
		if err != nil {
			a.log.Warn("spool read", "err", err)
			continue
		}
		if err := a.client.PostRaw(ctx, path, raw); err != nil {
			a.log.Debug("spool replay failed, will retry", "err", err)
			return
		}
		_ = a.spool.Remove(e.Path)
	}
}

func (a *Agent) spoolJSON(kind string, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		a.log.Error("marshal for spool", "err", err)
		return
	}
	if err := a.spool.Add(kind, raw); err != nil {
		a.log.Error("spool add", "kind", kind, "err", err)
	}
}

// tick invokes fn on each interval until ctx ends. fn receives ctx so long
// operations are cancellable on shutdown.
func (a *Agent) tick(ctx context.Context, intervalSec int, fn func(context.Context)) {
	ticker := time.NewTicker(time.Duration(intervalSec) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fn(ctx)
		}
	}
}

func sec(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}
