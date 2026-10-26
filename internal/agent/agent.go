// Package agent implements the Endpoint agent lifecycle: enrollment, heartbeat,
// config polling, inventory reporting, vulnerability scanning, detection event
// delivery, and offline-resilient transport via the spool.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/cladkins/siembox-endpoint/internal/config"
	"github.com/cladkins/siembox-endpoint/internal/detect"
	"github.com/cladkins/siembox-endpoint/internal/detect/yara"
	"github.com/cladkins/siembox-endpoint/internal/inventory"
	"github.com/cladkins/siembox-endpoint/internal/models"
	"github.com/cladkins/siembox-endpoint/internal/packages"
	"github.com/cladkins/siembox-endpoint/internal/telemetry"
	"github.com/cladkins/siembox-endpoint/internal/telemetry/osquery"
	"github.com/cladkins/siembox-endpoint/internal/transport"
	"github.com/cladkins/siembox-endpoint/internal/update"
	"github.com/cladkins/siembox-endpoint/internal/version"
	"github.com/cladkins/siembox-endpoint/internal/vuln"
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

	// packageResendEvery: the full package list goes out at least this often
	// even when unchanged (the server writes nothing if it already has it).
	packageResendEvery = 24 * time.Hour
	// packageUnsupportedBackoff: how long to wait after a server without
	// POST /api/edr/packages (404) before trying again.
	packageUnsupportedBackoff = 24 * time.Hour
)

// Agent ties together transport, collectors, and the detection engine.
type Agent struct {
	state   *config.State
	client  *transport.Client
	spool   *transport.Spool
	scanner vuln.Scanner
	engine  detect.Engine
	log     *slog.Logger
	updater *update.Updater

	// restartDetection signals the detection supervisor to stop and restart the
	// engine (re-reading the on-disk YARA signature file) after a rule update.
	restartDetection chan struct{}
	// yaraRescan signals the YARA scan loop to run its next pass over every
	// file, so files scanned under the old rules are checked against new ones.
	yaraRescan chan struct{}

	// YARA scan config (agent-driven, via osqueryi). Empty sigPath disables it.
	yaraOsqueryi string
	yaraSigPath  string
	yaraPaths    []string
	yaraExcludes []string // SQL LIKE patterns of paths to skip (the agent's own files)

	// Package inventory: the collector (packages.Collect; tests swap it), the
	// clock, and the back-off after a server that lacks the route.
	collectPackages     func(context.Context) packages.Result
	now                 func() time.Time
	packagesUnsupported time.Time // zero, or when to try a 404ing server again
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
		updater:          update.New(update.Options{State: state, Log: log}),
		state:            state,
		client:           client,
		spool:            spool,
		scanner:          vuln.NoopScanner{},
		engine:           detect.NoopEngine{},
		log:              log,
		restartDetection: make(chan struct{}, 1),
		yaraRescan:       make(chan struct{}, 1),
		collectPackages:  packages.Collect,
		now:              time.Now,
	}, nil
}

// WithScanner overrides the vulnerability scanner backend.
func (a *Agent) WithScanner(s vuln.Scanner) *Agent { a.scanner = s; return a }

// WithEngine overrides the detection engine backend.
func (a *Agent) WithEngine(e detect.Engine) *Agent { a.engine = e; return a }

// WithYaraScan enables the agent-driven YARA scan: it runs an on-demand osqueryi
// scan of paths against sigPath at startup and every YaraScanIntervalSec,
// evaluating matches through the engine. osqueryiBin/paths empty fall back to
// sensible defaults; empty sigPath leaves YARA disabled.
func (a *Agent) WithYaraScan(osqueryiBin, sigPath string, paths []string) *Agent {
	a.yaraOsqueryi = osqueryiBin
	a.yaraSigPath = sigPath
	if len(paths) == 0 {
		paths = osquery.DefaultYaraPaths()
	}
	a.yaraPaths = paths
	// Never scan the agent's own working files. grype's vulnerability database
	// in particular contains exploit/webshell signatures that otherwise
	// self-trigger the YARA rules (a high-severity false positive on
	// .../grype-*/vulnerability.db). Excludes are SQL LIKE patterns.
	a.yaraExcludes = []string{
		"%/siembox-endpoint/%", // agent namespace: grype DB cache + temp
		"%/siembox-edr/%",      // legacy namespace (pre-rebrand installs)
		a.state.Dir + "/%",     // state dir: yara sigs, osquery db, spool
	}
	return a
}

// Run enrolls if needed and then runs all loops until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	if !a.state.Enrolled() {
		if err := a.enrollWithRetry(ctx); err != nil {
			return err // only returns on ctx cancellation
		}
	}
	a.log.Info("agent running", "agent_id", a.state.Identity.AgentID, "version", version.Version)

	// Resolve a self-update left in flight by the previous process (succeeded if
	// we now run the target version, failed otherwise) so the first heartbeat
	// reports it, then act on any not-yet-attempted request in the cached config.
	a.updater.Startup()
	a.updater.Consider(ctx, a.state.Identity.Config.AgentUpdate)

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
	// Likewise the first YARA pass is already a full scan with these rules.
	select {
	case <-a.yaraRescan:
	default:
	}

	// Load rules up front so the YARA scan (which evaluates on demand) has them
	// before its first run; runDetection also (re)loads them.
	if err := a.engine.LoadRules(a.state.Identity.Config.Rules); err != nil {
		a.log.Warn("load rules", "err", err)
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
	if a.state.Settings.PackageInventoryEnabled() {
		interval := int(a.state.Settings.PackageInventoryInterval() / time.Second)
		run(func() { a.reportPackages(ctx); a.tick(ctx, interval, a.reportPackages) })
	} else {
		a.log.Info("package inventory disabled (package_inventory=false)")
	}
	run(func() { a.tick(ctx, spoolFlushSec, a.flushSpool) })
	run(func() { a.batchEvents(ctx, events) })
	run(func() { a.runDetection(ctx, events) })
	run(func() { a.runYaraScans(ctx, events) })

	<-ctx.Done()
	a.log.Info("shutting down")
	wg.Wait()
	a.updater.Wait()
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

// runYaraScans runs the agent-driven YARA scan immediately on startup and then
// every YaraScanIntervalSec, emitting a detection for each newly-seen matching
// file. It uses osqueryi (RunYaraScan) rather than an osqueryd scheduled query
// so detection runs right away and on a cadence the agent controls and logs.
// Dedups by path so a persistent matching file is alerted once per agent run.
//
// The startup pass reads every file under the watched paths; each later pass
// reads only files changed since the previous pass started, so a quiet host
// costs close to nothing per tick. A YARA rule update (yaraRescan) forces the
// next pass to read every file again.
func (a *Agent) runYaraScans(ctx context.Context, out chan<- models.Event) {
	if a.yaraSigPath == "" || len(a.yaraPaths) == 0 {
		return
	}
	seen := map[string]bool{}
	var since time.Time // zero: the next pass scans every file

	scan := func() {
		start := time.Now()
		full := since.IsZero()
		sctx, cancel := context.WithTimeout(ctx, osquery.YaraScanTimeout)
		defer cancel()
		records, err := osquery.RunYaraScan(sctx, a.yaraOsqueryi, osquery.YaraScan{
			Paths:        a.yaraPaths,
			SigPath:      a.yaraSigPath,
			Excludes:     a.yaraExcludes,
			MaxFileSize:  osquery.YaraMaxFileSize,
			ChangedSince: since,
		})
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if errors.Is(sctx.Err(), context.DeadlineExceeded) {
				// Advance the cutoff anyway: retrying the same pass every tick
				// would keep osqueryi pinned, the load this timeout exists to stop.
				a.log.Warn("yara scan timed out; next pass covers only files changed after it started",
					"timeout", osquery.YaraScanTimeout.String(), "full", full)
				since = start
				return
			}
			a.log.Debug("yara scan failed", "err", err)
			return
		}
		since = start
		fresh := make([]telemetry.Record, 0, len(records))
		for _, r := range records {
			p := r.Columns["path"]
			if p == "" || seen[p] {
				continue
			}
			seen[p] = true
			fresh = append(fresh, r)
		}
		a.log.Debug("yara scan complete", "full", full, "matches", len(records), "new", len(fresh),
			"took", time.Since(start).Round(time.Millisecond).String())
		for _, ev := range a.engine.Evaluate(ctx, fresh) {
			select {
			case out <- ev:
			case <-ctx.Done():
				return
			}
		}
	}

	scan() // immediate full scan at startup (catches files already present)
	ticker := time.NewTicker(time.Duration(osquery.YaraScanIntervalSec) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.yaraRescan:
			since = time.Time{}
		case <-ticker.C:
			scan()
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
	select {
	case a.yaraRescan <- struct{}{}:
	default:
	}
}

func (a *Agent) heartbeat(ctx context.Context) {
	a.updater.CheckPending()
	resp, err := a.client.Heartbeat(ctx, models.HeartbeatRequest{
		Status:       "online",
		AgentVersion: version.Version,
		Update:       a.updater.Report(),
	})
	if err != nil {
		a.log.Debug("heartbeat failed", "err", err)
		return
	}
	if resp.ConfigVersion > a.state.Identity.Config.ConfigVersion {
		a.log.Info("new config available", "version", resp.ConfigVersion)
		a.pollConfig(ctx)
	}
	a.considerUpdate(ctx)
}

// considerUpdate prunes a finished update report the server no longer asks
// about and starts any new update request from the current config. The attempt
// runs in its own goroutine, so this never blocks the heartbeat.
func (a *Agent) considerUpdate(ctx context.Context) {
	var req *models.AgentUpdateRequest
	a.state.View(func(id *config.Identity) { req = id.Config.AgentUpdate })
	if req == nil {
		a.updater.Prune("")
	} else {
		a.updater.Prune(req.RequestID)
	}
	a.updater.Consider(ctx, req)
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
	if err := a.state.Mutate(func(id *config.Identity) { id.Config = cfg }); err != nil {
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

// reportPackages reads the host's package databases and sends the list to the
// server when it changed since the last accepted snapshot (or a day has
// passed); otherwise it sends only the hash, which the server answers without
// touching its rows and which tells it the agent still reports. Not spooled:
// the next run supersedes a failed send. A server that answers 404 predates the
// route: logged once, then retried after packageUnsupportedBackoff.
func (a *Agent) reportPackages(ctx context.Context) {
	now := a.now()
	if now.Before(a.packagesUnsupported) {
		return
	}
	started := time.Now()
	res := a.collectPackages(ctx)
	for name, err := range res.Errors {
		a.log.Warn("package inventory source failed", "source", name, "err", err)
	}
	if len(res.Packages) == 0 {
		// Nothing to report (no known package database, or every source
		// failed). Never send an empty list: it would clear the server's.
		a.log.Debug("package inventory found no packages", "sources", res.Sources)
		return
	}
	hash := packages.Hash(res.Packages)
	var lastHash string
	var lastSent time.Time
	a.state.View(func(id *config.Identity) { lastHash, lastSent = id.PackagesHash, id.PackagesSentAt })

	report := models.PackageReport{AgentID: a.state.Identity.AgentID, SnapshotHash: hash, CollectedAt: now.UTC()}
	full := hash != lastHash || now.Sub(lastSent) >= packageResendEvery
	if full {
		report.Packages = res.Packages
	}
	resp, err := a.client.SendPackages(ctx, report)
	if err == nil && !full && resp.SnapshotRequired {
		// The server does not have our snapshot (a restored database, say).
		report.Packages = res.Packages
		full = true
		resp, err = a.client.SendPackages(ctx, report)
	}
	var se *transport.StatusError
	if errors.As(err, &se) && se.Status == 404 {
		a.packagesUnsupported = now.Add(packageUnsupportedBackoff)
		a.log.Info("server does not accept package inventory yet (404 on /api/edr/packages; update SIEMBox); will retry",
			"retry_in", packageUnsupportedBackoff.String())
		return
	}
	if err != nil {
		a.log.Debug("package inventory send failed; next run retries", "err", err)
		return
	}
	if !resp.Accepted {
		a.log.Debug("package inventory not accepted", "response", resp)
		return
	}
	if err := a.state.Mutate(func(id *config.Identity) {
		id.PackagesHash = hash
		if full {
			id.PackagesSentAt = now
		}
	}); err != nil {
		a.log.Warn("persist package inventory state", "err", err)
	}
	if full && !resp.Unchanged {
		a.log.Info("package inventory sent", "packages", len(res.Packages), "removed", resp.Removed,
			"sources", res.Sources, "took", time.Since(started).Round(time.Millisecond).String())
	} else {
		a.log.Debug("package inventory unchanged", "packages", len(res.Packages))
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
