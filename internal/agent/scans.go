package agent

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cladkins/siembox-endpoint/internal/models"
	"github.com/cladkins/siembox-endpoint/internal/transport"
)

// Scan coordination: every scan the agent runs (vulnerability, YARA, package
// inventory, host inventory), whether its own schedule or the console asked
// for it, goes through runScan, which
//   - never runs two scans of one type at once: a console request that
//     arrives while that scan is running waits and runs right after it (all
//     requests that waited share that one run); a scheduled run that finds
//     one running is skipped;
//   - reports the run to POST /api/edr/scans: a console request is moved to
//     running (the server may answer that it was cancelled, and it is not
//     run), then finished with a summary; a scheduled or startup run creates
//     its own history row. A server without the route (404) gets no reports
//     for scanReportBackoff; the scans themselves run regardless.
// Console requests arrive in the heartbeat response (handleScanRequests).

const (
	// scanReportBackoff: how long to stop reporting after a server without
	// POST /api/edr/scans (404).
	scanReportBackoff = 24 * time.Hour
	// handledScanTTL: how long a console scan id is remembered, so a request
	// the heartbeat keeps serving (queued behind a running scan) runs once.
	handledScanTTL = 48 * time.Hour
	// maxScanError: the server keeps at most this many characters.
	maxScanError = 500
)

// errScanUnavailable marks a scanner this host cannot run (grype missing,
// YARA or package inventory disabled). A scheduled run of it is not recorded.
var errScanUnavailable = errors.New("scan not available on this host")

// scanRun is one execution of a scan.
type scanRun struct {
	Type    string
	Trigger string
	// ScanID links the scan's payload (vulnerabilities, packages, inventory)
	// to its history row; empty when the run has no row (yet).
	ScanID string
	// Full: a YARA pass over every file rather than only changed ones.
	Full bool
}

// scanResult is what a scan function returns. Record false: a scheduled run
// that is not worth a history row (an incremental YARA pass with no hits).
type scanResult struct {
	Summary map[string]any
	Record  bool
}

type scanState struct {
	running bool
	queued  []string // console scan ids waiting for the next run
}

// scanCoordinator holds per-type run state and the console ids already seen.
type scanCoordinator struct {
	mu       sync.Mutex
	state    map[string]*scanState
	handled  map[string]time.Time
	wg       sync.WaitGroup
	noReport time.Time // zero, or until when not to report (404ing server)
}

func newScanCoordinator() *scanCoordinator {
	return &scanCoordinator{state: map[string]*scanState{}, handled: map[string]time.Time{}}
}

func (c *scanCoordinator) get(t string) *scanState {
	st := c.state[t]
	if st == nil {
		st = &scanState{}
		c.state[t] = st
	}
	return st
}

// scanFunc runs one scan type.
func (a *Agent) scanFunc(t string) func(context.Context, *scanRun) (scanResult, error) {
	switch t {
	case models.ScanTypeVuln:
		return a.vulnScan
	case models.ScanTypeYara:
		return a.yaraScan
	case models.ScanTypePackages:
		return a.packageScan
	case models.ScanTypeInventory:
		return a.inventoryScan
	}
	return nil
}

// recordsStart: whether a scheduled run of this type reports its start (and
// so gets a history row before it finishes). An incremental YARA pass every
// minute does not; it is recorded only when it finds something.
func (a *Agent) recordsStart(run *scanRun) bool {
	return run.Type != models.ScanTypeYara || run.Full
}

// handleScanRequests starts each console request from a heartbeat it has not
// seen yet, each in its own goroutine (runScan keeps a type's runs serial).
func (a *Agent) handleScanRequests(ctx context.Context, reqs []models.ScanRequest) {
	now := a.now()
	c := a.scans
	c.mu.Lock()
	for id, at := range c.handled {
		if now.Sub(at) > handledScanTTL {
			delete(c.handled, id)
		}
	}
	var fresh []models.ScanRequest
	for _, r := range reqs {
		if r.ScanID == "" || !c.handled[r.ScanID].IsZero() {
			continue
		}
		c.handled[r.ScanID] = now
		fresh = append(fresh, r)
	}
	c.mu.Unlock()

	for _, r := range fresh {
		r := r
		if a.scanFunc(r.ScanType) == nil {
			a.log.Warn("unknown on-demand scan type; reporting it failed", "scan_type", r.ScanType, "scan_id", r.ScanID)
			a.reportScan(ctx, models.ScanReport{
				ScanID: r.ScanID, ScanType: r.ScanType, Trigger: models.ScanTriggerConsole,
				Status: models.ScanStatusFailed, Error: "this agent version does not support scan type " + r.ScanType,
			})
			continue
		}
		a.log.Info("on-demand scan requested", "scan_type", r.ScanType, "scan_id", r.ScanID)
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			a.runScan(ctx, r.ScanType, models.ScanTriggerConsole, []string{r.ScanID})
		}()
	}
}

// runScan runs scan type t now, unless one is already running: then console
// ids are queued for a run right after it and a scheduled run is skipped.
func (a *Agent) runScan(ctx context.Context, t, trigger string, ids []string) {
	c := a.scans
	c.mu.Lock()
	st := c.get(t)
	if st.running {
		if len(ids) > 0 {
			st.queued = append(st.queued, ids...)
			a.log.Info("scan already running; on-demand request runs right after it", "scan_type", t)
		} else {
			a.log.Debug("scan already running; skipping this scheduled run", "scan_type", t, "trigger", trigger)
		}
		c.mu.Unlock()
		return
	}
	st.running = true
	c.mu.Unlock()

	for {
		a.execScan(ctx, t, trigger, ids)
		c.mu.Lock()
		if len(st.queued) == 0 || ctx.Err() != nil {
			// Queued ids left at shutdown stay pending on the server and are
			// served again after a restart.
			st.running = false
			c.mu.Unlock()
			return
		}
		ids, st.queued = st.queued, nil
		trigger = models.ScanTriggerConsole
		c.mu.Unlock()
	}
}

// execScan runs one scan and reports it.
func (a *Agent) execScan(ctx context.Context, t, trigger string, ids []string) {
	fn := a.scanFunc(t)
	run := &scanRun{Type: t, Trigger: trigger}
	if t == models.ScanTypeYara {
		run.Full = a.yaraNextFull(trigger)
	}
	started := a.now().UTC()

	// Console requests: tell the server they started; drop any it cancelled.
	if trigger == models.ScanTriggerConsole {
		live := ids[:0:0]
		for _, id := range ids {
			resp, ok := a.reportScan(ctx, models.ScanReport{
				ScanID: id, ScanType: t, Trigger: trigger, Status: models.ScanStatusRunning, StartedAt: &started,
			})
			if ok && !resp.Accepted && resp.Status != models.ScanStatusRunning {
				a.log.Info("on-demand scan not run", "scan_type", t, "scan_id", id, "status", resp.Status)
				continue
			}
			live = append(live, id)
		}
		if len(live) == 0 {
			return
		}
		ids = live
		run.ScanID = ids[0]
	} else if a.recordsStart(run) && a.scanAvailable(t) {
		resp, ok := a.reportScan(ctx, models.ScanReport{
			ScanType: t, Trigger: trigger, Status: models.ScanStatusRunning, StartedAt: &started,
		})
		if ok && resp.ScanID != "" {
			ids = []string{resp.ScanID}
			run.ScanID = resp.ScanID
		}
	}

	res, err := fn(ctx, run)
	if ctx.Err() != nil {
		// Shutting down mid-scan: the row stays running and expires on the
		// server; a console request is not re-run.
		return
	}
	if errors.Is(err, errScanUnavailable) && trigger != models.ScanTriggerConsole {
		return
	}
	if len(ids) == 0 && !res.Record {
		// A scheduled run without a history row that is not worth one (an
		// incremental YARA pass that found nothing, or failed: it retries in
		// a minute).
		if err != nil {
			a.log.Debug("scan failed", "scan_type", t, "trigger", trigger, "err", err)
		}
		return
	}
	completed := a.now().UTC()
	report := models.ScanReport{
		ScanType: t, Trigger: trigger, Status: models.ScanStatusSucceeded,
		StartedAt: &started, CompletedAt: &completed, Summary: res.Summary,
	}
	if err != nil {
		report.Status = models.ScanStatusFailed
		report.Error = clip(err.Error(), maxScanError)
		a.log.Warn("scan failed", "scan_type", t, "trigger", trigger, "err", err)
	}
	if len(ids) == 0 {
		// A scheduled run without a start row: one report creates its row.
		a.reportScan(ctx, report)
		return
	}
	for _, id := range ids {
		r := report
		r.ScanID = id
		a.reportScan(ctx, r)
	}
}

// reportScan sends one report; ok is false when it could not be delivered
// (best-effort: the scan history is informational).
func (a *Agent) reportScan(ctx context.Context, r models.ScanReport) (models.ScanReportResponse, bool) {
	c := a.scans
	now := a.now()
	c.mu.Lock()
	skip := now.Before(c.noReport)
	c.mu.Unlock()
	if skip {
		return models.ScanReportResponse{}, false
	}
	r.AgentID = a.state.Identity.AgentID
	resp, err := a.client.ReportScan(ctx, r)
	var se *transport.StatusError
	if errors.As(err, &se) && se.Status == 404 && r.ScanID == "" {
		c.mu.Lock()
		c.noReport = now.Add(scanReportBackoff)
		c.mu.Unlock()
		a.log.Info("server does not record scan history yet (404 on /api/edr/scans; update SIEMBox); will retry",
			"retry_in", scanReportBackoff.String())
		return resp, false
	}
	if err != nil {
		a.log.Debug("scan report failed", "scan_type", r.ScanType, "status", r.Status, "err", err)
		return resp, false
	}
	return resp, true
}

// scanAvailable: whether this host can run scan type t at all.
func (a *Agent) scanAvailable(t string) bool {
	switch t {
	case models.ScanTypeVuln:
		return a.scanner.Name() != "noop"
	case models.ScanTypeYara:
		return a.yaraSigPath != "" && len(a.yaraPaths) > 0
	case models.ScanTypePackages:
		return a.state.Settings.PackageInventoryEnabled()
	}
	return true
}

// unavailableError explains why a scanner cannot run; errors.Is matches
// errScanUnavailable. Its text is what the scan history shows.
type unavailableError struct{ msg string }

func (e *unavailableError) Error() string        { return e.msg }
func (e *unavailableError) Is(target error) bool { return target == errScanUnavailable }

func unavailable(format string, args ...any) error {
	return &unavailableError{msg: fmt.Sprintf(format, args...)}
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
