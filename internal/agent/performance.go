package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cladkins/siembox-endpoint/internal/config"
	"github.com/cladkins/siembox-endpoint/internal/metrics"
	"github.com/cladkins/siembox-endpoint/internal/models"
	"github.com/cladkins/siembox-endpoint/internal/transport"
)

// Machine performance reporting (POST /api/edr/metrics): a sample about
// once a minute, the top processes every few minutes, sent in a batch about
// once a minute. Unsent data waits in a bounded buffer (kept across a
// restart in metrics-pending.json), so a short outage leaves no gap in the
// server's charts; past the bound the oldest is dropped.
const (
	defaultPerfSampleSec  = 60
	defaultPerfSendSec    = 60
	defaultPerfProcessSec = 300

	// perfMaxPending: samples kept while the server is unreachable (3 hours
	// at one a minute). perfMaxPendingProcs: process snapshots kept.
	perfMaxPending      = 180
	perfMaxPendingProcs = 12
	// perfMaxPendingAge: buffered data older than this is not sent after a
	// restart (the server keeps raw samples 7 days; this keeps the replay short).
	perfMaxPendingAge = 6 * time.Hour
	// perfUnsupportedBackoff: after a 404 (a server without the route),
	// nothing is sent for this long.
	perfUnsupportedBackoff = time.Hour

	perfPendingFile = "metrics-pending.json"
)

// perfSettings is the effective performance config: the local switches
// (agent.json) AND the server's (AgentConfig.Performance, the endpoint's
// scan policy).
type perfSettings struct {
	enabled, processes bool
	sample, send, proc time.Duration
	top                int
}

func clampSec(v, def, lo, hi int) time.Duration {
	if v <= 0 {
		v = def
	}
	if v < lo {
		v = lo
	}
	if v > hi {
		v = hi
	}
	return time.Duration(v) * time.Second
}

func effectivePerf(local config.Settings, server *models.PerformanceConfig) perfSettings {
	p := perfSettings{
		enabled:   local.PerformanceMetricsEnabled(),
		processes: local.PerformanceProcessesEnabled(),
		sample:    defaultPerfSampleSec * time.Second,
		send:      defaultPerfSendSec * time.Second,
		proc:      defaultPerfProcessSec * time.Second,
		top:       metrics.DefaultTopProcesses,
	}
	if server != nil {
		p.enabled = p.enabled && server.Enabled
		p.processes = p.processes && server.Processes
		p.sample = clampSec(server.SampleIntervalSec, defaultPerfSampleSec, 30, 600)
		p.send = clampSec(server.SendIntervalSec, defaultPerfSendSec, 60, 900)
		p.proc = clampSec(server.ProcessIntervalSec, defaultPerfProcessSec, 60, 3600)
		if server.TopProcesses > 0 {
			p.top = min(server.TopProcesses, metrics.MaxTopProcesses)
		}
	}
	if p.send < p.sample {
		p.send = p.sample
	}
	p.processes = p.processes && p.enabled
	return p
}

// perfState is the metrics loop's buffer and back-off.
type perfState struct {
	mu          sync.Mutex
	samples     []models.MetricSample
	procs       []models.ProcessSnapshot
	unsupported time.Time // zero, or when to try a 404ing server again
	dropped     int       // samples dropped at the bound since the last successful send
}

func (s *perfState) add(sample *models.MetricSample, snap *models.ProcessSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sample != nil {
		s.samples = append(s.samples, *sample)
		if over := len(s.samples) - perfMaxPending; over > 0 {
			s.samples = append([]models.MetricSample(nil), s.samples[over:]...)
			s.dropped += over
		}
	}
	if snap != nil {
		s.procs = append(s.procs, *snap)
		if over := len(s.procs) - perfMaxPendingProcs; over > 0 {
			s.procs = append([]models.ProcessSnapshot(nil), s.procs[over:]...)
		}
	}
}

// perfConfig is the effective config from the current server config.
func (a *Agent) perfConfig() perfSettings {
	var server *models.PerformanceConfig
	a.state.View(func(id *config.Identity) { server = id.Config.Performance })
	return effectivePerf(a.state.Settings, server)
}

// perfCapable: this agent reports performance (a supported OS, not turned
// off in agent.json). Sent as CapabilityPerfMetrics.
func (a *Agent) perfCapable() bool {
	return a.perf != nil && a.state.Settings.PerformanceMetricsEnabled()
}

// runPerformance samples, buffers and sends until ctx ends.
func (a *Agent) runPerformance(ctx context.Context) {
	if a.perf == nil {
		return
	}
	if !a.state.Settings.PerformanceMetricsEnabled() {
		a.log.Info("performance metrics disabled (performance_metrics=false)")
		return
	}
	cfg := a.perfConfig()
	a.perf.Prime(cfg.processes)
	a.loadPendingMetrics()
	defer a.savePendingMetrics()

	lastProc := a.now()
	var lastSend time.Time
	timer := time.NewTimer(cfg.sample)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		was := cfg
		cfg = a.perfConfig()
		if was.enabled != cfg.enabled || was.processes != cfg.processes {
			a.log.Info("performance metrics setting changed", "enabled", cfg.enabled, "processes", cfg.processes)
		}
		if cfg.enabled {
			a.perfTick(ctx, cfg, &lastProc, &lastSend)
		} else {
			// Off on the server: nothing is collected, and what was waiting is not sent.
			a.perfState.mu.Lock()
			a.perfState.samples, a.perfState.procs = nil, nil
			a.perfState.mu.Unlock()
		}
		timer.Reset(cfg.sample)
	}
}

func (a *Agent) perfTick(ctx context.Context, cfg perfSettings, lastProc, lastSend *time.Time) {
	now := a.now()
	sample, err := a.perf.Sample()
	if err != nil {
		a.log.Debug("performance sample failed", "err", err)
		return
	}
	var snap *models.ProcessSnapshot
	if cfg.processes && now.Sub(*lastProc) >= cfg.proc-time.Second {
		*lastProc = now
		if snap, err = a.perf.Processes(cfg.top, sample.MemTotal); err != nil {
			a.log.Debug("process snapshot failed", "err", err)
			snap = nil
		}
	}
	a.perfState.add(&sample, snap)
	// The small slack lets a send ride the same tick when both intervals match.
	if now.Sub(*lastSend) >= cfg.send-5*time.Second {
		*lastSend = now
		a.sendMetrics(ctx)
	}
}

// sendMetrics sends everything buffered in one batch; on success the sent
// part leaves the buffer, otherwise it waits for the next send.
func (a *Agent) sendMetrics(ctx context.Context) {
	st := &a.perfState
	st.mu.Lock()
	if a.now().Before(st.unsupported) || len(st.samples)+len(st.procs) == 0 {
		st.mu.Unlock()
		return
	}
	batch := models.MetricsBatch{
		AgentID:   a.state.Identity.AgentID,
		Samples:   append([]models.MetricSample(nil), st.samples...),
		Processes: append([]models.ProcessSnapshot(nil), st.procs...),
	}
	st.mu.Unlock()
	if batch.Samples == nil {
		batch.Samples = []models.MetricSample{}
	}

	resp, err := a.client.SendMetrics(ctx, batch)
	var se *transport.StatusError
	if errors.As(err, &se) && se.Status == 404 {
		st.mu.Lock()
		st.unsupported = a.now().Add(perfUnsupportedBackoff)
		st.samples, st.procs = nil, nil
		st.mu.Unlock()
		a.log.Info("server does not accept performance metrics yet (404 on /api/edr/metrics; update SIEMBox); will retry",
			"retry_in", perfUnsupportedBackoff.String())
		return
	}
	if errors.As(err, &se) && se.Status == 400 {
		// The server refused the batch as a whole; resending it would fail forever.
		a.log.Warn("server rejected performance metrics batch; dropping it", "err", err)
		a.dropSent(len(batch.Samples), len(batch.Processes))
		return
	}
	if err != nil {
		a.log.Debug("performance metrics send failed; kept for the next send", "err", err, "pending", len(batch.Samples))
		return
	}
	a.dropSent(len(batch.Samples), len(batch.Processes))
	if resp.Rejected > 0 {
		a.log.Debug("server rejected some performance samples", "rejected", resp.Rejected)
	}
}

// dropSent removes the first n samples and p snapshots (the ones just sent;
// anything added meanwhile stays).
func (a *Agent) dropSent(n, p int) {
	st := &a.perfState
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.dropped > 0 {
		a.log.Info("performance samples were dropped while the server was unreachable", "dropped", st.dropped)
		st.dropped = 0
	}
	if n > len(st.samples) {
		n = len(st.samples)
	}
	if p > len(st.procs) {
		p = len(st.procs)
	}
	st.samples = append([]models.MetricSample(nil), st.samples[n:]...)
	st.procs = append([]models.ProcessSnapshot(nil), st.procs[p:]...)
}

type pendingMetrics struct {
	Samples   []models.MetricSample    `json:"samples"`
	Processes []models.ProcessSnapshot `json:"processes"`
}

// savePendingMetrics writes what is still unsent at shutdown.
func (a *Agent) savePendingMetrics() {
	st := &a.perfState
	st.mu.Lock()
	p := pendingMetrics{Samples: st.samples, Processes: st.procs}
	st.mu.Unlock()
	path := filepath.Join(a.state.Dir, perfPendingFile)
	if len(p.Samples)+len(p.Processes) == 0 {
		_ = os.Remove(path)
		return
	}
	raw, err := json.Marshal(p)
	if err == nil {
		err = os.WriteFile(path, raw, 0o600)
	}
	if err != nil {
		a.log.Warn("save pending performance metrics", "err", err)
	}
}

// loadPendingMetrics takes back what the previous run left unsent (recent
// enough to be worth sending), then removes the file.
func (a *Agent) loadPendingMetrics() {
	path := filepath.Join(a.state.Dir, perfPendingFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	_ = os.Remove(path)
	var p pendingMetrics
	if json.Unmarshal(raw, &p) != nil {
		return
	}
	cutoff := a.now().Add(-perfMaxPendingAge)
	for i := range p.Samples {
		if p.Samples[i].Timestamp.After(cutoff) {
			a.perfState.add(&p.Samples[i], nil)
		}
	}
	for i := range p.Processes {
		if p.Processes[i].Timestamp.After(cutoff) {
			a.perfState.add(nil, &p.Processes[i])
		}
	}
}
