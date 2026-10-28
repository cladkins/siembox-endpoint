package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cladkins/siembox-endpoint/internal/config"
	"github.com/cladkins/siembox-endpoint/internal/models"
)

// fakeMetricsServer mimics POST /api/edr/metrics and records each batch.
type fakeMetricsServer struct {
	mu      sync.Mutex
	status  int
	batches []models.MetricsBatch
}

func (f *fakeMetricsServer) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Path != "/api/edr/metrics" || r.Method != http.MethodPost || r.Header.Get("X-Agent-ID") != "agent-1" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var b models.MetricsBatch
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			t.Errorf("decode: %v", err)
		}
		f.batches = append(f.batches, b)
		if f.status != 0 {
			w.WriteHeader(f.status)
			w.Write([]byte(`{"error":"x"}`))
			return
		}
		json.NewEncoder(w).Encode(models.MetricsResponse{Accepted: len(b.Samples), Processes: len(b.Processes)})
	}
}

func (f *fakeMetricsServer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.batches)
}

func sampleAt(t time.Time) *models.MetricSample {
	return &models.MetricSample{Timestamp: t, CPUPct: 12.5, MemTotal: 100, MemUsed: 50}
}

func pending(a *Agent) (int, int) {
	a.perfState.mu.Lock()
	defer a.perfState.mu.Unlock()
	return len(a.perfState.samples), len(a.perfState.procs)
}

func TestSendMetricsKeepsBatchUntilAccepted(t *testing.T) {
	fake := &fakeMetricsServer{status: 503}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()
	a := newTestAgent(t, srv.URL, models.AgentConfig{})
	base := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return base }

	a.perfState.add(sampleAt(base), &models.ProcessSnapshot{Timestamp: base})
	a.sendMetrics(context.Background())
	if n, p := pending(a); n != 1 || p != 1 {
		t.Fatalf("a failed send must keep the batch: %d %d", n, p)
	}
	a.perfState.add(sampleAt(base.Add(time.Minute)), nil)
	fake.status = 0
	a.sendMetrics(context.Background())
	if n, p := pending(a); n != 0 || p != 0 {
		t.Fatalf("an accepted send must empty the buffer: %d %d", n, p)
	}
	last := fake.batches[len(fake.batches)-1]
	if len(last.Samples) != 2 || len(last.Processes) != 1 || last.AgentID != "agent-1" {
		t.Fatalf("batch %+v", last)
	}
	if !last.Samples[0].Timestamp.Before(last.Samples[1].Timestamp) {
		t.Fatal("samples must go oldest first")
	}
	// Nothing buffered: no request at all.
	before := fake.count()
	a.sendMetrics(context.Background())
	if fake.count() != before {
		t.Fatal("an empty buffer must not be sent")
	}
}

func TestSendMetricsBacksOffOn404(t *testing.T) {
	fake := &fakeMetricsServer{status: 404}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()
	a := newTestAgent(t, srv.URL, models.AgentConfig{})
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return now }

	a.perfState.add(sampleAt(now), nil)
	a.sendMetrics(context.Background())
	if n, _ := pending(a); n != 0 {
		t.Fatal("an old server's buffer is dropped, not grown")
	}
	a.perfState.add(sampleAt(now), nil)
	now = now.Add(30 * time.Minute)
	a.sendMetrics(context.Background())
	if fake.count() != 1 {
		t.Fatalf("within the back-off nothing is sent; requests=%d", fake.count())
	}
	now = now.Add(31 * time.Minute)
	fake.status = 0
	a.sendMetrics(context.Background())
	if fake.count() != 2 {
		t.Fatalf("after the back-off it tries again; requests=%d", fake.count())
	}
}

func TestPerfBufferIsBounded(t *testing.T) {
	a := newTestAgent(t, "http://127.0.0.1:1", models.AgentConfig{})
	base := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	for i := 0; i < perfMaxPending+40; i++ {
		a.perfState.add(sampleAt(base.Add(time.Duration(i)*time.Minute)), &models.ProcessSnapshot{Timestamp: base})
	}
	n, p := pending(a)
	if n != perfMaxPending || p != perfMaxPendingProcs || a.perfState.dropped != 40 {
		t.Fatalf("got %d samples %d snapshots, dropped %d", n, p, a.perfState.dropped)
	}
	// The oldest go first.
	if got := a.perfState.samples[0].Timestamp; !got.Equal(base.Add(40 * time.Minute)) {
		t.Fatalf("oldest kept %v", got)
	}
}

func TestPendingMetricsSurviveRestart(t *testing.T) {
	a := newTestAgent(t, "http://127.0.0.1:1", models.AgentConfig{})
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return now }
	a.perfState.add(sampleAt(now.Add(-10*time.Hour)), nil) // too old to replay
	a.perfState.add(sampleAt(now.Add(-time.Minute)), &models.ProcessSnapshot{Timestamp: now.Add(-time.Minute)})
	a.savePendingMetrics()

	b := newTestAgent(t, "http://127.0.0.1:1", models.AgentConfig{})
	b.state.Dir = a.state.Dir
	b.now = a.now
	b.loadPendingMetrics()
	if n, p := pending(b); n != 1 || p != 1 {
		t.Fatalf("restored %d samples %d snapshots", n, p)
	}
	if _, err := os.Stat(filepath.Join(a.state.Dir, perfPendingFile)); !os.IsNotExist(err) {
		t.Fatal("the pending file must be removed once read")
	}
}

func TestEffectivePerf(t *testing.T) {
	off := false
	// No server config (an older SIEMBox): on, with the defaults.
	p := effectivePerf(config.Settings{}, nil)
	if !p.enabled || !p.processes || p.sample != time.Minute || p.proc != 5*time.Minute || p.top != 10 {
		t.Fatalf("defaults %+v", p)
	}
	// The server turns processes off; intervals are clamped.
	p = effectivePerf(config.Settings{}, &models.PerformanceConfig{Enabled: true, Processes: false, SampleIntervalSec: 5, SendIntervalSec: 9999, TopProcesses: 99})
	if !p.enabled || p.processes || p.sample != 30*time.Second || p.send != 900*time.Second || p.top != 25 {
		t.Fatalf("clamped %+v", p)
	}
	// Off on the server: nothing runs.
	p = effectivePerf(config.Settings{}, &models.PerformanceConfig{Enabled: false, Processes: true})
	if p.enabled || p.processes {
		t.Fatalf("server off %+v", p)
	}
	// Off locally wins over the server.
	p = effectivePerf(config.Settings{PerformanceMetrics: &off}, &models.PerformanceConfig{Enabled: true, Processes: true})
	if p.enabled || p.processes {
		t.Fatalf("local off %+v", p)
	}
	p = effectivePerf(config.Settings{PerformanceProcesses: &off}, &models.PerformanceConfig{Enabled: true, Processes: true})
	if !p.enabled || p.processes {
		t.Fatalf("local processes off %+v", p)
	}
}

func TestPerfTickSamplesAndSends(t *testing.T) {
	fake := &fakeMetricsServer{}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()
	a := newTestAgent(t, srv.URL, models.AgentConfig{})
	if a.perf == nil {
		t.Skip("no collector on this OS")
	}
	cfg := effectivePerf(a.state.Settings, nil)
	a.perf.Prime(true)
	lastProc := time.Now().Add(-time.Hour)
	var lastSend time.Time
	a.perfTick(context.Background(), cfg, &lastProc, &lastSend)
	if fake.count() != 1 {
		t.Fatalf("requests %d", fake.count())
	}
	b := fake.batches[0]
	if len(b.Samples) != 1 || b.Samples[0].MemTotal == 0 || len(b.Processes) != 1 || len(b.Processes[0].ByMem) == 0 {
		t.Fatalf("batch %+v", b)
	}
	// Within the send interval the next sample only waits in the buffer.
	a.perfTick(context.Background(), cfg, &lastProc, &lastSend)
	if fake.count() != 1 {
		t.Fatalf("sent early: %d", fake.count())
	}
	if n, p := pending(a); n != 1 || p != 0 {
		t.Fatalf("pending %d %d", n, p)
	}
}

func TestHeartbeatAdvertisesPerfCapability(t *testing.T) {
	var got models.HeartbeatRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		w.Write([]byte(`{"config_version":0}`))
	}))
	defer srv.Close()
	a := newTestAgent(t, srv.URL, models.AgentConfig{})
	a.heartbeat(context.Background())
	has := false
	for _, c := range got.Capabilities {
		has = has || c == models.CapabilityPerfMetrics
	}
	if has != (a.perf != nil) {
		t.Fatalf("capabilities %v (collector %v)", got.Capabilities, a.perf != nil)
	}
	off := false
	a.state.Settings.PerformanceMetrics = &off
	a.heartbeat(context.Background())
	for _, c := range got.Capabilities {
		if c == models.CapabilityPerfMetrics {
			t.Fatal("turned off locally: no capability")
		}
	}
}
