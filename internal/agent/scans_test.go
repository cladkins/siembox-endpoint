package agent

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cladkins/siembox-endpoint/internal/models"
	"github.com/cladkins/siembox-endpoint/internal/packages"
	"github.com/cladkins/siembox-endpoint/internal/telemetry"
	"github.com/cladkins/siembox-endpoint/internal/telemetry/osquery"
)

// fakeScanServer mimics the SIEMBox routes a scan touches: heartbeat (serving
// scan_requests), POST /api/edr/scans, and the payload routes, recording what
// arrives.
type fakeScanServer struct {
	mu         sync.Mutex
	scansCode  int                                               // non-zero: answer /scans with this status
	startReply func(models.ScanReport) models.ScanReportResponse // nil: accept
	requests   []models.ScanRequest                              // served in every heartbeat
	config     models.AgentConfig                                // served by GET .../config
	heartbeats []models.HeartbeatRequest
	reports    []models.ScanReport
	packages   []models.PackageReport
	inventory  []models.InventoryRequest
	vulns      []models.VulnBatch
	nextID     int
}

func (f *fakeScanServer) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		body := io.Reader(r.Body)
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Errorf("gzip: %v", err)
				return
			}
			body = zr
		}
		dec := json.NewDecoder(body)
		switch {
		case strings.HasSuffix(r.URL.Path, "/config"):
			json.NewEncoder(w).Encode(f.config)
		case strings.HasSuffix(r.URL.Path, "/heartbeat"):
			var hb models.HeartbeatRequest
			_ = dec.Decode(&hb)
			f.heartbeats = append(f.heartbeats, hb)
			json.NewEncoder(w).Encode(models.HeartbeatResponse{ScanRequests: f.requests})
		case r.URL.Path == "/api/edr/scans":
			if f.scansCode != 0 {
				w.WriteHeader(f.scansCode)
				return
			}
			var rep models.ScanReport
			if err := dec.Decode(&rep); err != nil {
				t.Errorf("decode scan report: %v", err)
			}
			f.reports = append(f.reports, rep)
			resp := models.ScanReportResponse{ScanID: rep.ScanID, Status: rep.Status, Accepted: true}
			if rep.ScanID == "" {
				f.nextID++
				resp.ScanID = fmt.Sprintf("row-%d", f.nextID)
			}
			if rep.Status == models.ScanStatusRunning && f.startReply != nil {
				resp = f.startReply(rep)
			}
			json.NewEncoder(w).Encode(resp)
		case r.URL.Path == "/api/edr/packages":
			var rep models.PackageReport
			_ = dec.Decode(&rep)
			f.packages = append(f.packages, rep)
			json.NewEncoder(w).Encode(models.PackageReportResponse{Accepted: true, Stored: len(rep.Packages)})
		case r.URL.Path == "/api/edr/inventory":
			var inv models.InventoryRequest
			_ = dec.Decode(&inv)
			f.inventory = append(f.inventory, inv)
			w.WriteHeader(http.StatusAccepted)
		case r.URL.Path == "/api/edr/vulnerabilities":
			var b models.VulnBatch
			_ = dec.Decode(&b)
			f.vulns = append(f.vulns, b)
			w.WriteHeader(http.StatusAccepted)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}
}

func (f *fakeScanServer) takeReports() []models.ScanReport {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.reports
	f.reports = nil
	return r
}

func newScanTestAgent(t *testing.T) (*Agent, *fakeScanServer) {
	t.Helper()
	fake := &fakeScanServer{}
	srv := httptest.NewServer(fake.handler(t))
	t.Cleanup(srv.Close)
	a := newTestAgent(t, srv.URL, models.AgentConfig{})
	a.collectPackages = func(context.Context) packages.Result {
		return packages.Result{Packages: []models.Package{{Name: "bash", Version: "5.2", Type: "deb"}}}
	}
	return a, fake
}

func statuses(reps []models.ScanReport) string {
	var out []string
	for _, r := range reps {
		out = append(out, r.ScanType+":"+r.ScanID+":"+r.Status)
	}
	return strings.Join(out, ",")
}

func TestConsoleRequestRunsOnceAndIsReported(t *testing.T) {
	a, fake := newScanTestAgent(t)
	fake.requests = []models.ScanRequest{{ScanID: "req-1", ScanType: models.ScanTypePackages}}
	ctx := context.Background()

	// Served by two heartbeats in a row (the server keeps serving it until the
	// start report lands): it runs once.
	a.heartbeat(ctx)
	a.scans.wg.Wait()
	a.heartbeat(ctx)
	a.scans.wg.Wait()

	if len(fake.heartbeats) != 2 || strings.Join(fake.heartbeats[0].Capabilities, ",") != models.CapabilityAdhocScans+","+models.CapabilityPolicyScans {
		t.Fatalf("heartbeat capabilities: %+v", fake.heartbeats)
	}
	if len(fake.packages) != 1 || !fake.packages[0].Force || fake.packages[0].ScanID != "req-1" || len(fake.packages[0].Packages) != 1 {
		t.Fatalf("package reports: %+v", fake.packages)
	}
	reps := fake.takeReports()
	if got := statuses(reps); got != "packages:req-1:running,packages:req-1:succeeded" {
		t.Fatalf("scan reports: %s", got)
	}
	fin := reps[1]
	if fin.Trigger != models.ScanTriggerConsole || fin.StartedAt == nil || fin.CompletedAt == nil || fin.AgentID != "agent-1" {
		t.Errorf("finish report: %+v", fin)
	}
	if n, _ := fin.Summary["packages"].(float64); n != 1 {
		t.Errorf("summary: %+v", fin.Summary)
	}
}

func TestCancelledRequestIsNotRun(t *testing.T) {
	a, fake := newScanTestAgent(t)
	fake.startReply = func(r models.ScanReport) models.ScanReportResponse {
		return models.ScanReportResponse{ScanID: r.ScanID, Status: models.ScanStatusCancelled, Accepted: false}
	}
	a.runScan(context.Background(), models.ScanTypePackages, models.ScanTriggerConsole, []string{"req-1"})
	if len(fake.packages) != 0 {
		t.Fatalf("cancelled request ran: %+v", fake.packages)
	}
	if got := statuses(fake.takeReports()); got != "packages:req-1:running" {
		t.Fatalf("reports: %s", got)
	}
}

func TestScanTypeNeverRunsTwiceAtOnce(t *testing.T) {
	a, fake := newScanTestAgent(t)
	release := make(chan struct{})
	entered := make(chan struct{}, 4)
	var mu sync.Mutex
	running, maxRunning, calls := 0, 0, 0
	a.collectPackages = func(context.Context) packages.Result {
		mu.Lock()
		running++
		calls++
		if running > maxRunning {
			maxRunning = running
		}
		mu.Unlock()
		entered <- struct{}{}
		<-release
		mu.Lock()
		running--
		mu.Unlock()
		return packages.Result{Packages: []models.Package{{Name: "bash", Version: "5.2", Type: "deb"}}}
	}
	ctx := context.Background()
	done := make(chan struct{})
	go func() { a.runScan(ctx, models.ScanTypePackages, models.ScanTriggerSchedule, nil); close(done) }()
	<-entered

	// While the scheduled run is in flight: a console request queues (returns
	// at once), a second scheduled run is skipped.
	a.runScan(ctx, models.ScanTypePackages, models.ScanTriggerConsole, []string{"req-1"})
	a.runScan(ctx, models.ScanTypePackages, models.ScanTriggerConsole, []string{"req-2"})
	a.runScan(ctx, models.ScanTypePackages, models.ScanTriggerSchedule, nil)

	release <- struct{}{} // finish the scheduled run
	<-entered             // the queued requests' run starts right after
	release <- struct{}{}
	<-done

	if calls != 2 || maxRunning != 1 {
		t.Fatalf("calls=%d max concurrent=%d, want 2 and 1", calls, maxRunning)
	}
	got := statuses(fake.takeReports())
	want := "packages::running,packages:row-1:succeeded," +
		"packages:req-1:running,packages:req-2:running,packages:req-1:succeeded,packages:req-2:succeeded"
	if got != want {
		t.Fatalf("reports:\n got %s\nwant %s", got, want)
	}
	if len(fake.packages) != 2 || fake.packages[0].ScanID != "row-1" || fake.packages[1].ScanID != "req-1" || !fake.packages[1].Force {
		t.Fatalf("package reports: %+v", fake.packages)
	}
}

func TestScheduledRunCreatesItsRowAndLinksThePayload(t *testing.T) {
	a, fake := newScanTestAgent(t)
	a.runScan(context.Background(), models.ScanTypeInventory, models.ScanTriggerStartup, nil)
	reps := fake.takeReports()
	if got := statuses(reps); got != "inventory::running,inventory:row-1:succeeded" {
		t.Fatalf("reports: %s", got)
	}
	if reps[0].Trigger != models.ScanTriggerStartup {
		t.Errorf("trigger: %q", reps[0].Trigger)
	}
	if len(fake.inventory) != 1 || fake.inventory[0].ScanID != "row-1" {
		t.Fatalf("inventory: %+v", fake.inventory)
	}
}

func TestOldServerWithoutScanHistory(t *testing.T) {
	a, fake := newScanTestAgent(t)
	fake.scansCode = http.StatusNotFound
	clock := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return clock }
	var hits int
	inner := fake.handler(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/edr/scans" {
			hits++
		}
		inner(w, r)
	}))
	defer srv.Close()
	a = newTestAgent(t, srv.URL, models.AgentConfig{})
	a.now = func() time.Time { return clock }

	ctx := context.Background()
	a.runScan(ctx, models.ScanTypeInventory, models.ScanTriggerSchedule, nil)
	a.runScan(ctx, models.ScanTypeInventory, models.ScanTriggerSchedule, nil)
	if hits != 1 {
		t.Fatalf("/api/edr/scans hit %d times, want 1 (then backed off)", hits)
	}
	if len(fake.inventory) != 2 || fake.inventory[0].ScanID != "" {
		t.Fatalf("inventory still sent without a scan id: %+v", fake.inventory)
	}
	clock = clock.Add(25 * time.Hour)
	a.runScan(ctx, models.ScanTypeInventory, models.ScanTriggerSchedule, nil)
	if hits != 2 {
		t.Fatalf("after the back-off: %d hits", hits)
	}
}

func TestYaraIncrementalPassesRecordedOnlyWithNewHits(t *testing.T) {
	a, fake := newScanTestAgent(t)
	a.yaraSigPath = "/tmp/sig.yar"
	a.yaraPaths = []string{"/tmp"}
	var matches []telemetry.Record
	var gotSince []time.Time
	a.runYara = func(_ context.Context, _ string, s osquery.YaraScan) ([]telemetry.Record, error) {
		gotSince = append(gotSince, s.ChangedSince)
		return matches, nil
	}
	ctx := context.Background()

	a.runScan(ctx, models.ScanTypeYara, models.ScanTriggerStartup, nil)  // full, recorded
	a.runScan(ctx, models.ScanTypeYara, models.ScanTriggerSchedule, nil) // incremental, nothing found
	matches = []telemetry.Record{{Columns: map[string]string{"path": "/tmp/evil"}}}
	a.runScan(ctx, models.ScanTypeYara, models.ScanTriggerSchedule, nil)              // incremental, a new hit
	a.runScan(ctx, models.ScanTypeYara, models.ScanTriggerSchedule, nil)              // same file again: not new
	a.runScan(ctx, models.ScanTypeYara, models.ScanTriggerConsole, []string{"req-1"}) // on demand: full

	if len(gotSince) != 5 || !gotSince[0].IsZero() || gotSince[1].IsZero() || !gotSince[4].IsZero() {
		t.Fatalf("ChangedSince per pass: %v", gotSince)
	}
	reps := fake.takeReports()
	if got := statuses(reps); got != "yara::running,yara:row-1:succeeded,yara::succeeded,yara:req-1:running,yara:req-1:succeeded" {
		t.Fatalf("reports: %s", got)
	}
	if reps[1].Summary["full"] != true || reps[2].Summary["full"] != false || reps[2].Summary["new_hits"] != float64(1) {
		t.Errorf("summaries: %+v / %+v", reps[1].Summary, reps[2].Summary)
	}
	if reps[4].Summary["hits"] != float64(1) || reps[4].Summary["new_hits"] != float64(0) {
		t.Errorf("on-demand summary: %+v", reps[4].Summary)
	}
}

func TestUnavailableScanners(t *testing.T) {
	a, fake := newScanTestAgent(t) // noop vuln scanner, YARA not configured
	ctx := context.Background()

	// Scheduled vuln without grype: the empty report goes out as before, no history.
	a.runScan(ctx, models.ScanTypeVuln, models.ScanTriggerSchedule, nil)
	if len(fake.vulns) != 1 || len(fake.takeReports()) != 0 {
		t.Fatalf("scheduled noop vuln: vulns=%d", len(fake.vulns))
	}
	// On demand: failed, with the reason.
	a.runScan(ctx, models.ScanTypeVuln, models.ScanTriggerConsole, []string{"req-1"})
	a.runScan(ctx, models.ScanTypeYara, models.ScanTriggerConsole, []string{"req-2"})
	reps := fake.takeReports()
	if got := statuses(reps); got != "vuln:req-1:running,vuln:req-1:failed,yara:req-2:running,yara:req-2:failed" {
		t.Fatalf("reports: %s", got)
	}
	if !strings.Contains(reps[1].Error, "grype not found") || !strings.Contains(reps[3].Error, "YARA") {
		t.Errorf("errors: %q / %q", reps[1].Error, reps[3].Error)
	}
	if len(fake.vulns) != 1 {
		t.Errorf("on-demand noop vuln sent a report")
	}

	// A type this agent does not know: reported failed, nothing run.
	a.handleScanRequests(ctx, []models.ScanRequest{{ScanID: "req-3", ScanType: "memory"}})
	a.scans.wg.Wait()
	if reps = fake.takeReports(); len(reps) != 1 || reps[0].Status != models.ScanStatusFailed || reps[0].ScanID != "req-3" {
		t.Fatalf("unknown type: %+v", reps)
	}
}
