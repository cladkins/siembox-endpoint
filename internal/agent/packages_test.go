package agent

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/cladkins/siembox-endpoint/internal/models"
	"github.com/cladkins/siembox-endpoint/internal/packages"
)

// fakePackageServer mimics POST /api/edr/packages: it keeps the last stored
// hash, answers unchanged / snapshot_required, and records every request.
type fakePackageServer struct {
	mu       sync.Mutex
	status   int // non-zero: answer every request with this status
	stored   string
	requests []models.PackageReport
}

func (f *fakePackageServer) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Path != "/api/edr/packages" || r.Method != http.MethodPost {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Content-Encoding") != "gzip" || r.Header.Get("X-Agent-ID") != "agent-1" {
			t.Errorf("headers: %v", r.Header)
		}
		if f.status != 0 {
			w.WriteHeader(f.status)
			w.Write([]byte(`{"error":"Not found"}`))
			return
		}
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Fatalf("gzip: %v", err)
		}
		var rep models.PackageReport
		if err := json.NewDecoder(zr).Decode(&rep); err != nil {
			t.Fatalf("decode: %v", err)
		}
		f.requests = append(f.requests, rep)
		resp := models.PackageReportResponse{}
		switch {
		case rep.SnapshotHash == f.stored:
			resp = models.PackageReportResponse{Accepted: true, Unchanged: true}
		case rep.Packages == nil:
			resp = models.PackageReportResponse{SnapshotRequired: true}
		default:
			f.stored = rep.SnapshotHash
			resp = models.PackageReportResponse{Accepted: true, Stored: len(rep.Packages)}
		}
		json.NewEncoder(w).Encode(resp)
	}
}

func (f *fakePackageServer) take() []models.PackageReport {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.requests
	f.requests = nil
	return r
}

func TestReportPackages(t *testing.T) {
	fake := &fakePackageServer{}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()

	a := newTestAgent(t, srv.URL, models.AgentConfig{})
	clock := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return clock }
	list := []models.Package{{Name: "openssh-server", Version: "1:9.6p1", Type: "deb"}, {Name: "libc6", Version: "2.39", Type: "deb"}}
	a.collectPackages = func(context.Context) packages.Result {
		return packages.Result{Packages: packages.Normalize(list), Sources: map[string]int{"dpkg": len(list)}}
	}
	ctx := context.Background()

	// First run: the full list.
	a.reportPackages(ctx)
	reqs := fake.take()
	if len(reqs) != 1 || len(reqs[0].Packages) != 2 || reqs[0].SnapshotHash != packages.Hash(packages.Normalize(list)) {
		t.Fatalf("first run: %+v", reqs)
	}
	if a.state.Identity.PackagesHash != reqs[0].SnapshotHash || !a.state.Identity.PackagesSentAt.Equal(clock) {
		t.Errorf("state not persisted: %+v", a.state.Identity)
	}

	// Unchanged, an hour later: the hash alone.
	clock = clock.Add(time.Hour)
	a.reportPackages(ctx)
	if reqs = fake.take(); len(reqs) != 1 || reqs[0].Packages != nil {
		t.Fatalf("unchanged run: %+v", reqs)
	}

	// The server lost it: hash-only, snapshot_required, then the full list.
	fake.stored = ""
	a.reportPackages(ctx)
	if reqs = fake.take(); len(reqs) != 2 || reqs[0].Packages != nil || len(reqs[1].Packages) != 2 {
		t.Fatalf("snapshot_required: %+v", reqs)
	}

	// Changed: the full list.
	list = append(list, models.Package{Name: "nginx", Version: "1.24.0", Type: "deb"})
	a.reportPackages(ctx)
	if reqs = fake.take(); len(reqs) != 1 || len(reqs[0].Packages) != 3 {
		t.Fatalf("changed run: %+v", reqs)
	}

	// A day after the last full send: the full list again, unchanged or not.
	clock = clock.Add(25 * time.Hour)
	a.reportPackages(ctx)
	if reqs = fake.take(); len(reqs) != 1 || len(reqs[0].Packages) != 3 {
		t.Fatalf("daily resend: %+v", reqs)
	}

	// Nothing collected: nothing sent (an empty list would clear the server's).
	a.collectPackages = func(context.Context) packages.Result { return packages.Result{} }
	a.reportPackages(ctx)
	if reqs = fake.take(); len(reqs) != 0 {
		t.Fatalf("empty collection sent %+v", reqs)
	}
}

func TestReportPackagesBacksOffOn404(t *testing.T) {
	fake := &fakePackageServer{status: http.StatusNotFound}
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		fake.handler(t)(w, r)
	}))
	defer srv.Close()

	a := newTestAgent(t, srv.URL, models.AgentConfig{})
	clock := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return clock }
	collected := 0
	a.collectPackages = func(context.Context) packages.Result {
		collected++
		return packages.Result{Packages: []models.Package{{Name: "bash", Version: "5.2", Type: "deb"}}}
	}
	ctx := context.Background()
	a.reportPackages(ctx)
	clock = clock.Add(6 * time.Hour)
	a.reportPackages(ctx) // inside the back-off: not even collected
	if hits != 1 || collected != 1 {
		t.Fatalf("hits=%d collected=%d, want 1 and 1", hits, collected)
	}
	if a.state.Identity.PackagesHash != "" {
		t.Error("a 404 recorded a hash")
	}
	clock = clock.Add(19 * time.Hour)
	fake.status = 0
	a.reportPackages(ctx)
	if hits != 2 || len(fake.take()) != 1 {
		t.Fatalf("after the back-off: hits=%d", hits)
	}
}
