package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cladkins/siembox-endpoint/internal/config"
	"github.com/cladkins/siembox-endpoint/internal/models"
)

const reqID = "b6f1c2d0-1111-4222-8333-444455556666"

// release is a fake GitHub release for one version.
type release struct {
	files    map[string][]byte // asset name -> body
	sums     map[string]string // overrides the computed sum per name
	noSums   bool
	extra    string // appended to SHA256SUMS
	mu       sync.Mutex
	requests []string
}

func tarGz(t *testing.T, bin string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "siembox-agent", Mode: 0o755, Size: int64(len(bin)), Typeflag: tar.TypeReg})
	tw.Write([]byte(bin))
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func (r *release) handler(version string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.requests = append(r.requests, req.URL.Path)
		r.mu.Unlock()
		prefix := "/v" + version + "/"
		if !strings.HasPrefix(req.URL.Path, prefix) {
			http.NotFound(w, req)
			return
		}
		name := strings.TrimPrefix(req.URL.Path, prefix)
		if name == "SHA256SUMS" {
			if r.noSums {
				http.NotFound(w, req)
				return
			}
			var b strings.Builder
			for n, body := range r.files {
				sum := sha256.Sum256(body)
				h := hex.EncodeToString(sum[:])
				if o, ok := r.sums[n]; ok {
					h = o
				}
				fmt.Fprintf(&b, "%s  %s\n", h, n)
			}
			b.WriteString(r.extra)
			io.WriteString(w, b.String())
			return
		}
		body, ok := r.files[name]
		if !ok {
			http.NotFound(w, req)
			return
		}
		w.Write(body)
	})
}

type harness struct {
	u        *Updater
	state    *config.State
	exe      string
	launched []Command
	runner   *fakeRunner
	rel      *release
	now      time.Time
}

func newHarness(t *testing.T, current, target string, rel *release, runnerOut map[string]string, mutate func(*Options)) *harness {
	t.Helper()
	srv := httptest.NewTLSServer(rel.handler(target))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	exe := filepath.Join(dir, "siembox-agent")
	if err := os.WriteFile(exe, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}
	h := &harness{
		state:  &config.State{Dir: dir},
		exe:    exe,
		rel:    rel,
		now:    time.Unix(1_700_000_000, 0),
		runner: &fakeRunner{out: runnerOut},
	}
	// Self-check of the downloaded binary reports the target version.
	h.runner.out[exe+".new version"] = target + "\n"
	opts := Options{
		State: h.state, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		BaseURL: srv.URL, HTTPClient: srv.Client(), Runner: h.runner,
		Launch: func(c Command) error { h.launched = append(h.launched, c); return nil },
		GOOS:   "linux", GOARCH: "amd64", ExePath: exe, CurrentVersion: current,
		Now: func() time.Time { return h.now },
	}
	if mutate != nil {
		mutate(&opts)
	}
	h.u = New(opts)
	return h
}

func (h *harness) request(t *testing.T, id, ver string) bool {
	t.Helper()
	ok := h.u.Consider(context.Background(), &models.AgentUpdateRequest{RequestID: id, Version: ver})
	h.u.Wait()
	return ok
}

func (h *harness) report() *models.UpdateReport { return h.u.Report() }

func archiveRelease(t *testing.T, ver string) *release {
	return &release{files: map[string][]byte{
		fmt.Sprintf("siembox-endpoint_%s_linux_amd64.tar.gz", ver): tarGz(t, "NEW"),
		fmt.Sprintf("siembox-agent_%s_amd64.deb", ver):             []byte("deb-bytes"),
	}}
}

func wantFailed(t *testing.T, h *harness, substr string) {
	t.Helper()
	r := h.report()
	if r == nil || r.State != models.UpdateStateFailed || !strings.Contains(r.Error, substr) {
		t.Fatalf("want failed containing %q, got %+v", substr, r)
	}
	if len(h.launched) != 0 {
		t.Fatalf("installer must not launch on failure: %+v", h.launched)
	}
	if len(r.Error) > maxErrorLen {
		t.Fatalf("error too long: %d", len(r.Error))
	}
	h.state.View(func(id *config.Identity) {
		if id.PendingUpdate != nil {
			t.Error("failed attempt must not leave pending_update")
		}
	})
}

func TestArchiveUpdateSwapsBinaryAndRestarts(t *testing.T) {
	h := newHarness(t, "1.3.2", "1.4.0", archiveRelease(t, "1.4.0"), map[string]string{}, nil)
	if !h.request(t, reqID, "1.4.0") {
		t.Fatal("attempt not started")
	}
	if b, _ := os.ReadFile(h.exe); string(b) != "NEW" {
		t.Fatalf("exe not replaced: %q", b)
	}
	if len(h.launched) != 1 || strings.Join(h.launched[0].Argv, " ") != h.exe+" -dir "+h.state.Dir+" restart" {
		t.Fatalf("launch: %+v", h.launched)
	}
	r := h.report()
	if r.State != models.UpdateStateInstalling || r.RequestID != reqID || r.Version != "1.4.0" {
		t.Fatalf("report: %+v", r)
	}
	h.state.View(func(id *config.Identity) {
		p := id.PendingUpdate
		if p == nil || p.RequestID != reqID || p.Version != "1.4.0" || !p.StartedAt.Equal(h.now) {
			t.Errorf("pending: %+v", p)
		}
	})
	if _, err := os.Stat(h.exe + ".new"); err == nil {
		t.Error(".new must not linger")
	}
}

func TestDebUpdateUsesPackageInstaller(t *testing.T) {
	h := newHarness(t, "1.3.2", "1.4.0", archiveRelease(t, "1.4.0"), map[string]string{}, nil)
	h.runner.out["dpkg-query -S "+h.exe] = "siembox-agent: " + h.exe + "\n"
	h.request(t, reqID, "1.4.0")
	if len(h.launched) != 1 {
		t.Fatalf("launch: %+v (report %+v)", h.launched, h.report())
	}
	argv := h.launched[0].Argv
	wantPath := filepath.Join(h.state.Dir, "update", "siembox-agent_1.4.0_amd64.deb")
	if argv[len(argv)-1] != wantPath || argv[len(argv)-2] != "sh" {
		t.Fatalf("argv: %q", argv)
	}
	if b, _ := os.ReadFile(h.exe); string(b) != "OLD" {
		t.Error("deb path must not touch the binary itself")
	}
	if b, _ := os.ReadFile(wantPath); string(b) != "deb-bytes" {
		t.Error("verified asset missing")
	}
}

func TestUpdateFailures(t *testing.T) {
	const archive = "siembox-endpoint_1.4.0_linux_amd64.tar.gz"
	tests := []struct {
		name   string
		mutate func(*release)
		opts   func(*Options)
		want   string
	}{
		{"checksum mismatch", func(r *release) { r.sums = map[string]string{archive: strings.Repeat("0", 64)} }, nil, "checksum mismatch"},
		{"missing SHA256SUMS", func(r *release) { r.noSums = true }, nil, "no SHA256SUMS"},
		{"missing asset", func(r *release) { delete(r.files, archive) }, nil, "no asset"},
		{"asset listed but not served", func(r *release) {
			r.extra = strings.Repeat("a", 64) + "  siembox-endpoint_1.4.0_linux_amd64.tar.gz\n"
			delete(r.files, archive)
		}, nil, "not found"},
		{"oversize", nil, func(o *Options) { o.MaxSize = 10 }, "limit"},
		{"malformed SHA256SUMS", func(r *release) { r.extra = "garbage line\n" }, nil, "malformed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rel := archiveRelease(t, "1.4.0")
			if tt.mutate != nil {
				tt.mutate(rel)
			}
			h := newHarness(t, "1.3.2", "1.4.0", rel, map[string]string{}, tt.opts)
			h.request(t, reqID, "1.4.0")
			wantFailed(t, h, tt.want)
			if b, _ := os.ReadFile(h.exe); string(b) != "OLD" {
				t.Errorf("exe modified on failure: %q", b)
			}
		})
	}
}

func TestSelfCheckFailureKeepsOldBinary(t *testing.T) {
	h := newHarness(t, "1.3.2", "1.4.0", archiveRelease(t, "1.4.0"), map[string]string{}, nil)
	h.runner.out[h.exe+".new version"] = "9.9.9\n"
	h.request(t, reqID, "1.4.0")
	wantFailed(t, h, "self-check")
	if b, _ := os.ReadFile(h.exe); string(b) != "OLD" {
		t.Errorf("exe replaced despite failed self-check")
	}
}

func TestVersionPolicy(t *testing.T) {
	tests := []struct {
		name, current, target string
		wantStarted           bool
		wantErr               string
	}{
		{"downgrade refused", "1.5.0", "1.4.0", true, "not newer"},
		{"same version refused", "1.4.0", "1.4.0", true, "not newer"},
		{"dev build allowed", "dev", "1.4.0", true, ""},
		{"dirty dev build allowed", "a8922f4-dirty", "1.4.0", true, ""},
		{"prerelease target refused", "1.3.0", "1.4.0-rc1", true, "invalid target version"},
		{"v-prefixed target refused", "1.3.0", "v1.4.0", true, "invalid target version"},
		{"url-ish target refused", "1.3.0", "1.4.0/../../x", true, "invalid target version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, tt.current, "1.4.0", archiveRelease(t, "1.4.0"), map[string]string{}, nil)
			if got := h.request(t, reqID, tt.target); got != tt.wantStarted {
				t.Fatalf("started=%v", got)
			}
			if tt.wantErr != "" {
				wantFailed(t, h, tt.wantErr)
				for _, p := range h.rel.requests {
					t.Errorf("must not hit network, got %s", p)
				}
				return
			}
			if r := h.report(); r.State != models.UpdateStateInstalling || len(h.launched) != 1 {
				t.Fatalf("report %+v launched %v", r, h.launched)
			}
		})
	}
}

func TestSameRequestIDNotRetried(t *testing.T) {
	rel := archiveRelease(t, "1.4.0")
	rel.noSums = true
	h := newHarness(t, "1.3.2", "1.4.0", rel, map[string]string{}, nil)
	if !h.request(t, reqID, "1.4.0") {
		t.Fatal("first attempt should start")
	}
	n := len(rel.requests)
	if h.request(t, reqID, "1.4.0") {
		t.Fatal("same request_id must not be retried")
	}
	if len(rel.requests) != n {
		t.Fatal("retry hit the network")
	}
	// Survives restart: a new Updater over the same persisted identity.
	u2 := New(Options{State: h.state, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), BaseURL: "https://127.0.0.1:1", ExePath: h.exe, CurrentVersion: "1.3.2"})
	if u2.Consider(context.Background(), &models.AgentUpdateRequest{RequestID: reqID, Version: "1.4.0"}) {
		t.Fatal("same request_id retried after restart")
	}
	// A fresh request_id is attempted.
	rel.noSums = false
	if !h.request(t, "c7a2d3e1-0000-4000-8000-000000000001", "1.4.0") {
		t.Fatal("new request_id must be attempted")
	}
}

func TestInvalidRequestIDIgnored(t *testing.T) {
	h := newHarness(t, "1.3.2", "1.4.0", archiveRelease(t, "1.4.0"), map[string]string{}, nil)
	for _, id := range []string{"", "../etc", "bad id", strings.Repeat("a", 65), "zzz"} {
		if h.request(t, id, "1.4.0") {
			t.Errorf("id %q should be ignored", id)
		}
	}
	if h.report() != nil || len(h.rel.requests) != 0 {
		t.Error("invalid ids must have no effect")
	}
	if h.u.Consider(context.Background(), nil) {
		t.Error("nil request")
	}
}

func TestOneAttemptAtATime(t *testing.T) {
	block := make(chan struct{})
	h := newHarness(t, "1.3.2", "1.4.0", archiveRelease(t, "1.4.0"), map[string]string{}, func(o *Options) {
		o.Launch = func(Command) error { <-block; return nil }
	})
	if !h.u.Consider(context.Background(), &models.AgentUpdateRequest{RequestID: reqID, Version: "1.4.0"}) {
		t.Fatal("first should start")
	}
	// Wait until the first attempt is parked in Launch.
	deadline := time.After(5 * time.Second)
	for {
		var pending bool
		h.state.View(func(id *config.Identity) { pending = id.PendingUpdate != nil })
		if pending {
			break
		}
		select {
		case <-deadline:
			t.Fatal("attempt never reached launch")
		case <-time.After(5 * time.Millisecond):
		}
	}
	if h.u.Consider(context.Background(), &models.AgentUpdateRequest{RequestID: "c7a2d3e1-0000-4000-8000-000000000002", Version: "1.4.0"}) {
		t.Fatal("second attempt must not start while one runs")
	}
	close(block)
	h.u.Wait()
}

func TestLaunchFailureClearsPending(t *testing.T) {
	h := newHarness(t, "1.3.2", "1.4.0", archiveRelease(t, "1.4.0"), map[string]string{}, func(o *Options) {
		o.Launch = func(Command) error { return fmt.Errorf("boom") }
	})
	h.request(t, reqID, "1.4.0")
	r := h.report()
	if r.State != models.UpdateStateFailed || !strings.Contains(r.Error, "boom") {
		t.Fatalf("%+v", r)
	}
	h.state.View(func(id *config.Identity) {
		if id.PendingUpdate != nil {
			t.Error("pending must be cleared")
		}
	})
}

func TestStartupResolution(t *testing.T) {
	started := time.Unix(1_700_000_000, 0)
	pend := &config.PendingUpdate{RequestID: reqID, Version: "1.4.0", StartedAt: started}
	tests := []struct {
		name      string
		current   string
		pending   *config.PendingUpdate
		report    *models.UpdateReport
		log       string
		wantState string
		wantErr   string
	}{
		{"succeeded", "1.4.0", pend, nil, "", models.UpdateStateSucceeded, ""},
		{"failed still old", "1.3.2", pend, nil, "dpkg: error processing\n", models.UpdateStateFailed, "still version 1.3.2"},
		{"failed includes log tail", "1.3.2", pend, nil, "dpkg: error processing\n", models.UpdateStateFailed, "dpkg: error processing"},
		{"interrupted download", "1.3.2", nil, &models.UpdateReport{RequestID: reqID, Version: "1.4.0", State: models.UpdateStateDownloading}, "", models.UpdateStateFailed, "restarted"},
		{"finished report untouched", "1.3.2", nil, &models.UpdateReport{RequestID: reqID, Version: "1.4.0", State: models.UpdateStateFailed, Error: "x"}, "", models.UpdateStateFailed, "x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			st := &config.State{Dir: dir, Identity: config.Identity{PendingUpdate: tt.pending, UpdateReport: tt.report}}
			if tt.log != "" {
				os.WriteFile(filepath.Join(dir, "update.log"), []byte(tt.log), 0o600)
			}
			u := New(Options{State: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), CurrentVersion: tt.current, ExePath: filepath.Join(dir, "a")})
			u.Startup()
			r := u.Report()
			if r.State != tt.wantState || !strings.Contains(r.Error, tt.wantErr) || r.RequestID != reqID {
				t.Fatalf("%+v", r)
			}
			if st.Identity.PendingUpdate != nil {
				t.Error("pending must be resolved")
			}
			if tt.wantState == models.UpdateStateSucceeded && r.Error != "" {
				t.Error("no error on success")
			}
		})
	}
}

func TestPendingTimeout(t *testing.T) {
	dir := t.TempDir()
	started := time.Unix(1_700_000_000, 0)
	now := started.Add(PendingTimeout - time.Second)
	st := &config.State{Dir: dir, Identity: config.Identity{PendingUpdate: &config.PendingUpdate{RequestID: reqID, Version: "1.4.0", StartedAt: started}}}
	os.WriteFile(filepath.Join(dir, "update.log"), []byte("installer stuck\n"), 0o600)
	u := New(Options{State: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), CurrentVersion: "1.3.2", Now: func() time.Time { return now }})
	u.CheckPending()
	if u.Report() != nil || st.Identity.PendingUpdate == nil {
		t.Fatal("must not fail before the timeout")
	}
	now = started.Add(PendingTimeout)
	u.CheckPending()
	r := u.Report()
	if r == nil || r.State != models.UpdateStateFailed || !strings.Contains(r.Error, "installer stuck") || st.Identity.PendingUpdate != nil {
		t.Fatalf("%+v", r)
	}
}

func TestPrune(t *testing.T) {
	st := &config.State{Dir: t.TempDir()}
	u := New(Options{State: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	set := func(s string) {
		st.Identity.UpdateReport = &models.UpdateReport{RequestID: reqID, Version: "1.4.0", State: s}
	}
	set(models.UpdateStateSucceeded)
	u.Prune(reqID)
	if u.Report() == nil {
		t.Fatal("kept while config still carries the id")
	}
	u.Prune("")
	if u.Report() != nil {
		t.Fatal("dropped once config no longer carries the id")
	}
	set(models.UpdateStateInstalling)
	u.Prune("")
	if u.Report() == nil {
		t.Fatal("in-progress report must be kept")
	}
	set(models.UpdateStateFailed)
	u.Prune("c7a2d3e1-0000-4000-8000-000000000003")
	if u.Report() != nil {
		t.Fatal("dropped when config carries a different id")
	}
}

func TestErrorTruncation(t *testing.T) {
	s := strings.Repeat("é", 400)
	if got := truncate(s, maxErrorLen); len(got) > maxErrorLen || !strings.HasPrefix(s, got) {
		t.Fatalf("len %d", len(got))
	}
}

func TestDownloadClientIgnoresServerTLSSettings(t *testing.T) {
	c := NewHTTPClient()
	tr := c.Transport.(*http.Transport)
	if tr.TLSClientConfig.RootCAs != nil || tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("download client must use system CAs and verify")
	}
	if tr.Proxy == nil {
		t.Fatal("proxy from environment must be honored")
	}
	if err := c.CheckRedirect(&http.Request{URL: mustURL("http://example.com/x")}, nil); err == nil {
		t.Fatal("must refuse http redirect")
	}
}

func TestPlainHTTPBaseRejected(t *testing.T) {
	d := &Downloader{BaseURL: "http://example.com/releases"}
	if _, err := d.FetchSums(context.Background(), "1.4.0"); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("err=%v", err)
	}
	if _, err := d.FetchSums(context.Background(), "1.4.0/../x"); err == nil {
		t.Fatal("bad version must be rejected before any request")
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
