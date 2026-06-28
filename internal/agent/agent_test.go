package agent

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cladkins/siembox-endpoint/internal/config"
	"github.com/cladkins/siembox-endpoint/internal/models"
	"github.com/cladkins/siembox-endpoint/internal/transport"
)

func newTestAgent(t *testing.T, serverURL string, cfg models.AgentConfig) *Agent {
	t.Helper()
	dir := t.TempDir()
	state := &config.State{
		Dir:      dir,
		Settings: config.Settings{ServerURL: serverURL},
		Identity: config.Identity{AgentID: "agent-1", AgentAPIKey: "secret", Config: cfg},
	}
	spool, err := transport.NewSpool(filepath.Join(dir, "spool"))
	if err != nil {
		t.Fatalf("spool: %v", err)
	}
	a, err := New(state, spool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func TestSyncYaraRulesAppliesUpdate(t *testing.T) {
	const serverRule = "rule ServerDelivered { condition: true }\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/edr/agents/agent-1/yara" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		io.WriteString(w, serverRule)
	}))
	defer srv.Close()

	a := newTestAgent(t, srv.URL, models.AgentConfig{YaraRulesVersion: 3})
	a.syncYaraRules(context.Background())

	// Signature file should contain the embedded baseline AND the server rule.
	sig := filepath.Join(a.state.Dir, "yara", "siembox.yar")
	data, err := os.ReadFile(sig)
	if err != nil {
		t.Fatalf("read sig: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, "SIEMBOX_YARA_SELFTEST") {
		t.Error("baseline missing from written signatures")
	}
	if !strings.Contains(s, "rule ServerDelivered") {
		t.Error("server rule missing from written signatures")
	}

	if a.state.Identity.AppliedYaraRulesVersion != 3 {
		t.Errorf("applied version = %d, want 3", a.state.Identity.AppliedYaraRulesVersion)
	}
	// Applied version must be persisted to identity.json.
	idRaw, err := os.ReadFile(filepath.Join(a.state.Dir, "identity.json"))
	if err != nil {
		t.Fatalf("read identity.json: %v", err)
	}
	if !strings.Contains(string(idRaw), `"applied_yara_rules_version": 3`) {
		t.Errorf("applied version not persisted to identity.json: %s", idRaw)
	}
	// A restart should have been signalled.
	if len(a.restartDetection) != 1 {
		t.Error("expected a detection restart to be queued")
	}
}

func TestSyncYaraRulesSkipsWhenNotNewer(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	a := newTestAgent(t, srv.URL, models.AgentConfig{YaraRulesVersion: 2})
	a.state.Identity.AppliedYaraRulesVersion = 2 // already applied
	a.syncYaraRules(context.Background())

	if called {
		t.Error("server should not be contacted when version is not newer")
	}
	if len(a.restartDetection) != 0 {
		t.Error("no restart should be queued when nothing changed")
	}
}
