package agent

import (
	"context"
	"encoding/json"
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
	// New rules must reach files the incremental scan already passed over.
	if len(a.yaraRescan) != 1 {
		t.Error("expected a full YARA rescan to be queued")
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
	if len(a.yaraRescan) != 0 {
		t.Error("no YARA rescan should be queued when nothing changed")
	}
}

func TestHeartbeatCarriesUpdateReportUntilConfigDropsIt(t *testing.T) {
	const id = "b6f1c2d0-1111-4222-8333-444455556666"
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		got = append(got, body)
		io.WriteString(w, `{"config_version": 1}`)
	}))
	defer srv.Close()

	a := newTestAgent(t, srv.URL, models.AgentConfig{ConfigVersion: 1,
		AgentUpdate: &models.AgentUpdateRequest{Version: "1.4.0", RequestID: id}})
	a.state.Identity.LastUpdateRequestID = id // already attempted: Consider must not start it
	a.state.Identity.UpdateReport = &models.UpdateReport{RequestID: id, Version: "1.4.0", State: models.UpdateStateFailed, Error: "boom"}

	a.heartbeat(context.Background())
	u, _ := got[0]["update"].(map[string]any)
	if u["request_id"] != id || u["state"] != "failed" || u["error"] != "boom" || got[0]["agent_version"] == nil {
		t.Fatalf("heartbeat body: %v", got[0])
	}

	// Server cleared the request: the report is dropped and the field omitted.
	a.state.Identity.Config.AgentUpdate = nil
	a.heartbeat(context.Background()) // prunes after this one is sent
	a.heartbeat(context.Background())
	if _, present := got[len(got)-1]["update"]; present {
		t.Fatalf("update must be omitted once config no longer carries it: %v", got[len(got)-1])
	}
}
