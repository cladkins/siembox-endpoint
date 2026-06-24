package transport

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cladkins/siembox-edr/internal/models"
)

func newTestClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := New(Options{ServerURL: srv.URL, AgentID: "agent-1", AgentAPIKey: "secret"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestEnroll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/edr/agents/enroll" || r.Method != http.MethodPost {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var req models.EnrollRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if req.EnrollmentToken != "tok" {
			t.Errorf("token = %q", req.EnrollmentToken)
		}
		json.NewEncoder(w).Encode(models.EnrollResponse{
			AgentID:     "agent-1",
			AgentAPIKey: "secret",
			Config:      models.AgentConfig{ConfigVersion: 1},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	resp, err := c.Enroll(context.Background(), models.EnrollRequest{EnrollmentToken: "tok"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if resp.AgentID != "agent-1" || resp.Config.ConfigVersion != 1 {
		t.Errorf("unexpected response %+v", resp)
	}
}

func TestSendEventsAuthAndBody(t *testing.T) {
	var gotAuth, gotAgent string
	var gotEvents int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAgent = r.Header.Get("X-Agent-ID")
		var b models.EventBatch
		json.NewDecoder(r.Body).Decode(&b)
		gotEvents = len(b.Events)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	err := c.SendEvents(context.Background(), models.EventBatch{
		AgentID: "agent-1",
		Events:  []models.Event{{ID: "1", Title: "t"}, {ID: "2", Title: "u"}},
	})
	if err != nil {
		t.Fatalf("SendEvents: %v", err)
	}
	if gotAuth != "Bearer secret" {
		t.Errorf("auth header = %q", gotAuth)
	}
	if gotAgent != "agent-1" {
		t.Errorf("agent header = %q", gotAgent)
	}
	if gotEvents != 2 {
		t.Errorf("events = %d", gotEvents)
	}
}

func TestNon2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	err := c.SendInventory(context.Background(), models.InventoryRequest{AgentID: "agent-1"})
	if err == nil {
		t.Fatal("expected error on 401")
	}
}

func TestPostRaw(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	if err := c.PostRaw(context.Background(), "/api/edr/events", []byte(`{"x":1}`)); err != nil {
		t.Fatalf("PostRaw: %v", err)
	}
	if gotBody != `{"x":1}` {
		t.Errorf("body = %q", gotBody)
	}
}
